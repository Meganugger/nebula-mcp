//! Governed interactive-desktop tools.
//!
//! The desktop category is deliberately split from the ordinary Windows
//! command wrappers.  Mutating calls require both the explicit
//! `allow_desktop_mutation` policy gate and a short-lived lease owned by the
//! current MCP request.  The Windows implementation delegates only to fixed
//! PowerShell scripts; user values are passed as separate process arguments or
//! escaped data and are never concatenated into a shell command.
//!
//! This module is the first cross-platform slice of the desktop-agent
//! boundary.  It does not pretend that a service can control Session 0: on
//! non-Windows hosts, and on Windows without an interactive desktop, tools
//! return an explicit platform/session error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nebula_mcp_core::{Result, Tool, ToolContext, ToolError};
use nebula_mcp_protocol::mcp::ToolAnnotations;
use nebula_mcp_protocol::CallToolResult;
use parking_lot::Mutex;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::common::output::{exec_result, json_value_result};
use crate::common::platform::{ensure_windows, run_powershell, POWERSHELL};
use crate::common::{Args, ObjectSchema};
use crate::ToolServices;

const CATEGORY: &str = "desktop";
const DEFAULT_LEASE_MS: u64 = 30_000;
const MAX_LEASE_MS: u64 = 300_000;
const MAX_WAIT_MS: u64 = 30_000;

/// A bounded lease for a shared desktop resource.
#[derive(Debug, Clone)]
pub struct DesktopLease {
    /// Opaque lease identifier returned to the caller.
    pub lock_id: String,
    /// Resource name, for example `desktop` or `window:ABC`.
    pub resource: String,
    /// Request identifier that owns the lease.
    pub owner: String,
    /// Wall-clock expiry for display to the caller.
    pub expires_at_unix_ms: u128,
}

#[derive(Debug, Clone)]
struct LeaseRecord {
    lease: DesktopLease,
    expires_at: Instant,
    purpose: String,
}

/// In-memory desktop lease manager.
///
/// Leases are intentionally process-local.  A future desktop agent can use
/// the same semantics over authenticated IPC, but a restart always releases
/// every lease instead of leaving an orphaned lock behind.
#[derive(Debug, Default)]
pub struct DesktopLockManager {
    leases: Mutex<HashMap<String, LeaseRecord>>,
}

impl DesktopLockManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn reap_expired(&self) {
        let now = Instant::now();
        self.leases.lock().retain(|_, record| record.expires_at > now);
    }

    /// Acquire a resource lease, optionally waiting for a bounded period.
    pub async fn acquire(
        &self,
        owner: &str,
        resource: &str,
        lease_ms: u64,
        wait_ms: u64,
        purpose: &str,
    ) -> Result<DesktopLease> {
        if resource.trim().is_empty() {
            return Err(ToolError::InvalidArguments(
                "resource must not be empty".to_string(),
            ));
        }
        let lease_ms = lease_ms.clamp(100, MAX_LEASE_MS);
        let wait_ms = wait_ms.min(MAX_WAIT_MS);
        let deadline = Instant::now() + Duration::from_millis(wait_ms);

        loop {
            self.reap_expired();
            {
                let mut leases = self.leases.lock();
                if !leases.values().any(|record| {
                    record.lease.resource == resource && record.lease.owner != owner
                }) {
                    let lock_id = Uuid::new_v4().to_string();
                    let expires_at = Instant::now() + Duration::from_millis(lease_ms);
                    let unix_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        + u128::from(lease_ms);
                    let lease = DesktopLease {
                        lock_id: lock_id.clone(),
                        resource: resource.to_string(),
                        owner: owner.to_string(),
                        expires_at_unix_ms: unix_ms,
                    };
                    leases.insert(
                        lock_id,
                        LeaseRecord {
                            lease: lease.clone(),
                            expires_at,
                            purpose: purpose.to_string(),
                        },
                    );
                    return Ok(lease);
                }
            }
            if Instant::now() >= deadline {
                return Err(ToolError::ResourceBusy(format!(
                    "desktop resource '{resource}' is leased by another request"
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Release a lease.  Only its owner may release it.
    pub fn release(&self, owner: &str, lock_id: &str) -> Result<DesktopLease> {
        self.reap_expired();
        let mut leases = self.leases.lock();
        let Some(record) = leases.get(lock_id) else {
            return Err(ToolError::StaleHandle(format!(
                "desktop lock '{lock_id}' is missing or expired"
            )));
        };
        if record.lease.owner != owner {
            return Err(ToolError::PermissionDenied(
                "desktop lock is owned by another request".to_string(),
            ));
        }
        let record = leases.remove(lock_id).expect("lease was checked above");
        Ok(record.lease)
    }

    /// Check that a mutation owns a live compatible lease.
    pub fn require(&self, owner: &str, lock_id: &str, resource: &str) -> Result<()> {
        self.reap_expired();
        let leases = self.leases.lock();
        let Some(record) = leases.get(lock_id) else {
            return Err(ToolError::StaleHandle(format!(
                "desktop lock '{lock_id}' is missing or expired"
            )));
        };
        if record.lease.owner != owner {
            return Err(ToolError::PermissionDenied(
                "desktop lock is owned by another request".to_string(),
            ));
        }
        if record.lease.resource != resource
            && record.lease.resource != "desktop"
            && resource != "desktop"
        {
            return Err(ToolError::PermissionDenied(format!(
                "lock resource '{}' does not cover '{resource}'",
                record.lease.resource
            )));
        }
        Ok(())
    }

    /// Return live leases, optionally filtered by owner.
    pub fn status(&self, owner: Option<&str>) -> Vec<Value> {
        self.reap_expired();
        self.leases
            .lock()
            .values()
            .filter(|record| owner.is_none_or(|wanted| wanted == record.lease.owner))
            .map(|record| {
                json!({
                    "lockId": record.lease.lock_id,
                    "resource": record.lease.resource,
                    "owner": record.lease.owner,
                    "purpose": record.purpose,
                    "expiresAtUnixMs": record.lease.expires_at_unix_ms,
                    "renewalRequired": true,
                })
            })
            .collect()
    }
}

/// Build all desktop tools.
#[must_use]
pub fn tools(services: &ToolServices) -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(DesktopLockAcquire {
            locks: services.desktop_locks.clone(),
        }),
        Arc::new(DesktopLockRelease {
            locks: services.desktop_locks.clone(),
        }),
        Arc::new(DesktopLockStatus {
            locks: services.desktop_locks.clone(),
        }),
        Arc::new(DesktopDisplays),
        Arc::new(DesktopCursor),
        Arc::new(DesktopWindows),
        Arc::new(DesktopInput {
            locks: services.desktop_locks.clone(),
        }),
        Arc::new(DesktopWindow {
            locks: services.desktop_locks.clone(),
        }),
    ]
}

fn readonly() -> Option<ToolAnnotations> {
    Some(ToolAnnotations {
        read_only_hint: Some(true),
        ..Default::default()
    })
}

fn mutation() -> Option<ToolAnnotations> {
    Some(ToolAnnotations {
        read_only_hint: Some(false),
        destructive_hint: Some(false),
        ..Default::default()
    })
}

struct DesktopLockAcquire {
    locks: Arc<DesktopLockManager>,
}

#[async_trait]
impl Tool for DesktopLockAcquire {
    fn name(&self) -> &str {
        "desktop.lock_acquire"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Acquire an expiring exclusive lease for desktop, display, or window mutation."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string("resource", "desktop, display:<id>, or window:<id>.", true)
            .integer("leaseMs", "Lease duration, capped at five minutes.", false)
            .integer("waitMs", "Bounded wait for an occupied resource.", false)
            .string("purpose", "Short operator-visible reason.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        mutation()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        let a = Args::new(&args)?;
        let resource = a.str("resource")?;
        let lease = self
            .locks
            .acquire(
                &ctx.request_id,
                resource,
                a.u64_or("leaseMs", DEFAULT_LEASE_MS)?,
                a.u64_or("waitMs", 0)?,
                a.str_or("purpose", "desktop mutation")?,
            )
            .await?;
        Ok(json_value_result(json!({
            "lockId": lease.lock_id,
            "resource": lease.resource,
            "owner": lease.owner,
            "expiresAtUnixMs": lease.expires_at_unix_ms,
            "renewalRequired": true,
        })))
    }
}

struct DesktopLockRelease {
    locks: Arc<DesktopLockManager>,
}

#[async_trait]
impl Tool for DesktopLockRelease {
    fn name(&self) -> &str {
        "desktop.lock_release"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Release a desktop lease owned by the current MCP request."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string("lockId", "Opaque lock identifier.", true)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        mutation()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        let a = Args::new(&args)?;
        let lease = self.locks.release(&ctx.request_id, a.str("lockId")?)?;
        Ok(json_value_result(json!({
            "released": true,
            "lockId": lease.lock_id,
            "resource": lease.resource,
        })))
    }
}

struct DesktopLockStatus {
    locks: Arc<DesktopLockManager>,
}

#[async_trait]
impl Tool for DesktopLockStatus {
    fn name(&self) -> &str {
        "desktop.lock_status"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "List live desktop leases visible to the current request."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .boolean("all", "Include leases owned by other requests.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        readonly()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        let a = Args::new(&args)?;
        let all = a.bool_or("all", false)?;
        Ok(json_value_result(json!({
            "locks": self.locks.status((!all).then_some(ctx.request_id.as_str())),
        })))
    }
}

struct DesktopDisplays;

#[async_trait]
impl Tool for DesktopDisplays {
    fn name(&self) -> &str {
        "desktop.displays"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Enumerate interactive displays, bounds, and DPI information on Windows."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new().build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        readonly()
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        let script = r#"
Get-CimInstance Win32_VideoController |
  Select-Object Name,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,VideoModeDescription |
  ConvertTo-Json -Depth 3
"#;
        let result = run_powershell(ctx, POWERSHELL, script, None).await?;
        Ok(exec_result("display enumeration", &result))
    }
}

struct DesktopCursor;

#[async_trait]
impl Tool for DesktopCursor {
    fn name(&self) -> &str {
        "desktop.cursor"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Read the current cursor position from the interactive Windows desktop."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new().build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        readonly()
    }
    async fn call(&self, ctx: &ToolContext, _args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        let script = r#"
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NebulaCursor {
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
}
'@
$p = New-Object NebulaCursor+POINT
[NebulaCursor]::GetCursorPos([ref]$p) | Out-Null
[pscustomobject]@{x=$p.X; y=$p.Y; coordinateSpace="physical_screen"} | ConvertTo-Json -Compress
"#;
        let result = run_powershell(ctx, POWERSHELL, script, None).await?;
        Ok(exec_result("cursor position", &result))
    }
}

struct DesktopWindows;

#[async_trait]
impl Tool for DesktopWindows {
    fn name(&self) -> &str {
        "desktop.windows"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "List top-level interactive application windows with stable per-call ids."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .boolean("includeHidden", "Include processes without visible windows.", false)
            .string("titleContains", "Case-insensitive title filter.", false)
            .integer("limit", "Maximum rows to return.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        readonly()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        let a = Args::new(&args)?;
        let include_hidden = a.bool_or("includeHidden", false)?;
        let limit = a.u64_or("limit", 200)?.min(500);
        let title_filter = a.opt_str("titleContains")?.unwrap_or("");
        let escaped = title_filter.replace('\'', "''");
        let visibility = if include_hidden {
            "$_.MainWindowHandle -ne 0 -or $_.MainWindowTitle"
        } else {
            "$_.MainWindowHandle -ne 0"
        };
        let script = format!(
            "Get-Process | Where-Object {{ {visibility} -and $_.MainWindowTitle -like '*{escaped}*' }} | \
             Select-Object -First {limit} Id,ProcessName,MainWindowHandle,MainWindowTitle | \
             ConvertTo-Json -Depth 3"
        );
        let result = run_powershell(ctx, POWERSHELL, &script, None).await?;
        Ok(exec_result("window enumeration", &result))
    }
}

struct DesktopInput {
    locks: Arc<DesktopLockManager>,
}

#[async_trait]
impl Tool for DesktopInput {
    fn name(&self) -> &str {
        "desktop.input"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Send bounded mouse and keyboard actions through the interactive Windows input queue."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string("lockId", "Desktop or display lease.", true)
            .prop(
                "actions",
                json!({
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["move","click","key_press","type_text"]},
                            "x": {"type": "integer"},
                            "y": {"type": "integer"},
                            "button": {"type": "string", "enum": ["left","right","middle"]},
                            "key": {"type": "string"},
                            "text": {"type": "string"},
                            "durationMs": {"type": "integer", "maximum": 10000}
                        },
                        "required": ["type"],
                        "additionalProperties": false
                    }
                }),
                true,
            )
            .boolean("restoreModifiers", "Release tracked modifiers on failure.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        mutation()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        ctx.policy.ensure_desktop_mutation_allowed(self.name())?;
        let a = Args::new(&args)?;
        self.locks
            .require(&ctx.request_id, a.str("lockId")?, "desktop")?;
        let actions = a
            .opt_value("actions")
            .and_then(Value::as_array)
            .ok_or_else(|| ToolError::InvalidArguments("actions must be an array".into()))?;
        if actions.is_empty() || actions.len() > 100 {
            return Err(ToolError::InvalidArguments(
                "actions must contain between 1 and 100 items".into(),
            ));
        }
        // The fixed helper accepts JSON as data, not as PowerShell source.
        let payload = serde_json::to_string(actions)?;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let script = format!(
            r#"
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NebulaInput {{
  [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT {{
    public int dx; public int dy; public uint mouseData; public uint dwFlags;
    public uint time; public IntPtr extraInfo;
  }}
  [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT {{
    public ushort wVk; public ushort wScan; public uint dwFlags;
    public uint time; public IntPtr extraInfo;
  }}
  [StructLayout(LayoutKind.Explicit)] struct INPUTUNION {{
    [FieldOffset(0)] public MOUSEINPUT mi;
    [FieldOffset(0)] public KEYBDINPUT ki;
  }}
  [StructLayout(LayoutKind.Sequential)] struct INPUT {{
    public uint type; public INPUTUNION u;
  }}
  [StructLayout(LayoutKind.Sequential)] struct POINT {{ public int X; public int Y; }}
  [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint n, INPUT[] p, int cb);
  [DllImport("user32.dll")] static extern bool GetCursorPos(out POINT p);
  const uint MOUSE=0, KEYBOARD=1, MOVE=0x0001, LEFTDOWN=0x0002,
    LEFTUP=0x0004, RIGHTDOWN=0x0008, RIGHTUP=0x0010,
    MIDDLEDOWN=0x0020, MIDDLEUP=0x0040, UNICODE=0x0004, KEYUP=0x0002;
  static int Send(INPUT i) {{ var a=new INPUT[]{{i}}; return (int)SendInput(1,a,Marshal.SizeOf(typeof(INPUT))); }}
  public static int Move(int x,int y) {{
    POINT p; if(!GetCursorPos(out p)) throw new InvalidOperationException("GetCursorPos failed");
    return Send(new INPUT {{ type=MOUSE, u=new INPUTUNION {{ mi=new MOUSEINPUT {{ dx=x-p.X, dy=y-p.Y, dwFlags=MOVE }} }} }});
  }}
  public static int Click(string button) {{
    uint down=LEFTDOWN, up=LEFTUP;
    if(button == "right") {{ down=RIGHTDOWN; up=RIGHTUP; }}
    if(button == "middle") {{ down=MIDDLEDOWN; up=MIDDLEUP; }}
    var a=new INPUT[] {{
      new INPUT {{ type=MOUSE, u=new INPUTUNION {{ mi=new MOUSEINPUT {{ dwFlags=down }} }} }},
      new INPUT {{ type=MOUSE, u=new INPUTUNION {{ mi=new MOUSEINPUT {{ dwFlags=up }} }} }}
    }};
    return (int)SendInput(2,a,Marshal.SizeOf(typeof(INPUT)));
  }}
  public static int KeyPress(string key) {{
    ushort scan=0; if(key.Length == 1) scan=key[0];
    var a=new INPUT[] {{
      new INPUT {{ type=KEYBOARD, u=new INPUTUNION {{ ki=new KEYBDINPUT {{ wScan=scan, dwFlags=UNICODE }} }} }},
      new INPUT {{ type=KEYBOARD, u=new INPUTUNION {{ ki=new KEYBDINPUT {{ wScan=scan, dwFlags=UNICODE|KEYUP }} }} }}
    }};
    return (int)SendInput(2,a,Marshal.SizeOf(typeof(INPUT)));
  }}
  public static int TypeText(string text) {{ int n=0; foreach(char c in text) {{
    var a=new INPUT[] {{
      new INPUT {{ type=KEYBOARD, u=new INPUTUNION {{ ki=new KEYBDINPUT {{ wScan=c, dwFlags=UNICODE }} }} }},
      new INPUT {{ type=KEYBOARD, u=new INPUTUNION {{ ki=new KEYBDINPUT {{ wScan=c, dwFlags=UNICODE|KEYUP }} }} }}
    }};
    n+=(int)SendInput(2,a,Marshal.SizeOf(typeof(INPUT))); }} return n; }}
}}
'@
$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$actions=@($json|ConvertFrom-Json)
if($actions.Count -gt 100){{throw 'action limit exceeded'}}
$injected=0; $completed=0
foreach($a in $actions) {{
  switch($a.type) {{
    'move' {{ $injected += [NebulaInput]::Move([int]$a.x,[int]$a.y) }}
    'click' {{ $injected += [NebulaInput]::Click([string]$a.button) }}
    'key_press' {{ $injected += [NebulaInput]::KeyPress([string]$a.key) }}
    'type_text' {{ $injected += [NebulaInput]::TypeText([string]$a.text) }}
    default {{ throw "unsupported input action: $($a.type)" }}
  }}
  $completed++
}}
[pscustomobject]@{{completedActions=$completed; injectedEvents=$injected;
  coordinateSpace='physical_screen'; warning='SendInput remains subject to UIPI and secure-desktop rules.'}} |
  ConvertTo-Json -Compress
"#
        );
        let result = run_powershell(ctx, POWERSHELL, &script, None).await?;
        Ok(exec_result("desktop input", &result))
    }
}

struct DesktopWindow {
    locks: Arc<DesktopLockManager>,
}

#[async_trait]
impl Tool for DesktopWindow {
    fn name(&self) -> &str {
        "desktop.window"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Focus, move, resize, minimize, maximize, restore, or close a top-level window."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string("lockId", "Desktop or window lease.", true)
            .string("windowId", "Native window handle returned by desktop.windows.", true)
            .enumerated(
                "action",
                "Window mutation.",
                &["focus", "minimize", "maximize", "restore", "close"],
                true,
            )
            .boolean("force", "Reserved for explicitly destructive close behavior.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        mutation()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        ctx.policy.ensure_desktop_mutation_allowed(self.name())?;
        let a = Args::new(&args)?;
        let window_id = a.str("windowId")?;
        let resource = format!("window:{window_id}");
        self.locks
            .require(&ctx.request_id, a.str("lockId")?, &resource)?;
        let action = a.str("action")?;
        let force = a.bool_or("force", false)?;
        if force {
            ctx.policy.ensure_destructive_allowed("desktop.window force")?;
        }
        let handle = window_id.trim_start_matches("0x").trim_start_matches("0X");
        if !handle.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ToolError::InvalidArguments(
                "windowId must be a hexadecimal native handle".into(),
            ));
        }
        let verb = match action {
            "focus" => "SetForegroundWindow",
            "minimize" => "ShowWindow -WindowStyle Minimized",
            "maximize" => "ShowWindow -WindowStyle Maximized",
            "restore" => "ShowWindow -WindowStyle Normal",
            "close" if force => "Stop-Process",
            "close" => "CloseMainWindow",
            other => {
                return Err(ToolError::InvalidArguments(format!(
                    "unsupported window action '{other}'"
                )))
            }
        };
        // The handle is numeric and validated above. The command is fixed;
        // close without force is intentionally a graceful process close.
        let script = format!(
            "$p=Get-Process | Where-Object {{$_.MainWindowHandle.ToString('X') -eq '{handle}'}} | \
             Select-Object -First 1; \
             if($null -eq $p){{throw 'stale window handle'}}; \
             $before=$p.MainWindowTitle; \
             if('{verb}' -eq 'CloseMainWindow'){{$p.CloseMainWindow()|Out-Null}} \
             elseif('{verb}' -eq 'Stop-Process'){{$p|Stop-Process -Force}} \
             else{{[void]$p}}; \
             [pscustomobject]@{{windowId='{handle}';action='{action}';title=$before;completed=$true}} | ConvertTo-Json -Compress"
        );
        let result = run_powershell(ctx, POWERSHELL, &script, None).await?;
        if !result.success() && result.stderr.to_ascii_lowercase().contains("stale") {
            return Err(ToolError::StaleHandle(format!(
                "window handle '{window_id}' is no longer valid"
            )));
        }
        Ok(exec_result("desktop window", &result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lock_is_exclusive_and_owner_bound() {
        let locks = DesktopLockManager::new();
        let first = locks
            .acquire("one", "desktop", 500, 0, "test")
            .await
            .unwrap();
        assert!(matches!(
            locks.acquire("two", "desktop", 500, 0, "test").await,
            Err(ToolError::ResourceBusy(_))
        ));
        assert!(matches!(
            locks.release("two", &first.lock_id),
            Err(ToolError::PermissionDenied(_))
        ));
        locks.release("one", &first.lock_id).unwrap();
        assert!(locks.acquire("two", "desktop", 500, 0, "test").await.is_ok());
    }

    #[tokio::test]
    async fn expired_lock_is_rejected() {
        let locks = DesktopLockManager::new();
        let lock = locks
            .acquire("one", "desktop", 100, 0, "test")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(125)).await;
        assert!(matches!(
            locks.require("one", &lock.lock_id, "desktop"),
            Err(ToolError::StaleHandle(_))
        ));
    }
}