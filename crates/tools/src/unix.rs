//! Unix (Linux/macOS) subsystem tools mirroring the Windows category:
//! service managers (systemd/launchd), package managers, system logs, cron
//! and kernel parameters. Implemented as typed wrappers over `systemctl`,
//! `launchctl`, `journalctl`, `crontab`, `sysctl` and the native package
//! manager CLIs — every underlying binary must be on the command allowlist,
//! and the destructive/elevated gates apply exactly as for the Windows tools.

use std::sync::Arc;

use async_trait::async_trait;
use nebula_mcp_core::{Result, Tool, ToolContext, ToolError};
use nebula_mcp_protocol::mcp::ToolAnnotations;
use nebula_mcp_protocol::CallToolResult;
use serde_json::Value;

use crate::common::exec::{program_available, run_checked, CommandSpec};
use crate::common::output::exec_result;
use crate::common::platform::ensure_unix;
use crate::common::{Args, ObjectSchema};

const CATEGORY: &str = "unix";

/// Build Unix subsystem tools.
pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(UnixService),
        Arc::new(UnixPackage),
        Arc::new(UnixLogs),
        Arc::new(UnixCron),
        Arc::new(UnixSysctl),
    ]
}

fn ro() -> Option<ToolAnnotations> {
    Some(ToolAnnotations {
        read_only_hint: Some(true),
        ..Default::default()
    })
}

async fn run_cmd(
    ctx: &ToolContext,
    program: &str,
    args: Vec<String>,
    label: &str,
    timeout: Option<u64>,
) -> Result<CallToolResult> {
    let spec = CommandSpec::new(program, ctx.working_dir.clone(), ctx).args(args);
    let result = run_checked(ctx, spec, timeout).await?;
    Ok(exec_result(label, &result))
}

/// Service control via systemd (Linux) or launchd (macOS).
struct UnixService;

#[async_trait]
impl Tool for UnixService {
    fn name(&self) -> &str {
        "unix.service"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Query or control a service via systemctl (Linux) or launchctl (macOS): \
         status/list/start/stop/restart/enable/disable. stop/restart are destructive; \
         enable/disable require elevation. Set user=true for the per-user manager. \
         The systemctl/launchctl binary must be allowlisted. Unix only."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .enumerated(
                "action",
                "Action.",
                &[
                    "status", "list", "start", "stop", "restart", "enable", "disable",
                ],
                false,
            )
            .string(
                "name",
                "Service/unit name (required except for list).",
                false,
            )
            .boolean(
                "user",
                "Target the per-user service manager (systemctl --user).",
                false,
            )
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        ro()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_unix(self.name())?;
        let a = Args::new(&args)?;
        let action = a.str_or("action", "status")?;
        let user = a.bool_or("user", false)?;
        let name = a.opt_str("name")?.map(str::to_string);
        let require_name = || -> Result<String> {
            name.clone().ok_or_else(|| {
                ToolError::InvalidArguments(format!("action '{action}' requires 'name'"))
            })
        };

        // Prefer systemd; fall back to launchd on macOS.
        if program_available("systemctl") {
            let mut v: Vec<String> = Vec::new();
            if user {
                v.push("--user".into());
            }
            match action {
                "status" => {
                    v.extend(["status".into(), require_name()?, "--no-pager".into()]);
                }
                "list" => {
                    v.extend([
                        "list-units".into(),
                        "--type=service".into(),
                        "--no-pager".into(),
                        "--plain".into(),
                    ]);
                }
                "start" => v.extend(["start".into(), require_name()?]),
                "stop" => {
                    ctx.policy.ensure_destructive_allowed("unix.service stop")?;
                    v.extend(["stop".into(), require_name()?]);
                }
                "restart" => {
                    ctx.policy
                        .ensure_destructive_allowed("unix.service restart")?;
                    v.extend(["restart".into(), require_name()?]);
                }
                "enable" => {
                    ctx.policy.ensure_elevation_allowed()?;
                    v.extend(["enable".into(), require_name()?]);
                }
                "disable" => {
                    ctx.policy.ensure_elevation_allowed()?;
                    v.extend(["disable".into(), require_name()?]);
                }
                other => {
                    return Err(ToolError::InvalidArguments(format!(
                        "unknown action '{other}'"
                    )))
                }
            }
            return run_cmd(ctx, "systemctl", v, "systemctl", None).await;
        }
        if program_available("launchctl") {
            let v: Vec<String> = match action {
                "status" => vec!["list".into(), require_name()?],
                "list" => vec!["list".into()],
                "start" => vec!["start".into(), require_name()?],
                "stop" => {
                    ctx.policy.ensure_destructive_allowed("unix.service stop")?;
                    vec!["stop".into(), require_name()?]
                }
                "restart" => {
                    ctx.policy
                        .ensure_destructive_allowed("unix.service restart")?;
                    vec!["kickstart".into(), "-k".into(), require_name()?]
                }
                "enable" => {
                    ctx.policy.ensure_elevation_allowed()?;
                    vec!["enable".into(), require_name()?]
                }
                "disable" => {
                    ctx.policy.ensure_elevation_allowed()?;
                    vec!["disable".into(), require_name()?]
                }
                other => {
                    return Err(ToolError::InvalidArguments(format!(
                        "unknown action '{other}'"
                    )))
                }
            };
            return run_cmd(ctx, "launchctl", v, "launchctl", None).await;
        }
        Err(ToolError::ToolNotFound(
            "systemctl or launchctl".to_string(),
        ))
    }
}

/// Supported package managers, in detection order.
const PACKAGE_MANAGERS: &[&str] = &["apt", "dnf", "yum", "pacman", "zypper", "apk", "brew"];

/// Build the argv for a (manager, action) pair. Read-only actions only need
/// the manager binary allowlisted; install/remove are additionally gated.
fn package_args(manager: &str, action: &str, package: Option<&str>) -> Result<Vec<String>> {
    let need = |p: Option<&str>| -> Result<String> {
        p.map(str::to_string).ok_or_else(|| {
            ToolError::InvalidArguments(format!("action '{action}' requires 'package'"))
        })
    };
    let v: Vec<String> = match (manager, action) {
        ("apt", "list") => vec!["list".into(), "--installed".into()],
        ("apt", "info") => vec!["show".into(), need(package)?],
        ("apt", "search") => vec!["search".into(), need(package)?],
        ("apt", "install") => vec!["install".into(), "-y".into(), need(package)?],
        ("apt", "remove") => vec!["remove".into(), "-y".into(), need(package)?],
        ("dnf" | "yum", "list") => vec!["list".into(), "installed".into()],
        ("dnf" | "yum", "info") => vec!["info".into(), need(package)?],
        ("dnf" | "yum", "search") => vec!["search".into(), need(package)?],
        ("dnf" | "yum", "install") => vec!["install".into(), "-y".into(), need(package)?],
        ("dnf" | "yum", "remove") => vec!["remove".into(), "-y".into(), need(package)?],
        ("pacman", "list") => vec!["-Q".into()],
        ("pacman", "info") => vec!["-Si".into(), need(package)?],
        ("pacman", "search") => vec!["-Ss".into(), need(package)?],
        ("pacman", "install") => vec!["-S".into(), "--noconfirm".into(), need(package)?],
        ("pacman", "remove") => vec!["-R".into(), "--noconfirm".into(), need(package)?],
        ("zypper", "list") => vec!["packages".into(), "--installed-only".into()],
        ("zypper", "info") => vec!["info".into(), need(package)?],
        ("zypper", "search") => vec!["search".into(), need(package)?],
        ("zypper", "install") => vec!["install".into(), "-y".into(), need(package)?],
        ("zypper", "remove") => vec!["remove".into(), "-y".into(), need(package)?],
        ("apk", "list") => vec!["list".into(), "--installed".into()],
        ("apk", "info") => vec!["info".into(), need(package)?],
        ("apk", "search") => vec!["search".into(), need(package)?],
        ("apk", "install") => vec!["add".into(), need(package)?],
        ("apk", "remove") => vec!["del".into(), need(package)?],
        ("brew", "list") => vec!["list".into(), "--versions".into()],
        ("brew", "info") => vec!["info".into(), need(package)?],
        ("brew", "search") => vec!["search".into(), need(package)?],
        ("brew", "install") => vec!["install".into(), need(package)?],
        ("brew", "remove") => vec!["uninstall".into(), need(package)?],
        (m, a) => {
            return Err(ToolError::InvalidArguments(format!(
                "unsupported manager/action combination '{m}'/'{a}'"
            )))
        }
    };
    Ok(v)
}

/// Package manager operations (apt/dnf/yum/pacman/zypper/apk/brew).
struct UnixPackage;

#[async_trait]
impl Tool for UnixPackage {
    fn name(&self) -> &str {
        "unix.package"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Query or manage packages via the system package manager \
         (apt/dnf/yum/pacman/zypper/apk/brew, auto-detected or explicit): \
         list/info/search are read-only; install requires elevation; remove requires \
         elevation and the destructive gate. The manager binary must be allowlisted. Unix only."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .enumerated(
                "action",
                "Action.",
                &["list", "info", "search", "install", "remove"],
                true,
            )
            .string("package", "Package name (required except for list).", false)
            .enumerated(
                "manager",
                "Package manager (default: first available).",
                PACKAGE_MANAGERS,
                false,
            )
            .integer("timeoutSecs", "Timeout in seconds.", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        ro()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_unix(self.name())?;
        let a = Args::new(&args)?;
        let action = a.str("action")?;
        let package = a.opt_str("package")?;
        let timeout = a.opt_u64("timeoutSecs")?;
        let manager = match a.opt_str("manager")? {
            Some(m) => m.to_string(),
            None => PACKAGE_MANAGERS
                .iter()
                .find(|m| program_available(m))
                .map(|m| m.to_string())
                .ok_or_else(|| ToolError::ToolNotFound("a supported package manager".into()))?,
        };
        match action {
            "install" => ctx.policy.ensure_elevation_allowed()?,
            "remove" => {
                ctx.policy.ensure_elevation_allowed()?;
                ctx.policy
                    .ensure_destructive_allowed("unix.package remove")?;
            }
            _ => {}
        }
        let argv = package_args(&manager, action, package)?;
        let label = format!("{manager} {action}");
        run_cmd(ctx, &manager, argv, &label, timeout).await
    }
}

/// System log query via journalctl (Linux) or `log show` (macOS).
struct UnixLogs;

#[async_trait]
impl Tool for UnixLogs {
    fn name(&self) -> &str {
        "unix.logs"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Query system logs via journalctl (Linux, JSON output) or `log show` (macOS): \
         recent entries, optionally filtered by unit/priority. The journalctl/log binary \
         must be allowlisted. Unix only."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .integer("maxEntries", "Maximum entries (default 50).", false)
            .string("unit", "Optional systemd unit filter (Linux).", false)
            .enumerated(
                "priority",
                "Minimum priority (Linux journalctl).",
                &[
                    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
                ],
                false,
            )
            .string(
                "since",
                "Only entries since this time (e.g. '1 hour ago', '2026-01-01').",
                false,
            )
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        ro()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_unix(self.name())?;
        let a = Args::new(&args)?;
        let max = a.u64_or("maxEntries", 50)?;
        if program_available("journalctl") {
            let mut v: Vec<String> = vec![
                "--no-pager".into(),
                "--output=json".into(),
                "-n".into(),
                max.to_string(),
            ];
            if let Some(unit) = a.opt_str("unit")? {
                v.push("-u".into());
                v.push(unit.into());
            }
            if let Some(p) = a.opt_str("priority")? {
                v.push("-p".into());
                v.push(p.into());
            }
            if let Some(s) = a.opt_str("since")? {
                v.push("--since".into());
                v.push(s.into());
            }
            return run_cmd(ctx, "journalctl", v, "journalctl", None).await;
        }
        if program_available("log") {
            let mut v: Vec<String> = vec![
                "show".into(),
                "--style".into(),
                "json".into(),
                "--last".into(),
            ];
            v.push(a.opt_str("since")?.unwrap_or("10m").to_string());
            return run_cmd(ctx, "log", v, "log show", None).await;
        }
        Err(ToolError::ToolNotFound("journalctl or log".to_string()))
    }
}

/// Crontab inspection via `crontab -l`.
struct UnixCron;

#[async_trait]
impl Tool for UnixCron {
    fn name(&self) -> &str {
        "unix.cron"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "List the current (or a named) user's crontab entries via `crontab -l`. \
         Listing another user's crontab requires elevation. The crontab binary must be \
         allowlisted. Unix only."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string(
                "user",
                "User whose crontab to list (default: current).",
                false,
            )
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        ro()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_unix(self.name())?;
        let a = Args::new(&args)?;
        let mut v: Vec<String> = vec!["-l".into()];
        if let Some(user) = a.opt_str("user")? {
            ctx.policy.ensure_elevation_allowed()?;
            v.push("-u".into());
            v.push(user.into());
        }
        run_cmd(ctx, "crontab", v, "crontab -l", None).await
    }
}

/// Kernel parameter access via sysctl.
struct UnixSysctl;

#[async_trait]
impl Tool for UnixSysctl {
    fn name(&self) -> &str {
        "unix.sysctl"
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        "Get or set kernel parameters via sysctl: get one key, list keys by prefix, or set \
         a value (set requires elevation). The sysctl binary must be allowlisted. Unix only."
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .enumerated("action", "Action.", &["get", "list", "set"], true)
            .string("key", "Parameter name (e.g. net.core.somaxconn).", false)
            .string("value", "Value to set (for set).", false)
            .string("prefix", "Prefix filter for list (e.g. net.ipv4).", false)
            .build()
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_unix(self.name())?;
        let a = Args::new(&args)?;
        match a.str("action")? {
            "get" => {
                let key = a.str("key")?;
                run_cmd(
                    ctx,
                    "sysctl",
                    vec!["-n".into(), key.into()],
                    "sysctl -n",
                    None,
                )
                .await
            }
            "list" => {
                let mut v: Vec<String> = vec!["-a".into()];
                if let Some(prefix) = a.opt_str("prefix")? {
                    // `sysctl -a --pattern` is GNU-only; filter portably by
                    // querying the prefix subtree instead.
                    v = vec![prefix.into()];
                }
                run_cmd(ctx, "sysctl", v, "sysctl list", None).await
            }
            "set" => {
                ctx.policy.ensure_elevation_allowed()?;
                let key = a.str("key")?;
                let value = a.str("value")?;
                run_cmd(
                    ctx,
                    "sysctl",
                    vec!["-w".into(), format!("{key}={value}")],
                    "sysctl -w",
                    None,
                )
                .await
            }
            other => Err(ToolError::InvalidArguments(format!(
                "unknown action '{other}'"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebula_mcp_core::config::SecurityConfig;
    use nebula_mcp_core::security::EffectivePolicy;
    use nebula_mcp_core::Metrics;
    use serde_json::json;
    use tokio_util::sync::CancellationToken;

    fn ctx_with(base: SecurityConfig) -> ToolContext {
        let policy = EffectivePolicy::build("unix.test", &base, None).unwrap();
        ToolContext {
            policy: Arc::new(policy),
            working_dir: std::env::temp_dir(),
            cancel: CancellationToken::new(),
            metrics: Metrics::new(),
            config: Arc::new(Default::default()),
            request_id: "r".into(),
            progress: None,
        }
    }

    fn ctx() -> ToolContext {
        ctx_with(SecurityConfig {
            allowed_commands: vec![
                "systemctl".into(),
                "launchctl".into(),
                "journalctl".into(),
                "log".into(),
                "crontab".into(),
                "sysctl".into(),
            ],
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn unix_tools_gate_off_unix() {
        if cfg!(unix) {
            return;
        }
        for res in [
            UnixService.call(&ctx(), json!({"action": "list"})).await,
            UnixCron.call(&ctx(), json!({})).await,
            UnixSysctl
                .call(&ctx(), json!({"action": "get", "key": "kernel.ostype"}))
                .await,
        ] {
            assert!(matches!(
                res.unwrap_err(),
                ToolError::PlatformUnsupported(_)
            ));
        }
    }

    #[tokio::test]
    async fn service_stop_requires_destructive_gate() {
        if !cfg!(unix) {
            return;
        }
        let err = UnixService
            .call(&ctx(), json!({"action": "stop", "name": "whatever"}))
            .await
            .unwrap_err();
        // The gate check fires before any command resolution/execution
        // (default policy denies destructive), unless neither service manager
        // exists at all — then the not-found error is also acceptable.
        assert!(
            matches!(
                err,
                ToolError::PermissionDenied(_) | ToolError::ToolNotFound(_)
            ),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn package_remove_requires_gates() {
        if !cfg!(unix) {
            return;
        }
        let err = UnixPackage
            .call(&ctx(), json!({"action": "remove", "package": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn sysctl_set_requires_elevation() {
        if !cfg!(unix) {
            return;
        }
        let err = UnixSysctl
            .call(
                &ctx(),
                json!({"action": "set", "key": "kernel.x", "value": "1"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn sysctl_get_runs_when_binary_exists() {
        if !cfg!(unix) || !program_available("sysctl") {
            return;
        }
        let key = if cfg!(target_os = "macos") {
            "kern.ostype"
        } else {
            "kernel.ostype"
        };
        let res = UnixSysctl
            .call(&ctx(), json!({"action": "get", "key": key}))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn unlisted_binary_is_denied() {
        if !cfg!(unix) {
            return;
        }
        let ctx = ctx_with(SecurityConfig::default());
        let err = UnixCron.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::CommandNotAllowed(_)));
    }

    #[test]
    fn package_args_cover_all_managers() {
        for m in PACKAGE_MANAGERS {
            for action in ["list", "info", "search", "install", "remove"] {
                let pkg = if action == "list" { None } else { Some("jq") };
                let v = package_args(m, action, pkg).unwrap();
                assert!(!v.is_empty(), "{m}/{action}");
            }
        }
        // Missing package name errors clearly.
        assert!(matches!(
            package_args("apt", "info", None),
            Err(ToolError::InvalidArguments(_))
        ));
    }
}
