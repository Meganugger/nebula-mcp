//! Windows administration tools: services, registry, event log, performance
//! counters, scheduled tasks, persistent environment variables, firewall
//! rules and network adapters.
//!
//! Each tool runs a constant PowerShell script (or `schtasks` with fixed
//! options). What the caller sends reaches the script as environment
//! variables and is used as data, never as script text. Operations that act
//! on the whole machine need the elevated gate, removals the destructive
//! one. Creating services is not offered: a service is a program run as
//! SYSTEM.

use std::sync::Arc;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::process::{Command, Exec, Output};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{
    Category, Effects, Gate, Platforms, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::Value;

use crate::common::{clip, handler, spec, tool, SpecExt};
use crate::powershell::{platform_shell, script, SHELLS, STOP_ON_ERROR};

const READ: Effects = Effects::read_only().exec(SHELLS);

/// The `windows` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Windows;
    let win = |t: nebula_mcp_core::ToolSpec| t.on(Platforms::WINDOWS);
    let changes = Effects::writes()
        .overwrites()
        .destructive(Gate::Sometimes)
        .elevated(Gate::Sometimes)
        .exec(SHELLS);
    vec![
        tool(
            win(spec(
                "windows_service",
                c,
                "Windows services",
                "Query, start, stop or restart a Windows service; without `name`, list all \
                 services. Starting, stopping and restarting are elevated; stopping and \
                 restarting are destructive too. Services cannot be created or reconfigured.",
                ObjectSchema::new()
                    .string("name", "Service name (not the display name).", false)
                    .string_enum(
                        "action",
                        "What to do (default query).",
                        &["query", "start", "stop", "restart"],
                        false,
                    )
                    .build(),
                changes,
            )),
            handler!(service),
        ),
        tool(
            win(spec(
                "windows_registry",
                c,
                "Windows registry",
                "Read a registry key or value, set a value, or delete a value or key. Setting \
                 and deleting outside HKEY_CURRENT_USER are elevated; deleting is destructive.",
                ObjectSchema::new()
                    .string_enum("action", "What to do.", &["query", "set", "delete"], true)
                    .string(
                        "key",
                        "Key path starting with a hive, for example HKCU\\Software\\App.",
                        true,
                    )
                    .string(
                        "value",
                        "Value name. Omit to read the whole key, or to delete the key.",
                        false,
                    )
                    .string_enum(
                        "type",
                        "Type for set (default REG_SZ).",
                        &[
                            "REG_SZ",
                            "REG_EXPAND_SZ",
                            "REG_DWORD",
                            "REG_QWORD",
                            "REG_MULTI_SZ",
                            "REG_BINARY",
                        ],
                        false,
                    )
                    .string(
                        "data",
                        "Data for set: text, a number, lines for REG_MULTI_SZ, hex for REG_BINARY.",
                        false,
                    )
                    .build(),
                changes,
            )),
            handler!(registry),
        ),
        tool(
            win(spec(
                "windows_event_log",
                c,
                "Windows event log",
                "The most recent entries of a Windows event log as JSON: time, id, level, \
                 provider and message.",
                ObjectSchema::new()
                    .string(
                        "logName",
                        "Log to read, for example Application or System.",
                        true,
                    )
                    .integer_range(
                        "maxEvents",
                        "Entries to return (default 20).",
                        1,
                        500,
                        false,
                    )
                    .string_enum(
                        "level",
                        "Only this level.",
                        &["Critical", "Error", "Warning", "Information"],
                        false,
                    )
                    .build(),
                READ,
            )),
            handler!(event_log),
        ),
        tool(
            win(spec(
                "windows_perf_counters",
                c,
                "Performance counters",
                "Sample Windows performance counters and return the values as JSON.",
                ObjectSchema::new()
                    .string_array_max(
                        "counters",
                        "Counter paths, for example \\Processor(_Total)\\% Processor Time.",
                        20,
                        true,
                    )
                    .integer_range("samples", "Samples to take (default 1).", 1, 30, false)
                    .integer_range(
                        "intervalSecs",
                        "Seconds between samples (default 1).",
                        1,
                        10,
                        false,
                    )
                    .build(),
                READ,
            )),
            handler!(perf_counters),
        ),
        tool(
            win(spec(
                "windows_scheduled_tasks",
                c,
                "Scheduled tasks",
                "Show scheduled tasks, or run or end one that already exists. Running and \
                 ending are elevated, because a task can run as SYSTEM; ending is destructive. \
                 Tasks cannot be created here.",
                ObjectSchema::new()
                    .string_enum(
                        "action",
                        "What to do (default query).",
                        &["query", "run", "end"],
                        false,
                    )
                    .string(
                        "taskName",
                        "Task path, for example \\Microsoft\\Windows\\Defrag\\ScheduledDefrag.",
                        false,
                    )
                    .build(),
                Effects::writes()
                    .destructive(Gate::Sometimes)
                    .elevated(Gate::Sometimes)
                    .exec(Exec::Programs(&["schtasks"])),
            )),
            handler!(scheduled_tasks),
        ),
        tool(
            win(spec(
                "windows_env",
                c,
                "Persistent environment",
                "Read, set or delete a persistent environment variable of the user or the \
                 machine. Machine scope is elevated; deleting is destructive. Running programs \
                 do not see a change until they restart.",
                ObjectSchema::new()
                    .string_enum("action", "What to do.", &["get", "set", "delete"], true)
                    .string("name", "Variable name.", true)
                    .string_enum(
                        "scope",
                        "Whose variable (default User).",
                        &["User", "Machine"],
                        false,
                    )
                    .string("value", "New value, for set.", false)
                    .build(),
                changes,
            )),
            handler!(env),
        ),
        tool(
            win(spec(
                "windows_firewall",
                c,
                "Firewall rules",
                "Windows Firewall rules as JSON: name, enabled, direction, action and profile.",
                ObjectSchema::new()
                    .string(
                        "nameContains",
                        "Only rules whose display name contains this text.",
                        false,
                    )
                    .integer_range("limit", "Rules to return (default 50).", 1, 500, false)
                    .build(),
                READ,
            )),
            handler!(firewall),
        ),
        tool(
            win(spec(
                "windows_network_adapters",
                c,
                "Network adapters",
                "Network adapters as JSON: name, description, status, MAC address and link speed.",
                ObjectSchema::new().build(),
                READ,
            )),
            handler!(network_adapters),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// Text used as a name: no wildcards, since the cmdlets would expand them.
fn plain(value: &str, what: &str, max: usize) -> Result<String> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|c| c.is_control() || "*?[]`".contains(c))
    {
        return Err(ToolError::invalid(format!(
            "`{what}` must be a plain name without wildcards (* ? [ ]) or control characters"
        )));
    }
    Ok(value.to_string())
}

/// A registry key: (canonical path, whether it is in the user's own hive).
fn registry_key(key: &str) -> Result<(String, bool)> {
    let key = plain(key, "key", 1000)?;
    let (hive, rest) = key.split_once('\\').unwrap_or((key.as_str(), ""));
    let hive = match hive.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => "HKEY_CURRENT_USER",
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKEY_LOCAL_MACHINE",
        "HKCR" | "HKEY_CLASSES_ROOT" => "HKEY_CLASSES_ROOT",
        "HKU" | "HKEY_USERS" => "HKEY_USERS",
        "HKCC" | "HKEY_CURRENT_CONFIG" => "HKEY_CURRENT_CONFIG",
        _ => {
            return Err(ToolError::invalid(
                "`key` must start with a hive: HKCU, HKLM, HKCR, HKU or HKCC",
            ))
        }
    };
    if rest.split('\\').any(|part| part == ".." || part == ".") || rest.contains('/') {
        return Err(ToolError::invalid(
            "`key` must be a registry path with backslashes and no '..'",
        ));
    }
    let path = if rest.is_empty() {
        hive.to_string()
    } else {
        format!("{hive}\\{rest}")
    };
    Ok((path, hive == "HKEY_CURRENT_USER"))
}

fn registry_type(name: &str) -> &'static str {
    match name {
        "REG_EXPAND_SZ" => "ExpandString",
        "REG_DWORD" => "DWord",
        "REG_QWORD" => "QWord",
        "REG_MULTI_SZ" => "MultiString",
        "REG_BINARY" => "Binary",
        _ => "String",
    }
}

fn variable_name(name: &str) -> Result<String> {
    let mut chars = name.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.len() <= 255
        && chars.all(|c| c.is_ascii_alphanumeric() || "_()".contains(c));
    if ok {
        Ok(name.to_string())
    } else {
        Err(ToolError::invalid(
            "`name` must be an environment variable name: letters, digits and '_'",
        ))
    }
}

/// A scheduled-task path. It may not start with '/', where schtasks reads
/// options.
fn task_name(name: &str) -> Result<String> {
    let name = plain(name, "taskName", 500)?;
    if name.starts_with('/') || name.starts_with('-') || name.contains('"') {
        return Err(ToolError::invalid(
            "`taskName` must be a task path such as \\Folder\\Task",
        ));
    }
    Ok(name)
}

/// A fixed script with its values in the environment.
pub(crate) fn typed(body: &str, values: &[(&str, &str)]) -> Command {
    let mut cmd = script(platform_shell(), &format!("{STOP_ON_ERROR}{body}"));
    for (name, value) in values {
        cmd = cmd.env(*name, *value);
    }
    cmd
}

pub(crate) fn failure(what: &str, out: &Output) -> ToolError {
    let detail = if out.stderr.text.trim().is_empty() {
        out.stdout.text.trim()
    } else {
        out.stderr.text.trim()
    };
    ToolError::Execution(format!("{what} failed: {}", clip(detail, 2000)))
}

/// Run and return what the script printed.
pub(crate) async fn answer(ctx: &ToolContext, what: &str, cmd: Command) -> Result<ToolOutput> {
    let out = ctx.run(cmd.timeout(ctx.timeout(None))).await?;
    if !out.success() {
        return Err(failure(what, &out));
    }
    let text = out.stdout.text.trim();
    Ok(ToolOutput::text(if text.is_empty() { "[]" } else { text }))
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const SERVICE_FIELDS: &str = "Select-Object Name,DisplayName,\
     @{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$_.StartType.ToString()}} | \
     ConvertTo-Json -Depth 3";

async fn service(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a
        .opt_enum("action", &["query", "start", "stop", "restart"])?
        .unwrap_or("query");
    let Some(name) = a.opt_str("name")? else {
        if action != "query" {
            return Err(ToolError::invalid(format!(
                "`name` is required to {action} a service"
            )));
        }
        return answer(
            ctx,
            "listing services",
            typed(&format!("Get-Service | {SERVICE_FIELDS}"), &[]),
        )
        .await;
    };
    let name = plain(name, "name", 256)?;
    let verb = match action {
        "start" => "Start-Service -Name $env:NB_NAME;",
        "stop" => "Stop-Service -Name $env:NB_NAME -Force;",
        "restart" => "Restart-Service -Name $env:NB_NAME -Force;",
        _ => "",
    };
    if !verb.is_empty() {
        ctx.require_elevated("controlling a Windows service")?;
    }
    if matches!(action, "stop" | "restart") {
        ctx.require_destructive("stopping a Windows service")?;
    }
    let body = format!("{verb}Get-Service -Name $env:NB_NAME | {SERVICE_FIELDS}");
    answer(
        ctx,
        "the service request",
        typed(&body, &[("NB_NAME", &name)]),
    )
    .await
}

const REGISTRY_QUERY: &str = "$p = 'Registry::' + $env:NB_KEY;\
     if ($env:NB_VALUE) {\
       $item = Get-Item -LiteralPath $p;\
       if ($item.GetValueNames() -notcontains $env:NB_VALUE) { throw \"the key has no value named $($env:NB_VALUE)\" }\
       [pscustomobject]@{ key=$env:NB_KEY; value=$env:NB_VALUE; type=$item.GetValueKind($env:NB_VALUE).ToString(); data=$item.GetValue($env:NB_VALUE) } | ConvertTo-Json -Depth 4\
     } else {\
       $item = Get-Item -LiteralPath $p; $values = [ordered]@{};\
       foreach ($n in $item.GetValueNames()) { $values[$n] = $item.GetValue($n) }\
       [pscustomobject]@{ key=$env:NB_KEY; subkeys=@($item.GetSubKeyNames()); values=$values } | ConvertTo-Json -Depth 4\
     }";

const REGISTRY_SET: &str = "$p = 'Registry::' + $env:NB_KEY;\
     if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force | Out-Null }\
     $d = $env:NB_DATA; if ($null -eq $d) { $d = '' }\
     switch ($env:NB_TYPE) {\
       'DWord' { $d = [uint32]$d }\
       'QWord' { $d = [uint64]$d }\
       'MultiString' { $d = [string[]]@($d -split \"`n\") }\
       'Binary' { $h = $d -replace '[^0-9A-Fa-f]',''; $d = [byte[]]@(for ($i = 0; $i + 1 -lt $h.Length; $i += 2) { [Convert]::ToByte($h.Substring($i, 2), 16) }) }\
     }\
     New-ItemProperty -LiteralPath $p -Name $env:NB_VALUE -Value $d -PropertyType $env:NB_TYPE -Force | Out-Null;\
     'set'";

const REGISTRY_DELETE: &str = "$p = 'Registry::' + $env:NB_KEY;\
     if ($env:NB_VALUE) { Remove-ItemProperty -LiteralPath $p -Name $env:NB_VALUE } \
     else { Remove-Item -LiteralPath $p -Recurse }\
     'deleted'";

async fn registry(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a.str("action")?;
    let (key, own_hive) = registry_key(a.str("key")?)?;
    let value = match a.opt_str("value")? {
        Some(v) => plain(v, "value", 500)?,
        None => String::new(),
    };
    let mut values = vec![("NB_KEY", key.as_str()), ("NB_VALUE", value.as_str())];
    let body = match action {
        "query" => REGISTRY_QUERY,
        "set" => {
            if value.is_empty() {
                return Err(ToolError::invalid("`value` is required for set"));
            }
            if !own_hive {
                ctx.require_elevated("writing the registry outside HKEY_CURRENT_USER")?;
            }
            values.push(("NB_TYPE", registry_type(a.str_or("type", "REG_SZ")?)));
            values.push(("NB_DATA", a.str_or("data", "")?));
            REGISTRY_SET
        }
        "delete" => {
            ctx.require_destructive("deleting from the registry")?;
            if !own_hive {
                ctx.require_elevated("writing the registry outside HKEY_CURRENT_USER")?;
            }
            if key.split('\\').count() < 3 && value.is_empty() {
                return Err(ToolError::invalid(
                    "refusing to delete a hive or a top-level key; name a deeper key or a value",
                ));
            }
            REGISTRY_DELETE
        }
        other => return Err(ToolError::invalid(format!("unknown action '{other}'"))),
    };
    answer(ctx, "the registry request", typed(body, &values)).await
}

async fn event_log(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const BODY: &str = "$f = @{ LogName = $env:NB_LOG };\
         if ($env:NB_LEVEL) { $f['Level'] = [int]$env:NB_LEVEL }\
         try {\
           @(Get-WinEvent -FilterHashtable $f -MaxEvents ([int]$env:NB_MAX) | Select-Object \
             @{n='time';e={$_.TimeCreated.ToString('o')}}, @{n='id';e={$_.Id}}, \
             @{n='level';e={$_.LevelDisplayName}}, @{n='provider';e={$_.ProviderName}}, \
             @{n='message';e={$_.Message}}) | ConvertTo-Json -Depth 3\
         } catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]' } else { throw } }";
    let a = Args::new(&args)?;
    let log = plain(a.str("logName")?, "logName", 256)?;
    let max = a.u64_or("maxEvents", 20)?.clamp(1, 500).to_string();
    let level = match a.opt_enum("level", &["Critical", "Error", "Warning", "Information"])? {
        Some("Critical") => "1",
        Some("Error") => "2",
        Some("Warning") => "3",
        Some(_) => "4",
        None => "",
    };
    let values = [
        ("NB_LOG", log.as_str()),
        ("NB_MAX", max.as_str()),
        ("NB_LEVEL", level),
    ];
    answer(ctx, "reading the event log", typed(BODY, &values)).await
}

async fn perf_counters(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const BODY: &str = "$c = $env:NB_COUNTERS -split \"`n\";\
         @(Get-Counter -Counter $c -MaxSamples ([int]$env:NB_SAMPLES) -SampleInterval ([int]$env:NB_INTERVAL) | \
           ForEach-Object { $t = $_.Timestamp.ToString('o'); $_.CounterSamples | \
           ForEach-Object { [pscustomobject]@{ time=$t; path=$_.Path; value=$_.CookedValue } } }) | \
         ConvertTo-Json -Depth 3";
    let a = Args::new(&args)?;
    let counters = a.str_array("counters")?;
    if counters.is_empty()
        || counters
            .iter()
            .any(|c| !c.starts_with('\\') || c.len() > 300 || c.chars().any(char::is_control))
    {
        return Err(ToolError::invalid(
            "`counters` must be counter paths starting with '\\', for example \
             \\Memory\\Available MBytes",
        ));
    }
    let samples = a.u64_or("samples", 1)?.clamp(1, 30);
    let interval = a.u64_or("intervalSecs", 1)?.clamp(1, 10);
    let (joined, samples_text, interval_text) = (
        counters.join("\n"),
        samples.to_string(),
        interval.to_string(),
    );
    let cmd = typed(
        BODY,
        &[
            ("NB_COUNTERS", joined.as_str()),
            ("NB_SAMPLES", samples_text.as_str()),
            ("NB_INTERVAL", interval_text.as_str()),
        ],
    )
    .timeout(ctx.timeout(Some(samples * interval + 30)));
    let out = ctx.run(cmd).await?;
    if !out.success() {
        return Err(failure("sampling the counters", &out));
    }
    Ok(ToolOutput::text(out.stdout.text.trim().to_string()))
}

async fn scheduled_tasks(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a
        .opt_enum("action", &["query", "run", "end"])?
        .unwrap_or("query");
    let name = match a.opt_str("taskName")? {
        Some(name) => Some(task_name(name)?),
        None => None,
    };
    let mut cmd = Command::typed("schtasks");
    match (action, &name) {
        ("query", None) => cmd = cmd.args(["/query", "/fo", "CSV", "/nh"]),
        ("query", Some(name)) => {
            cmd = cmd.args(["/query", "/fo", "LIST", "/v", "/tn", name.as_str()])
        }
        (_, None) => {
            return Err(ToolError::invalid(format!(
                "`taskName` is required to {action} a task"
            )))
        }
        (verb, Some(name)) => {
            ctx.require_elevated("starting or ending a scheduled task")?;
            if verb == "end" {
                ctx.require_destructive("ending a running task")?;
            }
            cmd = cmd.arg(format!("/{verb}")).args(["/tn", name.as_str()]);
        }
    }
    let out = ctx.run(cmd.timeout(ctx.timeout(None))).await?;
    if !out.success() {
        return Err(failure("schtasks", &out));
    }
    Ok(ToolOutput::text(out.stdout.text.trim().to_string()))
}

async fn env(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const GET: &str = "$v = [Environment]::GetEnvironmentVariable($env:NB_NAME, $env:NB_SCOPE);\
         [pscustomobject]@{ name=$env:NB_NAME; scope=$env:NB_SCOPE; value=$v } | ConvertTo-Json";
    const SET: &str =
        "[Environment]::SetEnvironmentVariable($env:NB_NAME, $env:NB_DATA, $env:NB_SCOPE); 'set'";
    const DELETE: &str =
        "[Environment]::SetEnvironmentVariable($env:NB_NAME, $null, $env:NB_SCOPE); 'deleted'";
    let a = Args::new(&args)?;
    let action = a.str("action")?;
    let name = variable_name(a.str("name")?)?;
    let scope = a.opt_enum("scope", &["User", "Machine"])?.unwrap_or("User");
    let value = a.str_or("value", "")?;
    let body = match action {
        "get" => GET,
        "set" => {
            if value.is_empty() {
                return Err(ToolError::invalid(
                    "`value` must not be empty; use action delete to remove a variable",
                ));
            }
            SET
        }
        "delete" => {
            ctx.require_destructive("deleting an environment variable")?;
            DELETE
        }
        other => return Err(ToolError::invalid(format!("unknown action '{other}'"))),
    };
    if action != "get" && scope == "Machine" {
        ctx.require_elevated("changing a machine-wide environment variable")?;
    }
    let values = [
        ("NB_NAME", name.as_str()),
        ("NB_SCOPE", scope),
        ("NB_DATA", value),
    ];
    answer(ctx, "the environment request", typed(body, &values)).await
}

async fn firewall(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const BODY: &str = "$r = Get-NetFirewallRule;\
         if ($env:NB_FILTER) { $r = $r | Where-Object { $_.DisplayName -like ('*' + [WildcardPattern]::Escape($env:NB_FILTER) + '*') } }\
         @($r | Select-Object -First ([int]$env:NB_MAX) @{n='name';e={$_.DisplayName}}, \
           @{n='enabled';e={$_.Enabled.ToString()}}, @{n='direction';e={$_.Direction.ToString()}}, \
           @{n='action';e={$_.Action.ToString()}}, @{n='profile';e={$_.Profile.ToString()}}) | \
         ConvertTo-Json -Depth 3";
    let a = Args::new(&args)?;
    let filter = a.str_or("nameContains", "")?;
    if filter.chars().any(char::is_control) || filter.len() > 200 {
        return Err(ToolError::invalid(
            "`nameContains` must be short plain text",
        ));
    }
    let max = a.u64_or("limit", 50)?.clamp(1, 500).to_string();
    let values = [("NB_FILTER", filter), ("NB_MAX", max.as_str())];
    answer(ctx, "reading the firewall rules", typed(BODY, &values)).await
}

async fn network_adapters(ctx: &ToolContext, _: Value) -> Result<ToolOutput> {
    const BODY: &str = "@(Get-NetAdapter | Select-Object Name,InterfaceDescription,\
         @{n='Status';e={$_.Status.ToString()}},MacAddress,LinkSpeed) | ConvertTo-Json -Depth 3";
    answer(ctx, "reading the network adapters", typed(BODY, &[])).await
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
