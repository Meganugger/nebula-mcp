//! Diagnostics: what the server can do here, how it has been doing, its
//! configuration, and on Windows the crash-analysis tools.
//!
//! The debugger tools take no debugger commands from the caller: `cdb` runs
//! one of a fixed set of analyses. Dumps and live stacks are limited to
//! processes inside the caller's own terminal sessions, because a memory
//! dump of an arbitrary process is a copy of its secrets.

use std::sync::Arc;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::Kind;
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec, CONFINEMENT_AVAILABLE};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{
    Category, Effects, Gate, Platforms, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::{json, Map, Value};

use crate::common::{handler, rfc3339, spec, tool, SpecExt};
use crate::powershell::SHELLS;
use crate::process::in_my_sessions;
use crate::sessions::Sessions;
use crate::terminal::render_run;
use crate::windows::{answer, failure, typed};

/// Programs the tools of this server run, for the capability report.
const PROGRAMS: &[&str] = &[
    "git", "docker", "node", "pwsh", "powershell", "curl", "ping", "iperf3", "tcpdump",
    "schtasks", "cdb", "procdump", "logman",
];

/// The analyses `diagnostics_analyze_dump` offers, and the debugger commands
/// behind them.
const ANALYSES: &[(&str, &str)] = &[
    ("analyze", "!analyze -v"),
    ("stacks", "~*k"),
    ("modules", "lm"),
    ("threads", "~"),
];

/// The `diagnostics` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools(sessions: &Arc<Sessions>) -> Vec<Arc<dyn Tool>> {
    let c = Category::Diagnostics;
    let win = |t: nebula_mcp_core::ToolSpec| t.on(Platforms::WINDOWS);
    let (dump_sessions, stack_sessions) = (sessions.clone(), sessions.clone());
    vec![
        tool(
            spec(
                "diagnostics_capabilities",
                c,
                "Server capabilities",
                "What this server runs on and which external programs its tools can find: \
                 platform, version, enabled categories, and whether child processes are \
                 confined by the operating system.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .string("version", "Server version.", true)
                    .string("os", "Operating system.", true)
                    .string("arch", "CPU architecture.", true)
                    .string_array("categories", "Enabled tool categories.", true)
                    .boolean("confinement", "Whether child processes are confined by the OS.", true)
                    .prop(
                        "programs",
                        json!({"type": "object", "additionalProperties": {"type": "boolean"},
                               "description": "External programs and whether each was found."}),
                        true,
                    )
                    .build(),
            ),
            handler!(capabilities),
        ),
        tool(
            spec(
                "diagnostics_metrics",
                c,
                "Tool call metrics",
                "Per-tool call counts, failures, cancellations and durations since the server \
                 started.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "tools",
                        "One entry per tool that has been called.",
                        ObjectSchema::open()
                            .string("tool", "Tool name.", true)
                            .integer("calls", "Calls.", true)
                            .integer("successes", "Calls that succeeded.", true)
                            .integer("failures", "Calls that failed.", true)
                            .integer("cancellations", "Calls cancelled or timed out.", true)
                            .integer("meanDurationMs", "Mean duration.", true)
                            .integer("maxDurationMs", "Longest duration.", true)
                            .integer("outputBytes", "Output returned in total.", true),
                        true,
                    )
                    .build(),
            ),
            handler!(metrics),
        ),
        tool(
            spec(
                "diagnostics_config",
                c,
                "Show configuration",
                "The server's configuration as TOML, with tokens and secrets replaced.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            ),
            handler!(config),
        ),
        tool(
            win(spec(
                "diagnostics_wer_reports",
                c,
                "Windows error reports",
                "Recent Windows Error Reporting entries (application crashes and hangs) from \
                 the Application event log, as JSON.",
                ObjectSchema::new()
                    .integer_range("maxEvents", "Entries to return (default 20).", 1, 200, false)
                    .build(),
                Effects::read_only().exec(SHELLS),
            )),
            handler!(wer_reports),
        ),
        tool(
            win(spec(
                "diagnostics_crash_dumps",
                c,
                "List crash dumps",
                "Crash dump files (*.dmp) in a directory inside the allowed directories, newest \
                 first.",
                ObjectSchema::new()
                    .string("directory", "Directory to look in.", true)
                    .build(),
                Effects::read_only(),
            ))
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "dumps",
                        "Dump files, newest first.",
                        ObjectSchema::open()
                            .string("path", "The file.", true)
                            .integer("bytes", "Size.", true)
                            .nullable_string("modified", "Last modification, RFC 3339.", true),
                        true,
                    )
                    .build(),
            ),
            handler!(crash_dumps),
        ),
        tool(
            win(spec(
                "diagnostics_create_dump",
                c,
                "Dump process memory",
                "Write a full memory dump of a process that runs inside one of your terminal \
                 sessions, with Sysinternals procdump. Other processes are refused.",
                ObjectSchema::new()
                    .integer_min("pid", "Process id.", 1, true)
                    .string("outputPath", "Dump file to write (.dmp).", true)
                    .build(),
                Effects::writes().exec(Exec::Programs(&["procdump"])),
            )),
            move |ctx, args| {
                let sessions = dump_sessions.clone();
                Box::pin(async move { create_dump(ctx, &sessions, args).await })
            },
        ),
        tool(
            win(spec(
                "diagnostics_stack_trace",
                c,
                "Capture thread stacks",
                "The call stacks of every thread of a process that runs inside one of your \
                 terminal sessions, captured with cdb without stopping it.",
                ObjectSchema::new()
                    .integer_min("pid", "Process id.", 1, true)
                    .integer_min("timeoutSecs", "Seconds before cdb is stopped.", 1, false)
                    .build(),
                Effects::read_only().exec(Exec::Programs(&["cdb"])),
            )),
            move |ctx, args| {
                let sessions = stack_sessions.clone();
                Box::pin(async move { stack_trace(ctx, &sessions, args).await })
            },
        ),
        tool(
            win(spec(
                "diagnostics_analyze_dump",
                c,
                "Analyse crash dump",
                "Open a crash dump in cdb and return one analysis: `analyze` (the automatic \
                 crash analysis), `stacks`, `modules` or `threads`. Debugger commands cannot be \
                 passed.",
                ObjectSchema::new()
                    .string("dump", "The dump file.", true)
                    .string_enum(
                        "analysis",
                        "Which analysis (default analyze).",
                        &["analyze", "stacks", "modules", "threads"],
                        false,
                    )
                    .integer_min("timeoutSecs", "Seconds before cdb is stopped.", 1, false)
                    .build(),
                Effects::read_only().exec(Exec::Programs(&["cdb"])),
            )),
            handler!(analyze_dump),
        ),
        tool(
            win(spec(
                "diagnostics_etw_trace",
                c,
                "ETW trace session",
                "Create, start, stop, delete or query an Event Tracing for Windows session \
                 with logman. A trace can record system-wide activity, so every action is \
                 elevated; stop and delete are destructive.",
                ObjectSchema::new()
                    .string_enum("action", "What to do.", &["create", "start", "stop", "delete", "query"], true)
                    .string("session", "Session name: letters, digits, '-' and '_'.", true)
                    .string("provider", "Provider name or {GUID}, for create.", false)
                    .string("outputEtl", "Trace file to write (.etl), for create.", false)
                    .build(),
                Effects::writes()
                    .elevated(Gate::Always)
                    .destructive(Gate::Sometimes)
                    .exec(Exec::Programs(&["logman"])),
            )),
            handler!(etw_trace),
        ),
    ]
}

async fn capabilities(ctx: &ToolContext, _: Value) -> Result<ToolOutput> {
    let mut programs = Map::new();
    for program in PROGRAMS {
        programs.insert((*program).to_string(), json!(ctx.spawner().available(program)));
    }
    Ok(ToolOutput::json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "categories": ctx.config().server.categories,
        "confinement": CONFINEMENT_AVAILABLE,
        "programs": programs,
    })))
}

async fn metrics(ctx: &ToolContext, _: Value) -> Result<ToolOutput> {
    let tools: Vec<Value> = ctx
        .metrics()
        .snapshot()
        .into_iter()
        .map(|m| {
            json!({
                "tool": m.tool,
                "calls": m.calls,
                "successes": m.successes,
                "failures": m.failures,
                "cancellations": m.cancellations,
                "meanDurationMs": m.mean_duration_us / 1000,
                "maxDurationMs": m.max_duration_us / 1000,
                "outputBytes": m.output_bytes,
            })
        })
        .collect();
    Ok(ToolOutput::json(json!({"tools": tools})))
}

async fn config(ctx: &ToolContext, _: Value) -> Result<ToolOutput> {
    let text = ctx
        .config()
        .to_redacted_toml()
        .map_err(|e| ToolError::Internal(e.to_string()))?;
    Ok(ToolOutput::text(text))
}

async fn wer_reports(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const BODY: &str = "try {\
           @(Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='Windows Error Reporting' } \
             -MaxEvents ([int]$env:NB_MAX) | Select-Object @{n='time';e={$_.TimeCreated.ToString('o')}}, \
             @{n='id';e={$_.Id}}, @{n='message';e={$_.Message}}) | ConvertTo-Json -Depth 3\
         } catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]' } else { throw } }";
    let a = Args::new(&args)?;
    let max = a.u64_or("maxEvents", 20)?.clamp(1, 200).to_string();
    answer(ctx, "reading the error reports", typed(BODY, &[("NB_MAX", max.as_str())])).await
}

async fn crash_dumps(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("directory")?.to_string();
    let mut dumps = ctx
        .fs()
        .blocking(move |fs| {
            let dir = fs.resolve(&input, Access::Read)?;
            let (entries, _) = fs.read_dir(&dir)?;
            Ok(entries
                .into_iter()
                .filter(|e| e.meta.kind == Kind::File && e.name.to_ascii_lowercase().ends_with(".dmp"))
                .map(|e| (e.meta.modified, e.path.display(), e.meta.len))
                .collect::<Vec<_>>())
        })
        .await?;
    dumps.sort_by(|a, b| b.0.cmp(&a.0));
    let dumps: Vec<Value> = dumps
        .into_iter()
        .map(|(modified, path, bytes)| {
            json!({"path": path, "bytes": bytes, "modified": modified.and_then(rfc3339)})
        })
        .collect();
    Ok(ToolOutput::json(json!({"dumps": dumps})))
}

/// The pid of a process the caller may inspect.
async fn own_pid(ctx: &ToolContext, sessions: &Sessions, a: &Args<'_>) -> Result<u32> {
    let pid = u32::try_from(a.u64("pid")?)
        .map_err(|_| ToolError::invalid("`pid` is not a process id"))?;
    if !in_my_sessions(ctx, sessions, pid).await? {
        return Err(ToolError::denied(format!(
            "process {pid} does not run inside one of your terminal sessions; only those can be \
             dumped or inspected"
        )));
    }
    Ok(pid)
}

async fn create_dump(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let pid = own_pid(ctx, sessions, &a).await?;
    let dest = ctx.write_path(a.str("outputPath")?)?;
    if !dest.display().to_ascii_lowercase().ends_with(".dmp") {
        return Err(ToolError::invalid("`outputPath` must end in .dmp"));
    }
    let cmd = Command::typed("procdump")
        .args(["-accepteula", "-ma"])
        .arg(pid.to_string())
        .arg_path(&dest)
        .timeout(ctx.timeout(None));
    let out = ctx.run(cmd).await?;
    // procdump reports success with a non-zero code on some versions; the
    // file is what counts.
    let written = ctx.fs().try_metadata(&dest)?.map_or(0, |m| m.len);
    if written == 0 {
        return Err(failure("procdump", &out));
    }
    Ok(ToolOutput::text(format!(
        "[diagnostics_create_dump: wrote {} ({written} bytes)]",
        dest.display()
    )))
}

async fn stack_trace(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let pid = own_pid(ctx, sessions, &a).await?;
    let cmd = Command::typed("cdb")
        // Attach without becoming the debugger, print stacks, detach.
        .args(["-pv", "-p"])
        .arg(pid.to_string())
        .args(["-c", "~*k;qd"])
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    Ok(render_run("diagnostics_stack_trace", &ctx.run(cmd).await?))
}

async fn analyze_dump(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let wanted = a.str_or("analysis", "analyze")?;
    let commands = ANALYSES
        .iter()
        .find(|(name, _)| *name == wanted)
        .map(|(_, commands)| *commands)
        .ok_or_else(|| ToolError::invalid(format!("unknown analysis '{wanted}'")))?;
    let input = a.str("dump")?.to_string();
    let dump = ctx
        .fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Read)?;
            match fs.metadata(&path)?.kind {
                Kind::File => Ok(path),
                _ => Err(ToolError::invalid("`dump` must be a file")),
            }
        })
        .await?;
    let cmd = Command::typed("cdb")
        .arg("-z")
        .arg_path(&dump)
        .arg("-c")
        .arg(format!("{commands};q"))
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    Ok(render_run("diagnostics_analyze_dump", &ctx.run(cmd).await?))
}

/// A session name: it may not start with '-', where logman reads options.
fn session_name(name: &str) -> Result<String> {
    let mut chars = name.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(name.to_string())
    } else {
        Err(ToolError::invalid(
            "`session` must start with a letter or digit and contain only letters, digits, '-' \
             and '_'",
        ))
    }
}

/// An ETW provider: a name or a `{GUID}`.
fn provider_name(name: &str) -> Result<String> {
    let ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '{')
        && name.len() <= 200
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.-{}".contains(c));
    if ok {
        Ok(name.to_string())
    } else {
        Err(ToolError::invalid(
            "`provider` must be a provider name or a {GUID}",
        ))
    }
}

async fn etw_trace(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a.str("action")?;
    let session = session_name(a.str("session")?)?;
    let mut cmd = Command::typed("logman");
    match action {
        "create" => {
            let provider = provider_name(
                a.opt_str("provider")?
                    .ok_or_else(|| ToolError::invalid("`provider` is required for create"))?,
            )?;
            let output = ctx.write_path(
                a.opt_str("outputEtl")?
                    .ok_or_else(|| ToolError::invalid("`outputEtl` is required for create"))?,
            )?;
            cmd = cmd
                .args(["create", "trace", session.as_str(), "-p", provider.as_str(), "-o"])
                .arg_path(&output);
        }
        "start" | "query" => cmd = cmd.args([action, session.as_str()]),
        "stop" | "delete" => {
            ctx.require_destructive("stopping or deleting a trace session")?;
            cmd = cmd.args([action, session.as_str()]);
        }
        other => return Err(ToolError::invalid(format!("unknown action '{other}'"))),
    }
    let out = ctx.run(cmd.timeout(ctx.timeout(None))).await?;
    if !out.success() {
        return Err(failure("logman", &out));
    }
    Ok(ToolOutput::text(out.stdout.text.trim().to_string()))
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
