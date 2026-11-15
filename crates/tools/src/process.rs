//! Process tools: look at what is running, and signal what the caller's own
//! terminal sessions started.
//!
//! Listings carry names and numbers only. Command lines, environments and
//! working directories of other processes routinely hold credentials and are
//! not reported. `process_kill` reaches the processes inside the caller's
//! terminal sessions and nothing else: not the server, not another client's
//! sessions, not the rest of the machine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use nebula_mcp_core::args::Args;
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{Category, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Value};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System};

use crate::common::{rfc3339, spec, tool, SpecExt};
use crate::sessions::Sessions;

/// sysinfo needs two samples this far apart to report CPU usage.
const CPU_SAMPLE: Duration = Duration::from_millis(250);

fn process_schema() -> ObjectSchema {
    ObjectSchema::open()
        .integer("pid", "Process id.", true)
        .nullable_integer("parentPid", "Parent process id.", true)
        .string("name", "Executable name.", true)
        .string("status", "Run state as the system reports it.", true)
        .number(
            "cpuPercent",
            "CPU use over a short sample; 100 is one core.",
            true,
        )
        .integer("memoryBytes", "Resident memory.", true)
        .boolean(
            "inMySessions",
            "Whether it runs inside one of your terminal sessions (process_kill can signal it).",
            true,
        )
}

/// The `process` tools.
pub(crate) fn tools(sessions: &Arc<Sessions>) -> Vec<Arc<dyn Tool>> {
    let c = Category::Process;
    let (list_sessions, info_sessions, kill_sessions) =
        (sessions.clone(), sessions.clone(), sessions.clone());
    vec![
        tool(
            spec(
                "process_list",
                c,
                "List processes",
                "Running processes, busiest first: id, parent, name, CPU and memory. Command \
                 lines are not reported.",
                ObjectSchema::new()
                    .string(
                        "nameContains",
                        "Only processes whose name contains this text.",
                        false,
                    )
                    .integer_range(
                        "limit",
                        "Most processes to return (default 50).",
                        1,
                        500,
                        false,
                    )
                    .build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .object_array("processes", "Matching processes.", process_schema(), true)
                    .integer("total", "Processes that matched before `limit`.", true)
                    .build(),
            ),
            move |ctx, args| {
                let sessions = list_sessions.clone();
                Box::pin(async move { list(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "process_info",
                c,
                "Inspect process",
                "Details of one process: state, CPU, memory, start time and child processes. \
                 Without `pid`, the server itself.",
                ObjectSchema::new()
                    .integer_min("pid", "Process id (default: the server).", 1, false)
                    .build(),
                Effects::read_only(),
            )
            .returns(
                process_schema()
                    .integer("virtualMemoryBytes", "Virtual memory.", true)
                    .integer("runTimeSecs", "Seconds since it started.", true)
                    .nullable_string("startedAt", "Start time, RFC 3339.", true)
                    .prop(
                        "children",
                        json!({"type": "array", "items": {"type": "integer"},
                               "description": "Ids of its direct children."}),
                        true,
                    )
                    .build(),
            ),
            move |ctx, args| {
                let sessions = info_sessions.clone();
                Box::pin(async move { info(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "process_kill",
                c,
                "Stop process",
                "Stop a process that runs inside one of your terminal sessions (see \
                 `inMySessions` in process_list). Other processes are refused. To stop a whole \
                 session use terminal_session_close.",
                ObjectSchema::new()
                    .integer_min("pid", "Process id.", 1, true)
                    .boolean(
                        "force",
                        "Kill immediately instead of asking it to exit.",
                        false,
                    )
                    .build(),
                Effects::writes().destructive(Gate::Always),
            ),
            move |ctx, args| {
                let sessions = kill_sessions.clone();
                Box::pin(async move { kill(ctx, &sessions, args).await })
            },
        ),
    ]
}

/// A process table with CPU usage sampled.
async fn snapshot(ctx: &ToolContext) -> Result<System> {
    let task = tokio::task::spawn_blocking(|| {
        let kind = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .without_tasks();
        let mut system = System::new().map_err(|e| e.to_string())?;
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        std::thread::sleep(CPU_SAMPLE);
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        Ok::<_, String>(system)
    });
    ctx.deadline(ctx.timeout(None), async {
        match task.await {
            Ok(Ok(system)) => Ok(system),
            Ok(Err(e)) => Err(ToolError::Execution(format!(
                "the process table could not be read: {e}"
            ))),
            Err(_) => Err(ToolError::Internal(
                "reading the process table failed".to_string(),
            )),
        }
    })
    .await
}

/// Every process inside the caller's terminal sessions.
async fn mine(ctx: &ToolContext, sessions: &Sessions, system: &System) -> HashSet<Pid> {
    let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for (pid, process) in system.processes() {
        if let Some(parent) = process.parent() {
            children.entry(parent).or_default().push(*pid);
        }
    }
    let mut found = HashSet::new();
    let mut pending: Vec<Pid> = sessions
        .list(ctx)
        .await
        .into_iter()
        .filter(|s| s.exit.is_none())
        .filter_map(|s| s.pid)
        .map(Pid::from_u32)
        .filter(|pid| system.process(*pid).is_some())
        .collect();
    while let Some(pid) = pending.pop() {
        if found.insert(pid) {
            pending.extend(children.get(&pid).into_iter().flatten().copied());
        }
    }
    found
}

/// Whether `pid` runs inside one of the caller's terminal sessions.
pub(crate) async fn in_my_sessions(
    ctx: &ToolContext,
    sessions: &Sessions,
    pid: u32,
) -> Result<bool> {
    let system = snapshot(ctx).await?;
    Ok(mine(ctx, sessions, &system)
        .await
        .contains(&Pid::from_u32(pid)))
}

fn describe(pid: Pid, process: &sysinfo::Process, mine: &HashSet<Pid>) -> Value {
    json!({
        "pid": pid.as_u32(),
        "parentPid": process.parent().map(Pid::as_u32),
        "name": process.name().to_string_lossy(),
        "status": process.status().to_string(),
        "cpuPercent": (f64::from(process.cpu_usage()) * 10.0).round() / 10.0,
        "memoryBytes": process.memory(),
        "inMySessions": mine.contains(&pid),
    })
}

async fn list(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let filter = a.opt_str("nameContains")?.map(str::to_lowercase);
    let limit = a.usize_or("limit", 50)?.min(500);
    let system = snapshot(ctx).await?;
    let mine = mine(ctx, sessions, &system).await;
    let mut matching: Vec<(&Pid, &sysinfo::Process)> = system
        .processes()
        .iter()
        .filter(|(_, p)| {
            filter
                .as_ref()
                .is_none_or(|f| p.name().to_string_lossy().to_lowercase().contains(f))
        })
        .collect();
    matching.sort_by(|a, b| {
        b.1.cpu_usage()
            .total_cmp(&a.1.cpu_usage())
            .then(b.1.memory().cmp(&a.1.memory()))
            .then(a.0.cmp(b.0))
    });
    let total = matching.len();
    let processes: Vec<Value> = matching
        .into_iter()
        .take(limit)
        .map(|(pid, p)| describe(*pid, p, &mine))
        .collect();
    Ok(ToolOutput::json(
        json!({"processes": processes, "total": total}),
    ))
}

async fn info(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let pid = match a.opt_u64("pid")? {
        Some(pid) => pid_from(pid)?,
        None => Pid::from_u32(std::process::id()),
    };
    let system = snapshot(ctx).await?;
    let process = system
        .process(pid)
        .ok_or_else(|| ToolError::NotFound(format!("there is no process {pid}")))?;
    let mine = mine(ctx, sessions, &system).await;
    let mut out = describe(pid, process, &mine);
    let mut children: Vec<u32> = system
        .processes()
        .iter()
        .filter(|(_, p)| p.parent() == Some(pid))
        .map(|(child, _)| child.as_u32())
        .collect();
    children.sort_unstable();
    out["virtualMemoryBytes"] = json!(process.virtual_memory());
    out["runTimeSecs"] = json!(process.run_time());
    out["startedAt"] = json!(rfc3339(
        UNIX_EPOCH + Duration::from_secs(process.start_time())
    ));
    out["children"] = json!(children);
    Ok(ToolOutput::json(out))
}

fn pid_from(pid: u64) -> Result<Pid> {
    u32::try_from(pid)
        .map(Pid::from_u32)
        .map_err(|_| ToolError::invalid("`pid` is not a process id"))
}

async fn kill(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let pid = pid_from(a.u64("pid")?)?;
    let force = a.bool_or("force", false)?;
    let system = snapshot(ctx).await?;
    if !mine(ctx, sessions, &system).await.contains(&pid) {
        return Err(ToolError::denied(format!(
            "process {pid} does not run inside one of your terminal sessions. process_kill only \
             signals processes those sessions started; process_list marks them with \
             inMySessions."
        )));
    }
    let process = system
        .process(pid)
        .ok_or_else(|| ToolError::NotFound(format!("there is no process {pid}")))?;
    // Not every platform can ask politely; killing is the fallback.
    let delivered = if force {
        process.kill()
    } else {
        process
            .kill_with(Signal::Term)
            .unwrap_or_else(|| process.kill())
    };
    if !delivered {
        return Err(ToolError::Execution(format!(
            "the system refused to signal process {pid}; it may have exited already"
        )));
    }
    Ok(ToolOutput::text(format!(
        "[process_kill: {} process {pid} ({})]",
        if force { "killed" } else { "asked to exit" },
        process.name().to_string_lossy()
    )))
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
