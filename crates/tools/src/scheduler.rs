//! Scheduler tools: run an allowed program later, or repeatedly.
//!
//! A job is a deferred `terminal_run` call. It is checked against the policy
//! when it is scheduled and again, through the dispatcher, each time it
//! fires, so tightening the configuration stops jobs that were scheduled
//! under a looser one.

use std::sync::Arc;
use std::time::Duration;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{Category, Effects, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Map, Value};

use crate::common::{rfc3339, spec, tool, SpecExt};
use crate::jobs::{JobInfo, Jobs, Schedule, RUN_TOOL};

/// Longest delay or interval accepted: 30 days.
const MAX_SECS: i64 = 30 * 24 * 3600;

fn job_schema() -> Value {
    ObjectSchema::open()
        .string("jobId", "Job id.", true)
        .string("program", "Program the job runs.", true)
        .string_enum(
            "kind",
            "Whether it runs once or repeats.",
            &["once", "repeating"],
            true,
        )
        .string_enum(
            "state",
            "Where the job is in its life.",
            &["waiting", "running", "finished", "cancelled"],
            true,
        )
        .integer("runs", "Times it has run.", true)
        .integer("ageSecs", "Seconds since it was scheduled.", true)
        .build()
}

fn job_json(info: &JobInfo) -> Value {
    json!({
        "jobId": info.id,
        "program": info.program,
        "kind": info.kind,
        "state": info.state,
        "runs": info.runs,
        "ageSecs": info.age.as_secs(),
    })
}

fn command_schema() -> ObjectSchema {
    ObjectSchema::new()
        .string(
            "program",
            "Program to run, as for terminal_run: it must be allowed by the operator.",
            true,
        )
        .string_array_max(
            "args",
            "Arguments, passed verbatim as separate strings (no shell).",
            1000,
            false,
        )
        .string(
            "cwd",
            "Directory to run in, inside an allowed directory.",
            false,
        )
        .integer_min(
            "timeoutSecs",
            "Seconds each run may take before it is stopped.",
            1,
            false,
        )
}

/// The `scheduler` tools.
pub(crate) fn tools(jobs: &Arc<Jobs>) -> Vec<Arc<dyn Tool>> {
    let c = Category::Scheduler;
    let (after, every, list, results, cancel) = (
        jobs.clone(),
        jobs.clone(),
        jobs.clone(),
        jobs.clone(),
        jobs.clone(),
    );
    // Scheduling changes nothing by itself, but what it schedules is
    // arbitrary execution, and clients should treat it that way.
    let scheduling = Effects::writes().overwrites().open_world();
    vec![
        tool(
            spec(
                "scheduler_after",
                c,
                "Run later",
                "Schedule an allowed program to run once after a delay. The job belongs to this \
                 client and runs as a terminal_run call, under the server's policy at that \
                 time. Read its output with scheduler_results.",
                command_schema()
                    .integer_range(
                        "delaySecs",
                        "Seconds to wait before running.",
                        0,
                        MAX_SECS,
                        true,
                    )
                    .build(),
                scheduling,
            )
            .returns(job_schema()),
            move |ctx, args| {
                let jobs = after.clone();
                Box::pin(async move { schedule(ctx, &jobs, args, false).await })
            },
        ),
        tool(
            spec(
                "scheduler_every",
                c,
                "Run repeatedly",
                "Schedule an allowed program to run at a fixed interval until it is cancelled, \
                 its run limit is reached or this client goes away. Each run is a terminal_run \
                 call under the server's policy at that time.",
                command_schema()
                    .integer_range("intervalSecs", "Seconds between runs.", 5, MAX_SECS, true)
                    .integer_range(
                        "delaySecs",
                        "Seconds before the first run (default 0).",
                        0,
                        MAX_SECS,
                        false,
                    )
                    .integer_min("maxRuns", "Stop after this many runs.", 1, false)
                    .build(),
                scheduling,
            )
            .returns(job_schema()),
            move |ctx, args| {
                let jobs = every.clone();
                Box::pin(async move { schedule(ctx, &jobs, args, true).await })
            },
        ),
        tool(
            spec(
                "scheduler_list",
                c,
                "List jobs",
                "List the jobs this client has scheduled, including finished ones from the last \
                 hour.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .prop(
                        "jobs",
                        json!({
                            "type": "array",
                            "description": "Jobs, oldest first.",
                            "items": job_schema(),
                        }),
                        true,
                    )
                    .build(),
            ),
            move |ctx, _args| {
                let jobs = list.clone();
                Box::pin(async move {
                    let all: Vec<Value> = jobs.list(ctx).iter().map(job_json).collect();
                    Ok(ToolOutput::json(json!({"jobs": all})))
                })
            },
        ),
        tool(
            spec(
                "scheduler_results",
                c,
                "Job results",
                "Show the output of a job's most recent runs (the last 10 are kept, each cut to \
                 a few thousand characters).",
                ObjectSchema::new()
                    .string(
                        "jobId",
                        "Job id from scheduler_after or scheduler_every.",
                        true,
                    )
                    .build(),
                Effects::read_only(),
            ),
            move |ctx, args| {
                let jobs = results.clone();
                Box::pin(async move { show_results(ctx, &jobs, args) })
            },
        ),
        tool(
            spec(
                "scheduler_cancel",
                c,
                "Cancel job",
                "Cancel a job. A run in progress is stopped together with everything it started.",
                ObjectSchema::new()
                    .string(
                        "jobId",
                        "Job id from scheduler_after or scheduler_every.",
                        true,
                    )
                    .build(),
                Effects::writes().idempotent(true),
            )
            .returns(job_schema()),
            move |ctx, args| {
                let jobs = cancel.clone();
                Box::pin(async move {
                    let a = Args::new(&args)?;
                    let info = jobs.cancel(ctx, a.str("jobId")?)?;
                    Ok(ToolOutput::json(job_json(&info)))
                })
            },
        ),
    ]
}

async fn schedule(
    ctx: &ToolContext,
    jobs: &Arc<Jobs>,
    args: Value,
    repeating: bool,
) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let program = a.str("program")?.to_string();

    // Refuse now what would be refused when the job fires.
    let exposed = ctx
        .config()
        .is_tool_enabled(Category::Terminal.as_str(), RUN_TOOL);
    if !exposed {
        return Err(ToolError::denied(format!(
            "scheduled jobs run through {RUN_TOOL}, which is not enabled on this server; the \
             operator needs the terminal category in [server] categories"
        )));
    }
    ctx.policy()
        .commands()
        .authorize(&program, ctx.working_dir(), ctx.policy().paths())?;

    // The arguments of the terminal_run call the job will make.
    let mut call = Map::new();
    call.insert("program".into(), json!(program));
    for key in ["args", "cwd", "timeoutSecs"] {
        if let Some(value) = a.opt_value(key) {
            call.insert(key.into(), value.clone());
        }
    }

    let delay = Duration::from_secs(a.u64_or("delaySecs", 0)?);
    let when = if repeating {
        Schedule::Every {
            delay,
            interval: Duration::from_secs(a.u64("intervalSecs")?),
            max_runs: a.opt_u64("maxRuns")?,
        }
    } else {
        Schedule::Once { delay }
    };
    let id = jobs.schedule(ctx, program, Value::Object(call), when)?;
    let (info, _) = jobs.results(ctx, &id)?;
    Ok(ToolOutput::json(job_json(&info)))
}

fn show_results(ctx: &ToolContext, jobs: &Jobs, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let (info, runs) = jobs.results(ctx, a.str("jobId")?)?;
    let mut text = String::new();
    let first = info.runs.saturating_sub(runs.len() as u64) + 1;
    for (i, run) in runs.iter().enumerate() {
        text.push_str(&format!(
            "--- run {} at {} ({:.1}s, {}) ---\n{}\n",
            first + i as u64,
            rfc3339(run.started).unwrap_or_else(|| "?".to_string()),
            run.duration.as_secs_f64(),
            if run.ok { "ran" } else { "refused or failed" },
            run.output.trim_end()
        ));
    }
    text.push_str(&format!(
        "[scheduler_results: job {} is {}; {} runs so far, {} shown]",
        info.id,
        info.state,
        info.runs,
        runs.len()
    ));
    Ok(ToolOutput::text(text))
}

#[cfg(test)]
#[path = "scheduler_tests.rs"]
mod tests;
