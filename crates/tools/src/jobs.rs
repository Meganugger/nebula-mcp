//! Scheduled jobs: commands that run later or repeatedly.
//!
//! A job does not hold a capability. When it fires it makes an ordinary
//! `terminal_run` call through the dispatcher, so the configuration in force
//! at that moment decides whether, and how, the command runs.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{Call, Dispatcher, OwnerId, Result, ToolContext, ToolError};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::common::clip;

/// The tool a job runs.
pub(crate) const RUN_TOOL: &str = "terminal_run";
/// Runs remembered per job.
const KEPT_RUNS: usize = 10;
/// Characters of each run's output that are kept.
const KEPT_OUTPUT_CHARS: usize = 4000;
/// How long a finished job stays listed.
const FINISHED_TTL: Duration = Duration::from_secs(3600);

/// One execution of a job.
#[derive(Clone)]
pub(crate) struct Run {
    pub started: SystemTime,
    pub duration: Duration,
    /// Whether the tool call succeeded (the command may still have exited
    /// non-zero; the output says).
    pub ok: bool,
    pub output: String,
}

/// When a job runs.
#[derive(Clone, Copy)]
pub(crate) enum Schedule {
    Once {
        delay: Duration,
    },
    Every {
        delay: Duration,
        interval: Duration,
        max_runs: Option<u64>,
    },
}

struct Job {
    id: String,
    owner: OwnerId,
    program: String,
    arguments: Value,
    schedule: Schedule,
    created: Instant,
    cancel: CancellationToken,
    state: Mutex<JobState>,
}

#[derive(Default)]
struct JobState {
    runs: VecDeque<Run>,
    total_runs: u64,
    running: bool,
    finished: Option<Instant>,
    cancelled: bool,
}

/// What `list` reports about a job.
pub(crate) struct JobInfo {
    pub id: String,
    pub program: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub runs: u64,
    pub age: Duration,
}

/// Every job, of every owner.
#[derive(Default)]
pub(crate) struct Jobs {
    map: Mutex<HashMap<String, Arc<Job>>>,
    dispatcher: OnceLock<Weak<Dispatcher>>,
}

impl Jobs {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Job>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Give jobs the dispatcher they run through. Called once at startup.
    pub(crate) fn attach(&self, dispatcher: &Arc<Dispatcher>) {
        let _ = self.dispatcher.set(Arc::downgrade(dispatcher));
    }

    fn prune(&self) {
        self.lock().retain(|_, job| {
            let state = job.state.lock().unwrap_or_else(|e| e.into_inner());
            state.finished.is_none_or(|at| at.elapsed() < FINISHED_TTL)
        });
    }

    /// Schedule `terminal_run` with `arguments` for the calling owner.
    pub(crate) fn schedule(
        self: &Arc<Self>,
        ctx: &ToolContext,
        program: String,
        arguments: Value,
        schedule: Schedule,
    ) -> Result<String> {
        let Some(dispatcher) = self.dispatcher.get().cloned() else {
            return Err(ToolError::Internal(
                "the scheduler is not connected to the dispatcher".to_string(),
            ));
        };
        self.prune();
        let limit = ctx.config().limits.max_scheduled_jobs;
        let active = self
            .lock()
            .values()
            .filter(|j| {
                &j.owner == ctx.owner()
                    && j.state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .finished
                        .is_none()
            })
            .count();
        if active >= limit {
            return Err(ToolError::LimitExceeded(format!(
                "{active} jobs are scheduled, which is the limit; cancel one with \
                 scheduler_cancel first"
            )));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let job = Arc::new(Job {
            id: id.clone(),
            owner: ctx.owner().clone(),
            program,
            arguments,
            schedule,
            created: Instant::now(),
            cancel: CancellationToken::new(),
            state: Mutex::new(JobState::default()),
        });
        self.lock().insert(id.clone(), job.clone());
        tokio::spawn(drive(job, dispatcher));
        Ok(id)
    }

    fn find(&self, ctx: &ToolContext, id: &str) -> Result<Arc<Job>> {
        self.lock()
            .get(id)
            .filter(|j| &j.owner == ctx.owner())
            .cloned()
            .ok_or_else(|| {
                ToolError::NotFound(format!(
                    "no scheduled job '{id}'; scheduler_list shows the current ones"
                ))
            })
    }

    /// The caller's jobs, oldest first.
    pub(crate) fn list(&self, ctx: &ToolContext) -> Vec<JobInfo> {
        self.prune();
        let mut jobs: Vec<Arc<Job>> = self
            .lock()
            .values()
            .filter(|j| &j.owner == ctx.owner())
            .cloned()
            .collect();
        jobs.sort_by_key(|j| j.created);
        jobs.iter().map(|j| info(j)).collect()
    }

    /// The remembered runs of one of the caller's jobs, oldest first.
    pub(crate) fn results(&self, ctx: &ToolContext, id: &str) -> Result<(JobInfo, Vec<Run>)> {
        let job = self.find(ctx, id)?;
        let runs = job
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .runs
            .iter()
            .cloned()
            .collect();
        Ok((info(&job), runs))
    }

    /// Cancel one of the caller's jobs; a run in progress is stopped.
    pub(crate) fn cancel(&self, ctx: &ToolContext, id: &str) -> Result<JobInfo> {
        let job = self.find(ctx, id)?;
        stop(&job);
        Ok(info(&job))
    }

    /// Cancel the jobs of an owner that has gone away.
    pub(crate) fn cancel_owner(&self, owner: &OwnerId) -> usize {
        let jobs: Vec<Arc<Job>> = self
            .lock()
            .values()
            .filter(|j| &j.owner == owner)
            .cloned()
            .collect();
        jobs.iter().for_each(stop);
        self.lock().retain(|_, j| &j.owner != owner);
        jobs.len()
    }

    /// Cancel every job.
    pub(crate) fn cancel_all(&self) {
        let jobs: Vec<Arc<Job>> = self.lock().drain().map(|(_, j)| j).collect();
        jobs.iter().for_each(stop);
    }
}

fn stop(job: &Arc<Job>) {
    job.cancel.cancel();
    let mut state = job.state.lock().unwrap_or_else(|e| e.into_inner());
    if state.finished.is_none() {
        state.cancelled = true;
        state.finished = Some(Instant::now());
    }
}

fn info(job: &Job) -> JobInfo {
    let state = job.state.lock().unwrap_or_else(|e| e.into_inner());
    JobInfo {
        id: job.id.clone(),
        program: job.program.clone(),
        kind: match job.schedule {
            Schedule::Once { .. } => "once",
            Schedule::Every { .. } => "repeating",
        },
        state: if state.cancelled {
            "cancelled"
        } else if state.finished.is_some() {
            "finished"
        } else if state.running {
            "running"
        } else {
            "waiting"
        },
        runs: state.total_runs,
        age: job.created.elapsed(),
    }
}

/// Run the job on its schedule until it is done or cancelled.
async fn drive(job: Arc<Job>, dispatcher: Weak<Dispatcher>) {
    let (mut wait, interval, max_runs) = match job.schedule {
        Schedule::Once { delay } => (delay, None, Some(1)),
        Schedule::Every {
            delay,
            interval,
            max_runs,
        } => (delay, Some(interval), max_runs),
    };
    loop {
        tokio::select! {
            () = job.cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
        let Some(dispatcher) = dispatcher.upgrade() else {
            return;
        };
        if dispatcher.shutdown_token().is_cancelled() {
            return;
        }
        let run_number = {
            let mut state = job.state.lock().unwrap_or_else(|e| e.into_inner());
            state.running = true;
            state.total_runs + 1
        };
        let started = SystemTime::now();
        let clock = Instant::now();
        let outcome = dispatcher
            .call(Call {
                name: RUN_TOOL.to_string(),
                arguments: job.arguments.clone(),
                owner: job.owner.clone(),
                request_id: format!("job-{}-{run_number}", job.id),
                cancel: job.cancel.child_token(),
                progress: None,
            })
            .await;
        drop(dispatcher);
        let (ok, output) = match outcome {
            Ok(Ok(out)) => (
                true,
                out.content
                    .iter()
                    .filter_map(|c| match c {
                        Content::Text(t) => Some(t.as_str()),
                        Content::Image { .. } => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            Ok(Err(failure)) => (false, failure.text),
            Err(unknown) => (
                false,
                format!(
                    "{}. Scheduled jobs run through {RUN_TOOL}, which needs the terminal category.",
                    unknown.message
                ),
            ),
        };
        let done = {
            let mut state = job.state.lock().unwrap_or_else(|e| e.into_inner());
            state.running = false;
            state.total_runs += 1;
            if state.runs.len() == KEPT_RUNS {
                state.runs.pop_front();
            }
            state.runs.push_back(Run {
                started,
                duration: clock.elapsed(),
                ok,
                output: clip(&output, KEPT_OUTPUT_CHARS),
            });
            let done = max_runs.is_some_and(|m| state.total_runs >= m);
            if done && state.finished.is_none() {
                state.finished = Some(Instant::now());
            }
            done || state.finished.is_some()
        };
        match interval {
            Some(interval) if !done => wait = interval,
            _ => return,
        }
    }
}
