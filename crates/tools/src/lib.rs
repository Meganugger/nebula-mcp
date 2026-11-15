//! # nebula-mcp-tools
//!
//! The tools of the Nebula MCP server. A tool is a [`ToolSpec`] and an async
//! function. It reaches files, processes and the network only through the
//! capabilities of its [`ToolContext`]; `clippy.toml` in this crate bans the
//! standard-library and tokio routes around them.
//!
//! [`ToolSpec`]: nebula_mcp_core::ToolSpec
//! [`ToolContext`]: nebula_mcp_core::ToolContext

#![warn(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use nebula_mcp_core::{ConfigStore, Dispatcher, OwnerId, ToolRegistry};
use tokio_util::sync::CancellationToken;

mod common;
mod fs;
mod git;
mod github;
mod jobs;
mod scheduler;
mod sessions;
mod terminal;
#[cfg(test)]
mod testkit;

/// How often idle terminal sessions are looked for.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

/// State that outlives a tool call: terminal sessions and scheduled jobs.
/// Everything in it belongs to an [`OwnerId`] and is invisible to others.
#[derive(Clone, Default)]
pub struct ToolState {
    sessions: Arc<sessions::Sessions>,
    jobs: Arc<jobs::Jobs>,
}

impl ToolState {
    /// Connect the state to the running server: jobs run through
    /// `dispatcher`, idle sessions are closed on a timer, and everything is
    /// stopped when `shutdown` fires. Call once, inside the runtime.
    pub fn start(&self, dispatcher: &Arc<Dispatcher>, shutdown: CancellationToken) {
        self.jobs.attach(dispatcher);
        let state = self.clone();
        let store: ConfigStore = dispatcher.store().clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(MAINTENANCE_INTERVAL) => {}
                }
                let idle = store.snapshot().config.limits.terminal_session_idle_secs;
                let closed = state
                    .sessions
                    .expire(Duration::from_secs(idle.max(1)))
                    .await;
                if closed > 0 {
                    tracing::info!(closed, "closed idle terminal sessions");
                }
            }
            state.stop_all().await;
        });
    }

    /// Stop everything that belongs to an owner that has gone away.
    pub async fn close_owner(&self, owner: &OwnerId) {
        let jobs = self.jobs.cancel_owner(owner);
        let sessions = self.sessions.close_owner(owner).await;
        if jobs + sessions > 0 {
            tracing::info!(
                owner = owner.as_str(),
                jobs,
                sessions,
                "released a client's state"
            );
        }
    }

    /// Stop every job and kill every session.
    pub async fn stop_all(&self) {
        self.jobs.cancel_all();
        self.sessions.close_all().await;
    }

    /// Number of open terminal sessions, of all owners.
    #[must_use]
    pub fn open_sessions(&self) -> usize {
        self.sessions.count()
    }
}

/// Register every tool and return the state they share. An error names a
/// malformed definition, which is a bug in this crate (the tests register
/// everything).
pub fn register_all(registry: &mut ToolRegistry) -> Result<ToolState, String> {
    let state = ToolState::default();
    let all = fs::tools()
        .into_iter()
        .chain(git::tools())
        .chain(github::tools())
        .chain(terminal::tools(&state.sessions))
        .chain(scheduler::tools(&state.jobs));
    for tool in all {
        registry.register(tool)?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_definition_is_accepted_by_the_registry() {
        let mut registry = ToolRegistry::new();
        register_all(&mut registry).unwrap();
        assert!(!registry.is_empty());
    }

    #[test]
    fn descriptions_and_titles_are_reasonably_sized() {
        let mut registry = ToolRegistry::new();
        register_all(&mut registry).unwrap();
        for tool in registry.all() {
            let spec = tool.spec();
            assert!(spec.title.len() <= 40, "{}: title too long", spec.name);
            assert!(
                spec.description.len() <= 600,
                "{}: description is {} bytes; keep tools/list small",
                spec.name,
                spec.description.len()
            );
        }
    }
}
