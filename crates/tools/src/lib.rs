//! # nebula-mcp-tools
//!
//! Concrete MCP tool implementations for the Nebula MCP server, grouped by
//! category. Cross-platform categories (filesystem, terminal, process, git,
//! github, network, docker, scheduler, security, browser) work everywhere;
//! Windows categories (powershell, windows, diagnostics) compile everywhere but
//! return [`nebula_mcp_core::ToolError::PlatformUnsupported`] off Windows.
//!
//! All tools are constructed once and share a small set of stateful services
//! via [`ToolServices`].

#![warn(missing_docs)]

pub mod browser;
pub mod common;
pub mod desktop;
pub mod desktop_capture;
pub mod diagnostics;
pub mod docker;
pub mod filesystem;
pub mod git;
pub mod github;
pub mod network;
pub mod powershell;
pub mod process;
pub mod scheduler;
pub mod security;
pub mod terminal;
pub mod windows;

use std::sync::Arc;

use nebula_mcp_core::{Tool, ToolRegistry};

pub use common::scheduler::SchedulerManager;
pub use common::session::SessionManager;

/// Stateful services shared across tools for the process lifetime.
#[derive(Clone)]
pub struct ToolServices {
    /// Interactive session manager (persistent shells/REPLs).
    pub sessions: Arc<SessionManager>,
    /// Deferred/recurring job scheduler.
    pub scheduler: Arc<SchedulerManager>,
    /// Shared HTTP client with connection reuse for network/github tools.
    pub http: reqwest::Client,
    /// Lease manager shared by all desktop-mutating tools.
    pub desktop_locks: Arc<desktop::DesktopLockManager>,
}

impl ToolServices {
    /// Build the default services set.
    #[must_use]
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("nebula-mcp/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            sessions: Arc::new(SessionManager::new()),
            scheduler: Arc::new(SchedulerManager::new()),
            http,
            desktop_locks: Arc::new(desktop::DesktopLockManager::new()),
        }
    }
}

impl Default for ToolServices {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a registry containing every tool this crate provides.
#[must_use]
pub fn build_registry(services: &ToolServices) -> ToolRegistry {
    let mut reg = ToolRegistry::new();
    for t in all_tools(services) {
        reg.register(t);
    }
    reg
}

/// Collect every tool instance.
#[must_use]
pub fn all_tools(services: &ToolServices) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = Vec::new();
    v.extend(filesystem::tools());
    v.extend(terminal::tools(services));
    v.extend(process::tools());
    v.extend(git::tools());
    v.extend(github::tools(services));
    v.extend(network::tools(services));
    v.extend(powershell::tools());
    v.extend(windows::tools());
    v.extend(diagnostics::tools());
    v.extend(browser::tools());
    v.extend(docker::tools());
    v.extend(scheduler::tools(services));
    v.extend(security::tools());
    v.extend(desktop::tools(services));
    v.extend(desktop_capture::tools());
    v
}
