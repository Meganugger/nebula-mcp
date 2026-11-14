//! The engine shared by every transport: the tool registry, the live
//! configuration and the dispatcher. It holds no per-connection state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use nebula_mcp_core::config::ConfigError;
use nebula_mcp_core::store::Overlay;
use nebula_mcp_core::{ConfigStore, Dispatcher, ToolRegistry};
use tokio_util::sync::CancellationToken;

/// Server name and version reported to clients.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the model is told when the operator has not written instructions.
pub const DEFAULT_INSTRUCTIONS: &str = "Nebula MCP gives you policy-checked access to this machine. \
The operator decides which tool categories exist, which directories and programs are allowed and \
whether network access, destructive and elevated operations are permitted. A refusal starts with \
its category in square brackets, for example [path_not_allowed] or [permission_denied], and says \
what is allowed; do not retry a refused call unchanged. Relative paths resolve against the \
server's working directory.";

/// The engine.
pub struct App {
    dispatcher: Arc<Dispatcher>,
    shutdown: CancellationToken,
    started: Instant,
}

impl App {
    /// Build the engine from a configuration file (or the defaults).
    /// Returns warnings for the operator.
    pub fn load(
        config: Option<&Path>,
        overlay: Option<Overlay>,
        working_dir: PathBuf,
    ) -> Result<(Arc<Self>, Vec<String>), ConfigError> {
        let registry = registry()?;
        let (store, warnings) = ConfigStore::load(config, overlay, registry.catalog())?;
        Ok((Self::assemble(registry, store, working_dir), warnings))
    }

    fn assemble(registry: ToolRegistry, store: ConfigStore, working_dir: PathBuf) -> Arc<Self> {
        let shutdown = CancellationToken::new();
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(registry),
            store,
            working_dir,
            shutdown.clone(),
        ));
        Arc::new(Self {
            dispatcher,
            shutdown,
            started: Instant::now(),
        })
    }

    /// The dispatcher every tool call goes through.
    #[must_use]
    pub fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    /// The live configuration.
    #[must_use]
    pub fn store(&self) -> &ConfigStore {
        self.dispatcher.store()
    }

    /// Cancelled when the server is stopping; cancels every running call.
    #[must_use]
    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// When the engine was built.
    #[must_use]
    pub fn started(&self) -> Instant {
        self.started
    }
}

/// Every tool this build contains.
pub fn registry() -> Result<ToolRegistry, ConfigError> {
    let mut registry = ToolRegistry::new();
    nebula_mcp_tools::register_all(&mut registry)
        .map_err(|e| ConfigError(format!("internal error in a tool definition: {e}")))?;
    Ok(registry)
}
