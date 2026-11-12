//! The per-call context handed to a tool.
//!
//! Everything a tool may do to the outside world goes through here: files
//! through [`ToolContext::fs`], processes through [`ToolContext::command`]
//! and [`ToolContext::run`], and the network through [`ToolContext::net`].
//! Each hands out only what the call's [`Policy`] allows.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ConfigStore};
use crate::error::ToolError;
use crate::exec::{self, Command, ExecOutput};
use crate::fs::Fs;
use crate::metrics::Metrics;
use crate::net::Net;
use crate::policy::{CheckedPath, Policy, PolicyEnv};
use crate::progress::ProgressSink;

/// Who is making a call. Long-lived state such as terminal sessions and
/// scheduled jobs belongs to a principal and is invisible to every other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(Arc<str>);

impl Principal {
    /// The single client of a stdio server, or of an HTTP server running
    /// without authentication.
    #[must_use]
    pub fn local() -> Self {
        Self(Arc::from("local"))
    }

    /// A principal identified by an opaque, stable identifier (for example a
    /// digest of the credential it presented).
    #[must_use]
    pub fn new(id: &str) -> Self {
        Self(Arc::from(id))
    }

    /// The opaque identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// Resolves and caches policies for the active configuration.
#[derive(Clone)]
pub struct PolicySource {
    config: ConfigStore,
    env: Arc<PolicyEnv>,
    cache: Arc<Mutex<Cache>>,
}

#[derive(Default)]
struct Cache {
    generation: u64,
    policies: std::collections::HashMap<String, Arc<Policy>>,
    net: Option<Net>,
}

impl PolicySource {
    /// Create a source for the given configuration store.
    #[must_use]
    pub fn new(config: ConfigStore, env: PolicyEnv) -> Self {
        Self {
            config,
            env: Arc::new(env),
            cache: Arc::new(Mutex::new(Cache::default())),
        }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> Arc<Config> {
        self.config.snapshot()
    }

    /// The server environment policies are resolved against.
    #[must_use]
    pub fn env(&self) -> &PolicyEnv {
        &self.env
    }

    fn fresh<'a>(&self, cache: &'a mut Cache) -> &'a mut Cache {
        let generation = self.config.generation();
        if cache.generation != generation {
            *cache = Cache {
                generation,
                ..Cache::default()
            };
        }
        cache
    }

    /// The policy in force for `tool` right now. Long-lived work (sessions,
    /// scheduled jobs) calls this each time it acts, so a tightened
    /// configuration takes effect at once.
    pub fn policy(&self, tool: &str) -> Result<Arc<Policy>, ToolError> {
        let key = crate::config::canonical_tool_name(tool);
        let mut guard = self.cache.lock();
        let cache = self.fresh(&mut guard);
        if let Some(policy) = cache.policies.get(&key) {
            return Ok(policy.clone());
        }
        let policy = Arc::new(Policy::resolve(&self.config.snapshot(), &key, &self.env)?);
        cache.policies.insert(key, policy.clone());
        Ok(policy)
    }

    /// Network access under `policy`: an error unless its network gate is
    /// open.
    pub fn net(&self, policy: &Policy) -> Result<Net, ToolError> {
        policy.require_network()?;
        let mut guard = self.cache.lock();
        let cache = self.fresh(&mut guard);
        if let Some(net) = &cache.net {
            return Ok(net.clone());
        }
        let net = Net::new(
            policy.network().clone(),
            concat!("nebula-mcp/", env!("CARGO_PKG_VERSION")),
        )?;
        cache.net = Some(net.clone());
        Ok(net)
    }
}

/// Context for a single tool invocation.
#[derive(Clone)]
pub struct ToolContext {
    pub(crate) policy: Arc<Policy>,
    pub(crate) fs: Fs,
    pub(crate) net: Option<Net>,
    pub(crate) cancel: CancellationToken,
    pub(crate) progress: Option<ProgressSink>,
    pub(crate) principal: Principal,
    pub(crate) request_id: String,
    pub(crate) metrics: Metrics,
    pub(crate) policies: PolicySource,
}

impl ToolContext {
    /// The policy this call runs under (for inspection; the capabilities
    /// below already enforce it).
    #[must_use]
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// Resolves policies for work that outlives this call.
    #[must_use]
    pub fn policies(&self) -> &PolicySource {
        &self.policies
    }

    /// Policy-bound filesystem access.
    #[must_use]
    pub fn fs(&self) -> &Fs {
        &self.fs
    }

    /// Check a path argument, following links to what it names.
    pub fn resolve(&self, path: &str) -> Result<CheckedPath, ToolError> {
        self.fs.resolve(path)
    }

    /// Check a path argument as a directory entry (a final link is not
    /// followed).
    pub fn resolve_entry(&self, path: &str) -> Result<CheckedPath, ToolError> {
        self.fs.resolve_entry(path)
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        self.policy.working_dir()
    }

    /// Start building a command. Fails unless `program` is on the allowlist.
    pub fn command(&self, program: &str) -> Result<Command, ToolError> {
        self.policy.command(program)
    }

    /// Run a command to completion under this call's cancellation, reporting
    /// progress heartbeats if the client asked for them.
    pub async fn run(&self, command: Command) -> Result<ExecOutput, ToolError> {
        exec::run(command, &self.cancel, self.progress.clone()).await
    }

    /// Network access. Available only to tools that declare
    /// [`crate::tool::Gate::Network`] for this call.
    pub fn net(&self) -> Result<&Net, ToolError> {
        self.net.as_ref().ok_or_else(|| {
            ToolError::Internal(format!(
                "tool '{}' used the network without declaring the network gate",
                self.policy.tool()
            ))
        })
    }

    /// Fail unless the destructive gate is open. For operations that are only
    /// sometimes destructive, beyond what the tool's declaration covers.
    pub fn require_destructive(&self, what: &str) -> Result<(), ToolError> {
        self.policy.require_destructive(what)
    }

    /// Fail unless the elevation gate is open.
    pub fn require_elevated(&self, what: &str) -> Result<(), ToolError> {
        self.policy.require_elevated(what)
    }

    /// Timeout for this call, honouring an optional caller request.
    #[must_use]
    pub fn timeout(&self, requested_secs: Option<u64>) -> Duration {
        self.policy.effective_timeout(requested_secs)
    }

    /// Maximum bytes of output or content a result may carry per stream.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.policy.max_output_bytes()
    }

    /// Cancelled when the client cancels the call or the server shuts down.
    #[must_use]
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Return an error if the call has been cancelled.
    pub fn ensure_active(&self) -> Result<(), ToolError> {
        if self.cancel.is_cancelled() {
            Err(ToolError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Report progress if the client asked for it.
    pub fn report_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        if let Some(sink) = &self.progress {
            sink.report(progress, total, message.map(str::to_string));
        }
    }

    /// Who is calling.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Correlation id for logs.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Shared metrics registry.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}
