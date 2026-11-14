//! Per-call execution context handed to every tool.
//!
//! A [`ToolContext`] carries the capabilities a call may use: [`Fs`] for
//! files, [`Spawner`] for processes, [`Net`] for the network, plus the gates,
//! limits, cancellation and progress reporting. Tools have no other route to
//! those resources, so what the context refuses cannot be done.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::error::{Result, ToolError};
use crate::fs::{CheckedPath, Fs};
use crate::metrics::Metrics;
use crate::net::Net;
use crate::policy::{Access, Policy};
use crate::process::{Child, Command, Output, Spawner};
use crate::tool::{Effects, Gate};

/// A progress update emitted by a tool during a long call.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    /// Work completed so far; increases with every update.
    pub progress: f64,
    /// Total amount of work, when known.
    pub total: Option<f64>,
    /// Status text.
    pub message: Option<String>,
}

/// Where a tool sends progress. Sends never block; updates are dropped when
/// the receiver is gone or behind.
#[derive(Debug, Clone)]
pub struct ProgressSink {
    tx: tokio::sync::mpsc::Sender<ProgressUpdate>,
}

impl ProgressSink {
    /// Create a sink and its receiver.
    #[must_use]
    pub fn channel() -> (Self, tokio::sync::mpsc::Receiver<ProgressUpdate>) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (Self { tx }, rx)
    }

    /// Report progress.
    pub fn report(&self, progress: f64, total: Option<f64>, message: Option<String>) {
        let _ = self.tx.try_send(ProgressUpdate {
            progress,
            total,
            message,
        });
    }
}

/// Who owns state that outlives a call (terminal sessions, scheduled jobs).
/// Calls can only see and act on state with their own owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerId(Arc<str>);

impl OwnerId {
    /// An owner identified by `id`.
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    /// The single owner of a stdio connection.
    #[must_use]
    pub fn stdio() -> Self {
        Self::new("stdio")
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the dispatcher supplies to build a context.
pub struct ContextParts {
    /// Policy resolved for the tool.
    pub policy: Arc<Policy>,
    /// The tool's declared effects.
    pub effects: Effects,
    /// Configuration snapshot the call runs under.
    pub config: Arc<Config>,
    /// Directory relative paths resolve against.
    pub working_dir: PathBuf,
    /// Cancelled on client cancel, disconnect, timeout or shutdown.
    pub cancel: CancellationToken,
    /// Owner of long-lived state created by the call.
    pub owner: OwnerId,
    /// Correlation id for logs.
    pub request_id: String,
    /// Progress sink, when the client asked for progress.
    pub progress: Option<ProgressSink>,
    /// Shared metrics.
    pub metrics: Metrics,
}

/// Context for one tool invocation.
#[derive(Clone)]
pub struct ToolContext {
    policy: Arc<Policy>,
    effects: Effects,
    config: Arc<Config>,
    working_dir: PathBuf,
    cancel: CancellationToken,
    owner: OwnerId,
    request_id: String,
    progress: Option<ProgressSink>,
    metrics: Metrics,
    fs: Fs,
    spawner: Spawner,
    net: Net,
}

impl ToolContext {
    /// Build the context for a call.
    #[must_use]
    pub fn new(parts: ContextParts) -> Self {
        let fs = Fs::new(
            parts.policy.paths().clone(),
            parts.working_dir.clone(),
            !parts.effects.read_only,
            parts.cancel.clone(),
            parts.policy.max_output_bytes(),
        );
        let spawner = Spawner::new(
            parts.policy.clone(),
            parts.effects.exec,
            parts.working_dir.clone(),
            parts.cancel.clone(),
            parts.progress.clone(),
        );
        let net = Net::new(
            parts.policy.net().clone(),
            parts.cancel.clone(),
            parts.policy.max_output_bytes(),
        );
        Self {
            policy: parts.policy,
            effects: parts.effects,
            config: parts.config,
            working_dir: parts.working_dir,
            cancel: parts.cancel,
            owner: parts.owner,
            request_id: parts.request_id,
            progress: parts.progress,
            metrics: parts.metrics,
            fs,
            spawner,
            net,
        }
    }

    /// The policy this call runs under.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The configuration snapshot this call runs under.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// The call's cancellation token.
    #[must_use]
    pub fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Owner of long-lived state created by this call.
    #[must_use]
    pub fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Correlation id for logs.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Shared metrics.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Filesystem capability.
    #[must_use]
    pub fn fs(&self) -> &Fs {
        &self.fs
    }

    /// Check a path for reading.
    pub fn read_path(&self, path: &str) -> Result<CheckedPath> {
        self.fs.resolve(path, Access::Read)
    }

    /// Check a path for writing.
    pub fn write_path(&self, path: &str) -> Result<CheckedPath> {
        self.fs.resolve(path, Access::Write)
    }

    /// Process capability.
    #[must_use]
    pub fn spawner(&self) -> &Spawner {
        &self.spawner
    }

    /// Run a command to completion.
    pub async fn run(&self, command: Command) -> Result<Output> {
        self.spawner.run(command).await
    }

    /// Start a long-lived process.
    pub fn spawn(&self, command: Command) -> Result<Child> {
        self.spawner.spawn(command)
    }

    /// Network capability. Fails for tools that did not declare network use,
    /// and when policy has the network off.
    pub fn net(&self) -> Result<&Net> {
        if !self.effects.network {
            return Err(ToolError::Internal(format!(
                "tool '{}' used the network without declaring it",
                self.policy.tool()
            )));
        }
        self.policy.require_network()?;
        Ok(&self.net)
    }

    /// Fail unless destructive operations are permitted. Call before doing
    /// anything that deletes, overwrites or stops something.
    pub fn require_destructive(&self, what: &str) -> Result<()> {
        if self.effects.destructive == Gate::Never {
            return Err(ToolError::Internal(format!(
                "tool '{}' attempted a destructive operation without declaring it",
                self.policy.tool()
            )));
        }
        self.policy.require_destructive(what)
    }

    /// Fail unless elevated operations are permitted.
    pub fn require_elevated(&self, what: &str) -> Result<()> {
        if self.effects.elevated == Gate::Never {
            return Err(ToolError::Internal(format!(
                "tool '{}' attempted an elevated operation without declaring it",
                self.policy.tool()
            )));
        }
        self.policy.require_elevated(what)
    }

    /// Report progress if the client asked for it.
    pub fn report_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        if let Some(sink) = &self.progress {
            sink.report(progress, total, message.map(str::to_string));
        }
    }

    /// Return [`ToolError::Cancelled`] if the call has been cancelled.
    pub fn ensure_active(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            Err(ToolError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// The timeout to use, honouring a caller request up to the ceiling.
    #[must_use]
    pub fn timeout(&self, requested_secs: Option<u64>) -> Duration {
        self.policy.effective_timeout(requested_secs)
    }

    /// Maximum bytes per output stream or file read.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.policy.max_output_bytes()
    }

    /// Await `fut`, giving up with [`ToolError::Cancelled`] or
    /// [`ToolError::Timeout`]. For waits that are not process runs.
    pub async fn deadline<T>(
        &self,
        timeout: Duration,
        fut: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(ToolError::Cancelled),
            r = tokio::time::timeout(timeout, fut) => match r {
                Ok(inner) => inner,
                Err(_) => Err(ToolError::Timeout(timeout)),
            }
        }
    }
}
