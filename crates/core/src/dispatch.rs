//! The dispatcher: the one place a tool call passes through.
//!
//! Every `tools/call`, from any transport and protocol revision, goes through
//! [`Dispatcher::call`]. In order it:
//!
//! 1. resolves the tool from one configuration snapshot and refuses tools
//!    that are not exposed or cannot run on this platform;
//! 2. validates the arguments against the tool's schema;
//! 3. checks the gates the tool's metadata declares;
//! 4. bounds concurrency and queueing;
//! 5. runs the tool with capabilities limited to what it declared, isolating
//!    panics, enforcing the runtime ceiling and honouring cancellation;
//! 6. guarantees that when the call ends, for any reason, its cancellation
//!    token fires so nothing it started is left running.
//!
//! Tool authors cannot skip any of this: a tool only ever sees the
//! [`ToolContext`] built here.

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::context::{ContextParts, OwnerId, ProgressSink, ToolContext};
use crate::error::ToolError;
use crate::metrics::{Metrics, Outcome};
use crate::policy::Policy;
use crate::store::ConfigStore;
use crate::tool::{Gate, Tool, ToolOutput, ToolRegistry};

/// How long a cancelled or timed-out tool gets to stop its work before its
/// future is dropped (which kills whatever it still has running).
const WIND_DOWN: Duration = Duration::from_secs(6);

/// One tool invocation.
pub struct Call {
    /// Tool name.
    pub name: String,
    /// Arguments object (`null` is treated as `{}`).
    pub arguments: Value,
    /// Owner of long-lived state the call creates.
    pub owner: OwnerId,
    /// Correlation id for logs.
    pub request_id: String,
    /// Cancelled by the transport on client cancel or disconnect.
    pub cancel: CancellationToken,
    /// Where progress goes, when the client asked for it.
    pub progress: Option<ProgressSink>,
}

/// The call named a tool that does not exist or is not exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTool {
    /// Message for the client.
    pub message: String,
}

/// A failed tool call, ready to show to the model.
#[derive(Debug, Clone)]
pub struct CallFailure {
    /// The error.
    pub error: ToolError,
    /// `[category] message` plus guidance on how to correct the call.
    pub text: String,
}

/// Runs tool calls.
pub struct Dispatcher {
    registry: Arc<ToolRegistry>,
    store: ConfigStore,
    metrics: Metrics,
    working_dir: PathBuf,
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
    shutdown: CancellationToken,
}

impl Dispatcher {
    /// Create a dispatcher. `shutdown` cancels every running call.
    #[must_use]
    pub fn new(
        registry: Arc<ToolRegistry>,
        store: ConfigStore,
        working_dir: PathBuf,
        shutdown: CancellationToken,
    ) -> Self {
        let slots = store.snapshot().config.server.max_concurrent_calls.max(1);
        // Relative paths are joined to this directory and then compared with
        // the canonical roots, so it has to be canonical itself.
        let working_dir = std::fs::canonicalize(&working_dir)
            .map_or(working_dir, |c| crate::policy::simplify(&c));
        Self {
            registry,
            store,
            metrics: Metrics::new(),
            working_dir,
            permits: Arc::new(Semaphore::new(slots)),
            waiting: AtomicUsize::new(0),
            shutdown,
        }
    }

    /// The tool registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<ToolRegistry> {
        &self.registry
    }

    /// The configuration store.
    #[must_use]
    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    /// Call metrics.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn working_dir(&self) -> &std::path::Path {
        &self.working_dir
    }

    /// The token that stops everything at shutdown.
    #[must_use]
    pub fn shutdown_token(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// The tools exposed under the current configuration, sorted by name.
    #[must_use]
    pub fn exposed(&self) -> Vec<Arc<dyn Tool>> {
        let loaded = self.store.snapshot();
        self.registry.exposed(&loaded.config).cloned().collect()
    }

    /// Run one tool call.
    ///
    /// `Err(UnknownTool)` is a protocol-level failure. Otherwise the inner
    /// result is the tool's outcome, to be reported to the model.
    pub async fn call(&self, call: Call) -> Result<Result<ToolOutput, CallFailure>, UnknownTool> {
        let loaded = self.store.snapshot();
        let tool = self.lookup(&call.name, &loaded.config)?;
        let policy = loaded.policies.for_tool(&call.name);
        let span =
            tracing::info_span!("tool_call", tool = %call.name, request_id = %call.request_id);
        let started = Instant::now();

        let name = call.name.clone();
        let result = self
            .run(tool, policy.clone(), loaded.config.clone(), call)
            .instrument(span)
            .await;

        let elapsed = started.elapsed();
        let (outcome, bytes) = match &result {
            Ok(out) => (Outcome::Success, out.text_len()),
            Err(ToolError::Cancelled | ToolError::Timeout(_)) => (Outcome::Cancelled, 0),
            Err(_) => (Outcome::Failure, 0),
        };
        self.metrics.record(&name, outcome, elapsed, bytes);
        match &result {
            Ok(_) => tracing::info!(
                tool = %name,
                elapsed_ms = elapsed.as_millis() as u64,
                "tool call succeeded"
            ),
            Err(e) => tracing::info!(
                tool = %name,
                elapsed_ms = elapsed.as_millis() as u64,
                category = e.category(),
                denied = e.is_denial(),
                "tool call failed"
            ),
        }
        Ok(result.map_err(|error| CallFailure {
            text: self.describe(&error, &policy),
            error,
        }))
    }

    fn lookup(
        &self,
        name: &str,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn Tool>, UnknownTool> {
        let Some(tool) = self.registry.get(name) else {
            return Err(UnknownTool {
                message: format!("unknown tool '{name}'"),
            });
        };
        let spec = tool.spec();
        if !spec.platforms.includes_current() {
            return Err(UnknownTool {
                message: format!("tool '{name}' is not available on this platform"),
            });
        }
        if !config.is_tool_enabled(spec.category.as_str(), spec.name) {
            return Err(UnknownTool {
                message: format!("tool '{name}' is not enabled on this server"),
            });
        }
        Ok(tool.clone())
    }

    async fn run(
        &self,
        tool: Arc<dyn Tool>,
        policy: Arc<Policy>,
        config: Arc<crate::config::Config>,
        call: Call,
    ) -> Result<ToolOutput, ToolError> {
        let spec = tool.spec();
        let mut arguments = match call.arguments {
            Value::Null => Value::Object(serde_json::Map::new()),
            other => other,
        };
        drop_optional_nulls(&spec.input, &mut arguments);
        crate::schema::validate(&spec.input, &arguments).map_err(ToolError::InvalidArguments)?;

        if spec.effects.network {
            policy.require_network()?;
        }
        if spec.effects.destructive == Gate::Always {
            policy.require_destructive(spec.title)?;
        }
        if spec.effects.elevated == Gate::Always {
            policy.require_elevated(spec.title)?;
        }

        // The call's own token: cancelled by the client, by shutdown, and
        // always when this function returns or is dropped.
        let cancel = call.cancel.child_token();
        let _stop_on_exit = cancel.clone().drop_guard();
        let shutdown = self.shutdown.clone();

        let _permit = self.acquire(&config, &cancel).await?;

        let ctx = ToolContext::new(ContextParts {
            policy: policy.clone(),
            effects: spec.effects,
            config,
            working_dir: self.working_dir.clone(),
            cancel: cancel.clone(),
            owner: call.owner,
            request_id: call.request_id,
            progress: call.progress,
            metrics: self.metrics.clone(),
        });

        let ceiling = policy.max_runtime();
        let work = AssertUnwindSafe(tool.call(&ctx, arguments)).catch_unwind();
        tokio::pin!(work);

        let flatten = |r: std::thread::Result<Result<ToolOutput, ToolError>>| match r {
            Ok(inner) => inner,
            Err(panic) => {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                tracing::error!(tool = spec.name, panic = %what, "tool panicked");
                Err(ToolError::Internal(
                    "the tool failed unexpectedly; the server is still running".to_string(),
                ))
            }
        };

        tokio::select! {
            biased;
            r = &mut work => flatten(r),
            () = cancel.cancelled() => {
                let _ = tokio::time::timeout(WIND_DOWN, &mut work).await;
                Err(ToolError::Cancelled)
            }
            () = shutdown.cancelled() => {
                cancel.cancel();
                let _ = tokio::time::timeout(WIND_DOWN, &mut work).await;
                Err(ToolError::Cancelled)
            }
            () = tokio::time::sleep(ceiling) => {
                cancel.cancel();
                let _ = tokio::time::timeout(WIND_DOWN, &mut work).await;
                Err(ToolError::Timeout(ceiling))
            }
        }
    }

    /// Wait for an execution slot. Bounded: beyond `max_queued_calls`
    /// waiters the call is refused, and a waiting call can be cancelled.
    async fn acquire(
        &self,
        config: &crate::config::Config,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ToolError> {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Ok(permit);
        }
        let max_waiting = config.server.max_queued_calls;
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= max_waiting {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(ToolError::LimitExceeded(format!(
                "the server is running {} calls with {max_waiting} more queued; retry shortly",
                config.server.max_concurrent_calls
            )));
        }
        // Released on every exit, including when this future is dropped
        // while it waits.
        struct Waiting<'a>(&'a AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _waiting = Waiting(&self.waiting);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ToolError::Cancelled),
            () = self.shutdown.cancelled() => Err(ToolError::Cancelled),
            permit = self.permits.clone().acquire_owned() => {
                permit.map_err(|_| ToolError::Cancelled)
            }
        }
    }

    /// Render an error for the model: the stable category, the message, and
    /// what the policy would have accepted.
    #[must_use]
    pub fn describe(&self, error: &ToolError, policy: &Policy) -> String {
        let mut text = format!("[{}] {error}", error.category());
        match error {
            ToolError::PathNotAllowed { .. } => {
                let roots: Vec<String> = policy
                    .paths()
                    .roots()
                    .iter()
                    .map(|r| r.path().display().to_string())
                    .collect();
                if roots.is_empty() {
                    text.push_str("\nNo directories are allowed on this server.");
                } else {
                    text.push_str(&format!(
                        "\nAllowed directories: {}. Relative paths resolve against {}.",
                        roots.join(", "),
                        self.working_dir.display()
                    ));
                }
            }
            ToolError::CommandNotAllowed(_) => {
                let commands = policy.commands();
                if commands.is_empty() {
                    text.push_str("\nNo commands are allowed on this server.");
                } else {
                    let mut allowed: Vec<String> = commands.names().to_vec();
                    allowed.extend(commands.paths().iter().map(|p| p.display().to_string()));
                    text.push_str(&format!("\nAllowed commands: {}.", allowed.join(", ")));
                }
            }
            _ => {}
        }
        text
    }
}

/// Remove top-level arguments sent as `null` for optional properties whose
/// schema does not accept `null`. Many clients serialise an omitted optional
/// argument that way, and the typed accessors already read `null` as absent.
fn drop_optional_nulls(schema: &Value, arguments: &mut Value) {
    let Some(args) = arguments.as_object_mut() else {
        return;
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let accepts_null = |name: &str| {
        let Some(prop) = schema.get("properties").and_then(|p| p.get(name)) else {
            // Undeclared: leave it for the validator to report.
            return true;
        };
        match prop.get("type") {
            Some(Value::String(t)) => t == "null",
            Some(Value::Array(types)) => types.iter().any(|t| t == "null"),
            _ => true,
        }
    };
    args.retain(|name, value| {
        !value.is_null() || required.contains(&name.as_str()) || accepts_null(name)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::error::Result;
    use crate::tool::{Category, Effects, Platforms, ToolSpec};
    use async_trait::async_trait;
    use serde_json::json;

    enum Behaviour {
        Echo,
        Panic,
        Sleep,
        WriteWhileReadOnly,
        NetWithoutDeclaring,
        SetFlagOnCancel(Arc<std::sync::atomic::AtomicBool>),
    }

    struct Probe {
        spec: ToolSpec,
        behaviour: Behaviour,
    }

    #[async_trait]
    impl Tool for Probe {
        fn spec(&self) -> &ToolSpec {
            &self.spec
        }
        async fn call(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
            match &self.behaviour {
                Behaviour::Echo => Ok(ToolOutput::json(args)),
                Behaviour::Panic => panic!("boom"),
                Behaviour::Sleep => {
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(600)) => {}
                        () = ctx.cancel().cancelled() => return Err(ToolError::Cancelled),
                    }
                    Ok(ToolOutput::text("late"))
                }
                Behaviour::WriteWhileReadOnly => {
                    ctx.write_path("x.txt")?;
                    Ok(ToolOutput::text("wrote"))
                }
                Behaviour::NetWithoutDeclaring => {
                    ctx.net()?;
                    Ok(ToolOutput::text("connected"))
                }
                Behaviour::SetFlagOnCancel(flag) => {
                    ctx.cancel().cancelled().await;
                    flag.store(true, Ordering::SeqCst);
                    Err(ToolError::Cancelled)
                }
            }
        }
    }

    fn probe(name: &'static str, effects: Effects, behaviour: Behaviour) -> Arc<dyn Tool> {
        Arc::new(Probe {
            spec: ToolSpec {
                name,
                category: Category::Fs,
                title: "Probe",
                description: "A probe tool used by the dispatcher tests.",
                input: json!({
                    "type": "object",
                    "properties": {"n": {"type": "integer", "description": "A number."}},
                    "additionalProperties": false
                }),
                output: None,
                effects,
                platforms: Platforms::ALL,
            },
            behaviour,
        })
    }

    fn dispatcher(config: &str, tools: Vec<Arc<dyn Tool>>) -> Dispatcher {
        let mut registry = ToolRegistry::new();
        for t in tools {
            registry.register(t).unwrap();
        }
        let dir = std::env::temp_dir();
        let config = Config::from_toml_str(&format!(
            "[server]\ncategories = [\"fs\"]\n[security]\nallowed_paths = [\"{}\"]\n{config}",
            dir.display().to_string().replace('\\', "/")
        ))
        .unwrap();
        Dispatcher::new(
            Arc::new(registry),
            ConfigStore::from_config(config).unwrap(),
            dir,
            CancellationToken::new(),
        )
    }

    fn call(name: &str, arguments: Value) -> Call {
        Call {
            name: name.to_string(),
            arguments,
            owner: OwnerId::stdio(),
            request_id: "r1".into(),
            cancel: CancellationToken::new(),
            progress: None,
        }
    }

    #[tokio::test]
    async fn arguments_are_validated_before_the_tool_runs() {
        let d = dispatcher(
            "",
            vec![probe("fs_echo", Effects::read_only(), Behaviour::Echo)],
        );
        let ok = d.call(call("fs_echo", json!({"n": 1}))).await.unwrap();
        assert_eq!(ok.unwrap().structured, Some(json!({"n": 1})));
        assert!(d.call(call("fs_echo", Value::Null)).await.unwrap().is_ok());
        // An optional argument sent as null is read as absent.
        let ok = d.call(call("fs_echo", json!({"n": null}))).await.unwrap();
        assert_eq!(ok.unwrap().structured, Some(json!({})));

        for bad in [json!({"n": "one"}), json!({"m": 1}), json!([1])] {
            let failure = d.call(call("fs_echo", bad)).await.unwrap().unwrap_err();
            assert!(matches!(failure.error, ToolError::InvalidArguments(_)));
            assert!(failure.text.starts_with("[invalid_arguments]"));
        }
    }

    #[tokio::test]
    async fn unknown_and_unexposed_tools_are_protocol_errors() {
        let d = dispatcher(
            "[tools.fs_off]\nenabled = false\n",
            vec![probe("fs_off", Effects::read_only(), Behaviour::Echo)],
        );
        assert!(d.call(call("fs_missing", json!({}))).await.is_err());
        let e = d.call(call("fs_off", json!({}))).await.unwrap_err();
        assert!(e.message.contains("not enabled"));
        assert!(d.exposed().is_empty());
    }

    #[tokio::test]
    async fn a_panicking_tool_fails_only_its_own_call() {
        let d = dispatcher(
            "",
            vec![
                probe("fs_panic", Effects::read_only(), Behaviour::Panic),
                probe("fs_echo", Effects::read_only(), Behaviour::Echo),
            ],
        );
        let failure = d
            .call(call("fs_panic", json!({})))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(failure.error, ToolError::Internal(_)));
        assert!(!failure.text.contains("boom"), "panic text must not leak");
        assert!(d.call(call("fs_echo", json!({}))).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn declared_gates_are_checked_by_the_dispatcher() {
        let d = dispatcher(
            "",
            vec![
                probe("fs_net", Effects::read_only().network(), Behaviour::Echo),
                probe(
                    "fs_wipe",
                    Effects::writes().destructive(Gate::Always),
                    Behaviour::Echo,
                ),
                probe(
                    "fs_admin",
                    Effects::writes().elevated(Gate::Always),
                    Behaviour::Echo,
                ),
            ],
        );
        for name in ["fs_net", "fs_wipe", "fs_admin"] {
            let failure = d.call(call(name, json!({}))).await.unwrap().unwrap_err();
            assert!(
                matches!(failure.error, ToolError::PermissionDenied(_)),
                "{name}: {failure:?}"
            );
        }
        let d = dispatcher(
            "allow_network = true\nallow_destructive = true\nallow_elevated = true\n",
            vec![probe(
                "fs_wipe",
                Effects::writes().destructive(Gate::Always),
                Behaviour::Echo,
            )],
        );
        assert!(d.call(call("fs_wipe", json!({}))).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn capabilities_are_limited_to_what_the_tool_declared() {
        let d = dispatcher(
            "allow_network = true\n",
            vec![
                probe(
                    "fs_sneaky",
                    Effects::read_only(),
                    Behaviour::WriteWhileReadOnly,
                ),
                probe(
                    "fs_dial",
                    Effects::read_only(),
                    Behaviour::NetWithoutDeclaring,
                ),
            ],
        );
        for name in ["fs_sneaky", "fs_dial"] {
            let failure = d.call(call(name, json!({}))).await.unwrap().unwrap_err();
            assert!(matches!(failure.error, ToolError::Internal(_)), "{name}");
        }
    }

    #[tokio::test]
    async fn the_runtime_ceiling_ends_a_call() {
        let d = dispatcher(
            "max_runtime_secs = 1\n",
            vec![probe("fs_sleep", Effects::read_only(), Behaviour::Sleep)],
        );
        let failure = d
            .call(call("fs_sleep", json!({})))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(failure.error, ToolError::Timeout(_)));
    }

    #[tokio::test]
    async fn cancellation_reaches_the_tool_and_ends_the_call() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = dispatcher(
            "",
            vec![probe(
                "fs_wait",
                Effects::read_only(),
                Behaviour::SetFlagOnCancel(flag.clone()),
            )],
        );
        let c = call("fs_wait", json!({}));
        let cancel = c.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });
        let failure = d.call(c).await.unwrap().unwrap_err();
        assert!(matches!(failure.error, ToolError::Cancelled));
        assert!(flag.load(Ordering::SeqCst), "the tool saw the cancellation");
    }

    #[tokio::test]
    async fn dropping_a_call_cancels_what_it_started() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::new(tokio::sync::Notify::new());
        struct Leaky(
            ToolSpec,
            Arc<std::sync::atomic::AtomicBool>,
            Arc<tokio::sync::Notify>,
        );
        #[async_trait]
        impl Tool for Leaky {
            fn spec(&self) -> &ToolSpec {
                &self.0
            }
            async fn call(&self, ctx: &ToolContext, _args: Value) -> Result<ToolOutput> {
                let (token, flag, seen) = (ctx.cancel().clone(), self.1.clone(), self.2.clone());
                // Background work must stop when the call goes away.
                tokio::spawn(async move {
                    token.cancelled().await;
                    flag.store(true, Ordering::SeqCst);
                    seen.notify_one();
                });
                tokio::time::sleep(Duration::from_secs(600)).await;
                Ok(ToolOutput::text("never"))
            }
        }
        let spec = probe("fs_leak", Effects::read_only(), Behaviour::Echo)
            .spec()
            .clone();
        let d = dispatcher(
            "",
            vec![Arc::new(Leaky(spec, flag.clone(), observed.clone()))],
        );
        let fut = d.call(call("fs_leak", json!({})));
        let _ = tokio::time::timeout(Duration::from_millis(100), fut).await;
        tokio::time::timeout(Duration::from_secs(5), observed.notified())
            .await
            .expect("background work was not cancelled");
        assert!(flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn queueing_is_bounded_and_cancellable() {
        let d = Arc::new(dispatcher(
            "",
            vec![probe("fs_sleep", Effects::read_only(), Behaviour::Sleep)],
        ));
        // Shrink the limits through a config with one slot and one waiter.
        let mut cfg = (*d.store().snapshot().config).clone();
        cfg.server.max_concurrent_calls = 1;
        cfg.server.max_queued_calls = 1;
        let d = Arc::new(Dispatcher::new(
            d.registry().clone(),
            ConfigStore::from_config(cfg).unwrap(),
            std::env::temp_dir(),
            CancellationToken::new(),
        ));

        let running = call("fs_sleep", json!({}));
        let running_cancel = running.cancel.clone();
        let d1 = d.clone();
        let first = tokio::spawn(async move { d1.call(running).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let queued = call("fs_sleep", json!({}));
        let queued_cancel = queued.cancel.clone();
        let d2 = d.clone();
        let second = tokio::spawn(async move { d2.call(queued).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let refused = d
            .call(call("fs_sleep", json!({})))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(refused.error, ToolError::LimitExceeded(_)));

        queued_cancel.cancel();
        let second = second.await.unwrap().unwrap().unwrap_err();
        assert!(matches!(second.error, ToolError::Cancelled));
        running_cancel.cancel();
        let first = first.await.unwrap().unwrap().unwrap_err();
        assert!(matches!(first.error, ToolError::Cancelled));
    }

    #[tokio::test]
    async fn denials_explain_what_is_allowed() {
        let d = dispatcher(
            "",
            vec![probe("fs_echo", Effects::read_only(), Behaviour::Echo)],
        );
        let policy = d.store().snapshot().policies.for_tool("fs_echo");
        let text = d.describe(
            &ToolError::PathNotAllowed {
                path: "/etc/passwd".into(),
            },
            &policy,
        );
        assert!(text.starts_with("[path_not_allowed]"));
        assert!(text.contains("Allowed directories:"));
        let text = d.describe(&ToolError::CommandNotAllowed("rm".into()), &policy);
        assert!(text.contains("No commands are allowed"));
    }
}
