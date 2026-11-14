//! Test support: every tool is driven through the real dispatcher, with a
//! temporary directory as the only allowed root.

#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nebula_mcp_core::config::Config;
use nebula_mcp_core::policy::{simplify, slash_string};
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{
    Call, CallFailure, ConfigStore, Dispatcher, OwnerId, ToolOutput, ToolRegistry,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub(crate) struct Kit {
    _tmp: tempfile::TempDir,
    /// The allowed root (canonical).
    pub root: PathBuf,
    /// A directory next to the root that policy does not allow.
    pub outside: PathBuf,
    pub dispatcher: Arc<Dispatcher>,
    pub state: crate::ToolState,
    pub shutdown: CancellationToken,
    categories: String,
}

impl Kit {
    /// A dispatcher with every category enabled and `root` allowed.
    /// `security` is appended to the `[security]` table.
    pub(crate) fn new(security: &str) -> Self {
        Self::build(None, security, "")
    }

    /// Like [`Kit::new`], with further TOML appended after `[security]`.
    pub(crate) fn with_config(security: &str, rest: &str) -> Self {
        Self::build(None, security, rest)
    }

    /// Like [`Kit::new`], with only the named categories enabled.
    pub(crate) fn with_categories(categories: &[&str], security: &str) -> Self {
        Self::build(Some(categories), security, "")
    }

    fn build(categories: Option<&[&str]>, security: &str, rest: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = simplify(&std::fs::canonicalize(tmp.path()).unwrap());
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let mut registry = ToolRegistry::new();
        let state = crate::register_all(&mut registry).unwrap();
        let categories: Vec<String> = match categories {
            Some(list) => list.iter().map(|c| format!("\"{c}\"")).collect(),
            None => registry
                .catalog()
                .categories
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect(),
        };
        let categories = categories.join(", ");
        let config = Self::config(&categories, &root, security, rest);
        config.validate(&registry.catalog()).unwrap();
        let shutdown = CancellationToken::new();
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(registry),
            ConfigStore::from_config(config).unwrap(),
            root.clone(),
            shutdown.clone(),
        ));
        state.start(&dispatcher, shutdown.clone());
        Self {
            _tmp: tmp,
            root,
            outside,
            dispatcher,
            state,
            shutdown,
            categories,
        }
    }

    fn config(categories: &str, root: &Path, security: &str, rest: &str) -> Config {
        let text = format!(
            "[server]\ncategories = [{categories}]\n[security]\nallowed_paths = [\"{}\"]\n\
             {security}\n{rest}\n",
            slash_string(root)
        );
        Config::from_toml_str(&text).unwrap()
    }

    /// Swap the live configuration, as a hot reload would.
    pub(crate) fn reconfigure(&self, security: &str) {
        let config = Self::config(&self.categories, &self.root, security, "");
        self.dispatcher.store().replace(config).unwrap();
    }

    pub(crate) fn request(name: &str, arguments: Value, owner: &OwnerId) -> Call {
        Call {
            name: name.to_string(),
            arguments,
            owner: owner.clone(),
            request_id: "test".into(),
            cancel: CancellationToken::new(),
            progress: None,
        }
    }

    /// Call a tool as the stdio owner.
    pub(crate) async fn call(&self, name: &str, arguments: Value) -> Result<ToolOutput, CallFailure> {
        self.call_as(&OwnerId::stdio(), name, arguments).await
    }

    /// Call a tool as `owner`. Successful structured results are checked
    /// against the tool's declared output schema.
    pub(crate) async fn call_as(
        &self,
        owner: &OwnerId,
        name: &str,
        arguments: Value,
    ) -> Result<ToolOutput, CallFailure> {
        let result = self
            .dispatcher
            .call(Self::request(name, arguments, owner))
            .await
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
        if let Ok(out) = &result {
            let spec = self.dispatcher.registry().get(name).unwrap().spec().clone();
            match (&spec.output, &out.structured) {
                (Some(schema), Some(value)) => {
                    nebula_mcp_core::schema::validate_as(
                        "result",
                        "the structured result",
                        schema,
                        value,
                    )
                    .unwrap_or_else(|e| panic!("{name} broke its output schema: {e}"));
                }
                (Some(_), None) => panic!("{name} declares an output schema but returned text"),
                (None, Some(_)) => panic!("{name} returned a record without an output schema"),
                (None, None) => {}
            }
        }
        result
    }

    /// Call a tool that must succeed.
    pub(crate) async fn ok(&self, name: &str, arguments: Value) -> ToolOutput {
        match self.call(name, arguments).await {
            Ok(out) => out,
            Err(f) => panic!("{name} failed: {}", f.text),
        }
    }

    /// Call a tool that must fail; returns the text shown to the model.
    pub(crate) async fn err(&self, name: &str, arguments: Value) -> String {
        match self.call(name, arguments).await {
            Ok(out) => panic!("{name} unexpectedly succeeded: {}", text_of(&out)),
            Err(f) => f.text,
        }
    }

    /// Call a tool that must succeed and return its structured result.
    pub(crate) async fn json(&self, name: &str, arguments: Value) -> Value {
        self.ok(name, arguments)
            .await
            .structured
            .expect("structured result")
    }

    /// A path under the root as the forward-slash string a caller would send.
    pub(crate) fn path(&self, rel: &str) -> String {
        slash_string(&self.root.join(rel))
    }

    pub(crate) fn write(&self, rel: &str, content: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub(crate) fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
    }

    pub(crate) fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).symlink_metadata().is_ok()
    }

    /// Wait for a file under the root to exist with content, and return it.
    pub(crate) async fn wait_for_file(&self, rel: &str) -> String {
        let path = self.root.join(rel);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if !text.trim().is_empty() {
                    return text;
                }
            }
            assert!(Instant::now() < deadline, "{rel} never appeared");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Kit {
    fn drop(&mut self) {
        // Stops jobs and sessions the test left behind.
        self.shutdown.cancel();
    }
}

/// All text blocks of a result joined with newlines.
pub(crate) fn text_of(out: &ToolOutput) -> String {
    out.content
        .iter()
        .filter_map(|c| match c {
            Content::Text(t) => Some(t.as_str()),
            Content::Image { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write a file outside the allowed root.
pub(crate) fn write_outside(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

/// Whether process `pid` is gone (or a zombie), polling for a while.
#[cfg(unix)]
pub(crate) async fn gone(pid: &str) -> bool {
    let pid = pid.trim().to_string();
    for _ in 0..100 {
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .expect("run ps");
        let stat = String::from_utf8_lossy(&out.stdout);
        let stat = stat.trim();
        if stat.is_empty() || stat.starts_with('Z') {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}
