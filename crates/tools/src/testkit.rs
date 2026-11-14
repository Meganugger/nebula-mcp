//! Test support: every tool is driven through the real dispatcher, with a
//! temporary directory as the only allowed root.

#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

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
}

impl Kit {
    /// A dispatcher with every category enabled and `root` allowed.
    /// `security` is appended to the `[security]` table.
    pub(crate) fn new(security: &str) -> Self {
        Self::with_config(security, "")
    }

    /// Like [`Kit::new`], with further TOML appended after `[security]`.
    pub(crate) fn with_config(security: &str, rest: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = simplify(&std::fs::canonicalize(tmp.path()).unwrap());
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let mut registry = ToolRegistry::new();
        crate::register_all(&mut registry).unwrap();
        let categories: Vec<String> = registry
            .catalog()
            .categories
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect();
        let text = format!(
            "[server]\ncategories = [{}]\n[security]\nallowed_paths = [\"{}\"]\n{security}\n{rest}\n",
            categories.join(", "),
            slash_string(&root)
        );
        let config = Config::from_toml_str(&text).unwrap();
        config.validate(&registry.catalog()).unwrap();
        let dispatcher = Dispatcher::new(
            Arc::new(registry),
            ConfigStore::from_config(config).unwrap(),
            root.clone(),
            CancellationToken::new(),
        );
        Self {
            _tmp: tmp,
            root,
            outside,
            dispatcher: Arc::new(dispatcher),
        }
    }

    pub(crate) fn request(name: &str, arguments: Value) -> Call {
        Call {
            name: name.to_string(),
            arguments,
            owner: OwnerId::stdio(),
            request_id: "test".into(),
            cancel: CancellationToken::new(),
            progress: None,
        }
    }

    /// Call a tool. Successful structured results are checked against the
    /// tool's declared output schema.
    pub(crate) async fn call(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<ToolOutput, CallFailure> {
        let result = self
            .dispatcher
            .call(Self::request(name, arguments))
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
