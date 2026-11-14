//! Tool metadata, the [`Tool`] trait and the registry.
//!
//! A tool describes itself with a [`ToolSpec`]. The spec is not advisory: the
//! dispatcher enforces it (platform, schema, gates), the capabilities in
//! [`ToolContext`](crate::context::ToolContext) are limited by it (a tool that
//! declares itself read-only cannot obtain write access; a tool that declares
//! no programs cannot spawn any), and the annotations shown to clients are
//! derived from it rather than written by hand.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::config::{Catalog, Config};
use crate::context::ToolContext;
use crate::error::Result;
use crate::process::Exec;

/// Tool categories. A category is exposed only when the operator lists it in
/// `[server] categories`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Files and directories inside the allowed roots.
    Fs,
    /// Git repositories inside the allowed roots.
    Git,
    /// The GitHub API.
    Github,
    /// Running allowlisted programs.
    Terminal,
    /// Inspecting and signalling processes.
    Process,
    /// Network probes and HTTP requests.
    Net,
    /// Docker.
    Docker,
    /// Browser automation.
    Browser,
    /// Delayed and repeated commands.
    Scheduler,
    /// PowerShell scripts.
    Powershell,
    /// Windows services, registry, events and similar.
    Windows,
    /// Server self-diagnostics and Windows crash analysis.
    Diagnostics,
    /// Dry-run policy inspection.
    Security,
}

impl Category {
    /// Every category, in listing order.
    pub const ALL: [Category; 13] = [
        Category::Fs,
        Category::Git,
        Category::Github,
        Category::Terminal,
        Category::Process,
        Category::Net,
        Category::Docker,
        Category::Browser,
        Category::Scheduler,
        Category::Powershell,
        Category::Windows,
        Category::Diagnostics,
        Category::Security,
    ];

    /// The name used in configuration and as the tool-name prefix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Fs => "fs",
            Category::Git => "git",
            Category::Github => "github",
            Category::Terminal => "terminal",
            Category::Process => "process",
            Category::Net => "net",
            Category::Docker => "docker",
            Category::Browser => "browser",
            Category::Scheduler => "scheduler",
            Category::Powershell => "powershell",
            Category::Windows => "windows",
            Category::Diagnostics => "diagnostics",
            Category::Security => "security",
        }
    }

    /// What enabling the category grants, for operators.
    #[must_use]
    pub fn grants(self) -> &'static str {
        match self {
            Category::Fs => "read and write files inside allowed_paths",
            Category::Git => "run git in repositories inside allowed_paths",
            Category::Github => "call the GitHub API with the server's token",
            Category::Terminal => {
                "run programs from allowed_commands with the operator's privileges"
            }
            Category::Process => "list processes and signal the ones the server started",
            Category::Net => "make outbound network requests",
            Category::Docker => "control Docker, which is root-equivalent on most hosts",
            Category::Browser => "drive a headless browser",
            Category::Scheduler => "run programs from allowed_commands later or repeatedly",
            Category::Powershell => "run PowerShell scripts with the operator's privileges",
            Category::Windows => "inspect and change Windows services, registry and tasks",
            Category::Diagnostics => "inspect the server and analyse Windows crash dumps",
            Category::Security => "inspect the effective policy (no side effects)",
        }
    }
}

/// Operating systems a tool can run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platforms {
    /// Linux.
    pub linux: bool,
    /// macOS.
    pub macos: bool,
    /// Windows.
    pub windows: bool,
}

impl Platforms {
    /// Every supported platform.
    pub const ALL: Platforms = Platforms {
        linux: true,
        macos: true,
        windows: true,
    };
    /// Windows only.
    pub const WINDOWS: Platforms = Platforms {
        linux: false,
        macos: false,
        windows: true,
    };
    /// Linux and macOS.
    pub const UNIX: Platforms = Platforms {
        linux: true,
        macos: true,
        windows: false,
    };

    /// Whether the tool can run on the platform this binary was built for.
    #[must_use]
    pub fn includes_current(self) -> bool {
        if cfg!(windows) {
            self.windows
        } else if cfg!(target_os = "macos") {
            self.macos
        } else {
            self.linux
        }
    }
}

/// When a gated behaviour applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Never.
    Never,
    /// Depending on arguments; the tool calls the matching `require_*`.
    Sometimes,
    /// On every call; the dispatcher checks the gate before the tool runs.
    Always,
}

/// What a tool does to the world. Enforced, and the source of the
/// annotations sent to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effects {
    /// The tool changes nothing: no file writes, no state changes anywhere.
    pub read_only: bool,
    /// The tool can remove things or stop them: delete files, discard
    /// commits, kill processes. Gated by `allow_destructive`.
    pub destructive: Gate,
    /// The tool can replace the content of something that exists (rewrite a
    /// file, change a setting). Not gated, since any write can do it, but
    /// reported to clients as destructive.
    pub overwrites: bool,
    /// Repeating the call with the same arguments has no further effect.
    pub idempotent: bool,
    /// The tool reaches the network.
    pub network: bool,
    /// The tool interacts with things outside this machine and server.
    pub open_world: bool,
    /// The tool needs administrator / root rights.
    pub elevated: Gate,
    /// Programs the tool runs.
    pub exec: Exec,
}

impl Effects {
    /// A tool that only reads local state.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            read_only: true,
            destructive: Gate::Never,
            overwrites: false,
            idempotent: true,
            network: false,
            open_world: false,
            elevated: Gate::Never,
            exec: Exec::None,
        }
    }

    /// A tool that changes local state without destroying anything.
    #[must_use]
    pub const fn writes() -> Self {
        Self {
            read_only: false,
            destructive: Gate::Never,
            overwrites: false,
            idempotent: false,
            network: false,
            open_world: false,
            elevated: Gate::Never,
            exec: Exec::None,
        }
    }

    /// Set when the tool is destructive.
    #[must_use]
    pub const fn destructive(mut self, gate: Gate) -> Self {
        self.destructive = gate;
        self
    }

    /// Mark the tool idempotent (or not).
    #[must_use]
    pub const fn idempotent(mut self, yes: bool) -> Self {
        self.idempotent = yes;
        self
    }

    /// The tool can replace existing content.
    #[must_use]
    pub const fn overwrites(mut self) -> Self {
        self.overwrites = true;
        self
    }

    /// The tool reaches the network (implies open-world).
    #[must_use]
    pub const fn network(mut self) -> Self {
        self.network = true;
        self.open_world = true;
        self
    }

    /// The tool interacts with external systems without the server making a
    /// network connection itself (for example through a local daemon).
    #[must_use]
    pub const fn open_world(mut self) -> Self {
        self.open_world = true;
        self
    }

    /// Set when the tool needs elevation.
    #[must_use]
    pub const fn elevated(mut self, gate: Gate) -> Self {
        self.elevated = gate;
        self
    }

    /// Programs the tool runs.
    #[must_use]
    pub const fn exec(mut self, exec: Exec) -> Self {
        self.exec = exec;
        self
    }
}

/// Behaviour hints for clients, derived from [`Effects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Annotations {
    /// The tool does not modify its environment.
    pub read_only: bool,
    /// The tool may perform destructive updates.
    pub destructive: bool,
    /// Repeated identical calls have no additional effect.
    pub idempotent: bool,
    /// The tool interacts with external entities.
    pub open_world: bool,
}

/// Everything the server needs to know about a tool.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// Unique name, `<category>_<verb>` in lower snake case.
    pub name: &'static str,
    /// Category.
    pub category: Category,
    /// Short human-readable title.
    pub title: &'static str,
    /// What the tool does and when to use it, written for the model.
    pub description: &'static str,
    /// JSON Schema of the arguments; calls are validated against it.
    pub input: Value,
    /// JSON Schema of `structuredContent`, for tools that return records.
    pub output: Option<Value>,
    /// Effects.
    pub effects: Effects,
    /// Platforms the tool runs on.
    pub platforms: Platforms,
}

impl ToolSpec {
    /// The annotations clients see.
    #[must_use]
    pub fn annotations(&self) -> Annotations {
        let e = &self.effects;
        Annotations {
            read_only: e.read_only,
            destructive: !e.read_only && (e.destructive != Gate::Never || e.overwrites),
            idempotent: e.read_only || e.idempotent,
            open_world: e.open_world,
        }
    }
}

/// One piece of tool output.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// Text.
    Text(String),
    /// An image, base64-encoded.
    Image {
        /// Base64 data.
        data: String,
        /// MIME type, for example `image/png`.
        mime_type: String,
    },
}

/// What a tool returns on success.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ToolOutput {
    /// Content blocks for the model.
    pub content: Vec<Content>,
    /// Structured result, conforming to the tool's output schema.
    pub structured: Option<Value>,
}

impl ToolOutput {
    /// Plain text output.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text(text.into())],
            structured: None,
        }
    }

    /// A structured record. The same JSON is included as text for clients
    /// that do not read structured content.
    #[must_use]
    pub fn json(value: Value) -> Self {
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        Self {
            content: vec![Content::Text(text)],
            structured: Some(value),
        }
    }

    /// Append an image block.
    #[must_use]
    pub fn with_image(mut self, base64_data: String, mime_type: impl Into<String>) -> Self {
        self.content.push(Content::Image {
            data: base64_data,
            mime_type: mime_type.into(),
        });
        self
    }

    /// Total bytes of text content, for metrics.
    #[must_use]
    pub fn text_len(&self) -> u64 {
        self.content
            .iter()
            .map(|c| match c {
                Content::Text(t) => t.len() as u64,
                Content::Image { data, .. } => data.len() as u64,
            })
            .sum()
    }
}

/// A tool.
#[async_trait]
pub trait Tool: Send + Sync {
    /// The tool's metadata.
    fn spec(&self) -> &ToolSpec;

    /// Run the tool. `args` has already been validated against the input
    /// schema, and the gates marked [`Gate::Always`] have been checked.
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput>;
}

/// The set of registered tools.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Arc<dyn Tool>>,
}

impl ToolRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool. Fails on a duplicate or malformed definition, which
    /// is a programming error caught by the registry tests.
    pub fn register(&mut self, tool: Arc<dyn Tool>) -> std::result::Result<(), String> {
        let spec = tool.spec();
        check_spec(spec)?;
        let name = spec.name;
        if self.tools.insert(name, tool).is_some() {
            return Err(format!("duplicate tool name '{name}'"));
        }
        Ok(())
    }

    /// Number of registered tools on any platform.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(name)
    }

    /// Every registered tool, sorted by name.
    pub fn all(&self) -> impl Iterator<Item = &Arc<dyn Tool>> {
        self.tools.values()
    }

    /// The tools a client may see and call: enabled by `config` and able to
    /// run on this platform. Sorted by name, so listings are deterministic.
    pub fn exposed<'a>(&'a self, config: &'a Config) -> impl Iterator<Item = &'a Arc<dyn Tool>> {
        self.tools.values().filter(|t| {
            let spec = t.spec();
            spec.platforms.includes_current()
                && config.is_tool_enabled(spec.category.as_str(), spec.name)
        })
    }

    /// Names a configuration may refer to.
    #[must_use]
    pub fn catalog(&self) -> Catalog {
        Catalog {
            categories: Category::ALL
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            tools: self.tools.keys().map(|k| (*k).to_string()).collect(),
        }
    }
}

/// Longest tool name accepted. Some clients prefix names and cap the total.
pub const MAX_TOOL_NAME: usize = 32;

fn check_spec(spec: &ToolSpec) -> std::result::Result<(), String> {
    let name = spec.name;
    let valid_chars = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if name.is_empty() || name.len() > MAX_TOOL_NAME || !valid_chars {
        return Err(format!(
            "tool name '{name}' must be 1-{MAX_TOOL_NAME} characters of a-z, 0-9 and '_'"
        ));
    }
    let prefix = format!("{}_", spec.category.as_str());
    if !name.starts_with(&prefix) || name.len() == prefix.len() {
        return Err(format!("tool name '{name}' must start with '{prefix}'"));
    }
    if spec.title.trim().is_empty() || spec.description.trim().len() < 20 {
        return Err(format!(
            "tool '{name}' needs a title and a real description"
        ));
    }
    crate::schema::check_input_schema(&spec.input)
        .map_err(|e| format!("tool '{name}' input schema: {e}"))?;
    if let Some(out) = &spec.output {
        crate::schema::check_supported(out)
            .map_err(|e| format!("tool '{name}' output schema: {e}"))?;
        if out.get("type").and_then(Value::as_str) != Some("object") {
            return Err(format!("tool '{name}' output schema must be an object"));
        }
    }
    let e = &spec.effects;
    if e.read_only && (e.destructive != Gate::Never || e.overwrites || e.elevated == Gate::Always) {
        return Err(format!(
            "tool '{name}' is declared read-only but also destructive or always elevated"
        ));
    }
    if e.read_only && matches!(e.exec, Exec::CallerChosen(_)) {
        return Err(format!(
            "tool '{name}' runs caller-chosen programs and cannot be read-only"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Dummy(ToolSpec);

    #[async_trait]
    impl Tool for Dummy {
        fn spec(&self) -> &ToolSpec {
            &self.0
        }
        async fn call(&self, _ctx: &ToolContext, _args: Value) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

    fn spec(name: &'static str, category: Category) -> ToolSpec {
        ToolSpec {
            name,
            category,
            title: "Dummy",
            description: "A dummy tool used only by the registry tests.",
            input: json!({"type": "object", "properties": {}, "additionalProperties": false}),
            output: None,
            effects: Effects::read_only(),
            platforms: Platforms::ALL,
        }
    }

    #[test]
    fn exposure_follows_categories_tools_and_platform() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Dummy(spec("fs_read", Category::Fs))))
            .unwrap();
        reg.register(Arc::new(Dummy(spec("fs_delete", Category::Fs))))
            .unwrap();
        reg.register(Arc::new(Dummy(spec("git_status", Category::Git))))
            .unwrap();
        let mut other = spec("windows_env", Category::Windows);
        other.platforms = Platforms {
            linux: !cfg!(target_os = "linux"),
            macos: !cfg!(target_os = "macos"),
            windows: !cfg!(windows),
        };
        reg.register(Arc::new(Dummy(other))).unwrap();

        let config = Config::from_toml_str(
            "[server]\ncategories = [\"fs\", \"windows\"]\n[tools.fs_delete]\nenabled = false\n",
        )
        .unwrap();
        let names: Vec<_> = reg.exposed(&config).map(|t| t.spec().name).collect();
        assert_eq!(names, vec!["fs_read"]);
        assert!(reg.exposed(&Config::default()).next().is_none());
        assert_eq!(reg.len(), 4);
        assert!(reg.catalog().tools.contains(&"git_status".to_string()));
    }

    #[test]
    fn malformed_definitions_are_rejected() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Dummy(spec("fs_read", Category::Fs))))
            .unwrap();
        assert!(reg
            .register(Arc::new(Dummy(spec("fs_read", Category::Fs))))
            .is_err());
        assert!(reg
            .register(Arc::new(Dummy(spec("fs.read", Category::Fs))))
            .is_err());
        assert!(reg
            .register(Arc::new(Dummy(spec("read", Category::Fs))))
            .is_err());
        assert!(reg
            .register(Arc::new(Dummy(spec("git_x", Category::Fs))))
            .is_err());
        let mut lying = spec("fs_wipe", Category::Fs);
        lying.effects = Effects::read_only().destructive(Gate::Always);
        assert!(reg.register(Arc::new(Dummy(lying))).is_err());
    }

    #[test]
    fn annotations_are_derived_from_effects() {
        let mut s = spec("fs_read", Category::Fs);
        assert_eq!(
            s.annotations(),
            Annotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false
            }
        );
        s.effects = Effects::writes().destructive(Gate::Sometimes).network();
        let a = s.annotations();
        assert!(!a.read_only && a.destructive && !a.idempotent && a.open_world);
    }

    #[test]
    fn json_output_carries_text_and_structure() {
        let out = ToolOutput::json(json!({"a": 1}));
        assert_eq!(out.structured, Some(json!({"a": 1})));
        assert!(matches!(&out.content[0], Content::Text(t) if t.contains("\"a\": 1")));
    }
}
