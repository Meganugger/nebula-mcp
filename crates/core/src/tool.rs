//! The tool abstraction: what a tool declares about itself and what it
//! returns.
//!
//! A tool does not enforce its own policy. It declares, in its [`ToolSpec`],
//! the shape of its arguments, the gates it needs and the platforms it runs
//! on; [`crate::runtime::ToolRuntime`] validates and enforces all of that
//! before [`Tool::call`] runs. Inside `call`, files, processes and the network
//! are reachable only through the [`ToolContext`], which hands out nothing the
//! policy has not cleared.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::context::ToolContext;
use crate::error::{Result, ToolError};
use crate::exec::ExecOutput;
use crate::schema::{Args, Kind, ObjectSchema};

/// A capability the operator must switch on before a tool may use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Gate {
    /// Reaches the network (directly or through a program it runs).
    Network,
    /// Irreversibly discards data or state.
    Destructive,
    /// Needs administrator or root rights.
    Elevated,
}

impl Gate {
    /// The configuration key that opens this gate.
    #[must_use]
    pub fn config_key(self) -> &'static str {
        match self {
            Gate::Network => "allow_network",
            Gate::Destructive => "allow_destructive",
            Gate::Elevated => "allow_elevated",
        }
    }
}

/// Where a tool can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platforms {
    /// Every supported platform.
    All,
    /// Windows only.
    Windows,
    /// Unix-like systems only.
    Unix,
}

impl Platforms {
    /// Whether the running platform is included.
    #[must_use]
    pub fn includes_current(self) -> bool {
        match self {
            Platforms::All => true,
            Platforms::Windows => cfg!(windows),
            Platforms::Unix => cfg!(unix),
        }
    }

    /// Short label for documentation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Platforms::All => "all",
            Platforms::Windows => "windows",
            Platforms::Unix => "unix",
        }
    }
}

/// Everything a tool declares about itself.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    name: String,
    category: String,
    title: String,
    description: String,
    input: ObjectSchema,
    output: Option<Value>,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
    gates: Vec<Gate>,
    action_gates: Option<(String, BTreeMap<String, Vec<Gate>>)>,
    platforms: Platforms,
}

impl ToolSpec {
    /// Declare a tool. `description` is read by the model that decides
    /// whether and how to call the tool, so it should say what the tool does,
    /// when to use it, and what it returns.
    #[must_use]
    pub fn new(name: &str, category: &str, title: &str, description: &str, input: ObjectSchema) -> Self {
        Self {
            name: name.to_string(),
            category: category.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            input,
            output: None,
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
            gates: Vec::new(),
            action_gates: None,
            platforms: Platforms::All,
        }
    }

    /// The tool never changes anything.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// The tool can discard data even when no gate is involved (a hint for
    /// clients; gates imply it automatically).
    #[must_use]
    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    /// Calling the tool again with the same arguments changes nothing more.
    #[must_use]
    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    /// The tool interacts with things outside this machine.
    #[must_use]
    pub fn open_world(mut self) -> Self {
        self.open_world = true;
        self
    }

    /// Every call needs this gate.
    #[must_use]
    pub fn requires(mut self, gate: Gate) -> Self {
        if !self.gates.contains(&gate) {
            self.gates.push(gate);
        }
        self
    }

    /// The gates depend on the value of an enumerated argument. Every value
    /// the argument can take must be listed, so adding an action without
    /// classifying it is an error at start-up rather than a silent hole.
    #[must_use]
    pub fn action_gates(mut self, property: &str, table: &[(&str, &[Gate])]) -> Self {
        let map = table
            .iter()
            .map(|(value, gates)| ((*value).to_string(), gates.to_vec()))
            .collect();
        self.action_gates = Some((property.to_string(), map));
        self
    }

    /// Restrict the tool to some platforms. It is not listed, and cannot be
    /// called, anywhere else.
    #[must_use]
    pub fn platforms(mut self, platforms: Platforms) -> Self {
        self.platforms = platforms;
        self
    }

    /// Declare the JSON Schema of the structured result.
    #[must_use]
    pub fn output(mut self, schema: Value) -> Self {
        self.output = Some(schema);
        self
    }

    /// Tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Category, used by the enable switches.
    #[must_use]
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Human-readable title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Description for the model.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Argument schema.
    #[must_use]
    pub fn input(&self) -> &ObjectSchema {
        &self.input
    }

    /// Declared output schema, if any.
    #[must_use]
    pub fn output_schema(&self) -> Option<&Value> {
        self.output.as_ref()
    }

    /// Platforms the tool runs on.
    #[must_use]
    pub fn supported_platforms(&self) -> Platforms {
        self.platforms
    }

    /// Gates every call needs.
    #[must_use]
    pub fn static_gates(&self) -> &[Gate] {
        &self.gates
    }

    /// The per-action gate table, if the tool has one.
    #[must_use]
    pub fn action_gate_table(&self) -> Option<(&str, &BTreeMap<String, Vec<Gate>>)> {
        self.action_gates.as_ref().map(|(p, t)| (p.as_str(), t))
    }

    /// The gates a call with these arguments needs.
    #[must_use]
    pub fn gates_for(&self, args: &Args) -> Vec<Gate> {
        let mut gates = self.gates.clone();
        if let Some((property, table)) = &self.action_gates {
            let default = self
                .input
                .property(property)
                .and_then(|p| p.default.as_ref())
                .and_then(Value::as_str);
            if let Some(action) = args.opt_str(property).or(default) {
                for gate in table.get(action).into_iter().flatten() {
                    if !gates.contains(gate) {
                        gates.push(*gate);
                    }
                }
            }
        }
        gates
    }

    fn any_gate(&self, gate: Gate) -> bool {
        self.gates.contains(&gate)
            || self
                .action_gates
                .as_ref()
                .is_some_and(|(_, t)| t.values().any(|g| g.contains(&gate)))
    }

    /// Whether the tool never changes anything.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// The MCP annotation hints. All four are always stated, because the
    /// protocol's defaults for an absent hint assume the worst.
    #[must_use]
    pub fn annotations(&self) -> Value {
        json!({
            "title": self.title,
            "readOnlyHint": self.read_only,
            "destructiveHint": !self.read_only && (self.destructive || self.any_gate(Gate::Destructive)),
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world || self.any_gate(Gate::Network),
        })
    }

    /// Check the declaration for mistakes. Called when the tool is
    /// registered.
    pub fn check(&self) -> std::result::Result<(), String> {
        let valid_name = !self.name.is_empty()
            && self.name.len() <= 48
            && self.name.starts_with(|c: char| c.is_ascii_lowercase())
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid_name {
            return Err(format!(
                "tool name '{}' must be at most 48 characters of a-z, 0-9 and '_', starting with a letter",
                self.name
            ));
        }
        if self.description.trim().is_empty() || self.title.trim().is_empty() {
            return Err(format!("tool '{}' needs a title and a description", self.name));
        }
        if self.read_only && (self.destructive || self.any_gate(Gate::Destructive)) {
            return Err(format!(
                "tool '{}' is declared read-only but also destructive",
                self.name
            ));
        }
        if let Some((property, table)) = &self.action_gates {
            let Some(prop) = self.input.property(property) else {
                return Err(format!(
                    "tool '{}': action argument '{property}' is not declared",
                    self.name
                ));
            };
            let Kind::String { one_of: Some(values) } = &prop.kind else {
                return Err(format!(
                    "tool '{}': action argument '{property}' must be an enumerated string",
                    self.name
                ));
            };
            if !prop.required && prop.default.is_none() {
                return Err(format!(
                    "tool '{}': action argument '{property}' must be required or have a default",
                    self.name
                ));
            }
            for value in values {
                if !table.contains_key(value) {
                    return Err(format!(
                        "tool '{}': action '{value}' has no entry in the gate table",
                        self.name
                    ));
                }
            }
            for value in table.keys() {
                if !values.contains(value) {
                    return Err(format!(
                        "tool '{}': the gate table lists '{value}', which is not a value of '{property}'",
                        self.name
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What a tool call produced.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// The result as structured JSON (always an object).
    pub structured: Value,
    /// Text shown to the model. Defaults to the structured result, pretty
    /// printed.
    pub text: Option<String>,
    /// Whether the call failed in a way the model should react to.
    pub is_error: bool,
}

impl ToolOutput {
    /// A successful result.
    #[must_use]
    pub fn json(structured: Value) -> Self {
        Self {
            structured: into_object(structured),
            text: None,
            is_error: false,
        }
    }

    /// A result that reports a failure (for example a non-zero exit status)
    /// while still carrying structured detail.
    #[must_use]
    pub fn failed(structured: Value) -> Self {
        Self {
            structured: into_object(structured),
            text: None,
            is_error: true,
        }
    }

    /// The standard result of running a program.
    #[must_use]
    pub fn from_exec(command: &str, out: &ExecOutput) -> Self {
        let structured = json!({
            "command": command,
            "exitCode": out.exit_code,
            "success": out.success(),
            "timedOut": out.timed_out,
            "durationMs": u64::try_from(out.duration.as_millis()).unwrap_or(u64::MAX),
            "stdout": out.stdout,
            "stderr": out.stderr,
            "stdoutTruncated": out.stdout_truncated,
            "stderrTruncated": out.stderr_truncated,
        });
        if out.success() {
            Self::json(structured)
        } else {
            Self::failed(structured)
        }
    }

    /// The result for an error raised before or during the call.
    #[must_use]
    pub fn from_error(error: &ToolError) -> Self {
        Self {
            structured: json!({
                "error": { "category": error.category(), "message": error.to_string() }
            }),
            text: Some(format!("[{}] {error}", error.category())),
            is_error: true,
        }
    }

    /// The text block for the model.
    #[must_use]
    pub fn text_block(&self) -> String {
        match &self.text {
            Some(text) => text.clone(),
            None => serde_json::to_string_pretty(&self.structured)
                .unwrap_or_else(|_| self.structured.to_string()),
        }
    }
}

/// The JSON Schema of [`ToolOutput::from_exec`] results.
#[must_use]
pub fn exec_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The command line that was run."},
            "exitCode": {"type": ["integer", "null"], "description": "Exit status, or null if the process was killed."},
            "success": {"type": "boolean", "description": "True when the process exited with status 0."},
            "timedOut": {"type": "boolean", "description": "True when the process was killed at its time limit."},
            "durationMs": {"type": "integer"},
            "stdout": {"type": "string"},
            "stderr": {"type": "string"},
            "stdoutTruncated": {"type": "boolean", "description": "True when the middle of stdout was dropped."},
            "stderrTruncated": {"type": "boolean"}
        },
        "required": ["command", "exitCode", "success", "timedOut", "stdout", "stderr"]
    })
}

/// Structured results are always objects; anything else is wrapped.
fn into_object(value: Value) -> Value {
    if value.is_object() {
        value
    } else {
        json!({ "result": value })
    }
}

/// A capability the server exposes to clients.
#[async_trait]
pub trait Tool: Send + Sync + 'static {
    /// The tool's declaration. Called once, at registration.
    fn spec(&self) -> ToolSpec;

    /// Run the tool. `args` has been validated against the declared schema,
    /// and the gates the declaration names for these arguments are open.
    async fn call(&self, ctx: &ToolContext, args: Args) -> Result<ToolOutput>;
}

/// A registered tool.
#[derive(Clone)]
pub(crate) enum Entry {
    Current {
        spec: Arc<ToolSpec>,
        input_schema: Arc<Value>,
        tool: Arc<dyn Tool>,
    },
    Legacy(Arc<dyn crate::legacy::Tool>),
}

/// How a tool appears in a listing.
#[derive(Debug, Clone)]
pub struct ToolListing {
    /// Tool name.
    pub name: String,
    /// Category.
    pub category: String,
    /// Human-readable title.
    pub title: String,
    /// Description for the model.
    pub description: String,
    /// JSON Schema of the arguments.
    pub input_schema: Value,
    /// JSON Schema of the structured result, if declared.
    pub output_schema: Option<Value>,
    /// MCP annotation hints.
    pub annotations: Value,
    /// Platforms the tool runs on.
    pub platforms: Platforms,
    /// Gates every call needs.
    pub gates: Vec<Gate>,
    /// Per-action gates, if any: the argument name and its table.
    pub action_gates: Option<(String, BTreeMap<String, Vec<Gate>>)>,
}

/// The set of tools a server provides. Immutable once built.
#[derive(Default)]
pub struct ToolRegistry {
    entries: BTreeMap<String, Entry>,
}

impl ToolRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool. Panics if its declaration is inconsistent or its name
    /// is taken: both are programming errors that must not reach a release.
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        let spec = tool.spec();
        if let Err(problem) = spec.check() {
            panic!("invalid tool declaration: {problem}");
        }
        let name = spec.name().to_string();
        let entry = Entry::Current {
            input_schema: Arc::new(spec.input().to_json_schema()),
            spec: Arc::new(spec),
            tool,
        };
        if self.entries.insert(name.clone(), entry).is_some() {
            panic!("duplicate tool registration: {name}");
        }
    }

    /// Register a tool written against the old API.
    pub fn register_legacy(&mut self, tool: Arc<dyn crate::legacy::Tool>) {
        let name = crate::config::canonical_tool_name(tool.name());
        if self.entries.insert(name.clone(), Entry::Legacy(tool)).is_some() {
            panic!("duplicate tool registration: {name}");
        }
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Entry> {
        self.entries
            .get(name)
            .or_else(|| self.entries.get(&crate::config::canonical_tool_name(name)))
    }

    /// Every registered tool, in name order, whatever the platform or
    /// configuration.
    #[must_use]
    pub fn listings(&self) -> Vec<ToolListing> {
        self.entries
            .iter()
            .map(|(name, entry)| match entry {
                Entry::Current {
                    spec, input_schema, ..
                } => ToolListing {
                    name: name.clone(),
                    category: spec.category().to_string(),
                    title: spec.title().to_string(),
                    description: spec.description().to_string(),
                    input_schema: (**input_schema).clone(),
                    output_schema: spec.output_schema().cloned(),
                    annotations: spec.annotations(),
                    platforms: spec.supported_platforms(),
                    gates: spec.static_gates().to_vec(),
                    action_gates: spec
                        .action_gate_table()
                        .map(|(p, t)| (p.to_string(), t.clone())),
                },
                Entry::Legacy(tool) => ToolListing {
                    name: name.clone(),
                    category: tool.category().to_string(),
                    title: name.clone(),
                    description: tool.description().to_string(),
                    input_schema: tool.input_schema(),
                    output_schema: None,
                    annotations: tool
                        .annotations()
                        .and_then(|a| serde_json::to_value(a).ok())
                        .unwrap_or_else(|| json!({})),
                    platforms: Platforms::All,
                    gates: Vec::new(),
                    action_gates: None,
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ToolSpec {
        ToolSpec::new(
            "svc_control",
            "services",
            "Control a service",
            "Start, stop or remove a service.",
            ObjectSchema::new()
                .enumerated("action", "What to do.", &["status", "stop", "remove"], true)
                .string("name", "Service name.", true),
        )
        .action_gates(
            "action",
            &[
                ("status", &[]),
                ("stop", &[Gate::Destructive]),
                ("remove", &[Gate::Destructive, Gate::Elevated]),
            ],
        )
    }

    fn args(spec: &ToolSpec, value: Value) -> Args {
        spec.input().validate(value).unwrap()
    }

    #[test]
    fn gates_follow_the_action() {
        let s = spec();
        assert!(s.check().is_ok());
        assert!(s.gates_for(&args(&s, json!({"action": "status", "name": "x"}))).is_empty());
        assert_eq!(
            s.gates_for(&args(&s, json!({"action": "remove", "name": "x"}))),
            vec![Gate::Destructive, Gate::Elevated]
        );
    }

    #[test]
    fn an_unclassified_action_is_a_declaration_error() {
        let s = ToolSpec::new(
            "svc_control",
            "services",
            "Control a service",
            "Start or stop.",
            ObjectSchema::new().enumerated("action", "What.", &["status", "stop", "purge"], true),
        )
        .action_gates("action", &[("status", &[]), ("stop", &[Gate::Destructive])]);
        assert!(s.check().unwrap_err().contains("purge"));
    }

    #[test]
    fn annotations_state_every_hint_and_follow_the_gates() {
        let a = spec().annotations();
        assert_eq!(a["readOnlyHint"], false);
        assert_eq!(a["destructiveHint"], true);
        assert_eq!(a["openWorldHint"], false);
        assert_eq!(a["idempotentHint"], false);

        let reader = ToolSpec::new("x_read", "x", "Read", "Reads.", ObjectSchema::new())
            .read_only()
            .requires(Gate::Network);
        let a = reader.annotations();
        assert_eq!(a["readOnlyHint"], true);
        assert_eq!(a["destructiveHint"], false);
        assert_eq!(a["openWorldHint"], true);
    }

    #[test]
    fn inconsistent_declarations_are_rejected() {
        let bad = ToolSpec::new("x", "x", "X", "X.", ObjectSchema::new())
            .read_only()
            .requires(Gate::Destructive);
        assert!(bad.check().is_err());
        for name in ["fs.read", "Fs_read", "", "9lives", "has space"] {
            let s = ToolSpec::new(name, "x", "X", "X.", ObjectSchema::new());
            assert!(s.check().is_err(), "{name}");
        }
    }

    #[test]
    fn exec_results_are_errors_unless_the_program_succeeded() {
        let out = ExecOutput {
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "boom".into(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            duration: std::time::Duration::from_millis(5),
        };
        let result = ToolOutput::from_exec("git status", &out);
        assert!(result.is_error);
        assert_eq!(result.structured["exitCode"], 1);
        assert!(result.text_block().contains("boom"));
    }
}
