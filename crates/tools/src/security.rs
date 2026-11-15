//! Policy inspection: what the configuration would allow, without doing it.
//!
//! These tools answer from the same compiled policy the dispatcher enforces,
//! for any tool the caller names, so an agent can find out why something
//! would be refused before it tries.

use std::sync::{Arc, OnceLock, Weak};

use futures::future::BoxFuture;
use nebula_mcp_core::args::Args;
use nebula_mcp_core::policy::{expand_home, paths_equal};
use nebula_mcp_core::policy::{Access, Policy};
use nebula_mcp_core::process::Exec;
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{
    Category, Dispatcher, Effects, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::{json, Value};

use crate::common::{spec, tool, SpecExt};

/// Programs that run whatever they are given: allowing one allows anything.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "cmd",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "env",
    "xargs",
    "find",
    "awk",
    "make",
    "cargo",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "pip",
    "go",
    "git",
    "docker",
    "ssh",
    "sudo",
];

/// The running dispatcher, for the tools that inspect it.
#[derive(Default)]
pub(crate) struct Link(OnceLock<Weak<Dispatcher>>);

impl Link {
    pub(crate) fn attach(&self, dispatcher: &Arc<Dispatcher>) {
        let _ = self.0.set(Arc::downgrade(dispatcher));
    }

    fn get(&self) -> Result<Arc<Dispatcher>> {
        self.0
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| ToolError::Internal("the server is not running".to_string()))
    }
}

const TOOL_HELP: &str =
    "Answer for this tool (default: the baseline that applies to tools without overrides).";

fn verdict_schema(what: &str) -> Value {
    ObjectSchema::open()
        .boolean("allowed", "Whether policy allows it.", true)
        .nullable_string("reason", "Why not, when it is refused.", true)
        .nullable_string("resolved", what, true)
        .build()
}

type Inspector = fn(&ToolContext, &Dispatcher, Value) -> Result<ToolOutput>;

/// A handler that runs `f` against the running dispatcher.
fn bound(
    link: &Arc<Link>,
    f: Inspector,
) -> impl for<'a> Fn(&'a ToolContext, Value) -> BoxFuture<'a, Result<ToolOutput>> + Send + Sync + 'static
{
    let link = link.clone();
    move |ctx, args| {
        let link = link.clone();
        Box::pin(async move { f(ctx, &*link.get()?, args) })
    }
}

/// The `security` tools.
pub(crate) fn tools(link: &Arc<Link>) -> Vec<Arc<dyn Tool>> {
    let c = Category::Security;
    let bind = |f: Inspector| bound(link, f);
    vec![
        tool(
            spec(
                "security_check_path",
                c,
                "Would this path be allowed",
                "Dry run: would a file tool be allowed to read or write this path? Nothing is \
                 opened. Use it to find out why a path is refused.",
                ObjectSchema::new()
                    .string("path", "The path to test.", true)
                    .string_enum(
                        "access",
                        "Kind of access (default read).",
                        &["read", "write"],
                        false,
                    )
                    .string("tool", TOOL_HELP, false)
                    .build(),
                Effects::read_only(),
            )
            .returns(verdict_schema(
                "The path after symlink resolution, when allowed.",
            )),
            bind(check_path),
        ),
        tool(
            spec(
                "security_check_command",
                c,
                "Would this program be allowed",
                "Dry run: would terminal_run be allowed to start this program? Nothing is run. \
                 The answer names the executable file that would run.",
                ObjectSchema::new()
                    .string(
                        "program",
                        "Program name or path, as for terminal_run.",
                        true,
                    )
                    .string(
                        "tool",
                        "Answer for this tool (default terminal_run).",
                        false,
                    )
                    .build(),
                Effects::read_only(),
            )
            .returns(verdict_schema(
                "The executable that would run, when allowed.",
            )),
            bind(check_command),
        ),
        tool(
            spec(
                "security_effective_policy",
                c,
                "Show effective policy",
                "The limits in force for a tool: allowed directories and programs, network, \
                 destructive and elevated switches, timeouts, and whether the tool is exposed.",
                ObjectSchema::new().string("tool", TOOL_HELP, false).build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .nullable_string(
                        "tool",
                        "Tool the answer is for; null for the baseline.",
                        true,
                    )
                    .boolean("exposed", "Whether clients can call the tool.", true)
                    .string_array(
                        "allowedPaths",
                        "Directories file access is confined to.",
                        true,
                    )
                    .string_array(
                        "allowedCommands",
                        "Programs terminal tools may start; \"*\" is all.",
                        true,
                    )
                    .boolean("allowNetwork", "Whether network access is on.", true)
                    .boolean(
                        "allowPrivateNetwork",
                        "Whether private and loopback addresses are reachable.",
                        true,
                    )
                    .string_array(
                        "allowedHosts",
                        "Hosts the network is limited to; empty is any.",
                        true,
                    )
                    .boolean(
                        "allowDestructive",
                        "Whether destructive operations are permitted.",
                        true,
                    )
                    .boolean(
                        "allowElevated",
                        "Whether elevated operations are permitted.",
                        true,
                    )
                    .integer("timeoutSecs", "Default timeout of a call.", true)
                    .integer(
                        "maxRuntimeSecs",
                        "Ceiling a caller can raise the timeout to.",
                        true,
                    )
                    .integer("maxOutputBytes", "Bytes of output kept per stream.", true)
                    .string(
                        "sandbox",
                        "Operating-system confinement of child processes.",
                        true,
                    )
                    .string_array("categories", "Enabled tool categories.", true)
                    .build(),
            ),
            bind(effective_policy),
        ),
        tool(
            spec(
                "security_baseline",
                c,
                "Review configuration",
                "Review the server's configuration for settings that widen what an agent can \
                 do, such as an allow-all program list, interpreters, a broad directory or \
                 unconfined child processes. Read-only.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "findings",
                        "Settings worth a look, most serious first.",
                        ObjectSchema::open()
                            .string("level", "warning or note.", true)
                            .string("setting", "The configuration key.", true)
                            .string("message", "What it means.", true),
                        true,
                    )
                    .integer("warnings", "Number of findings at level warning.", true)
                    .build(),
            ),
            bind(baseline),
        ),
    ]
}

/// The policy for the tool named in `tool`, or the baseline.
fn policy_of(
    dispatcher: &Dispatcher,
    a: &Args<'_>,
    default: Option<&str>,
) -> Result<(Option<String>, Arc<Policy>)> {
    let name = a.opt_str("tool")?.or(default);
    let loaded = dispatcher.store().snapshot();
    match name {
        Some(name) => {
            if dispatcher.registry().get(name).is_none() {
                return Err(ToolError::invalid(format!(
                    "there is no tool named '{name}'"
                )));
            }
            Ok((Some(name.to_string()), loaded.policies.for_tool(name)))
        }
        // A name no tool has: the baseline without any override.
        None => Ok((None, loaded.policies.for_tool(""))),
    }
}

fn verdict(result: Result<String>, policy: &Policy, dispatcher: &Dispatcher) -> ToolOutput {
    ToolOutput::json(match result {
        Ok(resolved) => json!({"allowed": true, "reason": null, "resolved": resolved}),
        Err(error) => json!({
            "allowed": false,
            "reason": dispatcher.describe(&error, policy),
            "resolved": null,
        }),
    })
}

fn check_path(ctx: &ToolContext, dispatcher: &Dispatcher, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let (_, policy) = policy_of(dispatcher, &a, None)?;
    let access = match a.opt_enum("access", &["read", "write"])? {
        Some("write") => Access::Write,
        _ => Access::Read,
    };
    let result =
        nebula_mcp_core::fs::probe(policy.paths(), ctx.working_dir(), a.str("path")?, access);
    Ok(verdict(result, &policy, dispatcher))
}

fn check_command(ctx: &ToolContext, dispatcher: &Dispatcher, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let (name, policy) = policy_of(dispatcher, &a, Some("terminal_run"))?;
    let runs_caller_programs = name
        .as_deref()
        .and_then(|n| dispatcher.registry().get(n))
        .is_some_and(|t| matches!(t.spec().effects.exec, Exec::CallerChosen(_)));
    let result = if runs_caller_programs {
        policy
            .commands()
            .authorize(a.str("program")?, ctx.working_dir(), policy.paths())
            .map(|path| path.display().to_string())
    } else {
        Err(ToolError::invalid(format!(
            "{} does not run programs the caller chooses",
            name.as_deref().unwrap_or("that tool")
        )))
    };
    Ok(verdict(result, &policy, dispatcher))
}

fn effective_policy(_: &ToolContext, dispatcher: &Dispatcher, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let (name, policy) = policy_of(dispatcher, &a, None)?;
    let loaded = dispatcher.store().snapshot();
    let config = &loaded.config;
    let exposed = match name.as_deref().and_then(|n| dispatcher.registry().get(n)) {
        Some(t) => {
            let s = t.spec();
            s.platforms.includes_current() && config.is_tool_enabled(s.category.as_str(), s.name)
        }
        None => true,
    };
    let commands: Vec<String> = if policy.commands().allows_any() {
        vec!["*".to_string()]
    } else {
        policy
            .commands()
            .names()
            .iter()
            .cloned()
            .chain(
                policy
                    .commands()
                    .paths()
                    .iter()
                    .map(|p| p.display().to_string()),
            )
            .collect()
    };
    let roots: Vec<String> = policy
        .paths()
        .roots()
        .iter()
        .map(|r| r.path().display().to_string())
        .collect();
    Ok(ToolOutput::json(json!({
        "tool": name,
        "exposed": exposed,
        "allowedPaths": roots,
        "allowedCommands": commands,
        "allowNetwork": policy.net().enabled(),
        "allowPrivateNetwork": policy.net().allow_private(),
        "allowedHosts": config.security.allowed_hosts,
        "allowDestructive": policy.allow_destructive(),
        "allowElevated": policy.allow_elevated(),
        "timeoutSecs": policy.timeout().as_secs(),
        "maxRuntimeSecs": policy.max_runtime().as_secs(),
        "maxOutputBytes": policy.max_output_bytes(),
        "sandbox": format!("{:?}", policy.sandbox().mode).to_lowercase(),
        "categories": config.server.categories,
    })))
}

fn baseline(_: &ToolContext, dispatcher: &Dispatcher, _: Value) -> Result<ToolOutput> {
    let loaded = dispatcher.store().snapshot();
    let (config, policy) = (&loaded.config, loaded.policies.for_tool(""));
    let security = &config.security;
    let enabled = |category: Category| {
        config
            .server
            .categories
            .iter()
            .any(|c| c == category.as_str())
    };
    let runs_programs = enabled(Category::Terminal) || enabled(Category::Scheduler);
    let mut findings: Vec<(&str, &str, String)> = Vec::new();
    let mut warn =
        |setting: &'static str, message: String| findings.push(("warning", setting, message));

    if policy.commands().allows_any() {
        warn(
            "security.allowed_commands",
            "\"*\" allows every program: an agent with the terminal tools has the full \
             privileges of the server's user."
                .to_string(),
        );
    } else if runs_programs {
        let open: Vec<&str> = policy
            .commands()
            .names()
            .iter()
            .map(String::as_str)
            .filter(|n| INTERPRETERS.contains(n))
            .collect();
        if !open.is_empty() {
            warn(
                "security.allowed_commands",
                format!(
                    "{} can run arbitrary code, so allowing them is equivalent to allowing \
                     every program.",
                    open.join(", ")
                ),
            );
        }
    }
    for root in policy.paths().roots() {
        let path = root.path();
        if path.components().count() <= 2 || paths_equal(path, &expand_home("~")) {
            warn(
                "security.allowed_paths",
                format!(
                    "{} is very broad; allow project directories instead.",
                    path.display()
                ),
            );
        }
    }
    if !security.builtin_denied_paths {
        warn(
            "security.builtin_denied_paths",
            "the built-in protection of key and credential files is off.".to_string(),
        );
    }
    if security.allow_private_network {
        warn(
            "security.allow_private_network",
            "tools can reach loopback, private and link-local addresses, including services \
             that trust the local network."
                .to_string(),
        );
    }
    if security.allow_destructive {
        warn(
            "security.allow_destructive",
            "destructive operations are permitted for every tool; prefer [tools.<name>] \
             overrides."
                .to_string(),
        );
    }
    if security.allow_elevated {
        warn(
            "security.allow_elevated",
            "elevated operations are permitted for every tool.".to_string(),
        );
    }
    if enabled(Category::Docker) {
        warn(
            "server.categories",
            "docker is enabled: access to the Docker daemon is root-equivalent on most hosts."
                .to_string(),
        );
    }
    if enabled(Category::Powershell) {
        warn(
            "server.categories",
            "powershell is enabled: scripts run with the server user's privileges.".to_string(),
        );
    }
    let warnings = findings.len();
    let mut note =
        |setting: &'static str, message: String| findings.push(("note", setting, message));
    if runs_programs && !nebula_mcp_core::process::CONFINEMENT_AVAILABLE {
        note(
            "security.sandbox",
            "child processes are not confined by the operating system: a program an agent may \
             start can do whatever the server's user can."
                .to_string(),
        );
    }
    if security.allow_network && security.allowed_hosts.is_empty() {
        note(
            "security.allowed_hosts",
            "the network is on without a host list; any public host is reachable.".to_string(),
        );
    }
    for warning in loaded.policies.warnings() {
        note("configuration", warning.clone());
    }
    let findings: Vec<Value> = findings
        .into_iter()
        .map(|(level, setting, message)| json!({"level": level, "setting": setting, "message": message}))
        .collect();
    Ok(ToolOutput::json(
        json!({"findings": findings, "warnings": warnings}),
    ))
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
