//! The permission policy.
//!
//! A [`Policy`] is the `[security]` baseline with one tool's `[tools.<name>]`
//! override layered on top. It is the single place that decides which paths,
//! programs, environment variables and network destinations a call may use,
//! how long it may run, and whether it may do something destructive, elevated
//! or networked. Tools never consult configuration directly: they receive the
//! capabilities this policy hands out through [`crate::ToolContext`].

mod command;
mod network;
mod path;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

pub use command::{CheckedCommand, CommandRules};
pub use network::{classify, AddressClass, NetworkRules};
pub use path::{CheckedPath, PathRules, Visibility};

pub(crate) use path::{normalize, open_root};

use crate::config::Config;
use crate::error::ToolError;

/// Facts about the running server that the policy needs but that are not part
/// of the configuration document.
#[derive(Debug, Clone, Default)]
pub struct PolicyEnv {
    /// Directory relative paths and patterns resolve against.
    pub working_dir: PathBuf,
    /// The configuration file in use. Tools may never read or write it: a
    /// hot-reloaded policy that the governed agent could edit is no policy.
    pub config_path: Option<PathBuf>,
    /// The `PATH` the server started with, used to resolve program names.
    pub search_path: Option<OsString>,
}

impl PolicyEnv {
    /// Capture the environment of the current process.
    #[must_use]
    pub fn current(working_dir: PathBuf, config_path: Option<PathBuf>) -> Self {
        Self {
            working_dir,
            config_path,
            search_path: std::env::var_os("PATH"),
        }
    }
}

/// Variables a caller may never set on a child process, whatever the
/// operator's scrub list says: each makes the dynamic loader run code of the
/// caller's choosing inside an otherwise allowed program.
const LOADER_VARIABLES: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_PROFILE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
];

/// Which environment variables reach child processes.
#[derive(Debug, Clone)]
pub struct EnvRules {
    scrub: GlobSet,
    passthrough: GlobSet,
}

impl EnvRules {
    fn build(scrub: &[String], passthrough: &[String]) -> Result<Self, ToolError> {
        let compile = |patterns: &[String]| -> Result<GlobSet, ToolError> {
            let mut b = GlobSetBuilder::new();
            for p in patterns {
                b.add(
                    GlobBuilder::new(p)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| {
                            ToolError::InvalidArguments(format!(
                                "invalid environment pattern '{p}': {e}"
                            ))
                        })?,
                );
            }
            b.build()
                .map_err(|e| ToolError::InvalidArguments(format!("environment patterns: {e}")))
        };
        Ok(Self {
            scrub: compile(scrub)?,
            passthrough: compile(passthrough)?,
        })
    }

    /// Whether a variable inherited from the server is withheld from children.
    #[must_use]
    pub fn is_scrubbed(&self, name: &str) -> bool {
        self.scrub.is_match(name) && !self.passthrough.is_match(name)
    }

    /// Reject a variable a caller asked to set on a child process.
    pub fn check_caller_variable(&self, name: &str) -> Result<(), ToolError> {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(ToolError::InvalidArguments(format!(
                "'{name}' is not a valid environment variable name"
            )));
        }
        if LOADER_VARIABLES.iter().any(|v| v.eq_ignore_ascii_case(name)) {
            return Err(ToolError::PermissionDenied(format!(
                "environment variable '{name}' changes which code a program loads and cannot \
                 be set by a caller"
            )));
        }
        Ok(())
    }
}

/// A fully resolved policy for a single tool.
#[derive(Debug, Clone)]
pub struct Policy {
    tool: String,
    paths: Arc<PathRules>,
    commands: Arc<CommandRules>,
    network: Arc<NetworkRules>,
    env: Arc<EnvRules>,
    working_dir: PathBuf,
    timeout: Duration,
    max_runtime: Duration,
    max_output_bytes: usize,
    max_walk_entries: usize,
    allow_elevated: bool,
    allow_network: bool,
    allow_destructive: bool,
}

impl Policy {
    /// Resolve the policy for `tool` from `config`.
    pub fn resolve(config: &Config, tool: &str, env: &PolicyEnv) -> Result<Self, ToolError> {
        let base = &config.security;
        let ov = config.tool_override(tool);

        let mut allowed_paths = base.allowed_paths.clone();
        let mut allowed_commands = base.allowed_commands.clone();
        let mut timeout_secs = base.default_timeout_secs;
        let mut max_output_bytes = base.max_output_bytes;
        let mut allow_destructive = base.allow_destructive;
        let mut allow_elevated = base.allow_elevated;
        let mut allow_network = base.allow_network;
        if let Some(o) = ov {
            if let Some(extra) = &o.allowed_paths {
                allowed_paths.extend(extra.iter().cloned());
            }
            if let Some(extra) = &o.allowed_commands {
                allowed_commands.extend(extra.iter().cloned());
            }
            timeout_secs = o.timeout_secs.unwrap_or(timeout_secs);
            max_output_bytes = o.max_output_bytes.unwrap_or(max_output_bytes);
            allow_destructive = o.allow_destructive.unwrap_or(allow_destructive);
            allow_elevated = o.allow_elevated.unwrap_or(allow_elevated);
            allow_network = o.allow_network.unwrap_or(allow_network);
        }

        let mut protected: Vec<PathBuf> = Vec::new();
        protected.extend(env.config_path.iter().cloned());
        protected.extend(config.logging.directory.iter().cloned());

        let max_runtime = Duration::from_secs(base.max_runtime_secs.max(1));
        Ok(Self {
            tool: tool.to_string(),
            paths: Arc::new(PathRules::build(
                &allowed_paths,
                &base.effective_denied_paths(),
                &protected,
                &env.working_dir,
            )?),
            commands: Arc::new(CommandRules::build(
                &allowed_commands,
                env.search_path.clone(),
            )),
            network: Arc::new(NetworkRules::build(
                base.allow_private_networks,
                &base.allowed_hosts,
                &base.denied_hosts,
            )),
            env: Arc::new(EnvRules::build(
                &base.effective_env_scrub(),
                &base.env_passthrough,
            )?),
            working_dir: env.working_dir.clone(),
            timeout: Duration::from_secs(timeout_secs.max(1)).min(max_runtime),
            max_runtime,
            max_output_bytes: max_output_bytes.max(1024),
            max_walk_entries: config.limits.max_walk_entries.max(1),
            allow_elevated,
            allow_network,
            allow_destructive,
        })
    }

    /// Compile the baseline and every per-tool override, so a bad pattern is
    /// found when the configuration is loaded rather than at first use.
    pub fn validate_config(config: &Config) -> Result<(), ToolError> {
        let env = PolicyEnv {
            working_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            ..PolicyEnv::default()
        };
        Self::resolve(config, "", &env)?;
        for tool in config.tools.keys() {
            Self::resolve(config, tool, &env).map_err(|e| {
                ToolError::InvalidArguments(format!("[tools.{tool}]: {e}"))
            })?;
        }
        Ok(())
    }

    /// Name of the tool this policy applies to.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Path rules.
    #[must_use]
    pub fn paths(&self) -> &Arc<PathRules> {
        &self.paths
    }

    /// Command rules.
    #[must_use]
    pub fn commands(&self) -> &Arc<CommandRules> {
        &self.commands
    }

    /// Network destination rules.
    #[must_use]
    pub fn network(&self) -> &Arc<NetworkRules> {
        &self.network
    }

    /// Environment rules.
    #[must_use]
    pub fn env(&self) -> &Arc<EnvRules> {
        &self.env
    }

    /// Directory relative paths resolve against.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// The default per-call timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The absolute runtime ceiling.
    #[must_use]
    pub fn max_runtime(&self) -> Duration {
        self.max_runtime
    }

    /// Timeout for a call: the caller's request if given, never more than the
    /// ceiling.
    #[must_use]
    pub fn effective_timeout(&self, requested_secs: Option<u64>) -> Duration {
        match requested_secs {
            Some(s) => Duration::from_secs(s.max(1)).min(self.max_runtime),
            None => self.timeout,
        }
    }

    /// Maximum captured output per stream, in bytes.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Maximum entries one directory walk may visit.
    #[must_use]
    pub fn max_walk_entries(&self) -> usize {
        self.max_walk_entries
    }

    /// Whether the network gate is open for this tool.
    #[must_use]
    pub fn allow_network(&self) -> bool {
        self.allow_network
    }

    /// Whether the destructive gate is open for this tool.
    #[must_use]
    pub fn allow_destructive(&self) -> bool {
        self.allow_destructive
    }

    /// Whether the elevation gate is open for this tool.
    #[must_use]
    pub fn allow_elevated(&self) -> bool {
        self.allow_elevated
    }

    /// Check and resolve a path argument.
    pub fn resolve_path(&self, path: &str) -> Result<CheckedPath, ToolError> {
        self.paths.resolve(Path::new(path), &self.working_dir)
    }

    /// Check and resolve a program argument. Relative program paths are
    /// relative to `cwd`.
    pub fn resolve_command(&self, program: &str, cwd: &Path) -> Result<CheckedCommand, ToolError> {
        self.commands.resolve(program, cwd)
    }

    /// Fail unless the network gate is open.
    pub fn require_network(&self) -> Result<(), ToolError> {
        if self.allow_network {
            Ok(())
        } else {
            Err(self.gate_closed("network access", "allow_network"))
        }
    }

    /// Fail unless the destructive gate is open. `what` names the operation.
    pub fn require_destructive(&self, what: &str) -> Result<(), ToolError> {
        if self.allow_destructive {
            Ok(())
        } else {
            Err(self.gate_closed(&format!("the destructive operation '{what}'"), "allow_destructive"))
        }
    }

    /// Fail unless the elevation gate is open. `what` names the operation.
    pub fn require_elevated(&self, what: &str) -> Result<(), ToolError> {
        if self.allow_elevated {
            Ok(())
        } else {
            Err(self.gate_closed(&format!("the elevated operation '{what}'"), "allow_elevated"))
        }
    }

    fn gate_closed(&self, what: &str, key: &str) -> ToolError {
        let scope = if self.tool.is_empty() {
            String::new()
        } else {
            format!(" or [tools.{}]", self.tool)
        };
        ToolError::PermissionDenied(format!(
            "{what} is disabled by policy; the operator can enable it with `{key} = true` under \
             [security]{scope}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(dir: &Path) -> PolicyEnv {
        PolicyEnv {
            working_dir: dir.to_path_buf(),
            config_path: None,
            search_path: std::env::var_os("PATH"),
        }
    }

    #[test]
    fn overrides_layer_on_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::from_toml_str(
            r#"
            [security]
            allowed_paths = ["."]
            default_timeout_secs = 30
            max_runtime_secs = 100

            [tools.fs_delete]
            allow_destructive = true
            timeout_secs = 500

            [tools.net_http_request]
            allow_network = true
            "#,
        )
        .unwrap();
        let base = Policy::resolve(&config, "fs_read", &env(dir.path())).unwrap();
        assert!(!base.allow_destructive());
        assert!(!base.allow_network());
        assert_eq!(base.timeout(), Duration::from_secs(30));
        assert!(base.require_destructive("delete").is_err());

        let del = Policy::resolve(&config, "fs_delete", &env(dir.path())).unwrap();
        assert!(del.require_destructive("delete").is_ok());
        // Clamped to the ceiling.
        assert_eq!(del.timeout(), Duration::from_secs(100));
        assert_eq!(del.effective_timeout(Some(5)), Duration::from_secs(5));
        assert_eq!(del.effective_timeout(Some(9999)), Duration::from_secs(100));

        let net = Policy::resolve(&config, "net.http_request", &env(dir.path())).unwrap();
        assert!(net.require_network().is_ok());
    }

    #[test]
    fn gate_errors_name_the_setting() {
        let dir = tempfile::tempdir().unwrap();
        let p = Policy::resolve(&Config::default(), "git_push", &env(dir.path())).unwrap();
        let msg = p.require_network().unwrap_err().to_string();
        assert!(msg.contains("allow_network") && msg.contains("[tools.git_push]"), "{msg}");
    }

    #[test]
    fn the_configuration_file_is_never_accessible() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("nebula-mcp.toml");
        std::fs::write(&cfg, "").unwrap();
        let config = Config::from_toml_str("[security]\nallowed_paths = [\".\"]\n").unwrap();
        let mut e = env(dir.path());
        e.config_path = Some(cfg);
        let p = Policy::resolve(&config, "fs_write", &e).unwrap();
        assert!(p.resolve_path("nebula-mcp.toml").is_err());
        assert!(p.resolve_path("other.toml").is_ok());
    }

    #[test]
    fn environment_rules_scrub_credentials_and_refuse_loader_variables() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            Config::from_toml_str("[security]\nenv_passthrough = [\"NPM_TOKEN\"]\n").unwrap();
        let p = Policy::resolve(&config, "terminal_run", &env(dir.path())).unwrap();
        let rules = p.env();
        for name in ["NEBULA_MCP_AUTH_TOKEN", "GITHUB_TOKEN", "gh_token", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"] {
            assert!(rules.is_scrubbed(name), "{name}");
        }
        for name in ["PATH", "HOME", "CARGO_HOME", "NPM_TOKEN", "LANG"] {
            assert!(!rules.is_scrubbed(name), "{name}");
        }
        assert!(rules.check_caller_variable("RUST_BACKTRACE").is_ok());
        assert!(rules.check_caller_variable("LD_PRELOAD").is_err());
        assert!(rules.check_caller_variable("dyld_insert_libraries").is_err());
        assert!(rules.check_caller_variable("A=B").is_err());
    }
}
