//! TOML configuration.
//!
//! Sections:
//!
//! * `[server]`    – identity, concurrency and which tool categories are exposed.
//! * `[logging]`   – log sinks and verbosity.
//! * `[security]`  – the permission baseline every tool call is checked against.
//! * `[limits]`    – resource ceilings for long-lived state.
//! * `[transport]` – the HTTP transport and its authentication.
//! * `[github]`    – the GitHub API endpoint and where its token comes from.
//! * `[tools.<name>]` – per-tool overrides layered on the baseline.
//!
//! Unknown keys are errors: a typo in a switch that is meant to restrict
//! something must not silently leave it open.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A configuration error, worded for the operator.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Root configuration document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Server identity and tool exposure.
    pub server: ServerConfig,
    /// Logging and telemetry.
    pub logging: LoggingConfig,
    /// Permission baseline.
    pub security: SecurityConfig,
    /// Resource ceilings.
    pub limits: LimitsConfig,
    /// Transports.
    pub transport: TransportConfig,
    /// The GitHub API used by the `github` tools.
    pub github: GithubConfig,
    /// Per-tool overrides keyed by tool name (for example `fs_delete`).
    pub tools: BTreeMap<String, ToolOverride>,
}

/// Server identity and exposure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Advertised server name.
    pub name: String,
    /// Replaces the built-in instructions shown to the model, when set.
    pub instructions: Option<String>,
    /// Tool categories exposed to clients. Nothing is exposed unless listed.
    pub categories: Vec<String>,
    /// Tool calls executing at once.
    pub max_concurrent_calls: usize,
    /// Tool calls allowed to wait for a slot; further calls are refused.
    pub max_queued_calls: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "nebula-mcp".to_string(),
            instructions: None,
            categories: Vec::new(),
            max_concurrent_calls: 16,
            max_queued_calls: 64,
        }
    }
}

/// Logging / telemetry section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Verbosity: `error`, `warn`, `info`, `debug` or `trace`.
    pub level: String,
    /// Output format for the file sink.
    pub format: LogFormat,
    /// Directory for rotating log files. Unset disables file logs.
    pub directory: Option<PathBuf>,
    /// Log file name prefix.
    pub file_prefix: String,
    /// Rotation cadence for file logs.
    pub rotation: LogRotation,
    /// OTLP endpoint for trace export (needs the `otel` build feature).
    pub otel_endpoint: Option<String>,
    /// Log a per-tool metrics summary at shutdown.
    pub emit_metrics: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            directory: None,
            file_prefix: "nebula-mcp".to_string(),
            rotation: LogRotation::Daily,
            otel_endpoint: None,
            emit_metrics: true,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Structured JSON, one object per line.
    Json,
    /// Human-readable.
    Pretty,
}

/// Rotation cadence for the rolling file appender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// Rotate every minute.
    Minutely,
    /// Rotate hourly.
    Hourly,
    /// Rotate daily.
    Daily,
    /// Never rotate.
    Never,
}

/// Permission baseline. Every tool call is checked against it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Directories tools may work in. Empty denies all file access. Each
    /// entry is a directory; everything beneath it, and the directory itself,
    /// is allowed. `~` expands to the home directory.
    pub allowed_paths: Vec<String>,
    /// Extra glob patterns denied for all access, added to the built-in set.
    pub denied_paths: Vec<String>,
    /// Extra glob patterns that may be read but not written.
    pub read_only_paths: Vec<String>,
    /// Keep the built-in deny patterns for credentials and keys.
    pub builtin_denied_paths: bool,
    /// Programs the arbitrary-execution tools may run: bare names resolved
    /// on the server's `PATH`, or absolute paths. `"*"` allows everything.
    pub allowed_commands: Vec<String>,
    /// Environment variable names (globs) passed to child processes in
    /// addition to the built-in base set.
    pub env_passthrough: Vec<String>,
    /// Environment variable names (globs) a caller may set on a child.
    pub caller_env: Vec<String>,
    /// Default per-call timeout in seconds.
    pub default_timeout_secs: u64,
    /// Ceiling for any single call, in seconds.
    pub max_runtime_secs: u64,
    /// Maximum bytes returned per output stream or file read.
    pub max_output_bytes: usize,
    /// Allow tools that reach the network.
    pub allow_network: bool,
    /// When non-empty, the only hosts network tools may contact (exact
    /// names or `*.example.com`).
    pub allowed_hosts: Vec<String>,
    /// Allow loopback, private, link-local and other non-public addresses.
    pub allow_private_network: bool,
    /// Allow destructive operations.
    pub allow_destructive: bool,
    /// Allow operations that need administrator / root rights.
    pub allow_elevated: bool,
    /// Operating-system confinement of spawned processes.
    pub sandbox: SandboxConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            read_only_paths: Vec::new(),
            builtin_denied_paths: true,
            allowed_commands: Vec::new(),
            env_passthrough: Vec::new(),
            caller_env: Vec::new(),
            default_timeout_secs: 120,
            max_runtime_secs: 3600,
            max_output_bytes: 1024 * 1024,
            allow_network: false,
            allowed_hosts: Vec::new(),
            allow_private_network: false,
            allow_destructive: false,
            allow_elevated: false,
            sandbox: SandboxConfig::default(),
        }
    }
}

/// Operating-system confinement of spawned processes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    /// `off`, `auto` (confine when the platform supports it) or `require`
    /// (refuse to spawn when it does not).
    pub mode: SandboxMode,
    /// Extra directories children may read, beyond the allowed roots and the
    /// system directories.
    pub read_paths: Vec<String>,
    /// Extra directories children may write, beyond the allowed roots and
    /// the temp directory.
    pub write_paths: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::Off,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
        }
    }
}

/// How spawned processes are confined by the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    /// No OS confinement.
    Off,
    /// Confine when supported, otherwise run unconfined with a warning.
    Auto,
    /// Confine, and refuse to spawn where confinement is unavailable.
    Require,
}

/// Where the `github` tools find the GitHub API and its token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GithubConfig {
    /// Base URL of the REST API. Change it for GitHub Enterprise Server.
    pub api_url: String,
    /// Name of the server's environment variable that holds the token. The
    /// token itself never belongs in this file.
    pub token_env: String,
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.github.com".to_string(),
            token_env: "GITHUB_TOKEN".to_string(),
        }
    }
}

impl GithubConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let url = &self.api_url;
        let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| url.starts_with(p));
        let rest = url.split_once("://").map_or("", |(_, r)| r);
        if !(url.starts_with("https://") || loopback)
            || rest.is_empty()
            || rest.contains(['@', '?', '#', ' '])
            || url.ends_with('/')
        {
            return Err(ConfigError::new(
                "[github] api_url must be an https:// URL without credentials, query or \
                 trailing slash, for example https://api.github.com or \
                 https://github.example.com/api/v3",
            ));
        }
        let name = &self.token_env;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ConfigError::new(
                "[github] token_env must be the name of an environment variable",
            ));
        }
        Ok(())
    }
}

/// Resource ceilings for state that outlives a single call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest accepted JSON-RPC message on stdio, in bytes.
    pub max_message_bytes: usize,
    /// Interactive terminal sessions per client.
    pub max_terminal_sessions: usize,
    /// Seconds an idle terminal session is kept.
    pub terminal_session_idle_secs: u64,
    /// Scheduled jobs per client.
    pub max_scheduled_jobs: usize,
    /// Resource subscriptions per client.
    pub max_subscriptions: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: 4 * 1024 * 1024,
            max_terminal_sessions: 8,
            terminal_session_idle_secs: 1800,
            max_scheduled_jobs: 16,
            max_subscriptions: 64,
        }
    }
}

/// How the server is exposed to clients.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Streamable HTTP transport. Disabled by default.
    pub http: HttpConfig,
}

/// Configuration for the Streamable HTTP transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Enable the HTTP transport.
    pub enabled: bool,
    /// Socket address to bind.
    pub bind: String,
    /// The MCP endpoint path.
    pub path: String,
    /// The URL clients use to reach the endpoint through a tunnel or proxy,
    /// for example `https://mcp.example.com/mcp`. Required for OAuth.
    pub public_url: Option<String>,
    /// Static bearer tokens accepted in `Authorization: Bearer <token>`.
    pub auth_tokens: Vec<String>,
    /// Require authentication on every request.
    pub require_auth: bool,
    /// `Origin` values allowed for browser clients (exact match).
    pub allowed_origins: Vec<String>,
    /// Extra `Host` values accepted besides loopback names and the host of
    /// `public_url`.
    pub allowed_hosts: Vec<String>,
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
    /// Seconds between keep-alive comments on event streams. `0` disables.
    pub sse_keep_alive_secs: u64,
    /// Simultaneous connections.
    pub max_connections: usize,
    /// Seconds allowed for a client to send its request headers and body.
    pub read_timeout_secs: u64,
    /// Legacy protocol sessions kept at once.
    pub max_sessions: usize,
    /// Seconds an idle legacy session is kept.
    pub session_idle_secs: u64,
    /// OAuth 2.1 authorization for clients that cannot send a static token.
    pub oauth: OAuthConfig,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8765".to_string(),
            path: "/mcp".to_string(),
            public_url: None,
            auth_tokens: Vec::new(),
            require_auth: true,
            allowed_origins: Vec::new(),
            allowed_hosts: Vec::new(),
            max_body_bytes: 4 * 1024 * 1024,
            sse_keep_alive_secs: 20,
            max_connections: 64,
            read_timeout_secs: 30,
            max_sessions: 64,
            session_idle_secs: 3600,
            oauth: OAuthConfig::default(),
        }
    }
}

/// Embedded single-operator OAuth 2.1 authorization server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    /// Serve the OAuth endpoints and accept tokens they issue.
    pub enabled: bool,
    /// The secret the operator types on the consent page to approve a client.
    pub approval_secret: Option<String>,
    /// Lifetime of an access token, in seconds.
    pub access_token_ttl_secs: u64,
    /// Lifetime of a refresh token, in seconds.
    pub refresh_token_ttl_secs: u64,
    /// File where registered clients and refresh tokens persist across
    /// restarts. Unset keeps them in memory only.
    pub state_file: Option<PathBuf>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            approval_secret: None,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 30 * 24 * 3600,
            state_file: None,
        }
    }
}

/// Per-tool override. Unset fields fall back to `[security]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolOverride {
    /// Disable (or explicitly enable) this tool within an enabled category.
    pub enabled: Option<bool>,
    /// Default timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Maximum output bytes.
    pub max_output_bytes: Option<usize>,
    /// Additional allowed directories for this tool.
    pub allowed_paths: Option<Vec<String>>,
    /// Additional allowed commands for this tool.
    pub allowed_commands: Option<Vec<String>>,
    /// Network gate for this tool.
    pub allow_network: Option<bool>,
    /// Destructive gate for this tool.
    pub allow_destructive: Option<bool>,
    /// Elevation gate for this tool.
    pub allow_elevated: Option<bool>,
}

/// The names a configuration may refer to, supplied by the tool registry.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Every category name.
    pub categories: Vec<String>,
    /// Every tool name.
    pub tools: Vec<String>,
}

impl Config {
    /// Parse a config document, rejecting unknown keys and explaining keys
    /// that existed before 0.2.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        if let Ok(raw) = toml::from_str::<toml::Value>(text) {
            if let Some(msg) = legacy_key_message(&raw) {
                return Err(ConfigError::new(msg));
            }
        }
        toml::from_str(text).map_err(|e| ConfigError::new(format!("invalid configuration: {e}")))
    }

    /// Load a config document from disk.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(format!("reading {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    /// Serialise this config to TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| ConfigError::new(format!("serialising configuration: {e}")))
    }

    /// This configuration as TOML with every secret replaced, fit to show to
    /// an operator or a client.
    pub fn to_redacted_toml(&self) -> Result<String, ConfigError> {
        let mut copy = self.clone();
        for token in &mut copy.transport.http.auth_tokens {
            *token = "<redacted>".to_string();
        }
        if let Some(secret) = &mut copy.transport.http.oauth.approval_secret {
            *secret = "<redacted>".to_string();
        }
        copy.to_toml_string()
    }

    /// Check names against the registry and values against their ranges.
    /// Returns warnings; an `Err` means the config must not be used.
    pub fn validate(&self, catalog: &Catalog) -> Result<Vec<String>, ConfigError> {
        let mut warnings = Vec::new();
        for c in &self.server.categories {
            if !catalog.categories.iter().any(|k| k == c) {
                return Err(ConfigError::new(format!(
                    "[server] categories: unknown category '{c}'. Known categories: {}",
                    catalog.categories.join(", ")
                )));
            }
        }
        for name in self.tools.keys() {
            if !catalog.tools.iter().any(|t| t == name) {
                let hint = if name.contains('.') {
                    format!(
                        " Tool names use underscores since 0.2: '{}'.",
                        name.replace('.', "_")
                    )
                } else {
                    String::new()
                };
                return Err(ConfigError::new(format!(
                    "[tools.{name}]: unknown tool '{name}'.{hint}"
                )));
            }
        }
        let enabled = |name: &str| self.server.categories.iter().any(|c| c == name);
        if enabled("scheduler") && !enabled("terminal") {
            return Err(ConfigError::new(
                "[server] categories: scheduler needs terminal as well, because a scheduled job \
                 runs as a terminal_run call",
            ));
        }
        let s = &self.security;
        if s.default_timeout_secs == 0 || s.max_runtime_secs == 0 {
            return Err(ConfigError::new(
                "[security] default_timeout_secs and max_runtime_secs must be at least 1",
            ));
        }
        if s.max_output_bytes < 1024 {
            return Err(ConfigError::new(
                "[security] max_output_bytes must be at least 1024",
            ));
        }
        if self.server.max_concurrent_calls == 0 {
            return Err(ConfigError::new(
                "[server] max_concurrent_calls must be at least 1",
            ));
        }
        match self.logging.level.to_ascii_lowercase().as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            other => {
                return Err(ConfigError::new(format!(
                    "[logging] level '{other}' is not one of error, warn, info, debug, trace"
                )))
            }
        }
        self.github.validate()?;
        let http = &self.transport.http;
        if !http.path.starts_with('/') {
            return Err(ConfigError::new(
                "[transport.http] path must start with '/'",
            ));
        }
        if http.oauth.enabled {
            if http.public_url.is_none() {
                return Err(ConfigError::new(
                    "[transport.http.oauth] enabled needs [transport.http] public_url, the URL \
                     clients use to reach this server",
                ));
            }
            match &http.oauth.approval_secret {
                Some(secret) if secret.len() >= 16 => {}
                _ => {
                    return Err(ConfigError::new(
                        "[transport.http.oauth] enabled needs approval_secret of at least 16 \
                         characters",
                    ))
                }
            }
        }
        for token in &http.auth_tokens {
            if token.len() < 16 {
                return Err(ConfigError::new(
                    "[transport.http] auth_tokens entries must be at least 16 characters",
                ));
            }
        }

        if self.server.categories.is_empty() {
            warnings.push(
                "[server] categories is empty: no tools are exposed. List the categories to \
                 enable, for example categories = [\"fs\", \"git\"]."
                    .to_string(),
            );
        }
        if s.allowed_commands.iter().any(|c| c == "*") {
            warnings.push(
                "[security] allowed_commands contains \"*\": every program on this machine may \
                 be run by the connected agent with your privileges."
                    .to_string(),
            );
        }
        if !s.builtin_denied_paths {
            warnings.push(
                "[security] builtin_denied_paths = false: credential and key files inside \
                 allowed directories are readable by tools."
                    .to_string(),
            );
        }
        if s.max_runtime_secs < s.default_timeout_secs {
            warnings.push(
                "[security] max_runtime_secs is below default_timeout_secs; calls are cut at \
                 max_runtime_secs."
                    .to_string(),
            );
        }
        if s.allow_elevated && s.allow_destructive {
            warnings.push(
                "[security] allow_elevated and allow_destructive are both on globally; prefer \
                 per-tool overrides under [tools.<name>]."
                    .to_string(),
            );
        }
        Ok(warnings)
    }

    /// Whether `tool` in `category` is exposed.
    #[must_use]
    pub fn is_tool_enabled(&self, category: &str, tool: &str) -> bool {
        if !self.server.categories.iter().any(|c| c == category) {
            return false;
        }
        self.tools.get(tool).and_then(|o| o.enabled).unwrap_or(true)
    }
}

/// Explain keys that were valid in 0.1 so an old config fails with guidance
/// instead of a bare "unknown field".
fn legacy_key_message(raw: &toml::Value) -> Option<String> {
    if raw.get("categories").is_some() {
        return Some(
            "[categories.<name>] was replaced in 0.2: list the categories to expose as \
             [server] categories = [\"fs\", \"git\", ...]. Categories not listed are off."
                .to_string(),
        );
    }
    if raw.get("server").and_then(|s| s.get("version")).is_some() {
        return Some(
            "[server] version was removed in 0.2: the server always reports its own version."
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog {
            categories: vec!["fs".into(), "git".into()],
            tools: vec!["fs_read".into(), "fs_delete".into()],
        }
    }

    #[test]
    fn defaults_allow_nothing() {
        let c = Config::default();
        assert!(c.server.categories.is_empty());
        assert!(c.security.allowed_paths.is_empty());
        assert!(c.security.allowed_commands.is_empty());
        assert!(!c.security.allow_network);
        assert!(!c.security.allow_private_network);
        assert!(!c.security.allow_elevated);
        assert!(!c.security.allow_destructive);
        assert!(c.security.builtin_denied_paths);
        assert!(!c.is_tool_enabled("fs", "fs_read"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml_str("[security]\nallow_netwrok = false\n").unwrap_err();
        assert!(err.0.contains("allow_netwrok"), "{err}");
        let err = Config::from_toml_str("[sever]\nname = \"x\"\n").unwrap_err();
        assert!(err.0.contains("sever"), "{err}");
        let err = Config::from_toml_str("[tools.fs_read]\nenabeld = false\n").unwrap_err();
        assert!(err.0.contains("enabeld"), "{err}");
    }

    #[test]
    fn legacy_keys_get_migration_guidance() {
        let err = Config::from_toml_str("[categories.powershell]\nenabled = false\n").unwrap_err();
        assert!(err.0.contains("[server] categories"), "{err}");
    }

    #[test]
    fn categories_are_opt_in_and_tools_can_be_disabled() {
        let c = Config::from_toml_str(
            "[server]\ncategories = [\"fs\"]\n[tools.fs_delete]\nenabled = false\n",
        )
        .unwrap();
        assert!(c.is_tool_enabled("fs", "fs_read"));
        assert!(!c.is_tool_enabled("fs", "fs_delete"));
        assert!(!c.is_tool_enabled("git", "git_status"));
        assert!(c.validate(&catalog()).is_ok());
    }

    #[test]
    fn validation_names_unknown_tools_and_categories() {
        let c = Config::from_toml_str("[server]\ncategories = [\"filesystem\"]\n").unwrap();
        let err = c.validate(&catalog()).unwrap_err();
        assert!(err.0.contains("unknown category 'filesystem'"), "{err}");

        let c = Config::from_toml_str("[tools.\"fs.read\"]\nenabled = false\n").unwrap();
        let err = c.validate(&catalog()).unwrap_err();
        assert!(err.0.contains("fs_read"), "{err}");
    }

    #[test]
    fn wildcard_commands_and_empty_categories_warn() {
        let c = Config::from_toml_str("[security]\nallowed_commands = [\"*\"]\n").unwrap();
        let warnings = c.validate(&catalog()).unwrap();
        assert!(warnings.iter().any(|w| w.contains("\"*\"")));
        assert!(warnings.iter().any(|w| w.contains("categories is empty")));
    }

    #[test]
    fn oauth_needs_public_url_and_secret() {
        let c = Config::from_toml_str("[transport.http.oauth]\nenabled = true\n").unwrap();
        assert!(c.validate(&catalog()).is_err());
    }

    #[test]
    fn roundtrips_through_toml() {
        let c = Config::default();
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(back, c);
    }
}
