//! TOML-backed configuration with hot reload.
//!
//! The configuration is split into a small number of sections:
//!
//! * `[server]`   – identity and MCP handshake metadata.
//! * `[logging]`  – tracing/telemetry sinks and verbosity.
//! * `[security]` – the global permission baseline every tool inherits.
//! * `[tools.<name>]` – optional per-tool overrides layered on the baseline.
//!
//! A [`ConfigStore`] owns the parsed config behind an atomic swap so hot
//! reloads are lock-free for readers. See [`crate::hotreload`] for the file
//! watcher that drives reloads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::ToolError;

/// Root configuration document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Server identity and handshake metadata.
    pub server: ServerConfig,
    /// Logging and telemetry configuration.
    pub logging: LoggingConfig,
    /// Global permission baseline.
    pub security: SecurityConfig,
    /// Transport configuration (stdio and/or remote HTTP).
    pub transport: TransportConfig,
    /// Per-tool overrides keyed by fully-qualified tool name.
    pub tools: BTreeMap<String, ToolOverride>,
    /// Per-category enable switches keyed by category name (e.g. `network`).
    pub categories: BTreeMap<String, CategoryConfig>,
}

/// How the server is exposed to clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Remote HTTP (MCP Streamable HTTP) transport. Disabled by default; when
    /// enabled the server listens for JSON-RPC over HTTP so it can be reached
    /// by a URL from an AI platform.
    pub http: HttpConfig,
}

/// Configuration for the remote HTTP (Streamable HTTP) transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Enable the HTTP transport.
    pub enabled: bool,
    /// Socket address to bind. Defaults to loopback; set to `0.0.0.0:<port>`
    /// only when you intend to expose the server beyond this machine (and put
    /// it behind TLS + authentication).
    pub bind: String,
    /// The single MCP endpoint path clients POST/GET against.
    pub path: String,
    /// Bearer tokens accepted in the `Authorization: Bearer <token>` header.
    /// Any match grants access. Ignored when `require_auth` is false.
    pub auth_tokens: Vec<String>,
    /// Require a valid bearer token on every request. Strongly recommended
    /// whenever `bind` is not loopback; refusing to start otherwise.
    pub require_auth: bool,
    /// Permitted `Origin` header values (exact match) for browser-based
    /// clients. Empty allows requests without an `Origin` header (native
    /// clients) and denies cross-origin browser requests.
    pub allowed_origins: Vec<String>,
    /// Maximum accepted request body size, in bytes (DoS guard).
    pub max_body_bytes: usize,
    /// Seconds a session may sit idle before it is expired and its SSE replay
    /// buffer is dropped.
    pub session_idle_secs: u64,
    /// Number of server-initiated SSE events retained per session for
    /// `Last-Event-ID` resumption.
    pub sse_replay_events: usize,
    /// Optional OAuth2 bearer validation (RFC 7662 token introspection) in
    /// addition to the static `auth_tokens`.
    pub oauth: OAuthConfig,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8765".to_string(),
            path: "/mcp".to_string(),
            auth_tokens: Vec::new(),
            require_auth: true,
            allowed_origins: Vec::new(),
            max_body_bytes: 16 * 1024 * 1024,
            session_idle_secs: 1800,
            sse_replay_events: 256,
            oauth: OAuthConfig::default(),
        }
    }
}

/// OAuth2 bearer validation via RFC 7662 token introspection.
///
/// When enabled, a bearer token that does not match any static `auth_tokens`
/// entry is POSTed to `introspection_url` (authenticated with
/// `client_id`/`client_secret`); the request is accepted when the
/// authorization server reports the token `active` and carrying every scope in
/// `required_scopes`. Verdicts are cached for `cache_secs` to bound
/// introspection traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthConfig {
    /// Enable OAuth2 introspection as an additional bearer validator.
    pub enabled: bool,
    /// RFC 7662 introspection endpoint URL.
    pub introspection_url: String,
    /// Client id used to authenticate to the introspection endpoint.
    pub client_id: String,
    /// Client secret used to authenticate to the introspection endpoint.
    pub client_secret: String,
    /// Scopes the token must carry (all of them). Empty = any active token.
    pub required_scopes: Vec<String>,
    /// Seconds to cache an introspection verdict per token.
    pub cache_secs: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            introspection_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            required_scopes: Vec::new(),
            cache_secs: 60,
        }
    }
}

/// Server identity section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Advertised server name.
    pub name: String,
    /// Advertised server version.
    pub version: String,
    /// Optional instructions surfaced to the model during initialize.
    pub instructions: Option<String>,
    /// Maximum number of tool calls executed concurrently.
    pub max_concurrent_calls: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "nebula-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            instructions: Some(
                "Nebula MCP: a general-purpose autonomous software-engineering backend. \
                 It exposes the host machine's filesystem, terminal/process control, git, \
                 GitHub, networking, containers, browser automation and job scheduling so an \
                 AI agent can design, build, test and ship any program end-to-end. \
                 Cross-platform tools work everywhere; powershell/windows/diagnostics tools \
                 require a Windows host. Every call is gated by an allowlist-based permission \
                 policy — nothing is permitted until it is configured."
                    .to_string(),
            ),
            max_concurrent_calls: 16,
        }
    }
}

/// Logging / telemetry section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Verbosity filter (`error`, `warn`, `info`, `debug`, `trace`, or an
    /// `env_logger`-style directive such as `nebula=debug,info`).
    pub level: String,
    /// Output format for the file sink.
    pub format: LogFormat,
    /// Directory to write rotating log files into. `None` disables file logs.
    pub directory: Option<PathBuf>,
    /// Log file name prefix.
    pub file_prefix: String,
    /// Rotation cadence for file logs.
    pub rotation: LogRotation,
    /// When set, an OTLP endpoint URL to export traces to. Presence toggles
    /// OpenTelemetry export in the server binary.
    pub otel_endpoint: Option<String>,
    /// Emit per-tool metrics summaries to the logs.
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
    /// Human-readable, coloured when a TTY.
    Pretty,
}

/// Rotation cadence for the rolling file appender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// Rotate every minute (useful for stress tests).
    Minutely,
    /// Rotate hourly.
    Hourly,
    /// Rotate daily.
    Daily,
    /// Never rotate (single growing file).
    Never,
}

/// Global permission baseline. Every tool inherits these unless overridden.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Glob patterns of paths tools may access. Empty means "deny all file
    /// access" — a safe default that forces explicit configuration.
    pub allowed_paths: Vec<String>,
    /// Glob patterns explicitly denied even if matched by `allowed_paths`.
    pub denied_paths: Vec<String>,
    /// Executable names permitted for process/terminal tools (basename match,
    /// case-insensitive on Windows). Empty means "deny all execution".
    pub allowed_commands: Vec<String>,
    /// Default per-call timeout in seconds.
    pub default_timeout_secs: u64,
    /// Absolute maximum runtime a single call may request, in seconds.
    pub max_runtime_secs: u64,
    /// Maximum captured output per stream, in bytes.
    pub max_output_bytes: usize,
    /// Whether tools may request elevated (admin/root) execution.
    pub allow_elevated: bool,
    /// Whether tools that reach external networks are permitted.
    pub allow_network: bool,
    /// Whether destructive operations (delete, reset --hard, driver uninstall)
    /// are permitted at all.
    pub allow_destructive: bool,
    /// Default per-tool rate limit, in calls per minute. `None` disables rate
    /// limiting. Override per tool via `[tools."<name>"] rate_limit_per_minute`.
    pub rate_limit_per_minute: Option<u32>,
    /// Global resident-memory budget for the server process, in bytes. New
    /// tool calls are rejected (retryably) while usage exceeds the budget.
    /// `None` disables the guard.
    pub max_memory_bytes: Option<u64>,
    /// Global CPU budget for the server process, in percent of one core
    /// (100 = one full core; multi-core machines may exceed 100). New tool
    /// calls are rejected (retryably) while usage exceeds the budget. `None`
    /// disables the guard.
    pub max_cpu_percent: Option<f32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            denied_paths: default_denied_paths(),
            allowed_commands: Vec::new(),
            default_timeout_secs: 120,
            max_runtime_secs: 3600,
            max_output_bytes: 8 * 1024 * 1024,
            allow_elevated: false,
            allow_network: true,
            allow_destructive: false,
            rate_limit_per_minute: None,
            max_memory_bytes: None,
            max_cpu_percent: None,
        }
    }
}

/// Sensitive paths denied by default on every platform.
fn default_denied_paths() -> Vec<String> {
    vec![
        "**/.ssh/**".to_string(),
        "**/.aws/**".to_string(),
        "**/.gnupg/**".to_string(),
        "**/*.pem".to_string(),
        "**/*.key".to_string(),
        "**/id_rsa*".to_string(),
        "**/.env".to_string(),
    ]
}

/// Optional per-tool override. All fields are optional; unset fields fall back
/// to the [`SecurityConfig`] baseline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolOverride {
    /// Explicitly enable/disable this tool.
    pub enabled: Option<bool>,
    /// Override timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Override maximum output bytes.
    pub max_output_bytes: Option<usize>,
    /// Additional allowed paths (merged with the baseline).
    pub allowed_paths: Option<Vec<String>>,
    /// Additional allowed commands (merged with the baseline).
    pub allowed_commands: Option<Vec<String>>,
    /// Override the destructive flag for this tool.
    pub allow_destructive: Option<bool>,
    /// Override the elevation flag for this tool (least-privilege scoping).
    pub allow_elevated: Option<bool>,
    /// Override the rate limit (calls per minute) for this tool. `Some(0)` is
    /// treated as "no limit" (0 would otherwise deny every call).
    pub rate_limit_per_minute: Option<u32>,
}

/// Per-category enable switch. A disabled category disables all of its tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CategoryConfig {
    /// Whether the category is enabled.
    pub enabled: bool,
}

impl Default for CategoryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Config {
    /// Parse a config document from a TOML string.
    pub fn from_toml_str(text: &str) -> Result<Self, ToolError> {
        toml::from_str(text).map_err(|e| ToolError::Internal(format!("invalid config: {e}")))
    }

    /// Load a config document from disk.
    pub fn load(path: &Path) -> Result<Self, ToolError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ToolError::Io(format!("reading config {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    /// Serialise this config back to a TOML string.
    pub fn to_toml_string(&self) -> Result<String, ToolError> {
        toml::to_string_pretty(self)
            .map_err(|e| ToolError::Internal(format!("serialising config: {e}")))
    }

    /// Return `true` if the given tool (in the given category) is enabled.
    ///
    /// A tool is enabled unless its category is disabled or its own
    /// `enabled = false` override is set.
    #[must_use]
    pub fn is_tool_enabled(&self, category: &str, tool: &str) -> bool {
        if let Some(cat) = self.categories.get(category) {
            if !cat.enabled {
                return false;
            }
        }
        match self.tools.get(tool) {
            Some(o) => o.enabled.unwrap_or(true),
            None => true,
        }
    }
}

/// A concurrency-friendly holder for the active [`Config`].
///
/// Readers take a cheap `Arc` snapshot; writers (hot reload) swap the pointer
/// atomically. This keeps the hot path lock-free for tool execution.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<Arc<Config>>>,
    source_path: Option<PathBuf>,
}

impl ConfigStore {
    /// Create a store from an in-memory config.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(config))),
            source_path: None,
        }
    }

    /// Create a store backed by a file, remembering the path for reloads.
    pub fn from_path(path: &Path) -> Result<Self, ToolError> {
        let config = Config::load(path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(Arc::new(config))),
            source_path: Some(path.to_path_buf()),
        })
    }

    /// Take a cheap snapshot of the current configuration.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Config> {
        self.inner.read().clone()
    }

    /// The file this store was loaded from, if any.
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Replace the active configuration.
    pub fn replace(&self, config: Config) {
        *self.inner.write() = Arc::new(config);
    }

    /// Re-read the source file and swap in the new config.
    ///
    /// Returns an error (without changing the active config) if the file is
    /// missing or invalid, so a bad edit never takes down a running server.
    pub fn reload_from_disk(&self) -> Result<(), ToolError> {
        let Some(path) = &self.source_path else {
            return Err(ToolError::Internal(
                "config store has no backing file to reload".to_string(),
            ));
        };
        let config = Config::load(path)?;
        self.replace(config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_deny_file_and_command_access() {
        let c = Config::default();
        assert!(c.security.allowed_paths.is_empty());
        assert!(c.security.allowed_commands.is_empty());
        assert!(!c.security.allow_elevated);
        assert!(!c.security.allow_destructive);
    }

    #[test]
    fn parses_minimal_config() {
        let text = r#"
            [server]
            name = "custom"

            [security]
            allowed_paths = ["/work/**"]
            allowed_commands = ["git", "cargo"]
            default_timeout_secs = 30

            [tools."fs.delete"]
            enabled = false

            [categories.powershell]
            enabled = false
        "#;
        let c = Config::from_toml_str(text).unwrap();
        assert_eq!(c.server.name, "custom");
        assert_eq!(c.security.default_timeout_secs, 30);
        assert!(!c.is_tool_enabled("filesystem", "fs.delete"));
        assert!(!c.is_tool_enabled("powershell", "powershell.run"));
        assert!(c.is_tool_enabled("filesystem", "fs.read"));
    }

    #[test]
    fn roundtrips_through_toml() {
        let c = Config::default();
        let text = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&text).unwrap();
        assert_eq!(back.server.name, c.server.name);
    }

    #[test]
    fn store_replace_is_visible_to_new_snapshots() {
        let store = ConfigStore::new(Config::default());
        assert_eq!(store.snapshot().server.name, "nebula-mcp");
        let mut c = Config::default();
        c.server.name = "renamed".into();
        store.replace(c);
        assert_eq!(store.snapshot().server.name, "renamed");
    }
}
