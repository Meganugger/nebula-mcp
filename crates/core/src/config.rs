//! TOML configuration: the document model, defaults, validation and the
//! atomically swappable [`ConfigStore`].
//!
//! Sections:
//!
//! * `[server]`    – identity, concurrency and which categories are exposed.
//! * `[logging]`   – tracing sinks and verbosity.
//! * `[security]`  – the permission baseline every tool inherits.
//! * `[limits]`    – bounds on long-lived state (sessions, jobs, subscriptions).
//! * `[transport]` – the remote HTTP transport.
//! * `[github]`    – GitHub API endpoint.
//! * `[tools.<name>]` and `[categories.<name>]` – per-tool overrides and
//!   enable switches.
//!
//! Unknown keys are rejected everywhere: a typo in a disable switch must fail
//! loudly rather than leave the tool enabled.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::ToolError;

/// Canonical form of a tool name. Earlier releases used dots (`fs.read`);
/// names are now `[a-z0-9_]` only, and the dotted spelling is still accepted
/// in configuration keys and `tools/call`.
#[must_use]
pub fn canonical_tool_name(name: &str) -> String {
    name.replace('.', "_")
}

/// Root configuration document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Server identity and dispatch limits.
    pub server: ServerConfig,
    /// Logging and telemetry configuration.
    pub logging: LoggingConfig,
    /// Global permission baseline.
    pub security: SecurityConfig,
    /// Bounds on long-lived server state.
    pub limits: LimitsConfig,
    /// Transport configuration (remote HTTP).
    pub transport: TransportConfig,
    /// GitHub API settings.
    pub github: GithubConfig,
    /// Per-tool overrides keyed by tool name.
    pub tools: BTreeMap<String, ToolOverride>,
    /// Per-category enable switches keyed by category name.
    pub categories: BTreeMap<String, CategoryConfig>,
}

/// How the server is exposed to remote clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Remote HTTP (MCP Streamable HTTP) transport. Disabled by default.
    pub http: HttpConfig,
}

/// Configuration for the remote HTTP (Streamable HTTP) transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Enable the HTTP transport.
    pub enabled: bool,
    /// Socket address to bind. Loopback by default.
    pub bind: String,
    /// The single MCP endpoint path. Must start with `/`.
    pub path: String,
    /// Bearer tokens accepted in `Authorization: Bearer <token>`. Re-read on
    /// every request, so removing a token here revokes it without a restart.
    pub auth_tokens: Vec<String>,
    /// Require a valid bearer token on every request.
    pub require_auth: bool,
    /// Permitted `Origin` header values (exact match). Requests that carry any
    /// other `Origin` are rejected with 403.
    pub allowed_origins: Vec<String>,
    /// Permitted `Host` header values (without scheme, with port if any).
    /// Enforced when set, and always enforced (defaulting to the loopback
    /// names) when `require_auth` is false.
    pub allowed_hosts: Vec<String>,
    /// Maximum accepted request body size in bytes.
    pub max_body_bytes: usize,
    /// Seconds between keep-alive comments on event streams. `0` disables.
    pub sse_keep_alive_secs: u64,
    /// Maximum simultaneously open connections.
    pub max_connections: usize,
    /// Seconds a client may take to send its request headers.
    pub header_timeout_secs: u64,
    /// Seconds of inactivity after which a legacy protocol session expires.
    pub session_idle_secs: u64,
    /// Maximum simultaneously live legacy protocol sessions.
    pub max_sessions: usize,
    /// Failed authentication attempts allowed per client address per minute
    /// before further attempts are rejected with 429.
    pub max_auth_failures_per_minute: u32,
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
            allowed_hosts: Vec::new(),
            max_body_bytes: 4 * 1024 * 1024,
            sse_keep_alive_secs: 20,
            max_connections: 128,
            header_timeout_secs: 15,
            session_idle_secs: 3600,
            max_sessions: 64,
            max_auth_failures_per_minute: 10,
        }
    }
}

/// Server identity and dispatch limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Advertised server name.
    pub name: String,
    /// Advertised server version.
    pub version: String,
    /// Optional instructions surfaced to the model.
    pub instructions: Option<String>,
    /// Maximum number of tool calls executed concurrently.
    pub max_concurrent_calls: usize,
    /// Maximum number of calls allowed to wait for a free slot. Calls beyond
    /// this are rejected immediately with a `server_busy` error.
    pub max_queued_calls: usize,
    /// When set, only these categories are exposed. Unset exposes every
    /// category that is not disabled under `[categories]`.
    pub categories: Option<Vec<String>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "nebula-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            instructions: Some(
                "Nebula MCP gives you governed access to this machine: files, commands, git, \
                 GitHub, network, containers and browser automation. Every call is checked \
                 against the operator's policy. A `permission_denied` or `path_not_allowed` \
                 result means the operator has not allowed that action; use the \
                 `security_check_path`, `security_check_command` and `security_effective_policy` \
                 tools to see what is allowed instead of retrying."
                    .to_string(),
            ),
            max_concurrent_calls: 16,
            max_queued_calls: 64,
            categories: None,
        }
    }
}

/// Logging / telemetry section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Verbosity filter (`error`, `warn`, `info`, `debug`, `trace`, or a
    /// directive such as `nebula_mcp=debug,info`).
    pub level: String,
    /// Output format.
    pub format: LogFormat,
    /// Directory to write rotating log files into. `None` disables file logs.
    pub directory: Option<PathBuf>,
    /// Log file name prefix.
    pub file_prefix: String,
    /// Rotation cadence for file logs.
    pub rotation: LogRotation,
    /// OTLP endpoint URL for trace export (requires the `otel` build feature).
    pub otel_endpoint: Option<String>,
    /// Emit a per-tool metrics summary to the log on shutdown.
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

/// Global permission baseline. Every tool inherits these unless overridden.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Paths tools may access: a directory (the directory and everything
    /// beneath it) or a glob. Empty denies all file access.
    pub allowed_paths: Vec<String>,
    /// Extra patterns denied even inside an allowed path. These extend the
    /// built-in list; see `builtin_denied_paths`.
    pub denied_paths: Vec<String>,
    /// Apply the built-in secret patterns (`.env`, `.ssh`, private keys, ...).
    pub builtin_denied_paths: bool,
    /// Programs that may be executed: a bare name resolved on the server's
    /// `PATH`, an absolute path, or a standalone `"*"` for every program.
    /// Empty denies all execution.
    pub allowed_commands: Vec<String>,
    /// Default per-call timeout in seconds.
    pub default_timeout_secs: u64,
    /// Absolute maximum runtime of a single call, in seconds.
    pub max_runtime_secs: u64,
    /// Maximum captured output per stream, in bytes.
    pub max_output_bytes: usize,
    /// Whether tools may request elevated (admin/root) execution.
    pub allow_elevated: bool,
    /// Whether tools may reach the network.
    pub allow_network: bool,
    /// Whether destructive operations (delete, discard changes, kill) are
    /// permitted.
    pub allow_destructive: bool,
    /// Whether network tools may reach loopback, link-local, private and other
    /// non-public addresses.
    pub allow_private_networks: bool,
    /// When non-empty, network tools may only reach hosts matching one of
    /// these patterns (`example.com`, `*.example.com`).
    pub allowed_hosts: Vec<String>,
    /// Hosts network tools may never reach, even if otherwise allowed.
    pub denied_hosts: Vec<String>,
    /// Environment variables removed from every child process (glob patterns,
    /// case-insensitive). `None` uses the built-in list.
    pub env_scrub: Option<Vec<String>>,
    /// Environment variables exempt from `env_scrub`.
    pub env_passthrough: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            builtin_denied_paths: true,
            allowed_commands: Vec::new(),
            default_timeout_secs: 120,
            max_runtime_secs: 3600,
            max_output_bytes: 256 * 1024,
            allow_elevated: false,
            allow_network: false,
            allow_destructive: false,
            allow_private_networks: false,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            env_scrub: None,
            env_passthrough: Vec::new(),
        }
    }
}

impl SecurityConfig {
    /// The deny patterns in force: the built-in list (unless switched off)
    /// followed by the operator's additions.
    #[must_use]
    pub fn effective_denied_paths(&self) -> Vec<String> {
        let mut out = if self.builtin_denied_paths {
            builtin_denied_paths()
        } else {
            Vec::new()
        };
        out.extend(self.denied_paths.iter().cloned());
        out
    }

    /// The environment scrub patterns in force.
    #[must_use]
    pub fn effective_env_scrub(&self) -> Vec<String> {
        match &self.env_scrub {
            Some(list) => list.clone(),
            None => builtin_env_scrub(),
        }
    }
}

/// Secret-bearing paths denied on every platform unless
/// `builtin_denied_paths = false`. A pattern that names a directory denies
/// everything beneath it.
#[must_use]
pub fn builtin_denied_paths() -> Vec<String> {
    [
        "**/.ssh",
        "**/.aws",
        "**/.azure",
        "**/.gnupg",
        "**/.kube",
        "**/.docker/config.json",
        "**/.config/gcloud",
        "**/.config/gh",
        "**/.env",
        "**/.env.*",
        "**/.envrc",
        "**/.netrc",
        "**/_netrc",
        "**/.npmrc",
        "**/.pypirc",
        "**/.pgpass",
        "**/.git-credentials",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/*.jks",
        "**/*.keystore",
        "**/id_rsa*",
        "**/id_dsa*",
        "**/id_ecdsa*",
        "**/id_ed25519*",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Environment variables removed from child processes by default: the
/// server's own settings and anything that looks like a credential.
#[must_use]
pub fn builtin_env_scrub() -> Vec<String> {
    [
        "NEBULA_MCP_*",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "*TOKEN*",
        "*SECRET*",
        "*PASSWORD*",
        "*PASSWD*",
        "*API_KEY*",
        "*APIKEY*",
        "*ACCESS_KEY*",
        "*PRIVATE_KEY*",
        "*CREDENTIAL*",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Bounds on state that outlives a single call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum simultaneously open terminal sessions.
    pub max_sessions: usize,
    /// Seconds of inactivity after which a terminal session is closed.
    pub session_idle_secs: u64,
    /// Maximum simultaneously scheduled jobs.
    pub max_scheduled_jobs: usize,
    /// Maximum simultaneously watched resources.
    pub max_subscriptions: usize,
    /// Maximum size in bytes of one stdio message.
    pub max_message_bytes: usize,
    /// Maximum directory entries a single walk (search, glob, tree, copy,
    /// delete) may visit.
    pub max_walk_entries: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            session_idle_secs: 1800,
            max_scheduled_jobs: 16,
            max_subscriptions: 64,
            max_message_bytes: 16 * 1024 * 1024,
            max_walk_entries: 200_000,
        }
    }
}

/// GitHub API settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GithubConfig {
    /// Base URL of the REST API. Change it for GitHub Enterprise Server
    /// (`https://ghe.example.com/api/v3`). The token is only ever sent here.
    pub api_url: String,
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.github.com".to_string(),
        }
    }
}

/// Optional per-tool override. Unset fields fall back to `[security]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolOverride {
    /// Explicitly enable/disable this tool.
    pub enabled: Option<bool>,
    /// Override the default timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Override maximum output bytes.
    pub max_output_bytes: Option<usize>,
    /// Additional allowed paths for this tool only.
    pub allowed_paths: Option<Vec<String>>,
    /// Additional allowed commands for this tool only.
    pub allowed_commands: Option<Vec<String>>,
    /// Override the destructive gate for this tool.
    pub allow_destructive: Option<bool>,
    /// Override the elevation gate for this tool.
    pub allow_elevated: Option<bool>,
    /// Override the network gate for this tool.
    pub allow_network: Option<bool>,
}

/// Per-category enable switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CategoryConfig {
    /// Whether the category is enabled.
    pub enabled: bool,
}

impl Default for CategoryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// A tool known to the server, used to validate configuration keys.
#[derive(Debug, Clone, Copy)]
pub struct KnownTool<'a> {
    /// Canonical tool name.
    pub name: &'a str,
    /// Category the tool belongs to.
    pub category: &'a str,
}

/// The outcome of validating a configuration: it is usable, with these
/// warnings for the operator.
#[derive(Debug, Clone, Default)]
pub struct ValidationReport {
    /// Human-readable warnings, most important first.
    pub warnings: Vec<String>,
}

impl Config {
    /// Parse a config document from a TOML string. Tool names in `[tools]`
    /// are canonicalised.
    pub fn from_toml_str(text: &str) -> Result<Self, ToolError> {
        let mut config: Config = toml::from_str(text)
            .map_err(|e| ToolError::InvalidArguments(format!("invalid configuration: {e}")))?;
        let tools = std::mem::take(&mut config.tools);
        for (name, value) in tools {
            let canonical = canonical_tool_name(&name);
            if config.tools.insert(canonical.clone(), value).is_some() {
                return Err(ToolError::InvalidArguments(format!(
                    "invalid configuration: [tools.{canonical}] is configured more than once \
                     (the dotted and underscored spellings name the same tool)"
                )));
            }
        }
        Ok(config)
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

    /// The override block for `tool`, if any. Accepts either name spelling.
    #[must_use]
    pub fn tool_override(&self, tool: &str) -> Option<&ToolOverride> {
        self.tools
            .get(tool)
            .or_else(|| self.tools.get(&canonical_tool_name(tool)))
    }

    /// Whether a category is exposed at all.
    #[must_use]
    pub fn is_category_enabled(&self, category: &str) -> bool {
        if let Some(only) = &self.server.categories {
            if !only.iter().any(|c| c == category) {
                return false;
            }
        }
        self.categories.get(category).is_none_or(|c| c.enabled)
    }

    /// Whether the given tool (in the given category) is enabled.
    #[must_use]
    pub fn is_tool_enabled(&self, category: &str, tool: &str) -> bool {
        self.is_category_enabled(category)
            && self
                .tool_override(tool)
                .and_then(|o| o.enabled)
                .unwrap_or(true)
    }

    /// Check the document for errors that would make it unsafe or unusable,
    /// and collect warnings about risky settings.
    ///
    /// `known` lists the tools the server provides, so misspelt tool and
    /// category names are rejected instead of silently doing nothing.
    pub fn validate(&self, known: &[KnownTool<'_>]) -> Result<ValidationReport, ToolError> {
        let bad = |msg: String| ToolError::InvalidArguments(format!("invalid configuration: {msg}"));
        let mut report = ValidationReport::default();

        // Names.
        let categories: std::collections::BTreeSet<&str> =
            known.iter().map(|k| k.category).collect();
        if !known.is_empty() {
            for name in self.tools.keys() {
                if !known.iter().any(|k| canonical_tool_name(k.name) == *name) {
                    return Err(bad(format!("[tools.{name}] does not name a tool")));
                }
            }
            for name in self.categories.keys() {
                if !categories.contains(name.as_str()) {
                    return Err(bad(format!(
                        "[categories.{name}] does not name a category (known: {})",
                        categories.iter().copied().collect::<Vec<_>>().join(", ")
                    )));
                }
            }
            if let Some(only) = &self.server.categories {
                for name in only {
                    if !categories.contains(name.as_str()) {
                        return Err(bad(format!(
                            "server.categories entry '{name}' does not name a category"
                        )));
                    }
                }
            }
        }

        // Limits.
        if self.server.max_concurrent_calls == 0 {
            return Err(bad("server.max_concurrent_calls must be at least 1".into()));
        }
        if self.security.default_timeout_secs == 0 || self.security.max_runtime_secs == 0 {
            return Err(bad(
                "security.default_timeout_secs and security.max_runtime_secs must be at least 1"
                    .into(),
            ));
        }
        if self.security.max_output_bytes < 1024 {
            return Err(bad("security.max_output_bytes must be at least 1024".into()));
        }

        // Policy patterns compile (baseline and every override).
        crate::policy::Policy::validate_config(self).map_err(|e| bad(e.to_string()))?;

        // Logging.
        tracing_subscriber::EnvFilter::try_new(&self.logging.level)
            .map_err(|e| bad(format!("logging.level '{}': {e}", self.logging.level)))?;

        // HTTP transport.
        let http = &self.transport.http;
        let addr: std::net::SocketAddr = http
            .bind
            .parse()
            .map_err(|e| bad(format!("transport.http.bind '{}': {e}", http.bind)))?;
        if !http.path.starts_with('/') || http.path.contains(['?', '#', '*', '{']) {
            return Err(bad(format!(
                "transport.http.path '{}' must start with '/' and be a plain path",
                http.path
            )));
        }
        if http.max_connections == 0 || http.max_sessions == 0 {
            return Err(bad(
                "transport.http.max_connections and max_sessions must be at least 1".into(),
            ));
        }
        for token in &http.auth_tokens {
            if token.len() < 16 {
                return Err(bad(
                    "transport.http.auth_tokens entries must be at least 16 characters; \
                     generate one with `openssl rand -hex 32`"
                        .into(),
                ));
            }
        }
        url::Url::parse(&self.github.api_url)
            .ok()
            .filter(|u| u.scheme() == "https" && u.host_str().is_some())
            .ok_or_else(|| {
                bad(format!(
                    "github.api_url '{}' must be an https URL",
                    self.github.api_url
                ))
            })?;

        // Warnings.
        let sec = &self.security;
        if sec.allowed_commands.iter().any(|c| c == "*") {
            report.warnings.push(
                "security.allowed_commands contains \"*\": every program on this machine may be \
                 executed and the command allowlist is switched off."
                    .into(),
            );
        }
        if sec
            .allowed_paths
            .iter()
            .any(|p| matches!(p.as_str(), "/" | "/**" | "**" | "**/*"))
        {
            report.warnings.push(
                "security.allowed_paths allows the whole filesystem; only the deny list protects \
                 secrets."
                    .into(),
            );
        }
        if !sec.builtin_denied_paths {
            report.warnings.push(
                "security.builtin_denied_paths is false: the built-in secret patterns (.env, \
                 .ssh, private keys, ...) are not applied."
                    .into(),
            );
        }
        if sec.allow_elevated && sec.allow_destructive {
            report.warnings.push(
                "allow_elevated and allow_destructive are both enabled globally; consider \
                 enabling them per tool under [tools.<name>] instead."
                    .into(),
            );
        }
        if sec.allow_network && sec.allow_private_networks {
            report.warnings.push(
                "allow_private_networks is true: network tools can reach loopback, private and \
                 cloud-metadata addresses, including this server's own ports."
                    .into(),
            );
        }
        if sec.max_runtime_secs < sec.default_timeout_secs {
            report.warnings.push(
                "max_runtime_secs is below default_timeout_secs; timeouts are clamped to it."
                    .into(),
            );
        }
        if http.enabled {
            if !http.require_auth {
                report.warnings.push(
                    "transport.http.require_auth is false: anything that can reach the endpoint \
                     can run every allowed tool."
                        .into(),
                );
            }
            if !addr.ip().is_loopback() {
                report.warnings.push(format!(
                    "transport.http.bind {addr} is not loopback: the endpoint is reachable from \
                     the network and speaks plain HTTP; put a TLS-terminating proxy in front."
                ));
            }
        }
        if sec.allowed_paths.is_empty() {
            report
                .warnings
                .push("allowed_paths is empty: all file access is denied.".into());
        }
        if sec.allowed_commands.is_empty() {
            report
                .warnings
                .push("allowed_commands is empty: all command execution is denied.".into());
        }
        Ok(report)
    }
}

type Validator = dyn Fn(&Config) -> Result<ValidationReport, ToolError> + Send + Sync;

/// A concurrency-friendly holder for the active [`Config`].
///
/// Readers take a cheap `Arc` snapshot; a reload swaps the pointer atomically
/// and bumps [`ConfigStore::generation`]. A reload that fails validation
/// leaves the active configuration untouched.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<Arc<Config>>>,
    generation: Arc<AtomicU64>,
    source_path: Option<PathBuf>,
    validator: Arc<RwLock<Option<Arc<Validator>>>>,
}

impl ConfigStore {
    /// Create a store from an in-memory config.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(config))),
            generation: Arc::new(AtomicU64::new(0)),
            source_path: None,
            validator: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a store backed by a file, remembering the path for reloads.
    pub fn from_path(path: &Path) -> Result<Self, ToolError> {
        let config = Config::load(path)?;
        let mut store = Self::new(config);
        // Keep the real path so the policy can refuse to let tools rewrite it.
        store.source_path = Some(std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
        Ok(store)
    }

    /// Install the check every reload must pass before it is applied.
    pub fn set_validator<F>(&self, validator: F)
    where
        F: Fn(&Config) -> Result<ValidationReport, ToolError> + Send + Sync + 'static,
    {
        *self.validator.write() = Some(Arc::new(validator));
    }

    /// Take a cheap snapshot of the current configuration.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Config> {
        self.inner.read().clone()
    }

    /// Monotonic counter bumped on every successful replace; lets callers
    /// cache values derived from the configuration.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The real path of the file this store was loaded from, if any.
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Replace the active configuration.
    pub fn replace(&self, config: Config) {
        *self.inner.write() = Arc::new(config);
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Re-read the source file, validate it, and swap it in.
    ///
    /// On any error the active configuration is left unchanged, so a bad edit
    /// never weakens or breaks a running server.
    pub fn reload_from_disk(&self) -> Result<ValidationReport, ToolError> {
        let Some(path) = &self.source_path else {
            return Err(ToolError::Internal(
                "config store has no backing file to reload".to_string(),
            ));
        };
        let config = Config::load(path)?;
        let validator = self.validator.read().clone();
        let report = match validator {
            Some(v) => v(&config)?,
            None => config.validate(&[])?,
        };
        self.replace(config);
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_deny_everything() {
        let c = Config::default();
        assert!(c.security.allowed_paths.is_empty());
        assert!(c.security.allowed_commands.is_empty());
        assert!(!c.security.allow_elevated);
        assert!(!c.security.allow_destructive);
        assert!(!c.security.allow_network);
        assert!(!c.security.allow_private_networks);
        assert!(c.security.builtin_denied_paths);
    }

    #[test]
    fn parses_minimal_config_with_either_tool_spelling() {
        let text = r#"
            [server]
            name = "custom"

            [security]
            allowed_paths = ["/work"]
            allowed_commands = ["git", "cargo"]
            default_timeout_secs = 30

            [tools."fs.delete"]
            enabled = false

            [tools.git_push]
            allow_network = true

            [categories.powershell]
            enabled = false
        "#;
        let c = Config::from_toml_str(text).unwrap();
        assert_eq!(c.server.name, "custom");
        assert_eq!(c.security.default_timeout_secs, 30);
        assert!(!c.is_tool_enabled("filesystem", "fs_delete"));
        assert!(!c.is_tool_enabled("filesystem", "fs.delete"));
        assert!(!c.is_tool_enabled("powershell", "powershell_run"));
        assert!(c.is_tool_enabled("filesystem", "fs_read"));
        assert_eq!(c.tool_override("git.push").unwrap().allow_network, Some(true));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for text in [
            "[security]\nallow_destuctive = true\n",
            "[tools.fs_delete]\nenable = false\n",
            "[categories.powershell]\nenable = false\n",
            "[tool.fs_delete]\nenabled = false\n",
            "[transport.http]\nrequire_auht = false\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "accepted: {text}");
        }
    }

    #[test]
    fn duplicate_spellings_of_one_tool_are_rejected() {
        let text = "[tools.\"fs.read\"]\nenabled = false\n[tools.fs_read]\nenabled = true\n";
        assert!(Config::from_toml_str(text).is_err());
    }

    #[test]
    fn user_deny_patterns_extend_the_builtin_list() {
        let c = Config::from_toml_str("[security]\ndenied_paths = [\"**/secrets\"]\n").unwrap();
        let denied = c.security.effective_denied_paths();
        assert!(denied.iter().any(|p| p == "**/.ssh"));
        assert!(denied.iter().any(|p| p == "**/secrets"));
    }

    #[test]
    fn validation_rejects_misspelt_tool_and_category_names() {
        let known = [KnownTool {
            name: "fs_delete",
            category: "filesystem",
        }];
        let ok = Config::from_toml_str("[tools.fs_delete]\nenabled = false\n").unwrap();
        assert!(ok.validate(&known).is_ok());
        let typo = Config::from_toml_str("[tools.fs_delet]\nenabled = false\n").unwrap();
        assert!(typo.validate(&known).is_err());
        let cat = Config::from_toml_str("[categories.filesytem]\nenabled = false\n").unwrap();
        assert!(cat.validate(&known).is_err());
        let only = Config::from_toml_str("[server]\ncategories = [\"nope\"]\n").unwrap();
        assert!(only.validate(&known).is_err());
    }

    #[test]
    fn validation_rejects_broken_values_and_warns_about_risky_ones() {
        let bad_bind = Config::from_toml_str("[transport.http]\nbind = \"nope\"\n").unwrap();
        assert!(bad_bind.validate(&[]).is_err());
        let bad_path = Config::from_toml_str("[transport.http]\npath = \"mcp\"\n").unwrap();
        assert!(bad_path.validate(&[]).is_err());
        let bad_glob = Config::from_toml_str("[security]\nallowed_paths = [\"/a/[\"]\n").unwrap();
        assert!(bad_glob.validate(&[]).is_err());
        let short = Config::from_toml_str("[transport.http]\nauth_tokens = [\"short\"]\n").unwrap();
        assert!(short.validate(&[]).is_err());

        let star = Config::from_toml_str("[security]\nallowed_commands = [\"*\"]\n").unwrap();
        let report = star.validate(&[]).unwrap();
        assert!(report.warnings.iter().any(|w| w.contains("\"*\"")));
    }

    #[test]
    fn server_categories_restrict_what_is_exposed() {
        let c = Config::from_toml_str("[server]\ncategories = [\"filesystem\"]\n").unwrap();
        assert!(c.is_tool_enabled("filesystem", "fs_read"));
        assert!(!c.is_tool_enabled("git", "git_status"));
    }

    #[test]
    fn roundtrips_through_toml() {
        let c = Config::default();
        let text = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&text).unwrap();
        assert_eq!(back.server.name, c.server.name);
    }

    #[test]
    fn store_replace_bumps_the_generation() {
        let store = ConfigStore::new(Config::default());
        let before = store.generation();
        let mut c = Config::default();
        c.server.name = "renamed".into();
        store.replace(c);
        assert_eq!(store.snapshot().server.name, "renamed");
        assert!(store.generation() > before);
    }

    #[test]
    fn a_reload_that_fails_validation_keeps_the_old_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[server]\nname = \"one\"\n").unwrap();
        let store = ConfigStore::from_path(&path).unwrap();
        std::fs::write(&path, "[security]\nallowed_paths = [\"/a/[\"]\n").unwrap();
        assert!(store.reload_from_disk().is_err());
        assert_eq!(store.snapshot().server.name, "one");
        std::fs::write(&path, "[server]\nname = \"two\"\n").unwrap();
        assert!(store.reload_from_disk().is_ok());
        assert_eq!(store.snapshot().server.name, "two");
    }
}
