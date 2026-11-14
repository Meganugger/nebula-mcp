//! The permission policy.
//!
//! A [`PolicySet`] is compiled once from a [`Config`]; a [`Policy`] is what a
//! single tool call runs under. Everything a tool may touch is decided here:
//!
//! * [`PathRules`]: allowed root directories, deny patterns, read-only
//!   patterns and protected server files;
//! * [`CommandPolicy`]: which executables caller-chosen programs resolve to;
//! * [`EnvPolicy`]: which environment variables a child process receives;
//! * [`NetPolicy`]: whether, and to which hosts, a tool may connect;
//! * the destructive and elevation gates, timeouts and output limits.
//!
//! Empty allowlists deny. Deny patterns win over allowed roots.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::config::{Config, ConfigError, SandboxMode, SecurityConfig, ToolOverride};
use crate::error::ToolError;

/// What a path is wanted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read contents or metadata, or list.
    Read,
    /// Create, modify, rename or delete.
    Write,
}

/// Credential and key locations denied for all access unless the operator
/// sets `builtin_denied_paths = false`.
pub const BUILTIN_DENIED: &[&str] = &[
    "**/.ssh/**",
    "**/.aws/**",
    "**/.gnupg/**",
    "**/.azure/**",
    "**/.kube/**",
    "**/.config/gcloud/**",
    "**/.config/gh/**",
    "**/.docker/config.json",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/*.kdbx",
    "**/id_rsa*",
    "**/id_dsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "**/.netrc",
    "**/_netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.pgpass",
    "**/.htpasswd",
    "**/.git-credentials",
];

/// `.env.<suffix>` files that hold placeholders rather than secrets.
const ENV_FILE_SAFE_SUFFIXES: &[&str] = &["example", "sample", "template", "dist"];

/// Locations that may be read but never written through tools: writing into
/// a git directory can make later git commands run attacker-chosen programs.
pub const BUILTIN_READ_ONLY: &[&str] = &["**/.git", "**/.git/**"];

/// Environment variables every child process receives.
const BASE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "TZ",
    "TERM",
    "TMPDIR",
    "TEMP",
    "TMP",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    // Windows essentials.
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "HOMEDRIVE",
    "HOMEPATH",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "OS",
    "PSMODULEPATH",
];

/// Variables never passed to a child, whatever the configuration says.
const NEVER_PASSED_PREFIX: &str = "NEBULA_MCP_";

/// An allowed root directory.
#[derive(Debug, Clone)]
pub struct Root {
    /// Canonical absolute path.
    path: PathBuf,
    /// The path as configured, when it differs (for example `/tmp/x` on a
    /// system where `/tmp` is a symlink).
    alias: Option<PathBuf>,
}

impl Root {
    /// Canonical absolute path of the root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Which paths tools may reach.
#[derive(Debug)]
pub struct PathRules {
    roots: Vec<Root>,
    deny: GlobSet,
    deny_env_files: bool,
    read_only: GlobSet,
    protected: Vec<PathBuf>,
}

impl PathRules {
    fn compile(
        allowed: &[String],
        security: &SecurityConfig,
        protected: &[PathBuf],
        warnings: &mut Vec<String>,
    ) -> Result<Self, ConfigError> {
        let mut roots: Vec<Root> = Vec::new();
        for entry in allowed {
            let Some(root) = compile_root(entry, warnings)? else {
                continue;
            };
            if !roots.iter().any(|r| paths_equal(&r.path, &root.path)) {
                roots.push(root);
            }
        }

        let mut deny: Vec<String> = Vec::new();
        if security.builtin_denied_paths {
            deny.extend(BUILTIN_DENIED.iter().map(|s| (*s).to_string()));
        }
        deny.extend(security.denied_paths.iter().cloned());
        let mut read_only: Vec<String> =
            BUILTIN_READ_ONLY.iter().map(|s| (*s).to_string()).collect();
        read_only.extend(security.read_only_paths.iter().cloned());

        let rules = Self {
            roots,
            deny: build_globset(&deny, "denied_paths")?,
            deny_env_files: security.builtin_denied_paths,
            read_only: build_globset(&read_only, "read_only_paths")?,
            protected: protected.to_vec(),
        };
        for root in &rules.roots {
            if rules.denied(&root.path, Access::Read).is_some() {
                warnings.push(format!(
                    "allowed path '{}' is covered by a deny pattern and will be inaccessible",
                    root.path.display()
                ));
            }
        }
        Ok(rules)
    }

    /// The allowed roots.
    #[must_use]
    pub fn roots(&self) -> &[Root] {
        &self.roots
    }

    /// Whether any root is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The root containing `canonical`, an absolute symlink-free path.
    #[must_use]
    pub fn root_of(&self, canonical: &Path) -> Option<&Root> {
        // Prefer the deepest root so nested roots behave predictably.
        self.roots
            .iter()
            .filter(|r| path_starts_with(canonical, &r.path))
            .max_by_key(|r| r.path.components().count())
    }

    /// Rewrite a path given under a root's configured alias to the canonical
    /// root, so `/tmp/x/a` works when the root is really `/private/tmp/x`.
    #[must_use]
    pub fn unalias(&self, path: &Path) -> Option<PathBuf> {
        for r in &self.roots {
            if let Some(alias) = &r.alias {
                if path_starts_with(path, alias) {
                    let rest: PathBuf =
                        path.components().skip(alias.components().count()).collect();
                    return Some(r.path.join(rest));
                }
            }
        }
        None
    }

    /// Whether `path` lies inside (or is) any allowed root. Used to refuse
    /// running executables an agent could have written.
    #[must_use]
    pub fn inside_any_root(&self, canonical: &Path) -> bool {
        self.root_of(canonical).is_some()
    }

    /// Why `path` (absolute) is denied for `access`, if it is. The path and
    /// every ancestor are tested, so denying a directory denies its contents.
    #[must_use]
    pub fn denied(&self, path: &Path, access: Access) -> Option<&'static str> {
        for p in &self.protected {
            if path_starts_with(path, p) {
                return Some("it belongs to the server's own configuration or state");
            }
        }
        let mut prefix = PathBuf::new();
        for comp in path.components() {
            prefix.push(comp.as_os_str());
            if !matches!(comp, Component::Normal(_)) {
                continue;
            }
            let candidate = slash_string(&prefix);
            if self.deny.is_match(&candidate) {
                return Some("it matches a denied pattern");
            }
            if self.deny_env_files
                && is_env_secret_name(comp.as_os_str().to_string_lossy().as_ref())
            {
                return Some("it matches a denied pattern");
            }
            if access == Access::Write && self.read_only.is_match(&candidate) {
                return Some("it is read-only by policy");
            }
        }
        None
    }
}

/// `.env` and `.env.<anything>` except the well-known placeholder variants.
fn is_env_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == ".env" {
        return true;
    }
    match lower.strip_prefix(".env.") {
        Some(rest) => !ENV_FILE_SAFE_SUFFIXES.contains(&rest),
        None => false,
    }
}

fn compile_root(entry: &str, warnings: &mut Vec<String>) -> Result<Option<Root>, ConfigError> {
    let mut text = entry.trim().to_string();
    for suffix in ["/**", "\\**", "/*", "\\*"] {
        if let Some(stripped) = text.strip_suffix(suffix) {
            warnings.push(format!(
                "allowed_paths entry '{entry}': entries are directories since 0.2; using \
                 '{stripped}' (which covers everything beneath it)"
            ));
            text = stripped.to_string();
            break;
        }
    }
    if text.contains(['*', '?', '[', '{']) {
        return Err(ConfigError(format!(
            "allowed_paths entry '{entry}' is a glob pattern. Since 0.2 each entry is a \
             directory; list the directories to allow and use denied_paths for exclusions."
        )));
    }
    if text.is_empty() {
        return Err(ConfigError("allowed_paths contains an empty entry".into()));
    }
    let expanded = expand_home(&text);
    if !expanded.is_absolute() {
        return Err(ConfigError(format!(
            "allowed_paths entry '{entry}' must be an absolute path (or start with ~/)"
        )));
    }
    let canonical = match std::fs::canonicalize(&expanded) {
        Ok(p) => simplify(&p),
        Err(e) => {
            warnings.push(format!(
                "allowed_paths entry '{entry}' is unusable ({e}); it is ignored until it exists \
                 and the configuration is reloaded"
            ));
            return Ok(None);
        }
    };
    if !canonical.is_dir() {
        warnings.push(format!(
            "allowed_paths entry '{entry}' is not a directory; it is ignored"
        ));
        return Ok(None);
    }
    let lexical = lexical_normalize(&expanded);
    let alias = (!paths_equal(&lexical, &canonical)).then_some(lexical);
    Ok(Some(Root {
        path: canonical,
        alias,
    }))
}

/// Expand a leading `~` to the user's home directory.
#[must_use]
pub fn expand_home(text: &str) -> PathBuf {
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    };
    if text == "~" {
        if let Some(h) = home() {
            return h;
        }
    }
    if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        if let Some(h) = home() {
            return h.join(rest);
        }
    }
    PathBuf::from(text)
}

/// Resolve `.` and `..` lexically. Only for paths the operator supplied.
#[must_use]
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Drop the Windows verbatim prefix (`\\?\C:\x` -> `C:\x`) where that is
/// lossless, so paths compare and display the way users write them.
#[must_use]
pub fn simplify(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC\\") && rest.as_bytes().get(1) == Some(&b':') {
                return PathBuf::from(rest.to_string());
            }
        }
    }
    path.to_path_buf()
}

/// A path as a `/`-separated string for glob matching.
#[must_use]
pub fn slash_string(path: &Path) -> String {
    let s = path.to_string_lossy();
    if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.into_owned()
    }
}

fn component_eq(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// Component-wise prefix test (case-insensitive where the OS usually is).
#[must_use]
pub fn path_starts_with(path: &Path, base: &Path) -> bool {
    let mut p = path.components();
    for b in base.components() {
        match p.next() {
            Some(c) if component_eq(c.as_os_str(), b.as_os_str()) => {}
            _ => return false,
        }
    }
    true
}

/// Path equality under the same rules as [`path_starts_with`].
#[must_use]
pub fn paths_equal(a: &Path, b: &Path) -> bool {
    a.components().count() == b.components().count() && path_starts_with(a, b)
}

fn build_globset(patterns: &[String], key: &str) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let normalized = p.replace('\\', "/");
        let mut variants = vec![normalized.clone()];
        // `dir/**` should also match `dir` itself.
        if let Some(dir) = normalized.strip_suffix("/**") {
            variants.push(dir.to_string());
        }
        for v in variants {
            let glob = GlobBuilder::new(&v)
                .case_insensitive(true)
                .literal_separator(true)
                .build()
                .map_err(|e| {
                    ConfigError(format!("[security] {key}: invalid pattern '{p}': {e}"))
                })?;
            builder.add(glob);
        }
    }
    builder
        .build()
        .map_err(|e| ConfigError(format!("[security] {key}: {e}")))
}

/// Which executables caller-chosen programs may resolve to.
#[derive(Debug, Default)]
pub struct CommandPolicy {
    any: bool,
    names: Vec<String>,
    paths: Vec<PathBuf>,
}

impl CommandPolicy {
    fn compile(entries: &[String], warnings: &mut Vec<String>) -> Self {
        let mut policy = Self::default();
        for entry in entries {
            let e = entry.trim();
            if e == "*" {
                policy.any = true;
            } else if e.is_empty() {
                warnings.push("allowed_commands contains an empty entry; ignored".into());
            } else if e.contains(['/', '\\']) {
                match invocation_path(&expand_home(e)) {
                    Ok(p) => policy.paths.push(p),
                    Err(err) => warnings.push(format!(
                        "allowed_commands entry '{entry}' does not resolve ({err}); ignored"
                    )),
                }
            } else {
                policy.names.push(command_key(e));
            }
        }
        policy
    }

    /// Whether every command is allowed (`"*"`).
    #[must_use]
    pub fn allows_any(&self) -> bool {
        self.any
    }

    /// Whether nothing is allowed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.any && self.names.is_empty() && self.paths.is_empty()
    }

    /// The configured bare names (normalised).
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The configured absolute paths, as invocation paths.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Decide whether the caller may run `requested`, and return the
    /// executable that will run.
    ///
    /// The decision is made on the file that will run, never on the basename.
    /// A program is identified by its [`invocation_path`]:
    ///
    /// * a bare name is looked up on the server's `PATH` only, and a
    ///   bare-name entry never authorises a file inside an allowed root
    ///   (which an agent could have written);
    /// * a path must be an allowed absolute path, or be exactly where an
    ///   allowed bare name is found on `PATH`.
    pub fn authorize(
        &self,
        requested: &str,
        cwd: &Path,
        paths: &PathRules,
    ) -> Result<PathBuf, ToolError> {
        let deny = || ToolError::CommandNotAllowed(requested.to_string());
        if requested.is_empty() || requested.contains('\0') {
            return Err(ToolError::invalid("program must not be empty"));
        }
        if self.is_empty() {
            return Err(deny());
        }
        let is_path = requested.contains(['/', '\\']) || Path::new(requested).is_absolute();

        if !is_path {
            let named = self.names.contains(&command_key(requested));
            if !self.any && !named && self.paths.is_empty() {
                return Err(deny());
            }
            let resolved = resolve_on_path(requested)?;
            if self.any || self.paths.iter().any(|p| paths_equal(p, &resolved)) {
                return Ok(resolved);
            }
            if !named {
                return Err(deny());
            }
            if writable_by_tools(paths, &resolved) {
                return Err(ToolError::PermissionDenied(format!(
                    "'{requested}' resolves to '{}', which is inside an allowed directory that \
                     tools can write to. Allow it by absolute path in allowed_commands if that \
                     is intended.",
                    resolved.display()
                )));
            }
            return Ok(resolved);
        }

        let candidate = if Path::new(requested).is_absolute() {
            PathBuf::from(requested)
        } else {
            cwd.join(requested)
        };
        let resolved = match invocation_path(&candidate) {
            Ok(p) => p,
            // Do not reveal whether an arbitrary path exists.
            Err(_) if !self.any => return Err(deny()),
            Err(_) => return Err(ToolError::ProgramNotFound(requested.to_string())),
        };
        if self.any || self.paths.iter().any(|p| paths_equal(p, &resolved)) {
            return Ok(resolved);
        }
        // `/usr/bin/git` is fine when `git` is allowed and that is where
        // `git` is found on PATH.
        let file_name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if self.names.contains(&command_key(&file_name)) {
            if let Ok(by_name) = resolve_on_path(&file_name) {
                if paths_equal(&by_name, &resolved) && !writable_by_tools(paths, &resolved) {
                    return Ok(resolved);
                }
            }
        }
        Err(deny())
    }
}

/// The identity of an executable: its directory canonicalised and its file
/// name kept as invoked.
///
/// The name is kept because many programs dispatch on it (`sh` linked to
/// `dash`, multi-call binaries, toolchain proxies): running the link target
/// directly would change behaviour, and treating two names for one file as
/// the same program would let an allowed `ls` authorise `rm`.
pub fn invocation_path(path: &Path) -> std::io::Result<PathBuf> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let name = path.file_name().ok_or_else(invalid)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = std::fs::canonicalize(parent.ok_or_else(invalid)?)?;
    let full = simplify(&parent).join(name);
    // The target must exist and be a file.
    if !std::fs::metadata(&full)?.is_file() {
        return Err(invalid());
    }
    Ok(full)
}

/// Whether tools could have written the executable at `invocation`, either
/// because it sits in an allowed root or because it links into one.
fn writable_by_tools(paths: &PathRules, invocation: &Path) -> bool {
    if paths.inside_any_root(invocation) {
        return true;
    }
    match std::fs::canonicalize(invocation) {
        Ok(target) => paths.inside_any_root(&simplify(&target)),
        Err(_) => true,
    }
}

/// Normalise a program name for comparison: drop a known executable suffix,
/// and ignore case on Windows.
#[must_use]
pub fn command_key(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let suffixes: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ".com"]
    } else {
        &[".exe"]
    };
    for s in suffixes {
        if lower.ends_with(s) && lower.len() > s.len() {
            let stem = &name[..name.len() - s.len()];
            return if cfg!(windows) {
                stem.to_ascii_lowercase()
            } else {
                stem.to_string()
            };
        }
    }
    if cfg!(windows) {
        lower
    } else {
        name.to_string()
    }
}

/// Find `name` on the server's `PATH` (honouring `PATHEXT` on Windows) and
/// return its [`invocation_path`].
pub fn resolve_on_path(name: &str) -> Result<PathBuf, ToolError> {
    let found = which::which(name).map_err(|_| ToolError::ProgramNotFound(name.to_string()))?;
    invocation_path(&found).map_err(|_| ToolError::ProgramNotFound(name.to_string()))
}

/// Find a program a typed tool declared, on the server's `PATH`. Refused
/// when the file is somewhere tools can write, so an agent cannot plant its
/// own `git` ahead of the real one.
pub fn resolve_trusted_program(name: &str, paths: &PathRules) -> Result<PathBuf, ToolError> {
    let resolved = resolve_on_path(name)?;
    if writable_by_tools(paths, &resolved) {
        return Err(ToolError::PermissionDenied(format!(
            "'{name}' resolves to '{}', which is inside an allowed directory that tools can \
             write to; refusing to run it",
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Which environment variables a child process receives.
#[derive(Debug)]
pub struct EnvPolicy {
    passthrough: GlobSet,
    caller: GlobSet,
}

impl EnvPolicy {
    fn compile(security: &SecurityConfig) -> Result<Self, ConfigError> {
        let mut pass: Vec<String> = BASE_ENV.iter().map(|s| (*s).to_string()).collect();
        pass.extend(security.env_passthrough.iter().cloned());
        Ok(Self {
            passthrough: env_globset(&pass, "env_passthrough")?,
            caller: env_globset(&security.caller_env, "caller_env")?,
        })
    }

    /// The environment a child starts with: the server's variables that the
    /// policy passes through, and nothing else.
    #[must_use]
    pub fn base_env(&self) -> Vec<(OsString, OsString)> {
        std::env::vars_os()
            .filter(|(k, _)| {
                let name = k.to_string_lossy();
                !name.to_ascii_uppercase().starts_with(NEVER_PASSED_PREFIX)
                    && self.passthrough.is_match(name.as_ref())
            })
            .collect()
    }

    /// Whether a caller may set the variable `name` on a child.
    #[must_use]
    pub fn caller_may_set(&self, name: &str) -> bool {
        !name.is_empty()
            && !name.contains(['=', '\0'])
            && !name.to_ascii_uppercase().starts_with(NEVER_PASSED_PREFIX)
            && self.caller.is_match(name)
    }
}

fn env_globset(patterns: &[String], key: &str) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            // Windows environment names are case-insensitive.
            .case_insensitive(cfg!(windows))
            .build()
            .map_err(|e| ConfigError(format!("[security] {key}: invalid pattern '{p}': {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| ConfigError(format!("[security] {key}: {e}")))
}

/// Whether, and where, a tool may connect.
#[derive(Debug, Clone)]
pub struct NetPolicy {
    allow: bool,
    allow_private: bool,
    hosts: Arc<Vec<String>>,
}

impl NetPolicy {
    /// Whether network access is enabled at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.allow
    }

    /// Whether loopback, private and link-local destinations are allowed.
    #[must_use]
    pub fn allow_private(&self) -> bool {
        self.allow_private
    }

    /// Whether `host` passes the host allowlist (always true when empty).
    #[must_use]
    pub fn host_allowed(&self, host: &str) -> bool {
        if self.hosts.is_empty() {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(suffix) => {
                    host.len() > suffix.len() + 1 && host.ends_with(suffix) && {
                        let cut = host.len() - suffix.len();
                        host.as_bytes()[cut - 1] == b'.'
                    }
                }
                None => host == *pattern,
            })
    }

    /// A policy for tests and tools that build one explicitly.
    #[must_use]
    pub fn new(allow: bool, allow_private: bool, hosts: Vec<String>) -> Self {
        Self {
            allow,
            allow_private,
            hosts: Arc::new(hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect()),
        }
    }
}

/// OS confinement settings resolved to absolute paths.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Requested mode.
    pub mode: SandboxMode,
    /// Extra readable directories.
    pub read_paths: Vec<PathBuf>,
    /// Extra writable directories.
    pub write_paths: Vec<PathBuf>,
}

/// The policy one tool call runs under.
#[derive(Debug, Clone)]
pub struct Policy {
    tool: String,
    paths: Arc<PathRules>,
    commands: Arc<CommandPolicy>,
    env: Arc<EnvPolicy>,
    net: NetPolicy,
    sandbox: Arc<SandboxPolicy>,
    allow_destructive: bool,
    allow_elevated: bool,
    timeout: Duration,
    max_runtime: Duration,
    max_output_bytes: usize,
}

impl Policy {
    /// Name of the tool this policy was resolved for.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Path rules.
    #[must_use]
    pub fn paths(&self) -> &Arc<PathRules> {
        &self.paths
    }

    /// Command allowlist.
    #[must_use]
    pub fn commands(&self) -> &CommandPolicy {
        &self.commands
    }

    /// Child environment rules.
    #[must_use]
    pub fn env(&self) -> &EnvPolicy {
        &self.env
    }

    /// Network rules.
    #[must_use]
    pub fn net(&self) -> &NetPolicy {
        &self.net
    }

    /// OS confinement settings.
    #[must_use]
    pub fn sandbox(&self) -> &SandboxPolicy {
        &self.sandbox
    }

    /// Whether destructive operations are permitted.
    #[must_use]
    pub fn allow_destructive(&self) -> bool {
        self.allow_destructive
    }

    /// Whether elevated operations are permitted.
    #[must_use]
    pub fn allow_elevated(&self) -> bool {
        self.allow_elevated
    }

    /// Default timeout for a call.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Ceiling for any call.
    #[must_use]
    pub fn max_runtime(&self) -> Duration {
        self.max_runtime
    }

    /// The timeout to use given an optional caller request, never above the
    /// ceiling.
    #[must_use]
    pub fn effective_timeout(&self, requested_secs: Option<u64>) -> Duration {
        match requested_secs {
            Some(s) => Duration::from_secs(s.max(1)).min(self.max_runtime),
            None => self.timeout,
        }
    }

    /// Maximum bytes per output stream or file read.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Fail unless destructive operations are permitted.
    pub fn require_destructive(&self, what: &str) -> Result<(), ToolError> {
        if self.allow_destructive {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(format!(
                "{what} is destructive and allow_destructive is off. The operator can enable it \
                 for this tool with [tools.{}] allow_destructive = true.",
                self.tool
            )))
        }
    }

    /// Fail unless elevated operations are permitted.
    pub fn require_elevated(&self, what: &str) -> Result<(), ToolError> {
        if self.allow_elevated {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(format!(
                "{what} needs administrator rights and allow_elevated is off. The operator can \
                 enable it for this tool with [tools.{}] allow_elevated = true.",
                self.tool
            )))
        }
    }

    /// Fail unless network access is permitted.
    pub fn require_network(&self) -> Result<(), ToolError> {
        if self.net.allow {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(format!(
                "this tool needs network access and allow_network is off. The operator can \
                 enable it with [security] allow_network = true or [tools.{}] allow_network = \
                 true.",
                self.tool
            )))
        }
    }
}

/// Every policy derived from one configuration.
#[derive(Debug)]
pub struct PolicySet {
    base: Arc<Policy>,
    overrides: HashMap<String, Arc<Policy>>,
    warnings: Vec<String>,
}

impl PolicySet {
    /// Compile the policies for `config`. `protected` lists server-owned
    /// files and directories (config file, state, logs) no tool may touch.
    pub fn compile(config: &Config, protected: &[PathBuf]) -> Result<Self, ConfigError> {
        let mut warnings = Vec::new();
        let s = &config.security;
        let protected: Vec<PathBuf> = protected
            .iter()
            .map(|p| {
                std::fs::canonicalize(p).map_or_else(|_| lexical_normalize(p), |c| simplify(&c))
            })
            .collect();

        let paths = Arc::new(PathRules::compile(
            &s.allowed_paths,
            s,
            &protected,
            &mut warnings,
        )?);
        let commands = Arc::new(CommandPolicy::compile(&s.allowed_commands, &mut warnings));
        let env = Arc::new(EnvPolicy::compile(s)?);
        let hosts: Vec<String> = s.allowed_hosts.clone();
        let sandbox = Arc::new(SandboxPolicy {
            mode: s.sandbox.mode,
            read_paths: s
                .sandbox
                .read_paths
                .iter()
                .map(|p| expand_home(p))
                .collect(),
            write_paths: s
                .sandbox
                .write_paths
                .iter()
                .map(|p| expand_home(p))
                .collect(),
        });
        let max_runtime = Duration::from_secs(s.max_runtime_secs.max(1));
        let base = Arc::new(Policy {
            tool: String::new(),
            paths,
            commands,
            env,
            net: NetPolicy::new(s.allow_network, s.allow_private_network, hosts),
            sandbox,
            allow_destructive: s.allow_destructive,
            allow_elevated: s.allow_elevated,
            timeout: Duration::from_secs(s.default_timeout_secs.max(1)).min(max_runtime),
            max_runtime,
            max_output_bytes: s.max_output_bytes,
        });

        let mut overrides = HashMap::new();
        for (name, ov) in &config.tools {
            overrides.insert(
                name.clone(),
                Arc::new(apply_override(
                    &base,
                    name,
                    ov,
                    s,
                    &protected,
                    &mut warnings,
                )?),
            );
        }
        Ok(Self {
            base,
            overrides,
            warnings,
        })
    }

    /// The policy for `tool`.
    #[must_use]
    pub fn for_tool(&self, tool: &str) -> Arc<Policy> {
        match self.overrides.get(tool) {
            Some(p) => p.clone(),
            None => {
                let mut p = (*self.base).clone();
                p.tool = tool.to_string();
                Arc::new(p)
            }
        }
    }

    /// Non-fatal findings from compilation, for the operator.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

fn apply_override(
    base: &Policy,
    name: &str,
    ov: &ToolOverride,
    security: &SecurityConfig,
    protected: &[PathBuf],
    warnings: &mut Vec<String>,
) -> Result<Policy, ConfigError> {
    let mut p = base.clone();
    p.tool = name.to_string();
    if let Some(extra) = &ov.allowed_paths {
        let mut all = security.allowed_paths.clone();
        all.extend(extra.iter().cloned());
        p.paths = Arc::new(PathRules::compile(&all, security, protected, warnings)?);
    }
    if let Some(extra) = &ov.allowed_commands {
        let mut all = security.allowed_commands.clone();
        all.extend(extra.iter().cloned());
        p.commands = Arc::new(CommandPolicy::compile(&all, warnings));
    }
    if let Some(t) = ov.timeout_secs {
        p.timeout = Duration::from_secs(t.max(1)).min(p.max_runtime);
    }
    if let Some(m) = ov.max_output_bytes {
        p.max_output_bytes = m.max(1024);
    }
    if let Some(n) = ov.allow_network {
        p.net.allow = n;
    }
    if let Some(d) = ov.allow_destructive {
        p.allow_destructive = d;
    }
    if let Some(e) = ov.allow_elevated {
        p.allow_elevated = e;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(security: &SecurityConfig) -> (PathRules, Vec<String>) {
        let mut w = Vec::new();
        let r = PathRules::compile(&security.allowed_paths, security, &[], &mut w).unwrap();
        (r, w)
    }

    fn abs(p: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:{}", p.replace('/', "\\")))
        } else {
            PathBuf::from(p)
        }
    }

    #[test]
    fn builtin_patterns_deny_credentials_in_any_case() {
        let (r, _) = rules(&SecurityConfig::default());
        for p in [
            "/w/.env",
            "/w/.ENV",
            "/w/.env.local",
            "/w/.env.production",
            "/w/a/id_ed25519",
            "/w/a/ID_RSA.pub",
            "/w/.ssh",
            "/w/.ssh/config",
            "/w/x/.aws/credentials",
            "/w/server.PEM",
            "/w/.npmrc",
        ] {
            assert!(
                r.denied(&abs(p), Access::Read).is_some(),
                "{p} should be denied"
            );
        }
        for p in [
            "/w/.env.example",
            "/w/src/main.rs",
            "/w/environment.md",
            "/w/.envrc",
        ] {
            assert!(
                r.denied(&abs(p), Access::Read).is_none(),
                "{p} should be allowed"
            );
        }
    }

    #[test]
    fn denying_a_directory_denies_everything_beneath_it() {
        let s = SecurityConfig {
            denied_paths: vec!["**/secrets/**".into()],
            ..Default::default()
        };
        let (r, _) = rules(&s);
        assert!(r.denied(&abs("/w/secrets"), Access::Read).is_some());
        assert!(r.denied(&abs("/w/secrets/a/b.txt"), Access::Read).is_some());
        assert!(r.denied(&abs("/w/open/a.txt"), Access::Read).is_none());
    }

    #[test]
    fn custom_denies_extend_the_builtin_set() {
        let s = SecurityConfig {
            denied_paths: vec!["**/private/**".into()],
            ..Default::default()
        };
        let (r, _) = rules(&s);
        assert!(r.denied(&abs("/w/.env"), Access::Read).is_some());
        assert!(r.denied(&abs("/w/private/x"), Access::Read).is_some());
    }

    #[test]
    fn git_directories_are_read_only() {
        let (r, _) = rules(&SecurityConfig::default());
        assert!(r
            .denied(&abs("/w/.git/hooks/pre-commit"), Access::Write)
            .is_some());
        assert!(r.denied(&abs("/w/sub/.git"), Access::Write).is_some());
        assert!(r.denied(&abs("/w/.git/HEAD"), Access::Read).is_none());
        assert!(r.denied(&abs("/w/.gitignore"), Access::Write).is_none());
    }

    #[test]
    fn protected_server_files_are_denied() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let set = PolicySet::compile(&Config::default(), std::slice::from_ref(&cfg)).unwrap();
        let p = set.for_tool("fs_read");
        let canonical = simplify(&std::fs::canonicalize(&cfg).unwrap());
        assert!(p.paths().denied(&canonical, Access::Read).is_some());
    }

    #[test]
    fn roots_are_directories_and_legacy_globs_are_handled() {
        let dir = tempfile::tempdir().unwrap();
        let root = simplify(&std::fs::canonicalize(dir.path()).unwrap());
        let entry = format!("{}/**", slash_string(&root));
        let s = SecurityConfig {
            allowed_paths: vec![entry],
            ..Default::default()
        };
        let (r, w) = rules(&s);
        assert_eq!(r.roots().len(), 1);
        assert!(w.iter().any(|m| m.contains("directories since 0.2")));
        assert!(r.root_of(&root).is_some(), "the root itself is allowed");
        assert!(r.root_of(&root.join("a/b")).is_some());
        assert!(r.root_of(root.parent().unwrap()).is_none());

        let s = SecurityConfig {
            allowed_paths: vec!["/work/*.rs".into()],
            ..Default::default()
        };
        let mut w = Vec::new();
        assert!(PathRules::compile(&s.allowed_paths, &s, &[], &mut w).is_err());
    }

    #[test]
    fn missing_roots_warn_and_are_ignored() {
        let s = SecurityConfig {
            allowed_paths: vec![slash_string(&abs("/definitely/not/here-nebula"))],
            ..Default::default()
        };
        let (r, w) = rules(&s);
        assert!(r.is_empty());
        assert!(w.iter().any(|m| m.contains("unusable")));
    }

    #[test]
    fn sibling_prefix_is_not_inside_a_root() {
        assert!(path_starts_with(&abs("/work/a"), &abs("/work")));
        assert!(!path_starts_with(&abs("/workshop/a"), &abs("/work")));
        assert!(paths_equal(&abs("/work"), &abs("/work")));
    }

    #[test]
    fn empty_command_allowlist_denies() {
        let mut w = Vec::new();
        let c = CommandPolicy::compile(&[], &mut w);
        let (r, _) = rules(&SecurityConfig::default());
        assert!(matches!(
            c.authorize("git", Path::new("."), &r),
            Err(ToolError::CommandNotAllowed(_))
        ));
    }

    #[test]
    fn command_keys_ignore_exe_suffix() {
        assert_eq!(command_key("git.exe"), "git");
        assert_eq!(command_key("git"), "git");
        assert_eq!(command_key(".exe"), ".exe");
    }

    #[test]
    fn wildcard_is_only_a_standalone_entry() {
        let mut w = Vec::new();
        let c = CommandPolicy::compile(&["git*".to_string()], &mut w);
        assert!(!c.allows_any());
        let c = CommandPolicy::compile(&["*".to_string()], &mut w);
        assert!(c.allows_any());
    }

    #[cfg(unix)]
    #[test]
    fn a_name_entry_never_authorises_a_different_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let planted = root.join("sh");
        std::fs::write(&planted, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();

        let s = SecurityConfig {
            allowed_paths: vec![slash_string(&root)],
            ..Default::default()
        };
        let (r, _) = rules(&s);
        let mut w = Vec::new();
        let c = CommandPolicy::compile(&["sh".to_string()], &mut w);

        // The bare name resolves on PATH, outside the root.
        let ok = c.authorize("sh", &root, &r).unwrap();
        assert!(!path_starts_with(&ok, &root));
        // The planted file with the same basename is refused, by any spelling.
        assert!(c.authorize(&planted.to_string_lossy(), &root, &r).is_err());
        assert!(c.authorize("./sh", &root, &r).is_err());
        // The real path of an allowed name is accepted.
        assert!(c.authorize(&ok.to_string_lossy(), &root, &r).is_ok());
        // An absolute-path entry authorises exactly that file.
        let c2 = CommandPolicy::compile(&[planted.to_string_lossy().into_owned()], &mut w);
        assert!(c2.authorize("./sh", &root, &r).is_ok());
        assert!(c2.authorize("sh", &root, &r).is_err());
    }

    #[test]
    fn child_environment_is_an_allowlist() {
        let s = SecurityConfig {
            env_passthrough: vec!["NEBULA_TEST_PASS_*".into(), "NEBULA_MCP_*".into()],
            caller_env: vec!["RUSTFLAGS".into()],
            ..Default::default()
        };
        let env = EnvPolicy::compile(&s).unwrap();
        assert!(env.passthrough.is_match("PATH"));
        assert!(env.passthrough.is_match("LC_ALL"));
        assert!(!env.passthrough.is_match("GITHUB_TOKEN"));
        assert!(!env.passthrough.is_match("AWS_SECRET_ACCESS_KEY"));
        assert!(env.passthrough.is_match("NEBULA_TEST_PASS_X"));
        assert!(env.caller_may_set("RUSTFLAGS"));
        assert!(!env.caller_may_set("LD_PRELOAD"));
        assert!(!env.caller_may_set("NEBULA_MCP_AUTH_TOKEN"));
        // The server's own variables never pass, even when a pattern says so.
        assert!(env
            .base_env()
            .iter()
            .all(|(k, _)| !k.to_string_lossy().starts_with("NEBULA_MCP_")));
    }

    #[test]
    fn host_allowlist_matches_exact_and_wildcard() {
        let n = NetPolicy::new(
            true,
            false,
            vec!["api.github.com".into(), "*.Example.com".into()],
        );
        assert!(n.host_allowed("api.github.com"));
        assert!(n.host_allowed("API.GitHub.com."));
        assert!(n.host_allowed("a.example.com"));
        assert!(!n.host_allowed("example.com"));
        assert!(!n.host_allowed("evilexample.com"));
        assert!(!n.host_allowed("github.com"));
        assert!(NetPolicy::new(true, false, vec![]).host_allowed("anything.test"));
    }

    #[test]
    fn overrides_scope_gates_to_one_tool() {
        let cfg = Config::from_toml_str(
            "[tools.fs_delete]\nallow_destructive = true\ntimeout_secs = 5\n\
             [tools.net_http]\nallow_network = true\n",
        )
        .unwrap();
        let set = PolicySet::compile(&cfg, &[]).unwrap();
        assert!(set
            .for_tool("fs_delete")
            .require_destructive("delete")
            .is_ok());
        assert!(set.for_tool("fs_write").require_destructive("x").is_err());
        assert_eq!(set.for_tool("fs_delete").timeout(), Duration::from_secs(5));
        assert!(set.for_tool("net_http").require_network().is_ok());
        assert!(set.for_tool("net_dns").require_network().is_err());
    }

    #[test]
    fn caller_timeouts_never_exceed_the_ceiling() {
        let cfg = Config::from_toml_str("[security]\nmax_runtime_secs = 10\n").unwrap();
        let p = PolicySet::compile(&cfg, &[]).unwrap().for_tool("t");
        assert_eq!(p.effective_timeout(Some(999)), Duration::from_secs(10));
        assert_eq!(p.effective_timeout(Some(3)), Duration::from_secs(3));
        assert_eq!(p.timeout(), Duration::from_secs(10));
    }
}
