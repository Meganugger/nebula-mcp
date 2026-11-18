//! Permission policy engine.
//!
//! Every tool call runs under an [`EffectivePolicy`] derived by layering the
//! per-tool override (if any) on top of the global [`SecurityConfig`] baseline.
//! The policy is the single choke point for:
//!
//! * path access (allow/deny glob lists, lexical `..` containment and
//!   symlink-aware resolution),
//! * command allowlisting (resolved executable match, Windows-insensitive),
//! * timeouts and maximum runtime,
//! * maximum captured output,
//! * elevation, network and destructive-operation gates.
//!
//! An empty allowlist denies rather than permits. The only "allow everything"
//! switch is an explicit standalone `"*"` entry in `allowed_commands`.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use globset::{GlobSet, GlobSetBuilder};

use crate::config::{Config, SecurityConfig, ToolOverride};
use crate::error::ToolError;

/// A fully-resolved policy for a single tool.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    tool: String,
    allowed: GlobSet,
    denied: GlobSet,
    allowed_has_patterns: bool,
    allowed_pattern_count: usize,
    allowed_commands: Vec<String>,
    timeout: Duration,
    max_runtime: Duration,
    max_output_bytes: usize,
    allow_elevated: bool,
    allow_network: bool,
    allow_destructive: bool,
}

impl EffectivePolicy {
    /// Resolve the effective policy for `tool` from `config`.
    pub fn resolve(config: &Config, tool: &str) -> Result<Self, ToolError> {
        let base = &config.security;
        let ov = config.tools.get(tool);
        Self::build(tool, base, ov)
    }

    /// Build a policy from an explicit baseline and optional override.
    /// Exposed for unit testing and programmatic construction.
    pub fn build(
        tool: &str,
        base: &SecurityConfig,
        ov: Option<&ToolOverride>,
    ) -> Result<Self, ToolError> {
        let mut allowed_patterns = base.allowed_paths.clone();
        let mut allowed_commands = base.allowed_commands.clone();
        let mut denied_patterns = crate::config::default_denied_paths();
        denied_patterns.extend(base.denied_paths.iter().cloned());
        let mut timeout_secs = base.default_timeout_secs;
        let mut max_output_bytes = base.max_output_bytes;
        let mut allow_destructive = base.allow_destructive;
        let mut allow_elevated = base.allow_elevated;

        if let Some(o) = ov {
            if let Some(extra) = &o.allowed_paths {
                allowed_patterns.extend(extra.iter().cloned());
            }
            if let Some(extra) = &o.allowed_commands {
                allowed_commands.extend(extra.iter().cloned());
            }
            if let Some(t) = o.timeout_secs {
                timeout_secs = t;
            }
            if let Some(m) = o.max_output_bytes {
                max_output_bytes = m;
            }
            if let Some(d) = o.allow_destructive {
                allow_destructive = d;
            }
            if let Some(e) = o.allow_elevated {
                allow_elevated = e;
            }
        }

        // Clamp the requested timeout to the absolute maximum runtime.
        let max_runtime = Duration::from_secs(base.max_runtime_secs.max(1));
        let timeout = Duration::from_secs(timeout_secs.max(1)).min(max_runtime);

        let allowed = build_globset(&allowed_patterns)?;
        let denied = build_globset(&denied_patterns)?;

        Ok(Self {
            tool: tool.to_string(),
            allowed,
            denied,
            allowed_has_patterns: !allowed_patterns.is_empty(),
            allowed_pattern_count: allowed_patterns.len(),
            allowed_commands,
            timeout,
            max_runtime,
            max_output_bytes,
            allow_elevated,
            allow_network: base.allow_network,
            allow_destructive,
        })
    }

    /// Name of the tool this policy applies to.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The resolved per-call timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The absolute maximum runtime ceiling.
    #[must_use]
    pub fn max_runtime(&self) -> Duration {
        self.max_runtime
    }

    /// Effective timeout, honouring a caller-requested value but never
    /// exceeding the configured maximum runtime.
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

    /// Whether network-reaching operations are permitted.
    #[must_use]
    pub fn allow_network(&self) -> bool {
        self.allow_network
    }

    /// Whether destructive operations are permitted.
    #[must_use]
    pub fn allow_destructive(&self) -> bool {
        self.allow_destructive
    }

    /// Whether elevated execution is permitted.
    #[must_use]
    pub fn allow_elevated(&self) -> bool {
        self.allow_elevated
    }

    /// The command allowlist (names or explicit executable paths).
    #[must_use]
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Number of configured allowed-path glob patterns.
    #[must_use]
    pub fn allowed_pattern_count(&self) -> usize {
        self.allowed_pattern_count
    }

    /// Ensure elevation is permitted, returning an error otherwise.
    pub fn ensure_elevation_allowed(&self) -> Result<(), ToolError> {
        if self.allow_elevated {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(
                "elevated execution is disabled by policy".to_string(),
            ))
        }
    }

    /// Ensure destructive operations are permitted.
    pub fn ensure_destructive_allowed(&self, what: &str) -> Result<(), ToolError> {
        if self.allow_destructive {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(format!(
                "destructive operation '{what}' is disabled by policy"
            )))
        }
    }

    /// Ensure network operations are permitted.
    pub fn ensure_network_allowed(&self) -> Result<(), ToolError> {
        if self.allow_network {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(
                "network access is disabled by policy".to_string(),
            ))
        }
    }

    /// Validate and resolve a path against the allow/deny lists.
    ///
    /// Returns a path whose existing components have been canonicalized on
    /// success. The input may be relative; it is resolved against `base_dir`.
    /// Canonicalizing the deepest existing ancestor catches symlink escapes
    /// both for existing files and for new files below an existing symlink.
    pub fn check_path(&self, path: &Path, base_dir: &Path) -> Result<PathBuf, ToolError> {
        let normalized = normalize_path(path, base_dir)?;
        let checked = resolve_existing_ancestor(&normalized)?;

        // Deny list always wins.
        if self.denied.is_match(&checked) {
            return Err(ToolError::PermissionDenied(format!(
                "path '{}' matches a denied pattern",
                checked.display()
            )));
        }

        if !self.allowed_has_patterns {
            return Err(ToolError::PermissionDenied(format!(
                "no allowed_paths configured; access to '{}' denied",
                checked.display()
            )));
        }

        if !self.allowed.is_match(&checked) {
            return Err(ToolError::PathNotAllowed {
                path: checked.display().to_string(),
            });
        }

        Ok(checked)
    }

    /// Validate an executable name/path against the command allowlist.
    ///
    /// Bare command names match the resolved executable's basename. A program
    /// supplied as a path must be explicitly allowed by that path (or by
    /// `"*"`); this prevents a planted `/tmp/echo` from satisfying an
    /// allowlist entry for the trusted `echo` command.
    pub fn check_command(&self, program: &str) -> Result<(), ToolError> {
        self.check_command_resolved(program, Path::new(program))
    }

    /// Validate a command against the executable that will actually be
    /// spawned. `resolved` must be the result of executable resolution.
    pub fn check_command_resolved(&self, program: &str, resolved: &Path) -> Result<(), ToolError> {
        if self.allowed_commands.is_empty() {
            return Err(ToolError::CommandNotAllowed(program.to_string()));
        }
        let explicit_path = has_path_separator(program);
        let candidate = command_key(program);
        let resolved = resolved.to_string_lossy();
        let permitted = self.allowed_commands.iter().any(|c| {
            if c == "*" {
                return true;
            }
            if explicit_path || has_path_separator(c) {
                return normalize_command_path(c)
                    .map(|p| p == normalize_command_path(&resolved).unwrap_or_default())
                    .unwrap_or(false);
            }
            command_key(c) == candidate
        });
        if permitted {
            Ok(())
        } else {
            Err(ToolError::CommandNotAllowed(program.to_string()))
        }
    }

    /// Truncate output to the configured maximum, returning the (possibly
    /// truncated) bytes and whether truncation occurred.
    #[must_use]
    pub fn clamp_output<'a>(&self, data: &'a [u8]) -> (&'a [u8], bool) {
        if data.len() > self.max_output_bytes {
            (&data[..self.max_output_bytes], true)
        } else {
            (data, false)
        }
    }
}

/// Reduce an executable path/name to a comparison key.
fn has_path_separator(program: &str) -> bool {
    program.contains('/') || program.contains('\\') || Path::new(program).is_absolute()
}

fn normalize_command_path(program: &str) -> Option<String> {
    Some(
        std::fs::canonicalize(program)
            .unwrap_or_else(|_| PathBuf::from(program))
            .to_string_lossy()
            .replace('\\', "/"),
    )
}

fn command_key(program: &str) -> String {
    let base = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    let stem = base.strip_suffix(".exe").unwrap_or(base);
    if cfg!(windows) {
        stem.to_ascii_lowercase()
    } else {
        stem.to_string()
    }
}

/// Build a [`GlobSet`] from patterns, enabling literal-separator matching so
/// `**` behaves intuitively across path separators. A trailing `/**` also
/// grants the directory itself, which is what operators expect from an
/// allowed root.
fn build_globset(patterns: &[String]) -> Result<GlobSet, ToolError> {
    let mut builder = GlobSetBuilder::new();
    let mut expanded = BTreeSet::new();
    for pattern in patterns {
        expanded.insert(pattern.clone());
        if let Some(root) = pattern.strip_suffix("/**") {
            expanded.insert(root.to_string());
        }
    }
    for p in expanded {
        let glob = globset::GlobBuilder::new(&p)
            .literal_separator(true)
            .case_insensitive(cfg!(windows))
            .build()
            .map_err(|e| ToolError::Internal(format!("invalid glob pattern '{p}': {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| ToolError::Internal(format!("building glob set: {e}")))
}

/// Canonicalize the deepest existing ancestor and append the missing suffix.
///
/// This is intentionally performed before matching the allowlist. A lexical
/// path such as `allowed/link/secret` is not trusted merely because the
/// lexical spelling is under `allowed`; if `link` points outside, the
/// canonical path is outside as well. New files are handled by canonicalizing
/// their nearest existing parent.
fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf, ToolError> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        let name = existing.file_name().ok_or_else(|| {
            ToolError::PermissionDenied(format!(
                "path '{}' has no existing ancestor",
                path.display()
            ))
        })?;
        missing.push(name.to_os_string());
        if !existing.pop() {
            return Err(ToolError::PermissionDenied(format!(
                "path '{}' has no existing ancestor",
                path.display()
            )));
        }
    }
    let mut resolved = std::fs::canonicalize(&existing).map_err(|e| {
        ToolError::PermissionDenied(format!("cannot resolve path '{}': {e}", path.display()))
    })?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

/// Lexically normalise `path` (resolving `.`/`..`) against `base_dir` without
/// touching the filesystem, then reject any residual parent traversal.
///
/// Filesystem-free normalisation avoids TOCTOU races and works for paths that
/// do not yet exist (e.g. a file about to be written).
pub fn normalize_path(path: &Path, base_dir: &Path) -> Result<PathBuf, ToolError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };

    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(ToolError::PermissionDenied(format!(
                        "path '{}' traverses above the filesystem root",
                        path.display()
                    )));
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;

    fn policy_with(allowed: &[&str], cmds: &[&str]) -> EffectivePolicy {
        let base = SecurityConfig {
            allowed_paths: allowed.iter().map(|s| s.to_string()).collect(),
            allowed_commands: cmds.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        EffectivePolicy::build("test.tool", &base, None).unwrap()
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let p = policy_with(&[], &[]);
        let err = p
            .check_path(Path::new("/work/a.txt"), Path::new("/work"))
            .unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[test]
    fn allowed_glob_permits_matching_path() {
        let p = policy_with(&["/work/**"], &[]);
        let ok = p
            .check_path(Path::new("/work/src/main.rs"), Path::new("/work"))
            .unwrap();
        assert_eq!(ok, PathBuf::from("/work/src/main.rs"));
    }

    #[test]
    fn denied_glob_overrides_allowed() {
        let base = SecurityConfig {
            allowed_paths: vec!["/work/**".into()],
            denied_paths: vec!["**/*.key".into()],
            ..Default::default()
        };
        let p = EffectivePolicy::build("t", &base, None).unwrap();
        let err = p
            .check_path(Path::new("/work/secret.key"), Path::new("/work"))
            .unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[test]
    fn parent_traversal_is_contained() {
        let p = policy_with(&["/work/**"], &[]);
        let err = p
            .check_path(Path::new("../etc/passwd"), Path::new("/work"))
            .unwrap_err();
        // Normalises to /etc/passwd which is outside /work/**.
        assert!(matches!(err, ToolError::PathNotAllowed { .. }));
    }

    #[test]
    fn relative_paths_resolve_against_base() {
        let p = policy_with(&["/work/**"], &[]);
        let ok = p
            .check_path(Path::new("src/lib.rs"), Path::new("/work"))
            .unwrap();
        assert_eq!(ok, PathBuf::from("/work/src/lib.rs"));
    }

    #[test]
    fn command_allowlist_matches_basename() {
        let p = policy_with(&[], &["git", "cargo"]);
        assert!(p.check_command("git").is_ok());
        assert!(p.check_command("/usr/bin/git").is_err());
        let resolved =
            std::fs::canonicalize("/usr/bin/git").unwrap_or_else(|_| PathBuf::from("/usr/bin/git"));
        assert!(p.check_command_resolved("git", &resolved).is_ok());
        assert!(p.check_command("rm").is_err());
    }

    #[test]
    fn empty_command_allowlist_denies() {
        let p = policy_with(&[], &[]);
        assert!(p.check_command("git").is_err());
    }

    #[test]
    fn wildcard_command_allowlist_permits_any_command() {
        let p = policy_with(&[], &["*"]);
        for program in [
            "powershell.exe",
            "git",
            "/usr/bin/python3",
            "C:\\Tools\\some-arbitrary-tool.exe",
            "totally-unknown-binary",
        ] {
            assert!(
                p.check_command(program).is_ok(),
                "{program} should be allowed"
            );
        }

        // Without a standalone "*" entry the allowlist stays exact.
        let p = policy_with(&[], &["powershell.exe"]);
        assert!(p.check_command("powershell.exe").is_ok());
        assert!(p.check_command("git.exe").is_err());

        let p = policy_with(&[], &["git.exe", "python.exe"]);
        assert!(p.check_command("git.exe").is_ok());
        assert!(p.check_command("python.exe").is_ok());
        assert!(p.check_command("cargo.exe").is_err());

        // "*" is only a wildcard as a standalone entry, not as a glob.
        let p = policy_with(&[], &["git*"]);
        assert!(p.check_command("github").is_err());
    }

    #[test]
    fn output_clamped_to_limit() {
        let base = SecurityConfig {
            max_output_bytes: 4,
            ..Default::default()
        };
        let p = EffectivePolicy::build("t", &base, None).unwrap();
        let (out, truncated) = p.clamp_output(b"123456");
        assert_eq!(out, b"1234");
        assert!(truncated);
    }

    #[test]
    fn per_tool_elevation_override_grants_scoped_elevation() {
        let base = SecurityConfig {
            allow_elevated: false,
            ..Default::default()
        };
        // Baseline denies elevation.
        let p = EffectivePolicy::build("docker.rm", &base, None).unwrap();
        assert!(p.ensure_elevation_allowed().is_err());
        // A per-tool override grants it just for this tool.
        let ov = crate::config::ToolOverride {
            allow_elevated: Some(true),
            ..Default::default()
        };
        let p2 = EffectivePolicy::build("docker.rm", &base, Some(&ov)).unwrap();
        assert!(p2.ensure_elevation_allowed().is_ok());
    }

    #[test]
    fn allowed_root_matches_the_root_directory() {
        let p = policy_with(&["/work/**"], &[]);
        assert!(p.check_path(Path::new("/work"), Path::new("/")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_outside_allowed_root_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(&outside, allowed.join("link")).unwrap();
        let p = policy_with(&[format!("{}/**", allowed.display()).as_str()], &[]);
        let err = p
            .check_path(&allowed.join("link/secret.txt"), dir.path())
            .unwrap_err();
        assert!(matches!(err, ToolError::PathNotAllowed { .. }));
    }
}
