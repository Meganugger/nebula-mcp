//! Path rules: which files a tool may touch, decided on the real path.
//!
//! A request is accepted only if, after every symbolic link has been resolved,
//! the path lies beneath an allowed root, matches an allow pattern, and neither
//! it nor any directory above it matches a deny pattern. The result is a
//! [`CheckedPath`], which only this module can create and which is the only
//! thing [`crate::fs::Fs`] will open.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::error::ToolError;

/// File names differ only by case on these platforms' default filesystems.
const CASE_INSENSITIVE_FS: bool = cfg!(any(windows, target_os = "macos"));

/// An allowed directory: where it was configured and where it really is.
#[derive(Debug, Clone)]
struct Root {
    lexical: PathBuf,
    real: PathBuf,
}

/// Compiled path policy for one tool.
#[derive(Debug)]
pub struct PathRules {
    roots: Vec<Root>,
    allow: GlobSet,
    allow_patterns: Vec<String>,
    deny: GlobSet,
    deny_patterns: Vec<String>,
    protected: Vec<PathBuf>,
}

/// A path that has passed the policy.
///
/// It records the allowed root it was found beneath and the fully resolved
/// path relative to that root, so the filesystem layer can open it one
/// component at a time without following any link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedPath {
    root: PathBuf,
    rel: PathBuf,
    abs: PathBuf,
}

impl CheckedPath {
    /// The resolved absolute path. Use this for display and when a path must
    /// be handed to an external program.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.abs
    }

    /// The resolved absolute path as a string (lossy for non-UTF-8 names).
    #[must_use]
    pub fn display_string(&self) -> String {
        self.abs.display().to_string()
    }

    /// Whether this is an allowed root itself rather than something inside it.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.rel.as_os_str().is_empty()
    }

    /// Final path component, if any.
    #[must_use]
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.abs.file_name()
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn rel(&self) -> &Path {
        &self.rel
    }
}

impl std::fmt::Display for CheckedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.abs.display())
    }
}

/// What a directory walk may do with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Matches an allow pattern and no deny pattern: may be reported and read.
    Visible,
    /// A directory that is not itself allowed but may contain allowed entries.
    TraverseOnly,
    /// Denied: must not be reported, read or descended into.
    Denied,
}

impl PathRules {
    /// Compile rules from allow and deny patterns.
    ///
    /// `base` is the directory relative patterns and relative requests resolve
    /// against. `protected` lists files or directories no tool may touch
    /// whatever the patterns say (the server's own configuration and logs).
    pub fn build(
        allowed: &[String],
        denied: &[String],
        protected: &[PathBuf],
        base: &Path,
    ) -> Result<Self, ToolError> {
        let mut roots: Vec<Root> = Vec::new();
        let mut allow = GlobSetBuilder::new();
        let mut allow_patterns = Vec::new();

        for raw in allowed {
            let pattern = absolutize_pattern(raw, base)?;
            let lexical = PathBuf::from(literal_prefix(&pattern));
            let real = real_path_or_same(&lexical);
            let mut variants = expand_allow(&pattern);
            if real != lexical {
                let lexical_prefix = match_string(&lexical);
                let real_prefix = match_string(&real);
                let moved: Vec<String> = variants
                    .iter()
                    .filter_map(|v| v.strip_prefix(lexical_prefix.as_str()))
                    .map(|rest| format!("{real_prefix}{rest}"))
                    .collect();
                variants.extend(moved);
            }
            for v in variants {
                allow.add(compile(&v, CASE_INSENSITIVE_FS, raw)?);
                allow_patterns.push(v);
            }
            if !roots.iter().any(|r| r.real == real) {
                roots.push(Root { lexical, real });
            }
        }

        let mut deny = GlobSetBuilder::new();
        let mut deny_patterns = Vec::new();
        for raw in denied {
            for v in expand_deny(raw) {
                // Deny patterns always ignore case: a case-insensitive mount
                // must not turn `.ENV` into a way around `.env`.
                deny.add(compile(&v, true, raw)?);
                deny_patterns.push(v);
            }
        }

        let build = |b: GlobSetBuilder| {
            b.build()
                .map_err(|e| ToolError::InvalidArguments(format!("building path patterns: {e}")))
        };
        Ok(Self {
            roots,
            allow: build(allow)?,
            allow_patterns,
            deny: build(deny)?,
            deny_patterns,
            protected: protected.iter().map(|p| real_path_or_same(p)).collect(),
        })
    }

    /// Number of allowed roots.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// The allowed roots as configured (for diagnostics).
    #[must_use]
    pub fn roots(&self) -> Vec<PathBuf> {
        self.roots.iter().map(|r| r.lexical.clone()).collect()
    }

    /// The compiled allow patterns (for diagnostics).
    #[must_use]
    pub fn allow_patterns(&self) -> &[String] {
        &self.allow_patterns
    }

    /// The compiled deny patterns (for diagnostics).
    #[must_use]
    pub fn deny_patterns(&self) -> &[String] {
        &self.deny_patterns
    }

    /// Check a requested path and resolve it to its real location.
    ///
    /// The path need not exist yet: the deepest existing directory is
    /// resolved and the remaining components are appended as given.
    pub fn resolve(&self, input: &Path, base: &Path) -> Result<CheckedPath, ToolError> {
        let lexical = normalize(input, base)?;

        if self.is_denied(&lexical) {
            return Err(denied(&lexical));
        }
        if self.roots.is_empty() {
            return Err(ToolError::PermissionDenied(format!(
                "no allowed_paths are configured, so '{}' cannot be accessed",
                lexical.display()
            )));
        }
        let (root, rel) = self
            .root_containing(&lexical)
            .ok_or_else(|| not_allowed(&lexical))?;

        let dir = open_root(&root.real)?;
        let (root, rel) = match canonicalize_within(&dir, &rel) {
            Ok(real_rel) => (root.clone(), real_rel),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // The path leaves this root through a link. That is acceptable
                // only if it lands inside another allowed root.
                let target = ambient_canonicalize(&root.real.join(&rel)).map_err(|_| {
                    ToolError::PathNotAllowed {
                        path: format!(
                            "{} (it resolves outside the allowed roots through a link)",
                            lexical.display()
                        ),
                    }
                })?;
                let (other, other_rel) =
                    self.root_containing_real(&target)
                        .ok_or_else(|| ToolError::PathNotAllowed {
                            path: format!(
                                "{} (it resolves to {}, outside the allowed roots)",
                                lexical.display(),
                                target.display()
                            ),
                        })?;
                (other.clone(), other_rel)
            }
            Err(e) => {
                return Err(ToolError::Io(format!(
                    "resolving {}: {e}",
                    lexical.display()
                )))
            }
        };

        let abs = if rel.as_os_str().is_empty() {
            root.real.clone()
        } else {
            root.real.join(&rel)
        };
        if self.is_denied(&abs) {
            return Err(denied(&abs));
        }
        if !self.allow.is_match(match_string(&abs)) {
            return Err(not_allowed(&abs));
        }
        Ok(CheckedPath {
            root: root.real,
            rel,
            abs,
        })
    }

    /// Check a requested path as a directory entry: everything above the
    /// final component is resolved, but the final component is not followed
    /// if it is a link. Use this for operations that act on the entry itself
    /// (delete, rename, inspect) rather than on what it points to.
    pub fn resolve_entry(&self, input: &Path, base: &Path) -> Result<CheckedPath, ToolError> {
        let lexical = normalize(input, base)?;
        let (Some(parent), Some(name)) = (lexical.parent(), lexical.file_name()) else {
            return self.resolve(input, base);
        };
        if self.is_denied(&lexical) {
            return Err(denied(&lexical));
        }
        let parent = self.resolve_dir_for_entry(parent, &lexical)?;
        let abs = parent.abs.join(name);
        if self.is_denied(&abs) {
            return Err(denied(&abs));
        }
        if !self.allow.is_match(match_string(&abs)) {
            return Err(not_allowed(&abs));
        }
        Ok(CheckedPath {
            root: parent.root,
            rel: parent.rel.join(name),
            abs,
        })
    }

    /// Resolve the directory that holds an entry. The directory itself need
    /// not match an allow pattern (a narrow glob may allow only the entry),
    /// but it must be beneath a root and not denied.
    fn resolve_dir_for_entry(&self, parent: &Path, entry: &Path) -> Result<CheckedPath, ToolError> {
        match self.resolve(parent, parent) {
            Ok(p) => Ok(p),
            Err(ToolError::PathNotAllowed { .. }) => {
                let (root, rel) = self
                    .root_containing(parent)
                    .ok_or_else(|| not_allowed(entry))?;
                let dir = open_root(&root.real)?;
                let rel = canonicalize_within(&dir, &rel).map_err(|_| not_allowed(entry))?;
                let abs = root.real.join(&rel);
                if self.is_denied(&abs) {
                    return Err(denied(&abs));
                }
                Ok(CheckedPath {
                    root: root.real.clone(),
                    rel,
                    abs,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Decide what a walk may do with `name` inside the already-checked
    /// directory `parent`. The entry must not be a symbolic link.
    #[must_use]
    pub fn entry_visibility(&self, parent: &CheckedPath, name: &OsString, is_dir: bool) -> Visibility {
        let abs = parent.abs.join(name);
        // The parent was already cleared, so only the entry itself can add a
        // deny match.
        if self.deny.is_match(match_string(&abs)) || self.is_protected(&abs) {
            return Visibility::Denied;
        }
        if self.allow.is_match(match_string(&abs)) {
            Visibility::Visible
        } else if is_dir {
            Visibility::TraverseOnly
        } else {
            Visibility::Denied
        }
    }

    /// Build the checked path of a non-link entry found while walking
    /// `parent`. Callers must have consulted [`Self::entry_visibility`].
    #[must_use]
    pub(crate) fn child(&self, parent: &CheckedPath, name: &OsString) -> CheckedPath {
        CheckedPath {
            root: parent.root.clone(),
            rel: parent.rel.join(name),
            abs: parent.abs.join(name),
        }
    }

    fn is_protected(&self, path: &Path) -> bool {
        self.protected.iter().any(|p| path.starts_with(p))
    }

    fn is_denied(&self, path: &Path) -> bool {
        if self.is_protected(path) {
            return true;
        }
        // A deny pattern that matches a directory covers everything in it.
        let full = match_string(path);
        let mut current = full.as_str();
        loop {
            if self.deny.is_match(current) {
                return true;
            }
            match current.rfind('/') {
                Some(idx) if idx > 0 => current = &current[..idx],
                _ => return false,
            }
        }
    }

    fn root_containing(&self, lexical: &Path) -> Option<(&Root, PathBuf)> {
        self.roots
            .iter()
            .filter_map(|root| {
                strip_root(lexical, &root.lexical)
                    .or_else(|| strip_root(lexical, &root.real))
                    .map(|rel| (root, rel))
            })
            .min_by_key(|(_, rel)| rel.components().count())
    }

    fn root_containing_real(&self, real: &Path) -> Option<(&Root, PathBuf)> {
        self.roots
            .iter()
            .filter_map(|root| strip_root(real, &root.real).map(|rel| (root, rel)))
            .min_by_key(|(_, rel)| rel.components().count())
    }
}

fn denied(path: &Path) -> ToolError {
    ToolError::PermissionDenied(format!(
        "path '{}' matches a denied pattern",
        path.display()
    ))
}

fn not_allowed(path: &Path) -> ToolError {
    ToolError::PathNotAllowed {
        path: path.display().to_string(),
    }
}

/// Open an allowed root as a directory handle.
pub(crate) fn open_root(real: &Path) -> Result<Dir, ToolError> {
    Dir::open_ambient_dir(real, ambient_authority()).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            ToolError::NotFound(format!("allowed root {} does not exist", real.display()))
        } else {
            ToolError::Io(format!("opening allowed root {}: {e}", real.display()))
        }
    })
}

/// `path` relative to `root`, comparing case-insensitively where the
/// filesystem does.
fn strip_root(path: &Path, root: &Path) -> Option<PathBuf> {
    if let Ok(rel) = path.strip_prefix(root) {
        return Some(rel.to_path_buf());
    }
    if !CASE_INSENSITIVE_FS {
        return None;
    }
    let mut p = path.components();
    for r in root.components() {
        let c = p.next()?;
        if !c
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&r.as_os_str().to_string_lossy())
        {
            return None;
        }
    }
    Some(p.as_path().to_path_buf())
}

/// Resolve `rel` beneath `dir`, following only links that stay beneath it.
/// Components that do not exist yet are kept as given.
fn canonicalize_within(dir: &Dir, rel: &Path) -> io::Result<PathBuf> {
    let mut head = rel.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        let probe: &Path = if head.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &head
        };
        match dir.canonicalize(probe) {
            Ok(real) => {
                let mut out: PathBuf = real
                    .components()
                    .filter(|c| !matches!(c, Component::CurDir))
                    .collect();
                for name in tail.iter().rev() {
                    out.push(name);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match head.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    head.pop();
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
}

/// Resolve an absolute path through the ambient filesystem, keeping any
/// not-yet-existing tail.
fn ambient_canonicalize(path: &Path) -> io::Result<PathBuf> {
    let mut head = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&head) {
            Ok(real) => {
                let mut out = simplify(&real);
                for name in tail.iter().rev() {
                    out.push(name);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match head.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    if !head.pop() {
                        return Err(e);
                    }
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
}

/// The real location of `path`, or `path` itself when it does not exist.
pub(crate) fn real_path_or_same(path: &Path) -> PathBuf {
    ambient_canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Drop the Windows verbatim prefix (`\\?\`) that canonicalisation adds, so
/// paths compare equal to the form operators write.
fn simplify(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest.to_string())
    } else {
        path.to_path_buf()
    }
}

/// The form of a path that patterns are matched against: forward slashes, no
/// trailing separator.
fn match_string(path: &Path) -> String {
    let mut s = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        s = s.replace('\\', "/");
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

fn compile(pattern: &str, case_insensitive: bool, original: &str) -> Result<globset::Glob, ToolError> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(case_insensitive)
        .backslash_escape(false)
        .build()
        .map_err(|e| ToolError::InvalidArguments(format!("invalid path pattern '{original}': {e}")))
}

fn has_glob_meta(s: &str) -> bool {
    s.contains(['*', '?', '[', '{'])
}

/// Turn a configured allow entry into an absolute pattern with forward
/// slashes: expand `~`, resolve relative entries against `base`, and remove
/// `.`/`..` and trailing separators.
fn absolutize_pattern(raw: &str, base: &Path) -> Result<String, ToolError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ToolError::InvalidArguments(
            "an allowed_paths entry is empty".to_string(),
        ));
    }
    let mut s = if cfg!(windows) {
        trimmed.replace('\\', "/")
    } else {
        trimmed.to_string()
    };
    if s == "~" || s.starts_with("~/") {
        let home = dirs::home_dir().ok_or_else(|| {
            ToolError::InvalidArguments(format!(
                "allowed_paths entry '{raw}' uses '~' but the home directory is unknown"
            ))
        })?;
        s = format!("{}{}", match_string(&home), &s[1..]);
    }
    let absolute = s.starts_with('/') || is_windows_absolute(&s);
    if !absolute {
        s = format!("{}/{}", match_string(base), s);
    }

    // Normalise components. A leading empty component is the root.
    let mut out: Vec<&str> = Vec::new();
    let mut parts = s.split('/').peekable();
    let mut prefix = String::new();
    if s.starts_with("//") {
        prefix.push_str("//");
    } else if s.starts_with('/') {
        prefix.push('/');
    }
    while let Some(part) = parts.next() {
        match part {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(ToolError::InvalidArguments(format!(
                        "allowed_paths entry '{raw}' climbs above the filesystem root"
                    )));
                }
            }
            other => out.push(other),
        }
        let _ = parts.peek();
    }
    Ok(format!("{prefix}{}", out.join("/")))
}

fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/') || s.starts_with("//")
}

/// The directory part of a pattern that contains no wildcard.
fn literal_prefix(pattern: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in pattern.split('/') {
        if has_glob_meta(part) {
            break;
        }
        out.push(part);
    }
    let joined = out.join("/");
    if joined.is_empty() {
        "/".to_string()
    } else if is_drive_only(&joined) {
        format!("{joined}/")
    } else {
        joined
    }
}

fn is_drive_only(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// An allow entry without wildcards is a directory: it allows itself and
/// everything beneath it. `dir/**` means the same. Other globs match as
/// written.
fn expand_allow(pattern: &str) -> Vec<String> {
    let join = |dir: &str| {
        if dir.ends_with('/') {
            format!("{dir}**")
        } else {
            format!("{dir}/**")
        }
    };
    if !has_glob_meta(pattern) {
        return vec![pattern.to_string(), join(pattern)];
    }
    if let Some(dir) = pattern.strip_suffix("/**") {
        if !has_glob_meta(dir) {
            let dir = if dir.is_empty() { "/" } else { dir };
            return vec![dir.to_string(), join(dir)];
        }
    }
    vec![pattern.to_string()]
}

/// A deny entry that is not anchored matches at any depth, and `dir/**` also
/// denies `dir` itself (so the directory cannot be renamed out of the way).
fn expand_deny(raw: &str) -> Vec<String> {
    let mut s = raw.trim().to_string();
    if cfg!(windows) {
        s = s.replace('\\', "/");
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    let anchored = s.starts_with('/') || is_windows_absolute(&s) || s.starts_with("**/");
    if !anchored {
        s = format!("**/{s}");
    }
    let mut out = vec![s.clone()];
    if let Some(dir) = s.strip_suffix("/**") {
        if !dir.is_empty() {
            out.push(dir.to_string());
        }
    }
    out
}

/// Lexically normalise a requested path against `base`: make it absolute and
/// remove `.` and `..` without consulting the filesystem.
pub(crate) fn normalize(input: &Path, base: &Path) -> Result<PathBuf, ToolError> {
    let text = input.to_string_lossy();
    if text.is_empty() {
        return Err(ToolError::InvalidArguments("path is empty".to_string()));
    }
    if text.contains('\0') {
        return Err(ToolError::InvalidArguments(
            "path contains a NUL byte".to_string(),
        ));
    }
    #[cfg(windows)]
    reject_special_windows_forms(input)?;

    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        base.join(input)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(ToolError::PermissionDenied(format!(
                        "path '{}' climbs above the filesystem root",
                        input.display()
                    )));
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// Whether a Windows file name would be reinterpreted by the Win32 layer:
/// alternate data streams (`name:stream`) and names ending in a dot or space,
/// which Win32 silently strips. Either would let `.env.` or `.env::$DATA`
/// reach `.env` past a deny pattern.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_reinterpreted_windows_name(name: &str) -> bool {
    name.contains(':') || name.ends_with('.') && name != "." && name != ".." || name.ends_with(' ')
}

#[cfg(windows)]
fn reject_special_windows_forms(input: &Path) -> Result<(), ToolError> {
    use std::path::Prefix;
    let bad = |why: &str| {
        Err(ToolError::InvalidArguments(format!(
            "path '{}' is not accepted: {why}",
            input.display()
        )))
    };
    let mut comps = input.components().peekable();
    if let Some(Component::Prefix(prefix)) = comps.peek() {
        match prefix.kind() {
            Prefix::DeviceNS(_) => return bad("device namespace paths are not supported"),
            Prefix::Verbatim(_) => return bad("verbatim paths are not supported"),
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {
                comps.next();
                if !matches!(comps.peek(), Some(Component::RootDir)) {
                    return bad("drive-relative paths are not supported; use C:\\dir\\file");
                }
            }
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {}
        }
    }
    for comp in input.components() {
        if let Component::Normal(name) = comp {
            if is_reinterpreted_windows_name(&name.to_string_lossy()) {
                return bad("names containing ':' or ending in '.' or ' ' are not supported");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(allowed: &[&str], denied: &[&str], base: &Path) -> PathRules {
        let allowed: Vec<String> = allowed.iter().map(|s| (*s).to_string()).collect();
        let denied: Vec<String> = denied.iter().map(|s| (*s).to_string()).collect();
        PathRules::build(&allowed, &denied, &[], base).unwrap()
    }

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap();
        (dir, simplify(&real))
    }

    #[test]
    fn empty_allow_list_denies_everything() {
        let (_g, root) = tmp();
        let r = rules(&[], &[], &root);
        let err = r.resolve(Path::new("a.txt"), &root).unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[test]
    fn a_directory_entry_allows_itself_and_everything_beneath() {
        let (_g, root) = tmp();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "x").unwrap();
        for pattern in [match_string(&root), format!("{}/**", match_string(&root))] {
            let r = rules(&[&pattern], &[], &root);
            assert!(r.resolve(&root, &root).unwrap().is_root(), "{pattern}");
            let p = r.resolve(Path::new("src/main.rs"), &root).unwrap();
            assert_eq!(p.as_path(), root.join("src/main.rs"));
            // A path that does not exist yet resolves too.
            let n = r.resolve(Path::new("src/new/file.rs"), &root).unwrap();
            assert_eq!(n.as_path(), root.join("src/new/file.rs"));
        }
    }

    #[test]
    fn relative_and_dot_entries_resolve_against_the_base() {
        let (_g, root) = tmp();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let r = rules(&["."], &[], &root);
        assert!(r.resolve(Path::new("sub"), &root).is_ok());
        let r = rules(&["sub"], &[], &root);
        assert!(r.resolve(Path::new("sub/x"), &root).is_ok());
        assert!(r.resolve(Path::new("other"), &root).is_err());
    }

    #[test]
    fn star_does_not_cross_directories() {
        let (_g, root) = tmp();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let pattern = format!("{}/*.txt", match_string(&root));
        let r = rules(&[&pattern], &[], &root);
        assert!(r.resolve(Path::new("top.txt"), &root).is_ok());
        assert!(r.resolve(Path::new("a/b/deep.txt"), &root).is_err());
    }

    #[test]
    fn parent_traversal_cannot_leave_the_root() {
        let (_g, root) = tmp();
        let r = rules(&["."], &[], &root);
        let err = r.resolve(Path::new("../outside.txt"), &root).unwrap_err();
        assert!(matches!(err, ToolError::PathNotAllowed { .. }), "{err:?}");
        let err = r
            .resolve(Path::new("a/../../../../../../etc/passwd"), &root)
            .unwrap_err();
        assert!(
            matches!(err, ToolError::PathNotAllowed { .. } | ToolError::PermissionDenied(_)),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_root_is_refused() {
        let (_g, root) = tmp();
        let (_o, outside) = tmp();
        std::fs::write(outside.join("secret.txt"), "s").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("file-link")).unwrap();
        let r = rules(&["."], &[], &root);
        for p in ["link/secret.txt", "link", "file-link", "link/new.txt"] {
            let err = r.resolve(Path::new(p), &root).unwrap_err();
            assert!(matches!(err, ToolError::PathNotAllowed { .. }), "{p}: {err:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_into_another_allowed_root_is_followed_to_its_real_path() {
        let (_g, root) = tmp();
        let (_o, other) = tmp();
        std::fs::write(other.join("data.txt"), "d").unwrap();
        std::os::unix::fs::symlink(&other, root.join("link")).unwrap();
        let r = rules(&[&match_string(&root), &match_string(&other)], &[], &root);
        let p = r.resolve(Path::new("link/data.txt"), &root).unwrap();
        assert_eq!(p.as_path(), other.join("data.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_root_cannot_reach_a_denied_file() {
        let (_g, root) = tmp();
        std::fs::create_dir_all(root.join(".ssh")).unwrap();
        std::fs::write(root.join(".ssh/id_ed25519"), "k").unwrap();
        std::os::unix::fs::symlink(root.join(".ssh"), root.join("innocent")).unwrap();
        let r = rules(&["."], &["**/.ssh"], &root);
        let err = r.resolve(Path::new("innocent/id_ed25519"), &root).unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)), "{err:?}");
    }

    #[test]
    fn deny_wins_and_covers_the_directory_and_its_contents() {
        let (_g, root) = tmp();
        std::fs::create_dir_all(root.join(".ssh")).unwrap();
        for pattern in ["**/.ssh", "**/.ssh/**", ".ssh", ".ssh/"] {
            let r = rules(&["."], &[pattern], &root);
            for p in [".ssh", ".ssh/config", ".ssh/a/b"] {
                let err = r.resolve(Path::new(p), &root).unwrap_err();
                assert!(matches!(err, ToolError::PermissionDenied(_)), "{pattern} {p}");
            }
            assert!(r.resolve(Path::new("ok.txt"), &root).is_ok());
        }
    }

    #[test]
    fn deny_patterns_ignore_case_and_cover_env_variants() {
        let (_g, root) = tmp();
        let denied = crate::config::builtin_denied_paths();
        let denied: Vec<&str> = denied.iter().map(String::as_str).collect();
        let r = rules(&["."], &denied, &root);
        for p in [
            ".env",
            ".ENV",
            ".env.local",
            "sub/.Env.Production",
            "id_ed25519",
            "ID_RSA.pub",
            "certs/server.KEY",
            ".aws/credentials",
            ".git-credentials",
        ] {
            assert!(r.resolve(Path::new(p), &root).is_err(), "{p} should be denied");
        }
        for p in ["env.txt", "src/environment.rs", "keyboard.md"] {
            assert!(r.resolve(Path::new(p), &root).is_ok(), "{p} should be allowed");
        }
    }

    #[test]
    fn protected_paths_are_always_denied() {
        let (_g, root) = tmp();
        std::fs::write(root.join("nebula-mcp.toml"), "x").unwrap();
        let r = PathRules::build(
            &[".".to_string()],
            &[],
            &[root.join("nebula-mcp.toml")],
            &root,
        )
        .unwrap();
        let err = r.resolve(Path::new("nebula-mcp.toml"), &root).unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)));
        assert!(r.resolve(Path::new("other.toml"), &root).is_ok());
    }

    #[test]
    fn walk_visibility_hides_denied_entries_and_traverses_unlisted_directories() {
        let (_g, root) = tmp();
        let pattern = format!("{}/**/*.rs", match_string(&root));
        let r = rules(&[&match_string(&root), &pattern], &["**/.env"], &root);
        let top = r.resolve(&root, &root).unwrap();
        assert_eq!(r.entry_visibility(&top, &".env".into(), false), Visibility::Denied);
        assert_eq!(r.entry_visibility(&top, &"a.rs".into(), false), Visibility::Visible);

        let narrow = rules(&[&pattern], &[], &root);
        let fake = CheckedPath {
            root: root.clone(),
            rel: PathBuf::new(),
            abs: root.clone(),
        };
        assert_eq!(
            narrow.entry_visibility(&fake, &"src".into(), true),
            Visibility::TraverseOnly
        );
        assert_eq!(
            narrow.entry_visibility(&fake, &"notes.txt".into(), false),
            Visibility::Denied
        );
    }

    #[test]
    fn invalid_patterns_are_reported() {
        let (_g, root) = tmp();
        assert!(PathRules::build(&["/a/[".to_string()], &[], &[], &root).is_err());
        assert!(PathRules::build(&[String::new()], &[], &[], &root).is_err());
    }

    #[test]
    fn windows_names_that_win32_reinterprets_are_recognised() {
        for bad in [".env.", ".env ", "file.txt:stream", ".env::$DATA"] {
            assert!(is_reinterpreted_windows_name(bad), "{bad}");
        }
        for ok in [".env", "a.txt", "..", "."] {
            assert!(!is_reinterpreted_windows_name(ok), "{ok}");
        }
    }

    #[test]
    fn pattern_helpers() {
        assert_eq!(literal_prefix("/work/src/**/*.rs"), "/work/src");
        assert_eq!(literal_prefix("/**"), "/");
        assert_eq!(literal_prefix("C:/src/**"), "C:/src");
        assert_eq!(literal_prefix("C:/*"), "C:/");
        assert_eq!(expand_allow("/work"), vec!["/work", "/work/**"]);
        assert_eq!(expand_allow("/work/**"), vec!["/work", "/work/**"]);
        assert_eq!(expand_allow("/**"), vec!["/", "/**"]);
        assert_eq!(expand_allow("/work/*.txt"), vec!["/work/*.txt"]);
        assert_eq!(expand_deny("**/.ssh/**"), vec!["**/.ssh/**", "**/.ssh"]);
        assert_eq!(expand_deny("*.pem"), vec!["**/*.pem"]);
        assert_eq!(expand_deny("/etc/shadow"), vec!["/etc/shadow"]);
    }
}
