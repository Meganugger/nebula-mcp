//! Checked filesystem access.
//!
//! [`Fs`] is the only way tools reach the filesystem. A path from a caller is
//! turned into a [`CheckedPath`] by [`Fs::resolve`], which
//!
//! 1. refuses paths that are not lexically under an allowed root, before the
//!    filesystem is consulted;
//! 2. resolves symlinks and requires the result to be inside an allowed root;
//! 3. applies the deny rules to both the resolved and the requested path.
//!
//! Every operation then opens the path component by component beneath a
//! directory handle for the root, refusing symlinks at every step. A path
//! that was swapped for a symlink after the check therefore fails instead of
//! being followed: there is no check-then-use window.
//!
//! Operations are synchronous; run them through [`Fs::blocking`].

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use tokio_util::sync::CancellationToken;

use crate::error::{Result, ToolError};
use crate::policy::{
    lexical_normalize, path_starts_with, paths_equal, simplify, Access, PathRules,
};

/// The message of the [`ToolError::Execution`] that [`Fs::rename`] returns
/// when source and destination are on different filesystems, so a caller
/// can fall back to copying.
pub const CROSS_DEVICE: &str = "the source and the destination are on different filesystems";

/// A path that passed the policy. Only [`Fs`] can create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedPath {
    root: PathBuf,
    rel: PathBuf,
    access: Access,
}

impl CheckedPath {
    /// The absolute, symlink-free path, for messages and results.
    #[must_use]
    pub fn display(&self) -> String {
        self.abs().display().to_string()
    }

    /// The final component, if the path is not a root.
    #[must_use]
    pub fn file_name(&self) -> Option<String> {
        self.rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    }

    /// Whether this is an allowed root itself.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.rel.as_os_str().is_empty()
    }

    /// The path relative to its allowed root (empty for the root).
    #[must_use]
    pub fn relative(&self) -> &Path {
        &self.rel
    }

    /// The access this path was checked for.
    #[must_use]
    pub fn access(&self) -> Access {
        self.access
    }

    /// Whether `other` is this path or lies beneath it.
    #[must_use]
    pub fn contains(&self, other: &CheckedPath) -> bool {
        path_starts_with(&other.abs(), &self.abs())
    }

    /// The absolute path. Crate-private: handing a raw path to tools would
    /// let them bypass the handle-based access below.
    pub(crate) fn abs(&self) -> PathBuf {
        if self.is_root() {
            self.root.clone()
        } else {
            self.root.join(&self.rel)
        }
    }
}

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (never followed by walks).
    Symlink,
    /// Socket, device, FIFO or similar.
    Other,
}

impl Kind {
    /// Lower-case label used in tool output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
            Kind::Other => "other",
        }
    }
}

/// Metadata of a path, without following a final symlink.
#[derive(Debug, Clone)]
pub struct Meta {
    /// Entry type.
    pub kind: Kind,
    /// Size in bytes.
    pub len: u64,
    /// Last modification time.
    pub modified: Option<SystemTime>,
    /// Whether the entry is read-only for its owner.
    pub readonly: bool,
    /// Unix permission bits, where available.
    pub mode: Option<u32>,
}

/// One entry produced by [`Fs::read_dir`] or [`Fs::walk`].
#[derive(Debug, Clone)]
pub struct Entry {
    /// The checked path of the entry.
    pub path: CheckedPath,
    /// File name.
    pub name: String,
    /// Depth below the walk root (1 for direct children).
    pub depth: usize,
    /// Metadata.
    pub meta: Meta,
}

/// How to open a file for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Create or replace. Replacement is atomic (temp file, then rename).
    Replace,
    /// Create; fail if the path exists.
    CreateNew,
    /// Create if missing and append.
    Append,
}

/// Limits and behaviour of a directory walk.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Deepest level visited (1 = direct children only).
    pub max_depth: usize,
    /// Stop after this many entries.
    pub max_entries: usize,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 100_000,
        }
    }
}

/// What a walk visitor wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep going.
    Continue,
    /// Do not descend into this directory.
    SkipDir,
    /// Stop the walk.
    Stop,
}

/// What a walk saw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkSummary {
    /// Entries passed to the visitor.
    pub visited: usize,
    /// Entries hidden because policy denies them.
    pub denied: usize,
    /// Whether a limit or `Flow::Stop` ended the walk early.
    pub truncated: bool,
}

/// What a recursive copy did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopySummary {
    /// Files copied.
    pub files: u64,
    /// Directories created.
    pub dirs: u64,
    /// Bytes copied.
    pub bytes: u64,
    /// Entries skipped: denied by policy, symlinks and special files.
    pub skipped: u64,
}

/// Filesystem capability bound to one tool call's policy.
#[derive(Debug, Clone)]
pub struct Fs {
    rules: Arc<PathRules>,
    working_dir: PathBuf,
    writable: bool,
    cancel: CancellationToken,
    max_bytes: usize,
}

impl Fs {
    /// Create a capability. `writable` is false for tools that declared
    /// themselves read-only; such tools cannot obtain write access.
    #[must_use]
    pub fn new(
        rules: Arc<PathRules>,
        working_dir: PathBuf,
        writable: bool,
        cancel: CancellationToken,
        max_bytes: usize,
    ) -> Self {
        Self {
            rules,
            working_dir,
            writable,
            cancel,
            max_bytes,
        }
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Largest read this capability performs in one call.
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Run blocking filesystem work off the async runtime.
    pub async fn blocking<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Fs) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let fs = self.clone();
        match tokio::task::spawn_blocking(move || f(&fs)).await {
            Ok(result) => result,
            Err(e) if e.is_panic() => Err(ToolError::Internal(
                "a filesystem operation panicked".to_string(),
            )),
            Err(_) => Err(ToolError::Cancelled),
        }
    }

    /// Check a caller-supplied path against the policy.
    pub fn resolve(&self, input: &str, access: Access) -> Result<CheckedPath> {
        if input.is_empty() {
            return Err(ToolError::invalid("path must not be empty"));
        }
        if input.contains('\0') {
            return Err(ToolError::invalid("path must not contain NUL"));
        }
        if access == Access::Write && !self.writable {
            return Err(ToolError::Internal(
                "a tool declared read-only asked for write access".to_string(),
            ));
        }
        if self.rules.is_empty() {
            return Err(ToolError::PermissionDenied(
                "no directories are allowed: the operator has not set [security] allowed_paths"
                    .to_string(),
            ));
        }
        reject_special_syntax(input)?;

        let not_allowed = || ToolError::PathNotAllowed {
            path: input.to_string(),
        };
        let requested = if Path::new(input).is_absolute() {
            PathBuf::from(input)
        } else {
            self.working_dir.join(input)
        };

        // Lexical gate first: paths that are not written under an allowed
        // root are refused without consulting the filesystem, so the answer
        // reveals nothing about what exists elsewhere.
        let lexical = lexical_normalize(&requested);
        let lexical = self.rules.unalias(&lexical).unwrap_or(lexical);
        if self.rules.root_of(&lexical).is_none() {
            return Err(not_allowed());
        }

        let canonical = canonicalize_allowing_missing_tail(&requested)?;
        let root = self.rules.root_of(&canonical).ok_or_else(not_allowed)?;
        for candidate in [&canonical, &lexical] {
            if let Some(reason) = self.rules.denied(candidate, access) {
                return Err(ToolError::PermissionDenied(format!(
                    "'{input}' is not accessible: {reason}"
                )));
            }
        }
        let rel: PathBuf = canonical
            .components()
            .skip(root.path().components().count())
            .collect();
        Ok(CheckedPath {
            root: root.path().to_path_buf(),
            rel,
            access,
        })
    }

    /// The checked path of `name` directly inside `dir`.
    pub fn child(&self, dir: &CheckedPath, name: &str, access: Access) -> Result<CheckedPath> {
        let mut comps = Path::new(name).components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => {
                return Err(ToolError::invalid(format!(
                    "'{name}' is not a single file name"
                )))
            }
        }
        if access == Access::Write && !self.writable {
            return Err(ToolError::Internal(
                "a tool declared read-only asked for write access".to_string(),
            ));
        }
        let path = CheckedPath {
            root: dir.root.clone(),
            rel: dir.rel.join(name),
            access,
        };
        self.check(&path, access)?;
        Ok(path)
    }

    /// Re-check a path for a (possibly different) access.
    fn check(&self, path: &CheckedPath, access: Access) -> Result<()> {
        match self.rules.denied(&path.abs(), access) {
            Some(reason) => Err(ToolError::PermissionDenied(format!(
                "'{}' is not accessible: {reason}",
                path.display()
            ))),
            None => Ok(()),
        }
    }

    fn need_write(&self, path: &CheckedPath) -> Result<()> {
        if path.access != Access::Write {
            return Err(ToolError::Internal(
                "a path checked for reading was used for writing".to_string(),
            ));
        }
        Ok(())
    }

    fn open_root(&self, path: &CheckedPath) -> Result<Dir> {
        Dir::open_ambient_dir(&path.root, ambient_authority())
            .map_err(|e| ToolError::from_io(&path.root.display().to_string(), &e))
    }

    /// Open the directory `path` itself, refusing symlinks at every step.
    fn open_dir(&self, path: &CheckedPath) -> Result<Dir> {
        let mut dir = self.open_root(path)?;
        for comp in path.rel.components() {
            dir = dir
                .open_dir_nofollow(comp.as_os_str())
                .map_err(|e| map_walk_error(path, &e))?;
        }
        Ok(dir)
    }

    /// Open the parent directory of `path` and return it with the file name.
    fn open_parent(&self, path: &CheckedPath) -> Result<(Dir, OsString)> {
        let name = path.rel.file_name().ok_or_else(|| {
            ToolError::invalid(format!(
                "'{}' is an allowed root; this operation needs a path inside it",
                path.display()
            ))
        })?;
        let mut dir = self.open_root(path)?;
        if let Some(parent) = path.rel.parent() {
            for comp in parent.components() {
                dir = dir
                    .open_dir_nofollow(comp.as_os_str())
                    .map_err(|e| map_walk_error(path, &e))?;
            }
        }
        Ok((dir, name.to_os_string()))
    }

    /// Metadata of `path`, not following a final symlink.
    pub fn metadata(&self, path: &CheckedPath) -> Result<Meta> {
        let io = |e: std::io::Error| ToolError::from_io(&path.display(), &e);
        if path.is_root() {
            let m = self.open_root(path)?.dir_metadata().map_err(io)?;
            return Ok(meta_of(&m));
        }
        let (dir, name) = self.open_parent(path)?;
        let m = dir.symlink_metadata(&name).map_err(io)?;
        Ok(meta_of(&m))
    }

    /// Metadata of `path`, or `None` when it does not exist.
    pub fn try_metadata(&self, path: &CheckedPath) -> Result<Option<Meta>> {
        match self.metadata(path) {
            Ok(m) => Ok(Some(m)),
            Err(ToolError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Open a file for reading.
    pub fn open(&self, path: &CheckedPath) -> Result<std::fs::File> {
        let (dir, name) = self.open_parent(path)?;
        let mut opts = OpenOptions::new();
        opts.read(true).follow(FollowSymlinks::No);
        let file = dir
            .open_with(&name, &opts)
            .map_err(|e| map_walk_error(path, &e))?;
        let meta = file
            .metadata()
            .map_err(|e| ToolError::from_io(&path.display(), &e))?;
        if meta.is_dir() {
            return Err(ToolError::invalid(format!(
                "'{}' is a directory, not a file",
                path.display()
            )));
        }
        if !meta.is_file() {
            return Err(ToolError::invalid(format!(
                "'{}' is not a regular file",
                path.display()
            )));
        }
        Ok(file.into_std())
    }

    /// Read up to `max` bytes starting at `offset`. Returns the bytes and the
    /// file's total size. Never reads more than the policy's output limit.
    pub fn read(&self, path: &CheckedPath, offset: u64, max: usize) -> Result<(Vec<u8>, u64)> {
        let io = |e: std::io::Error| ToolError::from_io(&path.display(), &e);
        let mut file = self.open(path)?;
        let total = file.metadata().map_err(io)?.len();
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).map_err(io)?;
        }
        let limit = max.min(self.max_bytes) as u64;
        let mut buf = Vec::new();
        file.take(limit).read_to_end(&mut buf).map_err(io)?;
        Ok((buf, total))
    }

    /// Read a whole file, failing when it is larger than the policy's limit.
    pub fn read_all(&self, path: &CheckedPath) -> Result<Vec<u8>> {
        let (bytes, total) = self.read(path, 0, self.max_bytes)?;
        if total > bytes.len() as u64 {
            return Err(ToolError::LimitExceeded(format!(
                "'{}' is {total} bytes, above the {} byte limit for this operation",
                path.display(),
                self.max_bytes
            )));
        }
        Ok(bytes)
    }

    /// Open a file for writing and return the handle, for streamed writes.
    /// `Replace` truncates in place; use [`Fs::write`] for an atomic replace.
    pub fn create(&self, path: &CheckedPath, mode: WriteMode) -> Result<std::fs::File> {
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        let mut opts = OpenOptions::new();
        opts.write(true).follow(FollowSymlinks::No);
        match mode {
            WriteMode::Replace => opts.create(true).truncate(true),
            WriteMode::CreateNew => opts.create_new(true),
            WriteMode::Append => opts.create(true).append(true),
        };
        let file = dir.open_with(&name, &opts).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ToolError::Execution(format!("'{}' already exists", path.display()))
            } else {
                map_walk_error(path, &e)
            }
        })?;
        Ok(file.into_std())
    }

    /// Write `bytes` to `path`. `Replace` is atomic: readers see the old or
    /// the new content, never a partial file.
    pub fn write(&self, path: &CheckedPath, bytes: &[u8], mode: WriteMode) -> Result<()> {
        self.need_write(path)?;
        let io = |e: std::io::Error| ToolError::from_io(&path.display(), &e);
        if mode != WriteMode::Replace {
            let mut file = self.create(path, mode)?;
            file.write_all(bytes).map_err(io)?;
            return file.flush().map_err(io);
        }

        let (dir, name) = self.open_parent(path)?;
        let existing = dir.symlink_metadata(&name).ok();
        if let Some(m) = &existing {
            if m.is_dir() {
                return Err(ToolError::invalid(format!(
                    "'{}' is a directory",
                    path.display()
                )));
            }
            if m.is_symlink() {
                return Err(map_walk_error(
                    path,
                    &std::io::Error::from(std::io::ErrorKind::InvalidInput),
                ));
            }
        }
        let tmp = temp_name(&name);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).follow(FollowSymlinks::No);
        let mut file = dir.open_with(&tmp, &opts).map_err(io)?;
        let written = (|| {
            file.write_all(bytes)?;
            if let Some(m) = &existing {
                // Keep the replaced file's permissions.
                file.set_permissions(m.permissions())?;
            }
            file.sync_all()?;
            drop(file);
            dir.rename(&tmp, &dir, &name)
        })();
        if let Err(e) = written {
            let _ = dir.remove_file(&tmp);
            return Err(io(e));
        }
        Ok(())
    }

    /// Create a directory and any missing parents.
    pub fn create_dir_all(&self, path: &CheckedPath) -> Result<()> {
        self.need_write(path)?;
        let mut dir = self.open_root(path)?;
        let mut so_far = CheckedPath {
            root: path.root.clone(),
            rel: PathBuf::new(),
            access: Access::Write,
        };
        for comp in path.rel.components() {
            so_far.rel.push(comp.as_os_str());
            dir = match dir.open_dir_nofollow(comp.as_os_str()) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.check(&so_far, Access::Write)?;
                    match dir.create_dir(comp.as_os_str()) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(ToolError::from_io(&so_far.display(), &e)),
                    }
                    dir.open_dir_nofollow(comp.as_os_str())
                        .map_err(|e| map_walk_error(&so_far, &e))?
                }
                Err(e) => return Err(map_walk_error(&so_far, &e)),
            };
        }
        Ok(())
    }

    /// List a directory. Entries the policy denies are omitted; the second
    /// value counts them.
    pub fn read_dir(&self, path: &CheckedPath) -> Result<(Vec<Entry>, usize)> {
        let dir = self.open_dir(path)?;
        self.list(&dir, path, 1)
    }

    fn list(&self, dir: &Dir, path: &CheckedPath, depth: usize) -> Result<(Vec<Entry>, usize)> {
        let io = |e: std::io::Error| ToolError::from_io(&path.display(), &e);
        let mut entries = Vec::new();
        let mut denied = 0usize;
        for item in dir.entries().map_err(io)? {
            let item = item.map_err(io)?;
            let name_os = item.file_name();
            let child = CheckedPath {
                root: path.root.clone(),
                rel: path.rel.join(&name_os),
                access: Access::Read,
            };
            if self.rules.denied(&child.abs(), Access::Read).is_some() {
                denied += 1;
                continue;
            }
            // A vanished entry is not an error for a listing.
            let Ok(meta) = item.metadata() else { continue };
            entries.push(Entry {
                path: child,
                name: name_os.to_string_lossy().into_owned(),
                depth,
                meta: meta_of(&meta),
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((entries, denied))
    }

    /// Walk the tree under `path` in sorted, breadth-first order without
    /// following symlinks. Denied entries are never visited or descended.
    pub fn walk(
        &self,
        path: &CheckedPath,
        options: &WalkOptions,
        mut visit: impl FnMut(&Entry) -> Result<Flow>,
    ) -> Result<WalkSummary> {
        let mut summary = WalkSummary::default();
        let mut queue: VecDeque<(CheckedPath, usize)> = VecDeque::new();
        queue.push_back((path.clone(), 1));
        while let Some((dir_path, depth)) = queue.pop_front() {
            if self.cancel.is_cancelled() {
                return Err(ToolError::Cancelled);
            }
            let dir = match self.open_dir(&dir_path) {
                Ok(d) => d,
                // The starting directory must open; deeper ones may vanish
                // or be unreadable without failing the whole walk.
                Err(e) if depth == 1 => return Err(e),
                Err(_) => continue,
            };
            let (entries, denied) = self.list(&dir, &dir_path, depth)?;
            summary.denied += denied;
            for entry in entries {
                if summary.visited >= options.max_entries {
                    summary.truncated = true;
                    return Ok(summary);
                }
                if self.cancel.is_cancelled() {
                    return Err(ToolError::Cancelled);
                }
                summary.visited += 1;
                match visit(&entry)? {
                    Flow::Stop => {
                        summary.truncated = true;
                        return Ok(summary);
                    }
                    Flow::SkipDir => {}
                    Flow::Continue => {
                        if entry.meta.kind == Kind::Dir {
                            if depth < options.max_depth {
                                queue.push_back((entry.path.clone(), depth + 1));
                            } else {
                                summary.truncated = true;
                            }
                        }
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Fail if anything under `path` is denied for `access`. Used before
    /// operations that move or delete a whole tree.
    fn require_tree_allowed(&self, path: &CheckedPath, access: Access) -> Result<()> {
        let mut blocked: Option<String> = None;
        let mut queue: VecDeque<CheckedPath> = VecDeque::new();
        queue.push_back(path.clone());
        while let Some(dir_path) = queue.pop_front() {
            if self.cancel.is_cancelled() {
                return Err(ToolError::Cancelled);
            }
            let Ok(dir) = self.open_dir(&dir_path) else {
                continue;
            };
            let io = |e: std::io::Error| ToolError::from_io(&dir_path.display(), &e);
            for item in dir.entries().map_err(io)? {
                let item = item.map_err(io)?;
                let child = CheckedPath {
                    root: dir_path.root.clone(),
                    rel: dir_path.rel.join(item.file_name()),
                    access,
                };
                if self.rules.denied(&child.abs(), access).is_some() {
                    blocked = Some(child.display());
                    break;
                }
                if item.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    queue.push_back(child);
                }
            }
            if blocked.is_some() {
                break;
            }
        }
        match blocked {
            Some(p) => Err(ToolError::PermissionDenied(format!(
                "'{}' contains '{p}', which policy protects; the operation was not started",
                path.display()
            ))),
            None => Ok(()),
        }
    }

    /// Remove a file or symlink.
    pub fn remove_file(&self, path: &CheckedPath) -> Result<()> {
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        dir.remove_file(&name)
            .map_err(|e| ToolError::from_io(&path.display(), &e))
    }

    /// Remove an empty directory.
    pub fn remove_dir(&self, path: &CheckedPath) -> Result<()> {
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        dir.remove_dir(&name)
            .map_err(|e| ToolError::from_io(&path.display(), &e))
    }

    /// Remove a directory and everything in it. Refused when the tree holds
    /// anything the policy protects.
    pub fn remove_dir_all(&self, path: &CheckedPath) -> Result<()> {
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        self.require_tree_allowed(path, Access::Write)?;
        dir.remove_dir_all(&name)
            .map_err(|e| ToolError::from_io(&path.display(), &e))
    }

    /// Rename `from` to `to`. With `replace` false an existing destination is
    /// an error. Directories holding protected entries are not moved.
    pub fn rename(&self, from: &CheckedPath, to: &CheckedPath, replace: bool) -> Result<()> {
        self.need_write(from)?;
        self.need_write(to)?;
        let (from_dir, from_name) = self.open_parent(from)?;
        let (to_dir, to_name) = self.open_parent(to)?;
        let meta = from_dir
            .symlink_metadata(&from_name)
            .map_err(|e| ToolError::from_io(&from.display(), &e))?;
        if meta.is_dir() {
            if from.contains(to) {
                return Err(ToolError::invalid(format!(
                    "cannot move '{}' into itself",
                    from.display()
                )));
            }
            self.require_tree_allowed(from, Access::Write)?;
        }
        if !replace && to_dir.symlink_metadata(&to_name).is_ok() {
            return Err(ToolError::Execution(format!(
                "'{}' already exists",
                to.display()
            )));
        }
        from_dir.rename(&from_name, &to_dir, &to_name).map_err(|e| {
            if e.kind() == std::io::ErrorKind::CrossesDevices {
                ToolError::Execution(CROSS_DEVICE.to_string())
            } else {
                ToolError::from_io(&from.display(), &e)
            }
        })
    }

    /// The directory containing `path`; `None` for an allowed root.
    #[must_use]
    pub fn parent(&self, path: &CheckedPath) -> Option<CheckedPath> {
        let rel = path.rel.parent()?;
        Some(CheckedPath {
            root: path.root.clone(),
            rel: rel.to_path_buf(),
            access: path.access,
        })
    }

    /// Copy a file.
    pub fn copy_file(&self, from: &CheckedPath, to: &CheckedPath, replace: bool) -> Result<u64> {
        self.need_write(to)?;
        // Opening the destination truncates it, which would empty the source.
        if paths_equal(&from.abs(), &to.abs()) {
            return Err(ToolError::invalid(format!(
                "cannot copy '{}' onto itself",
                from.display()
            )));
        }
        let mut src = self.open(from)?;
        let mode = if replace {
            WriteMode::Replace
        } else {
            WriteMode::CreateNew
        };
        let mut dst = self.create(to, mode)?;
        let n =
            std::io::copy(&mut src, &mut dst).map_err(|e| ToolError::from_io(&to.display(), &e))?;
        if let Ok(m) = src.metadata() {
            let _ = dst.set_permissions(m.permissions());
        }
        Ok(n)
    }

    /// Copy a directory tree. Symlinks, special files and entries the policy
    /// denies are skipped and counted. The destination must not be inside the
    /// source.
    pub fn copy_tree(&self, from: &CheckedPath, to: &CheckedPath) -> Result<CopySummary> {
        self.need_write(to)?;
        if from.contains(to) {
            return Err(ToolError::invalid(format!(
                "cannot copy '{}' into itself",
                from.display()
            )));
        }
        let mut summary = CopySummary::default();
        self.create_dir_all(to)?;
        summary.dirs += 1;
        let mut queue: VecDeque<(CheckedPath, CheckedPath)> = VecDeque::new();
        queue.push_back((from.clone(), to.clone()));
        while let Some((src_dir, dst_dir)) = queue.pop_front() {
            if self.cancel.is_cancelled() {
                return Err(ToolError::Cancelled);
            }
            let (entries, denied) = self.read_dir(&src_dir)?;
            summary.skipped += denied as u64;
            for entry in entries {
                let Ok(dst) = self.child(&dst_dir, &entry.name, Access::Write) else {
                    summary.skipped += 1;
                    continue;
                };
                match entry.meta.kind {
                    Kind::Dir => {
                        self.create_dir_all(&dst)?;
                        summary.dirs += 1;
                        queue.push_back((entry.path, dst));
                    }
                    Kind::File => {
                        summary.bytes += self.copy_file(&entry.path, &dst, true)?;
                        summary.files += 1;
                    }
                    Kind::Symlink | Kind::Other => summary.skipped += 1,
                }
            }
        }
        Ok(summary)
    }

    /// Set Unix permission bits.
    #[cfg(unix)]
    pub fn set_mode(&self, path: &CheckedPath, mode: u32) -> Result<()> {
        use cap_std::fs::PermissionsExt;
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        let meta = dir
            .symlink_metadata(&name)
            .map_err(|e| ToolError::from_io(&path.display(), &e))?;
        if meta.is_symlink() {
            return Err(ToolError::invalid("cannot change the mode of a symlink"));
        }
        dir.set_permissions(&name, cap_std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(|e| ToolError::from_io(&path.display(), &e))
    }

    /// Set or clear the read-only attribute.
    pub fn set_readonly(&self, path: &CheckedPath, readonly: bool) -> Result<()> {
        self.need_write(path)?;
        let (dir, name) = self.open_parent(path)?;
        let io = |e: std::io::Error| ToolError::from_io(&path.display(), &e);
        let meta = dir.symlink_metadata(&name).map_err(io)?;
        if meta.is_symlink() {
            return Err(ToolError::invalid("cannot change a symlink's attributes"));
        }
        let mut perms = meta.permissions();
        perms.set_readonly(readonly);
        dir.set_permissions(&name, perms).map_err(io)
    }

    /// Where a symlink points, as text. The target is not followed.
    pub fn read_link(&self, path: &CheckedPath) -> Result<String> {
        let (dir, name) = self.open_parent(path)?;
        dir.read_link_contents(&name)
            .map(|p| p.display().to_string())
            .map_err(|e| ToolError::from_io(&path.display(), &e))
    }
}

fn meta_of(m: &cap_std::fs::Metadata) -> Meta {
    let kind = if m.is_symlink() {
        Kind::Symlink
    } else if m.is_dir() {
        Kind::Dir
    } else if m.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    #[cfg(unix)]
    let mode = {
        use cap_std::fs::PermissionsExt;
        Some(m.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let mode = None;
    Meta {
        kind,
        len: m.len(),
        modified: m.modified().ok().map(cap_std::time::SystemTime::into_std),
        readonly: m.permissions().readonly(),
        mode,
    }
}

/// A sibling temp name that deny patterns cannot mistake for a real file.
fn temp_name(name: &std::ffi::OsStr) -> OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut tmp = OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".nebula-tmp-{}-{n}-{nanos}", std::process::id()));
    tmp
}

/// Errors from the no-follow walk: a symlink where none was at check time
/// means the path changed underneath us.
fn map_walk_error(path: &CheckedPath, e: &std::io::Error) -> ToolError {
    // ELOOP (symlink met with no-follow) surfaces differently per platform.
    let symlink = matches!(e.raw_os_error(), Some(code) if is_symlink_errno(code));
    if symlink {
        return ToolError::PermissionDenied(format!(
            "'{}' changed while it was being accessed (a symbolic link appeared in the path)",
            path.display()
        ));
    }
    if e.kind() == std::io::ErrorKind::PermissionDenied && e.raw_os_error().is_none() {
        // cap-std's own refusal: the path led outside the root.
        return ToolError::PathNotAllowed {
            path: path.display(),
        };
    }
    ToolError::from_io(&path.display(), e)
}

#[cfg(target_os = "linux")]
fn is_symlink_errno(code: i32) -> bool {
    code == 40 // ELOOP
}
#[cfg(all(unix, not(target_os = "linux")))]
fn is_symlink_errno(code: i32) -> bool {
    code == 62 // ELOOP on macOS and the BSDs
}
#[cfg(windows)]
fn is_symlink_errno(code: i32) -> bool {
    code == 1920 // ERROR_CANT_ACCESS_FILE: reparse point not followed
}

/// Canonicalise the longest existing prefix of `path` and append the rest,
/// so paths that are about to be created can still be checked. The missing
/// tail must be plain names.
fn canonicalize_allowing_missing_tail(path: &Path) -> Result<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(c) => {
                let mut out = simplify(&c);
                for name in tail.iter().rev() {
                    out.push(name);
                }
                return Ok(out);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                match existing.components().next_back() {
                    Some(Component::Normal(name)) => {
                        tail.push(name.to_os_string());
                        existing.pop();
                    }
                    Some(Component::CurDir) => {
                        existing.pop();
                    }
                    _ => {
                        return Err(ToolError::invalid(format!(
                            "'{}' uses '..' beyond a directory that does not exist",
                            path.display()
                        )))
                    }
                }
            }
            Err(e) => return Err(ToolError::from_io(&path.display().to_string(), &e)),
        }
    }
}

/// Reject path syntax that names something other than a plain file: Windows
/// device namespaces, alternate data streams and reserved device names.
fn reject_special_syntax(input: &str) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    let bad = |why: &str| {
        Err(ToolError::invalid(format!(
            "'{input}' is not accepted: {why}"
        )))
    };
    if input.starts_with(r"\\") || input.starts_with("//") {
        return bad("UNC and device paths are not supported");
    }
    for (i, comp) in input.split(['/', '\\']).enumerate() {
        let is_drive = i == 0 && comp.len() == 2 && comp.ends_with(':');
        if !is_drive && comp.contains(':') {
            return bad("alternate data streams are not supported");
        }
        let stem = comp
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        let reserved = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
        if reserved {
            return bad("it names a Windows device");
        }
        if comp.ends_with(' ') || (comp.ends_with('.') && comp != "." && comp != "..") {
            return bad("names ending in a space or dot are not supported");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::policy::{slash_string, PolicySet};

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        outside: PathBuf,
        fs: Fs,
        ro: Fs,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = simplify(&std::fs::canonicalize(tmp.path()).unwrap());
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let mut cfg = Config::default();
        cfg.security.allowed_paths = vec![slash_string(&root)];
        cfg.security.denied_paths = vec!["**/vault/**".into()];
        let policy = PolicySet::compile(&cfg, &[]).unwrap().for_tool("t");
        let make = |writable| {
            Fs::new(
                policy.paths().clone(),
                root.clone(),
                writable,
                CancellationToken::new(),
                1 << 20,
            )
        };
        Fixture {
            fs: make(true),
            ro: make(false),
            _tmp: tmp,
            root,
            outside,
        }
    }

    fn text(fs: &Fs, p: &str) -> Result<String> {
        let c = fs.resolve(p, Access::Read)?;
        Ok(String::from_utf8(fs.read_all(&c)?).unwrap())
    }

    #[test]
    fn reads_and_writes_inside_the_root() {
        let f = fixture();
        let p = f.fs.resolve("a/b/c.txt", Access::Write).unwrap();
        f.fs.create_dir_all(&f.fs.resolve("a/b", Access::Write).unwrap())
            .unwrap();
        f.fs.write(&p, b"hello", WriteMode::Replace).unwrap();
        assert_eq!(text(&f.fs, "a/b/c.txt").unwrap(), "hello");
        f.fs.write(&p, b" world", WriteMode::Append).unwrap();
        assert_eq!(text(&f.fs, "a/b/c.txt").unwrap(), "hello world");
        assert!(f.fs.write(&p, b"x", WriteMode::CreateNew).is_err());
        // Atomic replace leaves no temp file behind.
        f.fs.write(&p, b"new", WriteMode::Replace).unwrap();
        let (entries, _) =
            f.fs.read_dir(&f.fs.resolve("a/b", Access::Read).unwrap())
                .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "c.txt");
    }

    #[test]
    fn the_root_itself_is_allowed() {
        let f = fixture();
        let root =
            f.fs.resolve(&f.root.to_string_lossy(), Access::Read)
                .unwrap();
        assert!(root.is_root());
        assert_eq!(f.fs.metadata(&root).unwrap().kind, Kind::Dir);
        assert!(f.fs.resolve(".", Access::Read).unwrap().is_root());
    }

    #[test]
    fn paths_outside_the_root_are_refused_without_probing() {
        let f = fixture();
        std::fs::write(f.outside.join("x"), "secret").unwrap();
        for p in [
            f.outside.join("x").to_string_lossy().into_owned(),
            f.outside.join("missing").to_string_lossy().into_owned(),
            "../outside/x".to_string(),
            "a/../../outside/x".to_string(),
        ] {
            assert!(
                matches!(
                    f.fs.resolve(&p, Access::Read),
                    Err(ToolError::PathNotAllowed { .. })
                ),
                "{p}"
            );
        }
    }

    #[test]
    fn deny_patterns_apply_to_the_requested_and_resolved_path() {
        let f = fixture();
        std::fs::create_dir_all(f.root.join("vault")).unwrap();
        std::fs::write(f.root.join("vault/k.txt"), "k").unwrap();
        std::fs::write(f.root.join(".env"), "S=1").unwrap();
        assert!(matches!(
            f.fs.resolve("vault/k.txt", Access::Read),
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(f.fs.resolve(".env", Access::Read).is_err());
        assert!(f.fs.resolve(".ENV", Access::Read).is_err());
        assert!(f.fs.resolve("new/.env", Access::Write).is_err());
        assert!(f
            .fs
            .resolve(".git/hooks/pre-commit", Access::Write)
            .is_err());
        assert!(f.fs.resolve(".git/HEAD", Access::Read).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_escape_or_dodge_deny_rules() {
        use std::os::unix::fs::symlink;
        let f = fixture();
        std::fs::write(f.outside.join("secret"), "OUT").unwrap();
        std::fs::write(f.root.join(".env"), "S=1").unwrap();
        std::fs::write(f.root.join("ok.txt"), "ok").unwrap();
        symlink(f.outside.join("secret"), f.root.join("escape")).unwrap();
        symlink(&f.outside, f.root.join("escape_dir")).unwrap();
        symlink(f.root.join(".env"), f.root.join("innocent")).unwrap();
        symlink(f.root.join("ok.txt"), f.root.join("alias")).unwrap();

        assert!(matches!(
            f.fs.resolve("escape", Access::Read),
            Err(ToolError::PathNotAllowed { .. })
        ));
        assert!(f.fs.resolve("escape_dir/secret", Access::Read).is_err());
        assert!(f.fs.resolve("escape_dir/new.txt", Access::Write).is_err());
        // A link to a denied file is denied on its resolved path.
        assert!(matches!(
            f.fs.resolve("innocent", Access::Read),
            Err(ToolError::PermissionDenied(_))
        ));
        // A link that stays inside resolves to its target.
        assert_eq!(text(&f.fs, "alias").unwrap(), "ok");
        assert!(!std::fs::read_dir(&f.outside)
            .unwrap()
            .any(|e| e.unwrap().file_name() == "new.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_swapped_for_a_symlink_after_the_check_is_not_followed() {
        use std::os::unix::fs::symlink;
        let f = fixture();
        std::fs::create_dir_all(f.root.join("d")).unwrap();
        std::fs::write(f.root.join("d/f.txt"), "in").unwrap();
        std::fs::write(f.outside.join("f.txt"), "OUT").unwrap();
        let checked = f.fs.resolve("d/f.txt", Access::Write).unwrap();
        // Swap the directory for a link to the outside after the check.
        std::fs::rename(f.root.join("d"), f.root.join("d.real")).unwrap();
        symlink(&f.outside, f.root.join("d")).unwrap();

        assert!(f.fs.read_all(&checked).is_err());
        assert!(f.fs.write(&checked, b"pwn", WriteMode::Replace).is_err());
        assert_eq!(
            std::fs::read_to_string(f.outside.join("f.txt")).unwrap(),
            "OUT"
        );
    }

    #[test]
    fn listing_and_walking_hide_denied_entries() {
        let f = fixture();
        std::fs::create_dir_all(f.root.join("src/vault")).unwrap();
        std::fs::write(f.root.join("src/a.rs"), "").unwrap();
        std::fs::write(f.root.join("src/vault/key"), "").unwrap();
        std::fs::write(f.root.join("src/.env"), "").unwrap();
        let root = f.fs.resolve(".", Access::Read).unwrap();
        let mut names = Vec::new();
        let summary =
            f.fs.walk(&root, &WalkOptions::default(), |e| {
                names.push(e.path.relative().to_string_lossy().replace('\\', "/"));
                Ok(Flow::Continue)
            })
            .unwrap();
        assert_eq!(names, vec!["src", "src/a.rs"]);
        assert_eq!(summary.denied, 2);
        assert!(!summary.truncated);
    }

    #[test]
    fn walk_honours_limits_and_cancellation() {
        let f = fixture();
        for i in 0..20 {
            std::fs::write(f.root.join(format!("f{i:02}")), "").unwrap();
        }
        let root = f.fs.resolve(".", Access::Read).unwrap();
        let opts = WalkOptions {
            max_entries: 5,
            ..Default::default()
        };
        let s = f.fs.walk(&root, &opts, |_| Ok(Flow::Continue)).unwrap();
        assert_eq!(s.visited, 5);
        assert!(s.truncated);

        let cancel = CancellationToken::new();
        let fs = Fs::new(
            f.fs.rules.clone(),
            f.root.clone(),
            true,
            cancel.clone(),
            1024,
        );
        cancel.cancel();
        assert!(matches!(
            fs.walk(&root, &WalkOptions::default(), |_| Ok(Flow::Continue)),
            Err(ToolError::Cancelled)
        ));
    }

    #[test]
    fn trees_holding_protected_entries_cannot_be_moved_or_deleted() {
        let f = fixture();
        std::fs::create_dir_all(f.root.join("proj/sub")).unwrap();
        std::fs::write(f.root.join("proj/sub/.env"), "S=1").unwrap();
        let proj = f.fs.resolve("proj", Access::Write).unwrap();
        let dest = f.fs.resolve("moved", Access::Write).unwrap();
        assert!(matches!(
            f.fs.rename(&proj, &dest, false),
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(f.fs.remove_dir_all(&proj).is_err());
        assert!(f.root.join("proj/sub/.env").exists());
    }

    #[test]
    fn copy_tree_skips_denied_entries_and_refuses_self_nesting() {
        let f = fixture();
        std::fs::create_dir_all(f.root.join("a/deep")).unwrap();
        std::fs::write(f.root.join("a/one.txt"), "1").unwrap();
        std::fs::write(f.root.join("a/deep/two.txt"), "22").unwrap();
        std::fs::write(f.root.join("a/.env"), "S=1").unwrap();
        let a = f.fs.resolve("a", Access::Read).unwrap();
        let b = f.fs.resolve("b", Access::Write).unwrap();
        let s = f.fs.copy_tree(&a, &b).unwrap();
        assert_eq!((s.files, s.bytes, s.skipped), (2, 3, 1));
        assert!(!f.root.join("b/.env").exists());
        assert_eq!(
            std::fs::read_to_string(f.root.join("b/deep/two.txt")).unwrap(),
            "22"
        );

        let nested = f.fs.resolve("a/deep/copy", Access::Write).unwrap();
        assert!(matches!(
            f.fs.copy_tree(&a, &nested),
            Err(ToolError::InvalidArguments(_))
        ));
    }

    #[test]
    fn copying_a_file_onto_itself_keeps_its_content() {
        let f = fixture();
        std::fs::write(f.root.join("keep.txt"), "data").unwrap();
        let from = f.fs.resolve("keep.txt", Access::Read).unwrap();
        let to = f.fs.resolve("./keep.txt", Access::Write).unwrap();
        assert!(matches!(
            f.fs.copy_file(&from, &to, true),
            Err(ToolError::InvalidArguments(_))
        ));
        assert_eq!(
            std::fs::read_to_string(f.root.join("keep.txt")).unwrap(),
            "data"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_short_form_of_a_private_path_is_accepted() {
        // Temp directories live under /private/var; callers write /var.
        let f = fixture();
        std::fs::write(f.root.join("s.txt"), "s").unwrap();
        let rest = f
            .root
            .strip_prefix("/private")
            .expect("temp dir under /private");
        let short = Path::new("/").join(rest).join("s.txt");
        assert_eq!(text(&f.fs, &short.to_string_lossy()).unwrap(), "s");
    }

    #[test]
    fn read_only_capability_cannot_write() {
        let f = fixture();
        assert!(f.ro.resolve("x.txt", Access::Read).is_ok());
        assert!(f.ro.resolve("x.txt", Access::Write).is_err());
        let read = f.fs.resolve("x.txt", Access::Read).unwrap();
        assert!(f.fs.write(&read, b"x", WriteMode::Replace).is_err());
    }

    #[test]
    fn reads_are_bounded() {
        let f = fixture();
        std::fs::write(f.root.join("big"), vec![b'x'; 4096]).unwrap();
        let fs = Fs::new(
            f.fs.rules.clone(),
            f.root.clone(),
            false,
            CancellationToken::new(),
            1024,
        );
        let p = fs.resolve("big", Access::Read).unwrap();
        let (bytes, total) = fs.read(&p, 0, usize::MAX).unwrap();
        assert_eq!((bytes.len(), total), (1024, 4096));
        let (bytes, _) = fs.read(&p, 4000, 1024).unwrap();
        assert_eq!(bytes.len(), 96);
        assert!(matches!(fs.read_all(&p), Err(ToolError::LimitExceeded(_))));
    }

    #[test]
    fn empty_policy_denies_everything() {
        let rules = PolicySet::compile(&Config::default(), &[])
            .unwrap()
            .for_tool("t")
            .paths()
            .clone();
        let fs = Fs::new(
            rules,
            std::env::temp_dir(),
            true,
            CancellationToken::new(),
            1024,
        );
        assert!(matches!(
            fs.resolve("a.txt", Access::Read),
            Err(ToolError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn blocking_runs_off_the_runtime() {
        let f = fixture();
        std::fs::write(f.root.join("t.txt"), "abc").unwrap();
        let n =
            f.fs.blocking(|fs| {
                let p = fs.resolve("t.txt", Access::Read)?;
                Ok(fs.read_all(&p)?.len())
            })
            .await
            .unwrap();
        assert_eq!(n, 3);
    }
}
