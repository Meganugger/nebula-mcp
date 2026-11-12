//! Policy-bound filesystem access.
//!
//! [`Fs`] is the only way tools read or change files. Every operation takes a
//! [`CheckedPath`], which only the path policy can create, and reaches the
//! file by opening each directory beneath the allowed root in turn without
//! following links. A file therefore cannot be swapped for a link to somewhere
//! else between the check and the use: the open would fail instead.
//!
//! All operations are synchronous and meant to run on the blocking pool; use
//! [`Fs::run`] from async code.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::ToolError;
use crate::policy::{open_root, CheckedPath, PathRules, Visibility};

/// What kind of thing a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (never followed by a walk).
    Symlink,
    /// Device, socket, FIFO or anything else.
    Other,
}

impl EntryKind {
    /// Lower-case name used in tool results.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "directory",
            EntryKind::Symlink => "symlink",
            EntryKind::Other => "other",
        }
    }
}

/// Metadata of one entry, without following a final link.
#[derive(Debug, Clone)]
pub struct Stat {
    /// Entry kind.
    pub kind: EntryKind,
    /// Size in bytes.
    pub len: u64,
    /// Last modification time, when the platform reports one.
    pub modified: Option<SystemTime>,
    /// Whether the entry is read-only.
    pub readonly: bool,
    /// Unix permission bits, when available.
    pub mode: Option<u32>,
    /// For a link, what it points to.
    pub link_target: Option<PathBuf>,
}

/// A slice of a file.
#[derive(Debug, Clone)]
pub struct ReadChunk {
    /// The bytes read.
    pub data: Vec<u8>,
    /// Total size of the file.
    pub file_size: u64,
    /// Whether the slice reaches the end of the file.
    pub eof: bool,
}

/// What to do when the destination of a write already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfExists {
    /// Fail with [`ToolError::AlreadyExists`].
    Fail,
    /// Replace it.
    Replace,
}

/// Options for [`Fs::write`].
#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// Create missing parent directories.
    pub create_parents: bool,
    /// Behaviour when the file exists.
    pub if_exists: IfExists,
}

/// Result of a write.
#[derive(Debug, Clone, Copy)]
pub struct WriteOutcome {
    /// Whether the file did not exist before.
    pub created: bool,
    /// Bytes written.
    pub bytes: u64,
}

/// Options for [`Fs::walk`].
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Deepest level to report (1 = direct children). `None` is unlimited.
    pub max_depth: Option<usize>,
    /// Stop after visiting this many entries (never more than the policy's
    /// limit).
    pub max_entries: usize,
    /// Fill in size and modification time (one extra stat per entry).
    pub with_metadata: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            max_entries: usize::MAX,
            with_metadata: false,
        }
    }
}

/// One entry reported by a walk.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    /// The entry's checked path (usable with any [`Fs`] operation).
    pub path: CheckedPath,
    /// Path relative to the directory the walk started in.
    pub rel: PathBuf,
    /// Entry kind.
    pub kind: EntryKind,
    /// Depth below the starting directory (direct children are 1).
    pub depth: usize,
    /// Size in bytes (0 unless `with_metadata`).
    pub len: u64,
    /// Modification time (`None` unless `with_metadata`).
    pub modified: Option<SystemTime>,
}

/// What a walk visitor wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep going (and descend, if this entry is a directory).
    Continue,
    /// Do not descend into this directory.
    SkipDir,
    /// End the walk.
    Stop,
}

/// Totals for a finished walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkSummary {
    /// Entries passed to the visitor.
    pub visited: usize,
    /// Entries hidden because they match a deny pattern or no allow pattern.
    pub hidden: usize,
    /// Whether the walk stopped at the entry limit.
    pub truncated: bool,
}

/// Totals for a finished copy.
#[derive(Debug, Clone, Copy, Default)]
pub struct CopyOutcome {
    /// Files copied.
    pub files: u64,
    /// Directories created.
    pub dirs: u64,
    /// Bytes copied.
    pub bytes: u64,
    /// Links left out (links are never copied or followed).
    pub skipped_links: u64,
    /// Entries left out because policy hides them.
    pub skipped_hidden: u64,
}

/// Totals for a finished removal.
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoveOutcome {
    /// Files and links removed.
    pub files: u64,
    /// Directories removed.
    pub dirs: u64,
}

/// Policy-bound filesystem accessor. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Fs {
    rules: Arc<PathRules>,
    base: PathBuf,
    max_walk_entries: usize,
}

/// The final step to an entry: the directory that holds it, or the allowed
/// root itself.
enum Leaf {
    Root(Dir),
    Child(Dir, OsString),
}

impl Fs {
    /// Create an accessor for the given rules. `base` is the directory
    /// relative paths resolve against.
    #[must_use]
    pub fn new(rules: Arc<PathRules>, base: PathBuf, max_walk_entries: usize) -> Self {
        Self {
            rules,
            base,
            max_walk_entries,
        }
    }

    /// The directory relative paths resolve against.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Check a path argument, following links to what it really names.
    pub fn resolve(&self, path: &str) -> Result<CheckedPath, ToolError> {
        self.rules.resolve(Path::new(path), &self.base)
    }

    /// Check a path argument as a directory entry: the final component is not
    /// followed if it is a link. For delete, rename and inspect.
    pub fn resolve_entry(&self, path: &str) -> Result<CheckedPath, ToolError> {
        self.rules.resolve_entry(Path::new(path), &self.base)
    }

    /// Run filesystem work on the blocking pool.
    pub async fn run<T, F>(&self, work: F) -> Result<T, ToolError>
    where
        T: Send + 'static,
        F: FnOnce(&Fs) -> Result<T, ToolError> + Send + 'static,
    {
        let fs = self.clone();
        tokio::task::spawn_blocking(move || work(&fs))
            .await
            .map_err(|e| ToolError::Internal(format!("filesystem task failed: {e}")))?
    }

    // ---- inspection -------------------------------------------------------

    /// Metadata of the entry, or `None` if it does not exist.
    pub fn try_stat(&self, path: &CheckedPath) -> Result<Option<Stat>, ToolError> {
        let leaf = match self.leaf(path, false) {
            Ok(leaf) => leaf,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(path, "inspecting", &e)),
        };
        let (meta, link_target) = match &leaf {
            Leaf::Root(dir) => (dir.dir_metadata(), None),
            Leaf::Child(parent, name) => {
                let meta = parent.symlink_metadata(name);
                let target = match &meta {
                    Ok(m) if m.is_symlink() => parent.read_link_contents(name).ok(),
                    _ => None,
                };
                (meta, target)
            }
        };
        match meta {
            Ok(meta) => Ok(Some(stat_from(&meta, link_target))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(path, "inspecting", &e)),
        }
    }

    /// Metadata of the entry; fails if it does not exist.
    pub fn stat(&self, path: &CheckedPath) -> Result<Stat, ToolError> {
        self.try_stat(path)?
            .ok_or_else(|| ToolError::NotFound(format!("{path} does not exist")))
    }

    // ---- reading ----------------------------------------------------------

    /// Open a regular file for reading.
    pub fn open_read(&self, path: &CheckedPath) -> Result<(std::fs::File, u64), ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, false)
            .map_err(|e| io_error(path, "opening", &e))?
        else {
            return Err(ToolError::InvalidArguments(format!(
                "{path} is a directory, not a file"
            )));
        };
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent
            .open_with(&name, &options)
            .map_err(|e| io_error(path, "opening", &e))?;
        let meta = file
            .metadata()
            .map_err(|e| io_error(path, "inspecting", &e))?;
        if meta.is_dir() {
            return Err(ToolError::InvalidArguments(format!(
                "{path} is a directory, not a file"
            )));
        }
        if !meta.is_file() {
            // Devices and FIFOs can block forever or never end.
            return Err(ToolError::InvalidArguments(format!(
                "{path} is not a regular file"
            )));
        }
        Ok((file.into_std(), meta.len()))
    }

    /// Read up to `max` bytes starting at `offset`.
    pub fn read_range(&self, path: &CheckedPath, offset: u64, max: usize) -> Result<ReadChunk, ToolError> {
        let (mut file, file_size) = self.open_read(path)?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| io_error(path, "seeking in", &e))?;
        }
        let mut data = Vec::with_capacity(max.min(64 * 1024));
        (&mut file)
            .take(max as u64)
            .read_to_end(&mut data)
            .map_err(|e| io_error(path, "reading", &e))?;
        let eof = offset.saturating_add(data.len() as u64) >= file_size;
        Ok(ReadChunk {
            data,
            file_size,
            eof,
        })
    }

    /// Read a whole file, failing if it is larger than `limit` bytes.
    pub fn read_all(&self, path: &CheckedPath, limit: usize) -> Result<Vec<u8>, ToolError> {
        let (mut file, file_size) = self.open_read(path)?;
        if file_size > limit as u64 {
            return Err(ToolError::OutputTooLarge { limit });
        }
        let mut data = Vec::with_capacity(file_size as usize);
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| io_error(path, "reading", &e))?;
        if data.len() > limit {
            return Err(ToolError::OutputTooLarge { limit });
        }
        Ok(data)
    }

    /// SHA-256 of a file's contents, as lowercase hex, and its size.
    pub fn sha256(&self, path: &CheckedPath, cancel: &CancellationToken) -> Result<(String, u64), ToolError> {
        let (mut file, _) = self.open_read(path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            if cancel.is_cancelled() {
                return Err(ToolError::Cancelled);
            }
            let n = file
                .read(&mut buf)
                .map_err(|e| io_error(path, "reading", &e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        Ok((hex::encode(hasher.finalize()), total))
    }

    // ---- writing ----------------------------------------------------------

    /// Write a whole file. The new contents replace the old in one step: the
    /// data is written to a temporary file beside the target and renamed over
    /// it, so a crash never leaves a half-written file.
    pub fn write(&self, path: &CheckedPath, data: &[u8], options: WriteOptions) -> Result<WriteOutcome, ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, options.create_parents)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::InvalidArguments(format!(
                "{path} is a directory, not a file"
            )));
        };
        let existing = match parent.symlink_metadata(&name) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(path, "inspecting", &e)),
        };
        if let Some(meta) = &existing {
            if meta.is_dir() {
                return Err(ToolError::InvalidArguments(format!(
                    "{path} is a directory, not a file"
                )));
            }
            if options.if_exists == IfExists::Fail {
                return Err(ToolError::AlreadyExists(format!("{path}")));
            }
        }

        let temp = temp_name(&name);
        let mut create = OpenOptions::new();
        create.write(true).create_new(true).follow(FollowSymlinks::No);
        let result = (|| -> io::Result<()> {
            let mut file = parent.open_with(&temp, &create)?;
            file.write_all(data)?;
            file.sync_data().ok();
            drop(file);
            if let Some(meta) = existing.as_ref().filter(|m| m.is_file()) {
                parent.set_permissions(&temp, meta.permissions()).ok();
            }
            parent.rename(&temp, &parent, &name)
        })();
        if let Err(e) = result {
            parent.remove_file(&temp).ok();
            return Err(io_error(path, "writing", &e));
        }
        Ok(WriteOutcome {
            created: existing.is_none(),
            bytes: data.len() as u64,
        })
    }

    /// Append to a file, optionally creating it.
    pub fn append(&self, path: &CheckedPath, data: &[u8], create: bool) -> Result<u64, ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, create)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::InvalidArguments(format!(
                "{path} is a directory, not a file"
            )));
        };
        let mut options = OpenOptions::new();
        options.append(true).create(create).follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|e| io_error(path, "opening", &e))?;
        file.write_all(data)
            .map_err(|e| io_error(path, "appending to", &e))?;
        file.metadata()
            .map(|m| m.len())
            .map_err(|e| io_error(path, "inspecting", &e))
    }

    /// Create (or truncate) a file and return it for streaming writes.
    pub fn create_file(&self, path: &CheckedPath, if_exists: IfExists, create_parents: bool) -> Result<std::fs::File, ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, create_parents)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::InvalidArguments(format!(
                "{path} is a directory, not a file"
            )));
        };
        let mut options = OpenOptions::new();
        options.write(true).follow(FollowSymlinks::No);
        match if_exists {
            IfExists::Fail => options.create_new(true),
            IfExists::Replace => options.create(true).truncate(true),
        };
        parent
            .open_with(&name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|e| io_error(path, "creating", &e))
    }

    /// Create a directory. Returns whether it was created by this call.
    pub fn create_dir(&self, path: &CheckedPath, parents: bool) -> Result<bool, ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, parents)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Ok(false);
        };
        match parent.create_dir(&name) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match parent.symlink_metadata(&name) {
                    Ok(meta) if meta.is_dir() => Ok(false),
                    _ => Err(ToolError::AlreadyExists(format!(
                        "{path} exists and is not a directory"
                    ))),
                }
            }
            Err(e) => Err(io_error(path, "creating", &e)),
        }
    }

    /// Set Unix permission bits. Special bits (setuid, setgid, sticky) are
    /// refused.
    #[cfg(unix)]
    pub fn set_mode(&self, path: &CheckedPath, mode: u32) -> Result<(), ToolError> {
        use std::os::unix::fs::PermissionsExt;
        if mode & !0o777 != 0 {
            return Err(ToolError::PermissionDenied(
                "setuid, setgid and sticky bits cannot be set".to_string(),
            ));
        }
        let Leaf::Child(parent, name) = self
            .leaf(path, false)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::PermissionDenied(
                "the permissions of an allowed root cannot be changed".to_string(),
            ));
        };
        let perms = cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(mode));
        parent
            .set_permissions(&name, perms)
            .map_err(|e| io_error(path, "changing permissions of", &e))
    }

    /// Set or clear the read-only flag.
    pub fn set_readonly(&self, path: &CheckedPath, readonly: bool) -> Result<(), ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, false)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::PermissionDenied(
                "the permissions of an allowed root cannot be changed".to_string(),
            ));
        };
        let meta = parent
            .symlink_metadata(&name)
            .map_err(|e| io_error(path, "inspecting", &e))?;
        let mut perms = meta.permissions();
        perms.set_readonly(readonly);
        parent
            .set_permissions(&name, perms)
            .map_err(|e| io_error(path, "changing permissions of", &e))
    }

    // ---- removing, renaming, copying --------------------------------------

    /// Remove a file, a link, or a directory. A non-empty directory needs
    /// `recursive`, and is refused if it holds anything policy hides.
    pub fn remove(&self, path: &CheckedPath, recursive: bool, cancel: &CancellationToken) -> Result<RemoveOutcome, ToolError> {
        let Leaf::Child(parent, name) = self
            .leaf(path, false)
            .map_err(|e| io_error(path, "opening the directory of", &e))?
        else {
            return Err(ToolError::PermissionDenied(format!(
                "{path} is an allowed root and cannot be removed"
            )));
        };
        let meta = parent
            .symlink_metadata(&name)
            .map_err(|e| io_error(path, "inspecting", &e))?;
        if !meta.is_dir() {
            parent
                .remove_file_or_symlink(&name)
                .map_err(|e| io_error(path, "removing", &e))?;
            return Ok(RemoveOutcome { files: 1, dirs: 0 });
        }
        if !recursive {
            return match parent.remove_dir(&name) {
                Ok(()) => Ok(RemoveOutcome { files: 0, dirs: 1 }),
                Err(e) if is_not_empty(&e) => Err(ToolError::InvalidArguments(format!(
                    "{path} is a directory that is not empty; pass recursive=true to remove it \
                     and everything in it"
                ))),
                Err(e) => Err(io_error(path, "removing", &e)),
            };
        }
        let outcome = self.count_tree_refusing_hidden(path, cancel, "removed")?;
        parent
            .remove_dir_all(&name)
            .map_err(|e| io_error(path, "removing", &e))?;
        Ok(RemoveOutcome {
            files: outcome.0,
            dirs: outcome.1 + 1,
        })
    }

    /// Rename an entry. Both paths should come from [`Fs::resolve_entry`].
    /// Fails with [`ToolError::AlreadyExists`] if the destination exists and
    /// `if_exists` is [`IfExists::Fail`].
    pub fn rename(&self, from: &CheckedPath, to: &CheckedPath, if_exists: IfExists, cancel: &CancellationToken) -> Result<(), ToolError> {
        let Leaf::Child(from_parent, from_name) = self
            .leaf(from, false)
            .map_err(|e| io_error(from, "opening the directory of", &e))?
        else {
            return Err(ToolError::PermissionDenied(format!(
                "{from} is an allowed root and cannot be renamed"
            )));
        };
        let meta = from_parent
            .symlink_metadata(&from_name)
            .map_err(|e| io_error(from, "inspecting", &e))?;
        if meta.is_dir() {
            if to.as_path().starts_with(from.as_path()) {
                return Err(ToolError::InvalidArguments(format!(
                    "cannot move {from} into itself"
                )));
            }
            // Moving a directory moves everything in it, including entries a
            // deny pattern protects by the directory's name.
            self.count_tree_refusing_hidden(from, cancel, "moved")?;
        }
        let Leaf::Child(to_parent, to_name) = self
            .leaf(to, false)
            .map_err(|e| io_error(to, "opening the directory of", &e))?
        else {
            return Err(ToolError::PermissionDenied(format!(
                "{to} is an allowed root and cannot be replaced"
            )));
        };
        match to_parent.symlink_metadata(&to_name) {
            Ok(_) if if_exists == IfExists::Fail => {
                return Err(ToolError::AlreadyExists(format!("{to}")));
            }
            Ok(existing) if existing.is_dir() != meta.is_dir() => {
                return Err(ToolError::InvalidArguments(format!(
                    "cannot replace {to}: one of the two is a directory and the other is not"
                )));
            }
            _ => {}
        }
        from_parent
            .rename(&from_name, &to_parent, &to_name)
            .map_err(|e| {
                if is_cross_device(&e) {
                    ToolError::Execution(format!(
                        "{from} and {to} are on different filesystems; copy and delete instead"
                    ))
                } else {
                    io_error(from, "renaming", &e)
                }
            })
    }

    /// Copy a file or a directory tree. Links are never followed or copied,
    /// and entries policy hides are left out; both are counted in the result.
    pub fn copy(&self, from: &CheckedPath, to: &CheckedPath, if_exists: IfExists, cancel: &CancellationToken) -> Result<CopyOutcome, ToolError> {
        let source = self.stat(from)?;
        let mut outcome = CopyOutcome::default();
        match source.kind {
            EntryKind::File => {
                outcome.bytes = self.copy_file(from, to, if_exists)?;
                outcome.files = 1;
            }
            EntryKind::Dir => {
                if to.as_path().starts_with(from.as_path()) {
                    return Err(ToolError::InvalidArguments(format!(
                        "cannot copy {from} into itself"
                    )));
                }
                if let Some(existing) = self.try_stat(to)? {
                    if if_exists == IfExists::Fail {
                        return Err(ToolError::AlreadyExists(format!("{to}")));
                    }
                    if existing.kind != EntryKind::Dir {
                        return Err(ToolError::InvalidArguments(format!(
                            "cannot copy the directory {from} over {to}, which is not a directory"
                        )));
                    }
                }
                self.create_dir(to, true)?;
                outcome.dirs = 1;
                let summary = self.walk(from, &WalkOptions::default(), cancel, &mut |entry| {
                    let target = self.rules.resolve(&to.as_path().join(&entry.rel), &self.base)?;
                    match entry.kind {
                        EntryKind::Dir => {
                            self.create_dir(&target, false)?;
                            outcome.dirs += 1;
                        }
                        EntryKind::File => {
                            outcome.bytes += self.copy_file(&entry.path, &target, if_exists)?;
                            outcome.files += 1;
                        }
                        EntryKind::Symlink | EntryKind::Other => outcome.skipped_links += 1,
                    }
                    Ok(Flow::Continue)
                })?;
                if summary.truncated {
                    return Err(ToolError::Execution(format!(
                        "{from} has more entries than one operation may visit; the copy is \
                         incomplete"
                    )));
                }
                outcome.skipped_hidden = summary.hidden as u64;
            }
            EntryKind::Symlink | EntryKind::Other => {
                return Err(ToolError::InvalidArguments(format!(
                    "{from} is not a regular file or directory"
                )))
            }
        }
        Ok(outcome)
    }

    fn copy_file(&self, from: &CheckedPath, to: &CheckedPath, if_exists: IfExists) -> Result<u64, ToolError> {
        let (mut source, _) = self.open_read(from)?;
        let Leaf::Child(parent, name) = self
            .leaf(to, false)
            .map_err(|e| io_error(to, "opening the directory of", &e))?
        else {
            return Err(ToolError::InvalidArguments(format!(
                "{to} is a directory, not a file"
            )));
        };
        match parent.symlink_metadata(&name) {
            Ok(_) if if_exists == IfExists::Fail => {
                return Err(ToolError::AlreadyExists(format!("{to}")));
            }
            Ok(meta) if meta.is_dir() => {
                return Err(ToolError::InvalidArguments(format!(
                    "{to} is a directory, not a file"
                )));
            }
            _ => {}
        }
        let temp = temp_name(&name);
        let mut create = OpenOptions::new();
        create.write(true).create_new(true).follow(FollowSymlinks::No);
        let result = (|| -> io::Result<u64> {
            let mut file = parent.open_with(&temp, &create)?.into_std();
            let bytes = io::copy(&mut source, &mut file)?;
            if let Ok(meta) = source.metadata() {
                file.set_permissions(meta.permissions()).ok();
            }
            drop(file);
            parent.rename(&temp, &parent, &name)?;
            Ok(bytes)
        })();
        result.map_err(|e| {
            parent.remove_file(&temp).ok();
            io_error(to, "writing", &e)
        })
    }

    // ---- walking ----------------------------------------------------------

    /// Visit everything beneath a directory, in name order, without following
    /// links. Entries policy hides are never passed to the visitor.
    pub fn walk(
        &self,
        root: &CheckedPath,
        options: &WalkOptions,
        cancel: &CancellationToken,
        visit: &mut dyn FnMut(&WalkEntry) -> Result<Flow, ToolError>,
    ) -> Result<WalkSummary, ToolError> {
        let start = match self
            .leaf(root, false)
            .map_err(|e| io_error(root, "opening", &e))?
        {
            Leaf::Root(dir) => dir,
            Leaf::Child(parent, name) => parent
                .open_dir_nofollow(&name)
                .map_err(|e| io_error(root, "opening", &e))?,
        };
        let limit = options.max_entries.min(self.max_walk_entries);
        let mut summary = WalkSummary::default();
        // Depth-first with an explicit stack; entries of the directory on top
        // are consumed in sorted order.
        let mut stack: Vec<(Dir, CheckedPath, PathBuf, usize)> =
            vec![(start, root.clone(), PathBuf::new(), 0)];
        while let Some((dir, dir_path, dir_rel, depth)) = stack.pop() {
            let mut names: Vec<(OsString, EntryKind)> = Vec::new();
            let entries = dir
                .entries()
                .map_err(|e| io_error(&dir_path, "listing", &e))?;
            for entry in entries {
                let entry = entry.map_err(|e| io_error(&dir_path, "listing", &e))?;
                let kind = match entry.file_type() {
                    Ok(t) if t.is_dir() => EntryKind::Dir,
                    Ok(t) if t.is_file() => EntryKind::File,
                    Ok(t) if t.is_symlink() => EntryKind::Symlink,
                    _ => EntryKind::Other,
                };
                names.push((entry.file_name(), kind));
            }
            names.sort();
            let mut subdirs: Vec<(Dir, CheckedPath, PathBuf, usize)> = Vec::new();
            for (name, kind) in names {
                if cancel.is_cancelled() {
                    return Err(ToolError::Cancelled);
                }
                let is_dir = kind == EntryKind::Dir;
                let visibility = self.rules.entry_visibility(&dir_path, &name, is_dir);
                if visibility == Visibility::Denied {
                    summary.hidden += 1;
                    continue;
                }
                let path = self.rules.child(&dir_path, &name);
                let rel = dir_rel.join(&name);
                let mut flow = Flow::Continue;
                if visibility == Visibility::Visible {
                    if summary.visited >= limit {
                        summary.truncated = true;
                        return Ok(summary);
                    }
                    summary.visited += 1;
                    let (len, modified) = if options.with_metadata {
                        dir.symlink_metadata(&name)
                            .map(|m| (m.len(), m.modified().ok().map(|t| t.into_std())))
                            .unwrap_or((0, None))
                    } else {
                        (0, None)
                    };
                    flow = visit(&WalkEntry {
                        path: path.clone(),
                        rel: rel.clone(),
                        kind,
                        depth: depth + 1,
                        len,
                        modified,
                    })?;
                    if flow == Flow::Stop {
                        return Ok(summary);
                    }
                }
                let within_depth = options.max_depth.is_none_or(|max| depth + 1 < max);
                if is_dir && flow == Flow::Continue && within_depth {
                    // Opened without following: a directory swapped for a link
                    // after it was listed is skipped rather than entered.
                    if let Ok(sub) = dir.open_dir_nofollow(&name) {
                        subdirs.push((sub, path, rel, depth + 1));
                    }
                }
            }
            // Reverse so the first subdirectory is popped next.
            stack.extend(subdirs.into_iter().rev());
        }
        Ok(summary)
    }

    /// Count the files and directories beneath `dir`, refusing if anything in
    /// it is hidden by policy or it is too large to inspect fully.
    fn count_tree_refusing_hidden(&self, dir: &CheckedPath, cancel: &CancellationToken, verb: &str) -> Result<(u64, u64), ToolError> {
        let (mut files, mut dirs) = (0u64, 0u64);
        let summary = self.walk(dir, &WalkOptions::default(), cancel, &mut |entry| {
            if entry.kind == EntryKind::Dir {
                dirs += 1;
            } else {
                files += 1;
            }
            Ok(Flow::Continue)
        })?;
        if summary.hidden > 0 {
            return Err(ToolError::PermissionDenied(format!(
                "{dir} contains {} entries that policy does not allow access to, so it cannot be \
                 {verb} as a whole",
                summary.hidden
            )));
        }
        if summary.truncated {
            return Err(ToolError::Execution(format!(
                "{dir} has more entries than one operation may visit, so it cannot be {verb} as a \
                 whole"
            )));
        }
        Ok((files, dirs))
    }

    // ---- plumbing ---------------------------------------------------------

    /// Open the directory that holds `path`, one component at a time, never
    /// following a link. With `create_parents`, missing directories are made.
    fn leaf(&self, path: &CheckedPath, create_parents: bool) -> io::Result<Leaf> {
        let root = open_root(path.root()).map_err(|e| io::Error::other(e.to_string()))?;
        let mut names: Vec<&OsStr> = Vec::new();
        for comp in path.rel().components() {
            match comp {
                Component::Normal(name) => names.push(name),
                Component::CurDir => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected path component",
                    ))
                }
            }
        }
        let Some((last, parents)) = names.split_last() else {
            return Ok(Leaf::Root(root));
        };
        let mut dir = root;
        for name in parents {
            dir = match dir.open_dir_nofollow(name) {
                Ok(next) => next,
                Err(e) if e.kind() == io::ErrorKind::NotFound && create_parents => {
                    match dir.create_dir(name) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e),
                    }
                    dir.open_dir_nofollow(name)?
                }
                Err(e) => return Err(e),
            };
        }
        Ok(Leaf::Child(dir, (*last).to_os_string()))
    }
}

fn stat_from(meta: &Metadata, link_target: Option<PathBuf>) -> Stat {
    let kind = if meta.is_symlink() {
        EntryKind::Symlink
    } else if meta.is_dir() {
        EntryKind::Dir
    } else if meta.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    #[cfg(unix)]
    let mode = {
        use cap_std::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let mode = None;
    Stat {
        kind,
        len: meta.len(),
        modified: meta.modified().ok().map(|t| t.into_std()),
        readonly: meta.permissions().readonly(),
        mode,
        link_target,
    }
}

fn temp_name(name: &OsStr) -> OsString {
    let mut temp = OsString::from(".");
    temp.push(name);
    temp.push(format!(".nebula-tmp-{}", uuid::Uuid::new_v4().simple()));
    temp
}

fn is_not_empty(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::DirectoryNotEmpty
}

fn is_cross_device(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::CrossesDevices
}

fn io_error(path: &CheckedPath, doing: &str, e: &io::Error) -> ToolError {
    match e.kind() {
        io::ErrorKind::NotFound => ToolError::NotFound(format!("{path} does not exist")),
        io::ErrorKind::AlreadyExists => ToolError::AlreadyExists(format!("{path}")),
        // A link where a directory or file was resolved a moment ago.
        io::ErrorKind::FilesystemLoop => ToolError::PermissionDenied(format!(
            "{path} changed while it was being accessed (a component is now a link)"
        )),
        _ => ToolError::Io(format!("{doing} {path}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _guard: tempfile::TempDir,
        root: PathBuf,
        fs: Fs,
        cancel: CancellationToken,
    }

    fn fixture(denied: &[&str]) -> Fixture {
        let guard = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(guard.path()).unwrap();
        let denied: Vec<String> = denied.iter().map(|s| (*s).to_string()).collect();
        let rules = PathRules::build(&[".".to_string()], &denied, &[], &root).unwrap();
        let fs = Fs::new(Arc::new(rules), root.clone(), 10_000);
        Fixture {
            _guard: guard,
            root,
            fs,
            cancel: CancellationToken::new(),
        }
    }

    const REPLACE: WriteOptions = WriteOptions {
        create_parents: true,
        if_exists: IfExists::Replace,
    };

    #[test]
    fn write_read_append_roundtrip() {
        let f = fixture(&[]);
        let p = f.fs.resolve("a/b/file.txt").unwrap();
        let out = f.fs.write(&p, b"hello", REPLACE).unwrap();
        assert!(out.created);
        assert_eq!(f.fs.read_all(&p, 100).unwrap(), b"hello");
        assert_eq!(f.fs.append(&p, b" world", false).unwrap(), 11);
        let chunk = f.fs.read_range(&p, 6, 3).unwrap();
        assert_eq!(chunk.data, b"wor");
        assert!(!chunk.eof);
        assert_eq!(chunk.file_size, 11);
        assert!(f.fs.read_range(&p, 6, 100).unwrap().eof);
        // No temporary files are left behind.
        let names: Vec<_> = std::fs::read_dir(f.root.join("a/b"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![OsString::from("file.txt")]);
    }

    #[test]
    fn write_refuses_to_replace_unless_asked() {
        let f = fixture(&[]);
        let p = f.fs.resolve("x.txt").unwrap();
        f.fs.write(&p, b"one", REPLACE).unwrap();
        let fail = WriteOptions {
            create_parents: false,
            if_exists: IfExists::Fail,
        };
        assert!(matches!(
            f.fs.write(&p, b"two", fail),
            Err(ToolError::AlreadyExists(_))
        ));
        assert_eq!(f.fs.read_all(&p, 100).unwrap(), b"one");
        assert!(!f.fs.write(&p, b"two", REPLACE).unwrap().created);
    }

    #[test]
    fn read_all_enforces_its_limit() {
        let f = fixture(&[]);
        let p = f.fs.resolve("big.bin").unwrap();
        f.fs.write(&p, &[7u8; 5000], REPLACE).unwrap();
        assert!(matches!(
            f.fs.read_all(&p, 4999),
            Err(ToolError::OutputTooLarge { .. })
        ));
        assert_eq!(f.fs.read_all(&p, 5000).unwrap().len(), 5000);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_a_link_after_the_check_is_not_followed() {
        let f = fixture(&[]);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "s").unwrap();
        std::fs::create_dir(f.root.join("dir")).unwrap();
        std::fs::write(f.root.join("dir/file"), "ok").unwrap();

        // Checked while everything is ordinary...
        let file = f.fs.resolve("dir/file").unwrap();
        let new = f.fs.resolve("dir/new.txt").unwrap();
        // ...then the directory is replaced by a link out of the root.
        std::fs::remove_dir_all(f.root.join("dir")).unwrap();
        std::os::unix::fs::symlink(outside.path(), f.root.join("dir")).unwrap();
        std::fs::write(outside.path().join("file"), "outside").unwrap();

        assert!(f.fs.read_all(&file, 100).is_err());
        assert!(f.fs.write(&new, b"x", REPLACE).is_err());
        assert!(!outside.path().join("new.txt").exists());

        // The same for a final component that becomes a link.
        std::fs::remove_file(f.root.join("dir")).unwrap();
        std::fs::write(f.root.join("plain"), "ok").unwrap();
        let plain = f.fs.resolve("plain").unwrap();
        std::fs::remove_file(f.root.join("plain")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), f.root.join("plain")).unwrap();
        assert!(f.fs.read_all(&plain, 100).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_link_removes_the_link_not_its_target() {
        let f = fixture(&[]);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), "k").unwrap();
        std::os::unix::fs::symlink(outside.path().join("keep"), f.root.join("link")).unwrap();
        let entry = f.fs.resolve_entry("link").unwrap();
        assert_eq!(f.fs.stat(&entry).unwrap().kind, EntryKind::Symlink);
        f.fs.remove(&entry, false, &f.cancel).unwrap();
        assert!(outside.path().join("keep").exists());
        assert!(f.fs.try_stat(&entry).unwrap().is_none());
    }

    #[test]
    fn walk_hides_denied_entries_and_never_follows_links() {
        let f = fixture(&["**/.env", "**/secrets"]);
        std::fs::create_dir_all(f.root.join("src/secrets")).unwrap();
        std::fs::write(f.root.join("src/main.rs"), "m").unwrap();
        std::fs::write(f.root.join("src/secrets/key"), "k").unwrap();
        std::fs::write(f.root.join(".env"), "E").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", f.root.join("rootlink")).unwrap();

        let top = f.fs.resolve(".").unwrap();
        let mut seen = Vec::new();
        let summary = f
            .fs
            .walk(&top, &WalkOptions::default(), &f.cancel, &mut |e| {
                seen.push((e.rel.to_string_lossy().replace('\\', "/"), e.kind));
                Ok(Flow::Continue)
            })
            .unwrap();
        let names: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"src") && names.contains(&"src/main.rs"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains(".env") || n.contains("secrets")), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("rootlink/")), "{names:?}");
        assert_eq!(summary.hidden, 2);
        #[cfg(unix)]
        assert!(seen.contains(&("rootlink".to_string(), EntryKind::Symlink)));
    }

    #[test]
    fn walk_respects_depth_and_entry_limits() {
        let f = fixture(&[]);
        std::fs::create_dir_all(f.root.join("a/b/c")).unwrap();
        for i in 0..5 {
            std::fs::write(f.root.join(format!("f{i}")), "x").unwrap();
        }
        let top = f.fs.resolve(".").unwrap();
        let mut count = 0;
        let shallow = WalkOptions {
            max_depth: Some(1),
            ..WalkOptions::default()
        };
        f.fs.walk(&top, &shallow, &f.cancel, &mut |e| {
            assert_eq!(e.depth, 1);
            count += 1;
            Ok(Flow::Continue)
        })
        .unwrap();
        assert_eq!(count, 6);

        let limited = WalkOptions {
            max_entries: 3,
            ..WalkOptions::default()
        };
        let summary = f
            .fs
            .walk(&top, &limited, &f.cancel, &mut |_| Ok(Flow::Continue))
            .unwrap();
        assert!(summary.truncated);
        assert_eq!(summary.visited, 3);
    }

    #[test]
    fn a_tree_holding_denied_entries_cannot_be_removed_or_moved_whole() {
        let f = fixture(&["**/.env"]);
        std::fs::create_dir_all(f.root.join("proj")).unwrap();
        std::fs::write(f.root.join("proj/.env"), "E").unwrap();
        std::fs::write(f.root.join("proj/ok"), "o").unwrap();
        let proj = f.fs.resolve_entry("proj").unwrap();
        let moved = f.fs.resolve_entry("moved").unwrap();
        assert!(matches!(
            f.fs.remove(&proj, true, &f.cancel),
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(matches!(
            f.fs.rename(&proj, &moved, IfExists::Fail, &f.cancel),
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(f.root.join("proj/.env").exists());
        // Copying leaves the hidden entry out and says so.
        let copy = f.fs.resolve("copy").unwrap();
        let outcome = f.fs.copy(&proj, &copy, IfExists::Fail, &f.cancel).unwrap();
        assert_eq!(outcome.files, 1);
        assert_eq!(outcome.skipped_hidden, 1);
        assert!(!f.root.join("copy/.env").exists());
        assert!(f.root.join("copy/ok").exists());
    }

    #[test]
    fn remove_rename_and_copy_basics() {
        let f = fixture(&[]);
        std::fs::create_dir_all(f.root.join("d/sub")).unwrap();
        std::fs::write(f.root.join("d/sub/a"), "a").unwrap();
        let d = f.fs.resolve_entry("d").unwrap();
        assert!(matches!(
            f.fs.remove(&d, false, &f.cancel),
            Err(ToolError::InvalidArguments(_))
        ));
        let e = f.fs.resolve_entry("e").unwrap();
        f.fs.rename(&d, &e, IfExists::Fail, &f.cancel).unwrap();
        assert!(f.root.join("e/sub/a").exists());
        let inside = f.fs.resolve("e/sub/copy").unwrap();
        assert!(f.fs.copy(&e, &inside, IfExists::Fail, &f.cancel).is_err());
        let out = f.fs.remove(&e, true, &f.cancel).unwrap();
        assert_eq!((out.files, out.dirs), (1, 2));
        let root = f.fs.resolve(".").unwrap();
        assert!(f.fs.remove(&root, true, &f.cancel).is_err());
    }

    #[test]
    fn sha256_and_create_dir() {
        let f = fixture(&[]);
        let p = f.fs.resolve("h.txt").unwrap();
        f.fs.write(&p, b"abc", REPLACE).unwrap();
        let (digest, size) = f.fs.sha256(&p, &f.cancel).unwrap();
        assert_eq!(size, 3);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let d = f.fs.resolve("x/y/z").unwrap();
        assert!(f.fs.create_dir(&d, true).unwrap());
        assert!(!f.fs.create_dir(&d, true).unwrap());
        assert!(matches!(
            f.fs.create_dir(&p, false),
            Err(ToolError::AlreadyExists(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn special_permission_bits_are_refused() {
        let f = fixture(&[]);
        let p = f.fs.resolve("s.sh").unwrap();
        f.fs.write(&p, b"#!/bin/sh\n", REPLACE).unwrap();
        assert!(f.fs.set_mode(&p, 0o4755).is_err());
        f.fs.set_mode(&p, 0o755).unwrap();
        assert_eq!(f.fs.stat(&p).unwrap().mode, Some(0o755));
    }
}
