//! File tools. Every operation goes through `ctx.fs()`, which confines paths
//! to the allowed directories after resolving symlinks, applies the deny
//! patterns to everything a tool touches or lists, and never follows a link
//! that appears after the check.

use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;

use base64::Engine;
use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::{
    CheckedPath, Flow, Fs, Kind, Meta, WalkOptions, WriteMode, CROSS_DEVICE,
};
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{Category, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Value};
use sha2::Digest;

use crate::common::{clip, handler, rfc3339, spec, tool, SpecExt};

const PATH_HELP: &str =
    "Absolute, or relative to the server's working directory. Must be inside an allowed directory.";

/// The `fs` tools.
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Fs;
    vec![
        tool(
            spec(
                "fs_read",
                c,
                "Read file",
                "Read a file as text (UTF-8) or as base64 for binary data. Large files are read in \
                 chunks: when the result says more remains, call again with the offset it names.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .integer_min("offset", "Byte offset to start at (default 0).", 0, false)
                    .integer_min(
                        "maxBytes",
                        "Most bytes to read in this call (default and ceiling: the server's \
                         output limit).",
                        1,
                        false,
                    )
                    .string_enum(
                        "encoding",
                        "utf8 (default) returns text; base64 returns the raw bytes encoded.",
                        &["utf8", "base64"],
                        false,
                    )
                    .build(),
                Effects::read_only(),
            ),
            handler!(read),
        ),
        tool(
            spec(
                "fs_write",
                c,
                "Write file",
                "Create a file or replace its whole content. The replacement is atomic. To change \
                 part of a file use fs_edit; to add to the end use fs_append.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .string("content", "The complete new content of the file.", true)
                    .string_enum(
                        "encoding",
                        "utf8 (default) writes the text as given; base64 decodes it first, for \
                         binary files.",
                        &["utf8", "base64"],
                        false,
                    )
                    .boolean_default(
                        "createParents",
                        "Create missing parent directories.",
                        true,
                    )
                    .build(),
                Effects::writes().overwrites().idempotent(true),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path of the file.", true)
                    .integer("bytes", "Bytes written.", true)
                    .boolean("created", "False when an existing file was replaced.", true)
                    .build(),
            ),
            handler!(write),
        ),
        tool(
            spec(
                "fs_edit",
                c,
                "Edit file",
                "Replace an exact piece of text in a UTF-8 file. oldString must occur exactly \
                 once, so include enough surrounding text to make it unique; set replaceAll or \
                 expectedCount to change several occurrences. Nothing is written unless the \
                 match count is as expected.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .string(
                        "oldString",
                        "Exact text to find, including whitespace. Must not be empty.",
                        true,
                    )
                    .string("newString", "Text to put in its place.", true)
                    .boolean_default(
                        "replaceAll",
                        "Replace every occurrence instead of requiring exactly one.",
                        false,
                    )
                    .integer_min(
                        "expectedCount",
                        "Require exactly this many occurrences, and replace them all.",
                        1,
                        false,
                    )
                    .build(),
                Effects::writes().overwrites(),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path of the file.", true)
                    .integer("replacements", "Occurrences replaced.", true)
                    .build(),
            ),
            handler!(edit),
        ),
        tool(
            spec(
                "fs_append",
                c,
                "Append to file",
                "Add text to the end of a file, creating the file if it does not exist.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .string("content", "Text to append.", true)
                    .build(),
                Effects::writes(),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path of the file.", true)
                    .integer("bytesAppended", "Bytes added.", true)
                    .integer("size", "Size of the file afterwards.", true)
                    .build(),
            ),
            handler!(append),
        ),
        tool(
            spec(
                "fs_mkdir",
                c,
                "Create directory",
                "Create a directory. Succeeds if it already exists.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .boolean_default("parents", "Create missing parent directories.", true)
                    .build(),
                Effects::writes().idempotent(true),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path of the directory.", true)
                    .boolean("created", "False when it already existed.", true)
                    .build(),
            ),
            handler!(mkdir),
        ),
        tool(
            spec(
                "fs_rename",
                c,
                "Rename",
                "Rename a file or directory. Fails if the destination exists; use fs_move to \
                 replace a destination or to move between filesystems.",
                ObjectSchema::new()
                    .string("from", "Existing path.", true)
                    .string("to", "New path. Must not exist.", true)
                    .build(),
                Effects::writes(),
            )
            .returns(moved_schema()),
            handler!(rename),
        ),
        tool(
            spec(
                "fs_move",
                c,
                "Move",
                "Move a file or directory, also between filesystems. Replacing an existing \
                 destination needs overwrite = true and the server's destructive permission.",
                ObjectSchema::new()
                    .string("from", "Existing path.", true)
                    .string("to", "Destination path.", true)
                    .boolean_default(
                        "overwrite",
                        "Replace the destination if it exists (a file, or an empty directory).",
                        false,
                    )
                    .build(),
                Effects::writes().destructive(Gate::Sometimes),
            )
            .returns(moved_schema()),
            handler!(move_path),
        ),
        tool(
            spec(
                "fs_copy",
                c,
                "Copy",
                "Copy a file, or a directory with everything in it. Symbolic links, special \
                 files and entries the server's policy protects are skipped and counted. \
                 Copying onto an existing destination needs overwrite = true and the server's \
                 destructive permission.",
                ObjectSchema::new()
                    .string("from", "Existing file or directory.", true)
                    .string("to", "Destination path.", true)
                    .boolean_default(
                        "overwrite",
                        "Write into the destination if it exists, replacing files of the same \
                         name.",
                        false,
                    )
                    .build(),
                Effects::writes().destructive(Gate::Sometimes),
            )
            .returns(
                ObjectSchema::open()
                    .string("from", "Resolved source path.", true)
                    .string("to", "Resolved destination path.", true)
                    .integer("files", "Files copied.", true)
                    .integer("directories", "Directories created.", true)
                    .integer("bytes", "Bytes copied.", true)
                    .integer("skipped", "Entries not copied.", true)
                    .build(),
            ),
            handler!(copy),
        ),
        tool(
            spec(
                "fs_delete",
                c,
                "Delete",
                "Delete a file, a symbolic link or a directory. A directory that is not empty \
                 needs recursive = true. Needs the server's destructive permission.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .boolean_default(
                        "recursive",
                        "Delete a directory together with everything in it.",
                        false,
                    )
                    .build(),
                Effects::writes().destructive(Gate::Always),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path that was deleted.", true)
                    .string_enum("type", "What it was.", &["file", "dir", "symlink", "other"], true)
                    .build(),
            ),
            handler!(delete),
        ),
        tool(
            spec(
                "fs_search",
                c,
                "Search file contents",
                "Search the text files under a directory for a regular expression and return \
                 matching lines as path:line: text. Binary files and files the server's policy \
                 protects are skipped. Narrow large searches with glob.",
                ObjectSchema::new()
                    .string("root", "Directory to search. Same rules as other paths.", true)
                    .string_max(
                        "pattern",
                        "Regular expression (Rust regex syntax; no look-around or back-references).",
                        2000,
                        true,
                    )
                    .string(
                        "glob",
                        "Only search files whose path below root matches, for example **/*.rs.",
                        false,
                    )
                    .boolean_default("ignoreCase", "Match case-insensitively.", false)
                    .integer_range(
                        "maxResults",
                        "Stop after this many matching lines (default 200).",
                        1,
                        10_000,
                        false,
                    )
                    .build(),
                Effects::read_only(),
            ),
            handler!(search),
        ),
        tool(
            spec(
                "fs_glob",
                c,
                "Find files",
                "List the files and directories under a directory whose path matches a glob \
                 pattern. Paths in the result are relative to root.",
                ObjectSchema::new()
                    .string("root", "Directory to search. Same rules as other paths.", true)
                    .string(
                        "pattern",
                        "Glob matched against the path below root, for example **/*.rs or \
                         src/*.toml. * does not cross a directory separator; ** does.",
                        true,
                    )
                    .integer_range(
                        "maxResults",
                        "Stop after this many matches (default 1000).",
                        1,
                        50_000,
                        false,
                    )
                    .build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .string("root", "Resolved search root.", true)
                    .string_array("matches", "Matching paths relative to root, sorted.", true)
                    .boolean("truncated", "True when a limit stopped the search early.", true)
                    .integer("hidden", "Entries not shown because policy protects them.", true)
                    .build(),
            ),
            handler!(glob),
        ),
        tool(
            spec(
                "fs_tree",
                c,
                "List directory tree",
                "List a directory as an indented tree with sizes. Use maxDepth = 1 for a plain \
                 listing. Symbolic links are shown but not followed.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .integer_range("maxDepth", "Levels to descend (default 3).", 1, 32, false)
                    .integer_range(
                        "maxEntries",
                        "Stop after this many entries (default 1000).",
                        1,
                        50_000,
                        false,
                    )
                    .build(),
                Effects::read_only(),
            ),
            handler!(tree),
        ),
        tool(
            spec(
                "fs_hash",
                c,
                "Hash file",
                "Compute the SHA-256 digest of a file of any size.",
                ObjectSchema::new().string("path", PATH_HELP, true).build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "Resolved path of the file.", true)
                    .string("sha256", "Digest in lower-case hexadecimal.", true)
                    .integer("size", "Bytes hashed.", true)
                    .build(),
            ),
            handler!(hash),
        ),
        tool(
            spec(
                "fs_metadata",
                c,
                "File metadata",
                "Report the type, size, modification time and permissions of a path. A symbolic \
                 link given as a path is resolved first; links seen while listing are reported \
                 as links.",
                ObjectSchema::new().string("path", PATH_HELP, true).build(),
                Effects::read_only(),
            )
            .returns(metadata_schema()),
            handler!(metadata),
        ),
        tool(
            spec(
                "fs_permissions",
                c,
                "Set permissions",
                "Change a file's permissions: a Unix mode (Linux and macOS) or the read-only \
                 flag. Returns the resulting metadata.",
                ObjectSchema::new()
                    .string("path", PATH_HELP, true)
                    .string_max(
                        "mode",
                        "Unix permission bits in octal, for example 644 or 0755. Not supported on \
                         Windows.",
                        5,
                        false,
                    )
                    .boolean("readonly", "Set or clear the read-only flag.", false)
                    .build(),
                Effects::writes().overwrites().idempotent(true),
            )
            .returns(metadata_schema()),
            handler!(permissions),
        ),
    ]
}

fn moved_schema() -> Value {
    ObjectSchema::open()
        .string("from", "Resolved source path.", true)
        .string("to", "Resolved destination path.", true)
        .build()
}

fn metadata_schema() -> Value {
    ObjectSchema::open()
        .string("path", "Resolved path.", true)
        .string_enum(
            "type",
            "Entry type.",
            &["file", "dir", "symlink", "other"],
            true,
        )
        .integer("size", "Size in bytes.", true)
        .nullable_string("modified", "Last modification time, RFC 3339 UTC.", true)
        .boolean("readonly", "Whether the owner cannot write it.", true)
        .nullable_string(
            "mode",
            "Unix permission bits in octal; null on Windows.",
            true,
        )
        .build()
}

fn metadata_json(path: &CheckedPath, meta: &Meta) -> Value {
    json!({
        "path": path.display(),
        "type": meta.kind.as_str(),
        "size": meta.len,
        "modified": meta.modified.and_then(rfc3339),
        "readonly": meta.readonly,
        "mode": meta.mode.map(|m| format!("{m:04o}")),
    })
}

/// Drop the bytes of a character cut off by the end of a chunk. Returns how
/// many were dropped (at most 3).
fn trim_partial_char(bytes: &mut Vec<u8>) -> usize {
    let len = bytes.len();
    for back in 1..=3.min(len) {
        let b = bytes[len - back];
        if b & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte: keep looking for the lead byte
        }
        let need = match b {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        if need > back {
            bytes.truncate(len - back);
            return back;
        }
        return 0;
    }
    0
}

async fn read(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let mut offset = a.u64_or("offset", 0)?;
    let max = a.usize_or("maxBytes", ctx.max_output_bytes())?;
    let as_base64 = a.opt_enum("encoding", &["utf8", "base64"])? == Some("base64");
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Read)?;
            // base64 grows the data by a third; keep the result inside the cap.
            let budget = if as_base64 { max / 4 * 3 } else { max }.max(1);
            let (mut bytes, total) = fs.read(&path, offset, budget)?;
            let text = if as_base64 {
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            } else {
                if offset > 0 {
                    // An arbitrary offset can land inside a character.
                    let skip = bytes
                        .iter()
                        .take(3)
                        .take_while(|b| **b & 0b1100_0000 == 0b1000_0000)
                        .count();
                    bytes.drain(..skip);
                    offset += skip as u64;
                }
                if offset + (bytes.len() as u64) < total {
                    trim_partial_char(&mut bytes);
                }
                String::from_utf8(bytes.clone()).map_err(|_| {
                    ToolError::invalid(format!(
                        "'{}' is not UTF-8 text; read it with encoding = \"base64\"",
                        path.display()
                    ))
                })?
            };
            let end = offset + bytes.len() as u64;
            let note = if total == 0 {
                Some("[fs_read: the file is empty]".to_string())
            } else if end < total {
                Some(format!(
                    "[fs_read: bytes {offset}-{end} of {total}. More remains: call again with \
                     offset = {end}]"
                ))
            } else if offset > 0 {
                Some(format!(
                    "[fs_read: bytes {offset}-{end} of {total}; end of file]"
                ))
            } else {
                None
            };
            let mut out = ToolOutput::text(text);
            if let Some(note) = note {
                out.content.push(Content::Text(note));
            }
            Ok(out)
        })
        .await
}

fn decode_content(content: &str, as_base64: bool) -> Result<Vec<u8>> {
    if !as_base64 {
        return Ok(content.as_bytes().to_vec());
    }
    let compact: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|e| ToolError::invalid(format!("content is not valid base64: {e}")))
}

fn ensure_parent(fs: &Fs, path: &CheckedPath, create: bool) -> Result<()> {
    let Some(parent) = fs.parent(path) else {
        return Ok(());
    };
    match fs.try_metadata(&parent)? {
        Some(m) if m.kind == Kind::Dir => Ok(()),
        Some(_) => Err(ToolError::invalid(format!(
            "'{}' is not a directory",
            parent.display()
        ))),
        None if create => fs.create_dir_all(&parent),
        None => Err(ToolError::NotFound(format!(
            "the directory '{}' does not exist; create it with fs_mkdir or pass \
             createParents = true",
            parent.display()
        ))),
    }
}

async fn write(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let as_base64 = a.opt_enum("encoding", &["utf8", "base64"])? == Some("base64");
    let bytes = decode_content(a.str("content")?, as_base64)?;
    let create_parents = a.bool_or("createParents", true)?;
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            let existing = fs.try_metadata(&path)?;
            if existing.as_ref().is_some_and(|m| m.kind == Kind::Dir) {
                return Err(ToolError::invalid(format!(
                    "'{}' is a directory",
                    path.display()
                )));
            }
            ensure_parent(fs, &path, create_parents)?;
            fs.write(&path, &bytes, WriteMode::Replace)?;
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "bytes": bytes.len(),
                "created": existing.is_none(),
            })))
        })
        .await
}

async fn edit(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let old = a.str("oldString")?.to_string();
    let new = a.str("newString")?.to_string();
    let replace_all = a.bool_or("replaceAll", false)?;
    let expected = a.opt_u64("expectedCount")?;
    if old.is_empty() {
        return Err(ToolError::invalid("oldString must not be empty"));
    }
    if old == new {
        return Err(ToolError::invalid(
            "oldString and newString are identical, so there is nothing to change",
        ));
    }
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            let content = String::from_utf8(fs.read_all(&path)?).map_err(|_| {
                ToolError::invalid(format!(
                    "'{}' is not UTF-8 text and cannot be edited as text",
                    path.display()
                ))
            })?;
            let count = content.matches(old.as_str()).count() as u64;
            if let Some(want) = expected {
                if count != want {
                    return Err(ToolError::Execution(format!(
                        "expected {want} occurrences of oldString but found {count}; nothing was \
                         changed"
                    )));
                }
            } else if count == 0 {
                return Err(ToolError::Execution(
                    "oldString was not found; nothing was changed. Read the file again and copy \
                     the text exactly, including indentation and line endings."
                        .to_string(),
                ));
            } else if count > 1 && !replace_all {
                return Err(ToolError::Execution(format!(
                    "oldString occurs {count} times; nothing was changed. Add surrounding text to \
                     make it unique, or set replaceAll = true or expectedCount = {count}."
                )));
            }
            let updated = content.replace(old.as_str(), &new);
            fs.write(&path, updated.as_bytes(), WriteMode::Replace)?;
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "replacements": count,
            })))
        })
        .await
}

async fn append(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let content = a.str("content")?.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            ensure_parent(fs, &path, false)?;
            fs.write(&path, content.as_bytes(), WriteMode::Append)?;
            let size = fs.metadata(&path)?.len;
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "bytesAppended": content.len(),
                "size": size,
            })))
        })
        .await
}

async fn mkdir(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let parents = a.bool_or("parents", true)?;
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            let created = match fs.try_metadata(&path)? {
                Some(m) if m.kind == Kind::Dir => false,
                Some(_) => {
                    return Err(ToolError::Execution(format!(
                        "'{}' exists and is not a directory",
                        path.display()
                    )))
                }
                None => {
                    ensure_parent(fs, &path, parents)?;
                    fs.create_dir_all(&path)?;
                    true
                }
            };
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "created": created,
            })))
        })
        .await
}

async fn rename(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let from = a.str("from")?.to_string();
    let to = a.str("to")?.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let src = fs.resolve(&from, Access::Write)?;
            let dst = fs.resolve(&to, Access::Write)?;
            fs.rename(&src, &dst, false).map_err(|e| match e {
                ToolError::Execution(m) if m == CROSS_DEVICE => ToolError::Execution(format!(
                    "{CROSS_DEVICE}; use fs_move, which copies and then removes the source"
                )),
                other => other,
            })?;
            Ok(ToolOutput::json(json!({
                "from": src.display(),
                "to": dst.display(),
            })))
        })
        .await
}

/// Whether the destination exists; when it does, `overwrite` and the
/// destructive gate are both required before anything is touched.
async fn check_destination(ctx: &ToolContext, to: &str, overwrite: bool) -> Result<bool> {
    let to = to.to_string();
    let existing = ctx
        .fs()
        .blocking(move |fs| {
            let dst = fs.resolve(&to, Access::Write)?;
            Ok(fs.try_metadata(&dst)?.map(|_| dst.display()))
        })
        .await?;
    let Some(shown) = existing else {
        return Ok(false);
    };
    if !overwrite {
        return Err(ToolError::Execution(format!(
            "'{shown}' already exists; nothing was changed. Pass overwrite = true to replace it."
        )));
    }
    ctx.require_destructive("replacing an existing destination")?;
    Ok(true)
}

async fn move_path(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let from = a.str("from")?.to_string();
    let to = a.str("to")?.to_string();
    let overwrite = a.bool_or("overwrite", false)?;
    let replace = check_destination(ctx, &to, overwrite).await?;
    ctx.fs()
        .blocking(move |fs| {
            let src = fs.resolve(&from, Access::Write)?;
            let dst = fs.resolve(&to, Access::Write)?;
            match fs.rename(&src, &dst, replace) {
                Ok(()) => {}
                Err(ToolError::Execution(m)) if m == CROSS_DEVICE => {
                    move_across_filesystems(fs, &src, &dst, replace)?;
                }
                Err(e) => return Err(e),
            }
            Ok(ToolOutput::json(json!({
                "from": src.display(),
                "to": dst.display(),
            })))
        })
        .await
}

fn move_across_filesystems(
    fs: &Fs,
    src: &CheckedPath,
    dst: &CheckedPath,
    replace: bool,
) -> Result<()> {
    let meta = fs.metadata(src)?;
    match meta.kind {
        Kind::Dir => {
            let summary = fs.copy_tree(src, dst)?;
            if summary.skipped > 0 {
                return Err(ToolError::Execution(format!(
                    "'{}' was copied to '{}' but {} entries (symbolic links, special files or \
                     protected files) could not be copied, so the source was kept",
                    src.display(),
                    dst.display(),
                    summary.skipped
                )));
            }
            fs.remove_dir_all(src)
        }
        Kind::File => {
            fs.copy_file(src, dst, replace)?;
            fs.remove_file(src)
        }
        Kind::Symlink | Kind::Other => Err(ToolError::Execution(format!(
            "'{}' is a symbolic link or special file and cannot be moved between filesystems",
            src.display()
        ))),
    }
}

async fn copy(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let from = a.str("from")?.to_string();
    let to = a.str("to")?.to_string();
    let overwrite = a.bool_or("overwrite", false)?;
    let replace = check_destination(ctx, &to, overwrite).await?;
    ctx.fs()
        .blocking(move |fs| {
            let src = fs.resolve(&from, Access::Read)?;
            let dst = fs.resolve(&to, Access::Write)?;
            let meta = fs.metadata(&src)?;
            let (files, dirs, bytes, skipped) = match meta.kind {
                Kind::Dir => {
                    let s = fs.copy_tree(&src, &dst)?;
                    (s.files, s.dirs, s.bytes, s.skipped)
                }
                Kind::File => {
                    ensure_parent(fs, &dst, false)?;
                    (1, 0, fs.copy_file(&src, &dst, replace)?, 0)
                }
                Kind::Symlink | Kind::Other => {
                    return Err(ToolError::invalid(format!(
                        "'{}' is a symbolic link or special file; only files and directories \
                         can be copied",
                        src.display()
                    )))
                }
            };
            Ok(ToolOutput::json(json!({
                "from": src.display(),
                "to": dst.display(),
                "files": files,
                "directories": dirs,
                "bytes": bytes,
                "skipped": skipped,
            })))
        })
        .await
}

async fn delete(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let recursive = a.bool_or("recursive", false)?;
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            if path.is_root() {
                return Err(ToolError::denied(format!(
                    "'{}' is an allowed directory itself and cannot be deleted",
                    path.display()
                )));
            }
            let meta = fs.metadata(&path)?;
            match meta.kind {
                Kind::Dir if recursive => fs.remove_dir_all(&path)?,
                Kind::Dir => fs.remove_dir(&path).map_err(|e| match e {
                    ToolError::Io(m) => ToolError::Execution(format!(
                        "{m}. A directory that is not empty needs recursive = true."
                    )),
                    other => other,
                })?,
                _ => fs.remove_file(&path)?,
            }
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "type": meta.kind.as_str(),
            })))
        })
        .await
}

fn compile_glob(pattern: &str) -> Result<globset::GlobMatcher> {
    globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| ToolError::invalid(format!("invalid glob pattern: {e}")))
}

fn rel_string(entry: &CheckedPath, base: &CheckedPath) -> String {
    let rel = entry
        .relative()
        .strip_prefix(base.relative())
        .unwrap_or(entry.relative());
    rel.to_string_lossy().replace('\\', "/")
}

/// Bytes of one file that a search reads; longer files are searched up to here.
const SEARCH_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Characters of a matching line that are shown.
const SEARCH_LINE_CHARS: usize = 300;

async fn search(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let root_in = a.str("root")?.to_string();
    let pattern = a.str("pattern")?;
    let regex = regex::RegexBuilder::new(pattern)
        .case_insensitive(a.bool_or("ignoreCase", false)?)
        .size_limit(4 * 1024 * 1024)
        .build()
        .map_err(|e| ToolError::invalid(format!("invalid regular expression: {e}")))?;
    let filter = a.opt_str("glob")?.map(compile_glob).transpose()?;
    let max_results = a.usize_or("maxResults", 200)?;
    let budget = ctx.max_output_bytes();
    ctx.fs()
        .blocking(move |fs| {
            let root = fs.resolve(&root_in, Access::Read)?;
            let mut out = String::new();
            let mut matches = 0usize;
            let mut files_with_matches = 0usize;
            let mut files_searched = 0usize;
            let mut stopped = false;
            let summary = fs.walk(&root, &WalkOptions::default(), |entry| {
                if entry.meta.kind != Kind::File {
                    return Ok(Flow::Continue);
                }
                let rel = rel_string(&entry.path, &root);
                if filter.as_ref().is_some_and(|g| !g.is_match(&rel)) {
                    return Ok(Flow::Continue);
                }
                let Ok(file) = fs.open(&entry.path) else {
                    return Ok(Flow::Continue);
                };
                files_searched += 1;
                let mut reader = BufReader::new(file.take(SEARCH_FILE_BYTES));
                let mut line = Vec::new();
                let mut number = 0usize;
                let mut hit = false;
                loop {
                    line.clear();
                    match reader.read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    number += 1;
                    if line.contains(&0) {
                        break; // binary file
                    }
                    let text = String::from_utf8_lossy(&line);
                    let text = text.trim_end_matches(['\n', '\r']);
                    if !regex.is_match(text) {
                        continue;
                    }
                    hit = true;
                    matches += 1;
                    out.push_str(&format!(
                        "{rel}:{number}: {}\n",
                        clip(text, SEARCH_LINE_CHARS)
                    ));
                    if matches >= max_results || out.len() >= budget {
                        stopped = true;
                        break;
                    }
                }
                files_with_matches += usize::from(hit);
                Ok(if stopped { Flow::Stop } else { Flow::Continue })
            })?;
            let mut tail = format!(
                "[fs_search: {matches} matching lines in {files_with_matches} of \
                 {files_searched} files searched under {}",
                root.display()
            );
            if summary.denied > 0 {
                tail.push_str(&format!(
                    "; {} entries skipped because policy protects them",
                    summary.denied
                ));
            }
            if stopped || summary.truncated {
                tail.push_str("; stopped at a limit, so there may be more. Narrow the search");
            }
            tail.push(']');
            let mut result = ToolOutput::text(out);
            result.content.push(Content::Text(tail));
            Ok(result)
        })
        .await
}

async fn glob(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let root_in = a.str("root")?.to_string();
    let matcher = compile_glob(a.str("pattern")?)?;
    let max_results = a.usize_or("maxResults", 1000)?;
    ctx.fs()
        .blocking(move |fs| {
            let root = fs.resolve(&root_in, Access::Read)?;
            let mut found: Vec<String> = Vec::new();
            let mut full = false;
            let summary = fs.walk(&root, &WalkOptions::default(), |entry| {
                let rel = rel_string(&entry.path, &root);
                if matcher.is_match(&rel) {
                    if found.len() >= max_results {
                        full = true;
                        return Ok(Flow::Stop);
                    }
                    found.push(rel);
                }
                Ok(Flow::Continue)
            })?;
            found.sort();
            Ok(ToolOutput::json(json!({
                "root": root.display(),
                "matches": found,
                "truncated": full || summary.truncated,
                "hidden": summary.denied,
            })))
        })
        .await
}

async fn tree(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let max_depth = a.usize_or("maxDepth", 3)?;
    let max_entries = a.usize_or("maxEntries", 1000)?;
    let budget = ctx.max_output_bytes();
    ctx.fs()
        .blocking(move |fs| {
            let root = fs.resolve(&input, Access::Read)?;
            let mut out = format!("{}\n", root.display());
            let mut shown = 0usize;
            let mut hidden = 0usize;
            let mut cut = false;
            list_tree(
                fs,
                &root,
                1,
                max_depth,
                &mut TreeState {
                    out: &mut out,
                    shown: &mut shown,
                    hidden: &mut hidden,
                    cut: &mut cut,
                    max_entries,
                    budget,
                },
            )?;
            let mut note = format!("[fs_tree: {shown} entries");
            if hidden > 0 {
                note.push_str(&format!(
                    "; {hidden} not shown because policy protects them"
                ));
            }
            if cut {
                note.push_str("; stopped at a limit, so the listing is incomplete");
            }
            note.push(']');
            let mut result = ToolOutput::text(out);
            result.content.push(Content::Text(note));
            Ok(result)
        })
        .await
}

struct TreeState<'a> {
    out: &'a mut String,
    shown: &'a mut usize,
    hidden: &'a mut usize,
    cut: &'a mut bool,
    max_entries: usize,
    budget: usize,
}

/// Depth-first listing; the recursion depth is bounded by `max_depth` (at
/// most 32 by the schema).
fn list_tree(
    fs: &Fs,
    dir: &CheckedPath,
    depth: usize,
    max_depth: usize,
    st: &mut TreeState<'_>,
) -> Result<()> {
    let (entries, denied) = match fs.read_dir(dir) {
        Ok(v) => v,
        Err(e) if depth == 1 => return Err(e),
        Err(_) => return Ok(()),
    };
    *st.hidden += denied;
    for entry in entries {
        if *st.shown >= st.max_entries || st.out.len() >= st.budget {
            *st.cut = true;
            return Ok(());
        }
        *st.shown += 1;
        let indent = "  ".repeat(depth);
        match entry.meta.kind {
            Kind::Dir => {
                st.out.push_str(&format!("{indent}{}/\n", entry.name));
                if depth < max_depth {
                    list_tree(fs, &entry.path, depth + 1, max_depth, st)?;
                    if *st.cut {
                        return Ok(());
                    }
                }
            }
            Kind::File => st.out.push_str(&format!(
                "{indent}{} ({} bytes)\n",
                entry.name, entry.meta.len
            )),
            Kind::Symlink => {
                let target = fs
                    .read_link(&entry.path)
                    .unwrap_or_else(|_| "?".to_string());
                st.out
                    .push_str(&format!("{indent}{} -> {target}\n", entry.name));
            }
            Kind::Other => st
                .out
                .push_str(&format!("{indent}{} (special file)\n", entry.name)),
        }
    }
    Ok(())
}

async fn hash(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let cancel = ctx.cancel().clone();
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Read)?;
            let mut file = fs.open(&path)?;
            let mut hasher = sha2::Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut size = 0u64;
            loop {
                if cancel.is_cancelled() {
                    return Err(ToolError::Cancelled);
                }
                let n = file
                    .read(&mut buf)
                    .map_err(|e| ToolError::from_io(&path.display(), &e))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                size += n as u64;
            }
            Ok(ToolOutput::json(json!({
                "path": path.display(),
                "sha256": hex::encode(hasher.finalize()),
                "size": size,
            })))
        })
        .await
}

async fn metadata(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Read)?;
            let meta = fs.metadata(&path)?;
            Ok(ToolOutput::json(metadata_json(&path, &meta)))
        })
        .await
}

async fn permissions(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let input = a.str("path")?.to_string();
    let mode = match a.opt_str("mode")? {
        None => None,
        Some(text) => Some(
            u32::from_str_radix(text, 8)
                .ok()
                .filter(|m| *m <= 0o7777)
                .ok_or_else(|| {
                    ToolError::invalid(format!(
                        "mode '{text}' is not an octal permission such as 644 or 0755"
                    ))
                })?,
        ),
    };
    let readonly = match a.opt_value("readonly") {
        None => None,
        Some(_) => Some(a.bool("readonly")?),
    };
    if mode.is_none() && readonly.is_none() {
        return Err(ToolError::invalid(
            "give mode or readonly; to only inspect permissions use fs_metadata",
        ));
    }
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Write)?;
            if let Some(mode) = mode {
                set_mode(fs, &path, mode)?;
            }
            if let Some(readonly) = readonly {
                fs.set_readonly(&path, readonly)?;
            }
            let meta = fs.metadata(&path)?;
            Ok(ToolOutput::json(metadata_json(&path, &meta)))
        })
        .await
}

#[cfg(unix)]
fn set_mode(fs: &Fs, path: &CheckedPath, mode: u32) -> Result<()> {
    fs.set_mode(path, mode)
}

#[cfg(not(unix))]
fn set_mode(_fs: &Fs, _path: &CheckedPath, _mode: u32) -> Result<()> {
    Err(ToolError::PlatformUnsupported(
        "Unix permission bits do not exist on this platform; use readonly instead".to_string(),
    ))
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod tests;
