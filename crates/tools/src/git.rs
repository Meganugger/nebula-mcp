//! Git tools.
//!
//! The server builds every argument vector itself. Caller strings never sit
//! where git would read an option: revisions are resolved to commit ids
//! first, paths are passed as literal pathspecs after `--`, and names are
//! refused when they start with `-`.
//!
//! Three further rules keep these tools inside the file policy:
//!
//! * A repository is used only when its git directory lies under a `.git`
//!   directory. File tools cannot write there, so a client cannot assemble a
//!   repository whose configuration or hooks git would then run.
//! * Paths that policy protects are left out of what is shown and of what is
//!   staged, and an operation that would rewrite one in the work tree is
//!   refused before git runs.
//! * Remotes are reached over https, ssh, http and git only, and their host
//!   is checked against the network policy first. Local-path remotes are
//!   refused: git would run the hooks of a directory the client can write.

use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::{CheckedPath, Kind};
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec, Output};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{
    Category, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::{json, Value};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::common::{clip, handler, spec, tool, SpecExt};

const GIT: &str = "git";
const PROGRAMS: Exec = Exec::Programs(&[GIT]);
const RO: Effects = Effects::read_only().exec(PROGRAMS);
const WRITE: Effects = Effects::writes().exec(PROGRAMS);
/// Tools that can replace files in the work tree.
const REWRITE: Effects = Effects::writes().overwrites().exec(PROGRAMS);

/// More protected paths than this in one listing and the call is refused
/// rather than passed to git as exclusions.
const MAX_EXCLUSIONS: usize = 500;

const REPO_HELP: &str =
    "Directory inside the repository's work tree (default: the server's working directory).";
const TIMEOUT_HELP: &str = "Seconds before git is stopped (default and ceiling set by the operator).";
const CONTROL: [&str; 3] = ["continue", "abort", "skip"];

fn schema() -> ObjectSchema {
    ObjectSchema::new().string("repo", REPO_HELP, false)
}

/// The `git` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Git;
    let net = |e: Effects| e.network();
    vec![
        tool(
            spec(
                "git_status",
                c,
                "Repository status",
                "Branch, upstream, ahead/behind counts and every changed or untracked path with \
                 its staged and unstaged state. Paths that policy protects are counted in \
                 `hidden`, not listed.",
                schema().build(),
                RO,
            )
            .returns(
                ObjectSchema::open()
                    .nullable_string("branch", "Current branch; null when HEAD is detached.", true)
                    .nullable_string("head", "Current commit; null before the first commit.", true)
                    .nullable_string("upstream", "Upstream branch, if one is set.", true)
                    .integer("ahead", "Commits not on the upstream.", true)
                    .integer("behind", "Upstream commits not here.", true)
                    .boolean("clean", "No changes and nothing untracked.", true)
                    .integer("hidden", "Changed paths not listed because policy protects them.", true)
                    .object_array(
                        "files",
                        "Changed and untracked paths.",
                        ObjectSchema::open()
                            .string("path", "Path relative to the repository.", true)
                            .string("staged", "State in the index.", true)
                            .string("unstaged", "State in the work tree.", true)
                            .string("from", "Previous path of a renamed file.", false),
                        true,
                    )
                    .build(),
            ),
            handler!(status),
        ),
        tool(
            spec(
                "git_diff",
                c,
                "Show changes",
                "Unified diff. With no arguments: unstaged changes. `staged`: what the next \
                 commit would contain. `from` alone: work tree against that commit. `from` and \
                 `to`: between two commits. Protected paths are left out.",
                schema()
                    .boolean("staged", "Compare the index with HEAD (or with `from`).", false)
                    .string("from", "Commit to compare from (branch, tag or id).", false)
                    .string("to", "Commit to compare to; needs `from`.", false)
                    .string("path", "Limit to this file or directory, relative to the repository.", false)
                    .boolean("stat", "Return the per-file summary instead of the diff.", false)
                    .build(),
                RO,
            ),
            handler!(diff),
        ),
        tool(
            spec(
                "git_log",
                c,
                "Commit history",
                "Commits, newest first, with author, date, parents and full message.",
                schema()
                    .integer_range("maxCount", "Commits to return (default 30).", 1, 500, false)
                    .integer_min("skip", "Commits to skip first, for paging.", 0, false)
                    .string(
                        "revRange",
                        "Revision or range, for example `main`, `v1.0..HEAD` (default HEAD).",
                        false,
                    )
                    .string("path", "Only commits that touch this file or directory.", false)
                    .build(),
                RO,
            )
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "commits",
                        "Commits, newest first.",
                        ObjectSchema::open()
                            .string("hash", "Commit id.", true)
                            .string("shortHash", "Abbreviated id.", true)
                            .string("author", "Author name.", true)
                            .string("email", "Author email.", true)
                            .string("date", "Author date, ISO 8601.", true)
                            .string_array("parents", "Parent commit ids.", true)
                            .string("message", "Full commit message.", true),
                        true,
                    )
                    .build(),
            ),
            handler!(log),
        ),
        tool(
            spec(
                "git_show",
                c,
                "Show commit or file",
                "A commit with its diff, or with `path` the content of one file as of that \
                 commit. Protected paths are left out or refused.",
                schema()
                    .string("object", "Commit to show: branch, tag or id (default HEAD).", false)
                    .string("path", "Return this file's content at the commit instead.", false)
                    .boolean("stat", "Return the per-file summary instead of the diff.", false)
                    .build(),
                RO,
            ),
            handler!(show),
        ),
        tool(
            spec(
                "git_blame",
                c,
                "Blame file",
                "The commit, author and date that last changed each line of a file.",
                schema()
                    .string("path", "File, relative to the repository.", true)
                    .string("ref", "Blame as of this commit (default: the work tree).", false)
                    .integer_min("startLine", "First line (1-based).", 1, false)
                    .integer_min("endLine", "Last line; needs startLine.", 1, false)
                    .build(),
                RO,
            ),
            handler!(blame),
        ),
        tool(
            spec(
                "git_reflog",
                c,
                "Reference log",
                "Where HEAD has been, newest first. Use it to find a commit to return to after a \
                 reset or rebase.",
                schema()
                    .integer_range("maxCount", "Entries to return (default 30).", 1, 500, false)
                    .build(),
                RO,
            ),
            handler!(reflog),
        ),
        tool(
            spec(
                "git_init",
                c,
                "Create repository",
                "Create an empty repository in a directory (created if missing). Safe to repeat. \
                 Follow with git_add and git_commit.",
                ObjectSchema::new()
                    .string("path", "Directory for the repository (default: the working directory).", false)
                    .string("initialBranch", "Name of the first branch (default: main).", false)
                    .build(),
                WRITE.idempotent(true),
            ),
            handler!(init),
        ),
        tool(
            spec(
                "git_clone",
                c,
                "Clone repository",
                "Clone a remote repository into a new directory. Remotes are https://, ssh:// (or \
                 user@host:path), http:// or git:// URLs; local paths are refused. Uses the \
                 operator's git credentials.",
                ObjectSchema::new()
                    .string("url", "Repository URL.", true)
                    .string("path", "Directory to create; it must not exist or must be empty.", true)
                    .string("branch", "Branch or tag to check out (default: the remote's default).", false)
                    .integer_min("depth", "Fetch only this many commits of history.", 1, false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                net(WRITE),
            ),
            handler!(clone),
        ),
        tool(
            spec(
                "git_add",
                c,
                "Stage changes",
                "Stage new, modified and deleted files for the next commit. `paths` are files or \
                 directories relative to the repository; `.` stages everything. Ignored files \
                 and paths that policy protects are skipped.",
                schema()
                    .string_array_max("paths", "Files or directories to stage.", 500, true)
                    .build(),
                WRITE.idempotent(true),
            )
            .returns(
                ObjectSchema::open()
                    .integer("staged", "Paths staged.", true)
                    .integer("skipped", "Paths not staged because policy protects them.", true)
                    .build(),
            ),
            handler!(add),
        ),
        tool(
            spec(
                "git_commit",
                c,
                "Commit",
                "Record the staged changes as a commit. `all` first stages every modified or \
                 deleted tracked file (new files need git_add). The repository's own hooks run.",
                schema()
                    .string("message", "Commit message: a summary line, a blank line, then details.", true)
                    .boolean("all", "Stage modified and deleted tracked files first.", false)
                    .boolean("allowEmpty", "Commit even when nothing changed.", false)
                    .string("authorName", "Author and committer name, when git has none configured.", false)
                    .string("authorEmail", "Author and committer email, when git has none configured.", false)
                    .build(),
                WRITE,
            )
            .returns(
                ObjectSchema::open()
                    .string("hash", "Id of the new commit.", true)
                    .string("subject", "Its summary line.", true)
                    .nullable_string("branch", "Branch that now points at it.", true)
                    .build(),
            ),
            handler!(commit),
        ),
        tool(
            spec(
                "git_branch",
                c,
                "Branches",
                "List, create, rename or delete branches. Deleting is destructive. Creating does \
                 not switch to the branch: use git_checkout.",
                schema()
                    .string_enum("mode", "What to do (default list).", &["list", "create", "delete", "rename"], false)
                    .string("name", "Branch to create, delete or rename.", false)
                    .string("newName", "New name, for rename.", false)
                    .string("startPoint", "Commit the new branch starts at (default HEAD).", false)
                    .boolean("force", "Delete a branch that is not merged, or move an existing one.", false)
                    .boolean("remotes", "Include remote-tracking branches in the list.", false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(branch),
        ),
        tool(
            spec(
                "git_checkout",
                c,
                "Switch branch",
                "Switch the work tree to a branch, tag or commit, or with `create` start a new \
                 branch and switch to it. Uncommitted changes are kept, or git refuses.",
                schema()
                    .string("ref", "Branch, tag or commit to switch to; with `create`, the new branch name.", true)
                    .boolean("create", "Create the branch `ref` first.", false)
                    .string("startPoint", "With `create`: commit the branch starts at (default HEAD).", false)
                    .build(),
                REWRITE,
            ),
            handler!(checkout),
        ),
        tool(
            spec(
                "git_merge",
                c,
                "Merge",
                "Merge a branch or commit into the current branch. On conflicts the error lists \
                 them: edit the files, git_add them and git_commit, or call again with `abort`.",
                schema()
                    .string("ref", "Branch, tag or commit to merge.", false)
                    .boolean("abort", "Abandon the merge in progress instead.", false)
                    .build(),
                REWRITE,
            ),
            handler!(merge),
        ),
        tool(
            spec(
                "git_rebase",
                c,
                "Rebase",
                "Replay the current branch's commits onto another commit. On conflicts: edit, \
                 git_add, then call with control `continue`; `skip` drops the commit being \
                 replayed; `abort` returns to the start.",
                schema()
                    .string("ref", "Commit to rebase onto.", false)
                    .string_enum("control", "Act on the rebase in progress instead.", &CONTROL, false)
                    .build(),
                REWRITE,
            ),
            handler!(rebase),
        ),
        tool(
            spec(
                "git_cherry_pick",
                c,
                "Cherry-pick",
                "Apply the change one commit made as a new commit on the current branch.",
                schema()
                    .string("commit", "Commit to apply.", false)
                    .string_enum("control", "Act on the cherry-pick in progress instead.", &CONTROL, false)
                    .build(),
                REWRITE,
            ),
            handler!(cherry_pick),
        ),
        tool(
            spec(
                "git_revert",
                c,
                "Revert commit",
                "Add a new commit that undoes the change one commit made.",
                schema()
                    .string("commit", "Commit to undo.", false)
                    .string_enum("control", "Act on the revert in progress instead.", &CONTROL, false)
                    .build(),
                REWRITE,
            ),
            handler!(revert),
        ),
        tool(
            spec(
                "git_reset",
                c,
                "Reset",
                "Move the current branch to a commit. `soft` keeps index and files, `mixed` \
                 (default) keeps files and unstages, `hard` also discards uncommitted changes \
                 and is destructive. With `paths`, only unstage those paths.",
                schema()
                    .string_enum("mode", "How much to reset (default mixed).", &["soft", "mixed", "hard"], false)
                    .string("ref", "Commit to reset to (default HEAD).", false)
                    .string_array_max("paths", "Unstage only these paths; files are untouched.", 500, false)
                    .build(),
                REWRITE.destructive(Gate::Sometimes),
            ),
            handler!(reset),
        ),
        tool(
            spec(
                "git_stash",
                c,
                "Stash",
                "Put uncommitted changes aside and bring them back. `push` saves and cleans the \
                 work tree, `pop` restores and removes the entry, `apply` restores and keeps it, \
                 `show` prints its diff, `drop` deletes it (destructive).",
                schema()
                    .string_enum("mode", "What to do (default push).", &["push", "pop", "apply", "list", "show", "drop"], false)
                    .string("message", "Label for a pushed stash.", false)
                    .boolean("includeUntracked", "With push: also stash untracked files.", false)
                    .integer_range("index", "Stash entry, 0 is the newest (default 0).", 0, 10_000, false)
                    .build(),
                REWRITE.destructive(Gate::Sometimes),
            ),
            handler!(stash),
        ),
        tool(
            spec(
                "git_tag",
                c,
                "Tags",
                "List, create or delete tags. A `message` makes an annotated tag. Deleting is \
                 destructive. Publish a tag with git_push.",
                schema()
                    .string_enum("mode", "What to do (default list).", &["list", "create", "delete"], false)
                    .string("name", "Tag to create or delete.", false)
                    .string("ref", "Commit to tag (default HEAD).", false)
                    .string("message", "Annotation; makes the tag an annotated one.", false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(tag),
        ),
        tool(
            spec(
                "git_clean",
                c,
                "Remove untracked files",
                "Delete files git does not track. Destructive unless `dryRun`, which only lists \
                 them. Protected paths are never removed. Ignored files are kept unless \
                 `includeIgnored`.",
                schema()
                    .boolean("dryRun", "List what would be removed without removing it.", false)
                    .boolean("includeIgnored", "Also remove files matched by .gitignore.", false)
                    .string("path", "Limit to this directory.", false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            )
            .returns(
                ObjectSchema::open()
                    .string_array("paths", "Files removed (or that would be), at most 500.", true)
                    .integer("count", "Number of files removed (or that would be).", true)
                    .integer("skipped", "Files kept because policy protects them.", true)
                    .boolean("dryRun", "Whether nothing was actually removed.", true)
                    .build(),
            ),
            handler!(clean),
        ),
        tool(
            spec(
                "git_apply",
                c,
                "Apply patch",
                "Apply a unified diff to the work tree. `check` only tests whether it applies. A \
                 patch that deletes files is destructive; one that touches a protected path is \
                 refused.",
                schema()
                    .string("patch", "The patch text, as produced by git_diff.", true)
                    .boolean("check", "Test only; change nothing.", false)
                    .build(),
                REWRITE.destructive(Gate::Sometimes),
            ),
            handler!(apply),
        ),
        tool(
            spec(
                "git_bisect",
                c,
                "Bisect",
                "Binary-search history for the commit that introduced a problem. `start`, then \
                 mark `bad` and `good` commits; each answer names the next commit to test. The \
                 work tree is not changed: check that commit out with git_checkout. `reset` ends.",
                schema()
                    .string_enum("action", "Step to take.", &["start", "good", "bad", "skip", "reset", "log"], true)
                    .string("rev", "Commit the mark applies to (default: the commit being tested).", false)
                    .build(),
                WRITE,
            ),
            handler!(bisect),
        ),
        tool(
            spec(
                "git_remote",
                c,
                "Remotes",
                "List, add, re-point or remove remotes. URLs must be https://, ssh:// (or \
                 user@host:path), http:// or git://. Removing is destructive. Credentials in \
                 URLs are not shown.",
                schema()
                    .string_enum("action", "What to do (default list).", &["list", "add", "set_url", "remove"], false)
                    .string("name", "Remote name, for example origin.", false)
                    .string("url", "Remote URL, for add and set_url.", false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(remote),
        ),
        tool(
            spec(
                "git_fetch",
                c,
                "Fetch",
                "Download commits and branches from a remote without changing the work tree.",
                schema()
                    .string("remote", "Remote to fetch (default origin).", false)
                    .boolean("all", "Fetch every remote.", false)
                    .boolean("prune", "Drop remote-tracking branches that no longer exist.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                net(WRITE),
            ),
            handler!(fetch),
        ),
        tool(
            spec(
                "git_pull",
                c,
                "Pull",
                "Fetch from a remote and merge (or with `rebase`, rebase onto) its branch. \
                 Without `branch` the current branch's upstream is used.",
                schema()
                    .string("remote", "Remote to pull from (default origin).", false)
                    .string("branch", "Remote branch to integrate.", false)
                    .boolean("rebase", "Rebase local commits instead of merging.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                net(REWRITE),
            ),
            handler!(pull),
        ),
        tool(
            spec(
                "git_push",
                c,
                "Push",
                "Upload a branch (default: the current one) or a tag to a remote, with the \
                 operator's git credentials. `force` overwrites the remote branch if it has not \
                 moved since the last fetch, and is destructive.",
                schema()
                    .string("remote", "Remote to push to (default origin).", false)
                    .string("branch", "Branch to push (default: the current branch).", false)
                    .string("tag", "Push this tag instead of a branch.", false)
                    .boolean("setUpstream", "Make the remote branch the upstream of the local one.", false)
                    .boolean("force", "Overwrite the remote branch (force-with-lease).", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                net(WRITE).destructive(Gate::Sometimes),
            ),
            handler!(push),
        ),
        tool(
            spec(
                "git_submodule",
                c,
                "Submodules",
                "Show the repository's submodules, and with `update` fetch and check out the \
                 ones that are not initialised yet. Submodules that are already checked out are \
                 not moved: work in them with the other git tools.",
                schema()
                    .boolean("update", "Initialise and fetch missing submodules.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                net(WRITE),
            ),
            handler!(submodule),
        ),
        tool(
            spec(
                "git_worktree",
                c,
                "Worktrees",
                "List, add, remove or prune additional work trees of the repository. `add` \
                 checks out `ref` (or a new `branch`) in a new directory. `remove` deletes a \
                 clean work tree and is destructive.",
                schema()
                    .string_enum("action", "What to do (default list).", &["list", "add", "remove", "prune"], false)
                    .string("path", "Directory of the work tree, for add and remove.", false)
                    .string("ref", "Commit to check out in the new work tree (default HEAD).", false)
                    .string("branch", "Create this branch for the new work tree.", false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(worktree),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Repository access
// ---------------------------------------------------------------------------

enum Held {
    Shared(#[allow(dead_code)] OwnedRwLockReadGuard<()>),
    Exclusive(#[allow(dead_code)] OwnedRwLockWriteGuard<()>),
}

/// A work tree that passed the checks, locked for the length of the call so
/// that what was checked is what git then acts on.
struct Repo {
    top: CheckedPath,
    top_abs: PathBuf,
    _held: Held,
}

fn lock_for(key: &str) -> Arc<RwLock<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<RwLock<()>>>>> = OnceLock::new();
    let mut map = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    map.entry(key.to_string()).or_default().clone()
}

/// git with the settings every invocation gets.
fn base() -> Command {
    Command::typed(GIT)
        .args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.http.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-c",
            "protocol.git.allow=always",
            "-c",
            "safe.bareRepository=explicit",
            "-c",
            "http.followRedirects=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "core.quotePath=false",
            "-c",
            "color.ui=false",
            "-c",
            "advice.detachedHead=false",
            "--no-pager",
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_EDITOR", "true")
        .env("GIT_SEQUENCE_EDITOR", "true")
        .env("GIT_PAGER", "cat")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .pass_env("SSH_AUTH_SOCK")
}

fn git(repo: &Repo) -> Command {
    base().cwd(&repo.top)
}

async fn dir_path(ctx: &ToolContext, input: &str, access: Access) -> Result<CheckedPath> {
    let input = input.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let dir = fs.resolve(&input, access)?;
            match fs.try_metadata(&dir)? {
                Some(meta) if meta.kind != Kind::Dir => Err(ToolError::invalid(format!(
                    "'{}' is not a directory",
                    dir.display()
                ))),
                Some(_) => Ok(dir),
                None => Err(ToolError::NotFound(format!(
                    "directory '{}' does not exist",
                    dir.display()
                ))),
            }
        })
        .await
}

fn has_git_component(path: &str) -> bool {
    Path::new(path).components().any(|c| match c {
        Component::Normal(name) => name.to_string_lossy().eq_ignore_ascii_case(".git"),
        _ => false,
    })
}

/// Find and check the repository around `repo`, and lock it.
async fn open(ctx: &ToolContext, a: &Args<'_>, exclusive: bool) -> Result<Repo> {
    let dir = dir_path(ctx, a.str_or("repo", ".")?, Access::Read).await?;
    let out = run(
        ctx,
        base().cwd(&dir).args([
            "rev-parse",
            "--is-bare-repository",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-toplevel",
        ]),
    )
    .await?;
    let lines: Vec<&str> = out.stdout.text.lines().collect();
    let unsupported = || {
        ToolError::denied(
            "this directory is a bare repository or a repository whose git directory is not \
             named .git; the git tools only work in ordinary work trees",
        )
    };
    if lines.first() == Some(&"true") {
        return Err(unsupported());
    }
    if !out.success() || lines.len() < 4 {
        return Err(ToolError::NotFound(format!(
            "'{}' is not inside a git work tree. Create a repository with git_init or pass \
             `repo`.",
            dir.display()
        )));
    }
    let base_dir = PathBuf::from(dir.display());
    let absolute = |text: &str| {
        let p = Path::new(text);
        if p.is_absolute() {
            text.to_string()
        } else {
            base_dir.join(p).to_string_lossy().into_owned()
        }
    };
    let (git_dir, common_dir, top) = (absolute(lines[1]), absolute(lines[2]), lines[3].to_string());
    let (top, key) = ctx
        .fs()
        .blocking(move |fs| {
            // Everything git will read or write must be inside the roots.
            let git_dir = fs.resolve(&git_dir, Access::Read)?;
            let common = fs.resolve(&common_dir, Access::Read)?;
            let top = fs.resolve(&top, Access::Read)?;
            Ok((top, (git_dir.display(), common.display())))
        })
        .await?;
    if !has_git_component(&key.0) || !has_git_component(&key.1) {
        return Err(unsupported());
    }
    let lock = lock_for(&key.1);
    let held = if exclusive {
        Held::Exclusive(lock.write_owned().await)
    } else {
        Held::Shared(lock.read_owned().await)
    };
    let top_abs = PathBuf::from(top.display());
    Ok(Repo {
        top,
        top_abs,
        _held: held,
    })
}

// ---------------------------------------------------------------------------
// Running git
// ---------------------------------------------------------------------------

async fn run(ctx: &ToolContext, cmd: Command) -> Result<Output> {
    ctx.run(cmd.timeout(ctx.timeout(None))).await
}

fn failure(what: &str, out: &Output) -> ToolError {
    ToolError::Execution(failure_text(what, out))
}

fn failure_text(what: &str, out: &Output) -> String {
    let mut detail = String::new();
    for stream in [&out.stdout.text, &out.stderr.text] {
        let text = stream.trim();
        if !text.is_empty() {
            if !detail.is_empty() {
                detail.push('\n');
            }
            detail.push_str(text);
        }
    }
    let code = out
        .code
        .map_or_else(|| "a signal".to_string(), |c| format!("code {c}"));
    format!("{what} exited with {code}: {}", clip(&detail, 4000))
}

/// Run and require exit code 0.
async fn ok(ctx: &ToolContext, cmd: Command, what: &str) -> Result<Output> {
    let out = run(ctx, cmd).await?;
    if out.success() {
        Ok(out)
    } else {
        Err(failure(what, &out))
    }
}

/// Run a command that prints NUL-separated paths.
async fn names(ctx: &ToolContext, cmd: Command) -> Result<Vec<String>> {
    let out = ok(ctx, cmd, "listing the affected paths").await?;
    if out.stdout.truncated {
        return Err(ToolError::LimitExceeded(
            "too many paths are affected to check them against policy; narrow the operation to \
             a directory or a smaller change"
                .to_string(),
        ));
    }
    Ok(out
        .stdout
        .text
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Both streams as one text result.
fn done(tool: &str, out: &Output) -> ToolOutput {
    let mut text = String::new();
    for stream in [&out.stdout.text, &out.stderr.text] {
        let part = stream.trim_end();
        if !part.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(part);
        }
    }
    if text.is_empty() {
        text = format!("[{tool}: done]");
    }
    ToolOutput::text(text)
}

/// Content exactly as git printed it, then a bracketed note.
fn content(tool: &str, out: &Output, hidden: usize) -> ToolOutput {
    let mut blocks = Vec::new();
    let mut notes = Vec::new();
    if out.stdout.text.is_empty() {
        notes.push("nothing to show".to_string());
    } else {
        blocks.push(Content::Text(out.stdout.text.clone()));
    }
    if out.stdout.truncated {
        notes.push(format!(
            "the output was {} bytes and its middle was omitted; narrow the request with `path`",
            out.stdout.total_bytes
        ));
    }
    if hidden > 0 {
        notes.push(format!(
            "{hidden} path(s) not shown because policy protects them"
        ));
    }
    if !notes.is_empty() {
        blocks.push(Content::Text(format!("[{tool}: {}]", notes.join("; "))));
    }
    ToolOutput {
        content: blocks,
        structured: None,
    }
}

// ---------------------------------------------------------------------------
// Argument checks
// ---------------------------------------------------------------------------

/// A revision expression: it may not look like an option.
fn check_rev(rev: &str) -> Result<()> {
    if rev.is_empty()
        || rev.len() > 255
        || rev.starts_with('-')
        || rev.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ToolError::invalid(format!(
            "'{}' is not a revision: use a branch, tag or commit id without spaces, not starting \
             with '-'",
            clip(rev, 60)
        )));
    }
    Ok(())
}

/// A branch, tag or remote name.
fn check_name(name: &str) -> Result<()> {
    check_rev(name)?;
    if name.contains(['~', '^', ':', '?', '*', '[', '\\', '+'])
        || name.contains("..")
        || name.contains("@{")
        || name.ends_with('/')
        || name.ends_with(".lock")
    {
        return Err(ToolError::invalid(format!(
            "'{name}' is not a valid name: avoid ~ ^ : ? * [ \\ + and '..'"
        )));
    }
    Ok(())
}

/// Resolve a revision to a commit id, so that what reaches git is hex.
async fn commit_id(ctx: &ToolContext, repo: &Repo, rev: &str) -> Result<String> {
    check_rev(rev)?;
    let out = run(
        ctx,
        git(repo)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{rev}^{{commit}}")),
    )
    .await?;
    let id = out.stdout.text.trim();
    if !out.success() || id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ToolError::NotFound(format!(
            "'{rev}' does not name a commit in this repository"
        )));
    }
    Ok(id.to_string())
}

/// HEAD's commit, or `None` before the first commit.
async fn head(ctx: &ToolContext, repo: &Repo) -> Result<Option<String>> {
    match commit_id(ctx, repo, "HEAD").await {
        Ok(id) => Ok(Some(id)),
        Err(ToolError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A caller path as a path relative to the top of the work tree.
fn rel_path(repo: &Repo, input: &str) -> Result<String> {
    if input.is_empty() || input.contains('\0') {
        return Err(ToolError::invalid("a path must not be empty"));
    }
    let path = Path::new(input);
    let rel = if path.is_absolute() {
        path.strip_prefix(&repo.top_abs).map_err(|_| {
            ToolError::invalid(format!(
                "'{input}' is outside the repository; use a path relative to it"
            ))
        })?
    } else {
        path
    };
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(ToolError::invalid(format!(
                        "'{input}' is outside the repository"
                    )));
                }
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case(".git") {
                    return Err(ToolError::denied(format!(
                        "'{input}' is inside the git directory"
                    )));
                }
                parts.push(name.into_owned());
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(ToolError::invalid(format!(
                    "'{input}' is outside the repository"
                )));
            }
        }
    }
    Ok(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}

/// A repository-relative path as a pathspec git takes literally.
fn literal(rel: &str) -> String {
    if rel == "." {
        ".".to_string()
    } else {
        format!(":(literal){rel}")
    }
}

/// Why policy protects a repository-relative path, if it does.
fn protected(ctx: &ToolContext, repo: &Repo, rel: &str, access: Access) -> Option<&'static str> {
    ctx.policy()
        .paths()
        .denied(&repo.top_abs.join(rel), access)
}

fn require_readable(ctx: &ToolContext, repo: &Repo, rel: &str) -> Result<()> {
    match protected(ctx, repo, rel, Access::Read) {
        Some(reason) if rel != "." => Err(ToolError::denied(format!(
            "'{rel}' is not accessible: {reason}"
        ))),
        _ => Ok(()),
    }
}

/// Pathspecs that leave unreadable paths out of a listing, and their count.
fn exclusions(ctx: &ToolContext, repo: &Repo, listed: &[String]) -> Result<(Vec<String>, usize)> {
    let hidden: BTreeSet<&String> = listed
        .iter()
        .filter(|p| protected(ctx, repo, p, Access::Read).is_some())
        .collect();
    if hidden.len() > MAX_EXCLUSIONS {
        return Err(ToolError::LimitExceeded(format!(
            "{} of the affected paths are protected by policy; narrow the request with `path`",
            hidden.len()
        )));
    }
    Ok((
        hidden
            .iter()
            .map(|p| format!(":(exclude,literal){p}"))
            .collect(),
        hidden.len(),
    ))
}

/// Refuse an operation that would rewrite or remove protected paths.
fn guard(ctx: &ToolContext, repo: &Repo, affected: &[String], operation: &str) -> Result<()> {
    let mut hidden = 0usize;
    let mut read_only: Vec<&str> = Vec::new();
    for path in affected {
        if protected(ctx, repo, path, Access::Read).is_some() {
            hidden += 1;
        } else if protected(ctx, repo, path, Access::Write).is_some() {
            read_only.push(path);
        }
    }
    if hidden == 0 && read_only.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "{operation} would change {} path(s) that policy protects",
        hidden + read_only.len()
    );
    if !read_only.is_empty() {
        read_only.truncate(5);
        message.push_str(&format!(" (read-only: {})", read_only.join(", ")));
    }
    message.push_str(". Nothing was changed.");
    Err(ToolError::denied(message))
}

/// Paths that differ between two commits.
async fn changed_between(ctx: &ToolContext, repo: &Repo, from: &str, to: &str) -> Result<Vec<String>> {
    names(
        ctx,
        git(repo).args(["diff", "--name-only", "--no-renames", "-z", from, to, "--"]),
    )
    .await
}

/// Refuse moving the work tree from HEAD to `target` over protected paths.
async fn guard_move(ctx: &ToolContext, repo: &Repo, target: &str, operation: &str) -> Result<()> {
    if let Some(head) = head(ctx, repo).await? {
        let affected = changed_between(ctx, repo, &head, target).await?;
        guard(ctx, repo, &affected, operation)?;
    }
    Ok(())
}

/// Where a remote URL connects, or why it is not accepted.
fn endpoint(url: &str) -> Result<(String, u16)> {
    let bad = |why: &str| {
        ToolError::invalid(format!(
            "remote URL not accepted: {why}. Use https://, ssh:// (or user@host:path), http:// \
             or git://."
        ))
    };
    if url.is_empty()
        || url.starts_with('-')
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(bad("it is empty, starts with '-' or contains spaces"));
    }
    let local = "local paths and file:// URLs are refused, because git would run the hooks of a \
                 directory the client can write";
    let (host, port) = if let Some((scheme, rest)) = url.split_once("://") {
        let default_port = match scheme.to_ascii_lowercase().as_str() {
            "https" => 443,
            "http" => 80,
            "ssh" => 22,
            "git" => 9418,
            "file" => return Err(bad(local)),
            _ => return Err(bad("the scheme is not one of the allowed ones")),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = if let Some(inner) = host_port.strip_prefix('[') {
            let (host, tail) = inner
                .split_once(']')
                .ok_or_else(|| bad("the IPv6 address is not closed"))?;
            (host, tail.strip_prefix(':'))
        } else {
            match host_port.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_port, None),
            }
        };
        let port = match port {
            None | Some("") => default_port,
            Some(p) => p.parse().map_err(|_| bad("the port is not a number"))?,
        };
        (host, port)
    } else {
        let Some((left, path)) = url.split_once(':') else {
            return Err(bad(local));
        };
        if path.starts_with(':') {
            return Err(bad("transport helpers (name::address) are refused"));
        }
        if left.len() <= 1 || left.contains(['/', '\\']) {
            return Err(bad(local));
        }
        (left.rsplit_once('@').map_or(left, |(_, h)| h), 22)
    };
    if host.is_empty() || host.starts_with('-') {
        return Err(bad("it has no host"));
    }
    Ok((host.to_string(), port))
}

/// Hide credentials embedded in a URL.
fn redact(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if let Some(at) = rest[..end].rfind('@') {
            return format!("{scheme}://***@{}", &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Check a remote URL against the network policy.
async fn vet(ctx: &ToolContext, url: &str) -> Result<()> {
    let (host, port) = endpoint(url)?;
    ctx.net()?.vet(&host, port).await?;
    Ok(())
}

/// The URL of a configured remote.
async fn remote_url(ctx: &ToolContext, repo: &Repo, remote: &str, push: bool) -> Result<String> {
    check_name(remote)?;
    let mut cmd = git(repo).args(["remote", "get-url"]);
    if push {
        cmd = cmd.arg("--push");
    }
    let out = run(ctx, cmd.arg(remote)).await?;
    let url = out.stdout.text.trim();
    if !out.success() || url.is_empty() {
        return Err(ToolError::NotFound(format!(
            "there is no remote named '{remote}'; add one with git_remote"
        )));
    }
    Ok(url.to_string())
}

async fn remote_names(ctx: &ToolContext, repo: &Repo) -> Result<Vec<String>> {
    let out = ok(ctx, git(repo).arg("remote"), "git remote").await?;
    Ok(out
        .stdout
        .text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

fn net_timeout(ctx: &ToolContext, a: &Args<'_>, cmd: Command) -> Result<Command> {
    Ok(cmd.timeout(ctx.timeout(a.opt_u64("timeoutSecs")?)))
}

// ---------------------------------------------------------------------------
// Read-only tools
// ---------------------------------------------------------------------------

fn state_word(c: char) -> &'static str {
    match c {
        '.' => "unchanged",
        'M' => "modified",
        'T' => "type_changed",
        'A' => "added",
        'D' => "deleted",
        'R' => "renamed",
        'C' => "copied",
        'U' => "unmerged",
        _ => "unknown",
    }
}

async fn status(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let out = ok(
        ctx,
        git(&repo).args(["status", "--porcelain=v2", "--branch", "-z"]),
        "git status",
    )
    .await?;
    if out.stdout.truncated {
        return Err(ToolError::LimitExceeded(
            "too many changed paths to report; commit or clean up in smaller steps".to_string(),
        ));
    }
    let (mut branch, mut head_id, mut upstream) = (Value::Null, Value::Null, Value::Null);
    let (mut ahead, mut behind, mut hidden) = (0i64, 0i64, 0usize);
    let mut files = Vec::new();
    let mut tokens = out.stdout.text.split('\0');
    while let Some(token) = tokens.next() {
        if let Some(v) = token.strip_prefix("# branch.oid ") {
            if v != "(initial)" {
                head_id = json!(v);
            }
        } else if let Some(v) = token.strip_prefix("# branch.head ") {
            if v != "(detached)" {
                branch = json!(v);
            }
        } else if let Some(v) = token.strip_prefix("# branch.upstream ") {
            upstream = json!(v);
        } else if let Some(v) = token.strip_prefix("# branch.ab ") {
            let mut parts = v.split(' ');
            ahead = parts
                .next()
                .and_then(|p| p.trim_start_matches('+').parse().ok())
                .unwrap_or(0);
            behind = parts
                .next()
                .and_then(|p| p.trim_start_matches('-').parse().ok())
                .unwrap_or(0);
        } else {
            let (kind, rest) = token.split_at(token.len().min(2));
            let entry = match kind {
                "1 " => rest.splitn(8, ' ').collect::<Vec<_>>(),
                "2 " => rest.splitn(9, ' ').collect(),
                "u " => rest.splitn(10, ' ').collect(),
                "? " => vec!["??", rest],
                _ => continue,
            };
            let (Some(xy), Some(path)) = (entry.first(), entry.last()) else {
                continue;
            };
            let from = if kind == "2 " { tokens.next() } else { None };
            let unreadable = |p: &str| protected(ctx, &repo, p.trim_end_matches('/'), Access::Read);
            if unreadable(path).is_some() || from.is_some_and(|f| unreadable(f).is_some()) {
                hidden += 1;
                continue;
            }
            let mut chars = xy.chars();
            let (staged, unstaged) = match kind {
                "? " => ("unchanged", "untracked"),
                "u " => ("unmerged", "unmerged"),
                _ => (
                    state_word(chars.next().unwrap_or('.')),
                    state_word(chars.next().unwrap_or('.')),
                ),
            };
            let mut file = json!({"path": path, "staged": staged, "unstaged": unstaged});
            if let Some(from) = from {
                file["from"] = json!(from);
            }
            files.push(file);
        }
    }
    Ok(ToolOutput::json(json!({
        "branch": branch,
        "head": head_id,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "clean": files.is_empty() && hidden == 0,
        "hidden": hidden,
        "files": files,
    })))
}

async fn diff(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let staged = a.bool_or("staged", false)?;
    let (from, to) = (a.opt_str("from")?, a.opt_str("to")?);
    if to.is_some() && from.is_none() {
        return Err(ToolError::invalid("`to` needs `from`"));
    }
    if staged && to.is_some() {
        return Err(ToolError::invalid(
            "`staged` compares the index with one commit; drop `to`",
        ));
    }
    let mut revs = Vec::new();
    for rev in [from, to].into_iter().flatten() {
        revs.push(commit_id(ctx, &repo, rev).await?);
    }
    let path = match a.opt_str("path")? {
        Some(p) => rel_path(&repo, p)?,
        None => ".".to_string(),
    };
    require_readable(ctx, &repo, &path)?;
    let build = |flags: &[&str]| {
        let mut cmd = git(&repo).args(["diff", "--no-ext-diff", "--no-textconv"]);
        if staged {
            cmd = cmd.arg("--cached");
        }
        cmd.args(flags.iter().copied())
            .args(revs.iter().cloned())
            .arg("--")
            .arg(literal(&path))
    };
    let listed = names(ctx, build(&["--name-only", "--no-renames", "-z"])).await?;
    let (excluded, hidden) = exclusions(ctx, &repo, &listed)?;
    let flags: &[&str] = if a.bool_or("stat", false)? {
        &["--stat"]
    } else {
        &[]
    };
    let out = ok(ctx, build(flags).args(excluded), "git diff").await?;
    Ok(content("git_diff", &out, hidden))
}

async fn log(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let mut cmd = git(&repo).args([
        "log".to_string(),
        format!("--max-count={}", a.u64_or("maxCount", 30)?.min(500)),
        format!("--skip={}", a.u64_or("skip", 0)?),
        "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%P%x1f%B%x1e".to_string(),
    ]);
    if let Some(range) = a.opt_str("revRange")? {
        check_rev(range)?;
        cmd = cmd.arg(range);
    }
    cmd = cmd.arg("--");
    if let Some(p) = a.opt_str("path")? {
        let path = rel_path(&repo, p)?;
        require_readable(ctx, &repo, &path)?;
        cmd = cmd.arg(literal(&path));
    }
    let out = run(ctx, cmd).await?;
    if !out.success() {
        if out.stderr.text.contains("does not have any commits yet") {
            return Ok(ToolOutput::json(json!({"commits": []})));
        }
        return Err(failure("git log", &out));
    }
    let commits: Vec<Value> = out
        .stdout
        .text
        .split('\x1e')
        .filter_map(|record| {
            let fields: Vec<&str> = record.trim_start_matches('\n').splitn(7, '\x1f').collect();
            (fields.len() == 7).then(|| {
                json!({
                    "hash": fields[0],
                    "shortHash": fields[1],
                    "author": fields[2],
                    "email": fields[3],
                    "date": fields[4],
                    "parents": fields[5].split_whitespace().collect::<Vec<_>>(),
                    "message": fields[6].trim_end(),
                })
            })
        })
        .collect();
    Ok(ToolOutput::json(json!({"commits": commits})))
}

async fn show(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let id = commit_id(ctx, &repo, a.str_or("object", "HEAD")?).await?;
    if let Some(p) = a.opt_str("path")? {
        let path = rel_path(&repo, p)?;
        if path == "." {
            return Err(ToolError::invalid("`path` must name a file"));
        }
        require_readable(ctx, &repo, &path)?;
        let object = format!("{id}:{path}");
        let kind = run(ctx, git(&repo).args(["cat-file", "-t"]).arg(&object)).await?;
        if kind.stdout.text.trim() != "blob" {
            return Err(ToolError::NotFound(format!(
                "'{path}' is not a file in that commit"
            )));
        }
        let out = ok(
            ctx,
            git(&repo).args(["cat-file", "blob"]).arg(&object),
            "git show",
        )
        .await?;
        return Ok(content("git_show", &out, 0));
    }
    let listed = names(
        ctx,
        git(&repo)
            .args(["show", "--format=", "--name-only", "--no-renames", "-z"])
            .arg(&id),
    )
    .await?;
    let (excluded, hidden) = exclusions(ctx, &repo, &listed)?;
    let mut cmd = git(&repo).args(["show", "--no-ext-diff", "--no-textconv", "--format=fuller"]);
    if a.bool_or("stat", false)? {
        cmd = cmd.arg("--stat");
    }
    let out = ok(ctx, cmd.arg(&id).args(["--", "."]).args(excluded), "git show").await?;
    Ok(content("git_show", &out, hidden))
}

async fn blame(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let path = rel_path(&repo, a.str("path")?)?;
    require_readable(ctx, &repo, &path)?;
    let mut cmd = git(&repo).args(["blame", "--date=short"]);
    match (a.opt_u64("startLine")?, a.opt_u64("endLine")?) {
        (Some(start), Some(end)) => cmd = cmd.arg(format!("-L{start},{end}")),
        (Some(start), None) => cmd = cmd.arg(format!("-L{start},")),
        (None, Some(_)) => return Err(ToolError::invalid("`endLine` needs `startLine`")),
        (None, None) => {}
    }
    if let Some(rev) = a.opt_str("ref")? {
        cmd = cmd.arg(commit_id(ctx, &repo, rev).await?);
    }
    let out = ok(ctx, cmd.arg("--").arg(&path), "git blame").await?;
    Ok(content("git_blame", &out, 0))
}

async fn reflog(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, false).await?;
    let out = run(
        ctx,
        git(&repo).args([
            "reflog".to_string(),
            "show".to_string(),
            format!("--max-count={}", a.u64_or("maxCount", 30)?.min(500)),
            "--format=%h %gd %gs".to_string(),
        ]),
    )
    .await?;
    if !out.success() && head(ctx, &repo).await?.is_some() {
        return Err(failure("git reflog", &out));
    }
    Ok(content("git_reflog", &out, 0))
}

// ---------------------------------------------------------------------------
// Creating and recording
// ---------------------------------------------------------------------------

async fn init(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let branch = a.str_or("initialBranch", "main")?;
    check_name(branch)?;
    let input = a.str_or("path", ".")?.to_string();
    let dir = ctx
        .fs()
        .blocking(move |fs| {
            let dir = fs.resolve(&input, Access::Write)?;
            fs.create_dir_all(&dir)?;
            Ok(dir)
        })
        .await?;
    let out = ok(
        ctx,
        base()
            .cwd(&dir)
            .arg("-c")
            .arg(format!("init.defaultBranch={branch}"))
            .arg("init"),
        "git init",
    )
    .await?;
    Ok(done("git_init", &out))
}

async fn clone(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let url = a.str("url")?;
    vet(ctx, url).await?;
    let dest = ctx.write_path(a.str("path")?)?;
    let mut cmd = base().args(["clone", "--no-recurse-submodules"]);
    if let Some(branch) = a.opt_str("branch")? {
        check_name(branch)?;
        cmd = cmd.arg(format!("--branch={branch}"));
    }
    if let Some(depth) = a.opt_u64("depth")? {
        cmd = cmd.arg(format!("--depth={depth}"));
    }
    let cmd = net_timeout(ctx, &a, cmd.arg("--").arg(url).arg_path(&dest))?;
    let out = ctx.run(cmd).await?;
    if !out.success() {
        return Err(failure("git clone", &out));
    }
    Ok(ToolOutput::text(format!(
        "[git_clone: cloned into {}]",
        dest.display()
    )))
}

/// Stage `candidates` except the protected ones. Returns (staged, skipped).
async fn stage(ctx: &ToolContext, repo: &Repo, candidates: Vec<String>) -> Result<(usize, usize)> {
    let unique: BTreeSet<String> = candidates
        .into_iter()
        // A trailing slash is a nested repository, which git does not add.
        .filter(|p| !p.ends_with('/'))
        .collect();
    let total = unique.len();
    let allowed: Vec<String> = unique
        .into_iter()
        .filter(|p| protected(ctx, repo, p, Access::Read).is_none())
        .collect();
    if !allowed.is_empty() {
        let list = allowed
            .iter()
            .map(|p| format!(":(literal){p}"))
            .collect::<Vec<_>>()
            .join("\0");
        ok(
            ctx,
            git(repo)
                .args(["add", "--all", "--pathspec-from-file=-", "--pathspec-file-nul"])
                .stdin(list),
            "git add",
        )
        .await?;
    }
    Ok((allowed.len(), total - allowed.len()))
}

async fn add(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let mut specs = Vec::new();
    for p in a.str_array("paths")? {
        specs.push(literal(&rel_path(&repo, &p)?));
    }
    if specs.is_empty() {
        return Err(ToolError::invalid(
            "`paths` is empty; pass files or directories, or \".\" for everything",
        ));
    }
    let candidates = names(
        ctx,
        git(&repo)
            .args([
                "ls-files",
                "-z",
                "--others",
                "--modified",
                "--deleted",
                "--exclude-standard",
                "--",
            ])
            .args(specs),
    )
    .await?;
    let (staged, skipped) = stage(ctx, &repo, candidates).await?;
    Ok(ToolOutput::json(json!({"staged": staged, "skipped": skipped})))
}

fn identity(value: &str, what: &str) -> Result<String> {
    if value.is_empty() || value.contains(['<', '>', '\n', '\r', '\0']) {
        return Err(ToolError::invalid(format!(
            "{what} must not be empty or contain < > or line breaks"
        )));
    }
    Ok(value.to_string())
}

async fn commit(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let message = a.str("message")?;
    if message.trim().is_empty() {
        return Err(ToolError::invalid("`message` must not be empty"));
    }
    if a.bool_or("all", false)? {
        let tracked = names(
            ctx,
            git(&repo).args(["ls-files", "-z", "--modified", "--deleted"]),
        )
        .await?;
        stage(ctx, &repo, tracked).await?;
    }
    let mut cmd = git(&repo).args(["commit", "--file=-"]);
    if a.bool_or("allowEmpty", false)? {
        cmd = cmd.arg("--allow-empty");
    }
    if let Some(name) = a.opt_str("authorName")? {
        let name = identity(name, "authorName")?;
        cmd = cmd
            .env("GIT_AUTHOR_NAME", name.clone())
            .env("GIT_COMMITTER_NAME", name);
    }
    if let Some(email) = a.opt_str("authorEmail")? {
        let email = identity(email, "authorEmail")?;
        cmd = cmd
            .env("GIT_AUTHOR_EMAIL", email.clone())
            .env("GIT_COMMITTER_EMAIL", email);
    }
    let out = run(ctx, cmd.stdin(message)).await?;
    if !out.success() {
        let mut error = failure_text("git commit", &out);
        if out.stdout.text.contains("nothing to commit")
            || out.stdout.text.contains("no changes added")
        {
            error.push_str("\nStage changes with git_add first.");
        } else if out.stderr.text.contains("Please tell me who you are")
            || out.stderr.text.contains("empty ident")
        {
            error.push_str("\nPass authorName and authorEmail.");
        }
        return Err(ToolError::Execution(error));
    }
    let info = ok(
        ctx,
        git(&repo).args(["log", "-1", "--format=%H%x1f%s"]),
        "git log",
    )
    .await?;
    let (hash, subject) = info
        .stdout
        .text
        .trim_end()
        .split_once('\x1f')
        .unwrap_or_default();
    let branch = run(ctx, git(&repo).args(["symbolic-ref", "--quiet", "--short", "HEAD"])).await?;
    let branch = branch.stdout.text.trim();
    Ok(ToolOutput::json(json!({
        "hash": hash,
        "subject": subject,
        "branch": if branch.is_empty() { Value::Null } else { json!(branch) },
    })))
}

// ---------------------------------------------------------------------------
// Branches, tags and moving the work tree
// ---------------------------------------------------------------------------

fn required<'a>(value: Option<&'a str>, key: &str, mode: &str) -> Result<&'a str> {
    value.ok_or_else(|| ToolError::invalid(format!("`{key}` is required for {mode}")))
}

async fn branch(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mode = a
        .opt_enum("mode", &["list", "create", "delete", "rename"])?
        .unwrap_or("list");
    let repo = open(ctx, &a, mode != "list").await?;
    let force = a.bool_or("force", false)?;
    let name = a.opt_str("name")?;
    if let Some(name) = name {
        check_name(name)?;
    }
    match mode {
        "create" => {
            let name = required(name, "name", mode)?;
            let mut cmd = git(&repo).arg("branch");
            if force {
                cmd = cmd.arg("--force");
            }
            cmd = cmd.arg(name);
            if let Some(start) = a.opt_str("startPoint")? {
                cmd = cmd.arg(commit_id(ctx, &repo, start).await?);
            }
            ok(ctx, cmd, "git branch").await?;
            Ok(ToolOutput::text(format!("[git_branch: created {name}]")))
        }
        "delete" => {
            let name = required(name, "name", mode)?;
            ctx.require_destructive("deleting a branch")?;
            let flag = if force { "-D" } else { "-d" };
            ok(ctx, git(&repo).args(["branch", flag, name]), "git branch").await?;
            Ok(ToolOutput::text(format!("[git_branch: deleted {name}]")))
        }
        "rename" => {
            let name = required(name, "name", mode)?;
            let new_name = required(a.opt_str("newName")?, "newName", mode)?;
            check_name(new_name)?;
            ok(
                ctx,
                git(&repo).args(["branch", "-m", name, new_name]),
                "git branch",
            )
            .await?;
            Ok(ToolOutput::text(format!(
                "[git_branch: renamed {name} to {new_name}]"
            )))
        }
        _ => {
            let mut cmd = git(&repo).args([
                "for-each-ref",
                "--format=%(HEAD) %(refname:short) %(objectname:short) %(upstream:short) %(subject)",
                "refs/heads",
            ]);
            if a.bool_or("remotes", false)? {
                cmd = cmd.arg("refs/remotes");
            }
            let out = ok(ctx, cmd, "git branch").await?;
            Ok(content("git_branch", &out, 0))
        }
    }
}

async fn checkout(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let name = a.str("ref")?;
    let cmd = if a.bool_or("create", false)? {
        check_name(name)?;
        let mut cmd = git(&repo).args(["checkout", "-b", name]);
        if let Some(start) = a.opt_str("startPoint")? {
            let start = commit_id(ctx, &repo, start).await?;
            guard_move(ctx, &repo, &start, "switching to that commit").await?;
            cmd = cmd.arg(start);
        }
        cmd
    } else {
        let target = commit_id(ctx, &repo, name).await.map_err(|e| match e {
            ToolError::NotFound(m) => ToolError::NotFound(format!(
                "{m}. For a branch that only exists on a remote, pass create with startPoint \
                 '<remote>/<branch>'."
            )),
            other => other,
        })?;
        guard_move(ctx, &repo, &target, "switching to that commit").await?;
        git(&repo).args(["checkout", name, "--"])
    };
    let out = ok(ctx, cmd, "git checkout").await?;
    Ok(done("git_checkout", &out))
}

async fn merge(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    if a.bool_or("abort", false)? {
        let out = ok(ctx, git(&repo).args(["merge", "--abort"]), "git merge").await?;
        return Ok(done("git_merge", &out));
    }
    let name = required(a.opt_str("ref")?, "ref", "a merge")?;
    let target = commit_id(ctx, &repo, name).await?;
    guard_move(ctx, &repo, &target, "this merge").await?;
    let out = ok(
        ctx,
        git(&repo)
            .args(["merge", "--no-edit", "-m"])
            .arg(format!("Merge {name}"))
            .arg(target),
        "git merge",
    )
    .await?;
    Ok(done("git_merge", &out))
}

async fn rebase(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let cmd = if let Some(control) = a.opt_enum("control", &CONTROL)? {
        git(&repo).arg("rebase").arg(format!("--{control}"))
    } else {
        let name = required(a.opt_str("ref")?, "ref", "a rebase")?;
        let target = commit_id(ctx, &repo, name).await?;
        guard_move(ctx, &repo, &target, "this rebase").await?;
        git(&repo).arg("rebase").arg(target)
    };
    let out = ok(ctx, cmd, "git rebase").await?;
    Ok(done("git_rebase", &out))
}

/// `cherry-pick` and `revert`: apply (or undo) one commit.
async fn replay(ctx: &ToolContext, args: Value, verb: &'static str, tool: &str) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let cmd = if let Some(control) = a.opt_enum("control", &CONTROL)? {
        git(&repo).arg(verb).arg(format!("--{control}"))
    } else {
        let name = required(a.opt_str("commit")?, "commit", tool)?;
        let id = commit_id(ctx, &repo, name).await?;
        let affected = names(
            ctx,
            git(&repo)
                .args([
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    "--root",
                    "-m",
                ])
                .arg(&id),
        )
        .await?;
        guard(ctx, &repo, &affected, "replaying that commit")?;
        git(&repo).args([verb, "--no-edit"]).arg(id)
    };
    let out = ok(ctx, cmd, tool).await?;
    Ok(done(tool, &out))
}

async fn cherry_pick(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    replay(ctx, args, "cherry-pick", "git_cherry_pick").await
}

async fn revert(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    replay(ctx, args, "revert", "git_revert").await
}

async fn reset(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let mode = a
        .opt_enum("mode", &["soft", "mixed", "hard"])?
        .unwrap_or("mixed");
    let paths = a.opt_str_array("paths")?;
    let rev = a.str_or("ref", "HEAD")?;
    if !paths.is_empty() {
        if mode != "mixed" {
            return Err(ToolError::invalid("`paths` only works with mode mixed"));
        }
        let mut cmd = git(&repo).args(["reset", "--quiet"]);
        // Before the first commit there is nothing to reset to; `rm --cached`
        // is how a path is unstaged then.
        if head(ctx, &repo).await?.is_some() {
            cmd = cmd.arg(commit_id(ctx, &repo, rev).await?);
        } else {
            cmd = git(&repo).args(["rm", "--cached", "--quiet", "-r"]);
        }
        cmd = cmd.arg("--");
        for p in &paths {
            cmd = cmd.arg(literal(&rel_path(&repo, p)?));
        }
        ok(ctx, cmd, "git reset").await?;
        return Ok(ToolOutput::text(format!(
            "[git_reset: unstaged {} path(s)]",
            paths.len()
        )));
    }
    let target = commit_id(ctx, &repo, rev).await?;
    if mode == "hard" {
        ctx.require_destructive("discarding uncommitted changes")?;
        let mut affected = names(
            ctx,
            git(&repo).args(["diff", "--name-only", "--no-renames", "-z", "HEAD", "--"]),
        )
        .await?;
        affected.extend(changed_between(ctx, &repo, "HEAD", &target).await?);
        guard(ctx, &repo, &affected, "this reset")?;
    }
    let out = ok(
        ctx,
        git(&repo).arg("reset").arg(format!("--{mode}")).arg(target),
        "git reset",
    )
    .await?;
    Ok(done("git_reset", &out))
}

/// Paths a stash entry holds: tracked changes, plus untracked files when it
/// was made with includeUntracked (git keeps those in a third parent).
async fn stash_paths(ctx: &ToolContext, repo: &Repo, entry: &str) -> Result<Vec<String>> {
    let id = commit_id(ctx, repo, entry)
        .await
        .map_err(|_| ToolError::NotFound(format!("there is no stash entry {entry}")))?;
    let base = commit_id(ctx, repo, &format!("{id}^1")).await?;
    let mut paths = changed_between(ctx, repo, &base, &id).await?;
    if let Ok(untracked) = commit_id(ctx, repo, &format!("{id}^3")).await {
        paths.extend(
            names(
                ctx,
                git(repo)
                    .args(["ls-tree", "-r", "-z", "--name-only"])
                    .arg(untracked),
            )
            .await?,
        );
    }
    Ok(paths)
}

async fn stash(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mode = a
        .opt_enum("mode", &["push", "pop", "apply", "list", "show", "drop"])?
        .unwrap_or("push");
    let repo = open(ctx, &a, mode != "list" && mode != "show").await?;
    let entry = format!("stash@{{{}}}", a.u64_or("index", 0)?);
    let out = match mode {
        "list" => ok(ctx, git(&repo).args(["stash", "list"]), "git stash").await?,
        "show" => {
            let listed = stash_paths(ctx, &repo, &entry).await?;
            let (excluded, hidden) = exclusions(ctx, &repo, &listed)?;
            let id = commit_id(ctx, &repo, &entry).await?;
            let out = ok(
                ctx,
                git(&repo)
                    .args(["diff", "--no-ext-diff", "--no-textconv"])
                    .arg(commit_id(ctx, &repo, &format!("{id}^1")).await?)
                    .arg(&id)
                    .args(["--", "."])
                    .args(excluded),
                "git stash",
            )
            .await?;
            return Ok(content("git_stash", &out, hidden));
        }
        "pop" | "apply" => {
            let held = stash_paths(ctx, &repo, &entry).await?;
            guard(ctx, &repo, &held, "restoring that stash")?;
            ok(ctx, git(&repo).args(["stash", mode, &entry]), "git stash").await?
        }
        "drop" => {
            ctx.require_destructive("dropping a stash")?;
            ok(ctx, git(&repo).args(["stash", "drop", &entry]), "git stash").await?
        }
        _ => {
            let untracked = a.bool_or("includeUntracked", false)?;
            let mut affected = Vec::new();
            if head(ctx, &repo).await?.is_some() {
                affected = names(
                    ctx,
                    git(&repo).args(["diff", "--name-only", "--no-renames", "-z", "HEAD", "--"]),
                )
                .await?;
            }
            let mut cmd = git(&repo).args(["stash", "push"]);
            if untracked {
                affected.extend(
                    names(
                        ctx,
                        git(&repo).args(["ls-files", "-z", "--others", "--exclude-standard"]),
                    )
                    .await?,
                );
                cmd = cmd.arg("--include-untracked");
            }
            guard(ctx, &repo, &affected, "stashing")?;
            if let Some(message) = a.opt_str("message")? {
                cmd = cmd.arg(format!("--message={message}"));
            }
            ok(ctx, cmd, "git stash").await?
        }
    };
    Ok(done("git_stash", &out))
}

async fn tag(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mode = a
        .opt_enum("mode", &["list", "create", "delete"])?
        .unwrap_or("list");
    let repo = open(ctx, &a, mode != "list").await?;
    let name = a.opt_str("name")?;
    if let Some(name) = name {
        check_name(name)?;
    }
    match mode {
        "create" => {
            let name = required(name, "name", mode)?;
            let target = commit_id(ctx, &repo, a.str_or("ref", "HEAD")?).await?;
            let mut cmd = git(&repo).arg("tag");
            if let Some(message) = a.opt_str("message")? {
                cmd = cmd.arg("--annotate").arg(format!("--message={message}"));
            }
            ok(ctx, cmd.arg(name).arg(target), "git tag").await?;
            Ok(ToolOutput::text(format!("[git_tag: created {name}]")))
        }
        "delete" => {
            let name = required(name, "name", mode)?;
            ctx.require_destructive("deleting a tag")?;
            ok(ctx, git(&repo).args(["tag", "--delete", name]), "git tag").await?;
            Ok(ToolOutput::text(format!("[git_tag: deleted {name}]")))
        }
        _ => {
            let out = ok(
                ctx,
                git(&repo).args([
                    "for-each-ref",
                    "--sort=-creatordate",
                    "--format=%(refname:short) %(objectname:short) %(subject)",
                    "refs/tags",
                ]),
                "git tag",
            )
            .await?;
            Ok(content("git_tag", &out, 0))
        }
    }
}

async fn clean(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let dry_run = a.bool_or("dryRun", false)?;
    if !dry_run {
        ctx.require_destructive("removing untracked files")?;
    }
    let scope = match a.opt_str("path")? {
        Some(p) => rel_path(&repo, p)?,
        None => ".".to_string(),
    };
    let mut cmd = git(&repo).args(["ls-files", "-z", "--others"]);
    if !a.bool_or("includeIgnored", false)? {
        cmd = cmd.arg("--exclude-standard");
    }
    let listed = names(ctx, cmd.arg("--").arg(literal(&scope))).await?;
    // The server deletes, through the file capability, so the file policy
    // decides for every single path.
    let top = repo.top_abs.clone();
    let (removed, skipped) = ctx
        .fs()
        .blocking(move |fs| {
            let mut removed = Vec::new();
            let mut skipped = 0usize;
            let mut dirs = BTreeSet::new();
            for rel in listed.iter().filter(|p| !p.ends_with('/')) {
                let full = top.join(rel).to_string_lossy().into_owned();
                let Ok(path) = fs.resolve(&full, Access::Write) else {
                    skipped += 1;
                    continue;
                };
                if !dry_run {
                    fs.remove_file(&path)?;
                    let mut dir = Path::new(rel).parent();
                    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
                        dirs.insert(d.to_path_buf());
                        dir = d.parent();
                    }
                }
                removed.push(rel.clone());
            }
            // Deepest first; a directory that still has content stays.
            for dir in dirs.iter().rev() {
                let full = top.join(dir).to_string_lossy().into_owned();
                if let Ok(path) = fs.resolve(&full, Access::Write) {
                    let _ = fs.remove_dir(&path);
                }
            }
            Ok((removed, skipped))
        })
        .await?;
    Ok(ToolOutput::json(json!({
        "count": removed.len(),
        "paths": removed.iter().take(500).collect::<Vec<_>>(),
        "skipped": skipped,
        "dryRun": dry_run,
    })))
}

async fn apply(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let patch = a.str("patch")?;
    let check = a.bool_or("check", false)?;
    // `--numstat -z`: "added<TAB>deleted<TAB>path", or for a rename an empty
    // path followed by the old and the new one.
    let stat = names(
        ctx,
        git(&repo).args(["apply", "--numstat", "-z", "-"]).stdin(patch),
    )
    .await?;
    let affected: Vec<String> = stat
        .iter()
        .map(|record| record.rsplit('\t').next().unwrap_or_default().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    for path in &affected {
        rel_path(&repo, path)?;
    }
    guard(ctx, &repo, &affected, "this patch")?;
    if !check {
        let summary = ok(
            ctx,
            git(&repo).args(["apply", "--summary", "-"]).stdin(patch),
            "git apply",
        )
        .await?;
        if summary
            .stdout
            .text
            .lines()
            .any(|l| l.trim_start().starts_with("delete mode"))
        {
            ctx.require_destructive("a patch that deletes files")?;
        }
    }
    let mut cmd = git(&repo).args(["apply", "--whitespace=nowarn"]);
    if check {
        cmd = cmd.arg("--check");
    }
    ok(ctx, cmd.arg("-").stdin(patch), "git apply").await?;
    Ok(ToolOutput::text(format!(
        "[git_apply: the patch {} {} file(s)]",
        if check { "applies cleanly to" } else { "was applied to" },
        affected.len()
    )))
}

async fn bisect(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let action = a.str("action")?;
    let mut cmd = git(&repo).args(["bisect", action]);
    match action {
        // The work tree is left alone: bisect only records and suggests.
        "start" => cmd = cmd.arg("--no-checkout"),
        "good" | "bad" | "skip" => {
            if let Some(rev) = a.opt_str("rev")? {
                cmd = cmd.arg(commit_id(ctx, &repo, rev).await?);
            }
        }
        "reset" | "log" => {}
        other => {
            return Err(ToolError::invalid(format!(
                "unknown bisect action '{other}'"
            )))
        }
    }
    let out = ok(ctx, cmd, "git bisect").await?;
    Ok(done("git_bisect", &out))
}

// ---------------------------------------------------------------------------
// Remotes
// ---------------------------------------------------------------------------

async fn remote(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a
        .opt_enum("action", &["list", "add", "set_url", "remove"])?
        .unwrap_or("list");
    let repo = open(ctx, &a, action != "list").await?;
    let name = a.opt_str("name")?;
    if let Some(name) = name {
        check_name(name)?;
    }
    match action {
        "add" | "set_url" => {
            let name = required(name, "name", action)?;
            let url = required(a.opt_str("url")?, "url", action)?;
            endpoint(url)?;
            let verb = if action == "add" { "add" } else { "set-url" };
            ok(ctx, git(&repo).args(["remote", verb, name, url]), "git remote").await?;
            Ok(ToolOutput::text(format!(
                "[git_remote: {name} is {}]",
                redact(url)
            )))
        }
        "remove" => {
            let name = required(name, "name", action)?;
            ctx.require_destructive("removing a remote")?;
            ok(ctx, git(&repo).args(["remote", "remove", name]), "git remote").await?;
            Ok(ToolOutput::text(format!("[git_remote: removed {name}]")))
        }
        _ => {
            let mut lines = Vec::new();
            for name in remote_names(ctx, &repo).await? {
                let fetch = remote_url(ctx, &repo, &name, false).await?;
                let push = remote_url(ctx, &repo, &name, true).await?;
                lines.push(if fetch == push {
                    format!("{name} {}", redact(&fetch))
                } else {
                    format!("{name} {} (push: {})", redact(&fetch), redact(&push))
                });
            }
            if lines.is_empty() {
                lines.push("[git_remote: no remotes; add one with action add]".to_string());
            }
            Ok(ToolOutput::text(lines.join("\n")))
        }
    }
}

async fn fetch(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let mut cmd = git(&repo).args(["fetch", "--no-recurse-submodules"]);
    if a.bool_or("prune", false)? {
        cmd = cmd.arg("--prune");
    }
    if a.bool_or("all", false)? {
        for name in remote_names(ctx, &repo).await? {
            vet(ctx, &remote_url(ctx, &repo, &name, false).await?).await?;
        }
        cmd = cmd.arg("--all");
    } else {
        let name = a.str_or("remote", "origin")?;
        vet(ctx, &remote_url(ctx, &repo, name, false).await?).await?;
        cmd = cmd.arg(name);
    }
    let out = ctx.run(net_timeout(ctx, &a, cmd)?).await?;
    if !out.success() {
        return Err(failure("git fetch", &out));
    }
    Ok(done("git_fetch", &out))
}

async fn pull(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let name = a.str_or("remote", "origin")?;
    vet(ctx, &remote_url(ctx, &repo, name, false).await?).await?;
    let branch = a.opt_str("branch")?;
    let mut cmd = git(&repo).args(["fetch", "--no-recurse-submodules", name]);
    if let Some(branch) = branch {
        check_name(branch)?;
        cmd = cmd.arg(format!("refs/heads/{branch}"));
    }
    let fetched = ctx.run(net_timeout(ctx, &a, cmd)?).await?;
    if !fetched.success() {
        return Err(failure("git fetch", &fetched));
    }
    let (target, label) = match branch {
        Some(branch) => (
            commit_id(ctx, &repo, "FETCH_HEAD").await?,
            format!("{name}/{branch}"),
        ),
        None => (
            commit_id(ctx, &repo, "@{upstream}").await.map_err(|_| {
                ToolError::invalid(
                    "the current branch has no upstream; pass `branch` to say what to pull",
                )
            })?,
            "the upstream branch".to_string(),
        ),
    };
    guard_move(ctx, &repo, &target, "this pull").await?;
    let cmd = if a.bool_or("rebase", false)? {
        git(&repo).arg("rebase").arg(target)
    } else {
        git(&repo)
            .args(["merge", "--no-edit", "-m"])
            .arg(format!("Merge {label}"))
            .arg(target)
    };
    let out = ok(ctx, cmd, "git pull").await?;
    Ok(done("git_pull", &out))
}

async fn push(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let name = a.str_or("remote", "origin")?;
    vet(ctx, &remote_url(ctx, &repo, name, true).await?).await?;
    let refspec = if let Some(tag) = a.opt_str("tag")? {
        check_name(tag)?;
        format!("refs/tags/{tag}:refs/tags/{tag}")
    } else {
        let branch = match a.opt_str("branch")? {
            Some(branch) => branch.to_string(),
            None => {
                let out = run(
                    ctx,
                    git(&repo).args(["symbolic-ref", "--quiet", "--short", "HEAD"]),
                )
                .await?;
                let current = out.stdout.text.trim().to_string();
                if current.is_empty() {
                    return Err(ToolError::invalid(
                        "HEAD is detached; pass `branch` to say what to push",
                    ));
                }
                current
            }
        };
        check_name(&branch)?;
        format!("refs/heads/{branch}:refs/heads/{branch}")
    };
    let mut cmd = git(&repo).arg("push");
    if a.bool_or("setUpstream", false)? {
        cmd = cmd.arg("--set-upstream");
    }
    if a.bool_or("force", false)? {
        ctx.require_destructive("overwriting a remote branch")?;
        cmd = cmd.arg("--force-with-lease");
    }
    let out = ctx
        .run(net_timeout(ctx, &a, cmd.arg(name).arg(refspec))?)
        .await?;
    if !out.success() {
        return Err(failure("git push", &out));
    }
    Ok(done("git_push", &out))
}

async fn submodule(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let repo = open(ctx, &a, true).await?;
    let status = ok(ctx, git(&repo).args(["submodule", "status"]), "git submodule").await?;
    if !a.bool_or("update", false)? {
        return Ok(content("git_submodule", &status, 0));
    }
    // "-<id> <path>" marks a submodule that is not initialised.
    let missing: Vec<String> = status
        .stdout
        .text
        .lines()
        .filter_map(|l| l.strip_prefix('-'))
        .filter_map(|l| l.split_once(' '))
        .map(|(_, path)| format!(":(literal){path}"))
        .collect();
    if missing.is_empty() {
        return Ok(ToolOutput::text(
            "[git_submodule: every submodule is already initialised]",
        ));
    }
    ok(
        ctx,
        git(&repo)
            .args(["submodule", "init", "--"])
            .args(missing.iter().cloned()),
        "git submodule",
    )
    .await?;
    let urls = names(
        ctx,
        git(&repo).args(["config", "-z", "--get-regexp", r"^submodule\..*\.url$"]),
    )
    .await?;
    for entry in &urls {
        // "key\nvalue"
        if let Some((_, url)) = entry.split_once('\n') {
            vet(ctx, url).await?;
        }
    }
    let cmd = git(&repo)
        .args(["submodule", "update", "--init", "--"])
        .args(missing.iter().cloned());
    let out = ctx.run(net_timeout(ctx, &a, cmd)?).await?;
    if !out.success() {
        return Err(failure("git submodule", &out));
    }
    Ok(done("git_submodule", &out))
}

async fn worktree(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a
        .opt_enum("action", &["list", "add", "remove", "prune"])?
        .unwrap_or("list");
    let repo = open(ctx, &a, action != "list").await?;
    let out = match action {
        "add" => {
            let path = ctx.write_path(required(a.opt_str("path")?, "path", action)?)?;
            let mut cmd = git(&repo).args(["worktree", "add"]);
            if let Some(branch) = a.opt_str("branch")? {
                check_name(branch)?;
                cmd = cmd.arg("-b").arg(branch);
            }
            cmd = cmd.arg_path(&path);
            if let Some(rev) = a.opt_str("ref")? {
                cmd = cmd.arg(commit_id(ctx, &repo, rev).await?);
            }
            ok(ctx, cmd, "git worktree").await?
        }
        "remove" => {
            let path = ctx.write_path(required(a.opt_str("path")?, "path", action)?)?;
            ctx.require_destructive("removing a work tree")?;
            ok(
                ctx,
                git(&repo).args(["worktree", "remove"]).arg_path(&path),
                "git worktree",
            )
            .await?
        }
        "prune" => ok(ctx, git(&repo).args(["worktree", "prune"]), "git worktree").await?,
        _ => ok(ctx, git(&repo).args(["worktree", "list"]), "git worktree").await?,
    };
    Ok(done("git_worktree", &out))
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
