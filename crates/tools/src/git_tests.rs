//! `git` tools driven through the dispatcher, against real repositories.

#![allow(clippy::disallowed_methods)]

use std::path::Path;

use serde_json::{json, Value};

use crate::testkit::{text_of, Kit};

const DESTRUCTIVE: &str = "allow_destructive = true";

/// Run git directly, the way an operator would outside the server.
fn raw(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=Operator",
            "-c",
            "user.email=operator@example.com",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A repository at `root/proj` with one commit containing `app.txt`.
fn project(kit: &Kit) -> std::path::PathBuf {
    let dir = kit.root.join("proj");
    std::fs::create_dir_all(&dir).unwrap();
    raw(&dir, &["init"]);
    kit.write("proj/app.txt", "one\n");
    raw(&dir, &["add", "app.txt"]);
    raw(&dir, &["commit", "-m", "first"]);
    dir
}

fn with_author(mut args: Value) -> Value {
    args["authorName"] = json!("Agent");
    args["authorEmail"] = json!("agent@example.com");
    args
}

fn paths_of(status: &Value) -> Vec<String> {
    status["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn add_commit_log_and_status_work_from_an_empty_directory() {
    let kit = Kit::new("");
    let out = kit.ok("git_init", json!({"path": "proj"})).await;
    assert!(text_of(&out).contains("nitialized"), "{}", text_of(&out));
    let status = kit.json("git_status", json!({"repo": "proj"})).await;
    assert_eq!(status["branch"], "main");
    assert_eq!(status["head"], Value::Null);
    assert_eq!(status["clean"], true);
    assert_eq!(
        kit.json("git_log", json!({"repo": "proj"})).await["commits"],
        json!([])
    );

    kit.ok(
        "fs_write",
        json!({"path": "proj/src/main.txt", "content": "hello\n"}),
    )
    .await;
    kit.write("proj/.env", "TOKEN=hunter2\n");
    let status = kit.json("git_status", json!({"repo": "proj"})).await;
    assert_eq!(paths_of(&status), ["src/"]);
    assert_eq!(status["hidden"], 1, "the .env file is counted, not named");

    let added = kit
        .json("git_add", json!({"repo": "proj", "paths": ["."]}))
        .await;
    assert_eq!(added, json!({"staged": 1, "skipped": 1}));
    let commit = kit
        .json(
            "git_commit",
            with_author(json!({"repo": "proj", "message": "Add main\n\nWith a body."})),
        )
        .await;
    assert_eq!(commit["subject"], "Add main");
    assert_eq!(commit["branch"], "main");

    let tracked = raw(&kit.root.join("proj"), &["ls-files"]);
    assert_eq!(tracked, "src/main.txt\n", "the protected file stayed out");
    let log = kit.json("git_log", json!({"repo": "proj/src"})).await;
    assert_eq!(log["commits"][0]["hash"], commit["hash"]);
    assert_eq!(log["commits"][0]["author"], "Agent");
    assert_eq!(log["commits"][0]["message"], "Add main\n\nWith a body.");

    // Nothing staged: the error says what to do next.
    let err = kit
        .err(
            "git_commit",
            with_author(json!({"repo": "proj", "message": "again"})),
        )
        .await;
    assert!(
        err.starts_with("[execution]") && err.contains("git_add"),
        "{err}"
    );
}

#[cfg(unix)]
mod daemon {
    use super::*;

    /// A `git daemon` serving one directory on loopback, stopped on drop.
    pub(super) struct Daemon {
        child: std::process::Child,
        pub port: u16,
    }

    impl Daemon {
        pub(super) fn serve(base: &Path) -> Self {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let child = std::process::Command::new("git")
                .args([
                    "daemon".to_string(),
                    "--reuseaddr".to_string(),
                    "--export-all".to_string(),
                    "--enable=receive-pack".to_string(),
                    "--listen=127.0.0.1".to_string(),
                    format!("--port={port}"),
                    format!("--base-path={}", base.display()),
                    base.display().to_string(),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("git daemon starts");
            for _ in 0..200 {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Self { child, port };
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            panic!("git daemon never listened on {port}");
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[tokio::test]
    async fn an_empty_directory_becomes_a_pushed_commit_with_typed_tools_alone() {
        let kit = Kit::new("allow_network = true\nallow_private_network = true");
        raw(&kit.outside, &["init", "--bare", "remote.git"]);
        let daemon = Daemon::serve(&kit.outside);
        let url = format!("git://127.0.0.1:{}/remote.git", daemon.port);

        kit.ok("git_init", json!({"path": "proj"})).await;
        kit.ok(
            "fs_write",
            json!({"path": "proj/README.md", "content": "# Project\n"}),
        )
        .await;
        kit.json("git_add", json!({"repo": "proj", "paths": ["README.md"]}))
            .await;
        let commit = kit
            .json(
                "git_commit",
                with_author(json!({"repo": "proj", "message": "Initial commit"})),
            )
            .await;
        kit.ok(
            "git_remote",
            json!({"repo": "proj", "action": "add", "name": "origin", "url": url}),
        )
        .await;
        kit.ok("git_push", json!({"repo": "proj", "setUpstream": true}))
            .await;

        let remote = kit.outside.join("remote.git");
        assert_eq!(
            raw(&remote, &["rev-parse", "main"]).trim(),
            commit["hash"].as_str().unwrap()
        );
        let status = kit.json("git_status", json!({"repo": "proj"})).await;
        assert_eq!(status["upstream"], "origin/main");
        assert_eq!(status["ahead"], 0);

        // And back: clone, change on the remote side, pull.
        kit.ok("git_clone", json!({"url": url, "path": "copy"}))
            .await;
        assert_eq!(kit.read("copy/README.md"), "# Project\n");
        kit.write("copy/more.txt", "more\n");
        kit.json("git_add", json!({"repo": "copy", "paths": ["."]}))
            .await;
        kit.json(
            "git_commit",
            with_author(json!({"repo": "copy", "message": "More"})),
        )
        .await;
        kit.ok("git_push", json!({"repo": "copy"})).await;
        kit.ok("git_pull", json!({"repo": "proj"})).await;
        assert_eq!(kit.read("proj/more.txt"), "more\n");
        let fetched = kit
            .ok("git_fetch", json!({"repo": "proj", "prune": true}))
            .await;
        assert!(!text_of(&fetched).is_empty());

        // A tag reaches the remote too.
        kit.ok(
            "git_tag",
            json!({"repo": "proj", "mode": "create", "name": "v1", "message": "one"}),
        )
        .await;
        kit.ok("git_push", json!({"repo": "proj", "tag": "v1"}))
            .await;
        assert!(raw(&remote, &["tag", "--list"]).contains("v1"));
    }

    #[tokio::test]
    async fn remotes_are_vetted_against_the_network_policy() {
        let kit = Kit::new("allow_network = true");
        project(&kit);
        kit.ok(
            "git_remote",
            json!({"repo": "proj", "action": "add", "name": "origin",
                   "url": "git://127.0.0.1:9/remote.git"}),
        )
        .await;
        for tool in ["git_fetch", "git_pull", "git_push"] {
            let err = kit.err(tool, json!({"repo": "proj"})).await;
            assert!(err.starts_with("[network_not_allowed]"), "{tool}: {err}");
        }
        let err = kit
            .err(
                "git_clone",
                json!({"url": "http://169.254.169.254/x.git", "path": "c"}),
            )
            .await;
        assert!(err.starts_with("[network_not_allowed]"), "{err}");
        assert!(!kit.exists("c"));

        kit.reconfigure("");
        let err = kit.err("git_fetch", json!({"repo": "proj"})).await;
        assert!(
            err.starts_with("[permission_denied]") && err.contains("allow_network"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_fabricated_repository_is_not_used() {
        let kit = Kit::new("");
        // Everything below can be written with the file tools: no path is
        // named .git.
        let marker = kit.root.join("ran");
        kit.write("fake/HEAD", "ref: refs/heads/main\n");
        std::fs::create_dir_all(kit.root.join("fake/objects")).unwrap();
        std::fs::create_dir_all(kit.root.join("fake/refs")).unwrap();
        std::fs::create_dir_all(kit.root.join("tree")).unwrap();
        kit.write(
            "fake/config",
            &format!(
                "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = {}\n\t\
                 fsmonitor = touch {} #\n",
                kit.root.join("tree").display(),
                marker.display()
            ),
        );
        for tool in ["git_status", "git_diff", "git_log"] {
            let err = kit.err(tool, json!({"repo": "fake"})).await;
            assert!(
                err.starts_with("[permission_denied]") || err.starts_with("[not_found]"),
                "{tool}: {err}"
            );
        }
        let err = kit
            .err("git_add", json!({"repo": "fake", "paths": ["."]}))
            .await;
        assert!(!err.is_empty());
        assert!(!marker.exists(), "git ran a program named by the client");
    }
}

#[tokio::test]
async fn protected_paths_are_neither_shown_nor_committed() {
    let kit = Kit::new("");
    let dir = project(&kit);
    // History made outside the server tracks a key file.
    kit.write("proj/server.pem", "KEY-ONE\n");
    raw(&dir, &["add", "-f", "server.pem"]);
    raw(&dir, &["commit", "-m", "track a key"]);
    kit.write("proj/server.pem", "KEY-TWO\n");
    kit.write("proj/app.txt", "one\ntwo\n");

    let status = kit.json("git_status", json!({"repo": "proj"})).await;
    assert_eq!(paths_of(&status), ["app.txt"]);
    assert_eq!(status["hidden"], 1);

    let diff = text_of(&kit.ok("git_diff", json!({"repo": "proj"})).await);
    assert!(diff.contains("+two"), "{diff}");
    assert!(!diff.contains("KEY") && !diff.contains("server.pem"), "{diff}");
    assert!(diff.contains("1 path(s) not shown"), "{diff}");

    let show = text_of(&kit.ok("git_show", json!({"repo": "proj"})).await);
    assert!(show.contains("track a key"), "{show}");
    assert!(!show.contains("KEY") && !show.contains("server.pem"), "{show}");

    for (tool, args) in [
        ("git_show", json!({"repo": "proj", "path": "server.pem"})),
        ("git_blame", json!({"repo": "proj", "path": "server.pem"})),
        ("git_log", json!({"repo": "proj", "path": "server.pem"})),
        ("git_diff", json!({"repo": "proj", "path": "./server.pem"})),
    ] {
        let err = kit.err(tool, args).await;
        assert!(err.starts_with("[permission_denied]"), "{tool}: {err}");
        assert!(!err.contains("KEY"), "{err}");
    }

    // `all` stages tracked changes, except the protected one.
    kit.json(
        "git_commit",
        with_author(json!({"repo": "proj", "message": "two", "all": true})),
    )
    .await;
    assert_eq!(
        raw(&dir, &["show", "--name-only", "--format=", "HEAD"]),
        "app.txt\n"
    );
    assert_eq!(raw(&dir, &["show", "HEAD:server.pem"]), "KEY-ONE\n");

    // A readable file's content at a commit.
    let old = kit
        .ok(
            "git_show",
            json!({"repo": "proj", "object": "HEAD~1", "path": "app.txt"}),
        )
        .await;
    assert_eq!(text_of(&old), "one\n");
    let blame = text_of(
        &kit.ok("git_blame", json!({"repo": "proj", "path": "app.txt"}))
            .await,
    );
    assert!(blame.contains("Operator") && blame.contains("Agent"), "{blame}");
}

#[tokio::test]
async fn the_work_tree_is_not_moved_over_protected_paths() {
    let kit = Kit::new(&format!(
        "{DESTRUCTIVE}\nread_only_paths = [\"**/locked/**\"]"
    ));
    let dir = project(&kit);
    raw(&dir, &["checkout", "-b", "keys"]);
    kit.write("proj/deploy.key", "NEW-KEY\n");
    raw(&dir, &["add", "-f", "deploy.key"]);
    raw(&dir, &["commit", "-m", "add a key"]);
    raw(&dir, &["checkout", "main"]);
    raw(&dir, &["checkout", "-b", "pinned"]);
    kit.write("proj/locked/version.txt", "2\n");
    raw(&dir, &["add", "."]);
    raw(&dir, &["commit", "-m", "bump"]);
    raw(&dir, &["checkout", "main"]);
    // The operator's own key, untracked, where the branch would write.
    kit.write("proj/deploy.key", "OPERATOR-KEY\n");

    for (tool, args) in [
        ("git_checkout", json!({"repo": "proj", "ref": "keys"})),
        ("git_merge", json!({"repo": "proj", "ref": "keys"})),
        ("git_rebase", json!({"repo": "proj", "ref": "keys"})),
        ("git_cherry_pick", json!({"repo": "proj", "commit": "keys"})),
        (
            "git_reset",
            json!({"repo": "proj", "mode": "hard", "ref": "keys"}),
        ),
        (
            "git_checkout",
            json!({"repo": "proj", "ref": "x", "create": true, "startPoint": "keys"}),
        ),
    ] {
        let err = kit.err(tool, args).await;
        assert!(
            err.starts_with("[permission_denied]") && err.contains("1 path(s) that policy protects"),
            "{tool}: {err}"
        );
        assert!(!err.contains("deploy.key"), "a denied name leaked: {err}");
    }
    assert_eq!(kit.read("proj/deploy.key"), "OPERATOR-KEY\n");
    assert_eq!(raw(&dir, &["branch", "--show-current"]).trim(), "main");

    // Read-only paths are named, because they are not secret.
    let err = kit
        .err("git_merge", json!({"repo": "proj", "ref": "pinned"}))
        .await;
    assert!(err.contains("read-only: locked/version.txt"), "{err}");

    // A patch is held to the same rule.
    let patch = "--- /dev/null\n+++ b/id_rsa\n@@ -0,0 +1 @@\n+KEY\n";
    let err = kit
        .err("git_apply", json!({"repo": "proj", "patch": patch}))
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert!(!kit.exists("proj/id_rsa"));
}

#[tokio::test]
async fn caller_strings_are_never_options() {
    let kit = Kit::new(DESTRUCTIVE);
    project(&kit);
    let target = kit.path("written");
    let option = format!("--output={target}");
    for (tool, args) in [
        ("git_diff", json!({"repo": "proj", "from": option})),
        ("git_diff", json!({"repo": "proj", "from": "HEAD", "to": option})),
        ("git_log", json!({"repo": "proj", "revRange": option})),
        ("git_show", json!({"repo": "proj", "object": option})),
        ("git_blame", json!({"repo": "proj", "path": "app.txt", "ref": option})),
        ("git_checkout", json!({"repo": "proj", "ref": "--orphan"})),
        ("git_checkout", json!({"repo": "proj", "ref": "-f", "create": true})),
        ("git_merge", json!({"repo": "proj", "ref": "--no-verify"})),
        ("git_rebase", json!({"repo": "proj", "ref": "--exec=touch x"})),
        ("git_cherry_pick", json!({"repo": "proj", "commit": "-n"})),
        ("git_reset", json!({"repo": "proj", "ref": "--hard"})),
        ("git_branch", json!({"repo": "proj", "mode": "create", "name": "-D"})),
        ("git_branch", json!({"repo": "proj", "mode": "delete", "name": "--all"})),
        ("git_tag", json!({"repo": "proj", "mode": "create", "name": "-d"})),
        ("git_push", json!({"repo": "proj", "remote": "--receive-pack=x"})),
        ("git_fetch", json!({"repo": "proj", "remote": "--upload-pack=x"})),
        ("git_bisect", json!({"repo": "proj", "action": "good", "rev": "--term-old"})),
        ("git_init", json!({"path": "new", "initialBranch": "--template=/tmp"})),
        ("git_clone", json!({"url": "--upload-pack=touch x", "path": "c"})),
        ("git_clone", json!({"url": "-u", "path": "c"})),
        ("git_clone", json!({"url": "ext::sh", "path": "c"})),
        ("git_clone", json!({"url": "file:///etc", "path": "c"})),
        ("git_clone", json!({"url": "/etc", "path": "c"})),
        ("git_clone", json!({"url": "../outside", "path": "c"})),
        ("git_remote", json!({"repo": "proj", "action": "add", "name": "o", "url": "ext::sh"})),
        ("git_remote", json!({"repo": "proj", "action": "add", "name": "o", "url": "../outside"})),
        ("git_remote", json!({"repo": "proj", "action": "add", "name": "--mirror", "url": "https://example.com/x"})),
        ("git_worktree", json!({"repo": "proj", "action": "add", "path": "wt", "branch": "-B"})),
    ] {
        let err = kit.err(tool, args.clone()).await;
        assert!(
            err.starts_with("[invalid_arguments]") || err.starts_with("[permission_denied]"),
            "{tool} {args}: {err}"
        );
    }
    assert!(!kit.exists("written") && !kit.exists("c") && !kit.exists("new"));

    // A pathspec is literal: no magic, no globbing.
    kit.write("proj/b.txt", "b\n");
    let added = kit
        .json("git_add", json!({"repo": "proj", "paths": [":(glob)**"]}))
        .await;
    assert_eq!(added["staged"], 0);
    let err = kit
        .err("git_add", json!({"repo": "proj", "paths": ["../.."]}))
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
    let err = kit
        .err("git_add", json!({"repo": "proj", "paths": [".git/config"]}))
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
}

#[tokio::test]
async fn a_repository_outside_the_roots_is_not_used() {
    let kit = Kit::new("");
    // The root sits inside a repository whose top is not allowed.
    let above = kit.root.parent().unwrap().to_path_buf();
    raw(&above, &["init"]);
    std::fs::write(above.join("outside/secret.txt"), "s3cret\n").unwrap();
    raw(&above, &["add", "outside/secret.txt"]);
    raw(&above, &["commit", "-m", "outside"]);
    for (tool, args) in [
        ("git_status", json!({})),
        ("git_log", json!({})),
        ("git_show", json!({"path": "outside/secret.txt"})),
        ("git_add", json!({"paths": ["."]})),
    ] {
        let err = kit.err(tool, args).await;
        assert!(err.starts_with("[path_not_allowed]"), "{tool}: {err}");
        assert!(!err.contains("s3cret"), "{err}");
    }
    // The repository's own config is not readable through the file tools.
    let err = kit
        .err("fs_read", json!({"path": kit.path("proj/.git/config")}))
        .await;
    assert!(!err.contains("[core]"), "{err}");
}

#[tokio::test]
async fn destructive_operations_need_the_gate() {
    let kit = Kit::new("");
    let dir = project(&kit);
    raw(&dir, &["branch", "old"]);
    raw(&dir, &["tag", "v0"]);
    kit.write("proj/.gitignore", "build/\n");
    raw(&dir, &["add", ".gitignore"]);
    raw(&dir, &["commit", "-m", "ignore"]);
    kit.write("proj/scratch/a.txt", "a\n");
    kit.write("proj/build/out.o", "o\n");
    kit.write("proj/.env", "TOKEN=1\n");
    raw(&dir, &["remote", "add", "up", "https://user:t0ken@example.com/x.git"]);

    let listing = kit
        .json("git_clean", json!({"repo": "proj", "dryRun": true}))
        .await;
    assert_eq!(listing["paths"], json!(["scratch/a.txt"]));
    assert_eq!(listing["skipped"], 1);
    let remotes = text_of(&kit.ok("git_remote", json!({"repo": "proj"})).await);
    assert_eq!(remotes, "up https://***@example.com/x.git");

    let delete_patch = "--- a/app.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-one\n";
    let gated = [
        ("git_clean", json!({"repo": "proj"})),
        ("git_reset", json!({"repo": "proj", "mode": "hard"})),
        ("git_branch", json!({"repo": "proj", "mode": "delete", "name": "old"})),
        ("git_tag", json!({"repo": "proj", "mode": "delete", "name": "v0"})),
        ("git_stash", json!({"repo": "proj", "mode": "drop"})),
        ("git_remote", json!({"repo": "proj", "action": "remove", "name": "up"})),
        ("git_apply", json!({"repo": "proj", "patch": delete_patch})),
        ("git_push", json!({"repo": "proj", "remote": "up", "force": true})),
        ("git_worktree", json!({"repo": "proj", "action": "remove", "path": "proj"})),
    ];
    for (tool, args) in &gated {
        let err = kit.err(tool, args.clone()).await;
        assert!(
            err.starts_with("[permission_denied]")
                && (err.contains("allow_destructive") || err.contains("allow_network")),
            "{tool}: {err}"
        );
    }
    assert!(kit.exists("proj/scratch/a.txt") && kit.exists("proj/app.txt"));

    kit.reconfigure(DESTRUCTIVE);
    let cleaned = kit
        .json("git_clean", json!({"repo": "proj", "includeIgnored": true}))
        .await;
    assert_eq!(cleaned["count"], 2);
    assert_eq!(cleaned["skipped"], 1);
    assert!(!kit.exists("proj/scratch") && !kit.exists("proj/build"));
    assert_eq!(kit.read("proj/.env"), "TOKEN=1\n", "protected files stay");
    kit.ok(
        "git_branch",
        json!({"repo": "proj", "mode": "delete", "name": "old"}),
    )
    .await;
    kit.ok("git_apply", json!({"repo": "proj", "patch": delete_patch}))
        .await;
    assert!(!kit.exists("proj/app.txt"));
    kit.ok("git_reset", json!({"repo": "proj", "mode": "hard"}))
        .await;
    assert_eq!(kit.read("proj/app.txt"), "one\n");
}

#[tokio::test]
async fn everyday_history_operations() {
    let kit = Kit::new(DESTRUCTIVE);
    let dir = project(&kit);
    let me = |args: Value| with_author(args);

    // Branch, change, commit.
    kit.ok(
        "git_checkout",
        json!({"repo": "proj", "ref": "feature", "create": true}),
    )
    .await;
    kit.write("proj/app.txt", "feature\n");
    kit.write("proj/new.txt", "new\n");
    let added = kit
        .json("git_add", json!({"repo": "proj", "paths": ["app.txt", "new.txt"]}))
        .await;
    assert_eq!(added["staged"], 2);
    let staged = text_of(
        &kit.ok("git_diff", json!({"repo": "proj", "staged": true, "stat": true}))
            .await,
    );
    assert!(staged.contains("app.txt") && staged.contains("new.txt"), "{staged}");
    // Unstage one path again, then put it back.
    kit.ok("git_reset", json!({"repo": "proj", "paths": ["new.txt"]}))
        .await;
    let status = kit.json("git_status", json!({"repo": "proj"})).await;
    assert_eq!(status["files"][1]["unstaged"], "untracked", "{status}");
    kit.json("git_add", json!({"repo": "proj", "paths": ["new.txt"]}))
        .await;
    kit.json("git_commit", me(json!({"repo": "proj", "message": "feature work"})))
        .await;

    // A conflicting change on main.
    kit.ok("git_checkout", json!({"repo": "proj", "ref": "main"}))
        .await;
    kit.write("proj/app.txt", "main\n");
    kit.json("git_commit", me(json!({"repo": "proj", "message": "main work", "all": true})))
        .await;
    let branches = text_of(&kit.ok("git_branch", json!({"repo": "proj"})).await);
    assert!(branches.contains("* main") && branches.contains("feature"), "{branches}");

    let err = kit
        .err("git_merge", json!({"repo": "proj", "ref": "feature"}))
        .await;
    assert!(err.starts_with("[execution]") && err.contains("CONFLICT"), "{err}");
    let status = kit.json("git_status", json!({"repo": "proj"})).await;
    assert!(status["files"].to_string().contains("unmerged"), "{status}");
    kit.ok("git_merge", json!({"repo": "proj", "abort": true}))
        .await;
    assert_eq!(kit.read("proj/app.txt"), "main\n");

    // Resolve it for real: merge, fix, add, commit.
    kit.err("git_merge", json!({"repo": "proj", "ref": "feature"}))
        .await;
    kit.write("proj/app.txt", "merged\n");
    kit.json("git_add", json!({"repo": "proj", "paths": ["app.txt"]}))
        .await;
    kit.json("git_commit", me(json!({"repo": "proj", "message": "merge feature"})))
        .await;
    let log = kit.json("git_log", json!({"repo": "proj", "maxCount": 1})).await;
    assert_eq!(log["commits"][0]["parents"].as_array().unwrap().len(), 2);

    // Diff between commits, stash, tag, revert, reflog.
    let diff = text_of(
        &kit.ok("git_diff", json!({"repo": "proj", "from": "HEAD~1", "to": "HEAD", "path": "new.txt"}))
            .await,
    );
    assert!(diff.contains("+new"), "{diff}");
    kit.write("proj/app.txt", "wip\n");
    kit.ok("git_stash", json!({"repo": "proj", "message": "wip"}))
        .await;
    assert_eq!(kit.read("proj/app.txt"), "merged\n");
    let shown = text_of(&kit.ok("git_stash", json!({"repo": "proj", "mode": "show"})).await);
    assert!(shown.contains("+wip"), "{shown}");
    kit.ok("git_stash", json!({"repo": "proj", "mode": "pop"}))
        .await;
    assert_eq!(kit.read("proj/app.txt"), "wip\n");
    kit.ok("git_reset", json!({"repo": "proj", "mode": "hard"}))
        .await;

    kit.ok("git_tag", json!({"repo": "proj", "mode": "create", "name": "v1"}))
        .await;
    let tags = text_of(&kit.ok("git_tag", json!({"repo": "proj"})).await);
    assert!(tags.starts_with("v1 "), "{tags}");
    kit.ok("git_revert", me(json!({"repo": "proj", "commit": "HEAD~1"})))
        .await;
    assert!(raw(&dir, &["log", "-1", "--format=%s"]).starts_with("Revert"));
    let reflog = text_of(&kit.ok("git_reflog", json!({"repo": "proj", "maxCount": 3})).await);
    assert_eq!(reflog.lines().count(), 3, "{reflog}");

    // A patch produced by git_diff applies with git_apply.
    kit.write("proj/new.txt", "new\nline\n");
    let patch = text_of(&kit.ok("git_diff", json!({"repo": "proj"})).await);
    raw(&dir, &["checkout", "--", "new.txt"]);
    kit.ok("git_apply", json!({"repo": "proj", "patch": patch, "check": true}))
        .await;
    assert_eq!(kit.read("proj/new.txt"), "new\n");
    kit.ok("git_apply", json!({"repo": "proj", "patch": patch}))
        .await;
    assert_eq!(kit.read("proj/new.txt"), "new\nline\n");

    // A second work tree, and bisect bookkeeping that leaves files alone.
    kit.ok(
        "git_worktree",
        json!({"repo": "proj", "action": "add", "path": "wt", "branch": "side"}),
    )
    .await;
    assert!(kit.exists("wt/app.txt"));
    let status = kit.json("git_status", json!({"repo": "wt"})).await;
    assert_eq!(status["branch"], "side");
    kit.ok("git_bisect", json!({"repo": "proj", "action": "start"}))
        .await;
    kit.ok("git_bisect", json!({"repo": "proj", "action": "bad"}))
        .await;
    let step = text_of(
        &kit.ok("git_bisect", json!({"repo": "proj", "action": "good", "rev": "HEAD~3"}))
            .await,
    );
    assert!(step.contains("Bisecting") || step.contains("first bad commit"), "{step}");
    assert_eq!(kit.read("proj/new.txt"), "new\nline\n", "bisect moved the work tree");
    kit.ok("git_bisect", json!({"repo": "proj", "action": "reset"}))
        .await;
}
