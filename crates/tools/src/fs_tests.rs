//! `fs` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]

use serde_json::json;

use crate::testkit::{text_of, write_outside, Kit};

#[tokio::test]
async fn read_returns_text_and_continues_in_chunks_on_character_boundaries() {
    let kit = Kit::new("");
    kit.write("a.txt", "héllo wörld");
    let whole = kit.ok("fs_read", json!({"path": "a.txt"})).await;
    assert_eq!(text_of(&whole), "héllo wörld");

    // "hé" is 3 bytes; a 2-byte chunk would cut the é in half.
    let first = kit
        .ok("fs_read", json!({"path": "a.txt", "maxBytes": 2}))
        .await;
    let text = text_of(&first);
    assert!(text.starts_with("h\n[fs_read: bytes 0-1 of 13."), "{text}");
    assert!(text.contains("offset = 1"), "{text}");
    let rest = kit
        .ok("fs_read", json!({"path": "a.txt", "offset": 1}))
        .await;
    assert!(text_of(&rest).starts_with("éllo wörld\n[fs_read: bytes 1-13 of 13; end of file]"));
    // An offset inside a character moves forward to the next one.
    let mid = kit
        .ok("fs_read", json!({"path": "a.txt", "offset": 2}))
        .await;
    assert!(text_of(&mid).starts_with("llo wörld"), "{}", text_of(&mid));
}

#[tokio::test]
async fn read_handles_binary_through_base64_only() {
    let kit = Kit::new("");
    std::fs::write(kit.root.join("b.bin"), [0u8, 159, 146, 150]).unwrap();
    let err = kit.err("fs_read", json!({"path": "b.bin"})).await;
    assert!(
        err.starts_with("[invalid_arguments]") && err.contains("base64"),
        "{err}"
    );
    let out = kit
        .ok("fs_read", json!({"path": "b.bin", "encoding": "base64"}))
        .await;
    assert_eq!(text_of(&out), "AJ+Slg==");
    kit.write("empty", "");
    let out = kit.ok("fs_read", json!({"path": kit.path("empty")})).await;
    assert_eq!(text_of(&out), "\n[fs_read: the file is empty]");
}

#[tokio::test]
async fn paths_outside_the_root_and_denied_files_are_refused() {
    let kit = Kit::new("");
    let secret = write_outside(&kit.outside, "secret.txt", "TOP");
    kit.write(".env", "TOKEN=1");
    kit.write("ok.txt", "fine");

    let err = kit
        .err("fs_read", json!({"path": secret.to_string_lossy()}))
        .await;
    assert!(err.starts_with("[path_not_allowed]"), "{err}");
    assert!(err.contains("Allowed directories:"), "{err}");
    let err = kit
        .err("fs_read", json!({"path": "../outside/secret.txt"}))
        .await;
    assert!(err.starts_with("[path_not_allowed]"), "{err}");
    let err = kit.err("fs_read", json!({"path": ".env"})).await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert!(!err.contains("TOKEN"));
    for tool in ["fs_write", "fs_append"] {
        let err = kit
            .err(tool, json!({"path": ".env.local", "content": "x"}))
            .await;
        assert!(err.starts_with("[permission_denied]"), "{tool}: {err}");
    }
    let err = kit
        .err(
            "fs_write",
            json!({"path": ".git/hooks/pre-commit", "content": "x"}),
        )
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert!(!kit.exists(".git"));
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_do_not_lead_out_of_the_root() {
    use std::os::unix::fs::symlink;
    let kit = Kit::new("allow_destructive = true");
    let secret = write_outside(&kit.outside, "secret.txt", "TOP");
    symlink(&secret, kit.root.join("link")).unwrap();
    symlink(&kit.outside, kit.root.join("dirlink")).unwrap();
    kit.write(".env", "TOKEN=1");
    symlink(kit.root.join(".env"), kit.root.join("innocent")).unwrap();

    for path in ["link", "dirlink/secret.txt"] {
        let err = kit.err("fs_read", json!({"path": path})).await;
        assert!(err.starts_with("[path_not_allowed]"), "{path}: {err}");
        assert!(!err.contains("TOP"));
    }
    let err = kit.err("fs_read", json!({"path": "innocent"})).await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    let err = kit
        .err(
            "fs_write",
            json!({"path": "dirlink/new.txt", "content": "x"}),
        )
        .await;
    assert!(err.starts_with("[path_not_allowed]"), "{err}");
    assert!(!kit.outside.join("new.txt").exists());

    // Copying and searching a tree never follow the links.
    std::fs::create_dir(kit.root.join("tree")).unwrap();
    symlink(&secret, kit.root.join("tree/link")).unwrap();
    symlink(&kit.outside, kit.root.join("tree/dirlink")).unwrap();
    kit.write("tree/plain.txt", "plain");
    let copied = kit
        .json("fs_copy", json!({"from": "tree", "to": "copy"}))
        .await;
    assert_eq!(
        (copied["files"].as_u64(), copied["skipped"].as_u64()),
        (Some(1), Some(2)),
        "{copied}"
    );
    let found = kit
        .ok("fs_search", json!({"root": ".", "pattern": "TOP|TOKEN"}))
        .await;
    assert!(
        text_of(&found).starts_with("\n[fs_search: 0 matching lines"),
        "{}",
        text_of(&found)
    );
    // Deleting a tree removes links, not what they point to.
    kit.ok("fs_delete", json!({"path": "tree", "recursive": true}))
        .await;
    assert!(secret.exists() && kit.outside.exists());
}

#[tokio::test]
async fn write_creates_replaces_and_decodes() {
    let kit = Kit::new("");
    let out = kit
        .json("fs_write", json!({"path": "a/b/c.txt", "content": "one"}))
        .await;
    assert_eq!(out["created"], true);
    assert_eq!(out["bytes"], 3);
    let out = kit
        .json("fs_write", json!({"path": "a/b/c.txt", "content": "two"}))
        .await;
    assert_eq!(out["created"], false);
    assert_eq!(kit.read("a/b/c.txt"), "two");

    let err = kit
        .err(
            "fs_write",
            json!({"path": "x/y.txt", "content": "z", "createParents": false}),
        )
        .await;
    assert!(err.starts_with("[not_found]"), "{err}");
    let err = kit
        .err("fs_write", json!({"path": "a", "content": "z"}))
        .await;
    assert!(err.contains("is a directory"), "{err}");

    kit.ok(
        "fs_write",
        json!({"path": "bin", "content": "AJ+S\nlg==", "encoding": "base64"}),
    )
    .await;
    assert_eq!(
        std::fs::read(kit.root.join("bin")).unwrap(),
        [0, 159, 146, 150]
    );
    let err = kit
        .err(
            "fs_write",
            json!({"path": "bin", "content": "%%%", "encoding": "base64"}),
        )
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
}

#[tokio::test]
async fn edit_replaces_exactly_what_was_asked_or_nothing() {
    let kit = Kit::new("");
    kit.write("f.txt", "alpha beta alpha gamma");

    let out = kit
        .json(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "beta", "newString": "BETA"}),
        )
        .await;
    assert_eq!(out["replacements"], 1);
    assert_eq!(kit.read("f.txt"), "alpha BETA alpha gamma");

    let err = kit
        .err(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "alpha", "newString": "x"}),
        )
        .await;
    assert!(
        err.contains("occurs 2 times") && err.contains("expectedCount = 2"),
        "{err}"
    );
    let err = kit
        .err(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "alpha", "newString": "x", "expectedCount": 3}),
        )
        .await;
    assert!(err.contains("found 2"), "{err}");
    let err = kit
        .err(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "missing", "newString": "x"}),
        )
        .await;
    assert!(err.contains("was not found"), "{err}");
    assert_eq!(
        kit.read("f.txt"),
        "alpha BETA alpha gamma",
        "failed edits change nothing"
    );

    let out = kit
        .json(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "alpha", "newString": "A", "replaceAll": true}),
        )
        .await;
    assert_eq!(out["replacements"], 2);
    assert_eq!(kit.read("f.txt"), "A BETA A gamma");
    let err = kit
        .err(
            "fs_edit",
            json!({"path": "f.txt", "oldString": "", "newString": "x"}),
        )
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
}

#[tokio::test]
async fn append_and_mkdir() {
    let kit = Kit::new("");
    let out = kit
        .json("fs_append", json!({"path": "log.txt", "content": "a\n"}))
        .await;
    assert_eq!(out["size"], 2);
    let out = kit
        .json("fs_append", json!({"path": "log.txt", "content": "b\n"}))
        .await;
    assert_eq!(
        (out["bytesAppended"].as_u64(), out["size"].as_u64()),
        (Some(2), Some(4))
    );
    assert_eq!(kit.read("log.txt"), "a\nb\n");

    let out = kit.json("fs_mkdir", json!({"path": "d/e/f"})).await;
    assert_eq!(out["created"], true);
    let out = kit.json("fs_mkdir", json!({"path": "d/e/f"})).await;
    assert_eq!(out["created"], false);
    let err = kit
        .err("fs_mkdir", json!({"path": "q/r", "parents": false}))
        .await;
    assert!(err.starts_with("[not_found]"), "{err}");
    let err = kit.err("fs_mkdir", json!({"path": "log.txt"})).await;
    assert!(err.contains("not a directory"), "{err}");
}

#[tokio::test]
async fn rename_move_and_copy_never_replace_silently() {
    let kit = Kit::new("");
    kit.write("a.txt", "A");
    kit.write("b.txt", "B");

    let err = kit
        .err("fs_rename", json!({"from": "a.txt", "to": "b.txt"}))
        .await;
    assert!(err.contains("already exists"), "{err}");
    for tool in ["fs_move", "fs_copy"] {
        let err = kit.err(tool, json!({"from": "a.txt", "to": "b.txt"})).await;
        assert!(
            err.contains("already exists") && err.contains("overwrite"),
            "{tool}: {err}"
        );
        // Replacing is destructive, and the gate is off.
        let err = kit
            .err(
                tool,
                json!({"from": "a.txt", "to": "b.txt", "overwrite": true}),
            )
            .await;
        assert!(err.starts_with("[permission_denied]"), "{tool}: {err}");
        assert!(err.contains("allow_destructive"), "{err}");
    }
    assert_eq!(kit.read("b.txt"), "B");

    kit.ok("fs_rename", json!({"from": "a.txt", "to": "c.txt"}))
        .await;
    assert!(!kit.exists("a.txt"));
    kit.ok("fs_move", json!({"from": "c.txt", "to": "./d.txt"}))
        .await;
    assert_eq!(kit.read("d.txt"), "A");
    let out = kit
        .json("fs_copy", json!({"from": "d.txt", "to": "e.txt"}))
        .await;
    assert_eq!(
        (out["files"].as_u64(), out["bytes"].as_u64()),
        (Some(1), Some(1))
    );

    let open = Kit::new("allow_destructive = true");
    open.write("a.txt", "A");
    open.write("b.txt", "B");
    open.ok(
        "fs_copy",
        json!({"from": "a.txt", "to": "b.txt", "overwrite": true}),
    )
    .await;
    assert_eq!(open.read("b.txt"), "A");
    open.write("b.txt", "B");
    open.ok(
        "fs_move",
        json!({"from": "a.txt", "to": "b.txt", "overwrite": true}),
    )
    .await;
    assert_eq!(open.read("b.txt"), "A");
    assert!(!open.exists("a.txt"));
}

#[tokio::test]
async fn copying_a_directory_skips_protected_files_and_refuses_recursion() {
    let kit = Kit::new("");
    kit.write("src/one.txt", "1");
    kit.write("src/deep/two.txt", "22");
    kit.write("src/.env", "S=1");
    kit.write("src/id_rsa", "KEY");

    let out = kit
        .json("fs_copy", json!({"from": "src", "to": "dst"}))
        .await;
    assert_eq!(out["files"], 2);
    assert_eq!(out["skipped"], 2);
    assert!(kit.exists("dst/deep/two.txt"));
    assert!(!kit.exists("dst/.env") && !kit.exists("dst/id_rsa"));

    let err = kit
        .err("fs_copy", json!({"from": "src", "to": "src/deep/again"}))
        .await;
    assert!(
        err.starts_with("[invalid_arguments]") && err.contains("into itself"),
        "{err}"
    );
    let err = kit
        .err("fs_move", json!({"from": "src", "to": "src/deep/again"}))
        .await;
    assert!(
        err.contains("into itself") || err.starts_with("[permission_denied]"),
        "{err}"
    );
}

#[tokio::test]
async fn delete_needs_the_destructive_gate_and_respects_protected_entries() {
    let closed = Kit::new("");
    closed.write("a.txt", "A");
    let err = closed.err("fs_delete", json!({"path": "a.txt"})).await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_destructive"),
        "{err}"
    );
    assert!(closed.exists("a.txt"));

    let kit = Kit::new("allow_destructive = true");
    kit.write("a.txt", "A");
    kit.write("d/x.txt", "x");
    kit.write("p/keep/.env", "S=1");
    let out = kit.json("fs_delete", json!({"path": "a.txt"})).await;
    assert_eq!(out["type"], "file");
    let err = kit.err("fs_delete", json!({"path": "d"})).await;
    assert!(err.contains("recursive = true"), "{err}");
    kit.ok("fs_delete", json!({"path": "d", "recursive": true}))
        .await;
    assert!(!kit.exists("d"));

    let err = kit
        .err("fs_delete", json!({"path": "p", "recursive": true}))
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert!(kit.exists("p/keep/.env"));
    let err = kit.err("fs_move", json!({"from": "p", "to": "q"})).await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    let err = kit
        .err("fs_delete", json!({"path": ".", "recursive": true}))
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    let err = kit.err("fs_delete", json!({"path": "nope"})).await;
    assert!(err.starts_with("[not_found]"), "{err}");
}

#[tokio::test]
async fn search_reports_lines_and_never_reads_protected_files() {
    let kit = Kit::new("");
    kit.write("src/a.rs", "fn main() {}\nlet needle = 1;\n");
    kit.write("src/b.txt", "Needle in text\n");
    kit.write(".env", "needle=secret-value\n");
    kit.write("keys/id_ed25519", "needle\n");
    std::fs::write(kit.root.join("blob.bin"), b"needle\0binary").unwrap();

    let out = kit
        .ok("fs_search", json!({"root": ".", "pattern": "needle"}))
        .await;
    let text = text_of(&out);
    assert!(text.contains("src/a.rs:2: let needle = 1;"), "{text}");
    assert!(
        !text.contains("secret-value") && !text.contains(".env:"),
        "{text}"
    );
    assert!(
        !text.contains("id_ed25519:") && !text.contains("blob.bin"),
        "{text}"
    );
    assert!(text.contains("1 matching lines in 1 of"), "{text}");
    assert!(
        text.contains("skipped because policy protects them"),
        "{text}"
    );

    let out = kit
        .ok(
            "fs_search",
            json!({"root": ".", "pattern": "needle", "ignoreCase": true, "glob": "**/*.txt"}),
        )
        .await;
    let text = text_of(&out);
    assert!(
        text.contains("src/b.txt:1: Needle in text") && !text.contains("a.rs"),
        "{text}"
    );

    for i in 0..20 {
        kit.write(&format!("many/{i}.txt"), "hit\nhit\n");
    }
    let out = kit
        .ok(
            "fs_search",
            json!({"root": "many", "pattern": "hit", "maxResults": 5}),
        )
        .await;
    let text = text_of(&out);
    assert_eq!(text.matches(": hit").count(), 5, "{text}");
    assert!(text.contains("stopped at a limit"), "{text}");

    let err = kit
        .err("fs_search", json!({"root": ".", "pattern": "("}))
        .await;
    assert!(
        err.starts_with("[invalid_arguments]") && err.contains("regular expression"),
        "{err}"
    );
}

#[tokio::test]
async fn glob_and_tree_hide_protected_names() {
    // Not "private": macOS temp directories live under /private.
    let kit = Kit::new("denied_paths = [\"**/vault/**\"]");
    kit.write("src/a.rs", "");
    kit.write("src/nested/b.rs", "");
    kit.write("src/.env", "");
    kit.write("vault/key.rs", "");
    kit.write("README.md", "hello");

    let out = kit
        .json("fs_glob", json!({"root": ".", "pattern": "**/*.rs"}))
        .await;
    assert_eq!(out["matches"], json!(["src/a.rs", "src/nested/b.rs"]));
    assert_eq!(out["hidden"], 2);
    assert_eq!(out["truncated"], false);
    let out = kit
        .json("fs_glob", json!({"root": "src", "pattern": "*.rs"}))
        .await;
    assert_eq!(
        out["matches"],
        json!(["a.rs"]),
        "* does not cross a separator"
    );
    let out = kit
        .json(
            "fs_glob",
            json!({"root": ".", "pattern": "**/*", "maxResults": 2}),
        )
        .await;
    assert_eq!(out["matches"].as_array().unwrap().len(), 2);
    assert_eq!(out["truncated"], true);

    let text = text_of(&kit.ok("fs_tree", json!({"path": "."})).await);
    assert!(text.contains("  README.md (5 bytes)\n"), "{text}");
    assert!(
        text.contains("  src/\n    a.rs (0 bytes)\n    nested/\n      b.rs (0 bytes)\n"),
        "{text}"
    );
    assert!(
        !text.contains(".env") && !text.contains("vault"),
        "{text}"
    );
    assert!(
        text.contains("2 not shown because policy protects them"),
        "{text}"
    );
    let text = text_of(&kit.ok("fs_tree", json!({"path": ".", "maxDepth": 1})).await);
    assert!(text.contains("src/") && !text.contains("a.rs"), "{text}");
    let text = text_of(
        &kit.ok("fs_tree", json!({"path": ".", "maxEntries": 1}))
            .await,
    );
    assert!(text.contains("stopped at a limit"), "{text}");
}

#[tokio::test]
async fn hash_metadata_and_permissions() {
    let kit = Kit::new("");
    kit.write("h.txt", "abc");
    let out = kit.json("fs_hash", json!({"path": "h.txt"})).await;
    assert_eq!(
        out["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(out["size"], 3);

    let meta = kit.json("fs_metadata", json!({"path": "h.txt"})).await;
    assert_eq!(
        (meta["type"].as_str(), meta["size"].as_u64()),
        (Some("file"), Some(3))
    );
    assert!(meta["modified"].as_str().unwrap().ends_with('Z'));
    let meta = kit.json("fs_metadata", json!({"path": "."})).await;
    assert_eq!(meta["type"], "dir");

    let out = kit
        .json("fs_permissions", json!({"path": "h.txt", "readonly": true}))
        .await;
    assert_eq!(out["readonly"], true);
    let out = kit
        .json(
            "fs_permissions",
            json!({"path": "h.txt", "readonly": false}),
        )
        .await;
    assert_eq!(out["readonly"], false);
    let err = kit.err("fs_permissions", json!({"path": "h.txt"})).await;
    assert!(err.contains("fs_metadata"), "{err}");
    let err = kit
        .err("fs_permissions", json!({"path": "h.txt", "mode": "9z"}))
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");

    #[cfg(unix)]
    {
        let out = kit
            .json("fs_permissions", json!({"path": "h.txt", "mode": "0640"}))
            .await;
        assert_eq!(out["mode"], "0640");
    }
}

#[tokio::test]
async fn arguments_are_checked_against_the_schema_first() {
    let kit = Kit::new("");
    let err = kit.err("fs_read", json!({"path": "a", "ofset": 1})).await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
    assert!(err.contains("did you mean \"offset\"?"), "{err}");
    let err = kit.err("fs_read", json!({"path": 7})).await;
    assert!(err.contains("args.path: expected a string"), "{err}");
    let err = kit.err("fs_read", json!({})).await;
    assert!(err.contains("required property is missing"), "{err}");
    let err = kit
        .err("fs_read", json!({"path": "a", "encoding": "latin1"}))
        .await;
    assert!(err.contains("must be one of"), "{err}");
    let err = kit
        .err("fs_tree", json!({"path": ".", "maxDepth": 99}))
        .await;
    assert!(err.contains("at most 32"), "{err}");
}
