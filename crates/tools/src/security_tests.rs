//! `security` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]

use serde_json::{json, Value};

use crate::testkit::{write_outside, Kit};

#[tokio::test]
async fn path_checks_answer_like_the_file_tools_without_touching_anything() {
    let kit = Kit::new("read_only_paths = [\"**/locked/**\"]");
    kit.write("notes.txt", "n");
    kit.write("locked/a.txt", "a");
    kit.write(".env", "TOKEN=1");
    let outside = write_outside(&kit.outside, "secret.txt", "s3cret");

    let ok = kit
        .json("security_check_path", json!({"path": "notes.txt"}))
        .await;
    assert_eq!(ok["allowed"], true);
    assert_eq!(ok["resolved"], kit.root.join("notes.txt").display().to_string());

    let write = json!({"path": "locked/a.txt", "access": "write"});
    let refused = kit.json("security_check_path", write.clone()).await;
    assert_eq!(refused["allowed"], false);
    assert!(refused["reason"].as_str().unwrap().contains("read-only"), "{refused}");
    assert_eq!(
        kit.json("security_check_path", json!({"path": "locked/a.txt"})).await["allowed"],
        true
    );
    // The answer matches what the real tool does.
    let err = kit
        .err("fs_write", json!({"path": "locked/a.txt", "content": "x"}))
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert_eq!(kit.read("locked/a.txt"), "a", "the dry run wrote nothing");

    for path in [".env".to_string(), outside.display().to_string()] {
        let refused = kit
            .json("security_check_path", json!({"path": path}))
            .await;
        assert_eq!(refused["allowed"], false, "{refused}");
        assert_eq!(refused["resolved"], Value::Null);
        assert!(!refused.to_string().contains("s3cret"));
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, kit.root.join("link")).unwrap();
        let refused = kit
            .json("security_check_path", json!({"path": "link"}))
            .await;
        assert_eq!(refused["allowed"], false, "a symlink out of the root: {refused}");
    }

    let err = kit
        .err("security_check_path", json!({"path": "x", "tool": "no_such_tool"}))
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn command_checks_name_the_file_that_would_run() {
    let kit = Kit::new("allowed_commands = [\"sh\"]");
    let ok = kit
        .json("security_check_command", json!({"program": "sh"}))
        .await;
    assert_eq!(ok["allowed"], true);
    assert!(ok["resolved"].as_str().unwrap().ends_with("/sh"), "{ok}");

    // A file named like an allowed program, where the agent can write.
    kit.write("sh", "#!/bin/sh\necho planted\n");
    for program in [kit.path("sh"), "./sh".to_string(), "ls".to_string()] {
        let refused = kit
            .json("security_check_command", json!({"program": program}))
            .await;
        assert_eq!(refused["allowed"], false, "{program}: {refused}");
    }
    let refused = kit
        .json(
            "security_check_command",
            json!({"program": "sh", "tool": "fs_read"}),
        )
        .await;
    assert_eq!(refused["allowed"], false, "{refused}");
}

#[tokio::test]
async fn the_effective_policy_follows_overrides_and_the_review_flags_risk() {
    let kit = Kit::with_config(
        "allowed_commands = [\"*\"]\nallow_private_network = true",
        "[tools.fs_delete]\nallow_destructive = true\n[tools.fs_copy]\nenabled = false",
    );
    let base = kit.json("security_effective_policy", json!({})).await;
    assert_eq!(base["tool"], Value::Null);
    assert_eq!(base["allowDestructive"], false);
    assert_eq!(base["allowNetwork"], false);
    assert_eq!(base["allowedCommands"], json!(["*"]));
    assert_eq!(
        base["allowedPaths"],
        json!([kit.root.display().to_string()])
    );
    assert_eq!(base["sandbox"], "off");

    let delete = kit
        .json("security_effective_policy", json!({"tool": "fs_delete"}))
        .await;
    assert_eq!(delete["allowDestructive"], true);
    assert_eq!(delete["exposed"], true);
    let copy = kit
        .json("security_effective_policy", json!({"tool": "fs_copy"}))
        .await;
    assert_eq!(copy["exposed"], false);

    let review = kit.json("security_baseline", json!({})).await;
    let text = review["findings"].to_string();
    assert!(text.contains("allows every program"), "{text}");
    assert!(text.contains("allow_private_network"), "{text}");
    assert!(text.contains("root-equivalent"), "docker is enabled in the kit: {text}");
    assert!(text.contains("not confined by the operating system"), "{text}");
    assert!(review["warnings"].as_u64().unwrap() >= 3);
    assert_eq!(review["findings"][0]["level"], "warning");

    kit.reconfigure("allowed_commands = [\"sh\", \"cat\"]");
    let review = kit.json("security_baseline", json!({})).await;
    let text = review["findings"].to_string();
    assert!(text.contains("sh can run arbitrary code"), "{text}");
    assert!(!text.contains("allows every program"), "{text}");
}
