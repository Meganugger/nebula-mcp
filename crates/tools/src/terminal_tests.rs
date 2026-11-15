//! `terminal` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]
#![cfg(unix)]

use nebula_mcp_core::OwnerId;
use serde_json::json;

use crate::testkit::{gone, text_of, Kit};

const SH: &str = "allowed_commands = [\"sh\", \"cat\"]";

#[tokio::test]
async fn run_returns_output_streams_and_exit_code() {
    let kit = Kit::new(SH);
    let out = kit
        .ok(
            "terminal_run",
            json!({"program": "sh", "args": ["-c", "echo out; echo err >&2; exit 3"]}),
        )
        .await;
    let text = text_of(&out);
    assert!(
        text.starts_with("out\n\n[stderr]\nerr\n\n[terminal_run: exit code 3 after "),
        "{text}"
    );

    let out = kit
        .ok("terminal_run", json!({"program": "cat", "stdin": "fed in"}))
        .await;
    assert!(text_of(&out).starts_with("fed in\n[terminal_run: exit code 0"));

    // Arguments are not shell-parsed.
    let out = kit
        .ok(
            "terminal_run",
            json!({"program": "sh", "args": ["-c", "printf '%s|' \"$@\"", "sh", "a b", "$HOME;ls"]}),
        )
        .await;
    assert!(
        text_of(&out).starts_with("a b|$HOME;ls|"),
        "{}",
        text_of(&out)
    );
}

#[tokio::test]
async fn only_allowed_programs_run_and_a_same_named_file_does_not_count() {
    let kit = Kit::new(SH);
    let err = kit.err("terminal_run", json!({"program": "ls"})).await;
    assert!(err.starts_with("[command_not_allowed]"), "{err}");
    assert!(err.contains("Allowed commands: sh, cat"), "{err}");

    // A file an agent could have written, named like an allowed program.
    use std::os::unix::fs::PermissionsExt;
    let planted = kit.root.join("sh");
    std::fs::write(&planted, "#!/bin/sh\necho pwned > planted-ran\n").unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();
    for program in [kit.path("sh"), "./sh".to_string()] {
        let err = kit.err("terminal_run", json!({"program": program})).await;
        assert!(err.starts_with("[command_not_allowed]"), "{program}: {err}");
    }
    assert!(!kit.exists("planted-ran"));
    // The allowed name still means the real program.
    let out = kit
        .ok(
            "terminal_run",
            json!({"program": "sh", "args": ["-c", "echo real"]}),
        )
        .await;
    assert!(text_of(&out).starts_with("real\n"));
    assert!(!kit.exists("planted-ran"));

    let none = Kit::new("");
    let err = none.err("terminal_run", json!({"program": "sh"})).await;
    assert!(err.contains("No commands are allowed"), "{err}");
}

#[tokio::test]
async fn environment_and_working_directory_are_policy_checked() {
    let kit = Kit::new(SH);
    let err = kit
        .err(
            "terminal_run",
            json!({"program": "sh", "args": ["-c", "true"], "env": {"LD_PRELOAD": "/x.so"}}),
        )
        .await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("caller_env"),
        "{err}"
    );
    let err = kit
        .err(
            "terminal_run",
            json!({"program": "sh", "args": ["-c", "pwd"], "cwd": kit.outside.to_string_lossy()}),
        )
        .await;
    assert!(err.starts_with("[path_not_allowed]"), "{err}");

    let open = Kit::new("allowed_commands = [\"sh\"]\ncaller_env = [\"GREETING\"]");
    open.write("sub/x", "");
    let out = open
        .ok(
            "terminal_run",
            json!({
                "program": "sh",
                "args": ["-c", "echo $GREETING; pwd"],
                "env": {"GREETING": "hi"},
                "cwd": "sub"
            }),
        )
        .await;
    let text = text_of(&out);
    assert!(
        text.starts_with("hi\n") && text.contains("/root/sub\n"),
        "{text}"
    );
}

#[tokio::test]
async fn a_timeout_stops_the_tree_and_returns_what_was_printed() {
    let kit = Kit::new(SH);
    let out = kit
        .ok(
            "terminal_run",
            json!({
                "program": "sh",
                "args": ["-c", "sleep 300 & echo $! > pid; echo before; wait"],
                "timeoutSecs": 1
            }),
        )
        .await;
    let text = text_of(&out);
    assert!(
        text.starts_with("before\n\n[terminal_run: timed out after "),
        "{text}"
    );
    assert!(
        gone(&kit.read("pid")).await,
        "the background process survived"
    );
}

#[tokio::test]
async fn sessions_are_interactive_and_private_to_their_owner() {
    let kit = Kit::new(SH);
    let opened = kit
        .json("terminal_session_open", json!({"program": "cat"}))
        .await;
    let id = opened["sessionId"].as_str().unwrap().to_string();
    let pid = opened["pid"].as_u64().unwrap().to_string();

    kit.ok(
        "terminal_session_write",
        json!({"sessionId": id, "data": "hello\n"}),
    )
    .await;
    let text = text_of(
        &kit.ok(
            "terminal_session_read",
            json!({"sessionId": id, "waitMs": 5000}),
        )
        .await,
    );
    assert_eq!(
        text,
        "hello\n\n[terminal_session_read: the program is running]"
    );
    let listed = kit.json("terminal_session_list", json!({})).await;
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(listed["sessions"][0]["running"], true);

    // Another client sees nothing and can touch nothing.
    let other = OwnerId::new("someone-else");
    let listed = kit
        .call_as(&other, "terminal_session_list", json!({}))
        .await
        .unwrap();
    assert_eq!(listed.structured.unwrap()["sessions"], json!([]));
    for (tool, args) in [
        ("terminal_session_read", json!({"sessionId": id})),
        (
            "terminal_session_write",
            json!({"sessionId": id, "data": "x"}),
        ),
        ("terminal_session_close", json!({"sessionId": id})),
    ] {
        let failure = kit.call_as(&other, tool, args).await.unwrap_err();
        assert!(
            failure.text.starts_with("[not_found]"),
            "{tool}: {}",
            failure.text
        );
    }

    let text = text_of(
        &kit.ok("terminal_session_close", json!({"sessionId": id}))
            .await,
    );
    assert!(text.contains("the program has exited"), "{text}");
    assert!(gone(&pid).await, "the session's process survived the close");
    let err = kit
        .err("terminal_session_read", json!({"sessionId": id}))
        .await;
    assert!(err.starts_with("[not_found]"), "{err}");
}

#[tokio::test]
async fn sessions_are_limited_and_die_with_their_owner_or_the_server() {
    let kit = Kit::with_config(SH, "[limits]\nmax_terminal_sessions = 1");
    let script = "sleep 300 & echo $! > pid; wait";
    let opened = kit
        .json(
            "terminal_session_open",
            json!({"program": "sh", "args": ["-c", script]}),
        )
        .await;
    let err = kit
        .err("terminal_session_open", json!({"program": "cat"}))
        .await;
    assert!(err.starts_with("[limit_exceeded]"), "{err}");
    // The limit is per owner.
    let other = OwnerId::new("other");
    let theirs = kit
        .call_as(&other, "terminal_session_open", json!({"program": "cat"}))
        .await
        .unwrap()
        .structured
        .unwrap();

    let grandchild = kit.wait_for_file("pid").await;
    kit.state.close_owner(&OwnerId::stdio()).await;
    assert!(gone(&grandchild).await, "the tree survived its owner");
    assert!(gone(&opened["pid"].to_string()).await);
    assert_eq!(
        kit.state.open_sessions(),
        1,
        "the other owner's session is untouched"
    );

    kit.state.stop_all().await;
    assert!(gone(&theirs["pid"].to_string()).await);
    assert_eq!(kit.state.open_sessions(), 0);
}

#[tokio::test]
async fn a_session_is_closed_when_policy_no_longer_allows_its_program() {
    let kit = Kit::new(SH);
    let opened = kit
        .json("terminal_session_open", json!({"program": "cat"}))
        .await;
    let id = opened["sessionId"].as_str().unwrap();
    kit.reconfigure("allowed_commands = [\"sh\"]");
    let err = kit
        .err(
            "terminal_session_write",
            json!({"sessionId": id, "data": "x\n"}),
        )
        .await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("was closed"),
        "{err}"
    );
    assert!(gone(&opened["pid"].to_string()).await);
    assert_eq!(kit.state.open_sessions(), 0);
}
