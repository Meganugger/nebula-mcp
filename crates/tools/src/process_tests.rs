//! `process` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]

use nebula_mcp_core::OwnerId;
use serde_json::json;

use crate::testkit::Kit;

#[tokio::test]
async fn listing_and_inspecting_report_names_and_numbers_only() {
    let kit = Kit::new("");
    let me = u64::from(std::process::id());
    let info = kit.json("process_info", json!({})).await;
    assert_eq!(info["pid"], me);
    assert!(info["memoryBytes"].as_u64().unwrap() > 0, "{info}");
    assert!(info["startedAt"].is_string(), "{info}");
    assert_eq!(info["inMySessions"], false);
    assert!(info.get("commandLine").is_none() && info.get("environment").is_none());

    let name = info["name"].as_str().unwrap().to_string();
    let listed = kit
        .json(
            "process_list",
            json!({"nameContains": name[..name.len().min(6)].to_uppercase(), "limit": 500}),
        )
        .await;
    let found = listed["processes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["pid"] == me);
    assert!(found, "the server is in its own listing: {listed}");
    assert!(listed["total"].as_u64().unwrap() >= 1);

    let one = kit.json("process_list", json!({"limit": 1})).await;
    assert_eq!(one["processes"].as_array().unwrap().len(), 1);
    assert!(one["total"].as_u64().unwrap() > 1);

    let err = kit
        .err("process_info", json!({"pid": 4_000_000_000u64}))
        .await;
    assert!(err.starts_with("[not_found]"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn kill_reaches_the_callers_sessions_and_nothing_else() {
    use crate::testkit::{gone, text_of};

    let kit = Kit::new("allowed_commands = [\"sh\"]\nallow_destructive = true");
    let me = u64::from(std::process::id());
    let alice = OwnerId::new("alice");
    let mallory = OwnerId::new("mallory");

    // A session with a child of its own.
    let opened = kit
        .call_as(
            &alice,
            "terminal_session_open",
            json!({"program": "sh", "args": ["-c", "sleep 300 & echo $!; wait"]}),
        )
        .await
        .unwrap()
        .structured
        .unwrap();
    let session = opened["sessionId"].as_str().unwrap().to_string();
    let shell = opened["pid"].as_u64().unwrap();
    let read = kit
        .call_as(
            &alice,
            "terminal_session_read",
            json!({"sessionId": session, "waitMs": 5000}),
        )
        .await
        .unwrap();
    let sleeper: u64 = text_of(&read)
        .lines()
        .next()
        .unwrap()
        .trim()
        .parse()
        .expect("the shell printed the pid of its child");

    // Not the server, not init, not a stranger's process, not another
    // client's session.
    for pid in [me, 1] {
        let err = kit
            .call_as(&alice, "process_kill", json!({"pid": pid, "force": true}))
            .await
            .unwrap_err()
            .text;
        assert!(err.starts_with("[permission_denied]"), "{pid}: {err}");
    }
    for pid in [shell, sleeper] {
        let err = kit
            .call_as(&mallory, "process_kill", json!({"pid": pid, "force": true}))
            .await
            .unwrap_err()
            .text;
        assert!(err.starts_with("[permission_denied]"), "{pid}: {err}");
    }
    let listed = kit
        .call_as(
            &alice,
            "process_list",
            json!({"nameContains": "sleep", "limit": 500}),
        )
        .await
        .unwrap()
        .structured
        .unwrap();
    let marked = listed["processes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["pid"] == sleeper)
        .expect("the sleeper is listed");
    assert_eq!(marked["inMySessions"], true);

    // The owner can stop a process inside the session.
    let out = kit
        .call_as(&alice, "process_kill", json!({"pid": sleeper}))
        .await
        .unwrap();
    assert!(text_of(&out).contains("asked to exit"), "{}", text_of(&out));
    assert!(gone(&sleeper.to_string()).await);

    // The gate is checked before anything else.
    kit.reconfigure("allowed_commands = [\"sh\"]");
    let err = kit
        .call_as(&alice, "process_kill", json!({"pid": shell}))
        .await
        .unwrap_err()
        .text;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_destructive"),
        "{err}"
    );
}
