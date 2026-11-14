//! `scheduler` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]
#![cfg(unix)]

use std::time::{Duration, Instant};

use nebula_mcp_core::OwnerId;
use serde_json::{json, Value};

use crate::testkit::{gone, text_of, Kit};

const SH: &str = "allowed_commands = [\"sh\"]";

/// Poll `scheduler_results` until `done` accepts the text.
async fn results_when(kit: &Kit, id: &str, done: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = text_of(&kit.ok("scheduler_results", json!({"jobId": id})).await);
        if done(&text) {
            return text;
        }
        assert!(Instant::now() < deadline, "job never got there: {text}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn id_of(job: &Value) -> String {
    job["jobId"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_job_runs_once_and_keeps_its_output() {
    let kit = Kit::new(SH);
    let job = kit
        .json(
            "scheduler_after",
            json!({"program": "sh", "args": ["-c", "echo ran-later"], "delaySecs": 0}),
        )
        .await;
    assert_eq!((job["kind"].as_str(), job["runs"].as_u64()), (Some("once"), Some(0)));
    let text = results_when(&kit, &id_of(&job), |t| t.contains("is finished")).await;
    assert!(text.contains("--- run 1 at ") && text.contains("ran-later"), "{text}");
    assert!(text.contains("exit code 0"), "{text}");
    let listed = kit.json("scheduler_list", json!({})).await;
    assert_eq!(listed["jobs"][0]["state"], "finished");
    assert_eq!(listed["jobs"][0]["runs"], 1);
}

#[tokio::test]
async fn a_repeating_job_stops_at_its_run_limit() {
    let kit = Kit::new(SH);
    let job = kit
        .json(
            "scheduler_every",
            json!({"program": "sh", "args": ["-c", "echo tick"], "intervalSecs": 5, "maxRuns": 2}),
        )
        .await;
    assert_eq!(job["kind"], "repeating");
    let text = results_when(&kit, &id_of(&job), |t| t.contains("is finished")).await;
    assert!(text.contains("--- run 2 at ") && text.contains("2 runs so far"), "{text}");
}

#[tokio::test]
async fn scheduling_is_refused_when_running_would_be() {
    let kit = Kit::new(SH);
    let err = kit
        .err("scheduler_after", json!({"program": "ls", "delaySecs": 0}))
        .await;
    assert!(err.starts_with("[command_not_allowed]"), "{err}");
    let err = kit
        .err("scheduler_every", json!({"program": "sh", "intervalSecs": 1}))
        .await;
    assert!(err.starts_with("[invalid_arguments]") && err.contains("at least 5"), "{err}");

    let alone = Kit::with_categories(&["scheduler"], SH);
    let err = alone
        .err("scheduler_after", json!({"program": "sh", "delaySecs": 0}))
        .await;
    assert!(err.starts_with("[permission_denied]") && err.contains("terminal"), "{err}");
}

#[tokio::test]
async fn a_job_is_checked_again_when_it_fires() {
    let kit = Kit::new(SH);
    let job = kit
        .json(
            "scheduler_after",
            json!({"program": "sh", "args": ["-c", "echo should-not-run > marker"], "delaySecs": 1}),
        )
        .await;
    // The operator tightens the policy before the job fires.
    kit.reconfigure("allowed_commands = []");
    let text = results_when(&kit, &id_of(&job), |t| t.contains("is finished")).await;
    assert!(text.contains("[command_not_allowed]"), "{text}");
    assert!(text.contains("refused or failed"), "{text}");
    assert!(!kit.exists("marker"));
}

#[tokio::test]
async fn cancelling_a_job_stops_its_running_tree() {
    let kit = Kit::new(SH);
    let job = kit
        .json(
            "scheduler_after",
            json!({
                "program": "sh",
                "args": ["-c", "sleep 300 & echo $! > pid; wait"],
                "delaySecs": 0
            }),
        )
        .await;
    let pid = kit.wait_for_file("pid").await;
    let cancelled = kit.json("scheduler_cancel", json!({"jobId": id_of(&job)})).await;
    assert_eq!(cancelled["state"], "cancelled");
    assert!(gone(&pid).await, "the job's process tree survived the cancel");
}

#[tokio::test]
async fn jobs_are_limited_and_private_to_their_owner() {
    let kit = Kit::with_config(SH, "[limits]\nmax_scheduled_jobs = 1");
    let job = kit
        .json(
            "scheduler_after",
            json!({"program": "sh", "args": ["-c", "true"], "delaySecs": 3600}),
        )
        .await;
    let err = kit
        .err("scheduler_after", json!({"program": "sh", "delaySecs": 3600}))
        .await;
    assert!(err.starts_with("[limit_exceeded]"), "{err}");

    let other = OwnerId::new("other");
    let listed = kit.call_as(&other, "scheduler_list", json!({})).await.unwrap();
    assert_eq!(listed.structured.unwrap()["jobs"], json!([]));
    for tool in ["scheduler_results", "scheduler_cancel"] {
        let failure = kit
            .call_as(&other, tool, json!({"jobId": id_of(&job)}))
            .await
            .unwrap_err();
        assert!(failure.text.starts_with("[not_found]"), "{tool}: {}", failure.text);
    }
    // When the owner goes away, so do its jobs.
    kit.state.close_owner(&OwnerId::stdio()).await;
    let listed = kit.json("scheduler_list", json!({})).await;
    assert_eq!(listed["jobs"], json!([]));
}
