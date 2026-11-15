//! `diagnostics` tools driven through the dispatcher.

#![allow(clippy::disallowed_methods)]

use serde_json::json;

use super::{provider_name, session_name};
use crate::testkit::{text_of, Kit};

#[tokio::test]
async fn the_server_describes_itself() {
    let kit = Kit::with_config(
        "",
        "[transport.http]\nauth_tokens = [\"a-very-secret-token-123456\"]",
    );
    let caps = kit.json("diagnostics_capabilities", json!({})).await;
    assert_eq!(caps["os"], std::env::consts::OS);
    assert_eq!(caps["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(caps["programs"]["git"], true, "the test machines have git");
    assert_eq!(caps["confinement"], false);
    assert!(caps["categories"].to_string().contains("\"fs\""));

    let shown = text_of(&kit.ok("diagnostics_config", json!({})).await);
    assert!(
        shown.contains("[security]") && shown.contains("<redacted>"),
        "{shown}"
    );
    assert!(!shown.contains("a-very-secret-token"), "{shown}");

    // Two calls so far, plus one that fails.
    kit.err("fs_read", json!({"path": "missing.txt"})).await;
    let metrics = kit.json("diagnostics_metrics", json!({})).await;
    let tools = metrics["tools"].as_array().unwrap();
    let of = |name: &str| {
        tools
            .iter()
            .find(|t| t["tool"] == name)
            .unwrap_or_else(|| panic!("{name} is missing from {metrics}"))
    };
    assert_eq!(of("diagnostics_capabilities")["successes"], 1);
    assert_eq!(of("fs_read")["failures"], 1);
}

#[test]
fn trace_session_arguments_cannot_be_options() {
    for bad in ["", "-ets", "a b", "a;b", "a/b", "--help"] {
        assert!(session_name(bad).is_err(), "{bad}");
    }
    assert!(session_name("nebula-trace_1").is_ok());
    for bad in ["", "-p", "a;b", "a\"b", "a|b"] {
        assert!(provider_name(bad).is_err(), "{bad}");
    }
    assert!(provider_name("Microsoft-Windows-Kernel-Process").is_ok());
    assert!(provider_name("{9E814AAD-3204-11D2-9A82-006008A86939}").is_ok());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_crash_tools_are_guarded() {
    let kit = Kit::new("");
    kit.write("dumps/app.dmp", "MDMP");
    kit.write("dumps/notes.txt", "x");
    let listed = kit
        .json("diagnostics_crash_dumps", json!({"directory": "dumps"}))
        .await;
    let dumps = listed["dumps"].as_array().unwrap();
    assert_eq!(dumps.len(), 1, "{listed}");
    assert!(dumps[0]["path"].as_str().unwrap().ends_with("app.dmp"));

    let reports = text_of(
        &kit.ok("diagnostics_wer_reports", json!({"maxEvents": 2}))
            .await,
    );
    assert!(
        reports.starts_with('[') || reports.starts_with('{'),
        "{reports}"
    );

    // Only processes inside the caller's own sessions can be dumped or
    // inspected; the server itself cannot.
    let me = std::process::id();
    for (tool, args) in [
        (
            "diagnostics_create_dump",
            json!({"pid": me, "outputPath": "dumps/self.dmp"}),
        ),
        ("diagnostics_stack_trace", json!({"pid": me})),
    ] {
        let err = kit.err(tool, args).await;
        assert!(err.starts_with("[permission_denied]"), "{tool}: {err}");
    }
    assert!(!kit.exists("dumps/self.dmp"));

    for (tool, args, needle) in [
        (
            "diagnostics_analyze_dump",
            json!({"dump": "dumps/app.dmp", "analysis": ".shell cmd"}),
            "[invalid_arguments]",
        ),
        (
            "diagnostics_analyze_dump",
            json!({"dump": "dumps/app.dmp", "commands": "!analyze -v"}),
            "[invalid_arguments]",
        ),
        (
            "diagnostics_etw_trace",
            json!({"action": "query", "session": "x"}),
            "allow_elevated",
        ),
    ] {
        let err = kit.err(tool, args).await;
        assert!(err.contains(needle), "{tool}: {err}");
    }
}
