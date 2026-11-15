//! `powershell` tools driven through the dispatcher, wherever a PowerShell
//! exists (every CI platform has one).

#![allow(clippy::disallowed_methods)]

use nebula_mcp_core::{Call, OwnerId};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::testkit::{text_of, Kit};

/// Whether `pwsh` can be started. CI must have it; elsewhere the live tests
/// are skipped when it is missing.
pub(crate) fn pwsh_available() -> bool {
    let found = std::process::Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        found || std::env::var_os("GITHUB_ACTIONS").is_none(),
        "CI runners are expected to have pwsh"
    );
    found
}

/// Whether this process has administrator or root rights, asked the way the
/// tool asks.
fn is_elevated() -> bool {
    let out = std::process::Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-Command", super::IS_ELEVATED])
        .output()
        .expect("pwsh runs");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .eq_ignore_ascii_case("true")
}

/// A kit in which scripts may run whether or not the test process is
/// elevated (Windows CI runners are).
fn kit() -> Kit {
    Kit::new("allow_elevated = true")
}

#[tokio::test]
async fn a_script_runs_verbatim_and_reports_streams_and_exit_code() {
    if !pwsh_available() {
        return;
    }
    let kit = kit();
    let script = "Write-Output ('a' + 'b')\n\
                  Write-Output \"quote`\"s & | ; $(1 + 1) 'single'\"\n\
                  [Console]::Error.WriteLine('to stderr')\n\
                  exit 3";
    let out = kit
        .ok("powershell_run", json!({"script": script, "shell": "pwsh"}))
        .await;
    let text = text_of(&out).replace("\r\n", "\n");
    assert!(
        text.starts_with("ab\nquote\"s & | ; 2 'single'\n"),
        "{text}"
    );
    assert!(text.contains("[stderr]\nto stderr"), "{text}");
    assert!(text.contains("[powershell_run: exit code 3"), "{text}");

    // The child does not inherit the server's environment.
    let out = kit
        .ok(
            "powershell_run",
            json!({"script": "\"[$env:CARGO_PKG_NAME]\"", "shell": "pwsh"}),
        )
        .await;
    assert!(text_of(&out).starts_with("[]"), "{}", text_of(&out));

    let out = kit
        .ok(
            "powershell_run",
            json!({"script": "Start-Sleep -Seconds 60", "shell": "pwsh", "timeoutSecs": 1}),
        )
        .await;
    assert!(text_of(&out).contains("timed out"), "{}", text_of(&out));
}

#[tokio::test]
async fn an_elevated_server_needs_the_elevated_gate() {
    if !pwsh_available() {
        return;
    }
    let script = json!({"script": "'ran'", "shell": "pwsh"});
    let strict = Kit::new("");
    let elevated = is_elevated();
    match strict.call("powershell_run", script.clone()).await {
        Ok(out) => {
            assert!(
                !elevated,
                "an elevated server ran a script without the gate"
            );
            assert!(text_of(&out).starts_with("ran"));
        }
        Err(failure) => {
            assert!(elevated, "{}", failure.text);
            assert!(
                failure.text.starts_with("[permission_denied]")
                    && failure.text.contains("allow_elevated"),
                "{}",
                failure.text
            );
        }
    }
    let out = kit().ok("powershell_run", script).await;
    assert!(text_of(&out).starts_with("ran"));
}

#[tokio::test]
async fn tools_for_another_platform_are_not_offered() {
    let kit = Kit::new("");
    let offered: Vec<&str> = kit
        .dispatcher
        .exposed()
        .iter()
        .map(|t| t.spec().name)
        .collect();
    let windows_only = [
        "powershell_remote",
        "windows_service",
        "windows_registry",
        "windows_env",
        "diagnostics_etw_trace",
        "diagnostics_analyze_dump",
    ];
    for name in windows_only {
        assert_eq!(offered.contains(&name), cfg!(windows), "{name}");
    }
    assert_eq!(offered.contains(&"net_packet_capture"), cfg!(unix));
    assert!(offered.contains(&"powershell_run") && offered.contains(&"diagnostics_capabilities"));

    if !cfg!(windows) {
        // Not listed means not callable either.
        let call = Call {
            name: "windows_registry".to_string(),
            arguments: json!({"action": "query", "key": "HKCU\\Software"}),
            owner: OwnerId::stdio(),
            request_id: "t".into(),
            cancel: CancellationToken::new(),
            progress: None,
        };
        assert!(kit.dispatcher.call(call).await.is_err());
        let err = kit
            .err(
                "powershell_run",
                json!({"script": "1", "shell": "powershell"}),
            )
            .await;
        assert!(
            err.starts_with("[platform_unsupported]") || err.starts_with("[program_not_found]"),
            "{err}"
        );
    }
}
