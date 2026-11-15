//! Regression tests for the defects reproduced against 0.1.0, driven through
//! the real binary over stdio. Each failed before its fix; none may be
//! ignored.

mod support;

use std::time::Duration;

use serde_json::json;
use support::{is_error, text_of, Proc, Sandbox};

/// A configuration with `categories` enabled, the sandbox root allowed and
/// `security` appended to `[security]`.
fn config(sandbox: &Sandbox, categories: &[&str], security: &str) -> String {
    let list: Vec<String> = categories.iter().map(|c| format!("\"{c}\"")).collect();
    format!(
        "[server]\ncategories = [{}]\n[security]\nallowed_paths = [\"{}\"]\n{security}\n",
        list.join(", "),
        sandbox.root_str()
    )
}

fn start(sandbox: &Sandbox, categories: &[&str], security: &str) -> Proc {
    let mut server = Proc::start(sandbox, &config(sandbox, categories, security));
    server.initialize("2025-11-25");
    server
}

/// G-EXEC-1: an allowed name authorises the program found on PATH, not a
/// file of the same name somewhere else.
#[cfg(unix)]
#[test]
fn an_allowed_name_does_not_authorise_a_planted_file() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = Sandbox::new();
    let planted = sandbox.root.join("echo");
    let marker = sandbox.root.join("planted-ran");
    std::fs::write(
        &planted,
        format!("#!/bin/sh\necho pwned > '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut server = start(&sandbox, &["terminal"], "allowed_commands = [\"echo\"]");
    for program in [planted.to_string_lossy().into_owned(), "./echo".to_string()] {
        let result = server.call("terminal_run", json!({"program": program, "args": ["x"]}));
        assert!(is_error(&result), "{program} ran: {result}");
        assert!(
            text_of(&result).starts_with("[command_not_allowed]"),
            "{result}"
        );
    }
    assert!(!marker.exists(), "the planted file was executed");
    let result = server.call("terminal_run", json!({"program": "echo", "args": ["real"]}));
    assert!(text_of(&result).starts_with("real\n"), "{result}");
    assert!(!marker.exists());
}

/// G-FS-1: a symlink inside an allowed directory does not reach outside it.
#[cfg(unix)]
#[test]
fn a_symlink_does_not_read_outside_the_allowed_directory() {
    let sandbox = Sandbox::new();
    let secret = sandbox.outside.join("secret.txt");
    std::fs::write(&secret, "TOP-SECRET").unwrap();
    std::os::unix::fs::symlink(&secret, sandbox.root.join("link.txt")).unwrap();
    std::os::unix::fs::symlink(&sandbox.outside, sandbox.root.join("dir")).unwrap();

    let mut server = start(&sandbox, &["fs"], "");
    for path in ["link.txt", "dir/secret.txt"] {
        let result = server.call("fs_read", json!({"path": path}));
        assert!(is_error(&result), "{path}: {result}");
        assert!(!text_of(&result).contains("TOP-SECRET"), "{result}");
        assert!(
            text_of(&result).starts_with("[path_not_allowed]"),
            "{result}"
        );
    }
    let result = server.call("fs_write", json!({"path": "dir/new.txt", "content": "x"}));
    assert!(is_error(&result), "{result}");
    assert!(!sandbox.outside.join("new.txt").exists());
}

/// G-FS-2: deny patterns apply to every file a search reads.
#[test]
fn search_does_not_return_the_contents_of_denied_files() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.root.join(".env"), "API_KEY=needle-secret\n").unwrap();
    std::fs::write(sandbox.root.join("notes.txt"), "a needle here\n").unwrap();

    let mut server = start(&sandbox, &["fs"], "");
    let result = server.call("fs_search", json!({"root": ".", "pattern": "needle"}));
    let text = text_of(&result);
    assert!(!is_error(&result), "{result}");
    assert!(text.contains("notes.txt:1: a needle here"), "{text}");
    assert!(
        !text.contains("needle-secret") && !text.contains(".env:"),
        "{text}"
    );

    for tool in ["fs_glob", "fs_tree"] {
        let args = if tool == "fs_glob" {
            json!({"root": ".", "pattern": "**/*"})
        } else {
            json!({"path": "."})
        };
        let listing = server.call(tool, args).to_string();
        assert!(
            listing.contains("notes.txt") && !listing.contains(".env"),
            "{tool}: {listing}"
        );
    }
}

/// G-FS-3: allowing a directory allows the directory itself.
#[test]
fn the_allowed_directory_itself_is_accessible() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.root.join("a.txt"), "a").unwrap();
    let mut server = start(&sandbox, &["fs"], "");
    for path in [sandbox.root_str(), ".".to_string()] {
        let result = server.call("fs_tree", json!({"path": path}));
        assert!(!is_error(&result), "{path}: {result}");
        assert!(text_of(&result).contains("a.txt"), "{result}");
        let result = server.call("fs_metadata", json!({"path": path}));
        assert_eq!(result["structuredContent"]["type"], "dir", "{result}");
    }
}

/// G-PROC-1: cancelling a call kills its whole process tree, stops its
/// progress notifications, and leaves a server that still exits cleanly.
#[cfg(unix)]
#[test]
fn cancelling_a_command_kills_its_tree_and_stops_its_progress() {
    let sandbox = Sandbox::new();
    let pidfile = sandbox.root.join("grandchild.pid");
    let mut server = start(&sandbox, &["terminal"], "allowed_commands = [\"sh\"]");

    let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
    let id = server.send_request(
        "tools/call",
        json!({
            "name": "terminal_run",
            "arguments": {"program": "sh", "args": ["-c", script]},
            "_meta": {"progressToken": "tok-1"}
        }),
    );
    assert!(
        support::wait_until(Duration::from_secs(20), || pidfile.exists()
            && !std::fs::read_to_string(&pidfile).unwrap().trim().is_empty()),
        "the command never started; stderr:\n{}",
        server.stderr()
    );
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(support::pid_alive(grandchild));

    server.notify(
        "notifications/cancelled",
        json!({"requestId": id, "reason": "test"}),
    );
    assert!(
        support::wait_until(Duration::from_secs(15), || !support::pid_alive(grandchild)),
        "the grandchild survived the cancellation"
    );

    // No progress for the dead token once things have settled.
    std::thread::sleep(Duration::from_millis(500));
    server.drain_notifications();
    std::thread::sleep(Duration::from_secs(7));
    let late: Vec<_> = server
        .drain_notifications()
        .into_iter()
        .filter(|m| m["method"] == "notifications/progress")
        .collect();
    assert!(
        late.is_empty(),
        "progress continued after the cancel: {late:?}"
    );

    // The server is still healthy, and exits when its input closes.
    let listed = server.request("tools/list", json!({}));
    assert!(listed["result"]["tools"].is_array(), "{listed}");
    let status = server.close_stdin_and_wait(Duration::from_secs(20));
    assert!(status.is_some(), "the server did not exit on end of input");
    assert!(status.unwrap().success());
}

/// G-PROC-1 (shutdown): a running command does not outlive the server, by
/// end of input or by SIGTERM.
#[cfg(unix)]
#[test]
fn a_running_command_does_not_outlive_the_server() {
    for by_signal in [false, true] {
        let sandbox = Sandbox::new();
        let pidfile = sandbox.root.join("grandchild.pid");
        let mut server = start(&sandbox, &["terminal"], "allowed_commands = [\"sh\"]");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        server.send_request(
            "tools/call",
            json!({"name": "terminal_run", "arguments": {"program": "sh", "args": ["-c", script]}}),
        );
        assert!(support::wait_until(Duration::from_secs(20), || {
            std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.trim().is_empty())
        }));
        let grandchild: u32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let status = if by_signal {
            let killed = std::process::Command::new("kill")
                .args(["-TERM", &server.pid().to_string()])
                .status()
                .unwrap();
            assert!(killed.success());
            server.wait(Duration::from_secs(20))
        } else {
            server.close_stdin_and_wait(Duration::from_secs(20))
        };
        assert!(
            status.is_some(),
            "the server did not exit (signal: {by_signal})"
        );
        assert!(
            support::wait_until(Duration::from_secs(10), || !support::pid_alive(grandchild)),
            "the grandchild outlived the server (signal: {by_signal})"
        );
    }
}
