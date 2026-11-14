//! Regression tests for defects reproduced against 0.1.0, driven through the
//! real binary over stdio. Each test names the guarantee it pins.

mod support;

use std::time::Duration;

use serde_json::json;
use support::{is_error, text_of, toml_path, Proc, Sandbox};

fn config(sandbox: &Sandbox, commands: &[&str], extra: &str) -> String {
    let root = sandbox.root_str();
    let cmds = commands
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[logging]\nlevel = \"error\"\n\n[security]\nallowed_paths = [\"{root}/**\"]\n\
         allowed_commands = [{cmds}]\nmax_runtime_secs = 120\n{extra}\n"
    )
}

/// G-EXEC-1: an allowlisted command name never runs a different executable
/// that merely shares its basename.
#[cfg(unix)]
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn allowlisted_name_does_not_run_a_planted_executable() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    let planted = sb.root.join("echo");
    let marker = sb.outside.join("planted-ran");
    std::fs::write(
        &planted,
        format!("#!/bin/sh\ntouch '{}'\necho PLANTED\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut p = Proc::start(&sb, &config(&sb, &["echo"], ""));
    p.initialize("2025-06-18");
    let result = p.call(
        "terminal.run",
        json!({"program": toml_path(&planted), "args": ["hi"]}),
    );
    assert!(
        !marker.exists() && !text_of(&result).contains("PLANTED"),
        "a planted script named like an allowlisted command was executed: {result}"
    );
    assert!(is_error(&result), "expected a policy error, got {result}");
}

/// G-FS-1: a symlink inside an allowed root cannot be used to read a file
/// outside every allowed root.
#[cfg(unix)]
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn symlink_inside_root_cannot_read_outside_it() {
    let sb = Sandbox::new();
    let secret = sb.outside.join("secret.txt");
    std::fs::write(&secret, "OUTSIDE-SECRET").unwrap();
    std::os::unix::fs::symlink(&secret, sb.root.join("link.txt")).unwrap();

    let mut p = Proc::start(&sb, &config(&sb, &[], ""));
    p.initialize("2025-06-18");
    let result = p.call("fs.read", json!({"path": "link.txt"}));
    assert!(
        !result.to_string().contains("OUTSIDE-SECRET"),
        "read escaped the root through a symlink: {result}"
    );
    assert!(is_error(&result));
}

/// G-FS-2: deny patterns apply to every file a tool reads, not only to the
/// path named in the call.
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn search_does_not_reveal_denied_files() {
    let sb = Sandbox::new();
    std::fs::write(sb.root.join(".env"), "API_KEY=DENIED-CONTENT\n").unwrap();
    std::fs::write(sb.root.join("notes.txt"), "API_KEY=public-example\n").unwrap();

    let mut p = Proc::start(&sb, &config(&sb, &[], ""));
    p.initialize("2025-06-18");
    let result = p.call("fs.search", json!({"root": ".", "pattern": "API_KEY"}));
    let text = result.to_string();
    assert!(
        text.contains("public-example"),
        "search should still find allowed files: {result}"
    );
    assert!(
        !text.contains("DENIED-CONTENT"),
        "search returned the contents of a denied file: {result}"
    );
}

/// G-FS-3: allowing a directory allows the directory itself.
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn allowed_root_itself_is_accessible() {
    let sb = Sandbox::new();
    std::fs::write(sb.root.join("a.txt"), "x").unwrap();
    let mut p = Proc::start(&sb, &config(&sb, &[], ""));
    p.initialize("2025-06-18");
    let result = p.call("fs.tree", json!({"path": sb.root_str()}));
    assert!(
        !is_error(&result),
        "the allowed root directory was refused: {result}"
    );
    assert!(text_of(&result).contains("a.txt"));
}

/// G-PROC-1: cancelling a call kills the whole process tree, stops progress
/// notifications for that call, and leaves the server able to shut down.
#[cfg(unix)]
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn cancel_kills_the_process_tree_and_the_server_still_exits() {
    let sb = Sandbox::new();
    let pidfile = sb.root.join("grandchild.pid");
    let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());

    let mut p = Proc::start(&sb, &config(&sb, &["sh"], ""));
    p.initialize("2025-06-18");
    let id = p.send_request(
        "tools/call",
        json!({
            "name": "terminal.run",
            "arguments": {"program": "sh", "args": ["-c", script], "timeoutSecs": 100},
            "_meta": {"progressToken": "tok-1"}
        }),
    );
    assert!(
        support::wait_until(Duration::from_secs(10), || pidfile.exists()
            && !std::fs::read_to_string(&pidfile).unwrap().trim().is_empty()),
        "the command never started"
    );
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(support::pid_alive(grandchild));

    p.notify("notifications/cancelled", json!({"requestId": id}));
    // A cancelled request may or may not be answered; either way the tree dies.
    let killed = support::wait_until(Duration::from_secs(10), || !support::pid_alive(grandchild));
    if !killed {
        // Do not leak the process from a failing test.
        let _ = std::process::Command::new("kill")
            .args(["-9", &grandchild.to_string()])
            .status();
    }
    assert!(killed, "the grandchild survived cancellation");

    // No progress for the dead call once things have settled.
    std::thread::sleep(Duration::from_millis(500));
    p.drain_notifications();
    std::thread::sleep(Duration::from_secs(4));
    let late: Vec<_> = p
        .drain_notifications()
        .into_iter()
        .filter(|m| m["method"] == "notifications/progress")
        .collect();
    assert!(
        late.is_empty(),
        "progress kept arriving after cancel: {late:?}"
    );

    let status = p.close_stdin_and_wait(Duration::from_secs(10));
    assert!(status.is_some(), "the server did not exit on stdin EOF");
}

/// G-AVAIL-1: no tool call can take the process down; a failing call is
/// answered and the next call still works.
#[test]
#[ignore = "fails on 0.1.0; enabled by the commit that fixes it"]
fn tls_probe_failure_is_answered_and_the_server_survives() {
    let sb = Sandbox::new();
    // A listener that accepts and immediately closes: a clean handshake error.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });

    let mut p = Proc::start(&sb, &config(&sb, &[], "allow_network = true"));
    p.initialize("2025-06-18");
    let id = p.send_request(
        "tools/call",
        json!({"name": "net.tls_info", "arguments": {"host": "127.0.0.1", "port": port, "timeoutMs": 3000}}),
    );
    let resp = p.response(id, Duration::from_secs(15));
    assert!(
        resp.is_some(),
        "net.tls_info was never answered; stderr:\n{}",
        p.stderr()
    );
    let listed = p.request("tools/list", json!({}));
    assert!(
        listed["result"]["tools"].is_array(),
        "server died: {listed}"
    );
}
