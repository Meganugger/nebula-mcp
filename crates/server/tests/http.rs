//! The HTTP transport, driven through the real binary: authentication, Host
//! and Origin checks, isolation between clients, both protocol eras, limits
//! and shutdown.

mod support;

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use support::http::HttpClient;
use support::{is_error, text_of, Proc, Sandbox};

const TOKEN_A: &str = "token-a-0123456789abcdef";
const TOKEN_B: &str = "token-b-0123456789abcdef";

fn config(sandbox: &Sandbox, categories: &[&str], security: &str, http: &str) -> String {
    let list: Vec<String> = categories.iter().map(|c| format!("\"{c}\"")).collect();
    format!(
        "[server]\ncategories = [{}]\n[security]\nallowed_paths = [\"{}\"]\n{security}\n\
         [transport.http]\nauth_tokens = [\"{TOKEN_A}\", \"{TOKEN_B}\"]\n{http}\n",
        list.join(", "),
        sandbox.root_str()
    )
}

fn start(sandbox: &Sandbox, categories: &[&str], security: &str, http: &str) -> (Proc, HttpClient) {
    Proc::start_http(sandbox, &config(sandbox, categories, security, http), &[])
}

fn ping() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

#[test]
fn requests_need_a_valid_token_and_failures_are_throttled() {
    let sandbox = Sandbox::new();
    let (server, anon) = start(&sandbox, &["fs"], "", "");

    let mut response = anon.post(&[], &ping());
    assert_eq!(response.status, 401);
    assert!(response
        .header("www-authenticate")
        .is_some_and(|v| v.starts_with("Bearer")));
    assert!(response.text().contains("no bearer token"));
    assert_eq!(
        anon.with_token("wrong-token-0123456789")
            .post(&[], &ping())
            .status,
        401
    );
    assert_eq!(anon.send("GET", "/metrics", &[], None).status, 401);
    // Health needs no credential and says nothing.
    let mut health = anon.send("GET", "/healthz", &[], None);
    assert_eq!((health.status, health.text().as_str()), (200, "ok\n"));

    let good = anon.with_token(TOKEN_A);
    good.initialize("2025-11-25");
    let mut metrics = good.send("GET", "/metrics", &[], None);
    assert_eq!(metrics.status, 200);
    assert!(metrics.text().contains("nebula_mcp"));

    // Repeated failures are told to slow down; a valid token still works.
    let statuses: Vec<u16> = (0..14)
        .map(|_| {
            anon.with_token("guess-0123456789abcdef")
                .post(&[], &ping())
                .status
        })
        .collect();
    assert_eq!(statuses.last(), Some(&429), "{statuses:?}");
    good.initialize("2025-11-25");
    assert!(server.stderr().contains("authentication failed"));
    assert!(!server.stderr().contains(TOKEN_A), "a token was logged");
}

#[test]
fn host_and_origin_are_checked_and_allowed_origins_get_cors() {
    let sandbox = Sandbox::new();
    let (_server, anon) = start(
        &sandbox,
        &["fs"],
        "",
        "allowed_origins = [\"https://app.example.com\"]\nallowed_hosts = [\"mcp.internal\"]",
    );
    let client = anon.with_token(TOKEN_A);

    // A name the server does not answer to: the DNS-rebinding case.
    let mut response = client.send("POST", "/mcp", &[("Host", "evil.example")], Some("{}"));
    assert_eq!(response.status, 403);
    assert!(response.text().contains("allowed_hosts"));
    assert_eq!(
        client
            .send("GET", "/metrics", &[("Host", "mcp.internal")], None)
            .status,
        200
    );

    assert_eq!(
        client
            .post(&[("Origin", "https://evil.example")], &ping())
            .status,
        403
    );
    let ok = client.send(
        "GET",
        "/metrics",
        &[("Origin", "https://app.example.com")],
        None,
    );
    assert_eq!(ok.status, 200);
    assert_eq!(
        ok.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );

    // A browser's preflight carries no credential and is answered for
    // allowed origins only.
    let preflight = anon.send(
        "OPTIONS",
        "/mcp",
        &[
            ("Origin", "https://app.example.com"),
            ("Access-Control-Request-Method", "POST"),
            (
                "Access-Control-Request-Headers",
                "authorization, mcp-session-id",
            ),
        ],
        None,
    );
    assert_eq!(preflight.status, 204);
    assert!(preflight
        .header("access-control-allow-headers")
        .is_some_and(|h| h.contains("Authorization") && h.contains("Mcp-Session-Id")));
    let refused = anon.send(
        "OPTIONS",
        "/mcp",
        &[
            ("Origin", "https://evil.example"),
            ("Access-Control-Request-Method", "POST"),
        ],
        None,
    );
    assert_eq!(refused.status, 403);
}

#[test]
fn tokens_follow_the_configuration_file_without_a_restart() {
    let sandbox = Sandbox::new();
    let (_server, anon) = start(&sandbox, &["fs"], "", "");
    let old = anon.with_token(TOKEN_A);
    assert_eq!(old.send("GET", "/metrics", &[], None).status, 200);

    let rotated = "rotated-token-0123456789";
    let text = config(&sandbox, &["fs"], "", "").replace(TOKEN_A, rotated);
    std::fs::write(Proc::config_path(&sandbox), text).unwrap();
    let fresh = anon.with_token(rotated);
    assert!(
        support::wait_until(Duration::from_secs(20), || {
            fresh.send("GET", "/metrics", &[], None).status == 200
        }),
        "the new token was never accepted"
    );
    assert_eq!(old.send("GET", "/metrics", &[], None).status, 401);
}

#[test]
fn legacy_sessions_are_bound_to_their_client() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.root.join("a.txt"), "alpha").unwrap();
    let (_server, anon) = start(&sandbox, &["fs"], "", "");
    let (alice, bob) = (anon.with_token(TOKEN_A), anon.with_token(TOKEN_B));

    let alice_session = alice.initialize("2025-11-25");
    let bob_session = bob.initialize("2025-06-18");
    assert_ne!(alice_session, bob_session);

    // Both use request id 1; each gets its own answer.
    let a = alice.session_call(&alice_session, 1, "fs_read", json!({"path": "a.txt"}));
    let b = bob.session_call(&bob_session, 1, "fs_metadata", json!({"path": "a.txt"}));
    assert_eq!(text_of(&a["result"]), "alpha");
    assert_eq!(b["result"]["structuredContent"]["size"], 5);

    // Bob cannot use, read from or end Alice's session.
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    assert_eq!(bob.session_post(&alice_session, &call).status, 404);
    assert_eq!(
        bob.send("GET", "/mcp", &[("Mcp-Session-Id", &alice_session)], None)
            .status,
        404
    );
    assert_eq!(
        bob.send(
            "DELETE",
            "/mcp",
            &[("Mcp-Session-Id", &alice_session)],
            None
        )
        .status,
        404
    );
    let still = alice.session_call(&alice_session, 3, "fs_read", json!({"path": "a.txt"}));
    assert_eq!(text_of(&still["result"]), "alpha");

    // A session that does not exist is not found either.
    assert_eq!(alice.session_post("no-such-session", &call).status, 404);
}

#[cfg(unix)]
#[test]
fn clients_cannot_see_or_cancel_each_others_work() {
    let sandbox = Sandbox::new();
    let (_server, anon) = start(
        &sandbox,
        &["terminal"],
        "allowed_commands = [\"sh\", \"cat\"]",
        "",
    );
    let (alice, bob) = (anon.with_token(TOKEN_A), anon.with_token(TOKEN_B));
    let alice_session = alice.initialize("2025-11-25");
    let bob_session = bob.initialize("2025-11-25");

    // Alice starts a long call with request id 7.
    let pidfile = sandbox.root.join("alice.pid");
    let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
    let mut running = alice.session_post(
        &alice_session,
        &json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "terminal_run", "arguments": {"program": "sh", "args": ["-c", script]}}}),
    );
    assert!(support::wait_until(Duration::from_secs(20), || {
        std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.trim().is_empty())
    }));
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // Bob cancels "request 7" in his own session: nothing of Alice's stops.
    let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": 7}});
    assert!(bob.session_post(&bob_session, &cancel).status < 300);
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        support::pid_alive(grandchild),
        "another client cancelled the call"
    );

    // Terminal sessions are per client.
    let opened = alice.session_call(
        &alice_session,
        8,
        "terminal_session_open",
        json!({"program": "cat"}),
    );
    let terminal = opened["result"]["structuredContent"]["sessionId"]
        .as_str()
        .unwrap()
        .to_string();
    let listed = bob.session_call(&bob_session, 2, "terminal_session_list", json!({}));
    assert_eq!(listed["result"]["structuredContent"]["sessions"], json!([]));
    let stolen = bob.session_call(
        &bob_session,
        3,
        "terminal_session_close",
        json!({"sessionId": terminal}),
    );
    assert!(is_error(&stolen["result"]), "{stolen}");
    assert!(text_of(&stolen["result"]).starts_with("[not_found]"));

    // Alice cancels her own call: the tree dies and the call answers.
    assert!(alice.session_post(&alice_session, &cancel).status < 300);
    assert!(
        support::wait_until(Duration::from_secs(15), || !support::pid_alive(grandchild)),
        "the call's tree survived its own cancellation"
    );
    drop(running.next_message());

    // Ending the session stops what it owned.
    let cat_pid = opened["result"]["structuredContent"]["pid"]
        .as_u64()
        .unwrap() as u32;
    assert!(support::pid_alive(cat_pid));
    let ended = alice.send(
        "DELETE",
        "/mcp",
        &[("Mcp-Session-Id", &alice_session)],
        None,
    );
    assert!(ended.status < 300, "{}", ended.status);
    assert!(
        support::wait_until(Duration::from_secs(15), || !support::pid_alive(cat_pid)),
        "a terminal session outlived its protocol session"
    );
}

#[test]
fn stateless_requests_work_without_a_session() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.root.join("a.txt"), "alpha").unwrap();
    let (_server, anon) = start(&sandbox, &["fs"], "", "");
    let client = anon.with_token(TOKEN_A);

    let mut discover = client.modern(1, "server/discover", json!({}));
    assert_eq!(discover.status, 200);
    assert!(discover.header("mcp-session-id").is_none());
    let info = discover.result_for(1);
    let versions = info["result"]["supportedVersions"].as_array().unwrap();
    assert!(versions.contains(&json!("2026-07-28")) && versions.contains(&json!("2024-11-05")));
    assert_eq!(info["result"]["resultType"], "complete");

    let read = client.modern_call(2, "fs_read", json!({"path": "a.txt"}));
    assert_eq!(text_of(&read["result"]), "alpha");
    assert_eq!(read["result"]["resultType"], "complete");
    let listed = client.modern(3, "tools/list", json!({})).result_for(3);
    assert!(listed["result"]["tools"].as_array().unwrap().len() >= 15);
    assert!(listed["result"]["ttlMs"].is_number(), "{listed}");

    // The stateless protocol has no ping, and a request must say what it is.
    let gone = client.modern(4, "ping", json!({})).result_for(4);
    assert_eq!(gone["error"]["code"], -32601, "{gone}");
    let mut bare = client.post(
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
    );
    let answer = bare.next_message().unwrap_or(Value::Null);
    assert!(
        bare.status == 400 || answer["error"]["code"] == -32602,
        "{} {answer}",
        bare.status
    );
    // Headers that disagree with the body are refused.
    let mut mismatch = client.post(
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "fs_read",
            "arguments": {"path": "a.txt"},
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                      "io.modelcontextprotocol/clientCapabilities": {}}}}),
    );
    let answer = mismatch.next_message().unwrap_or(Value::Null);
    assert!(
        mismatch.status == 400 || answer["error"].is_object(),
        "{} {answer}",
        mismatch.status
    );
    assert!(!text_of(&answer["result"]).contains("alpha"));
}

#[cfg(unix)]
#[test]
fn a_stateless_call_streams_progress_and_dies_with_its_connection() {
    let sandbox = Sandbox::new();
    let (_server, anon) = start(&sandbox, &["terminal"], "allowed_commands = [\"sh\"]", "");
    let client = anon.with_token(TOKEN_A);

    // Progress arrives on the request's own response stream.
    let mut response = client.modern(
        1,
        "tools/call",
        json!({"name": "terminal_run",
               "arguments": {"program": "sh", "args": ["-c", "echo done"]},
               "_meta": {"progressToken": "p1"}}),
    );
    let (result, before) = response.result_with_others(1);
    assert!(text_of(&result["result"]).starts_with("done\n"), "{result}");
    assert!(
        before.iter().any(
            |m| m["method"] == "notifications/progress" && m["params"]["progressToken"] == "p1"
        ),
        "no progress on the request's stream: {before:?}"
    );

    // Closing the connection cancels the call and kills its tree, both
    // while the response is streaming progress and while nothing has been
    // sent yet (a call without a progress token answers only at the end).
    for with_progress in [true, false] {
        let pidfile = sandbox.root.join(format!("gc-{with_progress}.pid"));
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        let mut params = json!({"name": "terminal_run",
            "arguments": {"program": "sh", "args": ["-c", script]}});
        if with_progress {
            params["_meta"]["progressToken"] = json!("p2");
        }
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params});
        let connection = client.write(
            "POST",
            "/mcp",
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "terminal_run"),
                ("Content-Type", "application/json"),
            ],
            Some(&body.to_string()),
        );
        assert!(support::wait_until(Duration::from_secs(20), || {
            std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.trim().is_empty())
        }));
        let grandchild: u32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(support::pid_alive(grandchild));
        drop(connection);
        assert!(
            support::wait_until(Duration::from_secs(20), || !support::pid_alive(grandchild)),
            "the call outlived its connection (progress: {with_progress})"
        );
    }
}

#[test]
fn limits_apply_to_bodies_and_sessions() {
    let sandbox = Sandbox::new();
    let (_server, anon) = start(
        &sandbox,
        &["fs"],
        "",
        "max_body_bytes = 2048\nmax_sessions = 1",
    );
    let client = anon.with_token(TOKEN_A);

    let big =
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x".repeat(8192)}});
    assert_eq!(client.post(&[], &big).status, 413);
    let mut bad = client.send("POST", "/mcp", &[], Some("{not json"));
    let status = bad.status;
    assert!((400..500).contains(&status), "{status} {}", bad.text());

    let session = client.initialize("2025-11-25");
    let mut second = client.post(
        &[],
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "x", "version": "0"}}}),
    );
    second.expect_status(503);
    // Closing the first frees the slot, and the server is still healthy.
    assert!(
        client
            .send("DELETE", "/mcp", &[("Mcp-Session-Id", &session)], None)
            .status
            < 300
    );
    assert!(support::wait_until(Duration::from_secs(10), || {
        client
            .post(
                &[],
                &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "x", "version": "0"}}}),
            )
            .status
            == 200
    }));
}

#[cfg(unix)]
#[test]
fn shutdown_is_bounded_with_streams_open_and_leaves_nothing_running() {
    let sandbox = Sandbox::new();
    let (mut server, anon) = start(&sandbox, &["terminal"], "allowed_commands = [\"sh\"]", "");
    let client = anon.with_token(TOKEN_A);
    let session = client.initialize("2025-11-25");

    // An open notification stream and a running call.
    let _stream = client.send("GET", "/mcp", &[("Mcp-Session-Id", &session)], None);
    let pidfile = sandbox.root.join("gc.pid");
    let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
    let _running = client.session_post(
        &session,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "terminal_run", "arguments": {"program": "sh", "args": ["-c", script]}}}),
    );
    assert!(support::wait_until(Duration::from_secs(20), || {
        std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.trim().is_empty())
    }));
    let grandchild: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let asked = Instant::now();
    assert!(std::process::Command::new("kill")
        .args(["-TERM", &server.pid().to_string()])
        .status()
        .unwrap()
        .success());
    let status = server.wait(Duration::from_secs(30));
    assert!(
        status.is_some(),
        "the server did not stop; stderr:\n{}",
        server.stderr()
    );
    assert!(asked.elapsed() < Duration::from_secs(25));
    assert!(
        support::wait_until(Duration::from_secs(10), || !support::pid_alive(grandchild)),
        "a process outlived the server"
    );
}

#[test]
fn the_server_refuses_to_be_exposed_without_authentication() {
    let sandbox = Sandbox::new();
    let text = format!("[security]\nallowed_paths = [\"{}\"]\n", sandbox.root_str());
    let mut open = Proc::start_with(support::Start {
        config: &text,
        workdir: &sandbox.root,
        config_dir: &sandbox.home,
        env: Vec::new(),
        args: ["--http", "--http-addr", "0.0.0.0:0", "--no-auth"]
            .map(String::from)
            .to_vec(),
    });
    let status = open.wait(Duration::from_secs(20)).expect("it should exit");
    assert!(!status.success());
    assert!(
        open.stderr().contains("without authentication"),
        "{}",
        open.stderr()
    );

    // Authentication required but no credential configured: also refused.
    let mut locked = Proc::start_with(support::Start {
        config: &text,
        workdir: &sandbox.root,
        config_dir: &sandbox.home,
        env: Vec::new(),
        args: ["--http", "--http-addr", "127.0.0.1:0"]
            .map(String::from)
            .to_vec(),
    });
    let status = locked
        .wait(Duration::from_secs(20))
        .expect("it should exit");
    assert!(!status.success());
    assert!(
        locked.stderr().contains("auth_tokens"),
        "{}",
        locked.stderr()
    );
}
