//! End-to-end tests for the remote HTTP (Streamable HTTP) transport.
//!
//! Each test binds the transport to an ephemeral loopback port and drives it
//! with a real `reqwest` client, exercising auth, the JSON-RPC request/response
//! path over HTTP, and notification acknowledgement.

use std::sync::Arc;

use nebula_mcp_core::config::{Config, ConfigStore, HttpConfig};
use nebula_mcp_server::server::Server;
use nebula_mcp_tools::{build_registry, ToolServices};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "test-secret-token";

/// Spawn the HTTP transport on an ephemeral port; return (base_url, cancel).
async fn spawn_http() -> (String, CancellationToken) {
    spawn_http_with_keep_alive(20).await
}

/// Spawn the HTTP transport with a custom SSE keep-alive interval (seconds).
async fn spawn_http_with_keep_alive(sse_keep_alive_secs: u64) -> (String, CancellationToken) {
    let mut config = Config::default();
    config.security.allowed_commands = vec!["echo".into()];
    config.security.allowed_paths = vec!["/tmp/**".into()];
    config.logging.level = "error".into();
    let store = ConfigStore::new(config);
    let registry = build_registry(&ToolServices::new());
    let cancel = CancellationToken::new();
    let server = Arc::new(Server::new(
        registry,
        store,
        std::env::temp_dir(),
        cancel.clone(),
    ));

    let http = HttpConfig {
        enabled: true,
        bind: "127.0.0.1:0".into(),
        path: "/mcp".into(),
        auth_tokens: vec![TOKEN.into()],
        require_auth: true,
        allowed_origins: vec![],
        max_body_bytes: 1024 * 1024,
        sse_keep_alive_secs,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let c = cancel.clone();
    tokio::spawn(async move {
        nebula_mcp_server::http::serve_on(server, http, listener, c)
            .await
            .unwrap();
    });
    (format!("http://{addr}/mcp"), cancel)
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn legacy_session(url: &str, version: &str) -> String {
    let response = client()
        .post(url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    response
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// Append chunks from an open SSE response into `buf` until `pred(buf)` holds.
/// Panics (failing the test) if the stream ends or 15 s pass first.
async fn read_sse_until(
    resp: &mut reqwest::Response,
    buf: &mut String,
    what: &str,
    pred: impl Fn(&str) -> bool,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !pred(buf) {
        let now = std::time::Instant::now();
        assert!(
            now < deadline,
            "timed out waiting for {what}; stream so far: {buf:?}"
        );
        let chunk = tokio::time::timeout(deadline - now, resp.chunk())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}; stream so far: {buf:?}"))
            .expect("SSE read failed");
        match chunk {
            Some(bytes) => buf.push_str(&String::from_utf8_lossy(&bytes)),
            None => panic!("SSE stream ended while waiting for {what}; stream so far: {buf:?}"),
        }
    }
}

#[tokio::test]
async fn rejects_requests_without_token() {
    let (url, cancel) = spawn_http().await;
    let resp = client()
        .post(&url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    cancel.cancel();
}

#[tokio::test]
async fn initialize_over_http() {
    let (url, cancel) = spawn_http().await;
    let resp = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert!(resp.headers().get("mcp-session-id").is_some());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "nebula-mcp");
    cancel.cancel();
}

/// A client requesting a modern revision the server supports must get that
/// exact revision echoed back — not a stale hardcoded one.
#[tokio::test]
async fn initialize_negotiates_modern_protocol_version() {
    let (url, cancel) = spawn_http().await;
    let body: Value = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    cancel.cancel();
}

/// Old-but-supported revisions are echoed back unchanged.
#[tokio::test]
async fn initialize_echoes_legacy_supported_version() {
    let (url, cancel) = spawn_http().await;
    let body: Value = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    assert_eq!(body["result"]["protocolVersion"], "2024-11-05");
    cancel.cancel();
}

/// An unknown/unsupported requested revision must not crash or error: the
/// server offers its own latest supported revision and lets the client decide.
#[tokio::test]
async fn initialize_with_unknown_version_offers_latest_supported() {
    let (url, cancel) = spawn_http().await;
    let resp = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2020-01-01","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    assert_eq!(
        body["result"]["protocolVersion"],
        nebula_mcp_protocol::LATEST_PROTOCOL_VERSION
    );
    cancel.cancel();
}

/// The `MCP-Protocol-Version` header on post-handshake requests is validated
/// against what `initialize` actually negotiated: the negotiated version and
/// an absent header (pre-2025-06-18 clients) pass; anything else is 400.
#[tokio::test]
async fn protocol_version_header_is_validated_against_negotiation() {
    let (url, cancel) = spawn_http().await;
    let c = client();

    // Handshake at 2025-06-18 (no header required on initialize itself).
    let init: Value = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    // Header matching the negotiated version: accepted.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .header("MCP-Protocol-Version", "2025-06-18")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // No header: accepted for backwards compatibility.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({"jsonrpc":"2.0","id":3,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Header naming a different version than negotiated: 400 Bad Request.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .header("MCP-Protocol-Version", "1999-01-01")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // Same validation applies to the SSE GET stream.
    let resp = c
        .get(&url)
        .bearer_auth(TOKEN)
        .header("MCP-Protocol-Version", "1999-01-01")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    cancel.cancel();
}

#[tokio::test]
async fn tools_list_and_call_over_http() {
    let (url, cancel) = spawn_http().await;
    let c = client();

    // tools/list
    let list: Value = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let count = list["result"]["tools"].as_array().unwrap().len();
    assert!(count > 70, "expected a rich tool set, got {count}");

    // tools/call: run `echo`
    let call: Value = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"terminal.run","arguments":{"program":"echo","args":["http-e2e"]}}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(call["result"]["isError"], false);
    assert!(call["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("http-e2e"));
    cancel.cancel();
}

#[tokio::test]
async fn notification_is_accepted_with_202() {
    let (url, cancel) = spawn_http().await;
    let resp = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    cancel.cancel();
}

#[tokio::test]
async fn sse_get_requires_token() {
    let (url, cancel) = spawn_http().await;
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    cancel.cancel();
}

#[tokio::test]
async fn sse_stream_emits_periodic_keep_alive_comments() {
    let (url, cancel) = spawn_http_with_keep_alive(1).await;
    let session = legacy_session(&url, "2025-11-25").await;
    let mut resp = client()
        .get(&url)
        .bearer_auth(TOKEN)
        .header("Mcp-Session-Id", session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let content_type = resp.headers()[reqwest::header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "unexpected content-type: {content_type}"
    );

    // Multiple heartbeats must arrive on an otherwise-idle stream (the first
    // immediately on connect, then one per configured interval).
    let mut buf = String::new();
    read_sse_until(&mut resp, &mut buf, "two keep-alive comments", |b| {
        b.matches(": keep-alive").count() >= 2
    })
    .await;
    cancel.cancel();
}

#[tokio::test]
async fn sse_keep_alive_interleaves_with_real_notifications() {
    let (url, cancel) = spawn_http_with_keep_alive(1).await;
    let session = legacy_session(&url, "2025-11-25").await;
    let mut resp = client()
        .get(&url)
        .bearer_auth(TOKEN)
        .header("Mcp-Session-Id", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // First heartbeat proves the SSE subscription is live before we trigger work.
    let mut buf = String::new();
    read_sse_until(&mut resp, &mut buf, "initial keep-alive", |b| {
        b.contains(": keep-alive")
    })
    .await;

    // A tool call carrying a progress token emits `notifications/progress`
    // frames onto the same stream.
    let call: Value = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .header("Mcp-Session-Id", session)
        .json(&json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{
                "name":"terminal.run",
                "arguments":{"program":"echo","args":["sse-interleave"]},
                "_meta":{"progressToken":"sse-test"}
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(call["result"]["isError"], false);

    // The real notification arrives as an SSE data event...
    read_sse_until(&mut resp, &mut buf, "a progress notification", |b| {
        b.contains("notifications/progress")
    })
    .await;
    // ...and heartbeats keep flowing after real traffic.
    let seen = buf.matches(": keep-alive").count();
    read_sse_until(&mut resp, &mut buf, "keep-alive after real traffic", |b| {
        b.matches(": keep-alive").count() > seen
    })
    .await;
    cancel.cancel();
}

#[tokio::test]
async fn legacy_sse_notifications_are_isolated_per_session() {
    let (url, cancel) = spawn_http_with_keep_alive(0).await;
    let session_a = legacy_session(&url, "2025-11-25").await;
    let session_b = legacy_session(&url, "2025-11-25").await;

    let mut stream_b = client()
        .get(&url)
        .bearer_auth(TOKEN)
        .header("Mcp-Session-Id", &session_b)
        .send()
        .await
        .unwrap();
    assert_eq!(stream_b.status(), reqwest::StatusCode::OK);

    let response = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .header("Mcp-Session-Id", session_a)
        .json(&json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{
                "name":"terminal.run",
                "arguments":{"program":"echo","args":["session-a"]},
                "_meta":{"progressToken":"only-a"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // With keep-alives disabled, session B must receive no event from A.
    let no_cross_session_event =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream_b.chunk()).await;
    assert!(
        no_cross_session_event.is_err(),
        "session B observed a notification produced by session A"
    );
    cancel.cancel();
}

#[tokio::test]
async fn malformed_json_is_parse_error() {
    let (url, cancel) = spawn_http().await;
    let resp = client()
        .post(&url)
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32700);
    cancel.cancel();
}
