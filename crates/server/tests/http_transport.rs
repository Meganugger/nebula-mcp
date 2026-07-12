//! End-to-end tests for the remote HTTP (Streamable HTTP) transport.
//!
//! Each test binds the transport to an ephemeral loopback port and drives it
//! with a real `reqwest` client, exercising auth, the JSON-RPC request/response
//! path over HTTP, and notification acknowledgement.

use std::sync::Arc;

use nebula_mcp_core::config::{Config, ConfigStore, HttpConfig, OAuthConfig};
use nebula_mcp_server::server::Server;
use nebula_mcp_tools::{build_registry, ToolServices};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "test-secret-token";

/// Spawn the HTTP transport on an ephemeral port; return (base_url, cancel).
async fn spawn_http() -> (String, CancellationToken) {
    spawn_http_with(|c| c).await
}

/// Spawn the HTTP transport with a customised [`HttpConfig`].
async fn spawn_http_with(
    tweak: impl FnOnce(HttpConfig) -> HttpConfig,
) -> (String, CancellationToken) {
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

    let http = tweak(HttpConfig {
        enabled: true,
        bind: "127.0.0.1:0".into(),
        path: "/mcp".into(),
        auth_tokens: vec![TOKEN.into()],
        require_auth: true,
        allowed_origins: vec![],
        max_body_bytes: 1024 * 1024,
        ..Default::default()
    });

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
async fn session_lifecycle_over_http() {
    let (url, cancel) = spawn_http().await;
    let c = client();

    // initialize mints a session id.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"it","version":"1"}}
        }))
        .send()
        .await
        .unwrap();
    let session = resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!session.is_empty());

    // Subsequent requests carrying the session id are served and echo it.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .header("mcp-session-id", &session)
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap(),
        session
    );

    // An unknown session id is rejected with 404 (client must re-initialize).
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .header("mcp-session-id", "not-a-session")
        .json(&json!({"jsonrpc":"2.0","id":3,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    // DELETE tears the session down; afterwards it is gone.
    let resp = c
        .delete(&url)
        .bearer_auth(TOKEN)
        .header("mcp-session-id", &session)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .header("mcp-session-id", &session)
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    cancel.cancel();
}

/// Read SSE chunks until `pred` matches or the deadline passes; returns the
/// accumulated text.
async fn read_sse_until(
    resp: &mut reqwest::Response,
    deadline: std::time::Duration,
    pred: impl Fn(&str) -> bool,
) -> String {
    let mut acc = String::new();
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return acc;
        }
        match tokio::time::timeout(remaining, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                acc.push_str(&String::from_utf8_lossy(&chunk));
                if pred(&acc) {
                    return acc;
                }
            }
            _ => return acc,
        }
    }
}

#[tokio::test]
async fn sse_stream_carries_ids_and_replays_on_resume() {
    let (url, cancel) = spawn_http().await;
    let c = client();

    // A tools/call with a progress token generates server-initiated
    // notifications that land in the SSE replay buffer.
    let call: Value = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&json!({
            "jsonrpc":"2.0","id":10,"method":"tools/call",
            "params":{
                "name":"terminal.run",
                "arguments":{"program":"echo","args":["sse-e2e"]},
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

    // Connect with Last-Event-ID: 0 — the missed progress event is replayed
    // with its id.
    let mut resp = c
        .get(&url)
        .bearer_auth(TOKEN)
        .header("accept", "text/event-stream")
        .header("last-event-id", "0")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let text = read_sse_until(&mut resp, std::time::Duration::from_secs(5), |t| {
        t.contains("notifications/progress")
    })
    .await;
    assert!(
        text.contains("notifications/progress"),
        "expected replayed progress event, got: {text}"
    );
    assert!(text.contains("id: "), "expected SSE event ids, got: {text}");
    let max_id: u64 = text
        .lines()
        .filter_map(|l| l.strip_prefix("id: "))
        .filter_map(|v| v.trim().parse().ok())
        .max()
        .unwrap();
    drop(resp);

    // Resuming *after* the last delivered id must not replay it again.
    let mut resp = c
        .get(&url)
        .bearer_auth(TOKEN)
        .header("accept", "text/event-stream")
        .header("last-event-id", max_id.to_string())
        .send()
        .await
        .unwrap();
    let text = read_sse_until(&mut resp, std::time::Duration::from_millis(800), |t| {
        t.contains("id: ")
    })
    .await;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("id: ") {
            let id: u64 = v.trim().parse().unwrap();
            assert!(
                id > max_id,
                "event {id} replayed despite Last-Event-ID {max_id}"
            );
        }
    }
    cancel.cancel();
}

/// Spawn a mock RFC 7662 introspection endpoint. Tokens equal to `good` are
/// active with scope `mcp`; everything else is inactive. Returns its URL and
/// a hit counter.
async fn spawn_introspection(good: &'static str) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use axum::{extract::State, routing::post, Router};
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = (good, hits.clone());
    let app = Router::new()
        .route(
            "/introspect",
            post(
                |State((good, hits)): State<(
                    &'static str,
                    Arc<std::sync::atomic::AtomicUsize>,
                )>,
                 body: String| async move {
                    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let active = body.split('&').any(|kv| kv == format!("token={good}"));
                    axum::Json(json!({"active": active, "scope": "mcp read"}))
                },
            ),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/introspect"), hits)
}

#[tokio::test]
async fn oauth_introspection_validates_and_caches_tokens() {
    let (introspect_url, hits) = spawn_introspection("oauth-good-token").await;
    let (url, cancel) = spawn_http_with(move |mut c| {
        c.oauth = OAuthConfig {
            enabled: true,
            introspection_url: introspect_url,
            client_id: "nebula".into(),
            client_secret: "s3cret".into(),
            required_scopes: vec!["mcp".into()],
            cache_secs: 60,
        };
        c
    })
    .await;
    let c = client();
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});

    // Static token still works without touching the introspection endpoint.
    let resp = c
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    // An OAuth token accepted by the AS is admitted.
    let resp = c
        .post(&url)
        .bearer_auth("oauth-good-token")
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // The verdict is cached: a second request does not re-introspect.
    let resp = c
        .post(&url)
        .bearer_auth("oauth-good-token")
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // An inactive token is rejected.
    let resp = c
        .post(&url)
        .bearer_auth("oauth-bad-token")
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
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
