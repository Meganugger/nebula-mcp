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
