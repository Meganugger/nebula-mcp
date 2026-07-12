//! Stress/soak tests driving thousands of concurrent calls over both
//! transports (stdio framing and remote HTTP).
//!
//! These are `#[ignore]`d in the default test run because they are
//! deliberately heavy; CI executes them in a dedicated job with
//! `cargo test --test stress -- --ignored`, and they can be run locally the
//! same way.

use std::sync::Arc;

use nebula_mcp_core::config::{Config, ConfigStore, HttpConfig};
use nebula_mcp_server::server::Server;
use nebula_mcp_tools::{build_registry, ToolServices};
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn test_server(cancel: CancellationToken) -> Arc<Server> {
    let mut config = Config::default();
    config.security.allowed_commands = vec!["echo".into()];
    config.security.allowed_paths = vec!["/tmp/**".into()];
    config.logging.level = "error".into();
    config.server.max_concurrent_calls = 32;
    let store = ConfigStore::new(config);
    let registry = build_registry(&ToolServices::new());
    Arc::new(Server::new(registry, store, std::env::temp_dir(), cancel))
}

/// Thousands of concurrent in-engine dispatches (the path both transports
/// share): every request must receive a well-formed response, under bounded
/// concurrency, without a panic or a lost reply.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "stress: run with --ignored"]
async fn engine_survives_thousands_of_concurrent_dispatches() {
    let cancel = CancellationToken::new();
    let server = test_server(cancel.clone());

    const CALLS: usize = 3_000;
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..CALLS {
        let server = server.clone();
        tasks.spawn(async move {
            // Mix cheap protocol methods with real tool executions.
            let request = match i % 4 {
                0 => json!({"jsonrpc":"2.0","id":i,"method":"tools/list","params":{}}),
                1 => json!({"jsonrpc":"2.0","id":i,"method":"ping"}),
                2 => json!({
                    "jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":"security.check_path","arguments":{"path":"/tmp/x.txt"}}
                }),
                _ => json!({
                    "jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":"terminal.run","arguments":{"program":"echo","args":[format!("n{i}")]}}
                }),
            };
            let req: nebula_mcp_protocol::Request = serde_json::from_value(request).unwrap();
            server.dispatch(req).await
        });
    }

    let mut answered = 0usize;
    while let Some(res) = tasks.join_next().await {
        let resp = res
            .expect("dispatch task must not panic")
            .expect("response");
        assert!(
            resp.result.is_some() || resp.error.is_some(),
            "response must carry a result or error"
        );
        answered += 1;
    }
    assert_eq!(answered, CALLS);

    // Metrics must account for every tools/call issued (half the requests).
    let total_calls: u64 = server.metrics().snapshot().iter().map(|m| m.calls).sum();
    assert_eq!(total_calls as usize, CALLS / 2);
    cancel.cancel();
}

/// Soak the stdio framing path: a single connection carrying thousands of
/// newline-delimited frames, responses all delivered before EOF completes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "stress: run with --ignored"]
async fn stdio_framing_survives_thousands_of_frames() {
    let cancel = CancellationToken::new();
    let server = test_server(cancel.clone());

    const CALLS: usize = 2_000;
    let mut input = String::new();
    for i in 0..CALLS {
        let frame = if i % 2 == 0 {
            json!({"jsonrpc":"2.0","id":i,"method":"ping"})
        } else {
            json!({
                "jsonrpc":"2.0","id":i,"method":"tools/call",
                "params":{"name":"security.check_command","arguments":{"program":"echo"}}
            })
        };
        input.push_str(&frame.to_string());
        input.push('\n');
    }

    let (client_write, server_read) = tokio::io::duplex(64 * 1024);
    let (server_write, client_read) = tokio::io::duplex(4 * 1024 * 1024);

    let serve = tokio::spawn(server.clone().serve(server_read, server_write));

    // Feed all frames then close, while draining responses concurrently so
    // neither side blocks on a full pipe.
    let writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut w = client_write;
        w.write_all(input.as_bytes()).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
    });

    let mut responses = 0usize;
    {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(client_read).lines();
        while let Some(line) = lines.next_line().await.unwrap() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["jsonrpc"], "2.0");
            responses += 1;
            if responses == CALLS {
                break;
            }
        }
    }
    assert_eq!(responses, CALLS);

    writer.await.unwrap();
    cancel.cancel();
    serve.await.unwrap().unwrap();
}

/// Soak the remote HTTP transport: thousands of concurrent POSTs over a
/// real TCP socket with bearer auth, every one answered 200 with a valid
/// JSON-RPC response.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "stress: run with --ignored"]
async fn http_transport_survives_thousands_of_concurrent_posts() {
    const TOKEN: &str = "stress-token";
    let cancel = CancellationToken::new();
    let server = test_server(cancel.clone());

    let http = HttpConfig {
        enabled: true,
        bind: "127.0.0.1:0".into(),
        path: "/mcp".into(),
        auth_tokens: vec![TOKEN.into()],
        require_auth: true,
        allowed_origins: vec![],
        max_body_bytes: 1024 * 1024,
        ..Default::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/mcp");
    let c = cancel.clone();
    tokio::spawn(async move {
        nebula_mcp_server::http::serve_on(server, http, listener, c)
            .await
            .unwrap();
    });

    const CALLS: usize = 2_000;
    /// Client-side concurrency bound so the test respects typical fd limits;
    /// the server side still sees a sustained flood of overlapping requests.
    const CONCURRENCY: usize = 128;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        .build()
        .unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..CALLS {
        let client = client.clone();
        let url = url.clone();
        let gate = gate.clone();
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await.unwrap();
            let body = if i % 2 == 0 {
                json!({"jsonrpc":"2.0","id":i,"method":"ping"})
            } else {
                json!({
                    "jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":"security.check_path","arguments":{"path":"/tmp/s.txt"}}
                })
            };
            let resp = client
                .post(&url)
                .bearer_auth(TOKEN)
                .json(&body)
                .send()
                .await
                .expect("request must not error");
            assert_eq!(resp.status(), reqwest::StatusCode::OK);
            let v: serde_json::Value = resp.json().await.expect("valid JSON");
            assert_eq!(v["jsonrpc"], "2.0");
        });
    }
    let mut done = 0usize;
    while let Some(res) = tasks.join_next().await {
        res.expect("request task must not panic");
        done += 1;
    }
    assert_eq!(done, CALLS);
    cancel.cancel();
}
