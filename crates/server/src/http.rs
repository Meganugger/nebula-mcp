//! Remote HTTP transport implementing the MCP **Streamable HTTP** binding.
//!
//! This lets the server be reached by a URL from an AI platform instead of a
//! local stdio pipe. A single endpoint (default `/mcp`) accepts JSON-RPC:
//!
//! * `POST` — the client sends one JSON-RPC message (or a JSON array of them).
//!   Requests are dispatched through the shared [`Server`] engine and answered
//!   with `Content-Type: application/json`. A body containing only
//!   notifications/responses is acknowledged with `202 Accepted`.
//! * `GET` — opens a `text/event-stream` (SSE) channel that carries
//!   server-initiated notifications (progress, resource updates) plus periodic
//!   keep-alive comments (interval set by `transport.http.sse_keep_alive_secs`)
//!   so idle streams are not silently reaped by tunnels/proxies/NATs.
//! * `DELETE` — ends the client session (best-effort; the engine is stateless
//!   across requests, so this is a no-op acknowledgement).
//!
//! ## Security
//!
//! Exposing a machine's shell to the network is dangerous, so the transport is
//! defense-in-depth:
//!
//! * **Bearer auth** — every request must carry `Authorization: Bearer <token>`
//!   matching a configured token (constant-time compared). The server refuses
//!   to start on a non-loopback bind without `require_auth`.
//! * **Origin allow-list** — browser `Origin` headers must match
//!   `allowed_origins` (DNS-rebinding guard).
//! * **Body-size cap** — oversized bodies are rejected before parsing.
//!
//! Actual command/filesystem authority is still governed entirely by the
//! per-tool permission policy; this layer only controls who may talk to the
//! server at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::post;
use axum::{Json, Router};
use nebula_mcp_core::config::HttpConfig;
use nebula_mcp_protocol::{error_codes, ErrorObject, Request, Response};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::server::Server;

/// Shared state for the HTTP handlers.
struct HttpState {
    server: Arc<Server>,
    config: HttpConfig,
    /// Fan-out of server-initiated notifications to any open SSE streams.
    notifications: broadcast::Sender<String>,
}

/// Bind and serve the HTTP transport until `cancel` fires.
///
/// Returns once the listener has shut down. The bound address is logged; when
/// `config.bind` uses port 0 the OS-assigned address is logged too.
pub async fn serve(
    server: Arc<Server>,
    config: HttpConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr: SocketAddr = config
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid transport.http.bind '{}': {e}", config.bind))?;

    // Refuse the footgun: a network-facing bind with authentication disabled.
    if !addr.ip().is_loopback() && !config.require_auth {
        anyhow::bail!(
            "refusing to start HTTP transport on non-loopback address {addr} with \
             require_auth = false; set transport.http.require_auth = true and configure \
             auth_tokens"
        );
    }
    if config.require_auth && config.auth_tokens.is_empty() {
        anyhow::bail!(
            "transport.http.require_auth is true but no auth_tokens are configured; \
             add at least one token (e.g. via the NEBULA_MCP_AUTH_TOKEN env var)"
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_on(server, config, listener, cancel).await
}

/// Serve the HTTP transport on an already-bound listener (used by `serve` and
/// by tests that need the OS-assigned port before the server starts).
pub async fn serve_on(
    server: Arc<Server>,
    config: HttpConfig,
    listener: tokio::net::TcpListener,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let (tx, _rx) = broadcast::channel::<String>(256);

    // Bridge the engine's notifier channel into the SSE broadcast.
    let mut notif_rx = server.install_notifier();
    let notif_tx = tx.clone();
    tokio::spawn(async move {
        while let Some(value) = notif_rx.recv().await {
            if let Ok(line) = serde_json::to_string(&value) {
                // Ignore send errors: they only mean no SSE client is attached.
                let _ = notif_tx.send(line);
            }
        }
    });

    let state = Arc::new(HttpState {
        server,
        config: config.clone(),
        notifications: tx,
    });

    let app = Router::new()
        .route(
            &config.path,
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .with_state(state);

    let local = listener.local_addr()?;
    tracing::info!(
        addr = %local,
        path = %config.path,
        auth = config.require_auth,
        "MCP Streamable HTTP transport listening on http://{local}{}",
        config.path
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;
    Ok(())
}

/// Constant-time-ish string equality (length-independent short-circuit avoided).
fn tokens_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Returns `Some(error_response)` if the request must be rejected, else `None`.
fn authorize(state: &HttpState, headers: &HeaderMap) -> Option<AxumResponse> {
    // Origin allow-list (DNS-rebinding guard for browser clients).
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !state.config.allowed_origins.is_empty()
            && !state.config.allowed_origins.iter().any(|o| o == origin)
        {
            return Some((StatusCode::FORBIDDEN, "origin not allowed").into_response());
        }
        if state.config.allowed_origins.is_empty() {
            // No configured origins: deny any browser cross-origin attempt.
            return Some((StatusCode::FORBIDDEN, "origin not allowed").into_response());
        }
    }

    if !state.config.require_auth {
        return None;
    }
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .unwrap_or("");
    let ok = !presented.is_empty()
        && state
            .config
            .auth_tokens
            .iter()
            .any(|t| tokens_match(t, presented));
    if ok {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "missing or invalid bearer token",
            )
                .into_response(),
        )
    }
}

/// Handle a `POST` carrying one JSON-RPC message or an array of them.
async fn handle_post(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers) {
        return rejected;
    }

    // Parse the body as a single message or a batch.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let resp = Response::error(
                None,
                ErrorObject::new(error_codes::PARSE_ERROR, e.to_string(), None),
            );
            return (StatusCode::BAD_REQUEST, Json(resp)).into_response();
        }
    };

    let messages: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    };

    let mut responses: Vec<Response> = Vec::new();
    for msg in messages {
        let req: Request = match serde_json::from_value(msg) {
            Ok(r) => r,
            Err(e) => {
                responses.push(Response::error(
                    None,
                    ErrorObject::new(error_codes::INVALID_REQUEST, e.to_string(), None),
                ));
                continue;
            }
        };
        if let Some(resp) = state.server.clone().dispatch(req).await {
            responses.push(resp);
        }
    }

    // A body of only notifications yields no responses: acknowledge with 202.
    if responses.is_empty() {
        return StatusCode::ACCEPTED.into_response();
    }

    let session = new_session_id();
    let headers = [(header::HeaderName::from_static("mcp-session-id"), session)];
    if responses.len() == 1 {
        (StatusCode::OK, headers, Json(responses.pop().unwrap())).into_response()
    } else {
        (StatusCode::OK, headers, Json(responses)).into_response()
    }
}

/// Handle a `GET`: open an SSE stream of server-initiated notifications.
///
/// The stream interleaves two kinds of writes:
///
/// * real JSON-RPC notifications fanned out from the engine, and
/// * periodic keep-alive comment lines (`: keep-alive`), sent whenever the
///   stream has been idle for `transport.http.sse_keep_alive_secs` seconds.
///
/// The heartbeat exists because an idle SSE response produces zero bytes of
/// traffic, and intermediaries on the path (ngrok / Cloudflare tunnels,
/// reverse proxies, NAT tables) reap connections that carry no data once
/// their idle timeout fires — silently, with no error surfaced to either
/// end. SSE comments are ignored by conforming clients, so the heartbeat is
/// invisible to the MCP layer while keeping bytes flowing on the wire.
///
/// The heartbeat timer lives inside the stream itself (no spawned task), so
/// it is dropped — and thereby cancelled — as soon as the client disconnects
/// and hyper drops the response body. Nothing leaks per connection.
async fn handle_get(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers) {
        return rejected;
    }
    let rx = state.notifications.subscribe();
    let keep_alive_secs = state.config.sse_keep_alive_secs;
    let stream = async_stream::stream! {
        let mut rx = rx;
        let heartbeat_enabled = keep_alive_secs > 0;
        // `tokio::time::interval` panics on a zero period; when the heartbeat
        // is disabled its select branch is never polled, so the clamped
        // placeholder period is irrelevant.
        let mut heartbeat =
            tokio::time::interval(Duration::from_secs(keep_alive_secs.max(1)));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Both `broadcast::Receiver::recv` and `Interval::tick` are
            // cancel-safe, so losing the select race never drops a message.
            tokio::select! {
                msg = rx.recv() => match msg {
                    Ok(line) => {
                        // Real traffic proves liveness: push the next
                        // heartbeat a full period out.
                        heartbeat.reset();
                        yield Ok::<Event, std::convert::Infallible>(Event::default().data(line));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                // Note: the first tick completes immediately, so a comment is
                // written as soon as the stream opens — a cheap "stream
                // established" signal through every intermediary.
                _ = heartbeat.tick(), if heartbeat_enabled => {
                    yield Ok::<Event, std::convert::Infallible>(Event::default().comment("keep-alive"));
                }
            }
        }
    };
    Sse::new(stream).into_response()
}

/// Handle a `DELETE`: acknowledge session teardown.
async fn handle_delete(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers) {
        return rejected;
    }
    StatusCode::OK.into_response()
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_compare() {
        assert!(tokens_match("secret", "secret"));
        assert!(!tokens_match("secret", "secreu"));
        assert!(!tokens_match("secret", "secre"));
        assert!(!tokens_match("", "x"));
    }
}
