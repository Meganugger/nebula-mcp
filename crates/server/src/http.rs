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
use dashmap::DashMap;
use nebula_mcp_core::config::HttpConfig;
use nebula_mcp_protocol::{error_codes, ErrorObject, Request, Response};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::server::Server;

/// Shared state for the HTTP handlers.
struct HttpState {
    server: Arc<Server>,
    config: HttpConfig,
    /// Legacy HTTP negotiation state, keyed by the client session id.
    sessions: DashMap<String, Arc<HttpSession>>,
}

/// Per-client notification state for the legacy HTTP transport.
struct HttpSession {
    version: String,
    sender: mpsc::UnboundedSender<serde_json::Value>,
    notifications: broadcast::Sender<String>,
    subscriptions: Arc<crate::resources::SubscriptionManager>,
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
    let state = Arc::new(HttpState {
        server,
        config: config.clone(),
        sessions: DashMap::new(),
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

/// The Streamable HTTP protocol-version header (header names are lowercase in
/// axum's `HeaderMap`).
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Validate the `MCP-Protocol-Version` header on non-`initialize` requests.
///
/// Per the Streamable HTTP transport spec (2025-06-18 onward) the client MUST
/// send the version negotiated during `initialize` on every subsequent HTTP
/// request, and the server MUST answer `400 Bad Request` when the header names
/// an invalid or unsupported revision. A missing header is accepted for
/// backwards compatibility (the spec tells servers to assume `2025-03-26`,
/// which this server supports). When a handshake has already negotiated a
/// version on this engine, the header must match it — not whatever the client
/// assumes.
fn check_protocol_version(state: &HttpState, headers: &HeaderMap) -> Option<AxumResponse> {
    let presented = match headers
        .get(PROTOCOL_VERSION_HEADER)
        .map(|v| v.to_str().map(str::to_owned))
    {
        None => return None, // Absent: pre-2025-06-18 client; accepted.
        Some(Ok(v)) => v,
        Some(Err(_)) => {
            return Some(
                (
                    StatusCode::BAD_REQUEST,
                    "invalid MCP-Protocol-Version header: not valid UTF-8",
                )
                    .into_response(),
            )
        }
    };
    let session_id = headers.get("mcp-session-id").and_then(|v| v.to_str().ok());
    match session_id.and_then(|id| state.sessions.get(id).map(|v| v.version.clone())) {
        Some(negotiated) if presented == negotiated => None,
        Some(negotiated) => Some(
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "MCP-Protocol-Version '{presented}' does not match the version \
                     negotiated for this HTTP session ('{negotiated}')"
                ),
            )
                .into_response(),
        ),
        None if nebula_mcp_protocol::is_supported_protocol_version(&presented) => None,
        None => Some(
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "unsupported MCP-Protocol-Version '{presented}'; supported versions: {}",
                    nebula_mcp_protocol::SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                ),
            )
                .into_response(),
        ),
    }
}

/// Validate the current revision's per-request metadata/header contract.
fn check_modern_headers(message: &serde_json::Value, headers: &HeaderMap) -> Option<AxumResponse> {
    let method = message.get("method").and_then(|v| v.as_str())?;
    let params = message.get("params").and_then(|v| v.as_object())?;
    let meta = params.get("_meta").and_then(|v| v.as_object())?;
    let version = meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(|v| v.as_str())?;
    if !nebula_mcp_protocol::is_modern_protocol_version(version) {
        return None;
    }

    let header_value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if header_value("mcp-protocol-version") != Some(version) {
        return Some(modern_header_error(
            error_codes::HEADER_MISMATCH,
            "MCP-Protocol-Version must match _meta protocolVersion",
        ));
    }
    if header_value("mcp-method") != Some(method) {
        return Some(modern_header_error(
            error_codes::HEADER_MISMATCH,
            "Mcp-Method must match the JSON-RPC method",
        ));
    }

    let required_name = match method {
        "tools/call" => params.get("name").and_then(|v| v.as_str()),
        "resources/read" => params.get("uri").and_then(|v| v.as_str()),
        "prompts/get" => params.get("name").and_then(|v| v.as_str()),
        _ => None,
    };
    if let Some(name) = required_name {
        if header_value("mcp-name") != Some(name) {
            return Some(modern_header_error(
                error_codes::HEADER_MISMATCH,
                "Mcp-Name must match the request target",
            ));
        }
    }
    None
}

fn modern_header_error(code: i64, message: &str) -> AxumResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(Response::error(None, ErrorObject::new(code, message, None))),
    )
        .into_response()
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

    for message in &messages {
        if let Some(rejected) = check_modern_headers(message, &headers) {
            return rejected;
        }
    }

    // The protocol-version header only applies to requests *after* the
    // handshake — an `initialize` request is what establishes the version, so
    // a body carrying one is exempt from the check.
    let contains_initialize = messages
        .iter()
        .any(|m| m.get("method").and_then(|v| v.as_str()) == Some("initialize"));
    if !contains_initialize {
        if let Some(rejected) = check_protocol_version(&state, &headers) {
            return rejected;
        }
    }

    let modern = messages.iter().any(|message| {
        message
            .get("params")
            .and_then(|params| params.get("_meta"))
            .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(|version| version.as_str())
            .map(nebula_mcp_protocol::is_modern_protocol_version)
            .unwrap_or(false)
    });
    let existing_session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Current requests are stateless and must not use the process-wide
    // notification sink. Legacy requests get a stable per-session sink so
    // progress and resource updates cannot cross client boundaries.
    let session = if modern {
        None
    } else if let Some(id) = existing_session.as_deref() {
        state.sessions.get(id).map(|session| session.clone())
    } else {
        Some(new_http_session("2025-03-26".to_string()))
    };
    if !modern && existing_session.is_some() && session.is_none() {
        return (StatusCode::NOT_FOUND, "unknown Mcp-Session-Id").into_response();
    }
    let request_notifier = session
        .as_ref()
        .map(|session| session.sender.clone())
        .unwrap_or_else(|| {
            let (sender, _receiver) = mpsc::unbounded_channel();
            sender
        });

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
        if let Some(resp) = state
            .server
            .clone()
            .dispatch_with_session(
                req,
                request_notifier.clone(),
                session
                    .as_ref()
                    .map(|value| value.subscriptions.clone())
                    .unwrap_or_else(|| Arc::new(crate::resources::SubscriptionManager::new())),
            )
            .await
        {
            responses.push(resp);
        }
    }

    // A body of only notifications yields no responses: acknowledge with 202.
    if responses.is_empty() {
        return StatusCode::ACCEPTED.into_response();
    }

    if !modern {
        let session_id = existing_session.unwrap_or_else(new_session_id);
        let negotiated = responses
            .first()
            .and_then(|response| response.result.as_ref())
            .and_then(|result| result.get("protocolVersion"))
            .and_then(|version| version.as_str())
            .unwrap_or("2025-03-26")
            .to_string();
        if let Some(session) = session {
            state.sessions.insert(
                session_id.clone(),
                Arc::new(HttpSession {
                    version: negotiated,
                    sender: session.sender.clone(),
                    notifications: session.notifications.clone(),
                    subscriptions: session.subscriptions.clone(),
                }),
            );
        }
        let headers = [(
            header::HeaderName::from_static("mcp-session-id"),
            session_id,
        )];
        return if responses.len() == 1 {
            (StatusCode::OK, headers, Json(responses.pop().unwrap())).into_response()
        } else {
            (StatusCode::OK, headers, Json(responses)).into_response()
        };
    }

    if responses.len() == 1 {
        (StatusCode::OK, Json(responses.pop().unwrap())).into_response()
    } else {
        (StatusCode::OK, Json(responses)).into_response()
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
    if let Some(rejected) = check_protocol_version(&state, &headers) {
        return rejected;
    }
    let session_id = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "legacy SSE requires Mcp-Session-Id",
            )
                .into_response()
        }
    };
    let session = match state.sessions.get(session_id) {
        Some(session) => session.clone(),
        None => return (StatusCode::NOT_FOUND, "unknown Mcp-Session-Id").into_response(),
    };
    let rx = session.notifications.subscribe();
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
    if let Some(rejected) = check_protocol_version(&state, &headers) {
        return rejected;
    }
    if let Some(id) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        state.sessions.remove(id);
    }
    StatusCode::OK.into_response()
}

fn new_http_session(version: String) -> Arc<HttpSession> {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let (notifications, _) = broadcast::channel(256);
    let output = notifications.clone();
    tokio::spawn(async move {
        while let Some(value) = receiver.recv().await {
            if let Ok(line) = serde_json::to_string(&value) {
                let _ = output.send(line);
            }
        }
    });
    Arc::new(HttpSession {
        version,
        sender,
        notifications,
        subscriptions: Arc::new(crate::resources::SubscriptionManager::new()),
    })
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
