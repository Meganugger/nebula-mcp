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
//!   keep-alives. Every event carries a monotonically increasing `id:`; a
//!   client that reconnects with `Last-Event-ID` receives the events it missed
//!   from a bounded replay buffer before the live stream resumes.
//! * `DELETE` — ends the client session identified by `Mcp-Session-Id`.
//!
//! ## Sessions
//!
//! The response to a `POST` carrying `initialize` includes an
//! `Mcp-Session-Id` header. Clients echo it on subsequent requests; the server
//! tracks per-session state (creation/last-use timestamps, request count) and
//! expires sessions after `session_idle_secs` of inactivity. A request that
//! presents an unknown/expired session id is answered with `404 Not Found`,
//! signalling the client to re-initialize. Requests without the header are
//! served statelessly for backwards compatibility.
//!
//! ## Security
//!
//! Exposing a machine's shell to the network is dangerous, so the transport is
//! defense-in-depth:
//!
//! * **Bearer auth** — every request must carry `Authorization: Bearer <token>`
//!   matching a configured static token (constant-time compared) **or**, when
//!   `[transport.http.oauth]` is enabled, a token the configured OAuth2
//!   authorization server reports as active (RFC 7662 token introspection)
//!   with every required scope. Introspection verdicts are cached briefly,
//!   keyed by token digest. The server refuses to start on a non-loopback
//!   bind without `require_auth`.
//! * **Origin allow-list** — browser `Origin` headers must match
//!   `allowed_origins` (DNS-rebinding guard).
//! * **Body-size cap** — oversized bodies are rejected before parsing.
//!
//! Actual command/filesystem authority is still governed entirely by the
//! per-tool permission policy; this layer only controls who may talk to the
//! server at all.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::post;
use axum::{Json, Router};
use dashmap::DashMap;
use nebula_mcp_core::config::{HttpConfig, OAuthConfig};
use nebula_mcp_protocol::{error_codes, ErrorObject, Request, Response};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::server::Server;

/// Header carrying the MCP session identifier.
const SESSION_HEADER: &str = "mcp-session-id";

/// Per-session state retained between requests.
struct HttpSession {
    created: Instant,
    last_seen: parking_lot::Mutex<Instant>,
    requests: AtomicU64,
}

impl HttpSession {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            created: now,
            last_seen: parking_lot::Mutex::new(now),
            requests: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        self.last_seen.lock().elapsed()
    }
}

/// Bounded, monotonically-id'd log of server-initiated events backing SSE
/// resumption (`Last-Event-ID`).
struct EventLog {
    buffer: parking_lot::Mutex<VecDeque<(u64, String)>>,
    next_id: AtomicU64,
    capacity: usize,
}

impl EventLog {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: parking_lot::Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            next_id: AtomicU64::new(1),
            capacity: capacity.max(1),
        }
    }

    /// Append an event, assigning and returning its id.
    fn append(&self, line: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut buf = self.buffer.lock();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back((id, line));
        id
    }

    /// Events with an id greater than `after`, oldest first.
    fn since(&self, after: u64) -> Vec<(u64, String)> {
        self.buffer
            .lock()
            .iter()
            .filter(|(id, _)| *id > after)
            .cloned()
            .collect()
    }
}

/// RFC 7662 token-introspection validator with a bounded verdict cache.
struct OAuthValidator {
    config: OAuthConfig,
    http: reqwest::Client,
    /// token digest → (verdict, expiry).
    cache: DashMap<String, (bool, Instant)>,
}

impl OAuthValidator {
    fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            cache: DashMap::new(),
        }
    }

    /// Validate a bearer token by introspection, consulting the cache first.
    async fn validate(&self, token: &str) -> bool {
        let key = hex_digest(token);
        if let Some(entry) = self.cache.get(&key) {
            let (verdict, expiry) = *entry;
            if Instant::now() < expiry {
                return verdict;
            }
        }
        let verdict = self.introspect(token).await;
        let ttl = Duration::from_secs(self.config.cache_secs.max(1));
        // Bound the cache: drop expired entries opportunistically.
        if self.cache.len() > 10_000 {
            let now = Instant::now();
            self.cache.retain(|_, (_, exp)| *exp > now);
        }
        self.cache.insert(key, (verdict, Instant::now() + ttl));
        verdict
    }

    async fn introspect(&self, token: &str) -> bool {
        let resp = self
            .http
            .post(&self.config.introspection_url)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&[("token", token)])
            .send()
            .await;
        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(status = %r.status(), "token introspection returned non-success");
                return false;
            }
            Err(e) => {
                tracing::warn!(error = %e, "token introspection request failed");
                return false;
            }
        };
        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "token introspection returned invalid JSON");
                return false;
            }
        };
        if body.get("active").and_then(|v| v.as_bool()) != Some(true) {
            return false;
        }
        if self.config.required_scopes.is_empty() {
            return true;
        }
        let granted: Vec<&str> = body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default();
        self.config
            .required_scopes
            .iter()
            .all(|req| granted.iter().any(|g| g == req))
    }
}

/// SHA-256 hex digest (used so raw bearer tokens never sit in the cache map).
fn hex_digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Shared state for the HTTP handlers.
struct HttpState {
    server: Arc<Server>,
    config: HttpConfig,
    /// Fan-out of live server-initiated events `(id, line)` to open SSE streams.
    notifications: broadcast::Sender<(u64, String)>,
    /// Replay buffer for SSE resumption.
    events: Arc<EventLog>,
    /// Active sessions keyed by `Mcp-Session-Id`.
    sessions: Arc<DashMap<String, Arc<HttpSession>>>,
    /// Optional OAuth2 introspection validator.
    oauth: Option<OAuthValidator>,
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
    if config.require_auth && config.auth_tokens.is_empty() && !config.oauth.enabled {
        anyhow::bail!(
            "transport.http.require_auth is true but no auth_tokens are configured and \
             OAuth2 introspection is disabled; add at least one token (e.g. via the \
             NEBULA_MCP_AUTH_TOKEN env var) or enable [transport.http.oauth]"
        );
    }
    if config.oauth.enabled && config.oauth.introspection_url.is_empty() {
        anyhow::bail!("transport.http.oauth.enabled is true but oauth.introspection_url is empty");
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
    let (tx, _rx) = broadcast::channel::<(u64, String)>(256);
    let events = Arc::new(EventLog::new(config.sse_replay_events));

    // Bridge the engine's notifier channel into the event log + SSE broadcast.
    let mut notif_rx = server.install_notifier();
    let notif_tx = tx.clone();
    let notif_events = events.clone();
    tokio::spawn(async move {
        while let Some(value) = notif_rx.recv().await {
            if let Ok(line) = serde_json::to_string(&value) {
                let id = notif_events.append(line.clone());
                // Ignore send errors: they only mean no SSE client is attached.
                let _ = notif_tx.send((id, line));
            }
        }
    });

    let sessions: Arc<DashMap<String, Arc<HttpSession>>> = Arc::new(DashMap::new());

    // Expire idle sessions in the background.
    let idle_limit = Duration::from_secs(config.session_idle_secs.max(1));
    let reaper_sessions = sessions.clone();
    let reaper_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                biased;
                () = reaper_cancel.cancelled() => break,
                _ = tick.tick() => {
                    reaper_sessions.retain(|id, s| {
                        let keep = s.idle() < idle_limit;
                        if !keep {
                            tracing::debug!(session = %id, "expiring idle MCP session");
                        }
                        keep
                    });
                }
            }
        }
    });

    let oauth = if config.oauth.enabled {
        Some(OAuthValidator::new(config.oauth.clone()))
    } else {
        None
    };

    let state = Arc::new(HttpState {
        server,
        config: config.clone(),
        notifications: tx,
        events,
        sessions,
        oauth,
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
        oauth = config.oauth.enabled,
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
async fn authorize(state: &HttpState, headers: &HeaderMap) -> Option<AxumResponse> {
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
    if !presented.is_empty() {
        // Static tokens first (cheap, offline).
        if state
            .config
            .auth_tokens
            .iter()
            .any(|t| tokens_match(t, presented))
        {
            return None;
        }
        // Fall back to OAuth2 introspection when configured.
        if let Some(oauth) = &state.oauth {
            if oauth.validate(presented).await {
                return None;
            }
        }
    }
    Some(
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or invalid bearer token",
        )
            .into_response(),
    )
}

/// Extract and validate the session referenced by the request headers.
///
/// Returns `Err(404)` when a session id is presented but unknown (expired);
/// `Ok(None)` when no session header is present (stateless request).
fn resolve_session(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<Option<Arc<HttpSession>>, Box<AxumResponse>> {
    let Some(id) = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    match state.sessions.get(id) {
        Some(s) => Ok(Some(s.clone())),
        None => Err(Box::new(
            (
                StatusCode::NOT_FOUND,
                "unknown or expired MCP session; re-initialize",
            )
                .into_response(),
        )),
    }
}

/// Handle a `POST` carrying one JSON-RPC message or an array of them.
async fn handle_post(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers).await {
        return rejected;
    }
    let session = match resolve_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(s) = &session {
        s.touch();
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

    let mut initialize_seen = false;
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
        initialize_seen |= req.method == "initialize";
        if let Some(resp) = state.server.clone().dispatch(req).await {
            responses.push(resp);
        }
    }

    // A body of only notifications yields no responses: acknowledge with 202.
    if responses.is_empty() {
        return StatusCode::ACCEPTED.into_response();
    }

    // Mint a session on initialize; otherwise echo the presented id (if any).
    let session_id = if initialize_seen {
        let id = uuid::Uuid::new_v4().to_string();
        state
            .sessions
            .insert(id.clone(), Arc::new(HttpSession::new()));
        Some(id)
    } else {
        headers
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    let mut response_headers = HeaderMap::new();
    if let Some(id) = session_id {
        if let Ok(v) = header::HeaderValue::from_str(&id) {
            response_headers.insert(header::HeaderName::from_static(SESSION_HEADER), v);
        }
    }
    if responses.len() == 1 {
        (
            StatusCode::OK,
            response_headers,
            Json(responses.pop().unwrap()),
        )
            .into_response()
    } else {
        (StatusCode::OK, response_headers, Json(responses)).into_response()
    }
}

/// Handle a `GET`: open an SSE stream of server-initiated notifications,
/// replaying missed events when the client presents `Last-Event-ID`.
async fn handle_get(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers).await {
        return rejected;
    }
    let session = match resolve_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Some(s) = &session {
        s.touch();
    }

    let last_event_id: u64 = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    // Subscribe *before* snapshotting the replay buffer so no event falls in
    // the gap; live events already replayed are skipped by id.
    let rx = state.notifications.subscribe();
    let replay = state.events.since(last_event_id);

    let stream = async_stream::stream! {
        let mut last_sent = last_event_id;
        for (id, line) in replay {
            last_sent = id;
            yield Ok::<Event, std::convert::Infallible>(
                Event::default().id(id.to_string()).data(line),
            );
        }
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok((id, line)) => {
                    if id <= last_sent {
                        continue; // Already delivered during replay.
                    }
                    last_sent = id;
                    yield Ok(Event::default().id(id.to_string()).data(line));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Handle a `DELETE`: tear down the session named by `Mcp-Session-Id`.
async fn handle_delete(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> AxumResponse {
    if let Some(rejected) = authorize(&state, &headers).await {
        return rejected;
    }
    if let Some(id) = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) {
        let Some((_, session)) = state.sessions.remove(id) else {
            return (StatusCode::NOT_FOUND, "unknown or expired MCP session").into_response();
        };
        tracing::debug!(
            session = %id,
            age_secs = session.created.elapsed().as_secs(),
            requests = session.requests.load(Ordering::Relaxed),
            "MCP session deleted by client"
        );
    }
    StatusCode::OK.into_response()
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

    #[test]
    fn event_log_assigns_monotonic_ids_and_replays_since() {
        let log = EventLog::new(3);
        assert_eq!(log.append("a".into()), 1);
        assert_eq!(log.append("b".into()), 2);
        assert_eq!(log.append("c".into()), 3);
        // Capacity 3: appending a fourth evicts the oldest.
        assert_eq!(log.append("d".into()), 4);
        let all = log.since(0);
        assert_eq!(
            all.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        let since_2 = log.since(2);
        assert_eq!(
            since_2.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(),
            vec!["c", "d"]
        );
        assert!(log.since(4).is_empty());
    }

    #[test]
    fn token_digest_is_stable_hex() {
        let d = hex_digest("abc");
        assert_eq!(
            d,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn session_touch_updates_idle() {
        let s = HttpSession::new();
        s.touch();
        assert!(s.idle() < Duration::from_secs(1));
        assert_eq!(s.requests.load(Ordering::Relaxed), 1);
        assert!(s.created.elapsed() < Duration::from_secs(5));
    }
}
