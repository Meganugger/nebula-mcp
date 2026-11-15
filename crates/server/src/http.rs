//! The HTTP transport: MCP Streamable HTTP behind authentication.
//!
//! Every request passes [`guard`] before anything reads its body: the `Host`
//! and `Origin` headers are checked, then the credential, all against the
//! configuration in force at that moment (so tokens, origins and hosts can be
//! rotated by editing the config file). Only then does the request reach the
//! protocol layer, which serves stateless 2026-07-28 requests and legacy
//! sessions on the same endpoint.
//!
//! Isolation between clients rests on two things done here. A legacy session
//! is bound to the credential that created it, and a request that names a
//! session with another credential is answered as if the session did not
//! exist. And every request carries its [`Principal`] to the handler, which
//! scopes long-lived state by it.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use nebula_mcp_core::config::HttpConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::app::App;
use crate::handler::Handler;

/// Time open connections get to finish once the server is stopping.
const DRAIN: Duration = Duration::from_secs(5);
/// Failed authentications from one address before it is told to slow down.
const MAX_FAILURES: u32 = 10;
/// Window over which failures are counted.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

const SESSION_HEADER: &str = "mcp-session-id";
const METHOD_HEADER: &str = "mcp-method";

/// Who a request is from, as far as authentication can tell. Carried in the
/// request extensions to the handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(Arc<str>);

impl Principal {
    fn anonymous() -> Self {
        Self(Arc::from("anonymous"))
    }

    /// A principal named after a digest of its static token, so the token
    /// itself appears nowhere.
    fn of_token(digest: &[u8]) -> Self {
        Self(Arc::from(format!("token:{}", hex::encode(&digest[..8]))))
    }

    /// A stable identifier, safe to log.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// The peer address of the connection a request arrived on.
#[derive(Debug, Clone, Copy)]
struct Remote(SocketAddr);

struct Failures {
    count: u32,
    since: Instant,
}

struct HttpState {
    app: Arc<App>,
    sessions: Arc<LocalSessionManager>,
    /// Legacy session id to the principal that created it.
    bindings: Mutex<HashMap<String, Principal>>,
    failures: Mutex<HashMap<IpAddr, Failures>>,
    mcp_path: String,
}

/// Why the server refuses to serve HTTP with a configuration.
pub fn check_exposure(http: &HttpConfig, bind: &SocketAddr) -> Result<(), String> {
    let has_credentials = !http.auth_tokens.is_empty() || http.oauth.enabled;
    if http.require_auth && !has_credentials {
        return Err(
            "[transport.http] require_auth is on but there is no auth_tokens entry and OAuth is \
             off, so every request would be refused. Add a token (16 characters or more), or \
             pass --auth-token."
                .to_string(),
        );
    }
    if !bind.ip().is_loopback() && !http.require_auth {
        return Err(format!(
            "refusing to serve without authentication on {bind}, which is reachable from other \
             machines. Keep require_auth on, or bind to 127.0.0.1."
        ));
    }
    Ok(())
}

/// Serve MCP over HTTP on `listener` until the app shuts down.
pub async fn serve(app: Arc<App>, listener: TcpListener) -> Result<(), String> {
    let loaded = app.store().snapshot();
    let http = loaded.config.transport.http.clone();
    drop(loaded);

    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = Some(Duration::from_secs(http.session_idle_secs.max(1)));
    let sessions = Arc::new(manager);

    let keep_alive =
        (http.sse_keep_alive_secs > 0).then(|| Duration::from_secs(http.sse_keep_alive_secs));
    let protocol = StreamableHttpServerConfig::default()
        .with_sse_keep_alive(keep_alive)
        .with_legacy_session_mode(true)
        // Event streams keep a tunnelled connection alive during long calls.
        .with_json_response(false)
        .with_cancellation_token(app.shutdown().child_token())
        // Host and Origin are validated in `guard`, against the live config.
        .disable_allowed_hosts()
        .with_max_request_body_bytes(http.max_body_bytes);
    let factory_app = app.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(Handler::for_http(factory_app.clone())),
        sessions.clone(),
        protocol,
    );

    let state = Arc::new(HttpState {
        app: app.clone(),
        sessions,
        bindings: Mutex::new(HashMap::new()),
        failures: Mutex::new(HashMap::new()),
        mcp_path: http.path.clone(),
    });
    let router = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/metrics", get(metrics))
        .nest_service(&http.path, mcp)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state.clone());

    accept_loop(
        &app,
        listener,
        router,
        http.max_connections.max(1),
        Duration::from_secs(http.read_timeout_secs.max(1)),
    )
    .await;
    Ok(())
}

/// Serve only `/metrics`, without authentication. Refused off loopback.
pub async fn serve_metrics(app: Arc<App>, listener: TcpListener) -> Result<(), String> {
    let addr = listener
        .local_addr()
        .map_err(|e| format!("metrics listener: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "the metrics listener has no authentication and only binds loopback addresses, not \
             {addr}. To scrape remotely use /metrics on the HTTP transport, which is \
             authenticated."
        ));
    }
    let metrics_app = app.clone();
    let router = Router::new().route(
        "/metrics",
        get(move || {
            let app = metrics_app.clone();
            async move { prometheus(&app) }
        }),
    );
    accept_loop(&app, listener, router, 16, Duration::from_secs(10)).await;
    Ok(())
}

/// Accept connections, at most `max_connections` at a time, until shutdown;
/// then give open connections a bounded time to finish.
async fn accept_loop(
    app: &Arc<App>,
    listener: TcpListener,
    router: Router,
    max_connections: usize,
    read_timeout: Duration,
) {
    let shutdown = app.shutdown().clone();
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(read_timeout);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    loop {
        // No slot, no accept: further clients wait in the listen backlog.
        let permit = tokio::select! {
            () = shutdown.cancelled() => break,
            permit = permits.clone().acquire_owned() => match permit {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let (stream, remote) = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("accepting a connection failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let router = router.clone();
        let service = hyper::service::service_fn(move |mut req: hyper::Request<_>| {
            req.extensions_mut().insert(Remote(remote));
            router.clone().oneshot(req)
        });
        let conn = builder
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
            drop(permit);
        });
    }

    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(DRAIN) => {
            tracing::info!("closing connections that did not finish in time");
        }
    }
}

fn prometheus(app: &App) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        app.dispatcher().metrics().to_prometheus(),
    )
        .into_response()
}

async fn metrics(State(state): State<Arc<HttpState>>) -> Response {
    prometheus(&state.app)
}

fn refuse(status: StatusCode, message: impl Into<String>) -> Response {
    let mut text: String = message.into();
    text.push('\n');
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text,
    )
        .into_response()
}

/// The host a request is addressed to, lower-case, as written (with port).
fn requested_host(req: &Request) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
        .map(|h| h.to_ascii_lowercase())
}

fn without_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => &authority[..=end],
            None => authority,
        };
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// `host[:port]` of the public URL, with the port only when it is not the
/// scheme's default.
fn public_authority(http: &HttpConfig) -> Option<String> {
    let url = url::Url::parse(http.public_url.as_deref()?).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// Whether the request names a host this server answers to. Rejecting other
/// names stops a web page from reaching the server through a DNS name it
/// controls.
fn host_allowed(http: &HttpConfig, host: &str) -> bool {
    let name = without_port(host);
    if matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
        return true;
    }
    if public_authority(http).is_some_and(|public| public == host || public == name) {
        return true;
    }
    http.allowed_hosts.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        entry == host || entry == name
    })
}

/// The request's `Origin` when it is on the allowlist; an error for an
/// origin that is not. Requests without an origin are not from a browser.
fn checked_origin(http: &HttpConfig, headers: &HeaderMap) -> Result<Option<HeaderValue>, ()> {
    let Some(value) = headers.get(header::ORIGIN) else {
        return Ok(None);
    };
    let origin = value.to_str().map_err(|_| ())?;
    let known = http
        .allowed_origins
        .iter()
        .any(|allowed| allowed.trim_end_matches('/').eq_ignore_ascii_case(origin));
    if known {
        Ok(Some(value.clone()))
    } else {
        Err(())
    }
}

fn add_cors(response: &mut Response, origin: Option<&HeaderValue>) {
    let Some(origin) = origin else { return };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate"),
    );
}

fn preflight(origin: Option<&HeaderValue>) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(&mut response, origin);
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, \
             Mcp-Method, Mcp-Name, Last-Event-ID",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Compare two digests without stopping at the first difference.
fn same_digest(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl HttpState {
    /// Identify the caller from its credential.
    fn authenticate(
        &self,
        http: &HttpConfig,
        headers: &HeaderMap,
    ) -> Result<Principal, &'static str> {
        let Some(token) = bearer(headers) else {
            return if http.require_auth {
                Err("no bearer token was sent")
            } else {
                Ok(Principal::anonymous())
            };
        };
        // Digests are compared, every configured token is looked at, and the
        // comparison does not stop early: timing says nothing about a token.
        let presented = Sha256::digest(token.as_bytes());
        let mut matched = false;
        for configured in &http.auth_tokens {
            matched |= same_digest(&Sha256::digest(configured.as_bytes()), &presented);
        }
        if matched {
            Ok(Principal::of_token(&presented))
        } else {
            Err("the bearer token is not valid")
        }
    }

    /// Count a failed authentication; `true` when the address has had too
    /// many recently.
    fn note_failure(&self, remote: Option<IpAddr>) -> bool {
        let Some(ip) = remote else { return false };
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        failures.retain(|_, f| f.since.elapsed() < FAILURE_WINDOW);
        let entry = failures.entry(ip).or_insert(Failures {
            count: 0,
            since: Instant::now(),
        });
        entry.count += 1;
        entry.count > MAX_FAILURES
    }

    fn binding(&self, session: &str) -> Option<Principal> {
        self.bindings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session)
            .cloned()
    }

    /// Remember who created a session, and forget sessions that are gone.
    async fn bind(&self, session: String, principal: Principal) {
        let live = self.sessions.sessions.read().await;
        let mut bindings = self.bindings.lock().unwrap_or_else(|e| e.into_inner());
        bindings.retain(|id, _| live.keys().any(|k| k.as_ref() == id.as_str()));
        bindings.insert(session, principal);
    }
}

/// Host, Origin and credential checks for every request, before its body is
/// read. See the module documentation.
async fn guard(State(state): State<Arc<HttpState>>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path == "/healthz" {
        return next.run(req).await;
    }
    let loaded = state.app.store().snapshot();
    let http = &loaded.config.transport.http;
    let remote = req.extensions().get::<Remote>().map(|r| r.0.ip());

    let host = requested_host(&req).unwrap_or_default();
    if !host_allowed(http, &host) {
        tracing::warn!(host = %host, remote = ?remote, "refused a request for an unknown host");
        return refuse(
            StatusCode::FORBIDDEN,
            "This server does not answer to that host name. The operator can add it to \
             [transport.http] allowed_hosts, or set public_url.",
        );
    }
    let Ok(origin) = checked_origin(http, req.headers()) else {
        tracing::warn!(remote = ?remote, "refused a request from an origin that is not allowed");
        return refuse(
            StatusCode::FORBIDDEN,
            "This origin is not allowed. The operator can add it to [transport.http] \
             allowed_origins.",
        );
    };
    let is_preflight = req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    if is_preflight {
        return preflight(origin.as_ref());
    }

    let principal = match state.authenticate(http, req.headers()) {
        Ok(principal) => principal,
        Err(reason) => {
            let limited = state.note_failure(remote);
            if !limited {
                tracing::warn!(remote = ?remote, reason, "authentication failed");
            }
            let mut response = if limited {
                let mut r = refuse(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed authentication attempts; wait a minute.",
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                r
            } else {
                let mut r = refuse(StatusCode::UNAUTHORIZED, format!("Unauthorized: {reason}."));
                r.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"nebula-mcp\""),
                );
                r
            };
            add_cors(&mut response, origin.as_ref());
            return response;
        }
    };

    // A session belongs to the credential that created it.
    let in_mcp = path == state.mcp_path || path.starts_with(&format!("{}/", state.mcp_path));
    let session = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut creating = false;
    if in_mcp {
        match &session {
            Some(id) => {
                if state.binding(id).is_some_and(|owner| owner != principal) {
                    tracing::warn!(
                        principal = principal.id(),
                        "refused a request for another client's session"
                    );
                    return refuse(StatusCode::NOT_FOUND, "Session not found.");
                }
            }
            // A POST with neither a session nor the per-request method header
            // of the stateless protocol can only be opening a legacy session.
            None if req.method() == Method::POST && !req.headers().contains_key(METHOD_HEADER) => {
                if state.sessions.sessions.read().await.len() >= http.max_sessions {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Too many sessions are open on this server; try again later.",
                    );
                }
                creating = true;
            }
            None => {}
        }
    }

    let deadline = Instant::now() + Duration::from_secs(http.read_timeout_secs.max(1));
    drop(loaded);
    req.extensions_mut().insert(principal.clone());
    let req = req.map(|body| Body::new(DeadlineBody::new(body, deadline)));

    let mut response = next.run(req).await;
    if creating {
        let created = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(id) = created {
            state.bind(id, principal).await;
        }
    }
    add_cors(&mut response, origin.as_ref());
    response
}

/// A request body that fails once its deadline passes, so a client cannot
/// hold a request open by sending its body slowly.
struct DeadlineBody {
    inner: Body,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl DeadlineBody {
    fn new(inner: Body, deadline: Instant) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep_until(deadline.into())),
        }
    }
}

impl http_body::Body for DeadlineBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request body was not received in time",
            )))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(public_url: Option<&str>, hosts: &[&str], origins: &[&str]) -> HttpConfig {
        HttpConfig {
            public_url: public_url.map(str::to_string),
            allowed_hosts: hosts.iter().map(|s| (*s).to_string()).collect(),
            allowed_origins: origins.iter().map(|s| (*s).to_string()).collect(),
            ..HttpConfig::default()
        }
    }

    #[test]
    fn hosts_are_loopback_the_public_url_or_listed() {
        let cfg = http(
            Some("https://mcp.example.com/mcp"),
            &["internal.lan:8765"],
            &[],
        );
        for ok in [
            "localhost",
            "localhost:8765",
            "127.0.0.1:1",
            "[::1]:8765",
            "mcp.example.com",
            "internal.lan:8765",
        ] {
            assert!(host_allowed(&cfg, ok), "{ok}");
        }
        for bad in [
            "evil.example",
            "mcp.example.com.evil.example",
            "internal.lan:1",
            "",
        ] {
            assert!(!host_allowed(&cfg, bad), "{bad}");
        }
    }

    #[test]
    fn origins_must_be_listed_and_absent_origins_pass() {
        let cfg = http(None, &[], &["https://app.example.com"]);
        let mut headers = HeaderMap::new();
        assert_eq!(checked_origin(&cfg, &headers), Ok(None));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.com"),
        );
        assert!(checked_origin(&cfg, &headers).unwrap().is_some());
        for bad in [
            "https://evil.example",
            "null",
            "https://app.example.com.evil.example",
        ] {
            headers.insert(header::ORIGIN, HeaderValue::from_static(bad));
            assert!(checked_origin(&cfg, &headers).is_err(), "{bad}");
        }
    }

    #[test]
    fn exposure_rules() {
        let loopback: SocketAddr = "127.0.0.1:8765".parse().unwrap();
        let public: SocketAddr = "0.0.0.0:8765".parse().unwrap();
        let mut cfg = HttpConfig::default();
        assert!(
            check_exposure(&cfg, &loopback).is_err(),
            "auth required, no credential"
        );
        cfg.auth_tokens = vec!["0123456789abcdef".into()];
        assert!(check_exposure(&cfg, &public).is_ok());
        cfg.require_auth = false;
        assert!(check_exposure(&cfg, &loopback).is_ok());
        assert!(
            check_exposure(&cfg, &public).is_err(),
            "no auth off loopback"
        );
    }

    #[test]
    fn digests_compare_fully() {
        assert!(same_digest(&[1, 2, 3], &[1, 2, 3]));
        assert!(!same_digest(&[1, 2, 3], &[1, 2, 4]));
        assert!(!same_digest(&[1, 2], &[1, 2, 3]));
        assert_eq!(bearer(&HeaderMap::new()), None);
    }
}
