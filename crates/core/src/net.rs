//! Outbound network access with a destination policy.
//!
//! [`Net`] is the only way a tool reaches the network, and it applies the
//! policy itself, so a tool author cannot forget a check:
//!
//! * network access must be enabled, and the host must pass the allowlist;
//! * a hostname is resolved once, **every** resolved address is classified and
//!   the host is refused if any one of them is not acceptable;
//! * the address that was vetted is the address that is connected to, so DNS
//!   cannot be re-answered between the check and the connection;
//! * loopback, private, link-local (including cloud metadata), carrier-grade
//!   NAT, unique-local, multicast, reserved and documentation ranges are refused
//!   unless the operator sets `[security] allow_private_network = true`, and
//!   unspecified, multicast and broadcast addresses are never allowed;
//! * redirects are followed here, one hop at a time, re-vetting each hop and
//!   dropping credentials when the origin changes;
//! * proxies, cookies and ambient connection settings are never used;
//! * TLS verifies against the bundled public web roots with an explicitly
//!   constructed crypto provider and cannot be told to skip verification.
//!
//! The same vetting is available for URLs that are handed to an external
//! program ([`Net::vet_url`]). That check cannot pin the program's own DNS
//! lookup: a program that resolves the name again is outside this guarantee.

use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::{Result, ToolError};
use crate::policy::NetPolicy;

const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECT_ATTEMPTS: usize = 8;
const MAX_VETTED_ADDRS: usize = 16;
const MAX_REDIRECTS: u8 = 10;
const MAX_URL_BYTES: usize = 8192;
const MAX_REQUEST_HEADERS: usize = 64;
const MAX_HEADER_NAME_BYTES: usize = 256;
const MAX_HEADER_VALUE_BYTES: usize = 8192;
const MAX_RESPONSE_HEADERS: usize = 100;
const MAX_RESPONSE_HEADER_VALUE: usize = 4096;
const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
const USER_AGENT: &str = concat!("nebula-mcp/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

/// What kind of destination an IP address is.
///
/// IPv6 forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64,
/// 6to4, Teredo) are classified by the embedded IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrClass {
    /// A globally routable unicast address.
    Public,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918 ranges and the deprecated IPv6 site-local range.
    Private,
    /// `169.254.0.0/16` (includes the cloud metadata address), `fe80::/10`.
    LinkLocal,
    /// Carrier-grade NAT, `100.64.0.0/10`.
    CarrierGradeNat,
    /// IPv6 unique-local, `fc00::/7`.
    UniqueLocal,
    /// `0.0.0.0/8` and `::`.
    Unspecified,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Documentation ranges (TEST-NET-1/2/3, `2001:db8::/32`, `3fff::/20`).
    Documentation,
    /// Benchmarking ranges (`198.18.0.0/15`, `2001:2::/48`).
    Benchmarking,
    /// Reserved or special-purpose space that is not globally routable
    /// (`240.0.0.0/4`, `192.0.0.0/24`, local-use NAT64, unallocated IPv6).
    Reserved,
}

impl AddrClass {
    /// A short phrase for error messages.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            AddrClass::Public => "public",
            AddrClass::Loopback => "loopback",
            AddrClass::Private => "private-network",
            AddrClass::LinkLocal => "link-local (this includes cloud metadata addresses)",
            AddrClass::CarrierGradeNat => "carrier-grade NAT",
            AddrClass::UniqueLocal => "unique-local",
            AddrClass::Unspecified => "unspecified",
            AddrClass::Multicast => "multicast",
            AddrClass::Broadcast => "broadcast",
            AddrClass::Documentation => "documentation-range",
            AddrClass::Benchmarking => "benchmarking-range",
            AddrClass::Reserved => "reserved",
        }
    }

    /// Whether the class is refused no matter what the operator configures.
    #[must_use]
    pub fn never_allowed(self) -> bool {
        matches!(
            self,
            AddrClass::Unspecified | AddrClass::Multicast | AddrClass::Broadcast
        )
    }

    /// Whether a destination of this class may be contacted.
    #[must_use]
    pub fn allowed(self, allow_private: bool) -> bool {
        match self {
            AddrClass::Public => true,
            c if c.never_allowed() => false,
            _ => allow_private,
        }
    }
}

/// Classify an IP address. See [`AddrClass`].
#[must_use]
pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => classify_v6(a),
    }
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    if a.is_broadcast() {
        return AddrClass::Broadcast;
    }
    let [o0, o1, o2, _] = a.octets();
    match (o0, o1, o2) {
        (0, _, _) => AddrClass::Unspecified,
        (10, _, _) => AddrClass::Private,
        (100, 64..=127, _) => AddrClass::CarrierGradeNat,
        (127, _, _) => AddrClass::Loopback,
        (169, 254, _) => AddrClass::LinkLocal,
        (172, 16..=31, _) => AddrClass::Private,
        (192, 0, 0) | (192, 88, 99) => AddrClass::Reserved,
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => AddrClass::Documentation,
        (192, 168, _) => AddrClass::Private,
        (198, 18..=19, _) => AddrClass::Benchmarking,
        (224..=239, _, _) => AddrClass::Multicast,
        (240..=255, _, _) => AddrClass::Reserved,
        _ => AddrClass::Public,
    }
}

fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

fn classify_v6(a: Ipv6Addr) -> AddrClass {
    if a.is_unspecified() {
        return AddrClass::Unspecified;
    }
    if a.is_loopback() {
        return AddrClass::Loopback;
    }
    let s = a.segments();
    let low_zero = s[..5] == [0; 5];
    // ::ffff:a.b.c.d (mapped) and the deprecated ::a.b.c.d (compatible).
    if low_zero && (s[5] == 0xffff || s[5] == 0) {
        return classify_v4(v4_from_segments(s[6], s[7]));
    }
    // NAT64 well-known prefix 64:ff9b::/96 embeds the target in the low 32 bits.
    if s[0] == 0x64 && s[1] == 0xff9b {
        if s[2..6] == [0; 4] {
            return classify_v4(v4_from_segments(s[6], s[7]));
        }
        // 64:ff9b:1::/48 is local-use NAT64: the embedding offset varies.
        if s[2] == 1 {
            return AddrClass::Reserved;
        }
    }
    // 6to4 2002::/16 embeds the gateway IPv4 address in bits 16..48.
    if s[0] == 0x2002 {
        return classify_v4(v4_from_segments(s[1], s[2]));
    }
    // Teredo 2001::/32: server IPv4 in bits 32..64, obfuscated client IPv4 in the low 32.
    if s[0] == 0x2001 && s[1] == 0 {
        let server = classify_v4(v4_from_segments(s[2], s[3]));
        let client = classify_v4(v4_from_segments(!s[6], !s[7]));
        return if client != AddrClass::Public {
            client
        } else {
            server
        };
    }
    if (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x3fff && s[1] < 0x1000) {
        return AddrClass::Documentation;
    }
    if s[0] == 0x2001 && s[1] == 2 && s[2] == 0 {
        return AddrClass::Benchmarking;
    }
    if s[0] == 0x100 && s[1..4] == [0; 3] {
        return AddrClass::Reserved;
    }
    match s[0] {
        x if x & 0xfe00 == 0xfc00 => AddrClass::UniqueLocal,
        x if x & 0xffc0 == 0xfe80 => AddrClass::LinkLocal,
        x if x & 0xffc0 == 0xfec0 => AddrClass::Private,
        x if x & 0xff00 == 0xff00 => AddrClass::Multicast,
        x if x & 0xe000 == 0x2000 => AddrClass::Public,
        _ => AddrClass::Reserved,
    }
}

// ---------------------------------------------------------------------------
// Host and URL parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostKind {
    Ip(IpAddr),
    Domain(String),
}

impl HostKind {
    /// The string the host allowlist is matched against.
    fn name(&self) -> String {
        match self {
            HostKind::Ip(ip) => ip.to_string(),
            HostKind::Domain(d) => d.clone(),
        }
    }
}

/// Parse and normalise a host name or IP literal.
fn parse_host(raw: &str) -> Result<HostKind> {
    let inner = match raw.strip_prefix('[') {
        Some(rest) => match rest.strip_suffix(']') {
            Some(v6) if v6.contains(':') => v6,
            _ => {
                return Err(ToolError::invalid(
                    "a bracketed host must be an IPv6 address such as [::1]",
                ))
            }
        },
        None => raw,
    };
    if inner.is_empty() {
        return Err(ToolError::invalid("the host is empty"));
    }
    if inner.len() > 253 {
        return Err(ToolError::invalid("the host is longer than 253 bytes"));
    }
    if inner.contains(':') {
        return Ipv6Addr::from_str(inner)
            .map(|a| HostKind::Ip(IpAddr::V6(a)))
            .map_err(|_| {
                ToolError::invalid(format!(
                    "'{}' is not a valid IPv6 address (scope ids such as %eth0 are not accepted)",
                    inner.escape_debug()
                ))
            });
    }
    if let Some(c) = inner.chars().find(|c| !c.is_ascii()) {
        return Err(ToolError::invalid(format!(
            "the host contains the non-ASCII character '{c}'; give internationalised names in \
             their ASCII (punycode, xn--) form"
        )));
    }
    let lowered = inner.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    if name.is_empty() {
        return Err(ToolError::invalid("the host is empty"));
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(ToolError::invalid(format!(
            "the host contains the character '{}', which is not allowed in a host name",
            c.escape_debug()
        )));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ToolError::invalid(
                "every dot-separated part of a host must be 1 to 63 characters long",
            ));
        }
    }
    // A last label that starts with a digit is a number to inet_aton and to
    // browsers (`0x7f.1`, `0177.0.0.1`, `2130706433`, `127.1`), so only the
    // canonical dotted quad is accepted.
    let last = name.rsplit('.').next().unwrap_or(name);
    if last.starts_with(|c: char| c.is_ascii_digit()) {
        return match Ipv4Addr::from_str(name) {
            Ok(ip) => Ok(HostKind::Ip(IpAddr::V4(ip))),
            Err(_) => Err(ToolError::invalid(format!(
                "'{name}' looks like an abbreviated, octal or hexadecimal IPv4 address, which \
                 different programs read differently; write it as a dotted quad such as 127.0.0.1"
            ))),
        };
    }
    Ok(HostKind::Domain(name.to_string()))
}

struct ParsedUrl {
    url: Url,
    host: HostKind,
    port: u16,
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ssh" => Some(22),
        "git" => Some(9418),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Parse `input` strictly: the host is read from the text itself and must
/// agree with what the URL library makes of it, so a parser difference
/// between this check and the connection cannot hide a destination.
fn parse_url(input: &str, schemes: &[&str], allow_userinfo: bool) -> Result<ParsedUrl> {
    if input.len() > MAX_URL_BYTES {
        return Err(ToolError::invalid(format!(
            "the URL is longer than {MAX_URL_BYTES} bytes"
        )));
    }
    if let Some(c) = input
        .chars()
        .find(|c| c.is_ascii_control() || *c == ' ' || *c == '\\')
    {
        return Err(ToolError::invalid(format!(
            "the URL contains the character '{}'; percent-encode it (for example %20 for a space)",
            c.escape_debug()
        )));
    }
    let not_absolute = || {
        ToolError::invalid(
            "the URL must be absolute and include a scheme and host, for example \
             https://example.com/path",
        )
    };
    let (scheme_raw, rest) = input.split_once("://").ok_or_else(not_absolute)?;
    let scheme_ok = scheme_raw.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return Err(not_absolute());
    }
    let scheme = scheme_raw.to_ascii_lowercase();
    if !schemes.iter().any(|s| s.eq_ignore_ascii_case(&scheme)) {
        return Err(ToolError::invalid(format!(
            "the URL scheme '{scheme}' is not supported here; use one of: {}",
            schemes.join(", ")
        )));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    if userinfo.is_some() && !allow_userinfo {
        return Err(ToolError::invalid(
            "URLs that embed credentials (user:password@host) are not accepted; send credentials \
             in a header instead",
        ));
    }
    let (host_text, port_text) = if hostport.starts_with('[') {
        let end = hostport.find(']').ok_or_else(not_absolute)?;
        let after = &hostport[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err(not_absolute()),
        };
        (&hostport[..=end], port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let host = parse_host(host_text)?;
    let explicit_port = match port_text {
        None | Some("") => None,
        Some(p) => {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ToolError::invalid(format!(
                    "'{p}' is not a valid port number"
                )));
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => {
                    return Err(ToolError::invalid(format!(
                        "port '{p}' is out of range; use 1 to 65535"
                    )))
                }
                Ok(n) => Some(n),
            }
        }
    };
    let port = explicit_port
        .or_else(|| default_port(&scheme))
        .ok_or_else(|| {
            ToolError::invalid(format!(
                "the URL has no port and the scheme '{scheme}' has no default port; add :<port>"
            ))
        })?;

    let url = Url::parse(input).map_err(|e| ToolError::invalid(format!("invalid URL: {e}")))?;
    let url_host = url
        .host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let agrees = match (&host, url_host) {
        (HostKind::Ip(ip), Some(h)) => IpAddr::from_str(&h).is_ok_and(|u| u == *ip),
        (HostKind::Domain(d), Some(h)) => *d == h,
        (_, None) => false,
    };
    let url_port = url.port().or_else(|| default_port(url.scheme()));
    if url.scheme() != scheme || !agrees || url_port != Some(port) {
        return Err(ToolError::invalid(
            "the URL is ambiguous: its host or port is read differently by the URL parser; \
             write it as scheme://host[:port]/path",
        ));
    }
    if !allow_userinfo && (!url.username().is_empty() || url.password().is_some()) {
        return Err(ToolError::invalid(
            "URLs that embed credentials (user:password@host) are not accepted",
        ));
    }
    Ok(ParsedUrl { url, host, port })
}

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// A URL whose destination passed the policy.
#[derive(Debug, Clone)]
pub struct Vetted {
    /// The parsed, normalised URL.
    pub url: Url,
    /// The host as matched against the allowlist (lower-case name or IP literal).
    pub host: String,
    /// The port, explicit or the scheme default.
    pub port: u16,
    /// The vetted addresses. Connecting to anything else is a policy bypass.
    pub addrs: Vec<SocketAddr>,
}

impl Vetted {
    fn host_header(&self) -> String {
        let host = match IpAddr::from_str(&self.host) {
            Ok(IpAddr::V6(_)) => format!("[{}]", self.host),
            _ => self.host.clone(),
        };
        if default_port(self.url.scheme()) == Some(self.port) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// One HTTP exchange to perform with [`Net::http`] or [`Net::http_download`].
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS (case-insensitive).
    pub method: String,
    /// An absolute http or https URL without embedded credentials.
    pub url: String,
    /// Extra request headers. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
    /// `Upgrade`, `Proxy-*`, `TE` and `Trailer` are managed here and cannot be set.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Option<Vec<u8>>,
    /// Total time allowed for the whole exchange including redirects (at least one second).
    pub timeout: Duration,
    /// How many redirects to follow, at most 10. Zero returns the redirect response itself.
    pub max_redirects: u8,
    /// The most response-body bytes to keep in memory.
    pub max_body_bytes: usize,
}

impl HttpRequest {
    /// A request with a 30 second timeout, up to 5 redirects and a 1 MiB body cap.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// The result of [`Net::http`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The final status code.
    pub status: u16,
    /// Response headers with lower-case names (at most 100, values cut at 4096 bytes).
    pub headers: Vec<(String, String)>,
    /// The body, at most the smaller of the request cap and the call's output cap.
    pub body: Vec<u8>,
    /// Whether the body was cut at the cap.
    pub truncated: bool,
    /// The full body size: from `Content-Length` when sent, otherwise the number of bytes read
    /// when the whole body was read.
    pub body_bytes_total: Option<u64>,
    /// The URL that produced this response.
    pub final_url: String,
    /// The URLs that answered with a redirect that was followed, in order.
    pub redirects: Vec<String>,
    /// The address of the server that produced this response.
    pub remote_addr: Option<SocketAddr>,
    /// Whether a redirect from https to http was followed.
    pub scheme_downgraded: bool,
}

/// The result of [`Net::http_download`].
#[derive(Debug, Clone)]
pub struct Download {
    /// The final status code. The body is written only when this is 2xx.
    pub status: u16,
    /// Response headers (see [`HttpResponse::headers`]).
    pub headers: Vec<(String, String)>,
    /// Bytes written to the sink.
    pub bytes_written: u64,
    /// The URL that produced the response.
    pub final_url: String,
    /// The URLs that answered with a redirect that was followed, in order.
    pub redirects: Vec<String>,
    /// The address of the server that produced the response.
    pub remote_addr: Option<SocketAddr>,
    /// Whether a redirect from https to http was followed.
    pub scheme_downgraded: bool,
}

/// An established, verified TLS session. See [`Net::connect_tls`].
pub struct TlsConnection {
    /// The encrypted stream.
    pub stream: tokio_rustls::client::TlsStream<TcpStream>,
    /// The address connected to.
    pub remote_addr: SocketAddr,
    /// `TLSv1.3`, `TLSv1.2`, ...
    pub protocol_version: String,
    /// The negotiated cipher suite, for example `TLS13_AES_256_GCM_SHA384`.
    pub cipher_suite: String,
    /// The negotiated ALPN protocol (`h2`, `http/1.1`), if any.
    pub alpn: Option<String>,
    /// The peer's certificate chain in DER, leaf first.
    pub peer_certificates: Vec<Vec<u8>>,
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnection")
            .field("remote_addr", &self.remote_addr)
            .field("protocol_version", &self.protocol_version)
            .field("cipher_suite", &self.cipher_suite)
            .field("alpn", &self.alpn)
            .field("certificates", &self.peer_certificates.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

fn build_tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[allow(clippy::expect_used)]
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

fn http1_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| build_tls_config(&[b"http/1.1"]))
        .clone()
}

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
trait Resolve: Send + Sync {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

struct SystemResolver;

#[async_trait::async_trait]
impl Resolve for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host((host, 0)).await?;
        Ok(addrs.map(|a| a.ip()).collect())
    }
}

// ---------------------------------------------------------------------------
// The capability
// ---------------------------------------------------------------------------

/// Network capability bound to one tool call's policy.
#[derive(Clone)]
pub struct Net {
    policy: NetPolicy,
    cancel: CancellationToken,
    max_bytes: usize,
    resolver: Arc<dyn Resolve>,
}

impl Net {
    /// Bind the network to `policy`. Every operation stops with
    /// [`ToolError::Cancelled`] when `cancel` fires, and in-memory response
    /// bodies are capped at `max_bytes`.
    #[must_use]
    pub(crate) fn new(policy: NetPolicy, cancel: CancellationToken, max_bytes: usize) -> Self {
        Self {
            policy,
            cancel,
            max_bytes,
            resolver: Arc::new(SystemResolver),
        }
    }

    #[cfg(test)]
    fn with_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = resolver;
        self
    }

    fn require_enabled(&self) -> Result<()> {
        if self.policy.enabled() {
            Ok(())
        } else {
            Err(ToolError::denied(
                "network access is disabled. The operator can enable it with \
                 [security] allow_network = true (or allow_network = true under the tool's \
                 [tools.<name>] section)",
            ))
        }
    }

    /// Race `fut` against cancellation and a time limit.
    async fn guarded<T>(&self, limit: Duration, fut: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(ToolError::Cancelled),
            r = tokio::time::timeout(limit, fut) => match r {
                Ok(v) => v,
                Err(_) => Err(ToolError::Timeout(limit)),
            },
        }
    }

    /// Resolve `host` and check the policy for it.
    ///
    /// Requires network access to be enabled and the host to be on the
    /// allowlist, and every resolved address to be an acceptable destination.
    /// IP literals are parsed rather than resolved. Returns the vetted
    /// addresses, which are the only ones a connection may use.
    pub async fn vet(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.require_enabled()?;
        if port == 0 {
            return Err(ToolError::invalid("the port must be between 1 and 65535"));
        }
        let kind = parse_host(host)?;
        self.guarded(DNS_TIMEOUT * 2, self.vet_kind(&kind, port))
            .await
    }

    /// Parse `url`, require its scheme to be one of `schemes`, and vet its host.
    ///
    /// Embedded credentials, empty hosts, port 0 and obfuscated IPv4 forms are
    /// rejected. Use this before handing a URL to an external program; the
    /// program's own lookup is not pinned (see the module documentation).
    pub async fn vet_url(&self, url: &str, schemes: &[&str]) -> Result<Vetted> {
        self.vet_url_with(url, schemes, false).await
    }

    /// Like [`Net::vet_url`], optionally accepting `user@host` (for example
    /// `ssh://git@host/repo`). Passwords in URLs are still discouraged.
    pub async fn vet_url_with(
        &self,
        url: &str,
        schemes: &[&str],
        allow_userinfo: bool,
    ) -> Result<Vetted> {
        self.require_enabled()?;
        let parsed = parse_url(url, schemes, allow_userinfo)?;
        let addrs = self
            .guarded(DNS_TIMEOUT * 2, self.vet_kind(&parsed.host, parsed.port))
            .await?;
        Ok(Vetted {
            host: parsed.host.name(),
            port: parsed.port,
            url: parsed.url,
            addrs,
        })
    }

    async fn vet_kind(&self, kind: &HostKind, port: u16) -> Result<Vec<SocketAddr>> {
        let name = kind.name();
        if !self.policy.host_allowed(&name) {
            return Err(ToolError::NetworkNotAllowed(format!(
                "host '{name}' is not on the allowlist. The operator can add it to \
                 [security] allowed_hosts"
            )));
        }
        let ips = match kind {
            HostKind::Ip(ip) => vec![ip.to_canonical()],
            HostKind::Domain(d) => self.lookup(d).await?,
        };
        let mut addrs: Vec<SocketAddr> = Vec::with_capacity(ips.len().min(MAX_VETTED_ADDRS));
        for ip in ips {
            let class = classify(ip);
            if !class.allowed(self.policy.allow_private()) {
                return Err(refused(&name, ip, class));
            }
            let addr = SocketAddr::new(ip, port);
            if addrs.len() < MAX_VETTED_ADDRS && !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        Ok(addrs)
    }

    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        let found = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(ToolError::Cancelled),
            r = tokio::time::timeout(DNS_TIMEOUT, self.resolver.resolve(host)) => match r {
                Ok(r) => r,
                Err(_) => return Err(ToolError::Timeout(DNS_TIMEOUT)),
            },
        };
        let ips =
            found.map_err(|e| ToolError::Io(format!("DNS lookup for '{host}' failed: {e}")))?;
        if ips.is_empty() {
            return Err(ToolError::Io(format!(
                "DNS lookup for '{host}' returned no addresses"
            )));
        }
        Ok(ips)
    }

    /// Open a TCP connection to `host:port`.
    ///
    /// The host is vetted once and each vetted address is tried in turn; the
    /// name is never resolved again.
    pub async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr)> {
        self.require_enabled()?;
        if port == 0 {
            return Err(ToolError::invalid("the port must be between 1 and 65535"));
        }
        let kind = parse_host(host)?;
        let timeout = timeout.max(Duration::from_secs(1));
        self.guarded(timeout, async {
            let addrs = self.vet_kind(&kind, port).await?;
            self.connect_addrs(&format!("{}:{port}", kind.name()), &addrs, timeout)
                .await
        })
        .await
    }

    async fn connect_addrs(
        &self,
        label: &str,
        addrs: &[SocketAddr],
        timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr)> {
        let start = Instant::now();
        let total = addrs.len().min(MAX_CONNECT_ATTEMPTS);
        let mut failures = Vec::new();
        let mut timeouts = 0;
        for (i, addr) in addrs.iter().take(total).enumerate() {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            let share = left / u32::try_from(total - i).unwrap_or(1);
            match tokio::time::timeout(share, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, *addr));
                }
                Ok(Err(e)) => failures.push(format!("{addr}: {e}")),
                Err(_) => {
                    timeouts += 1;
                    failures.push(format!("{addr}: timed out"));
                }
            }
        }
        if timeouts > 0 && timeouts == failures.len() {
            return Err(ToolError::Timeout(timeout));
        }
        Err(ToolError::Io(format!(
            "could not connect to {label} ({})",
            failures.join("; ")
        )))
    }

    /// The shared TLS client configuration: an explicit aws-lc-rs provider,
    /// the bundled public web roots and no way to disable verification.
    ///
    /// Offers `h2` and `http/1.1`.
    #[must_use]
    pub fn tls_config() -> Arc<ClientConfig> {
        static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
        CONFIG
            .get_or_init(|| build_tls_config(&[b"h2", b"http/1.1"]))
            .clone()
    }

    /// Connect to `host:port` and complete a verified TLS handshake.
    ///
    /// Fails with the TLS reason when the certificate is not trusted or does
    /// not match the host. Does not depend on a process-wide crypto provider.
    pub async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<TlsConnection> {
        self.connect_tls_with(Self::tls_config(), host, port, timeout)
            .await
    }

    async fn connect_tls_with(
        &self,
        config: Arc<ClientConfig>,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<TlsConnection> {
        self.require_enabled()?;
        if port == 0 {
            return Err(ToolError::invalid("the port must be between 1 and 65535"));
        }
        let kind = parse_host(host)?;
        let timeout = timeout.max(Duration::from_secs(1));
        self.guarded(timeout, async {
            let addrs = self.vet_kind(&kind, port).await?;
            let label = format!("{}:{port}", kind.name());
            let (tcp, remote_addr) = self.connect_addrs(&label, &addrs, timeout).await?;
            let stream = tls_handshake(config, &kind.name(), &label, tcp).await?;
            let (_, conn) = stream.get_ref();
            let protocol_version = match conn.protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
                Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
                Some(other) => format!("{other:?}"),
                None => "unknown".to_string(),
            };
            let cipher_suite = conn
                .negotiated_cipher_suite()
                .map_or_else(|| "unknown".to_string(), |c| format!("{:?}", c.suite()));
            let alpn = conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned());
            let peer_certificates = conn
                .peer_certificates()
                .map(|chain| chain.iter().map(|c| c.as_ref().to_vec()).collect())
                .unwrap_or_default();
            Ok(TlsConnection {
                stream,
                remote_addr,
                protocol_version,
                cipher_suite,
                alpn,
                peer_certificates,
            })
        })
        .await
    }

    /// Perform one HTTP exchange, following redirects manually.
    ///
    /// The response body is read into memory up to the smaller of
    /// `req.max_body_bytes` and the cap this [`Net`] was created with.
    pub async fn http(&self, req: HttpRequest) -> Result<HttpResponse> {
        self.require_enabled()?;
        let prepared = Prepared::new(&req)?;
        let cap = req.max_body_bytes.min(self.max_bytes);
        self.guarded(prepared.timeout, async {
            let mut ex = self.follow(&prepared).await?;
            let content_length = content_length(ex.resp.headers());
            let (body, truncated) = read_capped(&mut ex.resp, cap, content_length).await?;
            let body_bytes_total = content_length
                .or_else(|| (!truncated).then(|| u64::try_from(body.len()).unwrap_or(u64::MAX)));
            Ok(HttpResponse {
                status: ex.status,
                headers: response_headers(ex.resp.headers()),
                body,
                truncated,
                body_bytes_total,
                final_url: ex.final_url.to_string(),
                redirects: ex.redirects,
                remote_addr: Some(ex.remote_addr),
                scheme_downgraded: ex.downgraded,
            })
        })
        .await
    }

    /// Like [`Net::http`], but writes the body to `sink` instead of memory.
    ///
    /// Nothing is written unless the final status is 2xx. A body larger than
    /// `max_bytes` fails with [`ToolError::LimitExceeded`] (immediately when
    /// `Content-Length` says so); the caller removes any partial output.
    /// The sink is written synchronously, so it should be a local file.
    pub async fn http_download(
        &self,
        req: HttpRequest,
        sink: &mut (dyn Write + Send),
        max_bytes: u64,
    ) -> Result<Download> {
        self.require_enabled()?;
        let prepared = Prepared::new(&req)?;
        self.guarded(prepared.timeout, async {
            let mut ex = self.follow(&prepared).await?;
            let mut bytes_written = 0u64;
            if (200..300).contains(&ex.status) {
                if let Some(len) = content_length(ex.resp.headers()) {
                    if len > max_bytes {
                        return Err(download_too_large(max_bytes));
                    }
                }
                while let Some(frame) = ex.resp.body_mut().frame().await {
                    let frame = frame.map_err(|e| body_error(&e))?;
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    bytes_written += data.len() as u64;
                    if bytes_written > max_bytes {
                        return Err(download_too_large(max_bytes));
                    }
                    sink.write_all(&data).map_err(|e| {
                        ToolError::Io(format!("writing the downloaded data failed: {e}"))
                    })?;
                }
                sink.flush()
                    .map_err(|e| ToolError::Io(format!("flushing the download failed: {e}")))?;
            }
            Ok(Download {
                status: ex.status,
                headers: response_headers(ex.resp.headers()),
                bytes_written,
                final_url: ex.final_url.to_string(),
                redirects: ex.redirects,
                remote_addr: Some(ex.remote_addr),
                scheme_downgraded: ex.downgraded,
            })
        })
        .await
    }

    /// Send the request and follow redirects until a final response.
    async fn follow(&self, req: &Prepared) -> Result<Exchange> {
        let mut method = req.method.clone();
        let mut headers = req.headers.clone();
        let mut body = req.body.clone();
        let mut url = req.url.clone();
        let mut redirects: Vec<String> = Vec::new();
        let mut downgraded = false;
        let connect_timeout = req.timeout.min(Duration::from_secs(30));
        loop {
            let hop = if redirects.is_empty() {
                None
            } else {
                redirects.last().cloned()
            };
            let vetted = self
                .vet_url(&url, &["http", "https"])
                .await
                .map_err(|e| match &hop {
                    Some(from) => redirect_error(e, from, &url),
                    None => e,
                })?;
            let (resp, guard, remote_addr) = self
                .send_once(&vetted, &method, &headers, body.as_deref(), connect_timeout)
                .await?;
            let status = resp.status().as_u16();
            let location = if req.max_redirects > 0 && is_redirect(status) {
                resp.headers().get(http::header::LOCATION).cloned()
            } else {
                None
            };
            let Some(location) = location else {
                return Ok(Exchange {
                    resp,
                    _guard: guard,
                    status,
                    final_url: vetted.url,
                    redirects,
                    remote_addr,
                    downgraded,
                });
            };
            drop(resp);
            drop(guard);
            if redirects.len() >= usize::from(req.max_redirects) {
                return Err(ToolError::LimitExceeded(format!(
                    "stopped after {} redirects (the limit); the last one pointed to {}",
                    req.max_redirects,
                    String::from_utf8_lossy(location.as_bytes())
                )));
            }
            let target = location
                .to_str()
                .ok()
                .and_then(|l| vetted.url.join(l).ok())
                .ok_or_else(|| {
                    ToolError::Execution(format!(
                        "the server at {} sent a redirect with an unusable Location header",
                        vetted.url
                    ))
                })?;
            let plan = plan_redirect(status, &method, &vetted.url, &target)
                .map_err(|e| redirect_error(e, vetted.url.as_str(), target.as_str()))?;
            if plan.cross_origin {
                strip_credentials(&mut headers);
            }
            if plan.drop_body {
                body = None;
                headers.retain(|(n, _)| {
                    !matches!(
                        n.to_ascii_lowercase().as_str(),
                        "content-type" | "content-encoding" | "content-language"
                    )
                });
            }
            downgraded |= plan.downgraded;
            method = plan.method;
            redirects.push(vetted.url.to_string());
            url = target.to_string();
        }
    }

    async fn send_once(
        &self,
        vetted: &Vetted,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        connect_timeout: Duration,
    ) -> Result<(http::Response<Incoming>, ConnGuard, SocketAddr)> {
        let label = format!("{}:{}", vetted.host, vetted.port);
        let (tcp, remote) = self
            .connect_addrs(&label, &vetted.addrs, connect_timeout)
            .await?;
        let request = build_request(vetted, method, headers, body)?;
        let (resp, guard) = if vetted.url.scheme() == "https" {
            let tls = tls_handshake(http1_tls_config(), &vetted.host, &label, tcp).await?;
            exchange(tls, request, &label).await?
        } else {
            exchange(tcp, request, &label).await?
        };
        Ok((resp, guard, remote))
    }
}

fn refused(host: &str, ip: IpAddr, class: AddrClass) -> ToolError {
    let subject = if host == ip.to_string() {
        format!("the address {ip}")
    } else {
        format!("'{host}' resolves to {ip}, which")
    };
    let desc = class.description();
    if class.never_allowed() {
        ToolError::NetworkNotAllowed(format!(
            "{subject} is a {desc} address, and those are never allowed"
        ))
    } else {
        ToolError::NetworkNotAllowed(format!(
            "{subject} is a {desc} address. Connections to non-public destinations are \
             refused; the operator can allow them with [security] allow_private_network = true"
        ))
    }
}

fn redirect_error(e: ToolError, from: &str, to: &str) -> ToolError {
    match e {
        ToolError::InvalidArguments(m) | ToolError::NetworkNotAllowed(m) => {
            ToolError::NetworkNotAllowed(format!(
                "the redirect from {from} to {to} was refused: {m}"
            ))
        }
        other => other,
    }
}

fn download_too_large(max: u64) -> ToolError {
    ToolError::LimitExceeded(format!(
        "the response body is larger than the {max} byte limit; raise the limit or request a \
         smaller resource"
    ))
}

// ---------------------------------------------------------------------------
// Requests, redirects, responses
// ---------------------------------------------------------------------------

struct Prepared {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
    max_redirects: u8,
}

impl Prepared {
    fn new(req: &HttpRequest) -> Result<Self> {
        let method = req.method.trim().to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return Err(ToolError::invalid(format!(
                "unsupported HTTP method '{}'; use GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS",
                req.method.escape_debug()
            )));
        }
        validate_headers(&req.headers)?;
        Ok(Self {
            method,
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            timeout: req.timeout.max(Duration::from_secs(1)),
            max_redirects: req.max_redirects.min(MAX_REDIRECTS),
        })
    }
}

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_headers(headers: &[(String, String)]) -> Result<()> {
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(ToolError::invalid(format!(
            "too many request headers ({}); the limit is {MAX_REQUEST_HEADERS}",
            headers.len()
        )));
    }
    for (name, value) in headers {
        if name.len() > MAX_HEADER_NAME_BYTES || !is_token(name) {
            return Err(ToolError::invalid(format!(
                "'{}' is not a valid header name; use letters, digits and - only, for example \
                 Authorization",
                name.escape_debug()
            )));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "upgrade"
                | "te"
                | "trailer"
        ) || lower.starts_with("proxy-")
        {
            return Err(ToolError::invalid(format!(
                "the header '{name}' is set by the server and cannot be supplied"
            )));
        }
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(ToolError::invalid(format!(
                "the value of header '{name}' is longer than {MAX_HEADER_VALUE_BYTES} bytes"
            )));
        }
        if value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0 || (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err(ToolError::invalid(format!(
                "the value of header '{name}' contains a control character (CR, LF or NUL are \
                 never allowed)"
            )));
        }
    }
    Ok(())
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[derive(Debug, PartialEq, Eq)]
struct RedirectPlan {
    method: String,
    drop_body: bool,
    downgraded: bool,
    cross_origin: bool,
}

fn origin(u: &Url) -> (String, String, Option<u16>) {
    (
        u.scheme().to_string(),
        u.host_str().unwrap_or_default().to_ascii_lowercase(),
        u.port_or_known_default(),
    )
}

/// Decide how a redirect is followed: the next method, whether the body goes,
/// whether the scheme is downgraded and whether credentials must be dropped.
fn plan_redirect(status: u16, method: &str, from: &Url, to: &Url) -> Result<RedirectPlan> {
    let (next_method, drop_body) = match status {
        303 if method == "HEAD" => ("HEAD", true),
        303 => ("GET", true),
        301 | 302 if method == "POST" => ("GET", true),
        _ => (method, false),
    };
    let downgraded = from.scheme() == "https" && to.scheme() == "http";
    if downgraded && !matches!(next_method, "GET" | "HEAD") {
        return Err(ToolError::NetworkNotAllowed(format!(
            "a {next_method} request is not repeated over plain http after an https URL \
             redirected to it; request the http URL directly if that is intended"
        )));
    }
    Ok(RedirectPlan {
        method: next_method.to_string(),
        drop_body,
        downgraded,
        cross_origin: origin(from) != origin(to),
    })
}

fn is_credential_header(lower: &str) -> bool {
    matches!(lower, "authorization" | "proxy-authorization" | "cookie")
        || (lower.starts_with("x-") && ["token", "key", "secret"].iter().any(|w| lower.contains(w)))
        || ["token", "secret", "password", "api-key", "apikey"]
            .iter()
            .any(|w| lower.contains(w))
}

fn strip_credentials(headers: &mut Vec<(String, String)>) {
    headers.retain(|(n, _)| !is_credential_header(&n.to_ascii_lowercase()));
}

fn build_request(
    vetted: &Vetted,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<http::Request<Full<Bytes>>> {
    let mut target = vetted.url.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(q) = vetted.url.query() {
        target.push('?');
        target.push_str(q);
    }
    let mut builder = http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, vetted.host_header())
        .header(http::header::CONNECTION, "close");
    let has = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    if !has("user-agent") {
        builder = builder.header(http::header::USER_AGENT, USER_AGENT);
    }
    if !has("accept") {
        builder = builder.header(http::header::ACCEPT, "*/*");
    }
    if !has("accept-encoding") {
        builder = builder.header(http::header::ACCEPT_ENCODING, "identity");
    }
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let payload = body.map_or_else(Bytes::new, Bytes::copy_from_slice);
    builder
        .body(Full::new(payload))
        .map_err(|e| ToolError::invalid(format!("the request could not be built: {e}")))
}

/// Keeps the connection task alive and stops it when dropped, so no task
/// outlives the call that started it.
struct ConnGuard {
    task: tokio::task::JoinHandle<()>,
    _sender: http1::SendRequest<Full<Bytes>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Exchange {
    resp: http::Response<Incoming>,
    _guard: ConnGuard,
    status: u16,
    final_url: Url,
    redirects: Vec<String>,
    remote_addr: SocketAddr,
    downgraded: bool,
}

async fn exchange<S>(
    io: S,
    request: http::Request<Full<Bytes>>,
    label: &str,
) -> Result<(http::Response<Incoming>, ConnGuard)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::Builder::new()
        .max_headers(MAX_RESPONSE_HEADERS * 2)
        .max_header_size(MAX_RESPONSE_HEAD_BYTES)
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| {
            ToolError::Execution(format!("HTTP handshake with {label} failed: {}", chain(&e)))
        })?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = match sender.send_request(request).await {
        Ok(r) => r,
        Err(e) => {
            task.abort();
            return Err(ToolError::Execution(format!(
                "the request to {label} failed: {}",
                chain(&e)
            )));
        }
    };
    Ok((
        resp,
        ConnGuard {
            task,
            _sender: sender,
        },
    ))
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    out
}

fn body_error(e: &hyper::Error) -> ToolError {
    ToolError::Execution(format!("reading the response body failed: {}", chain(e)))
}

fn content_length(headers: &http::HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
    let first = values.next()?.to_str().ok()?.trim().parse::<u64>().ok()?;
    values
        .all(|v| v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok()) == Some(first))
        .then_some(first)
}

/// Read at most `cap` body bytes. Returns the bytes and whether more existed.
async fn read_capped(
    resp: &mut http::Response<Incoming>,
    cap: usize,
    content_length: Option<u64>,
) -> Result<(Vec<u8>, bool)> {
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    let mut truncated = false;
    while let Some(frame) = resp.body_mut().frame().await {
        let frame = frame.map_err(|e| body_error(&e))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let room = cap - buf.len();
        if data.len() > room {
            buf.extend_from_slice(&data[..room]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&data);
        if buf.len() == cap && content_length.is_some_and(|c| c > cap as u64) {
            truncated = true;
            break;
        }
    }
    Ok((buf, truncated))
}

fn response_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .take(MAX_RESPONSE_HEADERS)
        .map(|(name, value)| {
            let mut text = String::from_utf8_lossy(value.as_bytes()).into_owned();
            if text.len() > MAX_RESPONSE_HEADER_VALUE {
                let mut cut = MAX_RESPONSE_HEADER_VALUE;
                while !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                text.truncate(cut);
            }
            (name.as_str().to_string(), text)
        })
        .collect()
}

async fn tls_handshake(
    config: Arc<ClientConfig>,
    host: &str,
    label: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = match IpAddr::from_str(host) {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string())
            .map_err(|_| ToolError::invalid(format!("'{host}' is not a valid TLS server name")))?,
    };
    tokio_rustls::TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(|e| {
            let reason = chain(&e);
            let hint = if reason.contains("invalid peer certificate") {
                ". Only certificates that chain to the bundled public web roots are accepted \
                 and verification cannot be turned off"
            } else {
                ""
            };
            ToolError::Execution(format!("TLS handshake with {label} failed: {reason}{hint}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn net(allow: bool, private: bool, hosts: &[&str]) -> Net {
        Net::new(
            NetPolicy::new(
                allow,
                private,
                hosts.iter().map(|h| (*h).to_string()).collect(),
            ),
            CancellationToken::new(),
            1024 * 1024,
        )
    }

    struct Fixed(Vec<IpAddr>);

    #[async_trait::async_trait]
    impl Resolve for Fixed {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    /// A tiny HTTP/1.1 server: `respond` maps the request head to a full response.
    async fn serve(respond: impl Fn(&str) -> String + Send + Sync + 'static) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let respond = respond.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let _ = stream.write_all(respond(&head).as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn redirect(status: u16, to: &str) -> String {
        format!("HTTP/1.1 {status} Moved\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn destinations_are_classified() {
        let public = ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"];
        for ip in public {
            assert!(classify(ip.parse().unwrap()).allowed(false), "{ip}");
        }
        let private = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "0.1.2.3",
            "2001:db8::1",
        ];
        for ip in private {
            assert!(!classify(ip.parse().unwrap()).allowed(false), "{ip}");
        }
        // Never reachable, even with private destinations enabled.
        for ip in ["0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "ff02::1"] {
            assert!(!classify(ip.parse().unwrap()).allowed(true), "{ip}");
        }
        assert!(classify("127.0.0.1".parse().unwrap()).allowed(true));
    }

    #[tokio::test]
    async fn a_disabled_policy_refuses_everything_first() {
        let n = net(false, true, &[]);
        assert!(matches!(
            n.vet("example.com", 80).await,
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(matches!(
            n.connect_tcp("127.0.0.1", 9, Duration::from_secs(1)).await,
            Err(ToolError::PermissionDenied(_))
        ));
        assert!(matches!(
            n.http(HttpRequest::new("GET", "http://127.0.0.1:9/")).await,
            Err(ToolError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn private_destinations_need_the_switch() {
        let n = net(true, false, &[]);
        for host in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "localhost",
        ] {
            assert!(
                matches!(n.vet(host, 80).await, Err(ToolError::NetworkNotAllowed(_))),
                "{host}"
            );
        }
        assert!(matches!(
            n.http(HttpRequest::new("GET", "http://[::1]:8080/")).await,
            Err(ToolError::NetworkNotAllowed(_))
        ));
        assert!(net(true, true, &[]).vet("127.0.0.1", 80).await.is_ok());
    }

    #[tokio::test]
    async fn obfuscated_and_malformed_hosts_are_rejected() {
        let n = net(true, true, &[]);
        for host in [
            "0x7f.1",
            "0177.0.0.1",
            "2130706433",
            "127.1",
            "",
            "a b",
            "a/b",
            "user@host",
            "exa\0mple",
        ] {
            assert!(n.vet(host, 80).await.is_err(), "{host:?}");
        }
        assert!(n.vet("127.0.0.1", 0).await.is_err());
        for url in [
            "file:///etc/passwd",
            "gopher://127.0.0.1/",
            "http://user:pw@127.0.0.1/",
            "http:///nohost",
        ] {
            assert!(n.vet_url(url, &["http", "https"]).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn one_bad_address_refuses_the_whole_host() {
        let mixed: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ];
        let n = net(true, false, &[]).with_resolver(Arc::new(Fixed(mixed)));
        assert!(matches!(
            n.vet("rebind.example", 443).await,
            Err(ToolError::NetworkNotAllowed(_))
        ));
        let good: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        let n = net(true, false, &[]).with_resolver(Arc::new(Fixed(good)));
        let addrs = n.vet("ok.example", 443).await.unwrap();
        assert_eq!(addrs, vec!["93.184.216.34:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn the_host_allowlist_applies_before_resolution() {
        let n = net(true, true, &["api.example.com"]);
        assert!(matches!(
            n.vet("127.0.0.1", 80).await,
            Err(ToolError::NetworkNotAllowed(_))
        ));
        assert!(matches!(
            n.vet("other.example.com", 80).await,
            Err(ToolError::NetworkNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn get_returns_the_body_and_caps_it() {
        let port = serve(|_| ok("hello world")).await;
        let n = net(true, true, &[]);
        let r = n
            .http(HttpRequest::new("GET", format!("http://127.0.0.1:{port}/")))
            .await
            .unwrap();
        assert_eq!(
            (r.status, r.body.as_slice(), r.truncated),
            (200, &b"hello world"[..], false)
        );

        let mut req = HttpRequest::new("GET", format!("http://127.0.0.1:{port}/"));
        req.max_body_bytes = 5;
        let r = n.http(req).await.unwrap();
        assert_eq!(r.body, b"hello");
        assert!(r.truncated);
        assert_eq!(r.body_bytes_total, Some(11));
    }

    #[tokio::test]
    async fn every_redirect_hop_is_vetted_again() {
        // Only 127.0.0.1 is allowed; the server redirects to another name.
        let port = serve(|_| redirect(302, "http://localhost:1/next")).await;
        let n = net(true, true, &["127.0.0.1"]);
        let r = n
            .http(HttpRequest::new("GET", format!("http://127.0.0.1:{port}/")))
            .await;
        assert!(matches!(r, Err(ToolError::NetworkNotAllowed(_))), "{r:?}");

        // A redirect to a non-http scheme is refused.
        let port = serve(|_| redirect(302, "file:///etc/passwd")).await;
        let n = net(true, true, &[]);
        assert!(n
            .http(HttpRequest::new("GET", format!("http://127.0.0.1:{port}/")))
            .await
            .is_err());

        // Redirects are not followed when the caller asks for none.
        let mut req = HttpRequest::new("GET", format!("http://127.0.0.1:{port}/"));
        req.max_redirects = 0;
        assert_eq!(n.http(req).await.unwrap().status, 302);
    }

    #[tokio::test]
    async fn credentials_are_dropped_on_cross_origin_redirects() {
        let echo = |head: &str| {
            let lower = head.to_ascii_lowercase();
            ok(if lower.contains("authorization:") {
                "auth:present"
            } else {
                "auth:none"
            })
        };
        let target = serve(echo).await;
        let cross = serve(move |_| redirect(307, &format!("http://127.0.0.1:{target}/t"))).await;
        let n = net(true, true, &[]);
        let mut req = HttpRequest::new("GET", format!("http://127.0.0.1:{cross}/"));
        req.headers
            .push(("Authorization".into(), "Bearer secret".into()));
        let r = n.http(req).await.unwrap();
        assert_eq!(r.body, b"auth:none");
        assert_eq!(r.redirects.len(), 1);

        // Same origin keeps them.
        let same = serve(|head: &str| {
            if head.starts_with("GET /start") {
                redirect(302, "/end")
            } else if head.to_ascii_lowercase().contains("authorization:") {
                ok("auth:present")
            } else {
                ok("auth:none")
            }
        })
        .await;
        let mut req = HttpRequest::new("GET", format!("http://127.0.0.1:{same}/start"));
        req.headers
            .push(("Authorization".into(), "Bearer secret".into()));
        assert_eq!(n.http(req).await.unwrap().body, b"auth:present");
    }

    #[tokio::test]
    async fn see_other_turns_post_into_get() {
        let port = serve(|head: &str| {
            if head.starts_with("POST /form") {
                redirect(303, "/done")
            } else {
                ok(head.split_whitespace().next().unwrap_or(""))
            }
        })
        .await;
        let n = net(true, true, &[]);
        let mut req = HttpRequest::new("POST", format!("http://127.0.0.1:{port}/form"));
        req.body = Some(b"a=1".to_vec());
        assert_eq!(n.http(req).await.unwrap().body, b"GET");
    }

    #[tokio::test]
    async fn caller_headers_and_methods_are_validated() {
        let n = net(true, true, &[]);
        let bad = [
            ("X-A", "v\r\nInjected: 1"),
            ("Host", "evil.example"),
            ("Content-Length", "0"),
            ("Transfer-Encoding", "chunked"),
            ("bad name", "v"),
        ];
        for (name, value) in bad {
            let mut req = HttpRequest::new("GET", "http://127.0.0.1:9/");
            req.headers.push((name.into(), value.into()));
            assert!(
                matches!(n.http(req).await, Err(ToolError::InvalidArguments(_))),
                "{name}"
            );
        }
        assert!(matches!(
            n.http(HttpRequest::new("CONNECT", "http://127.0.0.1:9/"))
                .await,
            Err(ToolError::InvalidArguments(_))
        ));
    }

    #[tokio::test]
    async fn downloads_are_capped() {
        let port = serve(|_| ok(&"x".repeat(5000))).await;
        let n = net(true, true, &[]);
        let mut sink = Vec::new();
        let req = HttpRequest::new("GET", format!("http://127.0.0.1:{port}/"));
        let d = n
            .http_download(req.clone(), &mut sink, 10_000)
            .await
            .unwrap();
        assert_eq!((d.bytes_written, sink.len()), (5000, 5000));
        let mut sink = Vec::new();
        assert!(matches!(
            n.http_download(req, &mut sink, 100).await,
            Err(ToolError::LimitExceeded(_))
        ));
    }

    #[tokio::test]
    async fn cancellation_and_timeouts_end_a_stalled_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // accept, then say nothing
            }
        });
        let cancel = CancellationToken::new();
        let n = Net::new(NetPolicy::new(true, true, vec![]), cancel.clone(), 1024);
        let url = format!("http://127.0.0.1:{port}/");
        let mut req = HttpRequest::new("GET", url.clone());
        req.timeout = Duration::from_secs(1);
        assert!(matches!(n.http(req).await, Err(ToolError::Timeout(_))));

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
        });
        assert!(matches!(
            n.http(HttpRequest::new("GET", url)).await,
            Err(ToolError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn a_failed_tls_handshake_is_an_error_not_a_panic() {
        // No process-wide crypto provider is installed in this test binary.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let n = net(true, true, &[]);
        let r = n
            .connect_tls("127.0.0.1", port, Duration::from_secs(3))
            .await;
        assert!(r.is_err());
        let _ = Net::tls_config();
    }
}
