//! Destination-checked network access.
//!
//! [`Net`] is the only way tools open connections. A tool gets one only when
//! the network gate is open for it, and every connection made through it is
//! checked against the destination rules on the address actually connected
//! to: name resolution goes through a filtering resolver, redirects are
//! re-checked hop by hop, and proxies are not used (a proxy would resolve the
//! name itself, out of reach of the check).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::TcpStream;

use crate::error::ToolError;
use crate::policy::NetworkRules;

/// Maximum redirects followed by the HTTP client.
const MAX_REDIRECTS: usize = 10;

/// Destination-checked network accessor. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Net {
    rules: Arc<NetworkRules>,
    client: reqwest::Client,
}

struct FilteringResolver {
    rules: Arc<NetworkRules>,
}

impl Resolve for FilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let rules = self.rules.clone();
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs = resolve_checked(&rules, &host, 0).await?;
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// Resolve `host` and keep only the addresses the rules allow.
async fn resolve_checked(rules: &NetworkRules, host: &str, port: u16) -> Result<Vec<SocketAddr>, ToolError> {
    rules.check_host(host)?;
    let host_owned = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let found: Vec<SocketAddr> = tokio::net::lookup_host((host_owned.as_str(), port))
        .await
        .map_err(|e| ToolError::Execution(format!("resolving '{host}': {e}")))?
        .collect();
    if found.is_empty() {
        return Err(ToolError::Execution(format!(
            "'{host}' did not resolve to any address"
        )));
    }
    let mut refusal = None;
    let allowed: Vec<SocketAddr> = found
        .into_iter()
        .filter(|addr| match rules.check_ip(addr.ip()) {
            Ok(()) => true,
            Err(e) => {
                refusal = Some(e);
                false
            }
        })
        .collect();
    match (allowed.is_empty(), refusal) {
        (true, Some(e)) => Err(e),
        _ => Ok(allowed),
    }
}

fn check_url(rules: &NetworkRules, url: &url::Url) -> Result<(), ToolError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ToolError::InvalidArguments(format!(
            "only http and https URLs are supported, not '{}:'",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ToolError::InvalidArguments(
            "URLs with embedded credentials are not accepted".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ToolError::InvalidArguments("the URL has no host".to_string()))?;
    rules.check_host(host)
}

impl Net {
    /// Build an accessor for the given rules.
    pub fn new(rules: Arc<NetworkRules>, user_agent: &str) -> Result<Self, ToolError> {
        let redirect_rules = rules.clone();
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .no_proxy()
            .dns_resolver(Arc::new(FilteringResolver {
                rules: rules.clone(),
            }))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= MAX_REDIRECTS {
                    return attempt.error("too many redirects");
                }
                match check_url(&redirect_rules, attempt.url()) {
                    Ok(()) => attempt.follow(),
                    Err(e) => attempt.error(e.to_string()),
                }
            }))
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ToolError::Internal(format!("building the HTTP client: {e}")))?;
        Ok(Self { rules, client })
    }

    /// The destination rules in force.
    #[must_use]
    pub fn rules(&self) -> &NetworkRules {
        &self.rules
    }

    /// Parse and check an `http` or `https` URL without connecting. Use this
    /// before handing a URL to an external program, which the resolver filter
    /// cannot reach.
    pub fn check_url(&self, url: &str) -> Result<url::Url, ToolError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| ToolError::InvalidArguments(format!("invalid URL '{url}': {e}")))?;
        check_url(&self.rules, &parsed)?;
        Ok(parsed)
    }

    /// Start an HTTP request to a checked URL.
    pub fn request(&self, method: reqwest::Method, url: &str) -> Result<reqwest::RequestBuilder, ToolError> {
        let parsed = self.check_url(url)?;
        Ok(self.client.request(method, parsed))
    }

    /// Resolve a host to the addresses the rules allow.
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ToolError> {
        resolve_checked(&self.rules, host, port).await
    }

    /// Check that a host an external program is about to contact resolves
    /// only to allowed addresses. The program resolves the name again itself,
    /// so this narrows the exposure rather than closing it.
    pub async fn check_host_for_external_program(&self, host: &str) -> Result<(), ToolError> {
        let rules = &self.rules;
        rules.check_host(host)?;
        let host_owned = host.trim_start_matches('[').trim_end_matches(']').to_string();
        if let Ok(found) = tokio::net::lookup_host((host_owned.as_str(), 0)).await {
            for addr in found {
                rules.check_ip(addr.ip())?;
            }
        }
        Ok(())
    }

    /// Open a TCP connection to an allowed address of `host`.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> Result<(TcpStream, SocketAddr), ToolError> {
        let addrs = self.lookup(host, port).await?;
        let mut last = None;
        for addr in addrs {
            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok((stream, addr)),
                Ok(Err(e)) => last = Some(ToolError::Execution(format!("connecting to {addr}: {e}"))),
                Err(_) => last = Some(ToolError::Timeout(timeout)),
            }
        }
        Err(last.unwrap_or_else(|| {
            ToolError::Execution(format!("'{host}' has no reachable address"))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn net(allow_private: bool) -> Net {
        Net::new(Arc::new(NetworkRules::build(allow_private, &[], &[])), "test").unwrap()
    }

    /// A one-shot HTTP server on loopback that answers every request with
    /// `response`.
    async fn serve_once(response: String) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    #[test]
    fn urls_are_checked_before_any_connection() {
        let n = net(false);
        for url in [
            "http://127.0.0.1:8765/mcp",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://10.0.0.5/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/",
            "http://user:pass@example.com/",
            "not a url",
        ] {
            assert!(n.check_url(url).is_err(), "{url} should be refused");
        }
        assert!(n.check_url("https://example.com/path?q=1").is_ok());
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused_at_connect_time() {
        let n = net(false);
        // `localhost` passes the host-name lists; the address filter stops it.
        let err = n.lookup("localhost", 80).await.unwrap_err();
        assert!(matches!(err, ToolError::PermissionDenied(_)), "{err:?}");
        let err = n
            .request(reqwest::Method::GET, "http://localhost:1/")
            .unwrap()
            .send()
            .await
            .unwrap_err();
        assert!(err.is_connect(), "{err:?}");
        assert!(n.connect("localhost", 1, Duration::from_secs(2)).await.is_err());
    }

    #[tokio::test]
    async fn loopback_is_reachable_only_with_the_switch() {
        let addr = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()).await;
        let url = format!("http://{addr}/");
        assert!(net(false).request(reqwest::Method::GET, &url).is_err());
        let body = net(true)
            .request(reqwest::Method::GET, &url)
            .unwrap()
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn a_redirect_to_a_refused_destination_is_not_followed() {
        // Allowed first hop (private networks on) that redirects to a scheme
        // and host the rules refuse.
        let addr = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://blocked.example/\r\nContent-Length: 0\r\n\r\n"
                .to_string(),
        )
        .await;
        let rules = NetworkRules::build(true, &[], &["blocked.example".to_string()]);
        let n = Net::new(Arc::new(rules), "test").unwrap();
        let err = n
            .request(reqwest::Method::GET, &format!("http://{addr}/"))
            .unwrap()
            .send()
            .await
            .unwrap_err();
        assert!(err.is_redirect(), "{err:?}");
    }
}
