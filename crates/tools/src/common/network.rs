//! Shared destination validation for network-capable tools.
//!
//! URL syntax alone is not an SSRF defense. This module rejects non-network
//! schemes, embedded credentials, local/private destinations, and hostnames
//! that resolve to a local/private address before a client is allowed to make
//! a request. HTTP clients also disable redirects so a validated public URL
//! cannot redirect into a forbidden range.

use std::net::IpAddr;

use nebula_mcp_core::ToolError;
use url::Url;

/// Reject values that a child network utility could interpret as an option.
pub fn reject_option_like(value: &str, field: &str) -> Result<(), ToolError> {
    if value.starts_with('-') {
        return Err(ToolError::InvalidArguments(format!(
            "{field} must not start with '-'"
        )));
    }
    Ok(())
}

/// Validate a host before a tool opens a socket to it.
pub async fn validate_host(host: &str, port: u16) -> Result<(), ToolError> {
    reject_option_like(host, "host")?;
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.eq_ignore_ascii_case("local")
    {
        return Err(ToolError::PermissionDenied(
            "local destinations are denied by the network policy".into(),
        ));
    }
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ToolError::Execution(format!("resolving '{host}': {e}")))?;
    let mut found = false;
    for address in addresses {
        found = true;
        if forbidden_address(address.ip()) {
            return Err(ToolError::PermissionDenied(format!(
                "destination '{}' resolves to a private or local address",
                address.ip()
            )));
        }
    }
    if !found {
        return Err(ToolError::Execution(format!(
            "hostname '{host}' did not resolve to an address"
        )));
    }
    Ok(())
}

/// Validate a URL and resolve its hostname before use.
pub async fn validate_url(raw: &str, schemes: &[&str]) -> Result<Url, ToolError> {
    let url =
        Url::parse(raw).map_err(|e| ToolError::InvalidArguments(format!("invalid URL: {e}")))?;
    if !schemes.iter().any(|scheme| *scheme == url.scheme()) {
        return Err(ToolError::PermissionDenied(format!(
            "URL scheme '{}' is not permitted",
            url.scheme()
        )));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(ToolError::PermissionDenied(
            "URLs with embedded credentials are not permitted".into(),
        ));
    }
    {
        let host = url
            .host_str()
            .ok_or_else(|| ToolError::InvalidArguments("URL must contain a host".into()))?;
        if host.eq_ignore_ascii_case("localhost")
            || host.ends_with(".localhost")
            || host.eq_ignore_ascii_case("local")
        {
            return Err(ToolError::PermissionDenied(
                "local destinations are denied by the network policy".into(),
            ));
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ToolError::InvalidArguments("URL must contain a known port".into()))?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| ToolError::Execution(format!("resolving '{host}': {e}")))?;
        let mut found = false;
        for address in addresses {
            found = true;
            if forbidden_address(address.ip()) {
                return Err(ToolError::PermissionDenied(format!(
                    "destination '{}' resolves to a private or local address",
                    address.ip()
                )));
            }
        }
        if !found {
            return Err(ToolError::Execution(format!(
                "hostname '{host}' did not resolve to an address"
            )));
        }
    }
    Ok(url)
}

/// Validate a URL without performing DNS, for use by tools whose child process
/// owns the connection. The child still receives a public, credential-free URL.
pub fn validate_url_syntax(raw: &str, schemes: &[&str]) -> Result<Url, ToolError> {
    let url =
        Url::parse(raw).map_err(|e| ToolError::InvalidArguments(format!("invalid URL: {e}")))?;
    if !schemes.iter().any(|scheme| *scheme == url.scheme()) {
        return Err(ToolError::PermissionDenied(format!(
            "URL scheme '{}' is not permitted",
            url.scheme()
        )));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(ToolError::PermissionDenied(
            "URLs with embedded credentials are not permitted".into(),
        ));
    }
    if let Some(host) = url.host_str() {
        if host.eq_ignore_ascii_case("localhost")
            || host.ends_with(".localhost")
            || host
                .parse::<IpAddr>()
                .map(forbidden_address)
                .unwrap_or(false)
        {
            return Err(ToolError::PermissionDenied(
                "local destinations are denied by the network policy".into(),
            ));
        }
    }
    Ok(url)
}

fn forbidden_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || octets == [169, 254, 169, 254]
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_local_literal_destinations() {
        assert!(validate_url_syntax("http://127.0.0.1:80", &["http"]).is_err());
        assert!(validate_url_syntax("file:///etc/passwd", &["http", "https"]).is_err());
        assert!(validate_url_syntax("https://user:pass@example.com", &["https"]).is_err());
    }
}
