//! Network rules: which destinations network tools may reach.
//!
//! The network gate decides whether a tool may use the network at all. These
//! rules decide where: by default only public addresses, so a tool cannot be
//! pointed at loopback services, the local network or a cloud metadata
//! endpoint. Addresses are judged after name resolution, on the address that
//! is actually connected to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::ToolError;

/// Compiled destination policy.
#[derive(Debug, Clone, Default)]
pub struct NetworkRules {
    allow_private: bool,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
}

/// Why an address is not a public Internet address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Routable on the public Internet.
    Public,
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Private-use ranges (RFC 1918, carrier-grade NAT, unique local IPv6).
    Private,
    /// Link-local, which includes the cloud metadata address
    /// `169.254.169.254`.
    LinkLocal,
    /// Unspecified, multicast, broadcast, documentation or reserved.
    Reserved,
}

impl AddressClass {
    fn describe(self) -> &'static str {
        match self {
            AddressClass::Public => "public",
            AddressClass::Loopback => "loopback",
            AddressClass::Private => "private-network",
            AddressClass::LinkLocal => "link-local",
            AddressClass::Reserved => "reserved",
        }
    }
}

/// Classify an IP address.
#[must_use]
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, c, _] = ip.octets();
    if a == 127 {
        AddressClass::Loopback
    } else if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        AddressClass::Private
    } else if a == 100 && (64..=127).contains(&b) {
        // Carrier-grade NAT, also used by overlay networks.
        AddressClass::Private
    } else if a == 169 && b == 254 {
        AddressClass::LinkLocal
    } else if a == 0
        || a >= 224
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        AddressClass::Reserved
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4);
    }
    let seg = ip.segments();
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_unspecified() || seg[0] & 0xff00 == 0xff00 {
        AddressClass::Reserved
    } else if seg[0] & 0xfe00 == 0xfc00 {
        AddressClass::Private
    } else if seg[0] & 0xffc0 == 0xfe80 {
        AddressClass::LinkLocal
    } else if seg[0] & 0xffc0 == 0xfec0 || (seg[0] == 0x2001 && seg[1] == 0x0db8) {
        AddressClass::Reserved
    } else {
        AddressClass::Public
    }
}

/// The IPv4 address carried inside an IPv4-mapped, IPv4-compatible or NAT64
/// IPv6 address. Without this, `::ffff:127.0.0.1` would pass as public.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    let tail = || Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
    if seg[..5] == [0, 0, 0, 0, 0] && seg[5] == 0xffff {
        return Some(tail());
    }
    if seg[..6] == [0, 0, 0, 0, 0, 0] && (seg[6] != 0 || seg[7] > 1) {
        return Some(tail());
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return Some(tail());
    }
    None
}

impl NetworkRules {
    /// Compile the destination policy.
    #[must_use]
    pub fn build(allow_private: bool, allowed_hosts: &[String], denied_hosts: &[String]) -> Self {
        let norm = |list: &[String]| -> Vec<String> {
            list.iter()
                .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect()
        };
        Self {
            allow_private,
            allowed_hosts: norm(allowed_hosts),
            denied_hosts: norm(denied_hosts),
        }
    }

    /// Whether non-public addresses may be reached.
    #[must_use]
    pub fn allows_private(&self) -> bool {
        self.allow_private
    }

    /// The host allowlist (empty means any host).
    #[must_use]
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// The host denylist.
    #[must_use]
    pub fn denied_hosts(&self) -> &[String] {
        &self.denied_hosts
    }

    /// Check a host name (or IP literal) against the host lists and, for a
    /// literal, the address rule.
    pub fn check_host(&self, host: &str) -> Result<(), ToolError> {
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(ToolError::InvalidArguments("host is empty".to_string()));
        }
        if self.denied_hosts.iter().any(|p| host_matches(p, &host)) {
            return Err(ToolError::PermissionDenied(format!(
                "host '{host}' is on the denied_hosts list"
            )));
        }
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|p| host_matches(p, &host)) {
            return Err(ToolError::PermissionDenied(format!(
                "host '{host}' is not on the allowed_hosts list"
            )));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.check_ip(ip)?;
        }
        Ok(())
    }

    /// Check an address that is about to be connected to.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ToolError> {
        let class = classify(ip);
        if class == AddressClass::Public || self.allow_private {
            Ok(())
        } else {
            Err(ToolError::PermissionDenied(format!(
                "destination {ip} is a {} address; only public addresses may be reached unless \
                 the operator sets allow_private_networks = true",
                class.describe()
            )))
        }
    }
}

/// `example.com` matches itself, `*.example.com` matches any subdomain, and
/// `*` matches everything.
fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" || pattern == host {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(suffix) && {
            let cut = host.len() - suffix.len();
            host.as_bytes()[cut - 1] == b'.'
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(s: &str) -> AddressClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn classifies_non_public_ranges() {
        for s in ["127.0.0.1", "127.255.255.254", "::1"] {
            assert_eq!(class(s), AddressClass::Loopback, "{s}");
        }
        for s in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd00::1"] {
            assert_eq!(class(s), AddressClass::Private, "{s}");
        }
        for s in ["169.254.169.254", "fe80::1"] {
            assert_eq!(class(s), AddressClass::LinkLocal, "{s}");
        }
        for s in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1", "::", "ff02::1", "2001:db8::1"] {
            assert_eq!(class(s), AddressClass::Reserved, "{s}");
        }
        for s in ["1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"] {
            assert_eq!(class(s), AddressClass::Public, "{s}");
        }
    }

    #[test]
    fn ipv4_embedded_in_ipv6_is_classified_by_the_ipv4_address() {
        assert_eq!(class("::ffff:127.0.0.1"), AddressClass::Loopback);
        assert_eq!(class("::ffff:169.254.169.254"), AddressClass::LinkLocal);
        assert_eq!(class("::ffff:10.0.0.1"), AddressClass::Private);
        assert_eq!(class("64:ff9b::7f00:1"), AddressClass::Loopback);
        assert_eq!(class("::ffff:8.8.8.8"), AddressClass::Public);
    }

    #[test]
    fn private_addresses_need_the_switch() {
        let strict = NetworkRules::build(false, &[], &[]);
        assert!(strict.check_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(strict.check_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(strict.check_host("169.254.169.254").is_err());
        assert!(strict.check_host("[::1]").is_err());
        assert!(strict.check_host("example.com").is_ok());

        let open = NetworkRules::build(true, &[], &[]);
        assert!(open.check_ip("127.0.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn host_lists_match_exact_names_and_subdomains() {
        let r = NetworkRules::build(
            false,
            &["example.com".to_string(), "*.github.com".to_string()],
            &["evil.example.com".to_string()],
        );
        assert!(r.check_host("example.com").is_ok());
        assert!(r.check_host("EXAMPLE.com.").is_ok());
        assert!(r.check_host("api.github.com").is_ok());
        assert!(r.check_host("github.com").is_err());
        assert!(r.check_host("notgithub.com").is_err());
        assert!(r.check_host("other.org").is_err());

        let d = NetworkRules::build(false, &[], &["*.internal".to_string()]);
        assert!(d.check_host("db.internal").is_err());
        assert!(d.check_host("example.com").is_ok());
    }
}
