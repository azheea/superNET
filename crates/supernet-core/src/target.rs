//! Connection targets: a host (domain or IP) plus a port.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    /// Parse a host, normalising domains (lower case, no trailing dot) and
    /// stripping brackets from IPv6 literals.
    pub fn new(raw: &str) -> Option<Host> {
        let raw = raw.trim();
        let unbracketed = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(raw);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Some(Host::Ip(ip));
        }
        let domain = raw.trim_end_matches('.').to_ascii_lowercase();
        let valid = !domain.is_empty()
            && domain.len() <= 253
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        valid.then_some(Host::Domain(domain))
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            Host::Domain(d) => Some(d),
            Host::Ip(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Domain(d) => f.write_str(d),
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Host::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// Parse `host:port`, `[v6]:port`, or a bare host with `default_port`.
    pub fn parse(raw: &str, default_port: Option<u16>) -> Option<Target> {
        let raw = raw.trim();
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return Some(Target::new(Host::Ip(addr.ip()), addr.port()));
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Some(Target::new(Host::Ip(ip), default_port?));
        }
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.starts_with('[') => (h, Some(p.parse::<u16>().ok()?)),
            _ => (raw, None),
        };
        let port = port.or(default_port)?;
        if port == 0 {
            return None;
        }
        Some(Target::new(Host::new(host)?, port))
    }

    pub fn domain(&self) -> Option<&str> {
        self.host.domain()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        let t = Target::parse("WWW.Example.COM.:443", None).unwrap();
        assert_eq!(t.host, Host::Domain("www.example.com".into()));
        assert_eq!(t.port, 443);
        assert_eq!(Target::parse("[::1]:80", None).unwrap().to_string(), "[::1]:80");
        assert_eq!(Target::parse("10.0.0.1:22", None).unwrap().host, Host::Ip("10.0.0.1".parse().unwrap()));
        assert_eq!(Target::parse("example.com", Some(80)).unwrap().port, 80);
        assert!(Target::parse("example.com", None).is_none());
        assert!(Target::parse("bad host:80", None).is_none());
        assert!(Target::parse("example.com:0", None).is_none());
    }
}
