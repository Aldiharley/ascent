//! Engagement scope model and the fail-closed `ScopeGuard`.
//!
//! Scope enforcement is the pipeline's core safety boundary: a target is in
//! scope only if it can be *unambiguously* parsed to a validated host (a strict
//! LDH hostname or an IP literal) that matches the engagement. Anything that is
//! ambiguous, malformed, or that could be read differently by another URL/host
//! parser (backslashes, userinfo, whitespace, control characters, percent- or
//! IDNA-encoded hosts, extra slashes, ...) yields an empty host and is refused.

use ipnet::IpNet;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use url::{Host, Url};

#[derive(Debug, Deserialize, Clone)]
pub struct Engagement {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    /// ISO-8601 with timezone. Stored but not enforced in the MVP.
    pub starts: String,
    /// ISO-8601 with timezone. Stored but not enforced in the MVP.
    pub ends: String,
}

#[derive(Debug)]
pub struct OutOfScope(pub String);
impl fmt::Display for OutOfScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} is not in engagement scope", self.0)
    }
}
impl std::error::Error for OutOfScope {}

pub fn load_engagement(path: &str) -> Result<Engagement, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml_ng::from_str(&text)?)
}

/// Validate a bare host (no port, no brackets). Returns the canonical
/// lowercase form: an IP literal's canonical text, or a strict LDH hostname.
/// Returns an empty string for anything else.
fn validate_host(h: &str) -> String {
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip.to_string();
    }
    let h = h.to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 {
        return String::new();
    }
    let labels: Vec<&str> = h.split('.').collect();
    for l in &labels {
        let b = l.as_bytes();
        let edge_ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let ok = !b.is_empty()
            && b.len() <= 63
            && edge_ok(b[0])
            && edge_ok(b[b.len() - 1])
            && b.iter().all(|&c| edge_ok(c) || c == b'-');
        if !ok {
            return String::new();
        }
    }
    // An all-numeric final label that is not a valid IP is an IPv4-looking
    // name ("127.1", "0x7f.1", "10.1"): URL parsers and resolvers disagree on
    // what these mean, so refuse them.
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|c| c.is_ascii_digit()))
    {
        return String::new();
    }
    h
}

fn valid_port(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 5
        && p.bytes().all(|c| c.is_ascii_digit())
        && p.parse::<u16>().is_ok()
}

/// Extract and validate the host from a raw authority component
/// (`host`, `host:port`, `[v6]`, `[v6]:port`, or a bare IP literal).
/// Empty string on anything ambiguous or invalid.
fn host_from_authority(auth: &str) -> String {
    // Backslash and '@' (userinfo) are parser-differential vectors.
    if auth.is_empty() || auth.contains(['\\', '@']) {
        return String::new();
    }
    // A bare IP literal (covers unbracketed IPv6 such as "::1").
    if let Ok(ip) = auth.parse::<IpAddr>() {
        return ip.to_string();
    }
    let host = if let Some(rest) = auth.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return String::new();
        };
        let Ok(v6) = inner.parse::<Ipv6Addr>() else {
            return String::new();
        };
        if !after.is_empty() && !after.strip_prefix(':').is_some_and(valid_port) {
            return String::new();
        }
        v6.to_string()
    } else {
        let (h, port) = match auth.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (auth, None),
        };
        if port.is_some_and(|p| !valid_port(p)) {
            return String::new();
        }
        validate_host(h)
    };
    host
}

/// Extract the validated, lowercased host from a hostname / IP / URL target.
/// Returns an empty string for any target that is invalid or ambiguous.
fn host_of(target: &str) -> String {
    // Whitespace/control characters are stripped or reinterpreted by some URL
    // parsers (Url::parse drops tabs/newlines), so refuse them outright.
    if target.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return String::new();
    }
    let authority_end = |s: &str| s.find(['/', '?', '#']).unwrap_or(s.len());

    let Some(idx) = target.find("://") else {
        return host_from_authority(&target[..authority_end(target)]);
    };

    // URL form. The URL parser must agree with our own strict reading of the
    // raw authority, and there must be no userinfo.
    let Ok(u) = Url::parse(target) else {
        return String::new();
    };
    if u.scheme() != target[..idx].to_ascii_lowercase()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return String::new();
    }
    let rest = &target[idx + 3..];
    let host = host_from_authority(&rest[..authority_end(rest)]);
    let parsed = match u.host() {
        Some(Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => return String::new(),
    };
    if host == parsed {
        host
    } else {
        String::new()
    }
}

pub struct ScopeGuard {
    hosts: HashSet<String>,
    nets: Vec<IpNet>,
}

impl ScopeGuard {
    pub fn new(e: &Engagement) -> Self {
        let mut hosts: HashSet<String> = HashSet::new();
        let mut nets: Vec<IpNet> = Vec::new();
        let mut add = |h: String| {
            if h.is_empty() {
                return;
            }
            match h.parse::<IpAddr>() {
                // An explicitly-listed IP host is a /32 (or /128) network.
                Ok(ip) => nets.push(IpNet::from(ip)),
                Err(_) => {
                    hosts.insert(h);
                }
            }
        };
        for h in &e.hosts {
            add(validate_host(h));
        }
        for u in &e.urls {
            add(host_of(u));
        }
        for c in &e.cidrs {
            if let Ok(n) = c.parse::<IpNet>() {
                nets.push(n);
            }
        }
        ScopeGuard { hosts, nets }
    }

    pub fn in_scope(&self, target: &str) -> bool {
        let host = host_of(target);
        if host.is_empty() {
            return false;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.nets.iter().any(|n| n.contains(&ip));
        }
        self.hosts
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")))
    }

    pub fn assert_in_scope(&self, target: &str) -> Result<(), OutOfScope> {
        if self.in_scope(target) {
            Ok(())
        } else {
            Err(OutOfScope(target.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn eng() -> Engagement {
        Engagement {
            name: "t".into(),
            hosts: vec!["example.com".into()],
            cidrs: vec!["10.0.0.0/24".into()],
            urls: vec!["https://app.example.com/".into()],
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
        }
    }
    #[test]
    fn host_and_subdomain() {
        let g = ScopeGuard::new(&eng());
        assert!(g.in_scope("example.com"));
        assert!(g.in_scope("api.example.com"));
        assert!(g.in_scope("https://app.example.com/login"));
    }
    #[test]
    fn cidr() {
        assert!(ScopeGuard::new(&eng()).in_scope("10.0.0.5"));
    }
    #[test]
    fn out_of_scope() {
        let g = ScopeGuard::new(&eng());
        assert!(!g.in_scope("evil.com"));
        assert!(g.assert_in_scope("8.8.8.8").is_err());
    }

    fn eng_ip() -> Engagement {
        Engagement {
            name: "t2".into(),
            hosts: vec!["192.0.2.7".into(), "EXAMPLE.com".into(), "::1".into()],
            cidrs: vec!["10.0.0.0/24".into(), "not-a-cidr".into()],
            urls: vec![
                "http://198.51.100.9:8080/".into(),
                "https://App.Lab.Test/".into(),
            ],
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
        }
    }

    // ---- adversarial: every one of these MUST be out of scope (fail closed) ----
    #[test]
    fn adversarial_targets_are_refused() {
        let g = ScopeGuard::new(&eng());
        let bad = [
            "evil.com",
            "notexample.com",
            "example.com.evil.com",
            "evil.com/example.com",
            "evil.com?example.com",
            "evil.com#example.com",
            "evil.com\\.example.com",
            "evil.com\\@example.com",
            "http://evil.com\\@example.com/",
            "http://evil.com\\.example.com/",
            "http://user:pass@example.com/",
            "http://user@example.com/",
            "user@example.com",
            "evil.com@example.com",
            "http://evil.com@example.com/",
            "http://example.com@evil.com/",
            "http://example.com:80@evil.com/",
            "",
            " ",
            "10.0.1.5",
            "10.0.0.256",
            "http://10.0.1.5/",
            "example.com.",
            ".example.com",
            "..example.com",
            "-example.com",
            "exa mple.com",
            "example.com ",
            " example.com",
            "example.com\n",
            "exam\tple.com",
            "http://exam\tple.com/",
            "example.com\u{0}",
            "http://example.com\u{0}.evil.com/",
            "exa_mple.com",
            "*.example.com",
            "http://exa%6dple.com/",
            "http://exa%2e.evil.com/",
            "//example.com",
            "///example.com",
            "http:///example.com",
            "http:////example.com",
            "http:/example.com",
            "http:example.com",
            "http:\\\\example.com",
            "example.com:",
            "example.com:80:80",
            "example.com:99999",
            "example.com:http",
            "example.com:80@evil.com",
            "http://example.com:99999/",
            "http://",
            "://example.com",
            "file:///etc/passwd",
            "xn--exmple-cua.com",
            "ex\u{e4}mple.com",
            "[::1]",
            "[::ffff:10.0.0.5]",
            "10.0.0.5.evil.com",
            "10.0.0.5.",
            "0x0a.0.0.5",
            "10.1",
            "8.8.8.8",
            "::1",
            "localhost",
        ];
        for t in bad {
            assert!(!g.in_scope(t), "FAIL-OPEN: {t:?} was in scope");
            assert!(
                g.assert_in_scope(t).is_err(),
                "assert_in_scope accepted {t:?}"
            );
        }
    }

    #[test]
    fn empty_host_is_never_in_scope_even_with_junk_config() {
        let e = Engagement {
            name: "empty".into(),
            hosts: vec!["".into(), " ".into(), "*".into(), ".".into()],
            cidrs: vec![],
            urls: vec!["".into(), "http://".into(), "garbage".into()],
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
        };
        let g = ScopeGuard::new(&e);
        for t in ["", ".", "*", "example.com", "localhost", "1.2.3.4"] {
            assert!(!g.in_scope(t), "{t:?} must be out of scope");
        }
    }

    // ---- positive cases that must keep working ----
    #[test]
    fn legitimate_targets_in_scope() {
        let g = ScopeGuard::new(&eng());
        for t in [
            "example.com",
            "EXAMPLE.COM",
            "Api.Example.Com",
            "a.b.c.example.com",
            "example.com:8443",
            "api.example.com:443/path?x=1#frag",
            "example.com/some/path",
            "example.com?q=1",
            "https://app.example.com/",
            "https://app.example.com/login?next=/a@b",
            "HTTPS://APP.EXAMPLE.COM:8443/x",
            "http://example.com/a%20b",
            "10.0.0.0",
            "10.0.0.255",
            "10.0.0.5:8080",
            "10.0.0.5/path",
            "http://10.0.0.5:3000/x",
        ] {
            assert!(g.in_scope(t), "{t:?} should be in scope");
        }
    }

    #[test]
    fn explicit_ip_host_in_scope_as_single_address() {
        let g = ScopeGuard::new(&eng_ip());
        assert!(g.in_scope("192.0.2.7"));
        assert!(g.in_scope("192.0.2.7:8080"));
        assert!(g.in_scope("http://192.0.2.7/x"));
        assert!(!g.in_scope("192.0.2.8"));
        assert!(!g.in_scope("192.0.2.70"));
        // an IP url entry becomes a /32 as well
        assert!(g.in_scope("198.51.100.9"));
        assert!(g.in_scope("http://198.51.100.9:8080/a"));
        assert!(!g.in_scope("198.51.100.10"));
        // an ipv6 literal host becomes a /128
        assert!(g.in_scope("::1"));
        assert!(g.in_scope("[::1]:8080"));
        assert!(g.in_scope("http://[::1]:8080/"));
        assert!(!g.in_scope("::2"));
        assert!(!g.in_scope("[::2]"));
        // an IP literal never matches by hostname suffix
        assert!(!g.in_scope("x.192.0.2.7"));
        assert!(!g.in_scope("1.192.0.2.7"));
    }

    #[test]
    fn config_is_lowercased_and_invalid_entries_dropped() {
        let g = ScopeGuard::new(&eng_ip());
        assert!(g.in_scope("example.com"));
        assert!(g.in_scope("sub.example.com"));
        assert!(g.in_scope("app.lab.test"));
        assert!(g.in_scope("deep.APP.lab.TEST"));
        assert!(!g.in_scope("lab.test"));
        // "not-a-cidr" was dropped; 10.0.0.0/24 still works
        assert!(g.in_scope("10.0.0.9"));
        assert!(!g.in_scope("10.0.1.9"));
    }

    #[test]
    fn ipv6_cidr_scope() {
        let mut e = eng();
        e.cidrs.push("fd00::/64".into());
        let g = ScopeGuard::new(&e);
        assert!(g.in_scope("fd00::5"));
        assert!(g.in_scope("[fd00::5]:443"));
        assert!(g.in_scope("http://[fd00::5]/"));
        assert!(!g.in_scope("fd00:1::5"));
        assert!(!g.in_scope("[fd00:1::5]:443"));
    }

    #[test]
    fn userinfo_url_in_config_is_dropped() {
        let mut e = eng();
        e.hosts.clear();
        e.urls = vec!["http://user:pw@cfg.example.org/".into()];
        let g = ScopeGuard::new(&e);
        assert!(!g.in_scope("cfg.example.org"));
        assert!(!g.in_scope("http://cfg.example.org/"));
    }

    #[test]
    fn out_of_scope_error_message() {
        let g = ScopeGuard::new(&eng());
        let err = g.assert_in_scope("evil.com").unwrap_err();
        assert_eq!(err.0, "evil.com");
        assert_eq!(err.to_string(), "evil.com is not in engagement scope");
        assert!(g.assert_in_scope("example.com").is_ok());
    }

    #[test]
    fn sample_engagement_loads_and_is_lab_only() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/samples/engagement.example.yaml"
        );
        let e = load_engagement(path).expect("sample engagement must parse");
        assert!(!e.name.is_empty());
        assert!(!e.starts.is_empty() && !e.ends.is_empty());
        let g = ScopeGuard::new(&e);
        assert!(g.in_scope("localhost"));
        assert!(g.in_scope("127.0.0.1"));
        assert!(g.in_scope("http://localhost:3000/"));
        assert!(!g.in_scope("example.com"));
        assert!(!g.in_scope("8.8.8.8"));
    }

    #[test]
    fn load_engagement_errors_on_missing_file() {
        assert!(load_engagement("definitely/not/here.yaml").is_err());
    }
}
