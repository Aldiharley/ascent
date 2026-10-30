//! Engagement scope model and the fail-closed `ScopeGuard`.
//!
//! Scope enforcement is the pipeline's core safety boundary: a target is in
//! scope only if it can be *unambiguously* parsed to a validated host (a strict
//! LDH hostname or an IP literal) that matches the engagement. Anything that is
//! ambiguous, malformed, or that could be read differently by another URL/host
//! parser (backslashes, userinfo, whitespace, control characters, percent- or
//! IDNA-encoded hosts, extra slashes, ...) yields an empty host and is refused.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use url::{Host, Url};

/// How aggressive the DAST track may be. Ordered: Passive < Standard < Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DastProfile {
    Passive,
    #[default]
    Standard,
    Active,
}

impl DastProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            DastProfile::Passive => "passive",
            DastProfile::Standard => "standard",
            DastProfile::Active => "active",
        }
    }
}

/// DAST auth: the header NAME and the NAME of the environment variable that
/// holds its value. The value itself is never part of the engagement file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DastAuth {
    pub header: String,
    pub value_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DastConfig {
    #[serde(default)]
    pub profile: DastProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<DastAuth>,
}

fn is_header_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
}

fn is_env_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// Errors name the field and the rule only, never the offending text: a token pasted
/// into a name field must not reach stderr or the dashboard's 422 body.
pub fn validate_dast(d: &DastConfig) -> Result<(), String> {
    if let Some(a) = &d.auth {
        if !is_header_token(&a.header) {
            return Err(
                "dast.auth.header is not a valid HTTP header name (letters, digits and !#$%&'*+.^_`|~- only)"
                    .into(),
            );
        }
        if !is_env_name(&a.value_env) {
            return Err(
                "dast.auth.value_env must be an environment variable name like ASCENT_DAST_AUTH ([A-Z_][A-Z0-9_]*)"
                    .into(),
            );
        }
    }
    Ok(())
}

/// `Ok(None)` without auth; `Ok(Some((header_name, value)))` with it. Fails
/// closed: a configured but unset/empty value, or one containing any control
/// character other than TAB, is an error, and no error message ever contains the
/// value itself.
// Consumed by the DAST stage (later task); the `dashboard` binary includes this
// module but never calls it.
#[allow(dead_code)]
pub fn resolve_auth(
    d: &DastConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<(String, String)>, String> {
    let Some(a) = &d.auth else { return Ok(None) };
    validate_dast(d)?;
    let v = env(&a.value_env).unwrap_or_default();
    if v.trim().is_empty() {
        return Err(format!(
            "dast.auth is configured but environment variable {} is unset or empty; refusing to scan unauthenticated",
            a.value_env
        ));
    }
    if v.chars().any(|c| c.is_control() && c != '\t') {
        return Err(format!(
            "environment variable {} contains a line break or other control character; refusing to send it as a header",
            a.value_env
        ));
    }
    Ok(Some((a.header.clone(), v)))
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Engagement {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    /// Authorised source root for the SAST track (empty = no SAST).
    #[serde(default)]
    pub source: String,
    /// ISO-8601 with timezone. Stored but not enforced in the MVP.
    #[allow(dead_code)]
    pub starts: String,
    /// ISO-8601 with timezone. Stored but not enforced in the MVP.
    #[allow(dead_code)]
    pub ends: String,
    /// DAST track settings (profile, optional auth header).
    #[serde(default)]
    pub dast: DastConfig,
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
    let e: Engagement = serde_yaml_ng::from_str(&text)?;
    validate_dast(&e.dast)?;
    Ok(e)
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

/// Classify one raw target string into the engagement-scope list it belongs to.
///
/// Returns `(kind, stored)` where `kind` is `"hosts"`, `"cidrs"` or `"urls"` and
/// `stored` is the canonical text to write into the engagement YAML. Returns
/// `None` for anything invalid, ambiguous or out-of-form — the caller rejects it
/// and writes nothing. This applies exactly the same strict parsing as
/// [`ScopeGuard`] (via [`validate_host`] / [`host_of`]), surfaced so the New Scan
/// form can refuse a bad target before an engagement is ever created. It never
/// widens scope: a classified entry is one the guard built from it would accept.
// Used by the `dashboard` binary (New Scan) and this module's tests; the `ascent`
// binary links it but does not call it, so allow it to be unused there.
#[allow(dead_code)]
pub fn classify_target(raw: &str) -> Option<(&'static str, String)> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    // Whitespace/control anywhere is a parser-differential vector (same rule as host_of).
    if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if t.contains("://") {
        // A URL: accept only if our strict reader yields a real host (and there
        // is no userinfo, no ambiguity). Store it as typed; the guard re-validates.
        if host_of(t).is_empty() {
            return None;
        }
        return Some(("urls", t.to_string()));
    }
    if t.contains('/') {
        // A slash with no scheme must be a CIDR; a host+path is ambiguous -> refuse.
        return t.parse::<IpNet>().ok().map(|_| ("cidrs", t.to_string()));
    }
    // A bare hostname or IP literal.
    let h = validate_host(t);
    if h.is_empty() {
        None
    } else {
        Some(("hosts", h))
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
            source: String::new(),
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
            ..Default::default()
        }
    }
    #[test]
    fn engagement_parses_optional_source() {
        let y = "name: t\nurls: ['http://localhost:3000/']\nsource: ./src\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
        let e: Engagement = serde_yaml_ng::from_str(y).unwrap();
        assert_eq!(e.source, "./src");
        let y2 = "name: t\nhosts: [localhost]\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
        let e2: Engagement = serde_yaml_ng::from_str(y2).unwrap();
        assert_eq!(e2.source, "");
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
            source: String::new(),
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
            ..Default::default()
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
            source: String::new(),
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2030-01-01T00:00:00Z".into(),
            ..Default::default()
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
        assert!(g.in_scope("127.0.0.1"));
        assert!(g.in_scope("http://127.0.0.1:3000/"));
        // ProjectDiscovery tools may not resolve `localhost`: the sample avoids it
        assert!(!g.in_scope("localhost"));
        assert!(!g.in_scope("example.com"));
        assert!(!g.in_scope("8.8.8.8"));
    }

    #[test]
    fn every_sample_engagement_loads_and_avoids_localhost() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/samples");
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if !(name.starts_with("engagement") && name.ends_with(".yaml")) {
                continue;
            }
            let e = load_engagement(p.to_str().unwrap()).unwrap_or_else(|err| panic!("{name}: {err}"));
            let all = e.hosts.iter().chain(&e.urls).map(|s| s.to_ascii_lowercase());
            assert!(all.into_iter().all(|t| !t.contains("localhost")), "{name} targets localhost");
            assert!(!e.urls.is_empty() && e.urls.iter().all(|u| ScopeGuard::new(&e).in_scope(u)), "{name}");
            n += 1;
        }
        assert!(n >= 2, "expected the example and juice-shop samples, found {n}");
    }

    #[test]
    fn load_engagement_errors_on_missing_file() {
        assert!(load_engagement("definitely/not/here.yaml").is_err());
    }

    #[test]
    fn classify_buckets_valid_targets() {
        assert_eq!(
            classify_target("Example.COM"),
            Some(("hosts", "example.com".to_string()))
        );
        assert_eq!(
            classify_target("  10.0.0.5 "),
            Some(("hosts", "10.0.0.5".to_string()))
        );
        assert_eq!(
            classify_target("::1"),
            Some(("hosts", "::1".to_string()))
        );
        assert_eq!(
            classify_target("10.0.0.0/24"),
            Some(("cidrs", "10.0.0.0/24".to_string()))
        );
        assert_eq!(
            classify_target("fd00::/64"),
            Some(("cidrs", "fd00::/64".to_string()))
        );
        assert_eq!(
            classify_target("http://localhost:3000/"),
            Some(("urls", "http://localhost:3000/".to_string()))
        );
    }

    #[test]
    fn classify_refuses_the_same_targets_the_guard_refuses() {
        // A sampling of the adversarial inputs: none may classify.
        for bad in [
            "",
            " ",
            "evil.com/example.com",
            "http://user:pass@example.com/",
            "example.com\\@evil.com",
            "exa mple.com",
            "exam\tple.com",
            "*.example.com",
            "//example.com",
            "http://",
            "10.1",
            "0x0a.0.0.5",
            "example.com/some/path", // host+path is ambiguous -> refused
            "not-a-cidr/24",
            "10.0.0.0/999",
        ] {
            assert!(classify_target(bad).is_none(), "classified bad target {bad:?}");
        }
    }

    const BASE: &str = "name: t\nstarts: 'a'\nends: 'b'\n";

    #[test]
    fn dast_defaults_to_standard_without_auth() {
        let e: Engagement = serde_yaml_ng::from_str(BASE).unwrap();
        assert_eq!(e.dast.profile, DastProfile::Standard);
        assert!(e.dast.auth.is_none());
    }
    #[test]
    fn dast_block_parses() {
        let y = format!("{BASE}dast:\n  profile: active\n  auth:\n    header: Authorization\n    value_env: ASCENT_DAST_AUTH\n");
        let e: Engagement = serde_yaml_ng::from_str(&y).unwrap();
        assert_eq!(e.dast.profile, DastProfile::Active);
        assert_eq!(e.dast.auth.as_ref().unwrap().header, "Authorization");
        assert!(validate_dast(&e.dast).is_ok());
    }
    #[test]
    fn unknown_keys_are_rejected_everywhere() {
        for bad in [
            format!("{BASE}host: [x.com]\n"), // typo for hosts
            format!("{BASE}dast:\n  profle: active\n"),
            format!("{BASE}dast:\n  auth:\n    header: X\n    value: secret\n"),
            format!("{BASE}dast:\n  profile: aggressive\n"),
        ] {
            assert!(serde_yaml_ng::from_str::<Engagement>(&bad).is_err(), "accepted {bad:?}");
        }
    }
    #[test]
    fn validate_dast_checks_names() {
        let mk = |h: &str, v: &str| DastConfig {
            profile: DastProfile::Standard,
            auth: Some(DastAuth { header: h.into(), value_env: v.into() }),
        };
        assert!(validate_dast(&mk("Authorization", "ASCENT_DAST_AUTH")).is_ok());
        assert!(validate_dast(&mk("Cookie", "_X1")).is_ok());
        for (h, v) in [("", "A"), ("Bad Header", "A"), ("X:Y", "A"), ("X", ""), ("X", "lower"), ("X", "1A"), ("X", "A-B")] {
            assert!(validate_dast(&mk(h, v)).is_err(), "accepted header={h:?} env={v:?}");
        }
    }
    #[test]
    fn resolve_auth_reads_env_and_fails_closed() {
        let d = DastConfig {
            profile: DastProfile::Standard,
            auth: Some(DastAuth { header: "Authorization".into(), value_env: "TOK".into() }),
        };
        let got = resolve_auth(&d, &|k| (k == "TOK").then(|| "Bearer abc".to_string())).unwrap();
        assert_eq!(got, Some(("Authorization".into(), "Bearer abc".into())));
        assert!(resolve_auth(&d, &|_| None).unwrap_err().contains("TOK"));
        assert!(resolve_auth(&d, &|_| Some(String::new())).is_err());
        assert!(resolve_auth(&d, &|_| Some("a\r\nX-Injected: 1".into())).is_err());
        assert_eq!(resolve_auth(&DastConfig::default(), &|_| None).unwrap(), None);
    }
    #[test]
    fn resolve_auth_error_never_contains_the_value() {
        let d = DastConfig {
            profile: DastProfile::Standard,
            auth: Some(DastAuth { header: "Authorization".into(), value_env: "TOK".into() }),
        };
        let e = resolve_auth(&d, &|_| Some("Bearer s3cr3t\nmore".into())).unwrap_err();
        assert!(!e.contains("s3cr3t"), "{e}");
    }
    #[test]
    fn validate_dast_never_echoes_the_offending_string() {
        // a token pasted into a name field must not reach stderr or a 422 body
        for (h, v) in [("Bearer s3cr3t-tok", "ASCENT_DAST_AUTH"), ("Authorization", "Bearer s3cr3t-tok")] {
            let d = DastConfig {
                profile: DastProfile::Standard,
                auth: Some(DastAuth { header: h.into(), value_env: v.into() }),
            };
            let e = validate_dast(&d).unwrap_err();
            assert!(!e.contains("s3cr3t"), "{e}");
            assert!(e.starts_with("dast.auth."), "{e}");
        }
    }
    #[test]
    fn resolve_auth_rejects_every_control_character_but_tab() {
        let d = DastConfig {
            profile: DastProfile::Standard,
            auth: Some(DastAuth { header: "Authorization".into(), value_env: "TOK".into() }),
        };
        for bad in ["s3cr3t\u{0}", "s3cr3t\u{1b}[0m", "s3cr3t\u{7f}", "s3cr3t\u{85}", "a\rb", "a\nb"] {
            let e = resolve_auth(&d, &|_| Some(bad.to_string())).unwrap_err();
            assert!(!e.contains("s3cr3t") && e.contains("TOK"), "{e}");
        }
        assert!(resolve_auth(&d, &|_| Some("Bearer\tabc".to_string())).unwrap().is_some());
    }
    #[test]
    fn load_engagement_rejects_invalid_dast_auth() {
        let p = std::env::temp_dir().join(format!("ascent_scope_baddast_{}.yaml", std::process::id()));
        std::fs::write(
            &p,
            format!("{BASE}dast:\n  auth:\n    header: \"Bad Header\"\n    value_env: TOK\n"),
        )
        .unwrap();
        let r = load_engagement(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err());
    }

    #[test]
    fn classified_target_is_actually_in_scope_for_its_own_engagement() {
        // The core invariant: anything classify_target accepts, a ScopeGuard built
        // from that single entry must consider in scope. No fail-open gap.
        for raw in [
            "example.com",
            "10.0.0.5",
            "::1",
            "10.0.0.0/24",
            "http://localhost:3000/",
        ] {
            let (kind, stored) = classify_target(raw).expect("should classify");
            let mut e = Engagement {
                name: "t".into(),
                hosts: vec![],
                cidrs: vec![],
                urls: vec![],
                source: String::new(),
                starts: "2026-01-01T00:00:00Z".into(),
                ends: "2030-01-01T00:00:00Z".into(),
                ..Default::default()
            };
            match kind {
                "hosts" => e.hosts.push(stored.clone()),
                "cidrs" => e.cidrs.push(stored.clone()),
                "urls" => e.urls.push(stored.clone()),
                other => panic!("unexpected kind {other}"),
            }
            assert!(
                ScopeGuard::new(&e).in_scope(raw),
                "{raw:?} classified as {kind} but not in scope"
            );
        }
    }
}
