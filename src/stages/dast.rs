//! The DAST track: seed the surface from the whole declared scope, crawl, drop anything
//! out of scope (counted, never scanned, never fatal), run the profile's nuclei passes
//! with the optional auth header, scrub the auth value from every raw result, and report
//! what was and was not tested. dos / brute-force / default-login are never run.
use super::enumerate::enumerate_surface;
use super::recon::{ensure_httpx_identity, is_subfinder_candidate, probe_urls, recon};
use super::scan::{listed_count, scan_rows_with_deadline, write_new_lines, TempDir};
use crate::models::Finding;
use crate::normalise::normalise_nuclei;
use crate::runner::Runner;
use crate::scope::{DastProfile, Engagement, ScopeGuard};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const ALWAYS_EXCLUDED: &str = "dos,brute-force,default-login";
const PASSIVE_TAGS: &str = "tech,misconfig,exposure,headers,cors,cookie,session";
const STANDARD_TAGS: &str = "tech,misconfig,exposure,headers,cors,cookie,session,cve,sqli,xss,auth-bypass,jwt,idor,csrf,redirect,ssrf,lfi";

/// `-ni`: no interactsh, so no out-of-band traffic to a third-party OAST server.
/// `-duc`: no update check (no egress beyond the target).
/// `-nmhe`: never skip a host after `-max-host-error` errors. nuclei skips it silently
/// (nothing printed under `-silent`), so a handful of failing templates would lose
/// every later check against an in-scope host without a trace.
/// `-pt http`: http-protocol templates only (the `-dast` fuzzing templates are http).
/// network/dns/ssl/javascript/... templates can address hosts other than the input.
pub fn common_nuclei_args() -> Vec<String> {
    [
        "-silent",
        "-jsonl",
        "-rate-limit",
        "50",
        "-concurrency",
        "10",
        "-timeout",
        "10",
        "-ni",
        "-duc",
        "-nmhe",
        "-pt",
        "http",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The profile's nuclei passes. Every pass of every profile excludes
/// [`ALWAYS_EXCLUDED`] and disables redirects (`-dr`, so a redirect can never take
/// nuclei off scope); nothing here comes from engagement config. Only the active
/// profile (the opt-in "may change state" one) runs `intrusive` templates.
pub fn nuclei_passes(profile: DastProfile) -> Vec<Vec<String>> {
    let pass = |tags: &str, extra_etags: &str| -> Vec<String> {
        vec![
            "-tags".into(),
            tags.into(),
            "-etags".into(),
            format!("{ALWAYS_EXCLUDED},{extra_etags}"),
            "-dr".into(),
        ]
    };
    match profile {
        DastProfile::Passive => vec![pass(PASSIVE_TAGS, "intrusive,fuzz")],
        DastProfile::Standard => vec![pass(STANDARD_TAGS, "intrusive,fuzz")],
        DastProfile::Active => vec![
            pass(STANDARD_TAGS, "fuzz"),
            vec![
                "-dast".into(),
                "-etags".into(),
                ALWAYS_EXCLUDED.into(),
                "-dr".into(),
            ],
        ],
    }
}

const LISTING_NOT_RECOGNISED: &str = "nuclei template listing not recognised";
const TEMPLATE_UNREADABLE: &str = "nuclei listed a template that cannot be read";

/// nuclei variables that resolve to the scanned target. `{{Host}}`/`{{Hostname}}` are
/// a bare host (`host`, `host:port`); `{{BaseURL}}`/`{{RootURL}}` carry their own scheme.
const TARGET_HOST_VARS: [&str; 2] = ["{{Hostname}}", "{{Host}}"];
const TARGET_URL_VARS: [&str; 2] = ["{{BaseURL}}", "{{RootURL}}"];

/// What may follow a target variable: nothing, a path, or a numeric port (Ascent scope
/// is host/IP-level, so another port of the target stays in scope). Anything else
/// (`.evil.test`, `@evil.test`, `:{{port}}`) can name another host.
fn target_suffix_ok(rest: &str) -> bool {
    if rest.is_empty() || rest.starts_with('/') {
        return true;
    }
    let Some(port) = rest.strip_prefix(':') else {
        return false;
    };
    let port = port.split('/').next().unwrap_or("");
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|c| c.is_ascii_digit())
}

/// True when one `@Host:` annotation value keeps the request on the scanned target.
fn host_value_on_target(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    let lower = v.to_ascii_lowercase();
    let bare = ["http://", "https://"]
        .iter()
        .find(|s| lower.starts_with(**s))
        .map_or(v, |s| &v[s.len()..]);
    TARGET_HOST_VARS
        .iter()
        .find_map(|var| bare.strip_prefix(var))
        .or_else(|| TARGET_URL_VARS.iter().find_map(|var| v.strip_prefix(var)))
        .is_some_and(target_suffix_ok)
}

/// Every `@Host:` annotation value in a template (the name matched case-insensitively,
/// anywhere on a line; a value ends at the line end or at an escaped `\n`/`\r`).
fn host_annotations(template: &str) -> Vec<&str> {
    const KEY: &str = "@host:";
    let mut out = Vec::new();
    for line in template.lines() {
        let lower = line.to_ascii_lowercase(); // ASCII-only change: byte offsets agree
        let mut from = 0;
        while let Some(i) = lower[from..].find(KEY) {
            let start = from + i + KEY.len();
            let rest = &line[start..];
            let end = [rest.find("\\n"), rest.find("\\r")]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(rest.len());
            out.push(&rest[..end]);
            from = start;
        }
    }
    out
}

/// True when a template redirects any request away from the scanned target with the
/// raw-request `@Host:` annotation (a literal host, `localhost`, or anything that is
/// not a target variable). Ascent's scope guard only sees nuclei's `-l` targets, so
/// such a template would send a request (with the auth header) to an unchecked host.
pub fn sends_off_target(template: &str) -> bool {
    host_annotations(template)
        .iter()
        .any(|v| !host_value_on_target(v))
}

/// Top-level template sections that are not http. nuclei types a template by its
/// FIRST protocol, so `-pt http` still lists a template that starts with `http:` and
/// then dials something in a `javascript:`/`network:`/`ssl:`/... section. Neither
/// `@Host` nor the trace log's `address` (derived from the input) shows where those
/// sections connect. (`flow:` is not one: see [`flow_loads_modules`].)
const NON_HTTP_SECTIONS: [&str; 10] = [
    "javascript",
    "network",
    "tcp",
    "dns",
    "ssl",
    "code",
    "headless",
    "websocket",
    "whois",
    "file",
];

/// A template's lines, without a leading UTF-8 BOM on the first.
fn template_lines(template: &str) -> std::str::Lines<'_> {
    template
        .strip_prefix('\u{feff}')
        .unwrap_or(template)
        .lines()
}

/// True when a template has a top-level (column-0) non-http protocol section.
/// A text scan; [`yaml_structure_excluded`] reads the same thing as YAML.
pub fn has_non_http_protocol(template: &str) -> bool {
    template_lines(template).any(|line| {
        NON_HTTP_SECTIONS.iter().any(|k| {
            line.strip_prefix(k)
                .is_some_and(|rest| rest.starts_with(':'))
        })
    })
}

/// True when a template's top-level `flow:` value (the whole block, multi-line `|`
/// scalars included) contains `require(` (any case): flow is JavaScript, and a
/// loaded nuclei module (`nuclei/net`, ...) could dial a host the trace log never
/// shows. A flow without it can only orchestrate the template's own sections, which
/// are all http once [`has_non_http_protocol`] has passed, and every http request
/// is in the trace-log audit. A text scan; [`yaml_structure_excluded`] reads the
/// flow as YAML too.
pub fn flow_loads_modules(template: &str) -> bool {
    let mut in_flow = false;
    for line in template_lines(template) {
        let top_level = !line.is_empty() && !line.starts_with([' ', '\t', '\r']);
        if top_level {
            in_flow = line
                .strip_prefix("flow")
                .is_some_and(|r| r.starts_with(':'));
        }
        if in_flow && line.to_ascii_lowercase().contains("require(") {
            return true;
        }
    }
    false
}

/// The template read as YAML, so no valid spelling evades the text scans
/// (`javascript : []`, `"javascript": []`, an indented or flow-style root mapping, a
/// comment between `flow:` and its value, `require (`, a `<<:` merge key). Excluded
/// when it does not parse, its root is not a mapping, any top-level key is a non-http
/// protocol, or a `flow` is not a string or mentions `require` at all (any case, any
/// spacing).
pub fn yaml_structure_excluded(template: &str) -> bool {
    let text = template.strip_prefix('\u{feff}').unwrap_or(template);
    let Ok(mut doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else {
        return true;
    };
    // nuclei's YAML library applies merge keys, so read the root as nuclei will.
    if doc.apply_merge().is_err() {
        return true;
    }
    let serde_yaml_ng::Value::Mapping(root) = doc else {
        return true;
    };
    root.iter().any(|(k, v)| {
        let Some(key) = k.as_str() else {
            return false;
        };
        let key = key.trim().to_ascii_lowercase();
        if NON_HTTP_SECTIONS.contains(&key.as_str()) {
            return true;
        }
        key == "flow"
            && v.as_str()
                .is_none_or(|f| f.to_ascii_lowercase().contains("require"))
    })
}

/// True when Ascent never runs this template (see [`off_target_templates`]).
pub fn excluded_template(template: &str) -> bool {
    sends_off_target(template)
        || has_non_http_protocol(template)
        || flow_loads_modules(template)
        || yaml_structure_excluded(template)
}

/// A listed template path resolved under the listing's directory (nuclei prints
/// paths relative to it, with `\` on Windows).
fn resolve_listed(dir: &Path, rel: &str) -> PathBuf {
    if Path::new(rel).is_absolute() {
        return PathBuf::from(rel);
    }
    rel.split(['/', '\\'])
        .filter(|c| !c.is_empty())
        .fold(dir.to_path_buf(), |p, c| p.join(c))
}

/// The absolute template paths in `nuclei -tl` output: a banner
/// `Listing available <ver> nuclei templates for <DIR>`, then one path per line
/// relative to DIR. Fails closed — no banner, an unreadable DIR, or no template
/// listed is an error, so a scan never runs unfiltered.
pub fn parse_template_listing(out: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut lines = out.lines().map(str::trim);
    const MARK: &str = " nuclei templates for ";
    let banner = lines
        .by_ref()
        .find(|l| l.starts_with("Listing available") && l.contains(MARK))
        .ok_or(LISTING_NOT_RECOGNISED)?;
    // Everything after the marker is DIR, even when DIR itself contains " for ".
    let dir = banner.split_once(MARK).map_or("", |(_, d)| d.trim());
    if !Path::new(dir).is_absolute() || std::fs::read_dir(dir).is_err() {
        return Err(LISTING_NOT_RECOGNISED.into());
    }
    let dir = Path::new(dir);
    let paths: Vec<PathBuf> = lines
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.ends_with(".yaml") || l.ends_with(".yml")
        })
        .map(|l| resolve_listed(dir, l))
        .collect();
    if paths.is_empty() {
        return Err(LISTING_NOT_RECOGNISED.into());
    }
    Ok(paths)
}

/// The installed http templates Ascent never runs: those that send a request off
/// the target ([`sends_off_target`]), those with a non-http protocol section
/// ([`has_non_http_protocol`]) and those whose flow loads a JS module
/// ([`flow_loads_modules`]). Lists the templates once (no targets, no network).
/// A listed template that cannot be read is an error: Ascent cannot tell what it
/// sends, nor be sure the path it would exclude is the one nuclei loads.
fn off_target_templates(runner: &dyn Runner) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let args: Vec<String> = ["-tl", "-nc", "-duc", "-silent", "-pt", "http"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let out = runner.run_text("nuclei", &args, &[])?;
    let listed = parse_template_listing(&out)?;
    let mut off: BTreeSet<PathBuf> = BTreeSet::new();
    for p in listed {
        let bytes = std::fs::read(&p).map_err(|_| TEMPLATE_UNREADABLE)?;
        let text = String::from_utf8_lossy(&bytes);
        if excluded_template(&text) {
            off.insert(p);
        }
    }
    Ok(off.into_iter().collect())
}

const TRACE_MISSING: &str = "nuclei trace log missing";
/// A host is reported as failing when at least half of at least this many requests failed.
const FAILING_MIN_REQUESTS: usize = 20;
/// Minimum consecutive connection errors before a subsequent success qualifies as crash-and-recover.
const CRASH_RECOVER_MIN_ERRORS: usize = 20;
/// Off-scope host names listed by name; the rest are counted.
const OFF_SCOPE_NAMES_SHOWN: usize = 10;

/// An in-scope host most of whose requests failed (the target was overloaded or went down).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FailingHost {
    pub host: String,
    pub failed: usize,
    pub sent: usize,
}

/// The host of a trace-log `address`, lower-cased. nuclei writes
/// `Hostname() + ":" + port`, so an IPv6 host comes UNBRACKETED (`::1:3000`): the
/// port is always what follows the LAST `:`. A bracketed `[v6]:port` (or `[v6]`)
/// gives its inner host; an address with no `:` is the host itself.
fn address_host(address: &str) -> String {
    let a = address.trim();
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        a.rsplit_once(':').map_or(a, |(h, _)| h)
    };
    host.to_ascii_lowercase()
}

/// The host of a trace line's `input` (the URL nuclei requested; for an
/// `@Host`-rewritten request nuclei puts the rewritten URL there), lower-cased, or
/// `""` (no host: never in scope) when the input is ambiguous.
///
/// The RAW authority decides, because URL parsers disagree on it (WHATWG ends the
/// authority at `\`; Go, which nuclei is written in, reads `127.0.0.1\` as userinfo
/// and dials what follows the `@`). The authority is the text after `://` (or the
/// whole input without a scheme) up to the first `/`, `?` or `#`. One containing
/// `\`, `%`, whitespace or a control character has no host. Otherwise userinfo up to
/// the LAST `@` is dropped and the rest must be a valid `host[:port]` / `[v6][:port]`
/// (the scope guard's own authority reader). When the input also parses as a URL
/// with a host, that host must agree.
fn input_host(input: &str) -> String {
    let s = input.trim();
    let rest = s.find("://").map_or(s, |i| &s[i + 3..]);
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority
        .chars()
        .any(|c| c == '\\' || c == '%' || c.is_whitespace() || c.is_control())
    {
        return String::new();
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = crate::scope::host_from_authority(host_port);
    let parsed = url::Url::parse(s).ok().and_then(|u| {
        u.host().map(|h| match h {
            url::Host::Domain(d) => d.to_ascii_lowercase(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        })
    });
    match parsed {
        Some(p) if p != host => String::new(),
        _ => host,
    }
}

/// What the nuclei trace logs (`-tlog`: one JSON object per request sent, with
/// `address` = `host:port` and `error` = `none` or the cause) say about the requests.
#[derive(Default)]
struct TraceAudit {
    sent: usize,
    errors: usize,
    off_scope: BTreeSet<String>,
    off_scope_count: usize,
    /// In-scope host -> (sent, failed).
    per_host: std::collections::BTreeMap<String, (usize, usize)>,
}

impl TraceAudit {
    /// Streams one trace log (it can be tens of MB) and returns how many request lines
    /// it held. A request line is a JSON object with an `address`, `input`,
    /// `template` or `type` key; it is never skipped (see [`Self::record`]). Any
    /// other line is skipped.
    fn read(
        &mut self,
        path: &Path,
        guard: &ScopeGuard,
        secret: Option<&str>,
    ) -> std::io::Result<usize> {
        use std::io::BufRead;
        let mut r = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut buf = Vec::new();
        let mut n = 0;
        loop {
            buf.clear();
            if r.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(&buf) else {
                continue;
            };
            if !["address", "input", "template", "type"]
                .iter()
                .any(|k| o.contains_key(*k))
            {
                continue;
            }
            let s = |k: &str| o.get(k).and_then(Value::as_str);
            self.record(
                s("address"),
                s("input"),
                s("error").unwrap_or(""),
                guard,
                secret,
            );
            n += 1;
        }
        Ok(n)
    }

    /// One request. Its host is the `address` nuclei dialled; when that is missing
    /// or empty (raw/unsafe requests log `""`), the host of the `input` URL nuclei
    /// requested. With neither, it is `(no address)`: never assumed in scope.
    fn record(
        &mut self,
        address: Option<&str>,
        input: Option<&str>,
        error: &str,
        guard: &ScopeGuard,
        secret: Option<&str>,
    ) {
        self.sent += 1;
        let failed = !(error.is_empty() || error == "none");
        if failed {
            self.errors += 1;
        }
        // Scrubbed first, so nothing derived from them can carry the auth value.
        let address = address.map(|a| scrub_text(a, secret)).unwrap_or_default();
        let host = if address.trim().is_empty() {
            input_host(&scrub_text(input.unwrap_or(""), secret))
        } else {
            address_host(&address)
        };
        if host.is_empty() {
            self.off_scope_count += 1;
            self.off_scope.insert("(no address)".into());
            return;
        }
        if guard.in_scope(&host) {
            let e = self.per_host.entry(host).or_default();
            e.0 += 1;
            e.1 += usize::from(failed);
        } else {
            // A failed request still went towards the host (at least a DNS lookup).
            // The name reaches the report verbatim, so it is bounded (a DNS name is <= 253).
            self.off_scope_count += 1;
            self.off_scope.insert(host.chars().take(255).collect());
        }
    }

    /// The off-scope host names, sorted, at most [`OFF_SCOPE_NAMES_SHOWN`] plus
    /// "…and N more".
    fn off_scope_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .off_scope
            .iter()
            .take(OFF_SCOPE_NAMES_SHOWN)
            .cloned()
            .collect();
        if self.off_scope.len() > OFF_SCOPE_NAMES_SHOWN {
            v.push(format!(
                "…and {} more",
                self.off_scope.len() - OFF_SCOPE_NAMES_SHOWN
            ));
        }
        v
    }

    fn failing_hosts(&self) -> Vec<FailingHost> {
        self.per_host
            .iter()
            .filter(|(_, (sent, failed))| *sent >= FAILING_MIN_REQUESTS && failed * 2 >= *sent)
            .map(|(h, (sent, failed))| FailingHost {
                host: h.clone(),
                failed: *failed,
                sent: *sent,
            })
            .collect()
    }
}

/// True when `error` (case-insensitive) is one of the connection-error types
/// that signal a crashed target: `connection refused`, `connection reset`, or `eof`.
fn is_connection_error(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    e.contains("connection refused") || e.contains("connection reset") || e.contains("eof")
}

/// Detects hosts that crashed and recovered during a nuclei pass by analysing
/// its trace log.  A crash-and-recover means ≥ [`CRASH_RECOVER_MIN_ERRORS`]
/// consecutive connection errors (`connection refused`, `connection reset`, `EOF`
/// — case-insensitive) against ONE host, followed by ≥ 1 success for that same
/// host.  Counter-cases: a streak shorter than the threshold or one with no
/// subsequent success are not flagged.  Returns the list of affected hosts
/// (deduplicated, first-seen order).
pub fn detect_crash_recover(trace_path: &Path) -> Vec<String> {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(trace_path) else {
        return vec![];
    };
    let reader = std::io::BufReader::new(file);
    // per-host: (current consecutive connection-error streak, already recorded)
    let mut state: std::collections::HashMap<String, (usize, bool)> =
        std::collections::HashMap::new();
    let mut recovered: Vec<String> = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let address = s("address");
        if address.trim().is_empty() {
            continue;
        }
        let host = address_host(&address);
        if host.is_empty() {
            continue;
        }
        let error = s("error");
        let failed = !(error.is_empty() || error == "none");
        let entry = state.entry(host.clone()).or_insert((0, false));
        if !failed {
            // success: if we had a long-enough streak and haven't recorded it yet, record it
            if entry.0 >= CRASH_RECOVER_MIN_ERRORS && !entry.1 {
                entry.1 = true;
                recovered.push(host);
            }
            entry.0 = 0;
        } else if is_connection_error(&error) {
            entry.0 += 1;
        } else {
            // other error type — breaks the connection-error streak
            entry.0 = 0;
        }
    }
    recovered
}

/// `-H` plus exactly ONE `"Name: value"` element (never split, never other flags).
pub fn header_args(auth: Option<&(String, String)>) -> Vec<String> {
    match auth {
        Some((name, value)) => vec!["-H".into(), format!("{name}: {value}")],
        None => vec![],
    }
}

pub fn filter_in_scope(urls: Vec<String>, in_scope: &dyn Fn(&str) -> bool) -> (Vec<String>, usize) {
    let total = urls.len();
    let kept: Vec<String> = urls.into_iter().filter(|u| in_scope(u)).collect();
    let dropped = total - kept.len();
    (kept, dropped)
}

pub fn scrub_text(s: &str, secret: Option<&str>) -> String {
    match secret {
        Some(v) if !v.is_empty() => s.replace(v, "***"),
        _ => s.to_string(),
    }
}

/// A row that could not be re-parsed after replacement (should be impossible) is
/// kept as a placeholder built only from individually scrubbed fields, never dropped.
fn scrub_placeholder(row: &Value, secret: Option<&str>) -> Value {
    let s = |v: &Value, default: &str| -> String {
        let t = scrub_text(v.as_str().unwrap_or(""), secret);
        if t.is_empty() {
            default.to_string()
        } else {
            t
        }
    };
    let info = &row["info"];
    let tags: Vec<String> = row_tags(row)
        .iter()
        .map(|t| scrub_text(t, secret))
        .collect();
    json!({
        "template-id": s(&row["template-id"], "nuclei"),
        "matched-at": s(&row["matched-at"], ""),
        "host": s(&row["host"], ""),
        "info": {
            "name": s(&info["name"], "finding"),
            "severity": s(&info["severity"], "info"),
            "description": s(&info["description"], ""),
            "tags": tags,
        },
    })
}

/// Replace the auth value everywhere in each raw nuclei row (curl-command, request, …).
/// The value is replaced in the JSON *text*, in both its raw and its JSON-escaped form
/// (a value containing `"` or `\` appears escaped in the text).
pub fn scrub_rows(rows: Vec<Value>, secret: Option<&str>) -> Vec<Value> {
    let Some(v) = secret.filter(|v| !v.is_empty()) else {
        return rows;
    };
    let esc_full = serde_json::to_string(v).unwrap_or_default();
    let esc = esc_full
        .get(1..esc_full.len().saturating_sub(1))
        .unwrap_or("");
    rows.into_iter()
        .map(|r| {
            let mut text = r.to_string();
            if !esc.is_empty() {
                text = text.replace(esc, "***");
            }
            text = text.replace(v, "***");
            serde_json::from_str(&text).unwrap_or_else(|_| scrub_placeholder(&r, secret))
        })
        .collect()
}

struct Category {
    id: &'static str,
    name: &'static str,
    /// nuclei tags that test it; empty = Ascent never tests it (`note` says why).
    tags: &'static [&'static str],
    /// The active profile's `-dast` pass fuzzes parameters for it.
    fuzzed: bool,
    /// Why coverage is limited even when every tag ran (or, with no tags, why never).
    note: Option<&'static str>,
}

const fn def(
    id: &'static str,
    name: &'static str,
    tags: &'static [&'static str],
    fuzzed: bool,
    note: Option<&'static str>,
) -> Category {
    Category {
        id,
        name,
        tags,
        fuzzed,
        note,
    }
}

const IDOR_NOTE: &str = "few idor templates, mostly CVE- or product-specific; generic IDOR needs app logic and a second user";
const SSRF_NOTE: &str = "blind/out-of-band SSRF not tested (interactsh disabled)";
const RATE_LIMIT_NOTE: &str = "needs load generation; Ascent never floods a target";

const CATEGORIES: &[Category] = &[
    def("sqli", "SQL injection", &["sqli"], true, None),
    def("xss", "Cross-site scripting", &["xss"], true, None),
    def(
        "auth-bypass",
        "Authentication bypass",
        &["auth-bypass", "jwt"],
        false,
        None,
    ),
    def(
        "authz",
        "Authorization flaws (IDOR)",
        &["idor"],
        false,
        Some(IDOR_NOTE),
    ),
    def("cors", "CORS misconfiguration", &["cors"], false, None),
    def("headers", "Security headers", &["headers"], false, None),
    def(
        "session",
        "Session management",
        &["session", "cookie", "csrf"],
        false,
        None,
    ),
    def(
        "ssrf",
        "Server-side request forgery",
        &["ssrf"],
        true,
        Some(SSRF_NOTE),
    ),
    def(
        "lfi",
        "Path traversal / file inclusion",
        &["lfi"],
        true,
        None,
    ),
    def("redirect", "Open redirect", &["redirect"], true, None),
    def(
        "known-vulns",
        "Known CVEs, exposures, misconfiguration",
        &["cve", "exposure", "misconfig", "tech"],
        false,
        None,
    ),
    def(
        "rate-limit",
        "API rate limiting",
        &[],
        false,
        Some(RATE_LIMIT_NOTE),
    ),
];

/// The tags the profile's passes run and whether it runs the `-dast` fuzzing pass,
/// read from [`nuclei_passes`] so the coverage can never disagree with what ran.
fn tags_run(profile: DastProfile) -> (BTreeSet<String>, bool) {
    let mut tags = BTreeSet::new();
    let mut fuzz = false;
    for pass in nuclei_passes(profile) {
        fuzz |= pass.iter().any(|a| a == "-dast");
        if let Some(i) = pass.iter().position(|a| a == "-tags") {
            if let Some(list) = pass.get(i + 1) {
                tags.extend(list.split(',').map(|t| t.trim().to_string()));
            }
        }
    }
    (tags, fuzz)
}

/// The lowest profile that runs `tag`, if any.
fn profile_running(tag: &str) -> Option<DastProfile> {
    [
        DastProfile::Passive,
        DastProfile::Standard,
        DastProfile::Active,
    ]
    .into_iter()
    .find(|p| tags_run(*p).0.contains(tag))
}

/// "csrf runs in the standard profile" (grouped by profile).
fn missing_reason(missing: &[&str]) -> String {
    let mut by: Vec<(Option<DastProfile>, Vec<&str>)> = Vec::new();
    for t in missing {
        let p = profile_running(t);
        match by.iter_mut().find(|(q, _)| *q == p) {
            Some((_, v)) => v.push(t),
            None => by.push((p, vec![t])),
        }
    }
    by.iter()
        .map(|(p, v)| {
            let verb = if v.len() == 1 { "runs" } else { "run" };
            match p {
                Some(p) => format!("{} {verb} in the {} profile", v.join(", "), p.as_str()),
                None => format!("{} {verb} in no profile", v.join(", ")),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn row_tags(r: &Value) -> Vec<String> {
    match &r["info"]["tags"] {
        Value::Array(a) => a
            .iter()
            .filter_map(|t| t.as_str())
            .map(|t| t.trim().to_ascii_lowercase())
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .collect(),
        _ => vec![],
    }
}

/// What was and was not tested. `scanned` is the number of in-scope URLs nuclei
/// actually ran against: with zero, nothing was tested whatever the profile says.
/// A dry run sent nothing, so it always reports zero.
pub fn coverage(
    profile: DastProfile,
    authenticated: bool,
    scanned: usize,
    dry_run: bool,
    rows: &[Value],
) -> Value {
    let scanned = if dry_run { 0 } else { scanned };
    let zero_reason = if dry_run {
        "dry run: nothing was sent"
    } else {
        "no in-scope URL was reachable"
    };
    let tagsets: Vec<Vec<String>> = rows.iter().map(row_tags).collect();
    let (ran, fuzz) = tags_run(profile);
    let cats: Vec<Value> = CATEGORIES
        .iter()
        .map(|c| {
            // Per tag: all ran -> tested, some -> limited, none -> not_tested.
            let (tags_ran, tags_missing): (Vec<&str>, Vec<&str>) = if scanned == 0 {
                (vec![], c.tags.to_vec())
            } else {
                c.tags.iter().partition(|t| ran.contains(**t))
            };
            let (status, reason) = if c.tags.is_empty() {
                ("not_tested", c.note.unwrap_or("").to_string())
            } else if scanned == 0 {
                ("not_tested", zero_reason.to_string())
            } else if tags_ran.is_empty() {
                let p = tags_missing.iter().filter_map(|t| profile_running(t)).min();
                let reason = match p {
                    Some(p) => format!("enable the {} profile", p.as_str()),
                    None => missing_reason(&tags_missing),
                };
                ("not_tested", reason)
            } else {
                let mut notes: Vec<String> = Vec::new();
                if !tags_missing.is_empty() {
                    notes.push(missing_reason(&tags_missing));
                }
                if fuzz && c.fuzzed {
                    notes.push("templates plus parameter fuzzing".into());
                }
                notes.extend(c.note.map(String::from));
                let limited = !tags_missing.is_empty() || c.note.is_some();
                (if limited { "limited" } else { "tested" }, notes.join("; "))
            };
            let findings = if status == "not_tested" {
                0
            } else {
                tagsets
                    .iter()
                    .filter(|ts| ts.iter().any(|t| c.tags.contains(&t.as_str())))
                    .count()
            };
            json!({"id": c.id, "name": c.name, "tags": c.tags, "status": status, "reason": reason,
                "findings": findings, "tags_run": tags_ran, "tags_missing": tags_missing})
        })
        .collect();
    json!({"profile": profile.as_str(), "authenticated": authenticated, "scanned": scanned, "categories": cats})
}

/// Active runs two passes that can return the same hit; keep the first of each
/// (`template-id`, `matcher-name`, `matched-at`, `fuzzing_parameter`) key (missing
/// fields count as ""). The template pass runs first, so its verifiable copy wins.
fn dedupe_rows(rows: Vec<Value>) -> Vec<Value> {
    let mut seen: BTreeSet<[String; 4]> = BTreeSet::new();
    let f = |r: &Value, k: &str| r[k].as_str().unwrap_or("").to_string();
    rows.into_iter()
        .filter(|r| {
            seen.insert([
                f(r, "template-id"),
                f(r, "matcher-name"),
                f(r, "matched-at"),
                f(r, "fuzzing_parameter"),
            ])
        })
        .collect()
}

const EXCLUDED_WHY: &str =
    "Ascent cannot scope-check (an @Host naming another host, a non-http section, or a flow that loads modules)";

/// The report section, as a list: the dashboard's markdown renderer has no GFM tables.
pub fn coverage_markdown(cov: &Value) -> String {
    let mut out = format!(
        "\n## DAST coverage\n\nProfile: `{}` · authenticated: {} · URLs scanned: {}\n\n",
        cov["profile"].as_str().unwrap_or(""),
        if cov["authenticated"] == true {
            "yes"
        } else {
            "no"
        },
        cov["scanned"],
    );
    for c in cov["categories"].as_array().into_iter().flatten() {
        let name = c["name"].as_str().unwrap_or("");
        let status = c["status"].as_str().unwrap_or("").replace('_', " ");
        let reason = c["reason"].as_str().unwrap_or("");
        if status == "not tested" {
            out.push_str(&format!("- **{name}** — not tested: {reason}\n"));
            continue;
        }
        let n = c["findings"].as_u64().unwrap_or(0);
        let noun = if n == 1 { "finding" } else { "findings" };
        out.push_str(&format!("- **{name}** — {status} · {n} {noun}"));
        if !reason.is_empty() {
            out.push_str(&format!(": {reason}"));
        }
        out.push('\n');
    }
    let mut notes: Vec<String> = Vec::new();
    match cov["templates_excluded"].as_u64().unwrap_or(0) {
        0 => {}
        1 => notes.push(format!(
            "1 template excluded: it may send requests {EXCLUDED_WHY}"
        )),
        n => notes.push(format!(
            "{n} templates excluded: they may send requests {EXCLUDED_WHY}"
        )),
    }
    let plural = |n: u64| if n == 1 { "request" } else { "requests" };
    if cov["scanned"].as_u64().unwrap_or(0) > 0 {
        let sent = cov["requests_sent"].as_u64().unwrap_or(0);
        notes.push(format!(
            "nuclei sent {sent} {}; {} failed (timeouts/connection errors) — those checks produced no result",
            plural(sent),
            cov["request_errors"].as_u64().unwrap_or(0),
        ));
    }
    let off = cov["off_scope_request_count"].as_u64().unwrap_or(0);
    if off > 0 {
        let names: Vec<&str> = cov["out_of_scope_requests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        notes.push(format!(
            "nuclei sent {off} {} to hosts outside the scope: {} — the run is INCOMPLETE",
            plural(off),
            names.join(", ")
        ));
    }
    let gone: Vec<&str> = cov["stopped_answering"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !gone.is_empty() {
        notes.push(format!(
            "stopped answering during the scan: {} — the checks after that point produced no result; the run is INCOMPLETE",
            gone.join(", ")
        ));
    }
    if !notes.is_empty() {
        out.push('\n');
        for n in notes {
            out.push_str(&n);
            out.push_str("\n\n");
        }
        out.truncate(out.trim_end().len());
        out.push('\n');
    }
    out
}

/// What the DAST track did. Every field defaults, so an older `run.json` still parses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DastSummary {
    pub profile: String,
    pub authenticated: bool,
    pub auth_header: String,
    /// Live in-scope seed URLs handed to the crawler.
    pub seeded: usize,
    /// NEW endpoints katana found (seeds not counted).
    pub crawled: usize,
    pub out_of_scope_dropped: usize,
    /// In-scope URLs nuclei ran against (0 in a dry run).
    pub scanned: usize,
    /// Declared `urls` that answered / did not answer the httpx probe.
    pub reachable: usize,
    pub unreachable: usize,
    pub unreachable_urls: Vec<String>,
    /// Installed http templates never run because they send requests off the target.
    pub templates_excluded: usize,
    /// Requests nuclei sent (from its trace logs), and how many of them failed
    /// (timeouts/connection errors: those checks produced no result).
    pub requests_sent: usize,
    pub request_errors: usize,
    /// Hosts outside the engagement scope nuclei sent requests to (at most ten names,
    /// then "…and N more"), and how many requests went there. Any makes the run INCOMPLETE.
    pub out_of_scope_requests: Vec<String>,
    pub off_scope_request_count: usize,
    /// In-scope hosts where at least half of at least 20 requests failed.
    pub failing_hosts: Vec<FailingHost>,
    /// Live seed URLs that no longer answered the httpx probe after the scan: the
    /// target went down part-way, so the checks after that point produced no result.
    pub stopped_answering: Vec<String>,
    /// Hosts that crashed (≥ 20 consecutive connection errors) and then recovered
    /// (at least one subsequent success) during the scan.  The run is INCOMPLETE
    /// because checks during the outage produced no result.
    pub recovered_hosts: Vec<String>,
    /// True when the `--dast-timeout` wall-clock limit was reached and nuclei was
    /// stopped before all templates finished. Findings collected up to that point
    /// are kept, but the run is INCOMPLETE.
    pub wall_clock_limit_hit: bool,
}

pub struct DastOutcome {
    pub findings: Vec<Finding>,
    pub summary: DastSummary,
    pub coverage: Value,
}

/// `Ok(None)` when the engagement has no hosts and no urls (no DAST scope).
/// `live` is false for a dry run: every call still goes through the scope-checking
/// runner, but nothing is sent, so no declared URL is reported unreachable and the
/// coverage says nothing was scanned.
///
/// `dast_timeout_secs` is the wall-clock limit for all nuclei passes combined.
/// When the limit is hit, nuclei is stopped (SIGTERM then SIGKILL) and whatever
/// findings were collected so far are returned with `wall_clock_limit_hit = true`
/// in the summary. The engagement file cannot set this; it is a CLI concern.
pub fn run_dast(
    eng: &Engagement,
    runner: &dyn Runner,
    auth: Option<&(String, String)>,
    live: bool,
    dast_timeout_secs: u64,
) -> Result<Option<DastOutcome>, Box<dyn std::error::Error>> {
    if eng.hosts.is_empty() && eng.urls.is_empty() {
        return Ok(None);
    }
    let secret = auth.map(|(_, v)| v.as_str());
    let scrubbed = |e: Box<dyn std::error::Error>| -> Box<dyn std::error::Error> {
        scrub_text(&e.to_string(), secret).into()
    };
    // httpx runs whenever there is DAST scope: recon probes the hosts, the probe the urls.
    if live {
        ensure_httpx_identity(runner).map_err(scrubbed)?;
    }
    let guard = ScopeGuard::new(eng);
    // A declared URL the guard refuses is dropped and counted, never probed.
    let declared: BTreeSet<String> = eng.urls.iter().cloned().collect();
    let (declared, url_dropped) =
        filter_in_scope(declared.into_iter().collect(), &|u| guard.in_scope(u));
    // Only declared URLs that answer are crawled (hosts are probed by recon).
    let (live_urls, dead_urls) = probe_urls(runner, &declared).map_err(scrubbed)?;
    let (live_urls, dead_urls) = if live {
        (live_urls, dead_urls)
    } else {
        (declared, vec![])
    };
    let mut seed: BTreeSet<String> = live_urls.iter().cloned().collect();
    let mut recon_dropped = 0;
    for h in &eng.hosts {
        let (urls, d) = recon(runner, h, is_subfinder_candidate(h), &|n| guard.in_scope(n))
            .map_err(scrubbed)?;
        seed.extend(urls);
        recon_dropped += d;
    }
    // An off-scope seed (e.g. an httpx redirect target) is dropped and counted, never crawled.
    let (seed, seed_dropped) = filter_in_scope(seed.into_iter().collect(), &|u| guard.in_scope(u));
    let headers = header_args(auth);
    let crawled = enumerate_surface(runner, &seed, &headers).map_err(scrubbed)?;
    let seeds: BTreeSet<&String> = seed.iter().collect();
    let crawled_n = crawled.iter().filter(|u| !seeds.contains(u)).count();
    let (surface, crawl_dropped) = filter_in_scope(crawled, &|u| guard.in_scope(u));
    let dropped = url_dropped + recon_dropped + seed_dropped + crawl_dropped;
    let mut rows = Vec::new();
    let mut templates_excluded = 0;
    let mut audit = TraceAudit::default();
    let mut stopped_answering = Vec::new();
    let mut recovered_hosts: Vec<String> = Vec::new();
    let mut wall_clock_limit_hit = false;
    // The deadline applies to all nuclei passes combined; None when not live
    // (no real process is spawned) or when the runner is not timeout-capable.
    let deadline = if live && runner.supports_timeout() {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(dast_timeout_secs))
    } else {
        None
    };
    if !surface.is_empty() {
        // Live only: a private scratch directory (removed on every path, also on error)
        // for the template exclusion list. A dry run lists nothing and excludes nothing.
        let scratch = if live { Some(TempDir::create()?) } else { None };
        let mut exclude_args: Vec<String> = Vec::new();
        if let Some(dir) = &scratch {
            let off = off_target_templates(runner).map_err(scrubbed)?;
            templates_excluded = off.len();
            if !off.is_empty() {
                let p = dir.path().join("exclude-templates.txt");
                let lines: Vec<String> = off
                    .iter()
                    .map(|t| t.to_string_lossy().into_owned())
                    .collect();
                write_new_lines(&p, &lines)?;
                exclude_args = vec!["-et".into(), p.to_string_lossy().into_owned()];
            }
        }
        let listed = listed_count(&surface);
        'passes: for (i, pass) in nuclei_passes(eng.dast.profile).into_iter().enumerate() {
            // Tag the `-dast` fuzzing pass's rows so they normalise as `nuclei-dast`.
            let fuzz_pass = pass.iter().any(|a| a == "-dast");
            let mut args = common_nuclei_args();
            args.extend(pass);
            args.extend(exclude_args.iter().cloned());
            // Each pass logs every request it sends; nuclei creates the file itself, so
            // its absence after a successful pass means nothing was logged.
            let trace = scratch
                .as_ref()
                .map(|d| d.path().join(format!("trace-{i}.jsonl")));
            if let Some(t) = &trace {
                args.extend(["-tlog".into(), t.to_string_lossy().into_owned()]);
            }
            args.extend(headers.iter().cloned());
            let (pass_rows, timed_out) =
                scan_rows_with_deadline(runner, &surface, &args, deadline, secret)
                    .map_err(scrubbed)?;
            for mut r in pass_rows {
                if fuzz_pass {
                    if let Some(o) = r.as_object_mut() {
                        o.insert("ascent-pass".into(), json!("dast"));
                    }
                }
                rows.push(r);
            }
            if timed_out {
                wall_clock_limit_hit = true;
                // Audit the trace for the interrupted pass before breaking so that
                // off-scope requests made during the partial pass are not missed.
                // The log may be truncated; tolerate missing/unreadable files and
                // incomplete JSON lines. Skip only when no requests were made.
                if let Some(t) = &trace {
                    if listed > 0 {
                        let _ = audit.read(t, &guard, secret);
                        for h in detect_crash_recover(t) {
                            if !recovered_hosts.contains(&h) {
                                recovered_hosts.push(h);
                            }
                        }
                    }
                }
                break 'passes;
            }
            if let Some(t) = &trace {
                if listed > 0 {
                    let n = audit.read(t, &guard, secret).map_err(|_| TRACE_MISSING)?;
                    // The template pass always sends requests for a listed URL; the
                    // `-dast` pass only fuzzes URLs with parameters, so it may send none.
                    if n == 0 && !fuzz_pass {
                        return Err(TRACE_MISSING.into());
                    }
                    for h in detect_crash_recover(t) {
                        if !recovered_hosts.contains(&h) {
                            recovered_hosts.push(h);
                        }
                    }
                }
                // Tens of MB: free it now (the scratch dir is removed on every path anyway).
                let _ = std::fs::remove_file(t);
            }
        }
        // A target that crashed part-way leaves only a minority of failed requests in
        // the trace, so every live seed is probed again: one that no longer answers
        // means the later checks never reached it. A seed that misses the probe once is
        // retried once. A probe that fails outright counts every seed it covered as not
        // answering, so the scan's results are kept and the run still fails closed.
        // Skip the post-scan probe when the timeout hit: the target is likely fine.
        if live && !wall_clock_limit_hit {
            let dead =
                |urls: &[String]| probe_urls(runner, urls).map_or_else(|_| urls.to_vec(), |r| r.1);
            stopped_answering = dead(&seed);
            if !stopped_answering.is_empty() {
                stopped_answering = dead(&stopped_answering);
            }
        }
    }
    let rows = scrub_rows(dedupe_rows(rows), secret);
    let mut coverage = coverage(
        eng.dast.profile,
        auth.is_some(),
        surface.len(),
        !live,
        &rows,
    );
    let out_of_scope_requests = audit.off_scope_names();
    coverage["templates_excluded"] = json!(templates_excluded);
    coverage["requests_sent"] = json!(audit.sent);
    coverage["request_errors"] = json!(audit.errors);
    coverage["out_of_scope_requests"] = json!(out_of_scope_requests);
    coverage["off_scope_request_count"] = json!(audit.off_scope_count);
    coverage["stopped_answering"] = json!(stopped_answering);
    Ok(Some(DastOutcome {
        findings: normalise_nuclei(&rows),
        summary: DastSummary {
            profile: eng.dast.profile.as_str().into(),
            authenticated: auth.is_some(),
            auth_header: auth.map(|(n, _)| n.clone()).unwrap_or_default(),
            seeded: seed.len(),
            crawled: crawled_n,
            out_of_scope_dropped: dropped,
            scanned: if live { surface.len() } else { 0 },
            reachable: if live { live_urls.len() } else { 0 },
            unreachable: dead_urls.len(),
            unreachable_urls: dead_urls,
            templates_excluded,
            requests_sent: audit.sent,
            request_errors: audit.errors,
            out_of_scope_requests,
            off_scope_request_count: audit.off_scope_count,
            failing_hosts: audit.failing_hosts(),
            stopped_answering,
            recovered_hosts,
            wall_clock_limit_hit,
        },
        coverage,
    }))
}

/// Fixtures shared with the pipeline tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;

    /// `tests/fixtures/nuclei-templates`: a few small templates, on and off target.
    pub fn fixture_templates() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("nuclei-templates")
    }

    /// `nuclei -tl -nc -duc -silent -pt http` output (v3.11.1 shape) listing `rel` under `dir`.
    pub fn listing(dir: &std::path::Path, rel: &[&str]) -> String {
        format!(
            "\nListing available v10.4.9 nuclei templates for {}\n{}\n",
            dir.display(),
            rel.join("\n")
        )
    }

    /// A listing of one ordinary (on-target) fixture template.
    pub fn benign_listing() -> String {
        listing(&fixture_templates(), &["http/benign.yaml"])
    }

    /// One nuclei v3 `-tlog` trace line (with an empty `input`, so only `address`
    /// can name the host).
    pub fn trace_line(address: &str, error: &str) -> String {
        trace_line_with_input(address, "", error)
    }

    /// One nuclei v3 `-tlog` trace line with the URL nuclei requested.
    pub fn trace_line_with_input(address: &str, input: &str, error: &str) -> String {
        serde_json::json!({"template": "http/benign.yaml", "type": "http",
            "input": input, "address": address, "error": error})
        .to_string()
    }

    /// One successful trace line per URL, addressed to its `host:port`.
    pub fn trace_for_urls(urls: &[String]) -> Vec<String> {
        urls.iter()
            .filter_map(|u| url::Url::parse(u).ok())
            .filter_map(|u| Some(format!("{}:{}", u.host_str()?, u.port_or_known_default()?)))
            .map(|a| trace_line(&a, "none"))
            .collect()
    }

    /// The value after `flag` in a nuclei argv.
    pub fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a String> {
        args.windows(2).find(|w| w[0] == flag).map(|w| &w[1])
    }

    /// What a real nuclei pass leaves behind: a trace log (`-tlog`) with one successful
    /// request per URL of its `-l` list.
    pub fn write_default_trace(args: &[String]) {
        if let (Some(t), Some(l)) = (flag_value(args, "-tlog"), flag_value(args, "-l")) {
            let urls: Vec<String> = std::fs::read_to_string(l)
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
            std::fs::write(t, trace_for_urls(&urls).join("\n") + "\n").unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::cell::RefCell;

    const SECRET: &str = "Bearer s3cr3t";

    /// One row of real katana v1.7 `-jsonl` output.
    fn katana_row(endpoint: &str) -> Value {
        json!({"timestamp":"2026-10-31T00:00:00.000000+00:00",
            "request":{"method":"GET","endpoint":endpoint,"raw":"GET / HTTP/1.1\r\n\r\n"},
            "response":{"status_code":200}})
    }

    type Call = (String, Vec<String>, Vec<String>);

    /// Recording fake: canned output per tool, optional nuclei failure.
    struct Fake {
        calls: RefCell<Vec<Call>>,
        nuclei_err: Option<&'static str>,
        /// An extra (off-scope) URL httpx reports for example.com.
        extra_httpx: Option<&'static str>,
        /// nuclei returns its row twice per call (as two Active passes would).
        nuclei_twice: bool,
        /// Declared URLs the httpx probe gets no answer from.
        dead: Vec<&'static str>,
        /// URLs that answer the httpx probe until nuclei has run, then no longer do.
        down_after_scan: Vec<&'static str>,
        /// Once nuclei has run, the httpx URL probe fails outright.
        httpx_err_after_scan: bool,
        /// URLs that miss only the first httpx probe after the scan.
        slow_after_scan: Vec<&'static str>,
        /// `httpx -version` output.
        httpx_version: &'static str,
        /// Names subfinder reports for example.com.
        subs: Vec<&'static str>,
        /// The URL list file (`-l`) of each nuclei call, read while it exists.
        nuclei_lists: RefCell<Vec<Vec<String>>>,
        /// When set, the template pass returns these rows instead of the default one.
        template_rows: Option<Vec<Value>>,
        /// When set, the `-dast` pass returns these rows instead.
        dast_rows: Option<Vec<Value>>,
        /// `nuclei -tl` output (default: one ordinary fixture template).
        listing: String,
        /// Every `run_text` call.
        text_calls: RefCell<Vec<Call>>,
        /// The `-et` file of each nuclei scan call (None without `-et`), read while it exists.
        nuclei_excludes: RefCell<Vec<Option<Vec<String>>>>,
        /// Whether a pass writes its `-tlog` trace log at all (default true).
        write_trace: bool,
        /// Trace lines the template pass writes (default: one success per listed URL).
        trace_lines: Option<Vec<String>>,
        /// Trace lines the `-dast` pass writes (default: one success per listed URL).
        dast_trace_lines: Option<Vec<String>>,
        /// The `-tlog` path of each nuclei scan call.
        trace_paths: RefCell<Vec<String>>,
        /// URLs that answer the re-probe after the scan with a specific HTTP status code.
        /// Used to test 502/503/504 handling.
        status_code_after_scan: Vec<(&'static str, u16)>,
    }
    impl Fake {
        fn new() -> Self {
            Fake {
                write_trace: true,
                trace_lines: None,
                dast_trace_lines: None,
                trace_paths: RefCell::new(vec![]),
                listing: benign_listing(),
                text_calls: RefCell::new(vec![]),
                nuclei_excludes: RefCell::new(vec![]),
                calls: RefCell::new(vec![]),
                nuclei_err: None,
                extra_httpx: None,
                nuclei_twice: false,
                dead: vec![],
                down_after_scan: vec![],
                httpx_err_after_scan: false,
                slow_after_scan: vec![],
                httpx_version: "projectdiscovery.io\n[INF] Current Version: v1.12.0",
                subs: vec![],
                nuclei_lists: RefCell::new(vec![]),
                template_rows: None,
                dast_rows: None,
                status_code_after_scan: vec![],
            }
        }
        fn count(&self, tool: &str) -> usize {
            self.calls.borrow().iter().filter(|c| c.0 == tool).count()
        }
    }
    impl Runner for Fake {
        fn run_json(
            &self,
            tool: &str,
            args: &[String],
            targets: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            self.calls
                .borrow_mut()
                .push((tool.into(), args.to_vec(), targets.to_vec()));
            Ok(match tool {
                "subfinder" => self.subs.iter().map(|h| json!({ "host": h })).collect(),
                "httpx" => {
                    // A `-u` URL is a liveness probe (echoed back unless dead); a bare
                    // host is recon (only example.com answers).
                    let mut v = vec![];
                    for w in args.windows(2).filter(|w| w[0] == "-u") {
                        let u = w[1].as_str();
                        if u.contains("://") {
                            let scanned = self.count("nuclei") > 0;
                            if scanned && self.httpx_err_after_scan {
                                return Err("httpx exited 1".into());
                            }
                            // This call is already recorded, so the first probe after the scan sees 1.
                            let probes_since_scan = {
                                let calls = self.calls.borrow();
                                let last = calls.iter().rposition(|c| c.0 == "nuclei");
                                last.map_or(0, |i| {
                                    calls[i..].iter().filter(|c| c.0 == "httpx").count()
                                })
                            };
                            let slow = self.slow_after_scan.contains(&u) && probes_since_scan == 1;
                            let gone = (self.down_after_scan.contains(&u) && scanned) || slow;
                            let sc = scanned
                                .then(|| {
                                    self.status_code_after_scan
                                        .iter()
                                        .find(|(url, _)| *url == u)
                                        .map(|(_, code)| *code)
                                })
                                .flatten();
                            if !self.dead.contains(&u) && !gone {
                                if let Some(code) = sc {
                                    v.push(json!({"input": u, "url": u, "status_code": code}));
                                } else {
                                    v.push(json!({"input": u, "url": u}));
                                }
                            }
                        } else if u == "example.com" {
                            v.push(json!({"url":"https://example.com"}));
                            if let Some(x) = self.extra_httpx {
                                v.push(json!({ "url": x }));
                            }
                        }
                    }
                    v
                }
                "katana" => vec![
                    katana_row("https://github.com/x"),
                    katana_row("http://localhost:3000/rest/products"),
                    katana_row("https://example.com/a"),
                ],
                "nuclei" => {
                    if let Some(w) = args.windows(2).find(|w| w[0] == "-l") {
                        let text = std::fs::read_to_string(&w[1]).unwrap();
                        self.nuclei_lists
                            .borrow_mut()
                            .push(text.lines().map(String::from).collect());
                    }
                    let et = args.windows(2).find(|w| w[0] == "-et").map(|w| {
                        let text = std::fs::read_to_string(&w[1]).unwrap();
                        text.lines().map(String::from).collect()
                    });
                    self.nuclei_excludes.borrow_mut().push(et);
                    if let Some(e) = self.nuclei_err {
                        return Err(e.into());
                    }
                    let is_dast = args.iter().any(|a| a == "-dast");
                    if let Some(t) = flag_value(args, "-tlog") {
                        self.trace_paths.borrow_mut().push(t.clone());
                        let custom = if is_dast {
                            &self.dast_trace_lines
                        } else {
                            &self.trace_lines
                        };
                        match (self.write_trace, custom) {
                            (false, _) => {}
                            (true, None) => write_default_trace(args),
                            (true, Some(lines)) => std::fs::write(t, lines.join("\n")).unwrap(),
                        }
                    }
                    match (is_dast, &self.dast_rows, &self.template_rows) {
                        (true, Some(r), _) | (false, _, Some(r)) => return Ok(r.clone()),
                        _ => {}
                    }
                    let row = json!({
                        "template-id":"t1","matched-at":"http://localhost:3000/rest/products",
                        "info":{"name":"n","severity":"high","tags":["xss"]},
                        "curl-command": format!("curl -H 'Authorization: {SECRET}' http://localhost:3000/rest/products")
                    });
                    if self.nuclei_twice {
                        vec![row.clone(), row]
                    } else {
                        vec![row]
                    }
                }
                _ => vec![],
            })
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            self.text_calls
                .borrow_mut()
                .push((t.into(), a.to_vec(), g.to_vec()));
            Ok(match t {
                "httpx" => self.httpx_version.to_string(),
                "nuclei" if a.iter().any(|x| x == "-tl") => self.listing.clone(),
                _ => String::new(),
            })
        }
    }

    fn eng() -> Engagement {
        Engagement {
            name: "t".into(),
            hosts: vec!["example.com".into(), "localhost".into()],
            urls: vec!["http://localhost:3000/".into()],
            cidrs: vec!["127.0.0.0/8".into()],
            ..Default::default()
        }
    }

    fn joined(v: &[String]) -> String {
        v.join(" ")
    }

    #[test]
    fn passes_by_profile() {
        let p = nuclei_passes(DastProfile::Passive);
        assert_eq!(p.len(), 1);
        let s = joined(&p[0]);
        assert!(
            s.contains("dos,brute-force,default-login,intrusive,fuzz"),
            "{s}"
        );
        assert!(!s.contains("sqli"), "{s}");

        let st = nuclei_passes(DastProfile::Standard);
        assert_eq!(st.len(), 1);
        let tags = &st[0][1];
        assert!(tags.contains("sqli") && tags.contains("xss"), "{tags}");

        let a = nuclei_passes(DastProfile::Active);
        assert_eq!(a.len(), 2);
        assert_eq!(a[1][0], "-dast");
        assert!(joined(&a[1]).contains("dos,brute-force,default-login"));
    }

    fn etags_of(pass: &[String]) -> &str {
        let i = pass
            .iter()
            .position(|a| a == "-etags")
            .expect("-etags present");
        &pass[i + 1]
    }

    #[test]
    fn etags_per_profile_standard_excludes_intrusive_active_keeps_it() {
        let p = nuclei_passes(DastProfile::Passive);
        assert_eq!(
            etags_of(&p[0]),
            "dos,brute-force,default-login,intrusive,fuzz"
        );
        // standard is non-destructive: intrusive templates (RCE/file-write chains) never run
        let st = nuclei_passes(DastProfile::Standard);
        assert_eq!(
            etags_of(&st[0]),
            "dos,brute-force,default-login,intrusive,fuzz"
        );
        // active is the opt-in "may change state" profile: intrusive runs there only
        let a = nuclei_passes(DastProfile::Active);
        assert_eq!(etags_of(&a[0]), "dos,brute-force,default-login,fuzz");
        assert_eq!(etags_of(&a[1]), "dos,brute-force,default-login");
    }

    #[test]
    fn nuclei_never_skips_a_host_and_runs_http_templates_only() {
        let c = common_nuclei_args();
        assert!(c.contains(&"-nmhe".to_string()), "{c:?}");
        assert!(
            c.windows(2).any(|w| w[0] == "-pt" && w[1] == "http"),
            "{c:?}"
        );
        assert!(
            !c.iter().any(|a| a == "-mhe" || a == "-max-host-error"),
            "{c:?}"
        );
        // ...and every nuclei scan call of every profile carries them
        for prof in [
            DastProfile::Passive,
            DastProfile::Standard,
            DastProfile::Active,
        ] {
            let f = Fake::new();
            let mut e = eng();
            e.dast.profile = prof;
            run_dast(&e, &f, None, true, 7200).unwrap();
            let calls = f.calls.borrow();
            let scans: Vec<_> = calls.iter().filter(|c| c.0 == "nuclei").collect();
            assert_eq!(scans.len(), nuclei_passes(prof).len(), "{prof:?}");
            for c in scans {
                assert!(c.1.contains(&"-nmhe".to_string()), "{prof:?} {:?}", c.1);
                assert!(
                    c.1.windows(2).any(|w| w[0] == "-pt" && w[1] == "http"),
                    "{prof:?} {:?}",
                    c.1
                );
            }
        }
    }

    #[test]
    fn every_profile_excludes_dos_bruteforce_defaultlogin() {
        for prof in [
            DastProfile::Passive,
            DastProfile::Standard,
            DastProfile::Active,
        ] {
            for pass in nuclei_passes(prof) {
                let i = pass
                    .iter()
                    .position(|a| a == "-etags")
                    .expect("-etags present");
                let etags: Vec<&str> = pass[i + 1].split(',').collect();
                for t in ["dos", "brute-force", "default-login"] {
                    assert!(etags.contains(&t), "{prof:?} pass {pass:?} missing {t}");
                }
            }
        }
    }

    #[test]
    fn nuclei_never_uses_interactsh_update_checks_or_redirects() {
        let c = common_nuclei_args();
        assert!(c.contains(&"-ni".to_string()), "{c:?}");
        assert!(c.contains(&"-duc".to_string()), "{c:?}");
        for prof in [
            DastProfile::Passive,
            DastProfile::Standard,
            DastProfile::Active,
        ] {
            for pass in nuclei_passes(prof) {
                assert!(pass.contains(&"-dr".to_string()), "{prof:?} {pass:?}");
                assert!(!pass.iter().any(|a| a == "-fr" || a == "-fhr"), "{pass:?}");
            }
        }
    }

    #[test]
    fn ssrf_is_limited_because_interactsh_is_disabled() {
        for prof in [DastProfile::Standard, DastProfile::Active] {
            let c = coverage(prof, false, 1, false, &[]);
            assert_eq!(cat(&c, "ssrf")["status"], "limited", "{prof:?}");
            assert!(
                cat(&c, "ssrf")["reason"]
                    .as_str()
                    .unwrap()
                    .contains("blind/out-of-band SSRF not tested (interactsh disabled)"),
                "{prof:?} {}",
                cat(&c, "ssrf")
            );
        }
        // never claimed when nothing ran
        let p = coverage(DastProfile::Passive, false, 1, false, &[]);
        assert_eq!(cat(&p, "ssrf")["status"], "not_tested");
    }

    #[test]
    fn header_args_formats_name_value() {
        let a = ("Authorization".to_string(), "Bearer abc".to_string());
        assert_eq!(
            header_args(Some(&a)),
            vec!["-H", "Authorization: Bearer abc"]
        );
    }

    #[test]
    fn no_auth_no_header_args() {
        assert!(header_args(None).is_empty());
    }

    #[test]
    fn filter_drops_and_counts_out_of_scope() {
        let urls = vec![
            "http://a.test/1".to_string(),
            "http://evil.test/2".into(),
            "http://a.test/3".into(),
        ];
        let (kept, dropped) = filter_in_scope(urls, &|u| u.contains("a.test"));
        assert_eq!(kept, vec!["http://a.test/1", "http://a.test/3"]);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn scrub_removes_value_everywhere_including_json_escaped() {
        let v = r#"tok"en\x"#;
        let rows = vec![json!({
            "curl-command": format!("curl -H 'X: {v}' http://h/"),
            "request": format!("GET / HTTP/1.1\r\nX: {v}"),
            "info": {"name": "n"},
        })];
        let out = scrub_rows(rows, Some(v));
        assert_eq!(out.len(), 1);
        let text = out[0].to_string();
        assert!(!text.contains(v), "{text}");
        let esc = serde_json::to_string(v).unwrap();
        assert!(!text.contains(&esc[1..esc.len() - 1]), "{text}");
        assert!(out[0]["curl-command"].as_str().unwrap().contains("***"));
        assert_eq!(out[0]["info"]["name"], "n");
    }

    #[test]
    fn scrub_keeps_normal_rows_and_is_noop_without_secret() {
        let rows = vec![json!({"template-id":"a"}), json!({"template-id":"b"})];
        assert_eq!(scrub_rows(rows.clone(), None), rows);
        assert_eq!(scrub_rows(rows.clone(), Some("")), rows);
        let out = scrub_rows(rows.clone(), Some("zzz"));
        assert_eq!(out, rows);
    }

    #[test]
    fn scrub_placeholder_keeps_the_finding_without_the_secret() {
        let row = json!({"template-id": format!("t-{SECRET}"), "matched-at":"http://h/",
            "info":{"name": format!("n {SECRET}"), "severity":"high"}});
        let p = scrub_placeholder(&row, Some(SECRET));
        assert!(!p.to_string().contains(SECRET), "{p}");
        assert!(!p.is_null());
        assert_eq!(p["info"]["severity"], "high");
        assert_eq!(p["matched-at"], "http://h/");
    }

    #[test]
    fn scrub_text_replaces_value() {
        assert_eq!(
            scrub_text("bad Bearer s3cr3t here", Some("Bearer s3cr3t")),
            "bad *** here"
        );
        assert_eq!(scrub_text("keep", None), "keep");
    }

    fn cat<'a>(cov: &'a Value, id: &str) -> &'a Value {
        cov["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()
    }

    #[test]
    fn coverage_marks_profile_gaps_rate_limit_and_limited() {
        let rows = vec![
            json!({"info":{"tags":["xss","Other"]}}),
            json!({"info":{"tags":"cors, headers"}}),
            json!({"info":{"tags":["xss"]}}),
        ];
        let p = coverage(DastProfile::Passive, false, 3, false, &rows);
        assert_eq!(cat(&p, "sqli")["status"], "not_tested");
        assert_eq!(cat(&p, "sqli")["reason"], "enable the standard profile");
        assert_eq!(cat(&p, "rate-limit")["status"], "not_tested");
        assert_eq!(cat(&p, "cors")["status"], "tested");
        assert_eq!(cat(&p, "cors")["findings"], 1);
        assert_eq!(cat(&p, "headers")["findings"], 1);
        // not_tested categories never report findings
        assert_eq!(cat(&p, "xss")["findings"], 0);
        assert_eq!(p["authenticated"], false);
        assert_eq!(p["scanned"], 3);

        let s = coverage(DastProfile::Standard, true, 3, false, &rows);
        assert_eq!(cat(&s, "xss")["findings"], 2);
        assert_eq!(cat(&s, "authz")["status"], "limited");
        assert_eq!(cat(&s, "sqli")["status"], "tested");
        assert_eq!(cat(&s, "rate-limit")["status"], "not_tested");
        assert_eq!(s["authenticated"], true);

        let a = coverage(DastProfile::Active, false, 1, false, &[]);
        for id in ["sqli", "xss", "lfi", "redirect"] {
            assert_eq!(
                cat(&a, id)["reason"],
                "templates plus parameter fuzzing",
                "{id}"
            );
        }
        assert_eq!(cat(&a, "ssrf")["status"], "limited");
        assert_eq!(
            cat(&a, "ssrf")["reason"],
            "templates plus parameter fuzzing; blind/out-of-band SSRF not tested (interactsh disabled)"
        );
        assert_eq!(a["profile"], "active");
    }

    fn strs(v: &Value) -> Vec<&str> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect()
    }

    #[test]
    fn coverage_is_per_tag_from_the_profile_passes() {
        let p = coverage(DastProfile::Passive, false, 1, false, &[]);
        // passive runs session and cookie but not csrf
        let s = cat(&p, "session");
        assert_eq!(s["status"], "limited");
        assert_eq!(s["reason"], "csrf runs in the standard profile");
        assert_eq!(strs(&s["tags_run"]), ["session", "cookie"]);
        assert_eq!(strs(&s["tags_missing"]), ["csrf"]);
        // passive runs tech/misconfig/exposure but not cve
        let k = cat(&p, "known-vulns");
        assert_eq!(k["status"], "limited");
        assert_eq!(k["reason"], "cve runs in the standard profile");
        // nothing of sqli runs in passive
        assert_eq!(cat(&p, "sqli")["status"], "not_tested");
        assert_eq!(strs(&cat(&p, "sqli")["tags_run"]), Vec::<&str>::new());
        assert_eq!(strs(&cat(&p, "sqli")["tags_missing"]), ["sqli"]);
        assert_eq!(cat(&p, "cors")["status"], "tested");
        assert_eq!(cat(&p, "cors")["reason"], "");

        let st = coverage(DastProfile::Standard, false, 1, false, &[]);
        assert_eq!(cat(&st, "session")["status"], "tested");
        assert_eq!(
            strs(&cat(&st, "session")["tags_missing"]),
            Vec::<&str>::new()
        );
        assert_eq!(cat(&st, "known-vulns")["status"], "tested");
        assert_eq!(
            cat(&st, "authz")["reason"],
            "few idor templates, mostly CVE- or product-specific; generic IDOR needs app logic and a second user"
        );
        // every category tag is run by some profile (no orphan tags in the table)
        let all = coverage(DastProfile::Active, false, 1, false, &[]);
        for c in all["categories"].as_array().unwrap() {
            assert!(c["tags_missing"].as_array().unwrap().is_empty(), "{c}");
        }
    }

    #[test]
    fn no_hard_coded_template_counts_in_coverage_notes() {
        let c = coverage(DastProfile::Active, false, 1, false, &[]);
        for cat in c["categories"].as_array().unwrap() {
            let r = cat["reason"].as_str().unwrap();
            assert!(!r.chars().any(|ch| ch.is_ascii_digit()), "{r}");
        }
    }

    #[test]
    fn coverage_with_nothing_scanned_claims_nothing_tested() {
        for prof in [
            DastProfile::Passive,
            DastProfile::Standard,
            DastProfile::Active,
        ] {
            let c = coverage(prof, false, 0, false, &[]);
            assert_eq!(c["scanned"], 0);
            for cat in c["categories"].as_array().unwrap() {
                assert_eq!(cat["status"], "not_tested", "{prof:?} {cat}");
                assert_eq!(cat["findings"], 0);
            }
            assert_eq!(cat(&c, "sqli")["reason"], "no in-scope URL was reachable");
            assert_ne!(
                cat(&c, "rate-limit")["reason"],
                "no in-scope URL was reachable"
            );
            // a dry run sent nothing, whatever `scanned` the caller passes
            let d = coverage(prof, false, 5, true, &[]);
            assert_eq!(d["scanned"], 0);
            assert_eq!(cat(&d, "sqli")["reason"], "dry run: nothing was sent");
            assert!(d["categories"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["status"] == "not_tested"));
        }
    }

    #[test]
    fn coverage_markdown_is_a_list_item_per_category_not_a_table() {
        let rows = vec![
            json!({"info":{"tags":["cors"]}}),
            json!({"info":{"tags":["cors"]}}),
        ];
        let cov = coverage(DastProfile::Passive, false, 1, false, &rows);
        let md = coverage_markdown(&cov);
        assert!(md.contains("## DAST coverage"));
        assert!(
            !md.contains('|'),
            "the dashboard renders no GFM tables: {md}"
        );
        assert!(
            md.contains("- **SQL injection** — not tested: enable the standard profile"),
            "{md}"
        );
        assert!(
            md.contains("- **CORS misconfiguration** — tested · 2 findings"),
            "{md}"
        );
        assert!(
            md.contains("- **Security headers** — tested · 0 findings"),
            "{md}"
        );
        assert!(
            md.contains("- **Session management** — limited · 0 findings: csrf runs in the standard profile"),
            "{md}"
        );
        let items = md.lines().filter(|l| l.starts_with("- **")).count();
        assert_eq!(items, cov["categories"].as_array().unwrap().len());
        let one = coverage(DastProfile::Passive, false, 1, false, &rows[..1]);
        assert!(
            coverage_markdown(&one).contains("- **CORS misconfiguration** — tested · 1 finding\n")
        );
    }

    #[test]
    fn run_dast_none_without_scope() {
        let e = Engagement {
            name: "x".into(),
            ..Default::default()
        };
        let f = Fake::new();
        assert!(run_dast(&e, &f, None, true, 7200).unwrap().is_none());
        assert!(f.calls.borrow().is_empty());
    }

    #[test]
    fn run_dast_seeds_every_host_and_url_and_drops_off_scope() {
        let f = Fake::new();
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let out = run_dast(&eng(), &f, Some(&auth), true, 7200)
            .unwrap()
            .unwrap();
        assert_eq!(f.count("subfinder"), 1);
        {
            let calls = f.calls.borrow();
            let sf = calls.iter().find(|c| c.0 == "subfinder").unwrap();
            assert_eq!(sf.2, vec!["example.com".to_string()]);
            for c in calls.iter().filter(|c| c.0 == "nuclei") {
                assert!(!joined(&c.1).contains("github.com"), "{:?}", c.1);
                assert!(c
                    .1
                    .windows(2)
                    .any(|w| w[0] == "-H" && w[1] == format!("Authorization: {SECRET}")));
            }
        }
        assert_eq!(out.summary.seeded, 2);
        // only katana's NEW endpoints count as crawled, never the seeds
        assert_eq!(out.summary.crawled, 3);
        assert_eq!(out.summary.out_of_scope_dropped, 1);
        assert_eq!(out.summary.scanned, 4);
        assert_eq!(out.summary.reachable, 1);
        assert_eq!(out.summary.unreachable, 0);
        assert!(out.summary.unreachable_urls.is_empty());
        assert_eq!(out.summary.auth_header, "Authorization");
        assert!(out.summary.authenticated);
        assert_eq!(out.summary.profile, "standard");
        let lists = f.nuclei_lists.borrow();
        assert!(!lists.is_empty());
        for l in lists.iter() {
            assert!(
                l.contains(&"http://localhost:3000/rest/products".to_string()),
                "{l:?}"
            );
            assert!(!l.iter().any(|u| u.contains("github.com")), "{l:?}");
        }
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].evidence.contains("***"));
        assert!(!out.findings[0].evidence.contains("s3cr3t"));
        assert!(!out.coverage.to_string().contains("s3cr3t"));
        assert!(!serde_json::to_string(&out.summary)
            .unwrap()
            .contains("s3cr3t"));
    }

    #[test]
    fn run_dast_drops_off_scope_seeds_before_crawling_and_counts_them() {
        let mut f = Fake::new();
        f.extra_httpx = Some("https://evil.test/redirect");
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        // the off-scope seed is counted, never handed to katana, and does not abort
        assert_eq!(out.summary.seeded, 2);
        assert_eq!(out.summary.out_of_scope_dropped, 2); // 1 seed + github.com from the crawl
        let calls = f.calls.borrow();
        let katana = calls.iter().find(|c| c.0 == "katana").unwrap();
        assert!(!joined(&katana.1).contains("evil.test"), "{:?}", katana.1);
        assert!(!katana.2.iter().any(|t| t.contains("evil.test")));
    }

    #[test]
    fn run_dast_dedupes_rows_repeated_across_passes() {
        let mut f = Fake::new();
        f.nuclei_twice = true;
        let mut e = eng();
        e.dast.profile = DastProfile::Active; // two passes, each returning the row twice
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(f.count("nuclei"), 2);
        assert_eq!(out.findings.len(), 1);
        // the template-pass copy is kept, so the hit stays verifiable
        assert_eq!(out.findings[0].tool, "nuclei");
    }

    fn hit(matcher: Option<&str>, fuzz: Option<&str>) -> Value {
        let mut r = json!({"template-id":"t1","matched-at":"http://localhost:3000/rest/products",
            "info":{"name":"n","severity":"high","tags":["xss"]}});
        if let Some(m) = matcher {
            r["matcher-name"] = json!(m);
        }
        if let Some(p) = fuzz {
            r["fuzzing_parameter"] = json!(p);
        }
        r
    }

    #[test]
    fn multi_matcher_template_yields_one_finding_per_matcher() {
        let mut f = Fake::new();
        f.template_rows = Some(vec![
            hit(Some("a"), None),
            hit(Some("b"), None),
            hit(Some("a"), None),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.findings.len(), 2);
        assert_ne!(out.findings[0].id, out.findings[1].id);
    }

    #[test]
    fn dast_pass_rows_are_nuclei_dast_and_differ_by_fuzzing_parameter() {
        let mut f = Fake::new();
        f.template_rows = Some(vec![]);
        f.dast_rows = Some(vec![
            hit(None, Some("q")),
            hit(None, Some("id")),
            hit(None, Some("q")),
        ]);
        let mut e = eng();
        e.dast.profile = DastProfile::Active;
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.findings.len(), 2);
        assert!(
            out.findings.iter().all(|x| x.tool == "nuclei-dast"),
            "{:?}",
            out.findings
        );
    }

    #[test]
    fn run_dast_zero_scanned_reports_nothing_tested() {
        // every crawled and seeded URL is off scope
        let e = Engagement {
            name: "x".into(),
            hosts: vec!["example.com".into()],
            ..Default::default()
        };
        struct Off;
        impl Runner for Off {
            fn run_json(
                &self,
                tool: &str,
                _a: &[String],
                _t: &[String],
            ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
                Ok(match tool {
                    "httpx" => vec![json!({"url":"https://evil.test/"})],
                    _ => vec![],
                })
            }
            fn run_text(
                &self,
                _t: &str,
                _a: &[String],
                _g: &[String],
            ) -> Result<String, Box<dyn std::error::Error>> {
                Ok("projectdiscovery.io".into())
            }
        }
        let out = run_dast(&e, &Off, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.scanned, 0);
        assert_eq!(out.summary.out_of_scope_dropped, 1);
        assert!(out.coverage["categories"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["status"] == "not_tested"));
        assert_eq!(
            cat(&out.coverage, "sqli")["reason"],
            "no in-scope URL was reachable"
        );
    }

    #[test]
    fn run_dast_error_text_is_scrubbed() {
        let mut f = Fake::new();
        f.nuclei_err = Some("nuclei exited: header Bearer s3cr3t rejected");
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let e = run_dast(&eng(), &f, Some(&auth), true, 7200)
            .err()
            .expect("error");
        let t = e.to_string();
        assert!(t.contains("***"), "{t}");
        assert!(!t.contains("s3cr3t"), "{t}");
    }

    #[test]
    fn run_dast_probes_declared_urls_and_never_crawls_dead_ones() {
        let mut f = Fake::new();
        f.dead = vec!["http://localhost:3000/"];
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let out = run_dast(&eng(), &f, Some(&auth), true, 7200)
            .unwrap()
            .unwrap();
        assert_eq!(out.summary.reachable, 0);
        assert_eq!(out.summary.unreachable, 1);
        assert_eq!(out.summary.unreachable_urls, vec!["http://localhost:3000/"]);
        assert_eq!(out.summary.seeded, 1); // only https://example.com from recon
        let calls = f.calls.borrow();
        // the probe sends no auth header and only the declared URL
        let probe = calls
            .iter()
            .find(|c| c.0 == "httpx" && c.1.iter().any(|a| a.contains("://")))
            .expect("declared URLs are probed");
        assert!(
            !probe.1.iter().any(|a| a == "-H" || a.contains(SECRET)),
            "{:?}",
            probe.1
        );
        assert_eq!(probe.2, vec!["localhost".to_string()]);
        let katana = calls.iter().find(|c| c.0 == "katana").unwrap();
        assert!(
            !katana.1.contains(&"http://localhost:3000/".to_string()),
            "{:?}",
            katana.1
        );
    }

    #[test]
    fn run_dast_drops_and_counts_invalid_subfinder_names_without_aborting() {
        let mut f = Fake::new();
        f.subs = vec!["_dmarc.example.com", "www.example.com"];
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_dropped, 2); // _dmarc + github.com from the crawl
        let calls = f.calls.borrow();
        let recon = calls
            .iter()
            .find(|c| c.0 == "httpx" && c.2.contains(&"example.com".to_string()))
            .unwrap();
        assert!(
            recon.2.contains(&"www.example.com".to_string()),
            "{:?}",
            recon.2
        );
        assert!(
            !recon.1.iter().any(|a| a.contains("_dmarc")),
            "{:?}",
            recon.1
        );
    }

    #[test]
    fn run_dast_checks_httpx_identity_with_urls_only() {
        let mut f = Fake::new();
        f.httpx_version = "Usage: httpx [OPTIONS] URL";
        let e = Engagement {
            name: "x".into(),
            urls: vec!["http://127.0.0.1:3000/".into()],
            ..Default::default()
        };
        let err = run_dast(&e, &f, None, true, 7200)
            .err()
            .expect("python httpx refused");
        assert!(
            err.to_string().contains("not ProjectDiscovery httpx"),
            "{err}"
        );
        assert_eq!(f.count("httpx"), 0, "nothing probed with the wrong httpx");
    }

    #[test]
    fn dry_run_claims_nothing_was_scanned_and_nothing_unreachable() {
        let mut f = Fake::new();
        f.dead = vec!["http://localhost:3000/"]; // a dry run cannot know
        let out = run_dast(&eng(), &f, None, false, 7200).unwrap().unwrap();
        assert_eq!(out.summary.scanned, 0);
        assert!(out.summary.unreachable_urls.is_empty());
        assert_eq!(out.coverage["scanned"], 0);
        for c in out.coverage["categories"].as_array().unwrap() {
            assert_eq!(c["status"], "not_tested", "{c}");
        }
        assert_eq!(
            cat(&out.coverage, "sqli")["reason"],
            "dry run: nothing was sent"
        );
        // the plan still went through the (scope-checking) runner
        assert!(f.count("httpx") >= 1);
    }

    // ---- H2: templates that send requests off the target are excluded ----

    fn off(t: &str) -> bool {
        sends_off_target(t)
    }

    #[test]
    fn host_annotation_classifier() {
        let raw =
            |h: &str| format!("http:\n  - raw:\n      - |\n        {h}\n        GET / HTTP/1.1\n");
        for h in [
            "@Host: https://checkip.amazonaws.com",
            "@Host: https://x.example:443",
            "@Host: localhost",
            "@Host: 127.0.0.1",
            // a template variable used as a prefix of another name is NOT the target
            "@Host: {{Hostname}}.evil.test",
            "@Host: {{Hostname}}@evil.test",
            "@Host: http://{{BaseURL}}",
            // unknown/lower-case variables stay literal in nuclei
            "@Host: {{host}}",
            "@Host: {{Host}}:{{port}}",
            "@Host:",
            // the annotation name itself is matched case-insensitively (fail closed)
            "@host: https://evil.test",
        ] {
            assert!(off(&raw(h)), "{h} must be off-target");
        }
        for h in [
            "@Host: {{Hostname}}",
            "@Host: {{Host}}",
            "@Host: {{BaseURL}}",
            "@Host: {{RootURL}}/x",
            "@Host: http://{{Host}}:43800",
            "@Host: https://{{Hostname}}",
            "@Host: {{Host}}:9780",
            "@Host: \"{{BaseURL}}\"",
            "@Host: '{{Hostname}}'",
            "@Host:{{Hostname}}",
        ] {
            assert!(!off(&raw(h)), "{h} stays on the target");
        }
        // no @Host at all
        assert!(!off(
            "id: x\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
        ));
        // indentation and CRLF variants
        assert!(off("http:\r\n  - raw:\r\n      - |\r\n\t\t@Host: https://evil.test\r\n        GET / HTTP/1.1\r\n"));
        assert!(!off("http:\r\n  - raw:\r\n      - |\r\n          @Host: {{Hostname}}   \r\n        GET / HTTP/1.1\r\n"));
        // one off-target request among on-target ones excludes the whole template
        assert!(off(&format!(
            "{}{}",
            raw("@Host: {{Hostname}}"),
            raw("@Host: https://evil.test")
        )));
        // a raw request written as one escaped string
        assert!(off(
            "    raw: [\"@Host: https://evil.test\\nGET / HTTP/1.1\\n\\n\"]\n"
        ));
        assert!(!off(
            "    raw: [\"@Host: {{Hostname}}\\nGET / HTTP/1.1\\n\\n\"]\n"
        ));
    }

    #[test]
    fn template_listing_is_parsed_and_resolved_under_the_banner_dir() {
        let dir = fixture_templates();
        let out = listing(
            &dir,
            &["http/benign.yaml", "http\\cves\\off-target.yaml", ""],
        );
        let got = parse_template_listing(&out).unwrap();
        assert_eq!(
            got,
            vec![
                dir.join("http").join("benign.yaml"),
                dir.join("http").join("cves").join("off-target.yaml")
            ]
        );
        for bad in [
            "",
            "\n\n",
            "nuclei v3.11.1\nhttp/a.yaml\n",
            "[ERR] could not read templates\n",
            // banner but nothing listed
            &listing(&dir, &[]),
            // banner naming a directory that cannot be read
            &listing(&dir.join("no-such-dir"), &["http/a.yaml"]),
            // a relative DIR (this one exists relative to the test's working dir)
            &listing(
                Path::new("tests/fixtures/nuclei-templates"),
                &["http/benign.yaml"],
            ),
        ] {
            let e = parse_template_listing(bad).unwrap_err();
            assert_eq!(
                e.to_string(),
                "nuclei template listing not recognised",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_template_dir_containing_for_is_read_whole() {
        let scratch = TempDir::create().unwrap();
        let dir = scratch.path().join("templates for team");
        std::fs::create_dir_all(dir.join("http")).unwrap();
        std::fs::write(dir.join("http").join("a.yaml"), "id: a\n").unwrap();
        let got = parse_template_listing(&listing(&dir, &["http/a.yaml"])).unwrap();
        assert_eq!(got, vec![dir.join("http").join("a.yaml")]);
    }

    #[test]
    fn non_http_protocol_sections_are_classified() {
        // `flow:` alone is not a non-http section (its http requests are audited)
        assert!(!has_non_http_protocol(
            "id: x\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n"
        ));
        for key in [
            "javascript",
            "network",
            "tcp",
            "dns",
            "ssl",
            "code",
            "headless",
            "websocket",
            "whois",
            "file",
        ] {
            let t = format!("id: x\nhttp:\n  - method: GET\n    path: ['{{{{BaseURL}}}}']\n\n{key}:\n  - x: 1\n");
            assert!(has_non_http_protocol(&t), "{key}");
            // CRLF too
            assert!(
                has_non_http_protocol(&t.replace('\n', "\r\n")),
                "{key} crlf"
            );
            // only a top-level (column-0) key counts, never an indented one or a value
            let nested =
                format!("id: x\nhttp:\n  - method: GET\n    {key}: 1\n    path: ['{key}: x']\n");
            assert!(!has_non_http_protocol(&nested), "{key} nested");
        }
        assert!(!has_non_http_protocol(
            "id: x\ninfo:\n  name: n\nhttp:\n  - method: GET\n"
        ));
        assert!(!has_non_http_protocol(
            "id: x\nrequests:\n  - method: GET\n"
        ));
        // a key that only starts with a protocol name is not that protocol
        assert!(!has_non_http_protocol(
            "id: x\ncodename: y\nhttp:\n  - method: GET\n"
        ));
        // a UTF-8 BOM before the first key
        assert!(has_non_http_protocol("\u{feff}javascript: []\nhttp: []\n"));
        assert!(flow_loads_modules("\u{feff}flow: require('x')\nhttp: []\n"));
    }

    #[test]
    fn a_flow_is_excluded_only_when_it_loads_modules() {
        // inline flow, http only
        assert!(!flow_loads_modules(
            "id: x\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n"
        ));
        // no flow at all; `require(` elsewhere (a payload) does not count
        assert!(!flow_loads_modules(
            "id: x\nhttp:\n  - body: 'require(\"child_process\")'\n"
        ));
        assert!(!flow_loads_modules(
            "id: x\nflow: http(1)\n\nhttp:\n  - body: 'require(\"child_process\")'\n"
        ));
        // inline require, any case
        assert!(flow_loads_modules(
            "id: x\nflow: REQUIRE(\"nuclei/net\") && http(1)\nhttp: []\n"
        ));
        // multi-line block scalar: require on a later line, blank lines inside, CRLF
        let block = "id: x\nflow: |\n  http(1);\n\n  let n = Require('nuclei/net');\nhttp:\n  - method: GET\n";
        assert!(flow_loads_modules(block));
        assert!(flow_loads_modules(&block.replace('\n', "\r\n")));
        // the block ends at the next top-level key
        assert!(!flow_loads_modules(
            "flow: |\n  http(1);\nhttp:\n  - x: 'require(1)'\n"
        ));
    }

    #[test]
    fn template_structure_is_read_as_yaml_not_only_as_text() {
        let http = "http:\n  - method: GET\n    path: ['{{BaseURL}}/']\n";
        // ordinary templates stay
        assert!(!excluded_template(&format!("id: x\n{http}")));
        assert!(!excluded_template(&format!(
            "id: x\nflow: http(1) && http(2)\n{http}"
        )));
        assert!(!excluded_template(&format!(
            "id: x\nflow: |\n  http(1);\n  set('a', 1);\n{http}  - body: 'require(\"x\")'\n"
        )));
        // valid YAML spellings a line scanner misses
        for t in [
            format!("id: x\njavascript : []\n{http}"),
            // a merge key: nuclei's YAML merges `javascript` into the root
            format!("id: x\nbase: &a\n  javascript: []\n<<: *a\n{http}"),
            format!("id: x\n\"javascript\": []\n{http}"),
            format!("id: x\n'network': []\n{http}"),
            "  id: x\n  javascript: []\n  http: []\n".to_string(),
            "{id: x, javascript: [], http: []}".to_string(),
            format!("\u{feff}javascript: []\n{http}"),
            format!("\u{feff}flow: require('nuclei/net')\n{http}"),
            // flow: a column-0 comment between key and value, a space before the paren,
            // spaced / quoted keys, any case, a non-string value
            format!("id: x\nflow:\n# note\n  \"require('nuclei/net')\"\n{http}"),
            format!("id: x\nflow: require ('nuclei/net')\n{http}"),
            format!("id: x\nflow : require('nuclei/net')\n{http}"),
            format!("id: x\n\"flow\": REQUIRE('nuclei/net')\n{http}"),
            format!("id: x\nflow: [http(1)]\n{http}"),
            format!("id: x\nflow:\n  a: 1\n{http}"),
        ] {
            assert!(excluded_template(&t), "{t:?}");
        }
        // not parseable, or not a mapping at root: excluded (fail closed)
        for t in ["id: [unclosed\n", "- http: []\n", "just text\n", ""] {
            assert!(excluded_template(t), "{t:?}");
        }
    }

    #[test]
    fn an_unreadable_listed_template_fails_closed() {
        let dir = fixture_templates();
        let mut f = Fake::new();
        f.listing = listing(&dir, &["http/benign.yaml", "http/missing.yaml"]);
        let e = run_dast(&eng(), &f, None, true, 7200)
            .err()
            .expect("must fail closed");
        assert_eq!(
            e.to_string(),
            "nuclei listed a template that cannot be read"
        );
        assert_eq!(f.count("nuclei"), 0, "never scan unfiltered");
    }

    #[test]
    fn off_target_templates_are_excluded_from_every_pass() {
        let dir = fixture_templates();
        let mut f = Fake::new();
        f.listing = listing(
            &dir,
            &[
                "http/benign.yaml",
                "http\\cves\\off-target.yaml",
                "http/on-target.yaml",
                "http/off-localhost.yaml",
                // http first, then a javascript section: typed http, still excluded
                "http/multi-protocol.yaml",
                // a flow of http requests only: kept (its requests are audited)
                "http/flow-http.yaml",
                // a flow that loads a JS module: excluded
                "http/flow-require.yaml",
                // a flow over http and javascript sections: excluded (javascript)
                "http/flow-js.yaml",
            ],
        );
        let mut e = eng();
        e.dast.profile = DastProfile::Active;
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        // listed once, with no targets, before any scan
        let texts = f.text_calls.borrow();
        let tl: Vec<_> = texts
            .iter()
            .filter(|c| c.1.iter().any(|a| a == "-tl"))
            .collect();
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].0, "nuclei");
        assert_eq!(tl[0].1, ["-tl", "-nc", "-duc", "-silent", "-pt", "http"]);
        assert!(tl[0].2.is_empty());
        let want: BTreeSet<PathBuf> = [
            dir.join("http").join("cves").join("off-target.yaml"),
            dir.join("http").join("off-localhost.yaml"),
            dir.join("http").join("multi-protocol.yaml"),
            dir.join("http").join("flow-require.yaml"),
            dir.join("http").join("flow-js.yaml"),
        ]
        .into_iter()
        .collect();
        let excludes = f.nuclei_excludes.borrow();
        assert_eq!(excludes.len(), 2, "both active passes");
        for et in excludes.iter() {
            let got: BTreeSet<PathBuf> = et
                .as_ref()
                .expect("-et on every pass")
                .iter()
                .map(PathBuf::from)
                .collect();
            assert_eq!(got, want);
            assert!(got.iter().all(|p| p.is_absolute()), "{got:?}");
        }
        // the -et file is gone afterwards
        let calls = f.calls.borrow();
        for c in calls.iter().filter(|c| c.0 == "nuclei") {
            let p = c.1.windows(2).find(|w| w[0] == "-et").unwrap()[1].clone();
            assert!(!std::path::Path::new(&p).exists(), "{p} left behind");
        }
        assert_eq!(out.summary.templates_excluded, 5);
        assert_eq!(out.coverage["templates_excluded"], 5);
        let md = coverage_markdown(&out.coverage);
        assert!(
            md.contains(
                "5 templates excluded: they may send requests Ascent cannot scope-check \
                 (an @Host naming another host, a non-http section, or a flow that loads modules)"
            ),
            "{md}"
        );
    }

    #[test]
    fn no_off_target_template_means_no_exclusion_note() {
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.templates_excluded, 0);
        assert_eq!(out.coverage["templates_excluded"], 0);
        assert!(!coverage_markdown(&out.coverage).contains("excluded"));
    }

    #[test]
    fn unrecognised_template_listing_fails_closed_before_any_scan() {
        for bad in ["", "nuclei v3.11.1\n", "Usage: nuclei [flags]\n"] {
            let mut f = Fake::new();
            f.listing = bad.into();
            let e = run_dast(&eng(), &f, None, true, 7200)
                .err()
                .expect("must fail closed");
            assert_eq!(
                e.to_string(),
                "nuclei template listing not recognised",
                "{bad:?}"
            );
            assert_eq!(f.count("nuclei"), 0, "never scan unfiltered");
        }
    }

    /// Manual check against the installed nuclei. It only LISTS templates (no target,
    /// no network). Run with ProjectDiscovery's bin dir first on PATH:
    /// `cargo test --bin ascent real_nuclei_listing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_nuclei_listing_excludes_exactly_the_off_target_templates() {
        let r = crate::runner::ToolRunner::new(ScopeGuard::new(&Engagement::default()), false);
        let off = off_target_templates(&r).unwrap();
        // Why each one is excluded (a template can match several reasons).
        let (mut host, mut section, mut flow, mut yaml_only) = (0, 0, 0, Vec::new());
        for p in &off {
            let t = std::fs::read_to_string(p).unwrap_or_default();
            if sends_off_target(&t) {
                host += 1;
            } else if has_non_http_protocol(&t) {
                section += 1;
            } else if flow_loads_modules(&t) {
                flow += 1;
            } else {
                assert!(yaml_structure_excluded(&t), "{}", p.display());
                yaml_only.push(p);
            }
        }
        eprintln!(
            "{} excluded templates: {host} @Host off-target, {section} with a non-http section, \
             {flow} with a flow that loads modules, {} only by the YAML structure check",
            off.len(),
            yaml_only.len()
        );
        for p in &yaml_only {
            let t = std::fs::read_to_string(p).unwrap_or_default();
            let why = match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(
                t.strip_prefix('\u{feff}').unwrap_or(&t),
            ) {
                Err(e) => format!("does not parse: {e}"),
                Ok(v) if !v.is_mapping() => "root is not a mapping".into(),
                Ok(_) => "protocol key or flow".into(),
            };
            eprintln!("  yaml: {} ({why})", p.display());
        }
        let tl: Vec<String> = ["-tl", "-nc", "-duc", "-silent", "-pt", "http"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let before = parse_template_listing(&r.run_text("nuclei", &tl, &[]).unwrap()).unwrap();
        let dir = TempDir::create().unwrap();
        let et = dir.path().join("exclude-templates.txt");
        write_new_lines(
            &et,
            &off.iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut args = tl.clone();
        args.extend(["-et".to_string(), et.to_string_lossy().into_owned()]);
        let after = parse_template_listing(&r.run_text("nuclei", &args, &[]).unwrap()).unwrap();
        eprintln!("listed {} -> {} with -et", before.len(), after.len());
        assert!(off.iter().all(|p| before.contains(p)));
        assert!(
            off.iter().all(|p| !after.contains(p)),
            "nuclei did not honour -et"
        );
        assert_eq!(before.len() - after.len(), off.len());
    }

    #[test]
    fn dry_run_lists_no_templates() {
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, false, 7200).unwrap().unwrap();
        assert!(!f
            .text_calls
            .borrow()
            .iter()
            .any(|c| c.1.iter().any(|a| a == "-tl")));
        assert!(!f
            .calls
            .borrow()
            .iter()
            .any(|c| c.1.iter().any(|a| a == "-et")));
        assert_eq!(out.summary.templates_excluded, 0);
    }

    // ---- H3: every request nuclei sent is audited against the scope ----

    #[test]
    fn address_host_strips_port_and_brackets() {
        assert_eq!(
            address_host("checkip.amazonaws.com:3000"),
            "checkip.amazonaws.com"
        );
        assert_eq!(address_host("127.0.0.1:3000"), "127.0.0.1");
        assert_eq!(address_host("[::1]:3000"), "::1");
        assert_eq!(address_host("[::1]"), "::1");
        // nuclei logs Hostname() + ":" + port, so an IPv6 address comes UNBRACKETED
        assert_eq!(address_host("::1:3000"), "::1");
        assert_eq!(address_host("2001:db8::5:443"), "2001:db8::5");
        assert_eq!(address_host("example.com"), "example.com");
        assert_eq!(address_host("Example.COM:443"), "example.com");
        assert_eq!(address_host(" Example.COM:443 "), "example.com");
        assert_eq!(address_host(""), "");
    }

    #[test]
    fn an_unbracketed_ipv6_trace_address_is_checked_by_its_host() {
        let mut e = eng();
        e.cidrs.push("::1/128".into());
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line("::1:3000", "none"),
        ]);
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        assert!(
            out.summary.out_of_scope_requests.is_empty(),
            "{:?}",
            out.summary.out_of_scope_requests
        );
        // ...and the port is never read as part of the address: ::1:3000 is not ::0.1.48.0
        let mut e = eng();
        e.cidrs.push("::1:3000/128".into());
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line("::1:3000", "none"),
        ]);
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_requests, vec!["::1"]);
    }

    #[test]
    fn a_request_line_without_an_address_is_never_skipped() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            json!({"template": "http/x.yaml", "type": "http", "input": "", "error": "none"})
                .to_string(),
            json!({"type": "http", "address": 3000}).to_string(),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_requests, vec!["(no address)"]);
        assert_eq!(out.summary.off_scope_request_count, 2);
        assert_eq!(out.summary.requests_sent, 3);
    }

    #[test]
    fn every_live_pass_writes_a_trace_log_that_is_audited_then_deleted() {
        let f = Fake::new();
        let mut e = eng();
        e.dast.profile = DastProfile::Active;
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        let paths = f.trace_paths.borrow();
        assert_eq!(paths.len(), 2, "one trace log per pass");
        assert_ne!(paths[0], paths[1]);
        for p in paths.iter() {
            assert!(!std::path::Path::new(p).exists(), "{p} left behind");
        }
        // 4 in-scope URLs per pass, all answered
        assert_eq!(out.summary.requests_sent, 8);
        assert_eq!(out.summary.request_errors, 0);
        assert!(out.summary.out_of_scope_requests.is_empty());
        assert_eq!(out.summary.off_scope_request_count, 0);
        assert!(out.summary.failing_hosts.is_empty());
        let md = coverage_markdown(&out.coverage);
        assert!(
            md.contains("nuclei sent 8 requests; 0 failed (timeouts/connection errors) — those checks produced no result"),
            "{md}"
        );
    }

    #[test]
    fn requests_to_hosts_outside_scope_are_collected() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line("checkip.amazonaws.com:443", "none"),
            trace_line("checkip.amazonaws.com:3000", "no address found for host"),
            trace_line("::1:80", "none"),
            "not json".into(),
            "{\"truncated\":".into(),
            trace_line("127.0.0.1:3000", "context deadline exceeded"),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        let s = &out.summary;
        assert_eq!(
            s.out_of_scope_requests,
            vec!["::1", "checkip.amazonaws.com"]
        );
        assert_eq!(s.off_scope_request_count, 3);
        // malformed lines are skipped, not counted
        assert_eq!(s.requests_sent, 5);
        assert_eq!(s.request_errors, 2);
        assert_eq!(
            out.coverage["out_of_scope_requests"],
            json!(["::1", "checkip.amazonaws.com"])
        );
        let md = coverage_markdown(&out.coverage);
        assert!(
            md.contains(
                "nuclei sent 3 requests to hosts outside the scope: ::1, checkip.amazonaws.com"
            ),
            "{md}"
        );
    }

    #[test]
    fn a_request_with_neither_address_nor_input_host_is_never_assumed_in_scope() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line("", "none"),
            trace_line("", "dial failed"),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_requests, vec!["(no address)"]);
        // fail closed: with no host anywhere, a failed request counts too
        assert_eq!(out.summary.off_scope_request_count, 2);
    }

    #[test]
    fn an_empty_address_falls_back_to_the_input_host() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            // a real nuclei v3.11.1 line from a live run (raw/unsafe template)
            r#"{"template":"http/cves/2021/CVE-2021-34429.yaml","type":"http","input":"http://127.0.0.1:3000/%u002e/WEB-INF/web.xml","address":"","error":"none"}"#.to_string(),
            // no address key at all, input names the host
            json!({"template": "t", "type": "http", "input": "http://localhost:3000/x"}).to_string(),
            trace_line_with_input("", "http://evil.test/x", "none"),
            trace_line_with_input("", "", "none"),
            // userinfo never hides the real host
            trace_line_with_input("", "http://127.0.0.1@userinfo.evil.test/", "none"),
            // an address, when present, wins over the input
            trace_line_with_input("127.0.0.1:3000", "http://ignored.evil.test/", "none"),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(
            out.summary.out_of_scope_requests,
            vec!["(no address)", "evil.test", "userinfo.evil.test"]
        );
        assert_eq!(out.summary.off_scope_request_count, 3);
        assert_eq!(out.summary.requests_sent, 6);
    }

    #[test]
    fn input_host_parses_leniently() {
        assert_eq!(
            input_host("http://127.0.0.1:3000/%u002e/WEB-INF/web.xml"),
            "127.0.0.1"
        );
        assert_eq!(input_host("http://127.0.0.1@evil.test/"), "evil.test");
        assert_eq!(input_host("https://Example.COM/a?b#c"), "example.com");
        assert_eq!(input_host("http://[::1]:3000/x"), "::1");
        // not a valid URL: scheme stripped, authority up to / ? #, userinfo dropped
        assert_eq!(input_host("http://user@evil.test:8080/x y"), "evil.test");
        assert_eq!(input_host("evil.test:443/x"), "evil.test");
        assert_eq!(input_host("[::1]:3000?q"), "::1");
        assert_eq!(input_host(""), "");
        assert_eq!(input_host("http://"), "");
        assert_eq!(input_host("http:///"), "");
    }

    #[test]
    fn input_host_refuses_parser_differential_authorities() {
        // WHATWG ends the authority at '\', Go (nuclei) reads `127.0.0.1\` as userinfo
        // and dials evil.test: the raw authority decides, and an ambiguous one has no host.
        for probe in [
            "http://127.0.0.1\\@evil.test/",
            "http://127.0.0.1:3000\\@evil.test/x",
            "http://127.0.0.1%2f@evil.test/",
            "http://127.0.0.1%40evil.test/",
            "http://a b@evil.test/",
            "http://127.0.0.1\t@evil.test/",
            "127.0.0.1\\@evil.test/",
            // an invalid host or port is never guessed at
            "http://exa_mple.test/",
            "http://evil.test:99999/",
        ] {
            assert_eq!(input_host(probe), "", "{probe:?}");
        }
    }

    #[test]
    fn a_parser_differential_input_is_never_in_scope() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line_with_input("", "http://127.0.0.1\\@evil.test/", "none"),
            trace_line_with_input("", "http://127.0.0.1:3000\\@evil.test/x", "none"),
        ]);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_requests, vec!["(no address)"]);
        assert_eq!(out.summary.off_scope_request_count, 2);
    }

    #[test]
    fn the_off_scope_list_is_capped_at_ten_names() {
        let mut f = Fake::new();
        f.trace_lines = Some(
            (0..12)
                .map(|i| trace_line(&format!("h{i:02}.evil.test:80"), "none"))
                .collect(),
        );
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        let l = &out.summary.out_of_scope_requests;
        assert_eq!(l.len(), 11, "{l:?}");
        assert_eq!(l[0], "h00.evil.test");
        assert_eq!(l[9], "h09.evil.test");
        assert_eq!(l[10], "…and 2 more");
        assert_eq!(out.summary.off_scope_request_count, 12);
    }

    #[test]
    fn a_host_where_most_requests_failed_is_reported() {
        let mut f = Fake::new();
        let mut lines: Vec<String> = Vec::new();
        // localhost: 30 requests, 15 failed (50%) -> reported
        lines.extend((0..15).map(|_| trace_line("localhost:3000", "none")));
        lines.extend((0..15).map(|_| trace_line("localhost:3000", "context deadline exceeded")));
        // example.com: 19 requests, all failed -> too few to judge
        lines.extend((0..19).map(|_| trace_line("example.com:443", "connection refused")));
        // 127.0.0.1: 40 requests, 19 failed (<50%) -> fine
        lines.extend((0..21).map(|_| trace_line("127.0.0.1:3000", "none")));
        lines.extend((0..19).map(|_| trace_line("127.0.0.1:3000", "i/o timeout")));
        f.trace_lines = Some(lines);
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(
            out.summary.failing_hosts,
            vec![FailingHost {
                host: "localhost".into(),
                failed: 15,
                sent: 30
            }]
        );
        assert_eq!(out.summary.requests_sent, 89);
        assert_eq!(out.summary.request_errors, 53);
    }

    #[test]
    fn a_seed_that_stops_answering_during_the_scan_is_reported() {
        let mut f = Fake::new();
        f.down_after_scan = vec!["http://localhost:3000/"];
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let out = run_dast(&eng(), &f, Some(&auth), true, 7200)
            .unwrap()
            .unwrap();
        assert!(out.summary.unreachable_urls.is_empty());
        assert_eq!(
            out.summary.stopped_answering,
            vec!["http://localhost:3000/"]
        );
        assert_eq!(
            out.coverage["stopped_answering"],
            json!(["http://localhost:3000/"])
        );
        let md = coverage_markdown(&out.coverage);
        assert!(md.contains("stopped answering during the scan: http://localhost:3000/ — the checks after that point produced no result; the run is INCOMPLETE"), "{md}");
        // re-probed after the last nuclei pass, with every live seed and no auth header
        let calls = f.calls.borrow();
        let last_nuclei = calls.iter().rposition(|c| c.0 == "nuclei").unwrap();
        let reprobe = last_nuclei
            + calls[last_nuclei..]
                .iter()
                .position(|c| c.0 == "httpx" && c.1.iter().any(|a| a.contains("://")))
                .expect("re-probe runs after the scan");
        let args = &calls[reprobe].1;
        assert!(
            !args.iter().any(|a| a == "-H" || a.contains(SECRET)),
            "{args:?}"
        );
        for u in ["http://localhost:3000/", "https://example.com"] {
            assert!(args.contains(&u.to_string()), "{u} re-probed: {args:?}");
        }
    }

    #[test]
    fn seeds_still_answering_after_the_scan_are_not_reported() {
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert!(out.summary.stopped_answering.is_empty());
    }

    #[test]
    fn a_seed_that_misses_one_probe_is_retried_once() {
        let mut f = Fake::new();
        f.slow_after_scan = vec!["http://localhost:3000/"];
        f.down_after_scan = vec!["https://example.com"];
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.stopped_answering, vec!["https://example.com"]);
        let calls = f.calls.borrow();
        let retry = calls.iter().rev().find(|c| c.0 == "httpx").unwrap();
        // only the URLs that missed the first re-probe are retried
        assert!(
            retry.1.contains(&"http://localhost:3000/".to_string()),
            "{:?}",
            retry.1
        );
        assert!(
            retry.1.contains(&"https://example.com".to_string()),
            "{:?}",
            retry.1
        );
        assert_eq!(
            retry.1.iter().filter(|a| *a == "-u").count(),
            2,
            "{:?}",
            retry.1
        );
    }

    #[test]
    fn a_failed_re_probe_keeps_the_findings_and_reports_every_seed() {
        let mut f = Fake::new();
        f.httpx_err_after_scan = true;
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert!(!out.findings.is_empty(), "the scan's findings are kept");
        assert_eq!(
            out.summary.stopped_answering,
            vec!["http://localhost:3000/", "https://example.com"]
        );
    }

    #[test]
    fn a_dry_run_never_re_probes() {
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, false, 7200).unwrap().unwrap();
        assert!(out.summary.stopped_answering.is_empty());
        let calls = f.calls.borrow();
        let probes = calls
            .iter()
            .filter(|c| c.0 == "httpx" && c.1.iter().any(|a| a.contains("://")))
            .count();
        assert_eq!(probes, 1, "only the up-front probe of the declared URLs");
    }

    #[test]
    fn a_missing_trace_log_fails_closed() {
        let mut f = Fake::new();
        f.write_trace = false;
        let e = run_dast(&eng(), &f, None, true, 7200)
            .err()
            .expect("missing trace log");
        assert_eq!(e.to_string(), "nuclei trace log missing");
        let p = f.trace_paths.borrow()[0].clone();
        assert!(
            !std::path::Path::new(&p).parent().unwrap().exists(),
            "scratch dir left behind"
        );
    }

    #[test]
    fn a_trace_log_with_nothing_parseable_is_missing() {
        for lines in [
            vec![],
            vec!["garbage".to_string()],
            vec!["{\"no_address\":1}".to_string()],
        ] {
            let mut f = Fake::new();
            f.trace_lines = Some(lines.clone());
            let e = run_dast(&eng(), &f, None, true, 7200)
                .err()
                .expect("empty trace log");
            assert_eq!(e.to_string(), "nuclei trace log missing", "{lines:?}");
        }
    }

    #[test]
    fn an_empty_trace_log_of_the_fuzzing_pass_is_not_an_error() {
        // `-dast` templates only fire on URLs with parameters: zero requests is normal.
        let mut f = Fake::new();
        f.dast_trace_lines = Some(vec![]);
        let mut e = eng();
        e.dast.profile = DastProfile::Active;
        let out = run_dast(&e, &f, None, true, 7200).unwrap().unwrap();
        assert_eq!(out.summary.requests_sent, 4);
        // ...but a missing one still is
        let mut f = Fake::new();
        f.write_trace = false;
        assert!(run_dast(&e, &f, None, true, 7200).is_err());
    }

    #[test]
    fn trace_derived_text_is_scrubbed() {
        let mut f = Fake::new();
        f.trace_lines = Some(vec![
            trace_line("localhost:3000", "none"),
            trace_line(&format!("{SECRET}.evil.test:80"), "none"),
        ]);
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let out = run_dast(&eng(), &f, Some(&auth), true, 7200)
            .unwrap()
            .unwrap();
        let s = serde_json::to_string(&out.summary).unwrap();
        assert!(!s.contains("s3cr3t"), "{s}");
        assert!(!out.coverage.to_string().contains("s3cr3t"));
        assert_eq!(out.summary.off_scope_request_count, 1);
    }

    #[test]
    fn dry_run_writes_and_audits_no_trace_log() {
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, false, 7200).unwrap().unwrap();
        assert!(f.trace_paths.borrow().is_empty());
        assert_eq!(out.summary.requests_sent, 0);
        assert!(!coverage_markdown(&out.coverage).contains("nuclei sent"));
    }

    #[test]
    fn an_old_summary_without_the_audit_fields_still_parses() {
        let s: DastSummary =
            serde_json::from_str(r#"{"profile":"standard","scanned":3,"unreachable_urls":[]}"#)
                .unwrap();
        assert_eq!(s.scanned, 3);
        assert_eq!(
            (
                s.requests_sent,
                s.request_errors,
                s.off_scope_request_count,
                s.templates_excluded
            ),
            (0, 0, 0, 0)
        );
        assert!(s.out_of_scope_requests.is_empty() && s.failing_hosts.is_empty());
        assert!(s.stopped_answering.is_empty());
    }

    // ── detect_crash_recover unit tests ──────────────────────────────────────

    fn write_trace_file(lines: &[String]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ascent_crash_recover_{}_{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    #[test]
    fn detect_crash_recover_flags_20_consecutive_connection_errors_then_success() {
        // 20 "connection refused" errors for 127.0.0.1:8080, then one success.
        let mut lines: Vec<String> = (0..20)
            .map(|_| trace_line("127.0.0.1:8080", "connection refused"))
            .collect();
        lines.push(trace_line("127.0.0.1:8080", "none"));
        let path = write_trace_file(&lines);
        let recovered = detect_crash_recover(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            recovered,
            vec!["127.0.0.1".to_string()],
            "20-error streak + success must flag the host"
        );
    }

    #[test]
    fn detect_crash_recover_does_not_flag_19_error_streak_then_success() {
        // Exactly 19 errors — one short of the threshold — followed by a success.
        let mut lines: Vec<String> = (0..19)
            .map(|_| trace_line("127.0.0.1:8080", "connection refused"))
            .collect();
        lines.push(trace_line("127.0.0.1:8080", "none"));
        let path = write_trace_file(&lines);
        let recovered = detect_crash_recover(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            recovered.is_empty(),
            "19-error streak must NOT be flagged; got {recovered:?}"
        );
    }

    #[test]
    fn detect_crash_recover_does_not_flag_20_error_streak_without_success() {
        // 20 connection errors but the host never recovers (stopped_answering case).
        let lines: Vec<String> = (0..20)
            .map(|_| trace_line("127.0.0.1:8080", "connection refused"))
            .collect();
        let path = write_trace_file(&lines);
        let recovered = detect_crash_recover(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            recovered.is_empty(),
            "20-error streak without success must NOT be flagged; got {recovered:?}"
        );
    }

    // ── re-probe 502/503/504 tests ────────────────────────────────────────────

    #[test]
    fn reprobe_502_treated_as_not_answering() {
        let mut f = Fake::new();
        f.status_code_after_scan = vec![("http://localhost:3000/", 502)];
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert!(
            out.summary.stopped_answering.contains(&"http://localhost:3000/".to_string()),
            "502 re-probe must land in stopped_answering; got {:?}",
            out.summary.stopped_answering
        );
    }

    #[test]
    fn reprobe_503_treated_as_not_answering() {
        let mut f = Fake::new();
        f.status_code_after_scan = vec![("http://localhost:3000/", 503)];
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert!(
            out.summary.stopped_answering.contains(&"http://localhost:3000/".to_string()),
            "503 re-probe must land in stopped_answering; got {:?}",
            out.summary.stopped_answering
        );
    }

    #[test]
    fn reprobe_200_not_in_stopped_answering() {
        // Regression guard: a 200 response must NOT appear in stopped_answering.
        let f = Fake::new();
        let out = run_dast(&eng(), &f, None, true, 7200).unwrap().unwrap();
        assert!(
            out.summary.stopped_answering.is_empty(),
            "200 re-probe must NOT appear in stopped_answering; got {:?}",
            out.summary.stopped_answering
        );
    }
}
