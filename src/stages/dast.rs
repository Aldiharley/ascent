//! The DAST track: seed the surface from the whole declared scope, crawl, drop anything
//! out of scope (counted, never scanned, never fatal), run the profile's nuclei passes
//! with the optional auth header, scrub the auth value from every raw result, and report
//! what was and was not tested. dos / brute-force / default-login are never run.
use super::enumerate::enumerate_surface;
use super::recon::{ensure_httpx_identity, is_subfinder_candidate, probe_urls, recon};
use super::scan::scan_rows;
use crate::models::Finding;
use crate::normalise::normalise_nuclei;
use crate::runner::Runner;
use crate::scope::{DastProfile, Engagement, ScopeGuard};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const ALWAYS_EXCLUDED: &str = "dos,brute-force,default-login";
const PASSIVE_TAGS: &str = "tech,misconfig,exposure,headers,cors,cookie,session";
const STANDARD_TAGS: &str = "tech,misconfig,exposure,headers,cors,cookie,session,cve,sqli,xss,auth-bypass,jwt,idor,csrf,redirect,ssrf,lfi";

/// `-ni`: no interactsh, so no out-of-band traffic to a third-party OAST server.
/// `-duc`: no update check (no egress beyond the target).
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
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The profile's nuclei passes. Every pass of every profile excludes
/// [`ALWAYS_EXCLUDED`] and disables redirects (`-dr`, so a redirect can never take
/// nuclei off scope); nothing here comes from engagement config.
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
        DastProfile::Standard => vec![pass(STANDARD_TAGS, "fuzz")],
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
    tags: &'static [&'static str],
    min: Option<DastProfile>,   // None = never tested
    note: Option<&'static str>, // limited-coverage note
}

const CATEGORIES: &[Category] = &[
    Category {
        id: "sqli",
        name: "SQL injection",
        tags: &["sqli"],
        min: Some(DastProfile::Standard),
        note: None,
    },
    Category {
        id: "xss",
        name: "Cross-site scripting",
        tags: &["xss"],
        min: Some(DastProfile::Standard),
        note: None,
    },
    Category {
        id: "auth-bypass",
        name: "Authentication bypass",
        tags: &["auth-bypass", "jwt"],
        min: Some(DastProfile::Standard),
        note: None,
    },
    Category {
        id: "authz",
        name: "Authorization flaws (IDOR)",
        tags: &["idor"],
        min: Some(DastProfile::Standard),
        note: Some("12 generic templates; most IDOR needs app-specific logic and a second user"),
    },
    Category {
        id: "cors",
        name: "CORS misconfiguration",
        tags: &["cors"],
        min: Some(DastProfile::Passive),
        note: None,
    },
    Category {
        id: "headers",
        name: "Security headers",
        tags: &["headers"],
        min: Some(DastProfile::Passive),
        note: None,
    },
    Category {
        id: "session",
        name: "Session management",
        tags: &["session", "cookie", "csrf"],
        min: Some(DastProfile::Passive),
        note: None,
    },
    Category {
        id: "ssrf",
        name: "Server-side request forgery",
        tags: &["ssrf"],
        min: Some(DastProfile::Standard),
        note: Some("blind/out-of-band SSRF not tested (interactsh disabled)"),
    },
    Category {
        id: "lfi",
        name: "Path traversal / file inclusion",
        tags: &["lfi"],
        min: Some(DastProfile::Standard),
        note: None,
    },
    Category {
        id: "redirect",
        name: "Open redirect",
        tags: &["redirect"],
        min: Some(DastProfile::Standard),
        note: None,
    },
    Category {
        id: "known-vulns",
        name: "Known CVEs, exposures, misconfiguration",
        tags: &["cve", "exposure", "misconfig", "tech"],
        min: Some(DastProfile::Passive),
        note: None,
    },
    Category {
        id: "rate-limit",
        name: "API rate limiting",
        tags: &[],
        min: None,
        note: None,
    },
];

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
    let cats: Vec<Value> = CATEGORIES
        .iter()
        .map(|c| {
            let (status, reason) = match c.min {
                None => (
                    "not_tested",
                    "needs load generation; Ascent never floods a target".to_string(),
                ),
                Some(_) if scanned == 0 => ("not_tested", zero_reason.to_string()),
                Some(min) if min > profile => {
                    ("not_tested", format!("enable the {} profile", min.as_str()))
                }
                Some(_) => match c.note {
                    Some(n) => ("limited", n.to_string()),
                    None if profile == DastProfile::Active
                        && matches!(c.id, "sqli" | "xss" | "lfi" | "ssrf" | "redirect") =>
                    {
                        ("tested", "templates plus parameter fuzzing".to_string())
                    }
                    None => ("tested", String::new()),
                },
            };
            let findings = if status == "not_tested" {
                0
            } else {
                tagsets
                    .iter()
                    .filter(|ts| ts.iter().any(|t| c.tags.contains(&t.as_str())))
                    .count()
            };
            json!({"id": c.id, "name": c.name, "tags": c.tags, "status": status, "reason": reason, "findings": findings})
        })
        .collect();
    json!({"profile": profile.as_str(), "authenticated": authenticated, "scanned": scanned, "categories": cats})
}

/// Active runs two passes that can return the same hit; keep the first of each
/// (`template-id`, `matched-at`) pair.
fn dedupe_rows(rows: Vec<Value>) -> Vec<Value> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    rows.into_iter()
        .filter(|r| {
            let key = (
                r["template-id"].as_str().unwrap_or("").to_string(),
                r["matched-at"].as_str().unwrap_or("").to_string(),
            );
            seen.insert(key)
        })
        .collect()
}

pub fn coverage_markdown(cov: &Value) -> String {
    let mut out = format!(
        "\n## DAST coverage\n\nProfile: `{}` · authenticated: {}\n\n| Category | Status | Findings | Notes |\n|---|---|---|---|\n",
        cov["profile"].as_str().unwrap_or(""),
        if cov["authenticated"] == true { "yes" } else { "no" },
    );
    for c in cov["categories"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            c["name"].as_str().unwrap_or(""),
            c["status"].as_str().unwrap_or("").replace('_', " "),
            c["findings"],
            c["reason"].as_str().unwrap_or(""),
        ));
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
pub fn run_dast(
    eng: &Engagement,
    runner: &dyn Runner,
    auth: Option<&(String, String)>,
    live: bool,
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
    let (declared, url_dropped) = filter_in_scope(declared.into_iter().collect(), &|u| guard.in_scope(u));
    // Only declared URLs that answer are crawled (hosts are probed by recon).
    let (live_urls, dead_urls) = probe_urls(runner, &declared).map_err(scrubbed)?;
    let (live_urls, dead_urls) = if live { (live_urls, dead_urls) } else { (declared, vec![]) };
    let mut seed: BTreeSet<String> = live_urls.iter().cloned().collect();
    let mut recon_dropped = 0;
    for h in &eng.hosts {
        let (urls, d) = recon(runner, h, is_subfinder_candidate(h), &|n| guard.in_scope(n)).map_err(scrubbed)?;
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
    if !surface.is_empty() {
        for pass in nuclei_passes(eng.dast.profile) {
            let mut args = common_nuclei_args();
            args.extend(pass);
            args.extend(headers.iter().cloned());
            rows.extend(scan_rows(runner, &surface, &args).map_err(scrubbed)?);
        }
    }
    let rows = scrub_rows(dedupe_rows(rows), secret);
    let coverage = coverage(eng.dast.profile, auth.is_some(), surface.len(), !live, &rows);
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
        },
        coverage,
    }))
}

#[cfg(test)]
mod tests {
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
        /// `httpx -version` output.
        httpx_version: &'static str,
        /// Names subfinder reports for example.com.
        subs: Vec<&'static str>,
        /// The URL list file (`-l`) of each nuclei call, read while it exists.
        nuclei_lists: RefCell<Vec<Vec<String>>>,
    }
    impl Fake {
        fn new() -> Self {
            Fake {
                calls: RefCell::new(vec![]),
                nuclei_err: None,
                extra_httpx: None,
                nuclei_twice: false,
                dead: vec![],
                httpx_version: "projectdiscovery.io\n[INF] Current Version: v1.12.0",
                subs: vec![],
                nuclei_lists: RefCell::new(vec![]),
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
                            if !self.dead.contains(&u) {
                                v.push(json!({"input": u, "url": u}));
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
                    if let Some(e) = self.nuclei_err {
                        return Err(e.into());
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
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(if t == "httpx" { self.httpx_version.to_string() } else { String::new() })
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
        let etags = &st[0][3];
        for t in ["dos", "brute-force", "default-login", "fuzz"] {
            assert!(etags.contains(t), "{etags}");
        }
        assert!(!etags.contains("intrusive"), "{etags}");

        let a = nuclei_passes(DastProfile::Active);
        assert_eq!(a.len(), 2);
        assert_eq!(a[1][0], "-dast");
        assert!(joined(&a[1]).contains("dos,brute-force,default-login"));
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
        for prof in [DastProfile::Passive, DastProfile::Standard, DastProfile::Active] {
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
        assert_eq!(a["profile"], "active");
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
            assert!(d["categories"].as_array().unwrap().iter().all(|c| c["status"] == "not_tested"));
        }
    }

    #[test]
    fn coverage_markdown_has_a_row_per_category() {
        let cov = coverage(DastProfile::Passive, false, 1, false, &[]);
        let md = coverage_markdown(&cov);
        assert!(md.contains("## DAST coverage"));
        assert!(
            md.contains("| SQL injection | not tested | 0 | enable the standard profile |"),
            "{md}"
        );
        let rows = md
            .lines()
            .filter(|l| l.starts_with("| ") && !l.starts_with("| Category"))
            .count();
        assert_eq!(rows, cov["categories"].as_array().unwrap().len());
    }

    #[test]
    fn run_dast_none_without_scope() {
        let e = Engagement {
            name: "x".into(),
            ..Default::default()
        };
        let f = Fake::new();
        assert!(run_dast(&e, &f, None, true).unwrap().is_none());
        assert!(f.calls.borrow().is_empty());
    }

    #[test]
    fn run_dast_seeds_every_host_and_url_and_drops_off_scope() {
        let f = Fake::new();
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let out = run_dast(&eng(), &f, Some(&auth), true).unwrap().unwrap();
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
            assert!(l.contains(&"http://localhost:3000/rest/products".to_string()), "{l:?}");
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
        let out = run_dast(&eng(), &f, None, true).unwrap().unwrap();
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
        let out = run_dast(&e, &f, None, true).unwrap().unwrap();
        assert_eq!(f.count("nuclei"), 2);
        assert_eq!(out.findings.len(), 1);
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
        let out = run_dast(&e, &Off, None, true).unwrap().unwrap();
        assert_eq!(out.summary.scanned, 0);
        assert_eq!(out.summary.out_of_scope_dropped, 1);
        assert!(out.coverage["categories"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["status"] == "not_tested"));
        assert_eq!(cat(&out.coverage, "sqli")["reason"], "no in-scope URL was reachable");
    }

    #[test]
    fn run_dast_error_text_is_scrubbed() {
        let mut f = Fake::new();
        f.nuclei_err = Some("nuclei exited: header Bearer s3cr3t rejected");
        let auth = ("Authorization".to_string(), SECRET.to_string());
        let e = run_dast(&eng(), &f, Some(&auth), true)
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
        let out = run_dast(&eng(), &f, Some(&auth), true).unwrap().unwrap();
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
        assert!(!probe.1.iter().any(|a| a == "-H" || a.contains(SECRET)), "{:?}", probe.1);
        assert_eq!(probe.2, vec!["localhost".to_string()]);
        let katana = calls.iter().find(|c| c.0 == "katana").unwrap();
        assert!(!katana.1.contains(&"http://localhost:3000/".to_string()), "{:?}", katana.1);
    }

    #[test]
    fn run_dast_drops_and_counts_invalid_subfinder_names_without_aborting() {
        let mut f = Fake::new();
        f.subs = vec!["_dmarc.example.com", "www.example.com"];
        let out = run_dast(&eng(), &f, None, true).unwrap().unwrap();
        assert_eq!(out.summary.out_of_scope_dropped, 2); // _dmarc + github.com from the crawl
        let calls = f.calls.borrow();
        let recon = calls
            .iter()
            .find(|c| c.0 == "httpx" && c.2.contains(&"example.com".to_string()))
            .unwrap();
        assert!(recon.2.contains(&"www.example.com".to_string()), "{:?}", recon.2);
        assert!(!recon.1.iter().any(|a| a.contains("_dmarc")), "{:?}", recon.1);
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
        let err = run_dast(&e, &f, None, true).err().expect("python httpx refused");
        assert!(err.to_string().contains("not ProjectDiscovery httpx"), "{err}");
        assert_eq!(f.count("httpx"), 0, "nothing probed with the wrong httpx");
    }

    #[test]
    fn dry_run_claims_nothing_was_scanned_and_nothing_unreachable() {
        let mut f = Fake::new();
        f.dead = vec!["http://localhost:3000/"]; // a dry run cannot know
        let out = run_dast(&eng(), &f, None, false).unwrap().unwrap();
        assert_eq!(out.summary.scanned, 0);
        assert!(out.summary.unreachable_urls.is_empty());
        assert_eq!(out.coverage["scanned"], 0);
        for c in out.coverage["categories"].as_array().unwrap() {
            assert_eq!(c["status"], "not_tested", "{c}");
        }
        assert_eq!(cat(&out.coverage, "sqli")["reason"], "dry run: nothing was sent");
        // the plan still went through the (scope-checking) runner
        assert!(f.count("httpx") >= 1);
    }
}
