# DAST Surface Fixes and Veracode-Parity Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Ascent's DAST track scan the whole declared scope without aborting on off-scope links, add selectable scan profiles and authenticated scanning that cover the DAST checklist (SQLi, XSS, auth bypass, authz, CORS, headers, session; rate limiting honestly marked untested), and report a coverage matrix.

**Architecture:** The engagement file gains a validated `dast` block (`profile`, optional `auth` header name + env var name). A new `src/stages/dast.rs` orchestrates the DAST track: seed the surface from every host (recon) and every URL, crawl, drop out-of-scope URLs with a count, run one or two nuclei passes chosen by profile with the auth header, scrub the auth value from every raw result, and compute a coverage matrix. `run_pipeline` calls it, records a `dast` summary in `run.json`, writes `out/dast-coverage.json`, and appends a coverage section to `report.md`. The dashboard's New Scan form can set the profile and auth names.

**Tech Stack:** Rust 2021 (serde, serde_yaml_ng, serde_json, url, clap 4, crux), nuclei v3.11 / katana / httpx / subfinder (external), axum + React 18 + vitest.

Spec: `docs/superpowers/specs/2026-10-31-dast-coverage-design.md`.

## Global Constraints

- No new crate or npm dependencies.
- Exit codes unchanged: 0 pass/conditional (or no policy), 1 policy fail, 2 config/usage error, 3 incomplete/stage failure, 4 audit-chain integrity failure. Every new configuration error (unknown engagement key, bad `dast` values, auth env var missing/empty/CR-LF) is a `ConfigError` → exit 2, raised **before** any output is written.
- Every engagement struct uses `#[serde(deny_unknown_fields)]`.
- `dos`, `brute-force` and `default-login` nuclei tags are excluded in every profile. Ascent never floods a target and never guesses credentials.
- The auth header **value** must never appear in any file Ascent writes (`run.json`, `queue.json`, `report.md`, `gate.json`, SARIF, `dast-coverage.json`, `audit.jsonl`) nor in Ascent's error messages; only the header **name** may be recorded.
- Every network target still goes through the scope-checking runner; out-of-scope URLs are dropped (counted), never scanned, and never abort the run.
- Dashboard stays read-mostly: New Scan only writes an engagement file. Fluid Glass styling via existing `glass.css` tokens; no new image assets. Target-derived strings render as React text only.
- Tests pass on Windows and Linux; `cargo build`/`cargo test` warning-free at the end of every task.
- Commit messages end with a `Co-Authored-By:` trailer naming the model that wrote the commit.

## File Structure

| File | Responsibility |
|---|---|
| `src/scope.rs` (modify) | `DastProfile`, `DastAuth`, `DastConfig`, `validate_dast`, `resolve_auth`; `Engagement.dast`; `deny_unknown_fields` |
| `src/stages/recon.rs` (modify) | `recon(runner, host, use_subfinder)` + `is_subfinder_candidate` — subfinder optional |
| `src/stages/enumerate.rs` (modify) | `enumerate_surface(runner, urls, extra)` — passes auth header to katana |
| `src/stages/scan.rs` (modify) | `scan_rows(runner, urls, args) -> Vec<Value>` (raw rows) |
| `src/stages/dast.rs` (create) | profiles → args, coverage registry/matrix/markdown, scope filter, scrub, `run_dast` |
| `src/stages/mod.rs` (modify) | `pub mod dast;` |
| `src/runstatus.rs` (modify) | `RunStatus.dast: Option<DastSummary>`, derive `Default` |
| `src/pipeline.rs` (modify) | resolve auth (ConfigError), call `run_dast`, write coverage + report section + run.json summary |
| `src/main.rs` (modify) | print DAST summary line |
| `tests/cli_gate.rs` (modify) | exit 2 for unknown engagement key / missing auth env |
| `src/dashboard/newscan.rs`, `src/bin/dashboard.rs` (modify) | New Scan accepts + validates profile/auth names, writes `dast` block |
| `frontend/src/api.ts`, `frontend/src/screens/NewScan.tsx` (+test), `frontend/src/styles/glass.css` (modify) | profile select + auth name fields |
| `README.md`, `samples/engagement.juiceshop.yaml`, `docs/followups-pipeline-core.md`, `docs/followups-policy-gate.md` (modify) | docs |

---

### Task 1: Engagement `dast` schema, strict parsing, auth resolution

**Files:** Modify `src/scope.rs` (+ every `Engagement { … }` struct literal in `src/**` and `tests/**`, 15 sites — add `..Default::default()` or `dast: Default::default()`).

**Interfaces — Produces (`crate::scope`):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DastProfile { Passive, #[default] Standard, Active }
impl DastProfile { pub fn as_str(&self) -> &'static str }   // "passive" | "standard" | "active"

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DastAuth { pub header: String, pub value_env: String }

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DastConfig {
    #[serde(default)] pub profile: DastProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub auth: Option<DastAuth>,
}
pub fn validate_dast(d: &DastConfig) -> Result<(), String>;
/// `Ok(None)` without auth; `Ok(Some((header_name, value)))` with it.
pub fn resolve_auth(d: &DastConfig, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<(String, String)>, String>;
```
`Engagement` derives `Default` and `Serialize` too, gets `#[serde(deny_unknown_fields)]` and `#[serde(default)] pub dast: DastConfig`. `load_engagement` calls `validate_dast` and returns its error.

- [ ] **Step 1: Failing tests** (add to `scope.rs` tests):

```rust
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
            format!("{BASE}host: [x.com]\n"),                         // typo for hosts
            format!("{BASE}dast:\n  profle: active\n"),
            format!("{BASE}dast:\n  auth:\n    header: X\n    value: secret\n"),
            format!("{BASE}dast:\n  profile: aggressive\n"),
        ] {
            assert!(serde_yaml_ng::from_str::<Engagement>(&bad).is_err(), "accepted {bad:?}");
        }
    }
    #[test]
    fn validate_dast_checks_names() {
        let mk = |h: &str, v: &str| DastConfig { profile: DastProfile::Standard,
            auth: Some(DastAuth { header: h.into(), value_env: v.into() }) };
        assert!(validate_dast(&mk("Authorization", "ASCENT_DAST_AUTH")).is_ok());
        assert!(validate_dast(&mk("Cookie", "_X1")).is_ok());
        for (h, v) in [("", "A"), ("Bad Header", "A"), ("X:Y", "A"), ("X", ""), ("X", "lower"), ("X", "1A"), ("X", "A-B")] {
            assert!(validate_dast(&mk(h, v)).is_err(), "accepted header={h:?} env={v:?}");
        }
    }
    #[test]
    fn resolve_auth_reads_env_and_fails_closed() {
        let d = DastConfig { profile: DastProfile::Standard,
            auth: Some(DastAuth { header: "Authorization".into(), value_env: "TOK".into() }) };
        let got = resolve_auth(&d, &|k| (k == "TOK").then(|| "Bearer abc".to_string())).unwrap();
        assert_eq!(got, Some(("Authorization".into(), "Bearer abc".into())));
        assert!(resolve_auth(&d, &|_| None).unwrap_err().contains("TOK"));
        assert!(resolve_auth(&d, &|_| Some(String::new())).is_err());
        assert!(resolve_auth(&d, &|_| Some("a\r\nX-Injected: 1".into())).is_err());
        assert_eq!(resolve_auth(&DastConfig::default(), &|_| None).unwrap(), None);
    }
    #[test]
    fn resolve_auth_error_never_contains_the_value() {
        let d = DastConfig { profile: DastProfile::Standard,
            auth: Some(DastAuth { header: "Authorization".into(), value_env: "TOK".into() }) };
        let e = resolve_auth(&d, &|_| Some("Bearer s3cr3t\nmore".into())).unwrap_err();
        assert!(!e.contains("s3cr3t"), "{e}");
    }
```

  Also make `load_engagement` reject an engagement whose `dast.auth` fails `validate_dast` (test: write a temp yaml with `header: "Bad Header"` → `load_engagement` is `Err`).

- [ ] **Step 2: Run** `cargo test --bin ascent scope::` → FAIL.

- [ ] **Step 3: Implement** in `src/scope.rs` (add `use serde::Serialize;`):

```rust
impl DastProfile {
    pub fn as_str(&self) -> &'static str {
        match self { DastProfile::Passive => "passive", DastProfile::Standard => "standard", DastProfile::Active => "active" }
    }
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

pub fn validate_dast(d: &DastConfig) -> Result<(), String> {
    if let Some(a) = &d.auth {
        if !is_header_token(&a.header) {
            return Err(format!("dast.auth.header {:?} is not a valid HTTP header name", a.header));
        }
        if !is_env_name(&a.value_env) {
            return Err(format!("dast.auth.value_env {:?} must look like ASCENT_DAST_AUTH ([A-Z_][A-Z0-9_]*)", a.value_env));
        }
    }
    Ok(())
}

pub fn resolve_auth(d: &DastConfig, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<(String, String)>, String> {
    let Some(a) = &d.auth else { return Ok(None) };
    validate_dast(d)?;
    let v = env(&a.value_env).unwrap_or_default();
    if v.trim().is_empty() {
        return Err(format!(
            "dast.auth is configured but environment variable {} is unset or empty; refusing to scan unauthenticated",
            a.value_env
        ));
    }
    if v.contains('\r') || v.contains('\n') {
        return Err(format!("environment variable {} contains a line break; refusing to send it as a header", a.value_env));
    }
    Ok(Some((a.header.clone(), v)))
}
```

  `load_engagement`: after parsing, `validate_dast(&e.dast)?` (map the `String` into the boxed error). Update every `Engagement { … }` literal in `src/` and `tests/` to compile (prefer `..Default::default()`).

- [ ] **Step 4: CLI test** — add to `tests/cli_gate.rs`: an engagement file with an unknown key (`host: [x.com]`) given to `ascent run --dry-run` exits **2** (no `queue.json` written).

- [ ] **Step 5:** `cargo test` all green, `cargo build` 0 warnings (the dashboard binary includes `scope.rs` under `#[allow(dead_code)]`).

- [ ] **Step 6: Commit** — `feat(scope): engagement dast profile/auth schema, strict unknown-key rejection`.

---

### Task 2: Surface — every host and URL, auth-aware crawl, raw nuclei rows

**Files:** Modify `src/stages/recon.rs`, `src/stages/enumerate.rs`, `src/stages/scan.rs` (and their tests).

**Interfaces — Produces:**
- `pub fn recon(runner: &dyn Runner, host: &str, use_subfinder: bool) -> Result<Vec<String>, Box<dyn Error>>` — when `use_subfinder` is false, subfinder is not called; `host` itself is still probed by httpx.
- `pub fn is_subfinder_candidate(host: &str) -> bool` (in `recon.rs`): true only for a DNS name containing a `.` that is not an IP literal (`host.parse::<std::net::IpAddr>()` fails) — so `localhost`, `10.0.0.5`, `::1` → false; `example.com` → true.
- `pub fn enumerate_surface(runner: &dyn Runner, urls: &[String], extra: &[String]) -> Result<Vec<String>, Box<dyn Error>>` — `extra` (e.g. `["-H", "Authorization: …"]`) is appended to katana's args.
- `pub fn scan_rows(runner: &dyn Runner, urls: &[String], args: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn Error>>` — same scope-safe `-u`/targets derivation as today's `scan`, but the caller supplies every nuclei flag (`args`) and gets the **raw** JSON rows. Remove the old `scan` (its default tags move to Task 3's profiles); port its tests to `scan_rows` (pass `["-silent","-jsonl"]` as args and normalise in the test where needed).

- [ ] **Step 1: Failing tests** — `recon.rs`: `is_subfinder_candidate` table (`example.com` true; `localhost`, `127.0.0.1`, `::1`, `10.0.0.5`, `` false); `recon(…, false)` never calls `subfinder` (fake runner records calls) and still probes the host with httpx. `enumerate.rs`: `extra` args reach katana (assert the recorded args end with `["-H", "X-Test: 1"]`). `scan.rs`: `scan_rows` passes caller args verbatim before the `-u` list, returns raw rows, keeps the host-less-URL safety (port the two existing safety tests).
- [ ] **Step 2: Run** `cargo test --bin ascent stages::` → FAIL.
- [ ] **Step 3: Implement** the signatures above. Keep the existing scope-safety comments. `pipeline.rs` must keep compiling: temporarily adapt its calls (`recon(runner, &root, true)`, `enumerate_surface(runner, &urls, &[])`, and replace `scan(runner, &urls)?` with `normalise_nuclei(&scan_rows(runner, &urls, &["-silent".into(), "-jsonl".into(), "-tags".into(), "cve,exposure,misconfig,tech".into()])?)`). Task 4 replaces this wiring.
- [ ] **Step 4:** `cargo test` green, 0 warnings.
- [ ] **Step 5: Commit** — `refactor(dast): optional subfinder, auth-aware katana, raw nuclei rows`.

---

### Task 3: `src/stages/dast.rs` — profiles, scope filter, scrub, coverage, orchestration

**Files:** Create `src/stages/dast.rs`; modify `src/stages/mod.rs` (`pub mod dast;`).

**Interfaces:**
- Consumes: Task 1 `DastProfile`, `DastConfig`; Task 2 `recon`, `is_subfinder_candidate`, `enumerate_surface`, `scan_rows`; `crate::normalise::normalise_nuclei`; `crate::scope::{Engagement, ScopeGuard}`.
- Produces:
```rust
pub const ALWAYS_EXCLUDED: &str = "dos,brute-force,default-login";
pub fn nuclei_passes(profile: DastProfile) -> Vec<Vec<String>>;   // profile-specific flags per pass
pub fn common_nuclei_args() -> Vec<String>;                       // -silent -jsonl -rate-limit 50 -concurrency 10 -timeout 10
pub fn header_args(auth: Option<&(String, String)>) -> Vec<String>; // ["-H", "Name: value"] or []
pub fn filter_in_scope(urls: Vec<String>, in_scope: &dyn Fn(&str) -> bool) -> (Vec<String>, usize);
pub fn scrub_rows(rows: Vec<Value>, secret: Option<&str>) -> Vec<Value>;
pub fn scrub_text(s: &str, secret: Option<&str>) -> String;
pub fn coverage(profile: DastProfile, authenticated: bool, rows: &[Value]) -> Value;
pub fn coverage_markdown(cov: &Value) -> String;
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DastSummary { pub profile: String, pub authenticated: bool, pub auth_header: String,
                         pub seeded: usize, pub crawled: usize, pub out_of_scope_dropped: usize, pub scanned: usize }
pub struct DastOutcome { pub findings: Vec<Finding>, pub summary: DastSummary, pub coverage: Value }
/// `Ok(None)` when the engagement has no hosts and no urls (no DAST scope).
pub fn run_dast(eng: &Engagement, runner: &dyn Runner, auth: Option<&(String, String)>, check_httpx: bool)
    -> Result<Option<DastOutcome>, Box<dyn std::error::Error>>;
```

- [ ] **Step 1: Write `dast.rs` with tests first.** Implementation (write it after the failing tests):

```rust
//! The DAST track: seed the surface from the whole declared scope, crawl, drop anything
//! out of scope (counted, never scanned, never fatal), run the profile's nuclei passes
//! with the optional auth header, scrub the auth value from every raw result, and report
//! what was and was not tested. dos / brute-force / default-login are never run.
use super::enumerate::enumerate_surface;
use super::recon::{ensure_httpx_identity, is_subfinder_candidate, recon};
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

pub fn common_nuclei_args() -> Vec<String> {
    ["-silent", "-jsonl", "-rate-limit", "50", "-concurrency", "10", "-timeout", "10"]
        .iter().map(|s| s.to_string()).collect()
}

pub fn nuclei_passes(profile: DastProfile) -> Vec<Vec<String>> {
    let pass = |tags: &str, extra_etags: &str| -> Vec<String> {
        vec!["-tags".into(), tags.into(), "-etags".into(), format!("{ALWAYS_EXCLUDED},{extra_etags}")]
    };
    match profile {
        DastProfile::Passive => vec![pass(PASSIVE_TAGS, "intrusive,fuzz")],
        DastProfile::Standard => vec![pass(STANDARD_TAGS, "fuzz")],
        DastProfile::Active => vec![
            pass(STANDARD_TAGS, "fuzz"),
            vec!["-dast".into(), "-etags".into(), ALWAYS_EXCLUDED.into()],
        ],
    }
}

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

/// Replace the auth value everywhere in each raw nuclei row (curl-command, request, …).
pub fn scrub_rows(rows: Vec<Value>, secret: Option<&str>) -> Vec<Value> {
    let Some(v) = secret.filter(|v| !v.is_empty()) else { return rows };
    rows.into_iter()
        .map(|r| serde_json::from_str(&r.to_string().replace(v, "***")).unwrap_or(Value::Null))
        .filter(|r| !r.is_null())
        .collect()
}
```

  Note on `scrub_rows`: the value is replaced in the JSON *text*; a value containing JSON-escaped characters (e.g. `"` or `\`) appears escaped in the text, so ALSO replace the JSON-escaped form: compute `let esc = serde_json::to_string(v).unwrap(); let esc = &esc[1..esc.len()-1];` and replace both `v` and `esc`. Add a test with a value containing a `"`.

  Coverage registry and matrix:

```rust
struct Category {
    id: &'static str,
    name: &'static str,
    tags: &'static [&'static str],
    min: Option<DastProfile>,          // None = never tested
    note: Option<&'static str>,        // limited-coverage note
}

const CATEGORIES: &[Category] = &[
    Category { id: "sqli", name: "SQL injection", tags: &["sqli"], min: Some(DastProfile::Standard), note: None },
    Category { id: "xss", name: "Cross-site scripting", tags: &["xss"], min: Some(DastProfile::Standard), note: None },
    Category { id: "auth-bypass", name: "Authentication bypass", tags: &["auth-bypass", "jwt"], min: Some(DastProfile::Standard), note: None },
    Category { id: "authz", name: "Authorization flaws (IDOR)", tags: &["idor"], min: Some(DastProfile::Standard),
               note: Some("12 generic templates; most IDOR needs app-specific logic and a second user") },
    Category { id: "cors", name: "CORS misconfiguration", tags: &["cors"], min: Some(DastProfile::Passive), note: None },
    Category { id: "headers", name: "Security headers", tags: &["headers"], min: Some(DastProfile::Passive), note: None },
    Category { id: "session", name: "Session management", tags: &["session", "cookie", "csrf"], min: Some(DastProfile::Passive), note: None },
    Category { id: "ssrf", name: "Server-side request forgery", tags: &["ssrf"], min: Some(DastProfile::Standard), note: None },
    Category { id: "lfi", name: "Path traversal / file inclusion", tags: &["lfi"], min: Some(DastProfile::Standard), note: None },
    Category { id: "redirect", name: "Open redirect", tags: &["redirect"], min: Some(DastProfile::Standard), note: None },
    Category { id: "known-vulns", name: "Known CVEs, exposures, misconfiguration", tags: &["cve", "exposure", "misconfig", "tech"], min: Some(DastProfile::Passive), note: None },
    Category { id: "rate-limit", name: "API rate limiting", tags: &[], min: None, note: None },
];

fn row_tags(r: &Value) -> Vec<String> {
    match &r["info"]["tags"] {
        Value::Array(a) => a.iter().filter_map(|t| t.as_str()).map(|t| t.trim().to_ascii_lowercase()).collect(),
        Value::String(s) => s.split(',').map(|t| t.trim().to_ascii_lowercase()).collect(),
        _ => vec![],
    }
}

pub fn coverage(profile: DastProfile, authenticated: bool, rows: &[Value]) -> Value {
    let tagsets: Vec<Vec<String>> = rows.iter().map(row_tags).collect();
    let cats: Vec<Value> = CATEGORIES.iter().map(|c| {
        let findings = tagsets.iter().filter(|ts| ts.iter().any(|t| c.tags.contains(&t.as_str()))).count();
        let (status, reason) = match c.min {
            None => ("not_tested", "needs load generation; Ascent never floods a target".to_string()),
            Some(min) if min > profile => ("not_tested", format!("enable the {} profile", min.as_str())),
            Some(_) => match c.note {
                Some(n) => ("limited", n.to_string()),
                None if profile == DastProfile::Active && matches!(c.id, "sqli" | "xss") =>
                    ("tested", "templates plus parameter fuzzing".to_string()),
                None => ("tested", String::new()),
            },
        };
        json!({"id": c.id, "name": c.name, "tags": c.tags, "status": status, "reason": reason, "findings": findings})
    }).collect();
    json!({"profile": profile.as_str(), "authenticated": authenticated, "categories": cats})
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
```

  Orchestration:

```rust
pub fn run_dast(eng: &Engagement, runner: &dyn Runner, auth: Option<&(String, String)>, check_httpx: bool)
    -> Result<Option<DastOutcome>, Box<dyn std::error::Error>> {
    if eng.hosts.is_empty() && eng.urls.is_empty() {
        return Ok(None);
    }
    let secret = auth.map(|(_, v)| v.as_str());
    let scrubbed = |e: Box<dyn std::error::Error>| -> Box<dyn std::error::Error> { scrub_text(&e.to_string(), secret).into() };
    if check_httpx && !eng.hosts.is_empty() {
        ensure_httpx_identity(runner)?;
    }
    let mut seed: BTreeSet<String> = eng.urls.iter().cloned().collect();
    for h in &eng.hosts {
        for u in recon(runner, h, is_subfinder_candidate(h)).map_err(scrubbed)? {
            seed.insert(u);
        }
    }
    let seed: Vec<String> = seed.into_iter().collect();
    let headers = header_args(auth);
    let crawled = enumerate_surface(runner, &seed, &headers).map_err(scrubbed)?;
    let guard = ScopeGuard::new(eng);
    let crawled_n = crawled.len();
    let (surface, dropped) = filter_in_scope(crawled, &|u| guard.in_scope(u));
    let mut rows = Vec::new();
    if !surface.is_empty() {
        for pass in nuclei_passes(eng.dast.profile) {
            let mut args = common_nuclei_args();
            args.extend(pass);
            args.extend(headers.iter().cloned());
            rows.extend(scan_rows(runner, &surface, &args).map_err(scrubbed)?);
        }
    }
    let rows = scrub_rows(rows, secret);
    let coverage = coverage(eng.dast.profile, auth.is_some(), &rows);
    Ok(Some(DastOutcome {
        findings: normalise_nuclei(&rows),
        summary: DastSummary {
            profile: eng.dast.profile.as_str().into(),
            authenticated: auth.is_some(),
            auth_header: auth.map(|(n, _)| n.clone()).unwrap_or_default(),
            seeded: seed.len(),
            crawled: crawled_n,
            out_of_scope_dropped: dropped,
            scanned: surface.len(),
        },
        coverage,
    }))
}
```

  Tests (all with a recording fake runner; keep them in `dast.rs`):
  - `passes_by_profile`: passive has `-etags` containing `dos,brute-force,default-login,intrusive,fuzz` and no `sqli`; standard tags contain `sqli` and `xss`, etags contain `dos`,`brute-force`,`default-login`,`fuzz` but NOT `intrusive`; active = 2 passes, second starts with `-dast` and still excludes `dos,brute-force,default-login`.
  - `every_profile_excludes_dos_bruteforce_defaultlogin` (loop over all passes of all profiles).
  - `header_args_formats_name_value`, `no_auth_no_header_args`.
  - `filter_drops_and_counts_out_of_scope` with a closure.
  - `scrub_removes_value_everywhere_including_json_escaped` (rows with `curl-command` containing the value; value with a `"` inside).
  - `coverage_marks_profile_gaps_rate_limit_and_limited`: passive → sqli `not_tested` with reason `enable the standard profile`; rate-limit always `not_tested`; authz `limited` in standard; findings counted from `info.tags` (array and comma-string forms).
  - `coverage_markdown_has_a_row_per_category`.
  - `run_dast_none_without_scope`.
  - `run_dast_seeds_every_host_and_url_and_drops_off_scope`: engagement `hosts: [example.com, localhost]`, `urls: [http://localhost:3000/]`, `cidrs: [127.0.0.0/8]`; fake: `subfinder` → `[]`, `httpx` → `[{"url":"https://example.com"}]` for example.com and `[]` for localhost, `katana` → endpoints including `https://github.com/x` (off scope) and `http://localhost:3000/rest/products`, `nuclei` → one row with `curl-command` containing the auth value. Assert: subfinder called once (example.com only); summary `seeded`=2 (`https://example.com`, `http://localhost:3000/`), `out_of_scope_dropped`=1, scanned contains the localhost REST URL; no nuclei call targets `github.com`; the returned findings' evidence contains `***` and not the value; `auth_header`=`Authorization`.
  - `run_dast_error_text_is_scrubbed`: fake nuclei returns `Err("nuclei exited: header Bearer s3cr3t rejected")` → error text contains `***`, not `s3cr3t`.

- [ ] **Step 2: Run** `cargo test --bin ascent stages::dast` → FAIL, then implement → PASS. Full `cargo test` green; `run_dast` may be dead code until Task 4 — acceptable mid-plan (no other warnings).
- [ ] **Step 3: Commit** — `feat(dast): profiles, scope filter, auth scrubbing and coverage matrix`.

---

### Task 4: Pipeline wiring, run.json summary, coverage outputs

**Files:** Modify `src/runstatus.rs`, `src/pipeline.rs`, `src/main.rs`, `tests/cli_gate.rs`.

**Interfaces:**
- `RunStatus` derives `Default`; gains `#[serde(default)] pub dast: Option<crate::stages::dast::DastSummary>`. Update all `RunStatus { … }` literals (7 sites) with `..Default::default()` / `dast: None`.
- `Summary` gains `pub dast: Option<DastSummary>`.

- [ ] **Step 1: Failing tests** in `src/pipeline.rs`:
  - `dast_runs_over_every_host_and_url` (fake runner, engagement with 2 hosts + 1 url) → `run.json`'s `dast.seeded` matches and `Summary.urls == dast.scanned`.
  - `dast_writes_coverage_and_report_section` → `out/dast-coverage.json` exists with 12 categories; `report.md` contains `## DAST coverage`.
  - `no_dast_scope_writes_no_coverage` (source-only engagement) → no `dast-coverage.json`, `run.json` `dast` is null.
  - `stale_coverage_is_removed` → a pre-seeded `dast-coverage.json` does not survive a run that errors.
  - `auth_value_never_reaches_any_output`: engagement with `dast.auth {header: Authorization, value_env: <unique var name>}`; set that env var (`std::env::set_var`) to `Bearer tok-<unique>`; fake nuclei returns a row whose `curl-command` contains the value; run the pipeline with a `FakeTri` that copies findings into items; then read EVERY file in the out dir and assert none contains the value.
  - `missing_auth_env_is_a_config_error_and_writes_nothing` → `run_pipeline` returns an error that downcasts to `ConfigError`; `queue.json` not created.
- [ ] **Step 2: Implement** in `run_pipeline`:
  - Add `"dast-coverage.json"` to `STALE_OUTPUTS`.
  - Right after `resolve_source` (before any write): `let auth = if dry_run { None } else { crate::scope::resolve_auth(&eng.dast, &|k| std::env::var(k).ok()).map_err(ConfigError)? };` (dry run never needs the value).
  - Replace the DAST block (root/ensure/recon/enumerate/scan) with: `if !dry_run && (!eng.hosts.is_empty() || !eng.urls.is_empty()) { ensure_nuclei_version(runner)?; }` then `let dast = run_dast(eng, runner, auth.as_ref(), !dry_run)?;` and `let mut findings = dast.as_ref().map(|d| d.findings.clone()).unwrap_or_default();`.
  - After writing `report.md` with `to_markdown`, if `dast` is `Some`, append `coverage_markdown(&d.coverage)` to the report text before writing (build the string first), and write `dast-coverage.json` (pretty, via `write_atomic`).
  - Final `RunStatus` gets `dast: dast.as_ref().map(|d| d.summary.clone())`; `Summary.urls` = `dast.as_ref().map_or(0, |d| d.summary.scanned)`; `Summary.dast` likewise.
- [ ] **Step 3: main.rs** — after the `urls=… findings=…` line, if `s.dast` is `Some(d)`, print `dast: profile={} authenticated={} seeded={} crawled={} out_of_scope_dropped={} scanned={}` and `coverage: <out>/dast-coverage.json`.
- [ ] **Step 4: CLI test** — `run --dry-run` against an engagement with `dast.auth` and the env var unset still exits as before for dry run (0 without policy) — dry run never resolves the secret; and a NON-dry run with `dast.auth` and the env var unset exits **2** before scanning (no `queue.json`). Use an engagement with `urls: [http://127.0.0.1:9/]` so nothing could be reached anyway.
- [ ] **Step 5:** `cargo test` green, `cargo build` 0 warnings.
- [ ] **Step 6: Commit** — `feat(pipeline): whole-scope DAST with profiles, auth and coverage outputs`.

---

### Task 5: Dashboard New Scan — profile and auth names

**Files:** Modify `src/dashboard/newscan.rs`, `src/bin/dashboard.rs`, `frontend/src/api.ts`, `frontend/src/screens/NewScan.tsx`, `frontend/src/screens/NewScan.test.tsx`, `frontend/src/styles/glass.css`.

**Interfaces:**
- `NewScanRequest` gains `#[serde(default)] pub dast_profile: String` (`""` → standard; else `passive|standard|active`), `#[serde(default)] pub auth_header: String`, `#[serde(default)] pub auth_env: String`. Both auth fields empty → no auth; exactly one empty → error.
- `PrepareError` gains `BadDast(String)` → HTTP 422 `{"ok": false, "error": …, "field": "dast"}`.
- The written YAML contains a `dast:` block (always `profile`; `auth` only when set), built from `crate::scope::DastConfig` and validated with `crate::scope::validate_dast`. The generated file must load with `load_engagement` (round-trip test).
- Response JSON gains `"dast": {"profile": …, "auth_header": …}` (header NAME only).
- Frontend `NewScanInput` gains `dast_profile?: "passive"|"standard"|"active"`, `auth_header?: string`, `auth_env?: string`; `CreatedEngagement` gains `dast: {profile: string; auth_header: string}`.

- [ ] **Step 1: Rust tests** (newscan.rs): profile `active` written and round-trips through `serde_yaml_ng::from_str::<crate::scope::Engagement>`; auth header + env written; invalid header name → `BadDast`; only one of header/env set → `BadDast`; unknown profile string → `BadDast`; omitted fields → standard, no auth. Dashboard route test: POST with `dast_profile: "active"` → 200 and `v["dast"]["profile"] == "active"`; bad env name → 422 with `field: "dast"`.
- [ ] **Step 2: Frontend tests** (NewScan.test.tsx): the form has a "DAST profile" select defaulting to Standard; choosing Active and filling "Auth header name" = `Authorization` and "Env var holding its value" = `ASCENT_DAST_AUTH` posts `dast_profile: "active"`, `auth_header`, `auth_env`; the success card shows `Profile: active` and `Auth header: Authorization`; there is NO input that accepts the header value itself.
- [ ] **Step 3: Implement.** UI copy (exact):
  - Select label: `DAST profile`; options `Passive — non-intrusive checks only`, `Standard — known-vulnerability and injection templates (default)`, `Active — adds parameter fuzzing; only for targets you may actively test`.
  - Hint under the auth fields: `For authenticated scanning, name the header and the environment variable that holds its value (for example Authorization and ASCENT_DAST_AUTH). Ascent never stores the value; set the variable in the terminal that runs the scan.`
  - Reuse `.newscan .fld`, `label`, `.hint`, and style the `<select>` like the inputs (add `.newscan select` to the existing input rule in `glass.css`).
- [ ] **Step 4:** `cargo test` (incl. dashboard), `npm run test`, `npm run build` green; 0 warnings.
- [ ] **Step 5: Commit** — `feat(dashboard): New Scan sets DAST profile and auth header names`.

---

### Task 6: Docs and samples

**Files:** Modify `README.md`, `samples/engagement.juiceshop.yaml`, `samples/engagement.example.yaml`, `docs/followups-pipeline-core.md`, `docs/followups-policy-gate.md`.

- [ ] **Step 1:** `samples/engagement.juiceshop.yaml`: remove the outdated comment that hosts make the pipeline ignore `urls` (no longer true); add a commented `dast:` example (profile + auth with `ASCENT_DAST_AUTH`). `samples/engagement.example.yaml`: add `dast:\n  profile: standard` with a comment. Both must still load (`cargo test` has sample-loading tests).
- [ ] **Step 2:** README — add a `## DAST track` section (after `## SAST track`): how the surface is built (every host via recon — subfinder only for real DNS names — plus every URL; out-of-scope crawl results dropped and counted), the three profiles table (tags, always-excluded `dos,brute-force,default-login`, rate limit 50 req/s), authenticated scanning (header name + env var; value never written; argv visible to local users caveat), the coverage matrix (`out/dast-coverage.json`, report section) and a table mapping the Veracode/SecAI DAST checklist to Ascent's coverage (SQLi, XSS, auth bypass, authz — limited, CORS, security headers, session management, rate limiting — not tested by design, "validate exploitability" → human-gated detect-only re-test). Update the Quick start to mention the profile. Keep everything else intact.
- [ ] **Step 3:** `docs/followups-pipeline-core.md`: mark items 1 (urls ignored) and 2 (katana off-site abort) and 4's `deny_unknown_fields` part **Resolved (2026-10-31)**. `docs/followups-policy-gate.md`: add DAST follow-ups — scripted/form login and OAuth, OpenAPI/GraphQL import, headless JS crawl, verification allow-list cannot re-check `-dast` fuzz findings, argv exposure of the auth header.
- [ ] **Step 4:** `cargo test` green (sample tests). Commit — `docs(dast): DAST track, profiles, auth and Veracode coverage mapping`.

---

## Final validation (controller, after all tasks)

1. `cargo build` 0 warnings; `cargo test`; `npm run test`; `npm run build`.
2. Live: start Juice Shop bound to loopback (`docker run -d --rm -p 127.0.0.1:3000:3000 --name ascent-juiceshop bkimminich/juice-shop`), run `ascent run --engagement samples/engagement.juiceshop.yaml --out <scratch>/js-standard --policy samples/ascent-policy.example.yaml` (standard) and an `active` copy; confirm: DAST findings in several categories, `dast-coverage.json` present with honest statuses, `out_of_scope_dropped` > 0 if Juice Shop links off-site and the run does NOT abort, gate evaluates, dashboard Report shows the coverage table. Stop the container afterwards.
