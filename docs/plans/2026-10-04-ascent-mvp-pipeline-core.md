# Ascent MVP (Pipeline Core, Rust CLI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-binary, scope-enforced Rust CLI that runs recon → enumeration → DAST scan against an authorised lab target, normalises the findings, triages them through Crux (invoked as a subprocess), and writes a ranked markdown report plus a verified audit log.

**Architecture:** A Rust (cargo) binary that drives external OSS scanners as subprocesses through one scope-checked `ToolRunner`, normalises each tool's output into a common `Finding` struct, hands the findings to **Crux (the author's Python triage engine) as a subprocess** (writing a findings JSON, running the Crux CLI, reading back a triaged-queue JSON), and renders a report. Orchestration is a small staged pipeline. Stages depend on a `Runner` trait and triage on a `TriageEngine` trait, so everything is unit-testable without spawning real tools. No exploitation, no network LLM, no web service in this plan (those are later plans).

**Tech Stack:** Rust (stable), cargo, `serde`/`serde_json`/`serde_yaml_ng`, `clap` v4 (derive), `ipnet`, `url`. External tools (installed, invoked, never vendored): subfinder, dnsx, httpx, katana, nuclei (>= v3.10.0). Crux is the author's Python project at `M:/Projects/crux`, invoked via `python -m crux`.

## Global Constraints

- License: Apache-2.0 for all Ascent code. External tools and Crux are invoked as subprocesses; nothing copyleft is vendored into the binary.
- Scope is enforced at the execution boundary: every external invocation goes through `ToolRunner`, which refuses any target not in the signed engagement scope. No tool is ever spawned directly.
- nuclei must be >= v3.10.0 (CVE-2026-76802); the pipeline checks the version and refuses an older binary.
- No exploit-capable tool and no network LLM call in this plan. Crux runs in `--mock` (deterministic, offline).
- Secrets/tokens are never passed as command-line arguments; the MVP uses no credentials (unauthenticated lab scan).
- Rust stable; `cargo clippy` clean, `cargo fmt` applied; every task ends green and committed.
- Targets are local lab apps only (OWASP Juice Shop or WebGoat.NET).

---

### Task 1: Cargo scaffold, license, CI

**Files:**
- Create: `Cargo.toml`, `LICENSE`, `README.md`, `src/main.rs`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: a buildable binary crate `ascent`; `cargo test` runs.

- [ ] **Step 1: Write the failing test** (in `src/main.rs`)
```rust
fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

fn main() { println!("ascent {}", version()); }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn has_version() { assert!(!version().is_empty()); }
}
```
- [ ] **Step 2: Write `Cargo.toml` and verify the test fails first (no crate yet)**
```toml
[package]
name = "ascent"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml_ng = "0.10"   # maintained fork of serde_yaml
clap = { version = "4", features = ["derive"] }
ipnet = "2"
url = "2"
```
Run: `cargo test` → it should build and PASS once the crate exists. (If starting from an empty dir, `cargo init` first, then paste the above.) Add `LICENSE` (Apache-2.0 full text) and a `README.md` stating Apache-2.0 and the invoke-don't-vendor rule.
- [ ] **Step 3: Confirm green**
Run: `cargo test && cargo clippy -- -D warnings` → PASS, no warnings.
- [ ] **Step 4: Commit**
```bash
git add Cargo.toml LICENSE README.md src/main.rs .github/workflows/ci.yml
git commit -m "chore: scaffold ascent rust crate (Apache-2.0) with CI"
```

---

### Task 2: Engagement scope model and ScopeGuard

**Files:**
- Create: `src/scope.rs`, `samples/engagement.example.yaml`
- Modify: `src/main.rs` (add `mod scope;`)

**Interfaces:**
- Produces:
  - `struct Engagement { name: String, hosts: Vec<String>, cidrs: Vec<String>, urls: Vec<String>, starts: String, ends: String }` (serde `Deserialize`; time window stored but not enforced in the MVP).
  - `fn load_engagement(path: &str) -> anyhow::Result<Engagement>` (use `std::fs` + `serde_yaml_ng`; return `Result` with a plain error type, no `anyhow` dep needed, use `Box<dyn std::error::Error>`).
  - `struct ScopeGuard` with `fn new(e: &Engagement) -> ScopeGuard`, `fn in_scope(&self, target: &str) -> bool` (hostname, IP, or URL; subdomains of an in-scope host count), `fn assert_in_scope(&self, target: &str) -> Result<(), OutOfScope>`.
  - `struct OutOfScope(pub String)` implementing `std::error::Error + Display`.

- [ ] **Step 1: Write the failing test** (bottom of `src/scope.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn eng() -> Engagement {
        Engagement { name: "t".into(), hosts: vec!["example.com".into()],
            cidrs: vec!["10.0.0.0/24".into()], urls: vec!["https://app.example.com/".into()],
            starts: "2026-01-01T00:00:00Z".into(), ends: "2030-01-01T00:00:00Z".into() }
    }
    #[test] fn host_and_subdomain() {
        let g = ScopeGuard::new(&eng());
        assert!(g.in_scope("example.com"));
        assert!(g.in_scope("api.example.com"));
        assert!(g.in_scope("https://app.example.com/login"));
    }
    #[test] fn cidr() { assert!(ScopeGuard::new(&eng()).in_scope("10.0.0.5")); }
    #[test] fn out_of_scope() {
        let g = ScopeGuard::new(&eng());
        assert!(!g.in_scope("evil.com"));
        assert!(g.assert_in_scope("8.8.8.8").is_err());
    }
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test scope` → FAIL (module/types missing).
- [ ] **Step 3: Implement `src/scope.rs`**
```rust
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct Engagement {
    pub name: String,
    #[serde(default)] pub hosts: Vec<String>,
    #[serde(default)] pub cidrs: Vec<String>,
    #[serde(default)] pub urls: Vec<String>,
    pub starts: String,
    pub ends: String,
}

#[derive(Debug)]
pub struct OutOfScope(pub String);
impl fmt::Display for OutOfScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{} is not in engagement scope", self.0) }
}
impl std::error::Error for OutOfScope {}

pub fn load_engagement(path: &str) -> Result<Engagement, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml_ng::from_str(&text)?)
}

fn host_of(target: &str) -> String {
    if target.contains("://") {
        Url::parse(target).ok().and_then(|u| u.host_str().map(|s| s.to_string())).unwrap_or_default()
    } else {
        target.split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_string()
    }
}

pub struct ScopeGuard { hosts: HashSet<String>, nets: Vec<IpNet> }

impl ScopeGuard {
    pub fn new(e: &Engagement) -> Self {
        let mut hosts: HashSet<String> = e.hosts.iter().cloned().collect();
        for u in &e.urls { let h = host_of(u); if !h.is_empty() { hosts.insert(h); } }
        let nets = e.cidrs.iter().filter_map(|c| c.parse::<IpNet>().ok()).collect();
        ScopeGuard { hosts, nets }
    }
    pub fn in_scope(&self, target: &str) -> bool {
        let host = host_of(target);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.nets.iter().any(|n| n.contains(&ip));
        }
        self.hosts.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
    }
    pub fn assert_in_scope(&self, target: &str) -> Result<(), OutOfScope> {
        if self.in_scope(target) { Ok(()) } else { Err(OutOfScope(target.to_string())) }
    }
}
```
Add `mod scope;` to `src/main.rs`. Write `samples/engagement.example.yaml`.
- [ ] **Step 4: Run tests** → `cargo test` PASS; `cargo clippy` clean.
- [ ] **Step 5: Commit**
```bash
git add src/scope.rs src/main.rs samples/engagement.example.yaml
git commit -m "feat: engagement scope model and ScopeGuard"
```

---

### Task 3: Runner trait + scope-checked ToolRunner

**Files:**
- Create: `src/runner.rs`
- Modify: `src/main.rs` (`mod runner;`)

**Interfaces:**
- Produces:
  - `trait Runner { fn run_json(&self, tool: &str, args: &[String], targets: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>>; fn run_text(&self, tool: &str, args: &[String], targets: &[String]) -> Result<String, Box<dyn std::error::Error>>; }`
  - `pub fn parse_jsonl(stdout: &str) -> Vec<serde_json::Value>` (pure, unit-tested: one JSON value per non-empty line, falling back to a single JSON doc/array).
  - `struct ToolRunner { guard: ScopeGuard, dry_run: bool }` implementing `Runner`: `assert_in_scope` on every target before spawning via `std::process::Command`; `run_json` parses stdout with `parse_jsonl`.

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn jsonl_parses_lines() {
        let v = parse_jsonl("{\"a\":1}\n{\"a\":2}\n");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["a"], 1);
    }
    #[test] fn jsonl_falls_back_to_array() {
        let v = parse_jsonl("[{\"a\":1},{\"a\":2}]");
        assert_eq!(v.len(), 2);
    }
}
```
(Scope-refusal is covered by Task 2's `assert_in_scope`; here we unit-test the pure parser. The spawn path is exercised in the Task 11 smoke run.)
- [ ] **Step 2: Run, verify fail** — `cargo test runner` → FAIL.
- [ ] **Step 3: Implement `src/runner.rs`**
```rust
use crate::scope::ScopeGuard;
use serde_json::Value;
use std::process::Command;

pub trait Runner {
    fn run_json(&self, tool: &str, args: &[String], targets: &[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>>;
    fn run_text(&self, tool: &str, args: &[String], targets: &[String]) -> Result<String, Box<dyn std::error::Error>>;
}

pub fn parse_jsonl(stdout: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.is_empty() {
            if let Ok(v) = serde_json::from_str::<Value>(line) { rows.push(v); }
        }
    }
    if rows.is_empty() && !stdout.trim().is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(stdout) {
            match v { Value::Array(a) => return a, other => return vec![other] }
        }
    }
    rows
}

pub struct ToolRunner { pub guard: ScopeGuard, pub dry_run: bool }

impl ToolRunner {
    pub fn new(guard: ScopeGuard, dry_run: bool) -> Self { ToolRunner { guard, dry_run } }
    fn check(&self, targets: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        for t in targets { self.guard.assert_in_scope(t)?; }
        Ok(())
    }
}

impl Runner for ToolRunner {
    fn run_text(&self, tool: &str, args: &[String], targets: &[String]) -> Result<String, Box<dyn std::error::Error>> {
        self.check(targets)?;
        if self.dry_run { return Ok(String::new()); }
        let out = Command::new(tool).args(args).output()?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
    }
    fn run_json(&self, tool: &str, args: &[String], targets: &[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        self.check(targets)?;
        if self.dry_run { return Ok(vec![]); }
        let out = Command::new(tool).args(args).output()?;
        Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout)))
    }
}
```
Add `mod runner;`.
- [ ] **Step 4: Run tests** → PASS; clippy clean.
- [ ] **Step 5: Commit**
```bash
git add src/runner.rs src/main.rs
git commit -m "feat: Runner trait and scope-checked ToolRunner"
```

---

### Task 4: Finding model and nuclei normaliser

**Files:**
- Create: `src/models.rs`, `src/normalise.rs`, `samples/nuclei_sample.json`
- Modify: `src/main.rs` (`mod models; mod normalise;`)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Serialize)] struct Finding { id, tool, rule_id, severity, title, message, url, file, line, category, cwe, evidence }` with `fn to_crux_json(&self) -> serde_json::Value` producing the dict shape Crux's loader accepts (`code` = evidence).
  - `fn normalise_nuclei(rows: &[serde_json::Value]) -> Vec<Finding>`.

- [ ] **Step 1: Write the failing test** (in `src/normalise.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn nuclei_normalises() {
        let rows = vec![serde_json::json!({
            "template-id":"CVE-2021-1234",
            "info":{"name":"Example RCE","severity":"high","classification":{"cwe-id":["CWE-78"]}},
            "matched-at":"https://app.example.com/ping?ip=1","type":"http"})];
        let out = normalise_nuclei(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "CVE-2021-1234");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].url, "https://app.example.com/ping?ip=1");
        assert_eq!(out[0].cwe, "CWE-78");
        assert_eq!(out[0].to_crux_json()["tool"], "nuclei");
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/models.rs` then `src/normalise.rs`**
```rust
// src/models.rs
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Default)]
pub struct Finding {
    pub id: String, pub tool: String, pub rule_id: String, pub severity: String,
    pub title: String, pub message: String, pub url: String, pub file: String,
    pub line: i64, pub category: String, pub cwe: String, pub evidence: String,
}
impl Finding {
    pub fn to_crux_json(&self) -> Value {
        json!({ "id": self.id, "tool": self.tool, "rule_id": self.rule_id,
            "severity": self.severity, "title": self.title, "message": self.message,
            "url": self.url, "file": self.file, "line": self.line,
            "category": self.category, "cwe": self.cwe, "code": self.evidence })
    }
}
```
```rust
// src/normalise.rs
use crate::models::Finding;
use serde_json::Value;

fn cwe_of(info: &Value) -> String {
    let c = &info["classification"]["cwe-id"];
    if let Some(a) = c.as_array() { a.first().and_then(|v| v.as_str()).unwrap_or("").to_string() }
    else { c.as_str().unwrap_or("").to_string() }
}

pub fn normalise_nuclei(rows: &[Value]) -> Vec<Finding> {
    rows.iter().map(|r| {
        let info = &r["info"];
        let loc = r["matched-at"].as_str().or_else(|| r["host"].as_str()).unwrap_or("").to_string();
        let rid = r["template-id"].as_str().unwrap_or("nuclei").to_string();
        Finding {
            id: format!("nuclei:{rid}:{loc}"), tool: "nuclei".into(), rule_id: rid,
            severity: info["severity"].as_str().unwrap_or("info").to_uppercase(),
            title: info["name"].as_str().unwrap_or("finding").to_string(),
            message: info["description"].as_str().unwrap_or("").trim().to_string(),
            url: loc, category: "DAST".into(), cwe: cwe_of(info),
            evidence: r["curl-command"].as_str().unwrap_or("").to_string(), ..Default::default()
        }
    }).collect()
}
```
Save a JSONL `samples/nuclei_sample.json`. Add the modules.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/models.rs src/normalise.rs src/main.rs samples/nuclei_sample.json
git commit -m "feat: Finding model and nuclei normaliser"
```

---

### Task 5: Recon stage

**Files:**
- Create: `src/stages/mod.rs`, `src/stages/recon.rs`
- Modify: `src/main.rs` (`mod stages;`)

**Interfaces:**
- Consumes: `Runner`.
- Produces: `fn recon(runner: &dyn Runner, root_domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error>>` — subfinder then httpx; returns deduped live URLs (`url` field from httpx).

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::{json, Value};
    struct Fake;
    impl Runner for Fake {
        fn run_json(&self, tool:&str,_a:&[String],_t:&[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool { "subfinder" => vec![json!({"host":"app.example.com"})],
                "httpx" => vec![json!({"url":"https://app.example.com"})], _ => vec![] })
        }
        fn run_text(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<String, Box<dyn std::error::Error>> { Ok(String::new()) }
    }
    #[test] fn recon_live_urls() {
        assert_eq!(recon(&Fake, "example.com").unwrap(), vec!["https://app.example.com".to_string()]);
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/stages/mod.rs` (`pub mod recon;` etc.) and `src/stages/recon.rs`**
```rust
use crate::runner::Runner;
use std::collections::BTreeSet;

pub fn recon(runner: &dyn Runner, root_domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let subs = runner.run_json("subfinder",
        &["-silent".into(),"-json".into(),"-d".into(),root_domain.into()], &[root_domain.into()])?;
    let mut hosts: BTreeSet<String> = subs.iter().filter_map(|s| s["host"].as_str().map(String::from)).collect();
    hosts.insert(root_domain.into());
    let mut args = vec!["-silent".into(),"-json".into()];
    for h in &hosts { args.push("-u".into()); args.push(h.clone()); }
    let hv: Vec<String> = hosts.iter().cloned().collect();
    let live = runner.run_json("httpx", &args, &hv)?;
    let urls: BTreeSet<String> = live.iter().filter_map(|r| r["url"].as_str().map(String::from)).collect();
    Ok(urls.into_iter().collect())
}
```
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/stages/mod.rs src/stages/recon.rs src/main.rs
git commit -m "feat: recon stage (subfinder + httpx)"
```

---

### Task 6: Enumeration stage

**Files:**
- Create: `src/stages/enumerate.rs`
- Modify: `src/stages/mod.rs` (`pub mod enumerate;`)

**Interfaces:**
- Consumes: `Runner`.
- Produces: `fn enumerate_surface(runner: &dyn Runner, urls: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>>` — katana over URLs; returns inputs plus discovered endpoints, deduped.

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*; use crate::runner::Runner; use serde_json::{json, Value};
    struct Fake;
    impl Runner for Fake {
        fn run_json(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![json!({"endpoint":"https://app.example.com/login"})]) }
        fn run_text(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<String, Box<dyn std::error::Error>> { Ok(String::new()) }
    }
    #[test] fn merges_endpoints() {
        let out = enumerate_surface(&Fake, &["https://app.example.com".into()]).unwrap();
        assert!(out.contains(&"https://app.example.com/login".to_string()));
        assert!(out.contains(&"https://app.example.com".to_string()));
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/stages/enumerate.rs`**
```rust
use crate::runner::Runner;
use std::collections::BTreeSet;
use url::Url;

pub fn enumerate_surface(runner: &dyn Runner, urls: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if urls.is_empty() { return Ok(vec![]); }
    let hosts: BTreeSet<String> = urls.iter().filter_map(|u| Url::parse(u).ok().and_then(|p| p.host_str().map(String::from))).collect();
    let mut args = vec!["-silent".into(),"-jsonl".into()];
    for u in urls { args.push("-u".into()); args.push(u.clone()); }
    let hv: Vec<String> = hosts.into_iter().collect();
    let rows = runner.run_json("katana", &args, &hv)?;
    let mut set: BTreeSet<String> = urls.iter().cloned().collect();
    for r in rows { if let Some(e) = r["endpoint"].as_str() { set.insert(e.to_string()); } }
    Ok(set.into_iter().collect())
}
```
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/stages/enumerate.rs src/stages/mod.rs
git commit -m "feat: enumeration stage (katana)"
```

---

### Task 7: Crux additions (Python, in the crux repo)

Two small additions so a Rust subprocess can drive Crux. **Work in `M:/Projects/crux`.**

**Files:**
- Modify: `crux/crux/models.py` (Finding: url-based DAST), `crux/crux/cli.py` (add `--emit-json`), `crux/crux/report.py` or a small exporter.
- Test: `crux/tests/test_finding_dast.py`, `crux/tests/test_emit_json.py`

**Interfaces:**
- Produces: Crux `Finding` gains optional `url: str = ""`; `file`/`line` optional when `url` present; `locus()` returns `url or f"{file}:{line}"`; `content_hash()` includes `url`. Crux CLI gains `--emit-json <path>` writing the ranked triaged items as JSON: a list of `{finding:{...}, verdict, confidence, fp_likelihood, rationale, remediation}`.

- [ ] **Step 1: Write failing tests (crux repo)**
```python
# crux/tests/test_finding_dast.py
from crux.models import Finding
def test_url_finding():
    f = Finding.parse({"id":"n1","tool":"nuclei","rule_id":"r","severity":"HIGH",
                       "title":"t","message":"m","url":"https://a/p","category":"DAST"})
    assert f.url == "https://a/p" and f.locus() == "https://a/p"
```
```python
# crux/tests/test_emit_json.py
import json, subprocess, sys, pathlib
def test_emit_json(tmp_path):
    inp = tmp_path/"f.json"
    inp.write_text(json.dumps([{"id":"n1","tool":"nuclei","rule_id":"sqli","severity":"HIGH",
        "title":"SQLi","message":"m","url":"https://a/x","category":"DAST"}]))
    out = tmp_path/"q.json"
    subprocess.run([sys.executable,"-m","crux","--input",str(inp),"--mock",
                    "--emit-json",str(out),"--audit",str(tmp_path/"a.jsonl")], check=True, cwd="M:/Projects/crux")
    items = json.loads(out.read_text())
    assert items and "verdict" in items[0] and "finding" in items[0]
```
- [ ] **Step 2: Run, verify fail** — `cd /m/Projects/crux && pytest tests/test_finding_dast.py tests/test_emit_json.py -v` → FAIL.
- [ ] **Step 3: Implement** — add `url` to `Finding` + `locus()` + hash; in `cli.py` add `--emit-json` that serialises `items` (finding fields + verdict/confidence/fp_likelihood/rationale/remediation) to JSON.
- [ ] **Step 4: Run crux tests** → all PASS (existing SAST tests still green).
- [ ] **Step 5: Commit (crux repo)**
```bash
cd /m/Projects/crux && git add crux/ tests/ && git commit -m "feat: url-based findings + --emit-json queue export"
```

---

### Task 8: Scan stage + Crux triage bridge

**Files:**
- Create: `src/stages/scan.rs`, `src/triage.rs`
- Modify: `src/stages/mod.rs` (`pub mod scan;`), `src/main.rs` (`mod triage;`)

**Interfaces:**
- Consumes: `Runner`, `normalise_nuclei`, `Finding`.
- Produces:
  - `fn ensure_nuclei_version(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>>` (parse `nuclei -version`; error if < 3.10.0).
  - `fn scan(runner: &dyn Runner, urls: &[String]) -> Result<Vec<Finding>, Box<dyn std::error::Error>>`.
  - `trait TriageEngine { fn triage(&self, findings: &[Finding], out_dir: &str) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>>; }`
  - `#[derive(Deserialize)] struct TriageItem { finding: serde_json::Value, verdict: String, confidence: f64, fp_likelihood: f64, rationale: String, remediation: String }`
  - `pub fn parse_crux_queue(json: &str) -> Result<Vec<TriageItem>, serde_json::Error>` (pure, unit-tested).
  - `struct CruxTriager { python: String }` implementing `TriageEngine`: writes findings JSON, runs `python -m crux --input ... --mock --emit-json ... --audit ...`, reads and parses the queue JSON.

- [ ] **Step 1: Write the failing tests**
```rust
// in src/stages/scan.rs
#[cfg(test)]
mod tests {
    use super::*; use crate::runner::Runner; use serde_json::{json, Value};
    struct Fake;
    impl Runner for Fake {
        fn run_json(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![json!({"template-id":"CVE-1","info":{"name":"x","severity":"high"},
                "matched-at":"https://app.example.com/"})]) }
        fn run_text(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<String, Box<dyn std::error::Error>> { Ok(String::new()) }
    }
    #[test] fn scan_returns_findings() {
        let out = scan(&Fake, &["https://app.example.com/".into()]).unwrap();
        assert_eq!(out[0].tool, "nuclei"); assert_eq!(out[0].severity, "HIGH");
    }
}
```
```rust
// in src/triage.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn parses_queue() {
        let j = r#"[{"finding":{"title":"SQLi"},"verdict":"TRUE_POSITIVE","confidence":0.9,
                     "fp_likelihood":0.1,"rationale":"r","remediation":"fix"}]"#;
        let items = parse_crux_queue(j).unwrap();
        assert_eq!(items[0].verdict, "TRUE_POSITIVE");
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/stages/scan.rs` and `src/triage.rs`**
```rust
// src/stages/scan.rs
use crate::runner::Runner;
use crate::normalise::normalise_nuclei;
use crate::models::Finding;
use url::Url;
use std::collections::BTreeSet;

pub fn ensure_nuclei_version(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("nuclei", &["-version".into()], &[])?;
    let re_ok = out.split_whitespace().find_map(|w| {
        let w = w.trim_start_matches('v');
        let p: Vec<_> = w.split('.').filter_map(|n| n.parse::<u32>().ok()).collect();
        if p.len() == 3 { Some(p) } else { None }
    });
    match re_ok { Some(p) if (p[0],p[1],p[2]) >= (3,10,0) => Ok(()),
        _ => Err("nuclei >= v3.10.0 required (CVE-2026-76802)".into()) }
}

pub fn scan(runner: &dyn Runner, urls: &[String]) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    if urls.is_empty() { return Ok(vec![]); }
    let hosts: BTreeSet<String> = urls.iter().filter_map(|u| Url::parse(u).ok().and_then(|p| p.host_str().map(String::from))).collect();
    let mut args = vec!["-silent".into(),"-jsonl".into(),"-tags".into(),"cve,exposure,misconfig,tech".into()];
    for u in urls { args.push("-u".into()); args.push(u.clone()); }
    let hv: Vec<String> = hosts.into_iter().collect();
    Ok(normalise_nuclei(&runner.run_json("nuclei", &args, &hv)?))
}
```
```rust
// src/triage.rs
use crate::models::Finding;
use serde::Deserialize;
use serde_json::Value;
use std::process::Command;

#[derive(Deserialize, Debug)]
pub struct TriageItem {
    pub finding: Value, pub verdict: String, pub confidence: f64,
    pub fp_likelihood: f64, pub rationale: String, pub remediation: String,
}

pub trait TriageEngine {
    fn triage(&self, findings: &[Finding], out_dir: &str) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>>;
}

pub fn parse_crux_queue(json: &str) -> Result<Vec<TriageItem>, serde_json::Error> {
    serde_json::from_str(json)
}

pub struct CruxTriager { pub python: String }
impl Default for CruxTriager { fn default() -> Self { CruxTriager { python: "python".into() } } }

impl TriageEngine for CruxTriager {
    fn triage(&self, findings: &[Finding], out_dir: &str) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
        let dir = std::path::Path::new(out_dir);
        std::fs::create_dir_all(dir)?;
        let in_path = dir.join("findings.json");
        let q_path = dir.join("queue.json");
        let audit = dir.join("audit.jsonl");
        let arr: Vec<Value> = findings.iter().map(|f| f.to_crux_json()).collect();
        std::fs::write(&in_path, serde_json::to_string(&arr)?)?;
        let status = Command::new(&self.python)
            .args(["-m","crux","--input"]).arg(&in_path)
            .args(["--mock","--emit-json"]).arg(&q_path)
            .arg("--audit").arg(&audit).status()?;
        if !status.success() { return Err("crux triage failed".into()); }
        Ok(parse_crux_queue(&std::fs::read_to_string(&q_path)?)?)
    }
}
```
- [ ] **Step 4: Run tests** → PASS (unit tests don't spawn python; the real crux call is exercised in Task 11).
- [ ] **Step 5: Commit**
```bash
git add src/stages/scan.rs src/triage.rs src/stages/mod.rs src/main.rs
git commit -m "feat: nuclei scan stage + Crux subprocess triage bridge"
```

---

### Task 9: Report renderer

**Files:**
- Create: `src/report.rs`
- Modify: `src/main.rs` (`mod report;`)

**Interfaces:**
- Consumes: `TriageItem`.
- Produces: `fn to_markdown(items: &[TriageItem], engagement_name: &str) -> String` — ranked (TRUE_POSITIVE, then ABSTAIN, then LIKELY_FALSE_POSITIVE; then by confidence desc), each with locus (`finding.url` or `file:line`), severity, confidence, fp_likelihood, rationale, remediation; states nothing auto-closed.

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*; use crate::triage::TriageItem; use serde_json::json;
    #[test] fn renders() {
        let it = TriageItem { finding: json!({"title":"SQLi","url":"https://a/x","rule_id":"sqli","severity":"HIGH"}),
            verdict:"TRUE_POSITIVE".into(), confidence:0.9, fp_likelihood:0.1, rationale:"r".into(), remediation:"fix".into() };
        let md = to_markdown(&[it], "lab");
        assert!(md.contains("# Ascent report") && md.contains("SQLi") && md.contains("https://a/x"));
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/report.rs`**
```rust
use crate::triage::TriageItem;

fn rank(v: &str) -> u8 { match v { "TRUE_POSITIVE"=>0, "ABSTAIN"=>1, _=>2 } }
fn badge(v: &str) -> &str { match v { "TRUE_POSITIVE"=>"TRUE POSITIVE","ABSTAIN"=>"NEEDS HUMAN",_=>"LIKELY NOISE" } }
fn s(v: &serde_json::Value, k: &str) -> String { v[k].as_str().unwrap_or("").to_string() }

pub fn to_markdown(items: &[TriageItem], name: &str) -> String {
    let mut v: Vec<&TriageItem> = items.iter().collect();
    v.sort_by(|a,b| rank(&a.verdict).cmp(&rank(&b.verdict))
        .then(b.confidence.partial_cmp(&a.confidence).unwrap()));
    let mut out = format!("# Ascent report: {name}\n\nFindings: {}. Nothing has been auto-closed; this is a ranked queue for review.\n\n", items.len());
    for it in v {
        let f = &it.finding;
        let locus = if !s(f,"url").is_empty() { s(f,"url") } else { format!("{}:{}", s(f,"file"), f["line"].as_i64().unwrap_or(0)) };
        out += &format!("## [{}] {}\n\n- Where: `{}`\n- Rule / severity: `{}` ({})\n- Confidence: {:.2}  FP-likelihood: {:.2}\n- Why: {}\n- Fix: {}\n\n",
            badge(&it.verdict), s(f,"title"), locus, s(f,"rule_id"), s(f,"severity"),
            it.confidence, it.fp_likelihood, it.rationale, it.remediation);
    }
    out
}
```
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/report.rs src/main.rs && git commit -m "feat: markdown report renderer"
```

---

### Task 10: Pipeline orchestration

**Files:**
- Create: `src/pipeline.rs`
- Modify: `src/main.rs` (`mod pipeline;`)

**Interfaces:**
- Consumes: `Runner`, `TriageEngine`, all stages, `to_markdown`.
- Produces: `struct Summary { urls: usize, findings: usize, triaged: usize, report_path: String, audit_path: String }`; `fn run_pipeline(eng: &Engagement, runner: &dyn Runner, triager: &dyn TriageEngine, out_dir: &str) -> Result<Summary, Box<dyn std::error::Error>>` — version check, recon → enumerate → (conditional) scan → triage → write `report.md`; returns summary. (Injecting `runner` and `triager` makes it fully testable with fakes.)

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*; use crate::runner::Runner; use crate::triage::{TriageEngine,TriageItem};
    use crate::models::Finding; use crate::scope::Engagement; use serde_json::{json,Value};
    struct FakeRun;
    impl Runner for FakeRun {
        fn run_json(&self,tool:&str,_a:&[String],_t:&[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool { "subfinder"=>vec![json!({"host":"app.example.com"})],
                "httpx"=>vec![json!({"url":"https://app.example.com"})],
                "katana"=>vec![json!({"endpoint":"https://app.example.com/login"})],
                "nuclei"=>vec![json!({"template-id":"sqli","info":{"name":"SQLi","severity":"high"},
                    "matched-at":"https://app.example.com/login"})], _=>vec![] }) }
        fn run_text(&self,_t:&str,_a:&[String],_g:&[String]) -> Result<String, Box<dyn std::error::Error>> { Ok("nuclei v3.10.1".into()) }
    }
    struct FakeTri;
    impl TriageEngine for FakeTri {
        fn triage(&self, f:&[Finding], _o:&str) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
            Ok(f.iter().map(|x| TriageItem{ finding: x.to_crux_json(), verdict:"TRUE_POSITIVE".into(),
                confidence:0.9, fp_likelihood:0.1, rationale:"r".into(), remediation:"fix".into() }).collect()) }
    }
    #[test] fn end_to_end(tmpdir: ()) { let _ = tmpdir; }  // replaced below
    #[test] fn pipeline_runs() {
        let tmp = std::env::temp_dir().join(format!("ascent_test_{}", std::process::id()));
        let eng = Engagement{ name:"lab".into(), hosts:vec!["example.com".into()], cidrs:vec![],
            urls:vec!["https://app.example.com".into()], starts:"x".into(), ends:"y".into() };
        let s = run_pipeline(&eng, &FakeRun, &FakeTri, tmp.to_str().unwrap()).unwrap();
        assert!(s.findings >= 1);
        assert!(std::path::Path::new(&s.report_path).exists());
    }
}
```
(Delete the placeholder `end_to_end` test; keep `pipeline_runs`.)
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/pipeline.rs`**
```rust
use crate::scope::Engagement;
use crate::runner::Runner;
use crate::triage::TriageEngine;
use crate::stages::{recon::recon, enumerate::enumerate_surface, scan::{scan, ensure_nuclei_version}};
use crate::report::to_markdown;
use std::path::Path;

pub struct Summary { pub urls: usize, pub findings: usize, pub triaged: usize,
    pub report_path: String, pub audit_path: String }

pub fn run_pipeline(eng: &Engagement, runner: &dyn Runner, triager: &dyn TriageEngine, out_dir: &str)
    -> Result<Summary, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out_dir)?;
    ensure_nuclei_version(runner)?;
    let root = eng.hosts.first().cloned().unwrap_or_default();
    let mut urls = if !root.is_empty() { recon(runner, &root)? } else { eng.urls.clone() };
    urls = enumerate_surface(runner, &urls)?;
    let findings = if !urls.is_empty() { scan(runner, &urls)? } else { vec![] };
    let items = if !findings.is_empty() { triager.triage(&findings, out_dir)? } else { vec![] };
    let report_path = Path::new(out_dir).join("report.md");
    std::fs::write(&report_path, to_markdown(&items, &eng.name))?;
    Ok(Summary { urls: urls.len(), findings: findings.len(), triaged: items.len(),
        report_path: report_path.to_string_lossy().into(),
        audit_path: Path::new(out_dir).join("audit.jsonl").to_string_lossy().into() })
}
```
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/pipeline.rs src/main.rs && git commit -m "feat: end-to-end pipeline orchestration"
```

---

### Task 11: CLI wiring + smoke run

**Files:**
- Modify: `src/main.rs` (clap CLI)

**Interfaces:**
- Produces: `ascent run --engagement <file> --out <dir> [--dry-run]` — loads the engagement, builds `ScopeGuard` + `ToolRunner` + `CruxTriager`, calls `run_pipeline`, prints the summary and paths.

- [ ] **Step 1: Write the CLI and a parse test**
```rust
use clap::{Parser, Subcommand};
mod scope; mod runner; mod models; mod normalise; mod stages; mod triage; mod report; mod pipeline;
use scope::{load_engagement}; use runner::ToolRunner; use scope::ScopeGuard;
use triage::CruxTriager; use pipeline::run_pipeline;

#[derive(Parser)]
#[command(name="ascent")]
struct Cli { #[command(subcommand)] cmd: Cmd }
#[derive(Subcommand)]
enum Cmd { Run { #[arg(long)] engagement: String, #[arg(long, default_value="out")] out: String,
                 #[arg(long)] dry_run: bool } }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Run { engagement, out, dry_run } => {
            let eng = load_engagement(&engagement)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), dry_run);
            let s = run_pipeline(&eng, &runner, &CruxTriager::default(), &out)?;
            println!("urls={} findings={} triaged={}", s.urls, s.findings, s.triaged);
            println!("report: {}\naudit:  {}", s.report_path, s.audit_path);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser; use super::Cli;
    #[test] fn parses_run() { assert!(Cli::try_parse_from(["ascent","run","--engagement","e.yaml"]).is_ok()); }
}
```
(Keep the earlier `version()` smoke test or move it into a module; ensure `mod` declarations are not duplicated.)
- [ ] **Step 2: Run unit tests** → `cargo test` PASS; `cargo clippy -- -D warnings` clean.
- [ ] **Step 3: Real smoke run** — install the tools (nuclei >= v3.10.0) and `pip install -e M:/Projects/crux`; start OWASP Juice Shop or WebGoat.NET locally; write an engagement YAML scoped to `localhost`/`127.0.0.1`; run `cargo run -- run --engagement samples/engagement.example.yaml --out out`. Expect `out/report.md` and `out/audit.jsonl`.
- [ ] **Step 4: Commit**
```bash
git add src/main.rs && git commit -m "feat: ascent CLI + smoke run"
```

---

## Self-review notes (coverage)

- Scope gate (PRD Gate 0): Tasks 2, 3 (hook in ToolRunner). Recon/Enum/Scan (phases 1-3a): Tasks 5, 6, 8. Normalisation + Crux triage incl. DAST ingestion and the Rust↔Crux subprocess bridge (phases 3/4): Tasks 4, 7, 8. Reporting (phase 7): Task 9. Orchestration + conditional scan (section 9): Task 10. CLI: Task 11.
- Testability: every stage takes a `&dyn Runner`; triage takes a `&dyn TriageEngine`; pure helpers (`parse_jsonl`, `parse_crux_queue`) are unit-tested; the only steps needing real tools/python are the Task 11 smoke run.
- Deferred to later plans: exploitation/post-exploitation (phases 5-6), SAST track (3b), MCP server (Rust `rmcp`) so Claude Code drives Ascent, the `reqwest` Anthropic advisory calls, and the dashboard (section 8b).
- Safety: scope check before every spawn (Task 3), nuclei >= v3.10.0 (Task 8), no exploit tools, Crux offline (`--mock`), no credentials on the CLI.
- Verify in Task 7/8 that Crux's actual CLI flags match (`--input`, `--mock`, `--audit`, and the new `--emit-json`); adjust the `CruxTriager` command if names differ.
