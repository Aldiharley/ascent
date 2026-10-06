# Ascent SAST Track (white-box source analysis) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a white-box static-analysis track that runs source analysers (opengrep, gitleaks, trivy) as scope-checked subprocesses, normalises their output into the existing `Finding` shape, and feeds those findings into Crux triage alongside the DAST findings.

**Architecture:** A new `sast` stage calls each available analyser over an authorised source directory via the existing `Runner` (no network targets), normalises each tool's JSON into `Finding`, and the pipeline concatenates SAST findings with the DAST findings before triage. Triage, report and audit are unchanged — they already operate on `Vec<Finding>`. Based on `docs/superpowers/specs/2026-10-06-sast-stage-design.md`.

**Tech Stack:** Rust (stable), serde_json, the existing `Runner`/`Finding`/`CruxTriager`. External analysers (installed, invoked, never vendored): opengrep, gitleaks, trivy.

## Global Constraints

- License: Apache-2.0 for all Ascent code. Analysers are invoked as subprocesses, never vendored or linked. None is a bundle-forbidden license-trap tool.
- Scope: source analysis makes no network call, so every SAST runner call passes an EMPTY target list (never a network host). The authorised source root is the boundary; the stage refuses a source path outside the engagement's declared `source` root.
- Secrets safety: a gitleaks finding stores the rule id and location ONLY. The raw secret value (`Secret`/`Match`) is NEVER placed in any `Finding` field.
- No external LLM in this plan: triage stays offline (`CruxTriager`/`MockTriager`). Source never leaves the machine.
- Rust stable; `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt` applied; every task ends green and committed. Source files are LF (`.gitattributes`).
- Commit trailer: end every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1: Engagement gains an authorised source root

**Files:**
- Modify: `src/scope.rs` (the `Engagement` struct + its tests)

**Interfaces:**
- Produces: `Engagement` gains `#[serde(default)] pub source: String` (empty when absent). An engagement with a non-empty `source` is eligible for the SAST track.

- [ ] **Step 1: Write the failing test** (add to `src/scope.rs` tests)
```rust
#[test]
fn engagement_parses_optional_source() {
    let y = "name: t\nurls: ['http://localhost:3000/']\nsource: ./src\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
    let e: Engagement = serde_yaml_ng::from_str(y).unwrap();
    assert_eq!(e.source, "./src");
    let y2 = "name: t\nhosts: [localhost]\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
    let e2: Engagement = serde_yaml_ng::from_str(y2).unwrap();
    assert_eq!(e2.source, "");
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test engagement_parses_optional_source` → FAIL (no field `source`).
- [ ] **Step 3: Implement** — add to the `Engagement` struct, after `urls`:
```rust
    #[serde(default)]
    pub source: String,
```
- [ ] **Step 4: Run tests** → `cargo test` PASS; `cargo clippy --all-targets -- -D warnings` clean.
- [ ] **Step 5: Commit**
```bash
git add src/scope.rs
git commit -m "feat(sast): engagement gains an optional source root"
```

---

### Task 2: Normalisers for opengrep, gitleaks, trivy

**Files:**
- Modify: `src/normalise.rs` (add three functions + a small severity helper)
- Create: `samples/sast/opengrep_sample.json`, `samples/sast/gitleaks_sample.json`, `samples/sast/trivy_sample.json`
- Test: tests go at the bottom of `src/normalise.rs`

**Interfaces:**
- Consumes: `Finding` from `crate::models`.
- Produces:
  - `pub fn normalise_opengrep(rows: &[serde_json::Value]) -> Vec<Finding>` — reads the opengrep/semgrep JSON object (`{results:[...]}`); `category = "SAST"`.
  - `pub fn normalise_gitleaks(rows: &[serde_json::Value]) -> Vec<Finding>` — reads gitleaks' JSON array of findings; `category = "SAST"`; stores NO secret value.
  - `pub fn normalise_trivy(rows: &[serde_json::Value]) -> Vec<Finding>` — reads trivy `fs --format json` (`{Results:[{Vulnerabilities:[...]}]}`); `category = "SCA"`.

Note on `rows`: `Runner::run_json` parses whole-stdout-first, so a single JSON object comes back as a one-element `Vec` (`[object]`) and a top-level JSON array comes back flattened. opengrep and trivy emit a wrapper object; gitleaks emits a top-level array.

- [ ] **Step 1: Write the failing tests** (bottom of `src/normalise.rs`)
```rust
#[cfg(test)]
mod sast_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opengrep_normalises() {
        let rows = vec![json!({"results":[{
            "check_id":"rust.lang.security.sqli","path":"src/db.rs",
            "start":{"line":42},"end":{"line":42},
            "extra":{"severity":"ERROR","message":"possible sqli",
                     "metadata":{"cwe":["CWE-89: SQL Injection"]},"lines":"let q = format!(...)"}}]})];
        let out = normalise_opengrep(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "opengrep");
        assert_eq!(out[0].category, "SAST");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].file, "src/db.rs");
        assert_eq!(out[0].line, 42);
        assert_eq!(out[0].cwe, "CWE-89");
        assert_eq!(out[0].rule_id, "rust.lang.security.sqli");
    }

    #[test]
    fn gitleaks_normalises_and_redacts_the_secret() {
        let rows = vec![json!({"Description":"AWS Access Key","StartLine":10,"File":"config.py",
            "RuleID":"aws-access-token","Secret":"AKIAIOSFODNN7EXAMPLE","Match":"key = AKIAIOSFODNN7EXAMPLE"})];
        let out = normalise_gitleaks(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "gitleaks");
        assert_eq!(out[0].category, "SAST");
        assert_eq!(out[0].file, "config.py");
        assert_eq!(out[0].line, 10);
        assert_eq!(out[0].rule_id, "aws-access-token");
        // The raw secret must appear in NO field of the finding.
        let blob = serde_json::to_string(&out[0].to_crux_json()).unwrap();
        assert!(!blob.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into finding: {blob}");
    }

    #[test]
    fn trivy_normalises_sca() {
        let rows = vec![json!({"Results":[{"Target":"package-lock.json","Class":"lang-pkgs",
            "Vulnerabilities":[{"VulnerabilityID":"CVE-2021-1234","PkgName":"lodash",
                "Severity":"HIGH","Title":"Prototype pollution","Description":"desc","CweIDs":["CWE-1321"]}]}]})];
        let out = normalise_trivy(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "trivy");
        assert_eq!(out[0].category, "SCA");
        assert_eq!(out[0].rule_id, "CVE-2021-1234");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].cwe, "CWE-1321");
        assert_eq!(out[0].file, "package-lock.json");
    }
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test sast_tests` → FAIL (functions missing).
- [ ] **Step 3: Implement** (add to `src/normalise.rs`)
```rust
fn sev_from_semgrep(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "ERROR" => "HIGH",
        "WARNING" => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

fn cwe_first(v: &Value) -> String {
    // Accept ["CWE-89: ..."] or "CWE-89"; return just the "CWE-<n>" token.
    let raw = if let Some(a) = v.as_array() {
        a.first().and_then(|x| x.as_str()).unwrap_or("")
    } else {
        v.as_str().unwrap_or("")
    };
    raw.split(':').next().unwrap_or("").trim().to_string()
}

pub fn normalise_opengrep(rows: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for row in rows {
        let results = row.get("results").and_then(|v| v.as_array());
        let items: Vec<&Value> = match results {
            Some(a) => a.iter().collect(),
            None => vec![row], // tolerate a bare result object
        };
        for r in items {
            let path = r["path"].as_str().unwrap_or("");
            if path.is_empty() {
                continue;
            }
            let line = r["start"]["line"].as_i64().unwrap_or(0);
            let rid = r["check_id"].as_str().unwrap_or("opengrep").to_string();
            out.push(Finding {
                id: format!("opengrep:{rid}:{path}:{line}"),
                tool: "opengrep".into(),
                rule_id: rid.clone(),
                severity: sev_from_semgrep(r["extra"]["severity"].as_str().unwrap_or("INFO")),
                title: rid,
                message: r["extra"]["message"].as_str().unwrap_or("").trim().to_string(),
                url: String::new(),
                file: path.to_string(),
                line,
                category: "SAST".into(),
                cwe: cwe_first(&r["extra"]["metadata"]["cwe"]),
                evidence: r["extra"]["lines"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    out
}

pub fn normalise_gitleaks(rows: &[Value]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|r| {
            let file = r["File"].as_str()?;
            let line = r["StartLine"].as_i64().unwrap_or(0);
            let rid = r["RuleID"].as_str().unwrap_or("gitleaks").to_string();
            let desc = r["Description"].as_str().unwrap_or(&rid).to_string();
            // Deliberately store NO secret value (no `Secret`/`Match`) in any field.
            Some(Finding {
                id: format!("gitleaks:{rid}:{file}:{line}"),
                tool: "gitleaks".into(),
                rule_id: rid,
                severity: "HIGH".into(),
                title: format!("Hardcoded secret: {desc}"),
                message: "Potential hardcoded secret detected; rotate it and move it to a secret store.".into(),
                url: String::new(),
                file: file.to_string(),
                line,
                category: "SAST".into(),
                cwe: "CWE-798".into(),
                evidence: String::new(),
            })
        })
        .collect()
}

pub fn normalise_trivy(rows: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for row in rows {
        let Some(results) = row["Results"].as_array() else {
            continue;
        };
        for res in results {
            let target = res["Target"].as_str().unwrap_or("");
            let Some(vulns) = res["Vulnerabilities"].as_array() else {
                continue;
            };
            for v in vulns {
                let id = v["VulnerabilityID"].as_str().unwrap_or("trivy").to_string();
                let pkg = v["PkgName"].as_str().unwrap_or("");
                out.push(Finding {
                    id: format!("trivy:{id}:{target}:{pkg}"),
                    tool: "trivy".into(),
                    rule_id: id.clone(),
                    severity: v["Severity"].as_str().unwrap_or("UNKNOWN").to_uppercase(),
                    title: v["Title"].as_str().unwrap_or(&id).to_string(),
                    message: v["Description"].as_str().unwrap_or("").trim().to_string(),
                    url: String::new(),
                    file: target.to_string(),
                    line: 0,
                    category: "SCA".into(),
                    cwe: cwe_first(&v["CweIDs"]),
                    evidence: String::new(),
                });
            }
        }
    }
    out
}
```
Save realistic `samples/sast/*.json` (one opengrep `{results:[…]}`, one gitleaks `[…]` array, one trivy `{Results:[…]}`), using lab/dummy data only (no real secrets — use the literal `AKIAIOSFODNN7EXAMPLE` example key).
- [ ] **Step 4: Run tests** → PASS; clippy clean.
- [ ] **Step 5: Commit**
```bash
git add src/normalise.rs samples/sast/
git commit -m "feat(sast): opengrep/gitleaks/trivy normalisers (secret-redacting)"
```

---

### Task 3: SAST stage (tool detection, source-scope guard, run)

**Files:**
- Create: `src/stages/sast.rs`
- Modify: `src/stages/mod.rs` (`pub mod sast;`)

**Interfaces:**
- Consumes: `Runner`, `Finding`, the three normalisers.
- Produces:
  - `pub fn is_within(root: &std::path::Path, candidate: &std::path::Path) -> bool` — true iff `candidate` canonicalises to a path inside `root` (defends against `..` and symlink escape). Both must exist.
  - `pub fn tool_available(runner: &dyn Runner, tool: &str, version_arg: &str) -> bool`.
  - `pub fn sast(runner: &dyn Runner, source_dir: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>>` — runs each AVAILABLE analyser over `source_dir` with EMPTY targets, returns merged findings. A missing tool is skipped.

- [ ] **Step 1: Write the failing test** (bottom of `src/stages/sast.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::{json, Value};
    use std::cell::RefCell;

    struct Fake {
        present: Vec<&'static str>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }
    impl Runner for Fake {
        fn run_text(&self, tool: &str, _a: &[String], targets: &[String]) -> Result<String, Box<dyn std::error::Error>> {
            assert!(targets.is_empty(), "SAST must pass no network targets");
            if self.present.contains(&tool) { Ok(String::new()) } else { Err("not found".into()) }
        }
        fn run_json(&self, tool: &str, args: &[String], targets: &[String]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            assert!(targets.is_empty(), "SAST must pass no network targets");
            self.calls.borrow_mut().push((tool.to_string(), args.to_vec()));
            Ok(match tool {
                "opengrep" => vec![json!({"results":[{"check_id":"r","path":"a.rs","start":{"line":1},"extra":{"severity":"ERROR","message":"m","metadata":{"cwe":["CWE-89"]}}}]})],
                "gitleaks" => vec![json!({"File":"c.py","StartLine":2,"RuleID":"aws","Description":"k","Secret":"XSECRETX"})],
                "trivy" => vec![json!({"Results":[{"Target":"p.json","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","Title":"t"}]}]})],
                _ => vec![],
            })
        }
    }

    #[test]
    fn sast_runs_only_available_tools_and_merges() {
        let f = Fake { present: vec!["opengrep", "trivy"], calls: RefCell::new(vec![]) };
        let out = sast(&f, ".").unwrap();
        let tools: Vec<&str> = out.iter().map(|x| x.tool.as_str()).collect();
        assert!(tools.contains(&"opengrep") && tools.contains(&"trivy"));
        assert!(!tools.contains(&"gitleaks"), "absent tool must be skipped");
        // No secret from the (absent) gitleaks path, and nothing leaks regardless.
        assert!(!serde_json::to_string(&out.iter().map(|x| x.to_crux_json()).collect::<Vec<_>>()).unwrap().contains("XSECRETX"));
    }

    #[test]
    fn sast_with_no_tools_is_empty() {
        let f = Fake { present: vec![], calls: RefCell::new(vec![]) };
        assert!(sast(&f, ".").unwrap().is_empty());
    }

    #[test]
    fn is_within_rejects_traversal() {
        let root = std::env::temp_dir();
        assert!(is_within(&root, &root));
        assert!(!is_within(&root.join("sub"), &root)); // parent is not within child
    }
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test sast` → FAIL.
- [ ] **Step 3: Implement `src/stages/sast.rs`**
```rust
use crate::models::Finding;
use crate::normalise::{normalise_gitleaks, normalise_opengrep, normalise_trivy};
use crate::runner::Runner;
use std::path::Path;

/// True iff `candidate` resolves to a path inside `root`. Both must exist;
/// canonicalisation collapses `..` and resolves symlinks, so neither can escape.
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    match (root.canonicalize(), candidate.canonicalize()) {
        (Ok(r), Ok(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// A tool is "available" if its binary spawns (exit status is irrelevant).
pub fn tool_available(runner: &dyn Runner, tool: &str, version_arg: &str) -> bool {
    runner.run_text(tool, &[version_arg.into()], &[]).is_ok()
}

pub fn sast(runner: &dyn Runner, source_dir: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    if tool_available(runner, "opengrep", "--version") {
        let args = vec![
            "--json".into(), "--quiet".into(),
            "--config".into(), "auto".into(),
            source_dir.into(),
        ];
        findings.extend(normalise_opengrep(&runner.run_json("opengrep", &args, &[])?));
    }
    if tool_available(runner, "gitleaks", "version") {
        let args = vec![
            "detect".into(), "--no-git".into(),
            "--report-format".into(), "json".into(),
            "--report-path".into(), "/dev/stdout".into(),
            "--source".into(), source_dir.into(),
        ];
        findings.extend(normalise_gitleaks(&runner.run_json("gitleaks", &args, &[])?));
    }
    if tool_available(runner, "trivy", "--version") {
        let args = vec![
            "fs".into(), "--quiet".into(),
            "--format".into(), "json".into(),
            source_dir.into(),
        ];
        findings.extend(normalise_trivy(&runner.run_json("trivy", &args, &[])?));
    }
    Ok(findings)
}
```
Add `pub mod sast;` to `src/stages/mod.rs`. (Gitleaks/opengrep/trivy exact flags are validated at the Task 5 smoke run; the unit tests cover detection, merging, redaction and the empty-target invariant.)
- [ ] **Step 4: Run tests** → PASS; clippy clean.
- [ ] **Step 5: Commit**
```bash
git add src/stages/sast.rs src/stages/mod.rs
git commit -m "feat(sast): source-analysis stage with tool detection and source-scope guard"
```

---

### Task 4: Pipeline runs the SAST track when a source root is set

**Files:**
- Modify: `src/pipeline.rs` (`run_pipeline`: add an optional source root; run SAST; merge findings)

**Interfaces:**
- Consumes: `sast` from `crate::stages::sast`, `is_within`.
- Produces: `run_pipeline` gains a trailing `source: Option<&str>` parameter. New signature:
  `pub fn run_pipeline(eng: &Engagement, runner: &dyn Runner, triager: &dyn TriageEngine, out_dir: &str, dry_run: bool, source: Option<&str>) -> Result<Summary, Box<dyn std::error::Error>>`.
  Effective source root = `source` override if `Some` and non-empty, else `eng.source` if non-empty, else none. When a `--source` override is given AND `eng.source` is non-empty, the override must be within `eng.source` (via `is_within`) or `run_pipeline` returns an error. SAST runs only when a source root is resolved and `!dry_run`. SAST findings are concatenated with the DAST findings before triage.

- [ ] **Step 1: Write the failing test** (in `src/pipeline.rs` tests; reuse the existing fake-runner pattern, extend it to answer the SAST tools)
```rust
#[test]
fn pipeline_merges_sast_and_dast_findings() {
    // FakeRun answers recon/enum/scan (as the existing test) AND the SAST tools.
    // Build an engagement with urls + a source dir that exists (use a temp dir).
    let dir = std::env::temp_dir().join(format!("ascent_sast_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let eng = Engagement {
        name: "lab".into(), hosts: vec![], cidrs: vec![],
        urls: vec!["https://app.example.com".into()],
        source: dir.to_string_lossy().into(),
        starts: "x".into(), ends: "y".into(),
    };
    let s = run_pipeline(&eng, &SastRun, &FakeTri, dir.to_str().unwrap(), false, None).unwrap();
    // 1 DAST (nuclei) + 1 SAST (opengrep) finding both reach triage.
    assert!(s.findings >= 2);
}
```
(Define a `SastRun` fake whose `run_json` returns the nuclei row for "nuclei", the recon/enum rows for subfinder/httpx/katana, and an opengrep `{results:[…one…]}` for "opengrep"; `run_text` returns "nuclei v3.10.1" for nuclei-version and Ok for "opengrep --version", Err for gitleaks/trivy; `FakeTri` echoes each finding as a TRUE_POSITIVE item, as the existing pipeline test does.)
- [ ] **Step 2: Run, verify fail** — `cargo test pipeline_merges` → FAIL (arity mismatch / no SAST).
- [ ] **Step 3: Implement** — change `run_pipeline`:
```rust
pub fn run_pipeline(
    eng: &Engagement,
    runner: &dyn Runner,
    triager: &dyn TriageEngine,
    out_dir: &str,
    dry_run: bool,
    source: Option<&str>,
) -> Result<Summary, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out_dir)?;
    if !dry_run {
        ensure_nuclei_version(runner)?;
    }
    // ... existing recon -> enumerate -> scan producing `let mut findings = ...;` (DAST) ...

    // SAST track (white-box), when a source root is resolved.
    let eff_source: Option<String> = match source {
        Some(s) if !s.is_empty() => {
            if !eng.source.is_empty()
                && !crate::stages::sast::is_within(
                    std::path::Path::new(&eng.source),
                    std::path::Path::new(s),
                )
            {
                return Err("--source is outside the engagement's authorised source root".into());
            }
            Some(s.to_string())
        }
        _ => {
            if eng.source.is_empty() { None } else { Some(eng.source.clone()) }
        }
    };
    if let Some(src) = eff_source {
        if !dry_run {
            findings.extend(crate::stages::sast::sast(runner, &src)?);
        }
    }

    // ... existing triage -> report -> Summary (unchanged) ...
}
```
(Keep the existing DAST block and the triage/report/Summary block exactly as they are; only add the `source` param, the `eff_source` resolution, and the `findings.extend(...)`. `findings` must be `mut`.)
- [ ] **Step 4: Run tests** → PASS; clippy clean. (The existing `pipeline_runs` / `dry_run_skips_version_check` tests now need the extra `None` argument — update those call sites.)
- [ ] **Step 5: Commit**
```bash
git add src/pipeline.rs
git commit -m "feat(sast): pipeline runs the SAST track and merges it into triage"
```

---

### Task 5: CLI `--source` flag, README, smoke run

**Files:**
- Modify: `src/main.rs` (add `--source`, pass it through), `README.md`

**Interfaces:**
- Produces: `ascent run --engagement <f> --out <d> [--dry-run] [--source <dir>]`. `--source` overrides the engagement's `source`; both may be empty (then the SAST track is skipped).

- [ ] **Step 1: Write the CLI parse test** (in `src/main.rs` tests)
```rust
#[test]
fn parses_source_flag() {
    let c = Cli::try_parse_from(["ascent", "run", "--engagement", "e.yaml", "--source", "./src"]).unwrap();
    // matches on Cmd::Run { source: Some("./src"), .. }
    assert!(format!("{c:?}").contains("./src"));
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test parses_source_flag` → FAIL (no such arg).
- [ ] **Step 3: Implement** — add to `Cmd::Run`:
```rust
        /// Optional source directory for the white-box SAST track (overrides the engagement's `source`).
        #[arg(long)]
        source: Option<String>,
```
and pass it: `run_pipeline(&eng, &runner, &CruxTriager::default(), &out, dry_run, source.as_deref())?;` (bind `source` in the match arm). Derive `Debug` on `Cli`/`Cmd` if not already, for the test.
- [ ] **Step 4: Run tests** → `cargo test` PASS; `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check` ok.
- [ ] **Step 5: README + smoke run** — add a "SAST track" subsection to `README.md`: install opengrep, gitleaks, trivy (invoked, not vendored); add `source:` to an engagement or pass `--source <dir>`; run `cargo run -- run --engagement <f> --out out --source <dir>`; SAST findings join the DAST queue in the same report/audit. Then a real smoke run if the tools are installed: point `--source` at a small vulnerable sample repo and confirm `out/report.md` contains SAST/SCA findings; if the tools are not installed, note that each is skipped and the run still completes (DAST-only). Record whichever was done.
- [ ] **Step 6: Commit**
```bash
git add src/main.rs README.md
git commit -m "feat(sast): --source CLI flag + README; wire the SAST track end to end"
```

---

## Self-review (coverage)

- Spec "Engagement gains a source root" → Task 1. "Normalisers" (opengrep/gitleaks/trivy, secret redaction) → Task 2. "New stage + tool detection + source-scope check" → Task 3. "Pipeline integration (merge SAST+DAST before triage, conditionals)" → Task 4. "CLI --source + README + smoke" → Task 5.
- Safety: every SAST runner call passes empty targets (asserted in Task 3's fake); the gitleaks normaliser stores no secret (asserted in Tasks 2 and 3); source-scope `is_within` refuses traversal/escape (Task 3) and gates a `--source` override against the engagement root (Task 4); triage stays offline; analysers invoked, never vendored.
- Unchanged by design: triage, report, audit, the DAST track, and the dashboard all operate on `Vec<Finding>` and need no change. A per-track dashboard filter and SAST+DAST correlation are deferred (spec "out of scope").
- Verify at implementation: the exact opengrep/gitleaks/trivy CLI flags and JSON shapes at the Task 5 smoke run (as the pipeline-core plan did for nuclei); adjust the stage's arg lists if a tool's real output differs, keeping the normaliser contracts.
