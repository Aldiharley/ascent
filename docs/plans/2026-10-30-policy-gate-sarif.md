# Policy Gate, CI Exit Codes and Native SARIF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Ascent a policy verdict (PASS / CONDITIONAL / FAIL / INCOMPLETE) with a fail-closed CI exit-code contract, stable `ascent/v1` finding fingerprints, native SARIF 2.1.0 output, and a read-only Policy gate card on the dashboard.

**Architecture:** Scanners must now fail loudly (a non-zero exit is an error) and every run writes `out/run.json` saying whether it was complete. A new `src/gate/` module (fingerprint, policy, evaluate) reads `out/queue.json` + `run.json`, writes `out/gate.json`, and chains a `gate_evaluation` entry into `audit.jsonl`. `src/sarif.rs` turns the same triaged items into `out/ascent.sarif` (code findings) and `out/ascent-dast.sarif` (URL findings). `main.rs` maps every outcome to the exit-code table. The dashboard only reads `gate.json`.

**Tech Stack:** Rust 2021 (serde, serde_json, serde_yaml_ng, url, clap 4, crux `canon::hash_value` / `AuditLog`), axum 0.7 dashboard, React 18 + Vite + vitest frontend.

Spec: `docs/superpowers/specs/2026-10-30-policy-gate-sarif-design.md`. Research: `docs/research/2026-10-30-veracode-gap-analysis.md`.

## Global Constraints

- No new crate dependencies. Hash with `crux::canon::hash_value(&Value) -> String` (lowercase hex SHA-256 of canonical JSON). Timestamps with `crux::audit::format_ts(secs, micros)`.
- Exit codes, exactly: 0 = pass/conditional (or no policy), 1 = policy FAIL (or CONDITIONAL with `--fail-on-warn`), 2 = usage/config/policy error, 3 = incomplete (scanner/stage failed, dry run, missing run.json/queue.json), 4 = audit chain integrity failure.
- Never write a secret value, or any hash/derivative of a secret value, into any output (gate.json, SARIF, fingerprints, audit).
- SARIF never contains finding `code`/`evidence` snippets (they may contain secrets); the only exception is the SCA version string from trivy (`ascent.sca` property).
- Policy parsing is fail-closed: `deny_unknown_fields` everywhere; unknown keys, wrong version, unknown severities/categories, malformed CWE → exit 2.
- A `LIKELY_FALSE_POSITIVE` verdict may only *demote* a fail to a warning (default) — it never silently passes.
- The dashboard never launches runs; `/api/gate` is GET-only and read-only. Every target-derived string is rendered as React text, never HTML.
- Keep the Fluid Glass look: reuse `glass.css` tokens (`--ok`, `--crit`, `--med`, `--faint`, `.panel.glass`, `.phead`, `.ptitle`, `.count`, `.loc`, `.cmd`, `.note`). No new image assets.
- All tests must pass on Windows (path separators!) and Linux.
- Dead-code warnings for items not wired until a later task are acceptable mid-plan; the final task leaves `cargo test` warning-free.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## File Structure

| File | Responsibility |
|---|---|
| `src/runner.rs` (modify) | `run_json` errors on non-zero tool exit |
| `src/stages/sast.rs` (modify) | gitleaks `--exit-code 0`; return `SastOutcome { findings, failed_tools, skipped_tools }` |
| `src/normalise.rs` (modify) | trivy evidence carries pkg / installed / fixed / purl |
| `src/runstatus.rs` (create) | `RunStatus` + read/write `out/run.json`, `now_ts()` |
| `src/pipeline.rs` (modify) | write run.json (start: incomplete; end: final), write SARIF |
| `src/gate/mod.rs` (create) | module root |
| `src/gate/fingerprint.rs` (create) | `ascent/v1` fingerprints, path/URL normalisation, `kind()` |
| `src/gate/policy.rs` (create) | policy schema, load + validate, `policy_hash` |
| `src/gate/evaluate.rs` (create) | decision engine, `gate.json` document, audit chaining, `read_queue` |
| `src/sarif.rs` (create) | SARIF 2.1.0 documents + writer |
| `src/main.rs` (modify) | `--policy`, `--fail-on-warn`, `gate`, `sarif` subcommands, exit-code mapping |
| `tests/cli_gate.rs` (create) | end-to-end exit-code tests against the built binary |
| `samples/ascent-policy.example.yaml` (create) | example policy |
| `docs/ci/github-actions.yml`, `docs/followups-policy-gate.md`, `README.md` (create/modify) | CI docs + deferred milestones |
| `src/dashboard/read.rs`, `src/bin/dashboard.rs` (modify) | `read_gate`, `GET /api/gate` |
| `frontend/src/api.ts`, `components/PolicyGate.tsx` (+test), `App.tsx`, `screens/Audit.tsx` (+test), `screens/NewScan.tsx`, `styles/glass.css` (modify/create) | Policy gate card, audit rendering, copy |

---

### Task 1: Scanner exit integrity, run status, and SCA fix versions

**Files:**
- Modify: `src/runner.rs` (`ToolRunner::run_json`, tests)
- Modify: `src/stages/sast.rs` (signature + gitleaks args + tests)
- Modify: `src/normalise.rs` (`normalise_trivy` + tests in `mod sast_tests`)
- Create: `src/runstatus.rs`
- Modify: `src/pipeline.rs` (`Summary`, `run_pipeline`, tests), `src/main.rs` (`mod runstatus;`, print new summary fields)

**Interfaces:**
- Produces:
  - `pub struct SastOutcome { pub findings: Vec<Finding>, pub failed_tools: Vec<String>, pub skipped_tools: Vec<String> }` and `pub fn sast(runner: &dyn Runner, source_dir: &str) -> Result<SastOutcome, Box<dyn std::error::Error>>`
  - `crate::runstatus::{RunStatus, write_run_status, read_run_status, now_ts}`:
    ```rust
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct RunStatus { pub complete: bool, pub dry_run: bool,
        #[serde(default)] pub failed_tools: Vec<String>,
        #[serde(default)] pub skipped_tools: Vec<String>,
        #[serde(default)] pub finished_at: String }
    pub fn write_run_status(out_dir: &str, s: &RunStatus) -> std::io::Result<()>
    pub fn read_run_status(out_dir: &str) -> Option<RunStatus>
    pub fn now_ts() -> String
    ```
  - `Summary` gains `pub complete: bool, pub failed_tools: Vec<String>`.
  - trivy `Finding.evidence` = `"pkg=<name> installed=<ver> fixed=<ver|none> purl=<purl>"`; `Finding.id` stays version-free.

- [ ] **Step 1: Write the failing runner tests** — add to `mod tests` in `src/runner.rs`:

```rust
    #[test]
    fn run_json_errors_when_the_tool_exits_non_zero() {
        // `git` is present wherever this repo builds; an unknown flag exits 129.
        let r = runner(false);
        let err = r
            .run_json("git", &["--definitely-not-a-flag".into()], &[])
            .unwrap_err();
        assert!(err.to_string().contains("git exited with"), "{err}");
    }

    #[test]
    fn run_json_is_ok_on_a_zero_exit() {
        let r = runner(false);
        assert!(r.run_json("git", &["--version".into()], &[]).is_ok());
    }
```

- [ ] **Step 2: Run them** — `cargo test --bin ascent runner::tests` → `run_json_errors_when_the_tool_exits_non_zero` FAILS (no error today).

- [ ] **Step 3: Implement** — in `ToolRunner::run_json`, replace the last two lines with:

```rust
        let out = Command::new(tool).args(args).output()?;
        // A scanner that exits non-zero has FAILED. (gitleaks runs with
        // `--exit-code 0`, so "leaks found" is never a non-zero exit; opengrep and
        // trivy exit 0 with findings — verified against opengrep 1.30, gitleaks 8,
        // trivy 0.6x.) Treating it as an error means a crashed scanner can never
        // look like "0 findings" to the policy gate.
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
            return Err(format!("{tool} exited with {}: {}", out.status, last.trim()).into());
        }
        Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout)))
```

- [ ] **Step 4: Update SAST tests first (failing)** — in `src/stages/sast.rs` tests: change every `sast(&f, ".").unwrap()` used as a Vec to `sast(&f, ".").unwrap().findings` (`sast_runs_only_available_tools_and_merges`, `sast_with_no_tools_is_empty` → `assert!(sast(&f, ".").unwrap().findings.is_empty())`, `sast_survives_one_tool_erroring_and_keeps_the_others`). Add to `sast_survives_one_tool_erroring_and_keeps_the_others`:

```rust
        let out = sast(&f, ".").unwrap();
        assert_eq!(out.failed_tools, vec!["opengrep".to_string()]);
        let tools: Vec<&str> = out.findings.iter().map(|x| x.tool.as_str()).collect();
```

  Add to `sast_runs_only_available_tools_and_merges`: `assert_eq!(out.skipped_tools, vec!["gitleaks".to_string()]);` and to `sast_uses_portable_flags`:

```rust
        // gitleaks: findings must not change the exit status (only errors do).
        let j = gl.iter().position(|a| a == "--exit-code").unwrap();
        assert_eq!(gl[j + 1], "0");
```

- [ ] **Step 5: Implement `SastOutcome`** — in `src/stages/sast.rs`:

```rust
/// What the SAST track produced, and which analysers did not complete.
#[derive(Debug, Default)]
pub struct SastOutcome {
    pub findings: Vec<Finding>,
    /// Analysers that were present but errored: the run is INCOMPLETE.
    pub failed_tools: Vec<String>,
    /// Analysers not installed: coverage note only.
    pub skipped_tools: Vec<String>,
}
```

  Change `sast` to return `Result<SastOutcome, ...>`: start with `let mut o = SastOutcome::default();`; for each tool, `if tool_available(...) { ... } else { o.skipped_tools.push("<tool>".into()); }`; in each `Err(_) =>` arm also `o.failed_tools.push("<tool>".into());`; push findings into `o.findings`; return `Ok(o)`. Insert `"--exit-code".into(), "0".into(),` right after `"--no-git".into(),` in the gitleaks args.

- [ ] **Step 6: Write failing trivy enrichment tests** — in `src/normalise.rs` `mod sast_tests`:

```rust
    #[test]
    fn trivy_keeps_installed_and_fixed_versions() {
        let rows = vec![json!({"Results":[{"Target":"package-lock.json","Vulnerabilities":[{
            "VulnerabilityID":"CVE-2021-3749","PkgName":"axios","InstalledVersion":"0.21.1",
            "FixedVersion":"0.21.2","PkgIdentifier":{"PURL":"pkg:npm/axios@0.21.1"},
            "Severity":"HIGH","Title":"axios ReDoS"}]}]})];
        let out = normalise_trivy(&rows);
        assert_eq!(
            out[0].evidence,
            "pkg=axios installed=0.21.1 fixed=0.21.2 purl=pkg:npm/axios@0.21.1"
        );
        // id stays version-free so a fingerprint survives an upgrade that keeps the CVE
        assert!(!out[0].id.contains("0.21.1"), "{}", out[0].id);
    }

    #[test]
    fn trivy_without_a_fix_says_none() {
        let rows = vec![json!({"Results":[{"Target":"go.mod","Vulnerabilities":[{
            "VulnerabilityID":"CVE-1","PkgName":"x","InstalledVersion":"1.0.0","Severity":"LOW"}]}]})];
        assert_eq!(normalise_trivy(&rows)[0].evidence, "pkg=x installed=1.0.0 fixed=none purl=");
    }
```

- [ ] **Step 7: Implement** — in `normalise_trivy`, replace `evidence: String::new(),` with:

```rust
                    evidence: format!(
                        "pkg={pkg} installed={} fixed={} purl={}",
                        v["InstalledVersion"].as_str().unwrap_or(""),
                        v["FixedVersion"].as_str().filter(|s| !s.is_empty()).unwrap_or("none"),
                        v["PkgIdentifier"]["PURL"].as_str().unwrap_or(""),
                    ),
```

- [ ] **Step 8: Create `src/runstatus.rs`**:

```rust
//! `<out>/run.json`: whether every scanner in the last run completed. The
//! policy gate refuses to pass an incomplete run (exit 3). It is reset to
//! "incomplete" at the start of every run, so a crashed run stays incomplete.
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunStatus {
    pub complete: bool,
    pub dry_run: bool,
    #[serde(default)]
    pub failed_tools: Vec<String>,
    #[serde(default)]
    pub skipped_tools: Vec<String>,
    #[serde(default)]
    pub finished_at: String,
}

pub fn write_run_status(out_dir: &str, s: &RunStatus) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(s).map_err(std::io::Error::other)? + "\n";
    crate::triage::write_atomic(&Path::new(out_dir).join("run.json"), text.as_bytes())
}

/// `None` when missing or unparseable — callers treat that as incomplete.
pub fn read_run_status(out_dir: &str) -> Option<RunStatus> {
    std::fs::read_to_string(Path::new(out_dir).join("run.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

pub fn now_ts() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    crux::audit::format_ts(d.as_secs(), d.subsec_micros())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_and_missing_is_none() {
        let dir = std::env::temp_dir().join(format!("ascent_runstatus_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();
        assert_eq!(read_run_status(d), None);
        let s = RunStatus { complete: true, dry_run: false, failed_tools: vec![],
            skipped_tools: vec!["gitleaks".into()], finished_at: now_ts() };
        write_run_status(d, &s).unwrap();
        assert_eq!(read_run_status(d), Some(s));
        std::fs::write(dir.join("run.json"), "not json").unwrap();
        assert_eq!(read_run_status(d), None);
    }
}
```

  Add `mod runstatus;` to `src/main.rs` (alphabetical, after `mod runner;`).

- [ ] **Step 9: Write failing pipeline tests** — in `src/pipeline.rs` tests:

```rust
    #[test]
    fn dry_run_writes_an_incomplete_run_status() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None).unwrap();
        assert!(!s.complete);
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(!st.complete && st.dry_run);
    }

    #[test]
    fn full_run_writes_a_complete_run_status() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None).unwrap();
        assert!(s.complete && s.failed_tools.is_empty());
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(st.complete && !st.dry_run && !st.finished_at.is_empty());
    }
```

- [ ] **Step 10: Implement in `run_pipeline`** — add `use crate::runstatus::{now_ts, write_run_status, RunStatus};`. Right after the `queue.json` reset:

```rust
    // Reset the run status to "incomplete" so a run that dies part-way can never
    // leave a previous run's "complete" behind for the policy gate to trust.
    write_run_status(out_dir, &RunStatus { complete: false, dry_run, failed_tools: vec![],
        skipped_tools: vec![], finished_at: String::new() })?;
```

  Replace the SAST block with:

```rust
    let mut failed_tools = Vec::new();
    let mut skipped_tools = Vec::new();
    if let Some(src) = eff_source.as_deref() {
        if !dry_run {
            let o = sast(runner, src)?;
            findings.extend(o.findings);
            failed_tools = o.failed_tools;
            skipped_tools = o.skipped_tools;
        }
    }
```

  (If `eff_source` is `Option<String>`, `as_deref()` gives `Option<&str>`; adapt if it is already `Option<&str>`.) After writing `report.md`:

```rust
    let complete = !dry_run && failed_tools.is_empty();
    write_run_status(out_dir, &RunStatus { complete, dry_run, failed_tools: failed_tools.clone(),
        skipped_tools, finished_at: now_ts() })?;
```

  Add `complete, failed_tools,` to the returned `Summary` and the two fields to `pub struct Summary`. In `src/main.rs` after the existing `println!("urls=…")`, add:

```rust
            if !s.complete {
                println!("run INCOMPLETE (dry run or failed scanners: {:?})", s.failed_tools);
            }
```

- [ ] **Step 11: Run everything** — `cargo test` → all pass (both binaries).

- [ ] **Step 12: Commit**

```bash
git add src/runner.rs src/stages/sast.rs src/normalise.rs src/runstatus.rs src/pipeline.rs src/main.rs
git commit -m "feat(pipeline): fail closed on scanner errors, record run status, keep SCA fix versions" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `ascent/v1` finding fingerprints

**Files:**
- Create: `src/gate/mod.rs`, `src/gate/fingerprint.rs`
- Modify: `src/main.rs` (`mod gate;`)

**Interfaces:**
- Consumes: queue finding objects (Crux `--emit-json` shape: `id, tool, rule_id, severity, title, message, url, file, line, category, cwe, code`).
- Produces (`crate::gate::fingerprint`):
  - `pub const VERSION: &str = "ascent/v1";`
  - `pub fn kind(f: &Value) -> &'static str` → `"secret" | "sca" | "dast" | "sast"`
  - `pub fn normalise_path(p: &str, root: Option<&str>) -> String`
  - `pub fn normalise_url(raw: &str) -> String`
  - `pub fn fingerprints(findings: &[Value], root: Option<&str>) -> Vec<String>` (each `"ascent/v1:<64 hex>"`, same order as input)

- [ ] **Step 1: Create `src/gate/mod.rs`**:

```rust
//! The policy gate: fingerprints, policy, and the decision engine.
pub mod fingerprint;
```

  Add `mod gate;` to `src/main.rs` (after `mod gatesio;`).

- [ ] **Step 2: Write `src/gate/fingerprint.rs` with tests first** (implementation stubs `todo!()` are NOT allowed in the final commit; write tests, run them failing against `unimplemented!()` bodies, then implement). Tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sast(rule: &str, file: &str, line: i64, code: &str) -> Value {
        json!({"id":"x","tool":"opengrep","rule_id":rule,"severity":"HIGH","file":file,
               "line":line,"url":"","category":"SAST","code":code})
    }
    fn one(f: Value) -> String { fingerprints(&[f], None).remove(0) }

    #[test]
    fn has_version_prefix() {
        let fp = one(sast("r", "a.py", 1, "x()"));
        assert!(fp.starts_with("ascent/v1:") && fp.len() == "ascent/v1:".len() + 64, "{fp}");
    }
    #[test]
    fn sast_survives_line_shift_and_whitespace() {
        assert_eq!(one(sast("r", "a.py", 10, "q( x )")), one(sast("r", "a.py", 42, "q(x)")));
    }
    #[test]
    fn sast_changes_with_rule_path_or_code() {
        let base = one(sast("r", "a.py", 1, "q(x)"));
        assert_ne!(base, one(sast("r2", "a.py", 1, "q(x)")));
        assert_ne!(base, one(sast("r", "b.py", 1, "q(x)")));
        assert_ne!(base, one(sast("r", "a.py", 1, "q(y)")));
    }
    #[test]
    fn sast_without_code_falls_back_to_line() {
        assert_ne!(one(sast("r", "a.py", 1, "")), one(sast("r", "a.py", 2, "")));
    }
    #[test]
    fn secret_ignores_line_and_code() {
        let s = |line: i64, code: &str| json!({"id":"g","tool":"gitleaks","rule_id":"aws",
            "file":"c.py","line":line,"url":"","code":code});
        assert_eq!(one(s(2, "")), one(s(9, "AKIAEXAMPLE")));
    }
    #[test]
    fn sca_ignores_installed_version() {
        let s = |ev: &str| json!({"id":"trivy:CVE-1:package-lock.json:axios","tool":"trivy",
            "rule_id":"CVE-1","file":"package-lock.json","line":0,"url":"","code":ev});
        assert_eq!(one(s("pkg=axios installed=0.21.1")), one(s("pkg=axios installed=0.21.2")));
    }
    #[test]
    fn dast_ignores_query_values_ids_and_host_case() {
        let d = |u: &str| json!({"id":"n","tool":"nuclei","rule_id":"sqli","url":u,"file":"","line":0});
        assert_eq!(
            one(d("https://App.Example.com/users/42?b=2&a=1")),
            one(d("https://app.example.com/users/7?a=9&b=3"))
        );
        assert_ne!(one(d("https://app.example.com/users/42?a=1")),
                   one(d("https://app.example.com/users/42?c=1")));
    }
    #[test]
    fn identical_findings_get_distinct_stable_fingerprints() {
        let f = sast("r", "a.py", 1, "q(x)");
        let fps = fingerprints(&[f.clone(), f.clone()], None);
        assert_ne!(fps[0], fps[1]);
        assert_eq!(fps, fingerprints(&[f.clone(), f], None));
    }
    #[test]
    fn root_and_separators_are_normalised() {
        assert_eq!(normalise_path(".\\src\\a.py", Some("./src")), "a.py");
        assert_eq!(normalise_path("src/a.py", Some("src/")), "a.py");
        assert_eq!(normalise_path("./lib/b.rs", None), "lib/b.rs");
        assert_eq!(one(sast("r", "src\\a.py", 1, "x")), one(sast("r", "src/a.py", 1, "x")));
    }
    #[test]
    fn url_normalisation() {
        assert_eq!(normalise_url("HTTPS://Ex.com:443/a/123/b?z=1&y=2#f"), "https://ex.com/a/{}/b?y&z");
        assert_eq!(normalise_url("http://ex.com:8080/u/550e8400-e29b-41d4-a716-446655440000"),
                   "http://ex.com:8080/u/{}");
        assert_eq!(normalise_url("not a url"), "not a url");
    }
    #[test]
    fn kinds() {
        assert_eq!(kind(&json!({"tool":"gitleaks"})), "secret");
        assert_eq!(kind(&json!({"tool":"trivy"})), "sca");
        assert_eq!(kind(&json!({"tool":"nuclei","url":"https://x/"})), "dast");
        assert_eq!(kind(&json!({"tool":"opengrep","url":""})), "sast");
    }
}
```

- [ ] **Step 3: Run** — `cargo test --bin ascent gate::fingerprint` → FAIL.

- [ ] **Step 4: Implement** (top of `src/gate/fingerprint.rs`):

```rust
//! `ascent/v1` finding fingerprints: stable across line shifts, whitespace,
//! query values and dependency upgrades, so the gate, SARIF and (later)
//! baselines recognise the same finding run after run. Secrets are keyed on
//! rule + path + occurrence only: no secret value or hash of one, ever.
use serde_json::{json, Value};
use std::collections::HashMap;

pub const VERSION: &str = "ascent/v1";

fn s<'a>(f: &'a Value, k: &str) -> &'a str {
    f[k].as_str().unwrap_or("")
}

/// `"secret" | "sca" | "dast" | "sast"`.
pub fn kind(f: &Value) -> &'static str {
    match s(f, "tool") {
        "gitleaks" => "secret",
        "trivy" => "sca",
        _ if !s(f, "url").is_empty() => "dast",
        _ => "sast",
    }
}

fn strip_dot(mut p: &str) -> &str {
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p
}

/// Forward slashes, no leading `./`, and the source root prefix removed.
pub fn normalise_path(p: &str, root: Option<&str>) -> String {
    let p = p.replace('\\', "/");
    let p = strip_dot(&p);
    if let Some(r) = root {
        let r = r.replace('\\', "/");
        let r = strip_dot(r.trim_end_matches('/'));
        if !r.is_empty() && r != "." {
            if let Some(rest) = p.strip_prefix(&format!("{r}/")) {
                return rest.to_string();
            }
        }
    }
    p.to_string()
}

fn is_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn volatile(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.bytes().all(|b| b.is_ascii_digit())
            || is_uuid(seg)
            || (seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Scheme + lowercase host + non-default port + path with ids replaced by `{}`
/// + sorted query *names*. No values, no fragment. Unparseable → trimmed input.
pub fn normalise_url(raw: &str) -> String {
    let Ok(u) = url::Url::parse(raw.trim()) else {
        return raw.trim().to_string();
    };
    let mut out = format!("{}://{}", u.scheme(), u.host_str().unwrap_or("").to_ascii_lowercase());
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    let path: Vec<&str> = u.path().split('/').map(|seg| if volatile(seg) { "{}" } else { seg }).collect();
    out.push_str(&path.join("/"));
    let mut names: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    names.dedup();
    if !names.is_empty() {
        out.push('?');
        out.push_str(&names.join("&"));
    }
    out
}

fn inputs(f: &Value, root: Option<&str>) -> Vec<String> {
    let rule = s(f, "rule_id").to_string();
    let path = normalise_path(s(f, "file"), root);
    match kind(f) {
        "secret" => vec![rule, path],
        // The trivy id is `trivy:<vuln>:<target>:<pkg>`: version-free by construction.
        "sca" => vec![rule, path, s(f, "id").to_string()],
        "dast" => vec![rule, normalise_url(s(f, "url"))],
        _ => {
            let code = f["code"].as_str().or(f["evidence"].as_str()).unwrap_or("");
            let squashed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            let ctx = if squashed.is_empty() {
                format!("line:{}", f["line"].as_i64().unwrap_or(0))
            } else {
                crux::canon::hash_value(&json!(squashed))
            };
            vec![rule, path, ctx]
        }
    }
}

/// One fingerprint per finding, in input order. Identical findings in one run
/// are told apart by their occurrence index.
pub fn fingerprints(findings: &[Value], root: Option<&str>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    findings
        .iter()
        .map(|f| {
            let base = crux::canon::hash_value(&json!([VERSION, kind(f), inputs(f, root)]));
            let n = seen.entry(base.clone()).or_insert(0);
            let idx = *n;
            *n += 1;
            format!("{VERSION}:{}", crux::canon::hash_value(&json!([base, idx])))
        })
        .collect()
}
```

- [ ] **Step 5: Run** — `cargo test --bin ascent gate::fingerprint` → PASS; `cargo test` → all pass.

- [ ] **Step 6: Commit**

```bash
git add src/gate/mod.rs src/gate/fingerprint.rs src/main.rs
git commit -m "feat(gate): ascent/v1 finding fingerprints" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Policy schema, loader and example policy

**Files:**
- Create: `src/gate/policy.rs`, `samples/ascent-policy.example.yaml`
- Modify: `src/gate/mod.rs` (`pub mod policy;`)

**Interfaces:**
- Produces (`crate::gate::policy`):
  ```rust
  pub enum FpMode { DemoteToWarn, Enforce }              // serde snake_case
  pub struct FailRule { pub severity: Vec<String>, pub categories: Vec<String>, pub cwe: Vec<String> }
  pub struct WarnRule { pub severity: Vec<String>, pub cwe: Vec<String> }
  pub struct TriagePolicy { pub likely_false_positive: FpMode }
  pub struct Policy { pub version: u32, pub name: String, pub fail_on: FailRule,
                      pub warn_on: WarnRule, pub triage: TriagePolicy }
  pub const CATEGORIES: [&str; 4] = ["SAST", "SCA", "SECRETS", "DAST"];
  pub fn parse_policy(text: &str) -> Result<Policy, String>
  pub fn load_policy(path: &str) -> Result<Policy, String>
  pub fn policy_hash(p: &Policy) -> String
  ```
  All structs derive `Debug, Clone, PartialEq, Serialize, Deserialize` with `#[serde(deny_unknown_fields)]`. Severity/category/CWE strings are stored uppercase.

- [ ] **Step 1: Create the example policy** `samples/ascent-policy.example.yaml`:

```yaml
# Ascent policy (version 1). Evaluated by `ascent run --policy FILE` or
# `ascent gate --policy FILE`. Unknown keys are an error (exit 2) so a typo can
# never silently weaken the gate.
version: 1
name: default
fail_on:
  # A matching finding fails the gate (exit 1).
  severity: [CRITICAL, HIGH]
  categories: [SAST, SCA, SECRETS, DAST]
  cwe: [CWE-798]          # hardcoded credentials fail at any severity
warn_on:
  # A matching finding makes the gate CONDITIONAL (exit 0, or 1 with --fail-on-warn).
  severity: [MEDIUM]
  cwe: []
triage:
  # demote_to_warn: a fail_on match triaged LIKELY_FALSE_POSITIVE becomes a warning.
  # enforce: it fails like any other. A likely-FP is never silently passed.
  likely_false_positive: demote_to_warn
```

- [ ] **Step 2: Write failing tests** in `src/gate/policy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_policy_parses() {
        let p = load_policy(concat!(env!("CARGO_MANIFEST_DIR"), "/samples/ascent-policy.example.yaml")).unwrap();
        assert_eq!(p.name, "default");
        assert_eq!(p.fail_on.severity, vec!["CRITICAL", "HIGH"]);
        assert_eq!(p.fail_on.cwe, vec!["CWE-798"]);
        assert_eq!(p.triage.likely_false_positive, FpMode::DemoteToWarn);
    }
    #[test]
    fn minimal_policy_gets_safe_defaults() {
        let p = parse_policy("version: 1\n").unwrap();
        assert_eq!(p.name, "default");
        assert_eq!(p.fail_on.categories, CATEGORIES.to_vec());
        assert!(p.fail_on.severity.is_empty() && p.warn_on.severity.is_empty());
        assert_eq!(p.triage.likely_false_positive, FpMode::DemoteToWarn);
    }
    #[test]
    fn values_are_case_normalised() {
        let p = parse_policy("version: 1\nfail_on:\n  severity: [high]\n  categories: [sast]\n  cwe: [cwe-89]\n").unwrap();
        assert_eq!(p.fail_on.severity, vec!["HIGH"]);
        assert_eq!(p.fail_on.categories, vec!["SAST"]);
        assert_eq!(p.fail_on.cwe, vec!["CWE-89"]);
    }
    #[test]
    fn rejects_everything_suspicious() {
        for bad in [
            "version: 2\n",
            "name: x\n",                                           // version missing
            "version: 1\ngrace_days: {HIGH: 7}\n",                 // future key, top level
            "version: 1\nfail_on:\n  sevrity: [HIGH]\n",           // typo
            "version: 1\nfail_on:\n  severity: [SEVERE]\n",
            "version: 1\nfail_on:\n  categories: [LICENSE]\n",
            "version: 1\nfail_on:\n  cwe: ['89']\n",
            "version: 1\nwarn_on:\n  categories: [SAST]\n",        // warn_on has no categories
            "version: 1\ntriage:\n  likely_false_positive: ignore\n",
            "version: 1\nfail_on:\n  categories: []\n",            // would evaluate nothing
            ": : :",
        ] {
            assert!(parse_policy(bad).is_err(), "accepted bad policy: {bad:?}");
        }
    }
    #[test]
    fn load_reports_missing_file() {
        let e = load_policy("definitely/not/here.yaml").unwrap_err();
        assert!(e.contains("cannot read policy"), "{e}");
    }
    #[test]
    fn hash_is_stable_and_content_sensitive() {
        let a = parse_policy("version: 1\nfail_on:\n  severity: [HIGH]\n").unwrap();
        let b = parse_policy("version: 1\nfail_on:\n  severity: [high]\n").unwrap();
        let c = parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL]\n").unwrap();
        assert_eq!(policy_hash(&a), policy_hash(&b));
        assert_ne!(policy_hash(&a), policy_hash(&c));
        assert_eq!(policy_hash(&a).len(), 64);
    }
}
```

- [ ] **Step 3: Run** — `cargo test --bin ascent gate::policy` → FAIL.

- [ ] **Step 4: Implement** (top of `src/gate/policy.rs`):

```rust
//! Policy-as-code for the gate. Fail closed: any unknown key, wrong version or
//! unrecognised value is an error (the CLI maps it to exit 2).
use serde::{Deserialize, Serialize};

pub const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
pub const CATEGORIES: [&str; 4] = ["SAST", "SCA", "SECRETS", "DAST"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FpMode {
    #[default]
    DemoteToWarn,
    Enforce,
}

fn all_categories() -> Vec<String> {
    CATEGORIES.iter().map(|c| c.to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailRule {
    #[serde(default)]
    pub severity: Vec<String>,
    #[serde(default = "all_categories")]
    pub categories: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}
impl Default for FailRule {
    fn default() -> Self {
        FailRule { severity: vec![], categories: all_categories(), cwe: vec![] }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WarnRule {
    #[serde(default)]
    pub severity: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TriagePolicy {
    #[serde(default)]
    pub likely_false_positive: FpMode,
}

fn default_name() -> String {
    "default".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default)]
    pub fail_on: FailRule,
    #[serde(default)]
    pub warn_on: WarnRule,
    #[serde(default)]
    pub triage: TriagePolicy,
}

fn upper_all(v: &mut [String]) {
    for s in v.iter_mut() {
        *s = s.trim().to_ascii_uppercase();
    }
}

fn check_in(field: &str, vals: &[String], allowed: &[&str]) -> Result<(), String> {
    match vals.iter().find(|v| !allowed.contains(&v.as_str())) {
        Some(bad) => Err(format!("{field}: unknown value {bad:?} (allowed: {})", allowed.join(", "))),
        None => Ok(()),
    }
}

fn check_cwe(field: &str, vals: &[String]) -> Result<(), String> {
    for v in vals {
        let ok = v.strip_prefix("CWE-").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            return Err(format!("{field}: {v:?} is not a CWE id like CWE-89"));
        }
    }
    Ok(())
}

pub fn parse_policy(text: &str) -> Result<Policy, String> {
    let mut p: Policy = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;
    if p.version != 1 {
        return Err(format!("unsupported policy version {} (expected 1)", p.version));
    }
    upper_all(&mut p.fail_on.severity);
    upper_all(&mut p.fail_on.categories);
    upper_all(&mut p.fail_on.cwe);
    upper_all(&mut p.warn_on.severity);
    upper_all(&mut p.warn_on.cwe);
    check_in("fail_on.severity", &p.fail_on.severity, &SEVERITIES)?;
    check_in("warn_on.severity", &p.warn_on.severity, &SEVERITIES)?;
    check_in("fail_on.categories", &p.fail_on.categories, &CATEGORIES)?;
    if p.fail_on.categories.is_empty() {
        return Err("fail_on.categories is empty: the gate would evaluate nothing".into());
    }
    check_cwe("fail_on.cwe", &p.fail_on.cwe)?;
    check_cwe("warn_on.cwe", &p.warn_on.cwe)?;
    Ok(p)
}

pub fn load_policy(path: &str) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read policy {path}: {e}"))?;
    parse_policy(&text).map_err(|e| format!("invalid policy {path}: {e}"))
}

/// SHA-256 of the canonical JSON of the *parsed, normalised* policy, recorded
/// in gate.json and the audit log so the verdict proves which policy decided.
pub fn policy_hash(p: &Policy) -> String {
    crux::canon::hash_value(&serde_json::to_value(p).expect("policy serialises"))
}
```

  Add `pub mod policy;` to `src/gate/mod.rs`.

- [ ] **Step 5: Run** — `cargo test --bin ascent gate::policy` → PASS; `cargo test` → all pass.

- [ ] **Step 6: Commit**

```bash
git add src/gate/policy.rs src/gate/mod.rs samples/ascent-policy.example.yaml
git commit -m "feat(gate): fail-closed policy schema and example policy" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Gate evaluation, gate.json and audit chaining

**Files:**
- Create: `src/gate/evaluate.rs`
- Modify: `src/gate/mod.rs` (`pub mod evaluate;`)

**Interfaces:**
- Consumes: `fingerprint::{fingerprints, kind}`, `policy::{Policy, FpMode, policy_hash}`, `crate::runstatus::RunStatus`, `crate::gatesio::append_chained(audit_path: &str, body: serde_json::Map<String, Value>) -> Result<(), Box<dyn Error>>`, `crate::triage::write_atomic(&Path, &[u8]) -> io::Result<()>`.
- Produces (`crate::gate::evaluate`):
  ```rust
  #[serde(rename_all = "UPPERCASE")] pub enum Decision { Pass, Conditional, Fail, Incomplete }
  pub struct GateEntry { pub fingerprint, pub rule_id, pub severity, pub category, pub title, pub locus, pub reason: String }
  pub struct Counts { pub evaluated: usize, pub failed: usize, pub warned: usize, pub demoted_fp: usize }
  pub struct GateResult { pub decision: Decision, pub exit_code: u8, pub complete: bool, pub counts: Counts,
                          pub failed: Vec<GateEntry>, pub warned: Vec<GateEntry> }
  pub fn category_of(f: &Value) -> String
  pub fn evaluate(items: &[Value], policy: &Policy, status: Option<&RunStatus>, fail_on_warn: bool) -> GateResult
  pub fn gate_document(policy: &Policy, r: &GateResult, status: Option<&RunStatus>, ts: &str) -> Value
  pub enum WriteGateError { Integrity(String), Io(String) }
  pub fn write_gate(out_dir: &str, doc: &Value) -> Result<(), WriteGateError>
  pub fn read_queue(out_dir: &str) -> Result<Vec<Value>, String>
  ```
  `items` are queue entries `{finding: {...}, verdict, confidence, fp_likelihood, rationale, remediation}`.

- [ ] **Step 1: Write failing tests** in `src/gate/evaluate.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::policy::parse_policy;
    use serde_json::json;

    fn item(tool: &str, sev: &str, cwe: &str, verdict: &str) -> Value {
        json!({"finding": {"id": format!("{tool}:{sev}"), "tool": tool, "rule_id": "r",
            "severity": sev, "title": "t", "message": "m", "url": "", "file": "a.py",
            "line": 3, "category": if tool == "trivy" {"SCA"} else {"SAST"}, "cwe": cwe, "code": "q()"},
            "verdict": verdict, "confidence": 0.9, "fp_likelihood": 0.1, "rationale": "r", "remediation": "x"})
    }
    fn policy() -> Policy {
        parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL, HIGH]\n  cwe: [CWE-798]\nwarn_on:\n  severity: [MEDIUM]\n").unwrap()
    }
    fn done() -> RunStatus {
        RunStatus { complete: true, dry_run: false, failed_tools: vec![], skipped_tools: vec![], finished_at: "t".into() }
    }

    #[test]
    fn empty_complete_run_passes() {
        let r = evaluate(&[], &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Pass, 0));
    }
    #[test]
    fn high_true_positive_fails() {
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Fail, 1));
        assert_eq!(r.failed[0].reason, "severity HIGH in fail_on");
        assert!(r.failed[0].fingerprint.starts_with("ascent/v1:"));
        assert_eq!(r.failed[0].locus, "a.py:3");
    }
    #[test]
    fn cwe_rule_fails_a_low_secret_and_categorises_it() {
        let r = evaluate(&[item("gitleaks", "LOW", "CWE-798", "ABSTAIN")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
        assert_eq!(r.failed[0].category, "SECRETS");
        assert_eq!(r.failed[0].reason, "CWE-798 in fail_on");
    }
    #[test]
    fn medium_is_conditional_and_fail_on_warn_exits_1() {
        let items = [item("opengrep", "MEDIUM", "", "TRUE_POSITIVE")];
        let r = evaluate(&items, &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Conditional, 0));
        assert_eq!(evaluate(&items, &policy(), Some(&done()), true).exit_code, 1);
    }
    #[test]
    fn likely_false_positive_is_demoted_never_dropped() {
        let items = [item("opengrep", "CRITICAL", "", "LIKELY_FALSE_POSITIVE")];
        let r = evaluate(&items, &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Conditional);
        assert_eq!((r.counts.demoted_fp, r.warned.len(), r.failed.len()), (1, 1, 0));
        assert!(r.warned[0].reason.contains("demoted"));
        let enforce = parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL]\ntriage:\n  likely_false_positive: enforce\n").unwrap();
        assert_eq!(evaluate(&items, &enforce, Some(&done()), false).decision, Decision::Fail);
    }
    #[test]
    fn incomplete_or_missing_status_never_passes() {
        let mut st = done();
        st.complete = false;
        let r = evaluate(&[], &policy(), Some(&st), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Incomplete, 3));
        assert_eq!(evaluate(&[], &policy(), None, false).decision, Decision::Incomplete);
        // findings are still listed so a human can see them
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &policy(), None, false);
        assert_eq!((r.decision, r.failed.len()), (Decision::Incomplete, 1));
    }
    #[test]
    fn category_filter_excludes_findings() {
        let only_sca = parse_policy("version: 1\nfail_on:\n  severity: [HIGH]\n  categories: [SCA]\n").unwrap();
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &only_sca, Some(&done()), false);
        assert_eq!((r.decision, r.counts.evaluated), (Decision::Pass, 0));
    }

    fn tmp() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("ascent_gate_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
    }

    #[test]
    fn write_gate_records_a_verifiable_audit_entry() {
        let dir = tmp();
        let p = policy();
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &p, Some(&done()), false);
        let doc = gate_document(&p, &r, Some(&done()), "2026-10-30T00:00:00.000000+00:00");
        assert_eq!(doc["decision"], "FAIL");
        assert_eq!(doc["policy"]["hash"], crate::gate::policy::policy_hash(&p));
        write_gate(&dir, &doc).unwrap();
        let stored: Value = serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(&dir).join("gate.json")).unwrap()).unwrap();
        assert_eq!(stored, doc);
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        assert!(crux::AuditLog::new(&audit).verify().0);
        let last: Value = serde_json::from_str(std::fs::read_to_string(&audit).unwrap().lines().last().unwrap()).unwrap();
        assert_eq!(last["type"], "gate_evaluation");
        assert_eq!(last["decision"], "FAIL");
        assert_eq!(last["gate_hash"], crux::canon::hash_value(&doc));
    }
    #[test]
    fn broken_chain_refuses_and_writes_no_gate() {
        let dir = tmp();
        std::fs::write(std::path::Path::new(&dir).join("audit.jsonl"), "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n").unwrap();
        let p = policy();
        let r = evaluate(&[], &p, Some(&done()), false);
        let doc = gate_document(&p, &r, Some(&done()), "t");
        assert!(matches!(write_gate(&dir, &doc), Err(WriteGateError::Integrity(_))));
        assert!(!std::path::Path::new(&dir).join("gate.json").exists());
    }
    #[test]
    fn read_queue_requires_an_array() {
        let dir = tmp();
        assert!(read_queue(&dir).is_err());
        std::fs::write(std::path::Path::new(&dir).join("queue.json"), "{}").unwrap();
        assert!(read_queue(&dir).is_err());
        std::fs::write(std::path::Path::new(&dir).join("queue.json"), "[]").unwrap();
        assert!(read_queue(&dir).unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Run** — `cargo test --bin ascent gate::evaluate` → FAIL.

- [ ] **Step 3: Implement** (top of `src/gate/evaluate.rs`):

```rust
//! The gate decision: policy × triaged findings × run completeness →
//! PASS / CONDITIONAL / FAIL / INCOMPLETE, written to gate.json and chained
//! into audit.jsonl so the verdict is tamper-evident.
use super::fingerprint::{fingerprints, kind};
use super::policy::{policy_hash, FpMode, Policy};
use crate::runstatus::RunStatus;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Pass,
    Conditional,
    Fail,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub locus: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Counts {
    pub evaluated: usize,
    pub failed: usize,
    pub warned: usize,
    pub demoted_fp: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateResult {
    pub decision: Decision,
    pub exit_code: u8,
    pub complete: bool,
    pub counts: Counts,
    pub failed: Vec<GateEntry>,
    pub warned: Vec<GateEntry>,
}

fn s(f: &Value, k: &str) -> String {
    f[k].as_str().unwrap_or("").to_string()
}

/// `SECRETS` for gitleaks findings, else the finding's own category (upper-cased),
/// falling back to the fingerprint kind.
pub fn category_of(f: &Value) -> String {
    if kind(f) == "secret" {
        return "SECRETS".into();
    }
    let c = s(f, "category").to_ascii_uppercase();
    if !c.is_empty() {
        return c;
    }
    match kind(f) {
        "sca" => "SCA",
        "dast" => "DAST",
        _ => "SAST",
    }
    .into()
}

fn locus(f: &Value) -> String {
    let url = s(f, "url");
    if url.is_empty() {
        format!("{}:{}", s(f, "file"), f["line"].as_i64().unwrap_or(0))
    } else {
        url
    }
}

fn matches(sev: &str, cwe: &str, sevs: &[String], cwes: &[String], rule: &str) -> Option<String> {
    if sevs.iter().any(|x| x == sev) {
        Some(format!("severity {sev} in {rule}"))
    } else if !cwe.is_empty() && cwes.iter().any(|x| x == cwe) {
        Some(format!("{cwe} in {rule}"))
    } else {
        None
    }
}

pub fn evaluate(items: &[Value], policy: &Policy, status: Option<&RunStatus>, fail_on_warn: bool) -> GateResult {
    let findings: Vec<Value> = items.iter().map(|it| it["finding"].clone()).collect();
    let fps = fingerprints(&findings, None);
    let (mut failed, mut warned) = (Vec::new(), Vec::new());
    let mut counts = Counts::default();
    for (i, it) in items.iter().enumerate() {
        let f = &findings[i];
        let category = category_of(f);
        if !policy.fail_on.categories.contains(&category) {
            continue;
        }
        counts.evaluated += 1;
        let sev = s(f, "severity").to_ascii_uppercase();
        let cwe = s(f, "cwe").to_ascii_uppercase();
        let entry = |reason: String| GateEntry {
            fingerprint: fps[i].clone(),
            rule_id: s(f, "rule_id"),
            severity: sev.clone(),
            category: category.clone(),
            title: s(f, "title"),
            locus: locus(f),
            reason,
        };
        let likely_fp = it["verdict"].as_str() == Some("LIKELY_FALSE_POSITIVE");
        if let Some(r) = matches(&sev, &cwe, &policy.fail_on.severity, &policy.fail_on.cwe, "fail_on") {
            if likely_fp && policy.triage.likely_false_positive == FpMode::DemoteToWarn {
                counts.demoted_fp += 1;
                warned.push(entry(format!("{r}; demoted: triaged as likely false positive")));
            } else {
                failed.push(entry(r));
            }
        } else if let Some(r) = matches(&sev, &cwe, &policy.warn_on.severity, &policy.warn_on.cwe, "warn_on") {
            warned.push(entry(r));
        }
    }
    counts.failed = failed.len();
    counts.warned = warned.len();
    let complete = status.is_some_and(|st| st.complete);
    let decision = if !complete {
        Decision::Incomplete
    } else if !failed.is_empty() {
        Decision::Fail
    } else if !warned.is_empty() {
        Decision::Conditional
    } else {
        Decision::Pass
    };
    let exit_code = match decision {
        Decision::Pass => 0,
        Decision::Conditional => u8::from(fail_on_warn),
        Decision::Fail => 1,
        Decision::Incomplete => 3,
    };
    GateResult { decision, exit_code, complete, counts, failed, warned }
}

pub fn gate_document(policy: &Policy, r: &GateResult, status: Option<&RunStatus>, ts: &str) -> Value {
    json!({
        "policy": { "name": policy.name, "hash": policy_hash(policy) },
        "decision": r.decision,
        "exit_code": r.exit_code,
        "complete": r.complete,
        "failed_tools": status.map(|st| st.failed_tools.clone()).unwrap_or_default(),
        "dry_run": status.is_some_and(|st| st.dry_run),
        "counts": r.counts,
        "failed": r.failed,
        "warned": r.warned,
        "evaluated_at": ts,
    })
}

#[derive(Debug)]
pub enum WriteGateError {
    /// The audit chain did not verify: nothing was written (exit 4).
    Integrity(String),
    Io(String),
}

/// Verify the audit chain, write gate.json atomically, then chain a
/// `gate_evaluation` entry binding the document's hash.
pub fn write_gate(out_dir: &str, doc: &Value) -> Result<(), WriteGateError> {
    let dir = Path::new(out_dir);
    let audit = dir.join("audit.jsonl");
    let (ok, msg) = crux::AuditLog::new(&audit).verify();
    if !ok {
        return Err(WriteGateError::Integrity(msg));
    }
    let text = serde_json::to_string_pretty(doc).map_err(|e| WriteGateError::Io(e.to_string()))? + "\n";
    crate::triage::write_atomic(&dir.join("gate.json"), text.as_bytes()).map_err(|e| WriteGateError::Io(e.to_string()))?;
    let mut body = Map::new();
    body.insert("ts".into(), doc["evaluated_at"].clone());
    body.insert("type".into(), Value::from("gate_evaluation"));
    body.insert("decision".into(), doc["decision"].clone());
    body.insert("exit_code".into(), doc["exit_code"].clone());
    body.insert("policy_hash".into(), doc["policy"]["hash"].clone());
    body.insert("gate_hash".into(), Value::from(crux::canon::hash_value(doc)));
    let audit = audit.to_str().ok_or_else(|| WriteGateError::Io("audit path is not UTF-8".into()))?;
    crate::gatesio::append_chained(audit, body).map_err(|e| WriteGateError::Io(e.to_string()))
}

/// The triaged queue. Missing or non-array → Err (the CLI maps it to exit 3).
pub fn read_queue(out_dir: &str) -> Result<Vec<Value>, String> {
    let path = Path::new(out_dir).join("queue.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e} (run `ascent run` first)", path.display()))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Array(items)) => Ok(items),
        _ => Err(format!("{} is not a JSON array", path.display())),
    }
}
```

  Add `pub mod evaluate;` to `src/gate/mod.rs`.

- [ ] **Step 4: Run** — `cargo test --bin ascent gate::` → PASS; `cargo test` → all pass.

- [ ] **Step 5: Commit**

```bash
git add src/gate/evaluate.rs src/gate/mod.rs
git commit -m "feat(gate): policy evaluation, gate.json and chained gate_evaluation audit entry" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Native SARIF 2.1.0 output

**Files:**
- Create: `src/sarif.rs`
- Modify: `src/main.rs` (`mod sarif;`), `src/pipeline.rs` (write SARIF after the report + test)

**Interfaces:**
- Consumes: `crate::gate::fingerprint::{fingerprints, kind, normalise_path}`, `crate::gate::evaluate::category_of` is NOT needed (use `kind`).
- Produces (`crate::sarif`):
  - `pub fn to_sarif(items: &[Value], source_root: Option<&str>) -> (Value, Value)` → `(code_doc, dast_doc)`
  - `pub fn write_sarif(out_dir: &str, items: &[Value], source_root: Option<&str>) -> std::io::Result<()>` → writes `ascent.sarif` and `ascent-dast.sarif`
  - `pub fn item_values(items: &[crate::triage::TriageItem]) -> Vec<Value>` (queue-entry shape) used by the pipeline.

- [ ] **Step 1: Write failing tests** in `src/sarif.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn it(tool: &str, sev: &str, file: &str, line: i64, url: &str, verdict: &str, code: &str) -> Value {
        json!({"finding": {"id": format!("{tool}:{file}{url}"), "tool": tool,
            "rule_id": format!("{tool}.rule"), "severity": sev, "title": "Title",
            "message": "Message", "url": url, "file": file, "line": line,
            "category": "SAST", "cwe": "CWE-89", "code": code},
            "verdict": verdict, "confidence": 0.8, "fp_likelihood": 0.2,
            "rationale": "why", "remediation": "fix it"})
    }

    #[test]
    fn documents_are_valid_sarif_skeletons() {
        let (code, dast) = to_sarif(&[], None);
        for d in [&code, &dast] {
            assert_eq!(d["version"], "2.1.0");
            assert!(d["$schema"].as_str().unwrap().contains("sarif"));
        }
        let ids: Vec<&str> = code["runs"].as_array().unwrap().iter()
            .map(|r| r["automationDetails"]["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["ascent/sast/", "ascent/secrets/", "ascent/sca/"]);
        assert_eq!(dast["runs"][0]["automationDetails"]["id"], "ascent/dast/");
        assert_eq!(code["runs"][0]["tool"]["driver"]["name"], "Ascent");
    }
    #[test]
    fn maps_levels_locations_and_fingerprints() {
        let (code, _) = to_sarif(&[it("opengrep", "HIGH", "./src/db.rs", 0, "", "TRUE_POSITIVE", "q()")], Some("./src"));
        let run = &code["runs"][0];
        let r = &run["results"][0];
        assert_eq!(r["ruleId"], "opengrep.rule");
        assert_eq!(r["level"], "error");
        assert_eq!(r["message"]["text"], "Message");
        let loc = &r["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "db.rs");
        assert_eq!(loc["region"]["startLine"], 1); // line 0 clamps to 1
        assert!(r["partialFingerprints"]["ascentFindingHash/v1"].as_str().unwrap().starts_with("ascent/v1:"));
        let rule = &run["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "opengrep.rule");
        assert_eq!(rule["properties"]["security-severity"], "8.0");
        assert_eq!(rule["properties"]["tags"], json!(["security", "CWE-89"]));
        assert_eq!(r["properties"]["ascent.verdict"], "TRUE_POSITIVE");
    }
    #[test]
    fn severity_table() {
        for (sev, level, score) in [("CRITICAL", "error", Some("9.5")), ("HIGH", "error", Some("8.0")),
                                    ("MEDIUM", "warning", Some("5.5")), ("LOW", "note", Some("2.0")),
                                    ("INFO", "note", None)] {
            assert_eq!(level_of(sev), level);
            assert_eq!(security_severity(sev), score);
        }
    }
    #[test]
    fn likely_false_positive_is_suppressed_under_review() {
        let (code, _) = to_sarif(&[it("opengrep", "HIGH", "a.py", 3, "", "LIKELY_FALSE_POSITIVE", "")], None);
        let sup = &code["runs"][0]["results"][0]["suppressions"][0];
        assert_eq!(sup["kind"], "external");
        assert_eq!(sup["status"], "underReview");
        assert_eq!(sup["justification"], "why");
    }
    #[test]
    fn dast_goes_only_to_the_dast_document() {
        let (code, dast) = to_sarif(&[it("nuclei", "HIGH", "", 0, "https://app.example.com/login", "TRUE_POSITIVE", "")], None);
        assert!(code["runs"].as_array().unwrap().iter().all(|r| r["results"].as_array().unwrap().is_empty()));
        let r = &dast["runs"][0]["results"][0];
        assert_eq!(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "https://app.example.com/login");
    }
    #[test]
    fn categories_split_and_rules_dedupe() {
        let items = [
            it("opengrep", "HIGH", "a.py", 1, "", "TRUE_POSITIVE", "x"),
            it("opengrep", "LOW", "b.py", 2, "", "TRUE_POSITIVE", "y"),
            it("gitleaks", "HIGH", "c.py", 3, "", "TRUE_POSITIVE", ""),
            it("trivy", "MEDIUM", "package-lock.json", 0, "", "TRUE_POSITIVE", "pkg=axios installed=0.21.1 fixed=0.21.2 purl="),
        ];
        let (code, _) = to_sarif(&items, None);
        let runs = code["runs"].as_array().unwrap();
        assert_eq!(runs[0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(runs[0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        // the rule takes the highest severity of its results
        assert_eq!(runs[0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "8.0");
        assert_eq!(runs[1]["results"].as_array().unwrap().len(), 1);
        assert_eq!(runs[2]["results"][0]["properties"]["ascent.sca"], "pkg=axios installed=0.21.1 fixed=0.21.2 purl=");
    }
    #[test]
    fn never_exports_code_or_secret_material() {
        let items = [
            it("gitleaks", "HIGH", "c.py", 3, "", "TRUE_POSITIVE", "AKIASECRETVALUE"),
            it("opengrep", "HIGH", "d.py", 1, "", "TRUE_POSITIVE", "password = 'hunter2'"),
        ];
        let (code, dast) = to_sarif(&items, None);
        let all = format!("{code}{dast}");
        assert!(!all.contains("AKIASECRETVALUE") && !all.contains("hunter2"));
    }
    #[test]
    fn write_sarif_writes_both_files() {
        let dir = std::env::temp_dir().join(format!("ascent_sarif_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_sarif(dir.to_str().unwrap(), &[it("opengrep", "HIGH", "a.py", 1, "", "TRUE_POSITIVE", "")], None).unwrap();
        for f in ["ascent.sarif", "ascent-dast.sarif"] {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap();
            assert_eq!(v["version"], "2.1.0");
        }
    }
}
```

- [ ] **Step 2: Run** — `cargo test --bin ascent sarif` → FAIL.

- [ ] **Step 3: Implement** (top of `src/sarif.rs`):

```rust
//! Native SARIF 2.1.0: `ascent.sarif` (one run per code category, for GitHub
//! code scanning / IDE SARIF viewers) and `ascent-dast.sarif` (URL findings,
//! which GitHub cannot fingerprint). Never exports code snippets or secret
//! material; LIKELY_FALSE_POSITIVE results are suppressed `underReview`.
use crate::gate::fingerprint::{fingerprints, kind, normalise_path};
use serde_json::{json, Map, Value};
use std::path::Path;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const CODE_RUNS: [(&str, &str); 3] = [("sast", "ascent/sast/"), ("secret", "ascent/secrets/"), ("sca", "ascent/sca/")];

fn s(f: &Value, k: &str) -> String {
    f[k].as_str().unwrap_or("").to_string()
}

pub fn level_of(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// GitHub `security-severity` (string). Midpoints avoid the 9.0 band edge.
pub fn security_severity(sev: &str) -> Option<&'static str> {
    match sev {
        "CRITICAL" => Some("9.5"),
        "HIGH" => Some("8.0"),
        "MEDIUM" => Some("5.5"),
        "LOW" => Some("2.0"),
        _ => None,
    }
}

fn rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn result(item: &Value, fp: &str, root: Option<&str>) -> Value {
    let f = &item["finding"];
    let sev = s(f, "severity").to_ascii_uppercase();
    let text = if s(f, "message").is_empty() { s(f, "title") } else { s(f, "message") };
    let location = if kind(f) == "dast" {
        json!({"physicalLocation": {"artifactLocation": {"uri": s(f, "url")}}})
    } else {
        json!({"physicalLocation": {
            "artifactLocation": {"uri": normalise_path(&s(f, "file"), root)},
            "region": {"startLine": f["line"].as_i64().unwrap_or(0).max(1)}}})
    };
    let mut props = Map::new();
    props.insert("ascent.tool".into(), Value::from(s(f, "tool")));
    props.insert("ascent.verdict".into(), item["verdict"].clone());
    props.insert("ascent.confidence".into(), item["confidence"].clone());
    props.insert("ascent.remediation".into(), item["remediation"].clone());
    if kind(f) == "sca" {
        // The trivy version string is the only evidence ever exported.
        props.insert("ascent.sca".into(), Value::from(f["code"].as_str().or(f["evidence"].as_str()).unwrap_or("")));
    }
    let mut r = json!({
        "ruleId": s(f, "rule_id"),
        "level": level_of(&sev),
        "message": {"text": text},
        "locations": [location],
        "partialFingerprints": {"ascentFindingHash/v1": fp},
        "properties": props,
    });
    if item["verdict"].as_str() == Some("LIKELY_FALSE_POSITIVE") {
        r["suppressions"] = json!([{"kind": "external", "status": "underReview",
                                    "justification": item["rationale"].as_str().unwrap_or("")}]);
    }
    r
}

fn run(items: &[(&Value, &String)], automation_id: &str, root: Option<&str>) -> Value {
    // rules: one per rule_id, highest severity of its results
    let mut rules: Vec<(String, Value, String)> = Vec::new(); // (id, finding, max sev)
    for (item, _) in items {
        let f = &item["finding"];
        let id = s(f, "rule_id");
        let sev = s(f, "severity").to_ascii_uppercase();
        match rules.iter_mut().find(|(rid, _, _)| *rid == id) {
            Some(entry) if rank(&sev) > rank(&entry.2) => entry.2 = sev,
            Some(_) => {}
            None => rules.push((id, f.clone(), sev)),
        }
    }
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, f, sev)| {
            let mut tags = vec![Value::from("security")];
            let cwe = s(&f, "cwe");
            if !cwe.is_empty() {
                tags.push(Value::from(cwe));
            }
            let mut props = json!({"tags": tags});
            if let Some(score) = security_severity(&sev) {
                props["security-severity"] = Value::from(score);
            }
            let title: String = s(&f, "title").chars().take(1024).collect();
            json!({"id": id, "name": id, "shortDescription": {"text": title}, "properties": props})
        })
        .collect();
    json!({
        "tool": {"driver": {"name": "Ascent", "informationUri": "https://github.com/Aldiharley/ascent",
                            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": rules}},
        "automationDetails": {"id": automation_id},
        "results": items.iter().map(|(item, fp)| result(item, fp, root)).collect::<Vec<_>>(),
    })
}

fn doc(runs: Vec<Value>) -> Value {
    json!({"$schema": SCHEMA, "version": "2.1.0", "runs": runs})
}

pub fn to_sarif(items: &[Value], source_root: Option<&str>) -> (Value, Value) {
    let findings: Vec<Value> = items.iter().map(|it| it["finding"].clone()).collect();
    let fps = fingerprints(&findings, source_root);
    let pairs: Vec<(&Value, &String)> = items.iter().zip(fps.iter()).collect();
    let of_kind = |k: &str| -> Vec<(&Value, &String)> {
        pairs.iter().filter(|(it, _)| kind(&it["finding"]) == k).cloned().collect()
    };
    let code = doc(CODE_RUNS.iter().map(|(k, id)| run(&of_kind(k), id, source_root)).collect());
    let dast = doc(vec![run(&of_kind("dast"), "ascent/dast/", source_root)]);
    (code, dast)
}

pub fn write_sarif(out_dir: &str, items: &[Value], source_root: Option<&str>) -> std::io::Result<()> {
    let (code, dast) = to_sarif(items, source_root);
    for (name, d) in [("ascent.sarif", code), ("ascent-dast.sarif", dast)] {
        let text = serde_json::to_string_pretty(&d).map_err(std::io::Error::other)? + "\n";
        crate::triage::write_atomic(&Path::new(out_dir).join(name), text.as_bytes())?;
    }
    Ok(())
}

/// Triage items in the queue.json entry shape that `to_sarif`/`evaluate` read.
pub fn item_values(items: &[crate::triage::TriageItem]) -> Vec<Value> {
    items
        .iter()
        .map(|it| json!({"finding": it.finding, "verdict": it.verdict, "confidence": it.confidence,
                         "fp_likelihood": it.fp_likelihood, "rationale": it.rationale,
                         "remediation": it.remediation}))
        .collect()
}
```

  Add `mod sarif;` to `src/main.rs`.

- [ ] **Step 4: Wire into the pipeline (test first)** — add to `src/pipeline.rs` tests:

```rust
    #[test]
    fn pipeline_writes_sarif() {
        let dir = unique_dir();
        run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None).unwrap();
        let read = |n: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(&dir).join(n)).unwrap()).unwrap()
        };
        assert_eq!(read("ascent.sarif")["version"], "2.1.0");
        // FakeRun's nuclei finding is a URL finding: it lands in the DAST file
        assert_eq!(read("ascent-dast.sarif")["runs"][0]["results"].as_array().unwrap().len(), 1);
    }
```

  Then in `run_pipeline`, right after `std::fs::write(&report_path, …)?;`:

```rust
    crate::sarif::write_sarif(out_dir, &crate::sarif::item_values(&items), eff_source.as_deref())?;
```

  (`eff_source` must still be available here: Task 1 changed the SAST block to borrow it with `as_deref()`.)

- [ ] **Step 5: Run** — `cargo test` → all pass.

- [ ] **Step 6: Commit**

```bash
git add src/sarif.rs src/main.rs src/pipeline.rs
git commit -m "feat(sarif): native SARIF 2.1.0 output for code and DAST findings" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: CLI — `--policy`, `gate`, `sarif`, the exit-code contract, and CI docs

**Files:**
- Modify: `src/main.rs`
- Create: `tests/cli_gate.rs`, `docs/ci/github-actions.yml`, `docs/followups-policy-gate.md`
- Modify: `README.md` (new "Policy gate and CI" section before `## License`)

**Interfaces:**
- Consumes: everything above. `exploit::execute::verify_approved` returns `Err("audit chain verification failed: …")` on a broken chain.
- Produces: CLI `ascent run … [--policy FILE] [--fail-on-warn]`, `ascent gate --policy FILE [--out DIR] [--fail-on-warn]`, `ascent sarif [--out DIR] [--source-root DIR]`; process exit codes per Global Constraints.

- [ ] **Step 1: Write failing integration tests** `tests/cli_gate.rs`:

```rust
//! End-to-end exit-code contract against the real `ascent` binary.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static N: AtomicUsize = AtomicUsize::new(0);

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("ascent_cli_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.to_str().unwrap().to_string()
}
const POLICY: &str = "version: 1\nname: ci\nfail_on:\n  severity: [CRITICAL, HIGH]\nwarn_on:\n  severity: [MEDIUM]\n";
fn item(sev: &str) -> Value {
    json!({"finding": {"id": "x", "tool": "opengrep", "rule_id": "r", "severity": sev, "title": "t",
        "message": "m", "url": "", "file": "a.py", "line": 3, "category": "SAST", "cwe": "", "code": "q()"},
        "verdict": "TRUE_POSITIVE", "confidence": 0.9, "fp_likelihood": 0.1, "rationale": "r", "remediation": "x"})
}
fn out_dir(items: Vec<Value>, complete: bool) -> PathBuf {
    let d = tmp();
    write(&d, "queue.json", &Value::from(items).to_string());
    write(&d, "run.json", &json!({"complete": complete, "dry_run": false, "failed_tools": [], "skipped_tools": [], "finished_at": "t"}).to_string());
    d
}
fn gate(dir: &Path, policy_text: &str, extra: &[&str]) -> i32 {
    let p = write(dir, "policy.yaml", policy_text);
    Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args(["gate", "--policy", &p, "--out", dir.to_str().unwrap()])
        .args(extra)
        .status()
        .unwrap()
        .code()
        .unwrap()
}

#[test]
fn clean_complete_run_passes_with_0() {
    let d = out_dir(vec![], true);
    assert_eq!(gate(&d, POLICY, &[]), 0);
    let g: Value = serde_json::from_str(&std::fs::read_to_string(d.join("gate.json")).unwrap()).unwrap();
    assert_eq!(g["decision"], "PASS");
}
#[test]
fn high_finding_fails_with_1_and_is_audited() {
    let d = out_dir(vec![item("HIGH")], true);
    assert_eq!(gate(&d, POLICY, &[]), 1);
    let audit = std::fs::read_to_string(d.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"gate_evaluation\""));
    assert!(crux::AuditLog::new(d.join("audit.jsonl")).verify().0);
}
#[test]
fn medium_is_conditional_0_or_1_with_fail_on_warn() {
    let d = out_dir(vec![item("MEDIUM")], true);
    assert_eq!(gate(&d, POLICY, &[]), 0);
    assert_eq!(gate(&d, POLICY, &["--fail-on-warn"]), 1);
}
#[test]
fn malformed_policy_exits_2() {
    let d = out_dir(vec![], true);
    assert_eq!(gate(&d, "version: 1\ngrace_days: {HIGH: 7}\n", &[]), 2);
    assert!(!d.join("gate.json").exists());
}
#[test]
fn incomplete_or_missing_run_status_exits_3() {
    let d = out_dir(vec![], false);
    assert_eq!(gate(&d, POLICY, &[]), 3);
    std::fs::remove_file(d.join("run.json")).unwrap();
    assert_eq!(gate(&d, POLICY, &[]), 3);
    let empty = tmp(); // no queue.json at all
    assert_eq!(gate(&empty, POLICY, &[]), 3);
}
#[test]
fn broken_audit_chain_exits_4_and_writes_no_gate() {
    let d = out_dir(vec![], true);
    write(&d, "audit.jsonl", "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n");
    assert_eq!(gate(&d, POLICY, &[]), 4);
    assert!(!d.join("gate.json").exists());
}
#[test]
fn dry_run_with_policy_is_incomplete_3() {
    let d = tmp();
    let p = write(&d, "policy.yaml", POLICY);
    let eng = concat!(env!("CARGO_MANIFEST_DIR"), "/samples/engagement.example.yaml");
    let out = d.join("out");
    let code = Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args(["run", "--engagement", eng, "--out", out.to_str().unwrap(), "--dry-run", "--policy", &p])
        .status().unwrap().code().unwrap();
    assert_eq!(code, 3);
    assert!(out.join("gate.json").exists(), "an INCOMPLETE verdict is still recorded");
}
#[test]
fn bad_policy_fails_before_any_scan() {
    let d = tmp();
    let p = write(&d, "policy.yaml", "version: 9\n");
    let eng = concat!(env!("CARGO_MANIFEST_DIR"), "/samples/engagement.example.yaml");
    let out = d.join("out");
    let code = Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args(["run", "--engagement", eng, "--out", out.to_str().unwrap(), "--dry-run", "--policy", &p])
        .status().unwrap().code().unwrap();
    assert_eq!(code, 2);
    assert!(!out.join("queue.json").exists(), "nothing ran");
}
#[test]
fn missing_engagement_exits_2() {
    let d = tmp();
    let code = Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args(["run", "--engagement", "definitely/not/here.yaml", "--out", d.to_str().unwrap(), "--dry-run"])
        .status().unwrap().code().unwrap();
    assert_eq!(code, 2);
}
#[test]
fn sarif_subcommand_regenerates_files() {
    let d = out_dir(vec![item("HIGH")], true);
    let code = Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args(["sarif", "--out", d.to_str().unwrap()])
        .status().unwrap().code().unwrap();
    assert_eq!(code, 0);
    let s: Value = serde_json::from_str(&std::fs::read_to_string(d.join("ascent.sarif")).unwrap()).unwrap();
    assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
}
```

- [ ] **Step 2: Run** — `cargo test --test cli_gate` → FAIL (no `gate`/`sarif` subcommands; wrong exit codes).

- [ ] **Step 3: Implement in `src/main.rs`.** Add `use gate::evaluate::{evaluate, gate_document, read_queue, write_gate, Decision, WriteGateError};`, `use gate::policy::{load_policy, Policy};`, `use runstatus::{now_ts, read_run_status};`. Extend `Cmd`:

```rust
    // in Cmd::Run, after `min_confidence`:
        /// Evaluate this policy after the run; the exit code follows the verdict.
        #[arg(long)]
        policy: Option<String>,
        /// Treat a CONDITIONAL verdict (warnings only) as a failure (exit 1).
        #[arg(long)]
        fail_on_warn: bool,

    /// Evaluate a policy against an existing output directory (CI step).
    Gate {
        #[arg(long)]
        policy: String,
        #[arg(long, default_value = "out")]
        out: String,
        #[arg(long)]
        fail_on_warn: bool,
    },
    /// Regenerate ascent.sarif / ascent-dast.sarif from queue.json.
    Sarif {
        #[arg(long, default_value = "out")]
        out: String,
        /// Source root to make SARIF paths repository-relative.
        #[arg(long)]
        source_root: Option<String>,
    },
```

  Replace `fn main() -> Result<(), Box<dyn std::error::Error>>` with:

```rust
/// A CLI failure and the exit code it maps to (README: "Exit codes").
struct Failure {
    code: u8,
    msg: String,
}
impl Failure {
    fn usage(m: impl ToString) -> Self { Failure { code: 2, msg: m.to_string() } }
    fn incomplete(m: impl ToString) -> Self { Failure { code: 3, msg: m.to_string() } }
    fn integrity(m: impl ToString) -> Self { Failure { code: 4, msg: m.to_string() } }
}

fn main() -> std::process::ExitCode {
    match dispatch(Cli::parse().cmd) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(f) => {
            eprintln!("error: {}", f.msg);
            std::process::ExitCode::from(f.code)
        }
    }
}

/// Evaluate `policy` over `out`, record gate.json + the audit entry, return the exit code.
fn gate_step(out: &str, policy: &Policy, fail_on_warn: bool) -> Result<u8, Failure> {
    let items = read_queue(out).map_err(Failure::incomplete)?;
    let status = read_run_status(out);
    let result = evaluate(&items, policy, status.as_ref(), fail_on_warn);
    let doc = gate_document(policy, &result, status.as_ref(), &now_ts());
    match write_gate(out, &doc) {
        Ok(()) => {}
        Err(WriteGateError::Integrity(m)) => {
            return Err(Failure::integrity(format!("audit chain failed verification; gate not recorded: {m}")))
        }
        Err(WriteGateError::Io(m)) => return Err(Failure::incomplete(m)),
    }
    let label = match result.decision {
        Decision::Pass => "PASS",
        Decision::Conditional => "CONDITIONAL",
        Decision::Fail => "FAIL",
        Decision::Incomplete => "INCOMPLETE",
    };
    println!(
        "gate: {label} (exit {}) policy={} failed={} warned={} demoted_fp={}",
        result.exit_code, policy.name, result.counts.failed, result.counts.warned, result.counts.demoted_fp
    );
    for e in result.failed.iter().take(10) {
        println!("  FAIL {} {} {} — {}", e.severity, e.rule_id, e.locus, e.reason);
    }
    println!("gate:   {}", std::path::Path::new(out).join("gate.json").display());
    Ok(result.exit_code)
}

fn dispatch(cmd: Cmd) -> Result<u8, Failure> {
    match cmd {
        Cmd::Run { engagement, out, dry_run, source, propose: do_propose, min_confidence, policy, fail_on_warn } => {
            // Load the policy BEFORE scanning so a bad policy fails fast (exit 2).
            let policy = policy.as_deref().map(load_policy).transpose().map_err(Failure::usage)?;
            let eng = load_engagement(&engagement).map_err(Failure::usage)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), dry_run);
            let s = run_pipeline(&eng, &runner, &CruxTriager::default(), &out, dry_run, source.as_deref())
                .map_err(Failure::incomplete)?;
            println!("urls={} findings={} triaged={}", s.urls, s.findings, s.triaged);
            if !s.complete {
                println!("run INCOMPLETE (dry run or failed scanners: {:?})", s.failed_tools);
            }
            println!("report: {}\naudit:  {}", s.report_path, s.audit_path);
            println!("sarif:  {}", std::path::Path::new(&out).join("ascent.sarif").display());
            if do_propose {
                let queue_path = std::path::Path::new(&out).join("queue.json");
                let items: Vec<TriageItem> = std::fs::read_to_string(&queue_path)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default();
                if items.is_empty() {
                    println!("no triaged items in queue.json; skipping --propose");
                } else {
                    let gates = propose(&items, &runner.guard, min_confidence);
                    write_proposed(&out, &gates).map_err(Failure::incomplete)?;
                    println!("proposed {} gate(s)", gates.len());
                }
            }
            match policy {
                Some(p) => gate_step(&out, &p, fail_on_warn),
                None => Ok(0),
            }
        }
        Cmd::Gate { policy, out, fail_on_warn } => {
            let p = load_policy(&policy).map_err(Failure::usage)?;
            gate_step(&out, &p, fail_on_warn)
        }
        Cmd::Sarif { out, source_root } => {
            let items = read_queue(&out).map_err(Failure::incomplete)?;
            sarif::write_sarif(&out, &items, source_root.as_deref()).map_err(Failure::incomplete)?;
            println!("sarif: {}", std::path::Path::new(&out).join("ascent.sarif").display());
            println!("sarif: {}", std::path::Path::new(&out).join("ascent-dast.sarif").display());
            Ok(0)
        }
        Cmd::Verify { engagement, out } => {
            let eng = load_engagement(&engagement).map_err(Failure::usage)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), false);
            let results = verify_approved(&out, &runner.guard, &runner).map_err(|e| {
                let m = e.to_string();
                if m.contains("audit chain") { Failure::integrity(m) } else { Failure::incomplete(m) }
            })?;
            // (keep the existing confirmed/not_confirmed/refused counting and printing unchanged)
            Ok(0)
        }
    }
}
```

  Keep the Verify body's existing counting/printing lines between `let results = …` and `Ok(0)` exactly as they are today. Add CLI parse tests to `mod tests` in `main.rs`:

```rust
    #[test]
    fn parses_run_policy_flags() {
        let c = Cli::try_parse_from(["ascent", "run", "--engagement", "e", "--policy", "p.yaml", "--fail-on-warn"]).unwrap();
        let super::Cmd::Run { policy, fail_on_warn, .. } = c.cmd else { panic!("expected Run") };
        assert_eq!(policy.as_deref(), Some("p.yaml"));
        assert!(fail_on_warn);
    }
    #[test]
    fn parses_gate_and_sarif() {
        let c = Cli::try_parse_from(["ascent", "gate", "--policy", "p.yaml"]).unwrap();
        let super::Cmd::Gate { policy, out, fail_on_warn } = c.cmd else { panic!("expected Gate") };
        assert_eq!((policy.as_str(), out.as_str(), fail_on_warn), ("p.yaml", "out", false));
        assert!(Cli::try_parse_from(["ascent", "gate"]).is_err(), "--policy is required");
        let c = Cli::try_parse_from(["ascent", "sarif", "--source-root", "./src"]).unwrap();
        let super::Cmd::Sarif { source_root, .. } = c.cmd else { panic!("expected Sarif") };
        assert_eq!(source_root.as_deref(), Some("./src"));
    }
```

- [ ] **Step 4: Run** — `cargo test` (unit + `--test cli_gate`) → all pass, no warnings (`cargo build 2>&1 | grep -c warning` → 0).

- [ ] **Step 5: Docs.** Create `docs/ci/github-actions.yml`:

```yaml
# Example: gate a pull request on Ascent's policy and publish SARIF to GitHub
# code scanning. Assumes opengrep, gitleaks and trivy are installed on the runner
# and that `engagement.yaml` scopes only what this repository owns.
name: ascent
on: [pull_request]
permissions:
  contents: read
  security-events: write      # required by upload-sarif
jobs:
  ascent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Ascent
        run: cargo build --release
      - name: Scan, triage and gate
        id: ascent
        # exit 0 pass/conditional, 1 policy fail, 2 config error,
        # 3 incomplete scan, 4 audit-chain integrity failure
        run: ./target/release/ascent run --engagement engagement.yaml --source . --out out --policy ascent-policy.yaml
      - name: Upload SARIF (even when the gate fails)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: out/ascent.sarif
          category: ascent
      - name: Keep the evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ascent-out
          path: out/
```

  Create `docs/followups-policy-gate.md` listing the deferred milestones from the gap analysis, each with one-paragraph scope: (M2) finding state store keyed by `ascent/v1` fingerprint with `first_seen/last_seen`, SARIF `baselineState` new/unchanged/updated/absent, `not_rescanned` fail-closed state, `verified_fixed` via the existing hash-bound re-test, `--baseline`, `new_only`; (M2) waivers file with mandatory `expires`, proposer≠approver, approval through the dashboard gate flow, chained into audit.jsonl, exported as SARIF `suppressions`, grace periods keyed on `first_seen` that an expired waiver never resets; (M4) `trivy --scanners license` → LICENSE category with SPDX normalisation and policy deny/warn lists; (M4) `trivy image` scoped by pinned digest/registry allow-list; and a "verify early" list: opengrep exit codes were verified 2026-10-30 (0 with findings, 2 on error), fingerprint robustness vs real refactors, GitHub `security-severity` band edges. Non-goals: auto fix PRs, AI patches, IDE plugin, malware scanning.

  In `README.md`, insert before `## License`:

```markdown
## Policy gate and CI

`ascent run … --policy ascent-policy.yaml` evaluates a policy after triage and
exits with a CI-friendly code; `ascent gate --policy … --out out` evaluates an
existing output directory. Every run also writes native SARIF 2.1.0
(`out/ascent.sarif` for code findings, `out/ascent-dast.sarif` for URL findings;
regenerate with `ascent sarif`). See `samples/ascent-policy.example.yaml` and
`docs/ci/github-actions.yml`.

| Exit | Meaning |
|---|---|
| 0 | PASS, or CONDITIONAL (warnings only) — or no policy given |
| 1 | FAIL (or CONDITIONAL with `--fail-on-warn`) |
| 2 | Usage or configuration error (bad engagement, malformed policy) |
| 3 | INCOMPLETE: a scanner or stage failed, or it was a dry run — never a pass |
| 4 | The audit hash chain failed verification |

The verdict is written to `out/gate.json` and chained into `audit.jsonl`
(`gate_evaluation`). A finding Crux triages as LIKELY_FALSE_POSITIVE is demoted
to a warning, never silently passed. Findings carry a stable `ascent/v1`
fingerprint (no line numbers; secrets keyed on rule + path only — Ascent never
stores a secret or a hash of one). Runtime errors now exit 3 (previously 1), so
1 always means "policy failed".
```

- [ ] **Step 6: Commit**

```bash
git add src/main.rs tests/cli_gate.rs docs/ci/github-actions.yml docs/followups-policy-gate.md README.md
git commit -m "feat(cli): policy gate, gate/sarif subcommands and fail-closed exit-code contract" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Dashboard — Policy gate card, audit rendering, copy

**Files:**
- Modify: `src/dashboard/read.rs` (`read_gate` + test), `src/bin/dashboard.rs` (route + test)
- Modify: `frontend/src/api.ts` (`getGate`, types, `GateEvaluationAuditEntry`)
- Create: `frontend/src/components/PolicyGate.tsx`, `frontend/src/components/PolicyGate.test.tsx`
- Modify: `frontend/src/App.tsx` (Overview renders `<PolicyGate/>` above `<Findings/>`), `frontend/src/screens/Audit.tsx` (+ `Audit.test.tsx`), `frontend/src/screens/NewScan.tsx` (copy), `frontend/src/styles/glass.css`

**Interfaces:**
- Consumes: `out/gate.json` (shape from Task 4 `gate_document`).
- Produces: `GET /api/gate` → gate.json JSON or `null`; React `PolicyGate` component.

- [ ] **Step 1: Backend test first** — in `src/dashboard/read.rs` tests:

```rust
    #[test]
    fn read_gate_is_null_when_missing_and_json_when_present() {
        let dir = tmp();
        let d = dir.to_str().unwrap();
        assert_eq!(read_gate(d), Value::Null);
        std::fs::write(dir.join("gate.json"), r#"{"decision":"FAIL","exit_code":1}"#).unwrap();
        assert_eq!(read_gate(d)["decision"], "FAIL");
        std::fs::write(dir.join("gate.json"), "garbage").unwrap();
        assert_eq!(read_gate(d), Value::Null);
    }
```

  and in `src/bin/dashboard.rs` tests:

```rust
    #[tokio::test]
    async fn gate_route_returns_gate_json_or_null() {
        let dir = tmp();
        let resp = app_for(&dir).oneshot(api_get("/api/gate")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await, Value::Null);
        std::fs::write(dir.join("gate.json"), r#"{"decision":"PASS","exit_code":0}"#).unwrap();
        let resp = app_for(&dir).oneshot(api_get("/api/gate")).await.unwrap();
        assert_eq!(body_json(resp).await["decision"], "PASS");
    }

    #[tokio::test]
    async fn gate_route_is_read_only() {
        let dir = tmp();
        let req = Request::builder().method(Method::POST).uri("/api/gate")
            .header("host", "127.0.0.1:8787").header("origin", "http://127.0.0.1:8787")
            .header("x-ascent", "1").body(Body::empty()).unwrap();
        assert_eq!(app_for(&dir).oneshot(req).await.unwrap().status(), StatusCode::METHOD_NOT_ALLOWED);
    }
```

  Run `cargo test --bin dashboard` → FAIL.

- [ ] **Step 2: Implement backend.** In `src/dashboard/read.rs`:

```rust
/// `<out_dir>/gate.json` (the last policy verdict), or `Null` if missing/invalid.
pub fn read_gate(out_dir: &str) -> Value {
    std::fs::read_to_string(Path::new(out_dir).join("gate.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .unwrap_or(Value::Null)
}
```

  In `src/bin/dashboard.rs`: import `read_gate`; add

```rust
/// The last policy verdict. Read-only: the dashboard never evaluates or runs.
async fn gate(State(s): State<Shared>) -> Json<Value> {
    Json(read_gate(&s.out_dir))
}
```

  and `.route("/api/gate", get(gate))` next to `/api/report`. **Name clash:** the existing pending-gates handler is `async fn gates` — keep it; name the new one `gate_verdict` instead of `gate` if the compiler or readability requires (`.route("/api/gate", get(gate_verdict))`). Run `cargo test --bin dashboard` → PASS.

- [ ] **Step 3: Frontend API + types.** Append to `frontend/src/api.ts`:

```ts
// GET /api/gate: the last policy verdict (out/gate.json), or null when no
// policy has been evaluated. Strings can originate from scanned targets:
// render as React text only.
export type GateDecisionKind = "PASS" | "CONDITIONAL" | "FAIL" | "INCOMPLETE";

export interface GateEntryView {
  fingerprint: string;
  rule_id: string;
  severity: string;
  category: string;
  title: string;
  locus: string;
  reason: string;
}

export interface GateReport {
  policy: { name: string; hash: string };
  decision: GateDecisionKind;
  exit_code: number;
  complete: boolean;
  dry_run?: boolean;
  failed_tools?: string[];
  counts: { evaluated: number; failed: number; warned: number; demoted_fp: number };
  failed: GateEntryView[];
  warned: GateEntryView[];
  evaluated_at?: string;
}

const DECISIONS: readonly string[] = ["PASS", "CONDITIONAL", "FAIL", "INCOMPLETE"];

export async function getGate(): Promise<GateReport | null> {
  const res = await fetch("/api/gate");
  if (!res.ok) {
    throw new Error(`GET /api/gate failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  if (body === null) return null;
  if (!isObject(body) || typeof body.decision !== "string" || !DECISIONS.includes(body.decision)) {
    throw new Error("GET /api/gate returned an unexpected payload");
  }
  const list = (v: unknown) => (Array.isArray(v) ? v.filter(isObject) : []) as unknown as GateEntryView[];
  const policy = isObject(body.policy) ? body.policy : {};
  const counts = isObject(body.counts) ? body.counts : {};
  const num = (v: unknown) => (typeof v === "number" ? v : 0);
  return {
    policy: {
      name: typeof policy.name === "string" ? policy.name : "",
      hash: typeof policy.hash === "string" ? policy.hash : "",
    },
    decision: body.decision as GateDecisionKind,
    exit_code: num(body.exit_code),
    complete: body.complete === true,
    dry_run: body.dry_run === true,
    failed_tools: Array.isArray(body.failed_tools) ? body.failed_tools.filter((t): t is string => typeof t === "string") : [],
    counts: {
      evaluated: num(counts.evaluated),
      failed: num(counts.failed),
      warned: num(counts.warned),
      demoted_fp: num(counts.demoted_fp),
    },
    failed: list(body.failed),
    warned: list(body.warned),
    evaluated_at: typeof body.evaluated_at === "string" ? body.evaluated_at : undefined,
  };
}
```

  Also extend the audit types: add

```ts
export interface GateEvaluationAuditEntry {
  ts?: string;
  type: "gate_evaluation";
  decision?: string;
  exit_code?: number;
  policy_hash?: string;
  prev_hash?: string;
  entry_hash?: string;
}

export interface GateExecutionAuditEntry {
  ts?: string;
  type: "gate_execution";
  gate_id?: string;
  outcome?: string;
  prev_hash?: string;
  entry_hash?: string;
}
```

  and change `export type AuditEntry = TriageAuditEntry | GateAuditEntry;` to include both new interfaces.

- [ ] **Step 4: PolicyGate tests first** — `frontend/src/components/PolicyGate.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { PolicyGate } from "./PolicyGate";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}
function report(over: Record<string, unknown> = {}) {
  return {
    policy: { name: "ci", hash: "abcdef0123456789" },
    decision: "FAIL", exit_code: 1, complete: true, failed_tools: [],
    counts: { evaluated: 3, failed: 1, warned: 1, demoted_fp: 0 },
    failed: [{ fingerprint: "ascent/v1:aa", rule_id: "py.sqli", severity: "HIGH", category: "SAST",
               title: "SQL injection", locus: "app.py:3", reason: "severity HIGH in fail_on" }],
    warned: [], evaluated_at: "2026-10-30T00:00:00Z",
    ...over,
  };
}
afterEach(() => vi.restoreAllMocks());

test("shows a FAIL verdict with the failing finding and exit code", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  expect(await screen.findByText("FAIL")).toBeInTheDocument();
  expect(screen.getByText("SQL injection")).toBeInTheDocument();
  expect(screen.getByText("app.py:3")).toBeInTheDocument();
  expect(screen.getByText(/exit 1/)).toBeInTheDocument();
  expect(screen.getByText(/policy ci/)).toBeInTheDocument();
});

test("PASS and CONDITIONAL render their own labels", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ decision: "PASS", exit_code: 0, failed: [] })));
  const { unmount } = render(<PolicyGate />);
  expect(await screen.findByText("PASS")).toBeInTheDocument();
  unmount();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ decision: "CONDITIONAL", exit_code: 0, failed: [] })));
  render(<PolicyGate />);
  expect(await screen.findByText("CONDITIONAL")).toBeInTheDocument();
});

test("INCOMPLETE explains why it cannot pass", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ decision: "INCOMPLETE", exit_code: 3, complete: false, failed: [], failed_tools: ["opengrep"] })),
  );
  render(<PolicyGate />);
  expect(await screen.findByText("INCOMPLETE")).toBeInTheDocument();
  expect(screen.getByText(/opengrep/)).toBeInTheDocument();
});

test("no gate yet shows how to enable one", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(null));
  render(<PolicyGate />);
  expect(await screen.findByText(/No policy verdict yet/)).toBeInTheDocument();
  expect(screen.getByText(/--policy/)).toBeInTheDocument();
});

test("attacker-controlled strings render as text, not HTML", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ failed: [{ fingerprint: "f", rule_id: "r", severity: "HIGH", category: "DAST",
      title: "<img src=x onerror=alert(1)>", locus: "https://x/", reason: "r" }] })),
  );
  const { container } = render(<PolicyGate />);
  expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});
```

  Run `npm run test` in `frontend/` → FAIL.

- [ ] **Step 5: Implement `frontend/src/components/PolicyGate.tsx`:**

```tsx
import { useEffect, useState } from "react";
import { getGate } from "../api";
import type { GateDecisionKind, GateReport } from "../api";

type State = { status: "loading" } | { status: "error" } | { status: "ready"; gate: GateReport | null };

const LABEL: Record<GateDecisionKind, string> = {
  PASS: "Policy passed",
  CONDITIONAL: "Passed with warnings",
  FAIL: "Policy failed",
  INCOMPLETE: "Scan incomplete — cannot pass",
};

/** Read-only view of out/gate.json. It never evaluates a policy or starts a run. */
export function PolicyGate() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    getGate().then(
      (gate) => live && setState({ status: "ready", gate }),
      () => live && setState({ status: "error" }),
    );
    return () => {
      live = false;
    };
  }, []);

  if (state.status === "loading") {
    return (
      <section className="panel glass policy" role="status">
        <div className="phead">
          <span className="ptitle">Loading policy gate…</span>
        </div>
      </section>
    );
  }
  if (state.status === "error") {
    return (
      <section className="panel glass policy" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load the policy gate</span>
        </div>
      </section>
    );
  }
  const g = state.gate;
  if (g === null) {
    return (
      <section className="panel glass policy">
        <div className="phead">
          <span className="ptitle">Policy gate</span>
          <span className="verdict-pill v-none">NOT EVALUATED</span>
        </div>
        <div className="policy-body">
          <div className="note" style={{ textAlign: "left" }}>
            No policy verdict yet. Add <code>--policy ascent-policy.yaml</code> to <code>ascent run</code>, or run{" "}
            <code>ascent gate --policy ascent-policy.yaml</code>, to get a PASS / FAIL verdict and a CI exit code.
          </div>
        </div>
      </section>
    );
  }
  const shown = g.failed.length > 0 ? g.failed : g.warned;
  return (
    <section className={`panel glass policy policy-${g.decision.toLowerCase()}`}>
      <div className="phead">
        <span className="ptitle">Policy gate</span>
        <span className={`verdict-pill v-${g.decision.toLowerCase()}`}>{g.decision}</span>
        <span className="count">exit {g.exit_code}</span>
        <span className="policy-meta">
          policy {g.policy.name} · {g.policy.hash.slice(0, 12)}
        </span>
      </div>
      <div className="policy-body">
        <div className="policy-headline">{LABEL[g.decision]}</div>
        <div className="policy-counts">
          <span><b>{g.counts.failed}</b> failing</span>
          <span><b>{g.counts.warned}</b> warnings</span>
          <span><b>{g.counts.demoted_fp}</b> demoted likely-FP</span>
          <span><b>{g.counts.evaluated}</b> evaluated</span>
        </div>
        {g.decision === "INCOMPLETE" && (
          <div className="policy-why">
            {g.dry_run ? "This was a dry run: no scanners ran. " : ""}
            {g.failed_tools && g.failed_tools.length > 0 ? `Scanners that failed: ${g.failed_tools.join(", ")}. ` : ""}
            An incomplete scan never passes the gate.
          </div>
        )}
        {shown.length > 0 && (
          <ul className="policy-list">
            {shown.slice(0, 5).map((e) => (
              <li key={e.fingerprint}>
                <span className={`sev ${sevClass(e.severity)}`}>{e.severity}</span>
                <span className="policy-title">{e.title}</span>
                <span className="loc">{e.locus}</span>
                <span className="policy-reason">{e.reason}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="note" style={{ textAlign: "left" }}>
          Read-only verdict from out/gate.json{g.evaluated_at ? `, evaluated ${g.evaluated_at}` : ""}. It is chained into the audit log.
        </div>
      </div>
    </section>
  );
}

function sevClass(sev: string): string {
  switch (sev) {
    case "CRITICAL":
      return "crit";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "med";
    default:
      return "low";
  }
}
```

- [ ] **Step 6: Styles** — append to `frontend/src/styles/glass.css`:

```css
/* ---- Policy gate card (not in the mockup) ---- */
.policy{flex:none}
.policy .phead{gap:10px}
.policy-meta{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--faint)}
.verdict-pill{font-size:11px;font-weight:800;letter-spacing:.06em;padding:4px 11px;border-radius:999px}
.verdict-pill.v-pass{color:#0b6f69;background:rgba(18,165,148,.16)}
.verdict-pill.v-conditional{color:#8a6a00;background:rgba(224,164,0,.18)}
.verdict-pill.v-fail{color:#fff;background:var(--crit);box-shadow:0 8px 20px -10px var(--crit)}
.verdict-pill.v-incomplete,.verdict-pill.v-none{color:var(--muted);background:rgba(21,35,59,.08)}
.policy-body{padding:0 18px 16px;display:flex;flex-direction:column;gap:10px}
.policy-headline{font-size:15px;font-weight:700}
.policy-fail .policy-headline{color:#b21f24}
.policy-pass .policy-headline{color:#0b6f69}
.policy-counts{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--muted)}
.policy-counts b{color:var(--ink);font-variant-numeric:tabular-nums}
.policy-why{font-size:12px;color:var(--muted);background:rgba(21,35,59,.05);border-radius:10px;padding:8px 10px}
.policy-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
.policy-list li{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 10px;background:rgba(255,255,255,.55);border:1px solid var(--stroke);border-radius:12px;padding:8px 10px;font-size:12.5px}
.policy-title{font-weight:700}
.policy-reason{font-size:11px;color:var(--faint);margin-left:auto}
.policy-body code{font-family:var(--mono);font-size:11px;background:rgba(21,35,59,.06);padding:1px 5px;border-radius:6px}
```

- [ ] **Step 7: Wire into the Overview** — in `frontend/src/App.tsx` add `import { PolicyGate } from "./components/PolicyGate";` and change the default (overview) case's children from the single Findings boundary to:

```tsx
          <ErrorBoundary key="overview-gate">
            <PolicyGate />
          </ErrorBoundary>
          <ErrorBoundary key="overview-findings">
            <Findings />
          </ErrorBoundary>
```

  (`Shell` renders children inside `.main`, a flex column, so they stack.) Check `frontend/src/App.test.tsx`: tests that mock `fetch` with a fixed sequence of responses for the Overview must now account for the extra `/api/gate` request — prefer making those mocks URL-aware (`mockImplementation((url) => …)` returning `json(null)` for `/api/gate`) rather than reordering.

- [ ] **Step 8: Audit rendering** — in `frontend/src/screens/Audit.tsx` `EntryRow`, before the triage fallback add:

```tsx
  if (entry.type === "gate_evaluation") {
    return (
      <div className="ev">
        <span className="tick" aria-hidden="true" />
        <div className="m">
          <b>Policy gate</b> · {entry.decision ?? "?"} (exit {entry.exit_code ?? "?"})
          <div className="h">{entry.ts ?? ""}</div>
          {hash ? <div className="h">{hash}</div> : null}
        </div>
      </div>
    );
  }
  if (entry.type === "gate_execution") {
    return (
      <div className="ev">
        <span className="tick human" aria-hidden="true" />
        <div className="m">
          <b>Verification run</b> · gate {entry.gate_id ?? "?"} → {entry.outcome ?? "?"}
          <div className="h">{entry.ts ?? ""}</div>
          {hash ? <div className="h">{hash}</div> : null}
        </div>
      </div>
    );
  }
```

  (Use whatever `hash` variable `EntryRow` already computes for `gate_decision`; check the real field name of `gate_execution` entries in `src/exploit/execute.rs` — if the outcome field is named differently, render that field.) Add a test to `frontend/src/screens/Audit.test.tsx` following that file's existing fetch-mocking pattern: an entry `{type: "gate_evaluation", decision: "FAIL", exit_code: 1, ts: "t", prev_hash: "a", entry_hash: "b"}` renders text matching `/Policy gate/` and `/FAIL \(exit 1\)/`.

- [ ] **Step 9: New Scan copy** — in `frontend/src/screens/NewScan.tsx`, under the run-command row inside the success card, add:

```tsx
            <div className="hint">
              Add <code>--policy samples/ascent-policy.example.yaml</code> to gate the run: the command then exits 1 when the
              policy fails, ready for CI.
            </div>
```

  and add `.newscan .hint code{font-family:var(--mono);font-size:11px;background:rgba(21,35,59,.06);padding:1px 5px;border-radius:6px}` to `glass.css`.

- [ ] **Step 10: Run everything** — `cargo test` (all green, no warnings); in `frontend/`: `npm run test`, `npm run build` (tsc + vite) → green.

- [ ] **Step 11: Commit**

```bash
git add src/dashboard/read.rs src/bin/dashboard.rs frontend/src
git commit -m "feat(dashboard): read-only Policy gate card and gate audit entries" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Final validation (after all tasks)

1. `cargo test` and `cargo build` → green, zero warnings. `cd frontend && npm run test && npm run build` → green.
2. Live gate on real scanners: `ascent run --engagement samples/engagement.example.yaml --out out --dry-run --policy samples/ascent-policy.example.yaml` → exit 3, gate.json INCOMPLETE.
3. Live SAST + gate on a planted fixture (scratch dir with a SQLi line, an AWS-format test key, axios 0.21.1 lockfile) using an engagement whose `source` is that dir → findings from all three scanners, `out/ascent.sarif` valid, gate FAIL exit 1, SCA evidence shows `fixed=0.21.2`, no secret value anywhere in `out/` (`grep -r` for the planted key returns nothing).
4. Dashboard: restart, cache-bust (`?v=N`), Overview shows the Policy gate card with the verdict; Audit shows the "Policy gate" entry.
