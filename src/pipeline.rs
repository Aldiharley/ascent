use crate::gate::fingerprint::relative_to;
use crate::report::to_markdown;
use crate::runner::Runner;
use crate::runstatus::{now_ts, write_run_status, RunStatus};
use crate::scope::Engagement;
use crate::stages::{
    dast::{coverage_markdown, run_dast, DastSummary},
    sast::{is_within, sast},
    scan::ensure_nuclei_version,
};
use crate::triage::{write_atomic, TriageEngine};
use std::path::Path;

pub struct Summary {
    /// In-scope URLs nuclei scanned (0 without DAST scope).
    pub urls: usize,
    pub dast: Option<DastSummary>,
    pub findings: usize,
    pub triaged: usize,
    pub report_path: String,
    pub audit_path: String,
    /// True only for a non-dry run in which every SAST analyser that is present completed
    /// and, with DAST scope, at least one URL was scanned and every declared URL answered.
    pub complete: bool,
    pub failed_tools: Vec<String>,
    /// Why the run is incomplete beyond failed tools (also in run.json and gate.json).
    pub incomplete_reasons: Vec<String>,
}

/// The output directory's audit chain does not verify (CLI exit 4).
#[derive(Debug)]
pub struct IntegrityError(pub String);
impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for IntegrityError {}

/// A configuration/usage error such as a bad `--source` (CLI exit 2).
#[derive(Debug)]
pub struct ConfigError(pub String);
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

/// Outputs a previous run may have left behind that must never outlive a new run.
const STALE_OUTPUTS: [&str; 4] = [
    "gate.json",
    "ascent.sarif",
    "ascent-dast.sarif",
    "dast-coverage.json",
];

/// Effective SAST source root: the `--source` override if non-empty, else the
/// engagement's `source`, else none. An override must lie within the engagement's
/// source root (when one is set). The result is canonical, existing, and cannot
/// be read as a tool flag.
fn resolve_source(eng: &Engagement, source: Option<&str>) -> Result<Option<String>, ConfigError> {
    let raw = match source {
        Some(s) if !s.is_empty() => {
            if !eng.source.is_empty() && !is_within(Path::new(&eng.source), Path::new(s)) {
                return Err(ConfigError(
                    "--source is outside the engagement's authorised source root".into(),
                ));
            }
            s
        }
        _ if !eng.source.is_empty() => eng.source.as_str(),
        _ => return Ok(None),
    };
    if raw.starts_with('-') {
        return Err(ConfigError("source path must not start with '-'".into()));
    }
    let canon = Path::new(raw)
        .canonicalize()
        .map_err(|e| ConfigError(format!("source path {raw:?} is not accessible: {e}")))?;
    let canon = canon.to_string_lossy().into_owned();
    // Windows canonical paths carry a `\\?\` verbatim prefix many tools mishandle.
    let canon = match canon.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => rest.to_string(),
        _ => canon,
    };
    Ok(Some(canon))
}

pub fn run_pipeline(
    eng: &Engagement,
    runner: &dyn Runner,
    triager: &dyn TriageEngine,
    out_dir: &str,
    dry_run: bool,
    source: Option<&str>,
    dast_timeout_secs: u64,
) -> Result<Summary, Box<dyn std::error::Error>> {
    // A tampered audit chain stops the run before anything is reset or written.
    let (ok, msg) = crux::AuditLog::new(Path::new(out_dir).join("audit.jsonl")).verify();
    if !ok {
        return Err(Box::new(IntegrityError(format!(
            "audit chain failed verification; nothing was run: {msg}"
        ))));
    }
    // Resolve and validate the SAST source root first so a bad `--source` fails
    // before any tool runs or any output is written.
    let eff_source = resolve_source(eng, source)?;
    // Resolve the DAST auth header value (env var) before anything is written: a
    // configured-but-missing secret must fail closed rather than scan unauthenticated.
    // A dry run sends nothing, and a run without DAST scope (source only) sends no
    // request, so neither reads the secret.
    let auth = if dry_run || (eng.hosts.is_empty() && eng.urls.is_empty()) {
        None
    } else {
        crate::scope::resolve_auth(&eng.dast, &|k| std::env::var(k).ok()).map_err(ConfigError)?
    };
    std::fs::create_dir_all(out_dir)?;
    // A previous run's verdict and SARIF must never outlive this run.
    for name in STALE_OUTPUTS {
        match std::fs::remove_file(Path::new(out_dir).join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    // Reset the triage queue up front so a re-run that yields no findings (or
    // fails before triage writes it) never shows the previous run's findings.
    write_atomic(&Path::new(out_dir).join("queue.json"), b"[]\n")?;
    // Reset the run status to "incomplete" so a run that dies part-way can never
    // leave a previous run's "complete" behind for the policy gate to trust.
    write_run_status(
        out_dir,
        &RunStatus {
            complete: false,
            dry_run,
            ..Default::default()
        },
    )?;
    // In dry-run the runner returns empty output, which would always fail the version
    // check. nuclei is needed only with DAST scope; `run_dast` checks httpx itself.
    if !dry_run && (!eng.hosts.is_empty() || !eng.urls.is_empty()) {
        ensure_nuclei_version(runner)?;
    }
    let dast = run_dast(eng, runner, auth.as_ref(), !dry_run, dast_timeout_secs)?;
    let mut findings = dast
        .as_ref()
        .map(|d| d.findings.clone())
        .unwrap_or_default();
    // SAST track (white-box): only when a source root is resolved; never in dry-run.
    let mut failed_tools = Vec::new();
    let mut skipped_tools = Vec::new();
    if let Some(src) = eff_source.as_deref() {
        if !dry_run {
            let mut o = sast(runner, src)?;
            // The analysers report absolute paths under `src`: make every finding
            // source-relative once, here, so the gate and SARIF fingerprint the same path.
            for f in &mut o.findings {
                f.file = relative_to(&f.file, src);
            }
            findings.extend(o.findings);
            failed_tools = o.failed_tools;
            skipped_tools = o.skipped_tools;
        }
    }
    let items = if !findings.is_empty() {
        triager.triage(&findings, out_dir)?
    } else {
        vec![]
    };
    let report_path = Path::new(out_dir).join("report.md");
    let mut report = to_markdown(&items, &eng.name);
    if let Some(d) = &dast {
        report.push_str(&coverage_markdown(&d.coverage));
        let cov = serde_json::to_string_pretty(&d.coverage).map_err(std::io::Error::other)? + "\n";
        write_atomic(
            &Path::new(out_dir).join("dast-coverage.json"),
            cov.as_bytes(),
        )?;
    }
    std::fs::write(&report_path, report)?;
    crate::sarif::write_sarif(
        out_dir,
        &crate::sarif::item_values(&items),
        eff_source.as_deref(),
    )?;
    let dast_summary = dast.as_ref().map(|d| d.summary.clone());
    let incomplete_reasons = match &dast_summary {
        Some(d) if !dry_run => dast_incomplete_reasons(eng, d),
        _ => vec![],
    };
    let complete = !dry_run && failed_tools.is_empty() && incomplete_reasons.is_empty();
    write_run_status(
        out_dir,
        &RunStatus {
            complete,
            dry_run,
            failed_tools: failed_tools.clone(),
            skipped_tools,
            finished_at: now_ts(),
            dast: dast_summary.clone(),
            incomplete_reasons: incomplete_reasons.clone(),
        },
    )?;
    Ok(Summary {
        urls: dast_summary.as_ref().map_or(0, |d| d.scanned),
        dast: dast_summary,
        findings: findings.len(),
        triaged: items.len(),
        report_path: report_path.to_string_lossy().into(),
        audit_path: Path::new(out_dir)
            .join("audit.jsonl")
            .to_string_lossy()
            .into(),
        complete,
        failed_tools,
        incomplete_reasons,
    })
}

const LOCALHOST_HINT: &str = " — ProjectDiscovery tools may not resolve localhost; use 127.0.0.1";

fn is_localhost(target: &str) -> bool {
    let host = url::Url::parse(target)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| target.to_ascii_lowercase());
    host == "localhost"
}

/// Declared DAST scope that was not tested fails closed: a real run that scanned no
/// URL, or whose declared URLs did not all answer, is incomplete. So is one in which
/// nuclei sent any request outside scope, most requests to a host failed, or a seed
/// stopped answering during the scan.
fn dast_incomplete_reasons(eng: &Engagement, d: &DastSummary) -> Vec<String> {
    let mut reasons = Vec::new();
    if d.wall_clock_limit_hit {
        reasons.push("wall_clock_limit_hit".to_string());
    }
    if d.scanned == 0 {
        let mut r = "DAST: no in-scope URL was reachable".to_string();
        if eng.hosts.iter().any(|h| is_localhost(h)) {
            r.push_str(LOCALHOST_HINT);
        }
        reasons.push(r);
    }
    if !d.unreachable_urls.is_empty() {
        let mut r = format!(
            "DAST: declared URL(s) unreachable: {}",
            d.unreachable_urls.join(", ")
        );
        if d.unreachable_urls.iter().any(|u| is_localhost(u)) {
            r.push_str(LOCALHOST_HINT);
        }
        reasons.push(r);
    }
    // nuclei's own trace logs: a request to any host outside scope fails closed.
    if d.off_scope_request_count > 0 || !d.out_of_scope_requests.is_empty() {
        reasons.push(format!(
            "DAST: nuclei sent requests outside scope to: {}",
            d.out_of_scope_requests.join(", ")
        ));
    }
    for h in &d.failing_hosts {
        reasons.push(format!(
            "DAST: most requests to {} failed ({} of {}) — the target was overloaded or went down during the scan",
            h.host, h.failed, h.sent
        ));
    }
    if !d.stopped_answering.is_empty() {
        reasons.push(format!(
            "DAST: stopped answering during the scan: {} — the checks after that point produced no result; restart the target and run again",
            d.stopped_answering.join(", ")
        ));
    }
    for host in &d.recovered_hosts {
        reasons.push(format!("target_recovered_during_scan:{host}"));
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Finding;
    use crate::runner::Runner;
    use crate::scope::Engagement;
    use crate::stages::dast::test_support::{flag_value, trace_line, write_default_trace};
    use crate::triage::{TriageEngine, TriageItem};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir() -> String {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "ascent_test_{}_{}_{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p.to_str().unwrap().to_string()
    }

    fn engagement() -> Engagement {
        Engagement {
            name: "lab".into(),
            hosts: vec!["example.com".into()],
            cidrs: vec![],
            urls: vec!["https://app.example.com".into()],
            source: String::new(),
            starts: "x".into(),
            ends: "y".into(),
            ..Default::default()
        }
    }

    struct FakeRun;
    impl Runner for FakeRun {
        fn run_json(
            &self,
            tool: &str,
            a: &[String],
            _t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool {
                "subfinder" => vec![json!({"host":"app.example.com"})],
                "httpx" => vec![json!({"url":"https://app.example.com"})],
                // real katana v1.7 shape: the URL is nested under `request`
                "katana" => vec![json!({"timestamp":"2026-10-31T00:00:00.000000+00:00",
                    "request":{"method":"GET","endpoint":"https://app.example.com/login","raw":"GET /login HTTP/1.1"},
                    "response":{"status_code":200}})],
                "nuclei" => {
                    write_default_trace(a);
                    vec![
                        json!({"template-id":"sqli","info":{"name":"SQLi","severity":"high"},
                        "matched-at":"https://app.example.com/login"}),
                    ]
                }
                _ => vec![],
            })
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    /// `-version` output of the real ProjectDiscovery tools; `nuclei -tl` lists one
    /// ordinary fixture template.
    fn version_of(tool: &str, args: &[String]) -> String {
        match tool {
            "httpx" => "projectdiscovery.io\n[INF] Current Version: v1.12.0".into(),
            "nuclei" if args.iter().any(|a| a == "-tl") => {
                crate::stages::dast::test_support::benign_listing()
            }
            _ => "nuclei v3.10.1".into(),
        }
    }

    /// run_text returns "" (fails the nuclei version gate if it is called); run_json is empty.
    struct EmptyRun;
    impl Runner for EmptyRun {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![])
        }
        fn run_text(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(String::new())
        }
    }

    struct FakeTri;
    impl TriageEngine for FakeTri {
        fn triage(
            &self,
            f: &[Finding],
            _o: &str,
        ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
            Ok(f.iter()
                .map(|x| TriageItem {
                    finding: x.to_crux_json(),
                    verdict: "TRUE_POSITIVE".into(),
                    confidence: 0.9,
                    fp_likelihood: 0.1,
                    rationale: "r".into(),
                    remediation: "fix".into(),
                })
                .collect())
        }
    }

    #[test]
    fn pipeline_runs() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(s.findings >= 1);
        assert!(std::path::Path::new(&s.report_path).exists());
    }

    #[test]
    fn dry_run_writes_an_incomplete_run_status() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None, 7200).unwrap();
        assert!(!s.complete);
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(!st.complete && st.dry_run);
    }

    #[test]
    fn full_run_writes_a_complete_run_status() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(s.complete && s.failed_tools.is_empty());
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(st.complete && !st.dry_run && !st.finished_at.is_empty());
    }

    #[test]
    fn pipeline_writes_sarif() {
        let dir = unique_dir();
        run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None, 7200).unwrap();
        let read = |n: &str| -> Value {
            serde_json::from_str(
                &std::fs::read_to_string(std::path::Path::new(&dir).join(n)).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(read("ascent.sarif")["version"], "2.1.0");
        // FakeRun's nuclei finding is a URL finding: it lands in the DAST file
        assert_eq!(
            read("ascent-dast.sarif")["runs"][0]["results"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    /// Every DAST tool call errors (as a crashed scanner now does); version gate passes.
    struct FailRun;
    impl Runner for FailRun {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Err("boom".into())
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    #[test]
    fn source_only_engagement_needs_no_nuclei() {
        let src = std::path::PathBuf::from(unique_dir());
        let out = unique_dir();
        let mut eng = sast_engagement(&src);
        eng.urls = vec![];
        // EmptyRun's run_text returns "": the nuclei version gate would fail if it ran.
        let s = run_pipeline(&eng, &EmptyRun, &FakeTri, &out, false, None, 7200).unwrap();
        assert_eq!(s.findings, 0);
        assert!(s.complete);
    }

    /// A pip-installed Python `httpx` shadowing ProjectDiscovery httpx on PATH.
    struct PyHttpxRun;
    impl Runner for PyHttpxRun {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            FakeRun.run_json(t, a, g)
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(match t {
                "httpx" => "Usage: httpx [OPTIONS] URL".into(),
                _ => version_of(t, a),
            })
        }
    }

    #[test]
    fn recon_refuses_a_non_projectdiscovery_httpx() {
        let dir = unique_dir();
        let e = run_pipeline(
            &engagement(),
            &PyHttpxRun,
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("not ProjectDiscovery httpx"), "{e}");
        // dry-run skips the identity check (the runner returns "")
        assert!(run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None, 7200).is_ok());
    }

    #[test]
    fn aborted_run_does_not_leave_a_previous_complete_status() {
        let dir = unique_dir();
        crate::runstatus::write_run_status(
            &dir,
            &crate::runstatus::RunStatus {
                complete: true,
                dry_run: false,
                failed_tools: vec![],
                skipped_tools: vec![],
                finished_at: "old".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(run_pipeline(&engagement(), &FailRun, &FakeTri, &dir, false, None, 7200).is_err());
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(!st.complete, "stale complete=true survived an aborted run");
    }

    #[test]
    fn stale_gate_and_sarif_never_survive_a_new_run() {
        let dir = unique_dir();
        for n in STALE_OUTPUTS {
            std::fs::write(std::path::Path::new(&dir).join(n), r#"{"decision":"PASS"}"#).unwrap();
        }
        assert!(run_pipeline(&engagement(), &FailRun, &FakeTri, &dir, false, None, 7200).is_err());
        for n in STALE_OUTPUTS {
            assert!(
                !std::path::Path::new(&dir).join(n).exists(),
                "stale {n} survived an aborted run"
            );
        }
    }

    #[test]
    fn tampered_audit_is_an_integrity_error_and_nothing_is_reset() {
        let dir = unique_dir();
        seed_stale_queue(&dir);
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        std::fs::write(&audit, "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n").unwrap();
        let e = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None, 7200)
            .err()
            .unwrap();
        assert!(e.downcast_ref::<IntegrityError>().is_some(), "{e}");
        assert_eq!(queue(&dir)[0]["finding"]["title"], "stale from last run");
        assert!(!std::path::Path::new(&dir).join("run.json").exists());
    }

    #[test]
    fn bad_source_is_a_config_error() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let e = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            &out,
            false,
            Some("--config=evil"),
            7200,
        )
        .err()
        .unwrap();
        assert!(e.downcast_ref::<ConfigError>().is_some(), "{e}");
    }

    fn queue(dir: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(std::path::Path::new(dir).join("queue.json")).unwrap(),
        )
        .unwrap()
    }

    fn seed_stale_queue(dir: &str) {
        std::fs::write(
            std::path::Path::new(dir).join("queue.json"),
            r#"[{"verdict":"TRUE_POSITIVE","finding":{"title":"stale from last run"}}]"#,
        )
        .unwrap();
    }

    #[test]
    fn rerun_with_no_findings_resets_queue_json() {
        let dir = unique_dir();
        seed_stale_queue(&dir);
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None, 7200).unwrap();
        assert_eq!(s.findings, 0);
        assert_eq!(queue(&dir), json!([]));
        assert!(!std::path::Path::new(&dir).join("queue.json.tmp").exists());
    }

    struct FailTri;
    impl TriageEngine for FailTri {
        fn triage(
            &self,
            _f: &[Finding],
            _o: &str,
        ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
            Err("triage failed".into())
        }
    }

    #[test]
    fn failed_triage_leaves_empty_queue_json() {
        let dir = unique_dir();
        seed_stale_queue(&dir);
        assert!(run_pipeline(&engagement(), &FakeRun, &FailTri, &dir, false, None, 7200).is_err());
        assert_eq!(queue(&dir), json!([]));
    }

    #[test]
    fn dry_run_skips_version_check() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None, 7200).unwrap();
        assert_eq!(s.findings, 0);
        assert!(std::path::Path::new(&s.report_path).exists());
    }

    /// Answers the DAST tools like `FakeRun`, plus opengrep (one finding). gitleaks/trivy absent.
    struct SastRun;
    impl Runner for SastRun {
        fn run_json(
            &self,
            tool: &str,
            a: &[String],
            t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            if tool == "opengrep" {
                return Ok(vec![
                    json!({"results":[{"check_id":"r","path":"a.rs","start":{"line":1},
                    "extra":{"severity":"ERROR","message":"m","metadata":{"cwe":["CWE-89"]}}}]}),
                ]);
            }
            FakeRun.run_json(tool, a, t)
        }
        fn run_text(
            &self,
            tool: &str,
            a: &[String],
            g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            match tool {
                "gitleaks" | "trivy" => Err("not found".into()),
                _ => FakeRun.run_text(tool, a, g),
            }
        }
    }

    fn sast_engagement(source: &std::path::Path) -> Engagement {
        Engagement {
            name: "lab".into(),
            hosts: vec![],
            cidrs: vec![],
            urls: vec!["https://app.example.com".into()],
            source: source.to_string_lossy().into(),
            starts: "x".into(),
            ends: "y".into(),
            ..Default::default()
        }
    }

    /// opengrep reports an absolute path under the source root it was given (as the
    /// real tool does, with the platform's separators); other tools absent.
    struct AbsSastRun;
    impl Runner for AbsSastRun {
        fn run_json(
            &self,
            tool: &str,
            a: &[String],
            t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            if tool == "opengrep" {
                let root = a.last().unwrap();
                let path = std::path::Path::new(root).join("sub").join("a.rs");
                return Ok(vec![
                    json!({"results":[{"check_id":"r","path":path.to_string_lossy(),
                    "start":{"line":1},"extra":{"severity":"ERROR","message":"m","lines":"q(x)"}}]}),
                ]);
            }
            SastRun.run_json(tool, a, t)
        }
        fn run_text(
            &self,
            tool: &str,
            a: &[String],
            g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            SastRun.run_text(tool, a, g)
        }
    }

    /// Records the queue entries it produced.
    #[derive(Default)]
    struct RecTri(std::cell::RefCell<Vec<Value>>);
    impl TriageEngine for RecTri {
        fn triage(
            &self,
            f: &[Finding],
            o: &str,
        ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
            let items = FakeTri.triage(f, o)?;
            *self.0.borrow_mut() = crate::sarif::item_values(&items);
            Ok(items)
        }
    }

    #[test]
    fn sast_paths_are_source_relative_and_gate_matches_sarif_fingerprints() {
        let dir = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&dir);
        let tri = RecTri::default();
        run_pipeline(
            &eng,
            &AbsSastRun,
            &tri,
            dir.to_str().unwrap(),
            false,
            None,
            7200,
        )
        .unwrap();
        let items = tri.0.borrow().clone();
        let sast_item = items
            .iter()
            .find(|it| it["finding"]["tool"] == "opengrep")
            .unwrap();
        assert_eq!(sast_item["finding"]["file"], "sub/a.rs");
        // The gate fingerprint must equal the SARIF partialFingerprints value.
        let policy = crate::gate::policy::parse_policy(
            "version: 1\nfail_on:\n  severity: [CRITICAL, HIGH, MEDIUM, LOW, INFO]\n  categories: [SAST]\n",
        )
        .unwrap();
        let st = crate::runstatus::read_run_status(dir.to_str().unwrap()).unwrap();
        let r = crate::gate::evaluate::evaluate(&items, &policy, Some(&st), false);
        assert_eq!(r.failed.len(), 1);
        let sarif: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("ascent.sarif")).unwrap())
                .unwrap();
        let res = &sarif["runs"][0]["results"][0];
        assert_eq!(
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "sub/a.rs"
        );
        assert_eq!(
            res["partialFingerprints"]["ascentFindingHash/v1"],
            r.failed[0].fingerprint.as_str()
        );
    }

    /// opengrep is installed but crashes; the other analysers work.
    struct CrashingOpengrepRun;
    impl Runner for CrashingOpengrepRun {
        fn run_json(
            &self,
            tool: &str,
            a: &[String],
            t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            match tool {
                "opengrep" => Err("opengrep crashed".into()),
                _ => FakeRun.run_json(tool, a, t),
            }
        }
        fn run_text(
            &self,
            tool: &str,
            a: &[String],
            g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            FakeRun.run_text(tool, a, g)
        }
    }

    #[test]
    fn failing_sast_tool_makes_the_run_incomplete_and_is_recorded() {
        let dir = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&dir);
        let d = dir.to_str().unwrap();
        let s = run_pipeline(&eng, &CrashingOpengrepRun, &FakeTri, d, false, None, 7200).unwrap();
        assert!(!s.complete);
        assert_eq!(s.failed_tools, vec!["opengrep".to_string()]);
        let st = crate::runstatus::read_run_status(d).unwrap();
        assert!(!st.complete && !st.dry_run);
        assert_eq!(st.failed_tools, vec!["opengrep".to_string()]);
    }

    #[test]
    fn pipeline_merges_sast_and_dast_findings() {
        let dir = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&dir);
        let s = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            dir.to_str().unwrap(),
            false,
            None,
            7200,
        )
        .unwrap();
        // 1 DAST (nuclei) + 1 SAST (opengrep) finding both reach triage.
        assert_eq!(s.findings, 2);
        assert_eq!(s.triaged, 2);
    }

    #[test]
    fn engagement_without_source_runs_dast_only() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let s = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, None, 7200).unwrap();
        assert_eq!(s.findings, 1); // nuclei only; opengrep never ran
    }

    #[test]
    fn dry_run_skips_sast() {
        let dir = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&dir);
        let s = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            dir.to_str().unwrap(),
            true,
            None,
            7200,
        )
        .unwrap();
        assert_eq!(s.findings, 1); // DAST scan still planned by fake; no SAST
    }

    #[test]
    fn source_override_outside_engagement_root_errors() {
        let root = std::path::PathBuf::from(unique_dir());
        let other = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&root);
        let r = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            root.to_str().unwrap(),
            false,
            Some(other.to_str().unwrap()),
            7200,
        );
        assert!(r.is_err());
        assert!(r.err().unwrap().to_string().contains("outside"));
    }

    #[test]
    fn source_override_inside_engagement_root_is_used() {
        let root = std::path::PathBuf::from(unique_dir());
        let sub = root.join("svc");
        std::fs::create_dir_all(&sub).unwrap();
        let eng = sast_engagement(&root);
        let s = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            root.to_str().unwrap(),
            false,
            Some(sub.to_str().unwrap()),
            7200,
        )
        .unwrap();
        assert_eq!(s.findings, 2);
    }

    #[test]
    fn source_override_without_engagement_source_is_used() {
        let out = unique_dir();
        let src = std::path::PathBuf::from(unique_dir());
        let mut eng = sast_engagement(&src);
        eng.source = String::new();
        let s = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, src.to_str(), 7200).unwrap();
        assert_eq!(s.findings, 2);
    }

    #[test]
    fn resolved_source_is_canonical_without_verbatim_prefix() {
        let src = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&src);
        let got = resolve_source(&eng, None).unwrap().unwrap();
        assert!(!got.starts_with(r"\\?\"));
        assert!(std::path::Path::new(&got).is_dir());
    }

    #[test]
    fn nonexistent_source_errors() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let missing = std::path::Path::new(&out).join("does-not-exist");
        let r = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            &out,
            false,
            Some(missing.to_str().unwrap()),
            7200,
        );
        assert!(r.is_err());
    }

    /// httpx answers `https://<host>` for every `-u` host; nuclei returns one row per
    /// call whose `curl-command` embeds `leak` (when set); katana finds nothing new.
    struct HostRun {
        leak: Option<String>,
    }
    impl Runner for HostRun {
        fn run_json(
            &self,
            tool: &str,
            a: &[String],
            _t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool {
                // a declared URL is a liveness probe and is echoed back as live
                "httpx" => a
                    .windows(2)
                    .filter(|w| w[0] == "-u")
                    .map(|w| match w[1].contains("://") {
                        true => json!({"input": w[1], "url": w[1]}),
                        false => json!({"url": format!("https://{}", w[1])}),
                    })
                    .collect(),
                "nuclei" => {
                    write_default_trace(a);
                    vec![json!({
                        "template-id":"t1","matched-at":"https://c.example.com/",
                        "info":{"name":"n","severity":"high","tags":["xss"]},
                        "curl-command": format!("curl -H 'X: {}' https://c.example.com/",
                            self.leak.clone().unwrap_or_default())
                    })]
                }
                _ => vec![],
            })
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    fn dast_engagement() -> Engagement {
        Engagement {
            name: "lab".into(),
            hosts: vec!["a.example.com".into(), "b.example.com".into()],
            urls: vec!["https://c.example.com/".into()],
            starts: "x".into(),
            ends: "y".into(),
            ..Default::default()
        }
    }

    fn read_json(dir: &str, name: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(Path::new(dir).join(name)).unwrap()).unwrap()
    }

    #[test]
    fn dast_runs_over_every_host_and_url() {
        let dir = unique_dir();
        let s = run_pipeline(
            &dast_engagement(),
            &HostRun { leak: None },
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        let run = read_json(&dir, "run.json");
        assert_eq!(run["dast"]["seeded"], 3, "{run}");
        assert_eq!(run["dast"]["scanned"], 3, "{run}");
        assert_eq!(run["dast"]["profile"], "standard");
        assert_eq!(s.urls, 3);
        assert_eq!(s.dast.as_ref().unwrap().scanned, s.urls);
        assert!(s.complete);
    }

    /// `HostRun`, but every nuclei pass's trace log holds exactly `0`.
    struct TraceRun(Vec<String>);
    impl Runner for TraceRun {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            let rows = HostRun { leak: None }.run_json(t, a, g)?;
            if let Some(p) = flag_value(a, "-tlog") {
                std::fs::write(p, self.0.join("\n")).unwrap();
            }
            Ok(rows)
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    fn gate_decision(dir: &str) -> (crate::gate::evaluate::Decision, u8) {
        let policy =
            crate::gate::policy::parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL]\n")
                .unwrap();
        let st = crate::runstatus::read_run_status(dir).unwrap();
        let r = crate::gate::evaluate::evaluate(&[], &policy, Some(&st), false);
        (r.decision, r.exit_code)
    }

    #[test]
    fn a_request_sent_outside_scope_makes_the_run_incomplete() {
        let dir = unique_dir();
        let r = TraceRun(vec![
            trace_line("c.example.com:443", "none"),
            trace_line("checkip.amazonaws.com:443", "none"),
            trace_line("checkip.amazonaws.com:3000", "no address found for host"),
        ]);
        let s = run_pipeline(&dast_engagement(), &r, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(!s.complete);
        let want =
            vec!["DAST: nuclei sent requests outside scope to: checkip.amazonaws.com".to_string()];
        assert_eq!(s.incomplete_reasons, want);
        let run = read_json(&dir, "run.json");
        assert_eq!(run["complete"], false);
        assert_eq!(run["incomplete_reasons"], json!(want));
        assert_eq!(
            run["dast"]["out_of_scope_requests"],
            json!(["checkip.amazonaws.com"])
        );
        assert_eq!(run["dast"]["off_scope_request_count"], 2);
        assert_eq!(run["dast"]["requests_sent"], 3);
        assert_eq!(run["dast"]["request_errors"], 1);
        assert_eq!(
            gate_decision(&dir),
            (crate::gate::evaluate::Decision::Incomplete, 3)
        );
        let report = std::fs::read_to_string(Path::new(&dir).join("report.md")).unwrap();
        assert!(
            report.contains("outside the scope: checkip.amazonaws.com"),
            "{report}"
        );
    }

    #[test]
    fn a_host_where_most_requests_failed_makes_the_run_incomplete() {
        let dir = unique_dir();
        let mut lines: Vec<String> = (0..10)
            .map(|_| trace_line("c.example.com:443", "none"))
            .collect();
        lines.extend((0..10).map(|_| trace_line("c.example.com:443", "context deadline exceeded")));
        let s = run_pipeline(
            &dast_engagement(),
            &TraceRun(lines),
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        assert!(!s.complete);
        assert_eq!(
            s.incomplete_reasons,
            vec!["DAST: most requests to c.example.com failed (10 of 20) — the target was overloaded or went down during the scan".to_string()]
        );
        assert_eq!(gate_decision(&dir).1, 3);
    }

    /// `HostRun`, but once nuclei has run the httpx URL probe gets no answer.
    struct CrashRun(std::cell::Cell<bool>);
    impl Runner for CrashRun {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            if t == "nuclei" {
                self.0.set(true);
            }
            if t == "httpx" && self.0.get() {
                return Ok(vec![]);
            }
            HostRun { leak: None }.run_json(t, a, g)
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    #[test]
    fn a_target_that_stops_answering_during_the_scan_makes_the_run_incomplete() {
        let dir = unique_dir();
        let r = CrashRun(std::cell::Cell::new(false));
        let s = run_pipeline(&dast_engagement(), &r, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(!s.complete);
        let gone = &s.dast.as_ref().unwrap().stopped_answering;
        assert_eq!(gone.len(), 3, "{gone:?}");
        assert_eq!(
            s.incomplete_reasons,
            vec![format!(
                "DAST: stopped answering during the scan: {} — the checks after that point produced no result; restart the target and run again",
                gone.join(", ")
            )]
        );
        assert_eq!(
            read_json(&dir, "run.json")["dast"]["stopped_answering"],
            json!(gone)
        );
        assert_eq!(gate_decision(&dir).1, 3);
    }

    #[test]
    fn a_clean_trace_adds_no_reason_and_records_the_counts() {
        let dir = unique_dir();
        let mut lines: Vec<String> = (0..11)
            .map(|_| trace_line("c.example.com:443", "none"))
            .collect();
        lines.extend((0..9).map(|_| trace_line("c.example.com:443", "i/o timeout")));
        let s = run_pipeline(
            &dast_engagement(),
            &TraceRun(lines),
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        assert!(s.complete, "{:?}", s.incomplete_reasons);
        let run = read_json(&dir, "run.json");
        assert_eq!(run["dast"]["requests_sent"], 20);
        assert_eq!(run["dast"]["request_errors"], 9);
        assert_eq!(run["dast"]["off_scope_request_count"], 0);
        let report = std::fs::read_to_string(Path::new(&dir).join("report.md")).unwrap();
        assert!(
            report.contains("nuclei sent 20 requests; 9 failed (timeouts/connection errors)"),
            "{report}"
        );
    }

    #[test]
    fn a_missing_trace_log_aborts_the_run_incomplete() {
        struct NoTrace;
        impl Runner for NoTrace {
            fn run_json(
                &self,
                t: &str,
                a: &[String],
                g: &[String],
            ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
                let rows = HostRun { leak: None }.run_json(t, a, g)?;
                if let Some(p) = flag_value(a, "-tlog") {
                    let _ = std::fs::remove_file(p);
                }
                Ok(rows)
            }
            fn run_text(
                &self,
                t: &str,
                a: &[String],
                _g: &[String],
            ) -> Result<String, Box<dyn std::error::Error>> {
                Ok(version_of(t, a))
            }
        }
        let dir = unique_dir();
        let e = run_pipeline(
            &dast_engagement(),
            &NoTrace,
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .err()
        .unwrap();
        assert_eq!(e.to_string(), "nuclei trace log missing");
        assert!(!crate::runstatus::read_run_status(&dir).unwrap().complete);
    }

    #[test]
    fn dast_writes_coverage_and_report_section() {
        let dir = unique_dir();
        run_pipeline(
            &dast_engagement(),
            &HostRun { leak: None },
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        let cov = read_json(&dir, "dast-coverage.json");
        assert_eq!(cov["categories"].as_array().unwrap().len(), 12);
        let report = std::fs::read_to_string(Path::new(&dir).join("report.md")).unwrap();
        assert!(report.contains("## DAST coverage"), "{report}");
    }

    #[test]
    fn no_dast_scope_writes_no_coverage() {
        let src = std::path::PathBuf::from(unique_dir());
        let out = unique_dir();
        let mut eng = sast_engagement(&src);
        eng.urls = vec![];
        run_pipeline(&eng, &EmptyRun, &FakeTri, &out, false, None, 7200).unwrap();
        assert!(!Path::new(&out).join("dast-coverage.json").exists());
        let run = read_json(&out, "run.json");
        assert!(run["dast"].is_null(), "{run}");
        let report = std::fs::read_to_string(Path::new(&out).join("report.md")).unwrap();
        assert!(!report.contains("DAST coverage"));
    }

    #[test]
    fn stale_coverage_is_removed() {
        let dir = unique_dir();
        let p = Path::new(&dir).join("dast-coverage.json");
        std::fs::write(&p, r#"{"stale":true}"#).unwrap();
        assert!(run_pipeline(&engagement(), &FailRun, &FakeTri, &dir, false, None, 7200).is_err());
        assert!(
            !p.exists(),
            "stale dast-coverage.json survived an aborted run"
        );
    }

    fn auth_engagement(var: &str) -> Engagement {
        let mut eng = dast_engagement();
        eng.dast.auth = Some(crate::scope::DastAuth {
            header: "Authorization".into(),
            value_env: var.into(),
        });
        eng
    }

    #[test]
    fn auth_value_never_reaches_any_output() {
        const VAR: &str = "ASCENT_T4_AUTH_NEVER_LEAKS";
        let value = format!(
            "Bearer tok-{}-{}",
            std::process::id(),
            COUNTER.load(Ordering::SeqCst)
        );
        std::env::set_var(VAR, &value);
        let dir = unique_dir();
        let runner = HostRun {
            leak: Some(value.clone()),
        };
        let s = run_pipeline(
            &auth_engagement(VAR),
            &runner,
            &QueueTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        assert!(s.dast.as_ref().unwrap().authenticated);
        assert_eq!(s.dast.as_ref().unwrap().auth_header, "Authorization");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                let bytes = std::fs::read(&p).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains(&value),
                    "auth value leaked into {}",
                    p.display()
                );
                checked += 1;
            }
        }
        assert!(checked >= 4, "expected several outputs, saw {checked}");
        // the finding itself did get through, including into the queue the triager wrote
        assert_eq!(s.findings, 1);
        assert_eq!(queue(&dir).as_array().unwrap().len(), 1);
        // non-vacuous: the evidence carrying the value was written, with the value scrubbed
        let q = std::fs::read_to_string(Path::new(&dir).join("queue.json")).unwrap();
        assert!(q.contains("curl -H") && q.contains("***"), "{q}");
    }

    /// Like the real triager, persists `queue.json` (so that file is leak-checked too).
    struct QueueTri;
    impl TriageEngine for QueueTri {
        fn triage(
            &self,
            f: &[Finding],
            o: &str,
        ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
            let items = FakeTri.triage(f, o)?;
            let text = serde_json::to_string_pretty(&crate::sarif::item_values(&items))?;
            write_atomic(&Path::new(o).join("queue.json"), text.as_bytes())?;
            Ok(items)
        }
    }

    #[test]
    fn missing_auth_env_is_a_config_error_and_writes_nothing() {
        const VAR: &str = "ASCENT_T4_AUTH_UNSET";
        std::env::remove_var(VAR);
        let dir = unique_dir();
        let e = run_pipeline(
            &auth_engagement(VAR),
            &HostRun { leak: None },
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .err()
        .unwrap();
        assert!(e.downcast_ref::<ConfigError>().is_some(), "{e}");
        assert!(!Path::new(&dir).join("queue.json").exists());
        assert!(!Path::new(&dir).join("run.json").exists());
    }

    #[test]
    fn source_only_run_ignores_dast_auth() {
        const VAR: &str = "ASCENT_T4_AUTH_UNSET_SAST";
        std::env::remove_var(VAR);
        let src = std::path::PathBuf::from(unique_dir());
        let out = unique_dir();
        let mut eng = sast_engagement(&src);
        eng.urls = vec![];
        eng.dast.auth = Some(crate::scope::DastAuth {
            header: "Authorization".into(),
            value_env: VAR.into(),
        });
        let s = run_pipeline(&eng, &EmptyRun, &FakeTri, &out, false, None, 7200).unwrap();
        assert!(s.complete && s.dast.is_none());
    }

    #[test]
    fn dry_run_never_resolves_the_auth_secret() {
        const VAR: &str = "ASCENT_T4_AUTH_UNSET_DRY";
        std::env::remove_var(VAR);
        let dir = unique_dir();
        let s = run_pipeline(
            &auth_engagement(VAR),
            &EmptyRun,
            &FakeTri,
            &dir,
            true,
            None,
            7200,
        )
        .unwrap();
        assert!(!s.dast.as_ref().unwrap().authenticated);
    }

    /// Real-looking tool versions, but httpx answers no probe and nothing else finds anything.
    struct DeadRun;
    impl Runner for DeadRun {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![])
        }
        fn run_text(
            &self,
            t: &str,
            a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t, a))
        }
    }

    fn urls_engagement(urls: &[&str]) -> Engagement {
        Engagement {
            name: "lab".into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            cidrs: vec!["127.0.0.0/8".into()],
            starts: "x".into(),
            ends: "y".into(),
            ..Default::default()
        }
    }

    #[test]
    fn unreachable_declared_url_makes_the_run_incomplete() {
        let dir = unique_dir();
        let s = run_pipeline(
            &urls_engagement(&["http://127.0.0.1:9/"]),
            &DeadRun,
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        assert!(!s.complete);
        let want = [
            "DAST: no in-scope URL was reachable".to_string(),
            "DAST: declared URL(s) unreachable: http://127.0.0.1:9/".to_string(),
        ];
        assert_eq!(s.incomplete_reasons, want);
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(!st.complete && !st.dry_run);
        assert_eq!(st.incomplete_reasons, want);
        assert_eq!(
            st.dast.unwrap().unreachable_urls,
            vec!["http://127.0.0.1:9/"]
        );
        // coverage agrees: nothing was tested
        let cov = read_json(&dir, "dast-coverage.json");
        assert_eq!(cov["scanned"], 0);
    }

    #[test]
    fn one_dead_declared_url_among_live_ones_is_still_incomplete() {
        let dir = unique_dir();
        let mut eng = dast_engagement();
        eng.urls.push("https://d.example.com/".into());
        // HostRun echoes every probe; make d.example.com dead by wrapping it
        struct OneDead;
        impl Runner for OneDead {
            fn run_json(
                &self,
                t: &str,
                a: &[String],
                g: &[String],
            ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
                let rows = HostRun { leak: None }.run_json(t, a, g)?;
                Ok(rows
                    .into_iter()
                    .filter(|r| r["input"] != "https://d.example.com/")
                    .collect())
            }
            fn run_text(
                &self,
                t: &str,
                a: &[String],
                _g: &[String],
            ) -> Result<String, Box<dyn std::error::Error>> {
                Ok(version_of(t, a))
            }
        }
        let s = run_pipeline(&eng, &OneDead, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(s.urls > 0);
        assert!(!s.complete);
        assert_eq!(
            s.incomplete_reasons,
            vec!["DAST: declared URL(s) unreachable: https://d.example.com/".to_string()]
        );
    }

    #[test]
    fn unreachable_localhost_url_gets_the_resolver_hint() {
        let dir = unique_dir();
        let s = run_pipeline(
            &urls_engagement(&["http://localhost:3000/"]),
            &DeadRun,
            &FakeTri,
            &dir,
            false,
            None,
            7200,
        )
        .unwrap();
        assert!(!s.complete);
        let r = s
            .incomplete_reasons
            .iter()
            .find(|r| r.contains("unreachable"))
            .unwrap();
        assert_eq!(
            r,
            "DAST: declared URL(s) unreachable: http://localhost:3000/ — ProjectDiscovery tools may not resolve localhost; use 127.0.0.1"
        );
    }

    #[test]
    fn all_off_scope_surface_is_incomplete() {
        struct OffRun;
        impl Runner for OffRun {
            fn run_json(
                &self,
                t: &str,
                _a: &[String],
                _g: &[String],
            ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
                Ok(match t {
                    "httpx" => vec![json!({"url":"https://evil.test/"})],
                    _ => vec![],
                })
            }
            fn run_text(
                &self,
                t: &str,
                a: &[String],
                _g: &[String],
            ) -> Result<String, Box<dyn std::error::Error>> {
                Ok(version_of(t, a))
            }
        }
        let dir = unique_dir();
        let mut eng = engagement();
        eng.urls.clear();
        let s = run_pipeline(&eng, &OffRun, &FakeTri, &dir, false, None, 7200).unwrap();
        assert!(!s.complete);
        assert_eq!(
            s.incomplete_reasons,
            vec!["DAST: no in-scope URL was reachable".to_string()]
        );
    }

    #[test]
    fn dry_run_coverage_says_nothing_was_sent() {
        let dir = unique_dir();
        let s = run_pipeline(
            &dast_engagement(),
            &HostRun { leak: None },
            &FakeTri,
            &dir,
            true,
            None,
            7200,
        )
        .unwrap();
        assert!(!s.complete);
        // a dry run is incomplete by itself; no DAST reachability reasons are invented
        assert!(
            s.incomplete_reasons.is_empty(),
            "{:?}",
            s.incomplete_reasons
        );
        let cov = read_json(&dir, "dast-coverage.json");
        assert_eq!(cov["scanned"], 0);
        let sqli = cov["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "sqli")
            .unwrap()
            .clone();
        assert_eq!(sqli["status"], "not_tested");
        assert_eq!(sqli["reason"], "dry run: nothing was sent");
    }

    #[test]
    fn dash_prefixed_source_is_rejected() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let r = run_pipeline(
            &eng,
            &SastRun,
            &FakeTri,
            &out,
            false,
            Some("--config=evil"),
            7200,
        );
        assert!(r.is_err());
        assert!(r.err().unwrap().to_string().contains("'-'"));
    }
}
