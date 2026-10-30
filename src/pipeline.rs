use crate::gate::fingerprint::relative_to;
use crate::report::to_markdown;
use crate::runner::Runner;
use crate::runstatus::{now_ts, write_run_status, RunStatus};
use crate::scope::Engagement;
use crate::stages::{
    enumerate::enumerate_surface,
    recon::{ensure_httpx_identity, recon},
    sast::{is_within, sast},
    scan::{ensure_nuclei_version, scan},
};
use crate::triage::{write_atomic, TriageEngine};
use std::path::Path;

pub struct Summary {
    pub urls: usize,
    pub findings: usize,
    pub triaged: usize,
    pub report_path: String,
    pub audit_path: String,
    /// True only for a non-dry run in which every SAST analyser that is present completed.
    pub complete: bool,
    pub failed_tools: Vec<String>,
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
const STALE_OUTPUTS: [&str; 3] = ["gate.json", "ascent.sarif", "ascent-dast.sarif"];

/// Effective SAST source root: the `--source` override if non-empty, else the
/// engagement's `source`, else none. An override must lie within the engagement's
/// source root (when one is set). The result is canonical, existing, and cannot
/// be read as a tool flag.
fn resolve_source(
    eng: &Engagement,
    source: Option<&str>,
) -> Result<Option<String>, ConfigError> {
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
    write_run_status(out_dir, &RunStatus { complete: false, dry_run, failed_tools: vec![],
        skipped_tools: vec![], finished_at: String::new() })?;
    let root = eng.hosts.first().cloned().unwrap_or_default();
    // In dry-run the runner returns empty output, which would always fail these checks.
    // nuclei is needed only with DAST scope; httpx only when recon runs.
    if !dry_run && (!eng.hosts.is_empty() || !eng.urls.is_empty()) {
        ensure_nuclei_version(runner)?;
    }
    if !dry_run && !root.is_empty() {
        ensure_httpx_identity(runner)?;
    }
    let mut urls = if !root.is_empty() {
        recon(runner, &root)?
    } else {
        eng.urls.clone()
    };
    urls = enumerate_surface(runner, &urls)?;
    let mut findings = if !urls.is_empty() {
        scan(runner, &urls)?
    } else {
        vec![]
    };
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
    std::fs::write(&report_path, to_markdown(&items, &eng.name))?;
    crate::sarif::write_sarif(out_dir, &crate::sarif::item_values(&items), eff_source.as_deref())?;
    let complete = !dry_run && failed_tools.is_empty();
    write_run_status(out_dir, &RunStatus { complete, dry_run, failed_tools: failed_tools.clone(),
        skipped_tools, finished_at: now_ts() })?;
    Ok(Summary {
        urls: urls.len(),
        findings: findings.len(),
        triaged: items.len(),
        report_path: report_path.to_string_lossy().into(),
        audit_path: Path::new(out_dir)
            .join("audit.jsonl")
            .to_string_lossy()
            .into(),
        complete,
        failed_tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Finding;
    use crate::runner::Runner;
    use crate::scope::Engagement;
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
            _a: &[String],
            _t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool {
                "subfinder" => vec![json!({"host":"app.example.com"})],
                "httpx" => vec![json!({"url":"https://app.example.com"})],
                "katana" => vec![json!({"endpoint":"https://app.example.com/login"})],
                "nuclei" => vec![
                    json!({"template-id":"sqli","info":{"name":"SQLi","severity":"high"},
                    "matched-at":"https://app.example.com/login"}),
                ],
                _ => vec![],
            })
        }
        fn run_text(
            &self,
            t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t))
        }
    }

    /// `-version` output of the real ProjectDiscovery tools.
    fn version_of(tool: &str) -> String {
        match tool {
            "httpx" => "projectdiscovery.io\n[INF] Current Version: v1.12.0".into(),
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
        let s = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None).unwrap();
        assert!(s.findings >= 1);
        assert!(std::path::Path::new(&s.report_path).exists());
    }

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
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(version_of(t))
        }
    }

    #[test]
    fn source_only_engagement_needs_no_nuclei() {
        let src = std::path::PathBuf::from(unique_dir());
        let out = unique_dir();
        let mut eng = sast_engagement(&src);
        eng.urls = vec![];
        // EmptyRun's run_text returns "": the nuclei version gate would fail if it ran.
        let s = run_pipeline(&eng, &EmptyRun, &FakeTri, &out, false, None).unwrap();
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
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok(match t {
                "httpx" => "Usage: httpx [OPTIONS] URL".into(),
                _ => version_of(t),
            })
        }
    }

    #[test]
    fn recon_refuses_a_non_projectdiscovery_httpx() {
        let dir = unique_dir();
        let e = run_pipeline(&engagement(), &PyHttpxRun, &FakeTri, &dir, false, None).err().unwrap();
        assert!(e.to_string().contains("not ProjectDiscovery httpx"), "{e}");
        // dry-run skips the identity check (the runner returns "")
        assert!(run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None).is_ok());
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
            },
        )
        .unwrap();
        assert!(run_pipeline(&engagement(), &FailRun, &FakeTri, &dir, false, None).is_err());
        let st = crate::runstatus::read_run_status(&dir).unwrap();
        assert!(!st.complete, "stale complete=true survived an aborted run");
    }

    #[test]
    fn stale_gate_and_sarif_never_survive_a_new_run() {
        let dir = unique_dir();
        for n in STALE_OUTPUTS {
            std::fs::write(std::path::Path::new(&dir).join(n), r#"{"decision":"PASS"}"#).unwrap();
        }
        assert!(run_pipeline(&engagement(), &FailRun, &FakeTri, &dir, false, None).is_err());
        for n in STALE_OUTPUTS {
            assert!(!std::path::Path::new(&dir).join(n).exists(), "stale {n} survived an aborted run");
        }
    }

    #[test]
    fn tampered_audit_is_an_integrity_error_and_nothing_is_reset() {
        let dir = unique_dir();
        seed_stale_queue(&dir);
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        std::fs::write(&audit, "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n").unwrap();
        let e = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false, None).err().unwrap();
        assert!(e.downcast_ref::<IntegrityError>().is_some(), "{e}");
        assert_eq!(queue(&dir)[0]["finding"]["title"], "stale from last run");
        assert!(!std::path::Path::new(&dir).join("run.json").exists());
    }

    #[test]
    fn bad_source_is_a_config_error() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let e = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, Some("--config=evil")).err().unwrap();
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
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None).unwrap();
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
        assert!(run_pipeline(&engagement(), &FakeRun, &FailTri, &dir, false, None).is_err());
        assert_eq!(queue(&dir), json!([]));
    }

    #[test]
    fn dry_run_skips_version_check() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true, None).unwrap();
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
                return Ok(vec![json!({"results":[{"check_id":"r","path":path.to_string_lossy(),
                    "start":{"line":1},"extra":{"severity":"ERROR","message":"m","lines":"q(x)"}}]})]);
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
        run_pipeline(&eng, &AbsSastRun, &tri, dir.to_str().unwrap(), false, None).unwrap();
        let items = tri.0.borrow().clone();
        let sast_item = items.iter().find(|it| it["finding"]["tool"] == "opengrep").unwrap();
        assert_eq!(sast_item["finding"]["file"], "sub/a.rs");
        // The gate fingerprint must equal the SARIF partialFingerprints value.
        let policy = crate::gate::policy::parse_policy(
            "version: 1\nfail_on:\n  severity: [CRITICAL, HIGH, MEDIUM, LOW, INFO]\n  categories: [SAST]\n",
        )
        .unwrap();
        let st = crate::runstatus::read_run_status(dir.to_str().unwrap()).unwrap();
        let r = crate::gate::evaluate::evaluate(&items, &policy, Some(&st), false);
        assert_eq!(r.failed.len(), 1);
        let sarif: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("ascent.sarif")).unwrap()).unwrap();
        let res = &sarif["runs"][0]["results"][0];
        assert_eq!(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "sub/a.rs");
        assert_eq!(res["partialFingerprints"]["ascentFindingHash/v1"], r.failed[0].fingerprint.as_str());
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
        let s = run_pipeline(&eng, &CrashingOpengrepRun, &FakeTri, d, false, None).unwrap();
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
        let s = run_pipeline(&eng, &SastRun, &FakeTri, dir.to_str().unwrap(), false, None).unwrap();
        // 1 DAST (nuclei) + 1 SAST (opengrep) finding both reach triage.
        assert_eq!(s.findings, 2);
        assert_eq!(s.triaged, 2);
    }

    #[test]
    fn engagement_without_source_runs_dast_only() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let s = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, None).unwrap();
        assert_eq!(s.findings, 1); // nuclei only; opengrep never ran
    }

    #[test]
    fn dry_run_skips_sast() {
        let dir = std::path::PathBuf::from(unique_dir());
        let eng = sast_engagement(&dir);
        let s = run_pipeline(&eng, &SastRun, &FakeTri, dir.to_str().unwrap(), true, None).unwrap();
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
        let s = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, src.to_str()).unwrap();
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
        );
        assert!(r.is_err());
    }

    #[test]
    fn dash_prefixed_source_is_rejected() {
        let out = unique_dir();
        let mut eng = sast_engagement(std::path::Path::new(&out));
        eng.source = String::new();
        let r = run_pipeline(&eng, &SastRun, &FakeTri, &out, false, Some("--config=evil"));
        assert!(r.is_err());
        assert!(r.err().unwrap().to_string().contains("'-'"));
    }
}
