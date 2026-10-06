use crate::report::to_markdown;
use crate::runner::Runner;
use crate::scope::Engagement;
use crate::stages::{
    enumerate::enumerate_surface,
    recon::recon,
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
}

/// Effective SAST source root: the `--source` override if non-empty, else the
/// engagement's `source`, else none. An override must lie within the engagement's
/// source root (when one is set). The result is canonical, existing, and cannot
/// be read as a tool flag.
fn resolve_source(
    eng: &Engagement,
    source: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let raw = match source {
        Some(s) if !s.is_empty() => {
            if !eng.source.is_empty() && !is_within(Path::new(&eng.source), Path::new(s)) {
                return Err("--source is outside the engagement's authorised source root".into());
            }
            s
        }
        _ if !eng.source.is_empty() => eng.source.as_str(),
        _ => return Ok(None),
    };
    if raw.starts_with('-') {
        return Err("source path must not start with '-'".into());
    }
    let canon = Path::new(raw)
        .canonicalize()
        .map_err(|e| format!("source path {raw:?} is not accessible: {e}"))?;
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
    // Resolve and validate the SAST source root first so a bad `--source` fails
    // before any tool runs or any output is written.
    let eff_source = resolve_source(eng, source)?;
    std::fs::create_dir_all(out_dir)?;
    // Reset the triage queue up front so a re-run that yields no findings (or
    // fails before triage writes it) never shows the previous run's findings.
    write_atomic(&Path::new(out_dir).join("queue.json"), b"[]\n")?;
    // In dry-run the runner returns empty output, which would always fail the version gate.
    if !dry_run {
        ensure_nuclei_version(runner)?;
    }
    let root = eng.hosts.first().cloned().unwrap_or_default();
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
    if let Some(src) = eff_source {
        if !dry_run {
            findings.extend(sast(runner, &src)?);
        }
    }
    let items = if !findings.is_empty() {
        triager.triage(&findings, out_dir)?
    } else {
        vec![]
    };
    let report_path = Path::new(out_dir).join("report.md");
    std::fs::write(&report_path, to_markdown(&items, &eng.name))?;
    Ok(Summary {
        urls: urls.len(),
        findings: findings.len(),
        triaged: items.len(),
        report_path: report_path.to_string_lossy().into(),
        audit_path: Path::new(out_dir)
            .join("audit.jsonl")
            .to_string_lossy()
            .into(),
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
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            Ok("nuclei v3.10.1".into())
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
        }
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
