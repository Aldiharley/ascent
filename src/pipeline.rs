use crate::report::to_markdown;
use crate::runner::Runner;
use crate::scope::Engagement;
use crate::stages::{
    enumerate::enumerate_surface,
    recon::recon,
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

pub fn run_pipeline(
    eng: &Engagement,
    runner: &dyn Runner,
    triager: &dyn TriageEngine,
    out_dir: &str,
    dry_run: bool,
) -> Result<Summary, Box<dyn std::error::Error>> {
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
    let findings = if !urls.is_empty() {
        scan(runner, &urls)?
    } else {
        vec![]
    };
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
        let s = run_pipeline(&engagement(), &FakeRun, &FakeTri, &dir, false).unwrap();
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
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true).unwrap();
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
        assert!(run_pipeline(&engagement(), &FakeRun, &FailTri, &dir, false).is_err());
        assert_eq!(queue(&dir), json!([]));
    }

    #[test]
    fn dry_run_skips_version_check() {
        let dir = unique_dir();
        let s = run_pipeline(&engagement(), &EmptyRun, &FakeTri, &dir, true).unwrap();
        assert_eq!(s.findings, 0);
        assert!(std::path::Path::new(&s.report_path).exists());
    }
}
