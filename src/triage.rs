use crate::models::Finding;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub struct TriageItem {
    pub finding: Value,
    pub verdict: String,
    pub confidence: f64,
    pub fp_likelihood: f64,
    pub rationale: String,
    pub remediation: String,
}

pub trait TriageEngine {
    fn triage(
        &self,
        findings: &[Finding],
        out_dir: &str,
    ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>>;
}

/// Triage through Crux, linked in-process: offline `MockTriager`, Crux's abstain
/// gate and dedup, and a hash-chained audit log at `<out_dir>/audit.jsonl` that is
/// verified before any result is returned.
pub struct CruxTriager {
    pub abstain_below: f64,
}
impl Default for CruxTriager {
    fn default() -> Self {
        CruxTriager {
            abstain_below: crux::DEFAULT_ABSTAIN_BELOW,
        }
    }
}

impl TriageEngine for CruxTriager {
    fn triage(
        &self,
        findings: &[Finding],
        out_dir: &str,
    ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
        let dir = Path::new(out_dir);
        std::fs::create_dir_all(dir)?;
        // Same JSON contract Crux's loader validates, so a malformed finding is rejected.
        let crux_findings = findings
            .iter()
            .map(|f| crux::Finding::parse(&f.to_crux_json()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut audit = crux::AuditLog::new(dir.join("audit.jsonl"));
        let items = crux::triage(
            &crux_findings,
            &crux::MockTriager,
            &mut audit,
            self.abstain_below,
        )?;
        let (ok, msg) = audit.verify();
        if !ok {
            return Err(format!("crux audit log failed verification: {msg}").into());
        }
        // Crux's queue-entry serialisation is the `--emit-json` shape TriageItem reads.
        items
            .iter()
            .map(|it| Ok(serde_json::from_value(serde_json::to_value(it)?)?))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unique_dir() -> std::path::PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "ascent_triage_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn dast(id: &str, url: &str) -> Finding {
        Finding {
            id: id.into(),
            tool: "nuclei".into(),
            rule_id: "CVE-2021-1234".into(),
            severity: "HIGH".into(),
            title: "Example RCE".into(),
            message: "m".into(),
            url: url.into(),
            category: "DAST".into(),
            cwe: "CWE-78".into(),
            ..Default::default()
        }
    }

    #[test]
    fn crux_triages_dast_findings_and_writes_verified_audit() {
        let dir = unique_dir();
        let items = CruxTriager::default()
            .triage(
                &[dast("n1", "http://localhost:3000/ping")],
                dir.to_str().unwrap(),
            )
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(["TRUE_POSITIVE", "ABSTAIN", "LIKELY_FALSE_POSITIVE"]
            .contains(&items[0].verdict.as_str()));
        assert_eq!(items[0].finding["url"], "http://localhost:3000/ping");
        assert_eq!(items[0].finding["category"], "DAST");
        assert!(dir.join("audit.jsonl").exists());
    }

    #[test]
    fn crux_merges_duplicate_findings() {
        // Same CWE + same locus from two ids: Crux dedups them into one queue item.
        let dir = unique_dir();
        let items = CruxTriager::default()
            .triage(
                &[
                    dast("a", "http://localhost:3000/ping"),
                    dast("b", "http://localhost:3000/ping"),
                ],
                dir.to_str().unwrap(),
            )
            .unwrap();
        assert_eq!(items.len(), 1);
    }
}
