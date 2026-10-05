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
        write_atomic(
            &dir.join("queue.json"),
            (serde_json::to_string_pretty(&items)? + "\n").as_bytes(),
        )?;
        // Crux's queue-entry serialisation is the `--emit-json` shape TriageItem reads.
        items
            .iter()
            .map(|it| Ok(serde_json::from_value(serde_json::to_value(it)?)?))
            .collect()
    }
}

/// Replace `path` atomically: write `<path>.tmp` in the same directory, sync
/// it, then rename it over `path`. A failure never leaves a half-written file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| {
        let mut fh = std::fs::File::create(&tmp)?;
        fh.write_all(bytes)?;
        fh.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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

    #[test]
    fn write_atomic_replaces_file_and_leaves_no_temp() {
        let dir = unique_dir();
        let target = dir.join("queue.json");
        std::fs::write(&target, "old").unwrap();
        write_atomic(&target, b"[]\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "[]\n");
        assert!(!dir.join("queue.json.tmp").exists());
    }

    #[test]
    fn write_atomic_failure_keeps_old_file() {
        // The temp path is occupied by a directory, so the write must fail
        // without touching the existing queue.json.
        let dir = unique_dir();
        let target = dir.join("queue.json");
        std::fs::write(&target, "old").unwrap();
        std::fs::create_dir_all(dir.join("queue.json.tmp")).unwrap();
        assert!(write_atomic(&target, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
    }

    #[test]
    fn crux_writes_queue_json_in_emit_json_shape() {
        let dir = unique_dir();
        CruxTriager::default()
            .triage(
                &[dast("n1", "http://localhost:3000/ping")],
                dir.to_str().unwrap(),
            )
            .unwrap();
        let q: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(dir.join("queue.json")).unwrap())
                .unwrap();
        assert_eq!(q.len(), 1);
        for k in [
            "finding",
            "verdict",
            "confidence",
            "fp_likelihood",
            "rationale",
            "remediation",
            "triager",
            "duplicates",
        ] {
            assert!(q[0].get(k).is_some(), "queue.json entry missing {k}");
        }
        assert_eq!(q[0]["finding"]["url"], "http://localhost:3000/ping");
    }
}
