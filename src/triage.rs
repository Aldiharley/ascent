use crate::models::Finding;
use serde::Deserialize;
use serde_json::Value;
use std::process::Command;

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

pub fn parse_crux_queue(json: &str) -> Result<Vec<TriageItem>, serde_json::Error> {
    serde_json::from_str(json)
}

pub struct CruxTriager {
    pub python: String,
}
impl Default for CruxTriager {
    fn default() -> Self {
        CruxTriager {
            python: "python".into(),
        }
    }
}

impl TriageEngine for CruxTriager {
    fn triage(
        &self,
        findings: &[Finding],
        out_dir: &str,
    ) -> Result<Vec<TriageItem>, Box<dyn std::error::Error>> {
        let dir = std::path::Path::new(out_dir);
        std::fs::create_dir_all(dir)?;
        let in_path = dir.join("findings.json");
        let q_path = dir.join("queue.json");
        let audit = dir.join("audit.jsonl");
        let arr: Vec<Value> = findings.iter().map(|f| f.to_crux_json()).collect();
        std::fs::write(&in_path, serde_json::to_string(&arr)?)?;
        let status = Command::new(&self.python)
            .args(["-m", "crux", "--input"])
            .arg(&in_path)
            .args(["--mock", "--emit-json"])
            .arg(&q_path)
            .arg("--audit")
            .arg(&audit)
            .arg("--out")
            .arg(dir.join("triage_report.md"))
            .status()?;
        if !status.success() {
            return Err(format!("crux triage failed: {status}").into());
        }
        Ok(parse_crux_queue(&std::fs::read_to_string(&q_path)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_queue() {
        let j = r#"[{"finding":{"title":"SQLi"},"verdict":"TRUE_POSITIVE","confidence":0.9,
                     "fp_likelihood":0.1,"rationale":"r","remediation":"fix"}]"#;
        let items = parse_crux_queue(j).unwrap();
        assert_eq!(items[0].verdict, "TRUE_POSITIVE");
    }
}
