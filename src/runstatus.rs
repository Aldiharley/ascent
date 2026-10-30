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
