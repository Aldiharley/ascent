//! Pure readers over the pipeline output directory. None of these panic: any
//! missing or malformed input degrades to an empty value.
use serde_json::Value;
use std::path::Path;

/// Triaged items from `<out_dir>/queue.json`. Missing file or non-array JSON -> empty.
pub fn read_findings(out_dir: &str) -> Vec<Value> {
    std::fs::read_to_string(Path::new(out_dir).join("queue.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .unwrap_or_default()
}

/// Entries of `<out_dir>/audit.jsonl` plus whether Crux's own verifier accepts
/// the hash chain. Unparseable lines are skipped (the verifier flags them).
pub fn read_audit(out_dir: &str) -> (Vec<Value>, bool) {
    let path = Path::new(out_dir).join("audit.jsonl");
    let chain_ok = crux::AuditLog::new(&path).verify().0;
    let entries = std::fs::read_to_string(&path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .collect()
        })
        .unwrap_or_default();
    (entries, chain_ok)
}

/// Contents of `<out_dir>/report.md`, or `""` if unreadable.
pub fn read_report(out_dir: &str) -> String {
    std::fs::read_to_string(Path::new(out_dir).join("report.md")).unwrap_or_default()
}

/// The engagement YAML as JSON; `Null` if missing or unparseable.
pub fn read_engagement(path: &str) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_yaml_ng::from_str::<Value>(&t).ok())
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ascent_read_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn s(p: &std::path::Path) -> &str {
        p.to_str().unwrap()
    }

    fn write_audit(dir: &std::path::Path) {
        let mut log = crux::AuditLog::new(dir.join("audit.jsonl"));
        log.append("f1", "h1", "mock", "TRUE_POSITIVE", 0.9, 0.1)
            .unwrap();
        log.append("f2", "h2", "mock", "FALSE_POSITIVE", 0.8, 0.7)
            .unwrap();
    }

    #[test]
    fn reads_findings() {
        let dir = tmp();
        std::fs::write(
            dir.join("queue.json"),
            r#"[{"verdict":"TRUE_POSITIVE","confidence":0.9,"finding":{"title":"SQLi"}}]"#,
        )
        .unwrap();
        let f = read_findings(s(&dir));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["verdict"], "TRUE_POSITIVE");
    }

    #[test]
    fn missing_queue_is_empty() {
        assert!(read_findings(s(&tmp())).is_empty());
    }

    #[test]
    fn non_array_queue_is_empty() {
        let dir = tmp();
        std::fs::write(dir.join("queue.json"), r#"{"verdict":"x"}"#).unwrap();
        assert!(read_findings(s(&dir)).is_empty());
        std::fs::write(dir.join("queue.json"), "not json").unwrap();
        assert!(read_findings(s(&dir)).is_empty());
    }

    #[test]
    fn reads_report() {
        let dir = tmp();
        std::fs::write(dir.join("report.md"), "# Report\n").unwrap();
        assert_eq!(read_report(s(&dir)), "# Report\n");
    }

    #[test]
    fn missing_report_is_empty() {
        assert_eq!(read_report(s(&tmp())), "");
    }

    #[test]
    fn reads_engagement_yaml() {
        let dir = tmp();
        let p = dir.join("eng.yaml");
        std::fs::write(
            &p,
            "name: Acme\nhosts:\n  - a.example.com\n  - b.example.com\n",
        )
        .unwrap();
        let e = read_engagement(s(&p));
        assert_eq!(e["name"], "Acme");
        assert_eq!(e["hosts"][1], "b.example.com");
    }

    #[test]
    fn missing_engagement_is_null() {
        let dir = tmp();
        assert!(read_engagement(s(&dir.join("nope.yaml"))).is_null());
    }

    #[test]
    fn audit_from_crux_verifies() {
        let dir = tmp();
        write_audit(&dir);
        let (entries, ok) = read_audit(s(&dir));
        assert_eq!(entries.len(), 2);
        assert!(ok);
        assert_eq!(entries[0]["finding_id"], "f1");
    }

    #[test]
    fn tampered_audit_fails_chain() {
        let dir = tmp();
        write_audit(&dir);
        let path = dir.join("audit.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let edited = text.replacen("TRUE_POSITIVE", "TRUE_POSITIVEX", 1);
        assert_ne!(text, edited);
        std::fs::write(&path, edited).unwrap();
        let (entries, ok) = read_audit(s(&dir));
        assert_eq!(entries.len(), 2);
        assert!(!ok);
    }

    #[test]
    fn missing_audit_is_empty_and_ok() {
        let (entries, ok) = read_audit(s(&tmp()));
        assert!(entries.is_empty());
        assert!(ok);
    }

    #[test]
    fn invalid_audit_line_skipped_and_chain_fails() {
        let dir = tmp();
        write_audit(&dir);
        let path = dir.join("audit.jsonl");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("garbage\n\n");
        std::fs::write(&path, text).unwrap();
        let (entries, ok) = read_audit(s(&dir));
        assert_eq!(entries.len(), 2);
        assert!(!ok);
    }
}
