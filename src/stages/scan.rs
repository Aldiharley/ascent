use crate::models::Finding;
use crate::normalise::normalise_nuclei;
use crate::runner::Runner;
use std::collections::BTreeSet;
use url::Url;

/// Parses a strict `MAJOR.MINOR.PATCH` token; any non-numeric part rejects it.
fn parse_semver(tok: &str) -> Option<(u32, u32, u32)> {
    let p: Result<Vec<u32>, _> = tok.split('.').map(str::parse::<u32>).collect();
    match p.ok()?.as_slice() {
        [a, b, c] => Some((*a, *b, *c)),
        _ => None,
    }
}

pub fn ensure_nuclei_version(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("nuclei", &["-version".into()], &[])?;
    // Prefer a v-prefixed token; fall back to a bare one.
    let ver = out
        .split_whitespace()
        .find_map(|w| w.strip_prefix('v').and_then(parse_semver))
        .or_else(|| out.split_whitespace().find_map(parse_semver));
    match ver {
        Some(v) if v >= (3, 10, 0) => Ok(()),
        _ => Err("nuclei >= v3.10.0 required (CVE-2026-76802)".into()),
    }
}

pub fn scan(
    runner: &dyn Runner,
    urls: &[String],
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    // Targets and `-u` args are derived in one pass so every URL nuclei scans has its
    // host scope-checked; URLs without a host are never scanned.
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut args: Vec<String> = vec![
        "-silent".into(),
        "-jsonl".into(),
        "-tags".into(),
        "cve,exposure,misconfig,tech".into(),
    ];
    for u in urls {
        if let Some(h) = Url::parse(u)
            .ok()
            .and_then(|p| p.host_str().map(String::from))
        {
            hosts.insert(h);
            args.push("-u".into());
            args.push(u.clone());
        }
    }
    if hosts.is_empty() {
        return Ok(vec![]);
    }
    let hv: Vec<String> = hosts.into_iter().collect();
    Ok(normalise_nuclei(&runner.run_json("nuclei", &args, &hv)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::{json, Value};
    struct Fake;
    impl Runner for Fake {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(vec![
                json!({"template-id":"CVE-1","info":{"name":"x","severity":"high"},
                "matched-at":"https://app.example.com/"}),
            ])
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
    #[test]
    fn scan_returns_findings() {
        let out = scan(&Fake, &["https://app.example.com/".into()]).unwrap();
        assert_eq!(out[0].tool, "nuclei");
        assert_eq!(out[0].severity, "HIGH");
    }

    use std::cell::RefCell;
    type Call = (String, Vec<String>, Vec<String>);
    #[derive(Default)]
    struct Rec {
        calls: RefCell<Vec<Call>>,
    }
    impl Runner for Rec {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            self.calls
                .borrow_mut()
                .push((t.to_string(), a.to_vec(), g.to_vec()));
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

    #[test]
    fn host_less_url_is_neither_scanned_nor_gate_bypassing() {
        let rec = Rec::default();
        let urls = vec![
            "https://app.example.com/".to_string(),
            "evil.com:8080/x".to_string(),
        ];
        scan(&rec, &urls).unwrap();
        let calls = rec.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "nuclei");
        assert_eq!(targets, &vec!["app.example.com".to_string()]);
        assert!(!args.iter().any(|a| a.contains("evil.com")));
        assert!(args.contains(&"https://app.example.com/".to_string()));
    }

    #[test]
    fn all_host_less_input_does_not_call_runner() {
        let rec = Rec::default();
        let urls = vec!["evil.com/x".to_string(), "evil.com:8080/x".to_string()];
        let out = scan(&rec, &urls).unwrap();
        assert!(out.is_empty());
        assert!(rec.calls.borrow().is_empty());
    }

    struct Ver(&'static str);
    impl Runner for Ver {
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
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn nuclei_version_gate() {
        for ok in ["[INF] Nuclei Engine Version: v3.10.1", "3.10.0", "v3.10.0"] {
            assert!(ensure_nuclei_version(&Ver(ok)).is_ok(), "{ok}");
        }
        for bad in ["v3.9.9", "", "garbage", "x.3.10", "v2.99.99"] {
            assert!(ensure_nuclei_version(&Ver(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn nuclei_version_prefers_v_prefixed_token() {
        // An unrelated 3-number token must not be mistaken for the version.
        let out = "[INF] build 9.9.9 Nuclei Engine Version: v3.9.0";
        assert!(ensure_nuclei_version(&Ver(out)).is_err());
    }
}
