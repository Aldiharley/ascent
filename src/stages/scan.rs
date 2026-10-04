use crate::models::Finding;
use crate::normalise::normalise_nuclei;
use crate::runner::Runner;
use std::collections::BTreeSet;
use url::Url;

pub fn ensure_nuclei_version(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("nuclei", &["-version".into()], &[])?;
    let re_ok = out.split_whitespace().find_map(|w| {
        let w = w.trim_start_matches('v');
        let p: Vec<_> = w.split('.').filter_map(|n| n.parse::<u32>().ok()).collect();
        if p.len() == 3 {
            Some(p)
        } else {
            None
        }
    });
    match re_ok {
        Some(p) if (p[0], p[1], p[2]) >= (3, 10, 0) => Ok(()),
        _ => Err("nuclei >= v3.10.0 required (CVE-2026-76802)".into()),
    }
}

pub fn scan(
    runner: &dyn Runner,
    urls: &[String],
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    if urls.is_empty() {
        return Ok(vec![]);
    }
    let hosts: BTreeSet<String> = urls
        .iter()
        .filter_map(|u| {
            Url::parse(u)
                .ok()
                .and_then(|p| p.host_str().map(String::from))
        })
        .collect();
    let mut args: Vec<String> = vec![
        "-silent".into(),
        "-jsonl".into(),
        "-tags".into(),
        "cve,exposure,misconfig,tech".into(),
    ];
    for u in urls {
        args.push("-u".into());
        args.push(u.clone());
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
}
