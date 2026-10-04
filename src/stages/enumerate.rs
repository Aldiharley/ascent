use crate::runner::Runner;
use std::collections::BTreeSet;
use url::Url;

pub fn enumerate_surface(
    runner: &dyn Runner,
    urls: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if urls.is_empty() {
        return Ok(vec![]);
    }
    // Targets and `-u` args are derived in one pass so every URL katana scans has its
    // host scope-checked; URLs without a host are never scanned.
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut args: Vec<String> = vec!["-silent".into(), "-jsonl".into()];
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
    let mut set: BTreeSet<String> = urls.iter().cloned().collect();
    if hosts.is_empty() {
        return Ok(set.into_iter().collect());
    }
    let hv: Vec<String> = hosts.into_iter().collect();
    let rows = runner.run_json("katana", &args, &hv)?;
    for r in rows {
        if let Some(e) = r["endpoint"].as_str() {
            set.insert(e.to_string());
        }
    }
    Ok(set.into_iter().collect())
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
            Ok(vec![json!({"endpoint":"https://app.example.com/login"})])
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
    fn merges_endpoints() {
        let out = enumerate_surface(&Fake, &["https://app.example.com".into()]).unwrap();
        assert!(out.contains(&"https://app.example.com/login".to_string()));
        assert!(out.contains(&"https://app.example.com".to_string()));
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
            "evil.com:8080".to_string(),
            "https://app.example.com".to_string(),
        ];
        let out = enumerate_surface(&rec, &urls).unwrap();
        let calls = rec.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "katana");
        assert_eq!(targets, &vec!["app.example.com".to_string()]);
        assert!(!args.iter().any(|a| a.contains("evil.com")));
        assert!(args.contains(&"https://app.example.com".to_string()));
        assert!(out.contains(&"evil.com:8080".to_string()));
    }

    #[test]
    fn all_host_less_input_does_not_call_runner() {
        let rec = Rec::default();
        let urls = vec!["evil.com".to_string(), "evil.com:8080".to_string()];
        let out = enumerate_surface(&rec, &urls).unwrap();
        assert!(rec.calls.borrow().is_empty());
        assert_eq!(
            out,
            vec!["evil.com".to_string(), "evil.com:8080".to_string()]
        );
    }
}
