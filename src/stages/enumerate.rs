use crate::runner::Runner;
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

/// The URL of one katana `-jsonl` row: `request.endpoint` (katana v1.x), else a
/// legacy top-level `endpoint`.
fn endpoint_of(r: &Value) -> Option<&str> {
    r.pointer("/request/endpoint")
        .or_else(|| r.get("endpoint"))
        .and_then(Value::as_str)
}

pub fn enumerate_surface(
    runner: &dyn Runner,
    urls: &[String],
    extra: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if urls.is_empty() {
        return Ok(vec![]);
    }
    // Targets and `-u` args are derived in one pass so every URL katana scans has its
    // host scope-checked; URLs without a host are never scanned.
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    // `-fs fqdn`: crawl only the exact hostnames given (katana defaults to the whole
    // registered domain, which would contact, and send auth to, out-of-scope siblings).
    // `-jc` parses endpoints out of JavaScript (an SPA exposes nothing else), `-rl 50`
    // caps requests per second and `-dr` keeps katana from following redirects.
    let mut args: Vec<String> = vec![
        "-silent".into(),
        "-jsonl".into(),
        "-jc".into(),
        "-rl".into(),
        "50".into(),
        "-dr".into(),
        "-fs".into(),
        "fqdn".into(),
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
    let mut set: BTreeSet<String> = urls.iter().cloned().collect();
    if hosts.is_empty() {
        return Ok(set.into_iter().collect());
    }
    // Caller-supplied flags (e.g. an auth header) follow the `-u` list.
    args.extend(extra.iter().cloned());
    let hv: Vec<String> = hosts.into_iter().collect();
    let rows = runner.run_json("katana", &args, &hv)?;
    let found: Vec<&str> = rows.iter().filter_map(endpoint_of).collect();
    // Rows that all lack a URL mean katana's output format changed: fail closed
    // rather than report an empty crawl.
    if !rows.is_empty() && found.is_empty() {
        return Err("katana output format not recognised".into());
    }
    set.extend(found.into_iter().map(String::from));
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::{json, Value};

    /// One row of real katana v1.7 `-jsonl` output: the URL is nested under `request`.
    fn katana_row(endpoint: &str) -> Value {
        json!({"timestamp":"2026-10-31T00:00:00.000000+00:00",
            "request":{"method":"GET","endpoint":endpoint,"raw":"GET / HTTP/1.1\r\n\r\n"},
            "response":{"status_code":200}})
    }

    /// katana answers with the given rows.
    struct Fake(Vec<Value>);
    impl Runner for Fake {
        fn run_json(
            &self,
            _t: &str,
            _a: &[String],
            _g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(self.0.clone())
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
        let f = Fake(vec![katana_row("https://app.example.com/login")]);
        let out = enumerate_surface(&f, &["https://app.example.com".into()], &[]).unwrap();
        assert!(out.contains(&"https://app.example.com/login".to_string()));
        assert!(out.contains(&"https://app.example.com".to_string()));
    }

    #[test]
    fn legacy_top_level_endpoint_row_still_parses() {
        let f = Fake(vec![json!({"endpoint":"https://app.example.com/old"})]);
        let out = enumerate_surface(&f, &["https://app.example.com".into()], &[]).unwrap();
        assert!(out.contains(&"https://app.example.com/old".to_string()));
    }

    #[test]
    fn unrecognised_katana_output_fails_closed() {
        let f = Fake(vec![
            json!({"url":"https://app.example.com/x"}),
            json!({"request":{}}),
        ]);
        let e = enumerate_surface(&f, &["https://app.example.com".into()], &[]).unwrap_err();
        assert_eq!(e.to_string(), "katana output format not recognised");
        // no rows at all is a normal empty crawl, not format drift
        let out =
            enumerate_surface(&Fake(vec![]), &["https://app.example.com".into()], &[]).unwrap();
        assert_eq!(out, vec!["https://app.example.com".to_string()]);
    }

    #[test]
    fn katana_parses_js_is_rate_limited_and_does_not_follow_redirects() {
        let rec = Rec::default();
        enumerate_surface(&rec, &["https://app.example.com".to_string()], &[]).unwrap();
        let calls = rec.calls.borrow();
        let args = &calls[0].1;
        let u = args.iter().position(|a| a == "-u").unwrap();
        let before = &args[..u];
        assert!(before.contains(&"-jc".to_string()), "{args:?}");
        assert!(before.contains(&"-dr".to_string()), "{args:?}");
        let rl = before.iter().position(|a| a == "-rl").expect("-rl present");
        assert_eq!(args[rl + 1], "50");
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
        let out = enumerate_surface(&rec, &urls, &[]).unwrap();
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
    fn katana_is_limited_to_exact_hostnames_before_the_url_list() {
        let rec = Rec::default();
        enumerate_surface(&rec, &["https://app.example.com".to_string()], &[]).unwrap();
        let calls = rec.calls.borrow();
        let args = &calls[0].1;
        let fs = args.iter().position(|a| a == "-fs").expect("-fs present");
        assert_eq!(args[fs + 1], "fqdn");
        assert!(
            fs < args.iter().position(|a| a == "-u").unwrap(),
            "{args:?}"
        );
    }

    #[test]
    fn extra_args_reach_katana() {
        let rec = Rec::default();
        let extra = vec!["-H".to_string(), "X-Test: 1".to_string()];
        enumerate_surface(&rec, &["https://app.example.com".to_string()], &extra).unwrap();
        let calls = rec.calls.borrow();
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "katana");
        assert!(args.ends_with(&extra), "{args:?}");
        assert_eq!(targets, &vec!["app.example.com".to_string()]);
    }

    #[test]
    fn all_host_less_input_does_not_call_runner() {
        let rec = Rec::default();
        let urls = vec!["evil.com".to_string(), "evil.com:8080".to_string()];
        let out = enumerate_surface(&rec, &urls, &["-H".into(), "X-Test: 1".into()]).unwrap();
        assert!(rec.calls.borrow().is_empty());
        assert_eq!(
            out,
            vec!["evil.com".to_string(), "evil.com:8080".to_string()]
        );
    }
}
