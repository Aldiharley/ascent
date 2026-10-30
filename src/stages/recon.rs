use crate::runner::Runner;
use std::collections::BTreeSet;
use url::Url;

/// Refuse to run recon with anything but ProjectDiscovery httpx: a pip-installed
/// Python `httpx` (`Usage: httpx [OPTIONS] URL`) can shadow it on PATH.
pub fn ensure_httpx_identity(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("httpx", &["-version".into()], &[])?;
    if out.to_ascii_lowercase().contains("projectdiscovery") {
        Ok(())
    } else {
        Err(
            "httpx on PATH is not ProjectDiscovery httpx (a pip-installed Python `httpx` \
             can shadow it); put ProjectDiscovery httpx first on PATH"
                .into(),
        )
    }
}

/// True only for a DNS name worth passing to subfinder: it contains a `.` and is
/// not an IP literal. `localhost`, `10.0.0.5` and `::1` have no subdomains to find.
pub fn is_subfinder_candidate(host: &str) -> bool {
    host.contains('.') && host.parse::<std::net::IpAddr>().is_err()
}

/// Probes `host` (and, when `use_subfinder`, its discovered subdomains) with httpx
/// and returns the live URLs. Every host passed to a tool is also a scope target.
pub fn recon(
    runner: &dyn Runner,
    host: &str,
    use_subfinder: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    if use_subfinder {
        let subs = runner.run_json(
            "subfinder",
            &["-silent".into(), "-json".into(), "-d".into(), host.into()],
            &[host.into()],
        )?;
        hosts.extend(
            subs.iter()
                .filter_map(|s| s["host"].as_str().map(String::from)),
        );
    }
    hosts.insert(host.into());
    let mut args = vec!["-silent".into(), "-json".into()];
    for h in &hosts {
        args.push("-u".into());
        args.push(h.clone());
    }
    let hv: Vec<String> = hosts.iter().cloned().collect();
    let live = runner.run_json("httpx", &args, &hv)?;
    let urls: BTreeSet<String> = live
        .iter()
        .filter_map(|r| r["url"].as_str().map(String::from))
        .collect();
    Ok(urls.into_iter().collect())
}

/// Probes the declared `urls` with httpx (no auth header, no redirect following)
/// and splits them into `(live, dead)`, both in input order. A URL is live when
/// httpx returns a row whose `input` (else `url`) equals it, ignoring one trailing
/// `/` on either side. A URL without a host is dead and never probed. Every host
/// passed to httpx is also a scope target.
pub fn probe_urls(
    runner: &dyn Runner,
    urls: &[String],
) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut args: Vec<String> = vec!["-silent".into(), "-json".into(), "-rl".into(), "50".into()];
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
    let rows = if hosts.is_empty() {
        vec![]
    } else {
        let hv: Vec<String> = hosts.into_iter().collect();
        runner.run_json("httpx", &args, &hv)?
    };
    let norm = |s: &str| s.strip_suffix('/').unwrap_or(s).to_string();
    let answered: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r["input"].as_str().or_else(|| r["url"].as_str()))
        .map(norm)
        .collect();
    let (live, dead): (Vec<String>, Vec<String>) = urls
        .iter()
        .cloned()
        .partition(|u| Url::parse(u).is_ok_and(|p| p.host_str().is_some()) && answered.contains(&norm(u)));
    Ok((live, dead))
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
            tool: &str,
            _a: &[String],
            _t: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            Ok(match tool {
                "subfinder" => vec![json!({"host":"app.example.com"})],
                "httpx" => vec![json!({"url":"https://app.example.com"})],
                _ => vec![],
            })
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
    fn projectdiscovery_httpx_is_accepted() {
        let out = "\n    __    __  __       _  __\n   projectdiscovery.io\n[INF] Current Version: v1.12.0";
        assert!(ensure_httpx_identity(&Ver(out)).is_ok());
        assert!(ensure_httpx_identity(&Ver("ProjectDiscovery httpx")).is_ok());
    }

    #[test]
    fn python_httpx_is_rejected_with_a_clear_error() {
        let e = ensure_httpx_identity(&Ver("Usage: httpx [OPTIONS] URL")).unwrap_err();
        assert!(e.to_string().contains("not ProjectDiscovery httpx"), "{e}");
        assert!(e.to_string().contains("first on PATH"), "{e}");
    }

    #[test]
    fn recon_live_urls() {
        assert_eq!(
            recon(&Fake, "example.com", true).unwrap(),
            vec!["https://app.example.com".to_string()]
        );
    }

    #[test]
    fn subfinder_candidate_table() {
        assert!(is_subfinder_candidate("example.com"));
        assert!(is_subfinder_candidate("app.example.com"));
        for h in ["localhost", "127.0.0.1", "::1", "10.0.0.5", ""] {
            assert!(!is_subfinder_candidate(h), "{h:?}");
        }
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
            Ok(match t {
                "httpx" => vec![json!({"url":"http://localhost:3000"})],
                _ => vec![],
            })
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
    fn recon_without_subfinder_never_calls_it_and_still_probes_host() {
        let rec = Rec::default();
        let out = recon(&rec, "localhost", false).unwrap();
        assert_eq!(out, vec!["http://localhost:3000".to_string()]);
        let calls = rec.calls.borrow();
        assert!(calls.iter().all(|(t, _, _)| t != "subfinder"));
        assert_eq!(calls.len(), 1);
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "httpx");
        assert_eq!(targets, &vec!["localhost".to_string()]);
        assert!(args.contains(&"localhost".to_string()));
    }

    /// httpx answers with the given rows; every call is recorded.
    struct Probe {
        rows: Vec<Value>,
        calls: RefCell<Vec<Call>>,
    }
    impl Runner for Probe {
        fn run_json(
            &self,
            t: &str,
            a: &[String],
            g: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            self.calls
                .borrow_mut()
                .push((t.to_string(), a.to_vec(), g.to_vec()));
            Ok(self.rows.clone())
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
    fn probe_urls_uses_exact_args_and_url_hosts_as_targets() {
        let p = Probe { rows: vec![], calls: RefCell::new(vec![]) };
        let urls = vec![
            "http://127.0.0.1:3000/".to_string(),
            "https://app.example.com/login".to_string(),
        ];
        probe_urls(&p, &urls).unwrap();
        let calls = p.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (tool, args, targets) = &calls[0];
        assert_eq!(tool, "httpx");
        assert_eq!(
            args,
            &vec![
                "-silent",
                "-json",
                "-rl",
                "50",
                "-u",
                "http://127.0.0.1:3000/",
                "-u",
                "https://app.example.com/login"
            ]
        );
        assert_eq!(
            targets,
            &vec!["127.0.0.1".to_string(), "app.example.com".to_string()]
        );
    }

    #[test]
    fn probe_urls_matches_input_then_url_ignoring_one_trailing_slash() {
        let p = Probe {
            rows: vec![
                // `input` wins; a trailing slash on either side does not matter
                json!({"input":"http://127.0.0.1:3000","url":"http://127.0.0.1:3000/redirected"}),
                // no `input`: fall back to `url`
                json!({"url":"https://app.example.com/login/"}),
            ],
            calls: RefCell::new(vec![]),
        };
        let urls = vec![
            "http://127.0.0.1:3000/".to_string(),
            "https://app.example.com/login".to_string(),
            "http://127.0.0.1:9/".to_string(),
        ];
        let (live, dead) = probe_urls(&p, &urls).unwrap();
        assert_eq!(
            live,
            vec!["http://127.0.0.1:3000/", "https://app.example.com/login"]
        );
        assert_eq!(dead, vec!["http://127.0.0.1:9/"]);
    }

    #[test]
    fn probe_urls_host_less_url_is_dead_and_never_probed() {
        let p = Probe { rows: vec![], calls: RefCell::new(vec![]) };
        let (live, dead) = probe_urls(&p, &["evil.com:8080/x".to_string()]).unwrap();
        assert!(live.is_empty());
        assert_eq!(dead, vec!["evil.com:8080/x"]);
        assert!(p.calls.borrow().is_empty());
        let (live, dead) = probe_urls(&p, &[]).unwrap();
        assert!(live.is_empty() && dead.is_empty());
        assert!(p.calls.borrow().is_empty());
    }

    #[test]
    fn recon_with_subfinder_calls_it_scope_checked() {
        let rec = Rec::default();
        recon(&rec, "example.com", true).unwrap();
        let calls = rec.calls.borrow();
        assert_eq!(calls[0].0, "subfinder");
        assert_eq!(calls[0].2, vec!["example.com".to_string()]);
    }
}
