use crate::runner::Runner;
use std::collections::BTreeSet;

/// Refuse to run recon with anything but ProjectDiscovery httpx: a pip-installed
/// Python `httpx` (`Usage: httpx [OPTIONS] URL`) can shadow it on PATH.
pub fn ensure_httpx_identity(runner: &dyn Runner) -> Result<(), Box<dyn std::error::Error>> {
    let out = runner.run_text("httpx", &["-version".into()], &[])?;
    if out.to_ascii_lowercase().contains("projectdiscovery") {
        Ok(())
    } else {
        Err("httpx on PATH is not ProjectDiscovery httpx (a pip-installed Python `httpx` \
             can shadow it); put ProjectDiscovery httpx first on PATH"
            .into())
    }
}

pub fn recon(
    runner: &dyn Runner,
    root_domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let subs = runner.run_json(
        "subfinder",
        &[
            "-silent".into(),
            "-json".into(),
            "-d".into(),
            root_domain.into(),
        ],
        &[root_domain.into()],
    )?;
    let mut hosts: BTreeSet<String> = subs
        .iter()
        .filter_map(|s| s["host"].as_str().map(String::from))
        .collect();
    hosts.insert(root_domain.into());
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
            recon(&Fake, "example.com").unwrap(),
            vec!["https://app.example.com".to_string()]
        );
    }
}
