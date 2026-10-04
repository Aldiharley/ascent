use crate::runner::Runner;
use std::collections::BTreeSet;

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
    #[test]
    fn recon_live_urls() {
        assert_eq!(
            recon(&Fake, "example.com").unwrap(),
            vec!["https://app.example.com".to_string()]
        );
    }
}
