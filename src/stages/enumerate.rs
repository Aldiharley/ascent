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
    let hosts: BTreeSet<String> = urls
        .iter()
        .filter_map(|u| {
            Url::parse(u)
                .ok()
                .and_then(|p| p.host_str().map(String::from))
        })
        .collect();
    let mut args = vec!["-silent".into(), "-jsonl".into()];
    for u in urls {
        args.push("-u".into());
        args.push(u.clone());
    }
    let hv: Vec<String> = hosts.into_iter().collect();
    let rows = runner.run_json("katana", &args, &hv)?;
    let mut set: BTreeSet<String> = urls.iter().cloned().collect();
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
}
