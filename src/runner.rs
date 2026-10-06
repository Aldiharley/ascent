use crate::scope::ScopeGuard;
use serde_json::Value;
use std::process::Command;

pub trait Runner {
    fn run_json(
        &self,
        tool: &str,
        args: &[String],
        targets: &[String],
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>>;
    fn run_text(
        &self,
        tool: &str,
        args: &[String],
        targets: &[String],
    ) -> Result<String, Box<dyn std::error::Error>>;
}

pub fn parse_jsonl(stdout: &str) -> Vec<Value> {
    // A single JSON document (array, or one possibly pretty-printed object) takes precedence;
    // multi-line JSONL is not a valid single document and falls through to per-line parsing.
    if let Ok(v) = serde_json::from_str::<Value>(stdout) {
        return match v {
            Value::Array(a) => a,
            other => vec![other],
        };
    }
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

pub struct ToolRunner {
    pub guard: ScopeGuard,
    pub dry_run: bool,
}

impl ToolRunner {
    pub fn new(guard: ScopeGuard, dry_run: bool) -> Self {
        ToolRunner { guard, dry_run }
    }
    fn check(&self, targets: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        for t in targets {
            self.guard.assert_in_scope(t)?;
        }
        Ok(())
    }
}

impl Runner for ToolRunner {
    fn run_text(
        &self,
        tool: &str,
        args: &[String],
        targets: &[String],
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.check(targets)?;
        if self.dry_run {
            return Ok(String::new());
        }
        let out = Command::new(tool).args(args).output()?;
        Ok(
            String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr),
        )
    }
    fn run_json(
        &self,
        tool: &str,
        args: &[String],
        targets: &[String],
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        self.check(targets)?;
        if self.dry_run {
            return Ok(vec![]);
        }
        let out = Command::new(tool).args(args).output()?;
        Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Engagement;

    fn runner(dry_run: bool) -> ToolRunner {
        let e = Engagement {
            name: "t".into(),
            hosts: vec!["example.com".into()],
            cidrs: vec![],
            urls: vec![],
            source: String::new(),
            starts: "2026-01-01T00:00:00Z".into(),
            ends: "2026-12-31T00:00:00Z".into(),
        };
        ToolRunner::new(ScopeGuard::new(&e), dry_run)
    }

    #[test]
    fn run_json_refuses_out_of_scope_even_in_dry_run() {
        let r = runner(true);
        let err = r.run_json("httpx", &[], &["evil.com".into()]).unwrap_err();
        assert!(err.to_string().contains("not in engagement scope"));
    }

    #[test]
    fn run_text_refuses_out_of_scope_even_in_dry_run() {
        let r = runner(true);
        assert!(r.run_text("httpx", &[], &["evil.com".into()]).is_err());
    }

    #[test]
    fn one_out_of_scope_target_among_many_refuses_whole_call() {
        let r = runner(true);
        let targets = ["example.com".to_string(), "evil.com".to_string()];
        assert!(r.run_json("httpx", &[], &targets).is_err());
    }

    #[test]
    fn in_scope_dry_run_passes_gate_and_returns_empty_without_spawning() {
        let r = runner(true);
        let v = r.run_json("httpx", &[], &["example.com".into()]).unwrap();
        assert!(v.is_empty());
        let t = r.run_text("httpx", &[], &["example.com".into()]).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn jsonl_parses_lines() {
        let v = parse_jsonl("{\"a\":1}\n{\"a\":2}\n");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["a"], 1);
    }
    #[test]
    fn jsonl_falls_back_to_array() {
        let v = parse_jsonl("[{\"a\":1},{\"a\":2}]");
        assert_eq!(v.len(), 2);
    }
}
