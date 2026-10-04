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
