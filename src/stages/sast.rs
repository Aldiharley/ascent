use crate::models::Finding;
use crate::normalise::{normalise_gitleaks, normalise_opengrep, normalise_trivy};
use crate::runner::Runner;
use std::path::Path;

/// True iff `candidate` resolves to a path inside `root`. Both must exist;
/// canonicalisation collapses `..` and resolves symlinks, so neither can escape.
#[allow(dead_code)] // wired into the pipeline in Task 4
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    match (root.canonicalize(), candidate.canonicalize()) {
        (Ok(r), Ok(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// A tool is "available" if its binary spawns (exit status is irrelevant).
#[allow(dead_code)] // wired into the pipeline in Task 4
pub fn tool_available(runner: &dyn Runner, tool: &str, version_arg: &str) -> bool {
    runner.run_text(tool, &[version_arg.into()], &[]).is_ok()
}

/// Runs each available analyser over `source_dir` (always with EMPTY network
/// targets) and merges the normalised findings. Missing tools are skipped.
#[allow(dead_code)] // wired into the pipeline in Task 4
pub fn sast(
    runner: &dyn Runner,
    source_dir: &str,
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    if tool_available(runner, "opengrep", "--version") {
        let args = vec![
            "--json".into(),
            "--quiet".into(),
            "--config".into(),
            "auto".into(),
            source_dir.into(),
        ];
        findings.extend(normalise_opengrep(&runner.run_json(
            "opengrep",
            &args,
            &[],
        )?));
    }
    if tool_available(runner, "gitleaks", "version") {
        let args = vec![
            "detect".into(),
            "--no-git".into(),
            "--report-format".into(),
            "json".into(),
            "--report-path".into(),
            "/dev/stdout".into(),
            "--source".into(),
            source_dir.into(),
        ];
        findings.extend(normalise_gitleaks(&runner.run_json(
            "gitleaks",
            &args,
            &[],
        )?));
    }
    if tool_available(runner, "trivy", "--version") {
        let args = vec![
            "fs".into(),
            "--quiet".into(),
            "--format".into(),
            "json".into(),
            source_dir.into(),
        ];
        findings.extend(normalise_trivy(&runner.run_json("trivy", &args, &[])?));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Runner;
    use serde_json::{json, Value};
    use std::cell::RefCell;

    struct Fake {
        present: Vec<&'static str>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }
    impl Runner for Fake {
        fn run_text(
            &self,
            tool: &str,
            _a: &[String],
            targets: &[String],
        ) -> Result<String, Box<dyn std::error::Error>> {
            assert!(targets.is_empty(), "SAST must pass no network targets");
            if self.present.contains(&tool) {
                Ok(String::new())
            } else {
                Err("not found".into())
            }
        }
        fn run_json(
            &self,
            tool: &str,
            args: &[String],
            targets: &[String],
        ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            assert!(targets.is_empty(), "SAST must pass no network targets");
            self.calls
                .borrow_mut()
                .push((tool.to_string(), args.to_vec()));
            Ok(match tool {
                "opengrep" => vec![
                    json!({"results":[{"check_id":"r","path":"a.rs","start":{"line":1},"extra":{"severity":"ERROR","message":"m","metadata":{"cwe":["CWE-89"]}}}]}),
                ],
                "gitleaks" => vec![
                    json!({"File":"c.py","StartLine":2,"RuleID":"aws","Description":"k","Secret":"XSECRETX"}),
                ],
                "trivy" => vec![
                    json!({"Results":[{"Target":"p.json","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","Title":"t"}]}]}),
                ],
                _ => vec![],
            })
        }
    }

    #[test]
    fn sast_runs_only_available_tools_and_merges() {
        let f = Fake {
            present: vec!["opengrep", "trivy"],
            calls: RefCell::new(vec![]),
        };
        let out = sast(&f, ".").unwrap();
        let tools: Vec<&str> = out.iter().map(|x| x.tool.as_str()).collect();
        assert!(tools.contains(&"opengrep") && tools.contains(&"trivy"));
        assert!(!tools.contains(&"gitleaks"), "absent tool must be skipped");
        // No secret from the (absent) gitleaks path, and nothing leaks regardless.
        assert!(
            !serde_json::to_string(&out.iter().map(|x| x.to_crux_json()).collect::<Vec<_>>())
                .unwrap()
                .contains("XSECRETX")
        );
    }

    #[test]
    fn sast_with_no_tools_is_empty() {
        let f = Fake {
            present: vec![],
            calls: RefCell::new(vec![]),
        };
        assert!(sast(&f, ".").unwrap().is_empty());
    }

    #[test]
    fn is_within_rejects_traversal() {
        let root = std::env::temp_dir();
        assert!(is_within(&root, &root));
        assert!(!is_within(&root.join("sub"), &root)); // parent is not within child
    }
}
