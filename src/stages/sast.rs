use crate::models::Finding;
use crate::normalise::{normalise_gitleaks, normalise_opengrep, normalise_trivy};
use crate::runner::Runner;
use std::path::Path;

/// True iff `candidate` resolves to a path inside `root`. Both must exist;
/// canonicalisation collapses `..` and resolves symlinks, so neither can escape.
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    match (root.canonicalize(), candidate.canonicalize()) {
        (Ok(r), Ok(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// A tool is "available" if its binary spawns (exit status is irrelevant).
pub fn tool_available(runner: &dyn Runner, tool: &str, version_arg: &str) -> bool {
    runner.run_text(tool, &[version_arg.into()], &[]).is_ok()
}

/// Runs each available analyser over `source_dir` (always with EMPTY network
/// targets) and merges the normalised findings. Missing tools are skipped.
pub fn sast(
    runner: &dyn Runner,
    source_dir: &str,
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    if tool_available(runner, "opengrep", "--version") {
        // opengrep is semgrep-derived but drops `--metrics` (it sends no telemetry by
        // default). `--config auto` needs `--experimental`; `--disable-version-check`
        // stops the version phone-home. Verified against opengrep 1.30.
        let args = vec![
            "scan".into(),
            "--experimental".into(),
            "--disable-version-check".into(),
            "--json".into(),
            "--quiet".into(),
            "--config".into(),
            "auto".into(),
            source_dir.into(),
        ];
        // A tool that spawns but then errors must not drop the other analysers' findings.
        match runner.run_json("opengrep", &args, &[]) {
            Ok(rows) => findings.extend(normalise_opengrep(&rows)),
            Err(_) => eprintln!("sast: opengrep failed; continuing without its findings"),
        }
    }
    if tool_available(runner, "gitleaks", "version") {
        let args = vec![
            "detect".into(),
            "--no-git".into(),
            "--report-format".into(),
            "json".into(),
            "--report-path".into(),
            "-".into(),
            "--source".into(),
            source_dir.into(),
        ];
        match runner.run_json("gitleaks", &args, &[]) {
            Ok(rows) => findings.extend(normalise_gitleaks(&rows)),
            Err(_) => eprintln!("sast: gitleaks failed; continuing without its findings"),
        }
    }
    if tool_available(runner, "trivy", "--version") {
        let args = vec![
            "fs".into(),
            "--quiet".into(),
            "--format".into(),
            "json".into(),
            source_dir.into(),
        ];
        match runner.run_json("trivy", &args, &[]) {
            Ok(rows) => findings.extend(normalise_trivy(&rows)),
            Err(_) => eprintln!("sast: trivy failed; continuing without its findings"),
        }
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
        fail_json: Vec<&'static str>,
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
            if self.fail_json.contains(&tool) {
                return Err("tool crashed".into());
            }
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
            fail_json: vec![],
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
            fail_json: vec![],
            calls: RefCell::new(vec![]),
        };
        assert!(sast(&f, ".").unwrap().is_empty());
    }

    #[test]
    fn sast_survives_one_tool_erroring_and_keeps_the_others() {
        let f = Fake {
            present: vec!["opengrep", "gitleaks", "trivy"],
            fail_json: vec!["opengrep"],
            calls: RefCell::new(vec![]),
        };
        let out = sast(&f, ".").unwrap();
        let tools: Vec<&str> = out.iter().map(|x| x.tool.as_str()).collect();
        assert!(!tools.contains(&"opengrep"));
        assert!(tools.contains(&"gitleaks") && tools.contains(&"trivy"));
    }

    #[test]
    fn sast_uses_portable_flags() {
        let f = Fake {
            present: vec!["opengrep", "gitleaks", "trivy"],
            fail_json: vec![],
            calls: RefCell::new(vec![]),
        };
        sast(&f, ".").unwrap();
        let calls = f.calls.borrow();
        let args_of = |t: &str| calls.iter().find(|(n, _)| n == t).unwrap().1.clone();
        // opengrep: the `scan` subcommand, `--experimental` (required for `--config auto`),
        // and the version-check phone-home disabled. No invalid `--metrics` flag.
        let og = args_of("opengrep");
        assert_eq!(og.first().map(String::as_str), Some("scan"));
        assert!(og.contains(&"--experimental".to_string()));
        assert!(og.contains(&"--disable-version-check".to_string()));
        assert!(!og.iter().any(|a| a.starts_with("--metrics")));
        // gitleaks: report to stdout via `-` (portable).
        let gl = args_of("gitleaks");
        let i = gl.iter().position(|a| a == "--report-path").unwrap();
        assert_eq!(gl[i + 1], "-");
    }

    #[test]
    fn is_within_rejects_traversal() {
        let root = std::env::temp_dir();
        assert!(is_within(&root, &root));
        assert!(!is_within(&root.join("sub"), &root)); // parent is not within child
    }

    #[test]
    fn is_within_rejects_dotdot_escape_and_missing_paths() {
        let base = std::env::temp_dir().join(format!("ascent_iswithin_{}", std::process::id()));
        let root = base.join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        // Inside, even via a `..` detour.
        assert!(is_within(&root, &root.join("sub/..")));
        // `..` climbs out of root to its (existing) parent: must be rejected.
        assert!(!is_within(&root, &root.join("sub/../..")));
        // Nonexistent candidate or root fails closed.
        assert!(!is_within(&root, &root.join("does-not-exist")));
        assert!(!is_within(&base.join("missing-root"), &root));
        let _ = std::fs::remove_dir_all(&base);
    }
}
