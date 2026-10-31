use clap::{Parser, Subcommand};

mod exploit;
mod gate;
mod gatesio;
mod models;
mod normalise;
mod pipeline;
mod report;
mod runner;
mod runstatus;
mod sarif;
mod scope;
mod stages;
mod triage;

use exploit::execute::{verify_approved, Outcome};
use exploit::propose::{propose, write_proposed};
use gate::evaluate::{evaluate, gate_document, read_queue, write_gate, Decision, WriteGateError};
use gate::policy::{load_policy, Policy};
use pipeline::{run_pipeline, ConfigError, IntegrityError};
use runner::ToolRunner;
use runstatus::{now_ts, read_run_status};
use scope::{load_engagement, ScopeGuard};
use triage::{CruxTriager, TriageItem};

#[derive(Parser)]
#[command(name = "ascent", version, about = "Scope-enforced AppSec pipeline")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the recon -> scan -> triage -> report pipeline for an engagement.
    Run {
        /// Path to the engagement YAML (scope + rules of engagement).
        #[arg(long)]
        engagement: String,
        /// Output directory for report.md and audit.jsonl.
        #[arg(long, default_value = "out")]
        out: String,
        /// Plan only: spawn no tools and make no network requests.
        #[arg(long)]
        dry_run: bool,
        /// Optional source directory for the white-box SAST track (overrides the engagement's `source`).
        #[arg(long)]
        source: Option<String>,
        /// After triage, propose detect-only verification gates for human review.
        #[arg(long)]
        propose: bool,
        /// Minimum triage confidence for a finding to be proposed as a gate.
        #[arg(long, default_value_t = 0.8)]
        min_confidence: f64,
        /// Evaluate this policy after the run; the exit code follows the verdict.
        #[arg(long)]
        policy: Option<String>,
        /// Treat a CONDITIONAL verdict (warnings only) as a failure (exit 1).
        #[arg(long)]
        fail_on_warn: bool,
        /// Wall-clock limit in seconds for all nuclei DAST passes combined (default 2 h).
        /// When hit, nuclei is stopped (SIGTERM then SIGKILL) and findings collected so
        /// far are kept, but the run is marked INCOMPLETE with reason
        /// `wall_clock_limit_hit`. The engagement file cannot set this.
        /// Must be at least 1 second.
        #[arg(long, default_value_t = 7200, value_parser = clap::value_parser!(u64).range(1..))]
        dast_timeout: u64,
    },
    /// Evaluate a policy against an existing output directory (CI step).
    Gate {
        #[arg(long)]
        policy: String,
        #[arg(long, default_value = "out")]
        out: String,
        #[arg(long)]
        fail_on_warn: bool,
    },
    /// Regenerate ascent.sarif / ascent-dast.sarif from queue.json.
    Sarif {
        #[arg(long, default_value = "out")]
        out: String,
        /// Source root to make SARIF paths repository-relative.
        #[arg(long)]
        source_root: Option<String>,
    },
    /// Run the human-approved detect-only verification gates for an engagement.
    Verify {
        /// Path to the engagement YAML (scope + rules of engagement).
        #[arg(long)]
        engagement: String,
        /// Output directory holding gates.json/audit.jsonl (and where report.md lives).
        #[arg(long, default_value = "out")]
        out: String,
    },
}

/// A CLI failure and the exit code it maps to (README: "Exit codes").
struct Failure {
    code: u8,
    msg: String,
}
impl Failure {
    fn usage(m: impl ToString) -> Self {
        Failure {
            code: 2,
            msg: m.to_string(),
        }
    }
    fn incomplete(m: impl ToString) -> Self {
        Failure {
            code: 3,
            msg: m.to_string(),
        }
    }
    fn integrity(m: impl ToString) -> Self {
        Failure {
            code: 4,
            msg: m.to_string(),
        }
    }
}

fn main() -> std::process::ExitCode {
    match dispatch(Cli::parse().cmd) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(f) => {
            eprintln!("error: {}", f.msg);
            std::process::ExitCode::from(f.code)
        }
    }
}

/// Evaluate `policy` over `out`, record gate.json + the audit entry, return the exit code.
fn gate_step(out: &str, policy: &Policy, fail_on_warn: bool) -> Result<u8, Failure> {
    let items = read_queue(out).map_err(Failure::incomplete)?;
    let status = read_run_status(out);
    let result = evaluate(&items, policy, status.as_ref(), fail_on_warn);
    let doc = gate_document(policy, &result, status.as_ref(), &now_ts());
    match write_gate(out, &doc) {
        Ok(()) => {}
        Err(WriteGateError::Integrity(m)) => {
            return Err(Failure::integrity(format!(
                "audit chain failed verification; gate not recorded: {m}"
            )))
        }
        Err(WriteGateError::Io(m)) => return Err(Failure::incomplete(m)),
    }
    let label = match result.decision {
        Decision::Pass => "PASS",
        Decision::Conditional => "CONDITIONAL",
        Decision::Fail => "FAIL",
        Decision::Incomplete => "INCOMPLETE",
    };
    println!(
        "gate: {label} (exit {}) policy={} failed={} warned={} demoted_fp={}",
        result.exit_code,
        policy.name,
        result.counts.failed,
        result.counts.warned,
        result.counts.demoted_fp
    );
    for e in result.failed.iter().take(10) {
        println!(
            "  FAIL {} {} {} — {}",
            e.severity, e.rule_id, e.locus, e.reason
        );
    }
    println!(
        "gate:   {}",
        std::path::Path::new(out).join("gate.json").display()
    );
    Ok(result.exit_code)
}

fn dispatch(cmd: Cmd) -> Result<u8, Failure> {
    match cmd {
        Cmd::Run {
            engagement,
            out,
            dry_run,
            source,
            propose: do_propose,
            min_confidence,
            policy,
            fail_on_warn,
            dast_timeout,
        } => {
            // Load the policy BEFORE scanning so a bad policy fails fast (exit 2).
            let policy = policy
                .as_deref()
                .map(load_policy)
                .transpose()
                .map_err(Failure::usage)?;
            let eng = load_engagement(&engagement).map_err(Failure::usage)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), dry_run);
            let s = run_pipeline(
                &eng,
                &runner,
                &CruxTriager::default(),
                &out,
                dry_run,
                source.as_deref(),
                dast_timeout,
            )
            .map_err(|e| {
                // Typed errors pick the exit code; never match on message text.
                if e.downcast_ref::<IntegrityError>().is_some() {
                    Failure::integrity(e)
                } else if e.downcast_ref::<ConfigError>().is_some() {
                    Failure::usage(e)
                } else {
                    Failure::incomplete(e)
                }
            })?;
            println!(
                "urls={} findings={} triaged={}",
                s.urls, s.findings, s.triaged
            );
            if let Some(d) = &s.dast {
                println!(
                    "dast: profile={} authenticated={} seeded={} crawled={} out_of_scope_dropped={} scanned={} unreachable={}",
                    d.profile, d.authenticated, d.seeded, d.crawled, d.out_of_scope_dropped, d.scanned, d.unreachable
                );
                println!(
                    "nuclei: templates_excluded={} requests={} request_errors={} off_scope_requests={}",
                    d.templates_excluded, d.requests_sent, d.request_errors, d.off_scope_request_count
                );
                println!(
                    "coverage: {}",
                    std::path::Path::new(&out)
                        .join("dast-coverage.json")
                        .display()
                );
            }
            if !s.complete {
                // stderr, so CI logs show it even when stdout is captured.
                eprintln!(
                    "run INCOMPLETE (dry run or failed scanners: {:?})",
                    s.failed_tools
                );
                for r in &s.incomplete_reasons {
                    eprintln!("  {r}");
                }
            }
            println!("report: {}\naudit:  {}", s.report_path, s.audit_path);
            println!(
                "sarif:  {}",
                std::path::Path::new(&out).join("ascent.sarif").display()
            );
            if do_propose {
                let queue_path = std::path::Path::new(&out).join("queue.json");
                let items: Vec<TriageItem> = std::fs::read_to_string(&queue_path)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default();
                if items.is_empty() {
                    println!("no triaged items in queue.json; skipping --propose");
                } else {
                    let gates = propose(&items, &runner.guard, min_confidence);
                    write_proposed(&out, &gates).map_err(Failure::incomplete)?;
                    println!("proposed {} gate(s)", gates.len());
                }
            }
            match policy {
                Some(p) => gate_step(&out, &p, fail_on_warn),
                None => {
                    // A complete run or a dry run (which intentionally scans nothing)
                    // exits 0.  Anything that is not complete — including a run with a
                    // crashed scanner (`failed_tools` non-empty) even when
                    // `incomplete_reasons` is otherwise empty — exits 3.
                    if s.complete || dry_run {
                        Ok(0)
                    } else {
                        Ok(3)
                    }
                }
            }
        }
        Cmd::Gate {
            policy,
            out,
            fail_on_warn,
        } => {
            let p = load_policy(&policy).map_err(Failure::usage)?;
            gate_step(&out, &p, fail_on_warn)
        }
        Cmd::Sarif { out, source_root } => {
            let items = read_queue(&out).map_err(Failure::incomplete)?;
            sarif::write_sarif(&out, &items, source_root.as_deref())
                .map_err(Failure::incomplete)?;
            println!(
                "sarif: {}",
                std::path::Path::new(&out).join("ascent.sarif").display()
            );
            println!(
                "sarif: {}",
                std::path::Path::new(&out)
                    .join("ascent-dast.sarif")
                    .display()
            );
            Ok(0)
        }
        Cmd::Verify { engagement, out } => {
            let eng = load_engagement(&engagement).map_err(Failure::usage)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), false);
            let results = verify_approved(&out, &runner.guard, &runner).map_err(|e| {
                let m = e.to_string();
                if m.contains("audit chain") {
                    Failure::integrity(m)
                } else {
                    Failure::incomplete(m)
                }
            })?;
            let confirmed = results
                .iter()
                .filter(|r| r.outcome == Outcome::Confirmed)
                .count();
            let not_confirmed = results
                .iter()
                .filter(|r| r.outcome == Outcome::NotConfirmed)
                .count();
            let refused = results
                .iter()
                .filter(|r| matches!(r.outcome, Outcome::Refused(_)))
                .count();
            println!("confirmed={confirmed} not_confirmed={not_confirmed} refused={refused}");
            let report_path = std::path::Path::new(&out).join("report.md");
            let audit_path = std::path::Path::new(&out).join("audit.jsonl");
            println!(
                "report: {}\naudit:  {}",
                report_path.display(),
                audit_path.display()
            );
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn parses_run() {
        assert!(Cli::try_parse_from(["ascent", "run", "--engagement", "e.yaml"]).is_ok());
    }

    #[test]
    fn parses_dry_run_and_out() {
        assert!(Cli::try_parse_from([
            "ascent",
            "run",
            "--engagement",
            "e.yaml",
            "--out",
            "o",
            "--dry-run"
        ])
        .is_ok());
    }

    #[test]
    fn parses_source_flag() {
        let c = Cli::try_parse_from([
            "ascent",
            "run",
            "--engagement",
            "e.yaml",
            "--source",
            "./src",
        ])
        .unwrap();
        let super::Cmd::Run { source, .. } = c.cmd else {
            panic!("expected Run");
        };
        assert_eq!(source.as_deref(), Some("./src"));
    }

    #[test]
    fn requires_engagement() {
        assert!(Cli::try_parse_from(["ascent", "run"]).is_err());
    }

    #[test]
    fn parses_propose_and_min_confidence() {
        let c = Cli::try_parse_from([
            "ascent",
            "run",
            "--engagement",
            "e",
            "--propose",
            "--min-confidence",
            "0.9",
        ])
        .unwrap();
        let super::Cmd::Run {
            propose,
            min_confidence,
            ..
        } = c.cmd
        else {
            panic!("expected Run");
        };
        assert!(propose);
        assert_eq!(min_confidence, 0.9);
    }

    #[test]
    fn propose_defaults_to_false_and_min_confidence_to_default() {
        let c = Cli::try_parse_from(["ascent", "run", "--engagement", "e"]).unwrap();
        let super::Cmd::Run {
            propose,
            min_confidence,
            ..
        } = c.cmd
        else {
            panic!("expected Run");
        };
        assert!(!propose);
        assert_eq!(min_confidence, 0.8);
    }

    #[test]
    fn parses_verify() {
        let c =
            Cli::try_parse_from(["ascent", "verify", "--engagement", "e", "--out", "out"]).unwrap();
        let super::Cmd::Verify { engagement, out } = c.cmd else {
            panic!("expected Verify");
        };
        assert_eq!(engagement, "e");
        assert_eq!(out, "out");
    }

    #[test]
    fn verify_requires_engagement() {
        assert!(Cli::try_parse_from(["ascent", "verify"]).is_err());
    }

    #[test]
    fn parses_run_policy_flags() {
        let c = Cli::try_parse_from([
            "ascent",
            "run",
            "--engagement",
            "e",
            "--policy",
            "p.yaml",
            "--fail-on-warn",
        ])
        .unwrap();
        let super::Cmd::Run {
            policy,
            fail_on_warn,
            ..
        } = c.cmd
        else {
            panic!("expected Run")
        };
        assert_eq!(policy.as_deref(), Some("p.yaml"));
        assert!(fail_on_warn);
    }

    #[test]
    fn parses_gate_and_sarif() {
        let c = Cli::try_parse_from(["ascent", "gate", "--policy", "p.yaml"]).unwrap();
        let super::Cmd::Gate {
            policy,
            out,
            fail_on_warn,
        } = c.cmd
        else {
            panic!("expected Gate")
        };
        assert_eq!(
            (policy.as_str(), out.as_str(), fail_on_warn),
            ("p.yaml", "out", false)
        );
        assert!(
            Cli::try_parse_from(["ascent", "gate"]).is_err(),
            "--policy is required"
        );
        let c = Cli::try_parse_from(["ascent", "sarif", "--source-root", "./src"]).unwrap();
        let super::Cmd::Sarif { source_root, .. } = c.cmd else {
            panic!("expected Sarif")
        };
        assert_eq!(source_root.as_deref(), Some("./src"));
    }
}
