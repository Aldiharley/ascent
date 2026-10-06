use clap::{Parser, Subcommand};

mod exploit;
mod gatesio;
mod models;
mod normalise;
mod pipeline;
mod report;
mod runner;
mod scope;
mod stages;
mod triage;

use exploit::execute::{verify_approved, Outcome};
use exploit::propose::{propose, write_proposed};
use pipeline::run_pipeline;
use runner::ToolRunner;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Run {
            engagement,
            out,
            dry_run,
            source,
            propose: do_propose,
            min_confidence,
        } => {
            let eng = load_engagement(&engagement)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), dry_run);
            let s = run_pipeline(
                &eng,
                &runner,
                &CruxTriager::default(),
                &out,
                dry_run,
                source.as_deref(),
            )?;
            println!(
                "urls={} findings={} triaged={}",
                s.urls, s.findings, s.triaged
            );
            println!("report: {}\naudit:  {}", s.report_path, s.audit_path);
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
                    write_proposed(&out, &gates)?;
                    println!("proposed {} gate(s)", gates.len());
                }
            }
            Ok(())
        }
        Cmd::Verify { engagement, out } => {
            let eng = load_engagement(&engagement)?;
            let runner = ToolRunner::new(ScopeGuard::new(&eng), false);
            let results = verify_approved(&out, &runner.guard, &runner)?;
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
            Ok(())
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
}
