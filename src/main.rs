use clap::{Parser, Subcommand};

mod models;
mod normalise;
mod pipeline;
mod report;
mod runner;
mod scope;
mod stages;
mod triage;

use pipeline::run_pipeline;
use runner::ToolRunner;
use scope::{load_engagement, ScopeGuard};
use triage::CruxTriager;

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
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Run {
            engagement,
            out,
            dry_run,
            source,
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
        let super::Cmd::Run { source, .. } = c.cmd;
        assert_eq!(source.as_deref(), Some("./src"));
    }

    #[test]
    fn requires_engagement() {
        assert!(Cli::try_parse_from(["ascent", "run"]).is_err());
    }
}
