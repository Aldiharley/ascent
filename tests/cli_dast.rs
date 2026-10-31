//! Integration test: wall-clock limit on the DAST nuclei pass (task-1).
//!
//! This binary doubles as fake ProjectDiscovery tools. When invoked as
//! `httpx`, `katana`, or `nuclei` it behaves as that tool; otherwise it
//! runs the test suite via libtest.
//!
//! The fake `nuclei` sleeps forever on the actual scan call (`-l` flag
//! present), so a short `--dast-timeout` must kill it and record
//! `"wall_clock_limit_hit"` in the run-status.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/nuclei-templates"
);

fn main() {
    let me = std::env::current_exe().expect("own path");
    let name = me
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match name.as_str() {
        "httpx" => fake_httpx(&args),
        "katana" => {} // returns nothing
        "nuclei" => fake_nuclei_sleeping(&args),
        _ => run_tests(),
    }
}

fn fake_httpx(args: &[String]) {
    if args.iter().any(|a| a == "-version") {
        println!("projectdiscovery.io\n[INF] Current Version: v1.12.0");
        return;
    }
    // Every -u URL answers
    for w in args.windows(2).filter(|w| w[0] == "-u") {
        println!("{}", json!({"input": w[1], "url": w[1]}));
    }
    // Every bare host (recon) answers
    for w in args.windows(2).filter(|w| w[0] == "-u") {
        if !w[1].contains("://") {
            println!("{}", json!({"url": format!("https://{}", w[1])}));
        }
    }
}

fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| &w[1])
}

/// `-version` → version string, `-tl` → fixture template listing, `-l` → sleep forever.
fn fake_nuclei_sleeping(args: &[String]) {
    if args.iter().any(|a| a == "-version") {
        println!("[INF] Nuclei Engine Version: v3.11.1");
        return;
    }
    if args.iter().any(|a| a == "-tl") {
        println!(
            "\nListing available v10.4.9 nuclei templates for {}",
            Path::new(FIXTURES).display()
        );
        println!("http/benign.yaml");
        return;
    }
    if value_of(args, "-l").is_some() {
        // Actual scan: sleep until killed by the timeout
        std::thread::sleep(std::time::Duration::from_secs(9999));
    }
    // Other calls (e.g. -duc -tl): just return nothing
}

// ── test runner ──────────────────────────────────────────────────────────────

fn run_tests() {
    // Register tests manually to keep this file harness = false
    let tests: &[(&str, fn())] = &[(
        "test_dast_timeout_stops_nuclei",
        test_dast_timeout_stops_nuclei,
    )];

    let mut passed = 0usize;
    let mut failed = 0usize;
    for (name, f) in tests {
        let result = std::panic::catch_unwind(f);
        match result {
            Ok(()) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "(panic)".into());
                eprintln!("test {name} ... FAILED\n  {msg}");
                failed += 1;
            }
        }
    }
    println!("\ntest result: {} passed; {} failed", passed, failed);
    if failed > 0 {
        std::process::exit(101);
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

static N: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> Scratch {
    let d = std::env::temp_dir().join(format!(
        "ascent_cli_dast_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Scratch(d)
}

/// Copy `this` binary as httpx, katana, nuclei into a temp `bin` dir.
fn fake_bin(d: &Path) -> PathBuf {
    let me = std::env::current_exe().unwrap();
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for t in ["httpx", "katana", "nuclei", "subfinder"] {
        std::fs::copy(
            &me,
            bin.join(format!("{t}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    bin
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn read_json(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
}

// ── the test ──────────────────────────────────────────────────────────────────

fn test_dast_timeout_stops_nuclei() {
    let scratch = tmp();
    let d = scratch.0.clone();
    let bin = fake_bin(&d);

    let eng_text = "name: timeout-test\nurls: ['http://127.0.0.1:19999/']\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
    let eng = d.join("eng.yaml");
    std::fs::write(&eng, eng_text).unwrap();
    let out_dir = d.join("out");

    let start = std::time::Instant::now();
    let o = Command::new(env!("CARGO_BIN_EXE_ascent"))
        .args([
            "run",
            "--engagement",
            eng.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--dast-timeout",
            "1",
        ])
        .env("PATH", &bin)
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&o.stderr);

    // Must exit 3 (incomplete)
    assert_eq!(
        code(&o),
        3,
        "expected exit 3 (incomplete); got {}; stderr: {stderr}",
        code(&o)
    );

    // Must finish within ~15 s (1 s timeout + 10 s kill grace + buffer)
    assert!(
        elapsed.as_secs() < 20,
        "timeout did not stop nuclei quickly enough ({elapsed:?})"
    );

    // run.json must record the incomplete reason
    let run = read_json(&out_dir, "run.json");
    let reasons: Vec<&str> = run["incomplete_reasons"]
        .as_array()
        .expect("incomplete_reasons array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        reasons.contains(&"wall_clock_limit_hit"),
        "expected 'wall_clock_limit_hit' in incomplete_reasons; got {:?}",
        reasons
    );

    // complete must be false
    assert_eq!(run["complete"], false, "run must be incomplete: {run}");
}
