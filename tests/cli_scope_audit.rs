//! End-to-end: `ascent run --policy` fails closed (exit 3) when nuclei's trace log
//! shows a request outside the engagement scope.
//!
//! No target is ever contacted: this test binary doubles as fake ProjectDiscovery
//! tools. Copied into a temp `bin` dir as `httpx`, `katana` and `nuclei` (and put
//! alone on `PATH` for `ascent`), it behaves as that tool, chosen by its own file
//! name. Under any other name it runs the tests (`harness = false` in Cargo.toml).
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/nuclei-templates"
);
const POLICY: &str = "version: 1\nname: ci\nfail_on:\n  severity: [CRITICAL, HIGH]\n";
/// Where the fake nuclei appends one JSON line per scan call (its argv and `-et` file).
const LOG_ENV: &str = "ASCENT_FAKE_NUCLEI_LOG";
/// An extra `host:port` the fake nuclei reports in its trace log.
const OFF_SCOPE_ENV: &str = "ASCENT_FAKE_NUCLEI_OFF_SCOPE";

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
        "katana" => {} // finds nothing beyond the seeds
        "nuclei" => fake_nuclei(&args),
        _ => run_tests(&args),
    }
}

fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| &w[1])
}

/// `-version` identifies as ProjectDiscovery; every `-u` URL answers.
fn fake_httpx(args: &[String]) {
    if args.iter().any(|a| a == "-version") {
        println!("projectdiscovery.io\n[INF] Current Version: v1.12.0");
        return;
    }
    for w in args.windows(2).filter(|w| w[0] == "-u") {
        println!("{}", json!({"input": w[1], "url": w[1]}));
    }
}

/// `-version`, `-tl` (two fixture templates, one off-target), or a scan: logs its
/// argv, then writes a trace log with one successful request per listed URL (plus
/// the off-scope address, when set) and reports no finding.
fn fake_nuclei(args: &[String]) {
    if args.iter().any(|a| a == "-version") {
        println!("[INF] Nuclei Engine Version: v3.11.1");
        return;
    }
    if args.iter().any(|a| a == "-tl") {
        println!(
            "\nListing available v10.4.9 nuclei templates for {}",
            Path::new(FIXTURES).display()
        );
        println!("http/benign.yaml\nhttp\\cves\\off-target.yaml");
        return;
    }
    // With an auth header, report one finding whose evidence carries it (as real
    // nuclei's curl-command does), so the test can prove Ascent scrubs it.
    if let (Some(h), Some(list)) = (value_of(args, "-H"), value_of(args, "-l")) {
        let url = std::fs::read_to_string(list)
            .unwrap()
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!(
            "{}",
            json!({"template-id": "fake-tech", "matched-at": url, "host": url,
                "info": {"name": "Fake tech", "severity": "info", "tags": ["tech"]},
                "curl-command": format!("curl -H '{h}' {url}")})
        );
    }
    let et = value_of(args, "-et").map(|p| std::fs::read_to_string(p).expect("-et file readable"));
    if let Ok(log) = std::env::var(LOG_ENV) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .unwrap();
        writeln!(f, "{}", json!({"args": args, "et": et})).unwrap();
    }
    let (Some(list), Some(trace)) = (value_of(args, "-l"), value_of(args, "-tlog")) else {
        std::process::exit(2);
    };
    let mut lines: Vec<String> = std::fs::read_to_string(list)
        .unwrap()
        .lines()
        .filter_map(|u| url::Url::parse(u).ok())
        .map(|u| format!("{}:{}", u.host_str().unwrap(), u.port_or_known_default().unwrap()))
        .map(|a| json!({"template": "http/benign.yaml", "type": "http", "input": "x", "address": a, "error": "none"}).to_string())
        .collect();
    if let Ok(a) = std::env::var(OFF_SCOPE_ENV) {
        lines.push(json!({"template": "http/x.yaml", "type": "http", "input": "x", "address": a, "error": "none"}).to_string());
    }
    std::fs::write(trace, lines.join("\n") + "\n").unwrap();
}

// ---------------------------------------------------------------- the tests

static N: AtomicUsize = AtomicUsize::new(0);

/// A per-test temp dir (holding copies of this binary), removed when dropped,
/// also when an assertion fails.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> Scratch {
    let d = std::env::temp_dir().join(format!(
        "ascent_cli_audit_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Scratch(d)
}

/// A `bin` dir holding this binary as `httpx`, `katana` and `nuclei`.
fn fake_bin(d: &Path) -> PathBuf {
    let me = std::env::current_exe().unwrap();
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for t in ["httpx", "katana", "nuclei"] {
        std::fs::copy(
            &me,
            bin.join(format!("{t}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    bin
}

struct Run {
    out: Output,
    dir: PathBuf,
    calls: Vec<Value>,
    _scratch: Scratch,
}

const ENG: &str = "name: t\nurls: ['http://127.0.0.1:9/']\nstarts: '2026-01-01T00:00:00Z'\nends: '2030-01-01T00:00:00Z'\n";
const AUTH_ENV: &str = "ASCENT_CLI_AUDIT_AUTH";

fn run_ascent(off_scope: Option<&str>) -> Run {
    run_ascent_with(off_scope, ENG, None)
}

/// `auth`: the value to put in [`AUTH_ENV`] (the engagement must reference it).
fn run_ascent_with(off_scope: Option<&str>, engagement: &str, auth: Option<&str>) -> Run {
    let scratch = tmp();
    let d = scratch.0.clone();
    let bin = fake_bin(&d);
    let eng = d.join("eng.yaml");
    std::fs::write(&eng, engagement).unwrap();
    let policy = d.join("policy.yaml");
    std::fs::write(&policy, POLICY).unwrap();
    let out_dir = d.join("out");
    let log = d.join("nuclei-calls.jsonl");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ascent"));
    cmd.args([
        "run",
        "--engagement",
        eng.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .args(["--policy", policy.to_str().unwrap()])
    .env("PATH", &bin)
    .env(LOG_ENV, &log)
    .env_remove(OFF_SCOPE_ENV)
    .env_remove(AUTH_ENV);
    if let Some(a) = off_scope {
        cmd.env(OFF_SCOPE_ENV, a);
    }
    if let Some(v) = auth {
        cmd.env(AUTH_ENV, v);
    }
    let out = cmd.output().unwrap();
    let calls = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    Run {
        out,
        dir: out_dir,
        calls,
        _scratch: scratch,
    }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn read_json(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// Every nuclei scan never skips a host, runs http templates only, excludes the
/// off-target fixture and logs its requests; its temp files are gone afterwards.
fn assert_scan_calls(calls: &[Value]) {
    assert_eq!(calls.len(), 1, "standard profile: one pass: {calls:?}");
    for c in calls {
        let args: Vec<&str> = c["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(args.contains(&"-nmhe"), "{args:?}");
        assert!(args.windows(2).any(|w| w == ["-pt", "http"]), "{args:?}");
        let et = c["et"].as_str().expect("-et passed");
        let excluded: Vec<&str> = et.lines().collect();
        assert_eq!(excluded.len(), 1, "{et}");
        assert!(excluded[0].ends_with("off-target.yaml"), "{et}");
        for flag in ["-et", "-tlog", "-l"] {
            let i = args
                .iter()
                .position(|a| *a == flag)
                .unwrap_or_else(|| panic!("{flag} missing: {args:?}"));
            assert!(
                !Path::new(args[i + 1]).exists(),
                "{flag} file {} left behind",
                args[i + 1]
            );
        }
        // the private scratch dir holding -et and -tlog is gone too
        let i = args.iter().position(|a| *a == "-tlog").unwrap();
        let scratch = Path::new(args[i + 1]).parent().unwrap();
        assert!(
            !scratch.exists(),
            "scratch dir {} left behind",
            scratch.display()
        );
    }
}

fn request_outside_scope_is_incomplete_exit_3() {
    let r = run_ascent(Some("checkip.amazonaws.com:443"));
    let stderr = String::from_utf8_lossy(&r.out.stderr);
    assert_eq!(code(&r.out), 3, "stderr: {stderr}");
    let want = "DAST: nuclei sent requests outside scope to: checkip.amazonaws.com";
    assert!(
        stderr.contains("run INCOMPLETE") && stderr.contains(want),
        "{stderr}"
    );
    let g = read_json(&r.dir, "gate.json");
    assert_eq!(g["decision"], "INCOMPLETE", "{g}");
    assert_eq!(g["incomplete_reasons"], json!([want]), "{g}");
    let run = read_json(&r.dir, "run.json");
    assert_eq!(run["dast"]["off_scope_request_count"], 1, "{run}");
    assert_eq!(run["dast"]["requests_sent"], 2, "{run}");
    assert_eq!(run["dast"]["templates_excluded"], 1, "{run}");
    assert_scan_calls(&r.calls);
}

fn clean_trace_passes_exit_0() {
    let r = run_ascent(None);
    let stderr = String::from_utf8_lossy(&r.out.stderr);
    assert_eq!(code(&r.out), 0, "stderr: {stderr}");
    assert_eq!(read_json(&r.dir, "gate.json")["decision"], "PASS");
    let run = read_json(&r.dir, "run.json");
    assert_eq!(run["complete"], true, "{run}");
    assert_eq!(run["dast"]["requests_sent"], 1, "{run}");
    assert_eq!(run["dast"]["off_scope_request_count"], 0, "{run}");
    let report = std::fs::read_to_string(r.dir.join("report.md")).unwrap();
    assert!(
        report.contains(
            "1 template excluded: it may send requests Ascent cannot scope-check \
             (an @Host naming another host, a non-http section, or a flow that loads modules)"
        ),
        "{report}"
    );
    assert!(
        report.contains("nuclei sent 1 request; 0 failed"),
        "{report}"
    );
    assert_scan_calls(&r.calls);
}

fn auth_value_never_reaches_any_output() {
    let value = format!("Bearer cli-audit-{}-tok", std::process::id());
    let eng =
        format!("{ENG}dast:\n  auth:\n    header: Authorization\n    value_env: {AUTH_ENV}\n");
    let r = run_ascent_with(None, &eng, Some(&value));
    let stdout = String::from_utf8_lossy(&r.out.stdout);
    let stderr = String::from_utf8_lossy(&r.out.stderr);
    assert_eq!(code(&r.out), 0, "stderr: {stderr}");
    assert!(!stdout.contains(&value), "auth value on stdout");
    assert!(!stderr.contains(&value), "auth value on stderr");
    // non-vacuous: nuclei did get the header, and its finding evidence carried it
    let args = r.calls[0]["args"].to_string();
    assert!(
        args.contains(&value),
        "the fake nuclei never saw the header"
    );
    let files = files_under(&r.dir);
    assert!(files.len() >= 5, "{files:?}");
    for p in &files {
        let text = String::from_utf8_lossy(&std::fs::read(p).unwrap()).into_owned();
        assert!(
            !text.contains(&value),
            "auth value leaked into {}",
            p.display()
        );
    }
    let queue = std::fs::read_to_string(r.dir.join("queue.json")).unwrap();
    assert!(
        queue.contains("curl -H") && queue.contains("***"),
        "{queue}"
    );
    assert_eq!(read_json(&r.dir, "run.json")["dast"]["authenticated"], true);
}

/// libtest-style filters: positional args select tests by substring, `--skip X`
/// excludes; the values of other option flags are never mistaken for filters.
fn selected(name: &str, args: &[String]) -> bool {
    const TAKES_VALUE: [&str; 6] = [
        "--test-threads",
        "--format",
        "--color",
        "--logfile",
        "--shuffle-seed",
        "-Z",
    ];
    let (mut filters, mut skips) = (Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--skip" {
            skips.extend(it.next());
        } else if TAKES_VALUE.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with('-') {
            filters.push(a);
        }
    }
    (filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str())))
        && !skips.iter().any(|s| name.contains(s.as_str()))
}

fn run_tests(args: &[String]) {
    let tests: [(&str, fn()); 3] = [
        (
            "request_outside_scope_is_incomplete_exit_3",
            request_outside_scope_is_incomplete_exit_3,
        ),
        ("clean_trace_passes_exit_0", clean_trace_passes_exit_0),
        (
            "auth_value_never_reaches_any_output",
            auth_value_never_reaches_any_output,
        ),
    ];
    assert!(
        selected("abc", &["--test-threads".into(), "4".into()]),
        "an option value is not a filter"
    );
    assert!(!selected("abc", &["--skip".into(), "ab".into()]));
    assert!(!selected("abc", &["xyz".into()]) && selected("abc", &["b".into()]));
    if args.iter().any(|a| a == "--list") {
        for (n, _) in &tests {
            println!("{n}: test");
        }
        return;
    }
    let selected: Vec<_> = tests.iter().filter(|(n, _)| selected(n, args)).collect();
    println!("\nrunning {} tests", selected.len());
    let mut failed = Vec::new();
    for (name, f) in &selected {
        let ok = std::panic::catch_unwind(f).is_ok();
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        if !ok {
            failed.push(*name);
        }
    }
    let passed = selected.len() - failed.len();
    let verdict = if failed.is_empty() { "ok" } else { "FAILED" };
    println!(
        "\ntest result: {verdict}. {passed} passed; {} failed\n",
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(101);
    }
}
