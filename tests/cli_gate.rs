//! End-to-end exit-code contract against the real `ascent` binary.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static N: AtomicUsize = AtomicUsize::new(0);
const ENG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/samples/engagement.example.yaml");

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("ascent_cli_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.to_str().unwrap().to_string()
}
/// Runs `ascent` with captured stdout/stderr (nothing leaks into the test output).
fn ascent(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ascent")).args(args).output().unwrap()
}
fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}
const POLICY: &str = "version: 1\nname: ci\nfail_on:\n  severity: [CRITICAL, HIGH]\nwarn_on:\n  severity: [MEDIUM]\n";
fn item(sev: &str) -> Value {
    json!({"finding": {"id": "x", "tool": "opengrep", "rule_id": "r", "severity": sev, "title": "t",
        "message": "m", "url": "", "file": "a.py", "line": 3, "category": "SAST", "cwe": "", "code": "q()"},
        "verdict": "TRUE_POSITIVE", "confidence": 0.9, "fp_likelihood": 0.1, "rationale": "r", "remediation": "x"})
}
fn out_dir(items: Vec<Value>, complete: bool) -> PathBuf {
    let d = tmp();
    write(&d, "queue.json", &Value::from(items).to_string());
    write(&d, "run.json", &json!({"complete": complete, "dry_run": false, "failed_tools": [], "skipped_tools": [], "finished_at": "t"}).to_string());
    d
}
fn gate(dir: &Path, policy_text: &str, extra: &[&str]) -> i32 {
    let p = write(dir, "policy.yaml", policy_text);
    let mut args = vec!["gate", "--policy", &p, "--out", dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    code(&ascent(&args))
}

#[test]
fn clean_complete_run_passes_with_0() {
    let d = out_dir(vec![], true);
    assert_eq!(gate(&d, POLICY, &[]), 0);
    let g: Value = serde_json::from_str(&std::fs::read_to_string(d.join("gate.json")).unwrap()).unwrap();
    assert_eq!(g["decision"], "PASS");
}
#[test]
fn high_finding_fails_with_1_and_is_audited() {
    let d = out_dir(vec![item("HIGH")], true);
    assert_eq!(gate(&d, POLICY, &[]), 1);
    let audit = std::fs::read_to_string(d.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"gate_evaluation\""));
    assert!(crux::AuditLog::new(d.join("audit.jsonl")).verify().0);
}
#[test]
fn medium_is_conditional_0_or_1_with_fail_on_warn() {
    let d = out_dir(vec![item("MEDIUM")], true);
    assert_eq!(gate(&d, POLICY, &[]), 0);
    assert_eq!(gate(&d, POLICY, &["--fail-on-warn"]), 1);
}
#[test]
fn malformed_policy_exits_2() {
    let d = out_dir(vec![], true);
    assert_eq!(gate(&d, "version: 1\ngrace_days: {HIGH: 7}\n", &[]), 2);
    assert!(!d.join("gate.json").exists());
}
#[test]
fn gate_with_a_nonexistent_policy_exits_2() {
    let d = out_dir(vec![], true);
    let missing = d.join("no-such-policy.yaml");
    let o = ascent(&["gate", "--policy", missing.to_str().unwrap(), "--out", d.to_str().unwrap()]);
    assert_eq!(code(&o), 2);
    assert!(!d.join("gate.json").exists());
}
#[test]
fn incomplete_or_missing_run_status_exits_3() {
    let d = out_dir(vec![], false);
    assert_eq!(gate(&d, POLICY, &[]), 3);
    std::fs::remove_file(d.join("run.json")).unwrap();
    assert_eq!(gate(&d, POLICY, &[]), 3);
    let empty = tmp(); // no queue.json at all
    assert_eq!(gate(&empty, POLICY, &[]), 3);
}
#[test]
fn broken_audit_chain_exits_4_and_writes_no_gate() {
    let d = out_dir(vec![], true);
    write(&d, "audit.jsonl", "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n");
    assert_eq!(gate(&d, POLICY, &[]), 4);
    assert!(!d.join("gate.json").exists());
}
#[test]
fn dry_run_with_policy_is_incomplete_3() {
    let d = tmp();
    let p = write(&d, "policy.yaml", POLICY);
    let out = d.join("out");
    let o = ascent(&["run", "--engagement", ENG, "--out", out.to_str().unwrap(), "--dry-run", "--policy", &p]);
    assert_eq!(code(&o), 3);
    assert!(out.join("gate.json").exists(), "an INCOMPLETE verdict is still recorded");
}
#[test]
fn dry_run_without_policy_exits_0_and_reports_incomplete_on_stderr() {
    let d = tmp();
    let out = d.join("out");
    let o = ascent(&["run", "--engagement", ENG, "--out", out.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 0);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("run INCOMPLETE"), "stderr: {stderr}");
}
#[test]
fn bad_policy_fails_before_any_scan() {
    let d = tmp();
    let p = write(&d, "policy.yaml", "version: 9\n");
    let out = d.join("out");
    let o = ascent(&["run", "--engagement", ENG, "--out", out.to_str().unwrap(), "--dry-run", "--policy", &p]);
    assert_eq!(code(&o), 2);
    assert!(!out.join("queue.json").exists(), "nothing ran");
}
#[test]
fn missing_engagement_exits_2() {
    let d = tmp();
    let o = ascent(&["run", "--engagement", "definitely/not/here.yaml", "--out", d.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 2);
}
#[test]
fn bad_source_exits_2() {
    let d = tmp();
    let out = d.join("out");
    let missing = d.join("no-such-source");
    let o = ascent(&["run", "--engagement", ENG, "--out", out.to_str().unwrap(), "--dry-run",
                     "--source", missing.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "stderr: {}", String::from_utf8_lossy(&o.stderr));
    assert!(!out.join("queue.json").exists(), "nothing ran");
}
#[test]
fn tampered_audit_during_run_exits_4_and_rewrites_nothing() {
    let d = tmp();
    let out = d.join("out");
    std::fs::create_dir_all(&out).unwrap();
    write(&out, "audit.jsonl", "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n");
    write(&out, "queue.json", "[\"sentinel\"]");
    write(&out, "run.json", "{\"sentinel\":true}");
    let o = ascent(&["run", "--engagement", ENG, "--out", out.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 4, "stderr: {}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read_to_string(out.join("queue.json")).unwrap(), "[\"sentinel\"]");
    assert_eq!(std::fs::read_to_string(out.join("run.json")).unwrap(), "{\"sentinel\":true}");
}
#[test]
fn sarif_subcommand_regenerates_files() {
    let d = out_dir(vec![item("HIGH")], true);
    let o = ascent(&["sarif", "--out", d.to_str().unwrap()]);
    assert_eq!(code(&o), 0);
    let s: Value = serde_json::from_str(&std::fs::read_to_string(d.join("ascent.sarif")).unwrap()).unwrap();
    assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
}
#[test]
fn sarif_without_a_queue_exits_3() {
    let d = tmp();
    let o = ascent(&["sarif", "--out", d.to_str().unwrap()]);
    assert_eq!(code(&o), 3);
}
