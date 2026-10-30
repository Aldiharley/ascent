//! The gate decision: policy × triaged findings × run completeness →
//! PASS / CONDITIONAL / FAIL / INCOMPLETE, written to gate.json and chained
//! into audit.jsonl so the verdict is tamper-evident.
use super::fingerprint::{fingerprints, kind};
use super::policy::{canonical_cwe, policy_hash, FpMode, Policy, SEVERITIES};
use crate::runstatus::RunStatus;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Pass,
    Conditional,
    Fail,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub locus: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Counts {
    pub evaluated: usize,
    pub failed: usize,
    pub warned: usize,
    pub demoted_fp: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateResult {
    pub decision: Decision,
    pub exit_code: u8,
    pub complete: bool,
    pub counts: Counts,
    pub failed: Vec<GateEntry>,
    pub warned: Vec<GateEntry>,
}

fn s(f: &Value, k: &str) -> String {
    f[k].as_str().unwrap_or("").to_string()
}

/// `SECRETS` for gitleaks findings and credential-CWE findings (CWE-798/259/321,
/// as classified by `fingerprint::kind`), else the finding's own category
/// (upper-cased), falling back to the fingerprint kind.
pub fn category_of(f: &Value) -> String {
    if kind(f) == "secret" {
        return "SECRETS".into();
    }
    let c = s(f, "category").to_ascii_uppercase();
    if !c.is_empty() {
        return c;
    }
    match kind(f) {
        "sca" => "SCA",
        "dast" => "DAST",
        _ => "SAST",
    }
    .into()
}

/// The policy category an analyser covers (for `skipped_tools`).
fn tool_category(tool: &str) -> Option<&'static str> {
    match tool {
        "opengrep" => Some("SAST"),
        "gitleaks" => Some("SECRETS"),
        "trivy" => Some("SCA"),
        _ => None,
    }
}

fn locus(f: &Value) -> String {
    let url = s(f, "url");
    if url.is_empty() {
        format!("{}:{}", s(f, "file"), f["line"].as_i64().unwrap_or(0))
    } else {
        url
    }
}

fn matches(sev: &str, cwe: &str, sevs: &[String], cwes: &[String], rule: &str) -> Option<String> {
    if sevs.iter().any(|x| x == sev) {
        Some(format!("severity {sev} in {rule}"))
    } else if !cwe.is_empty() && cwes.iter().any(|x| x == cwe) {
        Some(format!("{cwe} in {rule}"))
    } else {
        None
    }
}

pub fn evaluate(items: &[Value], policy: &Policy, status: Option<&RunStatus>, fail_on_warn: bool) -> GateResult {
    let findings: Vec<Value> = items.iter().map(|it| it["finding"].clone()).collect();
    let fps = fingerprints(&findings, None);
    let (mut failed, mut warned) = (Vec::new(), Vec::new());
    let mut counts = Counts::default();
    for (i, it) in items.iter().enumerate() {
        let f = &findings[i];
        if !it["finding"].is_object() {
            // Fail closed: a malformed entry must never silently disappear.
            counts.evaluated += 1;
            failed.push(GateEntry {
                fingerprint: fps[i].clone(),
                rule_id: String::new(),
                severity: String::new(),
                category: String::new(),
                title: "malformed queue entry".into(),
                locus: String::new(),
                reason: "malformed queue entry: no finding object".into(),
            });
            continue;
        }
        let category = category_of(f);
        if !policy.fail_on.categories.contains(&category) {
            continue;
        }
        counts.evaluated += 1;
        let sev = s(f, "severity").to_ascii_uppercase();
        let cwe = s(f, "cwe").split(':').next().unwrap_or("").trim().to_ascii_uppercase();
        let cwe = canonical_cwe(&cwe).unwrap_or(cwe);
        let entry = |reason: String| GateEntry {
            fingerprint: fps[i].clone(),
            rule_id: s(f, "rule_id"),
            severity: sev.clone(),
            category: category.clone(),
            title: s(f, "title"),
            locus: locus(f),
            reason,
        };
        let likely_fp = it["verdict"].as_str() == Some("LIKELY_FALSE_POSITIVE");
        if let Some(r) = matches(&sev, &cwe, &policy.fail_on.severity, &policy.fail_on.cwe, "fail_on") {
            if likely_fp && policy.triage.likely_false_positive == FpMode::DemoteToWarn {
                counts.demoted_fp += 1;
                warned.push(entry(format!("{r}; demoted: triaged as likely false positive")));
            } else {
                failed.push(entry(r));
            }
        } else if !SEVERITIES.contains(&sev.as_str()) {
            // Unknown or missing severity (e.g. trivy's UNKNOWN): surface it, never drop it.
            warned.push(entry(format!("unrecognised severity {sev:?}: review manually")));
        } else if let Some(r) = matches(&sev, &cwe, &policy.warn_on.severity, &policy.warn_on.cwe, "warn_on") {
            warned.push(entry(r));
        }
    }
    counts.failed = failed.len();
    counts.warned = warned.len();
    // A policy category whose analyser was not installed was never scanned. A DAST
    // track that scanned nothing tested nothing, whatever `complete` claims (defence
    // in depth against a stale or hand-edited run.json).
    let complete = status.is_some_and(|st| {
        st.complete
            && !st.dast.as_ref().is_some_and(|d| d.scanned == 0)
            && !st.skipped_tools.iter().any(|t| {
                tool_category(t).is_some_and(|c| policy.fail_on.categories.iter().any(|x| x == c))
            })
    });
    let decision = if !complete {
        Decision::Incomplete
    } else if !failed.is_empty() {
        Decision::Fail
    } else if !warned.is_empty() {
        Decision::Conditional
    } else {
        Decision::Pass
    };
    let exit_code = match decision {
        Decision::Pass => 0,
        Decision::Conditional => u8::from(fail_on_warn),
        Decision::Fail => 1,
        Decision::Incomplete => 3,
    };
    GateResult { decision, exit_code, complete, counts, failed, warned }
}

pub fn gate_document(policy: &Policy, r: &GateResult, status: Option<&RunStatus>, ts: &str) -> Value {
    json!({
        "policy": { "name": policy.name, "hash": policy_hash(policy) },
        "decision": r.decision,
        "exit_code": r.exit_code,
        "complete": r.complete,
        "failed_tools": status.map(|st| st.failed_tools.clone()).unwrap_or_default(),
        "skipped_tools": status.map(|st| st.skipped_tools.clone()).unwrap_or_default(),
        "incomplete_reasons": status.map(|st| st.incomplete_reasons.clone()).unwrap_or_default(),
        "dry_run": status.is_some_and(|st| st.dry_run),
        "counts": r.counts,
        "failed": r.failed,
        "warned": r.warned,
        "evaluated_at": ts,
    })
}

#[derive(Debug)]
pub enum WriteGateError {
    /// The audit chain did not verify: nothing was written (exit 4).
    Integrity(String),
    Io(String),
}

/// Verify the audit chain, write gate.json atomically, then chain a
/// `gate_evaluation` entry binding the document's hash.
pub fn write_gate(out_dir: &str, doc: &Value) -> Result<(), WriteGateError> {
    let dir = Path::new(out_dir);
    let audit = dir.join("audit.jsonl");
    let (ok, msg) = crux::AuditLog::new(&audit).verify();
    if !ok {
        return Err(WriteGateError::Integrity(msg));
    }
    let text = serde_json::to_string_pretty(doc).map_err(|e| WriteGateError::Io(e.to_string()))? + "\n";
    crate::triage::write_atomic(&dir.join("gate.json"), text.as_bytes()).map_err(|e| WriteGateError::Io(e.to_string()))?;
    let mut body = Map::new();
    body.insert("ts".into(), doc["evaluated_at"].clone());
    body.insert("type".into(), Value::from("gate_evaluation"));
    body.insert("decision".into(), doc["decision"].clone());
    body.insert("exit_code".into(), doc["exit_code"].clone());
    body.insert("policy_hash".into(), doc["policy"]["hash"].clone());
    body.insert("gate_hash".into(), Value::from(crux::canon::hash_value(doc)));
    let appended = match audit.to_str() {
        Some(a) => crate::gatesio::append_chained(a, body).map_err(|e| e.to_string()),
        None => Err("audit path is not UTF-8".into()),
    };
    appended.map_err(|m| {
        // Never leave a verdict on disk that is not chained into the audit log.
        let _ = std::fs::remove_file(dir.join("gate.json"));
        WriteGateError::Io(m)
    })
}

/// The triaged queue. Missing or non-array → Err (the CLI maps it to exit 3).
pub fn read_queue(out_dir: &str) -> Result<Vec<Value>, String> {
    let path = Path::new(out_dir).join("queue.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e} (run `ascent run` first)", path.display()))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Array(items)) => Ok(items),
        _ => Err(format!("{} is not a JSON array", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::policy::parse_policy;
    use serde_json::json;

    fn item(tool: &str, sev: &str, cwe: &str, verdict: &str) -> Value {
        json!({"finding": {"id": format!("{tool}:{sev}"), "tool": tool, "rule_id": "r",
            "severity": sev, "title": "t", "message": "m", "url": "", "file": "a.py",
            "line": 3, "category": if tool == "trivy" {"SCA"} else {"SAST"}, "cwe": cwe, "code": "q()"},
            "verdict": verdict, "confidence": 0.9, "fp_likelihood": 0.1, "rationale": "r", "remediation": "x"})
    }
    fn policy() -> Policy {
        parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL, HIGH]\n  cwe: [CWE-798]\nwarn_on:\n  severity: [MEDIUM]\n").unwrap()
    }
    fn done() -> RunStatus {
        RunStatus { complete: true, dry_run: false, failed_tools: vec![], skipped_tools: vec![], finished_at: "t".into(), ..Default::default() }
    }

    #[test]
    fn empty_complete_run_passes() {
        let r = evaluate(&[], &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Pass, 0));
    }
    #[test]
    fn high_true_positive_fails() {
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Fail, 1));
        assert_eq!(r.failed[0].reason, "severity HIGH in fail_on");
        assert!(r.failed[0].fingerprint.starts_with("ascent/v1:"));
        assert_eq!(r.failed[0].locus, "a.py:3");
    }
    #[test]
    fn cwe_rule_fails_a_low_secret_and_categorises_it() {
        let r = evaluate(&[item("gitleaks", "LOW", "CWE-798", "ABSTAIN")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
        assert_eq!(r.failed[0].category, "SECRETS");
        assert_eq!(r.failed[0].reason, "CWE-798 in fail_on");
    }
    #[test]
    fn medium_is_conditional_and_fail_on_warn_exits_1() {
        let items = [item("opengrep", "MEDIUM", "", "TRUE_POSITIVE")];
        let r = evaluate(&items, &policy(), Some(&done()), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Conditional, 0));
        assert_eq!(evaluate(&items, &policy(), Some(&done()), true).exit_code, 1);
    }
    #[test]
    fn likely_false_positive_is_demoted_never_dropped() {
        let items = [item("opengrep", "CRITICAL", "", "LIKELY_FALSE_POSITIVE")];
        let r = evaluate(&items, &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Conditional);
        assert_eq!((r.counts.demoted_fp, r.warned.len(), r.failed.len()), (1, 1, 0));
        assert!(r.warned[0].reason.contains("demoted"));
        let enforce = parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL]\ntriage:\n  likely_false_positive: enforce\n").unwrap();
        assert_eq!(evaluate(&items, &enforce, Some(&done()), false).decision, Decision::Fail);
    }
    #[test]
    fn incomplete_or_missing_status_never_passes() {
        let mut st = done();
        st.complete = false;
        let r = evaluate(&[], &policy(), Some(&st), false);
        assert_eq!((r.decision, r.exit_code), (Decision::Incomplete, 3));
        assert_eq!(evaluate(&[], &policy(), None, false).decision, Decision::Incomplete);
        // findings are still listed so a human can see them
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &policy(), None, false);
        assert_eq!((r.decision, r.failed.len()), (Decision::Incomplete, 1));
    }
    #[test]
    fn missing_analyser_for_a_policy_category_is_incomplete() {
        let mut st = done();
        st.skipped_tools = vec!["gitleaks".into()];
        let r = evaluate(&[], &policy(), Some(&st), false); // default: all categories
        assert_eq!((r.decision, r.exit_code, r.complete), (Decision::Incomplete, 3, false));
        let sast_only = parse_policy("version: 1\nfail_on:\n  severity: [HIGH]\n  categories: [SAST]\n").unwrap();
        let r = evaluate(&[], &sast_only, Some(&st), false);
        assert_eq!((r.decision, r.complete), (Decision::Pass, true));
        st.skipped_tools = vec!["opengrep".into()];
        assert_eq!(evaluate(&[], &sast_only, Some(&st), false).decision, Decision::Incomplete);
    }
    #[test]
    fn gate_document_lists_skipped_tools() {
        let mut st = done();
        st.skipped_tools = vec!["trivy".into()];
        let r = evaluate(&[], &policy(), Some(&st), false);
        let doc = gate_document(&policy(), &r, Some(&st), "t");
        assert_eq!(doc["skipped_tools"], json!(["trivy"]));
        assert_eq!(gate_document(&policy(), &r, None, "t")["skipped_tools"], json!([]));
    }
    #[test]
    fn dast_that_scanned_nothing_is_never_complete() {
        // a stale or hand-edited run.json claiming complete cannot PASS
        let mut st = done();
        st.dast = Some(crate::stages::dast::DastSummary { scanned: 0, ..Default::default() });
        let r = evaluate(&[], &policy(), Some(&st), false);
        assert_eq!((r.decision, r.exit_code, r.complete), (Decision::Incomplete, 3, false));
        st.dast = Some(crate::stages::dast::DastSummary { scanned: 1, ..Default::default() });
        assert_eq!(evaluate(&[], &policy(), Some(&st), false).decision, Decision::Pass);
    }
    #[test]
    fn gate_document_lists_incomplete_reasons() {
        let mut st = done();
        st.complete = false;
        st.incomplete_reasons = vec!["DAST: no in-scope URL was reachable".into()];
        let r = evaluate(&[], &policy(), Some(&st), false);
        let doc = gate_document(&policy(), &r, Some(&st), "t");
        assert_eq!(doc["incomplete_reasons"], json!(["DAST: no in-scope URL was reachable"]));
        assert_eq!(gate_document(&policy(), &r, None, "t")["incomplete_reasons"], json!([]));
    }
    #[test]
    fn category_filter_excludes_findings() {
        let only_sca = parse_policy("version: 1\nfail_on:\n  severity: [HIGH]\n  categories: [SCA]\n").unwrap();
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &only_sca, Some(&done()), false);
        assert_eq!((r.decision, r.counts.evaluated), (Decision::Pass, 0));
    }

    #[test]
    fn malformed_entry_fails_closed() {
        let bad = json!({"verdict": "TRUE_POSITIVE"}); // no finding object
        let r = evaluate(&[bad], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
        assert_eq!(r.failed[0].reason, "malformed queue entry: no finding object");
        assert_eq!(r.counts.evaluated, 1);
    }
    #[test]
    fn unrecognised_severity_warns_instead_of_vanishing() {
        let r = evaluate(&[item("trivy", "UNKNOWN", "", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Conditional);
        assert!(r.warned[0].reason.contains("unrecognised severity"), "{}", r.warned[0].reason);
        // a fail_on CWE still fails even with an unrecognised severity
        let r = evaluate(&[item("opengrep", "UNKNOWN", "CWE-798", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
    }
    #[test]
    fn zero_padded_policy_cwe_matches_the_canonical_finding_cwe() {
        let p = parse_policy("version: 1\nfail_on:\n  cwe: [CWE-089]\n").unwrap();
        let r = evaluate(&[item("opengrep", "LOW", "CWE-89", "TRUE_POSITIVE")], &p, Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
        assert_eq!(r.failed[0].reason, "CWE-89 in fail_on");
        // and the other way round: a zero-padded finding CWE matches too
        let r = evaluate(&[item("opengrep", "LOW", "CWE-0798", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
    }
    #[test]
    fn cwe_with_a_description_suffix_still_matches() {
        let r = evaluate(&[item("opengrep", "LOW", "CWE-798: Use of Hard-coded Credentials", "TRUE_POSITIVE")], &policy(), Some(&done()), false);
        assert_eq!(r.decision, Decision::Fail);
    }

    fn tmp() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("ascent_gate_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
    }

    #[test]
    fn write_gate_records_a_verifiable_audit_entry() {
        let dir = tmp();
        let p = policy();
        let r = evaluate(&[item("opengrep", "HIGH", "", "TRUE_POSITIVE")], &p, Some(&done()), false);
        let doc = gate_document(&p, &r, Some(&done()), "2026-10-30T00:00:00.000000+00:00");
        assert_eq!(doc["decision"], "FAIL");
        assert_eq!(doc["policy"]["hash"], crate::gate::policy::policy_hash(&p));
        write_gate(&dir, &doc).unwrap();
        let stored: Value = serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(&dir).join("gate.json")).unwrap()).unwrap();
        assert_eq!(stored, doc);
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        assert!(crux::AuditLog::new(&audit).verify().0);
        let last: Value = serde_json::from_str(std::fs::read_to_string(&audit).unwrap().lines().last().unwrap()).unwrap();
        assert_eq!(last["type"], "gate_evaluation");
        assert_eq!(last["decision"], "FAIL");
        assert_eq!(last["gate_hash"], crux::canon::hash_value(&doc));
    }
    #[test]
    fn broken_chain_refuses_and_writes_no_gate() {
        let dir = tmp();
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        std::fs::write(&audit, "{\"prev_hash\":\"x\",\"entry_hash\":\"y\"}\n").unwrap();
        let before = std::fs::read(&audit).unwrap();
        let p = policy();
        let r = evaluate(&[], &p, Some(&done()), false);
        let doc = gate_document(&p, &r, Some(&done()), "t");
        assert!(matches!(write_gate(&dir, &doc), Err(WriteGateError::Integrity(_))));
        assert!(!std::path::Path::new(&dir).join("gate.json").exists());
        assert_eq!(std::fs::read(&audit).unwrap(), before, "audit log must not be appended to");
    }
    #[test]
    fn failed_audit_append_leaves_no_unchained_gate_json() {
        let dir = tmp();
        let audit = std::path::Path::new(&dir).join("audit.jsonl");
        std::fs::write(&audit, "").unwrap();
        let mut perm = std::fs::metadata(&audit).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&audit, perm.clone()).unwrap();
        // A privileged user (e.g. root) can still append; then there is nothing to test.
        let appendable = std::fs::OpenOptions::new().append(true).open(&audit).is_ok();
        let p = policy();
        let r = evaluate(&[], &p, Some(&done()), false);
        let res = write_gate(&dir, &gate_document(&p, &r, Some(&done()), "t"));
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&audit, perm).unwrap();
        if !appendable {
            assert!(matches!(res, Err(WriteGateError::Io(_))), "{res:?}");
            assert!(!std::path::Path::new(&dir).join("gate.json").exists(), "unchained gate.json left on disk");
        }
    }
    #[test]
    fn read_queue_requires_an_array() {
        let dir = tmp();
        assert!(read_queue(&dir).is_err());
        std::fs::write(std::path::Path::new(&dir).join("queue.json"), "{}").unwrap();
        assert!(read_queue(&dir).is_err());
        std::fs::write(std::path::Path::new(&dir).join("queue.json"), "[]").unwrap();
        assert!(read_queue(&dir).unwrap().is_empty());
    }
}
