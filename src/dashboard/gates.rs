//! Human-approval gates: `<out_dir>/gates.json` holds the actions awaiting a
//! human decision; each decision is recorded in Crux's hash-chained audit log
//! *before* the gate is marked resolved. Nothing here runs a gate's command.
use crate::gatesio::{all_gates, append_chained, first_decisions, gate_hash, is_pending};
use serde_json::{Map, Value};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why a decision was not recorded.
#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    /// No gate with that id exists.
    NotFound,
    /// The gate already carries a `status`.
    Resolved,
    /// Approve was requested for a gate whose `in_scope` is not `true`.
    OutOfScope,
    /// The audit chain failed verification; nothing was written.
    ChainBroken(String),
    /// A filesystem error.
    Io(String),
}

/// First `gate_decision` recorded in the audit log for each gate, as
/// `(gate_id, status, ts)`. The audit log is the source of truth for decisions:
/// it is written before `gates.json`, so it can be ahead of it after a failure.
fn recorded_decisions(out_dir: &str) -> Vec<(String, &'static str, String)> {
    first_decisions(out_dir)
        .into_iter()
        .map(|(id, status, ts, _)| (id, status, ts))
        .collect()
}

fn now_ts() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    crux::audit::format_ts(d.as_secs(), d.subsec_micros())
}

/// Append one Crux-compatible `gate_decision` entry. The caller has already
/// verified the chain. `gate_hash` (see [`gate_hash`]) is part of the hashed
/// body, so it is covered by the chain.
pub fn append_decision(
    audit: &Path,
    gate_id: &str,
    decision: &str,
    gate_hash: &str,
    ts: &str,
) -> Result<(), String> {
    let mut body = Map::new();
    body.insert("ts".into(), Value::from(ts));
    body.insert("type".into(), Value::from("gate_decision"));
    body.insert("gate_id".into(), Value::from(gate_id));
    body.insert("decision".into(), Value::from(decision));
    body.insert("gate_hash".into(), Value::from(gate_hash));
    let audit = audit
        .to_str()
        .ok_or_else(|| "audit path is not valid UTF-8".to_string())?;
    append_chained(audit, body).map_err(|e| e.to_string())
}

/// Replace `gates.json` atomically (temp file in the same dir, then rename).
fn write_gates_atomic(out_dir: &str, gates: &[Value]) -> Result<(), String> {
    let dir = Path::new(out_dir);
    let tmp = dir.join("gates.json.tmp");
    let text = serde_json::to_string_pretty(gates).map_err(|e| e.to_string())?;
    let result = (|| {
        let mut fh = std::fs::File::create(&tmp)?;
        fh.write_all(text.as_bytes())?;
        fh.sync_all()?;
        std::fs::rename(&tmp, dir.join("gates.json"))
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write gates.json: {e}")
    })
}

fn mark_resolved(gate: &mut Value, status: &str, ts: String) {
    if let Some(obj) = gate.as_object_mut() {
        obj.insert("status".into(), Value::from(status));
        obj.insert("decided_at".into(), Value::from(ts));
    }
}

/// Record a human decision on gate `id`. Order matters: validate the gate,
/// verify the audit chain (never extend a broken one), refuse (and self-heal)
/// if the log already holds a decision for this gate, append the audit entry,
/// and only then mark the gate resolved. The caller must serialise calls.
/// `id` is only compared against ids inside `gates.json`.
pub fn decide_gate(out_dir: &str, id: &str, approve: bool) -> Result<(), DecideError> {
    let mut gates = all_gates(out_dir);
    let id_matches = |g: &Value| g.get("id").and_then(Value::as_str) == Some(id);
    let idx = match gates.iter().position(|g| id_matches(g) && is_pending(g)) {
        Some(i) => i,
        None if gates.iter().any(id_matches) => return Err(DecideError::Resolved),
        None => return Err(DecideError::NotFound),
    };
    // Only a gate the scope guard marked in-scope may be approved; deny is
    // always allowed. Checked before anything is read or written.
    if approve && gates[idx].get("in_scope") != Some(&Value::Bool(true)) {
        return Err(DecideError::OutOfScope);
    }

    let audit = Path::new(out_dir).join("audit.jsonl");
    let (ok, msg) = crux::AuditLog::new(&audit).verify();
    if !ok {
        return Err(DecideError::ChainBroken(msg));
    }

    // A decision already in the audit log means a previous attempt crashed
    // before gates.json was updated. Never record a second (possibly opposite)
    // decision: heal gates.json from the log and report the gate as resolved.
    if let Some((_, status, ts)) = recorded_decisions(out_dir)
        .into_iter()
        .find(|(g, _, _)| g == id)
    {
        mark_resolved(&mut gates[idx], status, ts);
        write_gates_atomic(out_dir, &gates).map_err(DecideError::Io)?;
        return Err(DecideError::Resolved);
    }

    let (status, ts) = (if approve { "approved" } else { "denied" }, now_ts());
    let hash = gate_hash(&gates[idx]);
    append_decision(&audit, id, status, &hash, &ts).map_err(DecideError::Io)?;

    mark_resolved(&mut gates[idx], status, ts);
    write_gates_atomic(out_dir, &gates).map_err(DecideError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatesio::read_pending_gates;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ascent_gates_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn s(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    fn gate(id: &str) -> Value {
        json!({"id": id, "title": "t", "why": "w", "command": "c", "target": "x", "in_scope": true})
    }

    fn put(dir: &Path, v: Value) {
        std::fs::write(dir.join("gates.json"), v.to_string()).unwrap();
    }

    #[test]
    fn missing_or_invalid_gates_is_empty() {
        let dir = tmp();
        assert!(read_pending_gates(s(&dir)).is_empty());
        std::fs::write(dir.join("gates.json"), "not json").unwrap();
        assert!(read_pending_gates(s(&dir)).is_empty());
        std::fs::write(dir.join("gates.json"), r#"{"id":"g1"}"#).unwrap();
        assert!(read_pending_gates(s(&dir)).is_empty());
    }

    #[test]
    fn pending_excludes_resolved_and_non_objects() {
        let dir = tmp();
        let mut done = gate("g2");
        done["status"] = json!("denied");
        put(&dir, json!([gate("g1"), done, "junk", 7]));
        let p = read_pending_gates(s(&dir));
        assert_eq!(p.len(), 1);
        assert_eq!(p[0]["id"], "g1");
    }

    #[test]
    fn decide_chains_onto_crux_log_and_verifies() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        let audit = dir.join("audit.jsonl");
        crux::AuditLog::new(&audit)
            .append("f1", "h", "mock", "ABSTAIN", 0.1, 0.5)
            .unwrap();
        decide_gate(s(&dir), "g1", true).unwrap();
        // a later gate chains onto our own entry too
        put(&dir, json!([gate("g2")]));
        decide_gate(s(&dir), "g2", false).unwrap();
        let text = std::fs::read_to_string(&audit).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(crux::AuditLog::new(&audit).verify().0);
    }

    #[test]
    fn decide_errors() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        assert_eq!(decide_gate(s(&dir), "zz", true), Err(DecideError::NotFound));
        decide_gate(s(&dir), "g1", true).unwrap();
        assert_eq!(decide_gate(s(&dir), "g1", true), Err(DecideError::Resolved));
    }

    #[test]
    fn id_with_path_chars_is_just_not_found() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        assert_eq!(
            decide_gate(s(&dir), "../../etc/passwd", true),
            Err(DecideError::NotFound)
        );
    }

    #[test]
    fn unterminated_valid_chain_is_not_glued() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        let audit = dir.join("audit.jsonl");
        crux::AuditLog::new(&audit)
            .append("f1", "h", "mock", "ABSTAIN", 0.1, 0.5)
            .unwrap();
        let text = std::fs::read_to_string(&audit).unwrap();
        std::fs::write(&audit, text.trim_end()).unwrap();
        decide_gate(s(&dir), "g1", true).unwrap();
        assert_eq!(std::fs::read_to_string(&audit).unwrap().lines().count(), 2);
        assert!(crux::AuditLog::new(&audit).verify().0);
    }

    fn last_entry(audit: &Path) -> Value {
        let text = std::fs::read_to_string(audit).unwrap();
        serde_json::from_str(text.lines().last().unwrap()).unwrap()
    }

    #[test]
    fn decision_binds_gate_hash_into_chain() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        let audit = dir.join("audit.jsonl");
        crux::AuditLog::new(&audit)
            .append("f1", "h", "mock", "ABSTAIN", 0.1, 0.5)
            .unwrap();
        let listed = read_pending_gates(s(&dir)).remove(0);
        decide_gate(s(&dir), "g1", true).unwrap();
        let entry = last_entry(&audit);
        assert_eq!(entry["type"], "gate_decision");
        // the hash of the gate exactly as it was listed (pending) when decided
        assert_eq!(entry["gate_hash"], crux::canon::hash_value(&listed));
        // gate_hash is inside the hashed body, so the chain still verifies ...
        assert!(crux::AuditLog::new(&audit).verify().0);
        // ... and tampering with it breaks the chain
        let text = std::fs::read_to_string(&audit).unwrap();
        let h = entry["gate_hash"].as_str().unwrap();
        std::fs::write(&audit, text.replace(h, &"0".repeat(64))).unwrap();
        assert!(!crux::AuditLog::new(&audit).verify().0);
    }

    #[test]
    fn gate_hash_ignores_resolution_fields() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        decide_gate(s(&dir), "g1", false).unwrap();
        let stored = all_gates(s(&dir)).remove(0);
        assert_eq!(stored["status"], "denied");
        // the resolved gate in gates.json still matches what the log recorded
        assert_eq!(
            gate_hash(&stored),
            last_entry(&dir.join("audit.jsonl"))["gate_hash"]
        );
        assert_eq!(gate_hash(&stored), crux::canon::hash_value(&gate("g1")));
    }

    #[test]
    fn edited_gate_no_longer_matches_its_approval() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        decide_gate(s(&dir), "g1", true).unwrap();
        let recorded = last_entry(&dir.join("audit.jsonl"))["gate_hash"].clone();
        let mut edited = all_gates(s(&dir)).remove(0);
        assert_eq!(gate_hash(&edited), recorded);
        edited["command"] = json!("rm -rf /");
        assert_ne!(gate_hash(&edited), recorded);
        let mut retargeted = all_gates(s(&dir)).remove(0);
        retargeted["target"] = json!("http://elsewhere.example");
        assert_ne!(gate_hash(&retargeted), recorded);
    }

    #[test]
    fn approve_out_of_scope_writes_nothing() {
        let dir = tmp();
        let mut g = gate("g1");
        g["in_scope"] = json!(false);
        put(&dir, json!([g]));
        assert_eq!(
            decide_gate(s(&dir), "g1", true),
            Err(DecideError::OutOfScope)
        );
        assert!(!dir.join("audit.jsonl").exists());
        assert_eq!(read_pending_gates(s(&dir)).len(), 1);
        decide_gate(s(&dir), "g1", false).unwrap();
    }

    #[test]
    fn broken_chain_writes_nothing() {
        let dir = tmp();
        put(&dir, json!([gate("g1")]));
        let audit = dir.join("audit.jsonl");
        std::fs::write(&audit, "garbage\n").unwrap();
        assert!(matches!(
            decide_gate(s(&dir), "g1", true),
            Err(DecideError::ChainBroken(_))
        ));
        assert_eq!(std::fs::read_to_string(&audit).unwrap(), "garbage\n");
        assert_eq!(read_pending_gates(s(&dir)).len(), 1);
    }
}
