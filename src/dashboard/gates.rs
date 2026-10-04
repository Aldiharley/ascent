//! Human-approval gates: `<out_dir>/gates.json` holds the actions awaiting a
//! human decision; each decision is recorded in Crux's hash-chained audit log
//! *before* the gate is marked resolved. Nothing here runs a gate's command.
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
    /// The audit chain failed verification; nothing was written.
    ChainBroken(String),
    /// A filesystem error.
    Io(String),
}

fn all_gates(out_dir: &str) -> Vec<Value> {
    std::fs::read_to_string(Path::new(out_dir).join("gates.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .unwrap_or_default()
}

fn is_pending(gate: &Value) -> bool {
    gate.is_object() && gate.get("status").is_none()
}

/// First `gate_decision` recorded in the audit log for each gate, as
/// `(gate_id, status, ts)`. The audit log is the source of truth for decisions:
/// it is written before `gates.json`, so it can be ahead of it after a failure.
fn recorded_decisions(out_dir: &str) -> Vec<(String, &'static str, String)> {
    let text = std::fs::read_to_string(Path::new(out_dir).join("audit.jsonl")).unwrap_or_default();
    let mut seen: Vec<(String, &'static str, String)> = Vec::new();
    for entry in text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
    {
        if entry["type"] != "gate_decision" {
            continue;
        }
        let (Some(id), Some(ts)) = (entry["gate_id"].as_str(), entry["ts"].as_str()) else {
            continue;
        };
        let status = match entry["decision"].as_str() {
            Some("approved") => "approved",
            Some("denied") => "denied",
            _ => continue,
        };
        if !seen.iter().any(|(i, _, _)| i == id) {
            seen.push((id.to_string(), status, ts.to_string()));
        }
    }
    seen
}

/// Gates still awaiting a decision: no `status` field and no recorded
/// `gate_decision` in the audit log. Missing or invalid file -> empty.
pub fn read_pending_gates(out_dir: &str) -> Vec<Value> {
    let decided = recorded_decisions(out_dir);
    all_gates(out_dir)
        .into_iter()
        .filter(is_pending)
        .filter(|g| {
            let id = g.get("id").and_then(Value::as_str);
            !decided.iter().any(|(d, _, _)| Some(d.as_str()) == id)
        })
        .collect()
}

fn now_ts() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    crux::audit::format_ts(d.as_secs(), d.subsec_micros())
}

/// Append one Crux-compatible `gate_decision` entry. The caller has already
/// verified the chain.
pub fn append_decision(
    audit: &Path,
    gate_id: &str,
    decision: &str,
    ts: &str,
) -> Result<(), String> {
    let text = match std::fs::read_to_string(audit) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read audit log: {e}")),
    };
    let prev = text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| v["entry_hash"].as_str().map(String::from))
                .ok_or_else(|| "last audit entry has no entry_hash".to_string())
        })
        .transpose()?
        .unwrap_or_else(|| crux::audit::GENESIS.to_string());

    let mut body = Map::new();
    body.insert("ts".into(), Value::from(ts));
    body.insert("type".into(), Value::from("gate_decision"));
    body.insert("gate_id".into(), Value::from(gate_id));
    body.insert("decision".into(), Value::from(decision));
    body.insert("prev_hash".into(), Value::from(prev));
    let entry_hash = Value::from(crux::canon::hash_value(&Value::Object(body.clone())));

    let mut ordered: Vec<(&str, &Value)> = body.iter().map(|(k, v)| (k.as_str(), v)).collect();
    ordered.push(("entry_hash", &entry_hash));
    let line = crux::canon::to_json_ordered(&ordered);

    // A valid chain whose last line lacks a newline must not be glued onto.
    let sep = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let mut fh = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit)
        .map_err(|e| format!("cannot open audit log: {e}"))?;
    writeln!(fh, "{sep}{line}").map_err(|e| format!("cannot write audit log: {e}"))?;
    fh.sync_all()
        .map_err(|e| format!("cannot flush audit log: {e}"))
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
    append_decision(&audit, id, status, &ts).map_err(DecideError::Io)?;

    mark_resolved(&mut gates[idx], status, ts);
    write_gates_atomic(out_dir, &gates).map_err(DecideError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
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
