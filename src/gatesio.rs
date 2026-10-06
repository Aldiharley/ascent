//! Tamper-evident gate/audit primitives shared by the `ascent` pipeline and the
//! `dashboard` server, so there is exactly one implementation of `gate_hash`
//! (the value that binds a human approval to the exact gate that was approved).
// Each bin uses a different subset of these primitives; the rest are consumed
// by the exploit modules in later tasks.
#![allow(dead_code)]

use serde_json::{Map, Value};
use std::io::Write;
use std::path::Path;

/// Gates read from `<out_dir>/gates.json`. Missing/invalid file or non-array
/// content -> empty.
pub fn all_gates(out_dir: &str) -> Vec<Value> {
    std::fs::read_to_string(Path::new(out_dir).join("gates.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .unwrap_or_default()
}

pub fn is_pending(gate: &Value) -> bool {
    gate.is_object() && gate.get("status").is_none()
}

/// First `gate_decision` recorded in the audit log for each gate, as
/// `(gate_id, status, ts, recorded_gate_hash)`. The audit log is the source of
/// truth for decisions: it is written before `gates.json`, so it can be ahead
/// of it after a failure. The first decision for a gate wins.
pub fn first_decisions(out_dir: &str) -> Vec<(String, &'static str, String, Option<String>)> {
    let text = std::fs::read_to_string(Path::new(out_dir).join("audit.jsonl")).unwrap_or_default();
    let mut seen: Vec<(String, &'static str, String, Option<String>)> = Vec::new();
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
        if !seen.iter().any(|(i, _, _, _)| i == id) {
            let hash = entry["gate_hash"].as_str().map(String::from);
            seen.push((id.to_string(), status, ts.to_string(), hash));
        }
    }
    seen
}

/// Gates still awaiting a decision: no `status` field and no recorded
/// `gate_decision` in the audit log. Missing or invalid file -> empty.
pub fn read_pending_gates(out_dir: &str) -> Vec<Value> {
    let decided = first_decisions(out_dir);
    all_gates(out_dir)
        .into_iter()
        .filter(is_pending)
        .filter(|g| {
            let id = g.get("id").and_then(Value::as_str);
            !decided.iter().any(|(d, _, _, _)| Some(d.as_str()) == id)
        })
        .collect()
}

/// `(gate_id, recorded_gate_hash)` for every gate whose (first) recorded
/// decision in the audit log is `approved` and carries a `gate_hash`.
pub fn approved_decisions(out_dir: &str) -> Vec<(String, String)> {
    first_decisions(out_dir)
        .into_iter()
        .filter(|(_, status, _, _)| *status == "approved")
        .filter_map(|(id, _, _, hash)| hash.map(|h| (id, h)))
        .collect()
}

/// Crux canonical hash of a gate as it was presented for decision: the gate
/// object minus its resolution fields (`status`, `decided_at`). Recorded in the
/// chained `gate_decision` entry, so an approval stays bound to the exact
/// command/target that was approved even though `gates.json` is not chained.
pub fn gate_hash(gate: &Value) -> String {
    let mut g = gate.clone();
    if let Some(obj) = g.as_object_mut() {
        obj.remove("status");
        obj.remove("decided_at");
    }
    crux::canon::hash_value(&g)
}

/// Append one Crux-compatible hash-chained JSON line built from `body`:
/// `prev_hash` is set to the last entry's `entry_hash` (or `GENESIS`), then
/// `entry_hash` is the canonical hash of the body including `prev_hash`.
/// The caller is responsible for having verified the chain, and for
/// serialising concurrent calls.
pub fn append_chained(
    audit_path: &str,
    mut body: Map<String, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let audit = Path::new(audit_path);
    let text = match std::fs::read_to_string(audit) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read audit log: {e}").into()),
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

    body.remove("entry_hash");
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
    // One write call for the whole line, so it cannot be split across writes.
    fh.write_all(format!("{sep}{line}\n").as_bytes())
        .map_err(|e| format!("cannot write audit log: {e}"))?;
    fh.sync_all()
        .map_err(|e| format!("cannot flush audit log: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ascent_gio_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn body(ty: &str, id: &str, decision: Option<(&str, &str)>) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!(ty));
        m.insert("gate_id".into(), json!(id));
        m.insert("ts".into(), json!("2026-01-01T00:00:00.000000Z"));
        if let Some((d, h)) = decision {
            m.insert("decision".into(), json!(d));
            m.insert("gate_hash".into(), json!(h));
        }
        m
    }

    #[test]
    fn gate_hash_ignores_resolution_fields() {
        let a = json!({"id":"g1","command":"nuclei -id x -u http://h/","target":"http://h/"});
        let mut b = a.clone();
        b["status"] = json!("approved");
        b["decided_at"] = json!("t");
        assert_eq!(gate_hash(&a), gate_hash(&b));
        let mut c = a.clone();
        c["command"] = json!("rm -rf /");
        assert_ne!(gate_hash(&a), gate_hash(&c));
    }

    #[test]
    fn gate_hash_golden_vector() {
        let g = json!({
            "id": "verify:CVE-2021-1234:http://localhost:3000/x",
            "tool": "nuclei",
            "args": ["-id", "CVE-2021-1234", "-u", "http://localhost:3000/x", "-silent", "-jsonl"],
            "command": "nuclei -id CVE-2021-1234 -u http://localhost:3000/x -silent -jsonl",
            "target": "http://localhost:3000/x",
            "in_scope": true,
            "detect_only": true
        });
        assert_eq!(
            gate_hash(&g),
            "2bb40b558b92deba6a2f014ccc94e1090e7019cddf10c9519e5be06b664cbb8a"
        );
    }

    #[test]
    fn approved_decisions_skips_approved_entry_without_hash() {
        let d = tmp();
        let aps = d.join("audit.jsonl");
        let aps = aps.to_str().unwrap();
        // approved but no gate_hash recorded
        let mut nohash = body("gate_decision", "g1", None);
        nohash.insert("decision".into(), json!("approved"));
        append_chained(aps, nohash).unwrap();
        append_chained(
            aps,
            body("gate_decision", "g2", Some(("approved", "hash2"))),
        )
        .unwrap();
        assert_eq!(
            approved_decisions(d.to_str().unwrap()),
            vec![("g2".to_string(), "hash2".to_string())]
        );
    }

    #[test]
    fn append_chained_is_crux_verifiable_and_links() {
        let d = tmp();
        let ap = d.join("audit.jsonl");
        let aps = ap.to_str().unwrap();
        crux::AuditLog::new(&ap)
            .append("f1", "h", "mock", "ABSTAIN", 0.1, 0.5)
            .unwrap();
        append_chained(aps, body("gate_execution", "g1", None)).unwrap();
        append_chained(aps, body("gate_execution", "g2", None)).unwrap();
        assert!(crux::AuditLog::new(&ap).verify().0);
        let text = std::fs::read_to_string(&ap).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1]["prev_hash"], lines[0]["entry_hash"]);
        assert_eq!(lines[2]["prev_hash"], lines[1]["entry_hash"]);
    }

    #[test]
    fn append_chained_starts_from_genesis() {
        let d = tmp();
        let ap = d.join("audit.jsonl");
        append_chained(ap.to_str().unwrap(), body("gate_execution", "g1", None)).unwrap();
        let first: Value = serde_json::from_str(
            std::fs::read_to_string(&ap)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["prev_hash"], crux::audit::GENESIS);
        assert!(crux::AuditLog::new(&ap).verify().0);
    }

    #[test]
    fn approved_decisions_returns_only_approved_with_recorded_hash() {
        let d = tmp();
        let aps = d.join("audit.jsonl");
        let aps = aps.to_str().unwrap();
        append_chained(
            aps,
            body("gate_decision", "g1", Some(("approved", "hash1"))),
        )
        .unwrap();
        append_chained(aps, body("gate_decision", "g2", Some(("denied", "hash2")))).unwrap();
        append_chained(aps, body("gate_execution", "g1", None)).unwrap();
        append_chained(
            aps,
            body("gate_decision", "g3", Some(("approved", "hash3"))),
        )
        .unwrap();
        let a = approved_decisions(d.to_str().unwrap());
        assert_eq!(
            a,
            vec![
                ("g1".to_string(), "hash1".to_string()),
                ("g3".to_string(), "hash3".to_string())
            ]
        );
    }

    #[test]
    fn approved_decisions_first_decision_wins() {
        let d = tmp();
        let aps = d.join("audit.jsonl");
        let aps = aps.to_str().unwrap();
        append_chained(aps, body("gate_decision", "g1", Some(("denied", "h")))).unwrap();
        append_chained(aps, body("gate_decision", "g1", Some(("approved", "h")))).unwrap();
        assert!(approved_decisions(d.to_str().unwrap()).is_empty());
    }

    #[test]
    fn approved_decisions_missing_log_is_empty() {
        let d = tmp();
        assert!(approved_decisions(d.to_str().unwrap()).is_empty());
    }
}
