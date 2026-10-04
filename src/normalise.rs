use crate::models::Finding;
use serde_json::Value;

fn cwe_of(info: &Value) -> String {
    let c = &info["classification"]["cwe-id"];
    if let Some(a) = c.as_array() {
        a.first().and_then(|v| v.as_str()).unwrap_or("").to_string()
    } else {
        c.as_str().unwrap_or("").to_string()
    }
}

pub fn normalise_nuclei(rows: &[Value]) -> Vec<Finding> {
    rows.iter()
        .map(|r| {
            let info = &r["info"];
            let loc = r["matched-at"]
                .as_str()
                .or_else(|| r["host"].as_str())
                .unwrap_or("")
                .to_string();
            let rid = r["template-id"].as_str().unwrap_or("nuclei").to_string();
            Finding {
                id: format!("nuclei:{rid}:{loc}"),
                tool: "nuclei".into(),
                rule_id: rid,
                severity: info["severity"].as_str().unwrap_or("info").to_uppercase(),
                title: info["name"].as_str().unwrap_or("finding").to_string(),
                message: info["description"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                url: loc,
                category: "DAST".into(),
                cwe: cwe_of(info),
                evidence: r["curl-command"].as_str().unwrap_or("").to_string(),
                ..Default::default()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nuclei_normalises() {
        let rows = vec![serde_json::json!({
            "template-id":"CVE-2021-1234",
            "info":{"name":"Example RCE","severity":"high","classification":{"cwe-id":["CWE-78"]}},
            "matched-at":"https://app.example.com/ping?ip=1","type":"http"})];
        let out = normalise_nuclei(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "CVE-2021-1234");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].url, "https://app.example.com/ping?ip=1");
        assert_eq!(out[0].cwe, "CWE-78");
        assert_eq!(out[0].to_crux_json()["tool"], "nuclei");
    }
}
