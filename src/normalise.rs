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

#[allow(dead_code)] // wired into the SAST stage in a later task
fn sev_from_semgrep(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "ERROR" => "HIGH",
        "WARNING" => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

#[allow(dead_code)] // wired into the SAST stage in a later task
fn cwe_first(v: &Value) -> String {
    // Accept ["CWE-89: ..."] or "CWE-89"; return just the "CWE-<n>" token.
    let raw = if let Some(a) = v.as_array() {
        a.first().and_then(|x| x.as_str()).unwrap_or("")
    } else {
        v.as_str().unwrap_or("")
    };
    raw.split(':').next().unwrap_or("").trim().to_string()
}

#[allow(dead_code)] // wired into the SAST stage in a later task
pub fn normalise_opengrep(rows: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for row in rows {
        let results = row.get("results").and_then(|v| v.as_array());
        let items: Vec<&Value> = match results {
            Some(a) => a.iter().collect(),
            None => vec![row], // tolerate a bare result object
        };
        for r in items {
            let path = r["path"].as_str().unwrap_or("");
            if path.is_empty() {
                continue;
            }
            let line = r["start"]["line"].as_i64().unwrap_or(0);
            let rid = r["check_id"].as_str().unwrap_or("opengrep").to_string();
            out.push(Finding {
                id: format!("opengrep:{rid}:{path}:{line}"),
                tool: "opengrep".into(),
                rule_id: rid.clone(),
                severity: sev_from_semgrep(r["extra"]["severity"].as_str().unwrap_or("INFO")),
                title: rid,
                message: r["extra"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                url: String::new(),
                file: path.to_string(),
                line,
                category: "SAST".into(),
                cwe: cwe_first(&r["extra"]["metadata"]["cwe"]),
                evidence: r["extra"]["lines"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    out
}

#[allow(dead_code)] // wired into the SAST stage in a later task
pub fn normalise_gitleaks(rows: &[Value]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|r| {
            let file = r["File"].as_str()?;
            let line = r["StartLine"].as_i64().unwrap_or(0);
            let rid = r["RuleID"].as_str().unwrap_or("gitleaks").to_string();
            let desc = r["Description"].as_str().unwrap_or(&rid).to_string();
            // Deliberately store NO secret value (no `Secret`/`Match`) in any field.
            Some(Finding {
                id: format!("gitleaks:{rid}:{file}:{line}"),
                tool: "gitleaks".into(),
                rule_id: rid,
                severity: "HIGH".into(),
                title: format!("Hardcoded secret: {desc}"),
                message:
                    "Potential hardcoded secret detected; rotate it and move it to a secret store."
                        .into(),
                url: String::new(),
                file: file.to_string(),
                line,
                category: "SAST".into(),
                cwe: "CWE-798".into(),
                evidence: String::new(),
            })
        })
        .collect()
}

#[allow(dead_code)] // wired into the SAST stage in a later task
pub fn normalise_trivy(rows: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for row in rows {
        let Some(results) = row["Results"].as_array() else {
            continue;
        };
        for res in results {
            let target = res["Target"].as_str().unwrap_or("");
            let Some(vulns) = res["Vulnerabilities"].as_array() else {
                continue;
            };
            for v in vulns {
                let id = v["VulnerabilityID"].as_str().unwrap_or("trivy").to_string();
                let pkg = v["PkgName"].as_str().unwrap_or("");
                out.push(Finding {
                    id: format!("trivy:{id}:{target}:{pkg}"),
                    tool: "trivy".into(),
                    rule_id: id.clone(),
                    severity: v["Severity"].as_str().unwrap_or("UNKNOWN").to_uppercase(),
                    title: v["Title"].as_str().unwrap_or(&id).to_string(),
                    message: v["Description"].as_str().unwrap_or("").trim().to_string(),
                    url: String::new(),
                    file: target.to_string(),
                    line: 0,
                    category: "SCA".into(),
                    cwe: cwe_first(&v["CweIDs"]),
                    evidence: String::new(),
                });
            }
        }
    }
    out
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

#[cfg(test)]
mod sast_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opengrep_normalises() {
        let rows = vec![json!({"results":[{
            "check_id":"rust.lang.security.sqli","path":"src/db.rs",
            "start":{"line":42},"end":{"line":42},
            "extra":{"severity":"ERROR","message":"possible sqli",
                     "metadata":{"cwe":["CWE-89: SQL Injection"]},"lines":"let q = format!(...)"}}]})];
        let out = normalise_opengrep(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "opengrep");
        assert_eq!(out[0].category, "SAST");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].file, "src/db.rs");
        assert_eq!(out[0].line, 42);
        assert_eq!(out[0].cwe, "CWE-89");
        assert_eq!(out[0].rule_id, "rust.lang.security.sqli");
    }

    #[test]
    fn gitleaks_normalises_and_redacts_the_secret() {
        let rows = vec![
            json!({"Description":"AWS Access Key","StartLine":10,"File":"config.py",
            "RuleID":"aws-access-token","Secret":"AKIAIOSFODNN7EXAMPLE","Match":"key = AKIAIOSFODNN7EXAMPLE"}),
        ];
        let out = normalise_gitleaks(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "gitleaks");
        assert_eq!(out[0].category, "SAST");
        assert_eq!(out[0].file, "config.py");
        assert_eq!(out[0].line, 10);
        assert_eq!(out[0].rule_id, "aws-access-token");
        // The raw secret must appear in NO field of the finding.
        let blob = serde_json::to_string(&out[0].to_crux_json()).unwrap();
        assert!(
            !blob.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked into finding: {blob}"
        );
    }

    #[test]
    fn trivy_normalises_sca() {
        let rows = vec![
            json!({"Results":[{"Target":"package-lock.json","Class":"lang-pkgs",
            "Vulnerabilities":[{"VulnerabilityID":"CVE-2021-1234","PkgName":"lodash",
                "Severity":"HIGH","Title":"Prototype pollution","Description":"desc","CweIDs":["CWE-1321"]}]}]}),
        ];
        let out = normalise_trivy(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool, "trivy");
        assert_eq!(out[0].category, "SCA");
        assert_eq!(out[0].rule_id, "CVE-2021-1234");
        assert_eq!(out[0].severity, "HIGH");
        assert_eq!(out[0].cwe, "CWE-1321");
        assert_eq!(out[0].file, "package-lock.json");
    }
}
