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

fn sev_from_semgrep(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "ERROR" => "HIGH",
        "WARNING" => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

fn cwe_first(v: &Value) -> String {
    // Accept ["CWE-89: ..."] or "CWE-89"; return just the "CWE-<n>" token.
    let raw = if let Some(a) = v.as_array() {
        a.first().and_then(|x| x.as_str()).unwrap_or("")
    } else {
        v.as_str().unwrap_or("")
    };
    raw.split(':').next().unwrap_or("").trim().to_string()
}

/// Every `CWE-<n>` token in a `cwe` metadata value (array of strings or a single string).
fn cwe_all(v: &Value) -> Vec<String> {
    let items: Vec<&str> = match v.as_array() {
        Some(a) => a.iter().filter_map(|x| x.as_str()).collect(),
        None => v.as_str().into_iter().collect(),
    };
    items
        .iter()
        .map(|s| s.split(':').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

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
            let col = r["start"]["col"].as_i64().unwrap_or(0);
            let rid = r["check_id"].as_str().unwrap_or("opengrep").to_string();
            let cwe = cwe_first(&r["extra"]["metadata"]["cwe"]);
            // Secret-class rules must not carry the matched source line or a message that
            // may interpolate the secret (e.g. a `$SECRET` metavariable).
            let rid_lc = rid.to_lowercase();
            let secret_rule = cwe_all(&r["extra"]["metadata"]["cwe"])
                .iter()
                .any(|c| matches!(c.as_str(), "CWE-798" | "CWE-259" | "CWE-321" | "CWE-312"))
                || [
                    "secret",
                    "password",
                    "credential",
                    "token",
                    "api-key",
                    "apikey",
                    "private-key",
                    "privatekey",
                    "jwt",
                ]
                .iter()
                .any(|k| rid_lc.contains(k));
            let (evidence, message) = if secret_rule {
                (
                    String::new(),
                    "Potential hardcoded secret detected (details redacted).".to_string(),
                )
            } else {
                (
                    r["extra"]["lines"].as_str().unwrap_or("").to_string(),
                    r["extra"]["message"]
                        .as_str()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                )
            };
            out.push(Finding {
                id: format!("opengrep:{rid}:{path}:{line}:{col}"),
                tool: "opengrep".into(),
                rule_id: rid.clone(),
                severity: sev_from_semgrep(r["extra"]["severity"].as_str().unwrap_or("INFO")),
                title: rid,
                message,
                url: String::new(),
                file: path.to_string(),
                line,
                category: "SAST".into(),
                cwe,
                evidence,
            });
        }
    }
    out
}

pub fn normalise_gitleaks(rows: &[Value]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|r| {
            let file = r["File"].as_str()?;
            let line = r["StartLine"].as_i64().unwrap_or(0);
            let col = r["StartColumn"].as_i64().unwrap_or(0);
            let rid = r["RuleID"].as_str().unwrap_or("gitleaks").to_string();
            let desc = r["Description"].as_str().unwrap_or(&rid).to_string();
            // Deliberately store NO secret value (no `Secret`/`Match`) in any field.
            Some(Finding {
                id: format!("gitleaks:{rid}:{file}:{line}:{col}"),
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
    fn opengrep_redacts_evidence_for_secret_rules_only() {
        let mk = |rid: &str, cwe: &str| {
            json!({"results":[{
                "check_id":rid,"path":"a.py","start":{"line":3,"col":5},
                "extra":{"severity":"ERROR","message":"m",
                         "metadata":{"cwe":[cwe]},"lines":"pw = 'hunter2'"}}]})
        };
        // CWE-798 and CWE-259 are secret-class regardless of the rule id.
        for cwe in ["CWE-798: Hard-coded Credentials", "CWE-259"] {
            let out = normalise_opengrep(&[mk("generic.rule", cwe)]);
            assert_eq!(out[0].evidence, "", "evidence kept for {cwe}");
        }
        // Rule id keywords (case-insensitive) are secret-class regardless of the CWE.
        for rid in [
            "x.Hardcoded-SECRET",
            "x.password-in-code",
            "x.Credential-leak",
        ] {
            let out = normalise_opengrep(&[mk(rid, "CWE-89")]);
            assert_eq!(out[0].evidence, "", "evidence kept for {rid}");
        }
        // A non-secret rule keeps its evidence.
        let out = normalise_opengrep(&[mk("rust.lang.security.sqli", "CWE-89")]);
        assert_eq!(out[0].evidence, "pw = 'hunter2'");
    }

    #[test]
    fn opengrep_secret_class_scans_all_cwes_and_more_keywords_and_blanks_message() {
        let mk = |rid: &str, cwes: Value| {
            json!({"results":[{
                "check_id":rid,"path":"a.py","start":{"line":3,"col":5},
                "extra":{"severity":"ERROR","message":"found key $SECRET=abc123",
                         "metadata":{"cwe":cwes},"lines":"k = 'abc123'"}}]})
        };
        // Secret CWE appears second, not first.
        let out = normalise_opengrep(&[mk("generic.rule", json!(["CWE-312", "CWE-798"]))]);
        assert_eq!(out[0].evidence, "");
        assert!(!out[0].message.contains("abc123"), "{}", out[0].message);
        assert_eq!(
            out[0].message,
            "Potential hardcoded secret detected (details redacted)."
        );
        for cwe in ["CWE-321", "CWE-312", "CWE-259"] {
            let out = normalise_opengrep(&[mk("generic.rule", json!([cwe]))]);
            assert_eq!(out[0].evidence, "", "evidence kept for {cwe}");
        }
        // Extra rule-id keywords.
        for rid in [
            "x.hardcoded-token",
            "x.JWT-none",
            "x.api-key",
            "x.apikey-leak",
            "x.private-key",
            "x.PrivateKey",
        ] {
            let out = normalise_opengrep(&[mk(rid, json!(["CWE-89"]))]);
            assert_eq!(out[0].evidence, "", "evidence kept for {rid}");
            assert!(!out[0].message.contains("abc123"), "message kept for {rid}");
        }
        // Non-secret rule keeps evidence and message.
        let out = normalise_opengrep(&[mk("rust.lang.security.sqli", json!(["CWE-89"]))]);
        assert_eq!(out[0].evidence, "k = 'abc123'");
        assert_eq!(out[0].message, "found key $SECRET=abc123");
    }

    #[test]
    fn ids_include_column_so_same_line_findings_do_not_collide() {
        let og = |col: i64| {
            json!({"results":[{"check_id":"r","path":"a.rs","start":{"line":1,"col":col},
                "extra":{"severity":"INFO","message":"m"}}]})
        };
        let a = normalise_opengrep(&[og(3)]);
        let b = normalise_opengrep(&[og(40)]);
        assert_ne!(a[0].id, b[0].id);
        // Missing column falls back to 0.
        let none = normalise_opengrep(&[json!({"results":[{"check_id":"r","path":"a.rs",
            "start":{"line":1},"extra":{}}]})]);
        assert!(none[0].id.ends_with(":1:0"), "{}", none[0].id);

        let gl = |col: i64| json!({"File":"c.py","StartLine":2,"StartColumn":col,"RuleID":"aws","Description":"k"});
        let a = normalise_gitleaks(&[gl(1)]);
        let b = normalise_gitleaks(&[gl(30)]);
        assert_ne!(a[0].id, b[0].id);
        let none = normalise_gitleaks(&[json!({"File":"c.py","StartLine":2,"RuleID":"aws"})]);
        assert!(none[0].id.ends_with(":2:0"), "{}", none[0].id);
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
