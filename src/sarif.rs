//! Native SARIF 2.1.0: `ascent.sarif` (one run per code category, for GitHub
//! code scanning / IDE SARIF viewers) and `ascent-dast.sarif` (URL findings,
//! which GitHub cannot fingerprint). Never exports code snippets or secret
//! material; LIKELY_FALSE_POSITIVE results are suppressed `underReview`.
use crate::gate::fingerprint::{fingerprints, kind, normalise_path};
use serde_json::{json, Map, Value};
use std::path::Path;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const CODE_RUNS: [(&str, &str); 3] = [
    ("sast", "ascent/sast/"),
    ("secret", "ascent/secrets/"),
    ("sca", "ascent/sca/"),
];

fn s(f: &Value, k: &str) -> String {
    f[k].as_str().unwrap_or("").to_string()
}

pub fn level_of(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// GitHub `security-severity` (string). Midpoints avoid the 9.0 band edge.
pub fn security_severity(sev: &str) -> Option<&'static str> {
    match sev {
        "CRITICAL" => Some("9.5"),
        "HIGH" => Some("8.0"),
        "MEDIUM" => Some("5.5"),
        "LOW" => Some("2.0"),
        _ => None,
    }
}

fn rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn result(item: &Value, fp: &str, root: Option<&str>) -> Value {
    let f = &item["finding"];
    let sev = s(f, "severity").to_ascii_uppercase();
    let text = if s(f, "message").is_empty() {
        s(f, "title")
    } else {
        s(f, "message")
    };
    let location = if kind(f) == "dast" {
        json!({"physicalLocation": {"artifactLocation": {"uri": s(f, "url")}}})
    } else {
        json!({"physicalLocation": {
            "artifactLocation": {"uri": normalise_path(&s(f, "file"), root)},
            "region": {"startLine": f["line"].as_i64().unwrap_or(0).max(1)}}})
    };
    let mut props = Map::new();
    props.insert("ascent.tool".into(), Value::from(s(f, "tool")));
    props.insert("ascent.verdict".into(), item["verdict"].clone());
    props.insert("ascent.confidence".into(), item["confidence"].clone());
    props.insert("ascent.remediation".into(), item["remediation"].clone());
    if kind(f) == "sca" {
        // The trivy version string is the only evidence ever exported.
        props.insert(
            "ascent.sca".into(),
            Value::from(f["code"].as_str().or(f["evidence"].as_str()).unwrap_or("")),
        );
    }
    let mut r = json!({
        "ruleId": s(f, "rule_id"),
        "level": level_of(&sev),
        "message": {"text": text},
        "locations": [location],
        "partialFingerprints": {"ascentFindingHash/v1": fp},
        "properties": props,
    });
    if item["verdict"].as_str() == Some("LIKELY_FALSE_POSITIVE") {
        r["suppressions"] = json!([{"kind": "external", "status": "underReview",
                                    "justification": item["rationale"].as_str().unwrap_or("")}]);
    }
    r
}

fn run(items: &[(&Value, &String)], automation_id: &str, root: Option<&str>) -> Value {
    // rules: one per rule_id, highest severity of its results
    let mut rules: Vec<(String, Value, String)> = Vec::new(); // (id, finding, max sev)
    for (item, _) in items {
        let f = &item["finding"];
        let id = s(f, "rule_id");
        let sev = s(f, "severity").to_ascii_uppercase();
        match rules.iter_mut().find(|(rid, _, _)| *rid == id) {
            Some(entry) if rank(&sev) > rank(&entry.2) => entry.2 = sev,
            Some(_) => {}
            None => rules.push((id, f.clone(), sev)),
        }
    }
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, f, sev)| {
            let mut tags = vec![Value::from("security")];
            let cwe = s(&f, "cwe");
            if !cwe.is_empty() {
                tags.push(Value::from(cwe));
            }
            let mut props = json!({"tags": tags});
            if let Some(score) = security_severity(&sev) {
                props["security-severity"] = Value::from(score);
            }
            let title: String = s(&f, "title").chars().take(1024).collect();
            json!({"id": id.clone(), "name": id, "shortDescription": {"text": title}, "properties": props})
        })
        .collect();
    json!({
        "tool": {"driver": {"name": "Ascent", "informationUri": "https://github.com/Aldiharley/ascent",
                            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": rules}},
        "automationDetails": {"id": automation_id},
        "results": items.iter().map(|(item, fp)| result(item, fp, root)).collect::<Vec<_>>(),
    })
}

fn doc(runs: Vec<Value>) -> Value {
    json!({"$schema": SCHEMA, "version": "2.1.0", "runs": runs})
}

pub fn to_sarif(items: &[Value], source_root: Option<&str>) -> (Value, Value) {
    let findings: Vec<Value> = items.iter().map(|it| it["finding"].clone()).collect();
    let fps = fingerprints(&findings, source_root);
    let pairs: Vec<(&Value, &String)> = items.iter().zip(fps.iter()).collect();
    let of_kind = |k: &str| -> Vec<(&Value, &String)> {
        pairs
            .iter()
            .filter(|(it, _)| kind(&it["finding"]) == k)
            .cloned()
            .collect()
    };
    let code = doc(CODE_RUNS
        .iter()
        .map(|(k, id)| run(&of_kind(k), id, source_root))
        .collect());
    let dast = doc(vec![run(&of_kind("dast"), "ascent/dast/", source_root)]);
    (code, dast)
}

pub fn write_sarif(
    out_dir: &str,
    items: &[Value],
    source_root: Option<&str>,
) -> std::io::Result<()> {
    let (code, dast) = to_sarif(items, source_root);
    for (name, d) in [("ascent.sarif", code), ("ascent-dast.sarif", dast)] {
        let text = serde_json::to_string_pretty(&d).map_err(std::io::Error::other)? + "\n";
        crate::triage::write_atomic(&Path::new(out_dir).join(name), text.as_bytes())?;
    }
    Ok(())
}

/// Triage items in the queue.json entry shape that `to_sarif`/`evaluate` read.
pub fn item_values(items: &[crate::triage::TriageItem]) -> Vec<Value> {
    items
        .iter()
        .map(|it| {
            json!({"finding": it.finding, "verdict": it.verdict, "confidence": it.confidence,
                         "fp_likelihood": it.fp_likelihood, "rationale": it.rationale,
                         "remediation": it.remediation})
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn it(
        tool: &str,
        sev: &str,
        file: &str,
        line: i64,
        url: &str,
        verdict: &str,
        code: &str,
    ) -> Value {
        json!({"finding": {"id": format!("{tool}:{file}{url}"), "tool": tool,
            "rule_id": format!("{tool}.rule"), "severity": sev, "title": "Title",
            "message": "Message", "url": url, "file": file, "line": line,
            "category": "SAST", "cwe": "CWE-89", "code": code},
            "verdict": verdict, "confidence": 0.8, "fp_likelihood": 0.2,
            "rationale": "why", "remediation": "fix it"})
    }

    #[test]
    fn documents_are_valid_sarif_skeletons() {
        let (code, dast) = to_sarif(&[], None);
        for d in [&code, &dast] {
            assert_eq!(d["version"], "2.1.0");
            assert!(d["$schema"].as_str().unwrap().contains("sarif"));
        }
        let ids: Vec<&str> = code["runs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["automationDetails"]["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["ascent/sast/", "ascent/secrets/", "ascent/sca/"]);
        assert_eq!(dast["runs"][0]["automationDetails"]["id"], "ascent/dast/");
        assert_eq!(code["runs"][0]["tool"]["driver"]["name"], "Ascent");
    }
    #[test]
    fn maps_levels_locations_and_fingerprints() {
        let (code, _) = to_sarif(
            &[it(
                "opengrep",
                "HIGH",
                "./src/db.rs",
                0,
                "",
                "TRUE_POSITIVE",
                "q()",
            )],
            Some("./src"),
        );
        let run = &code["runs"][0];
        let r = &run["results"][0];
        assert_eq!(r["ruleId"], "opengrep.rule");
        assert_eq!(r["level"], "error");
        assert_eq!(r["message"]["text"], "Message");
        let loc = &r["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "db.rs");
        assert_eq!(loc["region"]["startLine"], 1); // line 0 clamps to 1
        assert!(r["partialFingerprints"]["ascentFindingHash/v1"]
            .as_str()
            .unwrap()
            .starts_with("ascent/v1:"));
        let rule = &run["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "opengrep.rule");
        assert_eq!(rule["properties"]["security-severity"], "8.0");
        assert_eq!(rule["properties"]["tags"], json!(["security", "CWE-89"]));
        assert_eq!(r["properties"]["ascent.verdict"], "TRUE_POSITIVE");
    }
    #[test]
    fn severity_table() {
        for (sev, level, score) in [
            ("CRITICAL", "error", Some("9.5")),
            ("HIGH", "error", Some("8.0")),
            ("MEDIUM", "warning", Some("5.5")),
            ("LOW", "note", Some("2.0")),
            ("INFO", "note", None),
        ] {
            assert_eq!(level_of(sev), level);
            assert_eq!(security_severity(sev), score);
        }
    }
    #[test]
    fn likely_false_positive_is_suppressed_under_review() {
        let (code, _) = to_sarif(
            &[it(
                "opengrep",
                "HIGH",
                "a.py",
                3,
                "",
                "LIKELY_FALSE_POSITIVE",
                "",
            )],
            None,
        );
        let sup = &code["runs"][0]["results"][0]["suppressions"][0];
        assert_eq!(sup["kind"], "external");
        assert_eq!(sup["status"], "underReview");
        assert_eq!(sup["justification"], "why");
    }
    #[test]
    fn dast_goes_only_to_the_dast_document() {
        let (code, dast) = to_sarif(
            &[it(
                "nuclei",
                "HIGH",
                "",
                0,
                "https://app.example.com/login",
                "TRUE_POSITIVE",
                "",
            )],
            None,
        );
        assert!(code["runs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["results"].as_array().unwrap().is_empty()));
        let r = &dast["runs"][0]["results"][0];
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://app.example.com/login"
        );
    }
    #[test]
    fn categories_split_and_rules_dedupe() {
        let items = [
            it("opengrep", "HIGH", "a.py", 1, "", "TRUE_POSITIVE", "x"),
            it("opengrep", "LOW", "b.py", 2, "", "TRUE_POSITIVE", "y"),
            it("gitleaks", "HIGH", "c.py", 3, "", "TRUE_POSITIVE", ""),
            it(
                "trivy",
                "MEDIUM",
                "package-lock.json",
                0,
                "",
                "TRUE_POSITIVE",
                "pkg=axios installed=0.21.1 fixed=0.21.2 purl=",
            ),
        ];
        let (code, _) = to_sarif(&items, None);
        let runs = code["runs"].as_array().unwrap();
        assert_eq!(runs[0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(
            runs[0]["tool"]["driver"]["rules"].as_array().unwrap().len(),
            1
        );
        // the rule takes the highest severity of its results
        assert_eq!(
            runs[0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
            "8.0"
        );
        assert_eq!(runs[1]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            runs[2]["results"][0]["properties"]["ascent.sca"],
            "pkg=axios installed=0.21.1 fixed=0.21.2 purl="
        );
    }
    #[test]
    fn never_exports_code_or_secret_material() {
        let items = [
            it(
                "gitleaks",
                "HIGH",
                "c.py",
                3,
                "",
                "TRUE_POSITIVE",
                "AKIASECRETVALUE",
            ),
            it(
                "opengrep",
                "HIGH",
                "d.py",
                1,
                "",
                "TRUE_POSITIVE",
                "password = 'hunter2'",
            ),
        ];
        let (code, dast) = to_sarif(&items, None);
        let all = format!("{code}{dast}");
        assert!(!all.contains("AKIASECRETVALUE") && !all.contains("hunter2"));
    }
    #[test]
    fn write_sarif_writes_both_files() {
        let dir = std::env::temp_dir().join(format!("ascent_sarif_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_sarif(
            dir.to_str().unwrap(),
            &[it("opengrep", "HIGH", "a.py", 1, "", "TRUE_POSITIVE", "")],
            None,
        )
        .unwrap();
        for f in ["ascent.sarif", "ascent-dast.sarif"] {
            let v: Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap();
            assert_eq!(v["version"], "2.1.0");
        }
    }
}
