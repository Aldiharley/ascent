//! `ascent/v1` finding fingerprints: stable across line shifts, whitespace,
//! query values and dependency upgrades, so the gate, SARIF and (later)
//! baselines recognise the same finding run after run. Secrets are keyed on
//! rule + path + occurrence only: no secret value or hash of one, ever.
use serde_json::{json, Value};
use std::collections::HashMap;

pub const VERSION: &str = "ascent/v1";

fn s<'a>(f: &'a Value, k: &str) -> &'a str {
    f[k].as_str().unwrap_or("")
}

/// `"secret" | "sca" | "dast" | "sast"`.
pub fn kind(f: &Value) -> &'static str {
    match s(f, "tool") {
        "gitleaks" => "secret",
        "trivy" => "sca",
        _ if !s(f, "url").is_empty() => "dast",
        _ => "sast",
    }
}

fn strip_dot(mut p: &str) -> &str {
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p
}

/// Forward slashes, no leading `./`, and the source root prefix removed.
pub fn normalise_path(p: &str, root: Option<&str>) -> String {
    let p = p.replace('\\', "/");
    let p = strip_dot(&p);
    if let Some(r) = root {
        let r = r.replace('\\', "/");
        let r = strip_dot(r.trim_end_matches('/'));
        if !r.is_empty() && r != "." {
            if let Some(rest) = p.strip_prefix(&format!("{r}/")) {
                return rest.to_string();
            }
        }
    }
    p.to_string()
}

fn is_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn volatile(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.bytes().all(|b| b.is_ascii_digit())
            || is_uuid(seg)
            || (seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Scheme + lowercase host + non-default port + path with ids replaced by `{}`
/// + sorted query *names*. No values, no fragment. Unparseable → trimmed input.
pub fn normalise_url(raw: &str) -> String {
    let Ok(u) = url::Url::parse(raw.trim()) else {
        return raw.trim().to_string();
    };
    let mut out = format!("{}://{}", u.scheme(), u.host_str().unwrap_or("").to_ascii_lowercase());
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    let path: Vec<&str> = u.path().split('/').map(|seg| if volatile(seg) { "{}" } else { seg }).collect();
    out.push_str(&path.join("/"));
    let mut names: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    names.dedup();
    if !names.is_empty() {
        out.push('?');
        out.push_str(&names.join("&"));
    }
    out
}

fn inputs(f: &Value, root: Option<&str>) -> Vec<String> {
    let rule = s(f, "rule_id").to_string();
    let path = normalise_path(s(f, "file"), root);
    match kind(f) {
        "secret" => vec![rule, path],
        // The trivy id is `trivy:<vuln>:<target>:<pkg>`: version-free by construction.
        "sca" => vec![rule, path, s(f, "id").to_string()],
        "dast" => vec![rule, normalise_url(s(f, "url"))],
        _ => {
            let code = f["code"].as_str().or(f["evidence"].as_str()).unwrap_or("");
            let squashed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            let ctx = if squashed.is_empty() {
                format!("line:{}", f["line"].as_i64().unwrap_or(0))
            } else {
                crux::canon::hash_value(&json!(squashed))
            };
            vec![rule, path, ctx]
        }
    }
}

/// One fingerprint per finding, in input order. Identical findings in one run
/// are told apart by their occurrence index.
pub fn fingerprints(findings: &[Value], root: Option<&str>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    findings
        .iter()
        .map(|f| {
            let base = crux::canon::hash_value(&json!([VERSION, kind(f), inputs(f, root)]));
            let n = seen.entry(base.clone()).or_insert(0);
            let idx = *n;
            *n += 1;
            format!("{VERSION}:{}", crux::canon::hash_value(&json!([base, idx])))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sast(rule: &str, file: &str, line: i64, code: &str) -> Value {
        json!({"id":"x","tool":"opengrep","rule_id":rule,"severity":"HIGH","file":file,
               "line":line,"url":"","category":"SAST","code":code})
    }
    fn one(f: Value) -> String { fingerprints(&[f], None).remove(0) }

    #[test]
    fn has_version_prefix() {
        let fp = one(sast("r", "a.py", 1, "x()"));
        assert!(fp.starts_with("ascent/v1:") && fp.len() == "ascent/v1:".len() + 64, "{fp}");
    }
    #[test]
    fn sast_survives_line_shift_and_whitespace() {
        assert_eq!(one(sast("r", "a.py", 10, "q( x )")), one(sast("r", "a.py", 42, "q(x)")));
    }
    #[test]
    fn sast_changes_with_rule_path_or_code() {
        let base = one(sast("r", "a.py", 1, "q(x)"));
        assert_ne!(base, one(sast("r2", "a.py", 1, "q(x)")));
        assert_ne!(base, one(sast("r", "b.py", 1, "q(x)")));
        assert_ne!(base, one(sast("r", "a.py", 1, "q(y)")));
    }
    #[test]
    fn sast_without_code_falls_back_to_line() {
        assert_ne!(one(sast("r", "a.py", 1, "")), one(sast("r", "a.py", 2, "")));
    }
    #[test]
    fn secret_ignores_line_and_code() {
        let s = |line: i64, code: &str| json!({"id":"g","tool":"gitleaks","rule_id":"aws",
            "file":"c.py","line":line,"url":"","code":code});
        assert_eq!(one(s(2, "")), one(s(9, "AKIAEXAMPLE")));
    }
    #[test]
    fn sca_ignores_installed_version() {
        let s = |ev: &str| json!({"id":"trivy:CVE-1:package-lock.json:axios","tool":"trivy",
            "rule_id":"CVE-1","file":"package-lock.json","line":0,"url":"","code":ev});
        assert_eq!(one(s("pkg=axios installed=0.21.1")), one(s("pkg=axios installed=0.21.2")));
    }
    #[test]
    fn dast_ignores_query_values_ids_and_host_case() {
        let d = |u: &str| json!({"id":"n","tool":"nuclei","rule_id":"sqli","url":u,"file":"","line":0});
        assert_eq!(
            one(d("https://App.Example.com/users/42?b=2&a=1")),
            one(d("https://app.example.com/users/7?a=9&b=3"))
        );
        assert_ne!(one(d("https://app.example.com/users/42?a=1")),
                   one(d("https://app.example.com/users/42?c=1")));
    }
    #[test]
    fn identical_findings_get_distinct_stable_fingerprints() {
        let f = sast("r", "a.py", 1, "q(x)");
        let fps = fingerprints(&[f.clone(), f.clone()], None);
        assert_ne!(fps[0], fps[1]);
        assert_eq!(fps, fingerprints(&[f.clone(), f], None));
    }
    #[test]
    fn root_and_separators_are_normalised() {
        assert_eq!(normalise_path(".\\src\\a.py", Some("./src")), "a.py");
        assert_eq!(normalise_path("src/a.py", Some("src/")), "a.py");
        assert_eq!(normalise_path("./lib/b.rs", None), "lib/b.rs");
        assert_eq!(one(sast("r", "src\\a.py", 1, "x")), one(sast("r", "src/a.py", 1, "x")));
    }
    #[test]
    fn url_normalisation() {
        assert_eq!(normalise_url("HTTPS://Ex.com:443/a/123/b?z=1&y=2#f"), "https://ex.com/a/{}/b?y&z");
        assert_eq!(normalise_url("http://ex.com:8080/u/550e8400-e29b-41d4-a716-446655440000"),
                   "http://ex.com:8080/u/{}");
        assert_eq!(normalise_url("not a url"), "not a url");
    }
    #[test]
    fn kinds() {
        assert_eq!(kind(&json!({"tool":"gitleaks"})), "secret");
        assert_eq!(kind(&json!({"tool":"trivy"})), "sca");
        assert_eq!(kind(&json!({"tool":"nuclei","url":"https://x/"})), "dast");
        assert_eq!(kind(&json!({"tool":"opengrep","url":""})), "sast");
    }
}
