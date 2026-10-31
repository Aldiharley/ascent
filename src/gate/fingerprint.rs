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

/// CWEs whose evidence is itself a credential: fingerprint these like secrets
/// (rule + path + occurrence) so no derivative of the credential is stored.
const CREDENTIAL_CWES: [&str; 3] = ["CWE-798", "CWE-259", "CWE-321"];

/// `"secret" | "sca" | "dast" | "sast"`.
pub fn kind(f: &Value) -> &'static str {
    let cwe = s(f, "cwe")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    match s(f, "tool") {
        "gitleaks" => "secret",
        "trivy" => "sca",
        _ if !s(f, "url").is_empty() => "dast",
        _ if CREDENTIAL_CWES.contains(&cwe.as_str()) => "secret",
        _ => "sast",
    }
}

/// Package name for an SCA finding: the `pkg=` token Ascent's trivy normaliser
/// writes into the evidence, else the id with its `trivy:<rule>:<target>:`
/// prefix stripped, else the whole id. Never the raw target path.
fn sca_package(f: &Value) -> String {
    let ev = f["code"].as_str().or(f["evidence"].as_str()).unwrap_or("");
    if let Some(p) = ev.split_whitespace().find_map(|t| t.strip_prefix("pkg=")) {
        return p.to_string();
    }
    let id = s(f, "id");
    let prefix = format!("trivy:{}:{}:", s(f, "rule_id"), s(f, "file"));
    id.strip_prefix(&prefix).unwrap_or(id).to_string()
}

fn strip_dot(mut p: &str) -> &str {
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p
}

/// Forward slashes, no Windows verbatim `//?/` prefix (from `\\?\`), no leading `./`.
fn clean_path(p: &str) -> String {
    let p = p.replace('\\', "/");
    let p = p.strip_prefix("//?/").unwrap_or(&p);
    strip_dot(p).to_string()
}

/// `file` relative to `root`, forward slashes. The root prefix is compared
/// case-insensitively on Windows and case-sensitively elsewhere; a path not
/// under `root` is returned cleaned but otherwise unchanged.
pub fn relative_to(file: &str, root: &str) -> String {
    let p = clean_path(file);
    let r = clean_path(root);
    let r = r.trim_end_matches('/');
    if r.is_empty()
        || r == "."
        || p.len() <= r.len()
        || p.as_bytes()[r.len()] != b'/'
        || !p.is_char_boundary(r.len())
    {
        return p;
    }
    let (head, rest) = p.split_at(r.len());
    let same = if cfg!(windows) {
        head.eq_ignore_ascii_case(r)
    } else {
        head == r
    };
    if same {
        rest[1..].to_string()
    } else {
        p
    }
}

/// Forward slashes, no leading `./`, and the source root prefix removed.
pub fn normalise_path(p: &str, root: Option<&str>) -> String {
    match root {
        Some(r) => relative_to(p, r),
        None => clean_path(p),
    }
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
    let mut out = format!(
        "{}://{}",
        u.scheme(),
        u.host_str().unwrap_or("").to_ascii_lowercase()
    );
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    let path: Vec<&str> = u
        .path()
        .split('/')
        .map(|seg| if volatile(seg) { "{}" } else { seg })
        .collect();
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
        // Keyed on the package name, never the raw trivy id (it embeds the unnormalised target).
        "sca" => vec![rule, path, sca_package(f)],
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
    fn one(f: Value) -> String {
        fingerprints(&[f], None).remove(0)
    }

    #[test]
    fn has_version_prefix() {
        let fp = one(sast("r", "a.py", 1, "x()"));
        assert!(
            fp.starts_with("ascent/v1:") && fp.len() == "ascent/v1:".len() + 64,
            "{fp}"
        );
    }
    #[test]
    fn sast_survives_line_shift_and_whitespace() {
        assert_eq!(
            one(sast("r", "a.py", 10, "q( x )")),
            one(sast("r", "a.py", 42, "q(x)"))
        );
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
        let s = |line: i64, code: &str| {
            json!({"id":"g","tool":"gitleaks","rule_id":"aws",
            "file":"c.py","line":line,"url":"","code":code})
        };
        assert_eq!(one(s(2, "")), one(s(9, "AKIAEXAMPLE")));
    }
    #[test]
    fn sca_is_stable_across_separators_versions_and_roots() {
        let s = |file: &str, ver: &str| {
            json!({"id": format!("trivy:CVE-1:{file}:axios"),
            "tool":"trivy","rule_id":"CVE-1","file":file,"line":0,"url":"",
            "code": format!("pkg=axios installed={ver} fixed=0.21.2 purl=pkg:npm/axios@{ver}")})
        };
        assert_eq!(
            one(s("src\\package-lock.json", "0.21.1")),
            one(s("src/package-lock.json", "0.21.2"))
        );
        assert_eq!(
            fingerprints(&[s("./app/package-lock.json", "0.21.1")], Some("./app")),
            fingerprints(&[s("package-lock.json", "0.21.1")], None)
        );
        let other = json!({"id":"trivy:CVE-1:package-lock.json:lodash","tool":"trivy","rule_id":"CVE-1",
            "file":"package-lock.json","line":0,"url":"","code":"pkg=lodash installed=1 fixed=2 purl="});
        assert_ne!(one(s("package-lock.json", "0.21.1")), one(other));
    }
    #[test]
    fn sca_without_evidence_falls_back_to_the_id_package() {
        let s = |file: &str| {
            json!({"id": format!("trivy:CVE-1:{file}:axios"),"tool":"trivy",
            "rule_id":"CVE-1","file":file,"line":0,"url":""})
        };
        assert_eq!(
            one(s("a\\package-lock.json")),
            one(s("a/package-lock.json"))
        );
    }
    #[test]
    fn sast_credential_findings_are_keyed_like_secrets() {
        let f = |code: &str, line: i64| {
            json!({"id":"o","tool":"opengrep","rule_id":"generic.hardcoded.cred",
            "file":"d.py","line":line,"url":"","cwe":"CWE-798","code":code})
        };
        assert_eq!(kind(&f("k = 'aa11'", 1)), "secret");
        assert_eq!(one(f("k = 'aa11'", 1)), one(f("k = 'bb22'", 9)));
    }
    #[test]
    fn dast_ignores_query_values_ids_and_host_case() {
        let d =
            |u: &str| json!({"id":"n","tool":"nuclei","rule_id":"sqli","url":u,"file":"","line":0});
        assert_eq!(
            one(d("https://App.Example.com/users/42?b=2&a=1")),
            one(d("https://app.example.com/users/7?a=9&b=3"))
        );
        assert_ne!(
            one(d("https://app.example.com/users/42?a=1")),
            one(d("https://app.example.com/users/42?c=1"))
        );
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
        assert_eq!(
            one(sast("r", "src\\a.py", 1, "x")),
            one(sast("r", "src/a.py", 1, "x"))
        );
    }
    #[test]
    fn relative_to_strips_a_posix_root() {
        assert_eq!(relative_to("/home/x/src/a.py", "/home/x/src"), "a.py");
        assert_eq!(
            relative_to("/home/x/src/lib/b.rs", "/home/x/src/"),
            "lib/b.rs"
        );
    }
    #[test]
    fn relative_to_strips_a_windows_verbatim_root() {
        assert_eq!(
            relative_to("\\\\?\\M:\\proj\\src\\a.py", "M:/proj/src"),
            "a.py"
        );
        assert_eq!(
            relative_to("M:\\proj\\src\\a.py", "\\\\?\\M:\\proj\\src"),
            "a.py"
        );
    }
    #[test]
    fn relative_to_leaves_paths_outside_the_root_normalised_but_unchanged() {
        assert_eq!(
            relative_to("/elsewhere/a.py", "/home/x/src"),
            "/elsewhere/a.py"
        );
        assert_eq!(
            relative_to("/home/x/srcfoo/a.py", "/home/x/src"),
            "/home/x/srcfoo/a.py"
        );
        assert_eq!(relative_to(".\\lib\\b.rs", "/home/x/src"), "lib/b.rs");
    }
    #[test]
    fn relative_to_root_case_is_folded_only_on_windows() {
        let got = relative_to("M:/Proj/Src/a.py", "m:/proj/src");
        if cfg!(windows) {
            assert_eq!(got, "a.py");
        } else {
            assert_eq!(got, "M:/Proj/Src/a.py");
        }
    }
    #[test]
    fn normalise_path_uses_relative_to() {
        assert_eq!(
            normalise_path("\\\\?\\M:\\proj\\src\\a.py", Some("M:/proj/src")),
            "a.py"
        );
    }
    #[test]
    fn url_normalisation() {
        assert_eq!(
            normalise_url("HTTPS://Ex.com:443/a/123/b?z=1&y=2#f"),
            "https://ex.com/a/{}/b?y&z"
        );
        assert_eq!(
            normalise_url("http://ex.com:8080/u/550e8400-e29b-41d4-a716-446655440000"),
            "http://ex.com:8080/u/{}"
        );
        assert_eq!(normalise_url("not a url"), "not a url");
    }
    #[test]
    fn kinds() {
        assert_eq!(kind(&json!({"tool":"gitleaks"})), "secret");
        assert_eq!(kind(&json!({"tool":"trivy"})), "sca");
        assert_eq!(kind(&json!({"tool":"nuclei","url":"https://x/"})), "dast");
        assert_eq!(kind(&json!({"tool":"opengrep","url":""})), "sast");
        assert_eq!(
            kind(
                &json!({"tool":"opengrep","url":"","cwe":"CWE-798: Use of Hard-coded Credentials"})
            ),
            "secret"
        );
    }
}
