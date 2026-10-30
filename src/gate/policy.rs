//! Policy-as-code for the gate. Fail closed: any unknown key, wrong version or
//! unrecognised value is an error (the CLI maps it to exit 2).
use serde::{Deserialize, Serialize};

pub const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
pub const CATEGORIES: [&str; 4] = ["SAST", "SCA", "SECRETS", "DAST"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FpMode {
    #[default]
    DemoteToWarn,
    Enforce,
}

fn all_categories() -> Vec<String> {
    CATEGORIES.iter().map(|c| c.to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailRule {
    #[serde(default)]
    pub severity: Vec<String>,
    #[serde(default = "all_categories")]
    pub categories: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}
impl Default for FailRule {
    fn default() -> Self {
        FailRule { severity: vec![], categories: all_categories(), cwe: vec![] }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WarnRule {
    #[serde(default)]
    pub severity: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TriagePolicy {
    #[serde(default)]
    pub likely_false_positive: FpMode,
}

fn default_name() -> String {
    "default".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default)]
    pub fail_on: FailRule,
    #[serde(default)]
    pub warn_on: WarnRule,
    #[serde(default)]
    pub triage: TriagePolicy,
}

fn upper_all(v: &mut [String]) {
    for s in v.iter_mut() {
        *s = s.trim().to_ascii_uppercase();
    }
}

fn check_in(field: &str, vals: &[String], allowed: &[&str]) -> Result<(), String> {
    match vals.iter().find(|v| !allowed.contains(&v.as_str())) {
        Some(bad) => Err(format!("{field}: unknown value {bad:?} (allowed: {})", allowed.join(", "))),
        None => Ok(()),
    }
}

/// `CWE-<n>` with the number re-rendered (`CWE-089` → `CWE-89`); `None` unless
/// the input is `CWE-` followed by digits only (case-insensitive prefix).
pub fn canonical_cwe(v: &str) -> Option<String> {
    let v = v.trim().to_ascii_uppercase();
    let d = v.strip_prefix("CWE-")?;
    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    d.parse::<u64>().ok().map(|n| format!("CWE-{n}"))
}

fn canonicalise_cwes(field: &str, vals: &mut [String]) -> Result<(), String> {
    for v in vals.iter_mut() {
        *v = canonical_cwe(v).ok_or_else(|| format!("{field}: {v:?} is not a CWE id like CWE-89"))?;
    }
    Ok(())
}

fn sort_dedupe(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

pub fn parse_policy(text: &str) -> Result<Policy, String> {
    let mut p: Policy = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;
    if p.version != 1 {
        return Err(format!("unsupported policy version {} (expected 1)", p.version));
    }
    upper_all(&mut p.fail_on.severity);
    upper_all(&mut p.fail_on.categories);
    upper_all(&mut p.fail_on.cwe);
    upper_all(&mut p.warn_on.severity);
    upper_all(&mut p.warn_on.cwe);
    check_in("fail_on.severity", &p.fail_on.severity, &SEVERITIES)?;
    check_in("warn_on.severity", &p.warn_on.severity, &SEVERITIES)?;
    check_in("fail_on.categories", &p.fail_on.categories, &CATEGORIES)?;
    if p.fail_on.categories.is_empty() {
        return Err("fail_on.categories is empty: the gate would evaluate nothing".into());
    }
    canonicalise_cwes("fail_on.cwe", &mut p.fail_on.cwe)?;
    canonicalise_cwes("warn_on.cwe", &mut p.warn_on.cwe)?;
    // Order and duplicates carry no meaning: normalise them so policy_hash is semantic.
    for v in [&mut p.fail_on.severity, &mut p.fail_on.categories, &mut p.fail_on.cwe,
              &mut p.warn_on.severity, &mut p.warn_on.cwe] {
        sort_dedupe(v);
    }
    Ok(p)
}

pub fn load_policy(path: &str) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read policy {path}: {e}"))?;
    parse_policy(&text).map_err(|e| format!("invalid policy {path}: {e}"))
}

/// SHA-256 of the canonical JSON of the *parsed, normalised* policy, recorded
/// in gate.json and the audit log so the verdict proves which policy decided.
pub fn policy_hash(p: &Policy) -> String {
    crux::canon::hash_value(&serde_json::to_value(p).expect("policy serialises"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_policy_parses() {
        let p = load_policy(concat!(env!("CARGO_MANIFEST_DIR"), "/samples/ascent-policy.example.yaml")).unwrap();
        assert_eq!(p.name, "default");
        assert_eq!(p.fail_on.severity, vec!["CRITICAL", "HIGH"]);
        assert_eq!(p.fail_on.cwe, vec!["CWE-798"]);
        assert_eq!(p.triage.likely_false_positive, FpMode::DemoteToWarn);
    }
    #[test]
    fn minimal_policy_gets_safe_defaults() {
        let p = parse_policy("version: 1\n").unwrap();
        assert_eq!(p.name, "default");
        let mut all = CATEGORIES.to_vec();
        all.sort(); // lists are stored sorted so the policy hash is order-independent
        assert_eq!(p.fail_on.categories, all);
        assert!(p.fail_on.severity.is_empty() && p.warn_on.severity.is_empty());
        assert_eq!(p.triage.likely_false_positive, FpMode::DemoteToWarn);
    }
    #[test]
    fn values_are_case_normalised() {
        let p = parse_policy("version: 1\nfail_on:\n  severity: [high]\n  categories: [sast]\n  cwe: [cwe-89]\n").unwrap();
        assert_eq!(p.fail_on.severity, vec!["HIGH"]);
        assert_eq!(p.fail_on.categories, vec!["SAST"]);
        assert_eq!(p.fail_on.cwe, vec!["CWE-89"]);
    }
    #[test]
    fn cwe_ids_are_canonical() {
        let p = parse_policy("version: 1\nfail_on:\n  cwe: [CWE-089, cwe-0798]\nwarn_on:\n  cwe: [CWE-0022]\n").unwrap();
        assert_eq!(p.fail_on.cwe, vec!["CWE-798", "CWE-89"]);
        assert_eq!(p.warn_on.cwe, vec!["CWE-22"]);
        for bad in ["CWE-", "CWE-8a9", "CWE--89", "CWE-+89", "89"] {
            assert!(parse_policy(&format!("version: 1\nfail_on:\n  cwe: ['{bad}']\n")).is_err(), "{bad}");
        }
    }
    #[test]
    fn hash_is_semantic_over_order_and_duplicates() {
        let a = parse_policy("version: 1\nfail_on:\n  severity: [HIGH, CRITICAL]\n").unwrap();
        let b = parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL, HIGH, HIGH]\n").unwrap();
        assert_eq!(policy_hash(&a), policy_hash(&b));
        let c = parse_policy("version: 1\nfail_on:\n  categories: [SCA, SAST, SAST]\n  cwe: [CWE-89, CWE-089]\n").unwrap();
        let d = parse_policy("version: 1\nfail_on:\n  categories: [SAST, SCA]\n  cwe: [CWE-89]\n").unwrap();
        assert_eq!(policy_hash(&c), policy_hash(&d));
    }
    #[test]
    fn rejects_everything_suspicious() {
        for bad in [
            "version: 2\n",
            "name: x\n",                                           // version missing
            "version: 1\ngrace_days: {HIGH: 7}\n",                 // future key, top level
            "version: 1\nfail_on:\n  sevrity: [HIGH]\n",           // typo
            "version: 1\nfail_on:\n  severity: [SEVERE]\n",
            "version: 1\nfail_on:\n  categories: [LICENSE]\n",
            "version: 1\nfail_on:\n  cwe: ['89']\n",
            "version: 1\nwarn_on:\n  categories: [SAST]\n",        // warn_on has no categories
            "version: 1\ntriage:\n  likely_false_positive: ignore\n",
            "version: 1\nfail_on:\n  categories: []\n",            // would evaluate nothing
            ": : :",
        ] {
            assert!(parse_policy(bad).is_err(), "accepted bad policy: {bad:?}");
        }
    }
    #[test]
    fn load_reports_missing_file() {
        let e = load_policy("definitely/not/here.yaml").unwrap_err();
        assert!(e.contains("cannot read policy"), "{e}");
    }
    #[test]
    fn hash_is_stable_and_content_sensitive() {
        let a = parse_policy("version: 1\nfail_on:\n  severity: [HIGH]\n").unwrap();
        let b = parse_policy("version: 1\nfail_on:\n  severity: [high]\n").unwrap();
        let c = parse_policy("version: 1\nfail_on:\n  severity: [CRITICAL]\n").unwrap();
        assert_eq!(policy_hash(&a), policy_hash(&b));
        assert_ne!(policy_hash(&a), policy_hash(&c));
        assert_eq!(policy_hash(&a).len(), 64);
    }
}
