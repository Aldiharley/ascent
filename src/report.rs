use crate::triage::TriageItem;

fn rank(v: &str) -> u8 {
    match v {
        "TRUE_POSITIVE" => 0,
        "ABSTAIN" => 1,
        _ => 2,
    }
}
fn badge(v: &str) -> &str {
    match v {
        "TRUE_POSITIVE" => "TRUE POSITIVE",
        "ABSTAIN" => "NEEDS HUMAN",
        _ => "LIKELY NOISE",
    }
}
fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

pub fn to_markdown(items: &[TriageItem], name: &str) -> String {
    let mut v: Vec<&TriageItem> = items.iter().collect();
    v.sort_by(|a, b| {
        rank(&a.verdict)
            .cmp(&rank(&b.verdict))
            .then(b.confidence.partial_cmp(&a.confidence).unwrap())
    });
    let mut out = format!("# Ascent report: {name}\n\nFindings: {}. Nothing has been auto-closed; this is a ranked queue for review.\n\n", items.len());
    for it in v {
        let f = &it.finding;
        let locus = if !s(f, "url").is_empty() {
            s(f, "url")
        } else {
            format!("{}:{}", s(f, "file"), f["line"].as_i64().unwrap_or(0))
        };
        out += &format!("## [{}] {}\n\n- Where: `{}`\n- Rule / severity: `{}` ({})\n- Confidence: {:.2}  FP-likelihood: {:.2}\n- Why: {}\n- Fix: {}\n\n",
            badge(&it.verdict), s(f,"title"), locus, s(f,"rule_id"), s(f,"severity"),
            it.confidence, it.fp_likelihood, it.rationale, it.remediation);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::TriageItem;
    use serde_json::json;
    #[test]
    fn renders() {
        let it = TriageItem {
            finding: json!({"title":"SQLi","url":"https://a/x","rule_id":"sqli","severity":"HIGH"}),
            verdict: "TRUE_POSITIVE".into(),
            confidence: 0.9,
            fp_likelihood: 0.1,
            rationale: "r".into(),
            remediation: "fix".into(),
        };
        let md = to_markdown(&[it], "lab");
        assert!(
            md.contains("# Ascent report") && md.contains("SQLi") && md.contains("https://a/x")
        );
    }
}
