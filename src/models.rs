use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Default)]
pub struct Finding {
    pub id: String,
    pub tool: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub url: String,
    pub file: String,
    pub line: i64,
    pub category: String,
    pub cwe: String,
    pub evidence: String,
}
impl Finding {
    pub fn to_crux_json(&self) -> Value {
        json!({ "id": self.id, "tool": self.tool, "rule_id": self.rule_id,
            "severity": self.severity, "title": self.title, "message": self.message,
            "url": self.url, "file": self.file, "line": self.line,
            "category": self.category, "cwe": self.cwe, "code": self.evidence })
    }
}
