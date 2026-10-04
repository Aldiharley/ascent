use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

#[path = "../dashboard/mod.rs"]
mod dashboard;

use dashboard::gates::{decide_gate, read_pending_gates, DecideError};
use dashboard::read::{read_audit, read_engagement, read_findings, read_report};

/// Only these `Host` values are served; anything else is a DNS-rebinding attempt.
const ALLOWED_HOSTS: [&str; 2] = ["127.0.0.1:8787", "localhost:8787"];
/// State-changing requests must also come from one of these origins.
const ALLOWED_ORIGINS: [&str; 2] = ["http://127.0.0.1:8787", "http://localhost:8787"];

pub struct AppState {
    pub out_dir: String,
    pub engagement: String,
    /// Held across a whole gate decision (audit append + gates.json rewrite) so
    /// concurrent decisions cannot interleave. Never held across an `.await`.
    decision_lock: Mutex<()>,
}

impl AppState {
    pub fn new(out_dir: String, engagement: String) -> Self {
        AppState {
            out_dir,
            engagement,
            decision_lock: Mutex::new(()),
        }
    }
}

type Shared = Arc<AppState>;

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Request guard protecting this local server from DNS rebinding and CSRF.
async fn guard(req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();
    match header_str(headers, header::HOST) {
        Some(h) if ALLOWED_HOSTS.contains(&h) => {}
        _ => return Err(StatusCode::FORBIDDEN),
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let origin_ok =
            header_str(headers, header::ORIGIN).is_some_and(|o| ALLOWED_ORIGINS.contains(&o));
        let marker_ok = headers.get("x-ascent").is_some_and(|v| v == "1");
        if !(origin_ok && marker_ok) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(next.run(req).await)
}

async fn engagement(State(s): State<Shared>) -> Json<Value> {
    Json(read_engagement(&s.engagement))
}

async fn findings(State(s): State<Shared>) -> Json<Vec<Value>> {
    Json(read_findings(&s.out_dir))
}

async fn audit(State(s): State<Shared>) -> Json<Value> {
    let (entries, chain_ok) = read_audit(&s.out_dir);
    Json(json!({ "entries": entries, "chain_ok": chain_ok }))
}

async fn report(State(s): State<Shared>) -> Json<Value> {
    Json(json!({ "markdown": read_report(&s.out_dir) }))
}

async fn gates(State(s): State<Shared>) -> Json<Vec<Value>> {
    Json(read_pending_gates(&s.out_dir))
}

/// Record a human approve/deny decision. This ONLY records the decision (audit
/// entry + gate status); it never runs the gate's command.
async fn decide(
    State(s): State<Shared>,
    Path((id, decision)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let approve = match decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "decision must be approve or deny",
            ))
        }
    };
    let result = {
        let _guard = s.decision_lock.lock().unwrap_or_else(|e| e.into_inner());
        decide_gate(&s.out_dir, &id, approve)
    };
    match result {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(DecideError::NotFound) => Err(err(StatusCode::NOT_FOUND, "unknown gate")),
        Err(DecideError::Resolved) => Err(err(StatusCode::CONFLICT, "gate already resolved")),
        Err(DecideError::ChainBroken(m)) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("audit chain failed verification; decision not recorded: {m}"),
        )),
        Err(DecideError::Io(m)) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, &m)),
    }
}

fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "ok": false, "error": msg })))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(|| async { Json(json!({ "ok": true })) }))
        .route("/api/engagement", get(engagement))
        .route("/api/findings", get(findings))
        .route("/api/audit", get(audit))
        .route("/api/report", get(report))
        .route("/api/gates", get(gates))
        .route("/api/gates/:id/:decision", post(decide))
        .fallback_service(ServeDir::new("frontend/dist"))
        .with_state(Arc::new(state))
        // Must stay the LAST call so no route escapes the guard.
        .layer(middleware::from_fn(guard))
}

#[tokio::main]
async fn main() {
    let state = AppState::new(
        std::env::var("ASCENT_OUT").unwrap_or_else(|_| "out".into()),
        std::env::var("ASCENT_ENG").unwrap_or_else(|_| "samples/engagement.example.yaml".into()),
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787")
        .await
        .expect("bind 127.0.0.1:8787");
    println!("ascent dashboard on http://127.0.0.1:8787");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::util::ServiceExt;

    fn app() -> Router {
        router(AppState::new("out".into(), "e.yaml".into()))
    }

    async fn send(req: Request<Body>) -> axum::response::Response {
        app().oneshot(req).await.unwrap()
    }

    fn get(host: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().uri("/api/health");
        if let Some(h) = host {
            b = b.header("host", h);
        }
        b.body(Body::empty()).unwrap()
    }

    fn post(origin: Option<&str>, ascent: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/health")
            .header("host", "127.0.0.1:8787");
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        if let Some(a) = ascent {
            b = b.header("x-ascent", a);
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = send(get(Some("127.0.0.1:8787"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_ok_with_localhost_host() {
        let resp = send(get(Some("localhost:8787"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_foreign_host() {
        let resp = send(get(Some("evil.example:8787"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_missing_host() {
        let resp = send(get(None)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_without_csrf_header_rejected() {
        let resp = send(post(Some("http://127.0.0.1:8787"), None)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_foreign_origin_rejected() {
        let resp = send(post(Some("http://evil.example"), Some("1"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_valid_origin_and_header_passes_guard() {
        let resp = send(post(Some("http://127.0.0.1:8787"), Some("1"))).await;
        // Past the guard; /api/health is GET-only so the router answers 405.
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn no_cors_header() {
        let resp = send(get(Some("127.0.0.1:8787"))).await;
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    // ---- Task 3: API routes ----

    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ascent_dash_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app_for(dir: &Path) -> Router {
        router(AppState::new(
            dir.to_str().unwrap().into(),
            dir.join("eng.yaml").to_str().unwrap().into(),
        ))
    }

    fn api_get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap()
    }

    fn api_post(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", "127.0.0.1:8787")
            .header("origin", "http://127.0.0.1:8787")
            .header("x-ascent", "1")
            .body(Body::empty())
            .unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn write_gates(dir: &Path, gates: Value) {
        std::fs::write(dir.join("gates.json"), gates.to_string()).unwrap();
    }

    fn gate(id: &str) -> Value {
        json!({"id": id, "title": "Confirm SSRF", "why": "w", "command": "nuclei -u http://localhost:3000",
               "target": "http://localhost:3000", "in_scope": true})
    }

    fn crux_audit(dir: &Path) {
        crux::AuditLog::new(dir.join("audit.jsonl"))
            .append("f1", "h1", "mock", "TRUE_POSITIVE", 0.9, 0.1)
            .unwrap();
    }

    fn audit_lines(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn findings_route_returns_json() {
        let dir = tmp();
        std::fs::write(
            dir.join("queue.json"),
            r#"[{"verdict":"TRUE_POSITIVE","finding":{"title":"SQLi"}}]"#,
        )
        .unwrap();
        let resp = app_for(&dir)
            .oneshot(api_get("/api/findings"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["finding"]["title"], "SQLi");
    }

    #[tokio::test]
    async fn audit_route_reports_chain_ok() {
        let dir = tmp();
        crux_audit(&dir);
        let resp = app_for(&dir).oneshot(api_get("/api/audit")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["chain_ok"], true);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn report_route_returns_markdown() {
        let dir = tmp();
        std::fs::write(dir.join("report.md"), "# Report\n").unwrap();
        let resp = app_for(&dir).oneshot(api_get("/api/report")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["markdown"], "# Report\n");
    }

    #[tokio::test]
    async fn engagement_route_returns_json() {
        let dir = tmp();
        std::fs::write(dir.join("eng.yaml"), "name: Acme\n").unwrap();
        let resp = app_for(&dir)
            .oneshot(api_get("/api/engagement"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["name"], "Acme");
    }

    #[tokio::test]
    async fn gates_route_lists_only_pending() {
        let dir = tmp();
        let mut done = gate("g2");
        done["status"] = json!("approved");
        write_gates(&dir, json!([gate("g1"), done]));
        let resp = app_for(&dir).oneshot(api_get("/api/gates")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["id"], "g1");
    }

    #[tokio::test]
    async fn approve_appends_audit() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        crux_audit(&dir);
        let app = app_for(&dir);
        let resp = app
            .clone()
            .oneshot(api_post("/api/gates/g1/approve"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await, json!({"ok": true}));
        let lines = audit_lines(&dir);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["type"], "gate_decision");
        assert_eq!(lines[1]["gate_id"], "g1");
        assert_eq!(lines[1]["decision"], "approved");
        assert_eq!(lines[1]["prev_hash"], lines[0]["entry_hash"]);
        assert!(crux::AuditLog::new(dir.join("audit.jsonl")).verify().0);
        let resp = app.oneshot(api_get("/api/gates")).await.unwrap();
        assert_eq!(body_json(resp).await, json!([]));
        let stored: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        assert_eq!(stored[0]["status"], "approved");
        assert_eq!(stored[0]["decided_at"], lines[1]["ts"]);
        assert!(!dir.join("gates.json.tmp").exists());
    }

    #[tokio::test]
    async fn approve_creates_audit_when_missing() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/approve"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let lines = audit_lines(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["prev_hash"], crux::audit::GENESIS);
        assert!(crux::AuditLog::new(dir.join("audit.jsonl")).verify().0);
    }

    #[tokio::test]
    async fn deny_records_denied() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        crux_audit(&dir);
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/deny"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let lines = audit_lines(&dir);
        assert_eq!(lines[1]["decision"], "denied");
        assert!(crux::AuditLog::new(dir.join("audit.jsonl")).verify().0);
        let stored: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        assert_eq!(stored[0]["status"], "denied");
    }

    #[tokio::test]
    async fn bad_decision_is_400() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/execute"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!dir.join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn unknown_gate_is_404() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/nope/approve"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!dir.join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn resolved_gate_is_409() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        let app = app_for(&dir);
        let first = app
            .clone()
            .oneshot(api_post("/api/gates/g1/approve"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app.oneshot(api_post("/api/gates/g1/deny")).await.unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
        assert_eq!(audit_lines(&dir).len(), 1);
    }

    #[tokio::test]
    async fn broken_chain_refuses_decision() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        crux_audit(&dir);
        let path = dir.join("audit.jsonl");
        let tampered =
            std::fs::read_to_string(&path)
                .unwrap()
                .replacen("TRUE_POSITIVE", "FALSE_POSITIVE", 1);
        std::fs::write(&path, &tampered).unwrap();
        let gates_before = std::fs::read(dir.join("gates.json")).unwrap();
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/approve"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(std::fs::read(&path).unwrap(), tampered.as_bytes());
        assert_eq!(std::fs::read(dir.join("gates.json")).unwrap(), gates_before);
    }

    #[tokio::test]
    async fn post_decision_without_csrf_header_is_403() {
        let dir = tmp();
        write_gates(&dir, json!([gate("g1")]));
        let mut req = api_post("/api/gates/g1/approve");
        req.headers_mut().remove("x-ascent");
        let resp = app_for(&dir).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!dir.join("audit.jsonl").exists());
    }

    // ---- guard coverage carried over from Task 1 review ----

    #[tokio::test]
    async fn guard_covers_static_fallback() {
        let req = Request::builder()
            .uri("/")
            .header("host", "evil.example:8787")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn head_with_good_host_is_ok() {
        let req = Request::builder()
            .method(Method::HEAD)
            .uri("/api/health")
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn options_with_good_host_passes_guard() {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/health")
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        assert_ne!(send(req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_ascent_zero_rejected() {
        let resp = send(post(Some("http://127.0.0.1:8787"), Some("0"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_without_origin_rejected() {
        let resp = send(post(None, Some("1"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
