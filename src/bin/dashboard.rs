use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

#[path = "../dashboard/mod.rs"]
mod dashboard;
#[path = "../gatesio.rs"]
mod gatesio;

use dashboard::gates::{decide_gate, DecideError};
use dashboard::read::{read_audit, read_engagement, read_findings, read_report};
use gatesio::read_pending_gates;

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
        Err(DecideError::OutOfScope) => Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "gate is not in scope; only deny is allowed",
        )),
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

/// Where the built UI lives: `ASCENT_DIST` if set (and non-empty), else the
/// crate's own `frontend/dist`, so the static files do not depend on the CWD.
fn dist_dir_from(env: Option<String>) -> PathBuf {
    match env {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/frontend/dist")),
    }
}

/// Sent on EVERY response (API, static files, 403s, 404s). Forbids framing so
/// Approve cannot be clickjacked, and pins scripts/connections to this origin.
/// `'unsafe-inline'` in style-src only covers React `style={{...}}` attributes;
/// the only third-party loads are the Google Fonts stylesheet and font files.
const CSP: &str = "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

const SECURITY_HEADERS: [(&str, &str); 4] = [
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("content-security-policy", CSP),
];

pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .route("/api/health", get(|| async { Json(json!({ "ok": true })) }))
        .route("/api/engagement", get(engagement))
        .route("/api/findings", get(findings))
        .route("/api/audit", get(audit))
        .route("/api/report", get(report))
        .route("/api/gates", get(gates))
        .route("/api/gates/:id/:decision", post(decide))
        .fallback_service(ServeDir::new(dist_dir_from(
            std::env::var("ASCENT_DIST").ok(),
        )))
        .with_state(Arc::new(state))
        // The guard wraps every route and the static fallback, so no route
        // escapes it.
        .layer(middleware::from_fn(guard));
    // Outermost: the security headers also land on the guard's own 403s.
    SECURITY_HEADERS.iter().fold(app, |app, (name, value)| {
        app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ))
    })
}

/// Loopback only: the dashboard is never exposed beyond this machine.
const ADDR: &str = "127.0.0.1:8787";

/// A human-readable reason the dashboard could not start listening.
fn bind_error_message(addr: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "{addr} is already in use: another Ascent dashboard (or another program) is \
             already running on this port.\n\
             Open http://{addr} to use the running one, or stop it first (Ctrl+C in its \
             window, or on Windows: Get-NetTCPConnection -LocalPort 8787 -State Listen | \
             ForEach-Object {{ Stop-Process -Id $_.OwningProcess }})."
        )
    } else {
        format!("could not listen on {addr}: {e}")
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let out_dir = std::env::var("ASCENT_OUT").unwrap_or_else(|_| "out".into());
    let engagement =
        std::env::var("ASCENT_ENG").unwrap_or_else(|_| "samples/engagement.example.yaml".into());
    let app = router(AppState::new(out_dir.clone(), engagement.clone()));
    let listener = match tokio::net::TcpListener::bind(ADDR).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {}", bind_error_message(ADDR, &e));
            return std::process::ExitCode::FAILURE;
        }
    };
    println!("ascent dashboard on http://{ADDR}");
    println!("  results:    {out_dir}  (set ASCENT_OUT to change)");
    println!("  engagement: {engagement}  (set ASCENT_ENG to change)");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("error: dashboard server stopped: {e}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
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

    #[test]
    fn bind_error_explains_port_in_use() {
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let msg = bind_error_message(ADDR, &e);
        assert!(msg.contains("127.0.0.1:8787 is already in use"), "{msg}");
        assert!(msg.contains("another Ascent dashboard"), "{msg}");
        assert!(msg.contains("Stop-Process"), "{msg}");
    }

    #[test]
    fn bind_error_other_kinds_are_reported_plainly() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = bind_error_message(ADDR, &e);
        assert!(
            msg.starts_with("could not listen on 127.0.0.1:8787"),
            "{msg}"
        );
        assert!(!msg.contains("already in use"), "{msg}");
    }

    #[tokio::test]
    async fn second_bind_on_same_port_is_addr_in_use() {
        // Guards the assumption bind_error_message relies on: a second listener on
        // a taken loopback port fails with AddrInUse (on Windows and Unix alike).
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = first.local_addr().unwrap();
        let err = tokio::net::TcpListener::bind(addr).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
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
        assert_eq!(lines[1]["gate_hash"], crux::canon::hash_value(&gate("g1")));
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

    /// Failure mode: the audit append succeeded but gates.json was never
    /// updated (e.g. rename failed), so the gate still looks pending.
    fn crash_after_audit(dir: &Path, id: &str, decision: &str) {
        crux_audit(dir);
        dashboard::gates::append_decision(
            &dir.join("audit.jsonl"),
            id,
            decision,
            &gatesio::gate_hash(&gate(id)),
            "2026-10-04T00:00:00.000000+00:00",
        )
        .unwrap();
        write_gates(dir, json!([gate(id)]));
    }

    #[tokio::test]
    async fn already_audited_gate_is_409_and_self_heals() {
        let dir = tmp();
        crash_after_audit(&dir, "g1", "approved");
        let before = std::fs::read(dir.join("audit.jsonl")).unwrap();
        // retry with the OPPOSITE decision must not be recorded
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/deny"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(std::fs::read(dir.join("audit.jsonl")).unwrap(), before);
        assert_eq!(audit_lines(&dir).len(), 2);
        assert!(crux::AuditLog::new(dir.join("audit.jsonl")).verify().0);
        let stored: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        assert_eq!(stored[0]["status"], "approved");
        assert_eq!(stored[0]["decided_at"], "2026-10-04T00:00:00.000000+00:00");
    }

    #[tokio::test]
    async fn gates_route_omits_already_audited_gate() {
        let dir = tmp();
        crash_after_audit(&dir, "g1", "denied");
        let resp = app_for(&dir).oneshot(api_get("/api/gates")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await, json!([]));
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

    // ---- F1: anti-framing / security headers on every response ----

    fn assert_security_headers(resp: &axum::response::Response) {
        let h = resp.headers();
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "csp: {csp}");
        assert!(csp.contains("script-src 'self'"), "csp: {csp}");
        assert!(csp.contains("default-src 'self'"), "csp: {csp}");
    }

    #[tokio::test]
    async fn security_headers_on_api() {
        let resp = send(get(Some("127.0.0.1:8787"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_security_headers(&resp);
    }

    #[tokio::test]
    async fn security_headers_on_static_fallback() {
        let req = Request::builder()
            .uri("/")
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        let resp = send(req).await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        assert_security_headers(&resp);
    }

    #[tokio::test]
    async fn security_headers_on_static_404() {
        let req = Request::builder()
            .uri("/no-such-file.js")
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        let resp = send(req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_security_headers(&resp);
    }

    #[tokio::test]
    async fn security_headers_on_guard_403() {
        let resp = send(get(Some("evil.example:8787"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_security_headers(&resp);
    }

    #[tokio::test]
    async fn security_headers_on_post_403() {
        let resp = send(post(Some("http://evil.example"), Some("1"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_security_headers(&resp);
    }

    // ---- F9: dist dir does not depend on the CWD ----

    #[test]
    fn dist_dir_defaults_to_manifest_dir() {
        let d = dist_dir_from(None);
        assert!(d.is_absolute(), "{d:?}");
        assert!(d.ends_with("frontend/dist"), "{d:?}");
        assert!(d.starts_with(env!("CARGO_MANIFEST_DIR")), "{d:?}");
    }

    #[test]
    fn dist_dir_honours_ascent_dist() {
        let d = dist_dir_from(Some("C:/somewhere/dist".into()));
        assert_eq!(d, std::path::PathBuf::from("C:/somewhere/dist"));
        // an empty value is treated as unset
        assert!(dist_dir_from(Some(String::new())).ends_with("frontend/dist"));
    }

    // ---- F8: server-side approve requires in_scope == true ----

    #[tokio::test]
    async fn approve_out_of_scope_gate_is_422_and_writes_nothing() {
        // false, null, a truthy-looking string, and a missing field are all refused.
        for in_scope in [
            Some(json!(false)),
            Some(json!(null)),
            Some(json!("true")),
            None,
        ] {
            let dir = tmp();
            let mut g = gate("g1");
            match &in_scope {
                Some(v) => g["in_scope"] = v.clone(),
                None => {
                    g.as_object_mut().unwrap().remove("in_scope");
                }
            }
            write_gates(&dir, json!([g]));
            crux_audit(&dir);
            let audit_before = std::fs::read(dir.join("audit.jsonl")).unwrap();
            let gates_before = std::fs::read(dir.join("gates.json")).unwrap();
            let resp = app_for(&dir)
                .oneshot(api_post("/api/gates/g1/approve"))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "in_scope={in_scope:?}"
            );
            assert_eq!(body_json(resp).await["ok"], false);
            assert_eq!(
                std::fs::read(dir.join("audit.jsonl")).unwrap(),
                audit_before
            );
            assert_eq!(std::fs::read(dir.join("gates.json")).unwrap(), gates_before);
        }
    }

    #[tokio::test]
    async fn deny_out_of_scope_gate_is_allowed() {
        let dir = tmp();
        let mut g = gate("g1");
        g["in_scope"] = json!(false);
        write_gates(&dir, json!([g]));
        let resp = app_for(&dir)
            .oneshot(api_post("/api/gates/g1/deny"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(audit_lines(&dir)[0]["decision"], "denied");
    }
}
