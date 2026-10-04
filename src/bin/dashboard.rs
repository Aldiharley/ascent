use axum::{
    extract::Request,
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use tower_http::services::ServeDir;

// wired into routes in Task 3
#[allow(dead_code)]
#[path = "../dashboard/mod.rs"]
mod dashboard;

/// Only these `Host` values are served; anything else is a DNS-rebinding attempt.
const ALLOWED_HOSTS: [&str; 2] = ["127.0.0.1:8787", "localhost:8787"];
/// State-changing requests must also come from one of these origins.
const ALLOWED_ORIGINS: [&str; 2] = ["http://127.0.0.1:8787", "http://localhost:8787"];

#[derive(Clone)]
pub struct AppState {
    pub out_dir: String,
    pub engagement: String,
}

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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/health",
            get(|| async { Json(serde_json::json!({ "ok": true })) }),
        )
        .fallback_service(ServeDir::new("frontend/dist"))
        .with_state(Arc::new(state))
        .layer(middleware::from_fn(guard))
}

#[tokio::main]
async fn main() {
    let state = AppState {
        out_dir: std::env::var("ASCENT_OUT").unwrap_or_else(|_| "out".into()),
        engagement: std::env::var("ASCENT_ENG")
            .unwrap_or_else(|_| "samples/engagement.example.yaml".into()),
    };
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
        router(AppState {
            out_dir: "out".into(),
            engagement: "e.yaml".into(),
        })
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
}
