//! Regression tests for the fail-closed authorization middleware.
//!
//! These tests exercise the middleware in-process, without binding a port.
//! The key invariant is that a protected handler is never reached without an
//! explicit authorization decision, and the response is never a 200.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header::CONTENT_TYPE},
    middleware,
    response::Response,
    routing::get,
};
use hodei_authz_axum::authorize_middleware;
use tower::ServiceExt;

#[derive(Clone)]
struct Probe(Arc<AtomicBool>);

async fn protected_handler(State(probe): State<Probe>) -> &'static str {
    probe.0.store(true, Ordering::SeqCst);
    "sensitive payload"
}

async fn health_handler() -> &'static str {
    "ok"
}

fn app() -> (Router, Arc<AtomicBool>) {
    let probe = Arc::new(AtomicBool::new(false));
    let protected = Router::new()
        .route("/protected", get(protected_handler).post(protected_handler))
        .with_state(Probe(probe.clone()))
        .layer(middleware::from_fn(authorize_middleware));
    let app = Router::new()
        .route("/health", get(health_handler))
        .merge(protected);
    (app, probe)
}

async fn assert_forbidden(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[CONTENT_TYPE].to_str().unwrap(),
        "text/plain; charset=utf-8"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"forbidden");
}

#[tokio::test]
async fn protected_request_is_denied_and_handler_is_not_reached() {
    let (app, probe) = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_forbidden(response).await;
    assert!(
        !probe.load(Ordering::SeqCst),
        "the protected handler must not run when authorization is unavailable"
    );
}

#[tokio::test]
async fn mutating_request_is_denied_without_side_effects() {
    let (app, probe) = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_forbidden(response).await;
    assert!(
        !probe.load(Ordering::SeqCst),
        "a denied mutation must not reach the handler"
    );
}

#[tokio::test]
async fn forged_identity_headers_do_not_change_the_denial() {
    let (app, probe) = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer forged-token")
                .header("x-tenant-id", "victim-account")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_forbidden(response).await;
    assert!(
        !probe.load(Ordering::SeqCst),
        "client-supplied headers must not establish an authorized identity"
    );
}

#[tokio::test]
async fn health_routes_outside_the_layer_remain_public() {
    let (app, _probe) = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}
