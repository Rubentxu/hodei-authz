//! The SDK re-export must resolve to the local, fail-closed `hodei-authz-axum`.
//!
//! This test is compiled only with the `axum` feature. It fails against the
//! published `0.1.0` middleware (which forwarded every request with a 200) and
//! passes against the local `0.1.1` fail-closed middleware.

#![cfg(feature = "axum")]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware,
    routing::get,
};
use tower::ServiceExt;

#[derive(Clone)]
struct Probe(Arc<AtomicBool>);

async fn protected_handler(State(probe): State<Probe>) -> &'static str {
    probe.0.store(true, Ordering::SeqCst);
    "sensitive payload"
}

#[tokio::test]
async fn sdk_reexport_is_fail_closed() {
    let probe = Arc::new(AtomicBool::new(false));
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .with_state(Probe(probe.clone()))
        .layer(middleware::from_fn(
            hodei_authz_sdk::prelude::authorize_middleware,
        ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !probe.load(Ordering::SeqCst),
        "the SDK re-export must not forward a protected request"
    );
}
