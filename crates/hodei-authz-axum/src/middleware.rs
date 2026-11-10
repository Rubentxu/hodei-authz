//! Axum middleware for authorization.
//!
//! # Security
//!
//! [`authorize_middleware`] is **fail-closed**. This crate does not yet own a
//! verified authorizer, so the middleware refuses to forward protected
//! requests: every request that crosses the layer is answered with
//! `403 Forbidden` and the handler is never executed. The previous
//! implementation called `next.run(req)` unconditionally, which made the layer
//! a no-op that looked like protection.
//!
//! The layer only covers routes registered before it in the same `Router`.
//! Attach it to a dedicated subrouter, or add it after every route, so a route
//! cannot be added later without the layer. Replace the layer with an
//! authorizing middleware once an authenticated authorizer adapter exists; do
//! not remove it to make a `403` disappear.

use std::sync::Once;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

static FAIL_CLOSED_LOGGED: Once = Once::new();

/// Unused placeholder retained for API compatibility.
#[deprecated(
    note = "unused placeholder; it will be removed when the authorizing middleware replaces the fail-closed layer"
)]
pub struct AuthorizationState {}

/// Deny every protected request until a verified authorizer is wired.
///
/// The function keeps the `axum::middleware::from_fn` shape so existing
/// layering compiles, but it deliberately never calls `next.run`. A missing,
/// failed or unimplemented authorization path must not become a permissive
/// fallback.
///
/// The denial is a generic `403` with the body `forbidden`. The configuration
/// error is logged once per process, not once per request, so unauthenticated
/// traffic cannot amplify logs or leak request paths.
///
/// # Example
///
/// ```rust,ignore
/// let app = Router::new()
///     .route("/protected", get(handler))
///     .layer(middleware::from_fn(authorize_middleware));
/// // Every request to /protected now receives 403.
/// ```
pub async fn authorize_middleware(
    _req: Request<Body>,
    _next: Next,
) -> Result<Response, StatusCode> {
    FAIL_CLOSED_LOGGED.call_once(|| {
        tracing::error!(
            "authorize_middleware is fail-closed: no verified authorizer is configured; \
             protected requests are denied"
        );
    });

    Ok((StatusCode::FORBIDDEN, "forbidden").into_response())
}
