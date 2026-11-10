//! Axum middleware for authorization.
//!
//! # Security
//!
//! [`authorize_middleware`] is the legacy fail-closed layer: it refuses to
//! forward protected requests because it has no verified authorizer. It is
//! retained for compatibility with existing routers.
//!
//! [`authorize_with_state`] is the authorizing middleware: it extracts a
//! bearer credential, verifies it through a [`PrincipalAuthenticator`], builds
//! an [`AuthorizationRequest`] with a route-specific target, and only calls the
//! handler when the [`Authorizer`] returns `Permit`. Missing/invalid
//! credentials map to `401`, deny/indeterminate to `403`; the handler is never
//! executed in those cases.
//!
//! The middleware does **not** replace use-case authorization when the
//! decision depends on resource state. It propagates the verified context as a
//! request extension; it never reads `x-tenant-id` or any client-supplied
//! tenant as identity.

use std::sync::{Arc, Once};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hodei_authz::Authorizer;
use hodei_authz::{
    ActionId, AuthorizationRequest, Credentials, PrincipalAuthenticator, ResourceRef,
    VerifiedContext, verify_principal,
};
use thiserror::Error;

static FAIL_CLOSED_LOGGED: Once = Once::new();

/// Unused placeholder retained for API compatibility.
#[deprecated(
    note = "unused placeholder; use the new `AuthorizeState` for the authorizing middleware"
)]
pub struct AuthorizationState {}

/// Immutable state needed by [`authorize_with_state`].
#[derive(Clone)]
pub struct AuthorizeState {
    authenticator: Arc<dyn PrincipalAuthenticator>,
    authorizer: Arc<dyn Authorizer>,
    target: Arc<dyn AuthorizationTarget>,
    allow_cross_account: bool,
}

impl AuthorizeState {
    pub fn new(
        authenticator: Arc<dyn PrincipalAuthenticator>,
        authorizer: Arc<dyn Authorizer>,
        target: Arc<dyn AuthorizationTarget>,
    ) -> Self {
        Self {
            authenticator,
            authorizer,
            target,
            allow_cross_account: false,
        }
    }

    /// Opt in to cross-account requests. The default is deny: the verified
    /// principal and the resource must share an account. Use this only for
    /// explicit administrative flows.
    pub fn allow_cross_account(mut self, allow: bool) -> Self {
        self.allow_cross_account = allow;
        self
    }
}

/// The action and resource of a request.
#[derive(Debug, Clone)]
pub struct Target {
    pub action: ActionId,
    pub resource: ResourceRef,
}

impl Target {
    pub fn new(action: ActionId, resource: ResourceRef) -> Self {
        Self { action, resource }
    }
}

/// Resolves the authorization target from the HTTP request.
///
/// Implementations must be pure and deterministic. Route/method mapping and
/// path parsing belong here; the client-supplied tenant header is never used
/// as identity.
pub trait AuthorizationTarget: Send + Sync {
    fn resolve(&self, request: &Request<Body>) -> Result<Target, TargetError>;
}

/// The request cannot be mapped to an authorization target.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("bad authorization target")]
pub struct TargetError;

/// Legacy fail-closed middleware.
///
/// This function keeps the `axum::middleware::from_fn` shape but deliberately
/// never calls `next.run`. Use [`authorize_with_state`] for real enforcement.
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

/// Authorize a request and forward it only on `Permit`.
///
/// Attach with `axum::middleware::from_fn_with_state(state, authorize_with_state)`.
pub async fn authorize_with_state(
    State(state): State<AuthorizeState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let token = match bearer_token(&req) {
        Some(token) => token,
        None => return unauthorized(),
    };

    let principal =
        match verify_principal(state.authenticator.as_ref(), &Credentials::bearer(token)).await {
            Ok(principal) => principal,
            Err(_) => return unauthorized(),
        };

    let target = match state.target.resolve(&req) {
        Ok(target) => target,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad request").into_response(),
    };

    let context = VerifiedContext::from_principal(principal);
    let request = AuthorizationRequest::new(context.clone(), target.action, target.resource);

    if !state.allow_cross_account && !request.is_same_account() {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    if !state.authorizer.decide(&request).allows_access() {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    // Per-request extension: no shared mutable context between requests.
    req.extensions_mut().insert(context);
    next.run(req).await
}

fn bearer_token(req: &Request<Body>) -> Option<String> {
    let value = req.headers().get(axum::http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer"),
    );
    response
}
