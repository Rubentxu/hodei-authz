//! Axum integration for the Hodei authorization framework.
//!
//! # Security
//!
//! [`authorize_with_state`] verifies a bearer credential through a
//! [`hodei_authz::PrincipalAuthenticator`], builds an
//! [`hodei_authz::AuthorizationRequest`] from a route target, and forwards the
//! request only when the [`hodei_authz::Authorizer`] returns `Permit`.
//! Missing/invalid credentials are `401`; deny/indeterminate are `403`; the
//! handler is never executed in those cases.
//!
//! [`authorize_middleware`] remains the legacy fail-closed layer for routers
//! that have not migrated. Do not build a security identity from unverified
//! headers or client-supplied tenant IDs.

pub mod middleware;

pub use middleware::{
    AuthorizationTarget, AuthorizeState, Target, TargetError, authorize_middleware,
    authorize_with_state,
};
