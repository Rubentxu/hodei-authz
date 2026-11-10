//! Axum integration for the Hodei authorization framework.
//!
//! # Security
//!
//! [`authorize_middleware`] is **fail-closed**: it denies every request until a
//! verified authorizer is wired, and it never forwards a protected request.
//! See the [`middleware`] module for the rationale and the migration path.
//!
//! The authenticated extractors are not enabled in this release. Do not build
//! a security identity from unverified headers or client-supplied tenant IDs.

pub mod middleware;

pub use middleware::authorize_middleware;
