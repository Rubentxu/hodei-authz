//! Authorization ports: authentication and pure decisions.

use async_trait::async_trait;
use hodei_hrn::Hrn;
use thiserror::Error;

use crate::decision::AuthorizationOutcome;
use crate::model::{AuthorizationRequest, Credentials, PrincipalClaims, VerifiedPrincipal};

/// Authentication adapter contract.
///
/// Implementations validate a credential (JWT, OIDC, etc.) and return claims.
/// They cannot construct a [`VerifiedPrincipal`] directly; the crate wraps the
/// accepted claims in [`verify_principal`].
#[async_trait]
pub trait PrincipalAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError>;
}

/// Authentication failure.
///
/// `ProviderUnavailable` is free-form; adapters MUST NOT put tokens or raw
/// provider payloads in it because it is rendered by `Display`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    #[error("missing credentials")]
    MissingCredentials,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("expired credentials")]
    Expired,
    #[error("wrong audience")]
    WrongAudience,
    #[error("authentication provider unavailable: {0}")]
    ProviderUnavailable(String),
}

/// Verify credentials through an authenticator and produce a trusted principal.
///
/// This is the only public path to a [`VerifiedPrincipal`].
pub async fn verify_principal(
    authenticator: &dyn PrincipalAuthenticator,
    credentials: &Credentials,
) -> Result<VerifiedPrincipal, AuthenticationError> {
    let claims = authenticator.authenticate(credentials).await?;
    // If the subject is an HRN, its tenant must be the account the adapter
    // claims. This prevents an authenticator defect from producing a
    // principal that talks about one account and acts as another.
    if claims.subject().as_str().starts_with("hrn:") {
        let hrn: Hrn = claims
            .subject()
            .as_str()
            .parse()
            .map_err(|_| AuthenticationError::InvalidCredentials)?;
        if hrn.account() != claims.account().as_str() {
            return Err(AuthenticationError::InvalidCredentials);
        }
    }
    Ok(VerifiedPrincipal::from_claims(claims))
}

/// Pure authorization port.
///
/// Implementations evaluate the configured policy snapshot and return an
/// explicit outcome. They do not perform IO: the request already carries the
/// verified principal, action, resource, resource/principal attributes and
/// request context. Loading the resource from storage belongs to the use case,
/// not to this port.
///
/// The name collides with `cedar_policy::Authorizer`; consumers that import
/// both can alias this one as `HodeiAuthorizer`.
pub trait Authorizer: Send + Sync {
    #[must_use]
    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationOutcome;
}
