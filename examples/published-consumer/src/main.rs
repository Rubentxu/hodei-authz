//! Reproducible consumer of the published authz crates.
//!
//! Run with:
//! `cargo run --manifest-path examples/published-consumer/Cargo.toml`
//! It resolves `hodei-authz` and `hodei-authz-axum` from crates.io, without
//! path dependencies, and checks one Permit and one Deny decision.

use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::Entities;
use hodei_authz::cedar::CedarAuthorizer;
use hodei_authz::hodei_hrn::Hrn;
use hodei_authz::hrn_mapper::HrnCedarMapper;
use hodei_authz::{
    AccountId, ActionId, AuthenticationError, AuthorizationOutcome, AuthorizationRequest,
    Authorizer, Credentials, PrincipalAuthenticator, PrincipalClaims, PrincipalId, ResourceRef,
    VerifiedContext, verify_principal,
};

struct TestAuthenticator;

#[async_trait]
impl PrincipalAuthenticator for TestAuthenticator {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        let name = match credentials {
            Credentials::Bearer(token) if token == "alice" => "alice",
            Credentials::Bearer(token) if token == "bob" => "bob",
            _ => return Err(AuthenticationError::InvalidCredentials),
        };
        Ok(PrincipalClaims::new(
            PrincipalId::new(format!("hrn:hodei:iam::acme:User/{name}")).unwrap(),
            AccountId::new("acme").unwrap(),
        ))
    }
}

fn hrn() -> Hrn {
    "hrn:hodei:artifacts:eu:acme:repository/releases"
        .parse()
        .expect("resource HRN")
}

fn resource() -> ResourceRef {
    ResourceRef::new(hrn()).expect("resource")
}

async fn context(token: &str) -> VerifiedContext {
    VerifiedContext::from_principal(
        verify_principal(&TestAuthenticator, &Credentials::bearer(token))
            .await
            .expect("verified principal"),
    )
}

#[tokio::main]
async fn main() {
    let policy = r#"permit(
        principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
        action == Artifacts::Action::"ReadRepository",
        resource
    );"#;
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        policy,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
    )
    .expect("authorizer");

    let action = ActionId::new("artifacts", "ReadRepository").unwrap();
    let alice = AuthorizationRequest::new(context("alice").await, action.clone(), resource());
    assert_eq!(authorizer.decide(&alice), AuthorizationOutcome::Permit);

    let bob = AuthorizationRequest::new(context("bob").await, action, resource());
    assert_eq!(
        authorizer.decide(&bob),
        AuthorizationOutcome::Deny(hodei_authz::DenyReason::NoMatchingPolicy)
    );

    // Prove the published Axum integration is part of the same consumer graph.
    let _ = std::any::type_name::<hodei_authz_axum::AuthorizeState>();
    println!("published authz consumer OK: alice=Permit bob=Deny");
}
