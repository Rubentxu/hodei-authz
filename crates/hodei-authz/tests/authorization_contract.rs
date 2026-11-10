//! Pure tests for the authorization contract.

use async_trait::async_trait;
use hodei_authz::hodei_hrn::Hrn;
use hodei_authz::{
    AccountId, ActionId, AttributeValue, AuthenticationError, AuthorizationOutcome,
    AuthorizationRequest, Authorizer, Credentials, DenyReason, GroupId, IndeterminateReason,
    PrincipalAuthenticator, PrincipalClaims, PrincipalId, ResourceRef, VerifiedContext,
    verify_principal,
};
use std::collections::BTreeMap;

struct MockAuthenticator {
    result: Result<PrincipalClaims, AuthenticationError>,
}

#[async_trait]
impl PrincipalAuthenticator for MockAuthenticator {
    async fn authenticate(
        &self,
        _credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        self.result.clone()
    }
}

fn claims() -> PrincipalClaims {
    PrincipalClaims::new(
        PrincipalId::new("hrn:hodei:iam::acme:User/alice").unwrap(),
        AccountId::new("acme").unwrap(),
    )
    .with_groups([GroupId::new("developers").unwrap()])
    .with_attributes(BTreeMap::from([(
        "role".to_string(),
        AttributeValue::String("admin".to_string()),
    )]))
}

fn resource(account: &str, name: &str) -> ResourceRef {
    let hrn: Hrn = format!("hrn:hodei:artifacts:eu:{account}:repository/{name}")
        .parse()
        .expect("valid HRN");
    ResourceRef::new(hrn).expect("resource ref")
}

async fn verified_principal() -> hodei_authz::VerifiedPrincipal {
    verify_principal(
        &MockAuthenticator {
            result: Ok(claims()),
        },
        &Credentials::bearer("token"),
    )
    .await
    .expect("verified principal")
}

#[tokio::test]
async fn verified_principal_requires_an_authenticator() {
    let principal = verified_principal().await;
    assert_eq!(principal.account().as_str(), "acme");
    assert_eq!(
        principal.subject().as_str(),
        "hrn:hodei:iam::acme:User/alice"
    );
    assert!(
        principal
            .groups()
            .contains(&GroupId::new("developers").unwrap())
    );
    assert_eq!(
        principal.attributes().get("role"),
        Some(&AttributeValue::String("admin".to_string()))
    );
}

#[tokio::test]
async fn subject_hrn_and_account_must_agree() {
    let mismatched = PrincipalClaims::new(
        PrincipalId::new("hrn:hodei:iam::victim:User/alice").unwrap(),
        AccountId::new("acme").unwrap(),
    );
    let authenticator = MockAuthenticator {
        result: Ok(mismatched),
    };
    let error = verify_principal(&authenticator, &Credentials::bearer("token"))
        .await
        .unwrap_err();
    assert_eq!(error, AuthenticationError::InvalidCredentials);
}

#[tokio::test]
async fn authentication_failures_do_not_produce_a_principal() {
    let authenticator = MockAuthenticator {
        result: Err(AuthenticationError::Expired),
    };
    let error = verify_principal(&authenticator, &Credentials::bearer("token"))
        .await
        .unwrap_err();
    assert_eq!(error, AuthenticationError::Expired);
}

#[test]
fn credentials_are_redacted_in_debug() {
    let credentials = Credentials::bearer("super-secret-token");
    let rendered = format!("{credentials:?}");
    assert!(!rendered.contains("super-secret-token"));
    assert!(rendered.contains("redacted"));
}

#[test]
fn permit_is_the_only_outcome_that_allows_access() {
    assert!(AuthorizationOutcome::Permit.allows_access());
    assert!(!AuthorizationOutcome::deny(DenyReason::ExplicitForbid).allows_access());
    assert!(
        !AuthorizationOutcome::indeterminate(IndeterminateReason::MissingPolicy).allows_access()
    );
    assert!(!AuthorizationOutcome::deny(DenyReason::NoMatchingPolicy).is_permit());
}

#[tokio::test]
async fn account_scope_comes_from_the_hrn_and_is_comparable() {
    let context = VerifiedContext::from_principal(verified_principal().await);
    let action = ActionId::new("artifacts", "ReadRepository").unwrap();

    let same = AuthorizationRequest::new(
        context.clone(),
        action.clone(),
        resource("acme", "releases"),
    );
    assert!(same.is_same_account());
    assert_eq!(same.resource().account().as_str(), "acme");

    let other = AuthorizationRequest::new(context, action, resource("victim", "releases"));
    assert!(!other.is_same_account());
    assert!(
        other
            .resource()
            .is_in_account(&AccountId::new("victim").unwrap())
    );
}

#[tokio::test]
async fn request_carries_action_resource_attributes_and_context() {
    let context = VerifiedContext::from_principal(verified_principal().await);
    let action = ActionId::new("artifacts", "ReadRepository").unwrap();
    let resource = resource("acme", "releases").with_attributes(BTreeMap::from([
        ("is_public".to_string(), AttributeValue::Bool(true)),
        (
            "owner_id".to_string(),
            AttributeValue::Entity("hrn:hodei:iam::acme:User/alice".to_string()),
        ),
    ]));
    let request = AuthorizationRequest::new(context, action.clone(), resource)
        .with_context_attributes(BTreeMap::from([(
            "ip_address".to_string(),
            AttributeValue::String("10.0.0.1".to_string()),
        )]));

    assert_eq!(request.action(), &action);
    assert_eq!(request.resource().hrn().tenant_id, "acme");
    assert_eq!(
        request.resource().attributes().get("is_public"),
        Some(&AttributeValue::Bool(true))
    );
    assert_eq!(
        request.resource().attributes().get("owner_id"),
        Some(&AttributeValue::Entity(
            "hrn:hodei:iam::acme:User/alice".to_string()
        ))
    );
    assert_eq!(
        request.context_attributes().get("ip_address"),
        Some(&AttributeValue::String("10.0.0.1".to_string()))
    );
}

#[test]
fn action_identity_is_canonical_and_injective() {
    let lowercase = ActionId::new("artifacts", "read").unwrap();
    let uppercase = ActionId::new("Artifacts", "read").unwrap();
    assert_eq!(lowercase, uppercase);
    assert_eq!(lowercase.to_string(), "Artifacts::Action::\"read\"");
    assert_eq!(
        ActionId::from_cedar_uid("Artifacts::Action::\"read\"").unwrap(),
        lowercase
    );

    assert_ne!(
        ActionId::new("a-1", "read").unwrap().to_cedar_uid(),
        ActionId::new("a1", "read").unwrap().to_cedar_uid()
    );
    assert_ne!(
        ActionId::new("foo-bar", "read").unwrap().to_cedar_uid(),
        ActionId::new("foo--bar", "read").unwrap().to_cedar_uid()
    );

    let json = serde_json::to_string(&lowercase).unwrap();
    let back: ActionId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lowercase);
}

#[test]
fn legacy_action_names_must_be_migrated() {
    // Existing `DocApp::Action::"Document::Read"` policies are not canonical:
    // they need the HSP-7 action migration.
    assert!(ActionId::new("docapp", "Document::Read").is_err());
    assert!(ActionId::from_cedar_uid("DocApp::Action::\"Document::Read\"").is_err());
}

#[test]
fn input_limits_are_enforced() {
    assert!(AccountId::new("a".repeat(128)).is_ok());
    assert!(AccountId::new("a".repeat(129)).is_err());
    assert!(PrincipalId::new("a".repeat(512)).is_ok());
    assert!(PrincipalId::new("a".repeat(513)).is_err());
    assert!(GroupId::new("a".repeat(128)).is_ok());
    assert!(GroupId::new("a".repeat(129)).is_err());
    assert!(ActionId::new("a".repeat(64), "read").is_ok());
    assert!(ActionId::new("a".repeat(65), "read").is_err());
    assert!(ActionId::new("artifacts", "a".repeat(128)).is_ok());
    assert!(ActionId::new("artifacts", "a".repeat(129)).is_err());
    assert!(
        ActionId::from_cedar_uid(&format!("Artifacts::Action::\"{}\"", "a".repeat(500))).is_err()
    );
}

#[test]
fn resource_ref_guards_the_legacy_hrn() {
    let action_as_resource: Hrn = "hrn:hodei:artifacts:eu:acme:Action/read".parse().unwrap();
    assert!(ResourceRef::new(action_as_resource).is_err());

    let uppercase_service: Hrn = "hrn:hodei:Artifacts:eu:acme:repository/r".parse().unwrap();
    assert!(ResourceRef::new(uppercase_service).is_err());

    // The old 0.1 parser only accepts two resource parts.
    assert!(
        "hrn:hodei:artifacts:eu:acme:repository/releases/v2"
            .parse::<ResourceRef>()
            .is_err()
    );
}

#[test]
fn identifiers_and_resource_refs_are_validated() {
    assert!(AccountId::new("").is_err());
    assert!(AccountId::new("-bad").is_err());
    assert!(PrincipalId::new("bad\nprincipal").is_err());
    assert!(GroupId::new("").is_err());
    assert!(ActionId::new("", "read").is_err());
    assert!(ActionId::new("9a", "read").is_err());
    assert!(ActionId::new("artifacts", "_read").is_err());
    assert!(ActionId::from_cedar_uid("IAM::Action::\"read\"").is_err());
    assert!("garbage".parse::<ResourceRef>().is_err());
}

struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: &AuthorizationRequest) -> AuthorizationOutcome {
        AuthorizationOutcome::deny(DenyReason::ExplicitForbid)
    }
}

#[tokio::test]
async fn authorizer_port_returns_an_explicit_outcome() {
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(verified_principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("acme", "releases"),
    );

    assert_eq!(
        DenyAll.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}
