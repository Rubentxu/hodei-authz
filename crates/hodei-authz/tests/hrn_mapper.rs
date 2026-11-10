//! HRN -> Cedar identity and hierarchy tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{Entities, EntityUid, Schema};
use hodei_authz::cedar::{CedarAuthorizer, CedarEntityMapper};
use hodei_authz::hodei_hrn::Hrn;
use hodei_authz::hrn_mapper::HrnCedarMapper;
use hodei_authz::{
    AccountId, ActionId, AttributeValue, AuthenticationError, AuthorizationOutcome,
    AuthorizationRequest, Authorizer, Credentials, DenyReason, GroupId, PrincipalAuthenticator,
    PrincipalClaims, PrincipalId, ResourceRef, VerifiedContext, verify_principal,
};

struct MockAuthenticator;

#[async_trait]
impl PrincipalAuthenticator for MockAuthenticator {
    async fn authenticate(
        &self,
        _credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        Ok(PrincipalClaims::new(
            PrincipalId::new("hrn:hodei:iam::acme:User/alice").unwrap(),
            AccountId::new("acme").unwrap(),
        )
        .with_groups([GroupId::new("developers").unwrap()])
        .with_attributes(BTreeMap::from([(
            "name".to_string(),
            AttributeValue::String("alice".to_string()),
        )])))
    }
}

fn resource(hrn: &str) -> ResourceRef {
    hrn.parse::<ResourceRef>().expect("resource")
}

async fn principal() -> hodei_authz::VerifiedPrincipal {
    verify_principal(&MockAuthenticator, &Credentials::bearer("token"))
        .await
        .expect("principal")
}

#[tokio::test]
async fn same_local_id_in_different_accounts_has_different_uids() {
    let acme = HrnCedarMapper
        .resource_uid(&resource("hrn:hodei:artifacts:eu:acme:repository/releases"))
        .expect("acme uid");
    let other = HrnCedarMapper
        .resource_uid(&resource(
            "hrn:hodei:artifacts:eu:other:repository/releases",
        ))
        .expect("other uid");

    assert_ne!(acme, other);
    assert!(acme.to_string().contains("acme"));
    assert!(other.to_string().contains("other"));
}

#[tokio::test]
async fn principal_and_owner_hrn_share_the_same_uid() {
    let principal = principal().await;
    let principal_uid = HrnCedarMapper
        .principal_uid(&principal)
        .expect("principal uid");
    let owner_uid = HrnCedarMapper
        .entity_reference("hrn:hodei:iam::acme:User/alice")
        .expect("owner uid");

    assert_eq!(principal_uid, owner_uid);
}

#[tokio::test]
async fn groups_become_account_scoped_parents() {
    let principal = principal().await;
    let parents = HrnCedarMapper
        .principal_parents(&principal)
        .expect("parents");
    let expected = HrnCedarMapper::group_uid(
        &AccountId::new("acme").unwrap(),
        &GroupId::new("developers").unwrap(),
    )
    .expect("group uid");
    let other = HrnCedarMapper::group_uid(
        &AccountId::new("other").unwrap(),
        &GroupId::new("developers").unwrap(),
    )
    .expect("other group");

    assert!(parents.contains(&expected));
    assert_ne!(expected, other);
}

#[tokio::test]
async fn group_membership_can_trigger_a_forbid() {
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(principal, action, resource);
        forbid(principal, action, resource)
        when { principal in Iam::Group::"hrn:hodei:iam::acme:Group/developers" };"#,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
    )
    .expect("authorizer");
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("hrn:hodei:artifacts:eu:acme:repository/releases"),
    );

    println!(
        "parents: {:?}",
        HrnCedarMapper
            .principal_parents(&request.principal().clone())
            .unwrap()
    );
    println!(
        "principal: {:?}",
        HrnCedarMapper.principal_uid(request.principal()).unwrap()
    );
    println!(
        "decision: {:?}",
        authorizer.decide_with_diagnostics(&request)
    );
    assert_eq!(
        authorizer.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}

#[tokio::test]
async fn resource_parents_are_prefixes_of_the_resource_id() {
    let hrn = Hrn::new(
        "hodei",
        "artifacts",
        "eu",
        "acme",
        "repository",
        "repository/releases/v2",
    )
    .unwrap();
    let resource = ResourceRef::new(hrn.clone()).expect("resource");
    let parents = HrnCedarMapper.resource_parents(&resource).expect("parents");

    let immediate_hrn = Hrn::new(
        "hodei",
        "artifacts",
        "eu",
        "acme",
        "repository",
        "repository/releases",
    )
    .unwrap();
    let immediate = HrnCedarMapper::hrn_to_uid(&immediate_hrn).expect("immediate");
    let root_hrn = Hrn::new(
        "hodei",
        "artifacts",
        "eu",
        "acme",
        "repository",
        "repository",
    )
    .unwrap();
    let root = HrnCedarMapper::hrn_to_uid(&root_hrn).expect("root");

    assert!(parents.contains(&immediate));
    assert!(parents.contains(&root));
    assert_eq!(parents.len(), 2);
}

#[test]
fn action_uid_matches_the_canonical_schema_name() {
    let action = ActionId::new("artifacts", "ReadRepository").unwrap();
    let uid = action.to_cedar_uid();
    assert_eq!(uid, "Artifacts::Action::\"ReadRepository\"");
    assert_eq!(uid.parse::<EntityUid>().unwrap().to_string(), uid);
}

#[test]
fn legacy_repository_service_maps_to_a_different_uid() {
    let legacy = resource("hrn:hodei:repository:eu:acme:repository/releases");
    let canonical = resource("hrn:hodei:artifacts:eu:acme:repository/releases");
    let legacy_uid = HrnCedarMapper.resource_uid(&legacy).unwrap();
    let canonical_uid = HrnCedarMapper.resource_uid(&canonical).unwrap();

    assert_ne!(legacy_uid, canonical_uid);
    assert!(legacy_uid.to_string().contains("Repository::Repository"));
    assert!(canonical_uid.to_string().contains("Artifacts::Repository"));
}

#[test]
fn non_hrn_entity_references_are_rejected() {
    assert!(HrnCedarMapper.entity_reference("User::\"alice\"").is_err());
    assert!(HrnCedarMapper.entity_reference("not-an-hrn").is_err());
}

#[tokio::test]
async fn mapper_works_with_the_validated_schema_path() {
    let schema = Schema::from_json_str(
        r#"{
            "Iam": {
                "entityTypes": {
                    "User": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}},
                        "memberOfTypes": ["Group"]
                    },
                    "Group": {}
                },
                "actions": {}
            },
            "Artifacts": {
                "entityTypes": {
                    "Repository": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}
                    }
                },
                "actions": {
                    "ReadRepository": {
                        "appliesTo": {
                            "principalTypes": ["Iam::User"],
                            "resourceTypes": ["Repository"]
                        }
                    }
                }
            }
        }"#,
    )
    .expect("schema");
    let authorizer = CedarAuthorizer::from_policies(
        r#"permit(
            principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Artifacts::Repository::"hrn:hodei:artifacts:eu:acme:repository/releases"
        );"#,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
        schema,
    )
    .expect("validated authorizer");

    let resource = resource("hrn:hodei:artifacts:eu:acme:repository/releases").with_attributes(
        BTreeMap::from([(
            "name".to_string(),
            AttributeValue::String("releases".to_string()),
        )]),
    );
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource,
    );
    let (outcome, diagnostic) = authorizer.decide_with_diagnostics(&request);
    assert_eq!(
        outcome,
        AuthorizationOutcome::Permit,
        "diagnostic: {diagnostic:?}"
    );
}

#[tokio::test]
async fn canonical_policy_does_not_match_a_legacy_identity() {
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(
            principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Artifacts::Repository::"hrn:hodei:artifacts:eu:acme:repository/releases"
        );"#,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
    )
    .expect("authorizer");
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("hrn:hodei:repository:eu:acme:repository/releases"),
    );

    assert_eq!(
        authorizer.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::NoMatchingPolicy)
    );
}

struct NonHrnAuthenticator;

#[async_trait]
impl PrincipalAuthenticator for NonHrnAuthenticator {
    async fn authenticate(
        &self,
        _credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        Ok(PrincipalClaims::new(
            PrincipalId::new("alice").unwrap(),
            AccountId::new("acme").unwrap(),
        ))
    }
}

#[tokio::test]
async fn non_hrn_subjects_are_rejected_by_the_mapper() {
    let principal = verify_principal(&NonHrnAuthenticator, &Credentials::bearer("token"))
        .await
        .expect("principal");
    assert!(HrnCedarMapper.principal_uid(&principal).is_err());
}

#[tokio::test]
async fn group_membership_is_account_scoped() {
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(principal, action, resource);
        forbid(principal, action, resource)
        when { principal in Iam::Group::"hrn:hodei:iam::other:Group/developers" };"#,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
    )
    .expect("authorizer");
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("hrn:hodei:artifacts:eu:acme:repository/releases"),
    );

    assert_eq!(authorizer.decide(&request), AuthorizationOutcome::Permit);
}

#[tokio::test]
async fn resource_parents_can_trigger_a_forbid() {
    let hrn = Hrn::new(
        "hodei",
        "artifacts",
        "eu",
        "acme",
        "repository",
        "repository/releases/v2",
    )
    .unwrap();
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(principal, action, resource);
        forbid(principal, action, resource)
        when { resource in Artifacts::Repository::"hrn:hodei:artifacts:eu:acme:repository/repository/releases" };"#,
        Entities::empty(),
        Arc::new(HrnCedarMapper),
    )
    .expect("authorizer");
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal().await),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        ResourceRef::new(hrn).expect("resource"),
    );

    assert_eq!(
        authorizer.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}

#[test]
fn single_segment_resource_has_no_parents() {
    let resource = resource("hrn:hodei:artifacts:eu:acme:repository/releases");
    assert!(
        HrnCedarMapper
            .resource_parents(&resource)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn empty_hrn_fields_are_rejected() {
    assert!(Hrn::new("hodei", "artifacts", "eu", "acme", "repository", "").is_err());
    assert!(Hrn::new("hodei", "artifacts", "eu", "", "repository", "releases").is_err());
    assert!(Hrn::new("hodei", "artifacts", "eu", "acme", "repository", "a//b").is_err());
}

#[test]
fn ambiguous_hrn_fields_are_rejected() {
    assert!(Hrn::new("hodei", "a:b", "eu", "acme", "repository", "releases").is_err());
    assert!(
        Hrn::new(
            "hodei",
            "artifacts",
            "x:a_b:y",
            "acme",
            "repository",
            "releases"
        )
        .is_err()
    );
    assert!(Hrn::new("hodei", "artifacts", "eu", "acme", "c:d", "releases").is_err());
    assert!(Hrn::new("hodei", "artifacts", "eu", "acme", "repository", "a//b").is_err());
}

#[test]
fn package_dash_and_underscore_are_distinct_cedar_types() {
    use hodei_authz::hodei_hrn::Hrn;

    let dash = Hrn::new("hodei", "artifacts", "eu", "acme", "package-version", "v1").unwrap();
    let underscore = Hrn::new("hodei", "artifacts", "eu", "acme", "package_version", "v1").unwrap();

    let dash_uid = HrnCedarMapper::hrn_to_uid(&dash).unwrap();
    let underscore_uid = HrnCedarMapper::hrn_to_uid(&underscore).unwrap();
    assert_ne!(dash_uid.to_string(), underscore_uid.to_string());
    assert!(dash_uid.to_string().contains("Package_x2Dversion"));
    assert!(underscore_uid.to_string().contains("Package_x5Fversion"));
}
