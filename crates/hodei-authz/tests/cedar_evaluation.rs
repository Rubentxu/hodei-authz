//! Pure Cedar evaluation tests, no IO or remote policy service.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{Entities, Entity, EntityId, EntityTypeName, EntityUid, Schema};
use hodei_authz::cedar::{CedarAuthorizer, CedarEntityMapper, CedarMappingError, CedarSetupError};
use hodei_authz::hodei_hrn::Hrn;
use hodei_authz::{
    AccountId, ActionId, AttributeValue, AuthenticationError, AuthorizationOutcome,
    AuthorizationRequest, Authorizer, Credentials, DenyReason, GroupId, IndeterminateReason,
    PrincipalAuthenticator, PrincipalClaims, PrincipalId, ResourceRef, VerifiedContext,
    verify_principal,
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

struct TestMapper;

fn uid(type_name: &str, id: &str) -> EntityUid {
    let type_name: EntityTypeName = type_name.parse().expect("valid type");
    let id: EntityId = id.parse().expect("valid id");
    EntityUid::from_type_name_and_id(type_name, id)
}

impl CedarEntityMapper for TestMapper {
    fn entity_reference(&self, value: &str) -> Result<EntityUid, CedarMappingError> {
        if let Ok(hrn) = value.parse::<Hrn>()
            && hrn.resource_type == "User"
        {
            return Ok(uid("User", &hrn.resource_id));
        }
        value
            .parse()
            .map_err(|error: cedar_policy::ParseErrors| CedarMappingError(error.to_string()))
    }

    fn principal_uid(
        &self,
        principal: &hodei_authz::VerifiedPrincipal,
    ) -> Result<EntityUid, CedarMappingError> {
        let name = principal
            .attributes()
            .get("name")
            .and_then(|value| match value {
                AttributeValue::String(value) => Some(value.as_str()),
                _ => None,
            })
            .ok_or_else(|| CedarMappingError("principal.name missing".to_string()))?;
        Ok(uid("User", name))
    }

    fn resource_uid(&self, resource: &ResourceRef) -> Result<EntityUid, CedarMappingError> {
        let name = resource
            .attributes()
            .get("name")
            .and_then(|value| match value {
                AttributeValue::String(value) => Some(value.as_str()),
                _ => None,
            })
            .ok_or_else(|| CedarMappingError("resource.name missing".to_string()))?;
        Ok(uid("Repository", name))
    }
}

async fn context() -> VerifiedContext {
    let principal = verify_principal(&MockAuthenticator, &Credentials::bearer("token"))
        .await
        .expect("principal");
    VerifiedContext::from_principal(principal)
}

fn resource(name: &str) -> ResourceRef {
    let hrn: Hrn = format!("hrn:hodei:artifacts:eu:acme:repository/{name}")
        .parse()
        .expect("HRN");
    ResourceRef::new(hrn)
        .expect("resource")
        .with_attributes(BTreeMap::from([(
            "name".to_string(),
            AttributeValue::String(name.to_string()),
        )]))
}

fn request(principal: VerifiedContext, resource: ResourceRef) -> AuthorizationRequest {
    AuthorizationRequest::new(
        principal,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource,
    )
}

fn authorizer(policies: &str) -> CedarAuthorizer {
    CedarAuthorizer::from_policies_unchecked(policies, Entities::empty(), Arc::new(TestMapper))
        .expect("authorizer")
}

#[tokio::test]
async fn permit_policy_allows_the_matching_request() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );"#,
    );

    let outcome = authorizer.decide(&request(context().await, resource("repo")));
    assert_eq!(outcome, AuthorizationOutcome::Permit);
    assert_eq!(authorizer.policy_count(), 1);
}

#[tokio::test]
async fn empty_policy_set_denies_with_valid_mapping() {
    let authorizer = authorizer("");
    let outcome = authorizer.decide(&request(context().await, resource("repo")));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Deny(DenyReason::NoMatchingPolicy)
    );
}

#[tokio::test]
async fn explicit_forbid_prevails_over_permit() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );
        forbid(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );"#,
    );

    let outcome = authorizer.decide(&request(context().await, resource("repo")));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}

#[test]
fn invalid_policies_do_not_build_an_authorizer() {
    let result = CedarAuthorizer::from_policies_unchecked(
        "permit(",
        Entities::empty(),
        Arc::new(TestMapper),
    );
    assert!(matches!(result, Err(CedarSetupError::Policy(_))));
}

#[tokio::test]
async fn missing_entity_data_is_indeterminate_not_permit() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        ) when { principal.role == "admin" };"#,
    );

    let outcome = authorizer.decide(&request(context().await, resource("repo")));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
}

#[tokio::test]
async fn context_attributes_reach_the_policy() {
    let policy = r#"permit(
        principal == User::"alice",
        action == Artifacts::Action::"ReadRepository",
        resource == Repository::"repo"
    ) when { context.ip_address == "10.0.0.1" };"#;
    let authorizer = authorizer(policy);

    let permitted =
        request(context().await, resource("repo")).with_context_attributes(BTreeMap::from([(
            "ip_address".to_string(),
            AttributeValue::String("10.0.0.1".to_string()),
        )]));
    assert_eq!(authorizer.decide(&permitted), AuthorizationOutcome::Permit);

    let missing = request(context().await, resource("repo"));
    assert_eq!(
        authorizer.decide(&missing),
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
}

#[tokio::test]
async fn mapping_errors_are_indeterminate() {
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(principal, action, resource);"#,
        Entities::empty(),
        Arc::new(TestMapper),
    )
    .expect("authorizer");

    // No `name` attribute: the mapper cannot build the Cedar entity.
    let principal = verify_principal(&MockAuthenticator, &Credentials::bearer("token"))
        .await
        .unwrap();
    let hrn: Hrn = "hrn:hodei:artifacts:eu:acme:repository/repo"
        .parse()
        .unwrap();
    let resource = ResourceRef::new(hrn).unwrap();
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal),
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource,
    );

    let (outcome, diagnostic) = authorizer.decide_with_diagnostics(&request);
    assert_eq!(
        outcome,
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
    assert!(
        diagnostic.is_some(),
        "mapping diagnostics must be preserved"
    );
}

async fn role_principal() -> hodei_authz::VerifiedPrincipal {
    let claims = PrincipalClaims::new(
        PrincipalId::new("hrn:hodei:iam::acme:User/alice").unwrap(),
        AccountId::new("acme").unwrap(),
    )
    .with_attributes(BTreeMap::from([
        (
            "name".to_string(),
            AttributeValue::String("alice".to_string()),
        ),
        (
            "role".to_string(),
            AttributeValue::String("admin".to_string()),
        ),
    ]));
    verify_principal(&RoleAuthenticator { claims }, &Credentials::bearer("token"))
        .await
        .expect("role principal")
}

struct RoleAuthenticator {
    claims: PrincipalClaims,
}

#[async_trait]
impl PrincipalAuthenticator for RoleAuthenticator {
    async fn authenticate(
        &self,
        _credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        Ok(self.claims.clone())
    }
}

#[tokio::test]
async fn entity_attributes_and_entity_references_reach_the_policy() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        ) when { principal.role == "admin" && resource.owner_id == principal };"#,
    );

    let owner: Hrn = "hrn:hodei:iam::acme:User/alice".parse().unwrap();
    let resource = resource("repo").with_attributes(BTreeMap::from([
        (
            "name".to_string(),
            AttributeValue::String("repo".to_string()),
        ),
        (
            "owner_id".to_string(),
            AttributeValue::Entity(owner.to_string()),
        ),
        ("is_public".to_string(), AttributeValue::Bool(false)),
    ]));
    let principal = VerifiedContext::from_principal(role_principal().await);
    let request = AuthorizationRequest::new(
        principal,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource,
    );

    assert_eq!(authorizer.decide(&request), AuthorizationOutcome::Permit);
}

#[tokio::test]
async fn non_matching_policy_is_default_deny() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"bob",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );"#,
    );
    let outcome = authorizer.decide(&request(context().await, resource("repo")));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Deny(DenyReason::NoMatchingPolicy)
    );
}

#[tokio::test]
async fn a_forbid_that_does_not_apply_does_not_deny() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );
        forbid(
            principal == User::"bob",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );"#,
    );
    assert_eq!(
        authorizer.decide(&request(context().await, resource("repo"))),
        AuthorizationOutcome::Permit
    );
}

#[tokio::test]
async fn permit_with_an_evaluation_error_is_indeterminate() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );
        forbid(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        ) when { context.missing_attribute == "x" };"#,
    );

    let (outcome, diagnostic) =
        authorizer.decide_with_diagnostics(&request(context().await, resource("repo")));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
    assert!(diagnostic.is_some());
}

#[tokio::test]
async fn empty_policy_snapshot_does_not_hide_a_mapping_error() {
    let authorizer =
        CedarAuthorizer::from_policies_unchecked("", Entities::empty(), Arc::new(TestMapper))
            .expect("authorizer");
    let hrn: Hrn = "hrn:hodei:artifacts:eu:acme:repository/repo"
        .parse()
        .unwrap();
    let resource = ResourceRef::new(hrn).unwrap();
    let request = AuthorizationRequest::new(
        context().await,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource,
    );

    let (outcome, diagnostic) = authorizer.decide_with_diagnostics(&request);
    assert_eq!(
        outcome,
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
    assert!(diagnostic.is_some());
}

#[tokio::test]
async fn all_context_value_variants_reach_cedar() {
    let authorizer = authorizer(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        ) when {
            context.flag == true
            && context.count == 7
            && context.owner == principal
            && context.tags.contains("a")
        };"#,
    );
    let permitted =
        request(context().await, resource("repo")).with_context_attributes(BTreeMap::from([
            ("flag".to_string(), AttributeValue::Bool(true)),
            ("count".to_string(), AttributeValue::Long(7)),
            (
                "owner".to_string(),
                AttributeValue::Entity("User::\"alice\"".to_string()),
            ),
            (
                "tags".to_string(),
                AttributeValue::Set(std::collections::BTreeSet::from(["a".to_string()])),
            ),
        ]));
    let (outcome, diagnostic) = authorizer.decide_with_diagnostics(&permitted);
    assert_eq!(
        outcome,
        AuthorizationOutcome::Permit,
        "diagnostic: {diagnostic:?}"
    );

    let invalid_entity =
        request(context().await, resource("repo")).with_context_attributes(BTreeMap::from([(
            "owner".to_string(),
            AttributeValue::Entity("not-a-uid".to_string()),
        )]));
    assert_eq!(
        authorizer.decide(&invalid_entity),
        AuthorizationOutcome::Indeterminate(IndeterminateReason::EvaluationError)
    );
}

struct NamespacedMapper;

impl CedarEntityMapper for NamespacedMapper {
    fn principal_uid(
        &self,
        _principal: &hodei_authz::VerifiedPrincipal,
    ) -> Result<EntityUid, CedarMappingError> {
        Ok(uid("Artifacts::User", "alice"))
    }

    fn resource_uid(&self, _resource: &ResourceRef) -> Result<EntityUid, CedarMappingError> {
        Ok(uid("Artifacts::Repository", "repo"))
    }
}

#[tokio::test]
async fn validated_schema_path_can_permit() {
    let schema = Schema::from_json_str(
        r#"{
            "Artifacts": {
                "entityTypes": {
                    "User": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}
                    },
                    "Repository": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}
                    }
                },
                "actions": {
                    "ReadRepository": {
                        "appliesTo": {
                            "principalTypes": ["User"],
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
            principal == Artifacts::User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Artifacts::Repository::"repo"
        );"#,
        Entities::empty(),
        Arc::new(NamespacedMapper),
        schema,
    )
    .expect("validated authorizer");

    let request = AuthorizationRequest::new(
        context().await,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("repo"),
    );
    assert_eq!(authorizer.decide(&request), AuthorizationOutcome::Permit);
}

#[tokio::test]
async fn action_group_membership_is_loaded_from_the_schema() {
    let schema = Schema::from_json_str(
        r#"{
            "Artifacts": {
                "entityTypes": {
                    "User": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}
                    },
                    "Repository": {
                        "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}
                    }
                },
                "actions": {
                    "Writes": {},
                    "ReadRepository": {
                        "memberOf": [{"id": "Writes"}],
                        "appliesTo": {
                            "principalTypes": ["User"],
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
            principal,
            action == Artifacts::Action::"ReadRepository",
            resource
        );
        forbid(
            principal,
            action in Artifacts::Action::"Writes",
            resource
        );"#,
        Entities::empty(),
        Arc::new(NamespacedMapper),
        schema,
    )
    .expect("authorizer");

    let request = AuthorizationRequest::new(
        context().await,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("repo"),
    );
    assert_eq!(
        authorizer.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}

#[tokio::test]
async fn base_parents_are_preserved_when_request_entities_are_merged() {
    let principal = uid("User", "alice");
    let blocked = uid("Group", "blocked");
    let base = Entities::from_entities(
        [Entity::new(
            principal,
            std::collections::HashMap::from([(
                "name".to_string(),
                cedar_policy::RestrictedExpression::new_string("alice".to_string()),
            )]),
            std::collections::HashSet::from([blocked]),
        )
        .expect("base entity")],
        None,
    )
    .expect("base entities");
    let authorizer = CedarAuthorizer::from_policies_unchecked(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );
        forbid(
            principal,
            action,
            resource
        ) when { principal in Group::"blocked" };"#,
        base,
        Arc::new(TestMapper),
    )
    .expect("authorizer");

    let request = AuthorizationRequest::new(
        context().await,
        ActionId::new("artifacts", "ReadRepository").unwrap(),
        resource("repo"),
    );
    assert_eq!(
        authorizer.decide(&request),
        AuthorizationOutcome::Deny(DenyReason::ExplicitForbid)
    );
}

#[test]
fn schema_validation_rejects_policies_with_unknown_actions() {
    let schema = Schema::from_json_str(
        r#"{
            "": {
                "entityTypes": {
                    "User": {},
                    "Repository": {}
                },
                "actions": {}
            }
        }"#,
    )
    .expect("schema");

    let result = CedarAuthorizer::from_policies(
        r#"permit(
            principal == User::"alice",
            action == Artifacts::Action::"ReadRepository",
            resource == Repository::"repo"
        );"#,
        Entities::empty(),
        Arc::new(TestMapper),
        schema,
    );

    assert!(matches!(result, Err(CedarSetupError::Validation(_))));
}
