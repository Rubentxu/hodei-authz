//! Cedar evaluation adapter.
//!
//! The functional core stays Cedar-agnostic; this module is the adapter that
//! turns a typed [`AuthorizationRequest`] into a Cedar request and maps the
//! engine response to [`AuthorizationOutcome`]. Evaluation is deterministic,
//! pure and fail-closed: parsing, mapping or evaluation errors become
//! `Indeterminate`, never `Permit`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{
    Authorizer as CedarEngine, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema, ValidationMode, Validator,
};
use thiserror::Error;

use crate::decision::{AuthorizationOutcome, DenyReason, IndeterminateReason};
use crate::model::{
    AttributeValue, Attributes, AuthorizationRequest, ResourceRef, VerifiedPrincipal,
};
use crate::ports::Authorizer;

/// Maps typed principals/resources to Cedar entity UIDs and parents.
///
/// The evaluator builds the per-request entities and injects their attributes
/// from the request. HSP-7 owns the canonical HRN -> Cedar mapping; this seam
/// keeps the evaluator free of domain-specific type names. Implementations are
/// part of the trusted computing base and must be pure and deterministic.
pub trait CedarEntityMapper: Send + Sync {
    fn principal_uid(&self, principal: &VerifiedPrincipal) -> Result<EntityUid, CedarMappingError>;
    fn resource_uid(&self, resource: &ResourceRef) -> Result<EntityUid, CedarMappingError>;

    /// Parents of the principal entity (groups, for example).
    ///
    /// Implementations must be pure and deterministic: no IO, clock or
    /// randomness.
    fn principal_parents(
        &self,
        _principal: &VerifiedPrincipal,
    ) -> Result<HashSet<EntityUid>, CedarMappingError> {
        Ok(HashSet::new())
    }

    /// Parents of the resource entity (for example a repository container).
    fn resource_parents(
        &self,
        _resource: &ResourceRef,
    ) -> Result<HashSet<EntityUid>, CedarMappingError> {
        Ok(HashSet::new())
    }

    /// Map an `AttributeValue::Entity` reference to a Cedar UID. The default
    /// accepts a Cedar UID; HSP-7 overrides it for canonical HRN references.
    fn entity_reference(&self, value: &str) -> Result<EntityUid, CedarMappingError> {
        value.parse().map_err(|error: cedar_policy::ParseErrors| {
            CedarMappingError(format!("invalid entity reference: {error}"))
        })
    }
}

/// Error returned by a [`CedarEntityMapper`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid Cedar entity mapping: {0}")]
pub struct CedarMappingError(pub String);

/// Error while preparing a [`CedarAuthorizer`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CedarSetupError {
    #[error("invalid policy set: {0}")]
    Policy(String),
    #[error("policy validation failed: {0}")]
    Validation(String),
    #[error("invalid entity set: {0}")]
    Entities(String),
}

/// A pure Cedar evaluator over immutable policies and base entities.
#[derive(Clone)]
pub struct CedarAuthorizer {
    policy_set: PolicySet,
    entities: Entities,
    mapper: Arc<dyn CedarEntityMapper>,
    schema: Option<Schema>,
}

impl CedarAuthorizer {
    /// Parse policies, validate them against the schema, validate the base
    /// entity snapshot and let Cedar add the schema's action entities (including
    /// action groups) before the authorizer can be used. Invalid policies or
    /// entities never produce an authorizer. The schema is mandatory here.
    pub fn from_policies(
        policies: &str,
        entities: Entities,
        mapper: Arc<dyn CedarEntityMapper>,
        schema: Schema,
    ) -> Result<Self, CedarSetupError> {
        let policy_set: PolicySet =
            policies
                .parse()
                .map_err(|error: cedar_policy::ParseErrors| {
                    CedarSetupError::Policy(error.to_string())
                })?;

        let result = Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
        if !result.validation_passed() {
            let errors = result
                .validation_errors()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CedarSetupError::Validation(errors));
        }

        // Validate the base snapshot and let Cedar add the action entities
        // declared by the schema (including action groups). Without this, an
        // `action in Action::"group"` forbid would silently not match.
        let entities = Entities::from_entities(entities.iter().cloned(), Some(&schema))
            .map_err(|error| CedarSetupError::Entities(format!("{error:?}")))?;

        Ok(Self {
            policy_set,
            entities,
            mapper,
            schema: Some(schema),
        })
    }

    /// Parse policies **without** schema validation and without schema action
    /// entities. This explicit escape hatch is for tests or fully trusted
    /// static policy snapshots. Prefer [`Self::from_policies`] for production.
    pub fn from_policies_unchecked(
        policies: &str,
        entities: Entities,
        mapper: Arc<dyn CedarEntityMapper>,
    ) -> Result<Self, CedarSetupError> {
        let policy_set: PolicySet =
            policies
                .parse()
                .map_err(|error: cedar_policy::ParseErrors| {
                    CedarSetupError::Policy(error.to_string())
                })?;
        Ok(Self {
            policy_set,
            entities,
            mapper,
            schema: None,
        })
    }

    /// Number of static policies in the immutable snapshot. Templates are not
    /// included (they are not evaluable without linking).
    pub fn policy_count(&self) -> usize {
        self.policy_set.num_of_policies()
    }

    fn decide_inner(&self, request: &AuthorizationRequest) -> Result<AuthorizationOutcome, String> {
        let principal_uid = self
            .mapper
            .principal_uid(request.principal())
            .map_err(|error| error.to_string())?;
        let resource_uid = self
            .mapper
            .resource_uid(request.resource())
            .map_err(|error| error.to_string())?;
        let action: EntityUid = request
            .action()
            .to_cedar_uid()
            .parse()
            .map_err(|error: cedar_policy::ParseErrors| error.to_string())?;

        let principal_entity = merge_entity(
            self.entities.get(&principal_uid).cloned(),
            principal_uid.clone(),
            cedar_attributes(request.principal().attributes(), self.mapper.as_ref())?,
            self.mapper
                .principal_parents(request.principal())
                .map_err(|error| error.to_string())?,
        )?;
        let resource_entity = merge_entity(
            self.entities.get(&resource_uid).cloned(),
            resource_uid.clone(),
            cedar_attributes(request.resource().attributes(), self.mapper.as_ref())?,
            self.mapper
                .resource_parents(request.resource())
                .map_err(|error| error.to_string())?,
        )?;

        // Preserve base parents/attributes; the request overrides attributes
        // with the same name and adds mapper parents. A base entity with the
        // same UID is replaced by this merged entity, never dropped.
        let entities = self
            .entities
            .clone()
            .remove_entities([principal_uid.clone(), resource_uid.clone()])
            .map_err(|error| error.to_string())?
            .add_entities([principal_entity, resource_entity], self.schema.as_ref())
            .map_err(|error| format!("{error:?}"))?;

        let context = cedar_context(request.context_attributes(), self.mapper.as_ref())?;
        let cedar_request = Request::new(
            principal_uid,
            action,
            resource_uid,
            context,
            self.schema.as_ref(),
        )
        .map_err(|error| error.to_string())?;

        let response =
            CedarEngine::new().is_authorized(&cedar_request, &self.policy_set, &entities);

        let errors = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }

        match response.decision() {
            Decision::Allow => Ok(AuthorizationOutcome::Permit),
            Decision::Deny => {
                if response.diagnostics().reason().next().is_some() {
                    Ok(AuthorizationOutcome::deny(DenyReason::ExplicitForbid))
                } else {
                    Ok(AuthorizationOutcome::deny(DenyReason::NoMatchingPolicy))
                }
            }
        }
    }

    /// Decide and return the technical diagnostic when evaluation could not
    /// reach a typed decision. The outcome is still fail-closed.
    pub fn decide_with_diagnostics(
        &self,
        request: &AuthorizationRequest,
    ) -> (AuthorizationOutcome, Option<String>) {
        match self.decide_inner(request) {
            Ok(outcome) => (outcome, None),
            Err(diagnostic) => (
                AuthorizationOutcome::indeterminate(IndeterminateReason::EvaluationError),
                Some(diagnostic),
            ),
        }
    }
}

impl Authorizer for CedarAuthorizer {
    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationOutcome {
        self.decide_with_diagnostics(request).0
    }
}

fn merge_entity(
    base: Option<Entity>,
    uid: EntityUid,
    request_attributes: HashMap<String, RestrictedExpression>,
    mapper_parents: HashSet<EntityUid>,
) -> Result<Entity, String> {
    let (mut attributes, mut parents) = match base {
        Some(base) => {
            let (_, attributes, parents) = base.into_inner();
            (attributes, parents)
        }
        None => (HashMap::new(), HashSet::new()),
    };
    attributes.extend(request_attributes);
    parents.extend(mapper_parents);
    Entity::new(uid, attributes, parents).map_err(|error| error.to_string())
}

fn cedar_attributes(
    attributes: &Attributes,
    mapper: &dyn CedarEntityMapper,
) -> Result<HashMap<String, RestrictedExpression>, String> {
    attributes
        .iter()
        .map(|(name, value)| Ok((name.clone(), cedar_expression(value, mapper)?)))
        .collect()
}

fn cedar_context(
    attributes: &Attributes,
    mapper: &dyn CedarEntityMapper,
) -> Result<Context, String> {
    let pairs = attributes
        .iter()
        .map(|(name, value)| Ok((name.clone(), cedar_expression(value, mapper)?)))
        .collect::<Result<Vec<_>, String>>()?;
    Context::from_pairs(pairs).map_err(|error| error.to_string())
}

fn cedar_expression(
    value: &AttributeValue,
    mapper: &dyn CedarEntityMapper,
) -> Result<RestrictedExpression, String> {
    match value {
        AttributeValue::String(value) => Ok(RestrictedExpression::new_string(value.clone())),
        AttributeValue::Bool(value) => Ok(RestrictedExpression::new_bool(*value)),
        AttributeValue::Long(value) => Ok(RestrictedExpression::new_long(*value)),
        AttributeValue::Entity(value) => mapper
            .entity_reference(value)
            .map(RestrictedExpression::new_entity_uid)
            .map_err(|error| error.to_string()),
        AttributeValue::Set(values) => {
            Ok(RestrictedExpression::new_set(values.iter().map(|value| {
                RestrictedExpression::new_string(value.clone())
            })))
        }
    }
}
