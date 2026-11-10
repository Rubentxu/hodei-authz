//! Trusted authorization context and request types.
//!
//! # Trust boundary
//!
//! [`PrincipalClaims`] is unverified data. [`VerifiedPrincipal`] has private
//! fields and is only produced by [`crate::ports::verify_principal`], which
//! requires a [`crate::ports::PrincipalAuthenticator`]. There is no implicit
//! `From<HeaderMap>`, no public constructor and no serde path that turns a
//! header into a verified principal by accident.
//!
//! The authenticator implementation is part of the trusted computing base: an
//! adapter that ignores the credential and copies `x-tenant-id` defeats the
//! contract. The trait only makes that trust decision explicit and reviewable.
//!
//! ```compile_fail,E0451
//! use hodei_authz::model::{AccountId, PrincipalId, VerifiedPrincipal};
//! let _forged = VerifiedPrincipal {
//!     subject: PrincipalId::new("attacker").unwrap(),
//!     account: AccountId::new("victim").unwrap(),
//!     groups: Default::default(),
//!     attributes: Default::default(),
//! };
//! ```
//!
//! ```compile_fail,E0308
//! use hodei_authz::model::{AccountId, PrincipalClaims, PrincipalId, VerifiedContext};
//! let claims = PrincipalClaims::new(
//!     PrincipalId::new("attacker").unwrap(),
//!     AccountId::new("victim").unwrap(),
//! );
//! let _ = VerifiedContext::from_principal(claims);
//! ```
//!
//! ```compile_fail,E0277
//! use hodei_authz::model::{AccountId, PrincipalClaims, PrincipalId, VerifiedPrincipal};
//! let claims = PrincipalClaims::new(
//!     PrincipalId::new("attacker").unwrap(),
//!     AccountId::new("victim").unwrap(),
//! );
//! let _: VerifiedPrincipal = claims.into();
//! ```
//!
//! ```compile_fail,E0277
//! // There is no serde path to a verified principal.
//! let _: hodei_authz::VerifiedPrincipal = serde_json::from_str("{}").unwrap();
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use hodei_hrn::Hrn;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Attribute value carried by a principal, resource or request context.
///
/// It is a small, Cedar-agnostic ADT; HSP-6 maps it to Cedar values. Keeping
/// it here avoids making the domain depend on `cedar-policy`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    String(String),
    Bool(bool),
    Long(i64),
    /// Reference to another Cedar entity (for example an owner).
    Entity(String),
    Set(BTreeSet<String>),
}

pub type Attributes = BTreeMap<String, AttributeValue>;

/// Invalid model value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ModelError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("invalid resource HRN")]
    InvalidResourceHrn,
}

/// Account (tenant) identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || !value
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ModelError::InvalidIdentifier("account"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Authenticated subject identifier (normally an HRN).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || !value.is_ascii()
            || value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(ModelError::InvalidIdentifier("principal"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Group identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(String);

impl GroupId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ':')
        {
            return Err(ModelError::InvalidIdentifier("group"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unverified claims returned by an authenticator adapter.
///
/// These claims are **not** a security context. Only
/// [`crate::ports::verify_principal`] turns them into a
/// [`VerifiedPrincipal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalClaims {
    subject: PrincipalId,
    account: AccountId,
    groups: BTreeSet<GroupId>,
    attributes: Attributes,
}

impl PrincipalClaims {
    pub fn new(subject: PrincipalId, account: AccountId) -> Self {
        Self {
            subject,
            account,
            groups: BTreeSet::new(),
            attributes: Attributes::new(),
        }
    }

    pub fn with_groups(mut self, groups: impl IntoIterator<Item = GroupId>) -> Self {
        self.groups = groups.into_iter().collect();
        self
    }

    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn subject(&self) -> &PrincipalId {
        &self.subject
    }

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    pub fn groups(&self) -> &BTreeSet<GroupId> {
        &self.groups
    }

    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }
}

/// A principal whose credentials were accepted by an authenticator.
///
/// Fields are private and there is no public constructor: outside this crate
/// the only way to obtain one is [`crate::ports::verify_principal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrincipal {
    subject: PrincipalId,
    account: AccountId,
    groups: BTreeSet<GroupId>,
    attributes: Attributes,
}

impl VerifiedPrincipal {
    pub(crate) fn from_claims(claims: PrincipalClaims) -> Self {
        Self {
            subject: claims.subject,
            account: claims.account,
            groups: claims.groups,
            attributes: claims.attributes,
        }
    }

    pub fn subject(&self) -> &PrincipalId {
        &self.subject
    }

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    pub fn groups(&self) -> &BTreeSet<GroupId> {
        &self.groups
    }

    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }
}

/// A verified principal plus the trusted request context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContext {
    principal: VerifiedPrincipal,
}

impl VerifiedContext {
    pub fn from_principal(principal: VerifiedPrincipal) -> Self {
        Self { principal }
    }

    pub fn principal(&self) -> &VerifiedPrincipal {
        &self.principal
    }

    pub fn account(&self) -> &AccountId {
        self.principal.account()
    }
}

/// Resource identity plus the account scope it belongs to.
///
/// The account is derived from the HRN's account field, not supplied as an
/// independent value. The HRN is the published `hodei-hrn` canonical type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    hrn: Hrn,
    account: AccountId,
    attributes: Attributes,
}

impl ResourceRef {
    pub fn new(hrn: Hrn) -> Result<Self, ModelError> {
        if hrn.partition().is_empty()
            || hrn.service().is_empty()
            || hrn.resource_type().is_empty()
            || hrn.resource_path().is_empty()
            || hrn.service() != hrn.service().to_ascii_lowercase()
            || hrn.resource_type().eq_ignore_ascii_case("action")
            || !valid_hrn_part(hrn.service())
            || !valid_hrn_part(hrn.resource_type())
            || !valid_hrn_part(hrn.resource_path())
        {
            return Err(ModelError::InvalidResourceHrn);
        }
        let account = AccountId::new(hrn.account().to_string())?;
        Ok(Self {
            hrn,
            account,
            attributes: Attributes::new(),
        })
    }

    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn hrn(&self) -> &Hrn {
        &self.hrn
    }

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// Whether the resource belongs to `account`.
    #[must_use]
    pub fn is_in_account(&self, account: &AccountId) -> bool {
        &self.account == account
    }
}

impl FromStr for ResourceRef {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hrn: Hrn = value.parse().map_err(|_| ModelError::InvalidResourceHrn)?;
        Self::new(hrn)
    }
}

/// Authorization action identity, canonical with the HRN contract.
///
/// Namespace construction is injective: `-` becomes `_` and the first letter
/// is uppercased, so `a-1` and `a1` cannot collide. This type mirrors the
/// canonical `hodei-hrn` contract; HSP-2/HSP-7 replace it with a re-export
/// when that crate is published in this workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionId {
    service: String,
    name: String,
}

impl ActionId {
    pub fn new(service: impl Into<String>, name: impl Into<String>) -> Result<Self, ModelError> {
        let service = service.into().to_ascii_lowercase();
        let name = name.into();
        if !valid_service(&service) {
            return Err(ModelError::InvalidIdentifier("action service"));
        }
        if !valid_action_name(&name) {
            return Err(ModelError::InvalidIdentifier("action name"));
        }
        Ok(Self { service, name })
    }

    /// Parse a canonical Cedar action UID (`Service::Action::"name"`).
    pub fn from_cedar_uid(input: &str) -> Result<Self, ModelError> {
        if input.len() > 512 {
            return Err(ModelError::InvalidIdentifier("action UID"));
        }
        let (namespace, quoted) = input
            .split_once("::Action::\"")
            .ok_or(ModelError::InvalidIdentifier("action UID"))?;
        let name = quoted
            .strip_suffix('"')
            .ok_or(ModelError::InvalidIdentifier("action UID"))?;
        if name.contains('"') {
            return Err(ModelError::InvalidIdentifier("action UID"));
        }
        let service = namespace.to_ascii_lowercase().replace('_', "-");
        let action = Self::new(service, name)?;
        if action.to_cedar_uid() != input {
            return Err(ModelError::InvalidIdentifier("action UID"));
        }
        Ok(action)
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn to_cedar_uid(&self) -> String {
        format!("{}::Action::\"{}\"", namespace(&self.service), self.name)
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_cedar_uid())
    }
}

impl FromStr for ActionId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_cedar_uid(s)
    }
}

impl Serialize for ActionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_cedar_uid())
    }
}

impl<'de> Deserialize<'de> for ActionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ActionId::from_cedar_uid(&raw).map_err(D::Error::custom)
    }
}

/// A complete request to authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    context: VerifiedContext,
    action: ActionId,
    resource: ResourceRef,
    context_attributes: Attributes,
}

impl AuthorizationRequest {
    pub fn new(context: VerifiedContext, action: ActionId, resource: ResourceRef) -> Self {
        Self {
            context,
            action,
            resource,
            context_attributes: Attributes::new(),
        }
    }

    pub fn with_context_attributes(mut self, attributes: Attributes) -> Self {
        self.context_attributes = attributes;
        self
    }

    pub fn context(&self) -> &VerifiedContext {
        &self.context
    }

    pub fn principal(&self) -> &VerifiedPrincipal {
        self.context.principal()
    }

    pub fn account(&self) -> &AccountId {
        self.context.account()
    }

    pub fn action(&self) -> &ActionId {
        &self.action
    }

    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    pub fn context_attributes(&self) -> &Attributes {
        &self.context_attributes
    }

    /// Whether the verified principal and the resource share an account.
    ///
    /// A cross-account request is not rejected here: an explicit policy may
    /// authorize it. The resource account is derived from its HRN.
    #[must_use]
    pub fn is_same_account(&self) -> bool {
        self.context.account() == self.resource.account()
    }
}

/// Credentials supplied by an adapter, never a verified identity.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credentials {
    Bearer(String),
}

impl Credentials {
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(token.into())
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
        }
    }
}

fn valid_service(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.ends_with('-')
}

fn valid_hrn_part(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\')
}

fn valid_action_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn namespace(service: &str) -> String {
    let first = service
        .chars()
        .next()
        .expect("validated service is non-empty")
        .to_ascii_uppercase();
    let rest: String = service
        .chars()
        .skip(1)
        .map(|c| if c == '-' { '_' } else { c })
        .collect();
    format!("{first}{rest}")
}
