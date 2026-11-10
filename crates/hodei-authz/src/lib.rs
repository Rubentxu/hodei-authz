//! Core authorization traits and the typed authorization contract.
//!
//! `async_trait` expands to a `#[must_use]` future and current clippy reports
//! `double_must_use` on the expansion, not on this crate's code.
#![allow(clippy::double_must_use)]

pub mod api;
pub mod cedar;
pub mod decision;
pub mod hrn_mapper;
pub mod model;
pub mod ports;
pub mod traits;

pub use hodei_derive::{HodeiAction, HodeiEntity};
pub use hodei_hrn;
pub use inventory;

pub use api::{
    ActionSchemaFragment, EntitySchemaFragment, RuntimeHodeiActionMapper, RuntimeHodeiEntityMapper,
};
pub use cedar::{CedarAuthorizer, CedarEntityMapper, CedarMappingError, CedarSetupError};
pub use decision::{AuthorizationOutcome, DenyReason, IndeterminateReason};
pub use hrn_mapper::HrnCedarMapper;
pub use model::{
    AccountId, ActionId, AttributeValue, Attributes, AuthorizationRequest, Credentials, GroupId,
    ModelError, PrincipalClaims, PrincipalId, ResourceRef, VerifiedContext, VerifiedPrincipal,
};
pub use ports::{AuthenticationError, Authorizer, PrincipalAuthenticator, verify_principal};
pub use traits::{CacheError, CacheInvalidation, PolicyStore, PolicyStoreError};

inventory::collect!(api::EntitySchemaFragment);
inventory::collect!(api::ActionSchemaFragment);
