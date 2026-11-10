//! HRN -> Cedar identity mapping.
//!
//! Cedar entity identities must be stable, injective and preserve the full HRN
//! scope (partition, service, region, account and resource type/id). This
//! mapper uses the complete canonical HRN string as the Cedar entity id and a
//! namespaced type derived from the HRN service and resource type.

use std::collections::HashSet;

use cedar_policy::{EntityId, EntityTypeName, EntityUid};
use hodei_hrn::Hrn;

use crate::cedar::{CedarEntityMapper, CedarMappingError};
use crate::model::{AccountId, GroupId, ResourceRef, VerifiedPrincipal};

/// Production mapper for the MVP.
///
/// - Entity type: `<Service>::<ResourceType>` with capitalized, validated segments.
/// - Entity id: the full canonical HRN, so the account/region/service are part
///   of the UID and two local ids in different accounts never collide.
/// - Groups: `Iam::Group::"hrn:hodei:iam::<account>:Group/<group>"`.
/// - Resource parents: prefixes of `resource_id` split by `/`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HrnCedarMapper;

impl HrnCedarMapper {
    pub fn new() -> Self {
        Self
    }

    /// Map a full HRN to a Cedar entity UID.
    pub fn hrn_to_uid(hrn: &Hrn) -> Result<EntityUid, CedarMappingError> {
        validate_hrn(hrn)?;
        let type_name: EntityTypeName =
            entity_type(hrn)
                .parse()
                .map_err(|error: cedar_policy::ParseErrors| {
                    CedarMappingError(format!("invalid Cedar type for HRN: {error}"))
                })?;
        let id: EntityId = match hrn.to_string().parse() {
            Ok(id) => id,
            Err(never) => match never {},
        };
        Ok(EntityUid::from_type_name_and_id(type_name, id))
    }

    /// UID for a group in an account. The account is embedded so the same
    /// group name in two accounts cannot collide.
    pub fn group_uid(account: &AccountId, group: &GroupId) -> Result<EntityUid, CedarMappingError> {
        let hrn = Hrn {
            partition: "hodei".to_string(),
            service: "iam".to_string(),
            region: String::new(),
            tenant_id: account.as_str().to_string(),
            resource_type: "Group".to_string(),
            resource_id: group.as_str().to_string(),
        };
        Self::hrn_to_uid(&hrn)
    }
}

impl CedarEntityMapper for HrnCedarMapper {
    fn principal_uid(&self, principal: &VerifiedPrincipal) -> Result<EntityUid, CedarMappingError> {
        let hrn: Hrn = principal
            .subject()
            .as_str()
            .parse()
            .map_err(|error| CedarMappingError(format!("principal is not an HRN: {error}")))?;
        if hrn.service != "iam" || !matches!(hrn.resource_type.as_str(), "User" | "ServiceAccount")
        {
            return Err(CedarMappingError(
                "principal HRN must be an IAM User or ServiceAccount".to_string(),
            ));
        }
        Self::hrn_to_uid(&hrn)
    }

    fn resource_uid(&self, resource: &ResourceRef) -> Result<EntityUid, CedarMappingError> {
        Self::hrn_to_uid(resource.hrn())
    }

    fn principal_parents(
        &self,
        principal: &VerifiedPrincipal,
    ) -> Result<HashSet<EntityUid>, CedarMappingError> {
        principal
            .groups()
            .iter()
            .map(|group| Self::group_uid(principal.account(), group))
            .collect()
    }

    fn resource_parents(
        &self,
        resource: &ResourceRef,
    ) -> Result<HashSet<EntityUid>, CedarMappingError> {
        let hrn = resource.hrn();
        let segments: Vec<&str> = hrn.resource_id.split('/').collect();
        let mut parents = HashSet::new();
        for end in 1..segments.len() {
            let mut parent = hrn.clone();
            parent.resource_id = segments[..end].join("/");
            parents.insert(Self::hrn_to_uid(&parent)?);
        }
        Ok(parents)
    }

    fn entity_reference(&self, value: &str) -> Result<EntityUid, CedarMappingError> {
        let hrn: Hrn = value.parse().map_err(|error| {
            CedarMappingError(format!("entity reference is not an HRN: {error}"))
        })?;
        Self::hrn_to_uid(&hrn)
    }
}

fn entity_type(hrn: &Hrn) -> String {
    format!("{}::{}", pascal(&hrn.service), pascal(&hrn.resource_type))
}

fn pascal(segment: &str) -> String {
    let sanitized = sanitize(segment);
    let mut characters = sanitized.chars();
    match characters.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
        None => "_".to_string(),
    }
}

fn sanitize(segment: &str) -> String {
    let mut sanitized: String = segment
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        sanitized.push('_');
    }
    if !sanitized
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
    {
        sanitized.insert(0, '_');
    }
    sanitized
}

fn validate_hrn(hrn: &Hrn) -> Result<(), CedarMappingError> {
    if !valid_partition(&hrn.partition)
        || !valid_service(&hrn.service)
        || !valid_region(&hrn.region)
        || !valid_account(&hrn.tenant_id)
        || !valid_resource_type(&hrn.resource_type)
        || !valid_resource_id(&hrn.resource_id)
    {
        return Err(CedarMappingError(
            "HRN does not match the canonical segment grammar".to_string(),
        ));
    }
    Ok(())
}

fn valid_partition(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ':'
        })
}

fn valid_service(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase())
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && !value.ends_with('-')
}

fn valid_region(value: &str) -> bool {
    value.is_empty()
        || (value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase())
            && value.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            }))
}

fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

fn valid_resource_type(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || character == '"'
                || character == '\\'
        })
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
