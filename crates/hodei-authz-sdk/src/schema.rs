//! Auto-discovery de schema Cedar usando inventory
//!
//! Este módulo recolecta automáticamente todos los EntitySchemaFragment y ActionSchemaFragment
//! registrados por los derives HodeiEntity y HodeiAction.

use cedar_policy::Schema;
use hodei_authz::{ActionSchemaFragment, EntitySchemaFragment};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Error al generar el schema
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("Error parsing schema: {0}")]
    ParseError(String),
    #[error("Invalid schema structure: {0}")]
    InvalidStructure(String),
}

/// Genera el schema Cedar automáticamente desde los fragments registrados con inventory
///
/// # Ejemplo
///
/// ```rust,ignore
/// use hodei_authz_sdk::schema::auto_discover_schema;
///
/// let schema = auto_discover_schema()?;
/// ```
pub fn auto_discover_schema() -> Result<Schema, SchemaError> {
    let mut namespaces: HashMap<String, Value> = HashMap::new();

    // Recolectar entity fragments
    for fragment in hodei_authz::inventory::iter::<EntitySchemaFragment>() {
        tracing::debug!("Discovered entity: {}", fragment.entity_type);
        merge_entity_fragment(&mut namespaces, fragment);
    }

    // Recolectar action fragments
    for fragment in hodei_authz::inventory::iter::<ActionSchemaFragment>() {
        tracing::debug!("Discovered action: {}", fragment.name);
        merge_action_fragment(&mut namespaces, fragment);
    }

    // Construir el schema final
    let schema_json = json!(namespaces);

    tracing::info!("Generated schema with {} namespaces", namespaces.len());

    Schema::from_json_str(&schema_json.to_string())
        .map_err(|e| SchemaError::ParseError(e.to_string()))
}

/// Merge un EntitySchemaFragment en el schema
fn merge_entity_fragment(namespaces: &mut HashMap<String, Value>, fragment: &EntitySchemaFragment) {
    // Parsear el entity_type para extraer namespace y entity name
    // Formato esperado: "Namespace::EntityName"
    let parts: Vec<&str> = fragment.entity_type.split("::").collect();
    if parts.len() != 2 {
        tracing::warn!("Invalid entity_type format: {}", fragment.entity_type);
        return;
    }

    let namespace = parts[0];
    let entity_name = parts[1];

    // Obtener o crear el namespace
    let ns = namespaces.entry(namespace.to_string()).or_insert_with(|| {
        json!({
            "entityTypes": {},
            "actions": {}
        })
    });

    // Agregar el entity type
    if let Some(entity_types) = ns.get_mut("entityTypes") {
        if let Some(obj) = entity_types.as_object_mut() {
            obj.insert(
                entity_name.to_string(),
                serde_json::from_str(&fragment.fragment_json).unwrap_or_else(|_| json!({})),
            );
        }
    }
}

/// Merge un ActionSchemaFragment en el schema
fn merge_action_fragment(namespaces: &mut HashMap<String, Value>, fragment: &ActionSchemaFragment) {
    // Parsear el name para extraer namespace
    // Formato esperado: "Namespace::ActionName" o "Namespace::Resource::ActionName"
    let parts: Vec<&str> = fragment.name.split("::").collect();
    if parts.is_empty() {
        tracing::warn!("Invalid action name format: {}", fragment.name);
        return;
    }

    let namespace = parts[0];
    let action_key = parts[1..].join("::");

    // Obtener o crear el namespace
    let ns = namespaces.entry(namespace.to_string()).or_insert_with(|| {
        json!({
            "entityTypes": {},
            "actions": {}
        })
    });

    // Agregar la action
    if let Some(actions) = ns.get_mut("actions") {
        if let Some(obj) = actions.as_object_mut() {
            obj.insert(
                action_key,
                serde_json::from_str(&fragment.fragment_json).unwrap_or_else(|_| json!({})),
            );
        }
    }
}

/// Genera un schema de ejemplo para testing
pub fn example_schema() -> Result<Schema, SchemaError> {
    let schema_json = json!({
        "DocApp": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "email": { "type": "String" },
                            "name": { "type": "String" },
                            "role": { "type": "String" }
                        }
                    }
                },
                "Document": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "owner_id": { "type": "Entity", "name": "User" },
                            "title": { "type": "String" },
                            "content": { "type": "String" },
                            "is_public": { "type": "Boolean" }
                        }
                    }
                }
            },
            "actions": {
                "Document::Read": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Document"]
                    }
                },
                "Document::Update": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Document"]
                    }
                }
            }
        }
    });

    Schema::from_json_str(&schema_json.to_string())
        .map_err(|e| SchemaError::ParseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_schema() {
        let schema = example_schema();
        assert!(schema.is_ok());
    }
}
