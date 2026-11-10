# hodei-authz-sdk-authz

Core traits and logic for the Hodei authorization framework.

> El contrato tipado de autorización (principal verificado, outcomes y puertos) está en [AUTHORIZATION.md](AUTHORIZATION.md). La evaluación Cedar pura está en [CEDAR.md](CEDAR.md).

## Overview

`hodei-authz-sdk-authz` provides the fundamental traits and abstractions for building authorization systems with Cedar Policy. It defines interfaces for policy storage, cache invalidation, and entity/action mapping.

## Features

- **PolicyStore Trait**: Abstract interface for policy storage backends
- **CacheInvalidation Trait**: Abstract interface for cache invalidation
- **Entity/Action Traits**: Map domain entities to Cedar Policy
- **Error Types**: Typed errors for better error handling
- **Schema Discovery**: Automatic Cedar schema generation via inventory

## Installation

```toml
[dependencies]
hodei-authz-sdk-authz = "0.1"
```

## Usage

### Implementing PolicyStore

```rust
use async_trait::async_trait;
use hodei_authz::{PolicyStore, PolicyStoreError};
use cedar_policy::PolicySet;

struct MyPolicyStore {
    // Your storage implementation
}

#[async_trait]
impl PolicyStore for MyPolicyStore {
    async fn create_policy(&self, content: String) -> Result<String, PolicyStoreError> {
        // Implementation
    }
    
    async fn get_policy(&self, id: &str) -> Result<Option<String>, PolicyStoreError> {
        // Implementation
    }
    
    async fn load_all_policies(&self) -> Result<PolicySet, PolicyStoreError> {
        // Implementation
    }
    
    // ... other methods
}
```

### Implementing CacheInvalidation

```rust
use async_trait::async_trait;
use hodei_authz::{CacheInvalidation, CacheError};

struct MyCacheInvalidation {
    // Your cache implementation
}

#[async_trait]
impl CacheInvalidation for MyCacheInvalidation {
    async fn invalidate_policies(&self) -> Result<(), CacheError> {
        // Publish invalidation event
    }
    
    async fn subscribe_to_invalidations<F>(&self, callback: F) -> Result<(), CacheError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Subscribe to invalidation events
    }
}
```

### Using Derive Macros

```rust
use hodei_derive::{HodeiEntity, HodeiAction};
use hodei_hrn::Hrn;
use serde::{Serialize, Deserialize};

#[derive(HodeiEntity, Serialize, Deserialize, Clone)]
#[hodei-authz-sdk(entity_type = "MyApp::User")]
struct User {
    id: Hrn,
    email: String,
    role: String,
}

#[derive(HodeiAction)]
#[hodei-authz-sdk(namespace = "MyApp")]
enum UserCommand {
    #[hodei-authz-sdk(principal = "User", resource = "User")]
    Read { id: Hrn },
    
    #[hodei-authz-sdk(principal = "User", resource = "User")]
    Update { id: Hrn },
}
```

## Traits

### PolicyStore

Abstraction for policy storage backends (PostgreSQL, file system, etc.):

- `create_policy` - Create a new policy
- `get_policy` - Retrieve a policy by ID
- `list_policies` - List all policies
- `update_policy` - Update an existing policy
- `delete_policy` - Delete a policy
- `load_all_policies` - Load all policies as a PolicySet

### CacheInvalidation

Abstraction for distributed cache invalidation:

- `invalidate_policies` - Publish invalidation event
- `subscribe_to_invalidations` - Subscribe to invalidation events

## Error Types

- `PolicyStoreError` - Errors from policy storage operations
- `CacheError` - Errors from cache operations

## Dependencies

- `cedar-policy` - Cedar Policy engine
- `hodei-authz-sdk-hrn` - Core types (HRN)
- `hodei-authz-sdk-derive` - Derive macros

## License

MIT OR Apache-2.0
