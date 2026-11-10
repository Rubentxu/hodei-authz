# Hodei Authorization Framework

Cedar Policy-based authorization framework for Rust applications, inspired by AWS IAM.

## Overview

Hodei is a complete authorization framework that provides:

> **Security status (2026-11-10).** The published `hodei-authz-axum 0.1.0`
> forwards protected requests without authorizing them. This source tree fixes
> it as `0.1.1`, which is not published yet. While `0.1.1` is unpublished, a
> fresh install of SDK `0.1.0` still resolves the vulnerable axum `0.1.0`;
> once axum `0.1.1` is published, the SDK's `^0.1.0` requirement admits it. A
> new SDK release is only needed to publish the source changes in this branch,
> not to receive the axum fix.


- **Cedar Policy Engine**: Policy-based access control using Amazon's Cedar
- **Multi-Tenancy**: Built-in tenant isolation with HRN (Hodei Resource Name)
- **Derive Macros**: Automatic code generation for entities and actions
- **Database Adapters**: PostgreSQL and Redis support out of the box
- **Web Integration**: Axum middleware (fail-closed; extractors not enabled yet)
- **Type-Safe**: Leverages Rust's type system for compile-time safety

## Quick Start

### Installation

```toml
[dependencies]
hodei-authz-sdk = { version = "0.1", features = ["full"] }
```

### Define Your Domain

```rust
use hodei-authz-sdk::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(HodeiEntity, Serialize, Deserialize, Clone)]
#[hodei-authz-sdk(entity_type = "MyApp::User")]
struct User {
    id: Hrn,
    email: String,
    role: String,
}

#[derive(HodeiEntity, Serialize, Deserialize, Clone)]
#[hodei-authz-sdk(entity_type = "MyApp::Document")]
struct Document {
    id: Hrn,
    #[entity_type = "MyApp::User"]
    owner_id: Hrn,
    title: String,
}

#[derive(HodeiAction)]
#[hodei-authz-sdk(namespace = "MyApp")]
enum DocumentCommand {
    #[hodei-authz-sdk(principal = "User", resource = "Document")]
    Read { id: Hrn },
    
    #[hodei-authz-sdk(principal = "User", resource = "Document")]
    Update { id: Hrn },
    
    #[hodei-authz-sdk(principal = "User", resource = "Document", creates_resource)]
    Create { title: String },
}
```

### Write Cedar Policies

```cedar
// Only document owner can read
permit(
    principal,
    action == Action::"Document::Read",
    resource
) when {
    resource.owner_id == principal
};

// Admins can do anything
permit(
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};
```

### Use in Your Application

```rust
use hodei_postgres::PostgresPolicyStore;
use hodei_redis::RedisCacheInvalidation;
use hodei_authz::{PolicyStore, CacheInvalidation};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup database
    let pool = PgPool::connect("postgres://...").await?;
    let store = PostgresPolicyStore::new(pool);
    store.migrate().await?;
    
    // Setup cache invalidation
    let cache = RedisCacheInvalidation::new("redis://...").await?;
    
    // Load policies
    let policy_set = store.load_all_policies().await?;
    
    // Check authorization
    use cedar_policy::{Authorizer, Request, Entities};
    
    let authorizer = Authorizer::new();
    let decision = authorizer.is_authorized(&request, &policy_set, &entities);
    
    if decision.decision() == Decision::Allow {
        println!("Access granted!");
    }
    
    Ok(())
}
```

## Features

### Core Features

- `default` - Core functionality (kernel + core + derive)
- `postgres` - PostgreSQL adapter
- `redis` - Redis cache invalidation
- `axum` - Axum fail-closed middleware (extractors not enabled yet)
- `full` - All features enabled (includes the `axum` caveat)

```toml
# Minimal installation
[dependencies]
hodei-authz-sdk = "0.1"

# With database support
[dependencies]
hodei-authz-sdk = { version = "0.1", features = ["postgres", "redis"] }

# Everything
[dependencies]
hodei-authz-sdk = { version = "0.1", features = ["full"] }
```

## Architecture

Hodei is composed of several crates:

- **hodei-authz-sdk-hrn**: Core types (HRN)
- **hodei-authz-sdk-derive**: Derive macros
- **hodei-authz-sdk-authz**: Traits and logic
- **hodei-authz-sdk-authz-postgres**: PostgreSQL adapter
- **hodei-authz-sdk-authz-redis**: Redis adapter
- **hodei-authz-sdk-authz-axum**: Axum integration
- **hodei-authz-sdk**: Meta-crate (this crate)

## Examples

### Basic Authorization

```rust
use hodei-authz-sdk::prelude::*;

let user = User {
    id: Hrn::builder()
        .service("myapp")
        .tenant_id("tenant-1")
        .resource("user/alice")
        .unwrap()
        .build()
        .unwrap(),
    email: "alice@example.com".to_string(),
    role: "user".to_string(),
};

// Check if user can read document
let can_read = check_authorization(
    &user,
    DocumentCommand::Read { id: document.id.clone() },
    &document,
).await?;
```

### With Axum

> **Not available in this release.** `hodei-authz-axum` is fail-closed: its
> middleware denies every protected request and its extractors are disabled
> until a verified authorizer is wired. See the
> [axum crate README](https://github.com/Rubentxu/hodei-authz/blob/main/crates/hodei-authz-axum/README.md).

## Documentation

- [Getting Started Guide](https://docs.rs/hodei-authz-sdk)
- [API Documentation](https://docs.rs/hodei-authz-sdk)
- [Examples](https://github.com/yourusername/hodei-authz-sdk/tree/main/examples)

## License

MIT OR Apache-2.0
