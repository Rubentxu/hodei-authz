//! Hodei Authorization SDK
//!
//! SDK completo que proporciona una solución de autorización lista para usar
//! con auto-discovery de schema, builder pattern, y todas las integraciones.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use hodei_authz_sdk::prelude::*;
//!
//! // 1. Definir entidades con derives
//! #[derive(HodeiEntity)]
//! #[hodei(entity_type = "MyApp::User")]
//! struct User {
//!     id: Hrn,
//!     email: String,
//! }
//!
//! // 2. Configurar el servicio
//! let auth = HodeiAuthService::builder()
//!     .with_postgres(pool)
//!     .with_redis("redis://localhost:6379")
//!     .auto_discover_schema()?
//!     .build()
//!     .await?;
//! ```

pub mod builder;
pub mod schema;

pub use builder::{BuildError, HodeiAuthService, HodeiAuthServiceBuilder};
pub use schema::{SchemaError, auto_discover_schema};

/// Prelude con todos los imports comunes
pub mod prelude {
    pub use hodei_authz::*;
    pub use hodei_derive::{HodeiAction, HodeiEntity};
    pub use hodei_hrn::*;

    pub use crate::builder::{BuildError, HodeiAuthService, HodeiAuthServiceBuilder};
    pub use crate::schema::{SchemaError, auto_discover_schema};

    #[cfg(feature = "postgres")]
    pub use hodei_authz_postgres::*;

    #[cfg(feature = "redis")]
    pub use hodei_authz_redis::*;

    #[cfg(feature = "axum")]
    pub use hodei_authz_axum::*;
}

// Re-exports de los crates base
pub use hodei_authz;
pub use hodei_derive;
pub use hodei_hrn;

#[cfg(feature = "postgres")]
pub use hodei_authz_postgres;

#[cfg(feature = "redis")]
pub use hodei_authz_redis;

#[cfg(feature = "axum")]
pub use hodei_authz_axum;
