//! PostgreSQL adapter for Hodei authorization framework
//!
//! This crate provides a PostgreSQL implementation of the `PolicyStore` trait.

use async_trait::async_trait;
use cedar_policy::{Policy, PolicySet};
use hodei_authz::{PolicyStore, PolicyStoreError};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// PostgreSQL implementation of PolicyStore
pub struct PostgresPolicyStore {
    pool: PgPool,
}

impl PostgresPolicyStore {
    /// Create a new PostgreSQL policy store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await
    }
}

#[async_trait]
impl PolicyStore for PostgresPolicyStore {
    async fn create_policy(&self, content: String) -> Result<String, PolicyStoreError> {
        let policy_id = Uuid::new_v4().to_string();

        sqlx::query("INSERT INTO policies (id, content, created_at) VALUES ($1, $2, NOW())")
            .bind(&policy_id)
            .bind(&content)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        Ok(policy_id)
    }

    async fn get_policy(&self, id: &str) -> Result<Option<String>, PolicyStoreError> {
        let record = sqlx::query("SELECT content FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        Ok(record.map(|r| r.try_get("content").unwrap()))
    }

    async fn list_policies(&self) -> Result<Vec<(String, String)>, PolicyStoreError> {
        let records = sqlx::query("SELECT id, content FROM policies ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        let policies = records
            .into_iter()
            .map(|r| {
                let id: String = r.try_get("id").unwrap();
                let content: String = r.try_get("content").unwrap();
                (id, content)
            })
            .collect();

        Ok(policies)
    }

    async fn update_policy(&self, id: &str, content: String) -> Result<(), PolicyStoreError> {
        let result =
            sqlx::query("UPDATE policies SET content = $1, updated_at = NOW() WHERE id = $2")
                .bind(&content)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(PolicyStoreError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn delete_policy(&self, id: &str) -> Result<(), PolicyStoreError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(PolicyStoreError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn load_all_policies(&self) -> Result<PolicySet, PolicyStoreError> {
        let records = sqlx::query("SELECT id, content FROM policies")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

        let mut policies = Vec::new();
        for record in records {
            let db_id: String = record
                .try_get("id")
                .map_err(|e| PolicyStoreError::Database(e.to_string()))?;
            let content: String = record
                .try_get("content")
                .map_err(|e| PolicyStoreError::Database(e.to_string()))?;

            let policy_id = cedar_policy::PolicyId::new(db_id.clone());
            let policy = Policy::parse(Some(policy_id), content)
                .map_err(|e| PolicyStoreError::Parse(e.to_string()))?;
            policies.push(policy);
        }

        PolicySet::from_policies(policies).map_err(|e| PolicyStoreError::Internal(e.to_string()))
    }
}
