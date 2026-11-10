//! Redis cache adapter for Hodei authorization framework
//!
//! This crate provides Redis-based cache invalidation for policies.

use async_trait::async_trait;
use futures_util::stream::StreamExt;
use hodei_authz::{CacheError, CacheInvalidation};
use redis::Client;

/// Redis implementation of CacheInvalidation
pub struct RedisCacheInvalidation {
    client: Client,
}

impl RedisCacheInvalidation {
    /// Create a new Redis cache invalidation handler
    pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = Client::open(redis_url)?;

        // Test connection
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<()>(&mut conn).await?;

        Ok(Self { client })
    }
}

#[async_trait]
impl CacheInvalidation for RedisCacheInvalidation {
    async fn invalidate_policies(&self) -> Result<(), CacheError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| CacheError::Connection(e.to_string()))?;

        redis::cmd("PUBLISH")
            .arg("hodei:policy:invalidate")
            .arg("reload")
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| CacheError::Publish(e.to_string()))?;

        Ok(())
    }

    async fn subscribe_to_invalidations<F>(&self, callback: F) -> Result<(), CacheError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Note: This is a simplified implementation
        // In production, you'd want proper PubSub handling with reconnection logic

        tracing::warn!("Redis PubSub subscription is not fully implemented in this version");
        tracing::info!("Cache invalidation will work via explicit invalidate_policies() calls");

        // For now, we just acknowledge the subscription request
        // A full implementation would require:
        // 1. A dedicated PubSub connection (not MultiplexedConnection)
        // 2. Proper error handling and reconnection
        // 3. Background task management

        Ok(())
    }
}
