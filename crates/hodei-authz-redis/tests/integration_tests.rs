//! Integration tests for Redis adapter
//!
//! Note: These tests require a running Redis instance
//! Run with: docker-compose up -d redis

use hodei_authz::CacheInvalidation;
use hodei_authz_redis::RedisCacheInvalidation;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
#[ignore] // Requires Redis
async fn test_redis_connection() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let cache = RedisCacheInvalidation::new(&redis_url)
        .await
        .expect("Failed to connect to Redis");

    // If we get here, connection was successful
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_invalidate_policies() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let cache = RedisCacheInvalidation::new(&redis_url)
        .await
        .expect("Failed to connect to Redis");

    // Publish invalidation
    cache
        .invalidate_policies()
        .await
        .expect("Failed to invalidate policies");
}

#[tokio::test]
#[ignore] // Requires Redis - This test is complex and may timeout
async fn test_pubsub_invalidation() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let cache_publisher = RedisCacheInvalidation::new(&redis_url)
        .await
        .expect("Failed to connect to Redis");

    let cache_subscriber = RedisCacheInvalidation::new(&redis_url)
        .await
        .expect("Failed to connect to Redis");

    let received = Arc::new(Mutex::new(false));
    let received_clone = received.clone();

    // Spawn subscriber in background
    let subscriber_handle = tokio::spawn(async move {
        let result = cache_subscriber
            .subscribe_to_invalidations(move || {
                *received_clone.lock().unwrap() = true;
            })
            .await;

        result
    });

    // Give subscriber time to connect
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish invalidation
    cache_publisher
        .invalidate_policies()
        .await
        .expect("Failed to publish invalidation");

    // Give time for message to be received
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if message was received
    let was_received = *received.lock().unwrap();

    // Cancel subscriber
    subscriber_handle.abort();

    assert!(was_received, "Invalidation message was not received");
}
