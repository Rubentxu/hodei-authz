//! Integration tests for PostgreSQL adapter
//!
//! Note: These tests require a running PostgreSQL instance
//! Run with: docker-compose up -d postgres

use hodei_authz::{PolicyStore, PolicyStoreError};
use hodei_authz_postgres::PostgresPolicyStore;
use sqlx::PgPool;

async fn create_test_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/hodei_test".to_string());

    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

#[tokio::test]
#[ignore] // Requires database
async fn test_create_and_get_policy() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    // Run migrations
    store.migrate().await.expect("Migration failed");

    // Create policy
    let policy_content = "permit(principal, action, resource);";
    let policy_id = store
        .create_policy(policy_content.to_string())
        .await
        .expect("Failed to create policy");

    // Get policy
    let retrieved = store
        .get_policy(&policy_id)
        .await
        .expect("Failed to get policy");

    assert_eq!(retrieved, Some(policy_content.to_string()));

    // Cleanup
    store.delete_policy(&policy_id).await.ok();
}

#[tokio::test]
#[ignore] // Requires database
async fn test_list_policies() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Create multiple policies
    let id1 = store
        .create_policy("permit(principal, action, resource);".to_string())
        .await
        .expect("Failed to create policy 1");

    let id2 = store
        .create_policy("forbid(principal, action, resource);".to_string())
        .await
        .expect("Failed to create policy 2");

    // List policies
    let policies = store
        .list_policies()
        .await
        .expect("Failed to list policies");

    assert!(policies.len() >= 2);
    assert!(policies.iter().any(|(id, _)| id == &id1));
    assert!(policies.iter().any(|(id, _)| id == &id2));

    // Cleanup
    store.delete_policy(&id1).await.ok();
    store.delete_policy(&id2).await.ok();
}

#[tokio::test]
#[ignore] // Requires database
async fn test_update_policy() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Create policy
    let policy_id = store
        .create_policy("permit(principal, action, resource);".to_string())
        .await
        .expect("Failed to create policy");

    // Update policy
    let new_content = "forbid(principal, action, resource);";
    store
        .update_policy(&policy_id, new_content.to_string())
        .await
        .expect("Failed to update policy");

    // Verify update
    let retrieved = store
        .get_policy(&policy_id)
        .await
        .expect("Failed to get policy");

    assert_eq!(retrieved, Some(new_content.to_string()));

    // Cleanup
    store.delete_policy(&policy_id).await.ok();
}

#[tokio::test]
#[ignore] // Requires database
async fn test_delete_policy() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Create policy
    let policy_id = store
        .create_policy("permit(principal, action, resource);".to_string())
        .await
        .expect("Failed to create policy");

    // Delete policy
    store
        .delete_policy(&policy_id)
        .await
        .expect("Failed to delete policy");

    // Verify deletion
    let retrieved = store
        .get_policy(&policy_id)
        .await
        .expect("Failed to get policy");

    assert_eq!(retrieved, None);
}

#[tokio::test]
#[ignore] // Requires database
async fn test_load_all_policies() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Create policies
    let id1 = store
        .create_policy(r#"permit(principal, action == Action::"Read", resource);"#.to_string())
        .await
        .expect("Failed to create policy 1");

    let id2 = store
        .create_policy(r#"permit(principal, action == Action::"Write", resource);"#.to_string())
        .await
        .expect("Failed to create policy 2");

    // Load all policies as PolicySet
    let policy_set = store
        .load_all_policies()
        .await
        .expect("Failed to load policies");

    // Verify policies are loaded
    // Note: We can't easily inspect PolicySet, but we can verify it was created

    // Cleanup
    store.delete_policy(&id1).await.ok();
    store.delete_policy(&id2).await.ok();
}

#[tokio::test]
#[ignore] // Requires database
async fn test_update_nonexistent_policy() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Try to update non-existent policy
    let result = store
        .update_policy("nonexistent-id", "content".to_string())
        .await;

    assert!(matches!(result, Err(PolicyStoreError::NotFound(_))));
}

#[tokio::test]
#[ignore] // Requires database
async fn test_delete_nonexistent_policy() {
    let pool = create_test_pool().await;
    let store = PostgresPolicyStore::new(pool);

    store.migrate().await.expect("Migration failed");

    // Try to delete non-existent policy
    let result = store.delete_policy("nonexistent-id").await;

    assert!(matches!(result, Err(PolicyStoreError::NotFound(_))));
}
