//! Tests for core traits

use async_trait::async_trait;
use cedar_policy::PolicySet;
use hodei_authz::{CacheError, CacheInvalidation, PolicyStore, PolicyStoreError};

// Mock implementations for testing

struct MockPolicyStore {
    policies: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl MockPolicyStore {
    fn new() -> Self {
        Self {
            policies: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait]
impl PolicyStore for MockPolicyStore {
    async fn create_policy(&self, content: String) -> Result<String, PolicyStoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        self.policies.lock().unwrap().insert(id.clone(), content);
        Ok(id)
    }

    async fn get_policy(&self, id: &str) -> Result<Option<String>, PolicyStoreError> {
        Ok(self.policies.lock().unwrap().get(id).cloned())
    }

    async fn list_policies(&self) -> Result<Vec<(String, String)>, PolicyStoreError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    async fn update_policy(&self, id: &str, content: String) -> Result<(), PolicyStoreError> {
        let mut policies = self.policies.lock().unwrap();
        if policies.contains_key(id) {
            policies.insert(id.to_string(), content);
            Ok(())
        } else {
            Err(PolicyStoreError::NotFound(id.to_string()))
        }
    }

    async fn delete_policy(&self, id: &str) -> Result<(), PolicyStoreError> {
        let mut policies = self.policies.lock().unwrap();
        if policies.remove(id).is_some() {
            Ok(())
        } else {
            Err(PolicyStoreError::NotFound(id.to_string()))
        }
    }

    async fn load_all_policies(&self) -> Result<PolicySet, PolicyStoreError> {
        Ok(PolicySet::new())
    }
}

struct MockCacheInvalidation {
    invalidation_count: std::sync::Arc<std::sync::Mutex<usize>>,
}

impl MockCacheInvalidation {
    fn new() -> Self {
        Self {
            invalidation_count: std::sync::Arc::new(std::sync::Mutex::new(0)),
        }
    }

    fn get_count(&self) -> usize {
        *self.invalidation_count.lock().unwrap()
    }
}

#[async_trait]
impl CacheInvalidation for MockCacheInvalidation {
    async fn invalidate_policies(&self) -> Result<(), CacheError> {
        *self.invalidation_count.lock().unwrap() += 1;
        Ok(())
    }

    async fn subscribe_to_invalidations<F>(&self, _callback: F) -> Result<(), CacheError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        Ok(())
    }
}

#[tokio::test]
async fn test_mock_policy_store_create() {
    let store = MockPolicyStore::new();

    let id = store
        .create_policy("test policy".to_string())
        .await
        .expect("Failed to create policy");

    assert!(!id.is_empty());
}

#[tokio::test]
async fn test_mock_policy_store_get() {
    let store = MockPolicyStore::new();

    let id = store
        .create_policy("test policy".to_string())
        .await
        .unwrap();

    let policy = store.get_policy(&id).await.expect("Failed to get policy");

    assert_eq!(policy, Some("test policy".to_string()));
}

#[tokio::test]
async fn test_mock_policy_store_update() {
    let store = MockPolicyStore::new();

    let id = store.create_policy("original".to_string()).await.unwrap();

    store
        .update_policy(&id, "updated".to_string())
        .await
        .expect("Failed to update policy");

    let policy = store.get_policy(&id).await.unwrap();

    assert_eq!(policy, Some("updated".to_string()));
}

#[tokio::test]
async fn test_mock_policy_store_delete() {
    let store = MockPolicyStore::new();

    let id = store.create_policy("test".to_string()).await.unwrap();

    store
        .delete_policy(&id)
        .await
        .expect("Failed to delete policy");

    let policy = store.get_policy(&id).await.unwrap();

    assert_eq!(policy, None);
}

#[tokio::test]
async fn test_mock_policy_store_list() {
    let store = MockPolicyStore::new();

    let id1 = store.create_policy("policy1".to_string()).await.unwrap();
    let id2 = store.create_policy("policy2".to_string()).await.unwrap();

    let policies = store
        .list_policies()
        .await
        .expect("Failed to list policies");

    assert_eq!(policies.len(), 2);
    assert!(policies.iter().any(|(id, _)| id == &id1));
    assert!(policies.iter().any(|(id, _)| id == &id2));
}

#[tokio::test]
async fn test_mock_cache_invalidation() {
    let cache = MockCacheInvalidation::new();

    assert_eq!(cache.get_count(), 0);

    cache
        .invalidate_policies()
        .await
        .expect("Failed to invalidate");

    assert_eq!(cache.get_count(), 1);

    cache
        .invalidate_policies()
        .await
        .expect("Failed to invalidate");

    assert_eq!(cache.get_count(), 2);
}
