//! Core traits for Hodei authorization framework

use async_trait::async_trait;
use cedar_policy::PolicySet;
use thiserror::Error;

/// Errors that can occur in policy storage operations
#[derive(Debug, Error)]
pub enum PolicyStoreError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Policy not found: {0}")]
    NotFound(String),
    #[error("Policy parse error: {0}")]
    Parse(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Errors that can occur in cache invalidation operations
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Publish error: {0}")]
    Publish(String),
    #[error("Subscribe error: {0}")]
    Subscribe(String),
}

/// Trait for policy storage backends
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Create a new policy and return its ID
    async fn create_policy(&self, content: String) -> Result<String, PolicyStoreError>;

    /// Get a policy by ID
    async fn get_policy(&self, id: &str) -> Result<Option<String>, PolicyStoreError>;

    /// List all policies as (id, content) tuples
    async fn list_policies(&self) -> Result<Vec<(String, String)>, PolicyStoreError>;

    /// Update an existing policy
    async fn update_policy(&self, id: &str, content: String) -> Result<(), PolicyStoreError>;

    /// Delete a policy by ID
    async fn delete_policy(&self, id: &str) -> Result<(), PolicyStoreError>;

    /// Load all policies as a PolicySet
    async fn load_all_policies(&self) -> Result<PolicySet, PolicyStoreError>;
}

/// Trait for cache invalidation mechanisms
#[async_trait]
pub trait CacheInvalidation: Send + Sync {
    /// Publish a cache invalidation event
    async fn invalidate_policies(&self) -> Result<(), CacheError>;

    /// Subscribe to cache invalidation events with a callback
    async fn subscribe_to_invalidations<F>(&self, callback: F) -> Result<(), CacheError>
    where
        F: Fn() + Send + Sync + 'static;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Mock PolicyStore para tests
    struct MockPolicyStore {
        policies: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MockPolicyStore {
        fn new() -> Self {
            Self {
                policies: Arc::new(Mutex::new(HashMap::new())),
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

    #[tokio::test]
    async fn test_mock_policy_store_create() {
        let store = MockPolicyStore::new();
        let id = store
            .create_policy("test policy".to_string())
            .await
            .unwrap();
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_mock_policy_store_get() {
        let store = MockPolicyStore::new();
        let id = store
            .create_policy("test policy".to_string())
            .await
            .unwrap();
        let policy = store.get_policy(&id).await.unwrap();
        assert_eq!(policy, Some("test policy".to_string()));
    }

    #[tokio::test]
    async fn test_mock_policy_store_update() {
        let store = MockPolicyStore::new();
        let id = store.create_policy("original".to_string()).await.unwrap();
        store
            .update_policy(&id, "updated".to_string())
            .await
            .unwrap();
        let policy = store.get_policy(&id).await.unwrap();
        assert_eq!(policy, Some("updated".to_string()));
    }

    #[tokio::test]
    async fn test_mock_policy_store_delete() {
        let store = MockPolicyStore::new();
        let id = store.create_policy("test".to_string()).await.unwrap();
        store.delete_policy(&id).await.unwrap();
        let policy = store.get_policy(&id).await.unwrap();
        assert_eq!(policy, None);
    }

    #[tokio::test]
    async fn test_mock_policy_store_list() {
        let store = MockPolicyStore::new();
        let id1 = store.create_policy("policy1".to_string()).await.unwrap();
        let id2 = store.create_policy("policy2".to_string()).await.unwrap();
        let policies = store.list_policies().await.unwrap();
        assert_eq!(policies.len(), 2);
        assert!(policies.iter().any(|(id, _)| id == &id1));
        assert!(policies.iter().any(|(id, _)| id == &id2));
    }
}
