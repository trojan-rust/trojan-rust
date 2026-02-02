//! Hot-reloadable authentication backend wrapper.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::error::AuthError;
use crate::result::AuthResult;
use crate::traits::AuthBackend;

/// A wrapper that allows hot-swapping the underlying auth backend.
///
/// This is useful for reloading configuration without restarting the server.
/// Uses `parking_lot::RwLock` which doesn't poison on panic.
///
/// # Example
/// ```
/// use trojan_auth::{ReloadableAuth, MemoryAuth};
///
/// let auth = ReloadableAuth::new(MemoryAuth::from_passwords(["initial"]));
///
/// // Later, reload with new passwords
/// auth.reload(MemoryAuth::from_passwords(["new_password"]));
/// ```
pub struct ReloadableAuth {
    inner: RwLock<Arc<dyn AuthBackend>>,
}

impl ReloadableAuth {
    /// Create a new reloadable auth with the given initial backend.
    pub fn new<A: AuthBackend + 'static>(auth: A) -> Self {
        Self {
            inner: RwLock::new(Arc::new(auth)),
        }
    }

    /// Replace the auth backend with a new one.
    ///
    /// This is an atomic operation - in-flight requests will complete
    /// with the old backend, new requests will use the new backend.
    pub fn reload<A: AuthBackend + 'static>(&self, auth: A) {
        let mut inner = self.inner.write();
        *inner = Arc::new(auth);
    }

    /// Replace the auth backend with a pre-wrapped Arc.
    pub fn reload_arc(&self, auth: Arc<dyn AuthBackend>) {
        let mut inner = self.inner.write();
        *inner = auth;
    }

    /// Get a clone of the current backend Arc.
    ///
    /// This is useful for passing the backend to other components
    /// without holding the lock.
    #[inline]
    pub fn get(&self) -> Arc<dyn AuthBackend> {
        self.inner.read().clone()
    }
}

// Cannot derive Debug due to dyn AuthBackend
impl std::fmt::Debug for ReloadableAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableAuth").finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthBackend for ReloadableAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        // Clone the Arc so we don't hold the lock across await
        let backend = self.get();
        backend.verify(hash).await
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        let backend = self.get();
        backend.record_traffic(user_id, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha224_hex;
    use crate::memory::MemoryAuth;

    #[tokio::test]
    async fn test_reload() {
        let auth = ReloadableAuth::new(MemoryAuth::from_passwords(["old_password"]));

        let old_hash = sha224_hex("old_password");
        let new_hash = sha224_hex("new_password");

        // Old password works
        auth.verify(&old_hash).await.unwrap();
        auth.verify(&new_hash).await.unwrap_err();

        // Reload with new passwords
        auth.reload(MemoryAuth::from_passwords(["new_password"]));

        // Now new password works, old doesn't
        auth.verify(&old_hash).await.unwrap_err();
        auth.verify(&new_hash).await.unwrap();
    }
}
