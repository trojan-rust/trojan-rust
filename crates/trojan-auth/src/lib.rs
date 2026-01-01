//! Authentication backends for trojan.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest, Sha224};

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: Option<String>,
}

#[async_trait]
pub trait AuthBackend: Send + Sync {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credential")]
    Invalid,
    #[error("backend error: {0}")]
    Backend(String),
}

pub fn sha224_hex(input: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

#[derive(Debug, Clone)]
pub struct MemoryAuth {
    hashes: HashSet<String>,
}

impl MemoryAuth {
    pub fn from_hashes<I, S>(hashes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let hashes = hashes.into_iter().map(Into::into).collect();
        Self { hashes }
    }

    pub fn from_plain<I, S>(passwords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hashes = passwords
            .into_iter()
            .map(|p| sha224_hex(p.as_ref()))
            .collect();
        Self { hashes }
    }
}

#[async_trait]
impl AuthBackend for MemoryAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        if self.hashes.contains(hash) {
            Ok(AuthResult { user_id: None })
        } else {
            Err(AuthError::Invalid)
        }
    }
}

/// Blanket implementation for Arc<A> where A: AuthBackend.
/// This allows passing Arc<ReloadableAuth> directly to functions expecting impl AuthBackend.
#[async_trait]
impl<A: AuthBackend + ?Sized> AuthBackend for Arc<A> {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        (**self).verify(hash).await
    }
}

/// A reloadable auth backend that wraps another backend and allows hot-swapping.
/// Uses parking_lot::RwLock which doesn't poison on panic.
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
    pub fn reload<A: AuthBackend + 'static>(&self, auth: A) {
        let mut inner = self.inner.write();
        *inner = Arc::new(auth);
    }
}

#[async_trait]
impl AuthBackend for ReloadableAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        // Clone the Arc so we don't hold the lock across await
        let backend = {
            let guard = self.inner.read();
            guard.clone()
        };
        backend.verify(hash).await
    }
}
