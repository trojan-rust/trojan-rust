//! Authentication backend trait.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::AuthError;
use crate::result::AuthResult;

/// Trait for authentication backends.
///
/// Implementations must be thread-safe (`Send + Sync`) as they may be
/// called concurrently from multiple connections.
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// Verify a password hash.
    ///
    /// # Arguments
    /// * `hash` - The SHA224 hex-encoded hash of the password
    ///
    /// # Returns
    /// * `Ok(AuthResult)` - Authentication successful
    /// * `Err(AuthError)` - Authentication failed
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError>;

    /// Optional: Record traffic usage for a user.
    ///
    /// Default implementation does nothing.
    #[inline]
    async fn record_traffic(&self, _user_id: &str, _bytes: u64) -> Result<(), AuthError> {
        Ok(())
    }

    /// Optional: drain any buffered state (e.g. batched traffic updates) and
    /// wait for it to reach the backend before returning.
    ///
    /// Backends that buffer writes (such as the HTTP/SQL stores with
    /// `TrafficRecordingMode::Batched`) override this so callers can flush on
    /// graceful shutdown. Backends without buffered state use the default
    /// no-op.
    #[inline]
    async fn shutdown(&self) {}
}

/// Blanket implementation for `Arc<A>` where `A: AuthBackend`.
///
/// This allows passing `Arc<AuthBackend>` directly to functions expecting `impl AuthBackend`.
#[async_trait]
impl<A: AuthBackend + ?Sized> AuthBackend for Arc<A> {
    #[inline]
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        (**self).verify(hash).await
    }

    #[inline]
    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        (**self).record_traffic(user_id, bytes).await
    }

    #[inline]
    async fn shutdown(&self) {
        (**self).shutdown().await
    }
}

/// Blanket implementation for `Box<A>` where `A: AuthBackend`.
#[async_trait]
impl<A: AuthBackend + ?Sized> AuthBackend for Box<A> {
    #[inline]
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        (**self).verify(hash).await
    }

    #[inline]
    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        (**self).record_traffic(user_id, bytes).await
    }

    #[inline]
    async fn shutdown(&self) {
        (**self).shutdown().await
    }
}
