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

    /// Optional: credit the relay hops that carried a user's traffic.
    ///
    /// `bytes` is the same figure passed to [`record_traffic`](Self::record_traffic)
    /// for this node, and every hop in `nodes` carried it too. Hops cannot
    /// account for it themselves: a relay never learns whose bytes it is
    /// forwarding, since the trojan handshake stays inside end-to-end TLS that
    /// only this node terminates.
    ///
    /// Default implementation does nothing, which is right for every backend
    /// that has no notion of other nodes.
    #[inline]
    async fn record_chain_traffic(
        &self,
        _user_id: &str,
        _bytes: u64,
        _nodes: &[String],
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Optional: bytes recorded for one hop of a relay chain but not yet
    /// reported to the backend.
    ///
    /// A per-node allowance is checked against a figure the backend computed
    /// when it last answered; this is what has happened since. Backends that
    /// do not buffer, or know nothing of other nodes, report nothing.
    #[inline]
    fn pending_chain_bytes(&self, _user_id: &str, _node_id: &str) -> u64 {
        0
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
    async fn record_chain_traffic(
        &self,
        user_id: &str,
        bytes: u64,
        nodes: &[String],
    ) -> Result<(), AuthError> {
        (**self).record_chain_traffic(user_id, bytes, nodes).await
    }

    #[inline]
    fn pending_chain_bytes(&self, user_id: &str, node_id: &str) -> u64 {
        (**self).pending_chain_bytes(user_id, node_id)
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
    async fn record_chain_traffic(
        &self,
        user_id: &str,
        bytes: u64,
        nodes: &[String],
    ) -> Result<(), AuthError> {
        (**self).record_chain_traffic(user_id, bytes, nodes).await
    }

    #[inline]
    fn pending_chain_bytes(&self, user_id: &str, node_id: &str) -> u64 {
        (**self).pending_chain_bytes(user_id, node_id)
    }

    #[inline]
    async fn shutdown(&self) {
        (**self).shutdown().await
    }
}
