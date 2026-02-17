//! Data-access trait for user stores.

use async_trait::async_trait;

use crate::AuthError;

use super::UserRecord;

/// Data-access layer for user authentication.
///
/// Implementations provide only data retrieval and traffic persistence.
/// Validation logic (enabled, expired, traffic exceeded) is handled by
/// [`StoreAuth`](super::StoreAuth), which wraps a `UserStore`.
///
/// Return `Ok(None)` when a hash is not found — `StoreAuth` maps this
/// to [`AuthError::Invalid`].
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Look up a user by password hash.
    ///
    /// Returns `None` if no user matches the hash.
    async fn find_by_hash(&self, hash: &str) -> Result<Option<UserRecord>, AuthError>;

    /// Persist a traffic increment for the given user.
    async fn add_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError>;
}
