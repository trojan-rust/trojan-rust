//! Universal user record from any store.

use super::cache::CachedUser;

/// User data returned by a [`UserStore`](super::UserStore) implementation.
///
/// This is the common representation of a user across all backends.
/// Validation logic lives in [`StoreAuth`](super::StoreAuth), not in the store itself.
#[derive(Debug, Clone)]
pub struct UserRecord {
    /// Optional user identifier (for traffic recording and logging).
    pub user_id: Option<String>,
    /// Traffic limit in bytes (0 = unlimited). Uses `i64` to match DB column types.
    pub traffic_limit: i64,
    /// Traffic already used in bytes.
    pub traffic_used: i64,
    /// Expiration as Unix timestamp (0 = never expires).
    pub expires_at: i64,
    /// Whether the account is enabled.
    pub enabled: bool,
}

impl From<CachedUser> for UserRecord {
    fn from(cached: CachedUser) -> Self {
        Self {
            user_id: cached.user_id,
            traffic_limit: cached.traffic_limit,
            traffic_used: cached.traffic_used,
            expires_at: cached.expires_at,
            enabled: cached.enabled,
        }
    }
}
