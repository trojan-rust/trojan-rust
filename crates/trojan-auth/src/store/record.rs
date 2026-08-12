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

/// Convert a domain counter into the signed form the stores use.
///
/// Byte counts and timestamps are unsigned in the domain but `i64` in storage,
/// because SQL `BIGINT` has no unsigned variant. Saturating keeps an
/// implausible value implausible; a plain `as` cast would wrap it negative,
/// and a negative counter reads as "under quota" or "not yet expired".
#[inline]
pub(crate) fn to_storage_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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

#[cfg(test)]
mod tests {
    use super::to_storage_i64;

    #[test]
    fn storage_conversion_saturates_instead_of_wrapping() {
        assert_eq!(to_storage_i64(0), 0);
        assert_eq!(to_storage_i64(4096), 4096);

        // The boundary is the whole point: `as` would turn these negative, and
        // a negative counter reads as "under quota" / "not yet expired".
        let max = u64::try_from(i64::MAX).expect("i64::MAX is non-negative");
        assert_eq!(to_storage_i64(max), i64::MAX);
        assert_eq!(to_storage_i64(max + 1), i64::MAX);
        assert_eq!(to_storage_i64(u64::MAX), i64::MAX);
    }
}
