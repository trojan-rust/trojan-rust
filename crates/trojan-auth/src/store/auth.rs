//! Generic store-based authentication wrapper.
//!
//! [`StoreAuth<S>`] wraps any [`UserStore`] implementation and provides:
//! - Validation logic (enabled → expired → traffic check)
//! - Optional result caching via [`AuthCache`], with in-memory traffic deltas
//! - Negative caching for invalid hashes (prevents DB flooding)
//! - Optional batched traffic recording via [`TrafficRecorder`]

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::error::AuthError;
use crate::result::{AuthMetadata, AuthResult};
use crate::traits::AuthBackend;

use super::cache::{AuthCache, CacheStats, CachedUser};
use super::config::{StoreAuthConfig, TrafficRecordingMode};
use super::record::UserRecord;
use super::traits::UserStore;

#[cfg(feature = "batched-traffic")]
use super::traffic::TrafficRecorder;

/// Generic authentication backend that wraps a [`UserStore`].
///
/// Provides shared validation, caching, and traffic batching logic.
/// New backends only need to implement [`UserStore`] (data access).
///
/// # Type parameter
///
/// - `S` — the underlying data store (e.g. `SqlStore`)
pub struct StoreAuth<S: UserStore> {
    store: S,
    auth_cache: Option<AuthCache>,
    #[cfg(feature = "batched-traffic")]
    traffic_recorder: Option<TrafficRecorder>,
    traffic_mode: TrafficRecordingMode,
}

impl<S: UserStore> StoreAuth<S> {
    /// Create a new `StoreAuth` wrapping the given store.
    ///
    /// For backends that need batched traffic recording, use
    /// [`with_traffic_recorder`](Self::with_traffic_recorder) after construction.
    pub fn new(store: S, config: &StoreAuthConfig) -> Self {
        let auth_cache = if config.cache_enabled {
            Some(AuthCache::new(config.cache_ttl, config.neg_cache_ttl))
        } else {
            None
        };

        Self {
            store,
            auth_cache,
            #[cfg(feature = "batched-traffic")]
            traffic_recorder: None,
            traffic_mode: config.traffic_mode,
        }
    }

    /// Attach a [`TrafficRecorder`] for batched traffic writes.
    #[cfg(feature = "batched-traffic")]
    pub fn with_traffic_recorder(mut self, recorder: TrafficRecorder) -> Self {
        self.traffic_recorder = Some(recorder);
        self
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Check if caching is enabled.
    pub fn cache_enabled(&self) -> bool {
        self.auth_cache.is_some()
    }

    /// Get cache statistics. Returns `None` if caching is disabled.
    pub fn cache_stats(&self) -> Option<CacheStats> {
        self.auth_cache.as_ref().map(|c| c.stats())
    }

    /// Invalidate cache entry by password hash.
    ///
    /// Also removes the hash from the negative cache so that a
    /// newly-added user is not blocked by a stale negative entry.
    pub fn cache_invalidate(&self, hash: &str) {
        if let Some(ref cache) = self.auth_cache {
            cache.remove(hash);
            cache.remove_negative(hash);
        }
    }

    /// Invalidate all cache entries for a user.
    pub fn cache_invalidate_user(&self, user_id: &str) {
        if let Some(ref cache) = self.auth_cache {
            cache.invalidate_user(user_id);
        }
    }

    /// Clear all cache entries.
    pub fn cache_clear(&self) {
        if let Some(ref cache) = self.auth_cache {
            cache.clear();
        }
    }

    /// Get current unix timestamp.
    #[inline]
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Validate a [`UserRecord`] against business rules.
    ///
    /// Checks: enabled → expired → traffic exceeded.
    fn validate_record(record: &UserRecord) -> Result<(), AuthError> {
        if !record.enabled {
            return Err(AuthError::Disabled);
        }

        let now = Self::now_unix();
        if record.expires_at > 0 && now >= record.expires_at {
            return Err(AuthError::Expired);
        }

        if record.traffic_limit > 0 && record.traffic_used >= record.traffic_limit {
            return Err(AuthError::TrafficExceeded);
        }

        Ok(())
    }

    /// Build an [`AuthResult`] from a validated [`UserRecord`].
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn record_to_result(record: &UserRecord) -> AuthResult {
        let metadata = AuthMetadata {
            traffic_limit: record.traffic_limit as u64,
            traffic_used: record.traffic_used as u64,
            expires_at: record.expires_at as u64,
            enabled: record.enabled,
        };

        AuthResult {
            user_id: record.user_id.clone(),
            metadata: Some(metadata),
        }
    }
}

#[async_trait]
impl<S: UserStore> AuthBackend for StoreAuth<S> {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        if let Some(ref cache) = self.auth_cache {
            // 1. Negative cache — reject known-invalid hashes without DB query
            if cache.is_negative(hash) {
                return Err(AuthError::Invalid);
            }

            // 2. Positive cache hit — validate with delta-adjusted traffic
            if let Some(cached) = cache.get(hash) {
                let delta = cached
                    .user_id
                    .as_deref()
                    .map(|uid| cache.get_traffic_delta(uid))
                    .unwrap_or(0);

                let mut record = UserRecord::from(cached);
                record.traffic_used += delta;

                if let Err(e) = Self::validate_record(&record) {
                    // Remove expired entries from positive cache
                    if matches!(e, AuthError::Expired) {
                        cache.remove(hash);
                    }
                    return Err(e);
                }

                return Ok(Self::record_to_result(&record));
            }
        }

        // 3. Cache miss — query the store
        let record = match self.store.find_by_hash(hash).await? {
            Some(record) => record,
            None => {
                // Insert into negative cache
                if let Some(ref cache) = self.auth_cache {
                    cache.insert_negative(hash);
                }
                return Err(AuthError::Invalid);
            }
        };

        // Validate business rules
        Self::validate_record(&record)?;

        // Cache successful result and reset traffic delta
        if let Some(ref cache) = self.auth_cache {
            if let Some(ref uid) = record.user_id {
                cache.clear_traffic_delta(uid);
            }
            let cached_user = CachedUser {
                user_id: record.user_id.clone(),
                traffic_limit: record.traffic_limit,
                traffic_used: record.traffic_used,
                expires_at: record.expires_at,
                enabled: record.enabled,
                cached_at: Instant::now(),
            };
            cache.insert(hash.to_string(), cached_user);
        }

        Ok(Self::record_to_result(&record))
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        // Update in-memory traffic delta so cache hits reflect accumulated traffic
        if let Some(ref cache) = self.auth_cache {
            cache.add_traffic_delta(user_id, bytes);
        }

        // Persist to backend
        match self.traffic_mode {
            TrafficRecordingMode::Immediate => self.store.add_traffic(user_id, bytes).await,
            TrafficRecordingMode::Batched => {
                #[cfg(feature = "batched-traffic")]
                if let Some(ref recorder) = self.traffic_recorder {
                    recorder.record(user_id.to_string(), bytes);
                }
                Ok(())
            }
            TrafficRecordingMode::Disabled => Ok(()),
        }
    }
}

impl<S: UserStore + std::fmt::Debug> std::fmt::Debug for StoreAuth<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreAuth")
            .field("store", &self.store)
            .field("traffic_mode", &self.traffic_mode)
            .field("cache_enabled", &self.auth_cache.is_some())
            .finish_non_exhaustive()
    }
}
