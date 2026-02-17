//! Authentication cache with TTL support.
//!
//! Caches successful authentication results to reduce database queries.
//! Also provides:
//! - **Traffic deltas**: in-memory tracking so cache hits reflect accumulated traffic
//! - **Negative caching**: short-lived entries for invalid hashes to prevent DB flooding

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Cached user data.
#[derive(Clone, Debug)]
pub struct CachedUser {
    /// User ID (optional identifier).
    pub user_id: Option<String>,
    /// Traffic limit in bytes (0 = unlimited).
    pub traffic_limit: i64,
    /// Traffic used in bytes.
    pub traffic_used: i64,
    /// Expiration timestamp (0 = never).
    pub expires_at: i64,
    /// Whether the user is enabled.
    pub enabled: bool,
    /// When this cache entry was created.
    pub cached_at: Instant,
}

/// Cache entry with expiration.
#[derive(Debug)]
struct CacheEntry {
    user: CachedUser,
    expires_at: Instant,
}

/// Authentication cache with configurable TTL.
///
/// Beyond basic positive caching, this provides:
/// - **Traffic deltas** (`user_id → i64`): accumulated traffic bytes since
///   the last DB fetch, applied on cache hit so traffic-limit checks are
///   accurate within a single cache window.
/// - **Negative cache** (`hash → expiry`): short-lived entries for hashes
///   that returned no DB row, preventing repeated SELECT storms from
///   invalid/attack traffic.
#[derive(Debug)]
pub struct AuthCache {
    /// Positive cache: hash → user data.
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// TTL for positive cache entries.
    ttl: Duration,

    /// Accumulated traffic bytes since last DB fetch, keyed by user_id.
    traffic_deltas: RwLock<HashMap<String, i64>>,

    /// Negative cache: hash → expiry instant.
    neg_cache: RwLock<HashMap<String, Instant>>,
    /// TTL for negative cache entries (Duration::ZERO = disabled).
    neg_ttl: Duration,

    /// Cache hit counter.
    hits: AtomicU64,
    /// Cache miss counter.
    misses: AtomicU64,
}

impl AuthCache {
    /// Create a new auth cache.
    ///
    /// - `ttl` — positive cache entry lifetime
    /// - `neg_ttl` — negative cache entry lifetime (`Duration::ZERO` to disable)
    pub fn new(ttl: Duration, neg_ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl,
            traffic_deltas: RwLock::new(HashMap::new()),
            neg_cache: RwLock::new(HashMap::new()),
            neg_ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    // ── Positive cache ──────────────────────────────────────────

    /// Get a cached user by password hash.
    ///
    /// Returns `Some(CachedUser)` if found and not expired, `None` otherwise.
    pub fn get(&self, hash: &str) -> Option<CachedUser> {
        let cache = self.cache.read();
        if let Some(entry) = cache.get(hash)
            && Instant::now() < entry.expires_at
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.user.clone());
        }
        drop(cache);

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a user into the cache.
    pub fn insert(&self, hash: String, user: CachedUser) {
        let entry = CacheEntry {
            user,
            expires_at: Instant::now() + self.ttl,
        };
        self.cache.write().insert(hash, entry);
    }

    /// Remove a user from the cache.
    pub fn remove(&self, hash: &str) {
        self.cache.write().remove(hash);
    }

    /// Invalidate a user by user_id.
    ///
    /// Removes all positive cache entries with matching user_id
    /// and clears the traffic delta for that user.
    pub fn invalidate_user(&self, user_id: &str) {
        self.cache
            .write()
            .retain(|_, entry| entry.user.user_id.as_deref() != Some(user_id));
        self.traffic_deltas.write().remove(user_id);
    }

    /// Clear all cache entries (positive, negative, and traffic deltas).
    pub fn clear(&self) {
        self.cache.write().clear();
        self.traffic_deltas.write().clear();
        self.neg_cache.write().clear();
    }

    /// Remove expired entries from positive and negative caches.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.cache
            .write()
            .retain(|_, entry| entry.expires_at > now);
        self.neg_cache.write().retain(|_, &mut exp| exp > now);
    }

    // ── Traffic deltas ──────────────────────────────────────────

    /// Increment the in-memory traffic delta for a user.
    ///
    /// Called by `StoreAuth::record_traffic()` so that subsequent
    /// cache hits reflect the accumulated traffic.
    #[allow(clippy::cast_possible_wrap)]
    pub fn add_traffic_delta(&self, user_id: &str, bytes: u64) {
        *self
            .traffic_deltas
            .write()
            .entry(user_id.to_string())
            .or_insert(0) += bytes as i64;
    }

    /// Read the accumulated traffic delta for a user.
    ///
    /// Returns 0 if no delta is tracked (user never had traffic recorded
    /// since the last DB fetch).
    pub fn get_traffic_delta(&self, user_id: &str) -> i64 {
        self.traffic_deltas
            .read()
            .get(user_id)
            .copied()
            .unwrap_or(0)
    }

    /// Clear the traffic delta for a user.
    ///
    /// Called when the cache re-fetches from DB, so the delta restarts
    /// from zero (the DB value is now authoritative).
    pub fn clear_traffic_delta(&self, user_id: &str) {
        self.traffic_deltas.write().remove(user_id);
    }

    // ── Negative cache ──────────────────────────────────────────

    /// Record a hash as "not found" in the negative cache.
    ///
    /// Subsequent lookups within `neg_ttl` will return `true` from
    /// [`is_negative`](Self::is_negative), skipping the DB query.
    pub fn insert_negative(&self, hash: &str) {
        if self.neg_ttl > Duration::ZERO {
            self.neg_cache
                .write()
                .insert(hash.to_string(), Instant::now() + self.neg_ttl);
        }
    }

    /// Check if a hash is in the negative cache (known invalid).
    ///
    /// Returns `true` if the hash was recently looked up and not found.
    /// Expired entries are lazily removed.
    pub fn is_negative(&self, hash: &str) -> bool {
        if self.neg_ttl == Duration::ZERO {
            return false;
        }
        let cache = self.neg_cache.read();
        if let Some(&exp) = cache.get(hash)
            && Instant::now() < exp
        {
            return true;
        }
        false
    }

    /// Remove a hash from the negative cache.
    ///
    /// Called by [`cache_invalidate`] so that a newly-added user
    /// is not blocked by a stale negative entry.
    pub fn remove_negative(&self, hash: &str) {
        self.neg_cache.write().remove(hash);
    }

    // ── Statistics ──────────────────────────────────────────────

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        CacheStats {
            size: cache.len(),
            neg_size: self.neg_cache.read().len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            ttl: self.ttl,
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of positive cache entries.
    pub size: usize,
    /// Number of negative cache entries.
    pub neg_size: usize,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Cache TTL.
    pub ttl: Duration,
}

impl CacheStats {
    /// Calculate hit rate (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> AuthCache {
        AuthCache::new(Duration::from_secs(60), Duration::from_secs(5))
    }

    fn make_user(user_id: &str, traffic_limit: i64, traffic_used: i64) -> CachedUser {
        CachedUser {
            user_id: Some(user_id.to_string()),
            traffic_limit,
            traffic_used,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        }
    }

    #[test]
    fn test_cache_basic() {
        let cache = make_cache();
        let user = make_user("user1", 1000, 100);

        cache.insert("hash1".to_string(), user);
        let cached = cache.get("hash1").unwrap();
        assert_eq!(cached.user_id, Some("user1".to_string()));
        assert_eq!(cached.traffic_limit, 1000);

        assert!(cache.get("hash2").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = AuthCache::new(Duration::from_millis(10), Duration::ZERO);
        let user = make_user("user1", 0, 0);

        cache.insert("hash1".to_string(), user);
        assert!(cache.get("hash1").is_some());

        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("hash1").is_none());
    }

    #[test]
    fn test_cache_invalidate_user() {
        let cache = make_cache();

        cache.insert("hash1".to_string(), make_user("user1", 0, 0));
        cache.insert("hash2".to_string(), make_user("user2", 0, 0));

        // Also add a traffic delta for user1
        cache.add_traffic_delta("user1", 500);

        cache.invalidate_user("user1");

        assert!(cache.get("hash1").is_none());
        assert!(cache.get("hash2").is_some());
        // Delta should also be cleared
        assert_eq!(cache.get_traffic_delta("user1"), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = make_cache();
        let user = CachedUser {
            user_id: None,
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        cache.insert("hash1".to_string(), user);

        cache.get("hash1"); // hit
        cache.get("hash1"); // hit
        cache.get("hash2"); // miss

        let stats = cache.stats();
        assert_eq!(stats.size, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 0.666).abs() < 0.01);
    }

    // ── Traffic delta tests ─────────────────────────────────────

    #[test]
    fn test_traffic_delta_accumulates() {
        let cache = make_cache();

        cache.add_traffic_delta("user1", 100);
        cache.add_traffic_delta("user1", 200);
        cache.add_traffic_delta("user1", 300);

        assert_eq!(cache.get_traffic_delta("user1"), 600);
        assert_eq!(cache.get_traffic_delta("user2"), 0); // no delta
    }

    #[test]
    fn test_traffic_delta_clear() {
        let cache = make_cache();

        cache.add_traffic_delta("user1", 500);
        assert_eq!(cache.get_traffic_delta("user1"), 500);

        cache.clear_traffic_delta("user1");
        assert_eq!(cache.get_traffic_delta("user1"), 0);
    }

    #[test]
    fn test_clear_resets_everything() {
        let cache = make_cache();

        cache.insert("hash1".to_string(), make_user("user1", 0, 0));
        cache.add_traffic_delta("user1", 100);
        cache.insert_negative("bad_hash");

        cache.clear();

        assert!(cache.get("hash1").is_none());
        assert_eq!(cache.get_traffic_delta("user1"), 0);
        assert!(!cache.is_negative("bad_hash"));
    }

    // ── Negative cache tests ────────────────────────────────────

    #[test]
    fn test_negative_cache_basic() {
        let cache = make_cache();

        assert!(!cache.is_negative("bad_hash"));

        cache.insert_negative("bad_hash");
        assert!(cache.is_negative("bad_hash"));
        assert!(!cache.is_negative("other_hash"));
    }

    #[test]
    fn test_negative_cache_expiration() {
        let cache = AuthCache::new(Duration::from_secs(60), Duration::from_millis(10));

        cache.insert_negative("bad_hash");
        assert!(cache.is_negative("bad_hash"));

        std::thread::sleep(Duration::from_millis(20));
        assert!(!cache.is_negative("bad_hash"));
    }

    #[test]
    fn test_negative_cache_disabled_when_zero_ttl() {
        let cache = AuthCache::new(Duration::from_secs(60), Duration::ZERO);

        cache.insert_negative("bad_hash");
        assert!(!cache.is_negative("bad_hash"));
    }

    #[test]
    fn test_negative_cache_remove() {
        let cache = make_cache();

        cache.insert_negative("bad_hash");
        assert!(cache.is_negative("bad_hash"));

        cache.remove_negative("bad_hash");
        assert!(!cache.is_negative("bad_hash"));
    }

    #[test]
    fn test_negative_cache_in_stats() {
        let cache = make_cache();

        cache.insert_negative("hash1");
        cache.insert_negative("hash2");

        let stats = cache.stats();
        assert_eq!(stats.neg_size, 2);
    }

    #[test]
    fn test_cleanup_expired_cleans_both() {
        let cache = AuthCache::new(Duration::from_millis(10), Duration::from_millis(10));

        cache.insert("hash1".to_string(), make_user("user1", 0, 0));
        cache.insert_negative("bad_hash");

        std::thread::sleep(Duration::from_millis(20));
        cache.cleanup_expired();

        let stats = cache.stats();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.neg_size, 0);
    }
}
