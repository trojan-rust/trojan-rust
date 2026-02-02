//! Authentication cache with TTL support.
//!
//! Caches successful authentication results to reduce database queries.
//! Failed authentications are not cached to ensure security.

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
#[derive(Debug)]
pub struct AuthCache {
    /// Cache storage: hash -> cached user data.
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// Time-to-live for cache entries.
    ttl: Duration,
    /// Cache hit counter.
    hits: AtomicU64,
    /// Cache miss counter.
    misses: AtomicU64,
}

impl AuthCache {
    /// Create a new auth cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

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

    /// Invalidate a user by user_id (removes all entries with matching user_id).
    pub fn invalidate_user(&self, user_id: &str) {
        let mut cache = self.cache.write();
        cache.retain(|_, entry| entry.user.user_id.as_deref() != Some(user_id));
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Remove expired entries from the cache.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut cache = self.cache.write();
        cache.retain(|_, entry| entry.expires_at > now);
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        CacheStats {
            size: cache.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            ttl: self.ttl,
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in the cache.
    pub size: usize,
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

    #[test]
    fn test_cache_basic() {
        let cache = AuthCache::new(Duration::from_secs(60));

        let user = CachedUser {
            user_id: Some("user1".to_string()),
            traffic_limit: 1000,
            traffic_used: 100,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        // Insert and retrieve
        cache.insert("hash1".to_string(), user.clone());
        let cached = cache.get("hash1").unwrap();
        assert_eq!(cached.user_id, Some("user1".to_string()));
        assert_eq!(cached.traffic_limit, 1000);

        // Miss on non-existent
        assert!(cache.get("hash2").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = AuthCache::new(Duration::from_millis(10));

        let user = CachedUser {
            user_id: Some("user1".to_string()),
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        cache.insert("hash1".to_string(), user);
        assert!(cache.get("hash1").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("hash1").is_none());
    }

    #[test]
    fn test_cache_invalidate_user() {
        let cache = AuthCache::new(Duration::from_secs(60));

        let user1 = CachedUser {
            user_id: Some("user1".to_string()),
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        let user2 = CachedUser {
            user_id: Some("user2".to_string()),
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        cache.insert("hash1".to_string(), user1);
        cache.insert("hash2".to_string(), user2);

        // Invalidate user1
        cache.invalidate_user("user1");

        assert!(cache.get("hash1").is_none());
        assert!(cache.get("hash2").is_some());
    }

    #[test]
    fn test_cache_stats() {
        let cache = AuthCache::new(Duration::from_secs(60));

        let user = CachedUser {
            user_id: None,
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            cached_at: Instant::now(),
        };

        cache.insert("hash1".to_string(), user);

        // Generate some hits and misses
        cache.get("hash1"); // hit
        cache.get("hash1"); // hit
        cache.get("hash2"); // miss

        let stats = cache.stats();
        assert_eq!(stats.size, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 0.666).abs() < 0.01);
    }
}
