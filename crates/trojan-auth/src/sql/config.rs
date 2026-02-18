//! SQL backend configuration.

use std::time::Duration;

use crate::store::{StoreAuthConfig, TrafficRecordingMode};

/// Configuration for SQL authentication backend.
#[derive(Debug, Clone)]
pub struct SqlAuthConfig {
    /// Database connection URL.
    ///
    /// Examples:
    /// - PostgreSQL: `postgres://user:pass@host/db`
    /// - MySQL: `mysql://user:pass@host/db`
    /// - SQLite: `sqlite:path/to/db.sqlite` or `sqlite::memory:`
    pub database_url: String,

    /// Maximum number of connections in the pool.
    pub max_connections: u32,

    /// Minimum number of connections to maintain.
    pub min_connections: u32,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Maximum connection lifetime.
    pub max_lifetime: Duration,

    /// Idle connection timeout.
    pub idle_timeout: Duration,

    /// Traffic recording mode.
    pub traffic_mode: TrafficRecordingMode,

    /// Batch flush interval (only used with Batched mode).
    pub batch_flush_interval: Duration,

    /// Maximum pending traffic updates before forced flush.
    pub batch_max_pending: usize,

    /// Whether to enable authentication caching.
    pub cache_enabled: bool,

    /// Cache TTL (time-to-live) for authenticated users.
    pub cache_ttl: Duration,

    /// Negative cache TTL for invalid hashes.
    ///
    /// Hashes that produce no DB row are cached for this duration,
    /// preventing repeated SELECT storms from invalid/attack traffic.
    /// Set to `Duration::ZERO` to disable.
    pub neg_cache_ttl: Duration,
}

impl Default for SqlAuthConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(1800), // 30 minutes
            idle_timeout: Duration::from_secs(600),  // 10 minutes
            traffic_mode: TrafficRecordingMode::default(),
            batch_flush_interval: Duration::from_secs(30),
            batch_max_pending: 1000,
            cache_enabled: false,
            cache_ttl: Duration::from_secs(60), // 1 minute default
            neg_cache_ttl: Duration::from_secs(5),
        }
    }
}

impl SqlAuthConfig {
    /// Create a new config with just the database URL.
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            ..Default::default()
        }
    }

    /// Builder: set max connections.
    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = n;
        self
    }

    /// Builder: set min connections.
    pub fn min_connections(mut self, n: u32) -> Self {
        self.min_connections = n;
        self
    }

    /// Builder: set connect timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: set traffic recording mode.
    pub fn traffic_mode(mut self, mode: TrafficRecordingMode) -> Self {
        self.traffic_mode = mode;
        self
    }

    /// Builder: set batch flush interval.
    pub fn batch_flush_interval(mut self, interval: Duration) -> Self {
        self.batch_flush_interval = interval;
        self
    }

    /// Builder: set max pending batch size.
    pub fn batch_max_pending(mut self, max: usize) -> Self {
        self.batch_max_pending = max;
        self
    }

    /// Builder: enable authentication caching.
    pub fn cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Builder: set cache TTL.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Builder: set negative cache TTL.
    pub fn neg_cache_ttl(mut self, ttl: Duration) -> Self {
        self.neg_cache_ttl = ttl;
        self
    }

    /// Extract the generic [`StoreAuthConfig`] portion.
    pub(crate) fn store_auth_config(&self) -> StoreAuthConfig {
        StoreAuthConfig {
            traffic_mode: self.traffic_mode,
            batch_flush_interval: self.batch_flush_interval,
            batch_max_pending: self.batch_max_pending,
            cache_enabled: self.cache_enabled,
            cache_ttl: self.cache_ttl,
            neg_cache_ttl: self.neg_cache_ttl,
            stale_ttl: Duration::ZERO, // SQL backend uses synchronous DB queries; SWR not needed
        }
    }
}
