//! SQL authentication backend.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};

use crate::error::AuthError;
use crate::result::{AuthMetadata, AuthResult};
use crate::traits::AuthBackend;

use super::cache::{AuthCache, CacheStats, CachedUser};
use super::config::{SqlAuthConfig, TrafficRecordingMode};
use super::queries;
use super::traffic::{FlushFn, TrafficRecorder};

/// Database type enum for query selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// PostgreSQL database.
    PostgreSQL,
    /// MySQL/MariaDB database.
    MySQL,
    /// SQLite database.
    SQLite,
}

impl DatabaseType {
    /// Detect database type from URL.
    pub fn from_url(url: &str) -> Option<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Some(Self::PostgreSQL)
        } else if url.starts_with("mysql://") || url.starts_with("mariadb://") {
            Some(Self::MySQL)
        } else if url.starts_with("sqlite:") {
            Some(Self::SQLite)
        } else {
            None
        }
    }
}

/// SQL-backed authentication.
///
/// Supports PostgreSQL, MySQL, and SQLite through SQLx.
///
/// # Example
///
/// ```ignore
/// use trojan_auth::sql::{SqlAuth, SqlAuthConfig, TrafficRecordingMode};
///
/// let config = SqlAuthConfig::new("postgres://user:pass@localhost/trojan")
///     .max_connections(20)
///     .traffic_mode(TrafficRecordingMode::Batched);
///
/// let auth = SqlAuth::connect(config).await?;
/// ```
pub struct SqlAuth {
    pool: AnyPool,
    db_type: DatabaseType,
    traffic_recorder: Option<TrafficRecorder>,
    auth_cache: Option<AuthCache>,
    config: SqlAuthConfig,
}

impl SqlAuth {
    /// Connect to database and create auth backend.
    pub async fn connect(config: SqlAuthConfig) -> Result<Self, AuthError> {
        // Install database drivers for the "any" pool
        sqlx::any::install_default_drivers();

        let db_type = DatabaseType::from_url(&config.database_url)
            .ok_or_else(|| AuthError::backend("unsupported database URL scheme"))?;

        let pool = AnyPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.connect_timeout)
            .max_lifetime(config.max_lifetime)
            .idle_timeout(config.idle_timeout)
            .connect(&config.database_url)
            .await?;

        // Set up traffic recorder if batched mode
        let traffic_recorder = match config.traffic_mode {
            TrafficRecordingMode::Batched => {
                let pool_clone = pool.clone();
                let db_type_clone = db_type;

                let flush_fn: FlushFn = Arc::new(move |batch| {
                    let pool = pool_clone.clone();
                    Box::pin(
                        async move { Self::flush_traffic_batch(&pool, db_type_clone, batch).await },
                    )
                });

                Some(TrafficRecorder::new(
                    config.batch_flush_interval,
                    config.batch_max_pending,
                    flush_fn,
                ))
            }
            _ => None,
        };

        // Set up auth cache if enabled
        let auth_cache = if config.cache_enabled {
            Some(AuthCache::new(config.cache_ttl))
        } else {
            None
        };

        Ok(Self {
            pool,
            db_type,
            traffic_recorder,
            auth_cache,
            config,
        })
    }

    /// Get current unix timestamp.
    #[inline]
    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Parse a user row from AnyRow.
    fn parse_user_row(row: AnyRow) -> Result<UserRowData, AuthError> {
        // SQLite stores booleans as integers, so try both types
        let enabled = row
            .try_get::<bool, _>("enabled")
            .or_else(|_| row.try_get::<i32, _>("enabled").map(|v| v != 0))
            .unwrap_or(true);

        Ok(UserRowData {
            user_id: row.try_get("user_id").ok(),
            traffic_limit: row.try_get("traffic_limit").unwrap_or(0),
            traffic_used: row.try_get("traffic_used").unwrap_or(0),
            expires_at: row.try_get("expires_at").unwrap_or(0),
            enabled,
        })
    }

    /// Verify user and return data if valid.
    async fn verify_user(&self, hash: &str) -> Result<UserRowData, AuthError> {
        let query = match self.db_type {
            DatabaseType::PostgreSQL => queries::FIND_BY_HASH_PG,
            DatabaseType::MySQL | DatabaseType::SQLite => queries::FIND_BY_HASH_MYSQL,
        };

        let row = sqlx::query(query)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AuthError::Invalid)?;

        let user = Self::parse_user_row(row)?;

        // Check account status
        if !user.enabled {
            return Err(AuthError::Disabled);
        }

        let now = Self::now_unix();
        if user.expires_at > 0 && now >= user.expires_at {
            return Err(AuthError::Expired);
        }

        if user.traffic_limit > 0 && user.traffic_used >= user.traffic_limit {
            return Err(AuthError::TrafficExceeded);
        }

        Ok(user)
    }

    /// Flush batched traffic updates to database.
    async fn flush_traffic_batch(
        pool: &AnyPool,
        db_type: DatabaseType,
        batch: HashMap<String, u64>,
    ) -> Result<(), AuthError> {
        if batch.is_empty() {
            return Ok(());
        }

        // Use transaction for atomicity
        let mut tx = pool.begin().await?;

        let query = match db_type {
            DatabaseType::PostgreSQL => queries::UPDATE_TRAFFIC_PG,
            DatabaseType::MySQL | DatabaseType::SQLite => queries::UPDATE_TRAFFIC_MYSQL,
        };

        for (user_id, bytes) in batch {
            sqlx::query(query)
                .bind(bytes as i64)
                .bind(&user_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Record traffic immediately to database.
    async fn record_traffic_immediate(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        let query = match self.db_type {
            DatabaseType::PostgreSQL => queries::UPDATE_TRAFFIC_PG,
            DatabaseType::MySQL | DatabaseType::SQLite => queries::UPDATE_TRAFFIC_MYSQL,
        };

        sqlx::query(query)
            .bind(bytes as i64)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get the connection pool (for advanced usage).
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// Get database type.
    pub fn database_type(&self) -> DatabaseType {
        self.db_type
    }

    /// Check if caching is enabled.
    pub fn cache_enabled(&self) -> bool {
        self.auth_cache.is_some()
    }

    /// Get cache statistics.
    ///
    /// Returns `None` if caching is disabled.
    pub fn cache_stats(&self) -> Option<CacheStats> {
        self.auth_cache.as_ref().map(|c| c.stats())
    }

    /// Invalidate cache entry by password hash.
    pub fn cache_invalidate(&self, hash: &str) {
        if let Some(ref cache) = self.auth_cache {
            cache.remove(hash);
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
}

/// Internal struct for parsed user data.
struct UserRowData {
    user_id: Option<String>,
    traffic_limit: i64,
    traffic_used: i64,
    expires_at: i64,
    enabled: bool,
}

#[async_trait]
impl AuthBackend for SqlAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        // Check cache first if enabled
        if let Some(ref cache) = self.auth_cache
            && let Some(cached) = cache.get(hash)
        {
            // Re-validate cached data (check expiration and traffic)
            if !cached.enabled {
                return Err(AuthError::Disabled);
            }

            let now = Self::now_unix();
            if cached.expires_at > 0 && now >= cached.expires_at {
                // Remove from cache since expired
                cache.remove(hash);
                return Err(AuthError::Expired);
            }

            if cached.traffic_limit > 0 && cached.traffic_used >= cached.traffic_limit {
                return Err(AuthError::TrafficExceeded);
            }

            let metadata = AuthMetadata {
                traffic_limit: cached.traffic_limit as u64,
                traffic_used: cached.traffic_used as u64,
                expires_at: cached.expires_at as u64,
                enabled: cached.enabled,
            };

            return Ok(AuthResult {
                user_id: cached.user_id,
                metadata: Some(metadata),
            });
        }

        // Cache miss - query database
        let user = self.verify_user(hash).await?;

        // Cache successful result
        if let Some(ref cache) = self.auth_cache {
            let cached_user = CachedUser {
                user_id: user.user_id.clone(),
                traffic_limit: user.traffic_limit,
                traffic_used: user.traffic_used,
                expires_at: user.expires_at,
                enabled: user.enabled,
                cached_at: Instant::now(),
            };
            cache.insert(hash.to_string(), cached_user);
        }

        let metadata = AuthMetadata {
            traffic_limit: user.traffic_limit as u64,
            traffic_used: user.traffic_used as u64,
            expires_at: user.expires_at as u64,
            enabled: user.enabled,
        };

        Ok(AuthResult {
            user_id: user.user_id,
            metadata: Some(metadata),
        })
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        match self.config.traffic_mode {
            TrafficRecordingMode::Immediate => self.record_traffic_immediate(user_id, bytes).await,
            TrafficRecordingMode::Batched => {
                if let Some(ref recorder) = self.traffic_recorder {
                    recorder.record(user_id.to_string(), bytes);
                }
                Ok(())
            }
            TrafficRecordingMode::Disabled => Ok(()),
        }
    }
}

// Debug implementation (don't leak credentials)
impl std::fmt::Debug for SqlAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlAuth")
            .field("db_type", &self.db_type)
            .field("max_connections", &self.config.max_connections)
            .field("traffic_mode", &self.config.traffic_mode)
            .field("cache_enabled", &self.config.cache_enabled)
            .finish_non_exhaustive()
    }
}
