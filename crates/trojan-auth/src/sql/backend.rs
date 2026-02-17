//! SQL authentication backend.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};

use crate::error::AuthError;
use crate::store::{
    FlushFn, StoreAuth, TrafficRecorder, TrafficRecordingMode, UserRecord, UserStore,
};

use super::config::SqlAuthConfig;
use super::queries;

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

// ── SqlStore ────────────────────────────────────────────────────────

/// SQL data store — implements [`UserStore`] for database backends.
///
/// Handles raw data access (queries, traffic writes) without any
/// validation or caching logic.
pub struct SqlStore {
    pool: AnyPool,
    db_type: DatabaseType,
}

impl std::fmt::Debug for SqlStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlStore")
            .field("db_type", &self.db_type)
            .finish_non_exhaustive()
    }
}

impl SqlStore {
    /// Parse a user row from `AnyRow`.
    fn parse_user_row(row: AnyRow) -> Result<UserRecord, AuthError> {
        // SQLite stores booleans as integers, so try both types
        let enabled = row
            .try_get::<bool, _>("enabled")
            .or_else(|_| row.try_get::<i32, _>("enabled").map(|v| v != 0))
            .unwrap_or(true);

        Ok(UserRecord {
            user_id: row.try_get("user_id").ok(),
            traffic_limit: row.try_get("traffic_limit").unwrap_or(0),
            traffic_used: row.try_get("traffic_used").unwrap_or(0),
            expires_at: row.try_get("expires_at").unwrap_or(0),
            enabled,
        })
    }

    /// Get the connection pool (for advanced usage / tests).
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// Get database type.
    pub fn database_type(&self) -> DatabaseType {
        self.db_type
    }

    /// Flush batched traffic updates to database.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    async fn flush_traffic_batch(
        pool: &AnyPool,
        db_type: DatabaseType,
        batch: HashMap<String, u64>,
    ) -> Result<(), AuthError> {
        if batch.is_empty() {
            return Ok(());
        }

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
}

#[async_trait]
impl UserStore for SqlStore {
    async fn find_by_hash(&self, hash: &str) -> Result<Option<UserRecord>, AuthError> {
        let query = match self.db_type {
            DatabaseType::PostgreSQL => queries::FIND_BY_HASH_PG,
            DatabaseType::MySQL | DatabaseType::SQLite => queries::FIND_BY_HASH_MYSQL,
        };

        let row = sqlx::query(query)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => Ok(Some(Self::parse_user_row(row)?)),
            None => Ok(None),
        }
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    async fn add_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
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
}

// ── SqlAuth ─────────────────────────────────────────────────────────

/// SQL-backed authentication.
///
/// This is `StoreAuth<SqlStore>` — the generic wrapper handles validation,
/// caching, and traffic batching while `SqlStore` provides data access.
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
pub type SqlAuth = StoreAuth<SqlStore>;

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

        let store_config = config.store_auth_config();
        let sql_store = SqlStore {
            pool: pool.clone(),
            db_type,
        };

        let mut auth = Self::new(sql_store, &store_config);

        // Set up traffic recorder if batched mode
        if store_config.traffic_mode == TrafficRecordingMode::Batched {
            let pool_clone = pool;
            let db_type_clone = db_type;

            let flush_fn: FlushFn = Arc::new(move |batch| {
                let pool = pool_clone.clone();
                Box::pin(
                    async move { SqlStore::flush_traffic_batch(&pool, db_type_clone, batch).await },
                )
            });

            let recorder = TrafficRecorder::new(
                store_config.batch_flush_interval,
                store_config.batch_max_pending,
                flush_fn,
            );
            auth = auth.with_traffic_recorder(recorder);
        }

        Ok(auth)
    }

    /// Get the connection pool (for advanced usage).
    pub fn pool(&self) -> &AnyPool {
        self.store().pool()
    }

    /// Get database type.
    pub fn database_type(&self) -> DatabaseType {
        self.store().database_type()
    }
}
