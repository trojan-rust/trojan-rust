//! Connection pool and schema bootstrap.

use std::str::FromStr;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::error::DashError;

/// Applied at startup and by `POST /admin/migrate`.
const SCHEMA: &str = include_str!("../schema.sql");

/// Open the database, creating it if missing.
///
/// Nodes flush their traffic batches on a timer, so writes arrive as a burst of
/// concurrent requests every flush interval rather than a steady trickle. WAL
/// plus a busy timeout is what keeps that burst from turning into
/// `SQLITE_BUSY`: writers queue on the lock instead of failing.
pub async fn connect(url: &str) -> Result<SqlitePool, DashError> {
    let options = SqliteConnectOptions::from_str(url)
        .map_err(|e| DashError::Config(format!("invalid database url {url:?}: {e}")))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(10))
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;

    Ok(pool)
}

/// Create the tables and indexes if they are absent.
pub async fn bootstrap(pool: &SqlitePool) -> Result<(), DashError> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    Ok(())
}
