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

/// Create the tables and indexes if they are absent, then add any columns a
/// database created by an older version is missing.
pub async fn bootstrap(pool: &SqlitePool) -> Result<(), DashError> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    migrate(pool).await
}

/// Columns added to `nodes` after the table first shipped.
///
/// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists,
/// so a database from an earlier version would keep the old shape and every
/// query naming a new column would fail. SQLite has no `ADD COLUMN IF NOT
/// EXISTS`, hence the lookup.
const NODE_COLUMNS: &[(&str, &str)] = &[
    ("node_type", "TEXT NOT NULL DEFAULT 'server'"),
    ("config", "TEXT NOT NULL DEFAULT '{}'"),
    ("config_version", "INTEGER NOT NULL DEFAULT 1"),
    ("agent_version", "TEXT NOT NULL DEFAULT ''"),
    ("connections_active", "INTEGER NOT NULL DEFAULT 0"),
    ("bytes_in", "INTEGER NOT NULL DEFAULT 0"),
    ("bytes_out", "INTEGER NOT NULL DEFAULT 0"),
    ("uptime_secs", "INTEGER NOT NULL DEFAULT 0"),
];

/// Bring an existing database up to the current schema.
async fn migrate(pool: &SqlitePool) -> Result<(), DashError> {
    let existing: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('nodes')")
        .fetch_all(pool)
        .await?;

    for (column, definition) in NODE_COLUMNS {
        if existing.iter().any(|name| name == column) {
            continue;
        }
        // Column names and definitions are constants above, never user input.
        sqlx::query(&format!(
            "ALTER TABLE nodes ADD COLUMN {column} {definition}"
        ))
        .execute(pool)
        .await?;
        tracing::info!(column, "added missing nodes column");
    }

    Ok(())
}
