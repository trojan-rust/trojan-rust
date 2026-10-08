//! Database connection and schema migration.

use std::time::Duration;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

use crate::error::DashError;
use crate::migration::Migrator;

/// Open the database, creating it if missing, and bring the schema up to date.
///
/// Nodes flush their traffic on a timer, so writes arrive as a burst of
/// concurrent requests every interval rather than a steady trickle. WAL plus a
/// busy timeout is what keeps that burst from turning into `SQLITE_BUSY`:
/// writers queue on the lock instead of failing.
pub async fn connect(url: &str) -> Result<DatabaseConnection, DashError> {
    let mut options = ConnectOptions::new(url.to_owned());
    options
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .sqlx_logging(false)
        .map_sqlx_sqlite_opts(|options| {
            // Agents discard reports after ACK, so every pooled connection must commit durably.
            options
                .pragma("journal_mode", "WAL")
                .pragma("synchronous", "FULL")
                .busy_timeout(Duration::from_secs(10))
                .foreign_keys(true)
        });

    let db = Database::connect(options).await?;

    Migrator::up(&db, None).await?;

    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_pool_connection_preserves_acknowledged_commits() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("traffic.db").display()
        );
        let db = connect(&url).await.unwrap();
        let mut connections = Vec::new();
        for _ in 0..8 {
            let mut connection = db.get_sqlite_connection_pool().acquire().await.unwrap();
            let synchronous: i64 = sea_orm::sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            let journal: String = sea_orm::sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            assert_eq!(
                synchronous, 2,
                "FULL is required before acknowledging a report"
            );
            assert_eq!(journal, "wal");
            // Keep each connection checked out so the test opens the complete pool.
            connections.push(connection);
        }
    }
}
