//! Database connection and schema migration.

use std::time::Duration;

use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
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
        .sqlx_logging(false);

    let db = Database::connect(options).await?;

    for pragma in [
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = NORMAL",
        "PRAGMA busy_timeout = 10000",
        "PRAGMA foreign_keys = ON",
    ] {
        db.execute(Statement::from_string(db.get_database_backend(), pragma))
            .await?;
    }

    Migrator::up(&db, None).await?;

    Ok(db)
}
