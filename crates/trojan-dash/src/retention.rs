//! Pruning the hourly rollup.
//!
//! `traffic_hourly` holds a row per user per node per hour, 24 times what the
//! daily table accrues, and nothing reads a bucket older than the longest
//! hour-resolution range on offer. Left alone it would grow without bound for
//! data no chart asks for, so it is trimmed to a retention window; the daily
//! table remains the record of history.

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use tokio_util::sync::CancellationToken;

use crate::util::hour_hours_ago;

/// How often to sweep. Retention is measured in days, so an hourly sweep keeps
/// the table within an hour of its bound without polling for no reason.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Delete hourly rows older than `retention_days`, returning how many went.
pub async fn prune(db: &DatabaseConnection, retention_days: u32) -> Result<u64, sea_orm::DbErr> {
    let cutoff = hour_hours_ago(i64::from(retention_days) * 24);

    let result = db
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "DELETE FROM traffic_hourly WHERE hour < ?1",
            [cutoff.clone().into()],
        ))
        .await?;

    Ok(result.rows_affected())
}

/// Sweep on a timer until `shutdown` is cancelled.
///
/// A failed sweep is logged and retried on the next tick: the rows it would
/// have deleted are stale, not harmful, and a database that cannot serve a
/// DELETE has a louder problem than this task.
pub async fn sweep(db: DatabaseConnection, retention_days: u32, shutdown: CancellationToken) {
    if retention_days == 0 {
        tracing::info!("hourly traffic retention disabled");
        return;
    }

    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => match prune(&db, retention_days).await {
                Ok(0) => {}
                Ok(rows) => tracing::debug!(rows, retention_days, "pruned hourly traffic"),
                Err(e) => tracing::warn!(error = %e, "could not prune hourly traffic"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{FromQueryResult, Value};

    use super::*;
    use crate::util::current_hour;

    /// A database with one hourly row per listed hours-ago.
    async fn with_rows(hours_ago: &[i64]) -> DatabaseConnection {
        let db = crate::db::connect("sqlite::memory:")
            .await
            .expect("an in-memory database");

        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO users (id, hash, username) VALUES (1, 'h', 'u')",
        ))
        .await
        .unwrap();
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO nodes (id, name, token) VALUES (1, 'n', 't')",
        ))
        .await
        .unwrap();

        for hours in hours_ago {
            db.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO traffic_hourly (user_id, node_id, bytes, hour) VALUES (1, 1, 1, ?1)",
                [Value::from(hour_hours_ago(*hours))],
            ))
            .await
            .unwrap();
        }

        db
    }

    async fn remaining(db: &DatabaseConnection) -> u64 {
        #[derive(FromQueryResult)]
        struct Count {
            n: i64,
        }

        let row = Count::find_by_statement(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM traffic_hourly",
        ))
        .one(db)
        .await
        .unwrap()
        .unwrap();

        u64::try_from(row.n).unwrap_or(0)
    }

    /// The window is a boundary, and the row exactly on it is the one a
    /// three-day chart still needs.
    #[tokio::test]
    async fn prune_keeps_what_is_inside_the_window() {
        // 14 days is the default retention: 24h ago stays, 15 days ago goes.
        let db = with_rows(&[1, 24, 24 * 13, 24 * 15, 24 * 40]).await;

        let deleted = prune(&db, 14).await.unwrap();

        assert_eq!(deleted, 2, "only the two past the window");
        assert_eq!(remaining(&db).await, 3);
    }

    #[tokio::test]
    async fn prune_on_an_untouched_window_deletes_nothing() {
        let db = with_rows(&[1, 5]).await;

        assert_eq!(prune(&db, 14).await.unwrap(), 0);
        assert_eq!(remaining(&db).await, 2);
    }

    /// The sweep returns immediately rather than holding shutdown open, and
    /// leaves the rows alone.
    #[tokio::test]
    async fn a_zero_retention_disables_the_sweep() {
        let db = with_rows(&[24 * 400]).await;

        sweep(db.clone(), 0, CancellationToken::new()).await;

        assert_eq!(remaining(&db).await, 1);
    }

    /// The current hour is always inside any window, however small.
    #[tokio::test]
    async fn prune_never_takes_the_hour_being_written() {
        let db = with_rows(&[0]).await;

        assert_eq!(prune(&db, 1).await.unwrap(), 0);
        assert_eq!(
            remaining(&db).await,
            1,
            "the row at {} is still being accumulated",
            current_hour()
        );
    }
}
