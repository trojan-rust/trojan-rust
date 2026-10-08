//! Accounting tests use migrated SQLite databases and explicit observation clocks.

use super::*;
use sea_orm::EntityTrait;

fn timestamp(value: &str) -> u64 {
    value
        .parse::<Timestamp>()
        .unwrap()
        .as_second()
        .cast_unsigned()
}

#[test]
fn monthly_boundaries_clamp_day_31_and_preserve_leap_year() {
    let before = period(31, "UTC", timestamp("2024-02-28T23:59:59Z")).unwrap();
    assert_eq!(
        before.start.cast_unsigned(),
        timestamp("2024-01-31T00:00:00Z")
    );
    assert_eq!(
        before.end.cast_unsigned(),
        timestamp("2024-02-29T00:00:00Z")
    );
    let after = period(31, "UTC", before.end.cast_unsigned()).unwrap();
    assert_eq!(after.start, before.end);
    assert_eq!(after.end.cast_unsigned(), timestamp("2024-03-31T00:00:00Z"));
    assert_eq!(
        period(31, "UTC", timestamp("2025-02-15T12:00:00Z"))
            .unwrap()
            .end
            .cast_unsigned(),
        timestamp("2025-02-28T00:00:00Z")
    );
}

#[test]
fn calendar_windows_follow_iana_offsets_and_midnight_dst_gaps() {
    let period = period(9, "America/New_York", timestamp("2025-03-10T00:00:00Z")).unwrap();
    assert_eq!(
        period.start.cast_unsigned(),
        timestamp("2025-03-09T05:00:00Z")
    );
    assert_eq!(
        period.end.cast_unsigned(),
        timestamp("2025-04-09T04:00:00Z")
    );
    let gap = super::period(4, "America/Sao_Paulo", timestamp("2018-11-05T00:00:00Z")).unwrap();
    assert_eq!(gap.start.cast_unsigned(), timestamp("2018-11-04T03:00:00Z"));
}

#[test]
fn policies_reject_invalid_calendar_and_unsigned_overflow() {
    for (limit, day, tz) in [
        (u64::MAX, 1, "UTC"),
        (0, 0, "UTC"),
        (0, 32, "UTC"),
        (0, 1, "Mars/Olympus"),
    ] {
        validate_policy(limit, day, tz).unwrap_err();
    }
}

async fn database(url: &str) -> DatabaseConnection {
    let db = crate::db::connect(url).await.unwrap();
    db.execute_unprepared(
        "INSERT INTO nodes (id, name, token) VALUES (1, 'relay', 'token') ON CONFLICT DO NOTHING",
    )
    .await
    .unwrap();
    db
}

fn report(sequence: u64, observed: u64, bytes_in: u64, bytes_out: u64) -> NodeTrafficReport {
    NodeTrafficReport {
        stream_id: "persistent-agent-stream".into(),
        sequence,
        observed_at: observed,
        bytes_in,
        bytes_out,
    }
}

#[tokio::test]
async fn replay_after_database_restart_does_not_charge_twice_and_catches_up_months() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("traffic.db").display()
    );
    let db = database(&url).await;
    let january = timestamp("2025-01-31T23:59:59Z");
    let february = timestamp("2025-02-01T00:00:00Z");
    let march = timestamp("2025-03-15T12:00:00Z");
    let first = report(1, january, 100, 200);
    assert_eq!(record(&db, 1, &first, january).await.unwrap(), 1);
    db.close().await.unwrap();

    let db = database(&url).await;
    assert_eq!(record(&db, 1, &first, march).await.unwrap(), 1);
    assert_eq!(
        record(&db, 1, &report(2, february, 400, 500), march)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        usage(&db, 1, period(1, "UTC", january).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        300
    );
    assert_eq!(
        usage(&db, 1, period(1, "UTC", february).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        900
    );
    assert_eq!(
        usage(&db, 1, period(1, "UTC", march).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        0
    );

    // A calendar edit changes the query window; stored traffic remains available.
    assert_eq!(
        usage(&db, 1, period(15, "UTC", february).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        1200
    );
}

#[tokio::test]
async fn gaps_and_invalid_reports_leave_the_cursor_and_usage_unchanged() {
    let db = database("sqlite::memory:").await;
    let now = timestamp("2025-06-15T12:00:00Z");
    record(&db, 1, &report(2, now, 100, 0), now)
        .await
        .unwrap_err();
    record(&db, 1, &report(1, now + 301, 100, 0), now)
        .await
        .unwrap_err();
    record(&db, 1, &report(1, now, u64::MAX, 0), now)
        .await
        .unwrap_err();
    assert_eq!(
        record(&db, 1, &report(1, now, 10, 20), now).await.unwrap(),
        1
    );
    assert_eq!(
        usage(&db, 1, period(1, "UTC", now).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        30
    );
}

#[tokio::test]
async fn concurrent_replays_commit_one_delta_and_separate_streams_can_restart() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("traffic.db").display()
    );
    let db = database(&url).await;
    let now = timestamp("2025-06-15T12:00:00Z");
    let first = report(1, now, 7, 11);
    let (left, right) = tokio::join!(record(&db, 1, &first, now), record(&db, 1, &first, now));
    assert_eq!(left.unwrap(), 1);
    assert_eq!(right.unwrap(), 1);
    let second = NodeTrafficReport {
        stream_id: "replacement-stream".into(),
        ..first
    };
    record(&db, 1, &second, now).await.unwrap();
    assert_eq!(
        usage(&db, 1, period(1, "UTC", now).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        36
    );
}

async fn cached(db: &DatabaseConnection, at: u64, day: i64) -> u64 {
    let node = nodes::Entity::find_by_id(1).one(db).await.unwrap().unwrap();
    current_usage(db, &node, period(day, "UTC", at).unwrap())
        .await
        .unwrap()
        .total()
        .unwrap()
}

#[tokio::test]
async fn cached_windows_reset_and_rebuild_without_losing_late_reports() {
    let db = database("sqlite::memory:").await;
    let january = timestamp("2025-01-31T23:59:59Z");
    let february = timestamp("2025-02-01T00:00:00Z");
    assert_eq!(cached(&db, january, 1).await, 0);
    record(&db, 1, &report(1, january, 100, 200), february)
        .await
        .unwrap();
    assert_eq!(cached(&db, january, 1).await, 300);
    assert_eq!(cached(&db, february, 1).await, 0);
    record(&db, 1, &report(2, january, 1, 2), february)
        .await
        .unwrap();
    assert_eq!(cached(&db, february, 1).await, 0);
    record(&db, 1, &report(3, february, 4, 5), february)
        .await
        .unwrap();
    assert_eq!(cached(&db, february, 1).await, 9);
    assert_eq!(cached(&db, february, 15).await, 312);
    assert_eq!(cached(&db, february, 1).await, 9);
}

#[tokio::test]
async fn combined_overflow_rolls_back_the_ledger_cache_and_cursor() {
    let db = database("sqlite::memory:").await;
    let now = timestamp("2025-06-15T12:00:00Z");
    assert_eq!(cached(&db, now, 1).await, 0);
    let max = i64::MAX.cast_unsigned();
    record(&db, 1, &report(1, now, max - 1, 1), now)
        .await
        .unwrap();
    record(&db, 1, &report(2, now + 1, 0, 1), now + 1)
        .await
        .unwrap_err();
    assert_eq!(cached(&db, now, 1).await, max);
    assert_eq!(
        usage(&db, 1, period(1, "UTC", now).unwrap())
            .await
            .unwrap()
            .total()
            .unwrap(),
        max
    );
    // Sequence two remains available because the overflowing report did not commit.
    assert_eq!(
        record(&db, 1, &report(2, now + 1, 0, 0), now + 1)
            .await
            .unwrap(),
        2
    );
}
