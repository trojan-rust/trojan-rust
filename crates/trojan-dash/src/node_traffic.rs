//! Timestamped node traffic and calendar billing windows, separate from user usage.

use jiff::{Timestamp, ToSpan, civil::Date, tz::TimeZone};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, FromQueryResult, Statement,
    TransactionTrait,
};
use serde::Serialize;
use trojan_protocol::NodeTrafficReport;

use crate::entity::nodes;
use crate::error::DashError;

/// A half-open billing window in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Period {
    pub start: i64,
    pub end: i64,
}

/// Validate policy input before storing it in the database.
pub(crate) fn validate_policy(limit: u64, day: i64, timezone: &str) -> Result<(), DashError> {
    if limit > i64::MAX as u64 {
        return Err(DashError::BadRequest(
            "traffic_limit exceeds i64::MAX".into(),
        ));
    }
    if !(1..=31).contains(&day) {
        return Err(DashError::BadRequest(
            "reset_day must be between 1 and 31".into(),
        ));
    }
    TimeZone::get(timezone).map_err(|e| DashError::BadRequest(e.to_string()))?;
    Ok(())
}

/// Resolve local midnight using the timezone database's compatible DST rule.
/// Missing dates use the month's last date; ambiguous midnight uses the first occurrence.
pub(crate) fn period(day: i64, timezone: &str, now: u64) -> Result<Period, DashError> {
    let tz = TimeZone::get(timezone)?;
    let timestamp = Timestamp::from_second(signed(now, "timestamp")?)?;
    let month = timestamp.to_zoned(tz.clone()).date().first_of_month();
    let boundary = |month: Date| -> Result<i64, DashError> {
        let reset_day = i8::try_from(day)
            .map_err(|_| DashError::BadRequest("invalid reset_day".into()))?
            .min(month.days_in_month());
        Ok(Date::new(month.year(), month.month(), reset_day)?
            .to_zoned(tz.clone())?
            .timestamp()
            .as_second())
    };
    let this_reset = boundary(month)?;
    if timestamp.as_second() < this_reset {
        Ok(Period {
            start: boundary(month.checked_sub(1.month())?)?,
            end: this_reset,
        })
    } else {
        Ok(Period {
            start: this_reset,
            end: boundary(month.checked_add(1.month())?)?,
        })
    }
}

/// The persisted directions in a billing window.
#[derive(Debug, Default, Serialize, FromQueryResult)]
pub(crate) struct Usage {
    pub bytes_in: i64,
    pub bytes_out: i64,
}

impl Usage {
    pub fn total(&self) -> Result<u64, DashError> {
        self.bytes_in
            .checked_add(self.bytes_out)
            .and_then(|total| u64::try_from(total).ok())
            .ok_or_else(|| DashError::BadRequest("node traffic total exceeds i64::MAX".into()))
    }
}

#[cfg(test)]
pub(crate) async fn usage<C: ConnectionTrait>(
    db: &C,
    node_id: i64,
    period: Period,
) -> Result<Usage, DashError> {
    Ok(Usage::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT COALESCE(SUM(bytes_in), 0) AS bytes_in, \
                COALESCE(SUM(bytes_out), 0) AS bytes_out \
         FROM node_traffic WHERE node_id = ?1 AND observed_at >= ?2 AND observed_at < ?3",
        [node_id.into(), period.start.into(), period.end.into()],
    ))
    .one(db)
    .await?
    .unwrap_or_default())
}

/// Rebuild the cached window only on calendar changes; reports update the cache transactionally.
pub(crate) async fn current_usage(
    db: &DatabaseConnection,
    node: &nodes::Model,
    period: Period,
) -> Result<Usage, DashError> {
    if node.traffic_period_start == period.start && node.traffic_period_end == period.end {
        return Ok(Usage {
            bytes_in: node.traffic_period_bytes_in,
            bytes_out: node.traffic_period_bytes_out,
        });
    }
    Usage::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE nodes SET traffic_period_start = ?2, traffic_period_end = ?3, \
             traffic_period_bytes_in = (SELECT COALESCE(SUM(bytes_in), 0) FROM node_traffic \
                 WHERE node_id = ?1 AND observed_at >= ?2 AND observed_at < ?3), \
             traffic_period_bytes_out = (SELECT COALESCE(SUM(bytes_out), 0) FROM node_traffic \
                 WHERE node_id = ?1 AND observed_at >= ?2 AND observed_at < ?3) \
         WHERE id = ?1 RETURNING traffic_period_bytes_in AS bytes_in, traffic_period_bytes_out AS bytes_out",
        [node.id.into(), period.start.into(), period.end.into()],
    ))
    .one(db)
    .await?
    .ok_or(DashError::NotFound)
}

fn signed(value: u64, field: &str) -> Result<i64, DashError> {
    i64::try_from(value).map_err(|_| DashError::BadRequest(format!("{field} exceeds i64::MAX")))
}

/// Commit one immutable report and its stream high-water mark in one transaction.
/// Returns the cumulative acknowledged sequence; repeated reports do not charge twice.
pub(crate) async fn record(
    db: &DatabaseConnection,
    node_id: i64,
    report: &NodeTrafficReport,
    now: u64,
) -> Result<u64, DashError> {
    if report.stream_id.is_empty() || report.stream_id.len() > 128 || report.sequence == 0 {
        return Err(DashError::BadRequest(
            "invalid traffic stream or sequence".into(),
        ));
    }
    if report.observed_at > now.saturating_add(300) {
        return Err(DashError::BadRequest(
            "traffic observation is in the future".into(),
        ));
    }
    let sequence = signed(report.sequence, "sequence")?;
    let observed = signed(report.observed_at, "observed_at")?;
    Timestamp::from_second(observed)?;
    let bytes_in = signed(report.bytes_in, "bytes_in")?;
    let bytes_out = signed(report.bytes_out, "bytes_out")?;
    let total = bytes_in
        .checked_add(bytes_out)
        .ok_or_else(|| DashError::BadRequest("traffic delta exceeds i64::MAX".into()))?;

    let tx = db.begin().await?;
    // Acquire SQLite's write lock before reading the cursor; concurrent sockets serialize here.
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO node_traffic_streams (node_id, stream_id, sequence) VALUES (?1, ?2, 0) \
         ON CONFLICT (node_id, stream_id) DO NOTHING",
        [node_id.into(), report.stream_id.clone().into()],
    ))
    .await?;

    #[derive(FromQueryResult)]
    struct Cursor {
        sequence: i64,
    }
    let cursor = Cursor::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT sequence FROM node_traffic_streams WHERE node_id = ?1 AND stream_id = ?2",
        [node_id.into(), report.stream_id.clone().into()],
    ))
    .one(&tx)
    .await?
    .ok_or(DashError::NotFound)?;
    if sequence <= cursor.sequence {
        tx.commit().await?;
        return Ok(cursor.sequence.cast_unsigned());
    }
    if cursor.sequence.checked_add(1) != Some(sequence) {
        return Err(DashError::BadRequest(format!(
            "traffic sequence gap: expected {}, received {sequence}",
            cursor.sequence + 1
        )));
    }
    let updated = tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE nodes SET traffic_total = traffic_total + ?5, \
             traffic_period_bytes_in = traffic_period_bytes_in + \
                 CASE WHEN ?2 >= traffic_period_start AND ?2 < traffic_period_end THEN ?3 ELSE 0 END, \
             traffic_period_bytes_out = traffic_period_bytes_out + \
                 CASE WHEN ?2 >= traffic_period_start AND ?2 < traffic_period_end THEN ?4 ELSE 0 END \
         WHERE id = ?1 AND traffic_total <= ?6",
        [node_id.into(), observed.into(), bytes_in.into(), bytes_out.into(), total.into(), (i64::MAX - total).into()],
    )).await?;
    if updated.rows_affected() == 0 {
        return Err(DashError::BadRequest(
            "lifetime node traffic exceeds i64::MAX".into(),
        ));
    }
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO node_traffic (node_id, observed_at, bytes_in, bytes_out) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (node_id, observed_at) DO UPDATE SET \
         bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out",
        [
            node_id.into(),
            observed.into(),
            bytes_in.into(),
            bytes_out.into(),
        ],
    ))
    .await?;
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE node_traffic_streams SET sequence = ?3 WHERE node_id = ?1 AND stream_id = ?2",
        [
            node_id.into(),
            report.stream_id.clone().into(),
            sequence.into(),
        ],
    ))
    .await?;
    tx.commit().await?;
    Ok(report.sequence)
}

#[cfg(test)]
mod tests;
