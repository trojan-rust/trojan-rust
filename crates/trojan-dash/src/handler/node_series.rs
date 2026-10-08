//! Bounded directional history from acknowledged node reports, separate from user settlement.

use axum::Json;
use axum::extract::{Path, Query, State};
use sea_orm::{ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, Statement};
use serde::{Deserialize, Serialize};

use crate::entity::nodes;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::nonneg;

const MAX_SPAN: u64 = 366 * 86400;
const MAX_BUCKETS: u64 = 2160;

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Bucket {
    Minute,
    #[default]
    Hour,
    Day,
}

impl Bucket {
    fn seconds(self) -> u64 {
        match self {
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86400,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SeriesQuery {
    start: u64,
    end: u64,
    #[serde(default)]
    bucket: Bucket,
}

impl SeriesQuery {
    fn validate(&self) -> Result<(), DashError> {
        if self.end <= self.start || self.end > i64::MAX as u64 || self.end - self.start > MAX_SPAN
        {
            return Err(DashError::BadRequest(
                "require 0 <= start < end <= i64::MAX and a range of at most 366 days".into(),
            ));
        }
        let step = self.bucket.seconds();
        if (self.end - 1) / step - self.start / step + 1 > MAX_BUCKETS {
            return Err(DashError::BadRequest(
                "range exceeds 2160 buckets; use a larger bucket or a shorter range".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SeriesResponse {
    node_id: u64,
    source: &'static str,
    missing_buckets: &'static str,
    start: u64,
    end: u64,
    bucket_seconds: u64,
    points: Vec<Point>,
}

#[derive(Debug, Serialize)]
struct Point {
    timestamp: u64,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(FromQueryResult)]
struct Row {
    timestamp: i64,
    bytes_in: i64,
    bytes_out: i64,
}

/// `GET /admin/nodes/{id}/traffic/series?start=&end=&bucket=hour`
pub(crate) async fn series(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(query): Query<SeriesQuery>,
) -> Result<Json<SeriesResponse>, DashError> {
    query.validate()?;
    nodes::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;
    Ok(Json(build(&state.db, id, &query).await?))
}

async fn build<C: ConnectionTrait>(
    db: &C,
    id: i64,
    query: &SeriesQuery,
) -> Result<SeriesResponse, DashError> {
    let rows = Row::find_by_statement(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "SELECT observed_at - observed_at % ?4 AS timestamp, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out \
         FROM node_traffic WHERE node_id = ?1 AND observed_at >= ?2 AND observed_at < ?3 GROUP BY 1 ORDER BY 1",
        [id.into(), query.start.into(), query.end.into(), query.bucket.seconds().into()],
    )).all(db).await?;
    Ok(SeriesResponse {
        node_id: nonneg(id),
        source: "node_traffic",
        missing_buckets: "unknown",
        start: query.start,
        end: query.end,
        bucket_seconds: query.bucket.seconds(),
        points: rows
            .into_iter()
            .map(|row| Point {
                timestamp: nonneg(row.timestamp),
                bytes_in: nonneg(row.bytes_in),
                bytes_out: nonneg(row.bytes_out),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn history_preserves_directions_and_exact_range_without_fabricating_gaps() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "INSERT INTO nodes (id, name, token) VALUES (1, 'n1', 't1'), (2, 'n2', 't2')",
        )
        .await
        .unwrap();
        db.execute_unprepared("INSERT INTO node_traffic VALUES (1, 0, 50, 60), (1, 60, 1, 2), (1, 90, 3, 4), (1, 180, 7, 8), (1, 240, 100, 200), (2, 60, 999, 999)").await.unwrap();
        let query = SeriesQuery {
            start: 60,
            end: 240,
            bucket: Bucket::Minute,
        };
        query.validate().unwrap();
        let history = build(&db, 1, &query).await.unwrap();
        assert_eq!(
            serde_json::to_value(history).unwrap()["points"],
            serde_json::json!([
                {"timestamp": 60, "bytes_in": 4, "bytes_out": 6},
                {"timestamp": 180, "bytes_in": 7, "bytes_out": 8}
            ])
        );
        let plan = db.query_all(Statement::from_string(DatabaseBackend::Sqlite,
            "EXPLAIN QUERY PLAN SELECT SUM(bytes_in) FROM node_traffic WHERE node_id = 1 AND observed_at >= 60 AND observed_at < 240"
        )).await.unwrap();
        assert!(plan.iter().any(|row| {
            row.try_get::<String>("", "detail")
                .unwrap()
                .contains("node_id=? AND observed_at>? AND observed_at<?")
        }));
    }

    #[test]
    fn rejects_unbounded_or_excessive_resolution() {
        for query in [
            SeriesQuery {
                start: 5,
                end: 5,
                bucket: Bucket::Hour,
            },
            SeriesQuery {
                start: 0,
                end: MAX_SPAN + 1,
                bucket: Bucket::Day,
            },
            SeriesQuery {
                start: 0,
                end: 2161 * 60,
                bucket: Bucket::Minute,
            },
            SeriesQuery {
                start: i64::MAX as u64,
                end: u64::MAX,
                bucket: Bucket::Day,
            },
        ] {
            assert!(query.validate().is_err());
        }
        SeriesQuery {
            start: 0,
            end: 2160 * 60,
            bucket: Bucket::Minute,
        }
        .validate()
        .unwrap();
    }
}
