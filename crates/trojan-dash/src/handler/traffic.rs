//! Admin view of the traffic log.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use crate::auth::AdminAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{DailyTrafficResponse, DailyTrafficRow, TrafficLogResponse, TrafficLogRow};
use crate::util::date_days_ago;

/// Optional filters for `GET /admin/traffic`.
#[derive(Debug, Deserialize)]
pub struct TrafficQuery {
    pub user_id: Option<i64>,
    pub node_id: Option<i64>,
}

/// `GET /admin/traffic?user_id=&node_id=`
///
/// Capped at the most recent 1000 rows, as the Workers version was.
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(filter): Query<TrafficQuery>,
) -> Result<Json<Vec<TrafficLogResponse>>, DashError> {
    let rows = sqlx::query_as::<_, TrafficLogRow>(
        "SELECT * FROM traffic_logs \
         WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR node_id = ?2) \
         ORDER BY date DESC, id DESC LIMIT 1000",
    )
    .bind(filter.user_id)
    .bind(filter.node_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(TrafficLogRow::to_response).collect()))
}

/// Window for `GET /admin/traffic/daily`.
#[derive(Debug, Deserialize)]
pub struct DailyQuery {
    /// How far back to reach, in days. Defaults to 30, capped at a year.
    pub days: Option<i64>,
}

/// `GET /admin/traffic/daily?days=`
///
/// Totals per day per node. The raw log endpoint stops at 1000 rows, which a
/// chart of any real deployment would hit within days; this aggregates in
/// SQLite instead, so the response is bounded by days × nodes.
pub async fn daily(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(window): Query<DailyQuery>,
) -> Result<Json<Vec<DailyTrafficResponse>>, DashError> {
    let days = window.days.unwrap_or(30).clamp(1, 365);

    let rows = sqlx::query_as::<_, DailyTrafficRow>(
        "SELECT t.date, t.node_id, n.name AS node_name, SUM(t.bytes) AS bytes \
         FROM traffic_logs t JOIN nodes n ON t.node_id = n.id \
         WHERE t.date >= ?1 \
         GROUP BY t.date, t.node_id \
         ORDER BY t.date, n.name",
    )
    .bind(date_days_ago(days - 1))
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.iter().map(DailyTrafficRow::to_response).collect(),
    ))
}
