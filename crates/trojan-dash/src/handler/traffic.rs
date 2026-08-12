//! Admin view of the traffic log.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use crate::auth::AdminAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{TrafficLogResponse, TrafficLogRow};

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
