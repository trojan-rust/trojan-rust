//! Admin views of the traffic log.

use axum::Json;
use axum::extract::{Query, State};
use sea_orm::{
    ColumnTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, Statement,
};

use crate::entity::traffic_logs;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{
    DailyQuery, DailyTrafficResponse, DailyTrafficRow, TrafficLogResponse, TrafficQuery,
};
use crate::util::date_days_ago;

/// The raw log is unbounded; a page of it is all any view needs.
const LIMIT: u64 = 1000;

/// `GET /admin/traffic?user_id=&node_id=`
pub async fn list(
    State(state): State<AppState>,
    Query(filter): Query<TrafficQuery>,
) -> Result<Json<Vec<TrafficLogResponse>>, DashError> {
    let mut select = traffic_logs::Entity::find();
    if let Some(user_id) = filter.user_id {
        select = select.filter(traffic_logs::Column::UserId.eq(user_id));
    }
    if let Some(node_id) = filter.node_id {
        select = select.filter(traffic_logs::Column::NodeId.eq(node_id));
    }

    let rows = select
        .order_by_desc(traffic_logs::Column::Date)
        .order_by_desc(traffic_logs::Column::Id)
        .limit(LIMIT)
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(TrafficLogResponse::from).collect()))
}

/// `GET /admin/traffic/daily?days=`
///
/// Totals per day per node. The raw log endpoint stops at 1000 rows, which a
/// chart of any real deployment would hit within days; this aggregates in
/// SQLite instead, so the response is bounded by days × nodes.
pub async fn daily(
    State(state): State<AppState>,
    Query(window): Query<DailyQuery>,
) -> Result<Json<Vec<DailyTrafficResponse>>, DashError> {
    let days = window.days.unwrap_or(30).clamp(1, 365);

    let rows = DailyTrafficRow::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT t.date AS date, t.node_id AS node_id, n.name AS node_name, \
                SUM(t.bytes) AS bytes \
         FROM traffic_logs t JOIN nodes n ON t.node_id = n.id \
         WHERE t.date >= ?1 \
         GROUP BY t.date, t.node_id \
         ORDER BY t.date, n.name",
        [date_days_ago(days - 1).into()],
    ))
    .all(&state.db)
    .await?;

    Ok(Json(rows.iter().map(DailyTrafficResponse::from).collect()))
}
