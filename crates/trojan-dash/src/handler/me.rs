//! User self-service.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use sea_orm::{DatabaseBackend, EntityTrait, FromQueryResult, QueryOrder, QuerySelect, Statement};

use crate::auth::check_basic_auth;
use crate::entity::sub_templates;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{
    Grouping, MeResponse, NodeTrafficResponse, NodeTrafficRow, SeriesQuery, SeriesResponse,
    UsageRow, UserResponse, nonneg,
};
use crate::util::{hour_hours_ago, month_start};

/// `GET /me` — the caller's own account, what it has spent recently, usage per
/// node, and the subscription names they can fetch.
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, DashError> {
    let user = check_basic_auth(&headers, &state).await?;

    // Both windows in one round trip: a client showing them side by side —
    // the Surge panel does — would otherwise ask twice.
    let usage = UsageRow::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT \
           (SELECT COALESCE(SUM(bytes), 0) FROM traffic_hourly \
            WHERE user_id = ?1 AND hour >= ?2) AS last_24h, \
           (SELECT COALESCE(SUM(bytes), 0) FROM traffic_logs \
            WHERE user_id = ?1 AND date >= ?3) AS month",
        [
            user.id.into(),
            hour_hours_ago(23).into(),
            month_start().into(),
        ],
    ))
    .one(&state.db)
    .await?
    .unwrap_or_default();

    let traffic = NodeTrafficRow::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT t.node_id AS node_id, n.name AS node_name, SUM(t.bytes) AS total_bytes \
         FROM traffic_logs t JOIN nodes n ON t.node_id = n.id \
         WHERE t.user_id = ?1 GROUP BY t.node_id ORDER BY total_bytes DESC",
        [user.id.into()],
    ))
    .all(&state.db)
    .await?;

    let names = sub_templates::Entity::find()
        .select_only()
        .column(sub_templates::Column::Name)
        .order_by_asc(sub_templates::Column::Id)
        .into_tuple::<String>()
        .all(&state.db)
        .await?;

    Ok(Json(MeResponse {
        user: UserResponse::from(&user),
        last_24h_bytes: nonneg(usage.last_24h),
        month_bytes: nonneg(usage.month),
        traffic_by_node: traffic.iter().map(NodeTrafficResponse::from).collect(),
        sub_templates: names,
    }))
}

/// `GET /me/traffic?range=&group=` — the caller's own traffic over time.
///
/// The same series the admin chart draws, scoped to whoever authenticated:
/// `user_id` comes from the credentials, never from the query string, so no
/// request can widen it to somebody else.
pub async fn traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SeriesQuery>,
) -> Result<Json<SeriesResponse>, DashError> {
    let user = check_basic_auth(&headers, &state).await?;

    let scoped = SeriesQuery {
        range: query.range,
        // A user has one account; breaking their own traffic down by user
        // would draw one line labelled with their name.
        group: match query.group {
            Grouping::User => Grouping::None,
            other => other,
        },
        user_id: Some(user.id),
        node_id: query.node_id,
    };

    Ok(Json(crate::handler::traffic::build(&state, &scoped).await?))
}
