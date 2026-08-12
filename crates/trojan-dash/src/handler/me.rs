//! User self-service.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use sea_orm::{DatabaseBackend, EntityTrait, FromQueryResult, QueryOrder, QuerySelect, Statement};

use crate::auth::check_basic_auth;
use crate::entity::sub_templates;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{MeResponse, NodeTrafficResponse, NodeTrafficRow, UserResponse};

/// `GET /me` — the caller's own account, usage per node, and the subscription
/// names they can fetch.
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, DashError> {
    let user = check_basic_auth(&headers, &state).await?;

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
        traffic_by_node: traffic.iter().map(NodeTrafficResponse::from).collect(),
        sub_templates: names,
    }))
}
