//! User self-service.

use axum::Json;
use axum::extract::State;

use crate::auth::UserAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{MeResponse, NodeTrafficRow};

/// `GET /me` — the caller's own account, usage per node, and the subscription
/// names they can fetch.
pub async fn me(
    State(state): State<AppState>,
    UserAuth(user): UserAuth,
) -> Result<Json<MeResponse>, DashError> {
    let traffic = sqlx::query_as::<_, NodeTrafficRow>(
        "SELECT t.node_id, n.name AS node_name, SUM(t.bytes) AS total_bytes \
         FROM traffic_logs t JOIN nodes n ON t.node_id = n.id \
         WHERE t.user_id = ?1 GROUP BY t.node_id ORDER BY total_bytes DESC",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let sub_templates =
        sqlx::query_scalar::<_, String>("SELECT name FROM sub_templates ORDER BY id")
            .fetch_all(&state.pool)
            .await?;

    Ok(Json(MeResponse {
        user: user.to_response(),
        traffic_by_node: traffic.iter().map(NodeTrafficRow::to_response).collect(),
        sub_templates,
    }))
}
