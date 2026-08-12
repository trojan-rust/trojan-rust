//! Per-node allowances: what one user may move through one node in a month.
//!
//! Like every write on `users`, each one settles the verify cache — a node
//! enforces the figures it was last handed, so a raised limit that stayed
//! cached would keep blocking.

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};

use crate::entity::{user_node_limits, users};
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{NodeLimitRequest, NodeLimitResponse, clamp_i64, nonneg};

/// `GET /admin/users/{id}/limits`
pub async fn list(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<Json<Vec<NodeLimitResponse>>, DashError> {
    let rows = user_node_limits::Entity::find()
        .filter(user_node_limits::Column::UserId.eq(user_id))
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(to_response).collect()))
}

/// `PUT /admin/users/{id}/limits/{node_id}` — set or replace one allowance.
pub async fn set(
    State(state): State<AppState>,
    Path((user_id, node_id)): Path<(i64, i64)>,
    Json(body): Json<NodeLimitRequest>,
) -> Result<Json<NodeLimitResponse>, DashError> {
    let user = users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    let limit = user_node_limits::ActiveModel {
        user_id: Set(user_id),
        node_id: Set(node_id),
        monthly_bytes: Set(clamp_i64(body.monthly_bytes)),
    };

    // The pair is the primary key, so a repeat call replaces rather than
    // collides — which is what "set this allowance" should mean.
    user_node_limits::Entity::insert(limit)
        .on_conflict(
            sea_orm::sea_query::OnConflict::columns([
                user_node_limits::Column::UserId,
                user_node_limits::Column::NodeId,
            ])
            .update_column(user_node_limits::Column::MonthlyBytes)
            .to_owned(),
        )
        .exec(&state.db)
        .await?;

    state.cache.verify.invalidate(&user.hash).await;

    Ok(Json(NodeLimitResponse {
        node_id: nonneg(node_id),
        monthly_bytes: body.monthly_bytes,
    }))
}

/// `DELETE /admin/users/{id}/limits/{node_id}` — back to uncapped.
pub async fn remove(
    State(state): State<AppState>,
    Path((user_id, node_id)): Path<(i64, i64)>,
) -> Result<&'static str, DashError> {
    let user = users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    user_node_limits::Entity::delete_by_id((user_id, node_id))
        .exec(&state.db)
        .await?;

    state.cache.verify.invalidate(&user.hash).await;

    Ok("deleted")
}

fn to_response(row: &user_node_limits::Model) -> NodeLimitResponse {
    NodeLimitResponse {
        node_id: nonneg(row.node_id),
        monthly_bytes: nonneg(row.monthly_bytes),
    }
}
