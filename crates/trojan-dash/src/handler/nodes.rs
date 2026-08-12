//! Admin node CRUD. A node's token is its only credential, so creating a node
//! and rotating its token both mint a fresh one.

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryOrder, Unchanged};

use crate::entity::nodes;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{AddNodeRequest, NodeResponse, UpdateNodeRequest, clamp_i64};
use crate::util::{gen_password, now_secs};

/// Store a config as text, defaulting to an empty object.
///
/// The agent receives these bytes verbatim, so what an operator wrote is what
/// the node boots.
fn encode_config(config: Option<&serde_json::Value>) -> String {
    config.map_or_else(|| "{}".to_owned(), ToString::to_string)
}

/// `GET /admin/nodes`
pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<NodeResponse>>, DashError> {
    let rows = nodes::Entity::find()
        .order_by_asc(nodes::Column::Id)
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(NodeResponse::from).collect()))
}

/// `POST /admin/nodes`
pub async fn add(
    State(state): State<AppState>,
    Json(body): Json<AddNodeRequest>,
) -> Result<Json<NodeResponse>, DashError> {
    let inserted = nodes::ActiveModel {
        name: Set(body.name),
        token: Set(gen_password()),
        enabled: Set(1),
        ip: Set(String::new()),
        last_seen: Set(0),
        created_at: Set(clamp_i64(now_secs())),
        node_type: Set(body.node_type),
        config: Set(encode_config(body.config.as_ref())),
        config_version: Set(1),
        agent_version: Set(String::new()),
        connections_active: Set(0),
        bytes_in: Set(0),
        bytes_out: Set(0),
        uptime_secs: Set(0),
        ..Default::default()
    }
    .insert(&state.db)
    .await
    .map_err(DashError::from_db)?;

    Ok(Json(NodeResponse::from(&inserted)))
}

/// `GET /admin/nodes/{id}`
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<NodeResponse>, DashError> {
    let row = nodes::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(NodeResponse::from(&row)))
}

/// `PATCH /admin/nodes/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateNodeRequest>,
) -> Result<Json<NodeResponse>, DashError> {
    let existing = nodes::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    let mut active = nodes::ActiveModel {
        id: Unchanged(existing.id),
        ..Default::default()
    };
    if let Some(name) = body.name {
        active.name = Set(name);
    }
    if let Some(v) = body.enabled {
        active.enabled = Set(i64::from(v));
    }
    if let Some(node_type) = body.node_type {
        active.node_type = Set(node_type);
    }
    if let Some(config) = body.config {
        // The version is how an agent tells one config from another; a changed
        // config that kept its version would be ignored.
        active.config = Set(config.to_string());
        active.config_version = Set(existing.config_version.saturating_add(1));
    }
    if !active.is_changed() {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }

    let updated = active.update(&state.db).await.map_err(DashError::from_db)?;

    Ok(Json(NodeResponse::from(&updated)))
}

/// `DELETE /admin/nodes/{id}`
pub async fn remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    nodes::Entity::delete_by_id(id).exec(&state.db).await?;
    Ok("deleted")
}

/// `POST /admin/nodes/{id}/rotate` — issue a new token, invalidating the old.
pub async fn rotate(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<NodeResponse>, DashError> {
    let existing = nodes::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    let updated = nodes::ActiveModel {
        id: Unchanged(existing.id),
        token: Set(gen_password()),
        ..Default::default()
    }
    .update(&state.db)
    .await
    .map_err(DashError::from_db)?;

    Ok(Json(NodeResponse::from(&updated)))
}
