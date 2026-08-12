//! Admin node CRUD. A node's token is its only credential, so creating a node
//! and rotating its token both mint a fresh one.

use axum::Json;
use axum::extract::{Path, State};

use crate::auth::AdminAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{AddNodeRequest, NodeResponse, NodeRow, UpdateNodeRequest, clamp_i64};
use crate::util::{gen_password, now_secs};

/// `GET /admin/nodes`
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<NodeResponse>>, DashError> {
    let rows = sqlx::query_as::<_, NodeRow>("SELECT * FROM nodes ORDER BY id")
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(rows.iter().map(NodeRow::to_response).collect()))
}

/// `POST /admin/nodes`
pub async fn add(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<AddNodeRequest>,
) -> Result<Json<NodeResponse>, DashError> {
    let row = sqlx::query_as::<_, NodeRow>(
        "INSERT INTO nodes (name, token, enabled, last_seen, created_at, node_type, config) \
         VALUES (?1, ?2, 1, 0, ?3, ?4, ?5) RETURNING *",
    )
    .bind(&body.name)
    .bind(gen_password())
    .bind(clamp_i64(now_secs()))
    .bind(&body.node_type)
    .bind(encode_config(body.config.as_ref()))
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(row.to_response()))
}

/// `GET /admin/nodes/{id}`
pub async fn get(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<Json<NodeResponse>, DashError> {
    let row = sqlx::query_as::<_, NodeRow>("SELECT * FROM nodes WHERE id = ?1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// `PATCH /admin/nodes/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
    Json(body): Json<UpdateNodeRequest>,
) -> Result<Json<NodeResponse>, DashError> {
    if body.name.is_none()
        && body.enabled.is_none()
        && body.node_type.is_none()
        && body.config.is_none()
    {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }

    // A new config is a new version: that is how an agent tells the config it
    // is running from the one it would be handed on reconnect.
    let config = body.config.as_ref().map(|c| encode_config(Some(c)));

    let row = sqlx::query_as::<_, NodeRow>(
        "UPDATE nodes SET \
             name      = COALESCE(?1, name), \
             enabled   = COALESCE(?2, enabled), \
             node_type = COALESCE(?3, node_type), \
             config    = COALESCE(?4, config), \
             config_version = config_version + CASE WHEN ?4 IS NULL THEN 0 ELSE 1 END \
         WHERE id = ?5 RETURNING *",
    )
    .bind(body.name)
    .bind(body.enabled)
    .bind(body.node_type)
    .bind(config)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// Store a config as text, defaulting to an empty object.
///
/// The panel never interprets it — only the agent's runner does — so it is
/// kept as written rather than validated against a schema this crate would
/// then have to track.
fn encode_config(config: Option<&serde_json::Value>) -> String {
    config.map_or_else(|| "{}".to_owned(), ToString::to_string)
}

/// `DELETE /admin/nodes/{id}`
pub async fn remove(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    sqlx::query("DELETE FROM nodes WHERE id = ?1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    Ok("deleted")
}

/// `POST /admin/nodes/{id}/rotate` — issue a new token, invalidating the old.
pub async fn rotate(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<Json<NodeResponse>, DashError> {
    let row = sqlx::query_as::<_, NodeRow>("UPDATE nodes SET token = ?1 WHERE id = ?2 RETURNING *")
        .bind(gen_password())
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}
