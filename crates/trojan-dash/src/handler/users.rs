//! Admin user CRUD.
//!
//! Every write here also settles the verify cache: a disabled or deleted user
//! that stayed cached would keep connecting until the entry expired.

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryOrder, Unchanged};
use trojan_auth::sha224_hex;

use crate::entity::users;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{AddUserRequest, CacheData, UpdateUserRequest, UserResponse, clamp_i64};
use crate::util::gen_password;

/// `GET /admin/users`
pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<UserResponse>>, DashError> {
    let rows = users::Entity::find()
        .order_by_asc(users::Column::Id)
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(UserResponse::from).collect()))
}

/// `POST /admin/users`
///
/// The generated password is returned exactly once — only its hash is stored.
pub async fn add(
    State(state): State<AppState>,
    Json(body): Json<AddUserRequest>,
) -> Result<Json<UserResponse>, DashError> {
    let password = body
        .password
        .as_deref()
        .filter(|p| !p.is_empty())
        .map_or_else(gen_password, str::to_owned);
    let hash = sha224_hex(&password);

    let inserted = users::ActiveModel {
        hash: Set(hash.clone()),
        username: Set(body.username),
        traffic_limit: Set(clamp_i64(body.traffic_limit)),
        traffic_used: Set(0),
        expires_at: Set(clamp_i64(body.expires_at)),
        enabled: Set(i64::from(body.enabled)),
        ..Default::default()
    }
    .insert(&state.db)
    .await
    .map_err(DashError::from_db)?;

    state
        .cache
        .verify
        .insert(hash, CacheData::from(&inserted))
        .await;

    let mut response = UserResponse::from(&inserted);
    response.password = Some(password);
    Ok(Json(response))
}

/// `GET /admin/users/{id}`
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<UserResponse>, DashError> {
    let row = users::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(UserResponse::from(&row)))
}

/// `PATCH /admin/users/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, DashError> {
    let existing = users::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    let mut active = users::ActiveModel {
        id: Unchanged(existing.id),
        ..Default::default()
    };
    if let Some(username) = body.username {
        active.username = Set(username);
    }
    if let Some(v) = body.traffic_limit {
        active.traffic_limit = Set(clamp_i64(v));
    }
    if let Some(v) = body.traffic_used {
        active.traffic_used = Set(clamp_i64(v));
    }
    if let Some(v) = body.expires_at {
        active.expires_at = Set(clamp_i64(v));
    }
    if let Some(v) = body.enabled {
        active.enabled = Set(i64::from(v));
    }
    if !active.is_changed() {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }

    let updated = active.update(&state.db).await.map_err(DashError::from_db)?;

    state
        .cache
        .verify
        .insert(updated.hash.clone(), CacheData::from(&updated))
        .await;

    Ok(Json(UserResponse::from(&updated)))
}

/// `DELETE /admin/users/{id}`
pub async fn remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    let existing = users::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    users::Entity::delete_by_id(existing.id)
        .exec(&state.db)
        .await?;
    state.cache.verify.invalidate(&existing.hash).await;

    Ok("deleted")
}
