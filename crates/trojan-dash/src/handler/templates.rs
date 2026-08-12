//! Admin CRUD for subscription templates.
//!
//! The public `/sub/{name}` endpoint reads these through a cache keyed by
//! name, so a rename has to drop the old key as well as write the new one.

use axum::Json;
use axum::extract::{Path, State};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryOrder, Unchanged};

use crate::entity::sub_templates;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{
    AddSubTemplateRequest, SubTemplateResponse, UpdateSubTemplateRequest, clamp_i64,
};
use crate::util::now_secs;

/// `GET /admin/sub-templates`
pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<SubTemplateResponse>>, DashError> {
    let rows = sub_templates::Entity::find()
        .order_by_asc(sub_templates::Column::Id)
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(SubTemplateResponse::from).collect()))
}

/// `POST /admin/sub-templates`
pub async fn add(
    State(state): State<AppState>,
    Json(body): Json<AddSubTemplateRequest>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    let now = clamp_i64(now_secs());

    let inserted = sub_templates::ActiveModel {
        name: Set(body.name),
        filename: Set(body.filename),
        content: Set(body.content),
        content_type: Set(body.content_type),
        update_interval: Set(body.update_interval),
        profile_url: Set(body.profile_url),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&state.db)
    .await
    .map_err(DashError::from_db)?;

    Ok(Json(SubTemplateResponse::from(&inserted)))
}

/// `GET /admin/sub-templates/{id}`
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    let row = sub_templates::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(SubTemplateResponse::from(&row)))
}

/// `PATCH /admin/sub-templates/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateSubTemplateRequest>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    let existing = sub_templates::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    let mut active = sub_templates::ActiveModel {
        id: Unchanged(existing.id),
        ..Default::default()
    };
    if let Some(name) = body.name {
        active.name = Set(name);
    }
    if let Some(filename) = body.filename {
        active.filename = Set(filename);
    }
    if let Some(content) = body.content {
        active.content = Set(content);
    }
    if let Some(content_type) = body.content_type {
        active.content_type = Set(content_type);
    }
    if let Some(update_interval) = body.update_interval {
        active.update_interval = Set(update_interval);
    }
    if let Some(profile_url) = body.profile_url {
        active.profile_url = Set(profile_url);
    }
    if !active.is_changed() {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }
    active.updated_at = Set(clamp_i64(now_secs()));

    let updated = active.update(&state.db).await.map_err(DashError::from_db)?;

    state
        .cache
        .sub
        .insert(updated.name.clone(), updated.clone())
        .await;
    if updated.name != existing.name {
        state.cache.sub.invalidate(&existing.name).await;
    }

    Ok(Json(SubTemplateResponse::from(&updated)))
}

/// `DELETE /admin/sub-templates/{id}`
pub async fn remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    let existing = sub_templates::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(DashError::NotFound)?;

    sub_templates::Entity::delete_by_id(existing.id)
        .exec(&state.db)
        .await?;
    state.cache.sub.invalidate(&existing.name).await;

    Ok("deleted")
}
