//! Admin CRUD for subscription templates.

use axum::Json;
use axum::extract::{Path, State};

use crate::auth::AdminAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{
    AddSubTemplateRequest, SubTemplateResponse, SubTemplateRow, UpdateSubTemplateRequest, clamp_i64,
};
use crate::util::now_secs;

/// `GET /admin/sub-templates`
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<SubTemplateResponse>>, DashError> {
    let rows = sqlx::query_as::<_, SubTemplateRow>("SELECT * FROM sub_templates ORDER BY id")
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(rows.iter().map(SubTemplateRow::to_response).collect()))
}

/// `POST /admin/sub-templates`
pub async fn add(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<AddSubTemplateRequest>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    let now = clamp_i64(now_secs());

    let row = sqlx::query_as::<_, SubTemplateRow>(
        "INSERT INTO sub_templates \
             (name, filename, content, content_type, update_interval, profile_url, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) RETURNING *",
    )
    .bind(&body.name)
    .bind(&body.filename)
    .bind(&body.content)
    .bind(&body.content_type)
    .bind(&body.update_interval)
    .bind(&body.profile_url)
    .bind(now)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(row.to_response()))
}

/// `GET /admin/sub-templates/{id}`
pub async fn get(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    let row = sqlx::query_as::<_, SubTemplateRow>("SELECT * FROM sub_templates WHERE id = ?1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// `PATCH /admin/sub-templates/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
    Json(body): Json<UpdateSubTemplateRequest>,
) -> Result<Json<SubTemplateResponse>, DashError> {
    if body.name.is_none()
        && body.filename.is_none()
        && body.content.is_none()
        && body.content_type.is_none()
        && body.update_interval.is_none()
        && body.profile_url.is_none()
    {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }

    let row = sqlx::query_as::<_, SubTemplateRow>(
        "UPDATE sub_templates SET \
             name            = COALESCE(?1, name), \
             filename        = COALESCE(?2, filename), \
             content         = COALESCE(?3, content), \
             content_type    = COALESCE(?4, content_type), \
             update_interval = COALESCE(?5, update_interval), \
             profile_url     = COALESCE(?6, profile_url), \
             updated_at      = ?7 \
         WHERE id = ?8 RETURNING *",
    )
    .bind(body.name)
    .bind(body.filename)
    .bind(body.content)
    .bind(body.content_type)
    .bind(body.update_interval)
    .bind(body.profile_url)
    .bind(clamp_i64(now_secs()))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// `DELETE /admin/sub-templates/{id}`
pub async fn remove(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    sqlx::query("DELETE FROM sub_templates WHERE id = ?1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    Ok("deleted")
}
