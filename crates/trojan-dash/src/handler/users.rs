//! Admin user CRUD.

use axum::Json;
use axum::extract::{Path, State};

use crate::auth::AdminAuth;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{AddUserRequest, UpdateUserRequest, UserResponse, UserRow, clamp_i64};
use crate::util::gen_password;
use trojan_auth::sha224_hex;

/// `GET /admin/users`
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<UserResponse>>, DashError> {
    let rows = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY id")
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(rows.iter().map(UserRow::to_response).collect()))
}

/// `POST /admin/users`
///
/// The generated password is returned exactly once — only its hash is stored.
pub async fn add(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<AddUserRequest>,
) -> Result<Json<UserResponse>, DashError> {
    let password = match body.password {
        Some(p) if !p.is_empty() => p,
        _ => gen_password(),
    };

    let row = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (hash, username, traffic_limit, traffic_used, expires_at, enabled) \
         VALUES (?1, ?2, ?3, 0, ?4, ?5) RETURNING *",
    )
    .bind(sha224_hex(&password))
    .bind(&body.username)
    .bind(clamp_i64(body.traffic_limit))
    .bind(clamp_i64(body.expires_at))
    .bind(body.enabled)
    .fetch_one(&state.pool)
    .await?;

    let mut response = row.to_response();
    response.password = Some(password);
    Ok(Json(response))
}

/// `GET /admin/users/{id}`
pub async fn get(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<Json<UserResponse>, DashError> {
    let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// `PATCH /admin/users/{id}` — absent fields keep their stored value.
pub async fn update(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, DashError> {
    if body.username.is_none()
        && body.traffic_limit.is_none()
        && body.traffic_used.is_none()
        && body.expires_at.is_none()
        && body.enabled.is_none()
    {
        return Err(DashError::BadRequest("no fields to update".to_owned()));
    }

    let row = sqlx::query_as::<_, UserRow>(
        "UPDATE users SET \
             username      = COALESCE(?1, username), \
             traffic_limit = COALESCE(?2, traffic_limit), \
             traffic_used  = COALESCE(?3, traffic_used), \
             expires_at    = COALESCE(?4, expires_at), \
             enabled       = COALESCE(?5, enabled) \
         WHERE id = ?6 RETURNING *",
    )
    .bind(body.username)
    .bind(body.traffic_limit.map(clamp_i64))
    .bind(body.traffic_used.map(clamp_i64))
    .bind(body.expires_at.map(clamp_i64))
    .bind(body.enabled)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(DashError::NotFound)?;

    Ok(Json(row.to_response()))
}

/// `DELETE /admin/users/{id}`
pub async fn remove(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<i64>,
) -> Result<&'static str, DashError> {
    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    Ok("deleted")
}
