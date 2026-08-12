//! The endpoints nodes call: `/verify` and `/traffic`.
//!
//! Both answer with an encoded `Result` under HTTP 200 — a rejected user is an
//! answer, not a transport failure. Only a bad token, a malformed body, or a
//! broken database produces a non-2xx status.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use trojan_auth::protocol::{AuthError, AuthResult, TrafficRequest, VerifyRequest};

use crate::auth::NodeAuth;
use crate::codec::Codec;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{UserRow, clamp_i64};
use crate::util::{now_secs, today_date};

/// `POST /verify` — is this password hash allowed to connect?
pub async fn verify(
    State(state): State<AppState>,
    _node: NodeAuth,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DashError> {
    let codec = Codec::detect(&headers);
    let request: VerifyRequest = codec.decode(&body)?;

    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE hash = ?1")
        .bind(&request.hash)
        .fetch_optional(&state.pool)
        .await?;

    let result: Result<AuthResult, AuthError> = match user {
        Some(user) => user.validate(now_secs()),
        None => Err(AuthError::NotFound),
    };

    Ok(codec.encode(&result))
}

/// `POST /traffic` — add to a user's usage, and to today's per-node total.
pub async fn traffic(
    State(state): State<AppState>,
    node: NodeAuth,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DashError> {
    let codec = Codec::detect(&headers);
    let request: TrafficRequest = codec.decode(&body)?;

    // `user_id` is what /verify handed out: the row id, as a string.
    let Ok(user_id) = request.user_id.parse::<i64>() else {
        return Ok(codec.encode(&Err::<(), _>(AuthError::NotFound)));
    };
    let bytes = clamp_i64(request.bytes);

    // The running total and the daily row are one accounting event; a partial
    // apply would silently misreport usage.
    let mut tx = state.pool.begin().await?;

    let updated = sqlx::query("UPDATE users SET traffic_used = traffic_used + ?1 WHERE id = ?2")
        .bind(bytes)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if updated == 0 {
        // Dropping the transaction rolls it back.
        return Ok(codec.encode(&Err::<(), _>(AuthError::NotFound)));
    }

    sqlx::query(
        "INSERT INTO traffic_logs (user_id, node_id, bytes, date) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(user_id, node_id, date) DO UPDATE SET bytes = bytes + ?3",
    )
    .bind(user_id)
    .bind(node.node_id)
    .bind(bytes)
    .bind(today_date())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(codec.encode(&Ok::<(), AuthError>(())))
}
