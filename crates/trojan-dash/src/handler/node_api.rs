//! The endpoints nodes call: `/verify`, `/traffic` and `/traffic/chain`.
//!
//! Both answer with an encoded `Result` under HTTP 200 — a rejected user is an
//! answer, not a transport failure. Only a bad token, a malformed body, or a
//! broken database produces a non-2xx status.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use trojan_auth::protocol::{
    AuthError, AuthResult, ChainTrafficRequest, TrafficRequest, VerifyRequest,
};

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

/// `POST /traffic/chain` — credit a relay hop for traffic it carried.
///
/// Sent by an exit node on behalf of the hops in front of it, which never see
/// whose traffic they forward. Only the per-node daily total moves: the user's
/// own quota is settled once, by `/traffic`, so a three-hop chain does not
/// bill a user three times for one download.
pub async fn chain_traffic(
    State(state): State<AppState>,
    _node: NodeAuth,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DashError> {
    let codec = Codec::detect(&headers);
    let request: ChainTrafficRequest = codec.decode(&body)?;

    let (Ok(user_id), Ok(node_id)) = (
        request.user_id.parse::<i64>(),
        request.node_id.parse::<i64>(),
    ) else {
        return Ok(codec.encode(&Err::<(), _>(AuthError::NotFound)));
    };

    // Both ids are claims about rows this database owns, and traffic_logs has
    // foreign keys on each. A chain naming a hop the panel has never heard of
    // is a stale config on the reporting node, not a server fault, so answer
    // with a verdict instead of letting the insert fail.
    let (user_known, node_known): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1), EXISTS(SELECT 1 FROM nodes WHERE id = ?2)",
    )
    .bind(user_id)
    .bind(node_id)
    .fetch_one(&state.pool)
    .await?;
    if !user_known || !node_known {
        return Ok(codec.encode(&Err::<(), _>(AuthError::NotFound)));
    }

    sqlx::query(
        "INSERT INTO traffic_logs (user_id, node_id, bytes, date) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(user_id, node_id, date) DO UPDATE SET bytes = bytes + ?3",
    )
    .bind(user_id)
    .bind(node_id)
    .bind(clamp_i64(request.bytes))
    .bind(today_date())
    .execute(&state.pool)
    .await?;

    Ok(codec.encode(&Ok::<(), AuthError>(())))
}
