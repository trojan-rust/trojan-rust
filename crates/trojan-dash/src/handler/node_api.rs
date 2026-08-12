//! The endpoints nodes call: `/verify`, `/traffic` and `/traffic/chain`.
//!
//! All three answer with an encoded `Result` under HTTP 200 — a rejected user
//! is an answer, not a transport failure. Only a bad token, a malformed body,
//! or a broken database produces a non-2xx status.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter,
    Statement, TransactionTrait,
};
use trojan_auth::protocol::{
    AuthError, AuthResult, ChainTrafficRequest, TrafficRequest, VerifyRequest,
};

use crate::auth::check_node;
use crate::codec::{Wire, encode};
use crate::entity::users;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{CacheData, NodeQuota, clamp_i64};
use crate::util::{current_hour, month_start, now_secs, today_date};

/// `POST /verify` — is this password hash allowed to connect?
pub async fn verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    wire: Wire<VerifyRequest>,
) -> Result<Response, DashError> {
    check_node(&headers, Some(peer.ip()), &state).await?;
    let Wire { codec, body } = wire;

    if let Some(cached) = state.cache.verify.get(&body.hash).await {
        return encode(codec, &cached.validate(now_secs()));
    }

    let user = users::Entity::find()
        .filter(users::Column::Hash.eq(&body.hash))
        .one(&state.db)
        .await?;

    let result: Result<AuthResult, AuthError> = match user {
        Some(ref model) => {
            let mut data = CacheData::from(model);
            data.node_quotas = node_quotas(&state, model.id).await?;
            state
                .cache
                .verify
                .insert(body.hash.clone(), data.clone())
                .await;
            data.validate(now_secs())
        }
        None => Err(AuthError::NotFound),
    };

    encode(codec, &result)
}

/// This user's per-node allowances, with what the current UTC month has spent.
///
/// One query, and usually no rows: an allowance exists only where an operator
/// set one. The spend is summed rather than stored, so a month rolls over on
/// its own.
async fn node_quotas(state: &AppState, user_id: i64) -> Result<Vec<NodeQuota>, DashError> {
    NodeQuota::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT l.node_id AS node_id, l.monthly_bytes AS monthly_bytes, \
                COALESCE(SUM(t.bytes), 0) AS used \
         FROM user_node_limits l \
         LEFT JOIN traffic_logs t \
           ON t.user_id = l.user_id AND t.node_id = l.node_id AND t.date >= ?2 \
         WHERE l.user_id = ?1 \
         GROUP BY l.node_id, l.monthly_bytes",
        [user_id.into(), month_start().into()],
    ))
    .all(&state.db)
    .await
    .map_err(Into::into)
}

/// `POST /traffic` — add to a user's usage, and to today's per-node total.
pub async fn traffic(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    wire: Wire<TrafficRequest>,
) -> Result<Response, DashError> {
    let node = check_node(&headers, Some(peer.ip()), &state).await?;
    let Wire { codec, body } = wire;

    // `user_id` is what /verify handed out: the row id, as a string.
    let Ok(user_id) = body.user_id.parse::<i64>() else {
        return encode(codec, &Err::<(), _>(AuthError::NotFound));
    };

    if !apply_traffic(&state, user_id, node.id, body.bytes).await? {
        return encode(codec, &Err::<(), _>(AuthError::NotFound));
    }

    encode(codec, &Ok::<(), AuthError>(()))
}

/// Add `bytes` to a user's usage and to today's total for one node.
///
/// Returns `false` when the user does not exist, which is the caller's cue to
/// answer `NotFound` rather than to fail. Shared with the agent socket, which
/// reports the same numbers over a different transport.
pub(crate) async fn apply_traffic(
    state: &AppState,
    user_id: i64,
    node_id: i64,
    bytes: u64,
) -> Result<bool, DashError> {
    let bytes = clamp_i64(bytes);

    // The running total and the daily row are one accounting event; a partial
    // apply would silently misreport usage.
    let tx = state.db.begin().await?;

    let updated = tx
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE users SET traffic_used = traffic_used + ?1 WHERE id = ?2",
            [bytes.into(), user_id.into()],
        ))
        .await?;

    if updated.rows_affected() == 0 {
        // Dropping the transaction rolls it back.
        return Ok(false);
    }

    record_usage(&tx, user_id, node_id, bytes).await?;

    tx.commit().await?;

    // The cached copy still carries the old total, and a user near their limit
    // would keep connecting until it expired.
    invalidate_user(state, user_id).await;

    Ok(true)
}

/// Record `bytes` against one user and node in both rollups.
///
/// The daily row is the record of history; the hourly one is what a short
/// range reads, and is pruned once it ages out. They describe one event, so a
/// caller writes them inside a transaction and they move together.
async fn record_usage<C: ConnectionTrait>(
    conn: &C,
    user_id: i64,
    node_id: i64,
    bytes: i64,
) -> Result<(), DashError> {
    conn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO traffic_logs (user_id, node_id, bytes, date) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(user_id, node_id, date) DO UPDATE SET bytes = bytes + excluded.bytes",
        [
            user_id.into(),
            node_id.into(),
            bytes.into(),
            today_date().into(),
        ],
    ))
    .await?;

    conn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO traffic_hourly (user_id, node_id, bytes, hour) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(user_id, node_id, hour) DO UPDATE SET bytes = bytes + excluded.bytes",
        [
            user_id.into(),
            node_id.into(),
            bytes.into(),
            current_hour().into(),
        ],
    ))
    .await?;

    Ok(())
}

/// Drop a user's cached verification after their row changed.
async fn invalidate_user(state: &AppState, user_id: i64) {
    match users::Entity::find_by_id(user_id).one(&state.db).await {
        Ok(Some(user)) => state.cache.verify.invalidate(&user.hash).await,
        Ok(None) => {}
        Err(e) => tracing::warn!(user_id, error = %e, "could not refresh cached user"),
    }
}

/// `POST /traffic/chain` — credit a relay hop for traffic it carried.
///
/// Sent by an exit node on behalf of the hops in front of it, which never see
/// whose traffic they forward. Only the per-node rollups move: the user's own
/// quota is settled once, by `/traffic`, so a three-hop chain does not bill a
/// user three times for one download.
pub async fn chain_traffic(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    wire: Wire<ChainTrafficRequest>,
) -> Result<Response, DashError> {
    check_node(&headers, Some(peer.ip()), &state).await?;
    let Wire { codec, body } = wire;

    let (Ok(user_id), Ok(node_id)) = (body.user_id.parse::<i64>(), body.node_id.parse::<i64>())
    else {
        return encode(codec, &Err::<(), _>(AuthError::NotFound));
    };

    // Both ids are claims about rows this database owns, and traffic_logs has
    // foreign keys on each. A chain naming a hop the panel has never heard of
    // is a stale config on the reporting node, not a server fault, so answer
    // with a verdict instead of letting the insert fail.
    let known = crate::entity::nodes::Entity::find_by_id(node_id)
        .one(&state.db)
        .await?
        .is_some()
        && users::Entity::find_by_id(user_id)
            .one(&state.db)
            .await?
            .is_some();
    if !known {
        return encode(codec, &Err::<(), _>(AuthError::NotFound));
    }

    let tx = state.db.begin().await?;
    record_usage(&tx, user_id, node_id, clamp_i64(body.bytes)).await?;
    tx.commit().await?;

    encode(codec, &Ok::<(), AuthError>(()))
}
