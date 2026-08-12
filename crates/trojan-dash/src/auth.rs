//! Authentication for the three kinds of caller: the operator, a node, a user.

use std::net::IpAddr;

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, Unchanged};
use subtle::ConstantTimeEq;
use trojan_auth::sha224_hex;

use crate::entity::{nodes, users};
use crate::error::DashError;
use crate::state::AppState;
use crate::types::clamp_i64;
use crate::util::now_secs;

/// Cloudflare's client address header, kept because the panel used to sit
/// behind it and may again.
const CF_CONNECTING_IP: &str = "cf-connecting-ip";
const X_REAL_IP: &str = "x-real-ip";
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Bearer token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Username and password from an `Authorization: Basic` header.
fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    let encoded = headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let (username, password) = credentials.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

/// Best guess at who is calling, for the node list.
///
/// A reverse proxy in front of the service is the normal deployment, so the
/// forwarded headers win over the socket address.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>) -> String {
    for name in [CF_CONNECTING_IP, X_REAL_IP, X_FORWARDED_FOR] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            // X-Forwarded-For carries the whole chain; the client is first.
            let first = value.split(',').next().unwrap_or(value).trim();
            if !first.is_empty() {
                return first.to_owned();
            }
        }
    }

    peer.map(|ip| ip.to_string()).unwrap_or_default()
}

/// Middleware guarding `/admin/*`.
pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, DashError> {
    let token = bearer(req.headers()).ok_or(DashError::Unauthorized)?;
    let digest = sha224_hex(token);
    if !bool::from(digest.as_bytes().ct_eq(state.admin_digest.as_bytes())) {
        return Err(DashError::Unauthorized);
    }
    Ok(next.run(req).await)
}

/// Resolve a node's bearer token to its row, refreshing `last_seen`.
///
/// The refresh is throttled by [`crate::config::DashConfig::node_last_seen_ttl`]
/// so a busy node does not turn every call into a write.
pub async fn check_node(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    state: &AppState,
) -> Result<nodes::Model, DashError> {
    let token = bearer(headers).ok_or(DashError::Unauthorized)?;

    let node = nodes::Entity::find()
        .filter(nodes::Column::Token.eq(token))
        .one(&state.db)
        .await?
        .ok_or(DashError::Unauthorized)?;

    if node.enabled == 0 {
        return Err(DashError::Unauthorized);
    }

    let now = clamp_i64(now_secs());
    let ttl = clamp_i64(state.cfg.node_last_seen_ttl);
    if now.saturating_sub(node.last_seen) >= ttl {
        let touch = nodes::ActiveModel {
            id: Unchanged(node.id),
            last_seen: Set(now),
            ip: Set(client_ip(headers, peer)),
            ..Default::default()
        };
        // A failed liveness stamp is not worth refusing the call over.
        if let Err(e) =
            <nodes::ActiveModel as sea_orm::ActiveModelTrait>::update(touch, &state.db).await
        {
            tracing::warn!(node_id = node.id, error = %e, "failed to stamp last_seen");
        }
    }

    Ok(node)
}

/// Authenticate a user with HTTP Basic credentials.
pub async fn check_basic_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<users::Model, DashError> {
    let (username, password) = basic(headers).ok_or(DashError::Unauthorized)?;

    users::Entity::find()
        .filter(users::Column::Username.eq(&username))
        .filter(users::Column::Hash.eq(sha224_hex(&password)))
        .one(&state.db)
        .await?
        .ok_or(DashError::Unauthorized)
}
