//! Extractors for the three kinds of caller: the operator, a node, a user.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header;
use axum::http::request::Parts;
use base64::Engine;
use subtle::ConstantTimeEq;
use trojan_auth::sha224_hex;

use crate::error::DashError;
use crate::state::AppState;
use crate::types::UserRow;
use crate::util::now_secs;

/// Proof that the caller presented the admin token.
#[derive(Debug)]
pub struct AdminAuth;

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = DashError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(DashError::Unauthorized)?;
        let digest = sha224_hex(token);
        if bool::from(digest.as_bytes().ct_eq(state.admin_digest.as_bytes())) {
            Ok(Self)
        } else {
            Err(DashError::Unauthorized)
        }
    }
}

/// An authenticated node, identified by its bearer token.
///
/// Extraction doubles as the liveness signal: `last_seen` and the source
/// address are refreshed here, throttled by
/// [`AppState::node_last_seen_ttl`] so a busy node does not turn every call
/// into a write.
#[derive(Debug)]
pub struct NodeAuth {
    /// Row id of the calling node, for attributing traffic.
    pub node_id: i64,
}

/// The columns [`NodeAuth`] needs; the rest of the row is irrelevant here.
#[derive(sqlx::FromRow)]
struct NodeLookup {
    id: i64,
    enabled: bool,
    last_seen: i64,
}

impl FromRequestParts<AppState> for NodeAuth {
    type Rejection = DashError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(DashError::Unauthorized)?.to_owned();

        let node = sqlx::query_as::<_, NodeLookup>(
            "SELECT id, enabled, last_seen FROM nodes WHERE token = ?1",
        )
        .bind(&token)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(DashError::Unauthorized)?;

        if !node.enabled {
            return Err(DashError::Unauthorized);
        }

        let now = now_secs();
        let last_seen = u64::try_from(node.last_seen).unwrap_or(0);
        if now.saturating_sub(last_seen) >= state.node_last_seen_ttl {
            let ip = client_ip(parts).unwrap_or_default();
            sqlx::query("UPDATE nodes SET last_seen = ?1, ip = ?2 WHERE id = ?3")
                .bind(i64::try_from(now).unwrap_or(i64::MAX))
                .bind(&ip)
                .bind(node.id)
                .execute(&state.pool)
                .await?;
        }

        Ok(Self { node_id: node.id })
    }
}

/// A user authenticated with HTTP Basic credentials (username + password).
#[derive(Debug)]
pub struct UserAuth(pub UserRow);

impl FromRequestParts<AppState> for UserAuth {
    type Rejection = DashError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let encoded = authorization(parts)
            .and_then(|v| v.strip_prefix("Basic "))
            .ok_or(DashError::Unauthorized)?;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| DashError::Unauthorized)?;
        let credentials = String::from_utf8(decoded).map_err(|_| DashError::Unauthorized)?;
        let (username, password) = credentials.split_once(':').ok_or(DashError::Unauthorized)?;

        let user =
            sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = ?1 AND hash = ?2")
                .bind(username)
                .bind(sha224_hex(password))
                .fetch_optional(&state.pool)
                .await?
                .ok_or(DashError::Unauthorized)?;

        Ok(Self(user))
    }
}

/// Raw `Authorization` header value.
fn authorization(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

/// Bearer token from the `Authorization` header.
fn bearer(parts: &Parts) -> Option<&str> {
    authorization(parts)?.strip_prefix("Bearer ")
}

/// Best guess at who is calling, for the node list.
///
/// A reverse proxy in front of the service is the normal deployment, so the
/// forwarded headers win over the socket address.
fn client_ip(parts: &Parts) -> Option<String> {
    let header_ip = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };

    header_ip("x-forwarded-for")
        .or_else(|| header_ip("x-real-ip"))
        .or_else(|| {
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
        })
}
