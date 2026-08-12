//! Database rows, and the JSON shapes the panel consumes.
//!
//! Columns are SQLite `INTEGER`, so rows carry `i64` and convert on the way
//! out; the protocol and the panel both speak unsigned.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use trojan_auth::protocol::{AuthError, AuthMetadata, AuthResult};

/// Clamp a column to the unsigned range. Negative values are not reachable
/// through the API; a hand-edited database is not worth a panic.
fn nonneg(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Clamp an API value to what SQLite can hold in an `INTEGER`.
pub(crate) fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

// ── users ─────────────────────────────────────────────────────────

/// A row of `users`.
#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: i64,
    pub hash: String,
    pub username: String,
    pub traffic_limit: i64,
    pub traffic_used: i64,
    pub expires_at: i64,
    pub enabled: bool,
}

impl UserRow {
    /// Decide whether this user may connect right now.
    pub fn validate(&self, now: u64) -> Result<AuthResult, AuthError> {
        let (limit, used, expires) = (
            nonneg(self.traffic_limit),
            nonneg(self.traffic_used),
            nonneg(self.expires_at),
        );

        if !self.enabled {
            Err(AuthError::Disabled)
        } else if expires > 0 && now >= expires {
            Err(AuthError::Expired)
        } else if limit > 0 && used >= limit {
            Err(AuthError::TrafficExceeded)
        } else {
            Ok(AuthResult {
                user_id: Some(self.id.to_string()),
                metadata: Some(AuthMetadata {
                    traffic_limit: limit,
                    traffic_used: used,
                    expires_at: expires,
                    enabled: self.enabled,
                }),
            })
        }
    }

    /// Render for the admin API. The password is only known at creation time.
    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: nonneg(self.id),
            hash: self.hash.clone(),
            username: self.username.clone(),
            password: None,
            traffic_limit: nonneg(self.traffic_limit),
            traffic_used: nonneg(self.traffic_used),
            expires_at: nonneg(self.expires_at),
            enabled: self.enabled,
        }
    }
}

/// A user as the panel sees it.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: u64,
    pub hash: String,
    pub username: String,
    /// Only present in the response that created the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

/// `POST /admin/users` body.
#[derive(Debug, Deserialize)]
pub struct AddUserRequest {
    /// Generated when absent or empty.
    #[serde(default)]
    pub password: Option<String>,
    pub username: String,
    #[serde(default)]
    pub traffic_limit: u64,
    #[serde(default)]
    pub expires_at: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// `PATCH /admin/users/:id` body. Absent fields are left alone.
#[derive(Debug, Default, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub traffic_limit: Option<u64>,
    pub traffic_used: Option<u64>,
    pub expires_at: Option<u64>,
    pub enabled: Option<bool>,
}

// ── nodes ─────────────────────────────────────────────────────────

/// A row of `nodes`.
#[derive(Debug, FromRow)]
pub struct NodeRow {
    pub id: i64,
    pub name: String,
    pub token: String,
    pub enabled: bool,
    pub ip: String,
    pub last_seen: i64,
    pub created_at: i64,
    /// Which service the agent on this node boots.
    pub node_type: String,
    /// Opaque service config, handed to the agent verbatim.
    pub config: String,
    /// Bumped on every config change, so an agent can tell one apart.
    pub config_version: i64,
    /// What the last heartbeat said. Zero until an agent connects.
    pub agent_version: String,
    pub connections_active: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub uptime_secs: i64,
}

impl NodeRow {
    pub fn to_response(&self) -> NodeResponse {
        NodeResponse {
            id: nonneg(self.id),
            name: self.name.clone(),
            token: self.token.clone(),
            enabled: self.enabled,
            ip: self.ip.clone(),
            last_seen: nonneg(self.last_seen),
            created_at: nonneg(self.created_at),
            node_type: self.node_type.clone(),
            // Stored as text so the panel never has to understand it; parsed
            // here only so the API answers with JSON rather than a JSON string.
            config: serde_json::from_str(&self.config).unwrap_or(serde_json::Value::Null),
            config_version: nonneg(self.config_version),
            agent_version: self.agent_version.clone(),
            connections_active: nonneg(self.connections_active),
            bytes_in: nonneg(self.bytes_in),
            bytes_out: nonneg(self.bytes_out),
            uptime_secs: nonneg(self.uptime_secs),
        }
    }
}

/// A node as the panel sees it.
#[derive(Debug, Serialize)]
pub struct NodeResponse {
    pub id: u64,
    pub name: String,
    pub token: String,
    pub enabled: bool,
    pub ip: String,
    pub last_seen: u64,
    pub created_at: u64,
    pub node_type: String,
    pub config: serde_json::Value,
    pub config_version: u64,
    pub agent_version: String,
    pub connections_active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_secs: u64,
}

/// `POST /admin/nodes` body.
#[derive(Debug, Deserialize)]
pub struct AddNodeRequest {
    pub name: String,
    /// Service to boot: `server`, `entry` or `relay`. Defaults to `server`.
    #[serde(default = "default_node_type")]
    pub node_type: String,
    /// Service config for the agent, passed through untouched.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

fn default_node_type() -> String {
    "server".to_owned()
}

/// `PATCH /admin/nodes/:id` body.
#[derive(Debug, Default, Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub node_type: Option<String>,
    /// Replaces the stored config and bumps `config_version`.
    pub config: Option<serde_json::Value>,
}

// ── traffic_logs ──────────────────────────────────────────────────

/// A row of `traffic_logs`.
#[derive(Debug, FromRow)]
pub struct TrafficLogRow {
    pub id: i64,
    pub user_id: i64,
    pub node_id: i64,
    pub bytes: i64,
    pub date: String,
}

impl TrafficLogRow {
    pub fn to_response(&self) -> TrafficLogResponse {
        TrafficLogResponse {
            id: nonneg(self.id),
            user_id: nonneg(self.user_id),
            node_id: nonneg(self.node_id),
            bytes: nonneg(self.bytes),
            date: self.date.clone(),
        }
    }
}

/// A traffic log entry as the panel sees it.
#[derive(Debug, Serialize)]
pub struct TrafficLogResponse {
    pub id: u64,
    pub user_id: u64,
    pub node_id: u64,
    pub bytes: u64,
    pub date: String,
}

/// One day's total for one node, for the dashboard chart.
#[derive(Debug, FromRow)]
pub struct DailyTrafficRow {
    pub date: String,
    pub node_id: i64,
    pub node_name: String,
    pub bytes: i64,
}

impl DailyTrafficRow {
    pub fn to_response(&self) -> DailyTrafficResponse {
        DailyTrafficResponse {
            date: self.date.clone(),
            node_id: nonneg(self.node_id),
            node_name: self.node_name.clone(),
            bytes: nonneg(self.bytes),
        }
    }
}

/// A point on the traffic chart.
#[derive(Debug, Serialize)]
pub struct DailyTrafficResponse {
    pub date: String,
    pub node_id: u64,
    pub node_name: String,
    pub bytes: u64,
}

/// Per-node totals for one user, for `/me`.
#[derive(Debug, FromRow)]
pub struct NodeTrafficRow {
    pub node_id: i64,
    pub node_name: String,
    pub total_bytes: i64,
}

impl NodeTrafficRow {
    pub fn to_response(&self) -> NodeTrafficResponse {
        NodeTrafficResponse {
            node_id: nonneg(self.node_id),
            node_name: self.node_name.clone(),
            total_bytes: nonneg(self.total_bytes),
        }
    }
}

/// Per-node totals as the panel sees them.
#[derive(Debug, Serialize)]
pub struct NodeTrafficResponse {
    pub node_id: u64,
    pub node_name: String,
    pub total_bytes: u64,
}

// ── sub_templates ─────────────────────────────────────────────────

/// A row of `sub_templates`.
#[derive(Debug, FromRow)]
pub struct SubTemplateRow {
    pub id: i64,
    pub name: String,
    pub filename: String,
    pub content: String,
    pub content_type: String,
    pub update_interval: String,
    pub profile_url: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl SubTemplateRow {
    pub fn to_response(&self) -> SubTemplateResponse {
        SubTemplateResponse {
            id: nonneg(self.id),
            name: self.name.clone(),
            filename: self.filename.clone(),
            content: self.content.clone(),
            content_type: self.content_type.clone(),
            update_interval: self.update_interval.clone(),
            profile_url: self.profile_url.clone(),
            created_at: nonneg(self.created_at),
            updated_at: nonneg(self.updated_at),
        }
    }
}

/// A subscription template as the panel sees it.
#[derive(Debug, Serialize)]
pub struct SubTemplateResponse {
    pub id: u64,
    pub name: String,
    pub filename: String,
    pub content: String,
    pub content_type: String,
    pub update_interval: String,
    pub profile_url: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// `POST /admin/sub-templates` body.
#[derive(Debug, Deserialize)]
pub struct AddSubTemplateRequest {
    pub name: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub content: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub update_interval: String,
    #[serde(default)]
    pub profile_url: String,
}

fn default_content_type() -> String {
    "text/plain; charset=utf-8".to_owned()
}

/// `PATCH /admin/sub-templates/:id` body.
#[derive(Debug, Default, Deserialize)]
pub struct UpdateSubTemplateRequest {
    pub name: Option<String>,
    pub filename: Option<String>,
    pub content: Option<String>,
    pub content_type: Option<String>,
    pub update_interval: Option<String>,
    pub profile_url: Option<String>,
}

// ── /me ───────────────────────────────────────────────────────────

/// Everything a user can see about their own account.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: UserResponse,
    pub traffic_by_node: Vec<NodeTrafficResponse>,
    pub sub_templates: Vec<String>,
}
