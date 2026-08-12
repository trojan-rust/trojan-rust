//! The JSON shapes the panel consumes, and the conversions from entity models.
//!
//! Columns are SQLite `INTEGER`, so models carry `i64` and convert on the way
//! out; the protocol and the panel both speak unsigned.

use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};
use trojan_auth::protocol::{AuthError, AuthMetadata, AuthResult};

use crate::entity::{nodes, sub_templates, traffic_logs, users};

/// Clamp a column to the unsigned range. Negative values are not reachable
/// through the API; a hand-edited database is not worth a panic.
fn nonneg(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Clamp an API value to what SQLite can hold in an `INTEGER`.
pub(crate) fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

// ── verify cache ──────────────────────────────────────────────────

/// What `/verify` needs to answer, small enough to keep in memory for every
/// user. Cached under the password hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub id: u64,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

impl From<&users::Model> for CacheData {
    fn from(m: &users::Model) -> Self {
        Self {
            id: nonneg(m.id),
            traffic_limit: nonneg(m.traffic_limit),
            traffic_used: nonneg(m.traffic_used),
            expires_at: nonneg(m.expires_at),
            enabled: m.enabled != 0,
        }
    }
}

impl CacheData {
    /// Decide whether this user may connect right now.
    pub fn validate(&self, now: u64) -> Result<AuthResult, AuthError> {
        if !self.enabled {
            Err(AuthError::Disabled)
        } else if self.expires_at > 0 && now >= self.expires_at {
            Err(AuthError::Expired)
        } else if self.traffic_limit > 0 && self.traffic_used >= self.traffic_limit {
            Err(AuthError::TrafficExceeded)
        } else {
            Ok(AuthResult {
                user_id: Some(self.id.to_string()),
                metadata: Some(AuthMetadata {
                    traffic_limit: self.traffic_limit,
                    traffic_used: self.traffic_used,
                    expires_at: self.expires_at,
                    enabled: self.enabled,
                }),
            })
        }
    }
}

// ── users ─────────────────────────────────────────────────────────

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

impl From<&users::Model> for UserResponse {
    fn from(m: &users::Model) -> Self {
        Self {
            id: nonneg(m.id),
            hash: m.hash.clone(),
            username: m.username.clone(),
            password: None,
            traffic_limit: nonneg(m.traffic_limit),
            traffic_used: nonneg(m.traffic_used),
            expires_at: nonneg(m.expires_at),
            enabled: m.enabled != 0,
        }
    }
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
    /// Stored as text; handed back as JSON so the panel can edit it.
    pub config: serde_json::Value,
    pub config_version: u64,
    pub agent_version: String,
    pub connections_active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_secs: u64,
}

impl From<&nodes::Model> for NodeResponse {
    fn from(m: &nodes::Model) -> Self {
        Self {
            id: nonneg(m.id),
            name: m.name.clone(),
            token: m.token.clone(),
            enabled: m.enabled != 0,
            ip: m.ip.clone(),
            last_seen: nonneg(m.last_seen),
            created_at: nonneg(m.created_at),
            node_type: m.node_type.clone(),
            // A config an operator hand-edited into invalid JSON should still
            // let the node list render.
            config: serde_json::from_str(&m.config).unwrap_or(serde_json::Value::Null),
            config_version: nonneg(m.config_version),
            agent_version: m.agent_version.clone(),
            connections_active: nonneg(m.connections_active),
            bytes_in: nonneg(m.bytes_in),
            bytes_out: nonneg(m.bytes_out),
            uptime_secs: nonneg(m.uptime_secs),
        }
    }
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

/// A traffic log entry as the panel sees it.
#[derive(Debug, Serialize)]
pub struct TrafficLogResponse {
    pub id: u64,
    pub user_id: u64,
    pub node_id: u64,
    pub bytes: u64,
    pub date: String,
}

impl From<&traffic_logs::Model> for TrafficLogResponse {
    fn from(m: &traffic_logs::Model) -> Self {
        Self {
            id: nonneg(m.id),
            user_id: nonneg(m.user_id),
            node_id: nonneg(m.node_id),
            bytes: nonneg(m.bytes),
            date: m.date.clone(),
        }
    }
}

/// Filters for `GET /admin/traffic`.
#[derive(Debug, Deserialize)]
pub struct TrafficQuery {
    pub user_id: Option<i64>,
    pub node_id: Option<i64>,
}

/// Window for `GET /admin/traffic/daily`.
#[derive(Debug, Deserialize)]
pub struct DailyQuery {
    /// How far back to reach, in days. Defaults to 30, capped at a year.
    pub days: Option<i64>,
}

/// One day's total for one node, as the aggregate query returns it.
#[derive(Debug, FromQueryResult)]
pub struct DailyTrafficRow {
    pub date: String,
    pub node_id: i64,
    pub node_name: String,
    pub bytes: i64,
}

/// A point on the traffic chart.
#[derive(Debug, Serialize)]
pub struct DailyTrafficResponse {
    pub date: String,
    pub node_id: u64,
    pub node_name: String,
    pub bytes: u64,
}

impl From<&DailyTrafficRow> for DailyTrafficResponse {
    fn from(r: &DailyTrafficRow) -> Self {
        Self {
            date: r.date.clone(),
            node_id: nonneg(r.node_id),
            node_name: r.node_name.clone(),
            bytes: nonneg(r.bytes),
        }
    }
}

/// Per-node totals for one user, as the aggregate query returns them.
#[derive(Debug, FromQueryResult)]
pub struct NodeTrafficRow {
    pub node_id: i64,
    pub node_name: String,
    pub total_bytes: i64,
}

/// Per-node totals as the panel sees them.
#[derive(Debug, Serialize)]
pub struct NodeTrafficResponse {
    pub node_id: u64,
    pub node_name: String,
    pub total_bytes: u64,
}

impl From<&NodeTrafficRow> for NodeTrafficResponse {
    fn from(r: &NodeTrafficRow) -> Self {
        Self {
            node_id: nonneg(r.node_id),
            node_name: r.node_name.clone(),
            total_bytes: nonneg(r.total_bytes),
        }
    }
}

// ── sub_templates ─────────────────────────────────────────────────

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

impl From<&sub_templates::Model> for SubTemplateResponse {
    fn from(m: &sub_templates::Model) -> Self {
        Self {
            id: nonneg(m.id),
            name: m.name.clone(),
            filename: m.filename.clone(),
            content: m.content.clone(),
            content_type: m.content_type.clone(),
            update_interval: m.update_interval.clone(),
            profile_url: m.profile_url.clone(),
            created_at: nonneg(m.created_at),
            updated_at: nonneg(m.updated_at),
        }
    }
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

// ── public endpoints ──────────────────────────────────────────────

/// Query string of `GET /sub/{name}`.
#[derive(Debug, Deserialize)]
pub struct SubQuery {
    /// The user's password — the subscription's only credential.
    pub pwd: Option<String>,
    /// Render inline instead of prompting a download.
    pub preview: Option<String>,
}

/// Everything a user can see about their own account.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: UserResponse,
    pub traffic_by_node: Vec<NodeTrafficResponse>,
    pub sub_templates: Vec<String>,
}
