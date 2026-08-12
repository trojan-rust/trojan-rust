//! The JSON shapes the panel consumes, and the conversions from entity models.
//!
//! Columns are SQLite `INTEGER`, so models carry `i64` and convert on the way
//! out; the protocol and the panel both speak unsigned.

use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};
use trojan_auth::protocol::{self, AuthError, AuthMetadata, AuthResult};

use crate::entity::{nodes, sub_templates, traffic_logs, users};

/// Clamp a column to the unsigned range. Negative values are not reachable
/// through the API; a hand-edited database is not worth a panic.
pub(crate) fn nonneg(v: i64) -> u64 {
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
    /// Allowances on individual nodes, and what this month has spent of them.
    ///
    /// Cached with the rest, so the spend a node enforces against is at most
    /// one verify TTL out of date — the limit is a budget, not a gate.
    #[serde(default)]
    pub node_quotas: Vec<NodeQuota>,
}

impl From<&users::Model> for CacheData {
    fn from(m: &users::Model) -> Self {
        Self {
            id: nonneg(m.id),
            traffic_limit: nonneg(m.traffic_limit),
            traffic_used: nonneg(m.traffic_used),
            expires_at: nonneg(m.expires_at),
            enabled: m.enabled != 0,
            node_quotas: Vec::new(),
        }
    }
}

/// One node's monthly allowance for a user, and the spend against it.
#[derive(Debug, Clone, Serialize, Deserialize, FromQueryResult)]
pub struct NodeQuota {
    pub node_id: i64,
    pub monthly_bytes: i64,
    pub used: i64,
}

impl NodeQuota {
    /// The wire form nodes receive.
    pub fn to_protocol(&self) -> protocol::NodeQuota {
        protocol::NodeQuota {
            node_id: self.node_id.to_string(),
            limit: nonneg(self.monthly_bytes),
            used: nonneg(self.used),
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
                    node_quotas: self
                        .node_quotas
                        .iter()
                        .map(NodeQuota::to_protocol)
                        .collect(),
                }),
            })
        }
    }
}

/// `PUT /admin/users/{id}/limits/{node_id}` body.
#[derive(Debug, Deserialize)]
pub struct NodeLimitRequest {
    /// Bytes per calendar month, UTC. Zero means unlimited.
    pub monthly_bytes: u64,
}

/// One allowance as the panel sees it.
#[derive(Debug, Serialize)]
pub struct NodeLimitResponse {
    pub node_id: u64,
    pub monthly_bytes: u64,
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

// ── traffic series ────────────────────────────────────────────────

/// How far back a chart reaches.
///
/// The two shortest read the hourly rollup, which is the only place sub-day
/// resolution exists; the rest read the daily table, which keeps history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum Range {
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "3d")]
    ThreeDays,
    #[serde(rename = "7d")]
    Week,
    #[default]
    #[serde(rename = "30d")]
    Month,
    #[serde(rename = "90d")]
    Quarter,
    #[serde(rename = "all")]
    All,
}

/// How wide one point is. Chosen by the range, reported so the panel can label
/// an axis without repeating the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bucket {
    Hour,
    Day,
    Week,
    Month,
}

/// What a series breaks down by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grouping {
    /// One line per node.
    #[default]
    Node,
    /// One line per user.
    User,
    /// One line, everything summed.
    None,
}

/// Query string of `GET /admin/traffic/series`.
#[derive(Debug, Default, Deserialize)]
pub struct SeriesQuery {
    #[serde(default)]
    pub range: Range,
    #[serde(default)]
    pub group: Grouping,
    pub user_id: Option<i64>,
    pub node_id: Option<i64>,
}

/// One bucket of one series, as the aggregate query returns it.
#[derive(Debug, FromQueryResult)]
pub struct SeriesRow {
    pub t: String,
    /// The node or user id this line belongs to; absent when ungrouped.
    pub key: Option<i64>,
    pub label: Option<String>,
    pub bytes: i64,
}

/// A point on a traffic chart.
#[derive(Debug, Serialize)]
pub struct SeriesPoint {
    pub t: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub bytes: u64,
}

impl From<&SeriesRow> for SeriesPoint {
    fn from(r: &SeriesRow) -> Self {
        Self {
            t: r.t.clone(),
            key: r.key.map(nonneg),
            label: r.label.clone(),
            bytes: nonneg(r.bytes),
        }
    }
}

/// A traffic chart: the points, and enough about the window to draw the axis.
#[derive(Debug, Serialize)]
pub struct SeriesResponse {
    pub bucket: Bucket,
    /// Inclusive lower bound, in the same form as a point's `t`.
    pub start: String,
    pub points: Vec<SeriesPoint>,
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
    /// Bytes over the last 24 hourly buckets. A window rather than a calendar
    /// day, so it reads the same from any timezone.
    pub last_24h_bytes: u64,
    /// Bytes since the first of the month, UTC — the window a node allowance
    /// is counted over.
    pub month_bytes: u64,
    pub traffic_by_node: Vec<NodeTrafficResponse>,
    pub sub_templates: Vec<String>,
}

/// The two figures above, as the aggregate query returns them.
#[derive(Debug, Default, FromQueryResult)]
pub struct UsageRow {
    pub last_24h: i64,
    pub month: i64,
}
