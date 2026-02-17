use serde::{Deserialize, Serialize};
use worker::*;

// ── Wire types (shared with trojan-auth::http) ────────────────────

#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct TrafficRequest {
    pub user_id: String,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResult {
    pub user_id: Option<String>,
    pub metadata: Option<AuthMetadata>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthMetadata {
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub enum AuthError {
    Invalid,
    Backend(String),
    NotFound,
    TrafficExceeded,
    Expired,
    Disabled,
}

// ── D1 rows ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UserRow {
    pub id: f64,
    pub hash: String,
    pub username: String,
    pub traffic_limit: f64,
    pub traffic_used: f64,
    pub expires_at: f64,
    pub enabled: f64,
}

impl UserRow {
    pub fn to_cache_data(&self) -> CacheData {
        CacheData {
            id: self.id as u64,
            traffic_limit: self.traffic_limit as u64,
            traffic_used: self.traffic_used as u64,
            expires_at: self.expires_at as u64,
            enabled: self.enabled != 0.0,
        }
    }

    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id as u64,
            hash: self.hash.clone(),
            username: self.username.clone(),
            password: None,
            traffic_limit: self.traffic_limit as u64,
            traffic_used: self.traffic_used as u64,
            expires_at: self.expires_at as u64,
            enabled: self.enabled != 0.0,
        }
    }
}

#[derive(Deserialize)]
pub struct NodeRow {
    pub id: f64,
    pub name: String,
    pub token: String,
    pub enabled: f64,
    pub ip: String,
    pub last_seen: f64,
    pub created_at: f64,
}

impl NodeRow {
    pub fn to_response(&self) -> NodeResponse {
        NodeResponse {
            id: self.id as u64,
            name: self.name.clone(),
            token: self.token.clone(),
            enabled: self.enabled != 0.0,
            ip: self.ip.clone(),
            last_seen: self.last_seen as u64,
            created_at: self.created_at as u64,
        }
    }
}

#[derive(Deserialize)]
pub struct NodeLookup {
    pub id: f64,
    pub enabled: f64,
}

#[derive(Deserialize)]
pub struct TrafficLogRow {
    pub id: f64,
    pub user_id: f64,
    pub node_id: f64,
    pub bytes: f64,
    pub recorded_at: f64,
}

impl TrafficLogRow {
    pub fn to_response(&self) -> TrafficLogResponse {
        TrafficLogResponse {
            id: self.id as u64,
            user_id: self.user_id as u64,
            node_id: self.node_id as u64,
            bytes: self.bytes as u64,
            recorded_at: self.recorded_at as u64,
        }
    }
}

// ── KV cache (always bincode, internal) ───────────────────────────

#[derive(Serialize, Deserialize)]
pub struct CacheData {
    pub id: u64,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

// ── Admin API — Users (JSON) ─────────────────────────────────────

#[derive(Deserialize)]
pub struct AddUserRequest {
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

#[derive(Serialize)]
pub struct UserResponse {
    pub id: u64,
    pub hash: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

#[derive(Deserialize, Default)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub traffic_limit: Option<u64>,
    pub traffic_used: Option<u64>,
    pub expires_at: Option<u64>,
    pub enabled: Option<bool>,
}

// ── Admin API — Nodes (JSON) ─────────────────────────────────────

#[derive(Deserialize)]
pub struct AddNodeRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct NodeResponse {
    pub id: u64,
    pub name: String,
    pub token: String,
    pub enabled: bool,
    pub ip: String,
    pub last_seen: u64,
    pub created_at: u64,
}

#[derive(Deserialize, Default)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

// ── Admin API — Traffic Logs (JSON) ──────────────────────────────

#[derive(Serialize)]
pub struct TrafficLogResponse {
    pub id: u64,
    pub user_id: u64,
    pub node_id: u64,
    pub bytes: u64,
    pub recorded_at: u64,
}

// ── Codec ─────────────────────────────────────────────────────────

pub enum Codec {
    Bincode,
    Json,
}

pub fn detect_codec(req: &Request) -> Codec {
    let is_json = req
        .headers()
        .get("Content-Type")
        .ok()
        .flatten()
        .is_some_and(|ct| ct.contains("json"));
    if is_json {
        Codec::Json
    } else {
        Codec::Bincode
    }
}

pub async fn decode<T: for<'de> Deserialize<'de>>(req: &mut Request, codec: &Codec) -> Result<T> {
    match codec {
        Codec::Bincode => {
            let body = req.bytes().await?;
            bincode::deserialize(&body).map_err(|e| Error::from(e.to_string()))
        }
        Codec::Json => req.json().await,
    }
}

pub fn encode<T: Serialize>(data: &T, codec: &Codec) -> Result<Response> {
    match codec {
        Codec::Bincode => {
            let bytes = bincode::serialize(data).map_err(|e| Error::from(e.to_string()))?;
            let mut resp = Response::from_bytes(bytes)?;
            resp.headers_mut()
                .set("Content-Type", "application/octet-stream")?;
            Ok(resp)
        }
        Codec::Json => Response::from_json(data),
    }
}
