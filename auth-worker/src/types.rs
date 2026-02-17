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

// ── D1 row ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UserRow {
    pub hash: String,
    pub user_id: String,
    pub traffic_limit: f64,
    pub traffic_used: f64,
    pub expires_at: f64,
    pub enabled: f64,
}

impl UserRow {
    pub fn to_cache_data(&self) -> CacheData {
        CacheData {
            user_id: self.user_id.clone(),
            traffic_limit: self.traffic_limit as u64,
            traffic_used: self.traffic_used as u64,
            expires_at: self.expires_at as u64,
            enabled: self.enabled != 0.0,
        }
    }
}

// ── KV cache (always bincode, internal) ───────────────────────────

#[derive(Serialize, Deserialize)]
pub struct CacheData {
    pub user_id: String,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
}

// ── Admin API (JSON) ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddUserRequest {
    pub password: String,
    pub user_id: String,
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
    pub hash: String,
    pub user_id: String,
    pub traffic_limit: u64,
    pub traffic_used: u64,
    pub expires_at: u64,
    pub enabled: bool,
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

pub async fn decode<T: for<'de> Deserialize<'de>>(
    req: &mut Request,
    codec: &Codec,
) -> Result<T> {
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
