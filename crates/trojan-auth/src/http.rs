//! HTTP authentication backend.
//!
//! Calls a remote auth-worker (Cloudflare Worker) over HTTP.
//! Supports bincode (default) and JSON serialization via [`Codec`].
//!
//! # Example
//!
//! ```no_run
//! use trojan_auth::http::{HttpAuth, Codec};
//!
//! let auth = HttpAuth::new("https://auth.example.workers.dev", Codec::Bincode, Some("node-token".into()));
//! ```

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{AuthBackend, AuthError, AuthMetadata, AuthResult};

// ── Codec ─────────────────────────────────────────────────────────

/// Serialization codec for the HTTP wire protocol.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// Bincode — compact binary format (default).
    #[default]
    Bincode,
    /// JSON — human-readable, easier to debug with curl.
    Json,
}

// ── HttpAuth ──────────────────────────────────────────────────────

/// HTTP authentication backend that delegates to a remote auth-worker.
#[derive(Debug)]
pub struct HttpAuth {
    client: Client,
    verify_url: String,
    traffic_url: String,
    codec: Codec,
    node_token: Option<String>,
}

impl HttpAuth {
    /// Create a new HTTP auth backend.
    ///
    /// `base_url` is the worker URL (e.g. `https://auth.example.workers.dev`).
    /// `node_token` is the Bearer token for node authentication (from admin dashboard).
    pub fn new(
        base_url: impl Into<String>,
        codec: Codec,
        node_token: Option<String>,
    ) -> Self {
        let base = base_url.into();
        let base = base.trim_end_matches('/');
        Self {
            client: Client::new(),
            verify_url: format!("{base}/verify"),
            traffic_url: format!("{base}/traffic"),
            codec,
            node_token,
        }
    }

    /// Create with a custom reqwest [`Client`] (for timeouts, proxies, etc.).
    pub fn with_client(
        client: Client,
        base_url: impl Into<String>,
        codec: Codec,
        node_token: Option<String>,
    ) -> Self {
        let base = base_url.into();
        let base = base.trim_end_matches('/');
        Self {
            client,
            verify_url: format!("{base}/verify"),
            traffic_url: format!("{base}/traffic"),
            codec,
            node_token,
        }
    }

    /// Send a request and decode the response.
    async fn request<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &Req,
    ) -> Result<Resp, AuthError> {
        let resp = match self.codec {
            Codec::Bincode => {
                let bytes = bincode::serialize(body).map_err(AuthError::backend)?;
                let mut req = self
                    .client
                    .post(url)
                    .header("Content-Type", "application/octet-stream");
                if let Some(ref token) = self.node_token {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
                req.body(bytes).send().await.map_err(AuthError::backend)?
            }
            Codec::Json => {
                let mut req = self.client.post(url);
                if let Some(ref token) = self.node_token {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
                req.json(body).send().await.map_err(AuthError::backend)?
            }
        };

        if !resp.status().is_success() {
            return Err(AuthError::Backend(format!(
                "HTTP {}",
                resp.status().as_u16()
            )));
        }

        match self.codec {
            Codec::Bincode => {
                let bytes = resp.bytes().await.map_err(AuthError::backend)?;
                bincode::deserialize(&bytes).map_err(AuthError::backend)
            }
            Codec::Json => resp.json().await.map_err(AuthError::backend),
        }
    }
}

#[async_trait]
impl AuthBackend for HttpAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        let req = wire::VerifyRequest {
            hash: hash.to_owned(),
        };
        let result: Result<wire::AuthResult, wire::AuthError> =
            self.request(&self.verify_url, &req).await?;
        result.map(Into::into).map_err(Into::into)
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        let req = wire::TrafficRequest {
            user_id: user_id.to_owned(),
            bytes,
        };
        let result: Result<(), wire::AuthError> =
            self.request(&self.traffic_url, &req).await?;
        result.map_err(Into::into)
    }
}

// ── Wire types (must match auth-worker exactly) ───────────────────

#[allow(missing_debug_implementations)]
mod wire {
    use serde::{Deserialize, Serialize};

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
}

// ── Wire ↔ core conversions ───────────────────────────────────────

impl From<wire::AuthResult> for AuthResult {
    fn from(w: wire::AuthResult) -> Self {
        Self {
            user_id: w.user_id,
            metadata: w.metadata.map(|m| AuthMetadata {
                traffic_limit: m.traffic_limit,
                traffic_used: m.traffic_used,
                expires_at: m.expires_at,
                enabled: m.enabled,
            }),
        }
    }
}

impl From<wire::AuthError> for AuthError {
    fn from(w: wire::AuthError) -> Self {
        match w {
            wire::AuthError::Invalid => Self::Invalid,
            wire::AuthError::Backend(s) => Self::Backend(s),
            wire::AuthError::NotFound => Self::NotFound,
            wire::AuthError::TrafficExceeded => Self::TrafficExceeded,
            wire::AuthError::Expired => Self::Expired,
            wire::AuthError::Disabled => Self::Disabled,
        }
    }
}
