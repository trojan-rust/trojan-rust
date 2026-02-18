//! HTTP authentication backend.
//!
//! Delegates authentication to a remote auth-worker (e.g. Cloudflare Worker)
//! over HTTP, with local stale-while-revalidate caching via [`StoreAuth`].
//!
//! # Example
//!
//! ```no_run
//! use trojan_auth::http::{HttpAuth, HttpAuthConfig, Codec};
//!
//! let config = HttpAuthConfig {
//!     base_url: "https://auth.example.workers.dev".into(),
//!     codec: Codec::Bincode,
//!     ..Default::default()
//! };
//! let auth = HttpAuth::new(config);
//! ```

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::store::{StoreAuth, StoreAuthConfig, TrafficRecordingMode, UserRecord, UserStore};
use crate::{AuthBackend, AuthError, AuthResult};

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

// ── HttpAuthConfig ────────────────────────────────────────────────

/// Configuration for the HTTP authentication backend.
#[derive(Debug, Clone)]
pub struct HttpAuthConfig {
    /// Auth-worker base URL (e.g. `https://auth.example.workers.dev`).
    pub base_url: String,
    /// Serialization codec for the wire protocol.
    pub codec: Codec,
    /// Bearer token for node authentication (from admin dashboard).
    pub node_token: Option<String>,
    /// Positive cache TTL (default: 300s = 5 min).
    pub cache_ttl: Duration,
    /// Stale-while-revalidate window (default: 600s = 10 min).
    ///
    /// Stale cache entries are served immediately while being
    /// revalidated in the background.
    pub stale_ttl: Duration,
    /// Negative cache TTL (default: 10s).
    ///
    /// Invalid hashes are cached for this duration to prevent flooding.
    pub neg_cache_ttl: Duration,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            codec: Codec::default(),
            node_token: None,
            cache_ttl: Duration::from_secs(300),
            stale_ttl: Duration::from_secs(600),
            neg_cache_ttl: Duration::from_secs(10),
        }
    }
}

impl HttpAuthConfig {
    /// Extract the generic [`StoreAuthConfig`] for constructing [`StoreAuth`].
    fn store_auth_config(&self) -> StoreAuthConfig {
        StoreAuthConfig {
            traffic_mode: TrafficRecordingMode::Immediate,
            batch_flush_interval: Duration::from_secs(30),
            batch_max_pending: 1000,
            cache_enabled: self.cache_ttl > Duration::ZERO,
            cache_ttl: self.cache_ttl,
            stale_ttl: self.stale_ttl,
            neg_cache_ttl: self.neg_cache_ttl,
        }
    }
}

// ── HttpStore ─────────────────────────────────────────────────────

/// HTTP user store that delegates to a remote auth-worker.
///
/// Implements [`UserStore`] by calling the auth-worker's `/verify` and
/// `/traffic` endpoints.
#[derive(Debug)]
pub struct HttpStore {
    client: Client,
    verify_url: String,
    traffic_url: String,
    codec: Codec,
    node_token: Option<String>,
}

impl HttpStore {
    /// Create a new HTTP store.
    fn new(base_url: &str, codec: Codec, node_token: Option<String>) -> Self {
        let base = base_url.trim_end_matches('/');
        Self {
            client: Client::new(),
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
impl UserStore for HttpStore {
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    async fn find_by_hash(&self, hash: &str) -> Result<Option<UserRecord>, AuthError> {
        let req = wire::VerifyRequest {
            hash: hash.to_owned(),
        };
        let result: Result<wire::AuthResult, wire::AuthError> =
            self.request(&self.verify_url, &req).await?;
        match result {
            Ok(auth_result) => {
                let meta = auth_result.metadata.as_ref();
                Ok(Some(UserRecord {
                    user_id: auth_result.user_id,
                    traffic_limit: meta.map_or(0, |m| m.traffic_limit as i64),
                    traffic_used: meta.map_or(0, |m| m.traffic_used as i64),
                    expires_at: meta.map_or(0, |m| m.expires_at as i64),
                    enabled: meta.is_none_or(|m| m.enabled),
                }))
            }
            Err(wire::AuthError::Invalid | wire::AuthError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn add_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        let req = wire::TrafficRequest {
            user_id: user_id.to_owned(),
            bytes,
        };
        let result: Result<(), wire::AuthError> = self.request(&self.traffic_url, &req).await?;
        result.map_err(Into::into)
    }
}

// ── HttpAuth ──────────────────────────────────────────────────────

/// HTTP authentication backend with stale-while-revalidate caching.
///
/// Wraps [`StoreAuth<HttpStore>`] to provide:
/// - Positive caching with configurable TTL
/// - Stale-while-revalidate: stale cache entries are served immediately
///   while being revalidated in the background
/// - Negative caching for invalid hashes
pub struct HttpAuth {
    inner: StoreAuth<HttpStore>,
}

impl HttpAuth {
    /// Create a new HTTP auth backend from configuration.
    pub fn new(config: HttpAuthConfig) -> Self {
        let store_config = config.store_auth_config();
        let store = HttpStore::new(&config.base_url, config.codec, config.node_token);
        Self {
            inner: StoreAuth::new(store, &store_config),
        }
    }
}

#[async_trait]
impl AuthBackend for HttpAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        self.inner.verify(hash).await
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        self.inner.record_traffic(user_id, bytes).await
    }
}

impl std::fmt::Debug for HttpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuth")
            .field("inner", &self.inner)
            .finish()
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
