//! Authentication configuration shared by the CLI and managed services.

use std::time::Duration;
use tracing::info;
use trojan_auth::{
    AuthBackend, MemoryAuth,
    http::{Codec, HttpAuth, HttpAuthConfig},
};

/// Build an auth backend from config.
///
/// If `http_url` is set, creates an [`HttpAuth`] backend that delegates to a
/// remote dashboard worker. Otherwise falls back to in-memory password auth.
pub fn build_auth(auth: &trojan_config::AuthConfig) -> Box<dyn AuthBackend> {
    if let Some(ref url) = auth.http_url {
        let codec = match auth.http_codec.as_deref() {
            Some("json") => Codec::Json,
            _ => Codec::Bincode,
        };
        info!(
            url = %url,
            codec = ?codec,
            cache_ttl = auth.http_cache_ttl_secs,
            stale_ttl = auth.http_cache_stale_ttl_secs,
            neg_cache_ttl = auth.http_cache_neg_ttl_secs,
            batch_flush_interval = auth.http_batch_flush_interval_secs,
            "using HTTP auth backend"
        );
        let config = HttpAuthConfig {
            base_url: url.clone(),
            codec,
            node_token: auth.http_node_token.clone(),
            cache_ttl: Duration::from_secs(auth.http_cache_ttl_secs),
            stale_ttl: Duration::from_secs(auth.http_cache_stale_ttl_secs),
            neg_cache_ttl: Duration::from_secs(auth.http_cache_neg_ttl_secs),
            batch_flush_interval: Duration::from_secs(auth.http_batch_flush_interval_secs),
        };
        Box::new(HttpAuth::new(config))
    } else {
        let mut mem = MemoryAuth::new();
        for pw in &auth.passwords {
            mem.add_password(pw, None);
        }
        for u in &auth.users {
            mem.add_password(&u.password, Some(u.id.clone()));
        }
        Box::new(mem)
    }
}
