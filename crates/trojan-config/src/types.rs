//! Configuration type definitions for server, TLS, WebSocket, auth, metrics, and logging.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::defaults::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub fallback: String,
    #[serde(default = "default_tcp_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default = "default_udp_timeout_secs")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_max_udp_payload")]
    pub max_udp_payload: usize,
    #[serde(default = "default_max_udp_buffer_bytes")]
    pub max_udp_buffer_bytes: usize,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Maximum concurrent connections (None = unlimited)
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Per-IP rate limiting configuration
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Fallback connection pool configuration
    #[serde(default)]
    pub fallback_pool: Option<FallbackPoolConfig>,
    /// Resource limits configuration
    #[serde(default)]
    pub resource_limits: Option<ResourceLimitsConfig>,
    /// TCP socket options
    #[serde(default)]
    pub tcp: TcpConfig,
    /// Named outbound connectors for rule-based routing.
    #[serde(default)]
    pub outbounds: HashMap<String, OutboundConfig>,
    /// Rule-set providers (local file or remote URL).
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,
    /// Ordered routing rules (first match wins).
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,
    /// GeoIP database configuration for rule-based routing.
    #[serde(default)]
    pub geoip: Option<GeoipConfig>,
}

/// GeoIP MaxMind database configuration.
///
/// Loading priority: `path` > `url` > `source` (built-in CDN).
/// When `auto_update` is true and no `path` is set, the database
/// is periodically re-downloaded in the background.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoipConfig {
    /// Built-in source name (e.g., "geolite2-country", "dbip-city").
    #[serde(default = "default_geoip_source")]
    pub source: String,
    /// Local file path (highest priority — skips download).
    #[serde(default)]
    pub path: Option<String>,
    /// Custom remote URL (overrides the built-in CDN URL for `source`).
    #[serde(default)]
    pub url: Option<String>,
    /// Enable automatic background updates.
    #[serde(default = "default_geoip_auto_update")]
    pub auto_update: bool,
    /// Update interval in seconds (default: 7 days = 604800).
    #[serde(default = "default_geoip_interval")]
    pub interval: u64,
    /// Cache file path for downloaded databases.
    #[serde(default)]
    pub cache_path: Option<String>,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        Self {
            source: default_geoip_source(),
            path: None,
            url: None,
            auto_update: default_geoip_auto_update(),
            interval: default_geoip_interval(),
            cache_path: None,
        }
    }
}

fn default_geoip_source() -> String {
    "geolite2-country".to_string()
}

fn default_geoip_auto_update() -> bool {
    true
}

fn default_geoip_interval() -> u64 {
    604800 // 7 days
}

/// GeoIP lookup result containing geographic information for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoResult {
    /// ISO 3166-1 alpha-2 country code (e.g., "CN", "US").
    pub country: String,
    /// Region/state/province name (e.g., "Shanghai", "California").
    pub region: String,
    /// City name (e.g., "Shanghai", "Los Angeles").
    pub city: String,
    /// Autonomous System Number.
    pub asn: u32,
    /// ASN organization name (e.g., "China Telecom").
    pub org: String,
    /// Longitude coordinate.
    pub longitude: f64,
    /// Latitude coordinate.
    pub latitude: f64,
}

/// TCP socket configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    /// Disable Nagle's algorithm (TCP_NODELAY) for lower latency.
    #[serde(default = "default_tcp_no_delay")]
    pub no_delay: bool,
    /// TCP Keep-Alive interval in seconds (0 = disabled).
    #[serde(default = "default_tcp_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Enable SO_REUSEPORT for multi-process load balancing.
    #[serde(default = "default_tcp_reuse_port")]
    pub reuse_port: bool,
    /// Enable TCP Fast Open (requires kernel support).
    #[serde(default = "default_tcp_fast_open")]
    pub fast_open: bool,
    /// TCP Fast Open queue length (server-side).
    #[serde(default = "default_tcp_fast_open_qlen")]
    pub fast_open_qlen: u32,
    /// Prefer IPv4 addresses when resolving DNS for outbound connections.
    #[serde(default = "default_tcp_prefer_ipv4")]
    pub prefer_ipv4: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            no_delay: default_tcp_no_delay(),
            keepalive_secs: default_tcp_keepalive_secs(),
            reuse_port: default_tcp_reuse_port(),
            fast_open: default_tcp_fast_open(),
            fast_open_qlen: default_tcp_fast_open_qlen(),
            prefer_ipv4: default_tcp_prefer_ipv4(),
        }
    }
}

/// Configuration for fallback connection warm pool.
///
/// Warm pool semantics:
/// - Pre-connects up to `max_idle` fresh connections in the background.
/// - Connections are handed out once and NOT returned to the pool.
/// - Pool is periodically refilled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPoolConfig {
    /// Maximum idle connections to keep in pool.
    #[serde(default = "default_pool_max_idle")]
    pub max_idle: usize,
    /// Maximum age of pooled connections in seconds.
    #[serde(default = "default_pool_max_age_secs")]
    pub max_age_secs: u64,
    /// Warm-fill batch size per cycle (1..=max_idle).
    #[serde(default = "default_pool_fill_batch")]
    pub fill_batch: usize,
    /// Delay (ms) between each connection attempt within a batch.
    #[serde(default = "default_pool_fill_delay_ms")]
    pub fill_delay_ms: u64,
}

/// Configuration for resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitsConfig {
    /// Buffer size for TCP relay (bytes).
    #[serde(default = "default_relay_buffer_size")]
    pub relay_buffer_size: usize,
    /// TCP socket send buffer size (SO_SNDBUF). If 0, uses OS default.
    #[serde(default)]
    pub tcp_send_buffer: usize,
    /// TCP socket receive buffer size (SO_RCVBUF). If 0, uses OS default.
    #[serde(default)]
    pub tcp_recv_buffer: usize,
    /// TCP listener backlog (pending connections queue size).
    #[serde(default = "default_connection_backlog")]
    pub connection_backlog: u32,
}

/// Rate limiting configuration for per-IP connection throttling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum new connections per IP within the time window.
    #[serde(default = "default_rate_limit_max_connections")]
    pub max_connections_per_ip: u32,
    /// Time window in seconds for rate limiting.
    #[serde(default = "default_rate_limit_window_secs")]
    pub window_secs: u64,
    /// Cleanup interval in seconds for expired entries.
    #[serde(default = "default_rate_limit_cleanup_secs")]
    pub cleanup_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Server certificate file path (PEM format).
    pub cert: String,
    /// Server private key file path (PEM format).
    pub key: String,
    /// ALPN protocols to advertise.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Minimum TLS version (tls12, tls13). Default: tls12
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
    /// Maximum TLS version (tls12, tls13). Default: tls13
    #[serde(default = "default_max_tls_version")]
    pub max_version: String,
    /// Path to CA certificate for client authentication (mTLS).
    /// If set, client certificates will be required and verified.
    #[serde(default)]
    pub client_ca: Option<String>,
    /// Cipher suites to use. If empty, uses rustls defaults.
    /// Example: ["TLS13_AES_256_GCM_SHA384", "TLS13_CHACHA20_POLY1305_SHA256"]
    #[serde(default)]
    pub cipher_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_ws_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ws_mode")]
    pub mode: String,
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default = "default_ws_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: default_ws_enabled(),
            mode: default_ws_mode(),
            path: default_ws_path(),
            host: None,
            listen: None,
            max_frame_bytes: default_ws_max_frame_bytes(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Simple password list (no user IDs).
    /// ```toml
    /// passwords = ["password1", "password2"]
    /// ```
    #[serde(default)]
    pub passwords: Vec<String>,

    /// User entries with explicit IDs.
    /// ```toml
    /// [[auth.users]]
    /// id = "alice"
    /// password = "secret1"
    /// ```
    #[serde(default)]
    pub users: Vec<UserEntry>,

    /// HTTP remote auth-worker URL.
    /// ```toml
    /// http_url = "https://auth.example.workers.dev"
    /// ```
    #[serde(default)]
    pub http_url: Option<String>,

    /// Bearer token for node authentication with the auth-worker.
    #[serde(default)]
    pub http_node_token: Option<String>,

    /// Serialization codec for HTTP auth: "bincode" (default) or "json".
    #[serde(default)]
    pub http_codec: Option<String>,

    /// HTTP auth cache TTL in seconds (default: 300 = 5 min).
    /// Only applies when `http_url` is set.
    #[serde(default = "default_http_cache_ttl_secs")]
    pub http_cache_ttl_secs: u64,

    /// HTTP auth stale-while-revalidate window in seconds (default: 600 = 10 min).
    /// Stale cache entries are served immediately while revalidated in the background.
    #[serde(default = "default_http_cache_stale_ttl_secs")]
    pub http_cache_stale_ttl_secs: u64,

    /// HTTP auth negative cache TTL in seconds (default: 10).
    /// Invalid hashes are cached for this duration to prevent request flooding.
    #[serde(default = "default_http_cache_neg_ttl_secs")]
    pub http_cache_neg_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub id: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    pub listen: Option<String>,
    /// GeoIP database for per-country metrics labels (country-level).
    #[serde(default)]
    pub geoip: Option<GeoipConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: Option<String>,
    /// Log format: json, pretty, or compact. Default: pretty.
    pub format: Option<String>,
    /// Output target: stdout or stderr. Default: stderr.
    pub output: Option<String>,
    /// Per-module log level filters (e.g., {"trojan_auth": "debug", "rustls": "warn"}).
    #[serde(default)]
    pub filters: HashMap<String, String>,
}

/// Named outbound connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Outbound type: "trojan", "direct", or "reject".
    #[serde(rename = "type")]
    pub outbound_type: String,
    /// Target address (required for trojan).
    #[serde(default)]
    pub addr: Option<String>,
    /// Password (for trojan outbound).
    #[serde(default)]
    pub password: Option<String>,
    /// SNI (for trojan outbound).
    #[serde(default)]
    pub sni: Option<String>,
    /// Bind to specific local IP (for direct outbound).
    #[serde(default)]
    pub bind: Option<String>,
}

/// Rule-set provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProviderConfig {
    /// Format: "surge" or "clash".
    pub format: String,
    /// Behavior: "domain", "ipcidr", "classical", or "domain-set".
    #[serde(default)]
    pub behavior: Option<String>,
    /// Source: "file" or "http".
    pub source: String,
    /// Local file path.
    #[serde(default)]
    pub path: Option<String>,
    /// Remote URL (for http source).
    #[serde(default)]
    pub url: Option<String>,
    /// Update interval in seconds (for http source).
    #[serde(default)]
    pub interval: Option<u64>,
}

/// A single routing rule entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRuleConfig {
    /// Reference to a named rule-set provider.
    #[serde(default, rename = "rule-set")]
    pub rule_set: Option<String>,
    /// Inline rule type: "GEOIP", "FINAL", "DOMAIN", "DOMAIN-SUFFIX", etc.
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    /// Inline rule value (e.g., "CN" for GEOIP, "example.com" for DOMAIN).
    #[serde(default)]
    pub value: Option<String>,
    /// Action: "DIRECT", "REJECT", or a named outbound.
    pub outbound: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geoip_config_defaults() {
        let cfg = GeoipConfig::default();
        assert_eq!(cfg.source, "geolite2-country");
        assert!(cfg.path.is_none());
        assert!(cfg.url.is_none());
        assert!(cfg.auto_update);
        assert_eq!(cfg.interval, 604800);
        assert!(cfg.cache_path.is_none());
    }

    #[test]
    fn geoip_config_deserialize_minimal() {
        let toml_str = r#"source = "dbip-city""#;
        let cfg: GeoipConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.source, "dbip-city");
        assert!(cfg.auto_update);
        assert_eq!(cfg.interval, 604800);
    }

    #[test]
    fn geoip_config_deserialize_full() {
        let toml_str = r#"
source = "geolite2-city"
path = "/tmp/test.mmdb"
url = "https://example.com/geo.mmdb"
auto_update = false
interval = 3600
cache_path = "/tmp/cache.mmdb"
"#;
        let cfg: GeoipConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.source, "geolite2-city");
        assert_eq!(cfg.path.as_deref(), Some("/tmp/test.mmdb"));
        assert_eq!(cfg.url.as_deref(), Some("https://example.com/geo.mmdb"));
        assert!(!cfg.auto_update);
        assert_eq!(cfg.interval, 3600);
        assert_eq!(cfg.cache_path.as_deref(), Some("/tmp/cache.mmdb"));
    }

    #[test]
    fn geo_result_default() {
        let r = GeoResult::default();
        assert!(r.country.is_empty());
        assert!(r.region.is_empty());
        assert!(r.city.is_empty());
        assert_eq!(r.asn, 0);
        assert!(r.org.is_empty());
        assert_eq!(r.longitude, 0.0);
        assert_eq!(r.latitude, 0.0);
    }

    #[test]
    fn geo_result_serde_roundtrip() {
        let r = GeoResult {
            country: "CN".into(),
            region: "Shanghai".into(),
            city: "Shanghai".into(),
            asn: 4134,
            org: "China Telecom".into(),
            longitude: 121.47,
            latitude: 31.23,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: GeoResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.country, "CN");
        assert_eq!(r2.asn, 4134);
        assert!((r2.longitude - 121.47).abs() < 0.001);
    }

    #[test]
    fn metrics_config_default() {
        let cfg = MetricsConfig::default();
        assert!(cfg.listen.is_none());
        assert!(cfg.geoip.is_none());
    }

    #[test]
    fn metrics_config_with_geoip() {
        let toml_str = r#"
listen = "0.0.0.0:9100"

[geoip]
source = "dbip-country"
"#;
        let cfg: MetricsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.listen.as_deref(), Some("0.0.0.0:9100"));
        let geoip = cfg.geoip.unwrap();
        assert_eq!(geoip.source, "dbip-country");
    }
}
