//! Configuration type definitions for server, TLS, WebSocket, auth, metrics, and logging.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use trojan_rules::config::GeoipConfig;

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
    /// Senders allowed to introduce a connection with a PROXY protocol header.
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

/// Who may hand this server a PROXY protocol v2 header, and thereby name the
/// client and the relay chain a connection came through.
///
/// A header is a claim about someone else, so it is only believed from an
/// address the operator listed: relays and load balancers that sit directly in
/// front of this server. An empty list turns the feature off entirely, since
/// believing anyone would let any client on the internet pick the address it
/// is rate-limited and logged as, and the nodes its traffic is billed to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyProtocolConfig {
    /// Trusted senders, as addresses (`10.0.0.7`) or blocks (`10.0.0.0/24`).
    #[serde(
        default,
        deserialize_with = "deserialize_networks",
        serialize_with = "serialize_networks"
    )]
    pub trusted: Vec<IpNet>,
}

impl ProxyProtocolConfig {
    /// Whether any sender is trusted, and so whether to look for a header.
    pub fn is_enabled(&self) -> bool {
        !self.trusted.is_empty()
    }

    /// Whether a header arriving from `peer` may be believed.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        // A dual-stack listener reports an IPv4 sender as `::ffff:a.b.c.d`,
        // which no IPv4 block would match. Test the address the operator
        // would have written down as well as the one the socket reports.
        let unmapped = match peer {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        self.trusted
            .iter()
            .any(|net| net.contains(&peer) || unmapped.is_some_and(|addr| net.contains(&addr)))
    }
}

/// Accept both plain addresses and CIDR blocks, so an operator listing a
/// single relay does not have to write `/32`.
fn deserialize_networks<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    de::Error::custom(format!("invalid IP address or CIDR block: {entry:?}"))
                })
        })
        .collect()
}

fn serialize_networks<S>(networks: &[IpNet], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(networks.len()))?;
    for net in networks {
        seq.serialize_element(&net.to_string())?;
    }
    seq.end()
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

/// A TLS protocol version this server will negotiate.
///
/// Declaration order is version order, so `min <= max` is a comparison rather
/// than a hand-written ordinal mapping.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
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
    /// Lowest version to negotiate. Default: tls12
    #[serde(default = "default_min_tls_version")]
    pub min_version: TlsVersion,
    /// Highest version to negotiate. Default: tls13
    #[serde(default = "default_max_tls_version")]
    pub max_version: TlsVersion,
    /// Path to CA certificate for client authentication (mTLS).
    /// If set, client certificates will be required and verified.
    #[serde(default)]
    pub client_ca: Option<String>,
    /// Cipher suites to use. If empty, uses rustls defaults.
    /// Example: ["TLS13_AES_256_GCM_SHA384", "TLS13_CHACHA20_POLY1305_SHA256"]
    #[serde(default)]
    pub cipher_suites: Vec<String>,
}

/// How the server carries WebSocket traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum WebSocketMode {
    /// One port carries both: a connection is inspected once TLS is up and
    /// either upgraded or handled as a plain trojan stream.
    #[default]
    Mixed,
    /// A port of its own, where a connection that does not upgrade is refused
    /// rather than passed to the fallback.
    Split,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_ws_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: WebSocketMode,
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
            mode: WebSocketMode::default(),
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

    /// HTTP remote dashboard worker URL.
    /// ```toml
    /// http_url = "https://auth.example.workers.dev"
    /// ```
    #[serde(default)]
    pub http_url: Option<String>,

    /// Bearer token for node authentication with the dashboard worker.
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

    /// HTTP auth traffic batch flush interval in seconds (default: 30).
    /// Traffic updates are accumulated in memory and flushed to the dashboard worker
    /// at this interval. Set higher to reduce HTTP requests at the cost of
    /// delayed traffic accounting.
    #[serde(default = "default_http_batch_flush_interval_secs")]
    pub http_batch_flush_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub id: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub listen: Option<String>,
    /// GeoIP database for per-country metrics labels (country-level).
    #[serde(default)]
    pub geoip: Option<GeoipConfig>,
    /// Emit per-destination byte counters (`trojan_target_bytes_total`).
    ///
    /// The destination host becomes a label value, so this metric holds one
    /// time series per destination ever reached, for the life of the process.
    /// Leave it on for deployments with a known, small destination set; turn
    /// it off on general-purpose exit nodes, where it grows without bound and
    /// inflates both resident memory and `/metrics` scrape size.
    ///
    /// Disabling it does not affect the global `trojan_bytes_*_total`
    /// counters or `trojan_target_connections_total`.
    #[serde(default = "default_metrics_per_target")]
    pub per_target: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: None,
            geoip: None,
            per_target: default_metrics_per_target(),
        }
    }
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

    #[test]
    fn proxy_protocol_is_off_until_a_sender_is_trusted() {
        let cfg = ProxyProtocolConfig::default();
        assert!(!cfg.is_enabled());
        assert!(!cfg.trusts("10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn proxy_protocol_trusts_bare_addresses_and_blocks() {
        let cfg: ProxyProtocolConfig =
            toml::from_str(r#"trusted = ["10.0.0.7", "192.168.8.0/24", "2001:db8::/32"]"#).unwrap();

        assert!(cfg.is_enabled());
        assert!(cfg.trusts("10.0.0.7".parse().unwrap()));
        assert!(!cfg.trusts("10.0.0.8".parse().unwrap()));
        assert!(cfg.trusts("192.168.8.99".parse().unwrap()));
        assert!(!cfg.trusts("192.168.9.1".parse().unwrap()));
        assert!(cfg.trusts("2001:db8::1".parse().unwrap()));
    }

    /// A dual-stack listener reports IPv4 senders in mapped form, which would
    /// otherwise never match the block an operator wrote.
    #[test]
    fn proxy_protocol_trusts_ipv4_mapped_senders() {
        let cfg: ProxyProtocolConfig = toml::from_str(r#"trusted = ["10.0.0.0/8"]"#).unwrap();

        assert!(cfg.trusts("::ffff:10.0.0.7".parse().unwrap()));
        assert!(!cfg.trusts("::ffff:11.0.0.7".parse().unwrap()));
    }

    #[test]
    fn proxy_protocol_rejects_nonsense_entries() {
        let err = toml::from_str::<ProxyProtocolConfig>(r#"trusted = ["not-an-address"]"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not-an-address"), "unexpected error: {err}");
    }
}
