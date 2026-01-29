//! Configuration loading and CLI definitions.

use std::{fs, path::Path};

use clap::Parser;
use serde::{Deserialize, Serialize};
use trojan_core::defaults;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub websocket: WebSocketConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub analytics: AnalyticsConfig,
}

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
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            no_delay: default_tcp_no_delay(),
            keepalive_secs: default_tcp_keepalive_secs(),
            reuse_port: default_tcp_reuse_port(),
            fast_open: default_tcp_fast_open(),
            fast_open_qlen: default_tcp_fast_open_qlen(),
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub passwords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    pub listen: Option<String>,
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
    pub filters: std::collections::HashMap<String, String>,
}

// ============================================================================
// Analytics Configuration
// ============================================================================

/// Analytics configuration for connection event collection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyticsConfig {
    /// Whether analytics is enabled (runtime switch).
    #[serde(default)]
    pub enabled: bool,

    /// ClickHouse configuration.
    #[serde(default)]
    pub clickhouse: Option<ClickHouseConfig>,

    /// Buffer configuration.
    #[serde(default)]
    pub buffer: AnalyticsBufferConfig,

    /// Sampling configuration.
    #[serde(default)]
    pub sampling: AnalyticsSamplingConfig,

    /// Privacy configuration.
    #[serde(default)]
    pub privacy: AnalyticsPrivacyConfig,

    /// Server identifier for multi-instance deployments.
    #[serde(default)]
    pub server_id: Option<String>,
}

/// ClickHouse connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    /// ClickHouse URL (e.g., "http://localhost:8123").
    pub url: String,

    /// Database name.
    #[serde(default = "default_analytics_database")]
    pub database: String,

    /// Table name.
    #[serde(default = "default_analytics_table")]
    pub table: String,

    /// Username (optional).
    #[serde(default)]
    pub username: Option<String>,

    /// Password (optional).
    #[serde(default)]
    pub password: Option<String>,

    /// Connection timeout in seconds.
    #[serde(default = "default_analytics_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Write timeout in seconds.
    #[serde(default = "default_analytics_write_timeout")]
    pub write_timeout_secs: u64,
}

/// Buffer configuration for event batching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsBufferConfig {
    /// Maximum number of events to buffer in memory.
    #[serde(default = "default_analytics_buffer_size")]
    pub size: usize,

    /// Flush interval in seconds.
    #[serde(default = "default_analytics_flush_interval")]
    pub flush_interval_secs: u64,

    /// Batch size for writes.
    #[serde(default = "default_analytics_batch_size")]
    pub batch_size: usize,

    /// Fallback file path for failed writes.
    #[serde(default)]
    pub fallback_path: Option<String>,
}

impl Default for AnalyticsBufferConfig {
    fn default() -> Self {
        Self {
            size: default_analytics_buffer_size(),
            flush_interval_secs: default_analytics_flush_interval(),
            batch_size: default_analytics_batch_size(),
            fallback_path: None,
        }
    }
}

/// Sampling configuration for high-traffic scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsSamplingConfig {
    /// Sampling rate (0.0 - 1.0, where 1.0 = 100%).
    #[serde(default = "default_analytics_sample_rate")]
    pub rate: f64,

    /// Users to always record (not affected by sampling).
    #[serde(default)]
    pub always_record_users: Vec<String>,
}

impl Default for AnalyticsSamplingConfig {
    fn default() -> Self {
        Self {
            rate: default_analytics_sample_rate(),
            always_record_users: Vec::new(),
        }
    }
}

/// Privacy configuration for data collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsPrivacyConfig {
    /// Whether to record client IP addresses.
    #[serde(default = "default_true")]
    pub record_peer_ip: bool,

    /// Whether to record full user ID (false = prefix only).
    #[serde(default)]
    pub full_user_id: bool,

    /// User ID prefix length when full_user_id is false.
    #[serde(default = "default_analytics_user_id_prefix_len")]
    pub user_id_prefix_len: usize,

    /// Whether to record SNI.
    #[serde(default = "default_true")]
    pub record_sni: bool,
}

impl Default for AnalyticsPrivacyConfig {
    fn default() -> Self {
        Self {
            record_peer_ip: true,
            full_user_id: false,
            user_id_prefix_len: default_analytics_user_id_prefix_len(),
            record_sni: true,
        }
    }
}

// Analytics default value functions
fn default_analytics_database() -> String {
    "trojan".to_string()
}

fn default_analytics_table() -> String {
    "connections".to_string()
}

fn default_analytics_buffer_size() -> usize {
    10000
}

fn default_analytics_flush_interval() -> u64 {
    5
}

fn default_analytics_batch_size() -> usize {
    1000
}

fn default_analytics_sample_rate() -> f64 {
    1.0
}

fn default_analytics_user_id_prefix_len() -> usize {
    8
}

fn default_analytics_connect_timeout() -> u64 {
    10
}

fn default_analytics_write_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Parser, Default)]
pub struct CliOverrides {
    /// Override server listen address, e.g. 0.0.0.0:443
    #[arg(long)]
    pub listen: Option<String>,
    /// Override fallback backend address, e.g. 127.0.0.1:80
    #[arg(long)]
    pub fallback: Option<String>,
    /// Override TLS cert path
    #[arg(long)]
    pub tls_cert: Option<String>,
    /// Override TLS key path
    #[arg(long)]
    pub tls_key: Option<String>,
    /// Override ALPN list (repeatable or comma-separated)
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub alpn: Option<Vec<String>>,
    /// Override password list (repeatable or comma-separated)
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub password: Option<Vec<String>>,
    /// Override TCP idle timeout (seconds)
    #[arg(long)]
    pub tcp_idle_timeout_secs: Option<u64>,
    /// Override UDP idle timeout (seconds)
    #[arg(long)]
    pub udp_timeout_secs: Option<u64>,
    /// Override maximum Trojan header bytes
    #[arg(long)]
    pub max_header_bytes: Option<usize>,
    /// Override maximum UDP payload size
    #[arg(long)]
    pub max_udp_payload: Option<usize>,
    /// Override maximum UDP buffer bytes
    #[arg(long)]
    pub max_udp_buffer_bytes: Option<usize>,
    /// Override maximum concurrent connections (0 = unlimited)
    #[arg(long)]
    pub max_connections: Option<usize>,
    /// Override metrics listen address
    #[arg(long)]
    pub metrics_listen: Option<String>,
    /// Override log level (trace/debug/info/warn/error)
    #[arg(long)]
    pub log_level: Option<String>,
    /// Enable rate limiting with max connections per IP (0 = disabled)
    #[arg(long)]
    pub rate_limit_max_per_ip: Option<u32>,
    /// Rate limit time window in seconds
    #[arg(long)]
    pub rate_limit_window_secs: Option<u64>,
    /// Minimum TLS version (tls12, tls13)
    #[arg(long)]
    pub tls_min_version: Option<String>,
    /// Maximum TLS version (tls12, tls13)
    #[arg(long)]
    pub tls_max_version: Option<String>,
    /// Path to CA certificate for client authentication (mTLS)
    #[arg(long)]
    pub tls_client_ca: Option<String>,
    /// Buffer size for TCP relay (bytes)
    #[arg(long)]
    pub relay_buffer_size: Option<usize>,
    /// TCP socket send buffer size (SO_SNDBUF, 0 = OS default)
    #[arg(long)]
    pub tcp_send_buffer: Option<usize>,
    /// TCP socket receive buffer size (SO_RCVBUF, 0 = OS default)
    #[arg(long)]
    pub tcp_recv_buffer: Option<usize>,
    /// TCP listener backlog size
    #[arg(long)]
    pub connection_backlog: Option<u32>,
    /// Enable WebSocket transport (default true)
    #[arg(long)]
    pub ws_enabled: Option<bool>,
    /// WebSocket mode: mixed | split
    #[arg(long)]
    pub ws_mode: Option<String>,
    /// WebSocket path
    #[arg(long)]
    pub ws_path: Option<String>,
    /// WebSocket host (optional)
    #[arg(long)]
    pub ws_host: Option<String>,
    /// WebSocket listen address for split mode
    #[arg(long)]
    pub ws_listen: Option<String>,
    /// WebSocket max frame bytes
    #[arg(long)]
    pub ws_max_frame_bytes: Option<usize>,
    /// Disable TCP_NODELAY (enable Nagle's algorithm)
    #[arg(long)]
    pub tcp_no_delay: Option<bool>,
    /// TCP Keep-Alive interval in seconds (0 = disabled)
    #[arg(long)]
    pub tcp_keepalive_secs: Option<u64>,
    /// Enable SO_REUSEPORT for multi-process load balancing
    #[arg(long)]
    pub tcp_reuse_port: Option<bool>,
    /// Enable TCP Fast Open (requires kernel support)
    #[arg(long)]
    pub tcp_fast_open: Option<bool>,
    /// TCP Fast Open queue length
    #[arg(long)]
    pub tcp_fast_open_qlen: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported config format")]
    UnsupportedFormat,
    #[error("validation: {0}")]
    Validation(String),
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let data = fs::read_to_string(path)?;
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "json" | "jsonc" => {
            let stripped = json_comments::StripComments::new(data.as_bytes());
            Ok(serde_json::from_reader(stripped)?)
        }
        "yaml" | "yml" => Ok(serde_yaml::from_str(&data)?),
        "toml" => Ok(toml::from_str(&data)?),
        _ => Err(ConfigError::UnsupportedFormat),
    }
}

pub fn apply_overrides(config: &mut Config, overrides: &CliOverrides) {
    if let Some(v) = &overrides.listen {
        config.server.listen = v.clone();
    }
    if let Some(v) = &overrides.fallback {
        config.server.fallback = v.clone();
    }
    if let Some(v) = overrides.tcp_idle_timeout_secs {
        config.server.tcp_idle_timeout_secs = v;
    }
    if let Some(v) = overrides.udp_timeout_secs {
        config.server.udp_timeout_secs = v;
    }
    if let Some(v) = overrides.max_header_bytes {
        config.server.max_header_bytes = v;
    }
    if let Some(v) = overrides.max_udp_payload {
        config.server.max_udp_payload = v;
    }
    if let Some(v) = overrides.max_udp_buffer_bytes {
        config.server.max_udp_buffer_bytes = v;
    }
    if let Some(v) = overrides.max_connections {
        config.server.max_connections = if v == 0 { None } else { Some(v) };
    }
    if let Some(v) = &overrides.tls_cert {
        config.tls.cert = v.clone();
    }
    if let Some(v) = &overrides.tls_key {
        config.tls.key = v.clone();
    }
    if let Some(v) = &overrides.alpn {
        config.tls.alpn = v.clone();
    }
    if let Some(v) = &overrides.password {
        config.auth.passwords = v.clone();
    }
    if let Some(v) = &overrides.metrics_listen {
        config.metrics.listen = Some(v.clone());
    }
    if let Some(v) = &overrides.log_level {
        config.logging.level = Some(v.clone());
    }
    // Rate limiting: 0 disables, > 0 enables with that limit
    if let Some(max) = overrides.rate_limit_max_per_ip {
        if max == 0 {
            config.server.rate_limit = None;
        } else {
            let rl = config
                .server
                .rate_limit
                .get_or_insert_with(|| RateLimitConfig {
                    max_connections_per_ip: default_rate_limit_max_connections(),
                    window_secs: default_rate_limit_window_secs(),
                    cleanup_interval_secs: default_rate_limit_cleanup_secs(),
                });
            rl.max_connections_per_ip = max;
        }
    }
    if let Some(window) = overrides.rate_limit_window_secs
        && let Some(ref mut rl) = config.server.rate_limit
    {
        rl.window_secs = window;
    }
    // TLS version overrides
    if let Some(v) = &overrides.tls_min_version {
        config.tls.min_version = v.clone();
    }
    if let Some(v) = &overrides.tls_max_version {
        config.tls.max_version = v.clone();
    }
    if let Some(v) = &overrides.tls_client_ca {
        config.tls.client_ca = Some(v.clone());
    }
    // Resource limits
    if overrides.relay_buffer_size.is_some()
        || overrides.tcp_send_buffer.is_some()
        || overrides.tcp_recv_buffer.is_some()
        || overrides.connection_backlog.is_some()
    {
        let rl = config
            .server
            .resource_limits
            .get_or_insert_with(|| ResourceLimitsConfig {
                relay_buffer_size: default_relay_buffer_size(),
                tcp_send_buffer: 0,
                tcp_recv_buffer: 0,
                connection_backlog: default_connection_backlog(),
            });
        if let Some(v) = overrides.relay_buffer_size {
            rl.relay_buffer_size = v;
        }
        if let Some(v) = overrides.tcp_send_buffer {
            rl.tcp_send_buffer = v;
        }
        if let Some(v) = overrides.tcp_recv_buffer {
            rl.tcp_recv_buffer = v;
        }
        if let Some(v) = overrides.connection_backlog {
            rl.connection_backlog = v;
        }
    }
    if let Some(v) = overrides.ws_enabled {
        config.websocket.enabled = v;
    }
    if let Some(v) = &overrides.ws_mode {
        config.websocket.mode = v.clone();
    }
    if let Some(v) = &overrides.ws_path {
        config.websocket.path = v.clone();
    }
    if let Some(v) = &overrides.ws_host {
        config.websocket.host = Some(v.clone());
    }
    if let Some(v) = &overrides.ws_listen {
        config.websocket.listen = Some(v.clone());
    }
    if let Some(v) = overrides.ws_max_frame_bytes {
        config.websocket.max_frame_bytes = v;
    }
    // TCP socket options
    if let Some(v) = overrides.tcp_no_delay {
        config.server.tcp.no_delay = v;
    }
    if let Some(v) = overrides.tcp_keepalive_secs {
        config.server.tcp.keepalive_secs = v;
    }
    if let Some(v) = overrides.tcp_reuse_port {
        config.server.tcp.reuse_port = v;
    }
    if let Some(v) = overrides.tcp_fast_open {
        config.server.tcp.fast_open = v;
    }
    if let Some(v) = overrides.tcp_fast_open_qlen {
        config.server.tcp.fast_open_qlen = v;
    }
}

pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
    if config.server.listen.trim().is_empty() {
        return Err(ConfigError::Validation("server.listen is empty".into()));
    }
    if config.server.fallback.trim().is_empty() {
        return Err(ConfigError::Validation("server.fallback is empty".into()));
    }
    if config.tls.cert.trim().is_empty() {
        return Err(ConfigError::Validation("tls.cert is empty".into()));
    }
    if config.tls.key.trim().is_empty() {
        return Err(ConfigError::Validation("tls.key is empty".into()));
    }
    if config.auth.passwords.is_empty() {
        return Err(ConfigError::Validation("auth.passwords is empty".into()));
    }
    if config.server.tcp_idle_timeout_secs == 0 {
        return Err(ConfigError::Validation(
            "server.tcp_idle_timeout_secs must be > 0".into(),
        ));
    }
    if config.server.udp_timeout_secs == 0 {
        return Err(ConfigError::Validation(
            "server.udp_timeout_secs must be > 0".into(),
        ));
    }
    if config.server.max_header_bytes < min_header_bytes() {
        return Err(ConfigError::Validation(format!(
            "server.max_header_bytes too small (min {})",
            min_header_bytes()
        )));
    }
    if config.server.max_udp_payload == 0 || config.server.max_udp_payload > u16::MAX as usize {
        return Err(ConfigError::Validation(
            "server.max_udp_payload must be 1..=65535".into(),
        ));
    }
    if config.server.max_udp_buffer_bytes == 0 {
        return Err(ConfigError::Validation(
            "server.max_udp_buffer_bytes must be > 0".into(),
        ));
    }
    if config.server.max_udp_buffer_bytes < config.server.max_udp_payload + 8 {
        return Err(ConfigError::Validation(
            "server.max_udp_buffer_bytes must be >= max_udp_payload + 8".into(),
        ));
    }
    // Validate TLS versions
    let valid_versions = ["tls12", "tls13"];
    if !valid_versions.contains(&config.tls.min_version.as_str()) {
        return Err(ConfigError::Validation(format!(
            "tls.min_version must be one of: {:?}",
            valid_versions
        )));
    }
    if !valid_versions.contains(&config.tls.max_version.as_str()) {
        return Err(ConfigError::Validation(format!(
            "tls.max_version must be one of: {:?}",
            valid_versions
        )));
    }
    // tls13 > tls12
    let min_ord = if config.tls.min_version == "tls13" {
        1
    } else {
        0
    };
    let max_ord = if config.tls.max_version == "tls13" {
        1
    } else {
        0
    };
    if min_ord > max_ord {
        return Err(ConfigError::Validation(
            "tls.min_version cannot be greater than tls.max_version".into(),
        ));
    }
    // Validate resource limits
    if let Some(ref rl) = config.server.resource_limits {
        if rl.relay_buffer_size < 1024 {
            return Err(ConfigError::Validation(
                "resource_limits.relay_buffer_size must be >= 1024".into(),
            ));
        }
        if rl.relay_buffer_size > 1024 * 1024 {
            return Err(ConfigError::Validation(
                "resource_limits.relay_buffer_size must be <= 1MB".into(),
            ));
        }
        if rl.connection_backlog == 0 {
            return Err(ConfigError::Validation(
                "resource_limits.connection_backlog must be > 0".into(),
            ));
        }
    }
    if let Some(ref pool) = config.server.fallback_pool {
        if pool.max_idle == 0 {
            return Err(ConfigError::Validation(
                "fallback_pool.max_idle must be > 0".into(),
            ));
        }
        if pool.max_age_secs == 0 {
            return Err(ConfigError::Validation(
                "fallback_pool.max_age_secs must be > 0".into(),
            ));
        }
        if pool.fill_batch == 0 || pool.fill_batch > pool.max_idle {
            return Err(ConfigError::Validation(
                "fallback_pool.fill_batch must be 1..=max_idle".into(),
            ));
        }
    }
    if config.websocket.mode != "mixed" && config.websocket.mode != "split" {
        return Err(ConfigError::Validation(
            "websocket.mode must be 'mixed' or 'split'".into(),
        ));
    }
    if config.websocket.path.is_empty() {
        return Err(ConfigError::Validation("websocket.path is empty".into()));
    }
    if config.websocket.enabled
        && config.websocket.mode == "split"
        && config.websocket.listen.as_deref().unwrap_or("").is_empty()
    {
        return Err(ConfigError::Validation(
            "websocket.listen is required in split mode".into(),
        ));
    }
    Ok(())
}

// ============================================================================
// Default Value Functions (for serde)
// ============================================================================

/// Generate default value functions that forward to trojan_core::defaults constants.
macro_rules! default_fns {
    // For Copy types (integers, bool, etc.)
    ($($fn_name:ident => $const_name:ident : $ty:ty),* $(,)?) => {
        $(
            fn $fn_name() -> $ty {
                defaults::$const_name
            }
        )*
    };
}

/// Generate default value functions that return String from &str constants.
macro_rules! default_string_fns {
    ($($fn_name:ident => $const_name:ident),* $(,)?) => {
        $(
            fn $fn_name() -> String {
                defaults::$const_name.to_string()
            }
        )*
    };
}

default_fns! {
    default_udp_timeout_secs      => DEFAULT_UDP_TIMEOUT_SECS: u64,
    default_tcp_timeout_secs      => DEFAULT_TCP_TIMEOUT_SECS: u64,
    default_max_udp_payload       => DEFAULT_MAX_UDP_PAYLOAD: usize,
    default_max_udp_buffer_bytes  => DEFAULT_MAX_UDP_BUFFER_BYTES: usize,
    default_max_header_bytes      => DEFAULT_MAX_HEADER_BYTES: usize,
    min_header_bytes              => MIN_HEADER_BYTES: usize,
    default_rate_limit_max_connections => DEFAULT_RATE_LIMIT_MAX_CONNECTIONS: u32,
    default_rate_limit_window_secs     => DEFAULT_RATE_LIMIT_WINDOW_SECS: u64,
    default_rate_limit_cleanup_secs    => DEFAULT_RATE_LIMIT_CLEANUP_SECS: u64,
    default_pool_max_idle         => DEFAULT_POOL_MAX_IDLE: usize,
    default_pool_max_age_secs     => DEFAULT_POOL_MAX_AGE_SECS: u64,
    default_pool_fill_batch       => DEFAULT_POOL_FILL_BATCH: usize,
    default_pool_fill_delay_ms    => DEFAULT_POOL_FILL_DELAY_MS: u64,
    default_relay_buffer_size     => DEFAULT_RELAY_BUFFER_SIZE: usize,
    default_connection_backlog    => DEFAULT_CONNECTION_BACKLOG: u32,
    default_ws_enabled            => DEFAULT_WS_ENABLED: bool,
    default_ws_max_frame_bytes    => DEFAULT_WS_MAX_FRAME_BYTES: usize,
    // TCP socket options
    default_tcp_no_delay          => DEFAULT_TCP_NO_DELAY: bool,
    default_tcp_keepalive_secs    => DEFAULT_TCP_KEEPALIVE_SECS: u64,
    default_tcp_reuse_port        => DEFAULT_TCP_REUSE_PORT: bool,
    default_tcp_fast_open         => DEFAULT_TCP_FAST_OPEN: bool,
    default_tcp_fast_open_qlen    => DEFAULT_TCP_FAST_OPEN_QLEN: u32,
}

default_string_fns! {
    default_min_tls_version => DEFAULT_TLS_MIN_VERSION,
    default_max_tls_version => DEFAULT_TLS_MAX_VERSION,
    default_ws_mode         => DEFAULT_WS_MODE,
    default_ws_path         => DEFAULT_WS_PATH,
}
