//! Configuration type definitions for server, TLS, WebSocket, auth, metrics, and logging.

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub id: String,
    pub password: String,
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
