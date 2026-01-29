//! CLI override definitions and application logic.

use clap::Parser;

use crate::Config;
use crate::defaults::*;
use crate::types::*;

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
