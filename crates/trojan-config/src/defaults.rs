//! Default value functions for serde deserialization.
//!
//! These functions forward to constants defined in `trojan_core::defaults`.

use trojan_core::defaults;

/// Generate default value functions that forward to trojan_core::defaults constants.
macro_rules! default_fns {
    // For Copy types (integers, bool, etc.)
    ($($fn_name:ident => $const_name:ident : $ty:ty),* $(,)?) => {
        $(
            pub(crate) fn $fn_name() -> $ty {
                defaults::$const_name
            }
        )*
    };
}

/// Generate default value functions that return String from &str constants.
macro_rules! default_string_fns {
    ($($fn_name:ident => $const_name:ident),* $(,)?) => {
        $(
            pub(crate) fn $fn_name() -> String {
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
