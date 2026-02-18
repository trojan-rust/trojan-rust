//! Default configuration values.
//!
//! Centralized default constants for use across all crates.

// ============================================================================
// Timeout Defaults
// ============================================================================

/// Default TCP idle timeout in seconds.
pub const DEFAULT_TCP_TIMEOUT_SECS: u64 = 600;
/// Default UDP timeout in seconds.
pub const DEFAULT_UDP_TIMEOUT_SECS: u64 = 60;
/// Default graceful shutdown timeout in seconds.
pub const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Buffer/Size Defaults
// ============================================================================

/// Default maximum UDP payload size (8 KiB).
pub const DEFAULT_MAX_UDP_PAYLOAD: usize = 8192;
/// Default maximum UDP buffer bytes for TCP->UDP framing.
pub const DEFAULT_MAX_UDP_BUFFER_BYTES: usize = 65536;
/// Default maximum header bytes.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8192;
/// Default relay buffer size (32 KiB — tuned for high-throughput relay chains).
pub const DEFAULT_RELAY_BUFFER_SIZE: usize = 32768;
/// Default TCP socket send buffer size (0 = OS default).
pub const DEFAULT_TCP_SEND_BUFFER: usize = 0;
/// Default TCP socket receive buffer size (0 = OS default).
pub const DEFAULT_TCP_RECV_BUFFER: usize = 0;

// ============================================================================
// TCP Socket Defaults
// ============================================================================

/// Default TCP_NODELAY (disable Nagle's algorithm for lower latency).
pub const DEFAULT_TCP_NO_DELAY: bool = true;
/// Default TCP Keep-Alive interval in seconds (0 = disabled).
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 300;
/// Default SO_REUSEPORT for multi-process load balancing.
pub const DEFAULT_TCP_REUSE_PORT: bool = false;
/// Default TCP Fast Open (TFO) enabled.
pub const DEFAULT_TCP_FAST_OPEN: bool = false;
/// Default TCP Fast Open queue length.
pub const DEFAULT_TCP_FAST_OPEN_QLEN: u32 = 5;
/// Prefer IPv4 addresses when resolving DNS (server-side outbound).
pub const DEFAULT_TCP_PREFER_IPV4: bool = false;

// ============================================================================
// Connection Defaults
// ============================================================================

/// Default TCP listener backlog.
pub const DEFAULT_CONNECTION_BACKLOG: u32 = 1024;

// ============================================================================
// Rate Limit Defaults
// ============================================================================

/// Default max connections per IP for rate limiting.
pub const DEFAULT_RATE_LIMIT_MAX_CONNECTIONS: u32 = 10;
/// Default rate limit window in seconds.
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Default rate limit cleanup interval in seconds.
pub const DEFAULT_RATE_LIMIT_CLEANUP_SECS: u64 = 300;

// ============================================================================
// Connection Pool Defaults
// ============================================================================

/// Default max idle connections in pool.
pub const DEFAULT_POOL_MAX_IDLE: usize = 10;
/// Default max age of pooled connections in seconds.
pub const DEFAULT_POOL_MAX_AGE_SECS: u64 = 300;
/// Default warm-fill batch size per cycle.
pub const DEFAULT_POOL_FILL_BATCH: usize = 2;
/// Default delay (ms) between warm-fill connection attempts.
pub const DEFAULT_POOL_FILL_DELAY_MS: u64 = 50;

// ============================================================================
// TLS Defaults
// ============================================================================

/// Default minimum TLS version.
pub const DEFAULT_TLS_MIN_VERSION: &str = "tls12";
/// Default maximum TLS version.
pub const DEFAULT_TLS_MAX_VERSION: &str = "tls13";
/// Default TLS handshake timeout in seconds.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

// ============================================================================
// WebSocket Defaults
// ============================================================================

/// Default WebSocket enabled.
pub const DEFAULT_WS_ENABLED: bool = true;
/// Default WebSocket mode: "mixed" or "split".
pub const DEFAULT_WS_MODE: &str = "mixed";
/// Default WebSocket path.
pub const DEFAULT_WS_PATH: &str = "/";
/// Default max WebSocket frame size.
pub const DEFAULT_WS_MAX_FRAME_BYTES: usize = 1 << 20;

// ============================================================================
// Auth Cache Defaults
// ============================================================================

/// Default auth cache TTL in seconds (positive cache).
pub const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 300;
/// Default auth cache stale-while-revalidate window in seconds.
pub const DEFAULT_AUTH_CACHE_STALE_TTL_SECS: u64 = 600;
/// Default auth negative cache TTL in seconds.
pub const DEFAULT_AUTH_CACHE_NEG_TTL_SECS: u64 = 10;

// ============================================================================
// Protocol Constants
// ============================================================================

/// Trojan protocol hash length (SHA-224 hex = 56 chars).
pub const HASH_LEN: usize = 56;
/// Minimum header bytes (hash + CRLF + cmd + atyp + ipv4 + port + CRLF).
pub const MIN_HEADER_BYTES: usize = HASH_LEN + 2 + 1 + 1 + 4 + 2 + 2;
