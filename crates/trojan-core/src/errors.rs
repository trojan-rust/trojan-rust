//! Error type constants for metrics and logging.
//!
//! These constants provide consistent error classification across all crates.

/// TLS handshake error.
pub const ERROR_TLS_HANDSHAKE: &str = "tls_handshake";
/// Protocol parsing/validation error.
pub const ERROR_PROTOCOL: &str = "protocol";
/// I/O error.
pub const ERROR_IO: &str = "io";
/// DNS/address resolution error.
pub const ERROR_RESOLVE: &str = "resolve";
/// Timeout error.
pub const ERROR_TIMEOUT: &str = "timeout";
/// Authentication error.
pub const ERROR_AUTH: &str = "auth";
/// Configuration error.
pub const ERROR_CONFIG: &str = "config";
