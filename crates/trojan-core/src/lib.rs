//! Core types and constants shared across trojan crates.
//!
//! This crate provides:
//! - Default configuration values
//! - Error type constants for metrics/logging
//! - I/O utilities (relay, stream adapters)
//! - Transport adapters (WebSocket, etc.)
//! - TLS material loading, behind the `tls` feature
//! - Common project metadata

pub mod defaults;
pub mod errors;
pub mod geo;
pub mod io;
pub mod proxy_protocol;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transport;

// Re-export commonly used items at crate root
pub use defaults::*;
pub use errors::*;

/// Project name.
pub const PROJECT_NAME: &str = "trojan-rs";
/// Project version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
