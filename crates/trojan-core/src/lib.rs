//! Core types and constants shared across trojan crates.
//!
//! This crate provides:
//! - Default configuration values
//! - Error type constants for metrics/logging
//! - Common project metadata

pub mod defaults;
pub mod errors;

// Re-export commonly used items at crate root
pub use defaults::*;
pub use errors::*;

/// Project name.
pub const PROJECT_NAME: &str = "trojan-rs";
/// Project version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
