//! # trojan-rs
//!
//! A Rust implementation of the Trojan protocol.
//!
//! This crate provides a modular implementation of the Trojan protocol,
//! suitable for building high-performance proxy servers and clients.
//!
//! ## Crates
//!
//! - [`trojan_core`] - Core types and default configurations
//! - [`trojan_proto`] - Protocol parsing and serialization
//! - [`trojan_auth`] - Authentication backends
//! - [`trojan_config`] - Configuration loading and validation
//! - [`trojan_metrics`] - Prometheus-compatible metrics
//! - [`trojan_server`] - Server implementation
//! - [`trojan_client`] - Client implementation (SOCKS5 proxy)
//! - [`trojan_relay`] - Relay chain (entry + relay nodes)

pub use trojan_auth as auth;
pub use trojan_client as client;
pub use trojan_config as config;
pub use trojan_core as core;
pub use trojan_metrics as metrics;
pub use trojan_proto as proto;
pub use trojan_relay as relay;
pub use trojan_server as server;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use trojan_auth::{AuthBackend, MemoryAuth, ReloadableAuth};
    pub use trojan_config::{Config, load_config, validate_config};
    pub use trojan_server::{CancellationToken, ServerError, run, run_with_shutdown};
}
