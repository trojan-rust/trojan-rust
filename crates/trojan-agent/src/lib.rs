//! Trojan panel agent — connects to a centralized management panel via
//! WebSocket, receives full configuration, boots the appropriate service,
//! and reports heartbeat + traffic back.
//!
//! # Usage
//!
//! ```bash
//! trojan agent -c agent.toml
//! ```
//!
//! The agent TOML only needs `panel_url` and `token`. Everything else
//! (TLS certs, listen addresses, auth, chains) comes from the panel.

pub mod cache;
pub mod cli;
pub mod client;
pub mod collector;
pub mod config;
pub mod error;
pub mod protocol;
pub mod reporter;
pub mod runner;

pub use cli::AgentArgs;
pub use error::AgentError;
