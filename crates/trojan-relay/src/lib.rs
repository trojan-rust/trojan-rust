//! Relay chain and entry node for trojan-rs multi-hop tunneling.
//!
//! This crate implements the relay chain system that enables multi-hop
//! TLS tunnels: `Client → A(entry) → B(relay) → ... → C(trojan-server)`.
//!
//! # Architecture
//!
//! - **Entry Node (A)**: Listens on multiple TCP ports, routes connections
//!   through named chains to destination trojan-servers.
//! - **Relay Node (B)**: Pluggable transport listener (TLS or plain TCP).
//!   Receives target address and transport metadata via relay handshake,
//!   connects to next hop using the specified transport, and forwards
//!   traffic bidirectionally.
//!
//! # Phase 1 (current)
//!
//! Basic relay without multiplexing. Each client connection creates a
//! dedicated tunnel through the chain.

pub mod config;
pub mod entry;
pub mod error;
pub mod handshake;
pub mod relay;
pub mod router;
pub mod transport;
