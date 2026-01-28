//! Transport adapters for different protocols.
//!
//! This module provides stream adapters that can be used by both
//! trojan-server and trojan-client.

#[cfg(feature = "ws")]
mod ws;

#[cfg(feature = "ws")]
pub use ws::WsIo;
