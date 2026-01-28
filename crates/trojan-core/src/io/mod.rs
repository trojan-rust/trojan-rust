//! I/O utilities for bidirectional relay and stream adapters.
//!
//! This module provides shared I/O primitives that can be used by both
//! trojan-server and trojan-client.

mod prefixed;
mod relay;

pub use prefixed::PrefixedStream;
pub use relay::{relay_bidirectional, NoOpMetrics, RelayMetrics};
