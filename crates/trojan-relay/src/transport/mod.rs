//! Pluggable transport abstraction.
//!
//! Re-exports from `trojan_transport`. The transport traits and
//! implementations now live in the standalone `trojan-transport` crate.

pub use trojan_transport::{TransportAcceptor, TransportConnector, TransportStream};

pub mod plain {
    pub use trojan_transport::plain::*;
}

pub mod tls {
    pub use trojan_transport::tls::*;
}

pub mod ws {
    pub use trojan_transport::ws::*;
}
