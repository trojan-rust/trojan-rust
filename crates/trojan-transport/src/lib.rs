//! Pluggable transport for the relay chain.
//!
//! A chain's hops each choose how to reach the next one, and that choice is
//! config — so an entry or relay node has to dial and accept over a transport
//! it only learns at runtime. [`TransportAcceptor`] and [`TransportConnector`]
//! are what let one relay loop serve all of them.
//!
//! # Scope
//!
//! This is the relay chain's abstraction, not the project's. The exit server
//! and the SOCKS5 client deliberately do not use it: their streams change type
//! part-way through — a server connection may turn out to be WebSocket only
//! after TLS is up and the first bytes are inspected — which a trait fixing
//! one `Stream` type per acceptor cannot express without boxing the stream and
//! paying a virtual call on every read. They terminate TLS directly instead,
//! and share the parts that genuinely have one implementation
//! (`trojan_core::tls`) rather than the trait.
//!
//! # Transports
//!
//! - [`plain`]: Plain TCP pass-through (no encryption).
//! - [`tls`]: TLS with auto-generated or file-based certificates.
//! - [`ws`]: WebSocket, reusing `trojan_core::transport::WsIo`.

pub mod error;
pub mod plain;
pub mod tls;
pub mod tls_config;
pub mod ws;

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use error::TransportError;

/// Marker trait for streams usable by the relay system.
pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> TransportStream for T {}

/// Accepts inbound TCP connections and wraps them in a transport stream.
pub trait TransportAcceptor: Clone + Send + Sync + 'static {
    /// The stream type produced by this acceptor.
    type Stream: TransportStream;

    /// Accept and wrap a raw TCP connection.
    fn accept(
        &self,
        tcp: TcpStream,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>>;
}

/// Connects outbound to a target address, producing a transport stream.
pub trait TransportConnector: Clone + Send + Sync + 'static {
    /// The stream type produced by this connector.
    type Stream: TransportStream;

    /// Connect to the given `host:port` address.
    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>>;
}
