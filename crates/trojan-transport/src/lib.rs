//! Pluggable transport abstraction for trojan-rs.
//!
//! Defines traits for accepting inbound connections and connecting outbound,
//! allowing the relay system to work with TLS, plain TCP, WebSocket, or future
//! TCP-based transports without changing core relay logic.
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
