//! Pluggable transport abstraction.
//!
//! Defines traits for accepting inbound connections and connecting outbound,
//! allowing the relay system to work with TLS, plain TCP, or future
//! TCP-based transports (WebSocket, H2, etc.) without changing core relay logic.

pub mod plain;
pub mod tls;

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::RelayError;

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
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, RelayError>> + Send + '_>>;
}

/// Connects outbound to a target address, producing a transport stream.
pub trait TransportConnector: Clone + Send + Sync + 'static {
    /// The stream type produced by this connector.
    type Stream: TransportStream;

    /// Connect to the given `host:port` address.
    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, RelayError>> + Send + '_>>;
}
