//! Plain TCP transport (no encryption).
//!
//! Useful for testing or trusted-network scenarios where TLS overhead
//! is not desired (e.g., localhost or wireguard tunnels).

use std::future::Future;
use std::pin::Pin;

use tokio::net::TcpStream;

use crate::error::TransportError;
use crate::{TransportAcceptor, TransportConnector};

/// Plain TCP acceptor — passes through the raw TCP stream.
#[derive(Clone)]
pub struct PlainTransportAcceptor;

impl TransportAcceptor for PlainTransportAcceptor {
    type Stream = TcpStream;

    fn accept(
        &self,
        tcp: TcpStream,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        Box::pin(async move { Ok(tcp) })
    }
}

/// Plain TCP connector — connects directly without encryption.
#[derive(Clone)]
pub struct PlainTransportConnector;

impl TransportConnector for PlainTransportConnector {
    type Stream = TcpStream;

    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        let addr = addr.to_string();
        Box::pin(async move {
            let tcp = TcpStream::connect(&addr).await?;
            tcp.set_nodelay(true)?;
            Ok(tcp)
        })
    }
}
