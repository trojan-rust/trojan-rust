//! WebSocket transport implementation.
//!
//! - `WsTransportAcceptor`: Accepts a raw TCP connection, performs a WebSocket
//!   server handshake, and wraps the result via `WsIo` for `AsyncRead/AsyncWrite`.
//! - `WsTransportConnector`: Connects to a target via TCP, performs a WebSocket
//!   client handshake, and wraps the result via `WsIo`.
//!
//! Both reuse `trojan_core::transport::WsIo` as the underlying adapter.

use std::future::Future;
use std::pin::Pin;

use tokio::net::TcpStream;
use tokio_tungstenite::{accept_async, client_async};

use trojan_core::transport::WsIo;

use crate::error::TransportError;
use crate::{TransportAcceptor, TransportConnector};

/// WebSocket transport acceptor — upgrades incoming TCP to WebSocket.
#[derive(Clone)]
pub struct WsTransportAcceptor;

impl TransportAcceptor for WsTransportAcceptor {
    type Stream = WsIo<TcpStream>;

    fn accept(
        &self,
        tcp: TcpStream,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        Box::pin(async move {
            let ws_stream = accept_async(tcp)
                .await
                .map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
            Ok(WsIo::new(ws_stream))
        })
    }
}

/// WebSocket transport connector — connects outbound and upgrades to WebSocket.
#[derive(Clone)]
pub struct WsTransportConnector;

impl TransportConnector for WsTransportConnector {
    type Stream = WsIo<TcpStream>;

    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        let addr = addr.to_string();
        Box::pin(async move {
            let tcp = TcpStream::connect(&addr).await?;
            tcp.set_nodelay(true)?;

            let url = format!("ws://{}/", addr);
            let (ws_stream, _response) = client_async(&url, tcp)
                .await
                .map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
            Ok(WsIo::new(ws_stream))
        })
    }
}
