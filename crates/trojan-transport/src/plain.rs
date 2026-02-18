//! Plain TCP transport (no encryption).
//!
//! Useful for testing or trusted-network scenarios where TLS overhead
//! is not desired (e.g., localhost or wireguard tunnels).

use std::future::Future;
use std::pin::Pin;

use tokio::net::TcpStream;
use trojan_dns::DnsResolver;

use crate::error::TransportError;
use crate::{TransportAcceptor, TransportConnector};

/// Plain TCP acceptor — passes through the raw TCP stream.
#[derive(Debug, Clone)]
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
///
/// When a [`DnsResolver`] is configured, domain names are resolved via
/// hickory-resolver (with caching and optional DoH/DoT) before connecting.
/// Without a resolver, falls back to `TcpStream::connect` with Tokio's
/// built-in system DNS resolution.
#[derive(Debug, Clone)]
pub struct PlainTransportConnector {
    resolver: Option<DnsResolver>,
}

impl PlainTransportConnector {
    /// Create a plain connector without a DNS resolver (uses system DNS).
    pub fn new() -> Self {
        Self { resolver: None }
    }

    /// Create a plain connector with a custom DNS resolver.
    pub fn with_resolver(resolver: DnsResolver) -> Self {
        Self {
            resolver: Some(resolver),
        }
    }
}

impl Default for PlainTransportConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportConnector for PlainTransportConnector {
    type Stream = TcpStream;

    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        let addr = addr.to_string();
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let tcp = if let Some(resolver) = resolver {
                let socket_addr = resolver
                    .resolve(&addr)
                    .await
                    .map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
                TcpStream::connect(socket_addr).await?
            } else {
                TcpStream::connect(&addr).await?
            };
            tcp.set_nodelay(true)?;
            Ok(tcp)
        })
    }
}
