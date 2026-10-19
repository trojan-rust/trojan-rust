//! Trojan client with SOCKS5 proxy.
//!
//! This crate provides a local SOCKS5 proxy that forwards connections through
//! the Trojan protocol over TLS to a remote trojan server.

pub mod cli;
pub mod config;
mod connector;
mod error;
mod handler;
pub mod socks5;

pub use cli::ClientArgs;
pub use config::{ClientConfig, load_client_config};
pub use connector::ClientState;
pub use error::ClientError;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use trojan_auth::sha224_hex;
use trojan_core::defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS;
use trojan_core::net::prepare_tcp_listener_socket;
use trojan_dns::DnsResolver;

/// Run the trojan client with the given configuration.
pub async fn run(config: ClientConfig, shutdown: CancellationToken) -> Result<(), ClientError> {
    // Compute password hash
    let hash_hex = sha224_hex(&config.client.password);

    // Build DNS resolver from config
    let dns_resolver = DnsResolver::new(&config.client.dns)
        .map_err(|e| ClientError::Config(format!("dns resolver: {e}")))?;
    info!(dns = ?config.client.dns.strategy, "dns resolver initialized");

    // Build TLS config
    let tls_config = connector::build_tls_config(&config.client.tls)?;
    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let sni = connector::resolve_sni(&config.client.tls, &config.client.remote)?;

    let state = Arc::new(ClientState {
        hash_hex,
        remote_addr: config.client.remote.clone(),
        tls_connector,
        sni,
        tcp_config: config.client.tcp.clone(),
        tls_handshake_timeout: Duration::from_secs(DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS),
        dns_resolver,
    });

    // Retain one SOCKS5 listener, with explicit IPv6 policy when requested.
    let listener = bind_socks5_listener(&config.client.listen, config.client.tcp.ipv6_only).await?;
    info!(listen = %config.client.listen, remote = %config.client.remote, "trojan client started");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let peer = canonical_client_peer(peer);
                        let state = state.clone();
                        tokio::spawn(async move {
                            handler::handle_socks5_conn(stream, peer, state).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "failed to accept connection");
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("shutting down client");
                break;
            }
        }
    }

    Ok(())
}

/// Only an explicitly configured IPv6 listener uses the shared Socket setup.
/// An absent setting preserves the old Tokio address resolution and OS defaults.
async fn bind_socks5_listener(
    listen: &str,
    ipv6_only: Option<bool>,
) -> Result<TcpListener, ClientError> {
    let Some(only_v6) = ipv6_only else {
        return Ok(TcpListener::bind(listen).await?);
    };
    let addr: SocketAddr = listen.parse().map_err(|_| {
        ClientError::Config(
            "client.tcp.ipv6_only requires a numeric IPv6 client.listen address".into(),
        )
    })?;
    if !addr.is_ipv6() {
        return Err(ClientError::Config(
            "client.tcp.ipv6_only requires an IPv6 client.listen address".into(),
        ));
    }

    let socket = prepare_tcp_listener_socket(addr, Some(only_v6))?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(socket))?)
}

/// A dual-stack IPv6 listener reports an IPv4 peer as an IPv4-mapped address.
/// Normalize before existing SOCKS5 UDP address-family selection.
fn canonical_client_peer(peer: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = peer
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(v4.into(), v6.port());
    }
    peer
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[test]
    fn mapped_ipv4_peer_is_canonical_ipv4() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5050".parse().unwrap();
        let ipv4: SocketAddr = "127.0.0.1:5050".parse().unwrap();
        let ipv6: SocketAddr = "[::1]:5050".parse().unwrap();
        assert_eq!(canonical_client_peer(mapped), ipv4);
        assert_eq!(canonical_client_peer(ipv4), ipv4);
        assert_eq!(canonical_client_peer(ipv6), ipv6);
    }

    #[tokio::test]
    async fn explicit_dual_stack_listener_accepts_both_families() {
        let listener = bind_socks5_listener("[::]:0", Some(false)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let v4 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let (_, peer4) = listener.accept().await.unwrap();
        assert_eq!(
            canonical_client_peer(peer4).ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        drop(v4);
        let v6 = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
        let (_, peer6) = listener.accept().await.unwrap();
        assert_eq!(
            peer6.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        drop(v6);
    }

    #[tokio::test]
    async fn ipv6_only_listener_rejects_ipv4() {
        let listener = bind_socks5_listener("[::]:0", Some(true)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect_err("an IPv6-only listener cannot receive IPv4 connections");
        let v6 = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
        drop(v6);
    }

    #[tokio::test]
    async fn implicit_mode_preserves_original_ipv4_bind() {
        let listener = bind_socks5_listener("127.0.0.1:0", None).await.unwrap();
        assert!(listener.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn explicit_ipv6_option_rejects_other_address_families() {
        for listen in ["0.0.0.0:0", "127.0.0.1:0", "localhost:0"] {
            assert!(matches!(
                bind_socks5_listener(listen, Some(false)).await,
                Err(ClientError::Config(_))
            ));
        }
    }
}
