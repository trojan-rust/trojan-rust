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

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use trojan_auth::sha224_hex;
use trojan_core::defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS;

/// Run the trojan client with the given configuration.
pub async fn run(config: ClientConfig, shutdown: CancellationToken) -> Result<(), ClientError> {
    // Compute password hash
    let hash_hex = sha224_hex(&config.client.password);

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
    });

    // Bind SOCKS5 listener
    let listener = TcpListener::bind(&config.client.listen).await?;
    info!(listen = %config.client.listen, remote = %config.client.remote, "trojan client started");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
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
