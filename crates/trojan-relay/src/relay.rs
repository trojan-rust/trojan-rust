//! Relay node (B) implementation.
//!
//! The relay node:
//! 1. Listens on a TCP port with pluggable transport (TLS or plain)
//! 2. Reads a relay handshake from the upstream (password + target + metadata)
//! 3. Verifies the relay password
//! 4. Connects to the target via the transport specified in handshake metadata
//!    (falls back to the node's default outbound transport if not specified)
//! 5. Bidirectionally relays data

use std::time::Duration;

use tokio::net::TcpListener;
use tracing::{debug, info, warn, Instrument, info_span};

use crate::config::{RelayNodeConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, verify_hash};
use crate::transport::TransportAcceptor;
use crate::transport::plain::{PlainTransportAcceptor, PlainTransportConnector};
use crate::transport::tls::{TlsTransportAcceptor, TlsTransportConnector};

use trojan_core::io::{NoOpMetrics, relay_bidirectional};

/// Outbound connectors for both transport types, used by the relay node.
#[derive(Clone)]
struct OutboundConnectors {
    tls: TlsTransportConnector,
    plain: PlainTransportConnector,
    /// Default transport when handshake metadata doesn't specify one.
    default_transport: TransportType,
    /// Default SNI when handshake metadata doesn't specify one.
    default_sni: String,
}

/// Run the relay node server.
pub async fn run(config: RelayNodeConfig, shutdown: tokio_util::sync::CancellationToken) -> Result<(), RelayError> {
    let relay_cfg = &config.relay;

    let connectors = OutboundConnectors {
        tls: TlsTransportConnector::new_insecure(relay_cfg.outbound.sni.clone()),
        plain: PlainTransportConnector,
        default_transport: relay_cfg.transport.clone(),
        default_sni: relay_cfg.outbound.sni.clone(),
    };

    match relay_cfg.transport {
        TransportType::Tls => {
            let acceptor = TlsTransportAcceptor::new(relay_cfg.tls.as_ref())?;
            run_inner(relay_cfg, acceptor, connectors, shutdown).await
        }
        TransportType::Plain => {
            let acceptor = PlainTransportAcceptor;
            run_inner(relay_cfg, acceptor, connectors, shutdown).await
        }
    }
}

async fn run_inner<A>(
    relay_cfg: &crate::config::RelayListenerConfig,
    acceptor: A,
    connectors: OutboundConnectors,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError>
where
    A: TransportAcceptor,
{
    let listener = TcpListener::bind(relay_cfg.listen).await?;
    info!(listen = %relay_cfg.listen, transport = ?relay_cfg.transport, "relay node started");

    let password = relay_cfg.auth.password.clone();
    let timeouts = relay_cfg.timeouts.clone();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("relay node shutting down");
                return Ok(());
            }
            accept_result = listener.accept() => {
                let (tcp_stream, peer_addr) = accept_result?;
                let acceptor = acceptor.clone();
                let connectors = connectors.clone();
                let password = password.clone();
                let timeouts = timeouts.clone();

                tokio::spawn(
                    async move {
                        if let Err(e) = handle_relay_connection(
                            tcp_stream,
                            acceptor,
                            connectors,
                            &password,
                            &timeouts,
                        ).await {
                            debug!(error = %e, "relay connection error");
                        }
                    }
                    .instrument(info_span!("relay", peer = %peer_addr)),
                );
            }
        }
    }
}

async fn handle_relay_connection<A>(
    tcp_stream: tokio::net::TcpStream,
    acceptor: A,
    connectors: OutboundConnectors,
    password: &str,
    timeouts: &TimeoutConfig,
) -> Result<(), RelayError>
where
    A: TransportAcceptor,
{
    let handshake_timeout = Duration::from_secs(timeouts.handshake_timeout_secs);
    let connect_timeout = Duration::from_secs(timeouts.connect_timeout_secs);
    let idle_timeout = Duration::from_secs(timeouts.idle_timeout_secs);

    // 1. Accept inbound transport
    let mut inbound = tokio::time::timeout(handshake_timeout, acceptor.accept(tcp_stream))
        .await
        .map_err(|_| RelayError::Handshake("transport accept timeout".into()))??;

    // 2. Read relay handshake (now includes metadata)
    let hs = tokio::time::timeout(handshake_timeout, handshake::read_handshake(&mut inbound))
        .await
        .map_err(|_| RelayError::Handshake("relay handshake timeout".into()))??;

    // 3. Verify password
    if !verify_hash(&hs, password) {
        warn!("relay auth failed");
        return Err(RelayError::AuthFailed);
    }

    debug!(target = %hs.target, "relay handshake accepted");

    // 4. Determine outbound transport from handshake metadata or node defaults
    let outbound_transport = hs.metadata.transport
        .as_ref()
        .unwrap_or(&connectors.default_transport);
    let outbound_sni = hs.metadata.sni
        .as_deref()
        .unwrap_or(&connectors.default_sni);

    debug!(
        transport = ?outbound_transport,
        sni = %outbound_sni,
        "outbound transport resolved"
    );

    // 5. Connect to target and relay
    match outbound_transport {
        TransportType::Tls => {
            let connector = connectors.tls.with_sni(outbound_sni.to_string());
            let outbound = tokio::time::timeout(
                connect_timeout,
                crate::transport::TransportConnector::connect(&connector, &hs.target),
            )
            .await
            .map_err(|_| RelayError::ConnectTimeout(hs.target.clone()))??;

            relay_bidirectional(inbound, outbound, idle_timeout, 8192, &NoOpMetrics).await?;
        }
        TransportType::Plain => {
            let outbound = tokio::time::timeout(
                connect_timeout,
                crate::transport::TransportConnector::connect(&connectors.plain, &hs.target),
            )
            .await
            .map_err(|_| RelayError::ConnectTimeout(hs.target.clone()))??;

            relay_bidirectional(inbound, outbound, idle_timeout, 8192, &NoOpMetrics).await?;
        }
    }

    Ok(())
}
