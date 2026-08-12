//! Relay node (B) implementation.
//!
//! The relay node:
//! 1. Listens on a TCP port with pluggable transport (TLS or plain)
//! 2. Reads a relay handshake from the upstream (password + target + metadata)
//! 3. Verifies the relay password
//! 4. Connects to the target via the transport specified in handshake metadata
//!    (falls back to the node's default outbound transport if not specified)
//! 5. Bidirectionally relays data

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{Instrument, debug, info, info_span, warn};

use trojan_metrics::{
    NodeStats, RelayCounters, record_auth_failure, record_connection_accepted,
    record_connection_closed,
};

use crate::config::{RelayNodeConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake;
use crate::transport::TransportAcceptor;
use crate::transport::plain::{PlainTransportAcceptor, PlainTransportConnector};
use crate::transport::tls::{TlsTransportAcceptor, TlsTransportConnector};
use crate::transport::ws::{WsTransportAcceptor, WsTransportConnector};

use trojan_core::io::relay_bidirectional;

/// Outbound connectors for all transport types, used by the relay node.
#[derive(Clone)]
struct OutboundConnectors {
    tls: TlsTransportConnector,
    plain: PlainTransportConnector,
    ws: WsTransportConnector,
    /// Default transport when handshake metadata doesn't specify one.
    default_transport: TransportType,
    /// Default SNI when handshake metadata doesn't specify one.
    default_sni: String,
}

/// Run the relay node server.
pub async fn run(
    config: RelayNodeConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    run_with_stats(config, NodeStats::new(), shutdown).await
}

/// Run the relay node server, accumulating its totals into `stats`.
///
/// Same as [`run`], for callers that report node traffic themselves — the
/// panel agent reads these totals for its heartbeats, which have no scraper to
/// diff Prometheus samples for them.
pub async fn run_with_stats(
    config: RelayNodeConfig,
    stats: Arc<NodeStats>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    crate::metrics::start_exporter(&config.metrics);

    let relay_cfg = &config.relay;

    // Build DNS resolver from config
    let resolver = trojan_dns::DnsResolver::new(&relay_cfg.dns)
        .map_err(|e| RelayError::Config(format!("dns resolver: {e}")))?;
    info!(dns = ?relay_cfg.dns.strategy, "dns resolver initialized");

    let connectors = OutboundConnectors {
        tls: TlsTransportConnector::new_insecure_with_resolver(
            relay_cfg.outbound.sni.clone(),
            resolver.clone(),
        ),
        plain: PlainTransportConnector::with_resolver(resolver.clone()),
        ws: WsTransportConnector::with_resolver(resolver),
        default_transport: relay_cfg.transport.clone(),
        default_sni: relay_cfg.outbound.sni.clone(),
    };

    match relay_cfg.transport {
        TransportType::Tls => {
            let transport_tls = relay_cfg.tls.as_ref().map(|c| c.to_transport_config());
            let acceptor = TlsTransportAcceptor::new(transport_tls.as_ref())?;
            run_inner(relay_cfg, acceptor, connectors, stats, shutdown).await
        }
        TransportType::Plain => {
            let acceptor = PlainTransportAcceptor;
            run_inner(relay_cfg, acceptor, connectors, stats, shutdown).await
        }
        TransportType::Ws => {
            let acceptor = WsTransportAcceptor;
            run_inner(relay_cfg, acceptor, connectors, stats, shutdown).await
        }
    }
}

async fn run_inner<A>(
    relay_cfg: &crate::config::RelayListenerConfig,
    acceptor: A,
    connectors: OutboundConnectors,
    stats: Arc<NodeStats>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError>
where
    A: TransportAcceptor,
{
    let listener = TcpListener::bind(relay_cfg.listen).await?;
    info!(listen = %relay_cfg.listen, transport = ?relay_cfg.transport, "relay node started");

    // One allocation for the node's lifetime instead of one per connection.
    let password_hash: Arc<str> = handshake::hash_password(&relay_cfg.auth.password).into();
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
                let _ = tcp_stream.set_nodelay(true);

                let session = RelaySession {
                    acceptor: acceptor.clone(),
                    connectors: connectors.clone(),
                    password_hash: password_hash.clone(),
                    timeouts: timeouts.clone(),
                    counters: RelayCounters::global().with_node_stats(stats.clone()),
                };
                // Taken here rather than inside the task so the node's active
                // count follows the accept, not the scheduler.
                let active = stats.connection_started();

                tokio::spawn(
                    async move {
                        let _active = active;
                        record_connection_accepted();
                        let started = Instant::now();

                        if let Err(e) = session.handle(tcp_stream).await {
                            debug!(error = %e, "relay connection error");
                        }

                        record_connection_closed(started.elapsed().as_secs_f64());
                    }
                    .instrument(info_span!("relay", peer = %peer_addr)),
                );
            }
        }
    }
}

/// One accepted upstream connection: authenticate, dial the next hop, relay.
struct RelaySession<A> {
    acceptor: A,
    connectors: OutboundConnectors,
    /// SHA-224 hex of the node's relay password, hashed once at startup.
    password_hash: Arc<str>,
    timeouts: TimeoutConfig,
    /// Byte counters for this session: global and node-wide.
    counters: RelayCounters,
}

impl<A> RelaySession<A>
where
    A: TransportAcceptor,
{
    async fn handle(self, tcp_stream: tokio::net::TcpStream) -> Result<(), RelayError> {
        let handshake_timeout = Duration::from_secs(self.timeouts.handshake_timeout_secs);
        let connect_timeout = Duration::from_secs(self.timeouts.connect_timeout_secs);
        let idle_timeout = Duration::from_secs(self.timeouts.idle_timeout_secs);
        let relay_buffer_size = self.timeouts.relay_buffer_size;

        // 1. Accept inbound transport
        let mut inbound = tokio::time::timeout(handshake_timeout, self.acceptor.accept(tcp_stream))
            .await
            .map_err(|_| RelayError::Handshake("transport accept timeout".into()))??;

        // 2. Read relay handshake (now includes metadata).
        // `residue` is any bytes read past the handshake's second CRLF — they
        // belong to whatever the upstream sent next (the next hop's handshake or
        // the client's payload) and must be forwarded to outbound verbatim.
        let (hs, residue) =
            tokio::time::timeout(handshake_timeout, handshake::read_handshake(&mut inbound))
                .await
                .map_err(|_| RelayError::Handshake("relay handshake timeout".into()))??;

        // 3. Verify password
        if !handshake::verify_hash_precomputed(&hs, &self.password_hash) {
            warn!("relay auth failed");
            record_auth_failure();
            return Err(RelayError::AuthFailed);
        }

        debug!(target = %hs.target, residue_len = residue.len(), "relay handshake accepted");

        // 4. Determine outbound transport from handshake metadata or node defaults
        let outbound_transport = hs
            .metadata
            .transport
            .as_ref()
            .unwrap_or(&self.connectors.default_transport);
        let outbound_sni = hs
            .metadata
            .sni
            .as_deref()
            .unwrap_or(&self.connectors.default_sni);

        debug!(
            transport = ?outbound_transport,
            sni = %outbound_sni,
            "outbound transport resolved"
        );

        // 5. Connect to target and relay
        match outbound_transport {
            TransportType::Tls => {
                let connector = self.connectors.tls.with_sni(outbound_sni.to_string());
                let mut outbound = tokio::time::timeout(
                    connect_timeout,
                    crate::transport::TransportConnector::connect(&connector, &hs.target),
                )
                .await
                .map_err(|_| RelayError::ConnectTimeout(hs.target.clone()))??;

                if !residue.is_empty() {
                    outbound.write_all(&residue).await?;
                }

                relay_bidirectional(
                    inbound,
                    outbound,
                    idle_timeout,
                    relay_buffer_size,
                    &self.counters,
                )
                .await?;
            }
            TransportType::Plain => {
                let mut outbound = tokio::time::timeout(
                    connect_timeout,
                    crate::transport::TransportConnector::connect(
                        &self.connectors.plain,
                        &hs.target,
                    ),
                )
                .await
                .map_err(|_| RelayError::ConnectTimeout(hs.target.clone()))??;

                if !residue.is_empty() {
                    outbound.write_all(&residue).await?;
                }

                relay_bidirectional(
                    inbound,
                    outbound,
                    idle_timeout,
                    relay_buffer_size,
                    &self.counters,
                )
                .await?;
            }
            TransportType::Ws => {
                let mut outbound = tokio::time::timeout(
                    connect_timeout,
                    crate::transport::TransportConnector::connect(&self.connectors.ws, &hs.target),
                )
                .await
                .map_err(|_| RelayError::ConnectTimeout(hs.target.clone()))??;

                if !residue.is_empty() {
                    outbound.write_all(&residue).await?;
                }

                relay_bidirectional(
                    inbound,
                    outbound,
                    idle_timeout,
                    relay_buffer_size,
                    &self.counters,
                )
                .await?;
            }
        }

        Ok(())
    }
}
