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
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{Instrument, debug, info, info_span, warn};

use trojan_metrics::{ConnectionMetrics, NodeStats, RelayCounters, record_auth_failure};

use crate::config::{RelayNodeConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, ConnectResponse};
use trojan_transport::plain::{PlainTransportAcceptor, PlainTransportConnector};
use trojan_transport::tls::{TlsTransportAcceptor, TlsTransportConnector};
use trojan_transport::ws::{WsTransportAcceptor, WsTransportConnector};
use trojan_transport::{TransportAcceptor, TransportConnector};

use trojan_core::io::{PrefixedStream, relay_bidirectional};

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

    let mut sessions = JoinSet::new();
    let shutdown = shutdown.child_token();
    let _cancel = shutdown.clone().drop_guard();
    let mut result = loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("relay node shutting down");
                break Ok(());
            }
            Some(completed) = sessions.join_next() => {
                if let Err(error) = completed {
                    break Err(error.into());
                }
            }
            accept_result = listener.accept() => {
                let (tcp_stream, peer_addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error.into()),
                };
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
                let connection = ConnectionMetrics::start();

                let shutdown = shutdown.clone();
                sessions.spawn(
                    async move {
                        let _active = active;
                        let _connection = connection;

                        tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => {},
                            result = session.handle(tcp_stream) => {
                                if let Err(e) = result {
                                    debug!(error = %e, "relay connection error");
                                }
                            }
                        }
                    }
                    .instrument(info_span!("relay", peer = %peer_addr)),
                );
            }
        }
    };
    shutdown.cancel();
    sessions.abort_all();
    while let Some(completed) = sessions.join_next().await {
        if let Err(error) = completed
            && !error.is_cancelled()
            && result.is_ok()
        {
            result = Err(error.into());
        }
    }
    result
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
            if hs.metadata.ack {
                handshake::write_response(&mut inbound, ConnectResponse::AuthFailed).await?;
            }
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

        // 5. Connect to target and relay. Only the connector differs per
        // transport; everything after the dial is the same stream of bytes.
        let hop = Hop {
            target: &hs.target,
            acknowledge: hs.metadata.ack,
            residue,
            timeouts: &self.timeouts,
            counters: &self.counters,
        };
        match outbound_transport {
            TransportType::Tls => {
                let connector = self.connectors.tls.with_sni(outbound_sni.to_string());
                dial_and_relay(inbound, &connector, hop).await
            }
            TransportType::Plain => dial_and_relay(inbound, &self.connectors.plain, hop).await,
            TransportType::Ws => dial_and_relay(inbound, &self.connectors.ws, hop).await,
        }
    }
}

/// The next hop of one relayed connection, whatever transport reaches it.
struct Hop<'a> {
    /// `host:port` to dial.
    target: &'a str,
    /// Legacy upstreams must receive payload bytes without a response prefix.
    acknowledge: bool,
    /// Bytes already read past the handshake, owed to the target verbatim.
    residue: Vec<u8>,
    timeouts: &'a TimeoutConfig,
    counters: &'a RelayCounters,
}

/// Dial the hop, hand it the residue, then relay `inbound` through it.
async fn dial_and_relay<I, C>(mut inbound: I, connector: &C, hop: Hop<'_>) -> Result<(), RelayError>
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: TransportConnector,
{
    let result = tokio::time::timeout(
        Duration::from_secs(hop.timeouts.connect_timeout_secs),
        connector.connect(hop.target),
    )
    .await
    .map_err(|_| RelayError::ConnectTimeout(hop.target.to_owned()))
    .and_then(|result| result.map_err(RelayError::from));

    if hop.acknowledge {
        let response = if result.is_ok() {
            ConnectResponse::Connected
        } else {
            ConnectResponse::ConnectFailed
        };
        handshake::write_response(&mut inbound, response).await?;
    }
    let outbound = result?;
    // Buffered payload must use the same byte accounting as later reads.
    let inbound = PrefixedStream::new(hop.residue.into(), inbound);

    relay_bidirectional(
        inbound,
        outbound,
        Duration::from_secs(hop.timeouts.idle_timeout_secs),
        hop.timeouts.relay_buffer_size,
        hop.counters,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn handshake_residue_counts_as_forwarded_node_traffic() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let (mut client, inbound) = tokio::io::duplex(64);
            let stats = NodeStats::new();
            let counters = RelayCounters::global().with_node_stats(stats.clone());
            let task = tokio::spawn(async move {
                dial_and_relay(
                    inbound,
                    &PlainTransportConnector::new(),
                    Hop {
                        target: &address,
                        acknowledge: false,
                        residue: b"buffered-".to_vec(),
                        timeouts: &TimeoutConfig::default(),
                        counters: &counters,
                    },
                )
                .await
            });
            client.write_all(b"payload").await.unwrap();
            client.shutdown().await.unwrap();
            let (mut target, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            target.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"buffered-payload");
            target.write_all(b"reply").await.unwrap();
            target.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"reply");
            task.await.unwrap().unwrap();
            assert_eq!(stats.snapshot().bytes_in, 16);
            assert_eq!(stats.snapshot().bytes_out, 5);
        })
        .await
        .expect("buffered payload relay did not complete");
    }
}
