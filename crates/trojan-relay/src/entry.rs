//! Entry node (A) implementation.
//!
//! The entry node:
//! 1. Parses config to build named chains and rules
//! 2. Listens on multiple TCP ports (one per rule)
//! 3. For each incoming connection, resolves the rule by listen address
//! 4. Builds a tunnel through the chain nodes to the destination
//! 5. Bidirectionally relays client traffic through the tunnel
//!
//! Per-hop transport control: the entry sends handshake metadata to each
//! relay node specifying what transport/sni to use for its outbound connection.
//! This allows mixed-transport chains (e.g. A→B1(TLS)→B2(Plain)→C(Plain TCP)).
//! The last hop to the trojan-server is always plain TCP — the trojan client
//! performs its own end-to-end TLS handshake through the relay tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, error, info, info_span};

use trojan_lb::{ConnectionGuard, LoadBalancer};
use trojan_metrics::{
    NodeStats, RelayCounters, record_connection_accepted, record_connection_closed,
};

use crate::config::{ChainConfig, EntryConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, ConnectResponse, HandshakeMetadata};
use crate::router::{CompiledChain, Router};
use trojan_transport::plain::PlainTransportConnector;
use trojan_transport::tls::TlsTransportConnector;
use trojan_transport::ws::WsTransportConnector;
use trojan_transport::{TransportConnector, TransportStream};

use trojan_core::io::relay_bidirectional;

#[cfg(test)]
mod tests;

/// Run the entry node server.
pub async fn run(
    config: EntryConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    run_with_stats(config, NodeStats::new(), shutdown).await
}

/// Run the entry node server, accumulating its totals into `stats`.
///
/// Same as [`run`], for callers that report node traffic themselves — the
/// panel agent reads these totals for its heartbeats, which have no scraper to
/// diff Prometheus samples for them.
pub async fn run_with_stats(
    config: EntryConfig,
    stats: Arc<NodeStats>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    crate::metrics::start_exporter(&config.metrics);

    let router = Arc::new(Router::new(&config)?);

    // Build DNS resolver from config
    let resolver = trojan_dns::DnsResolver::new(&config.dns)
        .map_err(|e| RelayError::Config(format!("dns resolver: {e}")))?;
    info!(dns = ?config.dns.strategy, "dns resolver initialized");

    let shared = SharedState {
        router: router.clone(),
        connectors: Connectors {
            tls: TlsTransportConnector::new_insecure_with_resolver(
                "crates.io".to_string(),
                resolver.clone(),
            ),
            plain: PlainTransportConnector::with_resolver(resolver.clone()),
            ws: WsTransportConnector::with_resolver(resolver),
        },
        timeouts: config.timeouts.clone(),
        stats,
    };

    // Spawn a listener task for each rule
    let mut handles = Vec::new();

    for rule in router.rules() {
        let listener = TcpListener::bind(rule.listen).await?;
        info!(
            name = %rule.name,
            listen = %rule.listen,
            chain = %rule.chain,
            dest = ?rule.dest,
            strategy = ?rule.strategy,
            "entry rule started"
        );

        let rule_listener = RuleListener {
            listener,
            addr: rule.listen,
            rule: rule.name.clone(),
            shared: shared.clone(),
        };
        let shutdown = shutdown.clone();

        handles.push(tokio::spawn(rule_listener.serve(shutdown)));
    }

    // Wait for all listener tasks
    for handle in handles {
        if let Err(e) = handle.await {
            error!(error = %e, "listener task panicked");
        }
    }

    Ok(())
}

/// State every listener on this node shares.
#[derive(Clone)]
struct SharedState {
    router: Arc<Router>,
    connectors: Connectors,
    timeouts: TimeoutConfig,
    stats: Arc<NodeStats>,
}

/// One rule's accept loop.
struct RuleListener {
    listener: TcpListener,
    /// The address `listener` is bound to, used to resolve the rule per accept.
    addr: SocketAddr,
    /// Rule name, for spans and the per-rule byte counters.
    rule: String,
    shared: SharedState,
}

impl RuleListener {
    /// Accept until the shutdown token fires.
    async fn serve(self, shutdown: tokio_util::sync::CancellationToken) -> Result<(), RelayError> {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    info!(rule = %self.rule, "entry listener shutting down");
                    return Ok(());
                }
                accept_result = self.listener.accept() => {
                    let (tcp_stream, peer_addr) = accept_result?;
                    let _ = tcp_stream.set_nodelay(true);

                    let route = match self.shared.router.resolve(&self.addr) {
                        Some(r) => r,
                        None => {
                            error!(listen = %self.addr, "no rule matched");
                            continue;
                        }
                    };

                    let session = EntrySession {
                        chain: route.chain.clone(),
                        lb: route.lb.clone(),
                        peer: peer_addr,
                        announce_client: route.rule.proxy_protocol,
                        connectors: self.shared.connectors.clone(),
                        timeouts: self.shared.timeouts.clone(),
                        counters: RelayCounters::with_rule(&self.rule)
                            .with_node_stats(self.shared.stats.clone()),
                    };
                    let rule_name = route.rule.name.clone();
                    // Taken here rather than inside the task so the node's
                    // active count follows the accept, not the scheduler.
                    let active = self.shared.stats.connection_started();

                    tokio::spawn(
                        async move {
                            let _active = active;
                            record_connection_accepted();
                            let started = Instant::now();

                            if let Err(e) = session.handle(tcp_stream).await {
                                debug!(error = %e, "entry connection error");
                            }

                            record_connection_closed(started.elapsed().as_secs_f64());
                        }
                        .instrument(info_span!("entry", rule = %rule_name, peer = %peer_addr)),
                    );
                }
            }
        }
    }
}

/// One accepted client connection, after its rule resolved.
struct EntrySession {
    chain: Arc<CompiledChain>,
    lb: Arc<LoadBalancer>,
    peer: SocketAddr,
    /// Whether to tell the destination who the client is and which hops
    /// carried the connection (`proxy_protocol` on the rule).
    announce_client: bool,
    connectors: Connectors,
    timeouts: TimeoutConfig,
    /// Byte counters for this session: global, per-rule, and node-wide.
    counters: RelayCounters,
}

impl EntrySession {
    /// Build a tunnel through the chain, then relay the client through it.
    async fn handle(self, client_stream: TcpStream) -> Result<(), RelayError> {
        let nodes = &self.chain.config().nodes;

        // The destination only ever sees the last hop, so the header has to
        // carry both ends of the original connection. `local_addr` is what the
        // client actually reached, which a wildcard listener does not tell us.
        let preamble = if self.announce_client {
            let local = client_stream.local_addr()?;
            Some(
                trojan_core::proxy_protocol::ProxyHeader::new(self.peer, local)
                    .with_chain(self.chain.path().clone())
                    .encode()?,
            )
        } else {
            None
        };

        // Determine the first hop's transport and SNI.
        // - Empty chain (direct): plain TCP to dest (client does its own TLS to trojan-server)
        // - Non-empty chain: use nodes[0].transport/sni to connect to first relay
        let first_transport = if nodes.is_empty() {
            &TransportType::Plain
        } else {
            &nodes[0].transport
        };
        let first_sni = if nodes.is_empty() {
            ""
        } else {
            nodes[0].sni.as_str()
        };

        match first_transport {
            TransportType::Tls => {
                let tls_connector = self.connectors.tls.with_sni(first_sni.to_string());
                self.connect_and_relay(client_stream, &tls_connector, preamble.as_deref())
                    .await
            }
            TransportType::Plain => {
                self.connect_and_relay(client_stream, &self.connectors.plain, preamble.as_deref())
                    .await
            }
            TransportType::Ws => {
                self.connect_and_relay(client_stream, &self.connectors.ws, preamble.as_deref())
                    .await
            }
        }
    }

    /// Retry only confirmed destination failures, before consuming client bytes.
    async fn connect_tunnel<C>(
        &self,
        connector: &C,
    ) -> Result<(C::Stream, Option<ConnectionGuard>), RelayError>
    where
        C: TransportConnector,
    {
        let mut attempted = Vec::new();
        loop {
            let selection = self.lb.select_excluding(self.peer.ip(), &attempted)?;
            let dest = selection.addr;
            debug!(%dest, "selected destination");

            match build_tunnel(&self.chain, &dest, connector, &self.timeouts).await {
                Ok(tunnel) => return Ok((tunnel, selection.guard)),
                Err(TunnelError::Destination(err)) if self.lb.is_failover() => {
                    debug!(%dest, error = %err, "marking backend unhealthy");
                    self.lb.mark_unhealthy(&dest);
                    attempted.push(dest);
                    if attempted.len() == self.lb.backend_count() {
                        return Err(err);
                    }
                }
                Err(TunnelError::Destination(err) | TunnelError::Relay(err)) => return Err(err),
            }
        }
    }

    /// Forward payload only after every relay has confirmed its target connection.
    async fn connect_and_relay<C>(
        &self,
        client_stream: TcpStream,
        connector: &C,
        preamble: Option<&[u8]>,
    ) -> Result<(), RelayError>
    where
        C: TransportConnector,
    {
        let (mut tunnel, _conn_guard) = self.connect_tunnel(connector).await?;
        // Once payload forwarding starts, retries could duplicate client data.
        if let Some(preamble) = preamble {
            tunnel.write_all(preamble).await?;
        }
        relay_bidirectional(
            client_stream,
            tunnel,
            Duration::from_secs(self.timeouts.idle_timeout_secs),
            self.timeouts.relay_buffer_size,
            &self.counters,
        )
        .await?;
        Ok(())
    }
}

/// The transports an entry node can dial its first hop over.
///
/// Which one is used depends on `nodes[0].transport`, so all three are built
/// once at startup and cloned per listener and per connection.
#[derive(Clone)]
struct Connectors {
    /// SNI is set per-connection via `with_sni`, so this stays a base config.
    tls: TlsTransportConnector,
    plain: PlainTransportConnector,
    ws: WsTransportConnector,
}

/// Only a direct dial failure or an explicit final-hop rejection proves an exit failed.
#[derive(Debug)]
enum TunnelError {
    Destination(RelayError),
    Relay(RelayError),
}

/// Build a tunnel through the chain to the destination.
///
/// For an empty chain (direct), just connect to dest via the connector.
/// For a chain with nodes [B1, B2, ...], connect to B1 and send relay
/// handshakes through the tunnel to build nested connections.
///
/// Each handshake includes metadata telling the relay node what transport
/// and SNI to use for its outbound connection.
async fn build_tunnel<C>(
    chain: &CompiledChain,
    dest: &str,
    connector: &C,
    timeouts: &TimeoutConfig,
) -> Result<C::Stream, TunnelError>
where
    C: TransportConnector,
    C::Stream: TransportStream,
{
    let config = chain.config();
    // One hash per node, guaranteed by `CompiledChain`'s construction.
    let prehashed = chain.password_hashes();

    let connect_timeout = Duration::from_secs(timeouts.connect_timeout_secs);
    let first_addr = config.nodes.first().map_or(dest, |node| node.addr.as_str());
    let mut stream = tokio::time::timeout(connect_timeout, connector.connect(first_addr))
        .await
        .map_err(|_| RelayError::ConnectTimeout(first_addr.to_owned()))
        .and_then(|result| result.map_err(RelayError::from))
        .map_err(|err| {
            if config.nodes.is_empty() {
                TunnelError::Destination(err)
            } else {
                TunnelError::Relay(err)
            }
        })?;

    // Allow the relay's dial timeout to produce a response before our read expires.
    let response_timeout = connect_timeout + Duration::from_secs(timeouts.handshake_timeout_secs);
    for (i, hash) in prehashed.iter().enumerate() {
        let (target, meta) = next_hop_info(config, dest, i);
        let response = tokio::time::timeout(response_timeout, async {
            handshake::write_handshake_prehashed(&mut stream, hash, &target, &meta).await?;
            handshake::read_response(&mut stream).await
        })
        .await
        .map_err(|_| {
            TunnelError::Relay(RelayError::Handshake(format!(
                "connection response timeout from {}",
                config.nodes[i].addr
            )))
        })?
        .map_err(TunnelError::Relay)?;

        match response {
            ConnectResponse::Connected => {}
            ConnectResponse::ConnectFailed => {
                let err = RelayError::RemoteConnectFailed(target);
                return Err(if i + 1 == config.nodes.len() {
                    TunnelError::Destination(err)
                } else {
                    TunnelError::Relay(err)
                });
            }
            ConnectResponse::AuthFailed => return Err(TunnelError::Relay(RelayError::AuthFailed)),
        }
    }

    Ok(stream)
}

/// Compute the target address and metadata for the handshake sent to `nodes[i]`.
///
/// - target = where nodes[i] should connect to (next node or dest)
/// - metadata = what transport/sni nodes[i] should use for that outbound connection
fn next_hop_info(chain: &ChainConfig, dest: &str, i: usize) -> (String, HandshakeMetadata) {
    if i + 1 < chain.nodes.len() {
        // Next hop is another relay node
        let next = &chain.nodes[i + 1];
        let meta = HandshakeMetadata {
            transport: Some(next.transport.clone()),
            sni: Some(next.sni.clone()),
            ack: true,
        };
        (next.addr.clone(), meta)
    } else {
        // Next hop is the final destination (trojan-server).
        // Use plain TCP — the trojan client performs its own TLS handshake
        // end-to-end with the trojan-server through the relay tunnel.
        let meta = HandshakeMetadata {
            transport: Some(TransportType::Plain),
            sni: None,
            ack: true,
        };
        (dest.to_string(), meta)
    }
}
