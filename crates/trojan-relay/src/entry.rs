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
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{Instrument, debug, error, info, info_span};

use trojan_lb::NodeStateStore;
use trojan_metrics::{ConnectionMetrics, NodeStats, RelayCounters, RouteFailure, RouteMetrics};

use crate::config::{ChainConfig, EntryConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, ConnectResponse, HandshakeMetadata};
use crate::router::{CompiledChain, RoutePool, RouteSelection, Router};
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
    let router = Router::new(&config)?;
    run_with_router(config, stats, router, shutdown).await
}

/// Run an entry with live node availability and quota updates.
///
/// Set `config.node_id` to the authenticated panel identifier to enforce this entry's quota.
/// Set remote hop identifiers to their panel identifiers to enforce remote quotas.
/// Remote hops without identifiers retain static availability.
pub async fn run_with_node_states(
    config: EntryConfig,
    stats: Arc<NodeStats>,
    node_states: Arc<NodeStateStore>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    let router = Router::with_node_states(&config, node_states)?;
    run_with_router(config, stats, router, shutdown).await
}

async fn run_with_router(
    config: EntryConfig,
    stats: Arc<NodeStats>,
    router: Router,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    crate::metrics::start_exporter(&config.metrics);

    let router = Arc::new(router);

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

    // Bind every socket before starting tasks so startup failure cannot leave a listener running.
    let mut listeners = Vec::new();

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

        listeners.push(RuleListener {
            listener,
            addr: rule.listen,
            rule: rule.name.clone(),
            metrics: Arc::new(RouteMetrics::new(&rule.name)),
            shared: shared.clone(),
        });
    }

    let mut handles = JoinSet::new();
    let shutdown = shutdown.child_token();
    let _cancel = shutdown.clone().drop_guard();
    for listener in listeners {
        handles.spawn(listener.serve(shutdown.clone()));
    }
    let mut result = Ok(());
    while let Some(completed) = handles.join_next().await {
        let completed = completed
            .map_err(RelayError::from)
            .and_then(|result| result);
        if let Err(error) = completed {
            shutdown.cancel();
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    result
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
    metrics: Arc<RouteMetrics>,
    shared: SharedState,
}

impl RuleListener {
    /// Accept until the shutdown token fires.
    async fn serve(self, shutdown: tokio_util::sync::CancellationToken) -> Result<(), RelayError> {
        let mut sessions = JoinSet::new();
        let shutdown = shutdown.child_token();
        let _cancel = shutdown.clone().drop_guard();
        let mut result = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    info!(rule = %self.rule, "entry listener shutting down");
                    break Ok(());
                }
                Some(completed) = sessions.join_next() => {
                    if let Err(error) = completed {
                        break Err(error.into());
                    }
                }
                accept_result = self.listener.accept() => {
                    let (tcp_stream, peer_addr) = match accept_result {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(error.into()),
                    };
                    let _ = tcp_stream.set_nodelay(true);

                    let route = match self.shared.router.resolve(&self.addr) {
                        Some(r) => r,
                        None => {
                            error!(listen = %self.addr, "no rule matched");
                            continue;
                        }
                    };

                    let session = EntrySession {
                        routes: route.pool.clone(),
                        peer: peer_addr,
                        announce_client: route.rule.proxy_protocol,
                        connectors: self.shared.connectors.clone(),
                        timeouts: self.shared.timeouts.clone(),
                        counters: RelayCounters::with_rule(&self.rule)
                            .with_node_stats(self.shared.stats.clone()),
                        metrics: self.metrics.clone(),
                    };
                    let rule_name = route.rule.name.clone();
                    // Taken here rather than inside the task so the node's
                    // active count follows the accept, not the scheduler.
                    let active = self.shared.stats.connection_started();
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
                                        debug!(error = %e, "entry connection error");
                                    }
                                }
                            }
                        }
                        .instrument(info_span!("entry", rule = %rule_name, peer = %peer_addr)),
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
}

/// One accepted client connection, after its rule resolved.
struct EntrySession {
    routes: Arc<RoutePool>,
    peer: SocketAddr,
    /// Whether to tell the destination who the client is and which hops
    /// carried the connection (`proxy_protocol` on the rule).
    announce_client: bool,
    connectors: Connectors,
    timeouts: TimeoutConfig,
    /// Byte counters for this session: global, per-rule, and node-wide.
    counters: RelayCounters,
    metrics: Arc<RouteMetrics>,
}

impl EntrySession {
    /// Build a tunnel through the chain, then relay the client through it.
    async fn handle(self, client_stream: TcpStream) -> Result<(), RelayError> {
        let (tunnel, route) = self.connect_tunnel().await?;

        // The destination only ever sees the last hop, so the header has to
        // carry both ends of the original connection. `local_addr` is what the
        // client actually reached, which a wildcard listener does not tell us.
        let preamble = if self.announce_client {
            let local = client_stream.local_addr()?;
            Some(
                trojan_core::proxy_protocol::ProxyHeader::new(self.peer, local)
                    .with_chain(route.candidate.chain.path().clone())
                    .encode()?,
            )
        } else {
            None
        };

        // The selected guard must survive until the complete transfer ends.
        let _guard = route.guard;
        match tunnel {
            Tunnel::Plain(stream) => {
                self.forward(client_stream, stream, preamble.as_deref())
                    .await
            }
            Tunnel::Tls(stream) => {
                self.forward(client_stream, stream, preamble.as_deref())
                    .await
            }
            Tunnel::Ws(stream) => {
                self.forward(client_stream, stream, preamble.as_deref())
                    .await
            }
        }
    }

    /// Complete every handshake before consuming client bytes.
    async fn connect_tunnel(&self) -> Result<(Tunnel, RouteSelection), RelayError> {
        let mut attempted = Vec::new();
        let mut last_error = None;
        let mut last_failure = None;
        loop {
            let selection = match self.routes.select(self.peer.ip(), &attempted) {
                Ok(selection) => selection,
                Err(err) => {
                    self.metrics.unavailable();
                    return Err(last_error.unwrap_or_else(|| err.into()));
                }
            };
            self.metrics.selected();
            if let Some(failure) = last_failure {
                self.metrics.failover(failure);
            }
            let attempt = self.metrics.setup_started();
            let route = &selection.candidate;
            debug!(dest = %route.dest, "selected route");
            let first = route.chain.config().nodes.first();
            let result = match first.map_or(&TransportType::Plain, |node| &node.transport) {
                TransportType::Plain => build_tunnel(
                    &route.chain,
                    &route.dest,
                    &self.connectors.plain,
                    &self.timeouts,
                )
                .await
                .map(Tunnel::Plain),
                TransportType::Ws => build_tunnel(
                    &route.chain,
                    &route.dest,
                    &self.connectors.ws,
                    &self.timeouts,
                )
                .await
                .map(|stream| Tunnel::Ws(Box::new(stream))),
                TransportType::Tls => {
                    let connector = self
                        .connectors
                        .tls
                        .with_sni(first.expect("TLS route has a first hop").sni.clone());
                    build_tunnel(&route.chain, &route.dest, &connector, &self.timeouts)
                        .await
                        .map(|stream| Tunnel::Tls(Box::new(stream)))
                }
            };
            match result {
                Ok(tunnel) => {
                    attempt.connected();
                    return Ok((tunnel, selection));
                }
                Err(TunnelError::Destination(err)) if self.routes.retry_destinations() => {
                    attempt.failed(RouteFailure::Destination);
                    self.routes.failed(route, true, &mut attempted);
                    last_error = Some(err);
                    last_failure = Some(RouteFailure::Destination);
                }
                Err(TunnelError::Relay(err)) if self.routes.retry_relays() => {
                    attempt.failed(RouteFailure::Relay);
                    self.routes.failed(route, false, &mut attempted);
                    last_error = Some(err);
                    last_failure = Some(RouteFailure::Relay);
                }
                Err(TunnelError::Destination(err)) => {
                    attempt.failed(RouteFailure::Destination);
                    return Err(err);
                }
                Err(TunnelError::Relay(err)) => {
                    attempt.failed(RouteFailure::Relay);
                    return Err(err);
                }
            }
        }
    }

    /// Forward payload only after every relay has confirmed its target connection.
    async fn forward<S: TransportStream>(
        &self,
        client_stream: TcpStream,
        mut tunnel: S,
        preamble: Option<&[u8]>,
    ) -> Result<(), RelayError> {
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

/// Keep concrete transport types so payload forwarding avoids virtual I/O calls.
#[derive(Debug)]
enum Tunnel {
    Plain(<PlainTransportConnector as TransportConnector>::Stream),
    Tls(Box<<TlsTransportConnector as TransportConnector>::Stream>),
    Ws(Box<<WsTransportConnector as TransportConnector>::Stream>),
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
