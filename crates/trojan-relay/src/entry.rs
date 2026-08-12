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

use trojan_lb::LoadBalancer;
use trojan_metrics::{
    NodeStats, RelayCounters, record_connection_accepted, record_connection_closed,
};

use crate::config::{ChainConfig, EntryConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, HandshakeMetadata};
use crate::router::{CompiledChain, Router};
use trojan_transport::plain::PlainTransportConnector;
use trojan_transport::tls::TlsTransportConnector;
use trojan_transport::ws::WsTransportConnector;
use trojan_transport::{TransportConnector, TransportStream};

use trojan_core::io::relay_bidirectional;

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

        // Select destination via load balancer
        let selection = self.lb.select(self.peer.ip())?;
        let selected_dest = selection.addr;
        // Hold the guard alive for the connection lifetime (tracks active connections)
        let _conn_guard = selection.guard;

        debug!(dest = %selected_dest, "selected destination");

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

        // Build tunnel and relay — dispatch on first hop transport type
        let params = TunnelParams {
            connect_timeout: Duration::from_secs(self.timeouts.connect_timeout_secs),
            idle_timeout: Duration::from_secs(self.timeouts.idle_timeout_secs),
            relay_buffer_size: self.timeouts.relay_buffer_size,
            counters: &self.counters,
            preamble: preamble.as_deref(),
        };
        let outcome = match first_transport {
            TransportType::Tls => {
                let tls_connector = self.connectors.tls.with_sni(first_sni.to_string());
                connect_and_relay(
                    client_stream,
                    &self.chain,
                    &selected_dest,
                    &tls_connector,
                    params,
                )
                .await
            }
            TransportType::Plain => {
                connect_and_relay(
                    client_stream,
                    &self.chain,
                    &selected_dest,
                    &self.connectors.plain,
                    params,
                )
                .await
            }
            TransportType::Ws => {
                connect_and_relay(
                    client_stream,
                    &self.chain,
                    &selected_dest,
                    &self.connectors.ws,
                    params,
                )
                .await
            }
        };

        match outcome {
            // The destination was never reached, so take it out of rotation.
            // Errors from the relay itself do not count: the tunnel was up, and a
            // backend that merely saw a stream end is still healthy.
            TunnelOutcome::ConnectFailed(err) => {
                if self.lb.is_failover() {
                    debug!(dest = %selected_dest, error = %err, "marking backend unhealthy");
                    self.lb.mark_unhealthy(&selected_dest);
                }
                Err(err)
            }
            TunnelOutcome::Relayed(result) => result,
        }
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

/// Timeouts, buffer sizing and counters for one tunnel attempt.
#[derive(Clone, Copy)]
struct TunnelParams<'a> {
    connect_timeout: Duration,
    idle_timeout: Duration,
    relay_buffer_size: usize,
    counters: &'a RelayCounters,
    /// Bytes to send through the finished tunnel before the client's own, if
    /// the rule asked the destination to be told about the client.
    preamble: Option<&'a [u8]>,
}

/// Which phase an attempt ended in.
///
/// Failover needs to tell "this destination is unreachable" apart from "the
/// stream through it ended badly"; collapsing both into one `Result` is what
/// previously left dead backends in rotation.
enum TunnelOutcome {
    /// The tunnel was never established.
    ConnectFailed(RelayError),
    /// The tunnel was established; this is what the relay returned.
    Relayed(Result<(), RelayError>),
}

/// Build a tunnel to `dest` and relay `client_stream` through it.
async fn connect_and_relay<C>(
    client_stream: TcpStream,
    chain: &CompiledChain,
    dest: &str,
    connector: &C,
    params: TunnelParams<'_>,
) -> TunnelOutcome
where
    C: TransportConnector,
    C::Stream: TransportStream,
{
    let mut tunnel =
        match tokio::time::timeout(params.connect_timeout, build_tunnel(chain, dest, connector))
            .await
        {
            Err(_) => {
                return TunnelOutcome::ConnectFailed(RelayError::ConnectTimeout(dest.to_string()));
            }
            Ok(Err(err)) => return TunnelOutcome::ConnectFailed(err),
            Ok(Ok(tunnel)) => tunnel,
        };

    // Goes in ahead of anything the client sends, since the destination reads
    // it before the TLS handshake it precedes. A failure here means the tunnel
    // broke on its first write, which is a dead destination, not a dead relay.
    if let Some(preamble) = params.preamble
        && let Err(e) = tunnel.write_all(preamble).await
    {
        return TunnelOutcome::ConnectFailed(RelayError::Io(e));
    }

    debug!("tunnel established, starting relay");
    TunnelOutcome::Relayed(
        relay_bidirectional(
            client_stream,
            tunnel,
            params.idle_timeout,
            params.relay_buffer_size,
            params.counters,
        )
        .await
        .map(|_stats| ())
        .map_err(RelayError::from),
    )
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
) -> Result<C::Stream, RelayError>
where
    C: TransportConnector,
    C::Stream: TransportStream,
{
    let config = chain.config();
    // One hash per node, guaranteed by `CompiledChain`'s construction.
    let prehashed = chain.password_hashes();

    if config.nodes.is_empty() {
        // Direct connection — no relay handshake needed
        return Ok(connector.connect(dest).await?);
    }

    let first_node = &config.nodes[0];

    // Determine the target and metadata for the handshake to the first relay node.
    //
    // The metadata tells B1 what transport/sni to use for its outbound connection:
    //   - If there's a B2, metadata = B2's transport/sni (how to reach B2)
    //   - If B1 is the last relay, metadata = rule's transport/sni (how to reach dest)
    let (handshake_target, handshake_meta) = next_hop_info(config, dest, 0);

    let mut stream = connector.connect(&first_node.addr).await?;

    // Send relay handshake to first node (using pre-computed hash)
    handshake::write_handshake_prehashed(
        &mut stream,
        &prehashed[0],
        &handshake_target,
        &handshake_meta,
    )
    .await?;

    // For chains with more than one node, send remaining handshakes through the tunnel.
    // Each relay node forwards bytes after its own handshake completes, so subsequent
    // handshakes flow through the established tunnel.
    //
    // Example: chain [B1, B2, B3] → dest C:
    //   A → B1: handshake(pw=B1, target=B2, meta={how to reach B2})
    //   A → (B1→B2): handshake(pw=B2, target=B3, meta={how to reach B3})
    //   A → (B1→B2→B3): handshake(pw=B3, target=C, meta={how to reach C})
    for (i, hash) in (1..config.nodes.len()).zip(&prehashed[1..]) {
        let (target, meta) = next_hop_info(config, dest, i);

        handshake::write_handshake_prehashed(&mut stream, hash, &target, &meta).await?;
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
        };
        (next.addr.clone(), meta)
    } else {
        // Next hop is the final destination (trojan-server).
        // Use plain TCP — the trojan client performs its own TLS handshake
        // end-to-end with the trojan-server through the relay tunnel.
        let meta = HandshakeMetadata {
            transport: Some(TransportType::Plain),
            sni: None,
        };
        (dest.to_string(), meta)
    }
}
