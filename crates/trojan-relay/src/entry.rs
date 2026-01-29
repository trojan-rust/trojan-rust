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

use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, Instrument, info_span};

use crate::config::{ChainConfig, EntryConfig, RuleConfig, TimeoutConfig, TransportType};
use crate::error::RelayError;
use crate::handshake::{self, HandshakeMetadata};
use crate::router::Router;
use crate::transport::{TransportConnector, TransportStream};
use crate::transport::plain::PlainTransportConnector;
use crate::transport::tls::TlsTransportConnector;

use trojan_core::io::{NoOpMetrics, relay_bidirectional};

/// Run the entry node server.
pub async fn run(config: EntryConfig, shutdown: tokio_util::sync::CancellationToken) -> Result<(), RelayError> {
    let router = Arc::new(Router::new(&config)?);
    let timeouts = config.timeouts.clone();

    // Shared insecure TLS client config (SNI set per-connection via with_sni)
    let base_tls_connector = TlsTransportConnector::new_insecure("crates.io".to_string());
    let plain_connector = PlainTransportConnector;

    // Spawn a listener task for each rule
    let mut handles = Vec::new();

    for rule in router.rules() {
        let listener = TcpListener::bind(rule.listen).await?;
        info!(
            name = %rule.name,
            listen = %rule.listen,
            chain = %rule.chain,
            dest = %rule.dest,
            "entry rule started"
        );

        let router = router.clone();
        let base_tls_connector = base_tls_connector.clone();
        let plain_connector = plain_connector.clone();
        let timeouts = timeouts.clone();
        let listen_addr = rule.listen;
        let rule_name = rule.name.clone();
        let shutdown = shutdown.clone();

        handles.push(tokio::spawn(async move {
            run_listener(
                listener, listen_addr, &rule_name, router,
                base_tls_connector, plain_connector, timeouts, shutdown,
            ).await
        }));
    }

    // Wait for all listener tasks
    for handle in handles {
        if let Err(e) = handle.await {
            error!(error = %e, "listener task panicked");
        }
    }

    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    listen_addr: std::net::SocketAddr,
    rule_name: &str,
    router: Arc<Router>,
    base_tls_connector: TlsTransportConnector,
    plain_connector: PlainTransportConnector,
    timeouts: TimeoutConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RelayError> {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!(rule = %rule_name, "entry listener shutting down");
                return Ok(());
            }
            accept_result = listener.accept() => {
                let (tcp_stream, peer_addr) = accept_result?;

                let route = match router.resolve(&listen_addr) {
                    Some(r) => r,
                    None => {
                        error!(listen = %listen_addr, "no rule matched");
                        continue;
                    }
                };

                let chain = route.chain.clone();
                let rule = route.rule.clone();
                let base_tls_connector = base_tls_connector.clone();
                let plain_connector = plain_connector.clone();
                let timeouts = timeouts.clone();
                let rule_name = rule.name.clone();

                tokio::spawn(
                    async move {
                        if let Err(e) = handle_entry_connection(
                            tcp_stream,
                            &chain,
                            &rule,
                            base_tls_connector,
                            plain_connector,
                            &timeouts,
                        ).await {
                            debug!(error = %e, "entry connection error");
                        }
                    }
                    .instrument(info_span!("entry", rule = %rule_name, peer = %peer_addr)),
                );
            }
        }
    }
}

/// Handle a single client connection: build tunnel through chain, then relay.
async fn handle_entry_connection(
    client_stream: TcpStream,
    chain: &ChainConfig,
    rule: &RuleConfig,
    base_tls_connector: TlsTransportConnector,
    plain_connector: PlainTransportConnector,
    timeouts: &TimeoutConfig,
) -> Result<(), RelayError> {
    let connect_timeout = Duration::from_secs(timeouts.connect_timeout_secs);
    let idle_timeout = Duration::from_secs(timeouts.idle_timeout_secs);

    // Determine the first hop's transport and SNI.
    // - Empty chain (direct): plain TCP to dest (client does its own TLS to trojan-server)
    // - Non-empty chain: use nodes[0].transport/sni to connect to first relay
    let first_transport = if chain.nodes.is_empty() {
        &TransportType::Plain
    } else {
        &chain.nodes[0].transport
    };
    let first_sni = if chain.nodes.is_empty() {
        ""
    } else {
        chain.nodes[0].sni.as_str()
    };

    // Build tunnel and relay — dispatch on first hop transport type
    match first_transport {
        TransportType::Tls => {
            let tls_connector = base_tls_connector.with_sni(first_sni.to_string());
            let tunnel = tokio::time::timeout(
                connect_timeout,
                build_tunnel(chain, rule, &tls_connector),
            )
            .await
            .map_err(|_| RelayError::ConnectTimeout(rule.dest.to_string()))??;

            debug!("tunnel established, starting relay");
            relay_bidirectional(client_stream, tunnel, idle_timeout, 8192, &NoOpMetrics).await?;
        }
        TransportType::Plain => {
            let tunnel = tokio::time::timeout(
                connect_timeout,
                build_tunnel(chain, rule, &plain_connector),
            )
            .await
            .map_err(|_| RelayError::ConnectTimeout(rule.dest.to_string()))??;

            debug!("tunnel established, starting relay");
            relay_bidirectional(client_stream, tunnel, idle_timeout, 8192, &NoOpMetrics).await?;
        }
    }

    Ok(())
}

/// Build a tunnel through the chain to the destination.
///
/// For an empty chain (direct), just connect to dest via the connector.
/// For a chain with nodes [B1, B2, ...], connect to B1 and send relay
/// handshakes through the tunnel to build nested connections.
///
/// Each handshake includes metadata telling the relay node what transport
/// and SNI to use for its outbound connection to the next hop.
async fn build_tunnel<C>(
    chain: &ChainConfig,
    rule: &RuleConfig,
    connector: &C,
) -> Result<C::Stream, RelayError>
where
    C: TransportConnector,
    C::Stream: TransportStream,
{
    if chain.nodes.is_empty() {
        // Direct connection — no relay handshake needed
        return connector.connect(&rule.dest).await;
    }

    let first_node = &chain.nodes[0];

    // Determine the target and metadata for the handshake to the first relay node.
    //
    // The metadata tells B1 what transport/sni to use for its outbound connection:
    //   - If there's a B2, metadata = B2's transport/sni (how to reach B2)
    //   - If B1 is the last relay, metadata = rule's transport/sni (how to reach dest)
    let (handshake_target, handshake_meta) = next_hop_info(chain, rule, 0);

    let mut stream = connector.connect(&first_node.addr).await?;

    // Send relay handshake to first node
    let password = first_node
        .password
        .as_deref()
        .ok_or_else(|| RelayError::Config("first chain node missing password".into()))?;

    handshake::write_handshake(&mut stream, password, &handshake_target, &handshake_meta).await?;

    // For chains with more than one node, send remaining handshakes through the tunnel.
    // Each relay node forwards bytes after its own handshake completes, so subsequent
    // handshakes flow through the established tunnel.
    //
    // Example: chain [B1, B2, B3] → dest C:
    //   A → B1: handshake(pw=B1, target=B2, meta={how to reach B2})
    //   A → (B1→B2): handshake(pw=B2, target=B3, meta={how to reach B3})
    //   A → (B1→B2→B3): handshake(pw=B3, target=C, meta={how to reach C})
    for i in 1..chain.nodes.len() {
        let node = &chain.nodes[i];
        let (target, meta) = next_hop_info(chain, rule, i);

        let password = node
            .password
            .as_deref()
            .ok_or_else(|| {
                RelayError::Config(format!("chain node {} missing password", node.addr))
            })?;

        handshake::write_handshake(&mut stream, password, &target, &meta).await?;
    }

    Ok(stream)
}

/// Compute the target address and metadata for the handshake sent to `nodes[i]`.
///
/// - target = where nodes[i] should connect to (next node or dest)
/// - metadata = what transport/sni nodes[i] should use for that outbound connection
fn next_hop_info(chain: &ChainConfig, rule: &RuleConfig, i: usize) -> (String, HandshakeMetadata) {
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
        (rule.dest.clone(), meta)
    }
}
