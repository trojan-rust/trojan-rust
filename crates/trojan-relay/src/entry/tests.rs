use super::*;
use crate::config::{ChainNodeConfig, RelayNodeConfig};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use trojan_lb::LbStrategy;

async fn unused_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn node(addr: SocketAddr, transport: TransportType) -> ChainNodeConfig {
    ChainNodeConfig {
        addr: addr.to_string(),
        node_id: None,
        password: Some("secret".into()),
        transport,
        sni: "test.local".into(),
    }
}

async fn start_relay(transport: TransportType, shutdown: &CancellationToken) -> ChainNodeConfig {
    let mut config: RelayNodeConfig =
        toml::from_str("[relay]\nlisten = '127.0.0.1:0'\n[relay.auth]\npassword = 'secret'")
            .unwrap();
    let addr = unused_addr().await;
    config.relay.listen = addr;
    config.relay.transport = transport.clone();
    let token = shutdown.clone();
    tokio::spawn(async move { crate::relay::run(config, token).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    node(addr, transport)
}

fn session(nodes: Vec<ChainNodeConfig>, dests: Vec<String>) -> EntrySession {
    static CRYPTO: std::sync::Once = std::sync::Once::new();
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    let mut config: EntryConfig = toml::from_str(
        "[chains.test]\nnodes = []\n[[rules]]\nname = 'test'\nlisten = '127.0.0.1:1'\nchain = 'test'\ndest = 'unused:1'\nstrategy = 'failover'",
    ).unwrap();
    config.chains.get_mut("test").unwrap().nodes = nodes;
    config.rules[0].dest = dests;
    let router = Router::new(&config).unwrap();
    let route = router.resolve(&config.rules[0].listen).unwrap();
    EntrySession {
        chain: route.chain.clone(),
        lb: route.lb.clone(),
        peer: "127.0.0.1:1234".parse().unwrap(),
        announce_client: false,
        connectors: Connectors {
            tls: TlsTransportConnector::new_insecure("test.local".into()),
            plain: PlainTransportConnector::new(),
            ws: WsTransportConnector::new(),
        },
        timeouts: TimeoutConfig::default(),
        counters: RelayCounters::global(),
    }
}

#[tokio::test]
async fn failover_preserves_the_first_client_connection_and_proxy_header() {
    // No entry readiness probe may warm up the load balancer before this client.
    for transport in [
        None,
        Some(TransportType::Plain),
        Some(TransportType::Tls),
        Some(TransportType::Ws),
    ] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = target.local_addr().unwrap().to_string();
        let dead = unused_addr().await.to_string();
        let shutdown = CancellationToken::new();
        let mut entry = session(vec![], vec![dead.clone(), dest.clone()]);
        if let Some(transport) = transport {
            let nodes = vec![
                start_relay(transport.clone(), &shutdown).await,
                start_relay(transport, &shutdown).await,
            ];
            entry = session(nodes, vec![dead.clone(), dest.clone()]);
        }
        // Zero cooldown must not make this connection retry its failed destination.
        entry.lb = Arc::new(LoadBalancer::new(
            vec![dead, dest],
            LbStrategy::Failover,
            Duration::ZERO,
        ));
        entry.announce_client = true;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        entry.peer = peer;
        let handler = tokio::spawn(entry.handle(accepted));
        let server = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let proxy = trojan_core::proxy_protocol::accept(&mut stream)
                .await
                .unwrap();
            assert_eq!(proxy.header.unwrap().source(), Some(peer));
            let mut stream = trojan_core::io::PrefixedStream::new(proxy.residue, stream);
            let mut payload = [0; 5];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
            stream.write_all(b"world").await.unwrap();
        });
        client.write_all(b"hello").await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"world");
        client.shutdown().await.unwrap();
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), handler)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        shutdown.cancel();
    }
}

#[tokio::test]
async fn relay_and_authentication_failures_leave_destinations_healthy() {
    let shutdown = CancellationToken::new();
    let first = start_relay(TransportType::Plain, &shutdown).await;
    let dead = node(unused_addr().await, TransportType::Plain);
    let mut wrong_password = first.clone();
    wrong_password.password = Some("wrong".into());
    let mut bad_transport = first.clone();
    bad_transport.transport = TransportType::Tls;
    let dests = vec!["127.0.0.1:1".into(), "127.0.0.1:2".into()];
    for nodes in [vec![dead.clone()], vec![first, dead], vec![wrong_password]] {
        let entry = session(nodes, dests.clone());
        entry
            .connect_tunnel(&entry.connectors.plain)
            .await
            .unwrap_err();
        assert_eq!(entry.lb.select(entry.peer.ip()).unwrap().addr, dests[0]);
    }
    let mut entry = session(vec![bad_transport], dests.clone());
    entry.timeouts.connect_timeout_secs = 1;
    entry
        .connect_tunnel(&entry.connectors.tls)
        .await
        .unwrap_err();
    assert_eq!(entry.lb.select(entry.peer.ip()).unwrap().addr, dests[0]);
    shutdown.cancel();
}

#[tokio::test]
async fn missing_response_times_out_without_consuming_payload_or_poisoning_destination() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut entry = session(
        vec![node(listener.local_addr().unwrap(), TransportType::Plain)],
        vec!["exit:443".into(), "backup:443".into()],
    );
    entry.timeouts.connect_timeout_secs = 1;
    entry.timeouts.handshake_timeout_secs = 0;
    let legacy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (request, residue) = handshake::read_handshake(&mut stream).await.unwrap();
        assert!(request.metadata.ack);
        assert!(residue.is_empty());
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let err = entry
        .connect_tunnel(&entry.connectors.plain)
        .await
        .unwrap_err();
    assert!(matches!(err, RelayError::Handshake(_)));
    assert_eq!(entry.lb.select(entry.peer.ip()).unwrap().addr, "exit:443");
    legacy.await.unwrap();
}

#[tokio::test]
async fn legacy_handshake_receives_payload_without_a_response_prefix() {
    let shutdown = CancellationToken::new();
    let relay = start_relay(TransportType::Plain, &shutdown).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let mut client = TcpStream::connect(relay.addr).await.unwrap();
    handshake::write_handshake(
        &mut client,
        "secret",
        &target_addr,
        &HandshakeMetadata {
            transport: Some(TransportType::Plain),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (mut stream, _) = target.accept().await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut reply = [0; 5];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"hello");
    shutdown.cancel();
}

#[tokio::test]
async fn all_destinations_down_are_attempted_once_even_without_cooldown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dests = vec!["exit:443".to_string(), "backup:443".to_string()];
    let mut entry = session(
        vec![node(listener.local_addr().unwrap(), TransportType::Plain)],
        dests.clone(),
    );
    entry.lb = Arc::new(LoadBalancer::new(
        dests.clone(),
        LbStrategy::Failover,
        Duration::ZERO,
    ));
    let relay = tokio::spawn(async move {
        let mut targets = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (request, residue) = handshake::read_handshake(&mut stream).await.unwrap();
            assert!(residue.is_empty());
            targets.push(request.target);
            handshake::write_response(&mut stream, ConnectResponse::ConnectFailed)
                .await
                .unwrap();
        }
        targets
    });
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        entry.connect_tunnel(&entry.connectors.plain),
    )
    .await
    .unwrap();
    assert!(
        matches!(result, Err(RelayError::RemoteConnectFailed(ref target)) if target == &dests[1])
    );
    assert_eq!(relay.await.unwrap(), dests);
}
