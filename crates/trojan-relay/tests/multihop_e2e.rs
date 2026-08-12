//! End-to-end multi-hop relay tests across all three transports.
//!
//! Regression for the v0.9.0 over-read bug in `read_handshake`. The entry
//! sends N relay handshakes back-to-back; if the relay drops bytes past the
//! second CRLF, downstream relays hang waiting for handshakes that already
//! arrived and were thrown away.
//!
//! Plain TCP and TLS are most likely to trigger the bug because their
//! `AsyncRead::read` can return data spanning multiple writes. WebSocket is
//! frame-aligned and unlikely to trigger it, but is included here so we have
//! e2e coverage for all three transports.

#![allow(clippy::tests_outside_test_module)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use trojan_relay::config::{
    ChainConfig, ChainNodeConfig, EntryConfig, RelayAuthConfig, RelayListenerConfig,
    RelayNodeConfig, RelayOutboundConfig, RuleConfig, TimeoutConfig, TransportType,
};

/// Install the rustls crypto provider once per test process.
/// Required by trojan-transport's TLS code paths.
fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Bind 127.0.0.1:0, read the assigned port, drop the listener.
/// Cheap port-picking for tests; small race with the OS but fine in practice.
async fn pick_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// TCP echo server. Echoes everything until peer half-closes.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Wait until something is listening on `addr` (with a hard cap).
async fn wait_ready(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("nothing listening on {addr} after 3s");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn relay_cfg(listen: SocketAddr, password: &str, transport: TransportType) -> RelayNodeConfig {
    RelayNodeConfig {
        relay: RelayListenerConfig {
            listen,
            transport,
            // None ⇒ trojan-transport auto-generates a self-signed cert in memory.
            // Entry's outbound TLS connector uses an insecure verifier (NoVerifier),
            // so the chain handshakes regardless of CA trust.
            tls: None,
            auth: RelayAuthConfig {
                password: password.to_string(),
            },
            outbound: RelayOutboundConfig::default(),
            timeouts: TimeoutConfig::default(),
            dns: Default::default(),
        },
    }
}

/// Run an N-hop chain over a single transport and verify a few payloads
/// round-trip through the chain to an echo target.
async fn run_chain(transport: TransportType, hop_count: usize, payloads: &[&[u8]]) {
    init_crypto();

    let echo = spawn_echo().await;
    let entry_addr = pick_addr().await;

    let shutdown = CancellationToken::new();

    // Spawn N relays. Pick all addresses up-front so we can reference them
    // when building the chain config.
    let mut relays: Vec<(SocketAddr, String)> = Vec::with_capacity(hop_count);
    for i in 0..hop_count {
        let addr = pick_addr().await;
        let pw = format!("pw-b{}", i + 1);
        relays.push((addr, pw));
    }

    for (addr, pw) in &relays {
        let cfg = relay_cfg(*addr, pw, transport.clone());
        let sd = shutdown.clone();
        tokio::spawn(async move {
            let _ = trojan_relay::relay::run(cfg, sd).await;
        });
    }

    for (addr, _) in &relays {
        wait_ready(*addr).await;
    }

    // Entry: chain references all relays in order, dest = echo
    let chain_nodes: Vec<ChainNodeConfig> = relays
        .iter()
        .map(|(addr, pw)| ChainNodeConfig {
            addr: addr.to_string(),
            password: Some(pw.clone()),
            transport: transport.clone(),
            sni: "test.local".to_string(),
        })
        .collect();

    let mut chains = HashMap::new();
    chains.insert("test-chain".to_string(), ChainConfig { nodes: chain_nodes });
    let entry_cfg = EntryConfig {
        chains,
        rules: vec![RuleConfig {
            name: "test-rule".to_string(),
            listen: entry_addr,
            chain: "test-chain".to_string(),
            dest: vec![echo.to_string()],
            strategy: Default::default(),
            failover_cooldown_secs: 30,
        }],
        timeouts: TimeoutConfig::default(),
        dns: Default::default(),
    };
    {
        let sd = shutdown.clone();
        tokio::spawn(async move {
            let _ = trojan_relay::entry::run(entry_cfg, sd).await;
        });
    }
    wait_ready(entry_addr).await;

    // Drive a TCP client through entry. Bytes flow:
    //   client → entry → B1 → ... → BN → echo → BN → ... → B1 → entry → client
    let mut sock = TcpStream::connect(entry_addr).await.unwrap();
    for payload in payloads {
        sock.write_all(payload).await.unwrap();
        sock.flush().await.unwrap();

        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(3),
            AsyncReadExt::read_exact(&mut sock, &mut buf),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("echo round-trip timed out — {hop_count}-hop {transport:?} chain desynced")
        })
        .unwrap();
        assert_eq!(&buf, payload);
    }

    shutdown.cancel();
}

// ── Destination load balancing ──

/// Start an entry with a direct (empty) chain and the given destinations.
async fn spawn_entry_with_dests(
    entry_addr: SocketAddr,
    dests: Vec<String>,
    strategy: trojan_lb::LbStrategy,
    shutdown: &CancellationToken,
) {
    let mut chains = HashMap::new();
    chains.insert("direct".to_string(), ChainConfig { nodes: vec![] });

    let cfg = EntryConfig {
        chains,
        rules: vec![RuleConfig {
            name: "lb-rule".to_string(),
            listen: entry_addr,
            chain: "direct".to_string(),
            dest: dests,
            strategy,
            failover_cooldown_secs: 30,
        }],
        timeouts: TimeoutConfig::default(),
        dns: Default::default(),
    };

    let sd = shutdown.clone();
    tokio::spawn(async move {
        let _ = trojan_relay::entry::run(cfg, sd).await;
    });
    wait_ready(entry_addr).await;
}

/// Echo server that prefixes every reply with `tag`, so a client can tell
/// which destination served it.
async fn spawn_tagged_echo(tag: u8) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            let mut reply = vec![tag];
                            reply.extend_from_slice(&buf[..n]);
                            if sock.write_all(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Round-robin spreads connections over every destination.
///
/// Each destination tags its replies, so the assertion is on which backend
/// actually answered — a policy that always picked the first would fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entry_round_robin_spreads_across_destinations() {
    init_crypto();

    let echo_a = spawn_tagged_echo(b'A').await;
    let echo_b = spawn_tagged_echo(b'B').await;
    let entry_addr = pick_addr().await;
    let shutdown = CancellationToken::new();

    spawn_entry_with_dests(
        entry_addr,
        vec![echo_a.to_string(), echo_b.to_string()],
        trojan_lb::LbStrategy::RoundRobin,
        &shutdown,
    )
    .await;

    let mut served = std::collections::BTreeSet::new();
    for i in 0..4 {
        let mut sock = TcpStream::connect(entry_addr).await.unwrap();
        let payload = format!("rr-{i}");
        sock.write_all(payload.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();

        let mut buf = vec![0u8; payload.len() + 1];
        tokio::time::timeout(
            Duration::from_secs(3),
            AsyncReadExt::read_exact(&mut sock, &mut buf),
        )
        .await
        .unwrap_or_else(|_| panic!("round-robin connection {i} timed out"))
        .unwrap();

        assert_eq!(&buf[1..], payload.as_bytes());
        served.insert(buf[0]);
    }

    assert_eq!(
        served,
        (*b"AB").into_iter().collect(),
        "round robin should have used both destinations, saw {served:?}"
    );
    shutdown.cancel();
}

/// IP hash sends the same client to the same destination every time.
///
/// The property that makes it useful is stickiness, so the assertion is that
/// repeated connections from one source all land on one backend — which
/// round-robin, the default, would fail.
///
/// One source address cannot tell stickiness apart from a policy that always
/// picks the first destination; distribution *across* sources is covered by
/// the unit tests in trojan-lb, which can vary the peer IP directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entry_ip_hash_is_sticky_per_client() {
    init_crypto();

    let echo_a = spawn_tagged_echo(b'A').await;
    let echo_b = spawn_tagged_echo(b'B').await;
    let entry_addr = pick_addr().await;
    let shutdown = CancellationToken::new();

    spawn_entry_with_dests(
        entry_addr,
        vec![echo_a.to_string(), echo_b.to_string()],
        trojan_lb::LbStrategy::IpHash,
        &shutdown,
    )
    .await;

    let mut served = std::collections::BTreeSet::new();
    for i in 0..6 {
        let mut sock = TcpStream::connect(entry_addr).await.unwrap();
        let payload = format!("hash-{i}");
        sock.write_all(payload.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();

        let mut buf = vec![0u8; payload.len() + 1];
        tokio::time::timeout(
            Duration::from_secs(3),
            AsyncReadExt::read_exact(&mut sock, &mut buf),
        )
        .await
        .unwrap_or_else(|_| panic!("ip-hash connection {i} timed out"))
        .unwrap();

        assert_eq!(&buf[1..], payload.as_bytes());
        served.insert(buf[0]);
    }

    assert_eq!(
        served.len(),
        1,
        "ip hash must be sticky for one source address, saw {served:?}"
    );
    shutdown.cancel();
}

/// Failover skips a destination that refuses connections.
///
/// The first attempt lands on the dead address and fails — the entry marks it
/// unhealthy but does not retry within that connection — so the assertion is
/// that a *subsequent* connection is served by the live destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entry_failover_skips_dead_destination() {
    init_crypto();

    let echo = spawn_echo().await;
    // Reserved and released: nothing is listening there.
    let dead = pick_addr().await;
    let entry_addr = pick_addr().await;
    let shutdown = CancellationToken::new();

    spawn_entry_with_dests(
        entry_addr,
        vec![dead.to_string(), echo.to_string()],
        trojan_lb::LbStrategy::Failover,
        &shutdown,
    )
    .await;

    // Failover converges rather than switching instantly: the connection that
    // lands on the dead destination is lost, and marking it unhealthy happens
    // in that connection's task. Retry until a connection is served, with a
    // bound so a policy that never fails over still fails the test.
    let payload = b"after-failover";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempts = 0;
    let served = loop {
        attempts += 1;
        if tokio::time::Instant::now() >= deadline {
            break false;
        }

        let Ok(mut sock) = TcpStream::connect(entry_addr).await else {
            continue;
        };
        if sock.write_all(payload).await.is_err() || sock.flush().await.is_err() {
            continue;
        }

        let mut buf = vec![0u8; payload.len()];
        match tokio::time::timeout(
            Duration::from_secs(2),
            AsyncReadExt::read_exact(&mut sock, &mut buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                assert_eq!(&buf, payload);
                break true;
            }
            // The dead destination — keep going.
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };

    assert!(
        served,
        "failover never reached the healthy destination after {attempts} attempts"
    );

    shutdown.cancel();
}

// ── Plain TCP ──

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_2_relays_plain() {
    run_chain(
        TransportType::Plain,
        2,
        &[b"hello", b"world!", b"final-frame"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_3_relays_plain() {
    // Three hops: entry sends 3 handshakes back-to-back to B1; B1 must
    // forward 2 of them; B2 must forward 1.
    run_chain(TransportType::Plain, 3, &[b"three-hop-payload"]).await;
}

// ── TLS ──

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_2_relays_tls() {
    run_chain(TransportType::Tls, 2, &[b"hello-tls", b"second-frame-tls"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_3_relays_tls() {
    run_chain(TransportType::Tls, 3, &[b"three-hop-tls-payload"]).await;
}

// ── WebSocket ──

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_2_relays_ws() {
    run_chain(TransportType::Ws, 2, &[b"hello-ws", b"second-frame-ws"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_chain_3_relays_ws() {
    run_chain(TransportType::Ws, 3, &[b"three-hop-ws-payload"]).await;
}
