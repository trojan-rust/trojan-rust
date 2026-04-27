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
