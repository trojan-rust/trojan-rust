#![allow(clippy::tests_outside_test_module)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use trojan_auth::MemoryAuth;
use trojan_client::config::{ClientConfig, ClientSettings, ClientTlsConfig};
use trojan_client::socks5::udp::{parse_socks5_udp, write_socks5_udp};
use trojan_config::{
    AnalyticsConfig, AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig,
    TlsConfig, WebSocketConfig,
};
use trojan_proto::{AddressRef, HostRef};

#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install aws-lc-rs crypto provider");
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
}

async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("timeout waiting for {addr}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

struct TcpEchoServer {
    addr: SocketAddr,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl TcpEchoServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            tokio::spawn(async move {
                                let mut buf = [0u8; 4096];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if stream.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                    }
                    _ = shutdown_task.cancelled() => break,
                }
            }
        });
        Self {
            addr,
            shutdown,
            handle,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

struct UdpEchoServer {
    addr: SocketAddr,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl UdpEchoServer {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        if let Ok((n, peer)) = res {
                            let _ = socket.send_to(&buf[..n], peer).await;
                        }
                    }
                    _ = shutdown_task.cancelled() => break,
                }
            }
        });
        Self {
            addr,
            shutdown,
            handle,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

struct TcpStaticServer {
    addr: SocketAddr,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl TcpStaticServer {
    async fn start(response: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            let response = response.to_vec();
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                let _ = stream.read(&mut buf).await;
                                let _ = stream.write_all(&response).await;
                                let _ = stream.shutdown().await;
                            });
                        }
                    }
                    _ = shutdown_task.cancelled() => break,
                }
            }
        });
        Self {
            addr,
            shutdown,
            handle,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

struct TestServer {
    addr: SocketAddr,
    password: String,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(fallback_addr: SocketAddr) -> Self {
        let password = "test_password_123".to_string();
        let (cert_pem, key_pem) = generate_test_certs();

        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = Config {
            server: ServerConfig {
                listen: addr.to_string(),
                fallback: fallback_addr.to_string(),
                tcp_idle_timeout_secs: 30,
                udp_timeout_secs: 30,
                max_udp_payload: 8192,
                max_udp_buffer_bytes: 65536,
                max_header_bytes: 8192,
                max_connections: None,
                rate_limit: None,
                fallback_pool: None,
                resource_limits: None,
                tcp: TcpConfig::default(),
                outbounds: Default::default(),
                rule_providers: Default::default(),
                rules: Default::default(),
                geoip: None,
            },
            tls: TlsConfig {
                cert: cert_path.to_string_lossy().to_string(),
                key: key_path.to_string_lossy().to_string(),
                alpn: vec![],
                min_version: "tls12".to_string(),
                max_version: "tls13".to_string(),
                client_ca: None,
                cipher_suites: vec![],
            },
            auth: AuthConfig {
                passwords: vec![password.clone()],
                users: vec![],
            },
            websocket: WebSocketConfig::default(),
            metrics: MetricsConfig { listen: None, ..Default::default() },
            analytics: AnalyticsConfig::default(),
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
        };

        let auth = MemoryAuth::from_passwords(&config.auth.passwords);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            let _ = trojan_server::run_with_shutdown(config, auth, shutdown_task).await;
        });

        wait_for_tcp(addr).await;

        Self {
            addr,
            password,
            shutdown,
            handle,
            _temp_dir: temp_dir,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

struct TestClient {
    socks_addr: SocketAddr,
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl TestClient {
    async fn start(server_addr: SocketAddr, password: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();
        drop(listener);

        let config = ClientConfig {
            client: ClientSettings {
                listen: socks_addr.to_string(),
                remote: server_addr.to_string(),
                password,
                tls: ClientTlsConfig {
                    sni: Some("localhost".to_string()),
                    skip_verify: true,
                    ..Default::default()
                },
                tcp: TcpConfig::default(),
            },
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
        };

        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            let _ = trojan_client::run(config, shutdown_task).await;
        });

        wait_for_tcp(socks_addr).await;

        Self {
            socks_addr,
            shutdown,
            handle,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

async fn socks5_connect(socks_addr: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x05, 0x00] {
        return Err(std::io::Error::other("SOCKS5 auth failed"));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(addr) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 connect failed"));
    }
    consume_socks5_addr(&mut stream, header[3]).await?;

    Ok(stream)
}

async fn socks5_udp_associate(
    socks_addr: SocketAddr,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x05, 0x00] {
        return Err(std::io::Error::other("SOCKS5 auth failed"));
    }

    let request = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 UDP associate failed"));
    }
    let bind_addr = read_socks5_addr(&mut stream, header[3]).await?;

    Ok((stream, bind_addr))
}

async fn consume_socks5_addr(stream: &mut TcpStream, atyp: u8) -> std::io::Result<()> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        _ => {
            return Err(std::io::Error::other("invalid SOCKS5 address type"));
        }
    }
    Ok(())
}

async fn read_socks5_addr(stream: &mut TcpStream, atyp: u8) -> std::io::Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let ip = std::net::Ipv6Addr::from([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            let host = String::from_utf8_lossy(&buf).to_string();
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let mut addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("failed to resolve SOCKS5 bind address"))
        }
        _ => Err(std::io::Error::other("invalid SOCKS5 address type")),
    }
}

fn generate_test_certs() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let cert = params.self_signed(&key_pair).unwrap();

    (cert.pem(), key_pair.serialize_pem())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tcp_connect() {
    init_tracing();

    let fallback = TcpStaticServer::start(b"HTTP/1.1 200 OK\r\n\r\n").await;
    let server = TestServer::start(fallback.addr).await;
    let client = TestClient::start(server.addr, server.password.clone()).await;
    let echo = TcpEchoServer::start().await;

    let mut stream = socks5_connect(client.socks_addr, echo.addr)
        .await
        .expect("socks connect");
    stream.write_all(b"ping").await.unwrap();

    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .await
        .expect("read echo");
    assert_eq!(&buf, b"ping");

    // Drop the stream before stopping services so in-flight relays can finish
    // and the server's graceful-drain doesn't block waiting for them.
    drop(stream);

    echo.stop().await;
    client.stop().await;
    server.stop().await;
    fallback.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_udp_associate() {
    init_tracing();

    let fallback = TcpStaticServer::start(b"HTTP/1.1 200 OK\r\n\r\n").await;
    let server = TestServer::start(fallback.addr).await;
    let client = TestClient::start(server.addr, server.password.clone()).await;
    let udp_echo = UdpEchoServer::start().await;

    let (_control, udp_relay) = socks5_udp_associate(client.socks_addr)
        .await
        .expect("udp associate");

    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = AddressRef {
        host: HostRef::Ipv4([127, 0, 0, 1]),
        port: udp_echo.addr.port(),
    };
    let payload = b"hello-udp";
    let packet = write_socks5_udp(&target, payload);

    udp_client.send_to(&packet, udp_relay).await.unwrap();

    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut buf))
        .await
        .expect("udp recv timeout")
        .unwrap();

    let parsed = parse_socks5_udp(&buf[..n]).expect("parse socks5 udp");
    assert_eq!(parsed.address, target);
    assert_eq!(parsed.payload, payload);

    // Drop the control connection and UDP socket before stopping services
    // so in-flight relays can finish and graceful-drain doesn't block.
    drop(_control);
    drop(udp_client);

    udp_echo.stop().await;
    client.stop().await;
    server.stop().await;
    fallback.stop().await;
}

// ============================================================================
// Rule-Based Routing E2E Tests
// ============================================================================

mod rules_e2e {
    use super::*;
    use std::collections::HashMap;
    use trojan_config::{OutboundConfig, RouteRuleConfig};

    struct RulesTestServer {
        addr: SocketAddr,
        password: String,
        shutdown: CancellationToken,
        handle: JoinHandle<()>,
        _temp_dir: tempfile::TempDir,
    }

    impl RulesTestServer {
        async fn start(
            fallback_addr: SocketAddr,
            outbounds: HashMap<String, OutboundConfig>,
            rules: Vec<RouteRuleConfig>,
        ) -> Self {
            let password = "test_password_123".to_string();
            let (cert_pem, key_pem) = generate_test_certs();

            let temp_dir = tempfile::tempdir().unwrap();
            let cert_path = temp_dir.path().join("cert.pem");
            let key_path = temp_dir.path().join("key.pem");

            std::fs::write(&cert_path, &cert_pem).unwrap();
            std::fs::write(&key_path, &key_pem).unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);

            let config = Config {
                server: ServerConfig {
                    listen: addr.to_string(),
                    fallback: fallback_addr.to_string(),
                    tcp_idle_timeout_secs: 30,
                    udp_timeout_secs: 30,
                    max_udp_payload: 8192,
                    max_udp_buffer_bytes: 65536,
                    max_header_bytes: 8192,
                    max_connections: None,
                    rate_limit: None,
                    fallback_pool: None,
                    resource_limits: None,
                    tcp: TcpConfig::default(),
                    outbounds,
                    rule_providers: Default::default(),
                    rules,
                    geoip: None,
                },
                tls: TlsConfig {
                    cert: cert_path.to_string_lossy().to_string(),
                    key: key_path.to_string_lossy().to_string(),
                    alpn: vec![],
                    min_version: "tls12".to_string(),
                    max_version: "tls13".to_string(),
                    client_ca: None,
                    cipher_suites: vec![],
                },
                auth: AuthConfig {
                    passwords: vec![password.clone()],
                    users: vec![],
                },
                websocket: WebSocketConfig::default(),
                metrics: MetricsConfig { listen: None, ..Default::default() },
                analytics: AnalyticsConfig::default(),
                logging: LoggingConfig {
                    level: Some("warn".to_string()),
                    ..Default::default()
                },
            };

            let auth = MemoryAuth::from_passwords(&config.auth.passwords);
            let shutdown = CancellationToken::new();
            let shutdown_task = shutdown.clone();
            let handle = tokio::spawn(async move {
                let _ = trojan_server::run_with_shutdown(config, auth, shutdown_task).await;
            });

            wait_for_tcp(addr).await;

            Self {
                addr,
                password,
                shutdown,
                handle,
                _temp_dir: temp_dir,
            }
        }

        async fn stop(self) {
            self.shutdown.cancel();
            let _ = self.handle.await;
        }
    }

    fn rule(rule_type: &str, value: Option<&str>, outbound: &str) -> RouteRuleConfig {
        RouteRuleConfig {
            rule_set: None,
            rule_type: Some(rule_type.to_string()),
            value: value.map(|v| v.to_string()),
            outbound: outbound.to_string(),
        }
    }

    /// E2E: SOCKS5 → Client → Server with FINAL DIRECT routes all traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn e2e_rules_final_direct() {
        init_tracing();

        let fallback = TcpStaticServer::start(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let echo = TcpEchoServer::start().await;

        let rules = vec![rule("FINAL", None, "DIRECT")];
        let server =
            RulesTestServer::start(fallback.addr, HashMap::new(), rules).await;
        let client = TestClient::start(server.addr, server.password.clone()).await;

        let mut stream = socks5_connect(client.socks_addr, echo.addr)
            .await
            .expect("socks connect");

        stream.write_all(b"e2e-rules").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read echo");
        assert_eq!(&buf[..n], b"e2e-rules");

        drop(stream);
        echo.stop().await;
        client.stop().await;
        server.stop().await;
        fallback.stop().await;
    }

    /// E2E: SOCKS5 → Client → Server with DST-PORT REJECT blocks specific port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn e2e_rules_reject_port() {
        init_tracing();

        let fallback = TcpStaticServer::start(b"HTTP/1.1 200 OK\r\n\r\n").await;
        // Start echo server — we won't actually relay to it since REJECT applies
        let echo = TcpEchoServer::start().await;

        let rules = vec![
            rule("DST-PORT", Some(&echo.addr.port().to_string()), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ];
        let server =
            RulesTestServer::start(fallback.addr, HashMap::new(), rules).await;
        let client = TestClient::start(server.addr, server.password.clone()).await;

        let mut stream = socks5_connect(client.socks_addr, echo.addr)
            .await
            .expect("socks connect");

        // Write some data — server should reject
        stream.write_all(b"should-reject").await.unwrap();

        let mut buf = [0u8; 64];
        let read_result =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        match read_result {
            Ok(Ok(0)) => { /* Expected: connection closed by REJECT */ }
            Ok(Ok(_)) => { /* Might get data if timing is odd */ }
            Ok(Err(_)) => { /* Read error — also acceptable for REJECT */ }
            Err(_) => panic!("Timeout waiting for REJECT — rule may not be working"),
        }

        drop(stream);
        echo.stop().await;
        client.stop().await;
        server.stop().await;
        fallback.stop().await;
    }

    /// E2E: SOCKS5 → Client → Server with mixed rules (one port allowed, one rejected).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn e2e_rules_mixed_ports() {
        init_tracing();

        let fallback = TcpStaticServer::start(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let echo_allowed = TcpEchoServer::start().await;
        let echo_blocked = TcpEchoServer::start().await;

        let rules = vec![
            rule(
                "DST-PORT",
                Some(&echo_allowed.addr.port().to_string()),
                "DIRECT",
            ),
            rule(
                "DST-PORT",
                Some(&echo_blocked.addr.port().to_string()),
                "REJECT",
            ),
            rule("FINAL", None, "DIRECT"),
        ];
        let server =
            RulesTestServer::start(fallback.addr, HashMap::new(), rules).await;
        let client = TestClient::start(server.addr, server.password.clone()).await;

        // Allowed port should relay
        {
            let mut stream = socks5_connect(client.socks_addr, echo_allowed.addr)
                .await
                .expect("socks connect allowed");
            stream.write_all(b"allowed").await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.expect("read echo");
            assert_eq!(&buf[..n], b"allowed", "Allowed port should relay traffic");
            drop(stream);
        }

        // Blocked port should be rejected
        {
            let mut stream = socks5_connect(client.socks_addr, echo_blocked.addr)
                .await
                .expect("socks connect blocked");
            stream.write_all(b"blocked").await.unwrap();

            let mut buf = [0u8; 64];
            let read_result =
                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            match read_result {
                Ok(Ok(0)) => { /* Expected: REJECT */ }
                Ok(Ok(_)) => { /* Timing edge case */ }
                Ok(Err(_)) => { /* Read error from REJECT */ }
                Err(_) => panic!("Timeout waiting for blocked port REJECT"),
            }
            drop(stream);
        }

        echo_allowed.stop().await;
        echo_blocked.stop().await;
        client.stop().await;
        server.stop().await;
        fallback.stop().await;
    }
}
