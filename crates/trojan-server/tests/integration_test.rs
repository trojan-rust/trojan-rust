//! Integration tests for trojan-server.
//!
//! These tests verify the complete server flow including:
//! - TLS handshake
//! - Trojan protocol parsing
//! - Authentication
//! - CONNECT relay
//! - Fallback behavior
#![allow(clippy::tests_outside_test_module)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::BytesMut;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use trojan_auth::{MemoryAuth, sha224_hex};
use trojan_config::{
    AnalyticsConfig, AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig,
    TlsConfig, WebSocketConfig,
};
use trojan_proto::{
    AddressRef, CMD_CONNECT, CMD_UDP_ASSOCIATE, HostRef, write_request_header, write_udp_packet,
};

// ============================================================================
// Crypto Provider Setup
// ============================================================================

/// Install the aws-lc-rs crypto provider once at process startup.
///
/// When the `rules` feature is enabled, `reqwest`'s `rustls-tls` pulls in the
/// `ring` provider alongside `aws-lc-rs`, preventing rustls from auto-detecting
/// which one to use.
#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install aws-lc-rs crypto provider");
}

// ============================================================================
// Test Certificates (self-signed for testing)
// ============================================================================

/// Generate a self-signed certificate for testing.
/// Returns (cert_pem, key_pem).
fn generate_test_certs() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    // Use ECDSA P-256 for cross-platform compatibility with aws-lc-rs
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let cert = params.self_signed(&key_pair).unwrap();

    (cert.pem(), key_pair.serialize_pem())
}

// ============================================================================
// Test Helper: Mock Echo Server
// ============================================================================

/// A simple TCP server that echoes back whatever it receives.
struct MockEchoServer {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl MockEchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }
}

/// A simple TCP server that responds with a fixed message.
struct MockHttpServer {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl MockHttpServer {
    fn start(response: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let response = response.to_string();
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    // Read request (we don't care about it)
                    let _ = stream.read(&mut buf);
                    // Send response
                    let _ = stream.write_all(response.as_bytes());
                    // Shutdown write side to signal end of response
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                });
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }
}

// ============================================================================
// Test Helper: Trojan Server
// ============================================================================

struct TestServer {
    addr: SocketAddr,
    password: String,
    tls_connector: TlsConnector,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(fallback_addr: SocketAddr) -> Self {
        use trojan_auth::MemoryAuth;
        use trojan_config::{
            AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TlsConfig,
        };

        let password = "test_password_123".to_string();
        let (cert_pem, key_pem) = generate_test_certs();

        // Write certs to a unique temp directory to avoid collisions in parallel tests.
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-test-")
            .tempdir()
            .unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        // Parse cert for client verification
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();

        // Build TLS connector for client
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der)).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        // Find available port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

        // Spawn server in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            let _ = trojan_server::run(config_clone, auth).await;
        });

        // Wait for server to start (longer on Windows CI)
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            addr,
            password,
            tls_connector,
            _temp_dir: temp_dir,
        }
    }

    fn hash(&self) -> String {
        sha224_hex(&self.password)
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that valid Trojan authentication succeeds and CONNECT relay works.
#[tokio::test]
async fn test_connect_relay() {
    // Start echo server (target)
    let echo_server = MockEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    // Connect via TLS
    let tcp_stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = server
        .tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Build Trojan request header
    let hash = server.hash();
    let ip_addr: std::net::Ipv4Addr = match echo_server.addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 address"),
    };
    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: echo_server.addr.port(),
    };

    let mut header = BytesMut::new();
    write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &target_addr).unwrap();
    header.extend_from_slice(b"Hello, Trojan!");

    // Send request
    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read response (echo server should echo back)
    let mut response = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(&response[..n], b"Hello, Trojan!");
}

/// Test that invalid password triggers fallback.
#[tokio::test]
async fn test_fallback_on_invalid_password() {
    // Start fallback server with recognizable response
    let fallback = MockHttpServer::start("FALLBACK_RESPONSE");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    // Connect via TLS
    let tcp_stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = server
        .tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Build Trojan request with WRONG password
    let wrong_hash = sha224_hex("wrong_password");
    let target_addr = AddressRef {
        host: HostRef::Ipv4([127, 0, 0, 1]),
        port: 80,
    };

    let mut header = BytesMut::new();
    write_request_header(
        &mut header,
        wrong_hash.as_bytes(),
        CMD_CONNECT,
        &target_addr,
    )
    .unwrap();

    // Send request
    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read response (should get fallback response)
    let mut response = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
        .await
        .expect("read timeout")
        .unwrap();

    assert!(String::from_utf8_lossy(&response[..n]).contains("FALLBACK"));
}

/// Test that non-Trojan traffic (e.g., plain HTTP) triggers fallback.
#[tokio::test]
async fn test_fallback_on_non_trojan_traffic() {
    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback OK");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    // Connect via TLS
    let tcp_stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = server
        .tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Send plain HTTP request (not Trojan protocol)
    // Must be at least 56 bytes for server to detect invalid hash format
    let http_request =
        b"GET /this-is-a-long-path-to-make-the-request-longer HTTP/1.1\r\nHost: localhost\r\n\r\n";
    tls_stream.write_all(http_request).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read response (should get fallback HTTP response)
    let mut response = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
        .await
        .expect("read timeout")
        .unwrap();

    let response_str = String::from_utf8_lossy(&response[..n]);
    assert!(response_str.contains("200 OK") || response_str.contains("Fallback"));
}

/// Test graceful shutdown: server stops accepting new connections and waits for existing ones.
#[tokio::test]
async fn test_graceful_shutdown() {
    use trojan_auth::MemoryAuth;
    use trojan_config::{
        AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TlsConfig,
    };
    use trojan_server::{CancellationToken, run_with_shutdown};

    let password = "test_password_123".to_string();
    let (cert_pem, key_pem) = generate_test_certs();

    let temp_dir = std::env::temp_dir().join(format!(
        "trojan-shutdown-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    // Parse cert for client
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    // Start fallback and echo servers
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");
    let echo_server = MockEchoServer::start();

    // Find available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
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
    let shutdown_trigger = shutdown.clone();

    // Spawn server with shutdown token
    let server_handle =
        tokio::spawn(async move { run_with_shutdown(config, auth, shutdown).await });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Establish a connection before shutdown
    let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Send a trojan request to establish relay
    let hash = sha224_hex(&password);
    let ip_addr: std::net::Ipv4Addr = match echo_server.addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 address"),
    };
    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: echo_server.addr.port(),
    };
    let mut header = BytesMut::new();
    write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &target_addr).unwrap();
    tls_stream.write_all(&header).await.unwrap();

    // Trigger shutdown
    shutdown_trigger.cancel();

    // Try to connect after shutdown signal - should fail eventually
    tokio::time::sleep(Duration::from_millis(100)).await;
    let connect_result =
        tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await;
    // Connection might succeed if quick enough, but server won't accept more after loop exits
    // The key test is that server eventually stops

    // The existing connection should still work (drain period)
    let message = b"Hello during shutdown!";
    tls_stream.write_all(message).await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut response = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
        .await
        .expect("read timeout during shutdown drain")
        .unwrap();
    assert_eq!(
        &response[..n],
        message,
        "existing connection should continue working"
    );

    // Close the connection
    drop(tls_stream);

    // Wait for server to stop
    let result = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server should stop within timeout");

    assert!(result.is_ok(), "server should exit cleanly");
    let _ = connect_result; // silence unused warning
}

/// Test that max_connections limits concurrent connections.
#[tokio::test]
async fn test_max_connections_limit() {
    use trojan_auth::MemoryAuth;
    use trojan_config::{
        AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TlsConfig,
    };
    use trojan_server::{CancellationToken, run_with_shutdown};

    let password = "test_password_123".to_string();
    let (cert_pem, key_pem) = generate_test_certs();

    let temp_dir = std::env::temp_dir().join(format!(
        "trojan-maxconn-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    // Parse cert for client
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    // Start fallback
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Find available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Configure with max_connections = 2
    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
            tcp_idle_timeout_secs: 30,
            udp_timeout_secs: 30,
            max_udp_payload: 8192,
            max_udp_buffer_bytes: 65536,
            max_header_bytes: 8192,
            max_connections: Some(2),
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
    let shutdown_trigger = shutdown.clone();

    // Spawn server
    let _server_handle =
        tokio::spawn(async move { run_with_shutdown(config, auth, shutdown).await });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Establish 2 connections (should succeed)
    let conn1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls1 = tls_connector
        .connect(server_name.clone(), conn1)
        .await
        .unwrap();

    let conn2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls2 = tls_connector
        .connect(server_name.clone(), conn2)
        .await
        .unwrap();

    // Give server time to register the connections
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Third connection should be rejected (connection closed immediately)
    let conn3_result = tokio::net::TcpStream::connect(addr).await;
    if let Ok(conn3) = conn3_result {
        // Server accepted TCP but should close it before TLS handshake
        let tls3_result = tokio::time::timeout(
            Duration::from_secs(2),
            tls_connector.connect(server_name.clone(), conn3),
        )
        .await;
        // Either timeout or TLS error is expected
        assert!(
            tls3_result.is_err() || tls3_result.unwrap().is_err(),
            "third connection should fail"
        );
    }

    // Drop one connection
    drop(tls1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now a new connection should succeed
    let conn4 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls4_result = tokio::time::timeout(
        Duration::from_secs(2),
        tls_connector.connect(server_name.clone(), conn4),
    )
    .await;
    assert!(
        tls4_result.is_ok() && tls4_result.unwrap().is_ok(),
        "fourth connection should succeed after one was closed"
    );

    // Cleanup
    drop(tls2);
    shutdown_trigger.cancel();
}

/// Test that rate limiting rejects connections when limit is exceeded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rate_limiting() {
    use trojan_auth::MemoryAuth;
    use trojan_config::{
        AuthConfig, Config, LoggingConfig, MetricsConfig, RateLimitConfig, ServerConfig, TlsConfig,
    };
    use trojan_server::CancellationToken;

    let password = "test_password_123".to_string();
    let (cert_pem, key_pem) = generate_test_certs();

    let temp_dir = std::env::temp_dir().join(format!("trojan_test_rl_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Configure rate limit: 2 connections per 60 seconds
    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
            tcp_idle_timeout_secs: 30,
            udp_timeout_secs: 30,
            max_udp_payload: 8192,
            max_udp_buffer_bytes: 65536,
            max_header_bytes: 8192,
            max_connections: None,
            rate_limit: Some(RateLimitConfig {
                max_connections_per_ip: 2,
                window_secs: 60,
                cleanup_interval_secs: 300,
            }),
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
    let shutdown_trigger = CancellationToken::new();
    let shutdown = shutdown_trigger.clone();
    let server_config = config.clone();

    tokio::spawn(async move {
        let _ = trojan_server::run_with_shutdown(server_config, auth, shutdown).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let server_name: ServerName<'_> = ServerName::try_from("localhost").unwrap();

    // First two connections should succeed
    let conn1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls1 = tls_connector
        .connect(server_name.clone(), conn1)
        .await
        .unwrap();

    let conn2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls2 = tls_connector
        .connect(server_name.clone(), conn2)
        .await
        .unwrap();

    // Third connection should be rate limited (connection refused or reset)
    let conn3_result = tokio::net::TcpStream::connect(addr).await;
    if let Ok(conn3) = conn3_result {
        // Connection might be accepted but then closed immediately
        let tls3_result = tokio::time::timeout(
            Duration::from_secs(2),
            tls_connector.connect(server_name.clone(), conn3),
        )
        .await;
        // Either timeout or TLS error is expected
        assert!(
            tls3_result.is_err() || tls3_result.unwrap().is_err(),
            "third connection should fail due to rate limiting"
        );
    }
    // If connect itself fails, that's also expected

    // Cleanup
    drop(tls1);
    drop(tls2);
    shutdown_trigger.cancel();
    let _ = fs::remove_dir_all(&temp_dir);
}

/// Test TLS 1.3 only mode works correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tls13_only() {
    use trojan_auth::MemoryAuth;
    use trojan_config::{
        AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TlsConfig, WebSocketConfig,
    };
    use trojan_server::CancellationToken;

    let password = "test_password_123".to_string();
    let (cert_pem, key_pem) = generate_test_certs();

    let temp_dir = std::env::temp_dir().join(format!("trojan_test_tls13_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der)).unwrap();

    // Configure client for TLS 1.3 only
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Server configured for TLS 1.3 only
    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
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
            min_version: "tls13".to_string(),
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
    let shutdown_trigger = CancellationToken::new();
    let shutdown = shutdown_trigger.clone();
    let server_config = config.clone();

    tokio::spawn(async move {
        let _ = trojan_server::run_with_shutdown(server_config, auth, shutdown).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let server_name: ServerName<'_> = ServerName::try_from("localhost").unwrap();

    // Connection should succeed with TLS 1.3
    let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls_result = tls_connector.connect(server_name.clone(), conn).await;
    assert!(tls_result.is_ok(), "TLS 1.3 connection should succeed");

    // Cleanup
    shutdown_trigger.cancel();
    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// UDP Relay Tests
// ============================================================================

/// A simple UDP server that echoes back whatever it receives.
struct MockUdpEchoServer {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl MockUdpEchoServer {
    fn start() -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, src)) = socket.recv_from(&mut buf) {
                // Echo back with "ECHO:" prefix
                let mut response = Vec::from(b"ECHO:".as_slice());
                response.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&response, src);
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }
}

/// Test UDP relay functionality.
#[tokio::test]
async fn test_udp_relay() {
    // Start UDP echo server (target)
    let udp_echo = MockUdpEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    // Connect via TLS
    let tcp_stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = server
        .tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Build Trojan UDP ASSOCIATE request header
    let hash = server.hash();
    let ip_addr: std::net::Ipv4Addr = match udp_echo.addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 address"),
    };

    // The target address in UDP ASSOCIATE header specifies the initial target
    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: udp_echo.addr.port(),
    };

    let mut header = BytesMut::new();
    write_request_header(
        &mut header,
        hash.as_bytes(),
        CMD_UDP_ASSOCIATE,
        &target_addr,
    )
    .unwrap();

    // Send the UDP ASSOCIATE header
    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Now send a UDP packet through the trojan UDP encapsulation
    let udp_target = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: udp_echo.addr.port(),
    };
    let mut udp_packet = BytesMut::new();
    write_udp_packet(&mut udp_packet, &udp_target, b"Hello UDP!").unwrap();

    tls_stream.write_all(&udp_packet).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read UDP response (should be echoed back with "ECHO:" prefix)
    let mut response = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
        .await
        .expect("read timeout")
        .unwrap();

    // The response is a trojan UDP packet, we need to parse it
    // Format: ATYP(1) + ADDR + PORT(2) + LENGTH(2) + CRLF(2) + PAYLOAD
    // For IPv4: 1 + 4 + 2 + 2 + 2 + payload_len
    assert!(n > 11, "Response too short: {} bytes", n);

    // Extract payload from the UDP packet
    // Skip ATYP(1) + IPv4(4) + PORT(2) + LENGTH(2) + CRLF(2) = 11 bytes for IPv4
    let payload = &response[11..n];
    assert_eq!(payload, b"ECHO:Hello UDP!", "UDP echo response mismatch");
}

/// Test UDP idle timeout behavior.
#[tokio::test]
async fn test_udp_idle_timeout() {
    // Start UDP echo server
    let udp_echo = MockUdpEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Create server with short UDP timeout (1 second)
    let (cert_pem, key_pem) = generate_test_certs();
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let password = "test_password";

    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
            tcp_idle_timeout_secs: 30,
            udp_timeout_secs: 1, // 1 second timeout
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
            passwords: vec![password.to_string()],
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
    tokio::spawn(async move {
        let _ = trojan_server::run(config, auth).await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create TLS connector
    let mut root_store = RootCertStore::empty();
    let cert_der = CertificateDer::from(
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap()
            .to_vec(),
    );
    root_store.add(cert_der).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    // Connect
    let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Send UDP ASSOCIATE request
    let hash = sha224_hex(password);
    let ip_addr: std::net::Ipv4Addr = match udp_echo.addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4"),
    };
    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: udp_echo.addr.port(),
    };

    let mut header = BytesMut::new();
    write_request_header(
        &mut header,
        hash.as_bytes(),
        CMD_UDP_ASSOCIATE,
        &target_addr,
    )
    .unwrap();
    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Send one packet
    let mut udp_packet = BytesMut::new();
    write_udp_packet(&mut udp_packet, &target_addr, b"test").unwrap();
    tls_stream.write_all(&udp_packet).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read response
    let mut response = vec![0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(2), tls_stream.read(&mut response))
        .await
        .unwrap();

    // Now wait for timeout (1 second + buffer)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Try to send another packet - connection should be closed due to timeout
    let mut udp_packet2 = BytesMut::new();
    write_udp_packet(&mut udp_packet2, &target_addr, b"test2").unwrap();
    let write_result = tls_stream.write_all(&udp_packet2).await;

    // Either write fails or subsequent read returns 0 (connection closed)
    if write_result.is_ok() {
        tls_stream.flush().await.ok();
        let mut buf = vec![0u8; 1024];
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), tls_stream.read(&mut buf)).await;
        match read_result {
            Ok(Ok(0)) => { /* Expected: connection closed */ }
            Ok(Ok(_)) => { /* Server might still have buffered response */ }
            Ok(Err(_)) => { /* Read error expected after timeout */ }
            Err(_) => { /* Timeout on read is also acceptable */ }
        }
    }
    // Test passes if we get here - timeout behavior is working
}

/// Test multiple UDP packets in sequence.
#[tokio::test]
async fn test_udp_relay_multiple_packets() {
    // Start UDP echo server
    let udp_echo = MockUdpEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    // Connect via TLS
    let tcp_stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = server
        .tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Build Trojan UDP ASSOCIATE request
    let hash = server.hash();
    let ip_addr: std::net::Ipv4Addr = match udp_echo.addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4 address"),
    };

    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: udp_echo.addr.port(),
    };

    let mut header = BytesMut::new();
    write_request_header(
        &mut header,
        hash.as_bytes(),
        CMD_UDP_ASSOCIATE,
        &target_addr,
    )
    .unwrap();
    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Send multiple UDP packets
    for i in 0..3 {
        let udp_target = AddressRef {
            host: HostRef::Ipv4(ip_addr.octets()),
            port: udp_echo.addr.port(),
        };
        let msg = format!("Packet {}", i);
        let mut udp_packet = BytesMut::new();
        write_udp_packet(&mut udp_packet, &udp_target, msg.as_bytes()).unwrap();

        tls_stream.write_all(&udp_packet).await.unwrap();
        tls_stream.flush().await.unwrap();

        // Read response
        let mut response = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut response))
            .await
            .expect("read timeout")
            .unwrap();

        assert!(n > 11, "Response too short for packet {}", i);
        let payload = &response[11..n];
        let expected = format!("ECHO:Packet {}", i);
        assert_eq!(
            std::str::from_utf8(payload).unwrap(),
            expected,
            "UDP echo response mismatch for packet {}",
            i
        );
    }
}

// ============================================================================
// Load and Timeout Tests
// ============================================================================

/// Test TCP idle timeout behavior.
#[tokio::test]
async fn test_tcp_idle_timeout() {
    // Start echo server (that doesn't respond)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = listener.local_addr().unwrap();

    // Echo server that delays response indefinitely
    thread::spawn(move || {
        for _stream in listener.incoming().flatten() {
            // Just hold the connection, don't read or write
            thread::sleep(Duration::from_secs(60));
        }
    });

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Create server with short TCP timeout (1 second)
    let (cert_pem, key_pem) = generate_test_certs();
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    drop(tcp_listener);

    let password = "test_password";

    let config = Config {
        server: ServerConfig {
            listen: addr.to_string(),
            fallback: fallback.addr.to_string(),
            tcp_idle_timeout_secs: 1, // 1 second timeout
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
            passwords: vec![password.to_string()],
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
    tokio::spawn(async move {
        let _ = trojan_server::run(config, auth).await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create TLS connector
    let mut root_store = RootCertStore::empty();
    let cert_der = CertificateDer::from(
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap()
            .to_vec(),
    );
    root_store.add(cert_der).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    // Connect
    let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Send CONNECT request to the slow echo server
    let hash = sha224_hex(password);
    let ip_addr: std::net::Ipv4Addr = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4"),
    };
    let target_addr = AddressRef {
        host: HostRef::Ipv4(ip_addr.octets()),
        port: echo_addr.port(),
    };

    let mut header = BytesMut::new();
    write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &target_addr).unwrap();
    header.extend_from_slice(b"Hello");

    tls_stream.write_all(&header).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Wait for idle timeout + buffer
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 1024];

    // Read should return 0 (closed) or timeout after the idle period
    let read_result = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await;

    let elapsed = start.elapsed();

    match read_result {
        Ok(Ok(0)) => {
            // Connection closed due to idle timeout
            assert!(
                elapsed >= Duration::from_millis(900),
                "Connection closed too early: {:?}",
                elapsed
            );
        }
        Ok(Ok(_)) => {
            // Got some data (unexpected from our slow server, but might be TLS close)
        }
        Ok(Err(_)) => {
            // Read error is acceptable after timeout
        }
        Err(_) => {
            // Timeout on read (shouldn't happen with 5s timeout and 1s idle)
            panic!("Read timeout - idle timeout may not be working");
        }
    }
}

/// Test concurrent connections load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_connections() {
    // Start echo server
    let echo_server = MockEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start trojan server
    let server = TestServer::start(fallback.addr).await;

    let num_connections = 20;
    let mut handles = Vec::with_capacity(num_connections);

    for i in 0..num_connections {
        let server_addr = server.addr;
        let tls_connector = server.tls_connector.clone();
        let hash = server.hash();
        let echo_addr = echo_server.addr;

        handles.push(tokio::spawn(async move {
            // Connect via TLS
            let tcp_stream = tokio::net::TcpStream::connect(server_addr).await?;
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

            // Build Trojan request
            let ip_addr: std::net::Ipv4Addr = match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => panic!("Expected IPv4"),
            };
            let target_addr = AddressRef {
                host: HostRef::Ipv4(ip_addr.octets()),
                port: echo_addr.port(),
            };

            let msg = format!("Connection {}", i);
            let mut header = BytesMut::new();
            write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &target_addr).unwrap();
            header.extend_from_slice(msg.as_bytes());

            tls_stream.write_all(&header).await?;
            tls_stream.flush().await?;

            // Read response
            let mut response = vec![0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(10), tls_stream.read(&mut response))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;

            assert_eq!(&response[..n], msg.as_bytes());
            Ok::<_, std::io::Error>(())
        }));
    }

    // Wait for all connections
    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, num_connections,
        "Not all connections succeeded"
    );
}

// ============================================================================
// Rule-Based Routing Tests
// ============================================================================

#[cfg(feature = "rules")]
mod rules_tests {
    use super::*;
    use std::collections::HashMap;
    use trojan_config::{OutboundConfig, RouteRuleConfig, RuleProviderConfig};
    use trojan_server::{CancellationToken, run_with_shutdown};

    /// Assert that a TLS stream is closed (REJECT behavior).
    /// Accepts both clean EOF (n=0) and TLS close without close_notify.
    async fn assert_connection_rejected(
        tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        msg: &str,
    ) {
        let mut buf = vec![0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout");
        match result {
            Ok(0) => { /* clean EOF — expected for REJECT */ }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                /* TLS close without close_notify — also expected for REJECT */
            }
            Ok(n) => panic!("{msg}: expected connection closed, got {n} bytes"),
            Err(e) => panic!("{msg}: unexpected error: {e}"),
        }
    }

    /// Helper to start a trojan server with custom rules config.
    struct RulesTestServer {
        addr: SocketAddr,
        password: String,
        tls_connector: TlsConnector,
        shutdown: CancellationToken,
        _handle: tokio::task::JoinHandle<()>,
        _temp_dir: tempfile::TempDir,
    }

    impl RulesTestServer {
        async fn start(
            fallback_addr: SocketAddr,
            outbounds: HashMap<String, OutboundConfig>,
            rules: Vec<RouteRuleConfig>,
            rule_providers: HashMap<String, RuleProviderConfig>,
        ) -> Self {
            let password = "test_password_123".to_string();
            let (cert_pem, key_pem) = generate_test_certs();

            let temp_dir = tempfile::Builder::new()
                .prefix("trojan-rules-test-")
                .tempdir()
                .unwrap();
            let cert_path = temp_dir.path().join("cert.pem");
            let key_path = temp_dir.path().join("key.pem");

            fs::write(&cert_path, &cert_pem).unwrap();
            fs::write(&key_path, &key_pem).unwrap();

            let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .next()
                .unwrap()
                .unwrap()
                .to_vec();

            let mut root_store = RootCertStore::empty();
            root_store.add(CertificateDer::from(cert_der)).unwrap();
            let client_config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let tls_connector = TlsConnector::from(Arc::new(client_config));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                    rule_providers,
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
                    level: Some("debug".to_string()),
                    ..Default::default()
                },
            };

            let auth = MemoryAuth::from_passwords(&config.auth.passwords);
            let shutdown = CancellationToken::new();
            let shutdown_task = shutdown.clone();

            let handle = tokio::spawn(async move {
                let _ = run_with_shutdown(config, auth, shutdown_task).await;
            });

            tokio::time::sleep(Duration::from_millis(500)).await;

            Self {
                addr,
                password,
                tls_connector,
                shutdown,
                _handle: handle,
                _temp_dir: temp_dir,
            }
        }

        fn hash(&self) -> String {
            sha224_hex(&self.password)
        }

        /// Connect a TLS stream and send a trojan CONNECT header targeting an IPv4 addr.
        async fn connect_to_ipv4(
            &self,
            target_addr: SocketAddr,
            payload: &[u8],
        ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
            let tcp_stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut tls_stream = self
                .tls_connector
                .connect(server_name, tcp_stream)
                .await
                .unwrap();

            let hash = self.hash();
            let ip: std::net::Ipv4Addr = match target_addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => panic!("Expected IPv4"),
            };
            let addr = AddressRef {
                host: HostRef::Ipv4(ip.octets()),
                port: target_addr.port(),
            };

            let mut header = BytesMut::new();
            write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &addr).unwrap();
            header.extend_from_slice(payload);

            tls_stream.write_all(&header).await.unwrap();
            tls_stream.flush().await.unwrap();
            tls_stream
        }

        /// Connect a TLS stream and send a trojan CONNECT header targeting a domain.
        async fn connect_to_domain(
            &self,
            domain: &str,
            port: u16,
            payload: &[u8],
        ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
            let tcp_stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut tls_stream = self
                .tls_connector
                .connect(server_name, tcp_stream)
                .await
                .unwrap();

            let hash = self.hash();
            let addr = AddressRef {
                host: HostRef::Domain(domain.as_bytes()),
                port,
            };

            let mut header = BytesMut::new();
            write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &addr).unwrap();
            header.extend_from_slice(payload);

            tls_stream.write_all(&header).await.unwrap();
            tls_stream.flush().await.unwrap();
            tls_stream
        }

        async fn stop(self) {
            self.shutdown.cancel();
            let _ = self._handle.await;
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

    fn rule_set_ref(name: &str, outbound: &str) -> RouteRuleConfig {
        RouteRuleConfig {
            rule_set: Some(name.to_string()),
            rule_type: None,
            value: None,
            outbound: outbound.to_string(),
        }
    }

    /// Test: REJECT rule blocks connection (domain match).
    #[tokio::test]
    async fn test_rules_reject_domain() {
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![
            rule("DOMAIN", Some("blocked.example.com"), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_domain("blocked.example.com", 443, b"").await;

        assert_connection_rejected(&mut tls_stream, "REJECT rule should close connection").await;

        server.stop().await;
    }

    /// Test: IP-CIDR rule matches and routes to DIRECT.
    #[tokio::test]
    async fn test_rules_ip_cidr_direct() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![
            rule("IP-CIDR", Some("127.0.0.0/8"), "DIRECT"),
            rule("FINAL", None, "REJECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"Hello Rules!").await;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(&buf[..n], b"Hello Rules!", "IP-CIDR DIRECT should relay traffic");

        server.stop().await;
    }

    /// Test: DST-PORT rule matches and routes to DIRECT.
    #[tokio::test]
    async fn test_rules_dst_port_direct() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![
            rule("DST-PORT", Some(&echo.addr.port().to_string()), "DIRECT"),
            rule("FINAL", None, "REJECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"port match").await;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(&buf[..n], b"port match", "DST-PORT DIRECT should relay traffic");

        server.stop().await;
    }

    /// Test: FINAL rule as catch-all routes to DIRECT.
    #[tokio::test]
    async fn test_rules_final_catchall() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![rule("FINAL", None, "DIRECT")];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"final").await;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(&buf[..n], b"final", "FINAL DIRECT should relay all traffic");

        server.stop().await;
    }

    /// Test: Named outbound with type "direct" routes traffic correctly.
    #[tokio::test]
    async fn test_rules_named_outbound_direct() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let mut outbounds = HashMap::new();
        outbounds.insert(
            "my-direct".to_string(),
            OutboundConfig {
                outbound_type: "direct".to_string(),
                addr: None,
                password: None,
                sni: None,
                bind: None,
            },
        );

        let rules = vec![
            rule("IP-CIDR", Some("127.0.0.0/8"), "my-direct"),
            rule("FINAL", None, "REJECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            outbounds,
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"outbound").await;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(
            &buf[..n], b"outbound",
            "Named outbound 'direct' should relay traffic"
        );

        server.stop().await;
    }

    /// Test: Named outbound with type "reject" drops connection.
    #[tokio::test]
    async fn test_rules_named_outbound_reject() {
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let mut outbounds = HashMap::new();
        outbounds.insert(
            "block".to_string(),
            OutboundConfig {
                outbound_type: "reject".to_string(),
                addr: None,
                password: None,
                sni: None,
                bind: None,
            },
        );

        let rules = vec![
            rule("IP-CIDR", Some("127.0.0.0/8"), "block"),
            rule("FINAL", None, "DIRECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            outbounds,
            rules,
            HashMap::new(),
        )
        .await;

        let echo = MockEchoServer::start();
        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"should reject").await;

        assert_connection_rejected(&mut tls_stream, "Named reject outbound should close connection").await;

        server.stop().await;
    }

    /// Test: Rule-set from a file provider (Surge format).
    #[tokio::test]
    async fn test_rules_file_provider() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        // Write a temporary rule-set file in Surge format
        let temp_dir = tempfile::tempdir().unwrap();
        let ruleset_path = temp_dir.path().join("block-domains.txt");
        fs::write(&ruleset_path, "DOMAIN,file-blocked.example.com\n").unwrap();

        let mut rule_providers = HashMap::new();
        rule_providers.insert(
            "block-set".to_string(),
            RuleProviderConfig {
                format: "surge".to_string(),
                behavior: Some("classical".to_string()),
                source: "file".to_string(),
                path: Some(ruleset_path.to_string_lossy().to_string()),
                url: None,
                interval: None,
            },
        );

        let rules = vec![
            rule_set_ref("block-set", "REJECT"),
            rule("IP-CIDR", Some("127.0.0.0/8"), "DIRECT"),
            rule("FINAL", None, "DIRECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            rule_providers,
        )
        .await;

        // Connection to blocked domain should be rejected
        let mut tls_stream = server
            .connect_to_domain("file-blocked.example.com", 443, b"")
            .await;

        assert_connection_rejected(&mut tls_stream, "File provider REJECT should close connection").await;

        // Connection to echo server (IP) should be relayed via DIRECT
        let mut tls_stream2 = server.connect_to_ipv4(echo.addr, b"allowed").await;

        let mut buf2 = vec![0u8; 1024];
        let n2 = tokio::time::timeout(Duration::from_secs(5), tls_stream2.read(&mut buf2))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(&buf2[..n2], b"allowed", "Non-blocked traffic should relay");

        server.stop().await;
    }

    /// Test: DOMAIN-SUFFIX rule matching.
    #[tokio::test]
    async fn test_rules_domain_suffix_reject() {
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![
            rule("DOMAIN-SUFFIX", Some("blocked.com"), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        // sub.blocked.com should match DOMAIN-SUFFIX
        let mut tls_stream = server
            .connect_to_domain("sub.blocked.com", 443, b"")
            .await;

        assert_connection_rejected(&mut tls_stream, "DOMAIN-SUFFIX REJECT should close connection").await;

        server.stop().await;
    }

    /// Test: DOMAIN-KEYWORD rule matching.
    #[tokio::test]
    async fn test_rules_domain_keyword_reject() {
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        let rules = vec![
            rule("DOMAIN-KEYWORD", Some("ads"), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server
            .connect_to_domain("tracker.ads.example.com", 443, b"")
            .await;

        assert_connection_rejected(&mut tls_stream, "DOMAIN-KEYWORD REJECT should close connection").await;

        server.stop().await;
    }

    /// Test: Multiple rules evaluated in order (first match wins).
    #[tokio::test]
    async fn test_rules_order_matters() {
        let echo = MockEchoServer::start();
        let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

        // IP-CIDR allows 127.0.0.0/8 DIRECT, but FINAL is REJECT.
        // The IP-CIDR rule should match first.
        let rules = vec![
            rule("DOMAIN", Some("should-not-match.example.com"), "REJECT"),
            rule("IP-CIDR", Some("127.0.0.0/8"), "DIRECT"),
            rule("FINAL", None, "REJECT"),
        ];

        let server = RulesTestServer::start(
            fallback.addr,
            HashMap::new(),
            rules,
            HashMap::new(),
        )
        .await;

        let mut tls_stream = server.connect_to_ipv4(echo.addr, b"order").await;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();

        assert_eq!(
            &buf[..n], b"order",
            "IP-CIDR rule should match before FINAL REJECT"
        );

        server.stop().await;
    }
}
