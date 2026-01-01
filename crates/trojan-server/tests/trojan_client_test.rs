//! Integration tests using real trojan/trojan-go client.
//!
//! These tests verify compatibility with the original trojan implementation.
//! Requires trojan-go or trojan to be installed and available in PATH.
//!
//! Run with: cargo test --package trojan-server --test trojan_client_test -- --ignored --nocapture

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

// ============================================================================
// Test Certificates
// ============================================================================

fn generate_test_certs() -> (String, String) {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    (cert.pem(), key_pair.serialize_pem())
}

// ============================================================================
// Mock Echo Server (target server that trojan proxies to)
// ============================================================================

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

// ============================================================================
// Mock Fallback Server
// ============================================================================

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
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(response.as_bytes());
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
// Test Server (our trojan-rs server)
// ============================================================================

struct TestServer {
    addr: SocketAddr,
    password: String,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(fallback_addr: SocketAddr) -> Self {
        use trojan_auth::MemoryAuth;
        use trojan_config::{
            AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TlsConfig,
            WebSocketConfig,
        };

        let password = "test_password_123".to_string();
        let (cert_pem, key_pem) = generate_test_certs();

        // Create temp directory for certs
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

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
            },
            websocket: WebSocketConfig::default(),
            metrics: MetricsConfig { listen: None },
            logging: LoggingConfig {
                level: Some("debug".to_string()),
            },
        };

        let auth = MemoryAuth::from_passwords(&config.auth.passwords);

        // Spawn server in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            let _ = trojan_server::run(config_clone, auth).await;
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(200)).await;

        Self {
            addr,
            password,
            _temp_dir: temp_dir,
        }
    }
}

// ============================================================================
// Trojan Client Wrapper
// ============================================================================

enum TrojanClientType {
    TrojanGo,
    Trojan,
}

struct TrojanClient {
    process: Child,
    socks_addr: SocketAddr,
    _temp_dir: tempfile::TempDir,
}

impl TrojanClient {
    fn start(
        client_type: TrojanClientType,
        server_addr: SocketAddr,
        password: &str,
        cert_path: Option<&str>,
    ) -> Result<Self, String> {
        let temp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;

        // Find available port for SOCKS5 proxy
        let socks_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let socks_addr = socks_listener.local_addr().map_err(|e| e.to_string())?;
        drop(socks_listener);

        let process = match client_type {
            TrojanClientType::TrojanGo => {
                Self::start_trojan_go(&temp_dir, server_addr, socks_addr, password)?
            }
            TrojanClientType::Trojan => {
                Self::start_trojan(&temp_dir, server_addr, socks_addr, password, cert_path)?
            }
        };

        // Wait for client to start
        thread::sleep(Duration::from_secs(1));

        Ok(Self {
            process,
            socks_addr,
            _temp_dir: temp_dir,
        })
    }

    fn start_trojan_go(
        temp_dir: &tempfile::TempDir,
        server_addr: SocketAddr,
        socks_addr: SocketAddr,
        password: &str,
    ) -> Result<Child, String> {
        // Check if trojan-go is available
        if Command::new("trojan-go").arg("-version").output().is_err() {
            return Err("trojan-go not found in PATH".to_string());
        }

        // Create trojan-go client config
        let config = serde_json::json!({
            "run_type": "client",
            "local_addr": socks_addr.ip().to_string(),
            "local_port": socks_addr.port(),
            "remote_addr": server_addr.ip().to_string(),
            "remote_port": server_addr.port(),
            "password": [password],
            "ssl": {
                "verify": false,
                "sni": "localhost"
            }
        });

        let config_path = temp_dir.path().join("client.json");
        fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| e.to_string())?;

        Command::new("trojan-go")
            .arg("-config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())
    }

    fn start_trojan(
        temp_dir: &tempfile::TempDir,
        server_addr: SocketAddr,
        socks_addr: SocketAddr,
        password: &str,
        _cert_path: Option<&str>,
    ) -> Result<Child, String> {
        // Check if trojan is available
        if Command::new("trojan").arg("--version").output().is_err() {
            return Err("trojan not found in PATH".to_string());
        }

        // Create trojan client config
        let config = serde_json::json!({
            "run_type": "client",
            "local_addr": socks_addr.ip().to_string(),
            "local_port": socks_addr.port(),
            "remote_addr": server_addr.ip().to_string(),
            "remote_port": server_addr.port(),
            "password": [password],
            "ssl": {
                "verify": false,
                "verify_hostname": false,
                "sni": "localhost"
            }
        });

        let config_path = temp_dir.path().join("client.json");
        fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| e.to_string())?;

        Command::new("trojan")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())
    }

    /// Connect through the SOCKS5 proxy to target address
    fn connect_through_socks(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.socks_addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // SOCKS5 handshake
        // 1. Send greeting (version, num auth methods, auth methods)
        stream.write_all(&[0x05, 0x01, 0x00])?; // SOCKS5, 1 method, NO AUTH

        // 2. Read server response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response)?;
        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(std::io::Error::other("SOCKS5 auth failed"));
        }

        // 3. Send connect request
        let mut request = vec![0x05, 0x01, 0x00]; // SOCKS5, CONNECT, reserved
        match target {
            SocketAddr::V4(addr) => {
                request.push(0x01); // IPv4
                request.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                request.push(0x04); // IPv6
                request.extend_from_slice(&addr.ip().octets());
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request)?;

        // 4. Read connect response
        let mut response = [0u8; 10]; // Minimum response size for IPv4
        stream.read_exact(&mut response)?;
        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(std::io::Error::other(format!(
                "SOCKS5 connect failed: {:02x}",
                response[1]
            )));
        }

        Ok(stream)
    }
}

impl Drop for TrojanClient {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test CONNECT relay using trojan-go client.
/// This test is ignored by default because it requires trojan-go to be installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_with_trojan_go_client() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    // Start echo server (target)
    let echo_server = MockEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start our trojan server
    let server = TestServer::start(fallback.addr).await;

    // Start trojan-go client
    let client = match TrojanClient::start(
        TrojanClientType::TrojanGo,
        server.addr,
        &server.password,
        None,
    ) {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping test: {}", e);
            return;
        }
    };

    // Connect through SOCKS5 proxy to echo server
    let mut stream = client
        .connect_through_socks(echo_server.addr)
        .expect("SOCKS5 connect failed");

    // Send data and verify echo
    let message = b"Hello from trojan-go client!";
    stream.write_all(message).unwrap();
    stream.flush().unwrap();

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).expect("Failed to read response");

    assert_eq!(&response[..n], message);
}

/// Test CONNECT relay using original trojan client.
/// This test is ignored by default because it requires trojan to be installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_with_trojan_client() {
    // Start echo server (target)
    let echo_server = MockEchoServer::start();

    // Start fallback server
    let fallback = MockHttpServer::start("HTTP/1.1 200 OK\r\n\r\nFallback");

    // Start our trojan server
    let server = TestServer::start(fallback.addr).await;
    println!("Server started on {}", server.addr);

    // Start trojan client
    let client = match TrojanClient::start(
        TrojanClientType::Trojan,
        server.addr,
        &server.password,
        None,
    ) {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping test: {}", e);
            return;
        }
    };
    println!("Client SOCKS5 proxy on {}", client.socks_addr);

    // Connect through SOCKS5 proxy to echo server
    let mut stream = client.connect_through_socks(echo_server.addr).unwrap();

    // Send data
    let message = b"Hello from trojan client!";
    stream.write_all(message).unwrap();

    // Read echo response
    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).unwrap();

    assert_eq!(&response[..n], message);
    println!("Test passed: trojan client successfully connected through trojan-rs server");
}

/// Test that checks which trojan clients are available.
#[test]
fn check_available_clients() {
    println!("\nChecking available trojan clients:");

    if Command::new("trojan-go").arg("-version").output().is_ok() {
        println!("  trojan-go: FOUND");
    } else {
        println!(
            "  trojan-go: NOT FOUND (install with: go install github.com/p4gefau1t/trojan-go@latest)"
        );
    }

    if Command::new("trojan").arg("--version").output().is_ok() {
        println!("  trojan: FOUND");
    } else {
        println!("  trojan: NOT FOUND (install with: apt install trojan)");
    }

    println!(
        "\nTo run client tests: cargo test --package trojan-server --test trojan_client_test -- --ignored --nocapture"
    );
}
