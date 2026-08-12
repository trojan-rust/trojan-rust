//! End-to-end tests for the SQL authentication backend.
//!
//! `trojan-auth` tests `SqlAuth` thoroughly against sqlite, but always in
//! isolation — nothing drove it through a running server. These do, so the
//! business rules that gate a connection (disabled, expired, over quota) are
//! checked where they actually take effect: on the wire.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use trojan_auth::{
    sha224_hex,
    sql::{SqlAuth, SqlAuthConfig, TrafficRecordingMode},
};
use trojan_config::{
    AnalyticsConfig, AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig,
    TlsConfig, WebSocketConfig,
};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};
use trojan_server::{CancellationToken, run_with_shutdown};

#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs crypto provider");
}

fn generate_test_certs() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

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
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            break;
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

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().cast_signed())
        .unwrap_or(0)
}

/// A user row as the server will see it.
struct SeedUser {
    password: &'static str,
    enabled: bool,
    expires_at: i64,
    traffic_limit: i64,
    traffic_used: i64,
}

/// Build a sqlite-backed `SqlAuth` seeded with `users`.
///
/// A file-backed database rather than `:memory:`, because sqlx hands out a
/// pool and an in-memory database is private to a single connection.
async fn seeded_sql_auth(db_path: &std::path::Path, users: &[SeedUser]) -> SqlAuth {
    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    let auth = SqlAuth::connect(
        SqlAuthConfig::new(&url)
            .max_connections(4)
            .traffic_mode(TrafficRecordingMode::Immediate),
    )
    .await
    .expect("connect sqlite");

    let pool = auth.pool();
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS trojan_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL UNIQUE,
            user_id TEXT,
            traffic_limit INTEGER NOT NULL DEFAULT 0,
            traffic_used INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create schema");

    for user in users {
        sqlx::query(
            "INSERT INTO trojan_users (password_hash, user_id, traffic_limit, traffic_used, expires_at, enabled)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(sha224_hex(user.password))
        .bind(user.password)
        .bind(user.traffic_limit)
        .bind(user.traffic_used)
        .bind(user.expires_at)
        .bind(i32::from(user.enabled))
        .execute(pool)
        .await
        .expect("seed user");
    }

    auth
}

struct TestServer {
    addr: SocketAddr,
    tls_connector: TlsConnector,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(users: &[SeedUser]) -> Self {
        let (cert_pem, key_pem) = generate_test_certs();
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-sql-auth-")
            .tempdir()
            .unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let auth = seeded_sql_auth(&temp_dir.path().join("auth.db"), users).await;

        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der)).unwrap();
        let tls_connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let fallback = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        drop(fallback);

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
                proxy_protocol: Default::default(),
            },
            tls: TlsConfig {
                cert: cert_path.to_string_lossy().into_owned(),
                key: key_path.to_string_lossy().into_owned(),
                alpn: vec![],
                min_version: "tls12".to_string(),
                max_version: "tls13".to_string(),
                client_ca: None,
                cipher_suites: vec![],
            },
            // Empty: every decision must come from the database.
            auth: AuthConfig::default(),
            websocket: WebSocketConfig::default(),
            metrics: MetricsConfig {
                listen: None,
                ..Default::default()
            },
            analytics: AnalyticsConfig::default(),
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
            dns: Default::default(),
            ddns: Default::default(),
        };

        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let handle = tokio::spawn(async move {
            let _ = run_with_shutdown(config, auth, token).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            addr,
            tls_connector,
            shutdown,
            _handle: handle,
            _temp_dir: temp_dir,
        }
    }

    /// Attempt a relay; `Ok` means the payload came back.
    async fn try_relay(&self, password: &str, target: SocketAddr) -> std::io::Result<()> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await?;
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = self.tls_connector.connect(name, tcp).await?;

        let ip = match target.ip() {
            std::net::IpAddr::V4(v4) => v4,
            other => panic!("expected IPv4 target, got {other}"),
        };
        let address = AddressRef {
            host: HostRef::Ipv4(ip.octets()),
            port: target.port(),
        };
        let mut header = BytesMut::new();
        write_request_header(
            &mut header,
            sha224_hex(password).as_bytes(),
            CMD_CONNECT,
            &address,
        )
        .unwrap();
        let payload = b"sql-auth-probe";
        header.extend_from_slice(payload);

        tls.write_all(&header).await?;
        tls.flush().await?;

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay timeout"))??;
        assert_eq!(&echoed[..], payload);
        // Close cleanly, matching how a well-behaved client ends a session.
        // Aborted sessions are accounted for too — see
        // `http_auth_reports_traffic_after_abrupt_disconnect`.
        tls.shutdown().await?;
        Ok(())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The database decides who gets through.
///
/// One valid user and four that must each be refused for a different reason.
/// Checking only the happy path would pass against a backend that accepted
/// everything, and checking only rejections would pass against one that
/// accepted nothing.
#[tokio::test]
async fn sql_auth_enforces_user_state() {
    let echo = MockEchoServer::start();
    let server = TestServer::start(&[
        SeedUser {
            password: "valid-user",
            enabled: true,
            expires_at: 0,
            traffic_limit: 0,
            traffic_used: 0,
        },
        SeedUser {
            password: "disabled-user",
            enabled: false,
            expires_at: 0,
            traffic_limit: 0,
            traffic_used: 0,
        },
        SeedUser {
            password: "expired-user",
            enabled: true,
            expires_at: now_unix() - 3600,
            traffic_limit: 0,
            traffic_used: 0,
        },
        SeedUser {
            password: "over-quota-user",
            enabled: true,
            expires_at: 0,
            traffic_limit: 1_000,
            traffic_used: 2_000,
        },
    ])
    .await;

    server
        .try_relay("valid-user", echo.addr)
        .await
        .expect("a valid user must be relayed");

    for (password, reason) in [
        ("disabled-user", "disabled"),
        ("expired-user", "expired"),
        ("over-quota-user", "over its traffic limit"),
        ("never-inserted", "absent from the database"),
    ] {
        server
            .try_relay(password, echo.addr)
            .await
            .expect_err(&format!("a user that is {reason} must not be relayed"));
    }
}

/// A user still under quota is relayed, and the bytes are persisted.
///
/// `TrafficRecordingMode::Immediate` writes on connection close, so the row
/// must reflect the transfer without waiting on a batch timer.
#[tokio::test]
async fn sql_auth_persists_traffic() {
    let echo = MockEchoServer::start();
    let server = TestServer::start(&[SeedUser {
        password: "billed-user",
        enabled: true,
        expires_at: 0,
        traffic_limit: 1_000_000,
        traffic_used: 0,
    }])
    .await;

    server
        .try_relay("billed-user", echo.addr)
        .await
        .expect("relay should succeed");

    // Traffic is recorded once the relay ends; poll rather than sleep blindly.
    // A second `SqlAuth` over the same file gives a pool with the Any drivers
    // already installed.
    let db = server._temp_dir.path().join("auth.db");
    let verifier = SqlAuth::connect(SqlAuthConfig::new(format!(
        "sqlite://{}?mode=rwc",
        db.display()
    )))
    .await
    .expect("reopen sqlite");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let used: i64 =
            sqlx::query_scalar("SELECT traffic_used FROM trojan_users WHERE user_id = ?")
                .bind("billed-user")
                .fetch_one(verifier.pool())
                .await
                .expect("read traffic_used");
        if used > 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relayed bytes were never persisted to the database"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
