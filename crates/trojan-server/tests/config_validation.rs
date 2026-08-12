//! A server refuses to start on a config that does not pass validation.
//!
//! The checks used to live in the CLI, so only a config read from a file was
//! ever seen by them. The panel agent deserializes a config the panel pushed
//! and starts the server directly, which meant a bad value from the panel
//! produced a node that came up and then behaved wrongly — a zero idle
//! timeout closing every association at once, a header limit no request could
//! fit under. These pin the checks to the start path itself, where no caller
//! can route around them.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use trojan_auth::MemoryAuth;
use trojan_config::{
    AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig, TlsConfig,
    TlsVersion, WebSocketConfig,
};
use trojan_server::{CancellationToken, ServerError, run_with_shutdown};

/// A config that passes validation, for a test to then spoil one field of.
fn valid_config() -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            fallback: "127.0.0.1:1".to_string(),
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
            // Never read: validation runs before any certificate is loaded.
            cert: "/nonexistent/cert.pem".to_string(),
            key: "/nonexistent/key.pem".to_string(),
            alpn: vec![],
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            client_ca: None,
            cipher_suites: vec![],
        },
        auth: AuthConfig {
            passwords: vec!["pw".to_string()],
            users: vec![],
            ..Default::default()
        },
        websocket: WebSocketConfig::default(),
        metrics: MetricsConfig {
            listen: None,
            ..Default::default()
        },
        analytics: Default::default(),
        logging: LoggingConfig::default(),
        dns: Default::default(),
        ddns: Default::default(),
    }
}

/// Start a server on `config` and return how it refused, failing if it did not.
async fn rejection_of(config: Config) -> String {
    let auth = MemoryAuth::from_passwords(&config.auth.passwords);
    let result = run_with_shutdown(config, auth, CancellationToken::new()).await;

    match result {
        Err(ServerError::Config(message)) => message,
        Err(other) => panic!("expected a config error, got {other}"),
        Ok(()) => panic!("the server accepted a config validation rejects"),
    }
}

/// Zero here makes the idle timer fire immediately, so every connection would
/// be closed the moment it was accepted.
#[tokio::test]
async fn a_zero_udp_timeout_is_refused() {
    let mut config = valid_config();
    config.server.udp_timeout_secs = 0;

    let message = rejection_of(config).await;

    assert!(
        message.contains("udp_timeout_secs"),
        "the error should name the offending field, got: {message}"
    );
}

/// Below the minimum, no trojan request can ever fit, so every connection
/// would silently fall through to the fallback target.
#[tokio::test]
async fn a_header_limit_under_the_minimum_is_refused() {
    let mut config = valid_config();
    config.server.max_header_bytes = 8;

    let message = rejection_of(config).await;

    assert!(
        message.contains("max_header_bytes"),
        "the error should name the offending field, got: {message}"
    );
}

/// A buffer that cannot hold one maximum-sized packet trips its own limit on
/// every packet that arrives.
#[tokio::test]
async fn a_udp_buffer_smaller_than_a_packet_is_refused() {
    let mut config = valid_config();
    config.server.max_udp_buffer_bytes = config.server.max_udp_payload;

    let message = rejection_of(config).await;

    assert!(
        message.contains("max_udp_buffer_bytes"),
        "the error should name the offending field, got: {message}"
    );
}

/// The version range is the one TLS setting the type cannot rule out on its
/// own — both ends are valid versions, only their order is wrong.
#[tokio::test]
async fn an_inverted_tls_version_range_is_refused() {
    let mut config = valid_config();
    config.tls.min_version = TlsVersion::Tls13;
    config.tls.max_version = TlsVersion::Tls12;

    let message = rejection_of(config).await;

    assert!(
        message.contains("min_version"),
        "the error should name the offending field, got: {message}"
    );
}

/// The guard is worth nothing if a good config cannot get past it, so check
/// the fixture itself reaches the next stage — loading the certificate that
/// deliberately is not there.
#[tokio::test]
async fn a_valid_config_gets_past_validation() {
    let config = valid_config();
    let auth = MemoryAuth::from_passwords(&config.auth.passwords);

    let result = run_with_shutdown(config, auth, CancellationToken::new()).await;

    assert!(
        matches!(result, Err(ServerError::TlsMaterial(_))),
        "expected the missing certificate to be what stops it, got {result:?}"
    );
}
