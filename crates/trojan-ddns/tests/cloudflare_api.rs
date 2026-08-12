//! End-to-end tests for the Cloudflare DDNS updater.
//!
//! Previously untestable: the updater hardcoded Cloudflare's production
//! endpoint, so exercising it meant making real API calls. `api_base_url`
//! makes it injectable, and the `cloudflare` crate documents
//! `Environment::Custom` for exactly this.
//!
//! These drive the updater against a stand-in API. They deliberately assert on
//! request shape and error handling rather than a successful update: the
//! crate's `Zone` type has around twenty required fields with nested
//! structures, and a hand-written fixture for it would break on any upstream
//! schema change while testing the crate's deserialiser more than our code.
#![cfg(feature = "updater")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use trojan_ddns::CloudflareDdnsConfig;
use trojan_ddns::{CloudflareUpdater, DdnsError};

/// One request as the stand-in API saw it.
#[derive(Clone, Debug)]
struct SeenRequest {
    method: String,
    target: String,
    authorization: Option<String>,
}

/// A stand-in Cloudflare API returning a fixed body to every request.
struct MockCloudflare {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    _handle: thread::JoinHandle<()>,
}

impl MockCloudflare {
    fn start(status: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);

        let handle = thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || {
                    let _ = Self::serve(stream, &recorded, status, body);
                });
            }
        });

        Self {
            addr,
            seen,
            _handle: handle,
        }
    }

    fn serve(
        mut stream: std::net::TcpStream,
        recorded: &Mutex<Vec<SeenRequest>>,
        status: &str,
        body: &str,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);

        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        let mut content_length = 0usize;
        let mut authorization = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                } else if name.eq_ignore_ascii_case("authorization") {
                    authorization = Some(value.trim().to_string());
                }
            }
        }
        if content_length > 0 {
            let mut discard = vec![0u8; content_length];
            reader.read_exact(&mut discard)?;
        }

        recorded.lock().unwrap().push(SeenRequest {
            method,
            target,
            authorization,
        });

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}

fn config_for(addr: SocketAddr) -> CloudflareDdnsConfig {
    CloudflareDdnsConfig {
        api_token: "test-token".to_string(),
        zone: "example.com".to_string(),
        records: vec!["home.example.com".to_string()],
        proxied: false,
        ttl: 1,
        api_base_url: Some(format!("http://{addr}")),
    }
}

/// Empty envelope: a valid response that simply lists no zones.
const NO_ZONES: &str = r#"{"result":[],"success":true,"errors":[],"messages":[]}"#;

/// Error envelope in Cloudflare's documented shape.
const API_ERROR: &str = r#"{"result":null,"success":false,"errors":[{"code":9103,"message":"Invalid API token"}],"messages":[]}"#;

/// `api_base_url` is honoured, and the zone lookup is a bearer-authenticated
/// GET against the configured host.
///
/// Without the override this could only ever have talked to Cloudflare, so
/// this is the assertion that makes the rest of the path testable at all.
#[tokio::test]
async fn updater_queries_the_configured_endpoint() {
    let api = MockCloudflare::start("200 OK", NO_ZONES);
    let mut updater = CloudflareUpdater::new(&config_for(api.addr)).expect("build updater");

    // No zone matches, so this fails — the point is where it went first.
    let result = updater.update("203.0.113.7".parse().unwrap()).await;
    assert!(
        matches!(result, Err(DdnsError::ZoneNotFound(ref zone)) if zone == "example.com"),
        "expected the configured zone to be reported missing, got {result:?}"
    );

    let seen = api.seen.lock().unwrap().clone();
    let first = seen.first().expect("the updater never called the API");
    assert_eq!(first.method, "GET");
    assert!(
        first.target.contains("/zones"),
        "expected a zone lookup, got {:?}",
        first.target
    );
    assert!(
        first.target.contains("example.com"),
        "zone lookup did not name the configured zone: {:?}",
        first.target
    );
    assert_eq!(
        first.authorization.as_deref(),
        Some("Bearer test-token"),
        "the configured API token was not presented"
    );
}

/// An API error is surfaced rather than swallowed.
#[tokio::test]
async fn updater_surfaces_api_errors() {
    let api = MockCloudflare::start("403 Forbidden", API_ERROR);
    let mut updater = CloudflareUpdater::new(&config_for(api.addr)).expect("build updater");

    let result = updater.update("203.0.113.7".parse().unwrap()).await;
    let err = result.expect_err("a rejected token must not look like success");
    assert!(
        matches!(err, DdnsError::Cloudflare(_)),
        "expected a Cloudflare error, got {err:?}"
    );
    assert!(
        err.to_string().contains("list zones"),
        "the error should say which call failed, got {err}"
    );
}

/// IPv6 updates take the same path, so a regression in one is not masked by
/// the other still working.
#[tokio::test]
async fn updater_queries_the_endpoint_for_ipv6_too() {
    let api = MockCloudflare::start("200 OK", NO_ZONES);
    let mut updater = CloudflareUpdater::new(&config_for(api.addr)).expect("build updater");

    let result = updater.update("2001:db8::1".parse().unwrap()).await;
    assert!(matches!(result, Err(DdnsError::ZoneNotFound(_))));

    // Give the mock thread a moment to record before asserting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !api.seen.lock().unwrap().is_empty(),
        "the IPv6 path never called the API"
    );
}
