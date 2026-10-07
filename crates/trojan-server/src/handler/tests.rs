use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Instant, sleep, timeout};
use trojan_auth::{AuthError, AuthResult, MemoryAuth, sha224_hex};
use trojan_proto::write_request_header;

pub(super) fn state() -> ServerState {
    ServerState {
        fallback_addr: "127.0.0.1:1".parse().unwrap(),
        max_udp_payload: 8192,
        max_udp_buffer_bytes: 65536,
        max_header_bytes: 8192,
        tcp_idle_timeout: Duration::from_secs(2),
        udp_idle_timeout: Duration::from_secs(2),
        fallback_pool: None,
        relay_buffer_size: 1024,
        tcp_send_buffer: 0,
        tcp_recv_buffer: 0,
        tcp_config: Default::default(),
        #[cfg(feature = "ws")]
        websocket: Default::default(),
        dns_resolver: trojan_dns::DnsResolver::new(&Default::default()).unwrap(),
        node_stats: Default::default(),
        proxy_protocol: Default::default(),
        per_target_metrics: false,
        #[cfg(feature = "analytics")]
        analytics: None,
        #[cfg(feature = "rules")]
        rule_engine: None,
        #[cfg(feature = "rules")]
        outbounds: Default::default(),
        #[cfg(feature = "geoip")]
        geoip_metrics: None,
        #[cfg(all(feature = "geoip", feature = "analytics"))]
        geoip_analytics: None,
    }
}

pub(super) fn connection() -> Connection {
    Connection {
        peer: "127.0.0.1:23456".parse().unwrap(),
        id: 1,
        chain: Default::default(),
        auth_deadline: Instant::now() + Duration::from_millis(200),
    }
}

pub(super) fn auth() -> Arc<MemoryAuth> {
    Arc::new(MemoryAuth::from_passwords(["secret"]))
}

pub(super) fn request(command: u8, address: SocketAddr) -> BytesMut {
    let mut buf = BytesMut::new();
    write_request_header(
        &mut buf,
        sha224_hex("secret").as_bytes(),
        command,
        &crate::resolve::address_from_socket(address),
    )
    .unwrap();
    buf
}

fn assert_timed_out(result: Result<(), ServerError>) {
    assert!(matches!(result, Err(ServerError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut));
}

#[tokio::test]
async fn empty_and_partial_headers_expire() {
    for prefix in [b"".as_slice(), b"abcdef"] {
        let (mut client, server) = duplex(1024);
        client.write_all(prefix).await.unwrap();
        let result = timeout(
            Duration::from_secs(2),
            handle_conn(server, Arc::new(state()), auth(), connection()),
        )
        .await
        .expect("unauthenticated stream must close");
        assert_timed_out(result);
    }
}

#[tokio::test]
async fn trickled_bytes_do_not_extend_authentication_deadline() {
    let (mut client, server) = duplex(1024);
    let conn = connection();
    let deadline = conn.auth_deadline;
    let task = tokio::spawn(handle_conn(server, Arc::new(state()), auth(), conn));
    let writer = tokio::spawn(async move {
        loop {
            if client.write_all(b"a").await.is_err() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    });
    assert_timed_out(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(Instant::now() < deadline + Duration::from_millis(500));
    writer.await.unwrap();
}

struct PendingAuth;

#[async_trait::async_trait]
impl AuthBackend for PendingAuth {
    async fn verify(&self, _: &str) -> Result<AuthResult, AuthError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn authentication_backend_shares_the_header_deadline() {
    let (mut client, server) = duplex(1024);
    client
        .write_all(&request(CMD_CONNECT, "127.0.0.1:80".parse().unwrap()))
        .await
        .unwrap();
    assert_timed_out(
        timeout(
            Duration::from_secs(2),
            handle_conn(
                server,
                Arc::new(state()),
                Arc::new(PendingAuth),
                connection(),
            ),
        )
        .await
        .unwrap(),
    );
}

#[tokio::test]
async fn authenticated_relay_outlives_authentication_deadline() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(handle_conn(server, Arc::new(state()), auth(), connection()));
    client
        .write_all(&request(CMD_CONNECT, target.local_addr().unwrap()))
        .await
        .unwrap();
    let (mut target, _) = timeout(Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    client.write_all(b"still connected").await.unwrap();
    let mut payload = [0; 15];
    timeout(Duration::from_secs(2), target.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload, b"still connected");
    client.shutdown().await.unwrap();
    target.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(feature = "ws")]
#[tokio::test(start_paused = true)]
async fn websocket_upgrade_does_not_reset_authentication_deadline() {
    for split in [false, true] {
        let mut state = state();
        state.websocket.enabled = true;
        let (client, server) = duplex(4096);
        let conn = connection();
        let deadline = conn.auth_deadline;
        let task = tokio::spawn(async move {
            if split {
                handle_ws_only(server, Arc::new(state), auth(), conn).await
            } else {
                handle_conn(server, Arc::new(state), auth(), conn).await
            }
        });
        sleep(Duration::from_millis(100)).await;
        let (_ws, _) = tokio_tungstenite::client_async("ws://localhost/", client)
            .await
            .unwrap();
        assert_timed_out(
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(Instant::now() < deadline + Duration::from_millis(80));
    }
}

#[cfg(feature = "ws")]
#[tokio::test]
async fn incomplete_websocket_upgrade_expires_on_both_listeners() {
    for split in [false, true] {
        let mut state = state();
        state.websocket.enabled = true;
        let (mut client, server) = duplex(1024);
        client.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
        let task = async {
            if split {
                handle_ws_only(server, Arc::new(state), auth(), connection()).await
            } else {
                handle_conn(server, Arc::new(state), auth(), connection()).await
            }
        };
        assert_timed_out(timeout(Duration::from_secs(2), task).await.unwrap());
    }
}
