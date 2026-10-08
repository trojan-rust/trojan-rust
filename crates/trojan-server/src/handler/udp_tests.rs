use super::tests::{auth, connection, request, state};
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trojan_proto::write_udp_packet;

#[tokio::test]
async fn udp_write_backpressure_does_not_block_uploads_or_idle_expiry() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = crate::resolve::address_from_socket(target.local_addr().unwrap());
    let mut initial = request(CMD_UDP_ASSOCIATE, "0.0.0.0:0".parse().unwrap());
    write_udp_packet(&mut initial, &address, b"first").unwrap();
    let mut state = state();
    state.udp_idle_timeout = Duration::from_millis(500);
    let state = Arc::new(state);
    let (mut client, server) = duplex(64);
    let task = tokio::spawn(handle_trojan_stream(
        server,
        initial,
        state.clone(),
        auth(),
        connection(),
    ));
    let mut packet = [0; 64];
    let (_, source) = timeout(Duration::from_secs(2), target.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    target.send_to(&[0x31; 4096], source).await.unwrap();
    // Observe the first response byte before leaving the write direction blocked.
    timeout(Duration::from_secs(2), client.read_u8())
        .await
        .unwrap()
        .unwrap();
    let mut next = BytesMut::new();
    write_udp_packet(&mut next, &address, b"next").unwrap();
    client.write_all(&next).await.unwrap();
    let (size, _) = timeout(Duration::from_millis(300), target.recv_from(&mut packet))
        .await
        .expect("a blocked response must not stop client datagrams")
        .unwrap();
    assert_eq!(&packet[..size], b"next");
    timeout(Duration::from_secs(2), task)
        .await
        .expect("idle expiry must cancel a blocked response")
        .unwrap()
        .unwrap();
    let mut remaining = Vec::new();
    client.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(
        state.node_stats.snapshot().bytes_out,
        (remaining.len() + 1) as u64
    );
    assert!(!remaining.is_empty());
}

#[tokio::test]
async fn stalled_udp_dns_does_not_block_another_destination() {
    use trojan_dns::{DnsConfig, DnsResolver, DnsStrategy};
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut state = state();
    state.dns_resolver = DnsResolver::new(&DnsConfig {
        strategy: DnsStrategy::Custom,
        servers: vec![format!("udp://{}", dns.local_addr().unwrap())],
        ..Default::default()
    })
    .unwrap();
    state.udp_idle_timeout = Duration::from_secs(1);
    let mut initial = request(CMD_UDP_ASSOCIATE, "0.0.0.0:0".parse().unwrap());
    write_udp_packet(
        &mut initial,
        &trojan_proto::AddressRef {
            host: trojan_proto::HostRef::Domain(b"stalled.example"),
            port: 53,
        },
        b"waiting",
    )
    .unwrap();
    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(handle_trojan_stream(
        server,
        initial,
        Arc::new(state),
        auth(),
        connection(),
    ));
    let mut packet = [0; 512];
    timeout(Duration::from_secs(2), dns.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    let mut next = BytesMut::new();
    write_udp_packet(
        &mut next,
        &crate::resolve::address_from_socket(target.local_addr().unwrap()),
        b"independent",
    )
    .unwrap();
    client.write_all(&next).await.unwrap();
    let (size, _) = timeout(Duration::from_millis(500), target.recv_from(&mut packet))
        .await
        .expect("an unresolved destination must not block an IP datagram")
        .unwrap();
    assert_eq!(&packet[..size], b"independent");
    timeout(Duration::from_secs(3), task)
        .await
        .expect("idle expiry must cancel DNS work")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn coalesced_udp_frame_is_forwarded_and_counted_without_another_read() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = crate::resolve::address_from_socket(target.local_addr().unwrap());
    let mut frame = BytesMut::new();
    write_udp_packet(&mut frame, &address, b"first").unwrap();
    let mut initial = request(CMD_UDP_ASSOCIATE, "0.0.0.0:0".parse().unwrap());
    initial.extend_from_slice(&frame);
    let state = Arc::new(state());
    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(handle_trojan_stream(
        server,
        initial,
        state.clone(),
        auth(),
        connection(),
    ));

    let mut packet = [0; 64];
    let (n, source) = timeout(Duration::from_secs(2), target.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..n], b"first");
    target.send_to(b"reply", source).await.unwrap();
    let mut expected = BytesMut::new();
    write_udp_packet(&mut expected, &address, b"reply").unwrap();
    let mut reply = vec![0; expected.len()];
    timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, expected);
    client.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let snapshot = state.node_stats.snapshot();
    assert_eq!(snapshot.bytes_in, frame.len() as u64);
    assert_eq!(snapshot.bytes_out, expected.len() as u64);
}

#[tokio::test]
async fn coalesced_udp_frame_obeys_buffer_limit() {
    let mut state = state();
    state.max_udp_buffer_bytes = 8;
    let mut initial = request(CMD_UDP_ASSOCIATE, "0.0.0.0:0".parse().unwrap());
    write_udp_packet(
        &mut initial,
        &crate::resolve::address_from_socket("127.0.0.1:9".parse().unwrap()),
        b"oversized",
    )
    .unwrap();
    let (_client, server) = duplex(1024);
    let result = timeout(
        Duration::from_secs(2),
        handle_trojan_stream(server, initial, Arc::new(state), auth(), connection()),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(ServerError::Config(_))));
}

#[cfg(feature = "rules")]
#[tokio::test]
async fn udp_routes_each_frame_and_never_leaks_rejected_or_unsupported_routes() {
    use trojan_rules::{Action, HotRuleEngine, RuleEngineBuilder, rule::ParsedRule};

    for rule in ["port", "ip", "domain", "bound", "unknown", "reject"] {
        let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut state = state();
        let mut rules = RuleEngineBuilder::new();
        // The association header is rejected, but only datagram destinations govern UDP routing.
        rules.add_inline_rule(ParsedRule::DstPort(0), Action::Reject);
        rules.add_inline_rule(
            ParsedRule::DstPort(allowed.local_addr().unwrap().port()),
            Action::Direct,
        );
        let (matcher, action) = match rule {
            "ip" => (
                ParsedRule::IpCidr("127.0.0.0/8".parse().unwrap()),
                Action::Reject,
            ),
            "domain" => (ParsedRule::Domain("localhost".into()), Action::Reject),
            "port" => (
                ParsedRule::DstPort(denied.local_addr().unwrap().port()),
                Action::Reject,
            ),
            name => (
                ParsedRule::DstPort(denied.local_addr().unwrap().port()),
                Action::Outbound(name.into()),
            ),
        };
        rules.add_inline_rule(matcher, action);
        rules.set_final(Action::Direct);
        state.rule_engine = Some(Arc::new(HotRuleEngine::new(rules.build().unwrap())));
        state.outbounds.insert(
            "bound".into(),
            Arc::new(crate::outbound::Outbound::Direct {
                bind: Some("127.0.0.1".parse().unwrap()),
            }),
        );
        state
            .outbounds
            .insert("reject".into(), Arc::new(crate::outbound::Outbound::Reject));
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(handle_conn(server, Arc::new(state), auth(), connection()));
        let mut first = request(CMD_UDP_ASSOCIATE, "0.0.0.0:0".parse().unwrap());
        let mut address = crate::resolve::address_from_socket(denied.local_addr().unwrap());
        if rule == "domain" {
            address.host = trojan_proto::HostRef::Domain(b"localhost");
        }
        write_udp_packet(&mut first, &address, b"must not arrive").unwrap();
        client.write_all(&first).await.unwrap();
        let mut next = BytesMut::new();
        write_udp_packet(
            &mut next,
            &crate::resolve::address_from_socket(allowed.local_addr().unwrap()),
            b"allowed",
        )
        .unwrap();
        client.write_all(&next).await.unwrap();
        let mut packet = [0; 64];
        let (n, _) = timeout(Duration::from_secs(2), allowed.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..n], b"allowed", "{rule}");
        assert!(
            timeout(Duration::from_millis(50), denied.recv_from(&mut packet))
                .await
                .is_err(),
            "{rule}"
        );
        client.shutdown().await.unwrap();
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
