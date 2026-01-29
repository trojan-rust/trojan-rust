//! Connection handlers for TCP CONNECT and UDP ASSOCIATE.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;
use trojan_core::defaults::{
    DEFAULT_RELAY_BUFFER_SIZE, DEFAULT_TCP_TIMEOUT_SECS, DEFAULT_UDP_TIMEOUT_SECS,
};
use trojan_core::io::{NoOpMetrics, relay_bidirectional};
use trojan_proto::{
    AddressRef, CMD_CONNECT, CMD_UDP_ASSOCIATE, ParseResult, parse_udp_packet,
    write_request_header, write_udp_packet,
};

use crate::connector::ClientState;
use crate::error::ClientError;
use crate::socks5::handshake::{
    self, REPLY_ADDRESS_TYPE_NOT_SUPPORTED, REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_NOT_ALLOWED, REPLY_CONNECTION_REFUSED, REPLY_GENERAL_FAILURE,
    REPLY_HOST_UNREACHABLE, REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED, REPLY_TTL_EXPIRED,
    Socks5Request, send_reply, send_reply_unspecified,
};
use crate::socks5::udp::{parse_socks5_udp, write_socks5_udp};

/// Handle a single SOCKS5 client connection.
pub async fn handle_socks5_conn(mut stream: TcpStream, peer: SocketAddr, state: Arc<ClientState>) {
    if let Err(e) = handle_socks5_conn_inner(&mut stream, peer, &state).await {
        debug!(peer = %peer, error = %e, "connection error");
    }
}

async fn handle_socks5_conn_inner(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &ClientState,
) -> Result<(), ClientError> {
    // SOCKS5 method negotiation
    handshake::negotiate_method(stream).await?;

    // Read SOCKS5 request
    let request = match handshake::read_request(stream).await {
        Ok(req) => req,
        Err(crate::error::Socks5Error::UnsupportedAddressType(atyp)) => {
            let _ = send_reply_unspecified(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await;
            return Err(crate::error::Socks5Error::UnsupportedAddressType(atyp).into());
        }
        Err(e) => return Err(e.into()),
    };

    match request.command {
        handshake::CMD_CONNECT => handle_connect(stream, &request, state).await,
        handshake::CMD_UDP_ASSOCIATE => handle_udp_associate(stream, peer, state).await,
        cmd => {
            let _ = send_reply_unspecified(stream, REPLY_COMMAND_NOT_SUPPORTED).await;
            Err(crate::error::Socks5Error::UnsupportedCommand(cmd).into())
        }
    }
}

/// Handle TCP CONNECT command.
async fn handle_connect(
    stream: &mut TcpStream,
    request: &Socks5Request,
    state: &ClientState,
) -> Result<(), ClientError> {
    let address = match request.to_address_ref() {
        Some(addr) => addr,
        None => {
            let _ = send_reply_unspecified(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await;
            return Err(crate::error::Socks5Error::UnsupportedAddressType(request.atyp).into());
        }
    };

    debug!(target = %format_address(&address), "CONNECT");

    // Connect to trojan server over TLS
    let mut tls_stream = match state.connect().await {
        Ok(s) => s,
        Err(e) => {
            let reply = reply_code_for_connect_error(&e);
            let _ = send_reply_unspecified(stream, reply).await;
            return Err(e);
        }
    };

    // Build and send Trojan request header (optionally coalesced with initial payload)
    let mut payload_buf = vec![0u8; DEFAULT_RELAY_BUFFER_SIZE];
    let mut payload_len = 0usize;
    match stream.try_read(&mut payload_buf) {
        Ok(0) => {}
        Ok(n) => payload_len = n,
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => {
            let _ = send_reply_unspecified(stream, REPLY_GENERAL_FAILURE).await;
            return Err(e.into());
        }
    }

    let mut header_buf = BytesMut::with_capacity(128 + payload_len);
    if let Err(e) = write_request_header(
        &mut header_buf,
        state.hash_hex.as_bytes(),
        CMD_CONNECT,
        &address,
    ) {
        let _ = send_reply_unspecified(stream, REPLY_GENERAL_FAILURE).await;
        return Err(e.into());
    }
    if payload_len > 0 {
        header_buf.extend_from_slice(&payload_buf[..payload_len]);
    }
    if let Err(e) = tls_stream.write_all(&header_buf).await {
        let _ = send_reply_unspecified(stream, REPLY_GENERAL_FAILURE).await;
        return Err(e.into());
    }

    // Send SOCKS5 success reply
    send_reply_unspecified(stream, REPLY_SUCCEEDED).await?;

    // Bidirectional relay
    let idle_timeout = Duration::from_secs(DEFAULT_TCP_TIMEOUT_SECS);
    relay_bidirectional(
        stream,
        tls_stream,
        idle_timeout,
        DEFAULT_RELAY_BUFFER_SIZE,
        &NoOpMetrics,
    )
    .await?;

    Ok(())
}

fn reply_code_for_connect_error(error: &ClientError) -> u8 {
    match error {
        ClientError::Resolve(_) => REPLY_HOST_UNREACHABLE,
        ClientError::Io(err) => match err.kind() {
            ErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
            ErrorKind::NetworkUnreachable => REPLY_NETWORK_UNREACHABLE,
            ErrorKind::HostUnreachable => REPLY_HOST_UNREACHABLE,
            ErrorKind::PermissionDenied => REPLY_CONNECTION_NOT_ALLOWED,
            ErrorKind::TimedOut => REPLY_TTL_EXPIRED,
            ErrorKind::AddrNotAvailable => REPLY_HOST_UNREACHABLE,
            _ => REPLY_GENERAL_FAILURE,
        },
        _ => REPLY_GENERAL_FAILURE,
    }
}

/// Handle UDP ASSOCIATE command.
async fn handle_udp_associate(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &ClientState,
) -> Result<(), ClientError> {
    // Bind a local UDP socket for the client
    let udp_bind = match peer {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0",
        SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0",
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let udp_socket = UdpSocket::bind(udp_bind).await?;
    let local_udp_addr = udp_socket.local_addr()?;

    debug!(udp_addr = %local_udp_addr, "UDP ASSOCIATE");

    // Send SOCKS5 reply with the UDP relay address
    send_reply(stream, REPLY_SUCCEEDED, &local_udp_addr).await?;

    // Connect to trojan server over TLS
    let mut tls_stream = state.connect().await?;

    // Send Trojan header with UDP_ASSOCIATE command
    // The address in the header is the address the client wants to communicate with.
    // For UDP ASSOCIATE, we use the peer address as a placeholder (per RFC 1928).
    let placeholder_addr = AddressRef {
        host: match peer {
            SocketAddr::V4(v4) => trojan_proto::HostRef::Ipv4(v4.ip().octets()),
            SocketAddr::V6(v6) => trojan_proto::HostRef::Ipv6(v6.ip().octets()),
        },
        port: peer.port(),
    };
    let mut header_buf = BytesMut::with_capacity(128);
    write_request_header(
        &mut header_buf,
        state.hash_hex.as_bytes(),
        CMD_UDP_ASSOCIATE,
        &placeholder_addr,
    )?;
    tls_stream.write_all(&header_buf).await?;

    // UDP relay loop
    let idle_timeout = Duration::from_secs(DEFAULT_UDP_TIMEOUT_SECS);
    let result = udp_relay_loop(stream, &udp_socket, &mut tls_stream, idle_timeout).await;

    if let Err(e) = &result {
        debug!(error = %e, "UDP relay ended");
    }

    result
}

/// Bidirectional UDP relay:
/// - Local UDP socket <-> SOCKS5 client
/// - TLS stream <-> trojan server
///
/// Also monitors the SOCKS5 TCP control connection — when it closes, the
/// UDP association ends (per RFC 1928).
async fn udp_relay_loop<S>(
    tcp_stream: &mut TcpStream,
    udp_socket: &UdpSocket,
    tls_stream: &mut S,
    idle_timeout: Duration,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut udp_buf = vec![0u8; 65536];
    let mut tcp_buf = vec![0u8; 65536];
    let mut tcp_acc = BytesMut::with_capacity(65536);
    let mut tcp_read_buf = [0u8; 1]; // for detecting TCP close
    let mut client_addr: Option<SocketAddr> = None;

    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            // Client sends UDP data via local socket
            result = udp_socket.recv_from(&mut udp_buf) => {
                let (n, from) = result?;
                client_addr = Some(from);

                // Parse SOCKS5 UDP header
                match parse_socks5_udp(&udp_buf[..n]) {
                    Ok(header) => {
                        // Encode as Trojan UDP packet and send over TLS
                        let mut trojan_buf = BytesMut::with_capacity(header.payload.len() + 64);
                        if write_udp_packet(&mut trojan_buf, &header.address, header.payload).is_ok() {
                            tls_stream.write_all(&trojan_buf).await?;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "invalid SOCKS5 UDP packet, dropping");
                    }
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }

            // Trojan server sends UDP data over TLS
            result = tls_stream.read(&mut tcp_buf) => {
                let n = result?;
                if n == 0 {
                    // TLS stream closed
                    return Ok(());
                }

                tcp_acc.extend_from_slice(&tcp_buf[..n]);

                let mut pending = Vec::new();
                let res = drain_trojan_udp_packets(&mut tcp_acc, |pkt| {
                    if let Some(addr) = client_addr {
                        let socks5_pkt = write_socks5_udp(&pkt.address, pkt.payload);
                        pending.push((socks5_pkt, addr));
                    }
                });

                if let Err(e) = res {
                    debug!(error = ?e, "invalid trojan UDP packet");
                }

                for (pkt, addr) in pending {
                    let _ = udp_socket.send_to(&pkt, addr).await;
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }

            // Monitor TCP control connection (if it closes, end the association)
            result = tcp_stream.read(&mut tcp_read_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("SOCKS5 TCP control connection closed, ending UDP association");
                        return Ok(());
                    }
                    Ok(_) => {
                        // Unexpected data on TCP control channel, ignore
                    }
                }
            }

            // Idle timeout
            _ = &mut idle_sleep => {
                debug!("UDP relay idle timeout");
                return Ok(());
            }
        }
    }
}

fn drain_trojan_udp_packets<F>(
    buffer: &mut BytesMut,
    mut on_packet: F,
) -> Result<(), trojan_proto::ParseError>
where
    F: FnMut(&trojan_proto::UdpPacket<'_>),
{
    let mut offset = 0;
    while offset < buffer.len() {
        match parse_udp_packet(&buffer[offset..]) {
            ParseResult::Complete(pkt) => {
                on_packet(&pkt);
                offset += pkt.packet_len;
            }
            ParseResult::Incomplete(_) => break,
            ParseResult::Invalid(e) => {
                buffer.clear();
                return Err(e);
            }
        }
    }

    if offset > 0 {
        buffer.advance(offset);
    }

    Ok(())
}

/// Format an AddressRef for logging.
fn format_address(addr: &AddressRef<'_>) -> String {
    match &addr.host {
        trojan_proto::HostRef::Ipv4(ip) => {
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], addr.port)
        }
        trojan_proto::HostRef::Ipv6(ip) => {
            let ipv6 = std::net::Ipv6Addr::from(*ip);
            format!("[{ipv6}]:{}", addr.port)
        }
        trojan_proto::HostRef::Domain(d) => {
            let s = std::str::from_utf8(d).unwrap_or("<invalid>");
            format!("{s}:{}", addr.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{drain_trojan_udp_packets, reply_code_for_connect_error};
    use bytes::BytesMut;
    use trojan_proto::{AddressRef, HostRef, write_udp_packet};
    use crate::error::ClientError;
    use crate::socks5::handshake::{
        REPLY_CONNECTION_NOT_ALLOWED, REPLY_CONNECTION_REFUSED, REPLY_GENERAL_FAILURE,
        REPLY_HOST_UNREACHABLE, REPLY_TTL_EXPIRED,
    };
    use std::io::ErrorKind;

    #[derive(Debug, PartialEq, Eq)]
    enum OwnedHost {
        Ipv4([u8; 4]),
        Ipv6([u8; 16]),
        Domain(Vec<u8>),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OwnedPacket {
        host: OwnedHost,
        port: u16,
        payload: Vec<u8>,
    }

    fn capture(pkt: &trojan_proto::UdpPacket<'_>) -> OwnedPacket {
        let host = match pkt.address.host {
            HostRef::Ipv4(ip) => OwnedHost::Ipv4(ip),
            HostRef::Ipv6(ip) => OwnedHost::Ipv6(ip),
            HostRef::Domain(d) => OwnedHost::Domain(d.to_vec()),
        };

        OwnedPacket {
            host,
            port: pkt.address.port,
            payload: pkt.payload.to_vec(),
        }
    }

    #[test]
    fn drain_preserves_incomplete_frames() {
        let address = AddressRef {
            host: HostRef::Ipv4([1, 2, 3, 4]),
            port: 53,
        };

        let mut packet = BytesMut::new();
        write_udp_packet(&mut packet, &address, b"hello").unwrap();

        let split = 3;
        let mut acc = BytesMut::new();
        acc.extend_from_slice(&packet[..split]);

        let mut parsed = Vec::new();
        drain_trojan_udp_packets(&mut acc, |pkt| parsed.push(capture(pkt))).unwrap();
        assert!(parsed.is_empty());
        assert_eq!(acc.len(), split);

        acc.extend_from_slice(&packet[split..]);
        drain_trojan_udp_packets(&mut acc, |pkt| parsed.push(capture(pkt))).unwrap();

        assert!(acc.is_empty());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].payload, b"hello");
        assert_eq!(parsed[0].port, 53);
        assert_eq!(parsed[0].host, OwnedHost::Ipv4([1, 2, 3, 4]));
    }

    #[test]
    fn reply_code_maps_common_errors() {
        let err = ClientError::Resolve("example.com".into());
        assert_eq!(reply_code_for_connect_error(&err), REPLY_HOST_UNREACHABLE);

        let err = ClientError::Io(std::io::Error::new(
            ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert_eq!(reply_code_for_connect_error(&err), REPLY_CONNECTION_REFUSED);

        let err = ClientError::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "denied",
        ));
        assert_eq!(reply_code_for_connect_error(&err), REPLY_CONNECTION_NOT_ALLOWED);

        let err = ClientError::Io(std::io::Error::new(ErrorKind::TimedOut, "timeout"));
        assert_eq!(reply_code_for_connect_error(&err), REPLY_TTL_EXPIRED);

        let err = ClientError::Io(std::io::Error::new(ErrorKind::Other, "other"));
        assert_eq!(reply_code_for_connect_error(&err), REPLY_GENERAL_FAILURE);
    }
}
