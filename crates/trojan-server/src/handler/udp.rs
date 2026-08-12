//! UDP ASSOCIATE command handler.

use std::net::SocketAddr;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::{debug, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{RelayCounters, record_udp_packet};
use trojan_proto::{ParseResult, parse_udp_packet, write_udp_packet};

use crate::error::ServerError;
use crate::handler::Session;
use crate::resolve::{address_from_socket, resolve_address};

/// Handle UDP ASSOCIATE command.
#[inline]
pub(crate) async fn handle_udp_associate<S, A>(
    mut stream: S,
    initial: &[u8],
    mut session: Session<'_, A>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let state = session.state.clone();
    let peer = session.peer;
    debug!(peer = %peer, "starting UDP associate");

    // The same counters the TCP path uses, so an association's bytes reach the
    // node's totals too — the agent reports those, and UDP traffic used to be
    // missing from them entirely. No target label: each packet has its own.
    let counters = state.relay_counters(None);

    // We'll bind sockets lazily based on target address family
    let mut udp_v4: Option<UdpSocket> = None;
    let mut udp_v6: Option<UdpSocket> = None;

    let mut tcp_buf = BytesMut::from(initial);
    // Separate buffers for each address family to avoid borrow conflicts
    let mut udp_buf_v4 = vec![0u8; state.max_udp_payload];
    let mut udp_buf_v6 = vec![0u8; state.max_udp_payload];
    // Reusable buffer for UDP responses (avoids allocation per packet)
    let mut response_buf = BytesMut::with_capacity(state.max_udp_payload + 64);
    let idle_sleep = tokio::time::sleep(state.udp_idle_timeout);
    tokio::pin!(idle_sleep);

    let mut packets_out: u64 = 0;
    let mut packets_in: u64 = 0;

    // The association runs inside an async block so that every way out of it —
    // including the `?`s below — passes through the settle that follows. An
    // I/O error mid-association used to return straight out, taking the
    // traffic it had already carried with it.
    let result = async {
        loop {
            tokio::select! {
                res = stream.read_buf(&mut tcp_buf) => {
                    let n = res?;
                    if n == 0 {
                        debug!(peer = %peer, packets_out, packets_in, "UDP associate ended (client closed)");
                        return Ok(());
                    }
                    if tcp_buf.len() > state.max_udp_buffer_bytes {
                        warn!(peer = %peer, bytes = tcp_buf.len(), max = state.max_udp_buffer_bytes, "UDP buffer too large");
                        return Err(ServerError::Config("udp buffer too large".into()));
                    }
                    counters.add_to_target(n as u64);
                    idle_sleep.as_mut().reset(Instant::now() + state.udp_idle_timeout);

                    // Process all complete UDP packets in buffer
                    loop {
                        match parse_udp_packet(&tcp_buf) {
                            ParseResult::Complete(pkt) => {
                                if pkt.length > state.max_udp_payload {
                                    warn!(peer = %peer, size = pkt.length, max = state.max_udp_payload, "UDP payload too large");
                                    return Err(ServerError::UdpPayloadTooLarge);
                                }
                                let target = resolve_address(&pkt.address, &state.dns_resolver).await?;

                                // Select or create appropriate socket based on target address family
                                let udp: &UdpSocket = match target {
                                    SocketAddr::V4(_) => {
                                        if udp_v4.is_none() {
                                            udp_v4 = Some(UdpSocket::bind("0.0.0.0:0").await?);
                                            debug!(peer = %peer, "bound UDP v4 socket");
                                        }
                                        // Just set above when it was absent.
                                        udp_v4.as_ref().expect("udp_v4 was just set")
                                    }
                                    SocketAddr::V6(_) => {
                                        if udp_v6.is_none() {
                                            udp_v6 = Some(UdpSocket::bind("[::]:0").await?);
                                            debug!(peer = %peer, "bound UDP v6 socket");
                                        }
                                        // Just set above when it was absent.
                                        udp_v6.as_ref().expect("udp_v6 was just set")
                                    }
                                };

                                udp.send_to(pkt.payload, target).await?;
                                record_udp_packet("outbound");
                                packets_out += 1;
                                tcp_buf.advance(pkt.packet_len);
                            }
                            ParseResult::Incomplete(_) => break,
                            ParseResult::Invalid(err) => return Err(ServerError::Proto(err)),
                        }
                    }
                }

                res = async {
                    if let Some(ref udp) = udp_v4 {
                        udp.recv_from(&mut udp_buf_v4).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    let (size, udp_peer) = res?;
                    if size <= state.max_udp_payload {
                        idle_sleep.as_mut().reset(Instant::now() + state.udp_idle_timeout);
                        send_udp_response(&mut stream, udp_peer, &udp_buf_v4[..size], &mut response_buf, &counters).await?;
                        record_udp_packet("inbound");
                        packets_in += 1;
                    }
                }

                res = async {
                    if let Some(ref udp) = udp_v6 {
                        udp.recv_from(&mut udp_buf_v6).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    let (size, udp_peer) = res?;
                    if size <= state.max_udp_payload {
                        idle_sleep.as_mut().reset(Instant::now() + state.udp_idle_timeout);
                        send_udp_response(&mut stream, udp_peer, &udp_buf_v6[..size], &mut response_buf, &counters).await?;
                        record_udp_packet("inbound");
                        packets_in += 1;
                    }
                }

                _ = &mut idle_sleep => {
                    debug!(peer = %peer, packets_out, packets_in, "UDP associate ended (idle timeout)");
                    return Ok(());
                }
            }
        }
    }
    .await;

    session.record_packets(packets_out, packets_in);
    session.settle(&counters, &result).await;

    result
}

/// Send a UDP response back to the client using a reusable buffer.
async fn send_udp_response<S>(
    stream: &mut S,
    peer: SocketAddr,
    payload: &[u8],
    buf: &mut BytesMut,
    counters: &RelayCounters,
) -> Result<(), ServerError>
where
    S: AsyncWrite + Unpin,
{
    buf.clear();
    let addr = address_from_socket(peer);
    write_udp_packet(buf, &addr, payload).map_err(ServerError::ProtoWrite)?;
    stream.write_all(buf).await?;
    stream.flush().await?;
    counters.add_to_client(buf.len() as u64);
    Ok(())
}
