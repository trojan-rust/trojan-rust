//! UDP ASSOCIATE command handler.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Buf, BytesMut};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, OnceCell};
use tokio::time::Instant;
use tracing::{debug, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{RelayCounters, record_udp_packet};
use trojan_proto::{AddressRef, HostRef, ParseResult, parse_udp_packet, write_udp_packet};

use crate::error::ServerError;
use crate::handler::Session;
use crate::resolve::{address_from_socket, resolve_address};
use crate::state::ServerState;

const MAX_PENDING_DATAGRAMS: usize = 16;

#[derive(Default)]
struct Association {
    v4: OnceCell<UdpSocket>,
    v6: OnceCell<UdpSocket>,
    socket_ready: Notify,
    activity: Notify,
    packets_out: AtomicU64,
    packets_in: AtomicU64,
}

enum Destination {
    Socket(SocketAddr),
    Domain(Vec<u8>, u16),
}

impl Destination {
    fn address(&self) -> AddressRef<'_> {
        match self {
            Self::Socket(address) => address_from_socket(*address),
            Self::Domain(domain, port) => AddressRef {
                host: HostRef::Domain(domain),
                port: *port,
            },
        }
    }
}

/// Relay UDP datagrams with bounded DNS work and independent stream directions.
pub(crate) async fn handle_udp_associate<S, A>(
    stream: S,
    initial: &[u8],
    mut session: Session<'_, A>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let state = session.state.clone();
    let peer = session.peer;
    let counters = state.relay_counters(None);
    let association = Association::default();
    let (reader, writer) = tokio::io::split(stream);
    counters.add_to_target(initial.len() as u64);

    let result = {
        let upload = receive_datagrams(reader, initial, &state, peer, &association, &counters);
        let download = return_datagrams(writer, &state, &association, &counters);
        tokio::pin!(upload, download);
        let idle = tokio::time::sleep(state.udp_idle_timeout);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                result = &mut upload => break result,
                result = &mut download => break result,
                _ = association.activity.notified() => {
                    idle.as_mut().reset(Instant::now() + state.udp_idle_timeout);
                }
                _ = &mut idle => break Ok(()),
            }
        }
    };

    session.record_packets(
        association.packets_out.load(Ordering::Relaxed),
        association.packets_in.load(Ordering::Relaxed),
    );
    session.settle(&counters, &result).await;
    result
}

async fn receive_datagrams<R: AsyncRead + Unpin>(
    mut reader: R,
    initial: &[u8],
    state: &ServerState,
    peer: SocketAddr,
    association: &Association,
    counters: &RelayCounters,
) -> Result<(), ServerError> {
    let mut buffer = BytesMut::from(initial);
    let mut pending = FuturesUnordered::new();
    let mut eof = false;
    loop {
        if buffer.len() > state.max_udp_buffer_bytes {
            warn!(%peer, bytes = buffer.len(), max = state.max_udp_buffer_bytes, "UDP buffer too large");
            return Err(ServerError::Config("udp buffer too large".into()));
        }
        while pending.len() < MAX_PENDING_DATAGRAMS {
            match parse_udp_packet(&buffer) {
                ParseResult::Complete(packet) => {
                    if packet.length > state.max_udp_payload {
                        return Err(ServerError::UdpPayloadTooLarge);
                    }
                    let destination = match packet.address.host {
                        HostRef::Ipv4(ip) => Destination::Socket((ip, packet.address.port).into()),
                        HostRef::Ipv6(ip) => Destination::Socket((ip, packet.address.port).into()),
                        HostRef::Domain(domain) => {
                            Destination::Domain(domain.to_vec(), packet.address.port)
                        }
                    };
                    let payload = packet.payload.to_vec();
                    let length = packet.packet_len;
                    buffer.advance(length);
                    pending.push(forward_datagram(
                        destination,
                        payload,
                        state,
                        peer,
                        association,
                    ));
                }
                ParseResult::Incomplete(_) => break,
                ParseResult::Invalid(error) => return Err(ServerError::Proto(error)),
            }
        }
        if eof && pending.is_empty() {
            return Ok(());
        }
        tokio::select! {
            Some(result) = pending.next(), if !pending.is_empty() => result?,
            result = reader.read_buf(&mut buffer), if !eof && pending.len() < MAX_PENDING_DATAGRAMS => {
                let bytes = result?;
                eof = bytes == 0;
                if !eof {
                    counters.add_to_target(bytes as u64);
                    association.activity.notify_one();
                }
            }
        }
    }
}

async fn forward_datagram(
    destination: Destination,
    payload: Vec<u8>,
    state: &ServerState,
    peer: SocketAddr,
    association: &Association,
) -> Result<(), ServerError> {
    let address = destination.address();
    #[cfg(feature = "rules")]
    let resolved = {
        let (action, resolved) = state.route(&address, peer).await?;
        let direct = match action {
            trojan_rules::Action::Direct => true,
            trojan_rules::Action::Reject => false,
            trojan_rules::Action::Outbound(name) => matches!(
                state.outbounds.get(&name).map(AsRef::as_ref),
                Some(crate::outbound::Outbound::Direct { bind: None })
            ),
        };
        if !direct {
            debug!(%peer, ?address, "UDP packet rejected by route");
            return Ok(());
        }
        resolved
    };
    #[cfg(not(feature = "rules"))]
    let resolved = None;
    let target = match resolved {
        Some(target) => target,
        None => resolve_address(&address, &state.dns_resolver).await?,
    };
    let (cell, bind) = if target.is_ipv4() {
        (&association.v4, "0.0.0.0:0")
    } else {
        (&association.v6, "[::]:0")
    };
    let udp = cell
        .get_or_try_init(|| async {
            let socket = UdpSocket::bind(bind).await?;
            association.socket_ready.notify_one();
            debug!(%peer, %bind, "bound UDP socket");
            Ok::<_, std::io::Error>(socket)
        })
        .await?;
    udp.send_to(&payload, target).await?;
    record_udp_packet("outbound");
    association.packets_out.fetch_add(1, Ordering::Relaxed);
    association.activity.notify_one();
    Ok(())
}

async fn return_datagrams<W: AsyncWrite + Unpin>(
    mut writer: W,
    state: &ServerState,
    association: &Association,
    counters: &RelayCounters,
) -> Result<(), ServerError> {
    let mut v4 = vec![0; state.max_udp_payload];
    let mut v6 = vec![0; state.max_udp_payload];
    let mut response = BytesMut::with_capacity(state.max_udp_payload + 64);
    loop {
        let (size, peer, payload) = tokio::select! {
            result = recv_datagram(&association.v4, &mut v4) => {
                let (size, peer) = result?;
                (size, peer, &v4[..])
            }
            result = recv_datagram(&association.v6, &mut v6) => {
                let (size, peer) = result?;
                (size, peer, &v6[..])
            }
            _ = association.socket_ready.notified() => continue,
        };
        association.activity.notify_one();
        send_udp_response(&mut writer, peer, &payload[..size], &mut response, counters).await?;
        record_udp_packet("inbound");
        association.packets_in.fetch_add(1, Ordering::Relaxed);
    }
}

async fn recv_datagram(
    socket: &OnceCell<UdpSocket>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket.get() {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
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
    crate::relay::write_all_counted(stream, buf, |bytes| counters.add_to_client(bytes)).await?;
    stream.flush().await?;
    Ok(())
}
