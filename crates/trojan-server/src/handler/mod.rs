//! Connection handlers for different trojan commands.

mod fallback;
mod tcp;
mod udp;
#[cfg(feature = "ws")]
mod ws;

pub use fallback::handle_fallback;
pub(crate) use tcp::handle_connect;
pub(crate) use udp::handle_udp_associate;
#[cfg(feature = "ws")]
pub use ws::handle_ws_only;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{debug, instrument, warn};
use trojan_auth::AuthBackend;
use trojan_core::defaults;
use trojan_core::proxy_protocol::ChainInfo;
use trojan_metrics::{
    record_auth_failure, record_auth_success, record_connect_request, record_fallback,
    record_udp_associate_request,
};
use trojan_proto::{CMD_CONNECT, CMD_UDP_ASSOCIATE, ParseError, ParseResult, parse_request};

use crate::error::ServerError;
use crate::state::ServerState;
#[cfg(feature = "ws")]
use crate::ws::{INITIAL_BUFFER_SIZE, WsInspect, WsIo, accept_ws, inspect_mixed, send_reject};

/// What the server knows about a connection before its trojan request arrives.
#[derive(Debug, Clone)]
pub struct Connection {
    /// The address to attribute the connection to. Behind a trusted proxy this
    /// is the client the PROXY header named, not the hop it arrived from.
    pub peer: SocketAddr,
    /// Monotonic id, for correlating logs and analytics events.
    pub id: u64,
    /// Relay hops that carried the connection, empty for a direct one.
    pub chain: ChainInfo,
}

/// Who a connection's traffic is charged to.
///
/// The user comes from the trojan handshake this server authenticated; the
/// chain comes from the header the entry node sent and names the other nodes
/// that carried the very same bytes. They travel together because they are
/// settled together, once, when the connection ends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Account<'a> {
    /// The authenticated user, absent when the backend named no one.
    pub user_id: Option<&'a str>,
    /// Hops to credit alongside this node.
    pub chain: &'a ChainInfo,
}

/// An authenticated connection, on its way to whatever it asked for.
///
/// Every command handler needs the same five things and settles them the same
/// way at the end, so they travel together rather than as a parameter list
/// repeated at each signature.
pub(crate) struct Session<'a, A: ?Sized> {
    pub state: Arc<ServerState>,
    pub auth: Arc<A>,
    /// Who this connection's bytes are charged to.
    pub account: Account<'a>,
    /// The client, as attributed — behind a trusted proxy, the real one.
    pub peer: SocketAddr,
    /// The in-flight analytics event, filed when the session ends.
    #[cfg(feature = "analytics")]
    pub analytics: Option<trojan_analytics::ConnectionEventBuilder>,
}

impl<A: AuthBackend + ?Sized> Session<'_, A> {
    /// Note UDP packet counts on the in-flight event.
    ///
    /// A no-op without the analytics feature, where there is no event to note
    /// them on.
    #[cfg_attr(
        not(feature = "analytics"),
        expect(
            unused_variables,
            reason = "there is no event to record on when the feature is off"
        )
    )]
    pub fn record_packets(&mut self, to_target: u64, to_client: u64) {
        #[cfg(feature = "analytics")]
        if let Some(ref mut event) = self.analytics {
            event.add_packets(to_target, to_client);
        }
    }

    /// Close the books on the connection: charge the user and the hops that
    /// carried it, then file the analytics event.
    ///
    /// Byte counts come from the relay counters rather than the relay's return
    /// value, so a session that ended in error still accounts for what it
    /// moved. A client that vanishes without a close_notify — a killed app, a
    /// dropped mobile link, an RST — is the common case, not the exception,
    /// and billing only the success path let that traffic through free on a
    /// server enforcing `traffic_limit`.
    pub async fn settle<T>(
        self,
        counters: &trojan_metrics::RelayCounters,
        result: &Result<T, ServerError>,
    ) {
        self.charge(counters.total_bytes()).await;
        self.file_event(counters, result);
    }

    /// Record the session's bytes against its user, and against every hop that
    /// carried them.
    ///
    /// The hops are credited the same count, not a share of it: each one
    /// really did move all of it. They cannot report it themselves — a relay
    /// never learns whose traffic it forwards — so this is the only place the
    /// panel can learn what a chain carried for whom.
    async fn charge(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let Some(uid) = self.account.user_id else {
            return;
        };
        let peer = self.peer;
        if let Err(e) = self.auth.record_traffic(uid, bytes).await {
            warn!(peer = %peer, user_id = uid, error = %e, "failed to record traffic");
        }
        if !self.account.chain.is_empty()
            && let Err(e) = self
                .auth
                .record_chain_traffic(uid, bytes, &self.account.chain.nodes)
                .await
        {
            warn!(peer = %peer, user_id = uid, error = %e, "failed to record chain traffic");
        }
    }

    /// Send the analytics event, with its byte counts and how it ended.
    #[cfg_attr(
        not(feature = "analytics"),
        expect(
            unused_variables,
            reason = "the body is behind cfg(analytics); with it off there is \
                      nothing to record and every parameter goes unread"
        )
    )]
    fn file_event<T>(
        self,
        counters: &trojan_metrics::RelayCounters,
        result: &Result<T, ServerError>,
    ) {
        #[cfg(feature = "analytics")]
        if let Some(mut event) = self.analytics {
            // `add_to_target` is the client → target direction, which the
            // event records as bytes sent.
            event.add_bytes(counters.sent_to_target(), counters.sent_to_client());
            event.finish(match result {
                Ok(_) => trojan_analytics::CloseReason::Normal,
                Err(_) => trojan_analytics::CloseReason::Error,
            });
        }
    }
}

/// Handle a new connection after TLS handshake.
#[instrument(level = "debug", skip(stream, state, auth), fields(client = %conn.peer))]
pub async fn handle_conn<S, A>(
    stream: S,
    state: Arc<ServerState>,
    auth: Arc<A>,
    conn: Connection,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    #[cfg(feature = "ws")]
    if state.websocket.enabled && state.websocket.mode == trojan_config::WebSocketMode::Mixed {
        return handle_conn_mixed_ws(stream, state, auth, conn).await;
    }
    handle_trojan_stream(stream, BytesMut::new(), state, auth, conn).await
}

#[cfg(feature = "ws")]
async fn handle_conn_mixed_ws<S, A>(
    mut stream: S,
    state: Arc<ServerState>,
    auth: Arc<A>,
    conn: Connection,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let peer = conn.peer;
    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER_SIZE);
    loop {
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

        match inspect_mixed(&buf, &state.websocket) {
            WsInspect::NeedMore => {
                if buf.len() > state.max_header_bytes {
                    warn!(peer = %peer, bytes = buf.len(), max = state.max_header_bytes, "header too large, fallback");
                    record_fallback();
                    return handle_fallback(stream, buf.freeze(), state, peer).await;
                }
                continue;
            }
            WsInspect::NotHttp => {
                return handle_trojan_stream(stream, buf, state, auth, conn).await;
            }
            WsInspect::HttpFallback => {
                record_fallback();
                return handle_fallback(stream, buf.freeze(), state, peer).await;
            }
            WsInspect::Reject(reason) => {
                send_reject(stream, reason).await?;
                return Ok(());
            }
            WsInspect::Upgrade => {
                let ws = accept_ws(stream, buf.freeze(), &state.websocket).await?;
                let ws = WsIo::new(ws);
                return handle_trojan_stream(ws, BytesMut::new(), state, auth, conn).await;
            }
        }
    }
}

#[cfg_attr(
    not(feature = "analytics"),
    allow(
        unused_variables,
        reason = "conn_id is only read when building the analytics event"
    )
)]
pub(crate) async fn handle_trojan_stream<S, A>(
    mut stream: S,
    mut buf: BytesMut,
    state: Arc<ServerState>,
    auth: Arc<A>,
    conn: Connection,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let peer = conn.peer;
    let conn_id = conn.id;
    // `read_buf` hands the stream only this buffer's spare capacity, and
    // `BytesMut` grows an exhausted buffer by 64 bytes — under
    // `MIN_HEADER_BYTES`. Callers that start from an empty buffer would
    // therefore always need a second read plus a reallocation before the
    // header could parse. Reserve once so the common case is a single read.
    buf.reserve(defaults::DEFAULT_HEADER_BUFFER_SIZE);

    loop {
        if !buf.is_empty() {
            match parse_request(&buf) {
                ParseResult::Complete(req) => {
                    let cmd_name = match req.command {
                        CMD_CONNECT => "CONNECT",
                        CMD_UDP_ASSOCIATE => "UDP_ASSOCIATE",
                        _ => "UNKNOWN",
                    };
                    debug!(peer = %peer, cmd = cmd_name, target = ?req.address, "trojan request");

                    // GeoIP lookup for metrics country tagging (executed once per connection)
                    #[cfg(feature = "geoip")]
                    let peer_country: String = state
                        .geoip_metrics
                        .as_ref()
                        .and_then(|db| db.country_code(peer.ip()))
                        .unwrap_or_default();

                    // Hex is case-insensitive on the wire but backends key on
                    // lowercase, so fold it. `parse_request` yields a fixed
                    // number of ASCII hex digits, so this fits the stack and
                    // needs no allocation on the authentication path.
                    let mut folded = *req.hash;
                    folded.make_ascii_lowercase();
                    let hash = std::str::from_utf8(&folded)
                        .expect("parse_request admits only ASCII hex digits");

                    let auth_result = match auth.verify(hash).await {
                        Ok(result) => result,
                        Err(err) => {
                            debug!(peer = %peer, reason = %err, "auth failed, fallback");
                            record_auth_failure();
                            #[cfg(feature = "geoip")]
                            if !peer_country.is_empty() {
                                trojan_metrics::record_auth_failure_with_geo(&peer_country);
                            }
                            record_fallback();
                            return handle_fallback(stream, buf.freeze(), state, peer).await;
                        }
                    };
                    let user_id = auth_result.user_id;

                    record_auth_success();
                    #[cfg(feature = "geoip")]
                    if !peer_country.is_empty() {
                        trojan_metrics::record_connection_with_geo(&peer_country);
                    }
                    debug!(peer = %peer, "auth success");

                    // Analytics: GeoIP lookup for geo fields (city-level)
                    #[cfg(all(feature = "geoip", feature = "analytics"))]
                    let analytics_geo: Option<trojan_core::geo::GeoResult> = state
                        .geoip_analytics
                        .as_ref()
                        .map(|db| db.lookup_city(peer.ip()));

                    // Analytics: record connection event if sampling passes.
                    // The builder sends the event on drop with duration auto-filled.
                    #[cfg(feature = "analytics")]
                    let analytics_event = state.analytics.as_ref().and_then(|collector| {
                        if !collector.should_sample(user_id.as_deref()) {
                            return None;
                        }
                        let mut builder = collector.connection(conn_id, peer);

                        // Everything the request already tells us. Left
                        // unset these ship as empty strings and zeroes,
                        // which is what the event looked like before.
                        let (host, target_type) = match req.address.host {
                            trojan_proto::HostRef::Ipv4(v4) => (
                                std::net::Ipv4Addr::from(v4).to_string(),
                                trojan_analytics::TargetType::Ipv4,
                            ),
                            trojan_proto::HostRef::Ipv6(v6) => (
                                std::net::Ipv6Addr::from(v6).to_string(),
                                trojan_analytics::TargetType::Ipv6,
                            ),
                            trojan_proto::HostRef::Domain(d) => (
                                String::from_utf8_lossy(d).into_owned(),
                                trojan_analytics::TargetType::Domain,
                            ),
                        };
                        builder = builder
                            .target(host, req.address.port, target_type)
                            .protocol(if req.command == CMD_UDP_ASSOCIATE {
                                trojan_analytics::Protocol::Udp
                            } else {
                                trojan_analytics::Protocol::Tcp
                            });
                        if let Some(ref uid) = user_id {
                            builder = builder.user(uid.clone());
                        }
                        #[cfg(feature = "geoip")]
                        if let Some(geo) = analytics_geo {
                            builder = builder.geo(geo, collector.privacy().geo_precision);
                        }
                        Some(builder)
                    });
                    let session = Session {
                        state: state.clone(),
                        auth: auth.clone(),
                        account: Account {
                            user_id: user_id.as_deref(),
                            chain: &conn.chain,
                        },
                        peer,
                        #[cfg(feature = "analytics")]
                        analytics: analytics_event,
                    };

                    // Rule-based routing: match target against rules
                    #[cfg(feature = "rules")]
                    if let Some(ref engine) = state.rule_engine {
                        let action = {
                            let domain = match &req.address.host {
                                trojan_proto::HostRef::Domain(d) => std::str::from_utf8(d).ok(),
                                _ => None,
                            };
                            let dest_ip = match &req.address.host {
                                trojan_proto::HostRef::Ipv4(v4) => {
                                    Some(std::net::IpAddr::from(*v4))
                                }
                                trojan_proto::HostRef::Ipv6(v6) => {
                                    Some(std::net::IpAddr::from(*v6))
                                }
                                _ => None,
                            };

                            let ctx = trojan_rules::rule::MatchContext {
                                domain,
                                dest_ip,
                                dest_port: req.address.port,
                                src_ip: peer.ip(),
                            };

                            // Per Sukka's analysis: only resolve DNS for IP-based rules
                            // when necessary to preserve rule order. Domain-only matches
                            // before any IP rule should avoid DNS entirely.
                            if ctx.dest_ip.is_none()
                                && ctx.domain.is_some()
                                && engine.has_ip_rules()
                            {
                                // Try lazy match first — returns Some(action) if a
                                // domain rule matched before any IP rule, None if DNS
                                // resolution is needed.
                                if let Some(action) = engine.match_request_lazy_ip(&ctx) {
                                    action
                                } else {
                                    // An IP-based rule appeared first; resolve and retry.
                                    match crate::resolve::resolve_address(
                                        &req.address,
                                        &state.dns_resolver,
                                    )
                                    .await
                                    {
                                        Ok(resolved) => {
                                            debug!(peer = %peer, domain = ?domain, resolved = %resolved, "DNS resolved for IP rule matching");
                                            let ctx = trojan_rules::rule::MatchContext {
                                                domain,
                                                dest_ip: Some(resolved.ip()),
                                                dest_port: req.address.port,
                                                src_ip: peer.ip(),
                                            };
                                            engine.match_request(&ctx)
                                        }
                                        Err(e) => {
                                            // DNS failure should not block the request — skip IP rules
                                            debug!(peer = %peer, domain = ?domain, error = %e, "DNS resolve failed for IP rule matching, skipping IP rules");
                                            engine.match_request(&ctx)
                                        }
                                    }
                                }
                            } else {
                                engine.match_request(&ctx)
                            }
                        };
                        match &action {
                            trojan_rules::Action::Reject => {
                                debug!(peer = %peer, target = ?req.address, "rule: REJECT");
                                return Ok(());
                            }
                            trojan_rules::Action::Outbound(name) => {
                                if let Some(outbound) = state.outbounds.get(name.as_str()) {
                                    debug!(peer = %peer, target = ?req.address, outbound = %name, "rule: outbound");
                                    if req.command == CMD_CONNECT {
                                        record_connect_request();
                                        let payload = &buf[req.header_len..];
                                        return handle_connect_via_outbound(
                                            stream,
                                            req.address,
                                            payload,
                                            outbound.clone(),
                                            session,
                                        )
                                        .await;
                                    }
                                    // UDP over outbound not supported yet; fall through to direct
                                    debug!(peer = %peer, "outbound does not support UDP, using direct");
                                } else {
                                    warn!(peer = %peer, outbound = %name, "unknown outbound, using direct");
                                }
                            }
                            trojan_rules::Action::Direct => {
                                debug!(peer = %peer, target = ?req.address, "rule: DIRECT");
                            }
                        }
                    }

                    // Use slice reference to avoid allocation
                    let payload = &buf[req.header_len..];

                    return match req.command {
                        CMD_CONNECT => {
                            record_connect_request();
                            handle_connect(stream, req.address, payload, session).await
                        }
                        CMD_UDP_ASSOCIATE => {
                            record_udp_associate_request();
                            handle_udp_associate(stream, payload, session).await
                        }
                        _ => Err(ServerError::Proto(ParseError::InvalidCommand)),
                    };
                }
                ParseResult::Incomplete(_) => {
                    if buf.len() > state.max_header_bytes {
                        warn!(peer = %peer, bytes = buf.len(), max = state.max_header_bytes, "header too large, fallback");
                        record_fallback();
                        return handle_fallback(stream, buf.freeze(), state, peer).await;
                    }
                }
                ParseResult::Invalid(err) => {
                    debug!(peer = %peer, error = ?err, "invalid header, fallback");
                    record_fallback();
                    return handle_fallback(stream, buf.freeze(), state, peer).await;
                }
            }
        }

        let n = stream.read_buf(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
    }
}

/// Handle TCP CONNECT via a named outbound connector.
#[cfg(feature = "rules")]
async fn handle_connect_via_outbound<S, A>(
    mut stream: S,
    address: trojan_proto::AddressRef<'_>,
    payload: &[u8],
    outbound: Arc<crate::outbound::Outbound>,
    session: Session<'_, A>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    use tokio::io::AsyncWriteExt;
    use trojan_metrics::{record_target_connect_duration, record_target_connection};

    let state = &session.state;
    let peer = session.peer;
    let target_label = crate::resolve::target_to_label(&address);
    record_target_connection(&target_label);
    // Resolved once here rather than per flush inside the relay loop.
    let counters = state.relay_counters(Some(&target_label));

    // Connect via the outbound. Any pre-relay failure (resolve, connect, or
    // initial payload write) drops the TLS stream — call shutdown first so
    // the client sees close_notify rather than UnexpectedEof. REJECT also
    // shuts down cleanly for the same reason.
    let connect_start = tokio::time::Instant::now();
    let maybe_outbound_stream = match outbound
        .connect(
            &address,
            &state.tcp_config,
            state.tcp_send_buffer,
            state.tcp_recv_buffer,
            &state.dns_resolver,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            let _ = stream.shutdown().await;
            return Err(e);
        }
    };
    record_target_connect_duration(connect_start.elapsed().as_secs_f64());

    let mut outbound_stream = match maybe_outbound_stream {
        Some(s) => s,
        None => {
            debug!(peer = %peer, target = ?address, "outbound: REJECT");
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    debug!(peer = %peer, target = ?address, "outbound connected");

    let payload_bytes = payload.len() as u64;
    if !payload.is_empty()
        && let Err(e) = outbound_stream.write_all(payload).await
    {
        let _ = stream.shutdown().await;
        return Err(e.into());
    }
    if !payload.is_empty() {
        // Client → target, matching how the relay loop attributes the rest
        // of this stream.
        counters.add_to_target(payload_bytes);
    }

    let result = crate::relay::relay_with_counters(
        stream,
        outbound_stream,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
        &counters,
    )
    .await;

    session.settle(&counters, &result).await;

    result?;
    debug!(peer = %peer, target = ?address, "outbound relay finished");

    Ok(())
}
