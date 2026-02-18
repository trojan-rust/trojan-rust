//! Connection handlers for different trojan commands.

mod fallback;
mod tcp;
mod udp;
#[cfg(feature = "ws")]
mod ws;

pub use fallback::handle_fallback;
pub use tcp::handle_connect;
pub use udp::handle_udp_associate;
#[cfg(feature = "ws")]
pub use ws::handle_ws_only;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{debug, instrument, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{
    record_auth_failure, record_auth_success, record_connect_request, record_fallback,
    record_udp_associate_request,
};
use trojan_proto::{
    CMD_CONNECT, CMD_UDP_ASSOCIATE, HASH_LEN, ParseError, ParseResult, parse_request,
};

use crate::error::ServerError;
use crate::state::ServerState;
#[cfg(feature = "ws")]
use crate::ws::{INITIAL_BUFFER_SIZE, WsInspect, WsIo, accept_ws, inspect_mixed, send_reject};

/// Handle a new connection after TLS handshake.
#[instrument(level = "debug", skip(stream, state, auth))]
pub async fn handle_conn<S, A>(
    stream: S,
    state: Arc<ServerState>,
    auth: Arc<A>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    #[cfg(feature = "ws")]
    if state.websocket.enabled && state.websocket.mode == "mixed" {
        return handle_conn_mixed_ws(stream, state, auth, peer).await;
    }
    handle_trojan_stream(stream, BytesMut::new(), state, auth, peer).await
}

#[cfg(feature = "ws")]
async fn handle_conn_mixed_ws<S, A>(
    mut stream: S,
    state: Arc<ServerState>,
    auth: Arc<A>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
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
                return handle_trojan_stream(stream, buf, state, auth, peer).await;
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
                return handle_trojan_stream(ws, BytesMut::new(), state, auth, peer).await;
            }
        }
    }
}

pub(crate) async fn handle_trojan_stream<S, A>(
    mut stream: S,
    mut buf: BytesMut,
    state: Arc<ServerState>,
    auth: Arc<A>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
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

                    // parse_request already validated hash format via is_valid_hash
                    let hash = match std::str::from_utf8(req.hash) {
                        Ok(v) => v,
                        Err(_) => {
                            debug!(peer = %peer, reason = "invalid_hash_encoding", "auth failed, fallback");
                            record_auth_failure();
                            #[cfg(feature = "geoip")]
                            if !peer_country.is_empty() {
                                trojan_metrics::record_auth_failure_with_geo(&peer_country);
                            }
                            record_fallback();
                            return handle_fallback(stream, buf.freeze(), state, peer).await;
                        }
                    };

                    // Normalize hash to lowercase using stack buffer (avoid heap allocation)
                    // HASH_LEN is 56 bytes for SHA-224, small enough for stack
                    let verify_result = if hash.bytes().any(|b| b.is_ascii_uppercase()) {
                        let mut buf = [0u8; HASH_LEN];
                        for (i, byte) in hash.bytes().enumerate() {
                            buf[i] = byte.to_ascii_lowercase();
                        }
                        // Safe: ASCII hex digits remain valid UTF-8 after lowercase
                        let hash_lower =
                            std::str::from_utf8(&buf).expect("ASCII hex is valid UTF-8");
                        auth.verify(hash_lower).await
                    } else {
                        auth.verify(hash).await
                    };
                    let auth_result = match verify_result {
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
                    let analytics_geo: Option<trojan_config::GeoResult> = state
                        .geoip_analytics
                        .as_ref()
                        .map(|db| db.lookup_city(peer.ip()));

                    // Analytics: record connection event if sampling passes.
                    // The builder sends the event on drop with duration auto-filled.
                    #[cfg(feature = "analytics")]
                    #[allow(unused_mut)]
                    let _analytics_builder = state.analytics.as_ref().and_then(|collector| {
                        if !collector.should_sample(None) {
                            return None;
                        }
                        let mut builder = collector.connection(0, peer);
                        #[cfg(feature = "geoip")]
                        if let Some(geo) = analytics_geo {
                            builder = builder.geo(geo, &collector.privacy().geo_precision);
                        }
                        Some(builder)
                    });

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
                                            state,
                                            auth,
                                            user_id.as_deref(),
                                            peer,
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
                            handle_connect(
                                stream,
                                req.address,
                                payload,
                                state,
                                auth,
                                user_id.as_deref(),
                                peer,
                            )
                            .await
                        }
                        CMD_UDP_ASSOCIATE => {
                            record_udp_associate_request();
                            handle_udp_associate(
                                stream,
                                payload,
                                state,
                                auth,
                                user_id.as_deref(),
                                peer,
                            )
                            .await
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
#[allow(clippy::too_many_arguments)]
async fn handle_connect_via_outbound<S, A>(
    stream: S,
    address: trojan_proto::AddressRef<'_>,
    payload: &[u8],
    outbound: Arc<crate::outbound::Outbound>,
    state: Arc<ServerState>,
    auth: Arc<A>,
    user_id: Option<&str>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    use tokio::io::AsyncWriteExt;
    use trojan_metrics::{
        record_bytes_sent, record_target_bytes, record_target_connect_duration,
        record_target_connection,
    };

    let target_label = crate::resolve::target_to_label(&address);
    record_target_connection(&target_label);

    let connect_start = tokio::time::Instant::now();
    let maybe_outbound_stream = outbound
        .connect(
            &address,
            &state.tcp_config,
            state.tcp_send_buffer,
            state.tcp_recv_buffer,
            &state.dns_resolver,
        )
        .await?;
    record_target_connect_duration(connect_start.elapsed().as_secs_f64());

    let mut outbound_stream = match maybe_outbound_stream {
        Some(s) => s,
        None => {
            // Reject: close the connection
            debug!(peer = %peer, target = ?address, "outbound: REJECT");
            return Ok(());
        }
    };

    debug!(peer = %peer, target = ?address, "outbound connected");

    let payload_bytes = payload.len() as u64;
    if !payload.is_empty() {
        outbound_stream.write_all(payload).await?;
        record_bytes_sent(payload_bytes);
        record_target_bytes(&target_label, "sent", payload_bytes);
    }

    let stats = crate::relay::relay_with_idle_timeout_and_metrics_per_target(
        stream,
        outbound_stream,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
        &target_label,
    )
    .await?;

    debug!(peer = %peer, target = ?address, "outbound relay finished");

    tcp::record_traffic_for_user(&*auth, user_id, payload_bytes + stats.total(), peer).await;

    Ok(())
}
