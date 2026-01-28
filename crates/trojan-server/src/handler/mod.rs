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
use trojan_proto::{CMD_CONNECT, CMD_UDP_ASSOCIATE, HASH_LEN, ParseError, ParseResult, parse_request};

use crate::error::ServerError;
use crate::state::ServerState;
#[cfg(feature = "ws")]
use crate::ws::{WsInspect, accept_ws, inspect_mixed, send_reject, WsIo, INITIAL_BUFFER_SIZE};

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

                    // parse_request already validated hash format via is_valid_hash
                    let hash = match std::str::from_utf8(req.hash) {
                        Ok(v) => v,
                        Err(_) => {
                            debug!(peer = %peer, reason = "invalid_hash_encoding", "auth failed, fallback");
                            record_auth_failure();
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
                        let hash_lower = std::str::from_utf8(&buf).expect("ASCII hex is valid UTF-8");
                        auth.verify(hash_lower).await
                    } else {
                        auth.verify(hash).await
                    };
                    if let Err(err) = verify_result {
                        debug!(peer = %peer, reason = %err, "auth failed, fallback");
                        record_auth_failure();
                        record_fallback();
                        return handle_fallback(stream, buf.freeze(), state, peer).await;
                    }

                    record_auth_success();
                    debug!(peer = %peer, "auth success");

                    // Use slice reference to avoid allocation
                    let payload = &buf[req.header_len..];

                    return match req.command {
                        CMD_CONNECT => {
                            record_connect_request();
                            handle_connect(stream, req.address, payload, state, peer).await
                        }
                        CMD_UDP_ASSOCIATE => {
                            record_udp_associate_request();
                            handle_udp_associate(stream, payload, state, peer).await
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
