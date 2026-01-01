//! Connection handlers for different trojan commands.

mod fallback;
mod tcp;
mod udp;

pub use fallback::handle_fallback;
pub use tcp::handle_connect;
pub use udp::handle_udp_associate;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{debug, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{
    record_auth_failure, record_auth_success, record_connect_request, record_fallback,
    record_udp_associate_request,
};
use trojan_proto::{parse_request, ParseError, ParseResult, CMD_CONNECT, CMD_UDP_ASSOCIATE};

use crate::error::ServerError;
use crate::state::ServerState;

/// Handle a new connection after TLS handshake.
pub async fn handle_conn<S, A>(
    mut stream: S,
    state: Arc<ServerState>,
    auth: Arc<A>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let mut buf = BytesMut::with_capacity(2048);
    loop {
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

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

                let verify_result = if hash.bytes().any(|b| b.is_ascii_uppercase()) {
                    let owned = hash.to_ascii_lowercase();
                    auth.verify(&owned).await
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
                continue;
            }
            ParseResult::Invalid(err) => {
                debug!(peer = %peer, error = ?err, "invalid header, fallback");
                record_fallback();
                return handle_fallback(stream, buf.freeze(), state, peer).await;
            }
        }
    }
}
