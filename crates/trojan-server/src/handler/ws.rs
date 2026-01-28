//! WebSocket-only handler for split mode.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{debug, warn};
use trojan_auth::AuthBackend;

use super::handle_trojan_stream;
use crate::error::ServerError;
use crate::state::ServerState;
use crate::ws::{INITIAL_BUFFER_SIZE, WsInspect, WsIo, accept_ws, inspect_mixed, send_reject};

/// Handle a TLS connection that must be upgraded to WebSocket (split mode).
pub async fn handle_ws_only<S, A>(
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
                    warn!(peer = %peer, bytes = buf.len(), max = state.max_header_bytes, "header too large on split listener");
                    return send_reject(stream, "request too large").await;
                }
                continue;
            }
            WsInspect::Upgrade => {
                let ws = accept_ws(stream, buf.freeze(), &state.websocket).await?;
                let ws = WsIo::new(ws);
                return handle_trojan_stream(ws, BytesMut::new(), state, auth, peer).await;
            }
            WsInspect::Reject(reason) => {
                return send_reject(stream, reason).await;
            }
            WsInspect::HttpFallback | WsInspect::NotHttp => {
                debug!(peer = %peer, "non-websocket request on split listener");
                return send_reject(stream, "websocket required").await;
            }
        }
    }
}
