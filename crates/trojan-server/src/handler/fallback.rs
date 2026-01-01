//! Fallback handler for non-trojan traffic.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::error::ServerError;
use crate::relay::relay_with_idle_timeout_and_metrics;
use crate::state::ServerState;
use crate::util::connect_with_buffers;

/// Handle fallback to HTTP backend for non-trojan traffic.
pub async fn handle_fallback<S>(
    stream: S,
    buffered: Bytes,
    state: Arc<ServerState>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(peer = %peer, fallback = %state.fallback_addr, buffered_bytes = buffered.len(), "connecting to fallback");

    // Get connection from pool or create new one
    let mut backend = match &state.fallback_pool {
        Some(pool) => pool.get().await?,
        None => {
            connect_with_buffers(
                state.fallback_addr,
                state.tcp_send_buffer,
                state.tcp_recv_buffer,
            )
            .await?
        }
    };

    if !buffered.is_empty() {
        backend.write_all(&buffered).await?;
    }
    relay_with_idle_timeout_and_metrics(
        stream,
        backend,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
    )
    .await?;
    debug!(peer = %peer, fallback = %state.fallback_addr, "fallback relay finished");

    // Note: We don't return the connection to the pool after relay because
    // bidirectional relay typically closes both sides of the connection.
    // The pool is mainly useful for reducing connection establishment overhead.

    Ok(())
}
