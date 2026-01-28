//! TCP CONNECT command handler.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tracing::{debug, instrument};
use trojan_metrics::{
    record_bytes_sent, record_target_bytes, record_target_connect_duration, record_target_connection,
};
use trojan_proto::AddressRef;

use crate::error::ServerError;
use crate::relay::relay_with_idle_timeout_and_metrics_per_target;
use crate::resolve::{resolve_address, target_to_label};
use crate::state::ServerState;
use crate::util::connect_with_buffers;

/// Handle TCP CONNECT command.
#[instrument(level = "debug", skip(stream, payload, state), fields(target = ?address))]
pub async fn handle_connect<S>(
    stream: S,
    address: AddressRef<'_>,
    payload: &[u8],
    state: Arc<ServerState>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = resolve_address(&address).await?;
    let target_label = target_to_label(&address);
    debug!(peer = %peer, target = %target, "connecting to target");

    // Record per-target connection
    record_target_connection(&target_label);

    // Measure target connection time
    let connect_start = Instant::now();
    let mut outbound =
        connect_with_buffers(target, state.tcp_send_buffer, state.tcp_recv_buffer).await?;
    record_target_connect_duration(connect_start.elapsed().as_secs_f64());
    debug!(peer = %peer, target = %target, "target connected");

    if !payload.is_empty() {
        outbound.write_all(payload).await?;
        record_bytes_sent(payload.len() as u64);
        record_target_bytes(&target_label, "sent", payload.len() as u64);
        debug!(peer = %peer, target = %target, bytes = payload.len(), "initial payload sent");
    }
    relay_with_idle_timeout_and_metrics_per_target(
        stream,
        outbound,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
        &target_label,
    )
    .await?;
    debug!(peer = %peer, target = %target, "relay finished");
    Ok(())
}
