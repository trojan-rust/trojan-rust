//! TCP CONNECT command handler.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, instrument, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{
    record_bytes_sent, record_target_bytes, record_target_connect_duration,
    record_target_connection,
};
use trojan_proto::AddressRef;

use crate::error::ServerError;
use crate::relay::relay_with_idle_timeout_and_metrics_per_target;
use crate::resolve::{resolve_all_addresses, target_to_label};
use crate::state::ServerState;
use crate::util::connect_with_buffers;

/// Handle TCP CONNECT command.
#[instrument(level = "debug", skip(stream, payload, state, auth, user_id), fields(target = ?address))]
pub async fn handle_connect<S, A>(
    mut stream: S,
    address: AddressRef<'_>,
    payload: &[u8],
    state: Arc<ServerState>,
    auth: Arc<A>,
    user_id: Option<&str>,
    peer: SocketAddr,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let target_label = target_to_label(&address);
    record_target_connection(&target_label);

    // Resolve + connect with fallthrough across address families. On any
    // pre-relay failure, send TLS close_notify before dropping the stream so
    // the client sees a clean close rather than UnexpectedEof — that bare
    // EOF masks resolve/connect failures and is the symptom users hit when
    // the target's first-resolved family is unreachable.
    let (mut outbound, target) = match dial_target(&address, &state, peer).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = stream.shutdown().await;
            return Err(e);
        }
    };

    let payload_bytes = payload.len() as u64;
    if !payload.is_empty() {
        outbound.write_all(payload).await?;
        record_bytes_sent(payload_bytes);
        record_target_bytes(&target_label, "sent", payload_bytes);
        debug!(peer = %peer, target = %target, bytes = payload.len(), "initial payload sent");
    }
    let stats = relay_with_idle_timeout_and_metrics_per_target(
        stream,
        outbound,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
        &target_label,
    )
    .await?;
    debug!(peer = %peer, target = %target, "relay finished");

    record_traffic_for_user(&*auth, user_id, payload_bytes + stats.total(), peer).await;

    Ok(())
}

/// Resolve all candidate addresses for `address` and try connecting to each
/// in order, returning the first success. If every candidate fails, returns
/// the last `io::Error` encountered.
async fn dial_target(
    address: &AddressRef<'_>,
    state: &ServerState,
    peer: SocketAddr,
) -> Result<(TcpStream, SocketAddr), ServerError> {
    let candidates = resolve_all_addresses(address, &state.dns_resolver).await?;
    let mut last_err: Option<std::io::Error> = None;

    for target in candidates {
        debug!(peer = %peer, target = %target, "connecting to target");
        let connect_start = Instant::now();
        match connect_with_buffers(
            target,
            state.tcp_send_buffer,
            state.tcp_recv_buffer,
            &state.tcp_config,
        )
        .await
        {
            Ok(stream) => {
                record_target_connect_duration(connect_start.elapsed().as_secs_f64());
                debug!(peer = %peer, target = %target, "target connected");
                return Ok((stream, target));
            }
            Err(e) => {
                debug!(peer = %peer, target = %target, error = %e, "connect attempt failed");
                last_err = Some(e);
            }
        }
    }

    Err(ServerError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no resolved address connected",
        )
    })))
}

/// Record traffic for a user if a user_id is available.
pub(crate) async fn record_traffic_for_user<A: AuthBackend + ?Sized>(
    auth: &A,
    user_id: Option<&str>,
    bytes: u64,
    peer: SocketAddr,
) {
    if bytes == 0 {
        return;
    }
    if let Some(uid) = user_id
        && let Err(e) = auth.record_traffic(uid, bytes).await
    {
        warn!(peer = %peer, user_id = uid, error = %e, "failed to record traffic");
    }
}
