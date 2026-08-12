//! TCP CONNECT command handler.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, instrument, warn};
use trojan_auth::AuthBackend;
use trojan_metrics::{record_target_connect_duration, record_target_connection};
use trojan_proto::AddressRef;

use crate::error::ServerError;
use crate::handler::AnalyticsEvent;
use crate::relay::relay_with_counters;
use crate::resolve::{resolve_all_addresses, target_to_label};
use crate::state::ServerState;
use crate::util::connect_with_buffers;

#[expect(
    clippy::too_many_arguments,
    reason = "one connection's worth of state; a struct here would only rename the fields"
)]
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
    analytics: AnalyticsEvent,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let target_label = target_to_label(&address);
    record_target_connection(&target_label);
    // Resolved once here rather than per flush inside the relay loop.
    let counters = state.relay_counters(&target_label);

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
        // A target that closes as soon as it accepts makes this write fail,
        // and returning straight out would drop the TLS stream without a
        // close_notify — the client then cannot tell a refused target from a
        // truncation. Same contract as the dial failure above.
        if let Err(e) = outbound.write_all(payload).await {
            let _ = stream.shutdown().await;
            return Err(e.into());
        }
        // Client → target, the same direction the relay loop reports as
        // inbound. Previously counted against the "bytes sent to client"
        // global, which contradicted how the relay attributes the rest of
        // that stream.
        counters.add_to_target(payload_bytes);
        debug!(peer = %peer, target = %target, bytes = payload.len(), "initial payload sent");
    }
    let result = relay_with_counters(
        stream,
        outbound,
        state.tcp_idle_timeout,
        state.relay_buffer_size,
        &counters,
    )
    .await;

    // Account for the bytes however the relay ended. A client that vanishes
    // without a close_notify — a killed app, a dropped mobile link, an RST —
    // makes this an error, and billing only the success path let that traffic
    // through free on a server enforcing `traffic_limit`. The counters carry a
    // running total precisely so this does not depend on `RelayStats`.
    record_traffic_for_user(&*auth, user_id, counters.total_bytes(), peer).await;
    finish_analytics(analytics, &counters, &result);

    result?;
    debug!(peer = %peer, target = %target, "relay finished");

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

/// Complete the connection's analytics event.
///
/// Byte counts come from the relay counters rather than `RelayStats`, so an
/// aborted session still reports what it moved, and the close reason
/// distinguishes a clean end from a failure. Without this the event shipped
/// with its byte fields at zero.
#[cfg_attr(
    not(feature = "analytics"),
    expect(
        unused_variables,
        reason = "the whole body is behind cfg(analytics); with it off there is \
                  nothing to record and every parameter goes unread"
    )
)]
pub(crate) fn finish_analytics(
    analytics: crate::handler::AnalyticsEvent,
    counters: &trojan_metrics::RelayCounters,
    result: &Result<trojan_core::io::RelayStats, ServerError>,
) {
    #[cfg(feature = "analytics")]
    if let Some(mut event) = analytics {
        // `add_to_target` is the client → target direction, which the event
        // records as bytes sent.
        event.add_bytes(counters.sent_to_target(), counters.sent_to_client());
        event.finish(match result {
            Ok(_) => trojan_analytics::CloseReason::Normal,
            Err(_) => trojan_analytics::CloseReason::Error,
        });
    }
}
