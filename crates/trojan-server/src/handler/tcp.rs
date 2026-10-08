//! TCP CONNECT command handler.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, instrument};
use trojan_auth::AuthBackend;
use trojan_metrics::record_target_connect_duration;
use trojan_proto::AddressRef;

use crate::error::ServerError;
use crate::handler::Session;
use crate::relay::{relay_with_counters, write_all_counted};
use crate::resolve::{resolve_all_addresses, target_to_label};
use crate::state::ServerState;
use crate::util::connect_candidates;

/// Handle TCP CONNECT command.
#[instrument(level = "debug", skip(stream, payload, session), fields(target = ?address))]
pub(crate) async fn handle_connect<S, A>(
    mut stream: S,
    address: AddressRef<'_>,
    payload: &[u8],
    session: Session<'_, A>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AuthBackend + ?Sized,
{
    let state = &session.state;
    let peer = session.peer;
    let target_label = state.per_target_metrics.then(|| target_to_label(&address));
    // Resolve handles before entering the data path.
    let counters = state.relay_counters(target_label.as_deref());

    // Resolve + connect with fallthrough across address families. On any
    // pre-relay failure, send TLS close_notify before dropping the stream so
    // the client sees a clean close rather than UnexpectedEof — that bare
    // EOF masks resolve/connect failures and is the symptom users hit when
    // the target's first-resolved family is unreachable.
    let (mut outbound, target) = match dial_target(&address, state, peer).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = stream.shutdown().await;
            return Err(e);
        }
    };

    if !payload.is_empty() {
        // A target that closes as soon as it accepts makes this write fail,
        // and returning straight out would drop the TLS stream without a
        // close_notify — the client then cannot tell a refused target from a
        // truncation. Same contract as the dial failure above.
        if let Err(e) = write_all_counted(&mut outbound, payload, |bytes| {
            counters.add_to_target(bytes);
        })
        .await
        {
            let _ = stream.shutdown().await;
            return Err(e.into());
        }
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

    session.settle(&counters, &result).await;

    result?;
    debug!(peer = %peer, target = %target, "relay finished");

    Ok(())
}

/// Resolve candidates and return the first successful connection within the shared deadline.
async fn dial_target(
    address: &AddressRef<'_>,
    state: &ServerState,
    peer: SocketAddr,
) -> Result<(TcpStream, SocketAddr), ServerError> {
    let candidates = resolve_all_addresses(address, &state.dns_resolver).await?;
    let started = Instant::now();
    let (stream, target) = connect_candidates(
        candidates,
        None,
        state.tcp_send_buffer,
        state.tcp_recv_buffer,
        &state.tcp_config,
    )
    .await?;
    record_target_connect_duration(started.elapsed().as_secs_f64());
    debug!(%peer, %target, "target connected");
    Ok((stream, target))
}
