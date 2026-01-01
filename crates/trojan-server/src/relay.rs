//! Bidirectional data relay with metrics.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use trojan_metrics::{record_bytes_received, record_bytes_sent, record_target_bytes};

use crate::error::ServerError;

/// Bidirectional relay with proper half-close handling and metrics.
///
/// When one side closes, we continue reading from the other side until it also closes,
/// ensuring all data is properly transferred in both directions.
pub async fn relay_with_idle_timeout_and_metrics<A, B>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
) -> Result<(), ServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_with_idle_timeout_and_metrics_per_target(inbound, outbound, idle_timeout, buffer_size, "")
        .await
}

/// Bidirectional relay with per-target metrics tracking.
pub async fn relay_with_idle_timeout_and_metrics_per_target<A, B>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
    target_label: &str,
) -> Result<(), ServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let (mut out_r, mut out_w) = tokio::io::split(outbound);

    let mut buf_in = vec![0u8; buffer_size];
    let mut buf_out = vec![0u8; buffer_size];
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut in_closed = false;
    let mut out_closed = false;
    let track_target = !target_label.is_empty();

    loop {
        if in_closed && out_closed {
            return Ok(());
        }

        tokio::select! {
            res = in_r.read(&mut buf_in), if !in_closed => {
                match res {
                    Ok(0) => {
                        in_closed = true;
                        let _ = out_w.shutdown().await;
                    }
                    Ok(n) => {
                        record_bytes_received(n as u64);
                        if track_target {
                            record_target_bytes(target_label, "sent", n as u64);
                        }
                        out_w.write_all(&buf_in[..n]).await?;
                        idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            res = out_r.read(&mut buf_out), if !out_closed => {
                match res {
                    Ok(0) => {
                        out_closed = true;
                        let _ = in_w.shutdown().await;
                    }
                    Ok(n) => {
                        record_bytes_sent(n as u64);
                        if track_target {
                            record_target_bytes(target_label, "received", n as u64);
                        }
                        in_w.write_all(&buf_out[..n]).await?;
                        idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ = &mut idle_sleep => {
                return Ok(());
            }
        }
    }
}
