use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use super::{Error, Result};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Stream for S {}
pub type Connection = Box<dyn Stream>;
type Start = watch::Receiver<Option<Instant>>;

pub async fn warmup(stream: &mut Connection, bytes: usize) -> Result<()> {
    let payload = vec![0x5a; bytes];
    let mut reply = vec![0; bytes];
    for _ in 0..8 {
        exchange(stream, &payload, &mut reply).await?;
    }
    Ok(())
}

async fn exchange(stream: &mut Connection, payload: &[u8], reply: &mut [u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(payload).await?;
        stream.flush().await?;
        stream.read_exact(reply).await?;
        if reply != payload {
            return Err(io::Error::other("echo payload mismatch"));
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}

pub async fn latency(
    mut stream: Connection,
    payload: Arc<Vec<u8>>,
    mut start: Start,
) -> Result<(Connection, Vec<u64>)> {
    start.changed().await?;
    let deadline = start.borrow().expect("measurement start was published");
    let mut reply = vec![0; payload.len()];
    let mut samples = Vec::new();
    while Instant::now() < deadline {
        let began = Instant::now();
        exchange(&mut stream, &payload, &mut reply).await?;
        samples.push(u64::try_from(began.elapsed().as_nanos())?);
    }
    Ok((stream, samples))
}

pub async fn bulk(stream: Connection, payload: Arc<Vec<u8>>, mut start: Start) -> Result<u64> {
    start.changed().await?;
    let deadline = start.borrow().expect("measurement start was published");
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Read concurrently with writes so socket backpressure cannot deadlock the echo path.
    let send = async {
        let mut sent = 0u64;
        while Instant::now() < deadline {
            writer.write_all(&payload).await?;
            sent += payload.len() as u64;
        }
        writer.shutdown().await?;
        Ok::<_, Error>(sent)
    };
    let receive = async {
        let mut received = 0u64;
        let mut buf = vec![0; payload.len()];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if buf[..n].iter().any(|&byte| byte != 0xa5) {
                return Err(io::Error::other("bulk echo payload mismatch").into());
            }
            received += n as u64;
        }
        Ok::<_, Error>(received)
    };
    let limit = deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(15);
    let (sent, received) =
        tokio::time::timeout(limit, async { tokio::try_join!(send, receive) }).await??;
    if sent != received {
        return Err(io::Error::other(format!(
            "echo byte count mismatch: sent {sent}, received {received}"
        ))
        .into());
    }
    Ok(received)
}
