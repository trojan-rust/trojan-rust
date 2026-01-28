//! WebSocket stream adapter.
//!
//! This module provides `WsIo`, an adapter that wraps a `WebSocketStream` and
//! exposes it as `AsyncRead + AsyncWrite` using binary frames. This allows
//! the Trojan protocol to work transparently over WebSocket transport.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    tungstenite::{Error as WsError, Message},
    WebSocketStream,
};

/// WebSocket stream adapter that exposes AsyncRead/AsyncWrite using binary frames.
///
/// This adapter allows the Trojan protocol to work over WebSocket by:
/// - Reading binary/text WebSocket frames as a continuous byte stream
/// - Writing data as binary WebSocket frames
/// - Automatically handling ping/pong frames
/// - Treating close frames as EOF
///
/// # Example
///
/// ```ignore
/// use trojan_core::transport::WsIo;
/// use tokio_tungstenite::WebSocketStream;
///
/// let ws_stream: WebSocketStream<_> = /* ... */;
/// let io = WsIo::new(ws_stream);
///
/// // Now `io` can be used with any code expecting AsyncRead + AsyncWrite
/// relay_bidirectional(client, io, timeout, buffer_size, &metrics).await?;
/// ```
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    read_buf: Bytes,
}

impl<S> WsIo<S> {
    /// Create a new WebSocket I/O adapter.
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: Bytes::new(),
        }
    }

    /// Consumes the adapter and returns the underlying WebSocket stream.
    pub fn into_inner(self) -> WebSocketStream<S> {
        self.ws
    }
}

impl<S> AsyncRead for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, drain any buffered data from previous frame
        if !self.read_buf.is_empty() {
            let to_copy = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf = self.read_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        // Read next WebSocket message
        loop {
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        self.read_buf = Bytes::from(data);
                        let to_copy = self.read_buf.len().min(buf.remaining());
                        buf.put_slice(&self.read_buf[..to_copy]);
                        self.read_buf = self.read_buf.slice(to_copy..);
                        return Poll::Ready(Ok(()));
                    }
                    Message::Text(text) => {
                        // Treat text frames as binary data
                        self.read_buf = Bytes::from(text.into_bytes());
                        let to_copy = self.read_buf.len().min(buf.remaining());
                        buf.put_slice(&self.read_buf[..to_copy]);
                        self.read_buf = self.read_buf.slice(to_copy..);
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(payload) => {
                        // Respond to ping with pong
                        let mut ws = Pin::new(&mut self.ws);
                        match ws.as_mut().poll_ready(cx) {
                            Poll::Ready(Ok(())) => {
                                if let Err(err) = ws.start_send(Message::Pong(payload)) {
                                    return Poll::Ready(Err(ws_err(err)));
                                }
                                continue;
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(ws_err(err))),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Message::Pong(_) => continue,
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    Message::Frame(_) => continue,
                },
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(ws_err(err))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut ws = Pin::new(&mut self.ws);
        match ws.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                if let Err(err) = ws.start_send(Message::Binary(data.to_vec())) {
                    return Poll::Ready(Err(ws_err(err)));
                }
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(ws_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let ws = Pin::new(&mut self.ws);
        ws.poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let ws = Pin::new(&mut self.ws);
        ws.poll_close(cx).map_err(ws_err)
    }
}

fn ws_err(err: WsError) -> std::io::Error {
    std::io::Error::other(err)
}

#[cfg(test)]
mod tests {
    // Note: Testing WsIo requires a full WebSocket mock, which is complex.
    // Integration tests in trojan-server cover the actual usage.
}
