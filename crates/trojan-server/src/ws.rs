//! WebSocket transport support.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Error as WsError,
        Message,
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
    },
};
use tracing::{debug, warn};
use trojan_config::WebSocketConfig as WsCfg;

use crate::error::ServerError;
use crate::util::PrefixedStream;

/// Initial buffer size for reading HTTP headers during WebSocket upgrade.
pub const INITIAL_BUFFER_SIZE: usize = 2048;

const HTTP_HEADER_END: &[u8] = b"\r\n\r\n";

pub enum WsInspect {
    NeedMore,
    NotHttp,
    HttpFallback,
    Upgrade,
    Reject(&'static str),
}

/// Inspect buffered bytes for WebSocket upgrade in mixed mode.
pub fn inspect_mixed(buf: &[u8], cfg: &WsCfg) -> WsInspect {
    let header_end = find_header_end(buf);
    if header_end.is_none() {
        return WsInspect::NeedMore;
    }
    let header_end = header_end.unwrap();
    let header_bytes = &buf[..header_end];
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(v) => v,
        Err(_) => return WsInspect::NotHttp,
    };
    let mut lines = header_str.split("\r\n");
    let request_line = match lines.next() {
        Some(v) => v,
        None => return WsInspect::NotHttp,
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return WsInspect::NotHttp;
    }
    if method != "GET" {
        return WsInspect::HttpFallback;
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut ws_key = false;
    let mut host: Option<&str> = None;

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value_trim = value.trim();
            let value_lower = value_trim.to_ascii_lowercase();
            match name.as_str() {
                "upgrade" => {
                    if value_lower.contains("websocket") {
                        upgrade = true;
                    }
                }
                "connection" => {
                    if value_lower.contains("upgrade") {
                        connection_upgrade = true;
                    }
                }
                "sec-websocket-key" => {
                    if !value_trim.is_empty() {
                        ws_key = true;
                    }
                }
                "host" => {
                    host = Some(value_trim);
                }
                _ => {}
            }
        }
    }

    if !upgrade || !connection_upgrade || !ws_key {
        return WsInspect::HttpFallback;
    }

    if !path_matches(cfg, path) || !host_matches(cfg, host) {
        return WsInspect::Reject("websocket path/host mismatch");
    }

    WsInspect::Upgrade
}

pub async fn accept_ws<S>(
    stream: S,
    initial: Bytes,
    cfg: &WsCfg,
) -> Result<WebSocketStream<PrefixedStream<S>>, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_frame = if cfg.max_frame_bytes == 0 {
        None
    } else {
        Some(cfg.max_frame_bytes)
    };
    let ws_cfg = WebSocketConfig {
        max_frame_size: max_frame,
        max_message_size: max_frame,
        ..WebSocketConfig::default()
    };
    let prefixed = PrefixedStream::new(initial, stream);
    let ws = accept_hdr_async_with_config(prefixed, |req: &Request, resp: Response| {
        debug!(path = %req.uri().path(), "websocket upgrade");
        Ok(resp)
    }, Some(ws_cfg))
    .await
    .map_err(|e| ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("websocket handshake failed: {e}"),
    )))?;
    Ok(ws)
}

pub async fn send_reject<S>(mut stream: S, reason: &'static str) -> Result<(), ServerError>
where
    S: AsyncWrite + Unpin,
{
    warn!(reason, "websocket rejected");
    let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut stream, response).await?;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(HTTP_HEADER_END.len())
        .position(|w| w == HTTP_HEADER_END)
        .map(|idx| idx + HTTP_HEADER_END.len())
}

fn path_matches(cfg: &WsCfg, path: &str) -> bool {
    let path_only = path.split('?').next().unwrap_or("");
    path_only == cfg.path
}

fn host_matches(cfg: &WsCfg, host: Option<&str>) -> bool {
    let expected = match cfg.host.as_deref() {
        Some(v) => v,
        None => return true,
    };
    let host = match host {
        Some(v) => v,
        None => return false,
    };
    let host_only = host.split(':').next().unwrap_or("");
    host_only.eq_ignore_ascii_case(expected)
}

/// WebSocket stream adapter that exposes AsyncRead/AsyncWrite using binary frames.
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    read_buf: Bytes,
}

impl<S> WsIo<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: Bytes::new(),
        }
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
        if !self.read_buf.is_empty() {
            let to_copy = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf = self.read_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

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
                        self.read_buf = Bytes::from(text.into_bytes());
                        let to_copy = self.read_buf.len().min(buf.remaining());
                        buf.put_slice(&self.read_buf[..to_copy]);
                        self.read_buf = self.read_buf.slice(to_copy..);
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(payload) => {
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let ws = Pin::new(&mut self.ws);
        ws.poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let ws = Pin::new(&mut self.ws);
        ws.poll_close(cx).map_err(ws_err)
    }
}

fn ws_err(err: WsError) -> std::io::Error {
    std::io::Error::other(err)
}
