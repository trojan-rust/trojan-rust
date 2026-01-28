//! WebSocket transport support.
//!
//! This module provides WebSocket upgrade handling for the server.
//! The `WsIo` adapter is provided by `trojan-core::transport`.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
    },
};
use tracing::{debug, warn};
use trojan_config::WebSocketConfig as WsCfg;

use crate::error::ServerError;
use crate::util::PrefixedStream;

// Re-export WsIo from trojan-core for convenience
pub use trojan_core::transport::WsIo;

/// Initial buffer size for reading HTTP headers during WebSocket upgrade.
pub const INITIAL_BUFFER_SIZE: usize = 2048;

const HTTP_HEADER_END: &[u8] = b"\r\n\r\n";

/// Result of inspecting buffered bytes for WebSocket upgrade.
pub enum WsInspect {
    /// Need more data to determine protocol.
    NeedMore,
    /// Not HTTP traffic, proceed as raw Trojan.
    NotHttp,
    /// HTTP but not WebSocket upgrade, fallback to HTTP backend.
    HttpFallback,
    /// Valid WebSocket upgrade request.
    Upgrade,
    /// Reject with reason (e.g., path/host mismatch).
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

/// Accept a WebSocket upgrade on the given stream.
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
    let ws = accept_hdr_async_with_config(
        prefixed,
        |req: &Request, resp: Response| {
            debug!(path = %req.uri().path(), "websocket upgrade");
            Ok(resp)
        },
        Some(ws_cfg),
    )
    .await
    .map_err(|e| {
        ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("websocket handshake failed: {e}"),
        ))
    })?;
    Ok(ws)
}

/// Send an HTTP 400 Bad Request response to reject the connection.
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
