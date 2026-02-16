//! Agent error types.

use crate::protocol::ErrorCode;

/// Agent error type.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("websocket: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("bincode: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error("panel error ({code:?}): {message}")]
    Panel { code: ErrorCode, message: String },

    #[error("registration failed: {0}")]
    Registration(String),

    #[error("service error: {0}")]
    Service(String),

    #[error("cache: {0}")]
    Cache(String),

    #[error("protocol version mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: u32, got: u32 },

    #[error("connection closed")]
    ConnectionClosed,
}
