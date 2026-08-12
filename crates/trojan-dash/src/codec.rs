//! Wire codec for the node-facing endpoints.
//!
//! Nodes default to bincode and can be configured for JSON; the encoding is
//! announced by `Content-Type` and echoed back on the response. The types
//! themselves live in [`trojan_auth::protocol`], so both ends compile the same
//! definitions.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::DashError;

/// Serialization used for one request/response pair.
#[derive(Debug, Clone, Copy)]
pub enum Codec {
    /// Compact binary, the node default.
    Bincode,
    /// Readable, for debugging with curl.
    Json,
}

impl Codec {
    /// Pick the codec the caller used.
    pub fn detect(headers: &HeaderMap) -> Self {
        let is_json = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("json"));
        if is_json { Self::Json } else { Self::Bincode }
    }

    /// Decode a request body.
    pub fn decode<T: DeserializeOwned>(self, body: &Bytes) -> Result<T, DashError> {
        match self {
            Self::Bincode => {
                bincode::deserialize(body).map_err(|e| DashError::Codec(e.to_string()))
            }
            Self::Json => serde_json::from_slice(body).map_err(|e| DashError::Codec(e.to_string())),
        }
    }

    /// Encode a response body.
    ///
    /// Protocol-level outcomes — an unknown hash, an expired account — travel
    /// as an encoded `Err` under HTTP 200, because they are answers rather
    /// than transport failures. Only a broken request or a broken backend
    /// gets a non-2xx status.
    pub fn encode<T: Serialize>(self, value: &T) -> Response {
        match self {
            Self::Bincode => match bincode::serialize(value) {
                Ok(bytes) => {
                    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to encode response");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            },
            Self::Json => axum::Json(value).into_response(),
        }
    }
}
