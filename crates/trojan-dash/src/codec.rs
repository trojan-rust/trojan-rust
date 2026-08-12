//! Wire codec for the node-facing endpoints.
//!
//! Nodes default to bincode and can be configured for JSON; the encoding is
//! announced by `Content-Type` and echoed back on the response. The types
//! themselves live in [`trojan_auth::protocol`], so both ends compile the same
//! definitions.

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode, header};
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
    fn detect(req: &Request) -> Self {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("json"));
        if is_json { Self::Json } else { Self::Bincode }
    }

    fn content_type(self) -> HeaderValue {
        match self {
            Self::Json => HeaderValue::from_static("application/json"),
            Self::Bincode => HeaderValue::from_static("application/octet-stream"),
        }
    }
}

/// A decoded request body, carrying the codec it arrived in so the handler can
/// answer in the same one.
#[derive(Debug)]
pub struct Wire<T> {
    pub codec: Codec,
    pub body: T,
}

impl<S, T> FromRequest<S> for Wire<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = DashError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let codec = Codec::detect(&req);
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| DashError::Codec(e.to_string()))?;

        let body = match codec {
            Codec::Json => {
                serde_json::from_slice(&bytes).map_err(|e| DashError::Codec(e.to_string()))?
            }
            Codec::Bincode => {
                bincode::deserialize(&bytes).map_err(|e| DashError::Codec(e.to_string()))?
            }
        };

        Ok(Self { codec, body })
    }
}

/// Encode a response in the codec the request arrived in.
///
/// Protocol-level outcomes — an unknown hash, an expired account — travel as
/// an encoded `Err` under HTTP 200, because they are answers rather than
/// transport failures. Only a broken request or a broken backend gets a
/// non-2xx status.
pub fn encode<T: Serialize>(codec: Codec, value: &T) -> Result<Response, DashError> {
    let bytes = match codec {
        Codec::Json => serde_json::to_vec(value).map_err(|e| DashError::Serde(e.to_string()))?,
        Codec::Bincode => bincode::serialize(value).map_err(|e| DashError::Serde(e.to_string()))?,
    };

    let mut response = (StatusCode::OK, Body::from(bytes)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, codec.content_type());
    Ok(response)
}
