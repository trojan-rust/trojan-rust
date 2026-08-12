//! Error type and its HTTP rendering.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Anything that can go wrong serving a request or starting the service.
#[derive(Debug, thiserror::Error)]
pub enum DashError {
    /// Missing or wrong credentials.
    #[error("unauthorized")]
    Unauthorized,

    /// No row matched.
    #[error("not found")]
    NotFound,

    /// The request itself was malformed.
    #[error("{0}")]
    BadRequest(String),

    /// The request body did not decode under the negotiated codec.
    #[error("malformed body: {0}")]
    Codec(String),

    /// The database rejected the statement or is unreachable.
    #[error(transparent)]
    Database(#[from] sqlx::Error),

    /// Configuration is unusable.
    #[error("{0}")]
    Config(String),

    /// Listening or reading from disk failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl IntoResponse for DashError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) | Self::Codec(_) => StatusCode::BAD_REQUEST,
            Self::Database(_) | Self::Config(_) | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Database and IO details describe our internals, not the caller's
        // mistake; they are logged rather than returned.
        let body = match &self {
            Self::Database(e) => {
                tracing::error!(error = %e, "database error");
                "internal error".to_owned()
            }
            Self::Io(e) => {
                tracing::error!(error = %e, "io error");
                "internal error".to_owned()
            }
            other => other.to_string(),
        };

        (status, body).into_response()
    }
}
