//! Error type and its HTTP rendering.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sea_orm::DbErr;
use serde_json::json;

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

    /// The row would collide with one that exists — a taken username, a
    /// duplicate node name.
    #[error("{0}")]
    Conflict(String),

    /// The request body did not decode under the negotiated codec.
    #[error("malformed body: {0}")]
    Codec(String),

    /// The database rejected the statement or is unreachable.
    #[error(transparent)]
    Database(#[from] DbErr),

    /// A value could not be encoded for the response.
    #[error("serialization: {0}")]
    Serde(String),

    /// Configuration is unusable.
    #[error("{0}")]
    Config(String),

    /// Listening or reading from disk failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl DashError {
    /// Map a database error to the status the caller deserves.
    ///
    /// A unique-constraint violation is the caller naming something already
    /// taken, not a server fault, and 500 would send them looking in the wrong
    /// place.
    pub fn from_db(error: DbErr) -> Self {
        let message = error.to_string();
        if message.contains("UNIQUE") || message.contains("unique") {
            Self::Conflict("that name is already taken".to_owned())
        } else {
            Self::Database(error)
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound | Self::Database(DbErr::RecordNotFound(_)) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) | Self::Codec(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_) | Self::Serde(_) | Self::Config(_) | Self::Io(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for DashError {
    fn into_response(self) -> Response {
        let status = self.status();

        // Database and IO details describe our internals, not the caller's
        // mistake; they are logged rather than returned.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed");
            "internal error".to_owned()
        } else {
            self.to_string()
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
