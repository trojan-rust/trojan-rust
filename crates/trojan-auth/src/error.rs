//! Authentication error types.

/// Authentication error.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Invalid credentials provided.
    #[error("invalid credential")]
    Invalid,

    /// Backend error (database, network, etc.).
    #[error("backend error: {0}")]
    Backend(String),

    /// Rate limited.
    #[error("rate limited")]
    RateLimited,

    /// User not found.
    #[error("user not found")]
    NotFound,

    /// Traffic limit exceeded.
    #[error("traffic limit exceeded")]
    TrafficExceeded,

    /// Account expired.
    #[error("account expired")]
    Expired,

    /// Account disabled.
    #[error("account disabled")]
    Disabled,
}

impl AuthError {
    /// Create a backend error from any error type.
    #[inline]
    pub fn backend<E: std::fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}

// SQLx error conversion (only when sql feature enabled)
#[cfg(feature = "sql")]
impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => AuthError::backend(err),
        }
    }
}
