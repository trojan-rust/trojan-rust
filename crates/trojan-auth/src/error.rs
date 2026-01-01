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
}

impl AuthError {
    /// Create a backend error from any error type.
    #[inline]
    pub fn backend<E: std::fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}
