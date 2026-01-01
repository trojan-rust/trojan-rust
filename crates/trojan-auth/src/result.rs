//! Authentication result types.

/// Result of a successful authentication.
#[derive(Debug, Clone, Default)]
pub struct AuthResult {
    /// Optional user identifier for logging/metrics.
    pub user_id: Option<String>,

    /// Optional user metadata.
    pub metadata: Option<AuthMetadata>,
}

impl AuthResult {
    /// Create a new auth result with no user ID.
    #[inline]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Create a new auth result with a user ID.
    #[inline]
    pub fn with_user_id(user_id: impl Into<String>) -> Self {
        Self {
            user_id: Some(user_id.into()),
            metadata: None,
        }
    }

    /// Add metadata to the result.
    #[inline]
    pub fn with_metadata(mut self, metadata: AuthMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Optional metadata associated with an authenticated user.
#[derive(Debug, Clone, Default)]
pub struct AuthMetadata {
    /// Traffic limit in bytes (0 = unlimited).
    pub traffic_limit: u64,

    /// Traffic used in bytes.
    pub traffic_used: u64,

    /// Expiration timestamp (0 = never).
    pub expires_at: u64,

    /// Whether the user is enabled.
    pub enabled: bool,
}

impl AuthMetadata {
    /// Create new metadata with defaults (unlimited, enabled).
    pub fn new() -> Self {
        Self {
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
        }
    }

    /// Check if the user has exceeded their traffic limit.
    #[inline]
    pub fn is_over_limit(&self) -> bool {
        self.traffic_limit > 0 && self.traffic_used >= self.traffic_limit
    }

    /// Check if the user has expired.
    #[inline]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at > 0 && now >= self.expires_at
    }
}
