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

/// One node's allowance for a user, as the panel computed it.
///
/// The window the figures cover — currently a calendar month in UTC — is the
/// panel's business: it publishes two numbers, and a node only ever asks
/// whether one has reached the other. Changing the window changes nothing
/// here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeQuota {
    /// The node this allowance is for, named as the relay chain names it.
    pub node_id: String,

    /// Bytes allowed in the panel's window. Zero means unlimited.
    pub limit: u64,

    /// Bytes already spent in that window when the panel answered.
    pub used: u64,
}

impl NodeQuota {
    /// Whether `extra` bytes on top of the panel's figure reach the limit.
    ///
    /// `extra` is what the caller knows and the panel does not — bytes
    /// recorded here but not yet reported. Passing zero asks the question the
    /// panel would answer.
    #[inline]
    pub fn is_exceeded(&self, extra: u64) -> bool {
        self.limit > 0 && self.used.saturating_add(extra) >= self.limit
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

    /// Per-node allowances, for the nodes that have one.
    ///
    /// Usually empty: a node only appears here when an operator has capped
    /// this user on it. A relay hop cannot enforce its own cap — it never
    /// learns whose traffic it carries — so the exit checks the hops a
    /// connection crossed against this list.
    pub node_quotas: Vec<NodeQuota>,
}

impl AuthMetadata {
    /// Create new metadata with defaults (unlimited, enabled).
    pub fn new() -> Self {
        Self {
            traffic_limit: 0,
            traffic_used: 0,
            expires_at: 0,
            enabled: true,
            node_quotas: Vec::new(),
        }
    }

    /// The first node in `chain` whose allowance is spent, if any.
    ///
    /// `pending` supplies bytes the caller has recorded for a node but not yet
    /// reported, so a decision made between two reports still counts them.
    pub fn exhausted_hop<F>(&self, chain: &[String], pending: F) -> Option<&NodeQuota>
    where
        F: Fn(&str) -> u64,
    {
        self.node_quotas
            .iter()
            .filter(|quota| chain.contains(&quota.node_id))
            .find(|quota| quota.is_exceeded(pending(&quota.node_id)))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(node_id: &str, limit: u64, used: u64) -> NodeQuota {
        NodeQuota {
            node_id: node_id.to_owned(),
            limit,
            used,
        }
    }

    fn metadata(quotas: Vec<NodeQuota>) -> AuthMetadata {
        AuthMetadata {
            node_quotas: quotas,
            ..AuthMetadata::new()
        }
    }

    #[test]
    fn a_hop_the_connection_did_not_cross_is_not_charged() {
        let meta = metadata(vec![quota("entry-a", 100, 100)]);

        assert!(
            meta.exhausted_hop(&["entry-b".to_owned()], |_| 0).is_none(),
            "only the hops a connection actually crossed may block it"
        );
    }

    #[test]
    fn a_spent_hop_on_the_path_blocks() {
        let meta = metadata(vec![quota("entry-a", 100, 100)]);

        let hop = meta
            .exhausted_hop(&["entry-a".to_owned(), "relay-b".to_owned()], |_| 0)
            .expect("a spent allowance on the path should block");
        assert_eq!(hop.node_id, "entry-a");
    }

    /// Reports are batched, so between two of them the panel's figure is
    /// behind by whatever this node is holding.
    #[test]
    fn unreported_bytes_count_towards_the_limit() {
        let meta = metadata(vec![quota("entry-a", 100, 60)]);
        let path = ["entry-a".to_owned()];

        assert!(meta.exhausted_hop(&path, |_| 0).is_none());
        assert!(meta.exhausted_hop(&path, |_| 40).is_some());
    }

    #[test]
    fn a_zero_limit_is_unlimited() {
        let meta = metadata(vec![quota("entry-a", 0, u64::MAX)]);

        assert!(
            meta.exhausted_hop(&["entry-a".to_owned()], |_| u64::MAX)
                .is_none(),
            "zero is the documented unlimited sentinel"
        );
    }
}
