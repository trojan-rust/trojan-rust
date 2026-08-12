//! The HTTP auth protocol.
//!
//! These are the exact structures exchanged with the dashboard worker (`dash`
//! in this repo) over `/verify` and `/traffic`. Both the node
//! ([`crate::http`]) and the worker
//! depend on this module, so the contract has one definition rather than two
//! hand-synchronized copies.
//!
//! Responses carry a serialized `Result<T, AuthError>`: [`AuthResult`] for
//! `/verify`, `()` for `/traffic`.
//!
//! # Compatibility
//!
//! The default codec is bincode 1.x, which encodes struct fields by position
//! and enum variants by index — no names travel on the wire. Reordering a
//! field, inserting an [`AuthError`] variant anywhere but the end, or changing
//! an integer width misdecodes silently on the peer instead of erroring. Treat
//! any such edit as a breaking release of this crate, and roll the worker out
//! before the nodes.

use serde::{Deserialize, Serialize};

/// `POST /verify` request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// SHA-224 hex digest of the password, as sent in the Trojan handshake.
    pub hash: String,
}

/// `POST /traffic` request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficRequest {
    /// User the traffic belongs to, as returned by `/verify`.
    pub user_id: String,
    /// Bytes to add to the user's usage counter.
    pub bytes: u64,
}

/// `POST /traffic/chain` request body.
///
/// Reports bytes another node carried for a user: the relay hops a connection
/// crossed on its way to the node sending this. Those hops cannot see who
/// their traffic belongs to — the trojan handshake is inside end-to-end TLS
/// only the exit terminates — so the exit reports on their behalf.
///
/// The bytes are the same ones the matching [`TrafficRequest`] carries, not
/// additional ones, and they do not move the user's quota: a three-hop chain
/// should not cost a user three times what it moved.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainTrafficRequest {
    /// User the traffic belongs to, as returned by `/verify`.
    pub user_id: String,
    /// The hop being credited, as the entry node named it.
    pub node_id: String,
    /// Bytes that hop carried.
    pub bytes: u64,
}

/// Successful `/verify` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    /// Identifier of the matched user, `None` when the hash is unknown.
    pub user_id: Option<String>,
    /// Quota and validity of the matched user.
    pub metadata: Option<AuthMetadata>,
}

/// Quota and validity attached to an [`AuthResult`].
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthMetadata {
    /// Byte quota, `0` for unlimited.
    pub traffic_limit: u64,
    /// Bytes consumed so far.
    pub traffic_used: u64,
    /// Expiry as a Unix timestamp in seconds, `0` for never.
    pub expires_at: u64,
    /// Whether the account is active.
    pub enabled: bool,
    /// Allowances on individual nodes, for the nodes that have one.
    ///
    /// Usually empty. Appended after `enabled`, which per the module note
    /// makes this a breaking change: roll the worker out before the nodes.
    pub node_quotas: Vec<NodeQuota>,
}

/// One node's allowance for a user, over a window the worker chooses.
///
/// Relay hops cannot enforce their own: a hop never learns whose traffic it
/// carries, so the exit checks the hops a connection crossed on their behalf.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeQuota {
    /// The node the allowance is for, named as the relay chain names it.
    pub node_id: String,
    /// Bytes allowed in the window, `0` for unlimited.
    pub limit: u64,
    /// Bytes spent in the window when this answer was built.
    pub used: u64,
}

/// Error response, mirroring [`crate::AuthError`]'s public variants.
///
/// New variants must be appended — see the module-level compatibility note.
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthError {
    /// Credentials did not match.
    Invalid,
    /// The worker's own backend failed.
    Backend(String),
    /// No user for the given hash.
    NotFound,
    /// The user is over quota.
    TrafficExceeded,
    /// The user's validity window has passed.
    Expired,
    /// The user is administratively disabled.
    Disabled,
}
