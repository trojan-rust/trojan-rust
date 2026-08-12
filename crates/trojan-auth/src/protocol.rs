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
