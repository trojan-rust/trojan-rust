//! Authentication backends for trojan.
//!
//! This crate provides authentication backends for the Trojan protocol.
//!
//! # Example
//!
//! ```
//! use trojan_auth::{AuthBackend, MemoryAuth, sha224_hex};
//!
//! # async fn example() -> Result<(), trojan_auth::AuthError> {
//! // Create an auth backend from passwords
//! let auth = MemoryAuth::from_passwords(["my_password"]);
//!
//! // Verify a hash
//! let hash = sha224_hex("my_password");
//! let result = auth.verify(&hash).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # SQL Backend
//!
//! Enable the `sql-postgres`, `sql-mysql`, or `sql-sqlite` feature to use
//! SQL database authentication:
//!
//! ```toml
//! [dependencies]
//! trojan-auth = { version = "0.1", features = ["sql-postgres"] }
//! ```
//!
//! See the [`sql`] module for more details.

mod error;
mod hash;
mod memory;
mod reloadable;
mod result;
mod traits;

// Generic store-based auth (always compiled; only depends on parking_lot + std)
pub mod store;

// SQL backend (optional feature)
#[cfg(feature = "sql")]
pub mod sql;

// HTTP backend (optional feature)
#[cfg(feature = "http")]
pub mod http;

// CLI module (optional feature)
#[cfg(feature = "cli")]
pub mod cli;

pub use error::AuthError;
pub use hash::{sha224_hex, verify_password};
pub use memory::MemoryAuth;
pub use reloadable::ReloadableAuth;
pub use result::{AuthMetadata, AuthResult};
pub use traits::AuthBackend;

#[cfg(feature = "cli")]
pub use cli::AuthArgs;

// Backward compatibility alias
#[doc(hidden)]
pub use memory::HashSetAuth;
