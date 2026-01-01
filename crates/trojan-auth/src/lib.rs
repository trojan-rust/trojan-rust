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

mod error;
mod hash;
mod memory;
mod reloadable;
mod result;
mod traits;

pub use error::AuthError;
pub use hash::{sha224_hex, verify_password};
pub use memory::MemoryAuth;
pub use reloadable::ReloadableAuth;
pub use result::{AuthMetadata, AuthResult};
pub use traits::AuthBackend;

// Backward compatibility alias
#[doc(hidden)]
pub use memory::HashSetAuth;
