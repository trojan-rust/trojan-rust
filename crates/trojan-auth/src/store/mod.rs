//! Generic store-based authentication.
//!
//! This module provides:
//!
//! - [`UserRecord`] — universal user data from any store
//! - [`UserStore`] — data-access trait (implement this for new backends)
//! - [`StoreAuth`] — generic wrapper that adds validation + caching + traffic batching
//! - [`AuthCache`] / [`CacheStats`] / [`CachedUser`] — optional result cache
//! - [`TrafficRecorder`] — optional batched traffic writer (requires `batched-traffic` feature)
//! - [`StoreAuthConfig`] / [`TrafficRecordingMode`] — configuration types
//!
//! # Adding a new backend
//!
//! ```ignore
//! use trojan_auth::store::{UserStore, UserRecord, StoreAuth, StoreAuthConfig};
//!
//! struct MyStore { /* ... */ }
//!
//! #[async_trait::async_trait]
//! impl UserStore for MyStore {
//!     async fn find_by_hash(&self, hash: &str) -> Result<Option<UserRecord>, AuthError> { todo!() }
//!     async fn add_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> { todo!() }
//! }
//!
//! // Then construct: StoreAuth::new(MyStore { .. }, config)
//! ```

mod auth;
mod cache;
mod config;
mod record;
mod traits;

#[cfg(feature = "batched-traffic")]
mod traffic;

pub use auth::StoreAuth;
pub use cache::{AuthCache, CacheStats, CachedUser};
pub use config::{StoreAuthConfig, TrafficRecordingMode};
pub use record::UserRecord;
pub use traits::UserStore;

#[cfg(feature = "batched-traffic")]
pub use traffic::{FlushFn, FlushFuture, TrafficRecorder};
