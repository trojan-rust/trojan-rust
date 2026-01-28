//! SQL database authentication backend.
//!
//! This module provides authentication using SQL databases (PostgreSQL, MySQL, SQLite)
//! through the SQLx library.
//!
//! # Features
//!
//! Enable one or more database features in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! trojan-auth = { version = "0.1", features = ["sql-postgres"] }
//! # or
//! trojan-auth = { version = "0.1", features = ["sql-mysql"] }
//! # or
//! trojan-auth = { version = "0.1", features = ["sql-sqlite"] }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use trojan_auth::sql::{SqlAuth, SqlAuthConfig, TrafficRecordingMode};
//! use std::time::Duration;
//!
//! // Connect with default settings
//! let auth = SqlAuth::connect(
//!     SqlAuthConfig::new("postgres://user:pass@localhost/trojan")
//! ).await?;
//!
//! // Or with custom configuration
//! let config = SqlAuthConfig::new("postgres://user:pass@localhost/trojan")
//!     .max_connections(20)
//!     .traffic_mode(TrafficRecordingMode::Batched)
//!     .batch_flush_interval(Duration::from_secs(10));
//!
//! let auth = SqlAuth::connect(config).await?;
//! ```
//!
//! # Database Schema
//!
//! Create the following table in your database:
//!
//! ```sql
//! CREATE TABLE trojan_users (
//!     id SERIAL PRIMARY KEY,
//!     password_hash VARCHAR(56) NOT NULL UNIQUE,  -- SHA224 hex
//!     user_id VARCHAR(255),
//!     traffic_limit BIGINT DEFAULT 0,   -- 0 = unlimited
//!     traffic_used BIGINT DEFAULT 0,
//!     expires_at BIGINT DEFAULT 0,      -- Unix timestamp, 0 = never
//!     enabled BOOLEAN DEFAULT TRUE
//! );
//!
//! CREATE INDEX idx_trojan_users_hash ON trojan_users(password_hash);
//! ```

mod backend;
mod cache;
mod config;
mod queries;
mod traffic;

#[cfg(test)]
mod tests;

pub use backend::{DatabaseType, SqlAuth};
pub use cache::{AuthCache, CacheStats, CachedUser};
pub use config::{SqlAuthConfig, TrafficRecordingMode};
