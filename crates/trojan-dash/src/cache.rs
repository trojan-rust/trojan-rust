//! In-process caches for the two hot read paths.
//!
//! Both are read on every node call and change only through the admin API, so
//! the entries are written straight through on update and dropped on delete —
//! a stale answer here would let a disabled account keep connecting.

use std::time::Duration;

use moka::future::Cache;

use crate::entity::sub_templates;
use crate::types::CacheData;

/// The caches, cloned into every handler through [`crate::state::AppState`].
#[derive(Debug, Clone)]
pub struct Caches {
    /// `hash -> CacheData`, for `/verify`.
    pub verify: Cache<String, CacheData>,
    /// `name -> template`, for the public `/sub/{name}`.
    pub sub: Cache<String, sub_templates::Model>,
}

impl Caches {
    pub fn new(verify_ttl: Duration, sub_ttl: Duration) -> Self {
        Self {
            verify: Cache::builder()
                .time_to_live(verify_ttl)
                .max_capacity(100_000)
                .build(),
            sub: Cache::builder()
                .time_to_live(sub_ttl)
                .max_capacity(1_000)
                .build(),
        }
    }
}
