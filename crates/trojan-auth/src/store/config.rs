//! Configuration for [`StoreAuth`](super::StoreAuth).

use std::time::Duration;

/// How traffic is recorded by [`StoreAuth`](super::StoreAuth).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrafficRecordingMode {
    /// Immediate write on each `record_traffic` call.
    /// Most accurate but highest backend load.
    Immediate,

    /// Batch updates at regular intervals via [`TrafficRecorder`](super::TrafficRecorder).
    /// Better performance, slight delay in traffic accounting.
    #[default]
    Batched,

    /// Do not record traffic at all.
    Disabled,
}

/// Shared configuration consumed by [`StoreAuth`](super::StoreAuth).
///
/// Backend-specific configs (e.g. `SqlAuthConfig`) extract a `StoreAuthConfig`
/// internally when constructing the `StoreAuth` wrapper.
#[derive(Debug, Clone)]
pub struct StoreAuthConfig {
    /// Traffic recording mode.
    pub traffic_mode: TrafficRecordingMode,
    /// Batch flush interval (only used with [`TrafficRecordingMode::Batched`]).
    pub batch_flush_interval: Duration,
    /// Maximum pending traffic updates before a forced flush.
    pub batch_max_pending: usize,
    /// Whether to enable authentication result caching.
    pub cache_enabled: bool,
    /// Positive cache entry TTL.
    pub cache_ttl: Duration,
    /// Negative cache entry TTL (invalid-hash rejection cache).
    ///
    /// Set to `Duration::ZERO` to disable negative caching.
    pub neg_cache_ttl: Duration,
}

impl Default for StoreAuthConfig {
    fn default() -> Self {
        Self {
            traffic_mode: TrafficRecordingMode::default(),
            batch_flush_interval: Duration::from_secs(30),
            batch_max_pending: 1000,
            cache_enabled: false,
            cache_ttl: Duration::from_secs(60),
            neg_cache_ttl: Duration::from_secs(5),
        }
    }
}
