//! Loading the GeoIP databases the server, its metrics and its analytics use.
//!
//! Three consumers may each name a database, and naming the same one is the
//! normal case — so a database is loaded once and shared rather than held
//! three times over.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use trojan_config::Config;
use trojan_rules::config::GeoipConfig;
use trojan_rules::geoip_db::{GeoipDb, geoip_auto_update_task, load_geoip};

/// What identifies one database, so two configs naming it can share an `Arc`.
type Key = (Option<String>, Option<String>, String);

/// The databases each consumer asked for, after sharing.
///
/// Rule matching's own database is absent: the engine was handed it when it
/// was built, so nothing out here needs to hold it a second time.
#[derive(Debug, Default)]
pub(crate) struct GeoipDatabases {
    /// For country-tagging metrics.
    pub metrics: Option<Arc<GeoipDb>>,
    /// For city-level analytics fields.
    #[cfg(feature = "analytics")]
    pub analytics: Option<Arc<GeoipDb>>,
}

/// Load every GeoIP database the config names, sharing repeats, and start a
/// background refresh for each one that asked to be kept current.
pub(crate) async fn load_geoip_databases(
    config: &Config,
    shutdown: &CancellationToken,
) -> GeoipDatabases {
    let mut loader = Loader::default();

    // Rule matching's database, and the fallback for the others.
    let server = match config.server.geoip.as_ref() {
        Some(cfg) => loader.load(cfg).await,
        None => None,
    };

    let metrics = match config.metrics.geoip.as_ref() {
        Some(cfg) => loader.load_refreshing(cfg).await,
        // Nothing of its own: tag with whatever rule matching already uses.
        None => server.clone(),
    };

    #[cfg(feature = "analytics")]
    let analytics = match config.analytics.geoip.as_ref() {
        Some(cfg) => loader.load_refreshing(cfg).await,
        None => None,
    };

    if !loader.loaded.is_empty() {
        info!(
            databases = loader.loaded.len(),
            "GeoIP databases loaded (deduplicated)"
        );
    }
    loader.spawn_refresh_tasks(shutdown);

    GeoipDatabases {
        metrics,
        #[cfg(feature = "analytics")]
        analytics,
    }
}

/// Loads databases, sharing any already loaded from the same source, and
/// collects the ones that want refreshing in the background.
#[derive(Default)]
struct Loader {
    loaded: HashMap<Key, Arc<GeoipDb>>,
    refreshing: Vec<(GeoipConfig, Arc<GeoipDb>)>,
}

impl Loader {
    /// Load `cfg`'s database, or hand back one already loaded from the same
    /// source. A database that fails to load is not fatal — the consumer that
    /// wanted it goes without, rather than the server refusing to start.
    async fn load(&mut self, cfg: &GeoipConfig) -> Option<Arc<GeoipDb>> {
        let key: Key = (cfg.path.clone(), cfg.url.clone(), cfg.source.clone());
        if let Some(existing) = self.loaded.get(&key) {
            return Some(existing.clone());
        }
        match load_geoip(cfg).await {
            Ok(db) => {
                let db = Arc::new(db);
                self.loaded.insert(key, db.clone());
                Some(db)
            }
            Err(e) => {
                warn!(source = %cfg.source, error = %e, "failed to load GeoIP database");
                None
            }
        }
    }

    /// Same as [`load`](Self::load), and mark the database for background
    /// refresh when the config asked for one. A config naming a local `path`
    /// is the operator's file to manage, so it is never fetched over again.
    async fn load_refreshing(&mut self, cfg: &GeoipConfig) -> Option<Arc<GeoipDb>> {
        let db = self.load(cfg).await?;
        if cfg.auto_update && cfg.path.is_none() {
            self.refreshing.push((cfg.clone(), db.clone()));
        }
        Some(db)
    }

    /// Start one refresh task per distinct database.
    ///
    /// Two consumers sharing a database share its `Arc`, so identity — not the
    /// config — is what tells a repeat apart from a second database.
    fn spawn_refresh_tasks(self, shutdown: &CancellationToken) {
        let mut seen = HashSet::new();
        for (cfg, db) in self.refreshing {
            if !seen.insert(Arc::as_ptr(&db).addr()) {
                continue;
            }
            info!(source = %cfg.source, "spawning GeoIP auto-update task");
            let swappable = Arc::new(arc_swap::ArcSwap::from(db));
            tokio::spawn(geoip_auto_update_task(
                cfg,
                swappable,
                shutdown.clone(),
                |success| {
                    if success {
                        trojan_metrics::record_rule_update();
                    } else {
                        trojan_metrics::record_rule_update_error();
                    }
                },
            ));
        }
    }
}
