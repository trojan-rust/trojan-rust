//! Prometheus exporter startup for entry and relay nodes.

use tracing::{info, warn};

use crate::config::MetricsConfig;

/// Start the Prometheus exporter when the config asks for one.
///
/// Counter handles bind to whichever recorder is installed at the moment they
/// are resolved, so this has to run before the first session builds its
/// counters — otherwise that session reports into the no-op recorder for its
/// whole lifetime.
pub(crate) fn start_exporter(config: &MetricsConfig) {
    let Some(listen) = config.listen else {
        return;
    };

    match trojan_metrics::init_metrics_server(&listen.to_string(), None) {
        Ok(_task) => info!(%listen, "metrics exporter started"),
        // The recorder is process-global. When the agent restarts a service
        // in-place after a config push, the second install fails while the
        // first exporter keeps serving — nothing is lost, and taking the node
        // down over it would turn a working export into an outage.
        Err(e) => warn!(error = %e, "metrics exporter unavailable"),
    }
}
