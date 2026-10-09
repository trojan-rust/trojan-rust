//! Prometheus exporter startup for entry and relay nodes.

use tracing::info;

use crate::config::MetricsConfig;
use crate::error::RelayError;

/// Start the Prometheus exporter when the config asks for one.
///
/// Counter handles bind to whichever recorder is installed at the moment they
/// are resolved, so this has to run before the first session builds its
/// counters — otherwise that session reports into the no-op recorder for its
/// whole lifetime.
pub(crate) async fn start_exporter(
    config: &MetricsConfig,
) -> Result<Option<trojan_metrics::MetricsServer>, RelayError> {
    if let Some(tls) = &config.tls {
        if config.listen.is_none() {
            return Err(RelayError::Config(
                "metrics.listen is required when metrics.tls is configured".into(),
            ));
        }
        tls.validate()
            .map_err(|error| RelayError::Config(error.into()))?;
    }
    let Some(listen) = config.listen else {
        return Ok(None);
    };

    let server =
        trojan_metrics::init_metrics_server(&listen.to_string(), config.tls.as_ref(), None).await?;
    info!(%listen, "metrics exporter bound");
    Ok(Some(server))
}
