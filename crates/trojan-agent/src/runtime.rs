//! Service lifetime and panel reconnection.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cache::{self, CachedConfig};
use crate::client::{self, RegistrationResult};
use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::node_traffic::NodeTraffic;
use crate::protocol::{AgentMessage, PanelMessage, ServiceState};
use crate::{reporter, runner};

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_e2e.rs"]
mod e2e;

#[cfg(test)]
#[path = "runtime_shutdown_tests.rs"]
mod shutdown_tests;

#[cfg(test)]
#[path = "runtime_capability_tests.rs"]
mod capability_tests;

struct Service {
    config: CachedConfig,
    started_at: u64,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), AgentError>>,
    stats: std::sync::Arc<trojan_metrics::NodeStats>,
}

impl Service {
    fn start(config: CachedConfig, sinks: runner::ServiceSinks) -> Self {
        let token = CancellationToken::new();
        let service_token = token.clone();
        let service_config = config.clone();
        let stats = sinks.stats.clone();
        let task = tokio::spawn(async move {
            runner::run_service(
                service_config.node_type,
                &service_config.config,
                sinks,
                service_token,
            )
            .await
        });
        Self {
            config,
            started_at: unix_now(),
            shutdown: token,
            task,
            stats,
        }
    }

    async fn stop(mut self, drain_timeout: Duration) -> Result<(), AgentError> {
        self.shutdown.cancel();
        let result = match tokio::time::timeout(drain_timeout, &mut self.task).await {
            Ok(result) => service_result(result),
            Err(_) => {
                warn!("service drain timed out, aborting service task");
                self.task.abort();
                let _ = (&mut self.task).await;
                Ok(())
            }
        };
        wait_for_connections(&self.stats).await;
        result
    }
}

async fn wait_for_connections(stats: &trojan_metrics::NodeStats) {
    // Runner abort drops owned tasks; wait for their final counter updates.
    while stats.snapshot().connections_active != 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

fn service_result(
    result: Result<Result<(), AgentError>, tokio::task::JoinError>,
) -> Result<(), AgentError> {
    result.map_err(|e| AgentError::Service(format!("service task failed: {e}")))?
}

async fn service_exit(service: &mut Option<Service>) -> Result<(), AgentError> {
    let Some(running) = service.as_mut() else {
        return std::future::pending().await;
    };
    let result = (&mut running.task).await;
    service.take();
    service_result(result)
}

async fn apply_config(
    service: &mut Option<Service>,
    config: CachedConfig,
    sinks: &runner::ServiceSinks,
    drain_timeout: Duration,
) -> Result<(), AgentError> {
    if let Some(running) = service.as_mut()
        && running.config.node_type == config.node_type
        && running.config.node_traffic == config.node_traffic
        && running.config.config == config.config
    {
        running.config = config;
        return Ok(());
    }
    if let Some(running) = service.take() {
        running.stop(drain_timeout).await?;
    }
    *service = Some(Service::start(config, sinks.clone()));
    Ok(())
}

async fn apply_node_traffic(
    supported: bool,
    service: &mut Option<Service>,
    sinks: &mut runner::ServiceSinks,
    traffic: &NodeTraffic,
) -> Result<(), AgentError> {
    if !supported && (sinks.node_traffic || traffic.requires_support().await?) {
        return Err(AgentError::Accounting(
            "panel no longer supports node traffic accounting; restore a capable panel before restarting the service".into(),
        ));
    }
    if supported && !sinks.node_traffic {
        if let Some(running) = service.take() {
            running
                .stop(trojan_server::DEFAULT_SHUTDOWN_TIMEOUT)
                .await?;
        }
        // Exclude all legacy traffic, including bytes carried while the old service drained.
        traffic.enable(sinks.stats.clone()).await?;
        sinks.node_states = Default::default();
        sinks.node_traffic = true;
    }
    Ok(())
}

pub(crate) async fn run(
    config: AgentConfig,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let mut sinks = runner::ServiceSinks::default();
    let cache_dir = cache::resolve_cache_dir(config.cache_dir.as_deref());
    let cached = cache::read_cache(&cache_dir).await;
    let interval = config.report_interval_secs.unwrap_or_else(|| {
        cached
            .as_ref()
            .map_or(30, |cached| u64::from(cached.report_interval_secs))
    });
    let traffic = NodeTraffic::open(&cache_dir, &config, interval).await?;
    let supported = cached.as_ref().is_some_and(|cached| cached.node_traffic)
        || traffic.requires_support().await?;
    let mut service = None;
    apply_node_traffic(supported, &mut service, &mut sinks, &traffic).await?;
    if traffic.can_start_cached().await?
        && let Some(node_id) = cached.as_ref().and_then(|cached| cached.node_id.as_ref())
    {
        traffic.bind_node(node_id).await?;
        sinks.node_id = Some(node_id.clone());
    }
    service = cached
        .filter(|_| sinks.node_id.is_some())
        .map(|mut cached| {
            cached.node_traffic = supported;
            info!(
                version = cached.version,
                "starting service from cached config"
            );
            Service::start(cached, sinks.clone())
        });
    let sampler_shutdown = CancellationToken::new();
    let sampler_guard = sampler_shutdown.clone().drop_guard();
    let sampler = {
        let traffic = traffic.clone();
        let stats = sinks.stats.clone();
        let shutdown = sampler_shutdown.clone();
        tokio::spawn(async move { traffic.run_sampler(stats, shutdown).await })
    };
    tokio::pin!(sampler);
    let (result, mut sampler_result) = tokio::select! {
        result = reconnect(&config, &shutdown, &mut sinks, &mut service, &traffic) => (result, None),
        result = &mut sampler => (Ok(()), Some(result)),
    };
    let drain_timeout = if sampler_result.is_some()
        || matches!(
            &result,
            Err(AgentError::Accounting(_) | AgentError::AccountingStorage(_))
        ) {
        Duration::ZERO
    } else {
        trojan_server::DEFAULT_SHUTDOWN_TIMEOUT
    };
    let stopped = match service {
        Some(running) if sampler_result.is_none() => tokio::select! {
            stopped = running.stop(drain_timeout) => stopped,
            sampled = &mut sampler => {
                // Dropping the stop future aborts the service before the connection wait below.
                sampler_result = Some(sampled);
                Ok(())
            }
        },
        Some(running) => running.stop(drain_timeout).await,
        None => Ok(()),
    };
    wait_for_connections(&sinks.stats).await;
    drop(sampler_guard);
    let sampled = match sampler_result {
        Some(result) => result,
        None => sampler.await,
    }
    .map_err(|e| AgentError::Accounting(format!("traffic sampler task failed: {e}")))?;
    sampled.and(result).and(stopped)
}

async fn reconnect(
    config: &AgentConfig,
    shutdown: &CancellationToken,
    sinks: &mut runner::ServiceSinks,
    service: &mut Option<Service>,
    traffic: &NodeTraffic,
) -> Result<(), AgentError> {
    let started = Instant::now();
    let mut delay_ms = config.reconnect.initial_delay_ms;
    loop {
        let session_shutdown = shutdown.child_token();
        let session_guard = session_shutdown.clone().drop_guard();
        let registration = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            result = service_exit(service) => return result,
            result = client::connect_and_register(config, session_shutdown.clone()) => result,
        };
        match registration {
            Ok(registered) => {
                delay_ms = config.reconnect.initial_delay_ms;
                let result = shutdown
                    .run_until_cancelled(connected(
                        config,
                        registered,
                        service,
                        sinks,
                        &session_shutdown,
                        started,
                        traffic,
                    ))
                    .await;
                match result {
                    None => return Ok(()),
                    Some(Err(e @ AgentError::Service(_))) => return Err(e),
                    Some(Err(e @ AgentError::Accounting(_))) => return Err(e),
                    Some(Err(e @ AgentError::AccountingStorage(_))) => return Err(e),
                    Some(Err(e)) => warn!(error = %e, "panel session ended"),
                    Some(Ok(())) => return Ok(()),
                }
            }
            Err(e) => warn!(error = %e, "panel connection failed"),
        }
        drop(session_guard);

        let jitter = 1.0 + config.reconnect.jitter * (2.0 * rand_f64() - 1.0);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "jitter scales a nonnegative reconnect delay"
        )]
        let delay = Duration::from_millis((delay_ms as f64 * jitter) as u64);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            result = service_exit(service) => return result,
            _ = tokio::time::sleep(delay) => {}
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "fractional milliseconds are discarded before clamping the delay"
        )]
        let next = (delay_ms as f64 * config.reconnect.multiplier) as u64;
        delay_ms = next.min(config.reconnect.max_delay_ms);
    }
}

async fn connected(
    config: &AgentConfig,
    (reg, tx, mut rx): (
        RegistrationResult,
        mpsc::Sender<AgentMessage>,
        mpsc::Receiver<PanelMessage>,
    ),
    service: &mut Option<Service>,
    sinks: &mut runner::ServiceSinks,
    session_shutdown: &CancellationToken,
    started: Instant,
    traffic: &NodeTraffic,
) -> Result<(), AgentError> {
    let cache_dir = cache::resolve_cache_dir(config.cache_dir.as_deref());
    traffic.bind_node(&reg.node_id).await?;
    apply_node_traffic(reg.node_traffic, service, sinks, traffic).await?;
    sinks.node_id = Some(reg.node_id.clone());
    let mut cached = CachedConfig {
        node_id: Some(reg.node_id),
        node_traffic: reg.node_traffic,
        version: reg.config_version,
        node_type: reg.node_type,
        report_interval_secs: reg.report_interval_secs,
        config: reg.config,
        cached_at: unix_now(),
    };
    apply_config(
        service,
        cached.clone(),
        sinks,
        trojan_server::DEFAULT_SHUTDOWN_TIMEOUT,
    )
    .await?;
    if let Err(e) = cache::write_cache(&cache_dir, &cached).await {
        warn!(error = %e, "failed to cache config; offline startup will use the previous cache");
    }
    let mut started_at = service
        .as_ref()
        .expect("config starts a service")
        .started_at;
    tx.send(AgentMessage::ServiceStatus {
        status: ServiceState::Running,
        started_at,
        config_version: cached.version,
    })
    .await
    .map_err(|_| AgentError::ConnectionClosed)?;
    let interval = Duration::from_secs(
        config
            .report_interval_secs
            .unwrap_or_else(|| u64::from(reg.report_interval_secs)),
    );
    traffic.set_interval(interval.as_secs())?;
    let reporting = reporter::run_reporter(
        tx.clone(),
        sinks.traffic.clone(),
        sinks.stats.clone(),
        interval,
        session_shutdown.clone(),
        started,
    );
    tokio::pin!(reporting);
    let sending = traffic.send_pending(tx.clone());
    tokio::pin!(sending);
    loop {
        tokio::select! {
            biased;
            result = service_exit(service) => {
                let _ = tx.send(AgentMessage::ServiceStatus { status: ServiceState::Error, started_at, config_version: cached.version }).await;
                return result;
            }
            _ = &mut reporting => return Err(AgentError::ConnectionClosed),
            result = &mut sending, if reg.node_traffic => return result,
            message = rx.recv() => match message {
                None => return Err(AgentError::ConnectionClosed),
                Some(PanelMessage::ConfigPush { version, restart_required, drain_timeout_secs, config: bytes }) => {
                    let new_config = match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(value) => value,
                        Err(e) => {
                            tx.send(AgentMessage::ConfigAck { version, ok: false, message: Some(format!("invalid config JSON: {e}")) }).await.map_err(|_| AgentError::ConnectionClosed)?;
                            continue;
                        }
                    };
                    if !restart_required && service.as_ref().is_some_and(|running| running.config.config != new_config) {
                        tx.send(AgentMessage::ConfigAck { version, ok: false, message: Some("config changes require a service restart".into()) }).await.map_err(|_| AgentError::ConnectionClosed)?;
                        continue;
                    }
                    let updated = CachedConfig { version, config: new_config, cached_at: unix_now(), ..cached.clone() };
                    let drain = drain_timeout_secs.map(|s| Duration::from_secs(u64::from(s))).unwrap_or(trojan_server::DEFAULT_SHUTDOWN_TIMEOUT);
                    if restart_required {
                        tx.send(AgentMessage::ServiceStatus { status: ServiceState::Restarting, started_at, config_version: cached.version }).await.map_err(|_| AgentError::ConnectionClosed)?;
                    }
                    apply_config(service, updated.clone(), sinks, drain).await?;
                    started_at = service.as_ref().expect("config starts a service").started_at;
                    if let Err(e) = cache::write_cache(&cache_dir, &updated).await {
                        warn!(error = %e, "failed to cache config; offline startup will use the previous cache");
                    }
                    cached = updated;
                    tx.send(AgentMessage::ConfigAck { version, ok: true, message: None }).await.map_err(|_| AgentError::ConnectionClosed)?;
                    tx.send(AgentMessage::ServiceStatus { status: ServiceState::Running, started_at, config_version: version }).await.map_err(|_| AgentError::ConnectionClosed)?;
                }
                Some(PanelMessage::NodeStates { snapshot }) if reg.node_traffic => sinks.node_states.update(snapshot),
                Some(PanelMessage::NodeTrafficAck { stream_id, sequence }) if reg.node_traffic => traffic.acknowledge(stream_id, sequence).await?,
                Some(PanelMessage::NodeStates { .. } | PanelMessage::NodeTrafficAck { .. }) => return Err(AgentError::Accounting("panel sent node traffic data without negotiating support".into())),
                Some(PanelMessage::Error { code: crate::protocol::ErrorCode::InvalidTrafficReport, message }) => return Err(AgentError::Accounting(format!("panel rejected traffic report: {message}"))),
                Some(PanelMessage::Error { code, message }) => warn!(?code, %message, "panel error"),
                Some(PanelMessage::Registered { .. }) => warn!("duplicate panel registration"),
                Some(PanelMessage::Ping) => {}
            }
        }
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_f64() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    f64::from(nanos) / 1_000_000_000.0
}
