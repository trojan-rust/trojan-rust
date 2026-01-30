//! Main server loop and connection handling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::error::ServerError;
use crate::handler::handle_conn;
use crate::pool::ConnectionPool;
use crate::rate_limit::RateLimiter;
use crate::resolve::resolve_sockaddr;
use crate::state::ServerState;
use crate::tls::load_tls_config;
use crate::util::{ConnectionGuard, ConnectionTracker, apply_tcp_options, create_listener};
use trojan_auth::AuthBackend;
use trojan_config::Config;
use trojan_core::defaults;
use trojan_metrics::{
    ERROR_TLS_HANDSHAKE, record_connection_accepted, record_connection_closed,
    record_connection_rejected, record_error, record_tls_handshake_duration,
    set_connection_queue_depth,
};

/// Default graceful shutdown timeout.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Global connection ID counter.
static CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique connection ID.
#[inline]
fn next_conn_id() -> u64 {
    CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Run the server with a cancellation token for graceful shutdown.
pub async fn run_with_shutdown(
    config: Config,
    auth: impl AuthBackend + 'static,
    shutdown: CancellationToken,
) -> Result<(), ServerError> {
    let tls_config = load_tls_config(&config.tls)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listen: SocketAddr = config
        .server
        .listen
        .parse()
        .map_err(|_| ServerError::Config("invalid listen address".into()))?;

    let fallback_addr = resolve_sockaddr(&config.server.fallback, config.server.tcp.prefer_ipv4).await?;

    // Initialize fallback connection pool if configured
    let fallback_pool: Option<Arc<ConnectionPool>> =
        config.server.fallback_pool.as_ref().map(|pool_cfg| {
            info!(
                max_idle = pool_cfg.max_idle,
                max_age_secs = pool_cfg.max_age_secs,
                fill_batch = pool_cfg.fill_batch,
                fill_delay_ms = pool_cfg.fill_delay_ms,
                "fallback connection pool enabled"
            );
            let pool = Arc::new(ConnectionPool::new(
                fallback_addr,
                pool_cfg.max_idle,
                pool_cfg.max_age_secs,
                pool_cfg.fill_batch,
                pool_cfg.fill_delay_ms,
            ));
            // Use max_age_secs as cleanup interval
            pool.start_cleanup_task(Duration::from_secs(pool_cfg.max_age_secs));
            pool
        });

    // Extract resource limits with defaults
    let (relay_buffer_size, tcp_send_buffer, tcp_recv_buffer, connection_backlog) =
        match &config.server.resource_limits {
            Some(rl) => {
                info!(
                    relay_buffer = rl.relay_buffer_size,
                    tcp_send_buffer = rl.tcp_send_buffer,
                    tcp_recv_buffer = rl.tcp_recv_buffer,
                    connection_backlog = rl.connection_backlog,
                    "resource limits configured"
                );
                (
                    rl.relay_buffer_size,
                    rl.tcp_send_buffer,
                    rl.tcp_recv_buffer,
                    rl.connection_backlog,
                )
            }
            None => (
                defaults::DEFAULT_RELAY_BUFFER_SIZE,
                defaults::DEFAULT_TCP_SEND_BUFFER,
                defaults::DEFAULT_TCP_RECV_BUFFER,
                defaults::DEFAULT_CONNECTION_BACKLOG,
            ),
        };

    // Initialize analytics if feature enabled and configured
    #[cfg(feature = "analytics")]
    let analytics = if config.analytics.enabled {
        match trojan_analytics::init(config.analytics.clone()).await {
            Ok(collector) => {
                info!("analytics enabled, sending to ClickHouse");
                Some(collector)
            }
            Err(e) => {
                warn!("failed to init analytics: {}, disabled", e);
                None
            }
        }
    } else {
        debug!("analytics disabled in config");
        None
    };

    // Log TCP options
    let tcp_cfg = &config.server.tcp;
    info!(
        no_delay = tcp_cfg.no_delay,
        keepalive_secs = tcp_cfg.keepalive_secs,
        reuse_port = tcp_cfg.reuse_port,
        fast_open = tcp_cfg.fast_open,
        "TCP options configured"
    );

    let state = Arc::new(ServerState {
        fallback_addr,
        max_udp_payload: config.server.max_udp_payload,
        max_udp_buffer_bytes: config.server.max_udp_buffer_bytes,
        max_header_bytes: config.server.max_header_bytes,
        tcp_idle_timeout: Duration::from_secs(config.server.tcp_idle_timeout_secs),
        udp_idle_timeout: Duration::from_secs(config.server.udp_timeout_secs),
        fallback_pool,
        relay_buffer_size,
        tcp_send_buffer,
        tcp_recv_buffer,
        tcp_config: config.server.tcp.clone(),
        websocket: config.websocket.clone(),
        #[cfg(feature = "analytics")]
        analytics,
    });
    let auth = Arc::new(auth);
    let tracker = ConnectionTracker::new();

    // Connection limiter (None = unlimited)
    let conn_limit: Option<Arc<Semaphore>> = config.server.max_connections.map(|n| {
        info!("max_connections set to {}", n);
        Arc::new(Semaphore::new(n))
    });

    // Rate limiter (None = disabled)
    let rate_limiter: Option<Arc<RateLimiter>> = config.server.rate_limit.as_ref().map(|rl| {
        info!(
            max_per_ip = rl.max_connections_per_ip,
            window_secs = rl.window_secs,
            "rate limiting enabled"
        );
        let limiter = Arc::new(RateLimiter::new(rl.max_connections_per_ip, rl.window_secs));
        limiter.start_cleanup_task(Duration::from_secs(rl.cleanup_interval_secs));
        limiter
    });

    // Create listener with custom backlog and TCP options using socket2
    let listener = create_listener(listen, connection_backlog, &config.server.tcp)?;
    info!(address = %listen, backlog = connection_backlog, "listening");

    #[cfg(feature = "ws")]
    if config.websocket.enabled && config.websocket.mode == "split" {
        let ws_listen = config.websocket.listen.clone().unwrap_or_default();
        let ws_addr: SocketAddr = ws_listen
            .parse()
            .map_err(|_| ServerError::Config("invalid websocket.listen address".into()))?;
        let ws_listener = create_listener(ws_addr, connection_backlog, &config.server.tcp)?;
        let ws_acceptor = acceptor.clone();
        let ws_state = state.clone();
        let ws_auth = auth.clone();
        let ws_tracker = tracker.clone();
        let ws_conn_limit = conn_limit.clone();
        let ws_rate_limiter = rate_limiter.clone();
        let ws_shutdown = shutdown.clone();

        info!(address = %ws_addr, "websocket split listener started");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = ws_shutdown.cancelled() => break,
                    result = ws_listener.accept() => {
                        let (tcp, peer) = match result {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        // Apply TCP socket options
                        if let Err(e) = apply_tcp_options(&tcp, &ws_state.tcp_config) {
                            tracing::debug!(error = %e, "failed to apply TCP options");
                        }

                        if let Some(ref limiter) = ws_rate_limiter {
                            let ip = peer.ip();
                            if !limiter.check_and_increment(ip) {
                                record_connection_rejected("rate_limit");
                                drop(tcp);
                                continue;
                            }
                        }

                        let permit: Option<OwnedSemaphorePermit> = match &ws_conn_limit {
                            Some(sem) => match sem.clone().try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    record_connection_rejected("max_connections");
                                    drop(tcp);
                                    continue;
                                }
                            },
                            None => None,
                        };

                        let conn_id = next_conn_id();
                        let acceptor = ws_acceptor.clone();
                        let state = ws_state.clone();
                        let auth = ws_auth.clone();
                        ws_tracker.increment();
                        let guard = ConnectionGuard::new(ws_tracker.clone());

                        let span = info_span!("conn", id = conn_id, peer = %peer, transport = "ws");
                        tokio::spawn(
                            async move {
                                let _guard = guard;
                                let _permit = permit;
                                record_connection_accepted();
                                let start = Instant::now();

                                let result = async {
                                    let tls_start = Instant::now();
                                    let tls_timeout =
                                        Duration::from_secs(defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS);
                                    match tokio::time::timeout(tls_timeout, acceptor.accept(tcp)).await
                                    {
                                        Ok(Ok(tls)) => {
                                            let tls_duration = tls_start.elapsed().as_secs_f64();
                                            record_tls_handshake_duration(tls_duration);
                                            crate::handler::handle_ws_only(tls, state, auth, peer).await
                                        }
                                        Ok(Err(err)) => {
                                            record_error(ERROR_TLS_HANDSHAKE);
                                            warn!(error = %err, "TLS handshake failed");
                                            Ok(())
                                        }
                                        Err(_) => {
                                            record_error(ERROR_TLS_HANDSHAKE);
                                            warn!(
                                                timeout_secs = tls_timeout.as_secs(),
                                                "TLS handshake timed out"
                                            );
                                            Ok(())
                                        }
                                    }
                                }
                                .await;

                                let duration_secs = start.elapsed().as_secs_f64();
                                record_connection_closed(duration_secs);

                                if let Err(ref err) = result {
                                    warn!(error = %err, "connection error");
                                }
                            }
                            .instrument(span),
                        );
                    }
                }
            }
        });
    }

    #[cfg(not(feature = "ws"))]
    if config.websocket.enabled {
        warn!("websocket.enabled=true but ws feature is disabled; ignoring websocket");
    }

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                info!("shutdown signal received, stopping accept loop");
                break;
            }

            result = listener.accept() => {
                let (tcp, peer) = result?;

                // Apply TCP socket options (no_delay, keepalive)
                if let Err(e) = apply_tcp_options(&tcp, &state.tcp_config) {
                    debug!(error = %e, "failed to apply TCP options");
                }

                // Update connection queue depth metric (based on semaphore usage)
                if let Some(ref sem) = conn_limit {
                    let available = sem.available_permits();
                    set_connection_queue_depth(available as f64);
                }

                // Check rate limit first
                if let Some(ref limiter) = rate_limiter {
                    let ip = peer.ip();
                    if !limiter.check_and_increment(ip) {
                        debug!(peer = %peer, reason = "rate_limit", "connection rejected");
                        record_connection_rejected("rate_limit");
                        drop(tcp);
                        continue;
                    }
                }

                // Try to acquire connection permit
                let permit: Option<OwnedSemaphorePermit> = match &conn_limit {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            debug!(peer = %peer, reason = "max_connections", "connection rejected");
                            record_connection_rejected("max_connections");
                            drop(tcp); // close immediately
                            continue;
                        }
                    },
                    None => None,
                };

                let conn_id = next_conn_id();
                debug!(conn_id, peer = %peer, "new connection");

                let acceptor = acceptor.clone();
                let state = state.clone();
                let auth = auth.clone();
                tracker.increment();
                let guard = ConnectionGuard::new(tracker.clone());

                let span = info_span!("conn", id = conn_id, peer = %peer);
                tokio::spawn(
                    async move {
                        let _guard = guard; // ensure decrement on drop
                        let _permit = permit; // hold permit until connection closes
                        record_connection_accepted();
                        let start = Instant::now();

                        let result = async {
                            // Measure TLS handshake duration with timeout
                            let tls_start = Instant::now();
                            let tls_timeout =
                                Duration::from_secs(defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS);
                            match tokio::time::timeout(tls_timeout, acceptor.accept(tcp)).await {
                                Ok(Ok(tls)) => {
                                    let tls_duration = tls_start.elapsed().as_secs_f64();
                                    record_tls_handshake_duration(tls_duration);
                                    debug!(duration_ms = tls_duration * 1000.0, "TLS handshake completed");
                                    handle_conn(tls, state, auth, peer).await
                                }
                                Ok(Err(err)) => {
                                    record_error(ERROR_TLS_HANDSHAKE);
                                    warn!(error = %err, "TLS handshake failed");
                                    Ok(())
                                }
                                Err(_) => {
                                    record_error(ERROR_TLS_HANDSHAKE);
                                    warn!(timeout_secs = tls_timeout.as_secs(), "TLS handshake timed out");
                                    Ok(())
                                }
                            }
                        }
                        .await;

                        let duration_secs = start.elapsed().as_secs_f64();
                        record_connection_closed(duration_secs);

                        if let Err(ref err) = result {
                            record_error(err.error_type());
                            warn!(duration_secs, error = %err, "connection closed with error");
                        } else {
                            debug!(duration_secs, "connection closed");
                        }
                    }
                    .instrument(span),
                );
            }
        }
    }

    // Shutdown rate limiter cleanup task
    if let Some(ref limiter) = rate_limiter {
        limiter.shutdown();
    }

    // Graceful drain: wait for active connections
    let active = tracker.count();
    if active > 0 {
        info!("waiting for {} active connections to drain", active);
        if tracker.wait_for_zero(DEFAULT_SHUTDOWN_TIMEOUT).await {
            info!("all connections drained");
        } else {
            warn!(
                "shutdown timeout, {} connections still active",
                tracker.count()
            );
        }
    }

    info!("server stopped");
    Ok(())
}

/// Run the server (blocking until error, no graceful shutdown).
/// For backward compatibility with existing code.
pub async fn run(config: Config, auth: impl AuthBackend + 'static) -> Result<(), ServerError> {
    run_with_shutdown(config, auth, CancellationToken::new()).await
}
