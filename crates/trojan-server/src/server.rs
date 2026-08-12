//! Main server loop and connection handling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::error::ServerError;
use crate::listener::{ListenerContext, ListenerKind};
use crate::pool::ConnectionPool;
use crate::rate_limit::RateLimiter;
use crate::resolve::resolve_sockaddr;
use crate::state::ServerState;
use crate::tls::load_tls_config;
use crate::util::{ConnectionTracker, create_listener};
use trojan_auth::AuthBackend;
#[cfg(feature = "ws")]
use trojan_config::WebSocketMode;
use trojan_config::{Config, validate_config};
use trojan_core::defaults;
use trojan_dns::DnsResolver;
use trojan_metrics::NodeStats;

/// Default graceful shutdown timeout.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the server with a cancellation token for graceful shutdown.
pub async fn run_with_shutdown(
    config: Config,
    auth: impl AuthBackend + 'static,
    shutdown: CancellationToken,
) -> Result<(), ServerError> {
    run_with_stats(config, auth, NodeStats::new(), shutdown).await
}

/// Run the server, accumulating its totals into `stats`.
///
/// Same as [`run_with_shutdown`], for callers that report node traffic
/// themselves — the panel agent reads these totals for its heartbeats, which
/// have no scraper to diff Prometheus samples for them.
pub async fn run_with_stats(
    config: Config,
    auth: impl AuthBackend + 'static,
    stats: Arc<NodeStats>,
    shutdown: CancellationToken,
) -> Result<(), ServerError> {
    // Every way of starting a server funnels through here, so this is the one
    // place the checks cannot be skipped. They used to sit in the CLI, which
    // left the panel agent — it deserializes a config the panel pushed and
    // starts the server directly — running whatever it was handed: a zero
    // idle timeout, a header limit below the minimum, a UDP buffer smaller
    // than one packet. The node came up and then behaved wrongly.
    validate_config(&config).map_err(|e| ServerError::Config(e.to_string()))?;

    let tls_config = load_tls_config(&config.tls)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listen: SocketAddr = config
        .server
        .listen
        .parse()
        .map_err(|_| ServerError::Config("invalid listen address".into()))?;

    // Build DNS resolver from config.
    // Backward compatibility: preserve legacy `server.tcp.prefer_ipv4` behavior.
    let mut dns_config = config.dns.clone();
    if config.server.tcp.prefer_ipv4 && !dns_config.prefer_ipv4 {
        dns_config.prefer_ipv4 = true;
        info!(
            "server.tcp.prefer_ipv4 is deprecated; mapped to dns.prefer_ipv4 for backward compatibility"
        );
    }
    let dns_resolver = DnsResolver::new(&dns_config)
        .map_err(|e| ServerError::Config(format!("dns resolver: {e}")))?;
    info!(
        dns = ?dns_config.strategy,
        prefer_ipv4 = dns_config.prefer_ipv4,
        "dns resolver initialized"
    );

    let fallback_addr = resolve_sockaddr(&config.server.fallback, &dns_resolver).await?;

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
        tracing::debug!("analytics disabled in config");
        None
    };

    // Initialize rule engine if feature enabled and rules configured
    #[cfg(feature = "rules")]
    let rule_engine = if !config.server.rules.is_empty() {
        match crate::rules::build_rule_engine(&config.server) {
            Ok(engine) => {
                info!(
                    rule_sets = engine.rule_set_count(),
                    rules = engine.rule_count(),
                    "rule engine initialized"
                );
                Some(Arc::new(trojan_rules::HotRuleEngine::new(engine)))
            }
            Err(e) => {
                return Err(ServerError::Rules(format!("failed to init rules: {e}")));
            }
        }
    } else {
        tracing::debug!("no routing rules configured");
        None
    };

    // Spawn background rule update task for HTTP providers
    #[cfg(feature = "rules")]
    if let Some(ref hot_engine) = rule_engine
        && crate::rules::has_http_providers(&config.server)
    {
        let interval_secs = crate::rules::http_update_interval(&config.server).unwrap_or(3600); // default: 1 hour
        let engine_ref = hot_engine.clone();
        let server_cfg = config.server.clone();
        let update_shutdown = shutdown.clone();
        info!(interval_secs, "starting background rule update task");
        tokio::spawn(async move {
            crate::rules::rule_update_loop(engine_ref, server_cfg, interval_secs, update_shutdown)
                .await;
        });
    }

    // Build outbound connectors from config
    #[cfg(feature = "rules")]
    let outbounds = {
        let mut map = std::collections::HashMap::new();
        for (name, outbound_cfg) in &config.server.outbounds {
            match crate::outbound::Outbound::from_config(name, outbound_cfg) {
                Ok(outbound) => {
                    info!(name = %name, "outbound connector configured");
                    map.insert(name.clone(), Arc::new(outbound));
                }
                Err(e) => {
                    return Err(ServerError::Config(format!("outbound '{name}': {e}")));
                }
            }
        }
        map
    };

    // Configs pointing at the same source share one `Arc`, which happens
    // inside the loader — so `server` itself has no user out here.
    #[cfg(feature = "geoip")]
    let geoip = crate::geoip::load_geoip_databases(&config, &shutdown).await;

    // Start metrics server (with debug routes if rules feature is enabled)
    if let Some(ref listen) = config.metrics.listen {
        #[cfg(feature = "rules")]
        let extra_routes = rule_engine
            .as_ref()
            .map(|engine| crate::debug_api::debug_routes(engine.clone()));
        #[cfg(not(feature = "rules"))]
        let extra_routes: Option<axum::Router> = None;

        match trojan_metrics::init_metrics_server(listen, extra_routes) {
            Ok(_handle) => {
                #[cfg(feature = "rules")]
                let endpoints = if rule_engine.is_some() {
                    "/metrics, /health, /ready, /debug/rules/match"
                } else {
                    "/metrics, /health, /ready"
                };
                #[cfg(not(feature = "rules"))]
                let endpoints = "/metrics, /health, /ready";
                info!("metrics server listening on {} ({})", listen, endpoints);
            }
            Err(e) => warn!("failed to start metrics server: {}", e),
        }
    }

    // Spawn DDNS update task if enabled
    #[cfg(feature = "ddns")]
    if config.ddns.enabled {
        let ddns_config = config.ddns.clone();
        let ddns_shutdown = shutdown.clone();
        info!("starting DDNS update task");
        tokio::spawn(async move {
            trojan_ddns::ddns_loop(ddns_config, ddns_shutdown).await;
        });
    }

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
        #[cfg(feature = "ws")]
        websocket: config.websocket.clone(),
        dns_resolver,
        node_stats: stats,
        proxy_protocol: config.server.proxy_protocol.clone(),
        per_target_metrics: config.metrics.per_target,
        #[cfg(feature = "analytics")]
        analytics,
        #[cfg(feature = "rules")]
        rule_engine,
        #[cfg(feature = "rules")]
        outbounds,
        #[cfg(feature = "geoip")]
        geoip_metrics: geoip.metrics,
        #[cfg(all(feature = "geoip", feature = "analytics"))]
        geoip_analytics: geoip.analytics,
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

    // Everything a listener needs beyond its own socket.
    let ctx = ListenerContext {
        tls: acceptor,
        state,
        auth,
        tracker: tracker.clone(),
        conn_limit,
        rate_limiter: rate_limiter.clone(),
    };

    // The dedicated WebSocket port, when `split` mode asks for one, runs
    // alongside the main listener rather than in place of it.
    #[cfg(feature = "ws")]
    if config.websocket.enabled && config.websocket.mode == WebSocketMode::Split {
        let ws_addr: SocketAddr = config
            .websocket
            .listen
            .as_deref()
            .unwrap_or_default()
            .parse()
            .map_err(|_| ServerError::Config("invalid websocket.listen address".into()))?;
        let ws_listener = ctx.listener(
            create_listener(ws_addr, connection_backlog, &config.server.tcp)?,
            ListenerKind::WebSocket,
        );
        let ws_shutdown = shutdown.clone();
        info!(address = %ws_addr, "websocket split listener started");
        tokio::spawn(async move {
            if let Err(e) = ws_listener.serve(ws_shutdown).await {
                warn!(error = %e, "websocket listener stopped");
            }
        });
    }

    #[cfg(not(feature = "ws"))]
    if config.websocket.enabled {
        warn!("websocket.enabled=true but ws feature is disabled; ignoring websocket");
    }

    ctx.listener(listener, ListenerKind::Trojan)
        .serve(shutdown)
        .await?;

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
