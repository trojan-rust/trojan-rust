//! Background DDNS update loop.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::cloudflare::CloudflareUpdater;
use crate::ip::IpDetector;
use trojan_config::DdnsConfig;

/// Run the DDNS update loop until the shutdown token is cancelled.
pub async fn ddns_loop(config: DdnsConfig, shutdown: CancellationToken) {
    let cf_config = match config.cloudflare {
        Some(ref cfg) => cfg,
        None => {
            warn!("DDNS enabled but no provider configured");
            return;
        }
    };

    let mut updater = match CloudflareUpdater::new(cf_config) {
        Ok(u) => u,
        Err(e) => {
            error!(error = %e, "failed to initialize Cloudflare DDNS updater");
            return;
        }
    };

    let ipv4_enabled = !config.ipv4_urls.is_empty();
    let ipv6_enabled = !config.ipv6_urls.is_empty();

    if !ipv4_enabled && !ipv6_enabled {
        warn!("DDNS enabled but no IP detection URLs configured");
        return;
    }

    let detector = IpDetector::new(config.ipv4_urls.clone(), config.ipv6_urls.clone());
    let mut cached_ipv4: Option<Ipv4Addr> = None;
    let mut cached_ipv6: Option<Ipv6Addr> = None;

    info!(
        interval_secs = config.interval,
        ipv4 = ipv4_enabled,
        ipv6 = ipv6_enabled,
        zone = %cf_config.zone,
        records = ?cf_config.records,
        "DDNS update loop started"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(config.interval));

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                debug!("DDNS update loop shutting down");
                return;
            }

            _ = interval.tick() => {
                let ipv4 = if ipv4_enabled {
                    detector.detect_ipv4().await
                } else {
                    None
                };
                let ipv6 = if ipv6_enabled {
                    detector.detect_ipv6().await
                } else {
                    None
                };

                let ipv4_changed = ipv4.is_some() && ipv4 != cached_ipv4;
                let ipv6_changed = ipv6.is_some() && ipv6 != cached_ipv6;

                if !ipv4_changed && !ipv6_changed {
                    debug!(?ipv4, ?ipv6, "IP unchanged, skipping DDNS update");
                    continue;
                }

                if ipv4_changed {
                    let ip = ipv4.unwrap();
                    info!(ip = %ip, "IPv4 changed, updating DNS records");
                    match updater.update_ipv4(ip).await {
                        Ok(()) => cached_ipv4 = ipv4,
                        Err(e) => warn!(error = %e, "failed to update A records"),
                    }
                }

                if ipv6_changed {
                    let ip = ipv6.unwrap();
                    info!(ip = %ip, "IPv6 changed, updating DNS records");
                    match updater.update_ipv6(ip).await {
                        Ok(()) => cached_ipv6 = ipv6,
                        Err(e) => warn!(error = %e, "failed to update AAAA records"),
                    }
                }
            }
        }
    }
}
