//! Public IP address detection via HTTP endpoints.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tracing::{debug, warn};

/// Detects the public IP address by querying external HTTP endpoints.
pub struct IpDetector {
    client: reqwest::Client,
    ipv4_urls: Vec<String>,
    ipv6_urls: Vec<String>,
}

impl std::fmt::Debug for IpDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpDetector")
            .field("ipv4_urls", &self.ipv4_urls)
            .field("ipv6_urls", &self.ipv6_urls)
            .finish()
    }
}

impl IpDetector {
    pub fn new(ipv4_urls: Vec<String>, ipv6_urls: Vec<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .expect("failed to build HTTP client for IP detection");
        Self {
            client,
            ipv4_urls,
            ipv6_urls,
        }
    }

    /// Detect the public IPv4 address by trying each configured URL in order.
    pub async fn detect_ipv4(&self) -> Option<Ipv4Addr> {
        for url in &self.ipv4_urls {
            match self.client.get(url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(text) => match text.trim().parse::<Ipv4Addr>() {
                        Ok(ip) => {
                            debug!(ip = %ip, url, "detected IPv4 address");
                            return Some(ip);
                        }
                        Err(e) => {
                            warn!(url, error = %e, "failed to parse IPv4 from response");
                        }
                    },
                    Err(e) => warn!(url, error = %e, "failed to read response body"),
                },
                Err(e) => warn!(url, error = %e, "IPv4 detection request failed"),
            }
        }
        None
    }

    /// Detect the public IPv6 address by trying each configured URL in order.
    pub async fn detect_ipv6(&self) -> Option<Ipv6Addr> {
        for url in &self.ipv6_urls {
            match self.client.get(url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(text) => match text.trim().parse::<Ipv6Addr>() {
                        Ok(ip) => {
                            debug!(ip = %ip, url, "detected IPv6 address");
                            return Some(ip);
                        }
                        Err(e) => {
                            warn!(url, error = %e, "failed to parse IPv6 from response");
                        }
                    },
                    Err(e) => warn!(url, error = %e, "failed to read response body"),
                },
                Err(e) => warn!(url, error = %e, "IPv6 detection request failed"),
            }
        }
        None
    }
}
