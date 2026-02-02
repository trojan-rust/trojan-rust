//! Event collector for non-blocking event recording.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use rand::Rng;
use tokio::sync::mpsc;
use tracing::debug;
use trojan_config::{AnalyticsConfig, AnalyticsPrivacyConfig};

use crate::event::{AuthResult, CloseReason, ConnectionEvent, Protocol, TargetType, Transport};

/// Event collector for recording connection events.
///
/// This struct is cheap to clone and can be shared across threads.
/// Events are sent through a bounded channel to a background writer.
#[derive(Debug, Clone)]
pub struct EventCollector {
    sender: mpsc::Sender<ConnectionEvent>,
    config: Arc<AnalyticsConfig>,
}

impl EventCollector {
    /// Create a new event collector.
    pub(crate) fn new(sender: mpsc::Sender<ConnectionEvent>, config: Arc<AnalyticsConfig>) -> Self {
        Self { sender, config }
    }

    /// Record a connection event (non-blocking).
    ///
    /// Returns `true` if the event was queued, `false` if the buffer is full.
    #[inline]
    pub fn record(&self, event: ConnectionEvent) -> bool {
        self.sender.try_send(event).is_ok()
    }

    /// Create a connection event builder for the given connection.
    ///
    /// The builder will automatically send the event when dropped.
    pub fn connection(&self, conn_id: u64, peer: SocketAddr) -> ConnectionEventBuilder {
        ConnectionEventBuilder::new(self.clone(), conn_id, peer, &self.config)
    }

    /// Check if an event should be recorded based on sampling configuration.
    ///
    /// Returns `true` if the event should be recorded.
    pub fn should_sample(&self, user_id: Option<&str>) -> bool {
        let sampling = &self.config.sampling;

        // Always record specified users
        if let Some(uid) = user_id
            && sampling.always_record_users.iter().any(|u| u == uid)
        {
            return true;
        }

        // Sample based on rate
        if sampling.rate >= 1.0 {
            return true;
        }
        if sampling.rate <= 0.0 {
            return false;
        }

        rand::thread_rng().r#gen::<f64>() < sampling.rate
    }

    /// Get the privacy configuration.
    pub fn privacy(&self) -> &AnalyticsPrivacyConfig {
        &self.config.privacy
    }

    /// Get the server ID.
    pub fn server_id(&self) -> Option<&str> {
        self.config.server_id.as_deref()
    }
}

/// Builder for constructing connection events.
///
/// Events are automatically sent when the builder is dropped,
/// or can be explicitly sent with `finish()`.
#[derive(Debug)]
pub struct ConnectionEventBuilder {
    collector: EventCollector,
    event: ConnectionEvent,
    start_time: Instant,
    sent: bool,
}

impl ConnectionEventBuilder {
    /// Create a new connection event builder.
    fn new(
        collector: EventCollector,
        conn_id: u64,
        peer: SocketAddr,
        config: &AnalyticsConfig,
    ) -> Self {
        let peer_ip = if config.privacy.record_peer_ip {
            peer.ip()
        } else {
            // Use unspecified address if not recording
            match peer {
                SocketAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            }
        };

        let mut event = ConnectionEvent::new(conn_id, peer_ip, peer.port());
        event.server_id = config.server_id.clone().unwrap_or_default();

        Self {
            collector,
            event,
            start_time: Instant::now(),
            sent: false,
        }
    }

    /// Set the user ID.
    pub fn user(mut self, user_id: impl Into<String>) -> Self {
        let uid = user_id.into();
        let privacy = self.collector.privacy();

        self.event.user_id = if privacy.full_user_id {
            uid
        } else {
            // Truncate to prefix length
            let len = privacy.user_id_prefix_len.min(uid.len());
            uid[..len].to_string()
        };
        self.event.auth_result = AuthResult::Success;
        self
    }

    /// Set authentication as failed.
    pub fn auth_failed(mut self) -> Self {
        self.event.auth_result = AuthResult::Failed;
        self
    }

    /// Set the target information.
    pub fn target(mut self, host: impl Into<String>, port: u16, target_type: TargetType) -> Self {
        self.event.target_host = host.into();
        self.event.target_port = port;
        self.event.target_type = target_type;
        self
    }

    /// Set the SNI (Server Name Indication).
    pub fn sni(mut self, sni: impl Into<String>) -> Self {
        if self.collector.privacy().record_sni {
            self.event.sni = sni.into();
        }
        self
    }

    /// Set the protocol type.
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.event.protocol = protocol;
        self
    }

    /// Set the transport type.
    pub fn transport(mut self, transport: Transport) -> Self {
        self.event.transport = transport;
        self
    }

    /// Mark as fallback connection.
    pub fn fallback(mut self) -> Self {
        self.event.is_fallback = true;
        self.event.auth_result = AuthResult::Skipped;
        self
    }

    /// Set GeoIP fields based on lookup result and privacy precision.
    ///
    /// Precision levels:
    /// - `"city"`: fill all geo fields (country, region, city, ASN, org, lat/lon)
    /// - `"country"`: fill only country code
    /// - `"none"` or other: no-op
    pub fn geo(mut self, result: trojan_config::GeoResult, precision: &str) -> Self {
        match precision {
            "city" => {
                self.event.peer_country = result.country;
                self.event.peer_region = result.region;
                self.event.peer_city = result.city;
                self.event.peer_asn = result.asn;
                self.event.peer_org = result.org;
                self.event.peer_longitude = result.longitude;
                self.event.peer_latitude = result.latitude;
            }
            "country" => {
                self.event.peer_country = result.country;
            }
            _ => {} // "none" or unknown: no-op
        }
        self
    }

    /// Add bytes to the traffic counters.
    #[inline]
    pub fn add_bytes(&mut self, sent: u64, recv: u64) {
        self.event.bytes_sent += sent;
        self.event.bytes_recv += recv;
    }

    /// Add packets to the packet counters (for UDP).
    #[inline]
    pub fn add_packets(&mut self, sent: u64, recv: u64) {
        self.event.packets_sent += sent;
        self.event.packets_recv += recv;
    }

    /// Get a mutable reference to the event for direct modification.
    pub fn event_mut(&mut self) -> &mut ConnectionEvent {
        &mut self.event
    }

    /// Finish and send the event with the given close reason.
    #[allow(clippy::cast_possible_truncation)]
    pub fn finish(mut self, close_reason: CloseReason) {
        self.event.duration_ms = self.start_time.elapsed().as_millis() as u64;
        self.event.close_reason = close_reason;
        self.send();
    }

    /// Send the event.
    fn send(&mut self) {
        if self.sent {
            return;
        }
        self.sent = true;

        if !self.collector.record(self.event.clone()) {
            debug!(
                conn_id = self.event.conn_id,
                "analytics buffer full, event dropped"
            );
        }
    }
}

impl Drop for ConnectionEventBuilder {
    #[allow(clippy::cast_possible_truncation)]
    fn drop(&mut self) {
        if !self.sent {
            self.event.duration_ms = self.start_time.elapsed().as_millis() as u64;
            self.send();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use trojan_config::{AnalyticsConfig, GeoResult};

    fn test_collector() -> (EventCollector, mpsc::Receiver<ConnectionEvent>) {
        let (tx, rx) = mpsc::channel(64);
        let config = Arc::new(AnalyticsConfig {
            enabled: true,
            ..Default::default()
        });
        (EventCollector::new(tx, config), rx)
    }

    fn test_peer() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 12345))
    }

    #[test]
    fn geo_builder_city_precision() {
        let (collector, _rx) = test_collector();
        let builder = collector.connection(1, test_peer());

        let geo = GeoResult {
            country: "US".into(),
            region: "California".into(),
            city: "Los Angeles".into(),
            asn: 15169,
            org: "Google LLC".into(),
            longitude: -118.24,
            latitude: 34.05,
        };

        let builder = builder.geo(geo, "city");
        assert_eq!(builder.event.peer_country, "US");
        assert_eq!(builder.event.peer_region, "California");
        assert_eq!(builder.event.peer_city, "Los Angeles");
        assert_eq!(builder.event.peer_asn, 15169);
        assert_eq!(builder.event.peer_org, "Google LLC");
        assert!((builder.event.peer_longitude - (-118.24)).abs() < 0.001);
        assert!((builder.event.peer_latitude - 34.05).abs() < 0.001);
    }

    #[test]
    fn geo_builder_country_precision() {
        let (collector, _rx) = test_collector();
        let builder = collector.connection(2, test_peer());

        let geo = GeoResult {
            country: "CN".into(),
            region: "Shanghai".into(),
            city: "Shanghai".into(),
            asn: 4134,
            org: "China Telecom".into(),
            longitude: 121.47,
            latitude: 31.23,
        };

        let builder = builder.geo(geo, "country");
        assert_eq!(builder.event.peer_country, "CN");
        assert!(builder.event.peer_region.is_empty());
        assert!(builder.event.peer_city.is_empty());
        assert_eq!(builder.event.peer_asn, 0);
    }

    #[test]
    fn geo_builder_none_precision() {
        let (collector, _rx) = test_collector();
        let builder = collector.connection(3, test_peer());

        let geo = GeoResult {
            country: "JP".into(),
            region: "Tokyo".into(),
            city: "Tokyo".into(),
            asn: 2497,
            org: "IIJ".into(),
            longitude: 139.69,
            latitude: 35.69,
        };

        let builder = builder.geo(geo, "none");
        assert!(builder.event.peer_country.is_empty());
        assert!(builder.event.peer_region.is_empty());
        assert_eq!(builder.event.peer_asn, 0);
    }

    #[tokio::test]
    async fn event_builder_sends_on_finish() {
        let (collector, mut rx) = test_collector();
        let builder = collector.connection(10, test_peer());
        builder
            .target("example.com".to_string(), 443, TargetType::Domain)
            .protocol(Protocol::Tcp)
            .finish(CloseReason::Normal);

        let event = rx.try_recv().unwrap();
        assert_eq!(event.conn_id, 10);
        assert_eq!(event.target_host, "example.com");
        assert_eq!(event.target_port, 443);
        assert_eq!(event.protocol, Protocol::Tcp);
        assert_eq!(event.close_reason, CloseReason::Normal);
    }

    #[tokio::test]
    async fn event_builder_sends_on_drop() {
        let (collector, mut rx) = test_collector();
        {
            let _builder = collector.connection(20, test_peer());
        }
        let event = rx.try_recv().unwrap();
        assert_eq!(event.conn_id, 20);
    }

    #[test]
    fn should_sample_always_record_user() {
        let (tx, _rx) = mpsc::channel(1);
        let config = Arc::new(AnalyticsConfig {
            enabled: true,
            sampling: trojan_config::AnalyticsSamplingConfig {
                rate: 0.0,
                always_record_users: vec!["vip-user".into()],
            },
            ..Default::default()
        });
        let collector = EventCollector::new(tx, config);
        assert!(collector.should_sample(Some("vip-user")));
        assert!(!collector.should_sample(Some("normal-user")));
    }

    #[test]
    fn should_sample_rate_boundaries() {
        let (tx, _rx) = mpsc::channel(1);
        let config = Arc::new(AnalyticsConfig {
            enabled: true,
            sampling: trojan_config::AnalyticsSamplingConfig {
                rate: 1.0,
                always_record_users: vec![],
            },
            ..Default::default()
        });
        let collector = EventCollector::new(tx, config);
        assert!(collector.should_sample(None));

        let (tx2, _rx2) = mpsc::channel(1);
        let config2 = Arc::new(AnalyticsConfig {
            enabled: true,
            sampling: trojan_config::AnalyticsSamplingConfig {
                rate: 0.0,
                always_record_users: vec![],
            },
            ..Default::default()
        });
        let collector2 = EventCollector::new(tx2, config2);
        assert!(!collector2.should_sample(None));
    }

    #[test]
    fn user_id_truncation() {
        let (collector, _rx) = test_collector();
        let builder = collector.connection(30, test_peer());
        let builder = builder.user("abcdef1234567890");
        assert_eq!(builder.event.user_id, "abcdef12");
    }

    #[test]
    fn add_bytes_and_packets() {
        let (collector, _rx) = test_collector();
        let mut builder = collector.connection(40, test_peer());
        builder.add_bytes(100, 200);
        builder.add_bytes(50, 25);
        builder.add_packets(3, 5);
        assert_eq!(builder.event.bytes_sent, 150);
        assert_eq!(builder.event.bytes_recv, 225);
        assert_eq!(builder.event.packets_sent, 3);
        assert_eq!(builder.event.packets_recv, 5);
    }
}
