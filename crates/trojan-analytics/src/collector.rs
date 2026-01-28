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
#[derive(Clone)]
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
    fn drop(&mut self) {
        if !self.sent {
            self.event.duration_ms = self.start_time.elapsed().as_millis() as u64;
            self.send();
        }
    }
}
