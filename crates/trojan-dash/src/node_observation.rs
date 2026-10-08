//! Receive-time heartbeat rates. Durable traffic reports remain the billing source.

use std::time::{Duration, Instant};

use serde::Serialize;

pub(crate) const HEARTBEAT_TTL: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy)]
pub(crate) struct HeartbeatSample {
    pub received: Instant,
    pub received_at: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HeartbeatRates {
    last: Option<HeartbeatSample>,
    rates: Option<(f64, f64, f64)>,
}

impl HeartbeatRates {
    pub fn observe(&mut self, sample: HeartbeatSample) {
        self.rates = self.last.and_then(|last| {
            let elapsed = sample.received.duration_since(last.received);
            if elapsed.is_zero()
                || elapsed >= HEARTBEAT_TTL
                || sample.uptime_secs < last.uptime_secs
            {
                return None;
            }
            let seconds = elapsed.as_secs_f64();
            Some((
                sample.bytes_in.checked_sub(last.bytes_in)? as f64 / seconds,
                sample.bytes_out.checked_sub(last.bytes_out)? as f64 / seconds,
                seconds,
            ))
        });
        self.last = Some(sample);
    }

    pub fn status(&self, sessions: usize, now: Instant) -> HeartbeatStatus {
        let age = self.last.map(|last| now.duration_since(last.received));
        let state = if sessions == 0 {
            "offline"
        } else if sessions > 1 {
            "multiple_sessions"
        } else if age.is_some_and(|age| age >= HEARTBEAT_TTL) {
            "stale"
        } else if self.rates.is_some() {
            "current"
        } else {
            "warming_up"
        };
        let rates = self.rates.filter(|_| state == "current");
        HeartbeatStatus {
            rate_status: state,
            bytes_in_per_second: rates.map(|rates| rates.0),
            bytes_out_per_second: rates.map(|rates| rates.1),
            rate_interval_seconds: rates.map(|rates| rates.2),
            heartbeat_received_at: self.last.map(|last| last.received_at),
            heartbeat_age_seconds: age.map(|age| age.as_secs_f64()),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct HeartbeatStatus {
    pub rate_status: &'static str,
    pub bytes_in_per_second: Option<f64>,
    pub bytes_out_per_second: Option<f64>,
    pub rate_interval_seconds: Option<f64>,
    pub heartbeat_received_at: Option<u64>,
    pub heartbeat_age_seconds: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_intervals_reset_and_staleness_never_fabricate_a_rate() {
        let start = Instant::now();
        let mut rates = HeartbeatRates::default();
        let mut sample = HeartbeatSample {
            received: start,
            received_at: 100,
            bytes_in: 100,
            bytes_out: 50,
            uptime_secs: 10,
        };
        rates.observe(sample);
        assert_eq!(rates.status(1, start).rate_status, "warming_up");
        sample.received += Duration::from_millis(2500);
        sample.received_at += 2;
        sample.bytes_in += 250;
        sample.bytes_out += 500;
        sample.uptime_secs += 2;
        rates.observe(sample);
        let status = rates.status(1, sample.received);
        assert_eq!(status.bytes_in_per_second, Some(100.0));
        assert_eq!(status.bytes_out_per_second, Some(200.0));
        assert_eq!(status.rate_interval_seconds, Some(2.5));
        assert_eq!(rates.status(2, sample.received).bytes_in_per_second, None);
        assert_eq!(rates.status(0, sample.received).rate_status, "offline");
        assert_eq!(
            rates.status(1, sample.received + HEARTBEAT_TTL).rate_status,
            "stale"
        );
        sample.received += Duration::from_secs(1);
        sample.bytes_in = 0;
        rates.observe(sample);
        assert_eq!(rates.status(1, sample.received).bytes_in_per_second, None);
        sample.received += Duration::from_secs(1);
        sample.uptime_secs = 0;
        rates.observe(sample);
        assert_eq!(rates.status(1, sample.received).bytes_in_per_second, None);
        sample.received += HEARTBEAT_TTL;
        rates.observe(sample);
        assert_eq!(rates.status(1, sample.received).bytes_in_per_second, None);
        sample.received += Duration::from_secs(1);
        rates.observe(sample);
        assert_eq!(
            rates.status(1, sample.received).bytes_in_per_second,
            Some(0.0)
        );
    }
}
