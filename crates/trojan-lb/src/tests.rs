use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn addrs(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("backend-{}:443", i)).collect()
}

fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// ── RoundRobin ──

#[test]
fn round_robin_cycles() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::RoundRobin, Duration::ZERO);
    let results: Vec<String> = (0..6)
        .map(|_| lb.select(localhost()).unwrap().addr)
        .collect();
    assert_eq!(
        results,
        vec![
            "backend-0:443",
            "backend-1:443",
            "backend-2:443",
            "backend-0:443",
            "backend-1:443",
            "backend-2:443",
        ]
    );
}

#[test]
fn round_robin_single() {
    let lb = LoadBalancer::new(addrs(1), LbStrategy::RoundRobin, Duration::ZERO);
    for _ in 0..5 {
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    }
}

// ── IpHash ──

#[test]
fn ip_hash_consistent() {
    let lb = LoadBalancer::new(addrs(5), LbStrategy::IpHash, Duration::ZERO);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let first = lb.select(ip).unwrap().addr;
    for _ in 0..20 {
        assert_eq!(lb.select(ip).unwrap().addr, first);
    }
}

#[test]
fn ip_hash_distributes() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::IpHash, Duration::ZERO);
    let mut seen = std::collections::HashSet::new();
    // Try many different IPs — should hit multiple backends
    for i in 0..100u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        seen.insert(lb.select(ip).unwrap().addr);
    }
    assert!(seen.len() > 1, "IP hash should distribute across backends");
}

#[test]
fn ip_hash_ipv6() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::IpHash, Duration::ZERO);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let result = lb.select(ip).unwrap();
    assert!(result.addr.starts_with("backend-"));
}

// ── LeastConnections ──

#[test]
fn least_connections_picks_minimum() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::LeastConnections, Duration::ZERO);

    // Acquire guards on backend-0 and backend-1
    let _g0 = lb.select(localhost()).unwrap().guard; // backend-0 gets 1 conn
    let _g1a = lb.select(localhost()).unwrap().guard; // backend-1 gets 1 conn (0 already has 1)

    // Wait, LeastConnections picks min. After first select, backend-0 has 1.
    // Second select: backend-1 has 0 (min), so it picks backend-1.
    // Third select: backend-2 has 0 (min), so it picks backend-2.
    // Fourth select: backend-1 and backend-2 both have 1, backend-0 has 1 — picks backend-0 (first min).

    // Actually let's verify step by step.
    let lb = LoadBalancer::new(addrs(3), LbStrategy::LeastConnections, Duration::ZERO);
    let s0 = lb.select(localhost()).unwrap();
    assert_eq!(s0.addr, "backend-0:443"); // all at 0, picks first

    let s1 = lb.select(localhost()).unwrap();
    assert_eq!(s1.addr, "backend-1:443"); // 0 has 1, 1 has 0

    let s2 = lb.select(localhost()).unwrap();
    assert_eq!(s2.addr, "backend-2:443"); // 0 has 1, 1 has 1, 2 has 0

    // Now all have 1
    let s3 = lb.select(localhost()).unwrap();
    assert_eq!(s3.addr, "backend-0:443"); // all at 1, picks first

    // Drop s1 → backend-1 goes to 0
    drop(s1);
    let s4 = lb.select(localhost()).unwrap();
    assert_eq!(s4.addr, "backend-1:443"); // 0:2, 1:0, 2:1
}

// ── Failover ──

#[test]
fn failover_prefers_first() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::Failover, Duration::from_secs(60));
    for _ in 0..5 {
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    }
}

#[test]
fn failover_skips_unhealthy() {
    let lb = LoadBalancer::new(addrs(3), LbStrategy::Failover, Duration::from_secs(60));
    lb.mark_unhealthy("backend-0:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

    lb.mark_unhealthy("backend-1:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-2:443");
}

#[test]
fn failover_recovers_after_cooldown() {
    let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_millis(50));
    lb.mark_unhealthy("backend-0:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

    // Wait for cooldown
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
}

#[test]
fn failover_all_unhealthy_returns_error() {
    let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_secs(60));
    lb.mark_unhealthy("backend-0:443");
    lb.mark_unhealthy("backend-1:443");
    assert!(matches!(
        lb.select(localhost()),
        Err(LbError::NoHealthyBackend)
    ));
}

#[test]
fn failover_mark_healthy_recovers() {
    let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_secs(60));
    lb.mark_unhealthy("backend-0:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

    lb.mark_healthy("backend-0:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
}

// ── Edge cases ──

#[test]
fn empty_backends_error() {
    let lb = LoadBalancer::new(vec![], LbStrategy::RoundRobin, Duration::ZERO);
    lb.select(localhost()).unwrap_err();
}

#[test]
fn send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LoadBalancer>();
}

// ── Custom policies ──

/// The point of `with_policy`: selection is delegated to the caller's
/// policy, and whatever state that policy needs it carries itself.
#[test]
fn with_policy_delegates_selection() {
    struct AlwaysLast;

    impl LbPolicy for AlwaysLast {
        fn select(&self, backends: &[Arc<Backend>], _peer_ip: IpAddr) -> Option<usize> {
            backends.len().checked_sub(1)
        }
    }

    let lb = LoadBalancer::with_policy(
        addrs(3),
        Box::new(AlwaysLast),
        // The strategy tag is metadata for callers; it must not override
        // the policy that was handed in.
        LbStrategy::RoundRobin,
    );

    for _ in 0..3 {
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-2:443");
    }
    assert!(!lb.is_failover());
}

#[test]
fn every_strategy_excludes_quota_health_and_attempted_backends() {
    for strategy in [
        LbStrategy::RoundRobin,
        LbStrategy::IpHash,
        LbStrategy::LeastConnections,
        LbStrategy::Failover,
        LbStrategy::TrafficAware,
    ] {
        let lb = LoadBalancer::new(addrs(4), strategy, Duration::from_secs(30));
        lb.mark_unhealthy("backend-1:443");
        let excluded = vec!["backend-2:443".into()];
        for _ in 0..10 {
            assert_eq!(
                lb.select_available(localhost(), &excluded, |addr| {
                    (addr != "backend-0:443").then_some(0.5)
                })
                .unwrap()
                .addr,
                "backend-3:443"
            );
        }
        lb.mark_unhealthy("backend-3:443");
        assert!(matches!(
            lb.select_available(localhost(), &excluded, |addr| (addr != "backend-0:443")
                .then_some(1.0)),
            Err(LbError::NoHealthyBackend)
        ));
        lb.mark_healthy("backend-0:443");
        assert!(matches!(
            lb.select_available(localhost(), &[], |_| None),
            Err(LbError::NoHealthyBackend)
        ));
    }
}

#[test]
fn traffic_aware_shares_active_connections_by_remaining_capacity() {
    let lb = LoadBalancer::new(addrs(2), LbStrategy::TrafficAware, Duration::ZERO);
    let choose = || {
        lb.select_available(localhost(), &[], |addr| {
            Some(if addr == "backend-0:443" { 1.0 } else { 0.25 })
        })
        .unwrap()
    };
    let mut active = Vec::new();
    for _ in 0..4 {
        let selected = choose();
        assert_eq!(selected.addr, "backend-0:443");
        active.push(selected);
    }
    assert_eq!(choose().addr, "backend-1:443");
    drop(active);
    assert_eq!(choose().addr, "backend-0:443");
}

#[test]
fn zero_cooldown_never_recovers_exhausted_quota() {
    let lb = LoadBalancer::new(addrs(1), LbStrategy::Failover, Duration::ZERO);
    lb.mark_unhealthy("backend-0:443");
    assert!(matches!(
        lb.select_available(localhost(), &[], |_| None),
        Err(LbError::NoHealthyBackend)
    ));
    assert_eq!(
        lb.select_available(localhost(), &[], |_| Some(1.0))
            .unwrap()
            .addr,
        "backend-0:443"
    );
}

#[test]
fn custom_failover_retains_its_own_recovery_delay() {
    let lb = LoadBalancer::with_policy(
        addrs(1),
        Box::new(Failover {
            cooldown: Duration::ZERO,
        }),
        LbStrategy::Failover,
    );
    lb.mark_unhealthy("backend-0:443");
    assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    lb.mark_unhealthy("backend-0:443");
    assert!(matches!(
        lb.select_available(localhost(), &[], |_| None),
        Err(LbError::NoHealthyBackend)
    ));
}
