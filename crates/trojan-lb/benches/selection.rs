use std::hint::black_box;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use criterion::{Criterion, criterion_group, criterion_main};
use trojan_lb::{LbStrategy, LoadBalancer, NodeStateStore};
use trojan_protocol::{NodeState, NodeStateSnapshot};

fn selection(c: &mut Criterion) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let addrs = (0..16)
        .map(|index| format!("exit-{index}"))
        .collect::<Vec<_>>();
    let states = NodeStateStore::default();
    states.update(NodeStateSnapshot {
        generated_at: now,
        valid_until: now + 3600,
        nodes: addrs
            .iter()
            .map(|id| NodeState {
                node_id: id.clone(),
                enabled: true,
                online: true,
                traffic_supported: true,
                traffic_limit: 1000,
                used_bytes: 200,
                period_start: now - 100,
                reset_at: now + 3600,
            })
            .collect(),
    });
    let peer = "127.0.0.1".parse().unwrap();
    let round_robin = LoadBalancer::new(
        addrs.clone(),
        LbStrategy::RoundRobin,
        Duration::from_secs(30),
    );
    let traffic = LoadBalancer::new(addrs, LbStrategy::TrafficAware, Duration::from_secs(30));
    c.bench_function("static_round_robin_16", |b| {
        b.iter(|| black_box(round_robin.select(peer).unwrap()))
    });
    c.bench_function("managed_traffic_aware_16", |b| {
        b.iter(|| {
            let snapshot = states.snapshot();
            black_box(
                traffic
                    .select_available(peer, &[], |id| snapshot.remaining_fraction(id))
                    .unwrap(),
            )
        })
    });
}

criterion_group!(benches, selection);
criterion_main!(benches);
