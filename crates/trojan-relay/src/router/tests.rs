use super::*;
use trojan_lb::{LbError, LbStrategy};
use trojan_protocol::{NodeState, NodeStateSnapshot};

fn managed_config() -> EntryConfig {
    toml::from_str(
        r#"
node_id = "entry"
[chains.a]
nodes = [{ addr = "relay-a:443", node_id = "relay-a", password = "secret" }]
[chains.b]
nodes = [{ addr = "relay-b:443", node_id = "relay-b", password = "secret" }]
[[rules]]
name = "routes"
listen = "127.0.0.1:1080"
strategy = "traffic_aware"
routes = [
    { chain = "a", dest = "exit-a:443", node_id = "exit-a" },
    { chain = "b", dest = "exit-b:443", node_id = "exit-b" },
]
"#,
    )
    .unwrap()
}

fn snapshot(used: [u64; 5]) -> NodeStateSnapshot {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    NodeStateSnapshot {
        generated_at: now,
        valid_until: now + 90,
        nodes: ["entry", "relay-a", "relay-b", "exit-a", "exit-b"]
            .into_iter()
            .zip(used)
            .map(|(id, used)| NodeState {
                node_id: id.into(),
                enabled: true,
                online: true,
                traffic_limit: 100,
                used_bytes: used,
                period_start: now - 10,
                reset_at: now + 3600,
            })
            .collect(),
    }
}

#[test]
fn all_strategies_filter_the_complete_managed_path_and_refresh_live() {
    for strategy in [
        LbStrategy::RoundRobin,
        LbStrategy::IpHash,
        LbStrategy::LeastConnections,
        LbStrategy::Failover,
        LbStrategy::TrafficAware,
    ] {
        let mut config = managed_config();
        config.rules[0].strategy = strategy;
        config.rules[0].failover_cooldown_secs = 0;
        let store = Arc::new(NodeStateStore::default());
        let router = Router::with_node_states(&config, store.clone()).unwrap();
        let pool = router.resolve(&config.rules[0].listen).unwrap().pool;
        let peer = "127.0.0.1".parse().unwrap();
        assert!(matches!(
            pool.select(peer, &[]),
            Err(LbError::NoHealthyBackend)
        ));
        store.update(snapshot([0, 100, 0, 0, 95]));
        for _ in 0..5 {
            assert_eq!(pool.select(peer, &[]).unwrap().candidate.dest, "exit-b:443");
        }
        store.update(snapshot([0, 0, 0, 0, 100]));
        assert_eq!(pool.select(peer, &[]).unwrap().candidate.dest, "exit-a:443");
        store.update(snapshot([100, 0, 0, 0, 0]));
        assert!(matches!(
            pool.select(peer, &[]),
            Err(LbError::NoHealthyBackend)
        ));
        let mut expired = snapshot([0; 5]);
        expired.valid_until = expired.generated_at;
        store.update(expired);
        assert!(matches!(
            pool.select(peer, &[]),
            Err(LbError::NoHealthyBackend)
        ));
        let mut offline = snapshot([0; 5]);
        offline.nodes[1].online = false;
        offline.nodes[4].enabled = false;
        store.update(offline);
        assert!(matches!(
            pool.select(peer, &[]),
            Err(LbError::NoHealthyBackend)
        ));
        store.update(snapshot([0; 5]));
        pool.select(peer, &[]).unwrap();
    }
}

#[test]
fn traffic_aware_uses_the_bottleneck_and_balances_unlimited_nodes() {
    let config = managed_config();
    let store = Arc::new(NodeStateStore::default());
    let router = Router::with_node_states(&config, store.clone()).unwrap();
    let pool = router.resolve(&config.rules[0].listen).unwrap().pool;
    let peer = "127.0.0.1".parse().unwrap();
    store.update(snapshot([0, 80, 20, 10, 70]));
    assert_eq!(pool.select(peer, &[]).unwrap().candidate.dest, "exit-b:443");
    let mut unlimited = snapshot([0, 0, 0, 75, 0]);
    for i in [0, 1, 2, 4] {
        unlimited.nodes[i].traffic_limit = 0;
    }
    store.update(unlimited);
    let active = (0..3)
        .map(|_| {
            let selected = pool.select(peer, &[]).unwrap();
            assert_eq!(selected.candidate.dest, "exit-b:443");
            selected
        })
        .collect::<Vec<_>>();
    assert_eq!(pool.select(peer, &[]).unwrap().candidate.dest, "exit-a:443");
    drop(active);
}

#[test]
fn explicit_routes_reject_ambiguous_legacy_fields() {
    let mut config = managed_config();
    config.rules[0].chain = "a".into();
    assert!(matches!(Router::new(&config), Err(RelayError::Config(_))));
}

fn make_config() -> EntryConfig {
    toml::from_str(
        r#"
[chains.jp]
nodes = [
  { addr = "relay-hk:443", password = "hk-secret" },
]

[chains.direct]
nodes = []

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"

[[rules]]
name = "singapore"
listen = "127.0.0.1:1082"
chain = "direct"
dest = "trojan-sg:443"
"#,
    )
    .unwrap()
}

#[test]
fn test_router_resolve() {
    let config = make_config();
    let router = Router::new(&config).unwrap();

    let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let route = router.resolve(&addr).unwrap();
    assert_eq!(route.rule.name, "japan");
    assert_eq!(route.rule.dest, vec!["trojan-jp:443"]);
    assert_eq!(route.pool.candidates["0"].chain.config().nodes.len(), 1);
    assert_eq!(
        route.pool.candidates["0"].chain.config().nodes[0].addr,
        "relay-hk:443"
    );
    // One hash per hop, resolved at build time.
    assert_eq!(route.pool.candidates["0"].chain.password_hashes().len(), 1);
    assert_eq!(route.pool.lb.backend_count(), 1);

    let addr: SocketAddr = "127.0.0.1:1082".parse().unwrap();
    let route = router.resolve(&addr).unwrap();
    assert_eq!(route.rule.name, "singapore");
    assert!(route.pool.candidates["0"].chain.config().nodes.is_empty());

    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    assert!(router.resolve(&addr).is_none());
}

#[test]
fn test_router_unknown_chain() {
    let config: EntryConfig = toml::from_str(
        r#"
[chains.jp]
nodes = []

[[rules]]
name = "bad"
listen = "127.0.0.1:1080"
chain = "nonexistent"
dest = "target:443"
"#,
    )
    .unwrap();

    let err = Router::new(&config).unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn test_router_duplicate_listen() {
    let config: EntryConfig = toml::from_str(
        r#"
[chains.jp]
nodes = []

[[rules]]
name = "a"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "target:443"

[[rules]]
name = "b"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "other:443"
"#,
    )
    .unwrap();

    let err = Router::new(&config).unwrap_err();
    assert!(err.to_string().contains("duplicate"));
}

#[test]
fn test_router_chain_node_missing_password() {
    let config: EntryConfig = toml::from_str(
        r#"
[chains.jp]
nodes = [
  { addr = "relay-hk:443" },
]

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"
"#,
    )
    .unwrap();

    // A hop with no password is a config error. Hashes are resolved when
    // the router is built, so it surfaces at startup rather than on the
    // first connection through that chain.
    let err = Router::new(&config).unwrap_err();
    assert!(
        err.to_string().contains("missing a password"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_router_listen_addrs() {
    let config = make_config();
    let router = Router::new(&config).unwrap();
    let addrs = router.listen_addrs();
    assert_eq!(addrs.len(), 2);
}

#[test]
fn test_router_multi_dest() {
    let config: EntryConfig = toml::from_str(
        r#"
[chains.jp]
nodes = []

[[rules]]
name = "ha"
listen = "127.0.0.1:1080"
chain = "jp"
dest = ["a:443", "b:443", "c:443"]
strategy = "ip_hash"
"#,
    )
    .unwrap();

    let router = Router::new(&config).unwrap();
    let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let route = router.resolve(&addr).unwrap();
    assert_eq!(route.pool.lb.backend_count(), 3);
}
