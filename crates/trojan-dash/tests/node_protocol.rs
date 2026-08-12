//! The node-facing half of the service, driven by the client a node actually
//! runs.
//!
//! `HttpAuth` is what a `trojan server` uses when `http_url` is configured, so
//! pointing it at a live `trojan-dash` exercises the real protocol — bincode
//! framing, bearer auth, batched traffic — instead of a hand-written stand-in.

// Integration tests are their own crate; there is no test module to sit in.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use trojan_auth::AuthBackend;
use trojan_auth::sha224_hex;
use trojan_dash::DashConfig;

mod common;

use common::{ADMIN_TOKEN, Dash, config_toml};

/// A Windows path must survive into the config unchanged.
///
/// This ran green on Linux and macOS while every dash test failed on Windows,
/// because only a Windows temp path contains the backslashes that TOML treats
/// as escapes.
#[test]
fn config_accepts_a_windows_style_database_path() {
    let raw = r"C:\Users\RUNNER~1\AppData\Local\Temp\.tmpZY3AhE\dash.db";
    let config: DashConfig = toml::from_str(&config_toml(8080, std::path::Path::new(raw)))
        .expect("a backslashed path must not be read as a unicode escape");

    assert_eq!(config.database_url, raw);
}

#[tokio::test]
async fn verify_admits_a_known_password_and_refuses_the_rest() {
    let dash = Dash::start().await;
    let node_token = dash.add_node("node-a").await;
    let (user_id, password) = dash.add_user("alice").await;

    let auth = dash.node_auth(&node_token);

    let result = auth
        .verify(&sha224_hex(&password))
        .await
        .expect("the created user should authenticate");
    assert_eq!(
        result.user_id.as_deref(),
        Some(user_id.to_string().as_str())
    );

    auth.verify(&sha224_hex("not-the-password"))
        .await
        .expect_err("an unknown hash must not authenticate");
}

#[tokio::test]
async fn a_disabled_user_stops_authenticating() {
    let dash = Dash::start().await;
    let node_token = dash.add_node("node-a").await;
    let (user_id, password) = dash.add_user("bob").await;
    let auth = dash.node_auth(&node_token);

    auth.verify(&sha224_hex(&password)).await.unwrap();

    let resp = dash
        .client
        .patch(format!("{}/admin/users/{user_id}", dash.base))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    auth.verify(&sha224_hex(&password))
        .await
        .expect_err("a disabled user must be refused");
}

#[tokio::test]
async fn reported_traffic_lands_on_the_user_and_the_node() {
    let dash = Dash::start().await;
    let node_token = dash.add_node("node-a").await;
    let (user_id, password) = dash.add_user("carol").await;

    let auth = dash.node_auth(&node_token);
    auth.verify(&sha224_hex(&password)).await.unwrap();

    auth.record_traffic(&user_id.to_string(), 4096)
        .await
        .unwrap();
    auth.record_traffic(&user_id.to_string(), 1024)
        .await
        .unwrap();
    // Traffic is batched; shutdown flushes what is pending.
    auth.shutdown().await;

    let user = dash.admin_get(&format!("/admin/users/{user_id}")).await;
    assert_eq!(
        user["traffic_used"].as_u64(),
        Some(5120),
        "both reports should accumulate on the user"
    );

    let logs = dash
        .admin_get(&format!("/admin/traffic?user_id={user_id}"))
        .await;
    let logs = logs.as_array().unwrap();
    assert_eq!(
        logs.len(),
        1,
        "same user, node and day is one row: {logs:?}"
    );
    assert_eq!(logs[0]["bytes"].as_u64(), Some(5120));

    let nodes = dash.admin_get("/admin/nodes").await;
    assert!(
        nodes[0]["last_seen"].as_u64().unwrap_or(0) > 0,
        "serving a node call should stamp last_seen"
    );

    let series = dash.admin_get("/admin/traffic/series?range=7d").await;
    let points = series["points"].as_array().unwrap();
    assert_eq!(points.len(), 1, "one node, one day: {points:?}");
    assert_eq!(points[0]["bytes"].as_u64(), Some(5120));
    assert_eq!(points[0]["label"].as_str(), Some("node-a"));
}

#[tokio::test]
async fn the_admin_api_refuses_a_wrong_token() {
    let dash = Dash::start().await;

    let resp = dash
        .client
        .get(format!("{}/admin/users", dash.base))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let resp = dash
        .client
        .get(format!("{}/admin/users", dash.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// The exit reports for the hops in front of it: each is credited the same
/// bytes, and none of it touches the user's quota — one download through a
/// three-hop chain is still one download's worth of quota.
#[tokio::test]
async fn chain_traffic_credits_each_hop_without_double_billing_the_user() {
    let dash = Dash::start().await;
    let exit_token = dash.add_node("exit").await;
    let entry_id = dash.add_node_id("entry").await;
    let relay_id = dash.add_node_id("relay").await;
    let (user_id, password) = dash.add_user("dave").await;

    let auth = dash.node_auth(&exit_token);
    auth.verify(&sha224_hex(&password)).await.unwrap();

    // What an exit does when a chained connection ends: settle the user, then
    // credit the hops that carried the same bytes.
    auth.record_traffic(&user_id.to_string(), 2048)
        .await
        .unwrap();
    auth.record_chain_traffic(
        &user_id.to_string(),
        2048,
        &[entry_id.to_string(), relay_id.to_string()],
    )
    .await
    .unwrap();
    auth.shutdown().await;

    let user = dash.admin_get(&format!("/admin/users/{user_id}")).await;
    assert_eq!(
        user["traffic_used"].as_u64(),
        Some(2048),
        "the chain must not multiply what the user is charged"
    );

    let series = dash.admin_get("/admin/traffic/series?range=7d").await;
    let mut by_node: Vec<(String, u64)> = series["points"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["label"].as_str().unwrap().to_owned(),
                row["bytes"].as_u64().unwrap(),
            )
        })
        .collect();
    by_node.sort();

    assert_eq!(
        by_node,
        vec![
            ("entry".to_string(), 2048),
            ("exit".to_string(), 2048),
            ("relay".to_string(), 2048),
        ],
        "every hop carried the same bytes and should be credited them"
    );
}

/// A hop the panel has never heard of is a stale config on the reporting node,
/// not a reason to fail the request or corrupt the log.
#[tokio::test]
async fn chain_traffic_for_an_unknown_hop_is_refused() {
    let dash = Dash::start().await;
    let exit_token = dash.add_node("exit").await;
    let (user_id, password) = dash.add_user("erin").await;

    let auth = dash.node_auth(&exit_token);
    auth.verify(&sha224_hex(&password)).await.unwrap();

    auth.record_chain_traffic(&user_id.to_string(), 512, &["9999".to_string()])
        .await
        .unwrap();
    auth.shutdown().await;

    let logs = dash
        .admin_get(&format!("/admin/traffic?user_id={user_id}"))
        .await;
    assert!(
        logs.as_array().unwrap().is_empty(),
        "an unknown hop must not produce a row: {logs:?}"
    );
}

/// An allowance on one node travels to the exit with the verify answer, and
/// carries what the month has already spent — the exit enforces it, because a
/// relay hop cannot: it never learns whose traffic it is carrying.
#[tokio::test]
async fn a_node_allowance_reaches_the_exit_with_the_months_spend() {
    let dash = Dash::start().await;
    let exit_token = dash.add_node("exit").await;
    let entry_id = dash.add_node_id("entry").await;
    let (user_id, password) = dash.add_user("gina").await;

    dash.admin_put(
        &format!("/admin/users/{user_id}/limits/{entry_id}"),
        serde_json::json!({ "monthly_bytes": 4096 }),
    )
    .await;

    // Spend part of it before the first verify, so the answer cannot come
    // from a cache that predates the traffic.
    let auth = dash.node_auth(&exit_token);
    auth.record_chain_traffic(&user_id.to_string(), 1024, &[entry_id.to_string()])
        .await
        .unwrap();
    auth.shutdown().await;

    let auth = dash.node_auth(&exit_token);
    let result = auth.verify(&sha224_hex(&password)).await.unwrap();
    let quotas = result.metadata.expect("metadata").node_quotas;

    assert_eq!(quotas.len(), 1, "only capped nodes appear: {quotas:?}");
    assert_eq!(quotas[0].node_id, entry_id.to_string());
    assert_eq!(quotas[0].limit, 4096);
    assert_eq!(quotas[0].used, 1024);
}

/// An uncapped user carries no allowances at all — the common case must not
/// pay for the feature.
#[tokio::test]
async fn a_user_with_no_caps_carries_no_allowances() {
    let dash = Dash::start().await;
    let exit_token = dash.add_node("exit").await;
    let (_user_id, password) = dash.add_user("hank").await;

    let auth = dash.node_auth(&exit_token);
    let result = auth.verify(&sha224_hex(&password)).await.unwrap();

    assert!(result.metadata.expect("metadata").node_quotas.is_empty());
}

/// Raising a cap has to reach the nodes, so the write settles the verify cache
/// the way every other write on a user does.
#[tokio::test]
async fn changing_a_cap_invalidates_the_cached_answer() {
    let dash = Dash::start().await;
    let exit_token = dash.add_node("exit").await;
    let entry_id = dash.add_node_id("entry").await;
    let (user_id, password) = dash.add_user("iris").await;

    let auth = dash.node_auth(&exit_token);
    auth.verify(&sha224_hex(&password)).await.unwrap();

    dash.admin_put(
        &format!("/admin/users/{user_id}/limits/{entry_id}"),
        serde_json::json!({ "monthly_bytes": 8192 }),
    )
    .await;

    let result = auth.verify(&sha224_hex(&password)).await.unwrap();
    let quotas = result.metadata.expect("metadata").node_quotas;
    assert_eq!(
        quotas.len(),
        1,
        "the cached answer should have been dropped"
    );
    assert_eq!(quotas[0].limit, 8192);

    let listed = dash
        .admin_get(&format!("/admin/users/{user_id}/limits"))
        .await;
    assert_eq!(listed[0]["monthly_bytes"].as_u64(), Some(8192));
}
