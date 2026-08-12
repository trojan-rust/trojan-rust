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

use std::net::TcpListener;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use trojan_auth::AuthBackend;
use trojan_auth::http::{Codec, HttpAuth, HttpAuthConfig};
use trojan_auth::sha224_hex;
use trojan_dash::DashConfig;

const ADMIN_TOKEN: &str = "test-admin-token";

/// Build the service config for a temp database.
///
/// The path goes through `toml::Value` rather than straight into the string: a
/// Windows temp path is full of backslashes, and TOML basic strings read those
/// as escapes, so an interpolated `C:\Users\...` fails to parse as an invalid
/// `\U` unicode escape. Letting toml quote its own value is correct on every
/// platform without hand-rolling the escaping.
fn config_toml(port: u16, database: &std::path::Path) -> String {
    let database = toml::Value::from(database.display().to_string());
    format!(
        r#"
        listen = "127.0.0.1:{port}"
        database = {database}
        admin_token = "{ADMIN_TOKEN}"
        "#
    )
}

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

    assert_eq!(config.database, raw);
}

/// A running service, torn down when dropped.
struct Dash {
    base: String,
    client: reqwest::Client,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

impl Drop for Dash {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl Dash {
    /// Start the service on a free port with an empty database.
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("dash.db");

        // Claim a port, then release it: the service binds it a moment later.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let config: DashConfig = toml::from_str(&config_toml(port, &database)).unwrap();

        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        tokio::spawn(async move {
            trojan_dash::run(config, token).await.unwrap();
        });

        let dash = Self {
            base: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::new(),
            shutdown,
            _dir: dir,
        };
        dash.await_ready().await;
        dash
    }

    async fn await_ready(&self) {
        for _ in 0..100 {
            if let Ok(resp) = self
                .client
                .get(format!("{}/health", self.base))
                .send()
                .await
                && resp.status().is_success()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("dash did not become ready");
    }

    async fn admin_post(&self, path: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(ADMIN_TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "POST {path}: {:?}",
            resp.status()
        );
        resp.json().await.unwrap()
    }

    async fn admin_get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(format!("{}{path}", self.base))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "GET {path}: {:?}",
            resp.status()
        );
        resp.json().await.unwrap()
    }

    /// Create a node and return its token.
    async fn add_node(&self, name: &str) -> String {
        let node = self
            .admin_post("/admin/nodes", serde_json::json!({ "name": name }))
            .await;
        node["token"].as_str().unwrap().to_owned()
    }

    /// Create a node and return its row id, for chains that name it.
    async fn add_node_id(&self, name: &str) -> u64 {
        let node = self
            .admin_post("/admin/nodes", serde_json::json!({ "name": name }))
            .await;
        node["id"].as_u64().unwrap()
    }

    /// Create a user and return its id and generated password.
    async fn add_user(&self, username: &str) -> (u64, String) {
        let user = self
            .admin_post("/admin/users", serde_json::json!({ "username": username }))
            .await;
        (
            user["id"].as_u64().unwrap(),
            user["password"].as_str().unwrap().to_owned(),
        )
    }

    /// An auth backend configured the way a node would configure it.
    fn node_auth(&self, node_token: &str) -> HttpAuth {
        HttpAuth::new(HttpAuthConfig {
            base_url: self.base.clone(),
            codec: Codec::Bincode,
            node_token: Some(node_token.to_owned()),
            // No local caching: every call must reach the service, or these
            // assertions would pass on stale answers.
            cache_ttl: Duration::ZERO,
            batch_flush_interval: Duration::from_millis(50),
            ..Default::default()
        })
    }
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

    let daily = dash.admin_get("/admin/traffic/daily?days=7").await;
    let daily = daily.as_array().unwrap();
    assert_eq!(daily.len(), 1, "one node, one day: {daily:?}");
    assert_eq!(daily[0]["bytes"].as_u64(), Some(5120));
    assert_eq!(daily[0]["node_name"].as_str(), Some("node-a"));
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

    let daily = dash.admin_get("/admin/traffic/daily?days=7").await;
    let mut by_node: Vec<(String, u64)> = daily
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["node_name"].as_str().unwrap().to_owned(),
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
