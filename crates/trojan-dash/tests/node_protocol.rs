//! The node-facing half of the service, driven by the client a node actually
//! runs.
//!
//! `HttpAuth` is what a `trojan server` uses when `http_url` is configured, so
//! pointing it at a live `trojan-dash` exercises the real protocol — bincode
//! framing, bearer auth, batched traffic — instead of a hand-written stand-in.

// Integration tests are their own crate; there is no test module to sit in.
#![allow(clippy::tests_outside_test_module)]

use std::net::TcpListener;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use trojan_auth::AuthBackend;
use trojan_auth::http::{Codec, HttpAuth, HttpAuthConfig};
use trojan_auth::sha224_hex;
use trojan_dash::DashConfig;

const ADMIN_TOKEN: &str = "test-admin-token";

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

        let config: DashConfig = toml::from_str(&format!(
            r#"
            listen = "127.0.0.1:{port}"
            database = "{}"
            admin_token = "{ADMIN_TOKEN}"
            "#,
            database.display()
        ))
        .unwrap();

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
