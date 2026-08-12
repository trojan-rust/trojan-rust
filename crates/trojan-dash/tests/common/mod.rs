//! A running `trojan-dash` and the calls a test makes against it.
//!
//! Shared by the integration tests so each one drives the real service rather
//! than a stand-in of it.

#![expect(
    dead_code,
    reason = "each test binary compiles this module and uses a subset of it"
)]

use std::net::TcpListener;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use trojan_auth::http::{Codec, HttpAuth, HttpAuthConfig};
use trojan_dash::DashConfig;

pub const ADMIN_TOKEN: &str = "test-admin-token";

/// Build the service config for a temp database.
///
/// The path goes through `toml::Value` rather than straight into the string: a
/// Windows temp path is full of backslashes, and TOML basic strings read those
/// as escapes, so an interpolated `C:\Users\...` fails to parse as an invalid
/// `\U` unicode escape. Letting toml quote its own value is correct on every
/// platform without hand-rolling the escaping.
pub fn config_toml(port: u16, database: &std::path::Path) -> String {
    let database = toml::Value::from(database.display().to_string());
    format!(
        r#"
        listen = "127.0.0.1:{port}"
        database = {database}
        admin_token = "{ADMIN_TOKEN}"
        "#
    )
}

/// A running service, torn down when dropped.
pub struct Dash {
    pub base: String,
    pub client: reqwest::Client,
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
    pub async fn start() -> Self {
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

    pub async fn admin_post(&self, path: &str, body: Value) -> Value {
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

    pub async fn admin_get(&self, path: &str) -> Value {
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
    pub async fn add_node(&self, name: &str) -> String {
        let node = self
            .admin_post("/admin/nodes", serde_json::json!({ "name": name }))
            .await;
        node["token"].as_str().unwrap().to_owned()
    }

    /// Create a node and return its row id, for chains that name it.
    pub async fn add_node_id(&self, name: &str) -> u64 {
        let node = self
            .admin_post("/admin/nodes", serde_json::json!({ "name": name }))
            .await;
        node["id"].as_u64().unwrap()
    }

    /// Create a user and return its id and generated password.
    pub async fn add_user(&self, username: &str) -> (u64, String) {
        let user = self
            .admin_post("/admin/users", serde_json::json!({ "username": username }))
            .await;
        (
            user["id"].as_u64().unwrap(),
            user["password"].as_str().unwrap().to_owned(),
        )
    }

    /// An auth backend configured the way a node would configure it.
    pub fn node_auth(&self, node_token: &str) -> HttpAuth {
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
