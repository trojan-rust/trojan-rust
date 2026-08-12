//! What a user's own client reads: the account view behind `/me`, and the
//! subscription rendering a Surge panel is installed through.

// Integration tests are their own crate; there is no test module to sit in.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use base64::Engine;
use serde_json::json;

mod common;

use common::Dash;

/// The two usage windows come from different tables — the hourly rollup and
/// the daily log — and must agree on what one accounting event reported.
#[tokio::test]
async fn me_reports_the_recent_and_monthly_windows() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (alice, alice_pw) = dash.add_user("alice").await;

    dash.report_traffic(&node, alice, 4096).await;

    let me = dash.user_get("/me", "alice", &alice_pw).await;

    assert_eq!(me["last_24h_bytes"].as_u64(), Some(4096), "{me}");
    assert_eq!(me["month_bytes"].as_u64(), Some(4096), "{me}");
    assert_eq!(
        me["traffic_by_node"][0]["node_name"].as_str(),
        Some("node-a")
    );
    assert_eq!(me["user"]["traffic_used"].as_u64(), Some(4096));
}

/// The figures are the caller's own: another user's traffic is not theirs, and
/// an account that has moved nothing reports zero rather than nothing.
#[tokio::test]
async fn me_covers_only_the_caller() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (alice, _) = dash.add_user("alice").await;
    let (_, bob_pw) = dash.add_user("bob").await;

    dash.report_traffic(&node, alice, 9000).await;

    let me = dash.user_get("/me", "bob", &bob_pw).await;

    assert_eq!(me["last_24h_bytes"].as_u64(), Some(0), "{me}");
    assert_eq!(me["month_bytes"].as_u64(), Some(0), "{me}");
    assert!(
        me["traffic_by_node"].as_array().is_some_and(Vec::is_empty),
        "{me}"
    );
}

/// A client script needs the credential in a form that survives being pasted
/// into a config file, which is what the template renders for it.
#[tokio::test]
async fn a_template_renders_the_basic_credential() {
    let dash = Dash::start().await;
    let (_, alice_pw) = dash.add_user("alice").await;

    dash.admin_post(
        "/admin/sub-templates",
        json!({ "name": "panel", "content": "auth={{ basic_auth }} user={{ username }}" }),
    )
    .await;

    let rendered = dash.sub("panel", &alice_pw).await;
    let (auth, username) = rendered
        .strip_prefix("auth=")
        .and_then(|rest| rest.split_once(' '))
        .expect("the template renders both placeholders");

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth)
        .expect("a Basic credential is base64");
    assert_eq!(
        String::from_utf8(decoded).unwrap(),
        format!("alice:{alice_pw}")
    );
    assert_eq!(username, "user=alice");
}

/// Surge fetches the script itself, so it has to be served as a script rather
/// than as whatever the panel directory falls back to.
#[tokio::test]
async fn the_panel_script_is_served_as_javascript() {
    let dash = Dash::start().await;

    let response = dash
        .client
        .get(format!("{}/surge/panel.js", dash.base))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/javascript; charset=utf-8")
    );

    let body = response.text().await.unwrap();
    assert!(
        body.contains("$done("),
        "the panel contract is a $done call"
    );
    assert!(
        body.contains("/me"),
        "the script reads the account endpoint"
    );
}
