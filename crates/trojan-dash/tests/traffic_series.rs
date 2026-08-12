//! The bucketed series every traffic chart is drawn from.
//!
//! Two things are worth holding down here: which table a range reads — the
//! short ones are the only reason the hourly rollup exists — and that a user
//! asking for their own series cannot widen it to somebody else's.

// Integration tests are their own crate; there is no test module to sit in.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use serde_json::Value;

mod common;

use common::Dash;

/// Sum every point, ignoring how they are split.
fn total(series: &Value) -> u64 {
    points(series)
        .iter()
        .filter_map(|p| p["bytes"].as_u64())
        .sum()
}

fn points(series: &Value) -> &Vec<Value> {
    series["points"].as_array().expect("a series has points")
}

fn labels(series: &Value) -> Vec<&str> {
    points(series)
        .iter()
        .filter_map(|p| p["label"].as_str())
        .collect()
}

/// A 24-hour range has no answer in the daily table, whose finest key is a
/// date. It must come from the hourly rollup, bucketed by the hour.
#[tokio::test]
async fn a_short_range_is_bucketed_by_the_hour() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (user_id, _) = dash.add_user("alice").await;

    dash.report_traffic(&node, user_id, 4096).await;

    let series = dash.admin_get("/admin/traffic/series?range=24h").await;

    assert_eq!(series["bucket"].as_str(), Some("hour"));
    assert_eq!(total(&series), 4096);
    assert_eq!(labels(&series), ["node-a"]);

    let t = points(&series)[0]["t"].as_str().unwrap();
    assert_eq!(t.len(), 13, "an hourly bucket is YYYY-MM-DDTHH: {t}");
}

/// Anything a week or wider reads the daily table, which keeps history the
/// hourly rollup is pruned out of.
#[tokio::test]
async fn a_long_range_is_bucketed_by_the_day() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (user_id, _) = dash.add_user("alice").await;

    dash.report_traffic(&node, user_id, 4096).await;

    for range in ["7d", "30d", "90d"] {
        let series = dash
            .admin_get(&format!("/admin/traffic/series?range={range}"))
            .await;

        assert_eq!(series["bucket"].as_str(), Some("day"), "range={range}");
        assert_eq!(total(&series), 4096, "range={range}");

        let t = points(&series)[0]["t"].as_str().unwrap();
        assert_eq!(t.len(), 10, "a daily bucket is YYYY-MM-DD: {t}");
    }
}

/// Both rollups are written by one accounting event, so the same bytes must
/// be visible whichever table the range reaches for.
#[tokio::test]
async fn the_two_rollups_agree_on_what_was_reported() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (user_id, _) = dash.add_user("alice").await;

    dash.report_traffic(&node, user_id, 1500).await;
    dash.report_traffic(&node, user_id, 2500).await;

    let hourly = dash.admin_get("/admin/traffic/series?range=24h").await;
    let daily = dash.admin_get("/admin/traffic/series?range=30d").await;

    assert_eq!(total(&hourly), 4000);
    assert_eq!(total(&daily), 4000);
}

#[tokio::test]
async fn grouping_splits_the_series_by_node_or_by_user() {
    let dash = Dash::start().await;
    let node_a = dash.add_node("node-a").await;
    let node_b = dash.add_node("node-b").await;
    let (alice, _) = dash.add_user("alice").await;
    let (bob, _) = dash.add_user("bob").await;

    dash.report_traffic(&node_a, alice, 1000).await;
    dash.report_traffic(&node_b, bob, 2000).await;

    let by_node = dash
        .admin_get("/admin/traffic/series?range=30d&group=node")
        .await;
    assert_eq!(labels(&by_node), ["node-a", "node-b"]);

    let by_user = dash
        .admin_get("/admin/traffic/series?range=30d&group=user")
        .await;
    assert_eq!(labels(&by_user), ["alice", "bob"]);

    // Same bytes either way — grouping changes the split, not the total.
    assert_eq!(total(&by_node), 3000);
    assert_eq!(total(&by_user), 3000);
}

#[tokio::test]
async fn an_ungrouped_series_is_one_line_with_no_label() {
    let dash = Dash::start().await;
    let node_a = dash.add_node("node-a").await;
    let node_b = dash.add_node("node-b").await;
    let (user_id, _) = dash.add_user("alice").await;

    dash.report_traffic(&node_a, user_id, 1000).await;
    dash.report_traffic(&node_b, user_id, 2000).await;

    let series = dash
        .admin_get("/admin/traffic/series?range=30d&group=none")
        .await;

    assert_eq!(points(&series).len(), 1, "one day, one line");
    assert_eq!(total(&series), 3000);
    assert!(
        points(&series)[0].get("label").is_none(),
        "an ungrouped point has nothing to label: {series}"
    );
}

#[tokio::test]
async fn filters_narrow_the_series_to_one_node_or_user() {
    let dash = Dash::start().await;
    let node_a = dash.add_node("node-a").await;
    let node_b = dash.add_node("node-b").await;
    let node_b_id = dash.add_node_id("node-c").await;
    let (alice, _) = dash.add_user("alice").await;
    let (bob, _) = dash.add_user("bob").await;

    dash.report_traffic(&node_a, alice, 1000).await;
    dash.report_traffic(&node_b, bob, 2000).await;

    let one_user = dash
        .admin_get(&format!("/admin/traffic/series?range=30d&user_id={alice}"))
        .await;
    assert_eq!(total(&one_user), 1000);
    assert_eq!(labels(&one_user), ["node-a"]);

    // A node nobody reported for is an empty series, not an error.
    let quiet = dash
        .admin_get(&format!(
            "/admin/traffic/series?range=30d&node_id={node_b_id}"
        ))
        .await;
    assert!(points(&quiet).is_empty(), "{quiet}");
}

/// The whole-history range has to reach past whatever the fixed windows cover,
/// and picks a coarser bucket than a day.
#[tokio::test]
async fn the_whole_history_range_uses_a_coarser_bucket() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (user_id, _) = dash.add_user("alice").await;

    dash.report_traffic(&node, user_id, 4096).await;

    let series = dash.admin_get("/admin/traffic/series?range=all").await;

    assert_eq!(series["bucket"].as_str(), Some("week"));
    assert_eq!(total(&series), 4096);
}

/// `user_id` on `/me/traffic` comes from the credentials. A user who asks for
/// somebody else's traffic gets their own.
#[tokio::test]
async fn a_user_series_covers_only_the_caller() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (alice, alice_pw) = dash.add_user("alice").await;
    let (bob, _) = dash.add_user("bob").await;

    dash.report_traffic(&node, alice, 1000).await;
    dash.report_traffic(&node, bob, 9000).await;

    let mine = dash
        .user_get("/me/traffic?range=30d", "alice", &alice_pw)
        .await;
    assert_eq!(total(&mine), 1000, "bob's traffic is not alice's: {mine}");

    let widened = dash
        .user_get(
            &format!("/me/traffic?range=30d&user_id={bob}"),
            "alice",
            &alice_pw,
        )
        .await;
    assert_eq!(
        total(&widened),
        1000,
        "a user_id in the query must not widen the scope: {widened}"
    );
}

/// Breaking one user's traffic down by user is one line named after them, so
/// the grouping collapses instead.
#[tokio::test]
async fn a_user_cannot_group_their_own_traffic_by_user() {
    let dash = Dash::start().await;
    let node = dash.add_node("node-a").await;
    let (alice, alice_pw) = dash.add_user("alice").await;

    dash.report_traffic(&node, alice, 1000).await;

    let series = dash
        .user_get("/me/traffic?range=30d&group=user", "alice", &alice_pw)
        .await;

    assert_eq!(total(&series), 1000);
    assert!(labels(&series).is_empty(), "{series}");
}

#[tokio::test]
async fn a_user_series_still_splits_by_node() {
    let dash = Dash::start().await;
    let node_a = dash.add_node("node-a").await;
    let node_b = dash.add_node("node-b").await;
    let (alice, alice_pw) = dash.add_user("alice").await;

    dash.report_traffic(&node_a, alice, 1000).await;
    dash.report_traffic(&node_b, alice, 2000).await;

    let series = dash
        .user_get("/me/traffic?range=24h&group=node", "alice", &alice_pw)
        .await;

    assert_eq!(labels(&series), ["node-a", "node-b"]);
    assert_eq!(total(&series), 3000);
}

#[tokio::test]
async fn an_unauthenticated_user_series_is_refused() {
    let dash = Dash::start().await;

    let status = dash
        .client
        .get(format!("{}/me/traffic", dash.base))
        .send()
        .await
        .unwrap()
        .status();

    assert_eq!(status, 401);
}
