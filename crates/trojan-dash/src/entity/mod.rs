//! Entity models, one per table rows are read from.
//!
//! Copied from the panel these tables came from, so a database written by
//! either service reads the same way. `traffic_hourly` has none: nothing reads
//! a row of it, only sums across it, so it lives in the migration and in the
//! aggregates alone.

pub mod nodes;
pub mod sub_templates;
pub mod traffic_logs;
pub mod user_node_limits;
pub mod users;
