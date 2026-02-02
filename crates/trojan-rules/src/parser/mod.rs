//! Rule-set parsers for Surge and Clash formats.

pub mod clash;
pub mod surge;

pub use clash::parse_clash_provider;
pub use surge::{parse_surge_domain_set, parse_surge_ruleset};
