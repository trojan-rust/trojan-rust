//! Rule-based routing engine for trojan-rs.
//!
//! Provides a rule matching engine compatible with Surge rule-set (`.list`)
//! and Clash rule-provider (YAML) formats. Supports DOMAIN, DOMAIN-SUFFIX,
//! DOMAIN-KEYWORD, and IP-CIDR rule types with optimized data structures.
//!
//! # Architecture
//!
//! - **Matchers**: `DomainMatcher` (FxHashSet), `KeywordMatcher` (Aho-Corasick),
//!   `CidrMatcher` (sorted binary search)
//! - **Parsers**: Surge `.list` and Clash YAML formats
//! - **Providers**: File-based loading (HTTP in Phase 3)
//! - **Engine**: `RuleEngine` compiles rule-sets and evaluates rules in order
//!
//! # Example
//!
//! ```
//! use trojan_rules::{RuleEngineBuilder, Action};
//! use trojan_rules::rule::{ParsedRule, MatchContext};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! let mut builder = RuleEngineBuilder::new();
//! builder.add_rule_set("ads", vec![
//!     ParsedRule::DomainSuffix("ad.example.com".into()),
//!     ParsedRule::DomainKeyword("tracking".into()),
//! ]);
//! builder.add_rule_set_rule("ads", Action::Reject);
//! builder.set_final(Action::Direct);
//!
//! let engine = builder.build().unwrap();
//!
//! let ctx = MatchContext {
//!     domain: Some("tracker.ad.example.com"),
//!     dest_ip: None,
//!     dest_port: 443,
//!     src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
//! };
//! assert_eq!(engine.match_request(&ctx), &Action::Reject);
//! ```

pub mod engine;
pub mod error;
#[cfg(feature = "geoip")]
pub mod geoip_db;
pub mod matcher;
pub mod parser;
pub mod provider;
pub mod rule;

pub use engine::{HotRuleEngine, MatchDecision, RuleEngine, RuleEngineBuilder};
pub use error::RulesError;
pub use rule::Action;
