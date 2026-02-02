//! Error types for the rule engine.

use thiserror::Error;

/// Errors that can occur in the rule engine.
#[derive(Error, Debug)]
pub enum RulesError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("invalid rule type: {0}")]
    InvalidRuleType(String),

    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("no FINAL rule defined")]
    NoFinalRule,

    #[error("unknown rule-set: {0}")]
    UnknownRuleSet(String),

    #[error("rule provider error: {0}")]
    Provider(String),

    #[error("geoip error: {0}")]
    GeoIp(String),

    #[error("http error: {0}")]
    Http(String),
}
