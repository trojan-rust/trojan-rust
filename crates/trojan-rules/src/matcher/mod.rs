//! Rule matchers for different rule types.

pub mod domain;
#[cfg(feature = "geoip")]
pub mod geoip;
pub mod ip;

pub use domain::{DomainMatcher, KeywordMatcher};
#[cfg(feature = "geoip")]
pub use geoip::GeoipMatcher;
pub use ip::CidrMatcher;
