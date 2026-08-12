//! What a GeoIP lookup says about an address.
//!
//! Lives here rather than with the database that produces it because the
//! consumers are elsewhere: the analytics collector files these fields on an
//! event, and the server carries one between the two. A plain data type in the
//! shared crate lets both name it without either depending on the other.

use serde::{Deserialize, Serialize};

/// Geographic information for an IP address.
///
/// Every field is defaulted rather than optional: a database that resolves an
/// address only partially — country but no city, no ASN — is the normal case,
/// not an error, and consumers write the blanks through unchanged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GeoResult {
    /// ISO 3166-1 alpha-2 country code (e.g., "CN", "US").
    pub country: String,
    /// Region/state/province name (e.g., "Shanghai", "California").
    pub region: String,
    /// City name (e.g., "Shanghai", "Los Angeles").
    pub city: String,
    /// Autonomous System Number.
    pub asn: u32,
    /// ASN organization name (e.g., "China Telecom").
    pub org: String,
    /// Longitude coordinate.
    pub longitude: f64,
    /// Latitude coordinate.
    pub latitude: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_result_default() {
        let r = GeoResult::default();
        assert!(r.country.is_empty());
        assert!(r.region.is_empty());
        assert!(r.city.is_empty());
        assert_eq!(r.asn, 0);
        assert!(r.org.is_empty());
        assert_eq!(r.longitude, 0.0);
        assert_eq!(r.latitude, 0.0);
    }

    #[test]
    fn geo_result_serde_roundtrip() {
        let r = GeoResult {
            country: "CN".into(),
            region: "Shanghai".into(),
            city: "Shanghai".into(),
            asn: 4134,
            org: "China Telecom".into(),
            longitude: 121.47,
            latitude: 31.23,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: GeoResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.country, "CN");
        assert_eq!(r2.asn, 4134);
        assert!((r2.longitude - 121.47).abs() < 0.001);
    }
}
