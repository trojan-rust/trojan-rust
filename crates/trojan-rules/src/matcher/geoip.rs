//! GeoIP matcher using MaxMind DB.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::Reader;

use crate::error::RulesError;

/// GeoIP matcher backed by a MaxMind DB file.
///
/// Wraps `maxminddb::Reader` and provides country-code lookup for IP addresses.
pub struct GeoipMatcher {
    reader: Reader<Vec<u8>>,
}

impl GeoipMatcher {
    /// Load a GeoIP database from a file path.
    pub fn from_file(path: &Path) -> Result<Self, RulesError> {
        let reader = Reader::open_readfile(path).map_err(|e| {
            RulesError::GeoIp(format!(
                "failed to open GeoIP database {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self { reader })
    }

    /// Load a GeoIP database from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, RulesError> {
        let reader = Reader::from_source(data)
            .map_err(|e| RulesError::GeoIp(format!("failed to parse GeoIP database: {e}")))?;
        Ok(Self { reader })
    }

    /// Look up the ISO country code for an IP address.
    ///
    /// Returns `None` if the IP is not found in the database or the record
    /// has no country ISO code.
    ///
    /// Tries Country record first, then falls back to City record
    /// (city-level DBs like geolite2-city use City records, not Country).
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        // Try Country record first (works for country-only DBs)
        if let Ok(result) = self.reader.lookup(ip)
            && let Ok(Some(country)) = result.decode::<maxminddb::geoip2::Country>()
            && let Some(code) = country.country.iso_code
        {
            return Some(code.to_uppercase());
        }
        // Fall back to City record (for city-level DBs)
        if let Ok(result) = self.reader.lookup(ip)
            && let Ok(Some(city)) = result.decode::<maxminddb::geoip2::City>()
            && let Some(code) = city.country.iso_code
        {
            return Some(code.to_uppercase());
        }
        None
    }

    /// Check if an IP address matches a given country code.
    pub fn matches(&self, ip: IpAddr, code: &str) -> bool {
        self.country_code(ip)
            .is_some_and(|c| c.eq_ignore_ascii_case(code))
    }
}

impl std::fmt::Debug for GeoipMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoipMatcher").finish_non_exhaustive()
    }
}

// GeoipMatcher is Send + Sync because maxminddb::Reader<Vec<u8>> is Send + Sync.
// The Reader uses memory-mapped data internally and is safe for concurrent access.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geoip_matcher_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GeoipMatcher>();
    }
}
