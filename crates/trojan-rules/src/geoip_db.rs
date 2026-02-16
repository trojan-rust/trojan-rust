//! GeoIP database management: loading, caching, and auto-updating.
//!
//! Provides `GeoipDb` which wraps a MaxMind DB reader and supports
//! country-level and city-level lookups, built-in CDN source registry,
//! cache-aware loading, and background auto-update.

#[cfg(feature = "geoip")]
mod inner {
    use std::net::IpAddr;
    use std::path::Path;

    use maxminddb::Reader;
    use trojan_config::{GeoResult, GeoipConfig};

    use crate::error::RulesError;

    /// Built-in source name → CDN URL mapping.
    ///
    /// All sources come from [ip-location-db](https://github.com/sapics/ip-location-db)
    /// distributed via jsDelivr CDN.
    pub fn source_to_url(source: &str) -> Option<String> {
        let (pkg, file) = match source {
            // Country-level
            "geolite2-country" => ("geolite2-country-mmdb", "geolite2-country"),
            "dbip-country" => ("dbip-country-mmdb", "dbip-country"),
            "geo-whois-asn-country" => ("geo-whois-asn-country-mmdb", "geo-whois-asn-country"),
            "asn-country" => ("asn-country-mmdb", "asn-country"),
            "iptoasn-country" => ("iptoasn-country-mmdb", "iptoasn-country"),
            // City-level
            "geolite2-city" => ("geolite2-city-mmdb", "geolite2-city"),
            "dbip-city" => ("dbip-city-mmdb", "dbip-city"),
            // ASN-level
            "geolite2-asn" => ("geolite2-asn-mmdb", "geolite2-asn"),
            "dbip-asn" => ("dbip-asn-mmdb", "dbip-asn"),
            "iptoasn-asn" => ("iptoasn-asn-mmdb", "iptoasn-asn"),
            _ => return None,
        };
        Some(format!(
            "https://cdn.jsdelivr.net/npm/@ip-location-db/{pkg}/{file}.mmdb"
        ))
    }

    /// High-level GeoIP database wrapper with country, city, and ASN lookups.
    pub struct GeoipDb {
        reader: Reader<Vec<u8>>,
    }

    impl GeoipDb {
        /// Load from a local `.mmdb` file.
        pub fn from_file(path: &Path) -> Result<Self, RulesError> {
            let reader = Reader::open_readfile(path).map_err(|e| {
                RulesError::GeoIp(format!(
                    "failed to open GeoIP database {}: {e}",
                    path.display()
                ))
            })?;
            Ok(Self { reader })
        }

        /// Load from raw bytes.
        pub fn from_bytes(data: Vec<u8>) -> Result<Self, RulesError> {
            let reader = Reader::from_source(data)
                .map_err(|e| RulesError::GeoIp(format!("failed to parse GeoIP database: {e}")))?;
            Ok(Self { reader })
        }

        /// Look up the ISO country code for an IP address.
        ///
        /// Tries Country record first, then falls back to City record
        /// (city-level DBs like geolite2-city use City records, not Country).
        pub fn country_code(&self, ip: IpAddr) -> Option<String> {
            // Try Country record first (works for country-only DBs)
            if let Ok(country) = self.reader.lookup::<maxminddb::geoip2::Country>(ip)
                && let Some(code) = country.country.and_then(|c| c.iso_code)
            {
                return Some(code.to_uppercase());
            }
            // Fall back to City record (for city-level DBs)
            if let Ok(city) = self.reader.lookup::<maxminddb::geoip2::City>(ip)
                && let Some(code) = city.country.and_then(|c| c.iso_code)
            {
                return Some(code.to_uppercase());
            }
            None
        }

        /// Check if an IP address matches a given country code.
        pub fn matches_country(&self, ip: IpAddr, code: &str) -> bool {
            self.country_code(ip)
                .is_some_and(|c| c.eq_ignore_ascii_case(code))
        }

        /// Full city-level lookup returning all available geo fields.
        pub fn lookup_city(&self, ip: IpAddr) -> GeoResult {
            let mut result = GeoResult::default();

            // Try city-level lookup first
            if let Ok(city) = self.reader.lookup::<maxminddb::geoip2::City>(ip) {
                if let Some(country) = city.country.and_then(|c| c.iso_code) {
                    result.country = country.to_uppercase();
                }
                if let Some(subdivisions) = city.subdivisions
                    && let Some(sub) = subdivisions.first()
                    && let Some(names) = &sub.names
                    && let Some(name) = names.get("en")
                {
                    result.region = (*name).to_string();
                }
                if let Some(city_record) = city.city
                    && let Some(names) = city_record.names
                    && let Some(name) = names.get("en")
                {
                    result.city = (*name).to_string();
                }
                if let Some(location) = city.location {
                    result.longitude = location.longitude.unwrap_or(0.0);
                    result.latitude = location.latitude.unwrap_or(0.0);
                }
            } else if let Ok(country) = self.reader.lookup::<maxminddb::geoip2::Country>(ip) {
                // Fall back to country-only lookup
                if let Some(c) = country.country.and_then(|c| c.iso_code) {
                    result.country = c.to_uppercase();
                }
            }

            // Try ASN lookup (separate record type in MaxMind DB)
            if let Ok(asn) = self.reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                result.asn = asn.autonomous_system_number.unwrap_or(0);
                result.org = asn.autonomous_system_organization.unwrap_or("").to_string();
            }

            result
        }

        /// Country-only lookup (cheaper — only fills the country field).
        pub fn lookup_country(&self, ip: IpAddr) -> GeoResult {
            let mut result = GeoResult::default();
            if let Some(code) = self.country_code(ip) {
                result.country = code;
            }
            result
        }

        /// Load a GeoIP database from config (file-only, no network).
        ///
        /// Tries `path` first, then `cache_path`.
        pub fn load_from_file(config: &GeoipConfig) -> Result<Self, RulesError> {
            if let Some(ref path) = config.path {
                return Self::from_file(Path::new(path));
            }
            if let Some(ref cache_path) = config.cache_path {
                let p = Path::new(cache_path);
                if p.exists() {
                    return Self::from_file(p);
                }
            }
            Err(RulesError::GeoIp(format!(
                "no local GeoIP database available for source '{}'; \
                 set 'path' or enable HTTP feature for auto-download",
                config.source
            )))
        }
    }

    impl std::fmt::Debug for GeoipDb {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GeoipDb").finish_non_exhaustive()
        }
    }

    // GeoipDb is Send + Sync because maxminddb::Reader<Vec<u8>> is Send + Sync.

    /// Resolve the download URL for a GeoIP config.
    ///
    /// Priority: `url` > `source_to_url(source)`.
    pub fn resolve_download_url(config: &GeoipConfig) -> Option<String> {
        if let Some(ref url) = config.url {
            return Some(url.clone());
        }
        source_to_url(&config.source)
    }

    /// Load a GeoIP database from config with network support.
    ///
    /// Priority: path > cache (if fresh) > download > stale cache.
    #[cfg(feature = "http")]
    pub async fn load_geoip(config: &GeoipConfig) -> Result<GeoipDb, RulesError> {
        // 1. Local file path has highest priority
        if let Some(ref path) = config.path {
            tracing::info!(path = %path, "loading GeoIP database from local file");
            return GeoipDb::from_file(Path::new(path));
        }

        // 2. Check cache freshness
        if let Some(ref cache_path) = config.cache_path {
            let p = Path::new(cache_path);
            if p.exists()
                && let Ok(metadata) = tokio::fs::metadata(p).await
                && let Ok(modified) = metadata.modified()
            {
                let age = modified.elapsed().unwrap_or_default();
                if age.as_secs() < config.interval {
                    tracing::info!(
                        cache = %cache_path,
                        age_secs = age.as_secs(),
                        "loading GeoIP database from fresh cache"
                    );
                    return GeoipDb::from_file(p);
                }
                tracing::info!(
                    cache = %cache_path,
                    age_secs = age.as_secs(),
                    interval = config.interval,
                    "GeoIP cache expired, attempting download"
                );
            }
        }

        // 3. Download
        let url = resolve_download_url(config).ok_or_else(|| {
            RulesError::GeoIp(format!(
                "unknown GeoIP source '{}' and no url configured",
                config.source
            ))
        })?;

        match download_mmdb(&url).await {
            Ok(data) => {
                // Write to cache atomically
                if let Some(ref cache_path) = config.cache_path
                    && let Err(e) = write_cache(Path::new(cache_path), &data).await
                {
                    tracing::warn!(cache = %cache_path, error = %e, "failed to write GeoIP cache");
                }
                tracing::info!(url = %url, bytes = data.len(), "downloaded GeoIP database");
                GeoipDb::from_bytes(data)
            }
            Err(e) => {
                // 4. Fall back to stale cache
                if let Some(ref cache_path) = config.cache_path {
                    let p = Path::new(cache_path);
                    if p.exists() {
                        tracing::warn!(
                            url = %url,
                            error = %e,
                            cache = %cache_path,
                            "download failed, using stale GeoIP cache"
                        );
                        return GeoipDb::from_file(p);
                    }
                }
                Err(RulesError::GeoIp(format!(
                    "failed to download GeoIP database from {url}: {e}"
                )))
            }
        }
    }

    /// Download an mmdb file from a URL.
    #[cfg(feature = "http")]
    async fn download_mmdb(url: &str) -> Result<Vec<u8>, RulesError> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| RulesError::Http(format!("GET {url}: {e}")))?;

        if !response.status().is_success() {
            return Err(RulesError::Http(format!(
                "GET {url}: HTTP {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| RulesError::Http(format!("reading response from {url}: {e}")))?;

        Ok(bytes.to_vec())
    }

    /// Write cache file atomically (write to .tmp, then rename).
    #[cfg(feature = "http")]
    async fn write_cache(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp_path = path.with_extension("mmdb.tmp");
        tokio::fs::write(&tmp_path, data).await?;
        #[cfg(target_os = "windows")]
        {
            let _ = tokio::fs::remove_file(path).await;
        }
        tokio::fs::rename(&tmp_path, path).await
    }

    /// Background auto-update task for GeoIP databases.
    ///
    /// Periodically re-downloads the database and swaps the `Arc` via `ArcSwap`.
    /// Stops when the `CancellationToken` is cancelled.
    ///
    /// Callers should wrap this with metrics recording (e.g., rule_update / rule_update_error)
    /// at the trojan-server level.
    #[cfg(feature = "http")]
    pub async fn geoip_auto_update_task(
        config: GeoipConfig,
        db: std::sync::Arc<arc_swap::ArcSwap<GeoipDb>>,
        cancel: tokio_util::sync::CancellationToken,
        on_update: impl Fn(bool) + Send + 'static,
    ) {
        use std::time::Duration;

        let interval = Duration::from_secs(config.interval.max(60)); // minimum 60s
        tracing::info!(
            source = %config.source,
            interval_secs = interval.as_secs(),
            "starting GeoIP auto-update task"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.cancelled() => {
                    tracing::debug!("GeoIP auto-update task cancelled");
                    return;
                }
            }

            let url = match resolve_download_url(&config) {
                Some(u) => u,
                None => {
                    tracing::warn!(source = %config.source, "no download URL for GeoIP auto-update");
                    continue;
                }
            };

            match download_mmdb(&url).await {
                Ok(data) => {
                    // Write cache
                    if let Some(ref cache_path) = config.cache_path
                        && let Err(e) = write_cache(Path::new(cache_path), &data).await
                    {
                        tracing::warn!(cache = %cache_path, error = %e, "failed to write GeoIP cache during update");
                    }

                    match GeoipDb::from_bytes(data) {
                        Ok(new_db) => {
                            db.store(std::sync::Arc::new(new_db));
                            tracing::info!(source = %config.source, "GeoIP database updated");
                            on_update(true);
                        }
                        Err(e) => {
                            tracing::warn!(source = %config.source, error = %e, "failed to parse downloaded GeoIP database");
                            on_update(false);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(source = %config.source, url = %url, error = %e, "GeoIP auto-update download failed");
                    on_update(false);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn source_to_url_known_sources() {
            assert!(
                source_to_url("geolite2-country")
                    .unwrap()
                    .contains("geolite2-country-mmdb")
            );
            assert!(
                source_to_url("dbip-city")
                    .unwrap()
                    .contains("dbip-city-mmdb")
            );
            assert!(
                source_to_url("geolite2-asn")
                    .unwrap()
                    .contains("geolite2-asn-mmdb")
            );
            assert!(
                source_to_url("iptoasn-country")
                    .unwrap()
                    .contains("iptoasn-country-mmdb")
            );
        }

        #[test]
        fn source_to_url_unknown() {
            assert!(source_to_url("nonexistent").is_none());
        }

        #[test]
        fn source_to_url_format() {
            let url = source_to_url("geolite2-country").unwrap();
            assert!(url.starts_with("https://cdn.jsdelivr.net/npm/@ip-location-db/"));
            assert!(url.ends_with(".mmdb"));
        }

        #[test]
        fn resolve_download_url_custom_url() {
            let config = GeoipConfig {
                source: "geolite2-country".to_string(),
                url: Some("https://example.com/custom.mmdb".to_string()),
                ..Default::default()
            };
            assert_eq!(
                resolve_download_url(&config).unwrap(),
                "https://example.com/custom.mmdb"
            );
        }

        #[test]
        fn resolve_download_url_source_fallback() {
            let config = GeoipConfig {
                source: "dbip-country".to_string(),
                url: None,
                ..Default::default()
            };
            let url = resolve_download_url(&config).unwrap();
            assert!(url.contains("dbip-country-mmdb"));
        }

        #[test]
        fn resolve_download_url_unknown_source_no_url() {
            let config = GeoipConfig {
                source: "unknown".to_string(),
                url: None,
                ..Default::default()
            };
            assert!(resolve_download_url(&config).is_none());
        }

        #[test]
        fn geoip_db_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<GeoipDb>();
        }

        #[test]
        fn load_from_file_missing() {
            let config = GeoipConfig {
                source: "geolite2-country".to_string(),
                path: None,
                cache_path: None,
                ..Default::default()
            };
            GeoipDb::load_from_file(&config).unwrap_err();
        }
    }
}

#[cfg(feature = "geoip")]
pub use inner::*;
