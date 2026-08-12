//! Cloudflare DNS provider implementation.

use std::net::IpAddr;

use cloudflare::endpoints::dns::dns::{
    CreateDnsRecord, CreateDnsRecordParams, DnsContent, ListDnsRecords, ListDnsRecordsParams,
    UpdateDnsRecord, UpdateDnsRecordParams,
};
use cloudflare::endpoints::zones::zone::{ListZones, ListZonesParams, Status};
use cloudflare::framework::Environment;
use cloudflare::framework::auth::Credentials;
use cloudflare::framework::client::ClientConfig;
use cloudflare::framework::client::async_api::Client;
use tracing::{debug, info, warn};

use crate::config::CloudflareDdnsConfig;
use crate::error::DdnsError;

/// Updates DNS records on Cloudflare when the public IP changes.
pub struct CloudflareUpdater {
    client: Client,
    zone_name: String,
    records: Vec<String>,
    proxied: bool,
    ttl: u32,
    zone_id: Option<String>,
}

impl std::fmt::Debug for CloudflareUpdater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareUpdater")
            .field("zone_name", &self.zone_name)
            .field("records", &self.records)
            .field("proxied", &self.proxied)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl CloudflareUpdater {
    pub fn new(config: &CloudflareDdnsConfig) -> Result<Self, DdnsError> {
        let credentials = Credentials::UserAuthToken {
            token: config.api_token.clone(),
        };
        let environment = match config.api_base_url {
            Some(ref url) => Environment::Custom(url.clone()),
            None => Environment::Production,
        };
        let client = Client::new(credentials, ClientConfig::default(), environment)
            .map_err(|e| DdnsError::Config(format!("failed to create Cloudflare client: {e}")))?;

        Ok(Self {
            client,
            zone_name: config.zone.clone(),
            records: config.records.clone(),
            proxied: config.proxied,
            ttl: config.ttl,
            zone_id: None,
        })
    }

    /// The configured zone's Cloudflare id, looked up once and then kept.
    async fn zone_id(&mut self) -> Result<&str, DdnsError> {
        let id = match self.zone_id.take() {
            Some(cached) => cached,
            None => self.fetch_zone_id().await?,
        };
        Ok(self.zone_id.insert(id).as_str())
    }

    /// Ask Cloudflare for the id of the zone this updater was configured with.
    async fn fetch_zone_id(&self) -> Result<String, DdnsError> {
        let zones = self
            .client
            .request(&ListZones {
                params: ListZonesParams {
                    name: Some(self.zone_name.clone()),
                    status: Some(Status::Active),
                    ..Default::default()
                },
            })
            .await
            .map_err(|e| DdnsError::Cloudflare(format!("list zones: {e}")))?;

        let zone = zones
            .result
            .into_iter()
            .find(|z| z.name == self.zone_name)
            .ok_or_else(|| DdnsError::ZoneNotFound(self.zone_name.clone()))?;

        info!(zone_id = %zone.id, zone = %self.zone_name, "resolved Cloudflare zone");
        Ok(zone.id)
    }

    /// Point every configured record at `ip`.
    ///
    /// One record failing does not stop the others: they are separate names
    /// that happen to share a config, and leaving the rest stale would make a
    /// single bad record cost the whole zone. The error reports how many.
    pub async fn update(&mut self, ip: IpAddr) -> Result<(), DdnsError> {
        let content = dns_content(ip);
        let kind = record_type(&content);
        let zone_id = self.zone_id().await?.to_owned();

        let mut failed = 0usize;
        for name in &self.records {
            if let Err(e) = self.upsert_record(&zone_id, name, content.clone()).await {
                warn!(name = %name, kind, error = %e, "failed to update DNS record");
                failed += 1;
            }
        }

        if failed > 0 {
            return Err(DdnsError::Cloudflare(format!(
                "{failed} of {} {kind} records failed to update",
                self.records.len()
            )));
        }
        Ok(())
    }

    /// Create or update a single DNS record.
    async fn upsert_record(
        &self,
        zone_id: &str,
        record_name: &str,
        content: DnsContent,
    ) -> Result<(), DdnsError> {
        // List existing records for this name
        let existing = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: zone_id,
                params: ListDnsRecordsParams {
                    name: Some(record_name.to_string()),
                    ..Default::default()
                },
            })
            .await
            .map_err(|e| DdnsError::Cloudflare(format!("list records for '{record_name}': {e}")))?;

        // Find existing record of matching type (A or AAAA)
        let matching = existing.result.iter().find(|r| {
            matches!(
                (&r.content, &content),
                (DnsContent::A { .. }, DnsContent::A { .. })
                    | (DnsContent::AAAA { .. }, DnsContent::AAAA { .. })
            )
        });

        if let Some(record) = matching {
            // Skip if content already matches
            if content_matches(&record.content, &content) {
                debug!(name = record_name, "DNS record already up to date");
                return Ok(());
            }

            self.client
                .request(&UpdateDnsRecord {
                    zone_identifier: zone_id,
                    identifier: &record.id,
                    params: UpdateDnsRecordParams {
                        name: record_name,
                        content,
                        ttl: Some(self.ttl),
                        proxied: Some(self.proxied),
                    },
                })
                .await
                .map_err(|e| {
                    DdnsError::Cloudflare(format!("update record '{record_name}': {e}"))
                })?;

            info!(name = record_name, "DNS record updated");
        } else {
            self.client
                .request(&CreateDnsRecord {
                    zone_identifier: zone_id,
                    params: CreateDnsRecordParams {
                        name: record_name,
                        content,
                        ttl: Some(self.ttl),
                        proxied: Some(self.proxied),
                        priority: None,
                    },
                })
                .await
                .map_err(|e| {
                    DdnsError::Cloudflare(format!("create record '{record_name}': {e}"))
                })?;

            info!(name = record_name, "DNS record created");
        }

        Ok(())
    }
}

/// Compare two `DnsContent` values for IP equality.
fn content_matches(a: &DnsContent, b: &DnsContent) -> bool {
    match (a, b) {
        (DnsContent::A { content: a }, DnsContent::A { content: b }) => a == b,
        (DnsContent::AAAA { content: a }, DnsContent::AAAA { content: b }) => a == b,
        _ => false,
    }
}

/// The record content that points at `ip`.
///
/// A free function rather than a `From` impl: `DnsContent` belongs to the
/// `cloudflare` crate, so the orphan rule puts that out of reach.
fn dns_content(ip: IpAddr) -> DnsContent {
    match ip {
        IpAddr::V4(content) => DnsContent::A { content },
        IpAddr::V6(content) => DnsContent::AAAA { content },
    }
}

/// The record type `content` belongs to, for logs and error messages.
fn record_type(content: &DnsContent) -> &'static str {
    match content {
        DnsContent::A { .. } => "A",
        DnsContent::AAAA { .. } => "AAAA",
        // Only ever built from an `IpAddr`, so nothing else reaches here.
        _ => "unknown",
    }
}
