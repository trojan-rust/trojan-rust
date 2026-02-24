//! Cloudflare DNS provider implementation.

use std::net::{Ipv4Addr, Ipv6Addr};

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

use crate::error::DdnsError;
use trojan_config::CloudflareDdnsConfig;

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
        let client = Client::new(
            credentials,
            ClientConfig::default(),
            Environment::Production,
        )
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

    /// Resolve and cache the Cloudflare zone ID for the configured zone name.
    async fn ensure_zone_id(&mut self) -> Result<&str, DdnsError> {
        if self.zone_id.is_none() {
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
            self.zone_id = Some(zone.id);
        }
        Ok(self.zone_id.as_deref().unwrap())
    }

    /// Update A records for all configured record names.
    pub async fn update_ipv4(&mut self, ip: Ipv4Addr) -> Result<(), DdnsError> {
        let zone_id = self.ensure_zone_id().await?.to_string();
        let content = DnsContent::A { content: ip };
        let mut any_failed = false;

        for record_name in self.records.clone() {
            if let Err(e) = self
                .upsert_record(&zone_id, &record_name, content.clone())
                .await
            {
                warn!(name = %record_name, error = %e, "failed to update A record");
                any_failed = true;
            }
        }

        if any_failed {
            Err(DdnsError::Cloudflare(
                "some A records failed to update".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Update AAAA records for all configured record names.
    pub async fn update_ipv6(&mut self, ip: Ipv6Addr) -> Result<(), DdnsError> {
        let zone_id = self.ensure_zone_id().await?.to_string();
        let content = DnsContent::AAAA { content: ip };
        let mut any_failed = false;

        for record_name in self.records.clone() {
            if let Err(e) = self
                .upsert_record(&zone_id, &record_name, content.clone())
                .await
            {
                warn!(name = %record_name, error = %e, "failed to update AAAA record");
                any_failed = true;
            }
        }

        if any_failed {
            Err(DdnsError::Cloudflare(
                "some AAAA records failed to update".into(),
            ))
        } else {
            Ok(())
        }
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
