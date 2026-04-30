//! Certificate Transparency lookup helpers.

use std::collections::BTreeSet;
use std::process::Command;

use anyhow::{Context, Result};
use chrono::Utc;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::SimpleQueryMessage;
use tracing::{debug, info, warn};

use crate::backend::{CtSubdomainCacheEntry, Storage};

const CRTSH_POSTGRES_CONN_STR: &str =
    "host=crt.sh port=5432 dbname=certwatch user=guest sslmode=require";

#[derive(Copy, Clone)]
pub(super) enum CtResponseFormat {
    CrtSh,
    CertSpotter,
    GoogleTransparency,
}

pub(super) struct CtSource {
    pub(super) name: &'static str,
    pub(super) url: String,
    pub(super) format: CtResponseFormat,
}

pub(super) struct CtFetchResponse {
    pub(super) status_code: String,
    pub(super) body: String,
}

pub(super) async fn query_ct_names(
    domain: &str,
    storage: Option<&Storage>,
    ct_cache_ttl_seconds: u64,
) -> Result<Vec<String>> {
    if ct_cache_ttl_seconds > 0 {
        if let Some(storage) = storage {
            if let Some(cache) = storage.load_ct_subdomain_cache(domain).await? {
                if ct_cache_is_fresh(&cache, ct_cache_ttl_seconds) {
                    info!(
                        domain = %domain,
                        source = cache.source,
                        count = cache.subdomains.len(),
                        cached_at = %cache.updated_at,
                        "using cached certificate transparency hosts"
                    );
                    return Ok(cache.subdomains);
                }
            }
        }
    }

    match query_ct_postgres(domain).await {
        Ok(Some(hosts)) => {
            info!(
                domain = %domain,
                source = "crt.sh-postgres",
                count = hosts.len(),
                "discovered subdomains from crt.sh postgres database"
            );
            if ct_cache_ttl_seconds > 0 {
                if let Some(storage) = storage {
                    storage
                        .upsert_ct_subdomain_cache(domain, "crt.sh-postgres", &hosts)
                        .await?;
                }
            }
            return Ok(hosts);
        }
        Ok(None) => {
            warn!(domain = %domain, "crt.sh postgres database returned no hosts");
        }
        Err(err) => {
            warn!(domain = %domain, error = ?err, "crt.sh postgres database query failed");
        }
    }

    let sources = [
        CtSource {
            name: "crt.sh",
            url: format!("https://crt.sh/?q={}&output=json", domain),
            format: CtResponseFormat::CrtSh,
        },
        CtSource {
            name: "certspotter",
            url: format!(
                "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
                domain
            ),
            format: CtResponseFormat::CertSpotter,
        },
        CtSource {
            name: "google transparency report",
            url: format!(
                "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain={}&include_expired=true&include_subdomains=true",
                domain
            ),
            format: CtResponseFormat::GoogleTransparency,
        },
    ];

    for source in sources {
        match fetch_ct_source_async(source.name, &source.url).await {
            Ok(Some(response)) => {
                if !response.status_code.starts_with('2') {
                    warn!(
                        domain = %domain,
                        source = source.name,
                        status = %response.status_code,
                        "CT source returned non-2xx response"
                    );
                    continue;
                }

                let raw = response.body;
                if raw.trim().is_empty() {
                    warn!(domain = %domain, source = source.name, "CT source returned empty body");
                    continue;
                }

                let hosts = parse_ct_response(&raw, domain, source.format);
                if !hosts.is_empty() {
                    info!(
                        domain = %domain,
                        source = source.name,
                        count = hosts.len(),
                        "discovered subdomains from certificate transparency"
                    );
                    if ct_cache_ttl_seconds > 0 {
                        if let Some(storage) = storage {
                            storage
                                .upsert_ct_subdomain_cache(domain, source.name, &hosts)
                                .await?;
                        }
                    }
                    return Ok(hosts);
                }

                warn!(
                    domain = %domain,
                    source = source.name,
                    "CT source returned no matching hosts"
                );
            }
            Ok(None) => {
                warn!(
                    domain = %domain,
                    source = source.name,
                    "CT source returned no usable response"
                );
            }
            Err(err) => {
                warn!(domain = %domain, source = source.name, error = %err, "CT source query failed");
            }
        }
    }

    if ct_cache_ttl_seconds > 0 {
        if let Some(storage) = storage {
            if let Some(cache) = storage.load_ct_subdomain_cache(domain).await? {
                if !cache.subdomains.is_empty() {
                    warn!(
                        domain = %domain,
                        source = cache.source,
                        count = cache.subdomains.len(),
                        cached_at = %cache.updated_at,
                        "using stale certificate transparency cache after source failure"
                    );
                    return Ok(cache.subdomains);
                }
            }
        }
    }

    warn!(domain = %domain, "all CT sources failed or returned no hosts, trying DNS-based discovery");
    Ok(super::dns::query_dns_wildcard(domain))
}

async fn fetch_ct_source_async(source_name: &str, url: &str) -> Result<Option<CtFetchResponse>> {
    let source_name = source_name.to_string();
    let url = url.to_string();
    tokio::task::spawn_blocking(move || fetch_ct_source(&source_name, &url))
        .await
        .context("ct source fetch task failed")?
}

async fn query_ct_postgres(domain: &str) -> Result<Option<Vec<String>>> {
    let connector = TlsConnector::builder()
        .build()
        .with_context(|| "failed to build TLS connector for crt.sh postgres")?;
    let connector = MakeTlsConnector::new(connector);

    let (client, connection) = tokio_postgres::connect(CRTSH_POSTGRES_CONN_STR, connector)
        .await
        .with_context(|| "failed to connect to crt.sh postgres database")?;

    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!(error = %err, "crt.sh postgres connection dropped");
        }
    });

    let escaped_domain = escape_sql_literal(domain);
    let query = format!(
        "SELECT DISTINCT cai.NAME_VALUE
         FROM certificate_and_identities cai
         WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(cai.CERTIFICATE)
           AND reverse(lower(cai.NAME_VALUE)) LIKE reverse(lower('%.{domain}'))
         ORDER BY cai.NAME_VALUE",
        domain = escaped_domain
    );

    let rows = client
        .simple_query(&query)
        .await
        .with_context(|| format!("failed to query crt.sh postgres database for {domain}"))?;

    let hosts: Vec<String> = rows
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => row.get(0).map(ToOwned::to_owned),
            _ => None,
        })
        .map(|value| super::canonical_host(value.trim_start_matches("*.").trim()))
        .filter(|value| !value.is_empty() && value.ends_with(domain))
        .collect();

    Ok(if hosts.is_empty() {
        None
    } else {
        Some(super::dedupe_strings(hosts))
    })
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

pub(super) fn ct_cache_is_fresh(cache: &CtSubdomainCacheEntry, ttl_seconds: u64) -> bool {
    let ttl_seconds = ttl_seconds.min(i64::MAX as u64) as i64;
    let age_seconds = Utc::now()
        .signed_duration_since(cache.updated_at)
        .num_seconds();
    age_seconds >= 0 && age_seconds <= ttl_seconds
}

fn fetch_ct_source(source_name: &str, url: &str) -> Result<Option<CtFetchResponse>> {
    let output = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg("20")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--location")
        .arg("--retry")
        .arg("2")
        .arg("--retry-delay")
        .arg("2")
        .arg("--user-agent")
        .arg("artisan-dap/0.1")
        .arg("--write-out")
        .arg("\n__HTTP_STATUS__:%{http_code}")
        .arg(url)
        .output()
        .with_context(|| format!("failed to query {source_name}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status_code) = split_body_and_status(&stdout);

    if !output.status.success() {
        debug!(source = source_name, status = %status_code, "CT source curl execution failed");
        return Ok(None);
    }

    Ok(Some(CtFetchResponse {
        status_code: status_code.to_string(),
        body: body.to_string(),
    }))
}

fn split_body_and_status(raw: &str) -> (&str, &str) {
    for line in raw.lines().rev() {
        if let Some(status) = line.strip_prefix("__HTTP_STATUS__:") {
            let body_len = raw.len().saturating_sub(line.len() + 1);
            let body = raw.get(..body_len).unwrap_or(raw).trim_end_matches('\n');
            return (body, status.trim());
        }
    }

    (raw, "000")
}

fn parse_ct_response(raw: &str, domain: &str, format: CtResponseFormat) -> Vec<String> {
    let mut hosts = BTreeSet::new();

    match format {
        CtResponseFormat::CrtSh => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
                if let Some(items) = value.as_array() {
                    for item in items {
                        if let Some(name_value) = item.get("name_value").and_then(|v| v.as_str()) {
                            for line in name_value.lines() {
                                let candidate =
                                    super::canonical_host(line.trim_start_matches("*."));
                                if !candidate.is_empty() && candidate.ends_with(domain) {
                                    hosts.insert(candidate);
                                }
                            }
                        }
                    }
                }
            }
        }
        CtResponseFormat::CertSpotter => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
                if let Some(items) = value.as_array() {
                    for item in items {
                        if let Some(dns_names) = item.get("dns_names").and_then(|v| v.as_array()) {
                            for dns_name in dns_names {
                                if let Some(name) = dns_name.as_str() {
                                    let candidate =
                                        super::canonical_host(name.trim_start_matches("*."));
                                    if !candidate.is_empty() && candidate.ends_with(domain) {
                                        hosts.insert(candidate);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        CtResponseFormat::GoogleTransparency => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
                for candidate in collect_json_strings(&value) {
                    let candidate = super::canonical_host(candidate.trim_start_matches("*."));
                    if !candidate.is_empty() && candidate.ends_with(domain) {
                        hosts.insert(candidate);
                    }
                }
            }
        }
    }

    hosts.into_iter().collect()
}

fn collect_json_strings(value: &serde_json::Value) -> Vec<String> {
    let mut values = Vec::new();
    match value {
        serde_json::Value::String(text) => values.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                values.extend(collect_json_strings(item));
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                values.extend(collect_json_strings(item));
            }
        }
        _ => {}
    }
    values
}
