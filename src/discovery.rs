//! Discovery scaffolding backed by native DNS lookups.
//!
//! This prototype shells out to `dig(1)` so we stay aligned with the ops
//! tooling already in use. When network resolution fails (e.g., in restricted
//! environments) we fall back to a local zone dump if one is available
//! (`<domain>.txt`).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    process::Command,
};

use anyhow::{Context, Result};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    config::{RunConfig, ScopeMode},
    facts::Fact,
};

/// Hard cap on recursive passive expansion so one sweep cannot run forever.
const MAX_DISCOVERY_DEPTH: usize = 2;

/// Strong WordPress fingerprints.
const WORDPRESS_MARKERS: &[&str] = &[
    "wp-content/",
    "wp-includes/",
    "wp-json",
    "xmlrpc.php",
    "wp-login.php",
    "meta name=\"generator\" content=\"wordpress",
];

/// Strong Ghost fingerprints.
const GHOST_MARKERS: &[&str] = &[
    "data-ghost",
    "/ghost/api/",
    "meta name=\"generator\" content=\"ghost",
    "ghost-content/",
    "ghost.org",
];

/// Website-builder and hosted platform fingerprints from returned resources.
const WIX_MARKERS: &[&str] = &[
    "static.wixstatic.com",
    "wixstatic.com",
    "wixsite.com",
    "wix-image://",
    "meta property=\"og:site_name\" content=\"wix",
];

const WEEBLY_MARKERS: &[&str] = &[
    "cdn2.editmysite.com",
    "editmysite.com",
    "weebly.com",
    "weeblysite.com",
];

const SQUARESPACE_MARKERS: &[&str] = &[
    "static1.squarespace.com",
    "images.squarespace-cdn.com",
    "sqspcdn.com",
    "data-squarespace-siteid",
    "meta name=\"generator\" content=\"squarespace",
    "squarespace.com",
];

const SQUARE_MARKERS: &[&str] = &[
    "square.site",
    "squareup.com",
    "cdn.square.site",
    "images.squareup-cdn.com",
];

const SHOPIFY_MARKERS: &[&str] = &[
    "cdn.shopify.com",
    "myshopify.com",
    "shopifycdn.net",
    "x-shopify",
    "shopify theme",
];

/// Common frontend/framework fingerprints that still count as basic sites.
const REACT_MARKERS: &[&str] = &[
    "data-reactroot",
    "react-refresh",
    "__react",
    "react/jsx-runtime",
    "__webpack_hmr",
];

const VITE_MARKERS: &[&str] = &[
    "@vite/client",
    "import.meta.hot",
    "data-vite-dev-id",
    "vite-preload-helper",
];

const ANGULAR_MARKERS: &[&str] = &["ng-version", "ng-app", "angular.js", "ng-server-context"];

const NEXTJS_MARKERS: &[&str] = &["__next_data__", "/_next/", "next.js"];

const VUE_MARKERS: &[&str] = &["__vue__", "vue-app", "data-v-"];

const SVELTEKIT_MARKERS: &[&str] = &["__sveltekit", "sveltekit"];

/// Common DKIM selectors worth checking passively.
const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "s1",
    "s2",
];

/// Result of the discovery process.
#[derive(Debug, Clone)]
pub struct DiscoveryOutcome {
    pub facts: Vec<Fact>,
    pub dead_hosts: Vec<DeadHost>,
    pub site_profiles: Vec<SiteProfile>,
}

/// Host that failed the liveness probes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeadHost {
    pub host: String,
    pub reason: String,
}

/// Lightweight summary of what a host appears to be.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteProfile {
    pub host: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub confidence: f64,
    pub signals: Vec<String>,
}

/// Execute the discovery phase and return observed facts plus unreachable hosts.
pub async fn perform_discovery(cfg: &RunConfig) -> Result<DiscoveryOutcome> {
    info!(target = %cfg.domain, "starting discovery via dig");

    let apex = cfg.domain.to_lowercase();
    let zone_dump = load_zone_dump(&apex);

    let mut facts = Vec::new();
    let mut dead_hosts = Vec::new();
    let mut site_profiles = Vec::new();

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut visited = BTreeSet::new();

    for host in collect_domain_mail_facts(&apex, &zone_dump, &mut facts, &mut site_profiles)? {
        if is_host_in_scope(&host, cfg, &apex) {
            queue.push_back((host, 0));
        }
    }

    for host in gather_seed_hosts(cfg, &zone_dump, &apex) {
        queue.push_back((host, 0));
    }

    for ct_host in query_ct_names(&apex)? {
        if is_host_in_scope(&ct_host, cfg, &apex) {
            queue.push_back((ct_host, 0));
        }
    }

    while let Some((host, depth)) = queue.pop_front() {
        if !is_host_in_scope(&host, cfg, &apex) {
            continue;
        }
        if !visited.insert(host.to_string()) {
            continue;
        }

        let host_outcome = inspect_host(&host, &apex, &zone_dump)?;
        if let Some(dead) = host_outcome.dead_host {
            dead_hosts.push(dead);
        }

        facts.extend(host_outcome.facts);
        if let Some(profile) = host_outcome.site_profile {
            site_profiles.push(profile);
        }

        if depth < MAX_DISCOVERY_DEPTH {
            for new_host in host_outcome.new_hosts {
                if is_host_in_scope(&new_host, cfg, &apex) && !visited.contains(&new_host) {
                    queue.push_back((new_host, depth + 1));
                }
            }
        }
    }

    info!(
        total_facts = facts.len(),
        dead_hosts = dead_hosts.len(),
        "discovery phase complete"
    );
    Ok(DiscoveryOutcome {
        facts,
        dead_hosts,
        site_profiles,
    })
}

fn gather_seed_hosts(cfg: &RunConfig, zone_dump: &ZoneDump, apex: &str) -> BTreeSet<String> {
    match cfg.scope.mode {
        ScopeMode::SingleSite => {
            let mut hosts = BTreeSet::new();
            let single = cfg
                .scope
                .site
                .as_deref()
                .map(|site| normalize_hostname(site, apex))
                .unwrap_or_else(|| apex.to_string());
            hosts.insert(single);
            hosts
        }
        ScopeMode::DomainSweep => {
            let mut hosts: BTreeSet<String> = zone_dump.hosts().clone();
            hosts.insert(apex.to_string());

            for include in &cfg.include {
                if let Some(root) = include.strip_prefix("*.") {
                    hosts.insert(canonical_host(root));
                } else {
                    hosts.insert(normalize_hostname(include, apex));
                }
            }

            hosts
        }
    }
}

fn is_host_in_scope(host: &str, cfg: &RunConfig, apex: &str) -> bool {
    if cfg
        .exclude
        .iter()
        .any(|pattern| matches_pattern(pattern, host))
    {
        return false;
    }

    if cfg.include.is_empty() {
        return host == apex || host.ends_with(&format!(".{}", apex));
    }

    cfg.include
        .iter()
        .any(|pattern| matches_pattern(pattern, host))
}

fn matches_pattern(pattern: &str, candidate: &str) -> bool {
    let pattern = canonical_host(pattern);
    let candidate = canonical_host(candidate);
    if pattern == candidate {
        return true;
    }

    if let Some(root) = pattern.strip_prefix("*.") {
        return candidate == root || candidate.ends_with(&format!(".{}", root));
    }

    candidate == pattern || candidate.ends_with(&format!(".{}", pattern))
}

/// Result of inspecting a single hostname.
#[derive(Debug)]
struct HostInspection {
    facts: Vec<Fact>,
    new_hosts: BTreeSet<String>,
    site_profile: Option<SiteProfile>,
    dead_host: Option<DeadHost>,
}

/// Inspect a hostname, capture DNS/web facts, and extract new host candidates.
fn inspect_host(host: &str, apex: &str, zone_dump: &ZoneDump) -> Result<HostInspection> {
    let mut facts = Vec::new();
    let mut new_hosts = BTreeSet::new();

    let liveness = check_host_liveness(host);
    let mut alive = matches!(liveness, HostLiveness::Alive);
    let mut dead_host = match &liveness {
        HostLiveness::Dead(reason) => Some(DeadHost {
            host: host.to_string(),
            reason: reason.clone(),
        }),
        HostLiveness::Alive => None,
    };

    let cname_target = query_cname_record(host, zone_dump)?;
    if let Some(ref target) = cname_target {
        let cname_attrs = vec![
            ("type".to_string(), json!("CNAME")),
            ("name".to_string(), json!(host)),
            ("value".to_string(), json!(target)),
        ];

        facts.push(Fact::with_attrs(
            host,
            "dns_record",
            format!("dns:CNAME:{}", host.replace('.', "_")),
            cname_attrs,
        ));

        new_hosts.insert(canonical_host(target));
    }

    let addresses = query_address_records(host, zone_dump)?;
    if !addresses.is_empty() {
        for address in &addresses {
            let family = ip_family(address).unwrap_or("unknown");
            facts.push(Fact::with_attrs(
                host,
                "ip_address",
                format!(
                    "ip:{}:{}",
                    host.replace('.', "_"),
                    address.replace(':', "_")
                ),
                vec![
                    ("host".to_string(), json!(host)),
                    ("ip".to_string(), json!(address)),
                    ("family".to_string(), json!(family)),
                ],
            ));
        }

        let mut surface = None;
        let mut site_profile = None;
        if alive {
            let observed = fetch_surface(host)?;
            if let Some(reason) = detect_surface_failure(&observed) {
                alive = false;
                dead_host = Some(DeadHost {
                    host: host.to_string(),
                    reason,
                });
            } else {
                let mut surface_signals = Vec::new();
                if let Some(text) = observed.body.as_deref() {
                    for extracted in extract_hosts(text) {
                        if extracted != host && extracted != apex {
                            new_hosts.insert(extracted);
                        }
                    }
                    surface_signals.extend(extract_signals(text));
                }
                if let Some(ref robots) = observed.robots {
                    for extracted in extract_hosts(robots) {
                        if extracted != host && extracted != apex {
                            new_hosts.insert(extracted);
                        }
                    }
                    surface_signals.extend(extract_signals(robots));
                }
                if let Some(ref sitemap) = observed.sitemap {
                    for extracted in extract_hosts(sitemap) {
                        if extracted != host && extracted != apex {
                            new_hosts.insert(extracted);
                        }
                    }
                    surface_signals.extend(extract_signals(sitemap));
                }
                if let Some(ref wp_sitemap) = observed.wp_sitemap {
                    for extracted in extract_hosts(wp_sitemap) {
                        if extracted != host && extracted != apex {
                            new_hosts.insert(extracted);
                        }
                    }
                    surface_signals.extend(extract_signals(wp_sitemap));
                }

                site_profile = classify_site(host, &observed, surface_signals);
            }

            surface = Some(observed);
        }

        let scheme = surface
            .as_ref()
            .map(|observed| observed.scheme.as_str())
            .unwrap_or("https");
        let port = if scheme == "http" { 80 } else { 443 };
        let mut web_attrs = vec![
            ("host".to_string(), json!(host)),
            ("scheme".to_string(), json!(scheme)),
            ("port".to_string(), json!(port)),
            ("alive".to_string(), json!(alive)),
            ("addresses".to_string(), json!(addresses)),
            (
                "psi_eligible".to_string(),
                json!(
                    alive
                        && surface
                            .as_ref()
                            .map(surface_is_psi_eligible)
                            .unwrap_or(false)
                ),
            ),
        ];
        if let Some(target) = cname_target.as_ref() {
            web_attrs.push(("cname_target".to_string(), json!(target)));
        }
        if let Some(dead) = dead_host.as_ref() {
            web_attrs.push(("dead_reason".to_string(), json!(&dead.reason)));
        }
        if let Some(observed) = surface.as_ref() {
            web_attrs.push(("body_present".to_string(), json!(observed.has_body())));
            web_attrs.push(("status_code".to_string(), json!(observed.status_code)));
            web_attrs.push(("server_banner".to_string(), json!(observed.server_banner)));
            web_attrs.push(("x_powered_by".to_string(), json!(observed.x_powered_by)));
            web_attrs.push(("content_type".to_string(), json!(observed.content_type)));
        }
        if let Some(profile) = site_profile.as_ref() {
            web_attrs.push(("site_type".to_string(), json!(&profile.kind)));
            if let Some(provider) = &profile.provider {
                web_attrs.push(("site_provider".to_string(), json!(provider)));
            }
            web_attrs.push(("site_confidence".to_string(), json!(profile.confidence)));
            web_attrs.push(("site_signals".to_string(), json!(&profile.signals)));
        }

        facts.push(Fact::with_attrs(
            host,
            "web_service",
            format!("web:https://{}", host),
            web_attrs,
        ));

        if let Some(profile) = site_profile.clone() {
            let mut attrs = vec![
                ("kind".to_string(), json!(&profile.kind)),
                ("confidence".to_string(), json!(profile.confidence)),
                ("signals".to_string(), json!(&profile.signals)),
            ];
            if let Some(provider) = &profile.provider {
                attrs.push(("provider".to_string(), json!(provider)));
            }

            facts.push(Fact::with_attrs(
                host,
                "site_profile",
                format!("site_profile:{}:{}", profile.kind, host),
                attrs,
            ));
        }

        return Ok(HostInspection {
            facts,
            new_hosts,
            site_profile,
            dead_host,
        });
    }

    // Keep the DNS facts even when there is no live web surface.
    let mut web_attrs = vec![
        ("host".to_string(), json!(host)),
        ("scheme".to_string(), json!("https")),
        ("port".to_string(), json!(443)),
        ("alive".to_string(), json!(alive)),
    ];
    if let Some(dead) = dead_host.as_ref() {
        web_attrs.push(("dead_reason".to_string(), json!(&dead.reason)));
    }
    if let Some(target) = cname_target.as_ref() {
        web_attrs.push(("cname_target".to_string(), json!(target)));
    }

    facts.push(Fact::with_attrs(
        host,
        "web_service",
        format!("web:https://{}", host),
        web_attrs,
    ));

    Ok(HostInspection {
        facts,
        new_hosts,
        site_profile: None,
        dead_host,
    })
}

/// Gather MX/SPF/DMARC/DKIM posture for the apex domain.
fn collect_domain_mail_facts(
    apex: &str,
    zone_dump: &ZoneDump,
    facts: &mut Vec<Fact>,
    site_profiles: &mut Vec<SiteProfile>,
) -> Result<Vec<String>> {
    let mut mx_hosts = Vec::new();
    let mut signals = Vec::new();

    for mx in query_mx_records(apex, zone_dump)? {
        let mx_id = format!("dns:MX:{}:{}", apex, mx.exchange.replace('.', "_"));
        facts.push(Fact::with_attrs(
            apex,
            "dns_record",
            mx_id,
            vec![
                ("type".to_string(), json!("MX")),
                ("name".to_string(), json!(apex)),
                (
                    "value".to_string(),
                    json!(format!("{} {}", mx.preference, mx.exchange)),
                ),
                ("preference".to_string(), json!(mx.preference)),
                ("exchange".to_string(), json!(mx.exchange)),
            ],
        ));

        signals.push(format!("mx:{}", mx.exchange));
        mx_hosts.push(mx.exchange.clone());
    }

    let provider = infer_mail_provider(&mx_hosts, apex);
    if let Some(provider_name) = provider.clone() {
        signals.push(format!("mx-provider:{provider_name}"));
    }

    let spf_records = query_txt_records(apex, zone_dump)?;
    for spf in spf_records
        .iter()
        .filter(|entry| entry.to_lowercase().starts_with("v=spf1"))
    {
        facts.push(Fact::with_attrs(
            apex,
            "dns_record",
            format!("dns:TXT:spf:{}", apex),
            vec![
                ("type".to_string(), json!("TXT")),
                ("name".to_string(), json!(apex)),
                ("value".to_string(), json!(spf)),
            ],
        ));
        signals.push("spf".to_string());
    }

    let dmarc_name = format!("_dmarc.{}", apex);
    for dmarc in query_txt_records(&dmarc_name, zone_dump)? {
        let lower = dmarc.to_lowercase();
        if lower.starts_with("v=dmarc1") {
            facts.push(Fact::with_attrs(
                apex,
                "dns_record",
                format!("dns:TXT:_dmarc.{}", apex),
                vec![
                    ("type".to_string(), json!("TXT")),
                    ("name".to_string(), json!(dmarc_name)),
                    ("value".to_string(), json!(dmarc)),
                ],
            ));
            signals.push("dmarc".to_string());
        }
    }

    for (selector, record) in query_dkim_records(apex, zone_dump)? {
        facts.push(Fact::with_attrs(
            apex,
            "dns_record",
            format!("dns:TXT:{}._domainkey:{}", selector, apex),
            vec![
                ("type".to_string(), json!("TXT")),
                (
                    "name".to_string(),
                    json!(format!("{}._domainkey.{}", selector, apex)),
                ),
                ("value".to_string(), json!(record)),
            ],
        ));
        signals.push(format!("dkim:{}", selector));
    }

    if !signals.is_empty() {
        site_profiles.push(SiteProfile {
            host: apex.to_string(),
            kind: "mail".to_string(),
            provider: provider.clone(),
            confidence: if mx_hosts.is_empty() { 0.75 } else { 0.95 },
            signals: signals.clone(),
        });

        facts.push(Fact::with_attrs(
            apex,
            "service_profile",
            format!("service_profile:mail:{}", apex),
            vec![
                ("role".to_string(), json!("mail")),
                ("provider".to_string(), json!(provider)),
                ("mx_hosts".to_string(), json!(&mx_hosts)),
                ("signals".to_string(), json!(signals)),
            ],
        ));
    }

    Ok(mx_hosts)
}

/// Pull public hostnames from a single page/asset using a conservative parser.
fn extract_hosts(text: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for token in extract_urls(text) {
        if let Some(host) = url_to_host(&token) {
            hosts.insert(host);
        }
    }
    hosts
}

/// Extract lightweight signal strings that help explain the classification.
fn extract_signals(text: &str) -> Vec<String> {
    let mut signals = Vec::new();
    signals.extend(markers_to_signals(text, "wordpress", WORDPRESS_MARKERS));
    signals.extend(markers_to_signals(text, "ghost", GHOST_MARKERS));
    signals.extend(markers_to_signals(text, "wix", WIX_MARKERS));
    signals.extend(markers_to_signals(text, "weebly", WEEBLY_MARKERS));
    signals.extend(markers_to_signals(text, "square", SQUARE_MARKERS));
    signals.extend(markers_to_signals(text, "squarespace", SQUARESPACE_MARKERS));
    signals.extend(markers_to_signals(text, "shopify", SHOPIFY_MARKERS));
    signals.extend(markers_to_signals(text, "react", REACT_MARKERS));
    signals.extend(markers_to_signals(text, "vite", VITE_MARKERS));
    signals.extend(markers_to_signals(text, "angular", ANGULAR_MARKERS));
    signals.extend(markers_to_signals(text, "nextjs", NEXTJS_MARKERS));
    signals.extend(markers_to_signals(text, "vue", VUE_MARKERS));
    signals.extend(markers_to_signals(text, "sveltekit", SVELTEKIT_MARKERS));

    let lower = text.to_lowercase();
    if lower.contains("application/json") || lower.trim_start().starts_with('{') {
        signals.push("json".to_string());
    }
    signals
}

/// Classify a host based on passive headers/body snippets.
fn classify_site(
    host: &str,
    surface: &SurfaceObservation,
    mut signals: Vec<String>,
) -> Option<SiteProfile> {
    let mut combined = String::new();
    combined.push_str(host);
    combined.push('\n');
    combined.push_str(&surface.headers_text.to_lowercase());
    combined.push('\n');
    if let Some(body) = &surface.body {
        combined.push_str(&body.to_lowercase());
    }
    if let Some(robots) = &surface.robots {
        combined.push_str(&robots.to_lowercase());
    }
    if let Some(sitemap) = &surface.sitemap {
        combined.push_str(&sitemap.to_lowercase());
    }
    if let Some(wp_sitemap) = &surface.wp_sitemap {
        combined.push_str(&wp_sitemap.to_lowercase());
    }

    let content_type = surface.content_type.as_deref().unwrap_or("").to_lowercase();
    let body = surface.body.as_deref().unwrap_or("").to_lowercase();

    if is_api_host(host, &combined, &content_type, &body) {
        signals.push("api-response".to_string());
        return Some(SiteProfile {
            host: host.to_string(),
            kind: "api".to_string(),
            provider: None,
            confidence: 0.8,
            signals: dedupe_signals(signals),
        });
    }

    if let Some((provider, provider_signals)) = detect_cms_provider(&combined) {
        signals.extend(provider_signals);
        return Some(SiteProfile {
            host: host.to_string(),
            kind: "cms".to_string(),
            provider: Some(provider),
            confidence: 0.94,
            signals: dedupe_signals(signals),
        });
    }

    if let Some((provider, provider_signals)) = detect_basic_provider(&combined) {
        signals.extend(provider_signals);
        return Some(SiteProfile {
            host: host.to_string(),
            kind: "basic".to_string(),
            provider: Some(provider),
            confidence: 0.78,
            signals: dedupe_signals(signals),
        });
    }

    signals.push("plain".to_string());
    Some(SiteProfile {
        host: host.to_string(),
        kind: "basic".to_string(),
        provider: None,
        confidence: 0.62,
        signals: dedupe_signals(signals),
    })
}

fn markers_to_signals(text: &str, label: &str, markers: &[&str]) -> Vec<String> {
    let lower = text.to_lowercase();
    markers
        .iter()
        .filter(|marker| lower.contains(*marker))
        .map(|marker| format!("{label}:{marker}"))
        .collect()
}

fn is_api_host(host: &str, combined: &str, content_type: &str, body: &str) -> bool {
    host.starts_with("api.")
        || host.starts_with("graphql.")
        || content_type.contains("application/json")
        || combined.contains("openapi")
        || combined.contains("swagger")
        || body.trim_start().starts_with('{')
        || body.trim_start().starts_with('[')
}

fn detect_cms_provider(combined: &str) -> Option<(String, Vec<String>)> {
    let providers: [(&str, &[&str]); 2] =
        [("wordpress", WORDPRESS_MARKERS), ("ghost", GHOST_MARKERS)];

    providers.iter().find_map(|(provider, markers)| {
        let signals = markers_to_signals(combined, provider, markers);
        if signals.is_empty() {
            None
        } else {
            Some(((*provider).to_string(), signals))
        }
    })
}

fn detect_basic_provider(combined: &str) -> Option<(String, Vec<String>)> {
    let hosted_providers: [(&str, &[&str]); 5] = [
        ("wix", WIX_MARKERS),
        ("weebly", WEEBLY_MARKERS),
        ("square", SQUARE_MARKERS),
        ("squarespace", SQUARESPACE_MARKERS),
        ("shopify", SHOPIFY_MARKERS),
    ];

    if let Some(found) = hosted_providers.iter().find_map(|(provider, markers)| {
        let signals = markers_to_signals(combined, provider, markers);
        if signals.is_empty() {
            None
        } else {
            Some(((*provider).to_string(), signals))
        }
    }) {
        return Some(found);
    }

    let providers: [(&str, &[&str]); 6] = [
        ("vite", VITE_MARKERS),
        ("angular", ANGULAR_MARKERS),
        ("react", REACT_MARKERS),
        ("nextjs", NEXTJS_MARKERS),
        ("vue", VUE_MARKERS),
        ("sveltekit", SVELTEKIT_MARKERS),
    ];

    providers.iter().find_map(|(provider, markers)| {
        let signals = markers_to_signals(combined, provider, markers);
        if signals.is_empty() {
            None
        } else {
            Some(((*provider).to_string(), signals))
        }
    })
}

fn dedupe_signals(signals: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    signals
        .into_iter()
        .filter(|signal| seen.insert(signal.clone()))
        .collect()
}

fn infer_mail_provider(mx_hosts: &[String], apex: &str) -> Option<String> {
    let providers: [(&str, &[&str]); 11] = [
        (
            "google-workspace",
            &["aspmx.l.google.com", ".google.com", ".googlemail.com"],
        ),
        (
            "microsoft-365",
            &[".mail.protection.outlook.com", ".outlook.com"],
        ),
        ("zoho-mail", &[".zoho.com", ".zohomail.com"]),
        ("fastmail", &[".messagingengine.com"]),
        ("mimecast", &[".mimecast.com"]),
        ("proofpoint", &[".pphosted.com"]),
        ("mailgun", &[".mailgun.org"]),
        ("sendgrid", &[".sendgrid.net"]),
        ("proton-mail", &[".protonmail.ch", ".protonmail.com"]),
        ("icloud-mail", &[".icloud.com", ".me.com"]),
        ("amazon-ses", &[".amazonses.com", ".awsapps.com"]),
    ];

    for host in mx_hosts {
        let candidate = canonical_host(host);
        for (provider, markers) in providers {
            if markers
                .iter()
                .any(|marker| candidate == *marker || candidate.ends_with(marker))
            {
                return Some(provider.to_string());
            }
        }
    }

    if mx_hosts
        .iter()
        .any(|host| is_same_domain_or_subdomain(host, apex))
    {
        return Some("custom-self-hosted".to_string());
    }

    mx_hosts.first().cloned()
}

/// Determine whether a hostname looks like the same domain family as the apex.
fn is_same_domain_or_subdomain(candidate: &str, apex: &str) -> bool {
    let candidate = canonical_host(candidate);
    let apex = canonical_host(apex);
    candidate == apex || candidate.ends_with(&format!(".{}", apex))
}

/// Container for a fetched surface snapshot.
#[derive(Debug, Default)]
struct SurfaceObservation {
    scheme: String,
    status_code: Option<u16>,
    headers_text: String,
    body: Option<String>,
    robots: Option<String>,
    sitemap: Option<String>,
    wp_sitemap: Option<String>,
    content_type: Option<String>,
    server_banner: Option<String>,
    x_powered_by: Option<String>,
}

impl SurfaceObservation {
    fn has_body(&self) -> bool {
        self.body
            .as_deref()
            .map(|body| !body.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Fetch a small passive snapshot of a host.
fn fetch_surface(host: &str) -> Result<SurfaceObservation> {
    let scheme = resolve_reachable_scheme(host).unwrap_or("https");
    let mut surface = SurfaceObservation::default();
    surface.scheme = scheme.to_string();

    let root_headers = fetch_headers(host, scheme, "/")?;
    surface.status_code = root_headers.status_code;
    surface.headers_text = root_headers.raw.clone();
    surface.content_type = root_headers.headers.get("content-type").cloned();
    surface.server_banner = root_headers.headers.get("server").cloned();
    surface.x_powered_by = root_headers.headers.get("x-powered-by").cloned();
    surface.body = fetch_body(host, scheme, "/")?.or(None);
    surface.robots = fetch_body(host, scheme, "/robots.txt")?;
    surface.sitemap = fetch_body(host, scheme, "/sitemap.xml")?;
    surface.wp_sitemap = fetch_body(host, scheme, "/wp-sitemap.xml")?;

    Ok(surface)
}

/// Get the first reachable scheme for a host.
fn resolve_reachable_scheme(host: &str) -> Option<&'static str> {
    match probe_https(host) {
        ProbeResult::Success => Some("https"),
        ProbeResult::Failure(_) => match probe_http(host) {
            ProbeResult::Success => Some("http"),
            ProbeResult::Failure(_) => None,
        },
    }
}

/// Result from fetching headers.
#[derive(Debug, Default)]
struct HeaderFetch {
    raw: String,
    status_code: Option<u16>,
    headers: BTreeMap<String, String>,
}

/// Fetch response headers for a path.
fn fetch_headers(host: &str, scheme: &str, path: &str) -> Result<HeaderFetch> {
    let url = format!("{scheme}://{host}{path}");
    let output = Command::new("curl")
        .arg("-sSIL")
        .arg("--max-time")
        .arg("8")
        .arg("--connect-timeout")
        .arg("3")
        .arg("--insecure")
        .arg(url)
        .output()
        .with_context(|| format!("failed to fetch headers for {host}{path}"))?;

    if !output.status.success() {
        return Ok(HeaderFetch::default());
    }

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let status_code = parse_status_code(&raw);
    let headers = parse_headers(&raw);
    Ok(HeaderFetch {
        raw,
        status_code,
        headers,
    })
}

/// Fetch response body for a path.
fn fetch_body(host: &str, scheme: &str, path: &str) -> Result<Option<String>> {
    let url = format!("{scheme}://{host}{path}");
    let output = Command::new("curl")
        .arg("-sSL")
        .arg("--max-time")
        .arg("8")
        .arg("--connect-timeout")
        .arg("3")
        .arg("--insecure")
        .arg(url)
        .output()
        .with_context(|| format!("failed to fetch body for {host}{path}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

/// Parse header lines into a map, keeping the last observed value.
fn parse_headers(raw: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in raw.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().to_string();
        if !name.is_empty() && !value.is_empty() {
            headers.insert(name, value);
        }
    }
    headers
}

fn parse_status_code(raw: &str) -> Option<u16> {
    raw.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("HTTP/") {
            return None;
        }
        trimmed
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
    })
}

fn detect_surface_failure(surface: &SurfaceObservation) -> Option<String> {
    let body = surface.body.as_deref().unwrap_or("");
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Some("zombie site: blank root response body".to_string());
    }

    if let Some(status_code) = surface.status_code {
        if matches!(
            status_code,
            500 | 502 | 503 | 504 | 521 | 522 | 523 | 524 | 525 | 526 | 530
        ) {
            return Some(format!("zombie site: upstream returned HTTP {status_code}"));
        }
    }

    let lower = trimmed.to_lowercase();
    let proxy_markers = [
        "bad gateway",
        "proxy error",
        "reverse proxy error",
        "origin is unreachable",
        "web server is returning an unknown error",
        "error code: 502",
        "error code: 503",
        "error code: 521",
        "error code: 522",
        "error code: 523",
        "error code: 524",
        "error code: 525",
        "error code: 526",
        "upstream connect error",
        "backend fetch failed",
        "no healthy upstream",
    ];
    if proxy_markers.iter().any(|marker| lower.contains(marker)) {
        return Some("zombie site: reverse proxy or upstream error page".to_string());
    }

    let content_type = surface.content_type.as_deref().unwrap_or("");
    let looks_html = content_type.to_lowercase().contains("html") || lower.contains("<html");
    if looks_html && !looks_like_website_body(body, content_type) {
        return Some("zombie site: HTML shell without real page content".to_string());
    }

    None
}

fn surface_is_psi_eligible(surface: &SurfaceObservation) -> bool {
    looks_like_website_body(
        surface.body.as_deref().unwrap_or(""),
        surface.content_type.as_deref().unwrap_or(""),
    )
}

fn looks_like_website_body(body: &str, content_type: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_lowercase();
    let htmlish_markers = ["<!doctype html", "<html", "<head", "<body"];
    let content_markers = [
        "<title",
        "<meta",
        "<main",
        "<section",
        "<article",
        "<div",
        "<script",
        "<link",
        "<img",
        "<h1",
        "id=\"app\"",
        "id='app'",
        "id=\"root\"",
        "id='root'",
    ];
    let htmlish = content_type.to_lowercase().contains("html")
        || htmlish_markers.iter().any(|marker| lower.contains(marker))
        || content_markers.iter().any(|marker| lower.contains(marker));
    if !htmlish {
        return false;
    }

    if content_markers.iter().any(|marker| lower.contains(marker)) {
        return true;
    }

    visible_text_len(trimmed) >= 20
}

fn visible_text_len(value: &str) -> usize {
    let mut len = 0;
    let mut inside_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag && ch.is_alphanumeric() => len += 1,
            _ => {}
        }
    }
    len
}

/// Convert a detected URL-like token into a host candidate.
fn url_to_host(token: &str) -> Option<String> {
    let token = token.trim();
    let token = token
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = token.split(['/', '?', '#']).next()?.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(canonical_host(host))
    }
}

/// Extract absolute URLs from passive text.
fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for needle in ["https://", "http://"] {
        let mut remaining = text;
        while let Some(start) = remaining.find(needle) {
            let after = &remaining[start..];
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
                .unwrap_or(after.len());
            let token =
                after[..end].trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ')' | '('));
            if !token.is_empty() {
                urls.push(token.to_string());
            }
            remaining = &after[end..];
        }
    }
    urls
}

#[derive(Debug, Clone)]
struct MxRecord {
    preference: u32,
    exchange: String,
}

fn query_txt_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<String>> {
    let records = dig_short(name, Some("TXT"))?;
    if !records.is_empty() {
        return Ok(records);
    }

    let records = host_short(name, "TXT")?;
    if !records.is_empty() {
        return Ok(records);
    }

    Ok(zone_dump.lookup(name, "TXT").cloned().unwrap_or_default())
}

fn query_mx_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<MxRecord>> {
    let mut records = Vec::new();
    for raw in dig_short(name, Some("MX"))? {
        if let Some(record) = parse_mx_record(&raw) {
            records.push(record);
        }
    }

    if records.is_empty() {
        for raw in host_short(name, "MX")? {
            if let Some(record) = parse_mx_record(&raw) {
                records.push(record);
            }
        }
    }

    if records.is_empty() {
        if let Some(values) = zone_dump.lookup(name, "MX") {
            for raw in values {
                if let Some(record) = parse_mx_record(raw) {
                    records.push(record);
                }
            }
        }
    }

    Ok(records)
}

fn query_dkim_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<(String, String)>> {
    let mut records = Vec::new();
    for selector in COMMON_DKIM_SELECTORS {
        let record_name = format!("{}._domainkey.{}", selector, name);
        for value in query_txt_records(&record_name, zone_dump)? {
            records.push((selector.to_string(), value));
        }
    }
    Ok(records)
}

fn parse_mx_record(raw: &str) -> Option<MxRecord> {
    let mut parts = raw.split_whitespace();
    let preference = parts.next()?.parse::<u32>().ok()?;
    let exchange = parts.next().map(canonical_host)?;
    Some(MxRecord {
        preference,
        exchange,
    })
}

fn query_ct_names(domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("10")
        .arg(url)
        .output()
        .with_context(|| format!("failed to query crt.sh for {}", domain))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            warn!(domain = %domain, error = %err, "failed to parse crt.sh response");
            return Ok(Vec::new());
        }
    };

    let mut hosts = BTreeSet::new();
    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(name_value) = item.get("name_value").and_then(|value| value.as_str()) {
                for line in name_value.lines() {
                    let candidate = canonical_host(line.trim_start_matches("*."));
                    if !candidate.is_empty() {
                        hosts.insert(candidate);
                    }
                }
            }
        }
    }

    Ok(hosts.into_iter().collect())
}

enum HostLiveness {
    Alive,
    Dead(String),
}

fn check_host_liveness(host: &str) -> HostLiveness {
    let mut reasons = Vec::new();

    match probe_https(host) {
        ProbeResult::Success => return HostLiveness::Alive,
        ProbeResult::Failure(reason) => reasons.push(reason),
    }

    match probe_http(host) {
        ProbeResult::Success => return HostLiveness::Alive,
        ProbeResult::Failure(reason) => reasons.push(reason),
    }

    match probe_ping(host) {
        ProbeResult::Success => HostLiveness::Alive,
        ProbeResult::Failure(reason) => {
            reasons.push(reason);
            HostLiveness::Dead(reasons.join(" | "))
        }
    }
}

enum ProbeResult {
    Success,
    Failure(String),
}

fn probe_https(host: &str) -> ProbeResult {
    probe_curl(host, true)
}

fn probe_http(host: &str) -> ProbeResult {
    probe_curl(host, false)
}

fn probe_curl(host: &str, https: bool) -> ProbeResult {
    let scheme = if https { "https" } else { "http" };
    let url = format!("{scheme}://{host}/");
    let mut command = Command::new("curl");
    command
        .arg("-I")
        .arg("--max-time")
        .arg("3")
        .arg("--connect-timeout")
        .arg("2")
        .arg("--silent")
        .arg("--output")
        .arg("/dev/null")
        .arg("--show-error")
        .arg("--insecure")
        .arg(url);

    run_probe(command, &format!("curl {scheme} {host}"))
}

fn probe_ping(host: &str) -> ProbeResult {
    let mut command = Command::new("ping");
    command.arg("-c").arg("1").arg("-W").arg("1").arg(host);
    run_probe(command, &format!("ping {host}"))
}

fn run_probe(mut command: Command, description: &str) -> ProbeResult {
    match command.output() {
        Ok(output) if output.status.success() => ProbeResult::Success,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            ProbeResult::Failure(format!(
                "{description} failed (status {:?}): {}",
                output.status.code(),
                stderr.trim()
            ))
        }
        Err(err) => ProbeResult::Failure(format!("{description} spawn error: {err}")),
    }
}

fn query_cname_record(name: &str, zone_dump: &ZoneDump) -> Result<Option<String>> {
    let records = dig_short(name, Some("CNAME"))?;
    if let Some(record) = records.into_iter().next() {
        return Ok(Some(record));
    }

    if let Some(record) = host_short(name, "CNAME")?.into_iter().next() {
        return Ok(Some(record));
    }

    Ok(zone_dump
        .lookup(name, "CNAME")
        .and_then(|values| values.first().cloned()))
}

fn query_address_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<String>> {
    let mut addresses = Vec::new();
    addresses.extend(dig_short(name, Some("A"))?);
    addresses.extend(dig_short(name, Some("AAAA"))?);
    let addresses = normalize_ip_addresses(addresses);
    if !addresses.is_empty() {
        return Ok(addresses);
    }

    let addresses = system_lookup_ip_addresses(name);
    if !addresses.is_empty() {
        return Ok(addresses);
    }

    let mut fallback = Vec::new();
    if let Some(values) = zone_dump.lookup(name, "A") {
        fallback.extend(values.clone());
    }
    if let Some(values) = zone_dump.lookup(name, "AAAA") {
        fallback.extend(values.clone());
    }
    Ok(normalize_ip_addresses(fallback))
}

fn ip_family(value: &str) -> Option<&'static str> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => Some("ipv4"),
        IpAddr::V6(_) => Some("ipv6"),
    }
}

fn normalize_ip_addresses(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter_map(|value| value.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn system_lookup_ip_addresses(name: &str) -> Vec<String> {
    let Ok(addresses) = (name, 0).to_socket_addrs() else {
        debug!(host = name, "system resolver returned no socket addresses");
        return Vec::new();
    };

    normalize_ip_addresses(addresses.map(|address| address.ip().to_string()).collect())
}

fn dig_short(name: &str, record_type: Option<&str>) -> Result<Vec<String>> {
    let mut args = Vec::new();
    args.push(name);
    if let Some(rt) = record_type {
        args.push(rt);
    }
    args.push("+short");
    args.push("+time=1");
    args.push("+tries=1");

    let output = Command::new("dig")
        .args(&args)
        .output()
        .with_context(|| format!("failed to invoke dig for {}", name))?;

    if !output.status.success() {
        debug!(
            command = "dig",
            host = name,
            status = %output.status,
            "dig command returned non-zero status"
        );
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let without_dot = trimmed.trim_end_matches('.');
        let unquoted = without_dot.trim_matches('"').to_string();
        if unquoted.is_empty() {
            continue;
        }
        lines.push(unquoted.to_lowercase());
    }
    Ok(lines)
}

fn host_short(name: &str, record_type: &str) -> Result<Vec<String>> {
    let output = Command::new("host")
        .arg("-t")
        .arg(record_type.to_ascii_lowercase())
        .arg(name)
        .output()
        .with_context(|| format!("failed to invoke host for {} {}", record_type, name))?;

    if !output.status.success() {
        debug!(
            command = "host",
            host = name,
            record_type,
            status = %output.status,
            "host command returned non-zero status"
        );
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_host_output(&stdout, record_type))
}

fn parse_host_output(stdout: &str, record_type: &str) -> Vec<String> {
    let record_type = record_type.to_ascii_uppercase();
    stdout
        .lines()
        .filter_map(|line| parse_host_output_line(line.trim(), &record_type))
        .collect()
}

fn parse_host_output_line(line: &str, record_type: &str) -> Option<String> {
    match record_type {
        "TXT" => parse_host_txt_line(line),
        "MX" => parse_host_mx_line(line),
        "CNAME" => parse_host_cname_line(line),
        _ => None,
    }
}

fn parse_host_txt_line(line: &str) -> Option<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    values.push(current.clone());
                    current.clear();
                    in_quotes = false;
                } else {
                    in_quotes = true;
                }
            }
            '\\' if in_quotes => {
                let mut octal = String::new();
                for _ in 0..3 {
                    let Some(next) = chars.peek().copied() else {
                        break;
                    };
                    if !matches!(next, '0'..='7') {
                        break;
                    }
                    octal.push(next);
                    let _ = chars.next();
                }

                if octal.len() == 3 {
                    if let Ok(value) = u8::from_str_radix(&octal, 8) {
                        current.push(value as char);
                    }
                } else if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            _ if in_quotes => current.push(ch),
            _ => {}
        }
    }

    if values.is_empty() {
        None
    } else {
        Some(
            values
                .join("")
                .chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        )
    }
}

fn parse_host_mx_line(line: &str) -> Option<String> {
    let suffix = line.split(" mail is handled by ").nth(1)?;
    let mut parts = suffix.split_whitespace();
    let preference = parts.next()?;
    let exchange = canonical_host(parts.next()?);
    Some(format!("{preference} {exchange}"))
}

fn parse_host_cname_line(line: &str) -> Option<String> {
    let target = line
        .split(" is an alias for ")
        .nth(1)
        .or_else(|| line.split(" is a nickname for ").nth(1))?;
    Some(canonical_host(target.trim_end_matches('.')))
}

#[derive(Default)]
struct ZoneDump {
    hosts: BTreeSet<String>,
    records: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl ZoneDump {
    fn hosts(&self) -> &BTreeSet<String> {
        &self.hosts
    }

    fn lookup(&self, name: &str, record_type: &str) -> Option<&Vec<String>> {
        let key = canonical_host(name);
        self.records
            .get(&key)
            .and_then(|types| types.get(&record_type.to_uppercase()))
    }

    fn insert(&mut self, name: String, record_type: &str, value: String) {
        self.hosts.insert(name.clone());
        self.records
            .entry(name)
            .or_insert_with(BTreeMap::new)
            .entry(record_type.to_uppercase())
            .or_insert_with(Vec::new)
            .push(value);
    }
}

fn load_zone_dump(domain: &str) -> ZoneDump {
    let mut dump = ZoneDump::default();
    let path = PathBuf::from(format!("{}.txt", domain));
    if !path.exists() {
        return dump;
    }

    let contents = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) => {
            warn!(
                dump = %path.display(),
                error = %err,
                "failed to read zone dump; skipping"
            );
            return dump;
        }
    };

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('$') {
            continue;
        }

        let without_comment = trimmed.splitn(2, ';').next().unwrap().trim();
        let tokens: Vec<&str> = without_comment.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        let mut name = tokens[0];
        if name.eq("@") {
            name = domain;
        }

        let mut idx = 1;
        let mut record_type: Option<&str> = None;
        while idx < tokens.len() {
            let token = tokens[idx];
            let upper = token.to_uppercase();
            if upper == "IN" || upper.chars().all(|c| c.is_ascii_digit()) {
                idx += 1;
                continue;
            }
            if matches!(upper.as_str(), "A" | "AAAA" | "CNAME" | "TXT" | "MX") {
                record_type = Some(tokens[idx]);
                idx += 1;
                break;
            }
            idx += 1;
        }

        let record_type = match record_type {
            Some(rt) => rt,
            None => continue,
        };

        if idx >= tokens.len() {
            continue;
        }

        let value = tokens[idx..].join(" ");
        let value = value
            .trim()
            .trim_matches('"')
            .trim_end_matches('.')
            .to_string();
        if value.is_empty() {
            continue;
        }

        if !matches!(
            record_type.to_uppercase().as_str(),
            "A" | "AAAA" | "CNAME" | "TXT" | "MX"
        ) {
            continue;
        }

        let host = normalize_zone_name(name, domain);
        dump.insert(host, record_type, canonical_value(record_type, value));
    }

    dump
}

fn normalize_zone_name(name: &str, domain: &str) -> String {
    if name == "@" {
        return domain.to_string();
    }
    canonical_host(name)
}

fn normalize_hostname(input: &str, domain: &str) -> String {
    let trimmed = canonical_host(input);
    if trimmed.ends_with(&canonical_host(domain)) {
        trimmed
    } else if trimmed.contains('.') {
        trimmed
    } else {
        format!("{}.{}", trimmed, canonical_host(domain))
    }
}

fn canonical_host(value: &str) -> String {
    value.trim_end_matches('.').to_lowercase()
}

fn canonical_value(record_type: &str, value: String) -> String {
    match record_type.to_uppercase().as_str() {
        "CNAME" => canonical_host(&value),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SurfaceObservation, detect_surface_failure, infer_mail_provider, looks_like_website_body,
        parse_host_cname_line, parse_host_mx_line, parse_host_txt_line, surface_is_psi_eligible,
    };

    #[test]
    fn detects_google_workspace_mx_provider() {
        let provider = infer_mail_provider(&["aspmx.l.google.com".to_string()], "example.com");
        assert_eq!(provider.as_deref(), Some("google-workspace"));
    }

    #[test]
    fn marks_blank_html_shell_as_zombie() {
        let surface = SurfaceObservation {
            scheme: "https".to_string(),
            status_code: Some(200),
            content_type: Some("text/html".to_string()),
            body: Some("<html><body></body></html>".to_string()),
            ..SurfaceObservation::default()
        };

        assert_eq!(
            detect_surface_failure(&surface).as_deref(),
            Some("zombie site: HTML shell without real page content")
        );
        assert!(!surface_is_psi_eligible(&surface));
    }

    #[test]
    fn html_app_shell_is_psi_eligible() {
        let body = "<!doctype html><html><head><title>Site</title></head><body><div id=\"root\"></div><script src=\"/app.js\"></script></body></html>";
        assert!(looks_like_website_body(body, "text/html; charset=utf-8"));
    }

    #[test]
    fn json_api_body_is_not_psi_eligible() {
        assert!(!looks_like_website_body(
            "{\"status\":\"ok\"}",
            "application/json"
        ));
    }

    #[test]
    fn parses_host_txt_lines() {
        assert_eq!(
            parse_host_txt_line(
                "_dmarc.example.com descriptive text \"v=DMARC1; p=quarantine;\\010rua=mailto:test@example.com\""
            )
            .as_deref(),
            Some("v=dmarc1; p=quarantine; rua=mailto:test@example.com")
        );
    }

    #[test]
    fn parses_host_mx_lines() {
        assert_eq!(
            parse_host_mx_line("example.com mail is handled by 10 mail.example.net.").as_deref(),
            Some("10 mail.example.net")
        );
    }

    #[test]
    fn parses_host_cname_lines() {
        assert_eq!(
            parse_host_cname_line("www.example.com is an alias for proxy.example.net.").as_deref(),
            Some("proxy.example.net")
        );
    }
}
