//! Host inspection and profile classification.

use std::collections::BTreeSet;

use anyhow::Result;
use serde_json::json;
use tracing::{debug, info};

use crate::config::DiscoveryProbeConfig;
use crate::facts::Fact;

use super::{
    DeadHost, SiteProfile, canonical_host,
    dns::{
        HostLiveness, ZoneDump, check_host_liveness, query_address_records, query_cname_record,
        query_dkim_records, query_mx_records, query_txt_records,
    },
    surface::{self, SurfaceObservation},
    text::{
        ANGULAR_MARKERS, GHOST_MARKERS, NEXTJS_MARKERS, REACT_MARKERS, SHOPIFY_MARKERS,
        SQUARE_MARKERS, SQUARESPACE_MARKERS, SVELTEKIT_MARKERS, VITE_MARKERS, VUE_MARKERS,
        WEEBLY_MARKERS, WIX_MARKERS, WORDPRESS_MARKERS, dedupe_signals, extract_signals,
        extract_surface_hosts, markers_to_signals,
    },
};

#[derive(Debug)]
pub(super) struct HostInspection {
    pub(super) facts: Vec<Fact>,
    pub(super) new_hosts: BTreeSet<String>,
    pub(super) site_profile: Option<SiteProfile>,
    pub(super) dead_host: Option<DeadHost>,
}

pub(super) fn inspect_host(
    host: &str,
    apex: &str,
    zone_dump: &ZoneDump,
    probes: &DiscoveryProbeConfig,
) -> Result<HostInspection> {
    debug!(target = %apex, host = %host, "starting host inspection");
    let mut facts = Vec::new();
    let mut new_hosts = BTreeSet::new();

    debug!(target = %apex, host = %host, "checking host liveness");
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
        debug!(target = %apex, host = %host, cname_target = %target, "observed cname record");
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

        new_hosts.insert(super::canonical_host(target));
    }

    let addresses = query_address_records(host, zone_dump)?;
    if !addresses.is_empty() {
        debug!(
            target = %apex,
            host = %host,
            address_count = addresses.len(),
            "observed address records"
        );
        for address in &addresses {
            let family = super::dns::ip_family(address).unwrap_or("unknown");
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
            debug!(target = %apex, host = %host, "fetching root surface snapshot");
            let observed = surface::fetch_surface(host)?;
            debug!(
                target = %apex,
                host = %host,
                scheme = %observed.scheme,
                status_code = ?observed.status_code,
                has_body = observed.has_body(),
                content_type = ?observed.content_type,
                "finished root surface snapshot"
            );
            let (surface_hosts, surface_signals) = gather_surface_evidence(host, apex, &observed);
            new_hosts.extend(surface_hosts);
            site_profile = classify_site(host, &observed, surface_signals);

            if surface::should_probe_dav_endpoints(site_profile.as_ref(), probes.dav_endpoints) {
                info!(
                    target = %apex,
                    host = %host,
                    endpoint_count = surface::DAV_ENDPOINT_PROBES.len(),
                    "probing dav endpoints"
                );

                if let Some(dav_probe) = surface::probe_dav_endpoints(host, &observed.scheme, apex)?
                {
                    info!(
                        target = %apex,
                        host = %host,
                        endpoint = %dav_probe.endpoint,
                        status_code = dav_probe.status_code,
                        content_type = ?dav_probe.content_type,
                        "identified dav surface via endpoint probe"
                    );
                    site_profile = Some(dav_probe.profile);
                    new_hosts.extend(dav_probe.new_hosts);
                }
            }

            if let Some(reason) = surface::detect_surface_failure(&observed) {
                if surface::should_probe_api_endpoints(
                    &reason,
                    site_profile.as_ref(),
                    probes.api_endpoints,
                ) {
                    info!(
                        target = %apex,
                        host = %host,
                        endpoint_count = surface::API_ENDPOINT_PROBES.len(),
                        "probing api endpoints after empty root response"
                    );

                    if let Some(api_probe) =
                        surface::probe_api_endpoints(host, &observed.scheme, apex)?
                    {
                        info!(
                            target = %apex,
                            host = %host,
                            endpoint = %api_probe.endpoint,
                            status_code = api_probe.status_code,
                            content_type = ?api_probe.content_type,
                            "identified api surface via endpoint probe"
                        );
                        site_profile = Some(api_probe.profile);
                        new_hosts.extend(api_probe.new_hosts);
                    } else {
                        alive = false;
                        dead_host = Some(DeadHost {
                            host: host.to_string(),
                            reason,
                        });
                    }
                } else if let Some(profile) = site_profile.as_ref() {
                    if is_strong_site_profile(profile) {
                        info!(
                            target = %apex,
                            host = %host,
                            site_type = %profile.kind,
                            site_provider = ?profile.provider,
                            "skipping api endpoint probing because site is already classified"
                        );
                    } else {
                        alive = false;
                        dead_host = Some(DeadHost {
                            host: host.to_string(),
                            reason,
                        });
                    }
                } else {
                    alive = false;
                    dead_host = Some(DeadHost {
                        host: host.to_string(),
                        reason,
                    });
                }
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
                            .map(surface::surface_is_psi_eligible)
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

fn gather_surface_evidence(
    host: &str,
    apex: &str,
    observed: &SurfaceObservation,
) -> (BTreeSet<String>, Vec<String>) {
    let mut new_hosts = BTreeSet::new();
    let mut surface_signals = Vec::new();

    if let Some(text) = observed.body.as_deref() {
        for extracted in extract_surface_hosts(text, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }
        surface_signals.extend(extract_signals(text));
    }
    if let Some(ref robots) = observed.robots {
        for extracted in extract_surface_hosts(robots, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }
        surface_signals.extend(extract_signals(robots));
    }
    if let Some(ref sitemap) = observed.sitemap {
        for extracted in extract_surface_hosts(sitemap, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }
        surface_signals.extend(extract_signals(sitemap));
    }
    if let Some(ref wp_sitemap) = observed.wp_sitemap {
        for extracted in extract_surface_hosts(wp_sitemap, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }
        surface_signals.extend(extract_signals(wp_sitemap));
    }
    for extracted in extract_surface_hosts(&observed.headers_text, apex) {
        if extracted != host && extracted != apex {
            new_hosts.insert(extracted);
        }
    }

    (new_hosts, surface_signals)
}

pub(super) fn classify_site(
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

    if let Some((provider, provider_signals)) = detect_dav_provider(&combined, None) {
        signals.extend(provider_signals);
        return Some(SiteProfile {
            host: host.to_string(),
            kind: "dav".to_string(),
            provider: Some(provider),
            confidence: 0.9,
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

pub(super) fn is_strong_site_profile(profile: &SiteProfile) -> bool {
    profile.kind != "basic" || profile.provider.is_some()
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
        [("wordpress", &WORDPRESS_MARKERS), ("ghost", &GHOST_MARKERS)];

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
        ("wix", &WIX_MARKERS),
        ("weebly", &WEEBLY_MARKERS),
        ("square", &SQUARE_MARKERS),
        ("squarespace", &SQUARESPACE_MARKERS),
        ("shopify", &SHOPIFY_MARKERS),
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
        ("vite", &VITE_MARKERS),
        ("angular", &ANGULAR_MARKERS),
        ("react", &REACT_MARKERS),
        ("nextjs", &NEXTJS_MARKERS),
        ("vue", &VUE_MARKERS),
        ("sveltekit", &SVELTEKIT_MARKERS),
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

fn detect_dav_provider(
    combined: &str,
    endpoint_hint: Option<&str>,
) -> Option<(String, Vec<String>)> {
    let providers: [(&str, &[&str]); 3] = [
        (
            "nextcloud",
            &[
                "nextcloud",
                "ocs/v2.php",
                "/remote.php/dav",
                "/remote.php/webdav",
            ],
        ),
        (
            "owncloud",
            &["owncloud", "/remote.php/dav", "/remote.php/webdav"],
        ),
        ("mailcow", &["mailcow", "sogo", "/SOGo/dav"]),
    ];

    for (provider, markers) in providers {
        let signals = markers_to_signals(combined, provider, markers);
        if !signals.is_empty() {
            return Some((provider.to_string(), signals));
        }
    }

    if let Some(endpoint) = endpoint_hint {
        let endpoint = endpoint.to_lowercase();
        if endpoint.contains("remote.php") {
            return Some((
                "nextcloud".to_string(),
                vec![format!("dav-endpoint:{endpoint}")],
            ));
        }
        if endpoint.contains("sogo") {
            return Some((
                "mailcow".to_string(),
                vec![format!("dav-endpoint:{endpoint}")],
            ));
        }
        if endpoint.contains("caldav")
            || endpoint.contains("carddav")
            || endpoint.contains("webdav")
        {
            return Some(("dav".to_string(), vec![format!("dav-endpoint:{endpoint}")]));
        }
    }

    None
}

pub(super) fn infer_mail_provider(mx_hosts: &[String], apex: &str) -> Option<String> {
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
        .any(|host| super::is_same_domain_or_subdomain(host, apex))
    {
        return Some("custom-self-hosted".to_string());
    }

    mx_hosts.first().cloned()
}

pub(super) fn collect_domain_mail_facts(
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
        info!(
            target = %apex,
            mx_hosts = mx_hosts.len(),
            signal_count = signals.len(),
            provider = ?provider,
            "detected apex mail posture"
        );
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
