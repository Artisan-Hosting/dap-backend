//! Discovery orchestration for host enumeration and passive classification.
//!
//! This module keeps the run-level workflow in one place while the detailed
//! DNS, CT, surface, and host-classification helpers live in submodules.

mod ct;
mod dns;
mod site;
mod surface;
mod text;

use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};

use anyhow::{Context, Result};
use tracing::info;

use crate::{
    backend::Storage,
    config::{RunConfig, ScopeMode},
    facts::Fact,
};

use self::dns::ZoneDump;

const MAX_DISCOVERY_DEPTH: usize = 5;

/// Result of the discovery process.
#[derive(Debug, Clone)]
pub struct DiscoveryOutcome {
    pub facts: Vec<Fact>,
    pub dead_hosts: Vec<DeadHost>,
    pub site_profiles: Vec<SiteProfile>,
    pub subdomain_count: usize,
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

/// Execute discovery with a DB-backed CT cache.
pub async fn perform_discovery_with_ct_cache(
    cfg: &RunConfig,
    storage: &Storage,
    ct_cache_ttl_seconds: u64,
) -> Result<DiscoveryOutcome> {
    perform_discovery_internal(cfg, Some(storage), ct_cache_ttl_seconds).await
}

async fn perform_discovery_internal(
    cfg: &RunConfig,
    storage: Option<&Storage>,
    ct_cache_ttl_seconds: u64,
) -> Result<DiscoveryOutcome> {
    info!(target = %cfg.domain, "starting discovery via hickory DNS resolver");

    let max_passes = cfg.discovery.max_passes.max(1).min(5);
    let backoff_ms = cfg.discovery.pass_backoff_ms;

    let mut best_outcome: Option<DiscoveryOutcome> = None;
    let mut last_count = 0;

    for pass in 1..=max_passes {
        let outcome = perform_discovery_pass(cfg, storage, ct_cache_ttl_seconds).await?;
        let pass_count = outcome.subdomain_count;

        info!(
            target = %cfg.domain,
            pass = pass,
            subdomains = pass_count,
            facts = outcome.facts.len(),
            dead_hosts = outcome.dead_hosts.len(),
            "discovery pass complete"
        );

        if best_outcome.is_none() || pass_count > last_count {
            best_outcome = Some(outcome.clone());
            last_count = pass_count;
        } else if pass_count == last_count && pass < max_passes {
            info!(
                target = %cfg.domain,
                pass = pass,
                converged_at = last_count,
                "discovery converged, stopping early"
            );
            break;
        }

        if pass < max_passes {
            tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
        }
    }

    let outcome = best_outcome.unwrap_or_else(|| DiscoveryOutcome {
        facts: Vec::new(),
        dead_hosts: Vec::new(),
        site_profiles: Vec::new(),
        subdomain_count: 0,
    });

    info!(
        target = %cfg.domain,
        total_facts = outcome.facts.len(),
        dead_hosts = outcome.dead_hosts.len(),
        subdomains = outcome.subdomain_count,
        "discovery phase complete"
    );
    Ok(outcome)
}

async fn perform_discovery_pass(
    cfg: &RunConfig,
    storage: Option<&Storage>,
    ct_cache_ttl_seconds: u64,
) -> Result<DiscoveryOutcome> {
    let apex = cfg.domain.to_lowercase();
    let zone_dump = Arc::new(dns::load_zone_dump(&apex));

    let mut facts = Vec::new();
    let mut dead_hosts = Vec::new();
    let mut site_profiles = Vec::new();

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut visited = BTreeSet::new();

    for host in site::collect_domain_mail_facts(&apex, &zone_dump, &mut facts, &mut site_profiles)?
    {
        if is_host_in_scope(&host, cfg, &apex) {
            queue.push_back((host, 0));
        }
    }

    let seed_hosts = gather_seed_hosts(cfg, &zone_dump, &apex);
    info!(
        target = %apex,
        mail_fact_count = facts.len(),
        mail_profile_count = site_profiles.len(),
        seed_count = seed_hosts.len(),
        zone_hosts = zone_dump.hosts().len(),
        "seeded discovery queue from local DNS and scope hints"
    );
    for host in seed_hosts {
        queue.push_back((host, 0));
    }

    let ct_hosts = ct::query_ct_names(&apex, storage, ct_cache_ttl_seconds).await?;
    info!(
        target = %apex,
        ct_candidate_count = ct_hosts.len(),
        queued_candidates = queue.len(),
        "loaded certificate transparency candidates"
    );
    for ct_host in ct_hosts {
        if is_host_in_scope(&ct_host, cfg, &apex) {
            queue.push_back((ct_host, 0));
        }
    }

    info!(
        target = %apex,
        initial_queue_size = queue.len(),
        "initial discovery queue populated"
    );

    let mut inspected_hosts = 0usize;
    let mut live_hosts = 0usize;
    let mut zombie_hosts = 0usize;
    let mut hard_dead_hosts = 0usize;
    let mut queued_new_hosts = 0usize;

    while let Some((host, depth)) = queue.pop_front() {
        if !is_host_in_scope(&host, cfg, &apex) {
            continue;
        }
        if !visited.insert(host.to_string()) {
            continue;
        }
        inspected_hosts += 1;

        let host_outcome = tokio::task::spawn_blocking({
            let host = host.clone();
            let apex = apex.clone();
            let zone_dump = zone_dump.clone();
            let discovery_probes = cfg.discovery_probes.clone();
            move || site::inspect_host(&host, &apex, &zone_dump, &discovery_probes)
        })
        .await
        .context("host inspection task failed")??;
        let inspection_new_hosts = host_outcome.new_hosts.len();
        queued_new_hosts += inspection_new_hosts;
        if let Some(dead) = host_outcome.dead_host {
            if dead.reason.starts_with("zombie site:") {
                zombie_hosts += 1;
            } else {
                hard_dead_hosts += 1;
            }
            dead_hosts.push(dead);
        } else {
            live_hosts += 1;
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

    let subdomain_count = visited.iter().filter(|host| host.as_str() != apex).count();

    info!(
        target = %apex,
        inspected_hosts = inspected_hosts,
        live_hosts = live_hosts,
        zombie_hosts = zombie_hosts,
        hard_dead_hosts = hard_dead_hosts,
        queued_new_hosts = queued_new_hosts,
        total_facts = facts.len(),
        site_profiles = site_profiles.len(),
        subdomains = subdomain_count,
        "discovery pass summary"
    );

    Ok(DiscoveryOutcome {
        facts,
        dead_hosts,
        site_profiles,
        subdomain_count,
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

fn canonical_host(value: &str) -> String {
    value.trim_end_matches('.').to_lowercase()
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

fn dedupe_signals(signals: Vec<String>) -> Vec<String> {
    text::dedupe_signals(signals)
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    text::dedupe_strings(values)
}

fn is_same_domain_or_subdomain(candidate: &str, apex: &str) -> bool {
    let candidate = canonical_host(candidate);
    let apex = canonical_host(apex);
    candidate == apex || candidate.ends_with(&format!(".{}", apex))
}

#[cfg(test)]
mod tests {
    use super::{SiteProfile, dedupe_strings};
    use crate::backend::CtSubdomainCacheEntry;
    use chrono::{Duration, Utc};

    use super::{
        ct::ct_cache_is_fresh,
        dns::{parse_host_cname_line, parse_host_mx_line, parse_host_txt_line},
        site::{classify_site, infer_mail_provider},
        surface::{
            SurfaceObservation, detect_surface_failure, is_api_endpoint_status,
            is_dav_endpoint_status, looks_like_website_body, should_probe_api_endpoints,
            should_probe_dav_endpoints, surface_is_psi_eligible,
        },
        text::extract_surface_hosts,
    };
    use crate::config::DiscoveryProbeConfig;

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

    #[test]
    fn dedupes_strings_preserving_first_occurrence() {
        assert_eq!(
            dedupe_strings(vec![
                "k2".to_string(),
                "k2".to_string(),
                "selector1".to_string(),
                "k2".to_string(),
            ]),
            vec!["k2".to_string(), "selector1".to_string()]
        );
    }

    #[test]
    fn ct_cache_freshness_honors_ttl() {
        let cache = CtSubdomainCacheEntry {
            domain: "example.com".to_string(),
            source: "crt.sh".to_string(),
            subdomains: vec!["a.example.com".to_string()],
            updated_at: Utc::now() - Duration::seconds(30),
        };

        assert!(ct_cache_is_fresh(&cache, 60));
        assert!(!ct_cache_is_fresh(&cache, 10));
    }

    #[test]
    fn api_endpoint_status_hints_are_conservative() {
        assert!(is_api_endpoint_status(200));
        assert!(is_api_endpoint_status(401));
        assert!(!is_api_endpoint_status(404));
        assert!(!is_api_endpoint_status(500));
    }

    #[test]
    fn dav_endpoint_status_hints_are_conservative() {
        assert!(is_dav_endpoint_status(200));
        assert!(is_dav_endpoint_status(401));
        assert!(is_dav_endpoint_status(405));
        assert!(!is_dav_endpoint_status(404));
        assert!(!is_dav_endpoint_status(500));
    }

    #[test]
    fn api_probe_skips_when_site_is_already_classified() {
        let profile = SiteProfile {
            host: "artisanhosting.net".to_string(),
            kind: "basic".to_string(),
            provider: Some("wordpress".to_string()),
            confidence: 0.9,
            signals: vec!["wordpress".to_string()],
        };

        assert!(!should_probe_api_endpoints(
            "zombie site: blank root response body",
            Some(&profile),
            true
        ));
    }

    #[test]
    fn api_probe_runs_for_weak_blank_sites() {
        let profile = SiteProfile {
            host: "artisanhosting.net".to_string(),
            kind: "basic".to_string(),
            provider: None,
            confidence: 0.62,
            signals: vec!["plain".to_string()],
        };

        assert!(should_probe_api_endpoints(
            "zombie site: blank root response body",
            Some(&profile),
            true
        ));
    }

    #[test]
    fn dav_probe_runs_for_weak_blank_sites() {
        let profile = SiteProfile {
            host: "artisanhosting.net".to_string(),
            kind: "basic".to_string(),
            provider: None,
            confidence: 0.62,
            signals: vec!["plain".to_string()],
        };

        assert!(should_probe_dav_endpoints(Some(&profile), true));
    }

    #[test]
    fn disabled_probes_do_not_run() {
        let profile = SiteProfile {
            host: "artisanhosting.net".to_string(),
            kind: "basic".to_string(),
            provider: None,
            confidence: 0.62,
            signals: vec!["plain".to_string()],
        };

        let probes = DiscoveryProbeConfig {
            api_endpoints: false,
            dav_endpoints: false,
        };

        assert!(!should_probe_api_endpoints(
            "zombie site: blank root response body",
            Some(&profile),
            probes.api_endpoints
        ));
        assert!(!should_probe_dav_endpoints(
            Some(&profile),
            probes.dav_endpoints
        ));
    }

    #[test]
    fn classifies_nextcloud_markers_as_dav() {
        let surface = SurfaceObservation {
            body: Some("nextcloud ocs/v2.php".to_string()),
            ..SurfaceObservation::default()
        };

        let profile = classify_site("files.artisanhosting.net", &surface, vec![])
            .expect("surface should classify");
        assert_eq!(profile.kind, "dav");
        assert_eq!(profile.provider.as_deref(), Some("nextcloud"));
    }

    #[test]
    fn extracts_bare_hostnames_from_surface_text() {
        let hosts = extract_surface_hosts(
            "api.artisanhosting.net dashboard.artisanhosting.net https://docs.artisanhosting.net foo.example.com",
            "artisanhosting.net",
        );

        assert!(hosts.contains("api.artisanhosting.net"));
        assert!(hosts.contains("dashboard.artisanhosting.net"));
        assert!(hosts.contains("docs.artisanhosting.net"));
        assert!(!hosts.contains("foo.example.com"));
    }
}
