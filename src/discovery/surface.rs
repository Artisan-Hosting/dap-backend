//! Surface fetch and classification helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
    time::Instant,
};

use anyhow::{Context, Result};
use tracing::debug;

use super::{SiteProfile, dedupe_signals};

const FETCH_HEADERS_MAX_TIME_SECS: u64 = 2;
const FETCH_HEADERS_CONNECT_TIMEOUT_SECS: u64 = 2;
const FETCH_BODY_MAX_TIME_SECS: u64 = 2;
const FETCH_BODY_CONNECT_TIMEOUT_SECS: u64 = 2;

/// Low-risk API endpoints to try when a host looks alive but the root body is empty.
pub(super) const API_ENDPOINT_PROBES: &[&str] = &[
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/livez",
    "/status",
    "/ping",
    "/version",
    "/healthcheck",
    "/health-check",
    "/status.json",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/v1",
    "/v1/health",
    "/v1/status",
    "/graphql",
    "/actuator/health",
    "/actuator/info",
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/docs",
    "/api/health",
    "/api/status",
    "/.well-known/health",
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/metrics",
    "/server-status",
];

/// Low-risk WebDAV / CalDAV / CardDAV endpoints to try when a host looks like
/// a DAV-backed service or remains otherwise ambiguous.
pub(super) const DAV_ENDPOINT_PROBES: &[&str] = &[
    "/.well-known/caldav",
    "/.well-known/carddav",
    "/remote.php/dav",
    "/remote.php/dav/",
    "/remote.php/webdav",
    "/dav",
    "/dav/",
    "/webdav",
    "/webdav/",
    "/SOGo/dav",
    "/SOGo/dav/",
];

/// Container for a fetched surface snapshot.
#[derive(Debug, Default)]
pub(super) struct SurfaceObservation {
    pub(super) scheme: String,
    pub(super) status_code: Option<u16>,
    pub(super) headers_text: String,
    pub(super) body: Option<String>,
    pub(super) robots: Option<String>,
    pub(super) sitemap: Option<String>,
    pub(super) wp_sitemap: Option<String>,
    pub(super) content_type: Option<String>,
    pub(super) server_banner: Option<String>,
    pub(super) x_powered_by: Option<String>,
}

impl SurfaceObservation {
    pub(super) fn has_body(&self) -> bool {
        self.body
            .as_deref()
            .map(|body| !body.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Result from fetching headers.
#[derive(Debug, Default)]
struct HeaderFetch {
    raw: String,
    status_code: Option<u16>,
    headers: BTreeMap<String, String>,
}

#[derive(Debug)]
pub(super) struct ApiProbeResult {
    pub(super) endpoint: String,
    pub(super) status_code: u16,
    pub(super) content_type: Option<String>,
    pub(super) profile: SiteProfile,
    pub(super) new_hosts: BTreeSet<String>,
}

#[derive(Debug)]
pub(super) struct DavProbeResult {
    pub(super) endpoint: String,
    pub(super) status_code: u16,
    pub(super) content_type: Option<String>,
    pub(super) profile: SiteProfile,
    pub(super) new_hosts: BTreeSet<String>,
}

/// Fetch a small passive snapshot of a host.
pub(super) fn fetch_surface(host: &str) -> Result<SurfaceObservation> {
    let scheme = resolve_reachable_scheme(host).unwrap_or("https");
    debug!(host = %host, scheme = %scheme, "fetching passive surface snapshot");
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
pub(super) fn resolve_reachable_scheme(host: &str) -> Option<&'static str> {
    debug!(host = %host, "resolving reachable scheme");
    match super::dns::probe_https(host) {
        super::dns::ProbeResult::Success => {
            debug!(host = %host, scheme = "https", "reachable scheme detected");
            Some("https")
        }
        super::dns::ProbeResult::Failure(reason) => {
            debug!(host = %host, scheme = "https", reason = %reason, "https probe failed, trying http");
            match super::dns::probe_http(host) {
                super::dns::ProbeResult::Success => {
                    debug!(host = %host, scheme = "http", "reachable scheme detected");
                    Some("http")
                }
                super::dns::ProbeResult::Failure(reason) => {
                    debug!(host = %host, scheme = "http", reason = %reason, "http probe failed");
                    None
                }
            }
        }
    }
}

/// Fetch response headers for a path.
fn fetch_headers(host: &str, scheme: &str, path: &str) -> Result<HeaderFetch> {
    let url = format!("{scheme}://{host}{path}");
    let started_at = Instant::now();
    debug!(
        host = %host,
        scheme = %scheme,
        path = %path,
        max_time_secs = FETCH_HEADERS_MAX_TIME_SECS,
        connect_timeout_secs = FETCH_HEADERS_CONNECT_TIMEOUT_SECS,
        "fetching headers"
    );
    let output = Command::new("curl")
        .arg("-sSIL")
        .arg("--max-time")
        .arg(FETCH_HEADERS_MAX_TIME_SECS.to_string())
        .arg("--connect-timeout")
        .arg(FETCH_HEADERS_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--insecure")
        .arg("--location")
        .arg(url)
        .output()
        .with_context(|| format!("failed to fetch headers for {host}{path}"))?;

    if !output.status.success() {
        debug!(
            host = %host,
            scheme = %scheme,
            path = %path,
            elapsed_ms = started_at.elapsed().as_millis(),
            status = ?output.status.code(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "failed to fetch headers"
        );
        return Ok(HeaderFetch::default());
    }

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let status_code = parse_status_code(&raw);
    let headers = parse_headers(&raw);
    debug!(
        host = %host,
        scheme = %scheme,
        path = %path,
        elapsed_ms = started_at.elapsed().as_millis(),
        status_code = ?status_code,
        header_count = headers.len(),
        "finished fetching headers"
    );
    Ok(HeaderFetch {
        raw,
        status_code,
        headers,
    })
}

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

/// Fetch response body for a path.
fn fetch_body(host: &str, scheme: &str, path: &str) -> Result<Option<String>> {
    let url = format!("{scheme}://{host}{path}");
    let started_at = Instant::now();
    debug!(
        host = %host,
        scheme = %scheme,
        path = %path,
        max_time_secs = FETCH_BODY_MAX_TIME_SECS,
        connect_timeout_secs = FETCH_BODY_CONNECT_TIMEOUT_SECS,
        "fetching body"
    );
    let output = Command::new("curl")
        .arg("-sSL")
        .arg("--max-time")
        .arg(FETCH_BODY_MAX_TIME_SECS.to_string())
        .arg("--connect-timeout")
        .arg(FETCH_BODY_CONNECT_TIMEOUT_SECS.to_string())
        .arg("--insecure")
        .arg("--location")
        .arg(url)
        .output()
        .with_context(|| format!("failed to fetch body for {host}{path}"))?;

    if !output.status.success() {
        debug!(
            host = %host,
            scheme = %scheme,
            path = %path,
            elapsed_ms = started_at.elapsed().as_millis(),
            status = ?output.status.code(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "failed to fetch body"
        );
        return Ok(None);
    }

    let body = String::from_utf8_lossy(&output.stdout).to_string();
    debug!(
        host = %host,
        scheme = %scheme,
        path = %path,
        elapsed_ms = started_at.elapsed().as_millis(),
        bytes = body.len(),
        "finished fetching body"
    );
    Ok(Some(body))
}

pub(super) fn detect_surface_failure(surface: &SurfaceObservation) -> Option<String> {
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

pub(super) fn should_probe_api_endpoints(reason: &str, profile: Option<&SiteProfile>) -> bool {
    reason == "zombie site: blank root response body"
        && !profile
            .map(super::site::is_strong_site_profile)
            .unwrap_or(false)
}

pub(super) fn should_probe_dav_endpoints(profile: Option<&SiteProfile>) -> bool {
    !profile
        .map(super::site::is_strong_site_profile)
        .unwrap_or(false)
}

pub(super) fn probe_api_endpoints(
    host: &str,
    scheme: &str,
    apex: &str,
) -> Result<Option<ApiProbeResult>> {
    debug!(
        target = %apex,
        host = %host,
        scheme = %scheme,
        endpoint_count = API_ENDPOINT_PROBES.len(),
        "starting api endpoint probing"
    );
    for endpoint in API_ENDPOINT_PROBES {
        debug!(
            target = %apex,
            host = %host,
            scheme = %scheme,
            endpoint = *endpoint,
            "probing api endpoint headers"
        );
        let headers = fetch_headers(host, scheme, endpoint)?;
        let Some(status_code) = headers.status_code else {
            debug!(
                target = %apex,
                host = %host,
                endpoint = *endpoint,
                "api endpoint returned no status code"
            );
            continue;
        };

        if !is_api_endpoint_status(status_code) {
            debug!(
                target = %apex,
                host = %host,
                endpoint = *endpoint,
                status_code = status_code,
                "api endpoint skipped by status filter"
            );
            continue;
        }

        debug!(
            target = %apex,
            host = %host,
            endpoint = *endpoint,
            status_code = status_code,
            "api endpoint matched status filter"
        );
        let body = fetch_body(host, scheme, endpoint)?;
        let mut signals = vec![
            "api-endpoint".to_string(),
            format!("endpoint:{endpoint}"),
            format!("status:{status_code}"),
        ];
        let mut new_hosts = BTreeSet::new();

        if let Some(content_type) = headers.headers.get("content-type") {
            signals.push(format!("content-type:{}", content_type.to_lowercase()));
        }

        for extracted in super::text::extract_surface_hosts(&headers.raw, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }

        if let Some(ref body) = body {
            signals.extend(super::text::extract_signals(body));
            for extracted in super::text::extract_surface_hosts(body, apex) {
                if extracted != host && extracted != apex {
                    new_hosts.insert(extracted);
                }
            }
        }

        debug!(
            target = %apex,
            host = %host,
            endpoint = *endpoint,
            discovered_hosts = new_hosts.len(),
            "api endpoint probe produced result"
        );

        return Ok(Some(ApiProbeResult {
            endpoint: (*endpoint).to_string(),
            status_code,
            content_type: headers.headers.get("content-type").cloned(),
            profile: SiteProfile {
                host: host.to_string(),
                kind: "api".to_string(),
                provider: Some(endpoint.trim_start_matches('/').to_string()),
                confidence: 0.9,
                signals: super::dedupe_signals(signals),
            },
            new_hosts,
        }));
    }

    Ok(None)
}

pub(super) fn is_api_endpoint_status(status_code: u16) -> bool {
    matches!(status_code, 200 | 204 | 301 | 302 | 307 | 308 | 401 | 403)
}

pub(super) fn probe_dav_endpoints(
    host: &str,
    scheme: &str,
    apex: &str,
) -> Result<Option<DavProbeResult>> {
    debug!(
        target = %apex,
        host = %host,
        scheme = %scheme,
        endpoint_count = DAV_ENDPOINT_PROBES.len(),
        "starting dav endpoint probing"
    );
    for endpoint in DAV_ENDPOINT_PROBES {
        debug!(
            target = %apex,
            host = %host,
            scheme = %scheme,
            endpoint = *endpoint,
            "probing dav endpoint headers"
        );
        let headers = fetch_headers(host, scheme, endpoint)?;
        let Some(status_code) = headers.status_code else {
            debug!(
                target = %apex,
                host = %host,
                endpoint = *endpoint,
                "dav endpoint returned no status code"
            );
            continue;
        };

        if !is_dav_endpoint_status(status_code) {
            debug!(
                target = %apex,
                host = %host,
                endpoint = *endpoint,
                status_code = status_code,
                "dav endpoint skipped by status filter"
            );
            continue;
        }

        debug!(
            target = %apex,
            host = %host,
            endpoint = *endpoint,
            status_code = status_code,
            "dav endpoint matched status filter"
        );
        let body = fetch_body(host, scheme, endpoint)?;
        let mut signals = vec![
            "dav-endpoint".to_string(),
            format!("endpoint:{endpoint}"),
            format!("status:{status_code}"),
        ];
        let mut new_hosts = BTreeSet::new();

        if let Some(content_type) = headers.headers.get("content-type") {
            signals.push(format!("content-type:{}", content_type.to_lowercase()));
        }

        for extracted in super::text::extract_surface_hosts(&headers.raw, apex) {
            if extracted != host && extracted != apex {
                new_hosts.insert(extracted);
            }
        }

        if let Some(ref body) = body {
            signals.extend(super::text::extract_signals(body));
            for extracted in super::text::extract_surface_hosts(body, apex) {
                if extracted != host && extracted != apex {
                    new_hosts.insert(extracted);
                }
            }
        }

        let profile = classify_dav_profile(host, endpoint, &headers.raw, body.as_deref(), signals);
        debug!(
            target = %apex,
            host = %host,
            endpoint = *endpoint,
            discovered_hosts = new_hosts.len(),
            "dav endpoint probe produced result"
        );

        return Ok(Some(DavProbeResult {
            endpoint: (*endpoint).to_string(),
            status_code,
            content_type: headers.headers.get("content-type").cloned(),
            profile,
            new_hosts,
        }));
    }

    Ok(None)
}

pub(super) fn is_dav_endpoint_status(status_code: u16) -> bool {
    matches!(status_code, 200 | 301 | 302 | 307 | 308 | 401 | 403 | 405)
}

fn classify_dav_profile(
    host: &str,
    endpoint: &str,
    headers_text: &str,
    body: Option<&str>,
    mut signals: Vec<String>,
) -> SiteProfile {
    let mut combined = String::new();
    combined.push_str(host);
    combined.push('\n');
    combined.push_str(endpoint);
    combined.push('\n');
    combined.push_str(&headers_text.to_lowercase());
    combined.push('\n');
    if let Some(body) = body {
        combined.push_str(&body.to_lowercase());
    }

    if let Some((provider, provider_signals)) = detect_dav_provider(&combined, Some(endpoint)) {
        signals.extend(provider_signals);
        return SiteProfile {
            host: host.to_string(),
            kind: "dav".to_string(),
            provider: Some(provider),
            confidence: 0.92,
            signals: dedupe_signals(signals),
        };
    }

    SiteProfile {
        host: host.to_string(),
        kind: "dav".to_string(),
        provider: Some("dav".to_string()),
        confidence: 0.84,
        signals: dedupe_signals(signals),
    }
}

pub(super) fn surface_is_psi_eligible(surface: &SurfaceObservation) -> bool {
    looks_like_website_body(
        surface.body.as_deref().unwrap_or(""),
        surface.content_type.as_deref().unwrap_or(""),
    )
}

pub(super) fn looks_like_website_body(body: &str, content_type: &str) -> bool {
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
        let signals = super::text::markers_to_signals(combined, provider, markers);
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
