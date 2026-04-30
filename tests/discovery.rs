use artisan_dap::{
    RunConfig,
    config::{DiscoveryConfig, DiscoveryProbeConfig, ReportConfig, ScopeConfig, ScopeMode},
    discovery::{
        SiteProfile,
        test_support::{self, SurfaceFixture},
    },
};

fn run_config(include: Vec<&str>, exclude: Vec<&str>) -> RunConfig {
    RunConfig {
        domain: "artisanhosting.net".to_string(),
        include: include.into_iter().map(str::to_string).collect(),
        exclude: exclude.into_iter().map(str::to_string).collect(),
        scope: ScopeConfig {
            mode: ScopeMode::DomainSweep,
            site: None,
        },
        discovery: DiscoveryConfig::default(),
        discovery_probes: DiscoveryProbeConfig::default(),
        psi: None,
        execution: Default::default(),
        report: ReportConfig::default(),
    }
}

#[test]
fn detects_google_workspace_mx_provider() {
    let provider =
        test_support::infer_mail_provider(&["aspmx.l.google.com".to_string()], "example.com");
    assert_eq!(provider.as_deref(), Some("google-workspace"));
}

#[test]
fn marks_blank_html_shell_as_zombie() {
    let surface = SurfaceFixture {
        scheme: "https".to_string(),
        status_code: Some(200),
        content_type: Some("text/html".to_string()),
        body: Some("<html><body></body></html>".to_string()),
    };

    assert_eq!(
        test_support::detect_surface_failure(surface.clone()).as_deref(),
        Some("zombie site: HTML shell without real page content")
    );
    assert!(!test_support::surface_is_psi_eligible(surface));
}

#[test]
fn html_app_shell_is_psi_eligible() {
    let body = "<!doctype html><html><head><title>Site</title></head><body><div id=\"root\"></div><script src=\"/app.js\"></script></body></html>";
    assert!(test_support::looks_like_website_body(
        body,
        "text/html; charset=utf-8"
    ));
}

#[test]
fn json_api_body_is_not_psi_eligible() {
    assert!(!test_support::looks_like_website_body(
        "{\"status\":\"ok\"}",
        "application/json"
    ));
}

#[test]
fn parses_host_txt_lines() {
    assert_eq!(
        test_support::parse_host_txt_line(
            "_dmarc.example.com descriptive text \"v=DMARC1; p=quarantine;\\010rua=mailto:test@example.com\""
        )
        .as_deref(),
        Some("v=dmarc1; p=quarantine; rua=mailto:test@example.com")
    );
}

#[test]
fn parses_host_mx_lines() {
    assert_eq!(
        test_support::parse_host_mx_line("example.com mail is handled by 10 mail.example.net.")
            .as_deref(),
        Some("10 mail.example.net")
    );
}

#[test]
fn parses_host_cname_lines() {
    assert_eq!(
        test_support::parse_host_cname_line("www.example.com is an alias for proxy.example.net.")
            .as_deref(),
        Some("proxy.example.net")
    );
}

#[test]
fn dedupes_strings_preserving_first_occurrence() {
    assert_eq!(
        test_support::dedupe_strings(vec![
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
    assert!(test_support::ct_cache_is_fresh(60, 30));
    assert!(!test_support::ct_cache_is_fresh(10, 30));
}

#[test]
fn api_endpoint_status_hints_are_conservative() {
    assert!(test_support::is_api_endpoint_status(200));
    assert!(test_support::is_api_endpoint_status(401));
    assert!(!test_support::is_api_endpoint_status(404));
    assert!(!test_support::is_api_endpoint_status(500));
}

#[test]
fn dav_endpoint_status_hints_are_conservative() {
    assert!(test_support::is_dav_endpoint_status(200));
    assert!(test_support::is_dav_endpoint_status(401));
    assert!(test_support::is_dav_endpoint_status(405));
    assert!(!test_support::is_dav_endpoint_status(404));
    assert!(!test_support::is_dav_endpoint_status(500));
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

    assert!(!test_support::should_probe_api_endpoints(
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

    assert!(test_support::should_probe_api_endpoints(
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

    assert!(test_support::should_probe_dav_endpoints(
        Some(&profile),
        true
    ));
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

    assert!(!test_support::should_probe_api_endpoints(
        "zombie site: blank root response body",
        Some(&profile),
        false
    ));
    assert!(!test_support::should_probe_dav_endpoints(
        Some(&profile),
        false
    ));
}

#[test]
fn classifies_nextcloud_markers_as_dav() {
    let profile = test_support::classify_site(
        "files.artisanhosting.net",
        Some("nextcloud ocs/v2.php"),
        None,
    )
    .expect("surface should classify");

    assert_eq!(profile.kind, "dav");
    assert_eq!(profile.provider.as_deref(), Some("nextcloud"));
}

#[test]
fn extracts_bare_hostnames_from_surface_text() {
    let hosts = test_support::extract_surface_hosts_for(
        "api.artisanhosting.net dashboard.artisanhosting.net https://docs.artisanhosting.net foo.example.com",
        "artisanhosting.net",
    );

    assert!(hosts.contains("api.artisanhosting.net"));
    assert!(hosts.contains("dashboard.artisanhosting.net"));
    assert!(hosts.contains("docs.artisanhosting.net"));
    assert!(!hosts.contains("foo.example.com"));
}

#[test]
fn matches_pattern_supports_wildcards() {
    assert!(test_support::matches_pattern(
        "*.artisanhosting.net",
        "api.artisanhosting.net"
    ));
    assert!(test_support::matches_pattern(
        "*.artisanhosting.net",
        "artisanhosting.net"
    ));
    assert!(!test_support::matches_pattern(
        "*.artisanhosting.net",
        "example.com"
    ));
}

#[test]
fn normalize_hostname_appends_apex_for_bare_labels() {
    assert_eq!(
        test_support::normalize_hostname("api", "artisanhosting.net"),
        "api.artisanhosting.net"
    );
}

#[test]
fn is_host_in_scope_respects_exclusions() {
    let cfg = run_config(
        vec!["*.artisanhosting.net"],
        vec!["beta.artisanhosting.net"],
    );
    assert!(test_support::is_host_in_scope(
        "api.artisanhosting.net",
        &cfg,
        "artisanhosting.net"
    ));
    assert!(!test_support::is_host_in_scope(
        "beta.artisanhosting.net",
        &cfg,
        "artisanhosting.net"
    ));
}
