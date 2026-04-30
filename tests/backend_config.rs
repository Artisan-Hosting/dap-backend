use artisan_dap::{
    backend::BackendConfig,
    config::{DiscoveryProbeConfig, ExecutionConfig, ScopeMode},
};

#[test]
fn execution_config_defaults_cap_total_concurrent_tests() {
    assert_eq!(ExecutionConfig::default().max_concurrent_tests, 10);
}

#[test]
fn scope_mode_for_hostname_forces_single_site() {
    let config = BackendConfig::default();
    assert_eq!(
        config.scope_mode_for_target("api.artisanhosting.net"),
        ScopeMode::SingleSite
    );
}

#[test]
fn audit_config_for_target_only_enables_requested_discovery_probes() {
    let mut config = BackendConfig::default();
    config.engine.discovery_probes = DiscoveryProbeConfig {
        api_endpoints: true,
        dav_endpoints: true,
    };

    let run_config = config.audit_config_for_target(
        "artisanhosting.net",
        &["discovery_dav_probe".to_string()],
    );
    assert!(!run_config.discovery_probes.api_endpoints);
    assert!(run_config.discovery_probes.dav_endpoints);
}

#[test]
fn audit_config_for_apex_uses_domain_sweep_scope() {
    let config = BackendConfig::default();
    let run_config = config.audit_config_for_target("artisanhosting.net", &[]);
    assert_eq!(run_config.scope.mode, ScopeMode::DomainSweep);
    assert!(run_config.scope.site.is_none());
}

#[test]
fn audit_config_for_target_disables_internal_probes_when_not_requested() {
    let config = BackendConfig::default();
    let run_config = config.audit_config_for_target("artisanhosting.net", &[]);
    assert!(!run_config.discovery_probes.api_endpoints);
    assert!(!run_config.discovery_probes.dav_endpoints);
}
