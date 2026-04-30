use artisan_dap::{
    backend::{BackendConfig, test_support},
    config::DiscoveryProbeConfig,
};

#[test]
fn internal_probe_tests_follow_config_toggles() {
    let mut config = BackendConfig::default();
    config.engine.discovery_probes = DiscoveryProbeConfig {
        api_endpoints: true,
        dav_endpoints: true,
    };

    let (visible, default_requested) = test_support::capability_registry_ids(&config);
    assert!(visible.contains(&"discovery_api_probe".to_string()));
    assert!(visible.contains(&"discovery_dav_probe".to_string()));
    assert!(!default_requested.contains(&"discovery_api_probe".to_string()));
    assert!(!default_requested.contains(&"discovery_dav_probe".to_string()));

    config.engine.discovery_probes = DiscoveryProbeConfig {
        api_endpoints: false,
        dav_endpoints: false,
    };

    let (visible, default_requested) = test_support::capability_registry_ids(&config);
    assert!(!visible.contains(&"discovery_api_probe".to_string()));
    assert!(!visible.contains(&"discovery_dav_probe".to_string()));
    assert!(default_requested.is_empty());
}

#[test]
fn enabled_tests_filter_can_limit_visible_internal_probes() {
    let mut config = BackendConfig::default();
    config.engine.discovery_probes = DiscoveryProbeConfig {
        api_endpoints: true,
        dav_endpoints: true,
    };
    config.engine.enabled_tests = vec!["discovery_api_probe".to_string()];

    let (visible, _default_requested) = test_support::capability_registry_ids(&config);
    assert_eq!(visible, vec!["discovery_api_probe".to_string()]);
}
