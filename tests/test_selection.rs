use artisan_dap::tests::{runs_in_late_phase, runs_on_dead_host};

#[test]
fn web_api_fuzz_is_deferred() {
    assert!(runs_in_late_phase("web_api_fuzz"));
    assert!(!runs_in_late_phase("web_hsts"));
}

#[test]
fn dead_host_bypass_list_stays_narrow() {
    assert!(runs_on_dead_host("web_well_known"));
    assert!(runs_on_dead_host("web_api_fuzz"));
    assert!(!runs_on_dead_host("web_hsts"));
}
