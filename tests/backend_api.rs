use artisan_dap::{Fact, backend::test_support};

#[test]
fn normalizes_valid_targets() {
    let target = test_support::normalize_target_parts(" API.ArtisanHosting.Net. ")
        .expect("target should normalize");
    assert_eq!(target.0, "API.ArtisanHosting.Net");
    assert_eq!(target.1, "api.artisanhosting.net");
}

#[test]
fn rejects_url_targets() {
    let err = test_support::normalize_target_parts("https://artisanhosting.net/path")
        .expect_err("url must fail");
    assert_eq!(err, axum::http::StatusCode::BAD_REQUEST);
}

#[test]
fn dedupes_requested_tests_preserving_order() {
    let tests = test_support::dedupe_test_ids(&[
        "web_hsts".to_string(),
        " web_hsts ".to_string(),
        "dns_dmarc_policy".to_string(),
    ]);
    assert_eq!(tests, vec!["web_hsts", "dns_dmarc_policy"]);
}

#[test]
fn derive_execution_target_prefers_first_fact_target() {
    let facts = vec![Fact::with_attrs(
        "www.example.com",
        "web_service",
        "web:https://www.example.com",
        [("host", serde_json::json!("www.example.com"))],
    )];

    let target = test_support::derive_execution_target_for_test(&facts, "example.com");
    assert_eq!(target, "www.example.com");
}

#[test]
fn derive_execution_target_falls_back_when_facts_are_empty() {
    let target = test_support::derive_execution_target_for_test(&[], "example.com");
    assert_eq!(target, "example.com");
}
