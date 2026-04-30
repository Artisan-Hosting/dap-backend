use artisan_dap::backend::test_support;

#[test]
fn dedupe_by_key_preserves_first_item_for_each_key() {
    let values =
        test_support::storage_dedupe_entries(&[("a", 1), ("a", 2), ("b", 3), ("c", 4), ("b", 5)]);

    assert_eq!(values, vec![1, 3, 4]);
}

#[test]
fn dedupe_strings_preserves_first_item_for_each_value() {
    let deduped = test_support::storage_dedupe_strings(vec![
        "a.example.com".to_string(),
        "a.example.com".to_string(),
        "b.example.com".to_string(),
    ]);

    assert_eq!(
        deduped,
        vec!["a.example.com".to_string(), "b.example.com".to_string()]
    );
}
