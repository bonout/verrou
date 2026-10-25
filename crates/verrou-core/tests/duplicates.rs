//! Duplicates on the mock vault, and a performance guard.

use std::time::Instant;

use verrou_core::duplicates::{Confidence, find_duplicates};
use verrou_core::mock::{self, MockLanguage};

const LANGUAGES: [MockLanguage; 5] = [
    MockLanguage::En,
    MockLanguage::Fr,
    MockLanguage::De,
    MockLanguage::Es,
    MockLanguage::It,
];

#[test]
fn the_mock_vault_has_no_duplicates() {
    // Nextcloud, Vaultwarden and Jellyfin: same domain, same username,
    // three services. Two GitHub accounts: two usernames.
    for language in LANGUAGES {
        assert_eq!(
            find_duplicates(&mock::vault_items(0, 42, language)),
            Vec::new()
        );
    }
}

#[test]
fn duplicate_fixtures_survive_a_large_vault() {
    for language in LANGUAGES {
        let mut items = mock::vault_items(2_000, 42, language);
        items.extend(mock::duplicate_items(language));
        let groups = find_duplicates(&items);
        let insurer = groups
            .iter()
            .find(|g| g.members.iter().any(|m| m.id == "dup-0"))
            .unwrap();
        assert_eq!(insurer.confidence, Confidence::Certain);
        assert_eq!(insurer.members.len(), 4);
    }
}

/// 10,000 items in under 200 ms (`cargo test --release -- --ignored`).
#[test]
#[ignore = "performance measurement: run in release"]
fn duplicates_are_fast() {
    let mut items = mock::vault_items(10_000, 7, MockLanguage::En);
    items.extend(mock::duplicate_items(MockLanguage::En));
    let _ = find_duplicates(&items);
    let started = Instant::now();
    let groups = find_duplicates(&items);
    let elapsed = started.elapsed();
    eprintln!(
        "{} items, {} groups: {elapsed:?}",
        items.len(),
        groups.len()
    );
    assert!(elapsed.as_millis() < 200, "too slow: {elapsed:?}");
}
