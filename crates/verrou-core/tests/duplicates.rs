//! Doublons sur le coffre fictif, et garde-fou de performance.

use std::time::Instant;

use verrou_core::duplicates::{Confidence, find_duplicates};
use verrou_core::mock;

#[test]
fn the_mock_vault_has_no_duplicates() {
    // Nextcloud, Vaultwarden et Jellyfin : même domaine, même identifiant,
    // trois services. Deux comptes GitHub : deux identifiants.
    assert_eq!(find_duplicates(&mock::vault_items(0, 42)), Vec::new());
}

#[test]
fn duplicate_fixtures_survive_a_large_vault() {
    let mut items = mock::vault_items(2_000, 42);
    items.extend(mock::duplicate_items());
    let groups = find_duplicates(&items);
    let maif = groups
        .iter()
        .find(|g| g.members.iter().any(|m| m.id == "dup-0"))
        .unwrap();
    assert_eq!(maif.confidence, Confidence::Certain);
    assert_eq!(maif.members.len(), 4);
}

/// 10 000 éléments en moins de 200 ms (`cargo test --release -- --ignored`).
#[test]
#[ignore = "mesure de performance : à lancer en release"]
fn duplicates_are_fast() {
    let mut items = mock::vault_items(10_000, 7);
    items.extend(mock::duplicate_items());
    let _ = find_duplicates(&items);
    let started = Instant::now();
    let groups = find_duplicates(&items);
    let elapsed = started.elapsed();
    eprintln!(
        "{} éléments, {} groupes : {elapsed:?}",
        items.len(),
        groups.len()
    );
    assert!(elapsed.as_millis() < 200, "trop lent : {elapsed:?}");
}
