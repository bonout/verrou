//! Search behaviour on the mock vault.

#![allow(clippy::assert_is_empty)]

use std::time::Instant;

use verrou_core::mock::{self, MockLanguage};
use verrou_core::{Filter, ItemKind, Sort, Vault};

fn vault() -> Vault {
    Vault::new(mock::vault_items(0, 42, MockLanguage::En))
}

fn french_vault() -> Vault {
    Vault::new(mock::vault_items(0, 42, MockLanguage::Fr))
}

fn titles(vault: &Vault, query: &str, filter: &Filter) -> Vec<String> {
    vault
        .search(query, filter, Sort::Relevance)
        .iter()
        .map(|hit| vault.items()[hit.index].title.clone())
        .collect()
}

#[test]
fn exact_title_comes_first() {
    let v = vault();
    let results = titles(&v, "github", &Filter::All);
    assert_eq!(results[0], "GitHub");
    assert!(results.contains(&"GitHub — work account".to_owned()));
}

#[test]
fn accents_and_case_are_ignored() {
    let v = french_vault();
    assert_eq!(
        titles(&v, "societe generale", &Filter::All)[0],
        "Société Générale"
    );
    assert_eq!(titles(&v, "IMPOTS", &Filter::All)[0], "Impôts");
}

#[test]
fn hosts_and_usernames_are_searchable() {
    let v = vault();
    assert_eq!(
        titles(&v, "kaiserpermanente", &Filter::All)[0],
        "Kaiser Permanente"
    );
    assert!(titles(&v, "emily-work", &Filter::All).contains(&"GitHub — work account".to_owned()));
    let fr = french_vault();
    assert_eq!(titles(&fr, "boursobank", &Filter::All)[0], "Boursorama");
}

#[test]
fn fuzzy_abbreviations_match() {
    let v = vault();
    assert_eq!(titles(&v, "amtrk", &Filter::All)[0], "Amtrak");
    assert_eq!(
        titles(&french_vault(), "sncf", &Filter::All)[0],
        "SNCF Connect"
    );
    assert!(titles(&v, "gthb", &Filter::All).contains(&"GitHub".to_owned()));
}

#[test]
fn every_word_must_match_somewhere() {
    let v = vault();
    let results = titles(&v, "github account", &Filter::All);
    assert_eq!(results[0], "GitHub — work account");
}

#[test]
fn secrets_are_not_indexed() {
    let v = vault();
    let github = v.items().iter().find(|i| i.title == "GitHub").unwrap();
    let password = github.field("password").unwrap().value.expose().to_owned();
    let hits = v.search(&password, &Filter::All, Sort::Relevance);
    assert!(hits.iter().all(|h| v.items()[h.index].title != "GitHub"));
    // Nor the body of notes.
    assert!(titles(&v, "Parker-5G", &Filter::All).is_empty());
}

#[test]
fn filters_and_inline_filters() {
    let v = vault();
    let cards = titles(&v, "", &Filter::Kind(ItemKind::Card));
    assert_eq!(cards.len(), 3);
    let banks = titles(&v, "tag:bank", &Filter::All);
    assert!(banks.contains(&"Chase".to_owned()));
    assert!(banks.iter().all(|t| !t.contains("GitHub")));
    let homelab = titles(&v, "folder:home", &Filter::Favorites);
    assert!(homelab.contains(&"Vaultwarden".to_owned()));
    assert_eq!(titles(&v, "dossier:home", &Filter::Favorites), homelab);
    let typed = titles(&v, "type:carte visa", &Filter::All);
    assert_eq!(typed, vec!["Chase Visa".to_owned()]);
    assert_eq!(titles(&v, "type:card visa", &Filter::All), typed);
    assert_eq!(
        titles(&v, "type:login", &Filter::All),
        titles(&v, "type:identifiant", &Filter::All)
    );
    let excluded = titles(&v, "github !emily-work", &Filter::All);
    assert!(excluded.contains(&"GitHub".to_owned()));
    assert!(!excluded.contains(&"GitHub — work account".to_owned()));
    // The French vault: French tags and folders.
    let fr = french_vault();
    assert!(titles(&fr, "tag:banque", &Filter::All).contains(&"Boursorama".to_owned()));
    assert!(titles(&fr, "dossier:maison", &Filter::Favorites).contains(&"Vaultwarden".to_owned()));
}

#[test]
fn empty_query_is_alphabetical_and_title_highlights_are_reported() {
    let v = vault();
    let all = titles(&v, "", &Filter::All);
    let mut sorted = all.clone();
    sorted.sort_by_key(|t| t.to_lowercase());
    assert_eq!(all.len(), v.len());
    assert_eq!(all.first(), sorted.first());
    let hit = &v.search("hub", &Filter::All, Sort::Relevance)[0];
    assert!(!hit.title_indices.is_empty());
}

#[test]
fn site_suggestions() {
    let v = vault();
    let suggested: Vec<_> = v
        .suggestions_for("https://github.com/login")
        .iter()
        .map(|i| i.title.clone())
        .collect();
    assert_eq!(suggested[0], "GitHub");
    assert!(suggested.contains(&"GitHub — work account".to_owned()));
    assert!(
        v.suggestions_for("https://github-login.evil.example")
            .is_empty()
    );
}

#[test]
fn app_suggestions_use_macapp_uris() {
    let v = vault();
    let suggested: Vec<_> = v
        .app_suggestions("com.tinyspeck.slackmacgap")
        .iter()
        .map(|i| i.title.clone())
        .collect();
    assert_eq!(suggested, ["Slack"]);
    assert!(v.app_suggestions("com.apple.Terminal").is_empty());
    assert!(v.app_suggestions("").is_empty());
    // An app address is not a site: no host, no web suggestion.
    let slack = v.items().iter().find(|i| i.title == "Slack").unwrap();
    assert_eq!(slack.primary_host().as_deref(), Some("slack.com"));
    assert!(
        v.suggestions_for("https://com.tinyspeck.slackmacgap")
            .is_empty()
    );
}

/// Performance guard, optimized builds only: 10,000 items,
/// a keystroke must stay well under one frame at 60 Hz.
/// Opening the vault builds its search index: on 10,000 items, it must
/// stay far below what a user notices after Touch ID.
#[test]
#[cfg_attr(debug_assertions, ignore = "measurement only meaningful in --release")]
fn vault_opens_fast_on_10k_items() {
    let items = mock::vault_items(10_000, 7, MockLanguage::En);
    let start = Instant::now();
    let v = Vault::new(items);
    let elapsed = start.elapsed();
    assert_eq!(v.len(), 10_000);
    eprintln!("index of 10,000 items: {elapsed:?}");
    assert!(elapsed.as_millis() < 150, "{elapsed:?} to open");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "measurement only meaningful in --release")]
fn search_is_fast_on_10k_items() {
    let v = Vault::new(mock::vault_items(10_000, 7, MockLanguage::En));
    let queries = [
        "g",
        "gi",
        "git",
        "gith",
        "githu",
        "github",
        "github pro",
        "emily",
        "zzzz",
    ];
    let start = Instant::now();
    for q in queries {
        let _ = v.search(q, &Filter::All, Sort::Relevance);
    }
    let per_query = start.elapsed() / queries.len() as u32;
    assert!(per_query.as_millis() < 16, "{per_query:?} per query");
}

#[test]
fn a_folder_holds_its_subfolders() {
    let mut items = mock::vault_items(0, 42, MockLanguage::En);
    items[0].folder = Some("Work/Clients/Acme".to_owned());
    items[1].folder = Some("Work".to_owned());
    items[2].folder = Some("Workshop".to_owned());
    let (client, own, other) = (
        items[0].title.clone(),
        items[1].title.clone(),
        items[2].title.clone(),
    );
    let v = Vault::new(items);
    let work = titles(&v, "", &Filter::Folder("work".to_owned()));
    assert!(work.contains(&client) && work.contains(&own));
    assert!(!work.contains(&other), "Workshop isn't inside Work");
    assert_eq!(
        titles(&v, "", &Filter::Folder("Work/Clients".to_owned())),
        vec![client]
    );
}

fn vault_with_passkeys() -> Vault {
    let items = mock::vault_items(0, 42, MockLanguage::En);
    let passkeys = mock::passkeys(&items, MockLanguage::En);
    Vault::new(items).with_passkeys(passkeys)
}

#[test]
fn passkey_keyword_and_filter() {
    let v = vault_with_passkeys();
    let mut expected = vec![
        "Apple ID".to_owned(),
        "GitHub".to_owned(),
        "Google".to_owned(),
    ];
    expected.sort();
    for query in [
        "passkey:",
        "has:passkey",
        "PASSKEY:",
        "with:passkey",
        "avec:passkey",
    ] {
        let mut found = titles(&v, query, &Filter::All);
        found.sort();
        assert_eq!(found, expected, "{query}");
    }
    let mut filtered = titles(&v, "", &Filter::Passkeys);
    filtered.sort();
    assert_eq!(filtered, expected);
    assert_eq!(v.counts().passkeys, 3);
    // By passkey site, and combined with a word.
    assert_eq!(titles(&v, "passkey:github", &Filter::All), vec!["GitHub"]);
    assert_eq!(titles(&v, "passkey:google", &Filter::All), vec!["Google"]);
    assert_eq!(titles(&v, "passkey: apple", &Filter::All), vec!["Apple ID"]);
    assert!(titles(&v, "passkey:netflix", &Filter::All).is_empty());
    // No known passkeys: nothing.
    assert!(titles(&vault(), "has:passkey", &Filter::All).is_empty());
    // `has:totp` and an unknown `has:` (searched as a word).
    assert!(titles(&v, "has:totp github", &Filter::All).contains(&"GitHub".to_owned()));
    assert!(titles(&v, "has:inconnu", &Filter::All).is_empty());
}

#[test]
fn sort_by_creation_and_last_use() {
    let v = vault();
    let hits = v.search("", &Filter::All, Sort::Created);
    let created: Vec<i64> = hits.iter().map(|h| v.items()[h.index].created).collect();
    assert!(created.windows(2).all(|w| w[0] >= w[1]));

    let netflix = v.items().iter().find(|i| i.title == "Netflix").unwrap();
    let github = v.items().iter().find(|i| i.title == "GitHub").unwrap();
    let usage =
        std::collections::HashMap::from([(github.id.clone(), 100), (netflix.id.clone(), 200)]);
    let hits = v.search_with_usage("", &Filter::All, Sort::LastUsed, &usage);
    let order: Vec<&str> = hits
        .iter()
        .map(|h| v.items()[h.index].title.as_str())
        .collect();
    assert_eq!(&order[..2], &["Netflix", "GitHub"]);
    // The others follow, in alphabetical order.
    let by_title: Vec<&str> = v
        .search("", &Filter::All, Sort::Title)
        .iter()
        .map(|h| v.items()[h.index].title.as_str())
        .filter(|t| !["Netflix", "GitHub"].contains(t))
        .collect();
    assert_eq!(&order[2..], &by_title[..]);
    // With a query: only the results, in the same order.
    let hits = v.search_with_usage("git", &Filter::All, Sort::LastUsed, &usage);
    assert_eq!(v.items()[hits[0].index].title, "GitHub");
}
