//! Comportement de la recherche sur le coffre fictif.

#![allow(clippy::assert_is_empty)]

use std::time::Instant;

use verrou_core::{Filter, ItemKind, Sort, Vault, mock};

fn vault() -> Vault {
    Vault::new(mock::vault_items(0, 42))
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
    assert!(results.contains(&"GitHub — compte pro".to_owned()));
}

#[test]
fn accents_and_case_are_ignored() {
    let v = vault();
    assert_eq!(
        titles(&v, "societe generale", &Filter::All)[0],
        "Société Générale"
    );
    assert_eq!(titles(&v, "IMPOTS", &Filter::All)[0], "Impôts");
}

#[test]
fn hosts_and_usernames_are_searchable() {
    let v = vault();
    assert_eq!(titles(&v, "boursobank", &Filter::All)[0], "Boursorama");
    assert!(titles(&v, "camille-pro", &Filter::All).contains(&"GitHub — compte pro".to_owned()));
}

#[test]
fn fuzzy_abbreviations_match() {
    let v = vault();
    assert_eq!(titles(&v, "sncf", &Filter::All)[0], "SNCF Connect");
    assert!(titles(&v, "gthb", &Filter::All).contains(&"GitHub".to_owned()));
}

#[test]
fn every_word_must_match_somewhere() {
    let v = vault();
    let results = titles(&v, "github pro", &Filter::All);
    assert_eq!(results[0], "GitHub — compte pro");
}

#[test]
fn secrets_are_not_indexed() {
    let v = vault();
    let github = v.items().iter().find(|i| i.title == "GitHub").unwrap();
    let password = github.field("password").unwrap().value.expose().to_owned();
    let hits = v.search(&password, &Filter::All, Sort::Relevance);
    assert!(hits.iter().all(|h| v.items()[h.index].title != "GitHub"));
    // Le corps des notes non plus.
    assert!(titles(&v, "Martin-5G", &Filter::All).is_empty());
}

#[test]
fn filters_and_inline_filters() {
    let v = vault();
    let cards = titles(&v, "", &Filter::Kind(ItemKind::Card));
    assert_eq!(cards.len(), 3);
    let banks = titles(&v, "tag:banque", &Filter::All);
    assert!(banks.contains(&"Boursorama".to_owned()));
    assert!(banks.iter().all(|t| !t.contains("GitHub")));
    let homelab = titles(&v, "dossier:maison", &Filter::Favorites);
    assert!(homelab.contains(&"Vaultwarden".to_owned()));
    let typed = titles(&v, "type:carte visa", &Filter::All);
    assert_eq!(typed, vec!["Visa Boursorama".to_owned()]);
    let excluded = titles(&v, "github !pro", &Filter::All);
    assert!(excluded.contains(&"GitHub".to_owned()));
    assert!(!excluded.contains(&"GitHub — compte pro".to_owned()));
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
    assert!(suggested.contains(&"GitHub — compte pro".to_owned()));
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
    // Une adresse d'app n'est pas un site : ni hôte, ni suggestion web.
    let slack = v.items().iter().find(|i| i.title == "Slack").unwrap();
    assert_eq!(slack.primary_host().as_deref(), Some("slack.com"));
    assert!(
        v.suggestions_for("https://com.tinyspeck.slackmacgap")
            .is_empty()
    );
}

/// Garde-fou de performance, en version optimisée seulement : 10 000 éléments,
/// une frappe doit rester bien sous la durée d'une image à 60 Hz.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "mesure significative en --release uniquement"
)]
fn search_is_fast_on_10k_items() {
    let v = Vault::new(mock::vault_items(10_000, 7));
    let queries = [
        "g",
        "gi",
        "git",
        "gith",
        "githu",
        "github",
        "github pro",
        "camille",
        "zzzz",
    ];
    let start = Instant::now();
    for q in queries {
        let _ = v.search(q, &Filter::All, Sort::Relevance);
    }
    let per_query = start.elapsed() / queries.len() as u32;
    assert!(per_query.as_millis() < 16, "{per_query:?} par requête");
}
