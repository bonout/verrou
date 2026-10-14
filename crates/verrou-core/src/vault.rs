//! Le coffre déverrouillé : les éléments et leur index de recherche.

use std::collections::{BTreeMap, HashMap};

use crate::matching::{SiteMatch, site_match};
use crate::model::{Item, ItemKind, ItemState};
use crate::passkey::Passkey;
use crate::search::{Filter, Hit, SearchIndex, Sort, fold};

pub struct Vault {
    items: Vec<Item>,
    index: SearchIndex,
    by_id: HashMap<String, usize>,
    /// Passkeys des identifiants ([`Vault::with_passkeys`]).
    passkeys: Vec<Passkey>,
}

/// Effectifs affichés dans la barre latérale.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Éléments actifs (ni archivés, ni à la corbeille), comme les suivants.
    pub all: usize,
    pub archived: usize,
    pub trashed: usize,
    pub favorites: usize,
    pub with_totp: usize,
    pub kinds: Vec<(ItemKind, usize)>,
    pub folders: Vec<(String, usize)>,
    pub tags: Vec<(String, usize)>,
    /// Éléments actifs par organisation et par collection (identifiants).
    pub organizations: Vec<(String, usize)>,
    pub collections: Vec<(String, usize)>,
}

impl Vault {
    pub fn new(items: Vec<Item>) -> Self {
        let index = SearchIndex::build(&items);
        let by_id = items
            .iter()
            .enumerate()
            .map(|(i, item)| (item.id.clone(), i))
            .collect();
        Self {
            items,
            index,
            by_id,
            passkeys: Vec::new(),
        }
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Item> {
        self.by_id.get(id).map(|&i| &self.items[i])
    }

    pub fn search(&self, query: &str, filter: &Filter, sort: Sort) -> Vec<Hit> {
        self.index.search(&self.items, query, filter, sort)
    }

    /// Identifiants proposés pour une page, du plus précis au moins précis.
    pub fn suggestions_for(&self, page_url: &str) -> Vec<&Item> {
        let mut found: Vec<(SiteMatch, &Item)> = self
            .items
            .iter()
            .filter(|item| item.kind == ItemKind::Login && item.is_active())
            .map(|item| (site_match(&item.urls, page_url), item))
            .filter(|(m, _)| *m != SiteMatch::None)
            .collect();
        found.sort_by(|(ma, a), (mb, b)| {
            mb.cmp(ma)
                .then(b.favorite.cmp(&a.favorite))
                .then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        found.into_iter().map(|(_, item)| item).collect()
    }

    /// Identifiants reliés à une application du Mac (`macapp://`), favoris
    /// d'abord, puis par titre.
    pub fn app_suggestions(&self, bundle_id: &str) -> Vec<&Item> {
        let mut found: Vec<&Item> = self
            .items
            .iter()
            .filter(|item| item.kind == ItemKind::Login && item.is_active())
            .filter(|item| crate::apps::matches_app(&item.urls, bundle_id))
            .collect();
        found.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        found
    }

    pub fn counts(&self) -> Counts {
        let mut kinds: BTreeMap<ItemKind, usize> = BTreeMap::new();
        let mut folders: BTreeMap<String, usize> = BTreeMap::new();
        let mut tags: BTreeMap<String, usize> = BTreeMap::new();
        let mut organizations: BTreeMap<String, usize> = BTreeMap::new();
        let mut collections: BTreeMap<String, usize> = BTreeMap::new();
        let mut counts = Counts::default();
        for item in &self.items {
            match item.state {
                ItemState::Archived => counts.archived += 1,
                ItemState::Trashed => counts.trashed += 1,
                ItemState::Active => {}
            }
            if !item.is_active() {
                continue;
            }
            counts.all += 1;
            *kinds.entry(item.kind).or_default() += 1;
            if let Some(folder) = &item.folder {
                *folders.entry(folder.clone()).or_default() += 1;
            }
            for tag in &item.tags {
                *tags.entry(tag.clone()).or_default() += 1;
            }
            if let Some(shared) = &item.shared {
                *organizations
                    .entry(shared.organization_id.clone())
                    .or_default() += 1;
                for (id, _) in &shared.collections {
                    *collections.entry(id.clone()).or_default() += 1;
                }
            }
            counts.favorites += usize::from(item.favorite);
            counts.with_totp += usize::from(item.has_totp());
        }
        counts.kinds = ItemKind::ALL
            .iter()
            .map(|k| (*k, kinds.get(k).copied().unwrap_or(0)))
            .collect();
        counts.folders = folders.into_iter().collect();
        counts.tags = tags.into_iter().collect();
        counts.organizations = organizations.into_iter().collect();
        counts.collections = collections.into_iter().collect();
        counts
    }
}

// MARK: Passkeys

impl Vault {
    /// Les passkeys des éléments du coffre (leur clé privée comprise, effacée
    /// à la libération).
    #[must_use]
    pub fn with_passkeys(mut self, passkeys: Vec<Passkey>) -> Self {
        self.passkeys = passkeys;
        self
    }

    pub fn passkeys(&self) -> &[Passkey] {
        &self.passkeys
    }

    /// Les passkeys d'un élément.
    pub fn passkeys_of(&self, item: &str) -> Vec<&Passkey> {
        self.passkeys.iter().filter(|p| p.item == item).collect()
    }

    /// Les passkeys utilisables pour le site `rp_id` : celles des
    /// identifiants actifs.
    pub fn passkeys_for(&self, rp_id: &str) -> Vec<&Passkey> {
        self.passkeys
            .iter()
            .filter(|p| {
                p.rp_id.eq_ignore_ascii_case(rp_id)
                    && self
                        .get(&p.item)
                        .is_some_and(|i| i.kind == ItemKind::Login && i.is_active())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{self, MOCK_COLLECTION, MOCK_ORGANIZATION};
    use crate::{Field, FieldKind, Sharing};

    #[test]
    fn shared_items_have_their_own_filters_and_counts() {
        let vault = Vault::new(mock::vault_items(0, 42));
        let counts = vault.counts();
        assert_eq!(
            counts.organizations,
            vec![(MOCK_ORGANIZATION.0.to_owned(), 1)]
        );
        assert_eq!(counts.collections, vec![(MOCK_COLLECTION.0.to_owned(), 1)]);
        for filter in [
            Filter::Organization(MOCK_ORGANIZATION.0.to_owned()),
            Filter::Collection(MOCK_COLLECTION.0.to_owned()),
        ] {
            let hits = vault.search("", &filter, Sort::Title);
            assert_eq!(hits.len(), 1);
            assert_eq!(vault.items()[hits[0].index].title, "Google — famille");
        }
        // Le nom de l'organisation se cherche comme un dossier.
        let hits = vault.search("famille martin", &Filter::All, Sort::Relevance);
        assert_eq!(vault.items()[hits[0].index].title, "Google — famille");
    }

    #[test]
    fn hidden_passwords_follow_the_organization_rule() {
        let mut item = mock::vault_items(0, 42).remove(0);
        item.fields
            .push(Field::new("custom-0", "PIN", FieldKind::Concealed, "1234"));
        item.fields
            .push(Field::new("history-0", "Ancien", FieldKind::Concealed, "x"));
        let hidden_count = |item: &Item| item.fields.iter().filter(|f| item.hides(f)).count();
        assert_eq!(hidden_count(&item), 0, "coffre personnel : rien de caché");
        item.shared = Some(Sharing {
            hide_passwords: true,
            ..Sharing::default()
        });
        let hidden: Vec<&str> = item
            .fields
            .iter()
            .filter(|f| item.hides(f))
            .map(|f| f.id.as_str())
            .collect();
        assert!(hidden.contains(&"password") && hidden.contains(&"custom-0"));
        assert!(hidden.contains(&"history-0"));
        assert!(!hidden.contains(&"username"));
        assert!(item.is_writable());
    }
}
