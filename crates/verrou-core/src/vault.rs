//! The unlocked vault: the items and their search index.

use std::collections::{BTreeMap, HashMap};

use crate::matching::{MatchRules, matching_items};
use crate::model::{Item, ItemKind, ItemState};
use crate::passkey::Passkey;
use crate::search::{Filter, Hit, SearchIndex, Sort, fold};
use crate::template::Template;

pub struct Vault {
    items: Vec<Item>,
    index: SearchIndex,
    by_id: HashMap<String, usize>,
    /// The logins' passkeys ([`Vault::with_passkeys`]).
    passkeys: Vec<Passkey>,
    /// The device's match rules ([`Vault::with_match_rules`]).
    match_rules: MatchRules,
}

/// Counts shown in the sidebar.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Active items (neither archived nor in the trash), like the following ones.
    pub all: usize,
    pub archived: usize,
    pub trashed: usize,
    pub favorites: usize,
    pub with_totp: usize,
    /// Active logins that carry at least one passkey.
    pub passkeys: usize,
    pub kinds: Vec<(ItemKind, usize)>,
    /// Templates present in the vault (the others are not listed).
    pub templates: Vec<(Template, usize)>,
    pub folders: Vec<(String, usize)>,
    pub tags: Vec<(String, usize)>,
    /// Active items per organization and per collection (ids).
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
            match_rules: MatchRules::default(),
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
        self.search_with_usage(query, filter, sort, &HashMap::new())
    }

    /// Like [`Vault::search`], with the last-used dates on the
    /// device (id → Unix timestamp) for [`Sort::LastUsed`].
    pub fn search_with_usage(
        &self,
        query: &str,
        filter: &Filter,
        sort: Sort,
        last_used: &HashMap<String, i64>,
    ) -> Vec<Hit> {
        self.index
            .search(&self.items, query, filter, sort, last_used)
    }

    /// The device's match rules (default, folders, the account's equivalent
    /// domains).
    #[must_use]
    pub fn with_match_rules(mut self, rules: MatchRules) -> Self {
        self.match_rules = rules;
        self
    }

    /// Changes the match rules (device settings changed).
    pub fn set_match_rules(&mut self, rules: MatchRules) {
        self.match_rules = rules;
    }

    pub fn match_rules(&self) -> &MatchRules {
        &self.match_rules
    }

    /// Logins suggested for a page, from most to least precise.
    /// Each site follows its match rule (see `matching`).
    pub fn suggestions_for(&self, page_url: &str) -> Vec<&Item> {
        let mut found = matching_items(
            self.items
                .iter()
                .filter(|item| item.kind == ItemKind::Login && item.is_active()),
            page_url,
            &self.match_rules,
        );
        found.sort_by(|(ma, a), (mb, b)| {
            mb.cmp(ma)
                .then(b.favorite.cmp(&a.favorite))
                .then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        found.into_iter().map(|(_, item)| item).collect()
    }

    /// Logins linked to a Mac app (`macapp://`), favorites
    /// first, then by title.
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
        let mut templates: BTreeMap<Template, usize> = BTreeMap::new();
        let mut folders: BTreeMap<String, usize> = BTreeMap::new();
        let mut tags: BTreeMap<String, usize> = BTreeMap::new();
        let mut organizations: BTreeMap<String, usize> = BTreeMap::new();
        let mut collections: BTreeMap<String, usize> = BTreeMap::new();
        let mut counts = Counts::default();
        for (index, item) in self.items.iter().enumerate() {
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
            if let Some(template) = item.template() {
                *templates.entry(template).or_default() += 1;
            }
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
            counts.passkeys += usize::from(self.index.has_passkey(index));
        }
        counts.kinds = ItemKind::ALL
            .iter()
            .map(|k| (*k, kinds.get(k).copied().unwrap_or(0)))
            .collect();
        counts.templates = templates.into_iter().collect();
        counts.folders = folders.into_iter().collect();
        counts.tags = tags.into_iter().collect();
        counts.organizations = organizations.into_iter().collect();
        counts.collections = collections.into_iter().collect();
        counts
    }
}

// MARK: Passkeys

impl Vault {
    /// The passkeys of the vault's items (their private key included, wiped
    /// when dropped).
    #[must_use]
    pub fn with_passkeys(mut self, passkeys: Vec<Passkey>) -> Self {
        self.index.mark_passkeys(&self.by_id, &passkeys);
        self.passkeys = passkeys;
        self
    }

    pub fn passkeys(&self) -> &[Passkey] {
        &self.passkeys
    }

    /// An item's passkeys.
    pub fn passkeys_of(&self, item: &str) -> Vec<&Passkey> {
        self.passkeys.iter().filter(|p| p.item == item).collect()
    }

    /// The passkeys usable for the site `rp_id`: those of the
    /// active logins.
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
    use crate::mock::{self, MOCK_COLLECTION_ID, MOCK_ORGANIZATION_ID, MockLanguage};
    use crate::{Field, FieldKind, Sharing};

    #[test]
    fn shared_items_have_their_own_filters_and_counts() {
        let vault = Vault::new(mock::vault_items(0, 42, MockLanguage::En));
        let counts = vault.counts();
        assert_eq!(
            counts.organizations,
            vec![(MOCK_ORGANIZATION_ID.to_owned(), 1)]
        );
        assert_eq!(counts.collections, vec![(MOCK_COLLECTION_ID.to_owned(), 1)]);
        for filter in [
            Filter::Organization(MOCK_ORGANIZATION_ID.to_owned()),
            Filter::Collection(MOCK_COLLECTION_ID.to_owned()),
        ] {
            let hits = vault.search("", &filter, Sort::Title);
            assert_eq!(hits.len(), 1);
            assert_eq!(vault.items()[hits[0].index].title, "Google — family");
        }
        // The organization's name is searchable like a folder.
        let hits = vault.search("parker family", &Filter::All, Sort::Relevance);
        assert_eq!(vault.items()[hits[0].index].title, "Google — family");
    }

    #[test]
    fn hidden_passwords_follow_the_organization_rule() {
        let mut item = mock::vault_items(0, 42, MockLanguage::En).remove(0);
        item.fields
            .push(Field::new("custom-0", "PIN", FieldKind::Concealed, "1234"));
        item.fields
            .push(Field::new("history-0", "Ancien", FieldKind::Concealed, "x"));
        let hidden_count = |item: &Item| item.fields.iter().filter(|f| item.hides(f)).count();
        assert_eq!(hidden_count(&item), 0, "personal vault: nothing hidden");
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
