//! Le coffre déverrouillé : les éléments et leur index de recherche.

use std::collections::{BTreeMap, HashMap};

use crate::matching::{SiteMatch, site_match};
use crate::model::{Item, ItemKind, ItemState};
use crate::search::{Filter, Hit, SearchIndex, Sort, fold};

pub struct Vault {
    items: Vec<Item>,
    index: SearchIndex,
    by_id: HashMap<String, usize>,
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
            counts.favorites += usize::from(item.favorite);
            counts.with_totp += usize::from(item.has_totp());
        }
        counts.kinds = ItemKind::ALL
            .iter()
            .map(|k| (*k, kinds.get(k).copied().unwrap_or(0)))
            .collect();
        counts.folders = folders.into_iter().collect();
        counts.tags = tags.into_iter().collect();
        counts
    }
}
