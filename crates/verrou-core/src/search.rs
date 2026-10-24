//! Local search, entirely in memory.
//!
//! Nothing leaves the machine: the index is built when the vault opens from
//! the **non-secret** fields (title, displayed username, sites,
//! folder, tags), and wiped with it on lock. Passwords,
//! notes and card numbers are never indexed.
//!
//! Ranking relies on `nucleo-matcher`, the `fzf` algorithm rewritten in
//! Rust: fuzzy subsequence matching, bonus at word starts,
//! accents ignored ("societe" finds "Société Générale"). Each word of the
//! query must fit in at least one field, with a weight that
//! favours the title, then the site.

use std::collections::HashMap;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32String};
use unicode_normalization::UnicodeNormalization;

use crate::model::{Item, ItemKind, ItemState};
use crate::passkey::Passkey;
use crate::template::Template;

/// What the sidebar shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Favorites,
    Kind(ItemKind),
    /// Items of a template (Wi-Fi, passport…).
    Template(Template),
    Folder(String),
    Tag(String),
    WithTotp,
    /// Archived items.
    Archived,
    /// Items in the trash.
    Trash,
    /// Items of an organization (shared vault), by id.
    Organization(String),
    /// Items of an organization collection, by id.
    Collection(String),
    /// Logins that carry at least one passkey.
    Passkeys,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    /// Relevance when searching, alphabetical order otherwise.
    #[default]
    Relevance,
    Title,
    RecentlyModified,
    /// Creation, newest first.
    Created,
    /// Last use on this device (fill, copy, showing a secret), most
    /// recent first; never-used items after that, by title.
    LastUsed,
}

/// A result: position of the item in the vault, score, and positions of the
/// title characters to highlight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub index: usize,
    pub score: u32,
    pub title_indices: Vec<u32>,
}

/// Set of the characters present (folded letters and digits), to rule out
/// in one instruction a field that cannot contain the searched word.
#[derive(Clone, Copy, Default)]
struct CharMask(u64);

impl CharMask {
    fn of(folded: &str) -> Self {
        Self(folded.chars().fold(0, |mask, c| mask | Self::bit(c)))
    }

    fn bit(c: char) -> u64 {
        match c {
            'a'..='z' => 1 << (c as u32 - 'a' as u32),
            '0'..='9' => 1 << (26 + c as u32 - '0' as u32),
            _ => 0,
        }
    }

    fn contains(self, needle: Self) -> bool {
        self.0 & needle.0 == needle.0
    }
}

struct Entry {
    masks: [CharMask; 4],
    title: Utf32String,
    subtitle: Utf32String,
    hosts: Utf32String,
    extra: Utf32String,
    /// Names of the item's category and template, in English and French:
    /// matched as whole substrings only, so that these words common to
    /// many items add no fuzzy noise.
    labels: Utf32String,
    /// Folded title (lowercase, no accents) for sorting and the prefix
    /// bonus.
    folded_title: String,
    /// Alphabetical rank, computed once: sorting 10,000 results compares
    /// integers instead of strings.
    title_rank: u32,
    folder: Option<String>,
    tags: Vec<String>,
    /// Sites of the item's passkeys (folded `rpId`s); empty: none.
    passkey_sites: Vec<String>,
}

pub(crate) struct SearchIndex {
    entries: Vec<Entry>,
}

// Field weights: a word found in the title counts four times more than
// in the tags.
const WEIGHT_TITLE: u32 = 4;
const WEIGHT_HOST: u32 = 3;
const WEIGHT_SUBTITLE: u32 = 2;
const WEIGHT_EXTRA: u32 = 1;
const BONUS_TITLE_PREFIX: u32 = 400;
const BONUS_TITLE_EXACT: u32 = 800;
const BONUS_FAVORITE: u32 = 24;
/// Results whose title highlighting is computed (beyond that, they are not
/// on screen).
pub const HIGHLIGHT_LIMIT: usize = 200;

/// Folded text: lowercase, no accents ("Société" → "societe").
pub fn fold(text: &str) -> String {
    text.nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

impl SearchIndex {
    pub(crate) fn build(items: &[Item]) -> Self {
        let entries = items
            .iter()
            .map(|item| {
                let hosts: Vec<String> = item
                    .urls
                    .iter()
                    .filter_map(|u| crate::matching::host_of(u))
                    .collect();
                let kind = item.kind;
                let mut labels = vec![kind.label(), kind.french_label()];
                labels.extend(kind.keywords());
                if let Some(template) = item.template() {
                    labels.push(template.label());
                    labels.push(template.french_label());
                    labels.extend(template.keywords());
                }
                let labels = labels.join(" ");
                let mut extra = Vec::new();
                extra.extend(item.folder.iter().cloned());
                extra.extend(item.tags.iter().cloned());
                // A shared item is also found by the name of its
                // organization or of its collections.
                if let Some(shared) = &item.shared {
                    extra.push(shared.organization.clone());
                    extra.extend(shared.collections.iter().map(|(_, name)| name.clone()));
                }
                let hosts = hosts.join(" ");
                let extra = extra.join(" ");
                Entry {
                    masks: [
                        CharMask::of(&fold(&item.title)),
                        CharMask::of(&fold(&hosts)),
                        CharMask::of(&fold(&item.subtitle)),
                        CharMask::of(&fold(&extra)),
                    ],
                    title: Utf32String::from(item.title.as_str()),
                    subtitle: Utf32String::from(item.subtitle.as_str()),
                    hosts: Utf32String::from(hosts.as_str()),
                    extra: Utf32String::from(extra.as_str()),
                    labels: Utf32String::from(labels.as_str()),
                    folded_title: fold(&item.title),
                    title_rank: 0,
                    folder: item.folder.as_deref().map(fold),
                    tags: item.tags.iter().map(|t| fold(t)).collect(),
                    passkey_sites: Vec::new(),
                }
            })
            .collect::<Vec<Entry>>();
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by(|&a, &b| {
            entries[a]
                .folded_title
                .cmp(&entries[b].folded_title)
                .then(a.cmp(&b))
        });
        let mut entries = entries;
        for (rank, index) in order.into_iter().enumerate() {
            entries[index].title_rank = rank as u32;
        }
        Self { entries }
    }

    /// Records each item's passkeys ("Passkeys" filter, `passkey:`
    /// keyword).
    pub(crate) fn mark_passkeys(&mut self, by_id: &HashMap<String, usize>, passkeys: &[Passkey]) {
        for entry in &mut self.entries {
            entry.passkey_sites.clear();
        }
        for passkey in passkeys {
            if let Some(&index) = by_id.get(&passkey.item) {
                self.entries[index].passkey_sites.push(fold(&passkey.rp_id));
            }
        }
    }

    pub(crate) fn has_passkey(&self, index: usize) -> bool {
        self.entries
            .get(index)
            .is_some_and(|e| !e.passkey_sites.is_empty())
    }

    pub(crate) fn search(
        &self,
        items: &[Item],
        query: &str,
        filter: &Filter,
        sort: Sort,
        last_used: &HashMap<String, i64>,
    ) -> Vec<Hit> {
        let parsed = ParsedQuery::parse(query);
        let mut matcher = Matcher::new({
            let mut config = Config::DEFAULT;
            config.prefer_prefix = true;
            config
        });
        let mut hits: Vec<Hit> = Vec::new();

        for (index, (item, entry)) in items.iter().zip(&self.entries).enumerate() {
            if !filter_accepts(filter, item, entry) || !parsed.filters_accept(item, entry) {
                continue;
            }
            if parsed.atoms.is_empty() {
                hits.push(Hit {
                    index,
                    score: 0,
                    title_indices: Vec::new(),
                });
                continue;
            }
            let Some(score) = score_entry(&parsed, entry, item, &mut matcher) else {
                continue;
            };
            hits.push(Hit {
                index,
                score,
                title_indices: Vec::new(),
            });
        }

        let by_title = |a: &Hit, b: &Hit| {
            self.entries[a.index]
                .title_rank
                .cmp(&self.entries[b.index].title_rank)
        };
        match sort {
            Sort::Relevance if !parsed.atoms.is_empty() => {
                hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| by_title(a, b)));
            }
            Sort::Relevance | Sort::Title => hits.sort_unstable_by(by_title),
            Sort::RecentlyModified => hits.sort_by(|a, b| {
                items[b.index]
                    .modified
                    .cmp(&items[a.index].modified)
                    .then_with(|| by_title(a, b))
            }),
            Sort::Created => hits.sort_by(|a, b| {
                items[b.index]
                    .created
                    .cmp(&items[a.index].created)
                    .then_with(|| by_title(a, b))
            }),
            Sort::LastUsed => {
                let used = |hit: &Hit| last_used.get(&items[hit.index].id).copied();
                // `Some` (used) before `None`, most recent first.
                hits.sort_by(|a, b| used(b).cmp(&used(a)).then_with(|| by_title(a, b)));
            }
        }
        // Highlighting only serves visible rows: computing it for the
        // 10,000 results of a single letter doubled the keystroke time.
        let mut indices = Vec::new();
        for hit in hits.iter_mut().take(HIGHLIGHT_LIMIT) {
            for atom in parsed.atoms.iter().filter(|a| !a.negative) {
                indices.clear();
                let title = self.entries[hit.index].title.slice(..);
                if atom.indices(title, &mut matcher, &mut indices).is_some() {
                    hit.title_indices.extend_from_slice(&indices);
                }
            }
            hit.title_indices.sort_unstable();
            hit.title_indices.dedup();
        }
        hits
    }
}

fn filter_accepts(filter: &Filter, item: &Item, entry: &Entry) -> bool {
    match filter {
        Filter::Archived => return item.state == ItemState::Archived,
        Filter::Trash => return item.state == ItemState::Trashed,
        _ if !item.is_active() => return false,
        _ => {}
    }
    match filter {
        Filter::All | Filter::Archived | Filter::Trash => true,
        Filter::Favorites => item.favorite,
        Filter::Kind(kind) => item.kind == *kind,
        Filter::Template(template) => item.template() == Some(*template),
        // A folder holds its subfolders' items too: "Work" shows
        // "Work/Clients" (Bitwarden's nested folders, named with "/").
        Filter::Folder(folder) => entry.folder.as_deref().is_some_and(|name| {
            let folder = fold(folder);
            name == folder
                || name
                    .strip_prefix(folder.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        }),
        Filter::Tag(tag) => entry.tags.contains(&fold(tag)),
        Filter::WithTotp => item.has_totp(),
        Filter::Organization(id) => item
            .shared
            .as_ref()
            .is_some_and(|s| &s.organization_id == id),
        Filter::Collection(id) => item
            .shared
            .as_ref()
            .is_some_and(|s| s.collections.iter().any(|(c, _)| c == id)),
        Filter::Passkeys => !entry.passkey_sites.is_empty(),
    }
}

fn score_entry(
    parsed: &ParsedQuery,
    entry: &Entry,
    item: &Item,
    matcher: &mut Matcher,
) -> Option<u32> {
    let fields = [
        (&entry.title, WEIGHT_TITLE),
        (&entry.hosts, WEIGHT_HOST),
        (&entry.subtitle, WEIGHT_SUBTITLE),
        (&entry.extra, WEIGHT_EXTRA),
    ];
    let mut total = 0u32;
    for ((atom, mask), label_atom) in parsed
        .atoms
        .iter()
        .zip(&parsed.masks)
        .zip(&parsed.label_atoms)
    {
        if atom.negative {
            // An excluded word (`!travail`) drops the item if it appears
            // anywhere. For a negative atom, `score` returns `None` when the
            // word is present.
            if fields
                .iter()
                .map(|(haystack, _)| *haystack)
                .chain([&entry.labels])
                .any(|haystack| atom.score(haystack.slice(..), matcher).is_none())
            {
                return None;
            }
            continue;
        }
        let label = label_atom
            .score(entry.labels.slice(..), matcher)
            .map(|s| u32::from(s) * WEIGHT_EXTRA);
        let best = fields
            .iter()
            .zip(entry.masks)
            .filter(|(_, field_mask)| field_mask.contains(*mask))
            .filter_map(|((haystack, weight), _)| {
                atom.score(haystack.slice(..), matcher)
                    .map(|s| u32::from(s) * weight)
            })
            .chain(label)
            .max()?;
        total += best;
    }
    if !parsed.folded_text.is_empty() {
        if entry.folded_title == parsed.folded_text {
            total += BONUS_TITLE_EXACT;
        } else if entry.folded_title.starts_with(&parsed.folded_text) {
            total += BONUS_TITLE_PREFIX;
        }
    }
    if item.favorite {
        total += BONUS_FAVORITE;
    }
    Some(total)
}

/// A query word without its search operators (`!`, `^`, `'`, `$`).
fn bare(word: &str) -> &str {
    word.trim_start_matches(['!', '^', '\''])
        .trim_end_matches('$')
}

/// The first of `all` with a keyword that starts with `prefix`: English
/// keywords first, then the French aliases.
fn keyword_match<T: Copy>(
    all: &[T],
    keywords: fn(T) -> &'static [&'static str],
    prefix: &str,
) -> Option<T> {
    if prefix.is_empty() {
        return None;
    }
    let max = all.iter().map(|t| keywords(*t).len()).max().unwrap_or(0);
    (0..max).find_map(|rank| {
        all.iter().copied().find(|t| {
            keywords(*t)
                .get(rank)
                .is_some_and(|k| fold(k).starts_with(prefix))
        })
    })
}

/// Split query: words to search for, and explicit filters (`tag:`,
/// `folder:`/`dossier:`, `type:`, `passkey:`, `has:`/`with:`/`avec:`).
struct ParsedQuery {
    atoms: Vec<Atom>,
    /// Each word as a plain substring, for the category names
    /// (`Entry::labels`), in `atoms` order.
    label_atoms: Vec<Atom>,
    /// Characters required by each word, in `atoms` order.
    masks: Vec<CharMask>,
    folded_text: String,
    tags: Vec<String>,
    folders: Vec<String>,
    kinds: Vec<ItemKind>,
    templates: Vec<Template>,
    /// `passkey:` (empty: any passkey) or `passkey:github`
    /// (passkey site that starts with…), and `has:passkey`.
    passkeys: Vec<String>,
    /// `has:totp` (or `has:otp`).
    with_totp: bool,
}

impl ParsedQuery {
    fn parse(query: &str) -> Self {
        let mut words = Vec::new();
        let mut tags = Vec::new();
        let mut folders = Vec::new();
        let mut kinds = Vec::new();
        let mut templates = Vec::new();
        let mut passkeys = Vec::new();
        let mut with_totp = false;
        for token in query.split_whitespace() {
            let lower = fold(token);
            if let Some(site) = lower
                .strip_prefix("passkey:")
                .or_else(|| lower.strip_prefix("passkeys:"))
            {
                passkeys.push(site.to_owned());
            } else if let Some(what) = lower
                .strip_prefix("has:")
                .or_else(|| lower.strip_prefix("with:"))
                .or_else(|| lower.strip_prefix("avec:"))
            {
                match what {
                    "passkey" | "passkeys" => passkeys.push(String::new()),
                    "totp" | "otp" | "2fa" => with_totp = true,
                    // Unknown: searched as a word.
                    _ => words.push(token),
                }
            } else if let Some(tag) = lower
                .strip_prefix("tag:")
                .or_else(|| lower.strip_prefix('#'))
            {
                if !tag.is_empty() {
                    tags.push(tag.to_owned());
                }
            } else if let Some(folder) = lower
                .strip_prefix("folder:")
                .or_else(|| lower.strip_prefix("dossier:"))
            {
                if !folder.is_empty() {
                    folders.push(folder.to_owned());
                }
            } else if let Some(kind) = lower.strip_prefix("type:") {
                if let Some(k) = keyword_match(&ItemKind::ALL, ItemKind::keywords, kind) {
                    kinds.push(k);
                } else if let Some(t) = keyword_match(&Template::ALL, Template::keywords, kind) {
                    templates.push(t);
                }
            } else {
                words.push(token);
            }
        }
        let atoms: Vec<Atom> = words
            .iter()
            .map(|w| Atom::parse(w, CaseMatching::Ignore, Normalization::Smart))
            .collect();
        let masks = words.iter().map(|w| CharMask::of(&fold(bare(w)))).collect();
        let label_atoms = words
            .iter()
            .map(|w| {
                Atom::new(
                    bare(w),
                    CaseMatching::Ignore,
                    Normalization::Smart,
                    AtomKind::Substring,
                    false,
                )
            })
            .collect();
        let folded_text = fold(&words.join(" "));
        Self {
            atoms,
            label_atoms,
            masks,
            folded_text,
            tags,
            folders,
            kinds,
            templates,
            passkeys,
            with_totp,
        }
    }

    fn filters_accept(&self, item: &Item, entry: &Entry) -> bool {
        (!self.with_totp || item.has_totp())
            && self.passkeys.iter().all(|site| {
                entry.passkey_sites.iter().any(|rp| {
                    // `passkey:github` finds `github.com` and `login.github.com`.
                    rp.starts_with(site.as_str())
                        || rp.split('.').any(|label| label.starts_with(site.as_str()))
                })
            })
            && self.kinds.iter().all(|k| item.kind == *k)
            && self.templates.iter().all(|t| item.template() == Some(*t))
            && self
                .tags
                .iter()
                .all(|t| entry.tags.iter().any(|tag| tag.starts_with(t.as_str())))
            && self.folders.iter().all(|f| {
                entry
                    .folder
                    .as_deref()
                    .is_some_and(|folder| folder.starts_with(f.as_str()))
            })
    }
}
