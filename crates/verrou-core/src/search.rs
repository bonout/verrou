//! Recherche locale, entièrement en mémoire.
//!
//! Rien ne quitte la machine : l'index est construit à l'ouverture du coffre à
//! partir des champs **non secrets** (titre, identifiant affiché, sites,
//! dossier, étiquettes), et effacé avec lui au verrouillage. Les mots de passe,
//! notes et numéros de carte ne sont jamais indexés.
//!
//! Le classement repose sur `nucleo-matcher`, l'algorithme de `fzf` réécrit en
//! Rust : correspondance floue par sous-séquence, bonus aux débuts de mots,
//! accents ignorés (« societe » trouve « Société Générale »). Chaque mot de la
//! requête doit trouver sa place dans au moins un champ, avec un poids qui
//! favorise le titre puis le site.

use nucleo_matcher::pattern::{Atom, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32String};
use unicode_normalization::UnicodeNormalization;

use crate::model::{Item, ItemKind};

/// Ce que montre la barre latérale.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Favorites,
    Kind(ItemKind),
    Folder(String),
    Tag(String),
    WithTotp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    /// Pertinence quand on cherche, ordre alphabétique sinon.
    #[default]
    Relevance,
    Title,
    RecentlyModified,
}

/// Un résultat : position de l'élément dans le coffre, score, et positions des
/// caractères du titre à surligner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub index: usize,
    pub score: u32,
    pub title_indices: Vec<u32>,
}

/// Ensemble des caractères présents (lettres et chiffres repliés), pour
/// écarter en une instruction un champ qui ne peut pas contenir le mot cherché.
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
    /// Titre replié (minuscules, sans accents) pour le tri et le bonus de
    /// préfixe.
    folded_title: String,
    /// Rang alphabétique, calculé une fois : trier 10 000 résultats compare
    /// des entiers au lieu de chaînes.
    title_rank: u32,
    folder: Option<String>,
    tags: Vec<String>,
}

pub(crate) struct SearchIndex {
    entries: Vec<Entry>,
}

// Poids des champs : un mot trouvé dans le titre compte quatre fois plus que
// dans les étiquettes.
const WEIGHT_TITLE: u32 = 4;
const WEIGHT_HOST: u32 = 3;
const WEIGHT_SUBTITLE: u32 = 2;
const WEIGHT_EXTRA: u32 = 1;
const BONUS_TITLE_PREFIX: u32 = 400;
const BONUS_TITLE_EXACT: u32 = 800;
const BONUS_FAVORITE: u32 = 24;
/// Résultats dont on calcule le surlignage du titre (au-delà, ils ne sont pas
/// à l'écran).
pub const HIGHLIGHT_LIMIT: usize = 200;

pub(crate) fn fold(text: &str) -> String {
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
                let mut extra = vec![item.kind.label().to_owned(), item.kind.keyword().to_owned()];
                extra.extend(item.folder.iter().cloned());
                extra.extend(item.tags.iter().cloned());
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
                    folded_title: fold(&item.title),
                    title_rank: 0,
                    folder: item.folder.as_deref().map(fold),
                    tags: item.tags.iter().map(|t| fold(t)).collect(),
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

    pub(crate) fn search(
        &self,
        items: &[Item],
        query: &str,
        filter: &Filter,
        sort: Sort,
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
        }
        // Le surlignage ne sert qu'aux lignes visibles : le calculer pour
        // les 10 000 résultats d'une seule lettre doublait le temps de frappe.
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
        Filter::All => true,
        Filter::Favorites => item.favorite,
        Filter::Kind(kind) => item.kind == *kind,
        Filter::Folder(folder) => entry.folder.as_deref() == Some(fold(folder).as_str()),
        Filter::Tag(tag) => entry.tags.contains(&fold(tag)),
        Filter::WithTotp => item.has_totp(),
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
    for (atom, mask) in parsed.atoms.iter().zip(&parsed.masks) {
        if atom.negative {
            // Un mot exclu (`!travail`) élimine l'élément s'il apparaît où que
            // ce soit. Pour un atome négatif, `score` rend `None` quand le
            // mot est présent.
            if fields
                .iter()
                .any(|(haystack, _)| atom.score(haystack.slice(..), matcher).is_none())
            {
                return None;
            }
            continue;
        }
        let best = fields
            .iter()
            .zip(entry.masks)
            .filter(|(_, field_mask)| field_mask.contains(*mask))
            .filter_map(|((haystack, weight), _)| {
                atom.score(haystack.slice(..), matcher)
                    .map(|s| u32::from(s) * weight)
            })
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

/// Requête découpée : mots à chercher, et filtres explicites (`tag:`,
/// `dossier:`, `type:`).
struct ParsedQuery {
    atoms: Vec<Atom>,
    /// Caractères exigés par chaque mot, dans l'ordre de `atoms`.
    masks: Vec<CharMask>,
    folded_text: String,
    tags: Vec<String>,
    folders: Vec<String>,
    kinds: Vec<ItemKind>,
}

impl ParsedQuery {
    fn parse(query: &str) -> Self {
        let mut words = Vec::new();
        let mut tags = Vec::new();
        let mut folders = Vec::new();
        let mut kinds = Vec::new();
        for token in query.split_whitespace() {
            let lower = fold(token);
            if let Some(tag) = lower
                .strip_prefix("tag:")
                .or_else(|| lower.strip_prefix('#'))
            {
                if !tag.is_empty() {
                    tags.push(tag.to_owned());
                }
            } else if let Some(folder) = lower
                .strip_prefix("dossier:")
                .or_else(|| lower.strip_prefix("folder:"))
            {
                if !folder.is_empty() {
                    folders.push(folder.to_owned());
                }
            } else if let Some(kind) = lower.strip_prefix("type:") {
                if let Some(k) = ItemKind::ALL
                    .iter()
                    .find(|k| fold(k.keyword()).starts_with(kind) && !kind.is_empty())
                {
                    kinds.push(*k);
                }
            } else {
                words.push(token);
            }
        }
        let atoms: Vec<Atom> = words
            .iter()
            .map(|w| Atom::parse(w, CaseMatching::Ignore, Normalization::Smart))
            .collect();
        let masks = words
            .iter()
            .map(|w| {
                CharMask::of(&fold(
                    w.trim_start_matches(['!', '^', '\'']).trim_end_matches('$'),
                ))
            })
            .collect();
        let folded_text = fold(&words.join(" "));
        Self {
            atoms,
            masks,
            folded_text,
            tags,
            folders,
            kinds,
        }
    }

    fn filters_accept(&self, item: &Item, entry: &Entry) -> bool {
        self.kinds.iter().all(|k| item.kind == *k)
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
