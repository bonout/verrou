//! Duplicates: between an import and the vault, and within the vault.
//!
//! The same account often arrives several times, from Apple, 1Password and
//! Proton Pass, with different URLs and titles
//! (`connect.maif.fr`, `www.maif.fr/espace-perso`, "Maif", "MAIF -
//! Espace sociétaire"). Each login is therefore summarised as signals
//! (`signals`): sites and domains of its URLs (scheme, port, path
//! and sign-in prefixes ignored; app URLs compared with each
//! other), normalised title and its brand ("Maif" ↔ `maif.fr`), normalised
//! username, passkeys. Passwords and TOTP seeds are compared
//! here, in Rust, in constant time: the UI only receives a verdict.
//!
//! Three levels:
//! - **Certain**: same site (or brand ↔ domain), same username, same
//!   password. The copies are checked for the trash.
//! - **Probable**: same site, same username, different password (or one
//!   username missing, same password); same title, same
//!   username, no URL. Suggested, not checked.
//! - **To review**: same site, different usernames but same
//!   password; same brand without username; two subdomains (often
//!   two services: `cloud.exemple.fr` and `vault.exemple.fr`). Never
//!   checked.
//!
//! Comparisons are made by buckets (same domain, same app, same
//! brand, same title), never the whole vault against the whole vault.

mod signals;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use sha2::{Digest as _, Sha256};

pub use signals::{Confidence, site_of};
use signals::{PasswordLink, Signals, Source, relate, relate_with, same_secret};

use crate::import::{IdentityData, ImportKind, ImportedItem};
use crate::model::{Item, ItemKind, ItemState};
use crate::search::fold;
use crate::secret::SecretString;

/// The already known item that an imported item resembles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Existing {
    /// Id of a vault item.
    Vault(String),
    /// Position of an item earlier in the same import.
    Import(usize),
}

/// What an imported item is relative to the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    /// Certain duplicate (same site, same username, same password):
    /// already present.
    Exact(Existing),
    /// Already present, but the import brings a one-time code that
    /// the vault item lacks.
    AddsTotp(String),
    /// Probable duplicate, with a different password.
    NewPassword(Existing),
    /// Probable duplicate, same password (one username missing, or a
    /// title without a site): to complete rather than create.
    Similar(Existing),
}

/// What the import will do with an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Don't import it (keep the existing one).
    Skip,
    /// Create it, next to the existing one if there is one.
    Create,
    /// Complete the vault item: new password (the old one
    /// goes to the history), one-time code and missing sites.
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub status: Status,
    /// Default proposed choice.
    pub decision: Decision,
    /// Why it resembles the existing one ("same site (maif.fr), same
    /// username, different password"). Never a secret.
    pub reason: Option<String>,
}

fn vault_username(item: &Item) -> Option<&str> {
    item.field("username").map(|f| f.value.expose())
}

fn vault_password(item: &Item) -> &str {
    item.field("password").map_or("", |f| f.value.expose())
}

fn vault_totp(item: &Item) -> Option<&str> {
    item.field("totp").map(|f| f.value.expose())
}

fn imported_password(item: &ImportedItem) -> &str {
    item.password.as_ref().map_or("", |p| p.expose())
}

fn card_digits(number: &str) -> String {
    number.chars().filter(char::is_ascii_digit).collect()
}

fn vault_card_digits(item: &Item) -> String {
    item.field("number")
        .map(|f| card_digits(f.value.expose()))
        .unwrap_or_default()
}

/// Key of a template note (Wi-Fi, passport…): the template and the title.
fn template_key(template: &str, title: &str) -> String {
    format!("template:{template}:{}", fold(title.trim()))
}

/// Key of an identity: the title and the full name.
fn identity_key(title: &str, full_name: &str) -> String {
    format!("identity:{}:{}", fold(title.trim()), fold(full_name.trim()))
}

fn vault_full_name(item: &Item) -> String {
    ["first_name", "middle_name", "last_name"]
        .iter()
        .filter_map(|id| item.field(id))
        .map(|f| f.value.expose().trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn notes_key(title: &str, notes: Option<&str>) -> Option<(String, String)> {
    let notes = notes.map(str::trim).filter(|n| !n.is_empty())?;
    Some((fold(title.trim()), notes.to_owned()))
}

const SAME_CARD: &str = "same card number";
const SAME_NOTE: &str = "same title, same content";

/// What the vault knows about an item outside its fields: its
/// passkeys and its attachments. None of it is merged: the item
/// that has some is preferably kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemExtras {
    /// Passkey sites (`rpId`).
    pub passkey_sites: Vec<String>,
    pub attachments: usize,
}

const NO_PASSKEYS: &[String] = &[];

fn item_signals<'a>(item: &'a Item, owner: &'a str, extras: Option<&'a ItemExtras>) -> Signals<'a> {
    Signals::new(&Source {
        owner,
        title: &item.title,
        urls: &item.urls,
        passkeys: extras.map_or(NO_PASSKEYS, |e| e.passkey_sites.as_slice()),
        username: vault_username(item),
        password: vault_password(item),
        totp: vault_totp(item),
    })
}

fn imported_signals(item: &ImportedItem) -> Signals<'_> {
    Signals::new(&Source {
        owner: "",
        title: &item.title,
        urls: &item.urls,
        passkeys: NO_PASSKEYS,
        username: item.username.as_deref(),
        password: imported_password(item),
        totp: item.totp.as_ref().map(SecretString::expose),
    })
}

// MARK: Buckets

/// Beyond this, a bucket is no longer compared pair by pair: only the
/// items that share a username or a password, and those without a
/// username.
const SMALL_BUCKET: usize = 48;

/// Login buckets: same domain or same app ("web"), same brand
/// or same title ("name": only for an item without a web URL).
#[derive(Default)]
struct Buckets {
    web: HashMap<String, Vec<usize>>,
    name: HashMap<String, Vec<usize>>,
}

impl Buckets {
    fn add(&mut self, index: usize, signals: &Signals) {
        for key in signals.web_keys() {
            self.web.entry(key).or_default().push(index);
        }
        for key in signals.name_keys() {
            self.name.entry(key).or_default().push(index);
        }
    }

    /// Indexed items that may resemble `signals` (for the import).
    fn candidates(&self, signals: &Signals, known: &[Signals]) -> Vec<usize> {
        let mut found: Vec<usize> = signals
            .web_keys()
            .filter_map(|k| self.web.get(&k))
            .flatten()
            .copied()
            .collect();
        for key in signals.name_keys() {
            if let Some(members) = self.name.get(&key) {
                found.extend(
                    members
                        .iter()
                        .filter(|&&i| !signals.has_web || !known[i].has_web),
                );
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Pairs to compare, each once.
    fn pairs(&self, signals: &[Signals], blind: bool) -> HashSet<(usize, usize)> {
        let hasher = std::collections::hash_map::RandomState::new();
        let mut pairs = HashSet::new();
        for members in self.web.values() {
            bucket_pairs(members, signals, false, blind, &hasher, &mut pairs);
        }
        for members in self.name.values() {
            bucket_pairs(members, signals, true, blind, &hasher, &mut pairs);
        }
        pairs
    }
}

/// A pair to compare. In a "name" bucket, at least one of the two
/// has no web URL.
fn push_pair(
    pairs: &mut HashSet<(usize, usize)>,
    signals: &[Signals],
    (a, b): (usize, usize),
    name: bool,
) {
    if a == b || (name && signals[a].has_web && signals[b].has_web) {
        return;
    }
    pairs.insert((a.min(b), a.max(b)));
}

fn all_pairs(
    members: &[usize],
    signals: &[Signals],
    name: bool,
    pairs: &mut HashSet<(usize, usize)>,
) {
    for (i, &a) in members.iter().enumerate() {
        for &b in &members[i + 1..] {
            push_pair(pairs, signals, (a, b), name);
        }
    }
}

/// Pairs of a bucket. A large bucket (a domain shared by
/// hundreds of items) is subdivided: same username, same
/// password (by in-memory hash, equality is then checked in constant
/// time), or without username. Two items that have none of
/// this in common are never duplicates.
fn bucket_pairs<S: BuildHasher>(
    members: &[usize],
    signals: &[Signals],
    name: bool,
    blind: bool,
    hasher: &S,
    pairs: &mut HashSet<(usize, usize)>,
) {
    if members.len() < 2 || (name && members.iter().all(|&m| signals[m].has_web)) {
        return;
    }
    if members.len() <= SMALL_BUCKET {
        all_pairs(members, signals, name, pairs);
        return;
    }
    let mut by_user: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut by_password: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut anonymous = Vec::new();
    for &m in members {
        let s = &signals[m];
        if s.user.base.is_empty() {
            anonymous.push(m);
        } else {
            by_user.entry(s.user.base.as_str()).or_default().push(m);
        }
        if !blind {
            by_password
                .entry(hasher.hash_one(s.password))
                .or_default()
                .push(m);
        }
    }
    for group in by_user.values().chain(by_password.values()) {
        all_pairs(group, signals, name, pairs);
    }
    for &a in &anonymous {
        for &b in members {
            push_pair(pairs, signals, (a, b), name);
        }
    }
}

// MARK: Import

/// Classifies each imported item relative to the vault and to the items
/// imported before it. Cautious: only a certain duplicate is skipped
/// by default; a probable duplicate completes the vault item (a replaced
/// password goes to its history).
pub fn classify(imported: &[ImportedItem], vault: &[Item]) -> Vec<Classification> {
    let mut classifier = Classifier::new(vault);
    imported
        .iter()
        .enumerate()
        .map(|(position, item)| match item.kind {
            ImportKind::Login => classifier.login(position, item),
            ImportKind::Card => classifier.card(position, item),
            ImportKind::SecureNote => match item.template {
                Some(template) => {
                    classifier.keyed(position, template_key(template.key(), &item.title))
                }
                None => classifier.note(position, item),
            },
            ImportKind::Identity => {
                let name = item
                    .identity
                    .as_ref()
                    .map(IdentityData::full_name)
                    .unwrap_or_default();
                classifier.keyed(position, identity_key(&item.title, &name))
            }
        })
        .collect()
}

/// Index of the vault, and of the imported items already seen.
struct Classifier<'a> {
    vault: &'a [Item],
    /// Vault logins: position in the vault, and their signals.
    logins: Vec<usize>,
    login_signals: Vec<Signals<'a>>,
    login_buckets: Buckets,
    cards: HashMap<String, usize>,
    notes: HashMap<(String, String), usize>,
    /// Identities and template notes, by key.
    others: HashMap<String, usize>,
    /// New imported logins: position in the import.
    seen_logins: Vec<usize>,
    seen_signals: Vec<Signals<'a>>,
    seen_buckets: Buckets,
    seen_cards: HashMap<String, usize>,
    seen_notes: HashMap<(String, String), usize>,
    seen_others: HashMap<String, usize>,
}

const NEW: Classification = Classification {
    status: Status::New,
    decision: Decision::Create,
    reason: None,
};

fn exact(existing: Existing, reason: &str) -> Classification {
    Classification {
        status: Status::Exact(existing),
        decision: Decision::Skip,
        reason: Some(reason.to_owned()),
    }
}

impl<'a> Classifier<'a> {
    fn new(vault: &'a [Item]) -> Self {
        let mut classifier = Self {
            vault,
            logins: Vec::new(),
            login_signals: Vec::new(),
            login_buckets: Buckets::default(),
            cards: HashMap::new(),
            notes: HashMap::new(),
            others: HashMap::new(),
            seen_logins: Vec::new(),
            seen_signals: Vec::new(),
            seen_buckets: Buckets::default(),
            seen_cards: HashMap::new(),
            seen_notes: HashMap::new(),
            seen_others: HashMap::new(),
        };
        for (index, item) in vault.iter().enumerate() {
            // An item in the trash doesn't count: it will disappear.
            if item.state == ItemState::Trashed {
                continue;
            }
            match item.kind {
                ItemKind::Login => {
                    // The import goes to the personal vault, but a shared
                    // copy of the same account counts too: no vault.
                    let signals = item_signals(item, "", None);
                    classifier
                        .login_buckets
                        .add(classifier.login_signals.len(), &signals);
                    classifier.login_signals.push(signals);
                    classifier.logins.push(index);
                }
                ItemKind::Card => {
                    let digits = vault_card_digits(item);
                    if !digits.is_empty() {
                        classifier.cards.entry(digits).or_insert(index);
                    }
                }
                ItemKind::SecureNote if item.template().is_some() => {
                    let key = item
                        .template()
                        .map(crate::template::Template::key)
                        .unwrap_or_default();
                    classifier
                        .others
                        .entry(template_key(key, &item.title))
                        .or_insert(index);
                }
                ItemKind::Identity => {
                    classifier
                        .others
                        .entry(identity_key(&item.title, &vault_full_name(item)))
                        .or_insert(index);
                }
                ItemKind::SecureNote => {
                    if let Some(key) =
                        notes_key(&item.title, item.notes.as_ref().map(SecretString::expose))
                    {
                        classifier.notes.entry(key).or_insert(index);
                    }
                }
                ItemKind::SshKey => {}
            }
        }
        classifier
    }

    fn login(&mut self, position: usize, item: &'a ImportedItem) -> Classification {
        let signals = imported_signals(item);
        // The best match in the vault: the most certain, then
        // the same password, then the most recent.
        let best = self
            .login_buckets
            .candidates(&signals, &self.login_signals)
            .into_iter()
            .filter_map(|i| relate(&signals, &self.login_signals[i]).map(|r| (self.logins[i], r)))
            .max_by(|(a, ra), (b, rb)| {
                ra.confidence
                    .cmp(&rb.confidence)
                    .then(
                        (ra.password == PasswordLink::Same)
                            .cmp(&(rb.password == PasswordLink::Same)),
                    )
                    .then(self.vault[*a].modified.cmp(&self.vault[*b].modified))
            });
        if let Some((index, relation)) = best
            && relation.confidence >= Confidence::Probable
        {
            let existing = &self.vault[index];
            let reason = Some(relation.reason());
            if relation.confidence == Confidence::Certain {
                if item.totp.is_some() && !existing.has_totp() {
                    return Classification {
                        status: Status::AddsTotp(existing.id.clone()),
                        decision: Decision::Update,
                        reason,
                    };
                }
                return Classification {
                    reason,
                    ..exact(Existing::Vault(existing.id.clone()), "")
                };
            }
            if relation.password == PasswordLink::Same {
                return Classification {
                    status: Status::Similar(Existing::Vault(existing.id.clone())),
                    decision: Decision::Update,
                    reason,
                };
            }
            // The export says the item is older than the vault's: keep
            // the vault. Otherwise (or without a date), the new password replaces
            // the old one, which goes to the history.
            let older = item.modified.is_some_and(|m| m < existing.modified);
            return Classification {
                status: Status::NewPassword(Existing::Vault(existing.id.clone())),
                decision: if older {
                    Decision::Skip
                } else {
                    Decision::Update
                },
                reason,
            };
        }
        let earlier = self
            .seen_buckets
            .candidates(&signals, &self.seen_signals)
            .into_iter()
            .filter_map(|i| relate(&signals, &self.seen_signals[i]).map(|r| (i, r)))
            .filter(|(_, r)| r.confidence >= Confidence::Probable)
            // The most certain, then the first in the file.
            .max_by(|(a, ra), (b, rb)| ra.confidence.cmp(&rb.confidence).then(b.cmp(a)));
        if let Some((seen, relation)) = earlier {
            let earlier = self.seen_logins[seen];
            let reason = Some(relation.reason());
            if relation.confidence == Confidence::Certain {
                return Classification {
                    reason,
                    ..exact(Existing::Import(earlier), "")
                };
            }
            let status = if relation.password == PasswordLink::Same {
                Status::Similar(Existing::Import(earlier))
            } else {
                Status::NewPassword(Existing::Import(earlier))
            };
            return Classification {
                status,
                decision: Decision::Create,
                reason,
            };
        }
        self.seen_buckets.add(self.seen_signals.len(), &signals);
        self.seen_signals.push(signals);
        self.seen_logins.push(position);
        NEW
    }

    fn card(&mut self, position: usize, item: &ImportedItem) -> Classification {
        let digits = item
            .card
            .as_ref()
            .and_then(|c| c.number.as_ref())
            .map(|n| card_digits(n.expose()))
            .unwrap_or_default();
        if digits.is_empty() {
            return NEW;
        }
        if let Some(&index) = self.cards.get(&digits) {
            return exact(Existing::Vault(self.vault[index].id.clone()), SAME_CARD);
        }
        if let Some(&earlier) = self.seen_cards.get(&digits) {
            return exact(Existing::Import(earlier), SAME_CARD);
        }
        self.seen_cards.insert(digits, position);
        NEW
    }

    /// Identity or template note: same key, same item.
    fn keyed(&mut self, position: usize, key: String) -> Classification {
        if let Some(&index) = self.others.get(&key) {
            return exact(Existing::Vault(self.vault[index].id.clone()), SAME_NOTE);
        }
        if let Some(&earlier) = self.seen_others.get(&key) {
            return exact(Existing::Import(earlier), SAME_NOTE);
        }
        self.seen_others.insert(key, position);
        NEW
    }

    fn note(&mut self, position: usize, item: &ImportedItem) -> Classification {
        let Some(key) = notes_key(&item.title, item.notes.as_ref().map(SecretString::expose))
        else {
            return NEW;
        };
        if let Some(&index) = self.notes.get(&key) {
            return exact(Existing::Vault(self.vault[index].id.clone()), SAME_NOTE);
        }
        if let Some(&earlier) = self.seen_notes.get(&key) {
            return exact(Existing::Import(earlier), SAME_NOTE);
        }
        self.seen_notes.insert(key, position);
        NEW
    }
}

// MARK: Vault duplicates

/// An item of a duplicate group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateMember {
    pub id: String,
    /// Resemblance to the kept item; `None` for the kept item.
    pub confidence: Option<Confidence>,
    /// Why ("same site (maif.fr), same username, different password");
    /// empty for the kept item.
    pub reason: String,
    /// Checked for the trash by default: only a certain duplicate.
    pub preselected: bool,
}

/// Vault items that designate the same account (or the same card,
/// the same note).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// Fingerprint of the set of items: an ignored group doesn't come back
    /// as long as it doesn't change.
    pub key: String,
    /// Site of the kept item (or its title).
    pub label: String,
    /// Username of the kept item.
    pub username: String,
    /// The strongest level among the items.
    pub confidence: Confidence,
    /// The reason for that level.
    pub reason: String,
    /// The item suggested to keep first: passkeys, attachments, one-time
    /// code, the most recent, a URL, the most complete, the most
    /// history.
    pub members: Vec<DuplicateMember>,
    /// All items have the same password (the same value, for a
    /// card or a note).
    pub same_password: bool,
    /// Logins: "Merge" is possible.
    pub mergeable: bool,
}

impl DuplicateGroup {
    pub fn ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.id.clone()).collect()
    }

    /// The item suggested to keep.
    pub fn kept(&self) -> &str {
        &self.members[0].id
    }
}

/// Minimal union-find: each item points to the representative of its
/// group.
struct Groups(Vec<usize>);

impl Groups {
    fn root(&mut self, mut i: usize) -> usize {
        while self.0[i] != i {
            self.0[i] = self.0[self.0[i]];
            i = self.0[i];
        }
        i
    }

    fn join(&mut self, a: usize, b: usize) -> usize {
        let (a, b) = (self.root(a), self.root(b));
        let (low, high) = (a.min(b), a.max(b));
        self.0[high] = low;
        low
    }
}

fn history_len(item: &Item) -> usize {
    item.fields
        .iter()
        .filter(|f| f.id.starts_with("history-"))
        .count()
}

fn richness(item: &Item) -> usize {
    usize::from(item.notes.is_some())
        + item
            .fields
            .iter()
            .filter(|f| f.id.starts_with("custom-"))
            .count()
}

/// Fingerprint of a set of items (order-independent).
pub fn group_key(ids: &[String]) -> String {
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let digest = Sha256::digest(sorted.join("\n").as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..12])
}

/// The vault's duplicate groups, most certain first.
pub fn find_duplicates(items: &[Item]) -> Vec<DuplicateGroup> {
    find_duplicates_with(items, &HashMap::new())
}

/// Like [`find_duplicates`], with the passkeys and attachments of each
/// item (by id).
#[allow(clippy::implicit_hasher)]
pub fn find_duplicates_with(
    items: &[Item],
    extras: &HashMap<String, ItemExtras>,
) -> Vec<DuplicateGroup> {
    Finder::new(items, extras, false).groups()
}

/// Like [`find_duplicates_with`], without ever comparing two passwords or two
/// one-time code seeds: the groups, their confidence and their reasons say
/// nothing about whether secrets are equal. For what an agent may read: a
/// group only tells that logins look alike by site, title and username.
#[allow(clippy::implicit_hasher)]
pub fn find_duplicates_blind_with(
    items: &[Item],
    extras: &HashMap<String, ItemExtras>,
) -> Vec<DuplicateGroup> {
    Finder::new(items, extras, true).groups()
}

fn owner_of(item: &Item) -> &str {
    item.shared
        .as_ref()
        .map_or("", |s| s.organization_id.as_str())
}

/// Key of a card or a note: (kind, value, value, vault).
type ExactKey<'a> = (u8, String, String, &'a str);

/// A "to review" link that rests only on a missing username (different
/// password): the item without a username resembles every account
/// of the site. It joins one only if there is just one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vague {
    No,
    /// This item (position in `items`) has no username.
    From(usize),
    /// Neither has one.
    Both,
}

#[derive(Clone, Copy, Debug)]
struct Edge {
    a: usize,
    b: usize,
    level: Confidence,
    vague: Vague,
}

struct Finder<'a> {
    items: &'a [Item],
    extras: &'a HashMap<String, ItemExtras>,
    signals: Vec<Signals<'a>>,
    /// Position in `items` → position in `signals`.
    login_of: HashMap<usize, usize>,
    /// Resemblances (positions in `items`).
    edges: Vec<Edge>,
    /// Passwords and seeds are never compared (see [`find_duplicates_blind_with`]).
    blind: bool,
}

impl<'a> Finder<'a> {
    fn new(items: &'a [Item], extras: &'a HashMap<String, ItemExtras>, blind: bool) -> Self {
        let mut logins = Vec::new();
        let mut signals = Vec::new();
        let mut login_of = HashMap::new();
        let mut edges = Vec::new();
        // Cards and notes: same key, same item.
        let mut first: HashMap<ExactKey, usize> = HashMap::new();
        for (index, item) in items.iter().enumerate() {
            // Archive and trash: already set aside. A read-only shared
            // item cannot go to the trash.
            if !item.is_active() || !item.is_writable() {
                continue;
            }
            // A personal copy and a shared copy are not
            // duplicates to clean up: only compare within the same vault.
            let owner = owner_of(item);
            let key: ExactKey = match item.kind {
                ItemKind::Login => {
                    login_of.insert(index, signals.len());
                    logins.push(index);
                    signals.push(item_signals(item, owner, extras.get(&item.id)));
                    continue;
                }
                ItemKind::Card => {
                    let digits = vault_card_digits(item);
                    if digits.is_empty() {
                        continue;
                    }
                    (1, digits, String::new(), owner)
                }
                ItemKind::SecureNote => {
                    match notes_key(&item.title, item.notes.as_ref().map(SecretString::expose)) {
                        Some((title, notes)) => (2, title, notes, owner),
                        None => continue,
                    }
                }
                ItemKind::Identity | ItemKind::SshKey => continue,
            };
            match first.get(&key) {
                Some(&other) => edges.push(Edge {
                    a: other,
                    b: index,
                    level: Confidence::Certain,
                    vague: Vague::No,
                }),
                None => {
                    first.insert(key, index);
                }
            }
        }
        let mut buckets = Buckets::default();
        for (position, s) in signals.iter().enumerate() {
            buckets.add(position, s);
        }
        let mut pairs: Vec<(usize, usize)> = buckets.pairs(&signals, blind).into_iter().collect();
        pairs.sort_unstable();
        for (a, b) in pairs {
            if let Some(relation) = relate_with(&signals[a], &signals[b], blind) {
                let vague = if relation.confidence == Confidence::Review
                    && relation.password != PasswordLink::Same
                {
                    match relation.user {
                        signals::UserLink::BothMissing => Vague::Both,
                        signals::UserLink::OneMissing if signals[a].user.full.is_empty() => {
                            Vague::From(logins[a])
                        }
                        signals::UserLink::OneMissing => Vague::From(logins[b]),
                        _ => Vague::No,
                    }
                } else {
                    Vague::No
                };
                edges.push(Edge {
                    a: logins[a],
                    b: logins[b],
                    level: relation.confidence,
                    vague,
                });
            }
        }
        Self {
            items,
            extras,
            signals,
            login_of,
            edges,
            blind,
        }
    }

    /// The resemblance of `other` to `kept`, and its reason.
    fn describe(&self, kept: usize, other: usize) -> Option<(Confidence, String)> {
        match self.items[kept].kind {
            ItemKind::Login => {
                let (a, b) = (self.login_of.get(&kept)?, self.login_of.get(&other)?);
                relate_with(&self.signals[*a], &self.signals[*b], self.blind).map(|r| {
                    let reason = if self.blind {
                        r.reason_without_secrets()
                    } else {
                        r.reason()
                    };
                    (r.confidence, reason)
                })
            }
            ItemKind::Card => Some((Confidence::Certain, SAME_CARD.to_owned())),
            _ => Some((Confidence::Certain, SAME_NOTE.to_owned())),
        }
    }

    /// Preference order of the item to keep: what can't be merged
    /// (passkeys, attachments), the one-time code, the most
    /// recent, a URL, the most complete, the most history.
    fn rank(&self, index: usize) -> (bool, bool, bool, i64, bool, usize, usize) {
        let item = &self.items[index];
        let extras = self.extras.get(&item.id);
        (
            extras.is_some_and(|e| !e.passkey_sites.is_empty()),
            extras.is_some_and(|e| e.attachments > 0),
            item.has_totp(),
            item.modified,
            !item.urls.is_empty(),
            richness(item),
            history_len(item),
        )
    }

    fn groups(self) -> Vec<DuplicateGroup> {
        let n = self.items.len();
        let mut groups = Groups((0..n).collect());
        // Strong links first (certain, probable). A "to review" link
        // never merges two already formed groups: it attaches a lone
        // item to a group, or two lone items to each other.
        for edge in &self.edges {
            if edge.level >= Confidence::Probable {
                groups.join(edge.a, edge.b);
            }
        }
        let mut size = vec![0usize; n];
        for i in 0..n {
            let root = groups.root(i);
            size[root] += 1;
        }
        let core: Vec<bool> = (0..n).map(|i| size[groups.root(i)] > 1).collect();
        let mut anchored: Vec<bool> = (0..n).map(|i| size[i] > 1).collect();
        let mut neighbours: HashMap<usize, Vec<(usize, Confidence)>> = HashMap::new();
        for edge in &self.edges {
            neighbours
                .entry(edge.a)
                .or_default()
                .push((edge.b, edge.level));
            neighbours
                .entry(edge.b)
                .or_default()
                .push((edge.a, edge.level));
            if edge.level >= Confidence::Probable || edge.vague != Vague::No {
                continue;
            }
            let (ra, rb) = (groups.root(edge.a), groups.root(edge.b));
            if ra == rb || (anchored[ra] && anchored[rb]) {
                continue;
            }
            let either = anchored[ra] || anchored[rb];
            let root = groups.join(edge.a, edge.b);
            anchored[root] = either;
        }
        // Finally, a lone item without a username joins the only group (or
        // the only item) that resembles it; if there are several, nothing.
        let mut targets: HashMap<usize, HashSet<usize>> = HashMap::new();
        for edge in &self.edges {
            let pairs: &[(usize, usize)] = match edge.vague {
                Vague::No => &[],
                Vague::From(x) if x == edge.a => &[(edge.a, edge.b)],
                Vague::From(_) => &[(edge.b, edge.a)],
                Vague::Both => &[(edge.a, edge.b), (edge.b, edge.a)],
            };
            for &(anonymous, other) in pairs {
                let root = groups.root(other);
                targets.entry(anonymous).or_default().insert(root);
            }
        }
        let mut targets: Vec<(usize, HashSet<usize>)> = targets.into_iter().collect();
        targets.sort_unstable_by_key(|(x, _)| *x);
        let mut count = vec![0usize; n];
        for i in 0..n {
            let root = groups.root(i);
            count[root] += 1;
        }
        for (anonymous, roots) in targets {
            let own = groups.root(anonymous);
            let mut roots = roots.into_iter().map(|r| groups.root(r));
            if let (Some(target), None) = (roots.next(), roots.next())
                && count[own] == 1
                && target != own
            {
                let total = count[own] + count[target];
                let root = groups.join(anonymous, target);
                count[root] = total;
            }
        }

        let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
        for index in 0..n {
            let root = groups.root(index);
            members.entry(root).or_default().push(index);
        }
        let mut result: Vec<DuplicateGroup> = members
            .into_values()
            .filter(|m| m.len() > 1)
            .map(|mut m| {
                // The kept item comes from the group's core (strong links),
                // not from an item attached as "to review".
                let has_core = m.iter().any(|&i| core[i]);
                m.sort_by(|&a, &b| {
                    (core[b] || !has_core)
                        .cmp(&(core[a] || !has_core))
                        .then_with(|| self.rank(b).cmp(&self.rank(a)))
                        .then_with(|| self.items[a].id.cmp(&self.items[b].id))
                });
                self.group(&m, &neighbours)
            })
            .collect();
        result.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| fold(&a.label).cmp(&fold(&b.label)))
                .then_with(|| a.username.cmp(&b.username))
                .then_with(|| a.key.cmp(&b.key))
        });
        result
    }

    /// A group, with the item to keep first.
    fn group(
        &self,
        members: &[usize],
        neighbours: &HashMap<usize, Vec<(usize, Confidence)>>,
    ) -> DuplicateGroup {
        let kept_index = members[0];
        let keep = &self.items[kept_index];
        let mut list = vec![DuplicateMember {
            id: keep.id.clone(),
            confidence: None,
            reason: String::new(),
            preselected: false,
        }];
        for &other in &members[1..] {
            let (confidence, reason) = self.describe(kept_index, other).unwrap_or_else(|| {
                // Linked to the kept item only through another item.
                let via = neighbours
                    .get(&other)
                    .into_iter()
                    .flatten()
                    .filter(|(n, _)| members.contains(n))
                    .max_by_key(|(_, level)| *level)
                    .map_or("", |(n, _)| self.items[*n].title.as_str());
                (Confidence::Review, format!("close to \"{via}\""))
            });
            list.push(DuplicateMember {
                id: self.items[other].id.clone(),
                confidence: Some(confidence),
                reason,
                preselected: confidence == Confidence::Certain,
            });
        }
        let (confidence, reason) = list[1..]
            .iter()
            .filter_map(|m| m.confidence.map(|c| (c, m.reason.clone())))
            .max_by_key(|(c, _)| *c)
            .unwrap_or((Confidence::Review, String::new()));
        let same_password = match keep.kind {
            ItemKind::Login => members
                .iter()
                .all(|&i| same_secret(vault_password(&self.items[i]), vault_password(keep))),
            // Same number, same note: grouped because identical.
            _ => true,
        };
        let label = match keep.kind {
            ItemKind::Login => keep
                .urls
                .iter()
                .find_map(|u| site_of(u))
                .unwrap_or_else(|| keep.title.clone()),
            _ => keep.title.clone(),
        };
        let ids: Vec<String> = list.iter().map(|m| m.id.clone()).collect();
        DuplicateGroup {
            key: group_key(&ids),
            label,
            username: vault_username(keep).unwrap_or_default().trim().to_owned(),
            confidence,
            reason,
            members: list,
            same_password,
            mergeable: keep.kind == ItemKind::Login,
        }
    }
}
