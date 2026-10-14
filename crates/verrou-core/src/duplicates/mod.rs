//! Doublons : entre un import et le coffre, et à l'intérieur du coffre.
//!
//! Un même compte arrive souvent plusieurs fois, d'Apple, de 1Password et
//! de Proton Pass, avec des adresses et des titres différents
//! (`connect.maif.fr`, `www.maif.fr/espace-perso`, « Maif », « MAIF -
//! Espace sociétaire »). Chaque identifiant est donc résumé en signaux
//! (`signals`) : sites et domaines de ses adresses (schéma, port, chemin
//! et préfixes de connexion ignorés ; adresses d'app comparées entre
//! elles), titre normalisé et sa marque (« Maif » ↔ `maif.fr`), identifiant
//! normalisé, passkeys. Les mots de passe et les graines TOTP sont comparés
//! ici, dans Rust, en temps constant : l'interface ne reçoit qu'un verdict.
//!
//! Trois degrés :
//! - **Certain** : même site (ou marque ↔ domaine), même identifiant, même
//!   mot de passe. Les copies sont cochées pour la corbeille.
//! - **Probable** : même site, même identifiant, autre mot de passe (ou un
//!   identifiant manquant, même mot de passe) ; même titre, même
//!   identifiant, sans adresse. Suggéré, pas coché.
//! - **À vérifier** : même site, autres identifiants mais même mot de
//!   passe ; même marque sans identifiant ; deux sous-domaines (souvent
//!   deux services : `cloud.exemple.fr` et `vault.exemple.fr`). Jamais
//!   coché.
//!
//! Les comparaisons se font par paquets (même domaine, même app, même
//! marque, même titre), jamais tout le coffre contre tout le coffre.

mod signals;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use sha2::{Digest as _, Sha256};

pub use signals::{Confidence, site_of};
use signals::{PasswordLink, Signals, Source, relate, same_secret};

use crate::import::{IdentityData, ImportKind, ImportedItem};
use crate::model::{Item, ItemKind, ItemState};
use crate::search::fold;
use crate::secret::SecretString;

/// L'élément déjà connu auquel un élément importé ressemble.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Existing {
    /// Identifiant d'un élément du coffre.
    Vault(String),
    /// Position d'un élément plus haut dans le même import.
    Import(usize),
}

/// Ce qu'est un élément importé par rapport au coffre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    /// Doublon certain (même site, même identifiant, même mot de passe) :
    /// déjà présent.
    Exact(Existing),
    /// Déjà présent, mais l'import apporte un code à usage unique que
    /// l'élément du coffre n'a pas.
    AddsTotp(String),
    /// Doublon probable, avec un autre mot de passe.
    NewPassword(Existing),
    /// Doublon probable, même mot de passe (un identifiant manquant, ou un
    /// titre sans site) : à compléter plutôt qu'à créer.
    Similar(Existing),
}

/// Ce que l'import fera d'un élément.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Ne pas l'importer (garder l'existant).
    Skip,
    /// Le créer, à côté de l'existant s'il y en a un.
    Create,
    /// Compléter l'élément du coffre : nouveau mot de passe (l'ancien
    /// rejoint l'historique), code à usage unique et sites manquants.
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub status: Status,
    /// Choix proposé par défaut.
    pub decision: Decision,
    /// Pourquoi il ressemble à l'existant (« même site (maif.fr), même
    /// identifiant, autre mot de passe »). Jamais de secret.
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

/// Clé d'une note d'un modèle (Wi-Fi, passeport…) : le modèle et le titre.
fn template_key(template: &str, title: &str) -> String {
    format!("modèle:{template}:{}", fold(title.trim()))
}

/// Clé d'une identité : le titre et le nom complet.
fn identity_key(title: &str, full_name: &str) -> String {
    format!("identité:{}:{}", fold(title.trim()), fold(full_name.trim()))
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

const SAME_CARD: &str = "même numéro de carte";
const SAME_NOTE: &str = "même titre, même contenu";

/// Ce que le coffre sait d'un élément en dehors de ses champs : ses
/// passkeys et ses pièces jointes. Rien de cela ne se fusionne : l'élément
/// qui en a est gardé de préférence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemExtras {
    /// Sites des passkeys (`rpId`).
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

// MARK: Paquets

/// Au-delà, un paquet n'est plus comparé paire par paire : seulement les
/// éléments qui partagent un identifiant ou un mot de passe, et ceux sans
/// identifiant.
const SMALL_BUCKET: usize = 48;

/// Paquets d'identifiants : même domaine ou même app (« web »), même marque
/// ou même titre (« nom » : seulement pour un élément sans adresse web).
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

    /// Éléments indexés qui peuvent ressembler à `signals` (pour l'import).
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

    /// Paires à comparer, chacune une fois.
    fn pairs(&self, signals: &[Signals]) -> HashSet<(usize, usize)> {
        let hasher = std::collections::hash_map::RandomState::new();
        let mut pairs = HashSet::new();
        for members in self.web.values() {
            bucket_pairs(members, signals, false, &hasher, &mut pairs);
        }
        for members in self.name.values() {
            bucket_pairs(members, signals, true, &hasher, &mut pairs);
        }
        pairs
    }
}

/// Une paire à comparer. Dans un paquet « nom », l'un des deux au moins
/// est sans adresse web.
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

/// Paires d'un paquet. Un grand paquet (un domaine partagé par des
/// centaines d'éléments) se subdivise : même identifiant, même mot de
/// passe (par empreinte en mémoire, l'égalité est vérifiée ensuite en temps
/// constant), ou sans identifiant. Deux éléments qui n'ont rien de tout
/// cela en commun ne sont jamais des doublons.
fn bucket_pairs<S: BuildHasher>(
    members: &[usize],
    signals: &[Signals],
    name: bool,
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
        by_password
            .entry(hasher.hash_one(s.password))
            .or_default()
            .push(m);
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

/// Classe chaque élément importé par rapport au coffre et aux éléments
/// importés avant lui. Prudent : seul un doublon certain est ignoré
/// d'office ; un doublon probable complète l'élément du coffre (un mot de
/// passe remplacé rejoint son historique).
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

/// Index du coffre, et des éléments importés déjà vus.
struct Classifier<'a> {
    vault: &'a [Item],
    /// Identifiants du coffre : position dans le coffre, et leurs signaux.
    logins: Vec<usize>,
    login_signals: Vec<Signals<'a>>,
    login_buckets: Buckets,
    cards: HashMap<String, usize>,
    notes: HashMap<(String, String), usize>,
    /// Identités et notes des modèles, par clé.
    others: HashMap<String, usize>,
    /// Identifiants importés nouveaux : position dans l'import.
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
            // Un élément à la corbeille ne compte pas : il va disparaître.
            if item.state == ItemState::Trashed {
                continue;
            }
            match item.kind {
                ItemKind::Login => {
                    // L'import va dans le coffre personnel, mais une copie
                    // partagée du même compte compte aussi : pas de coffre.
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
        // Le meilleur rapprochement dans le coffre : le plus certain, puis
        // le même mot de passe, puis le plus récent.
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
            // L'export dit l'élément plus ancien que celui du coffre : on garde
            // le coffre. Sinon (ou sans date), le nouveau mot de passe remplace
            // l'ancien, qui rejoint l'historique.
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
            // Le plus certain, puis le premier du fichier.
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

    /// Identité ou note d'un modèle : même clé, même élément.
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

// MARK: Doublons du coffre

/// Un élément d'un groupe de doublons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateMember {
    pub id: String,
    /// Ressemblance avec l'élément gardé ; `None` pour l'élément gardé.
    pub confidence: Option<Confidence>,
    /// Pourquoi (« même site (maif.fr), même identifiant, autre mot de
    /// passe ») ; vide pour l'élément gardé.
    pub reason: String,
    /// Coché d'office pour la corbeille : seulement un doublon certain.
    pub preselected: bool,
}

/// Des éléments du coffre qui désignent le même compte (ou la même carte,
/// la même note).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// Empreinte de l'ensemble des éléments : un groupe ignoré ne revient
    /// pas tant qu'il ne change pas.
    pub key: String,
    /// Site de l'élément gardé (ou son titre).
    pub label: String,
    /// Identifiant de l'élément gardé.
    pub username: String,
    /// Le degré le plus fort parmi les éléments.
    pub confidence: Confidence,
    /// La raison de ce degré.
    pub reason: String,
    /// L'élément suggéré à garder d'abord : passkeys, pièces jointes, code
    /// à usage unique, le plus récent, une adresse, le plus complet, le plus
    /// d'historique.
    pub members: Vec<DuplicateMember>,
    /// Tous les éléments ont le même mot de passe (la même valeur, pour une
    /// carte ou une note).
    pub same_password: bool,
    /// Des identifiants : « Fusionner » est possible.
    pub mergeable: bool,
}

impl DuplicateGroup {
    pub fn ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.id.clone()).collect()
    }

    /// L'élément suggéré à garder.
    pub fn kept(&self) -> &str {
        &self.members[0].id
    }
}

/// Union-find minimal : chaque élément pointe vers le représentant de son
/// groupe.
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

/// Empreinte d'un ensemble d'éléments (ordre indifférent).
pub fn group_key(ids: &[String]) -> String {
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let digest = Sha256::digest(sorted.join("\n").as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..12])
}

/// Les groupes de doublons du coffre, les plus certains d'abord.
pub fn find_duplicates(items: &[Item]) -> Vec<DuplicateGroup> {
    find_duplicates_with(items, &HashMap::new())
}

/// Comme [`find_duplicates`], avec les passkeys et pièces jointes de chaque
/// élément (par identifiant).
#[allow(clippy::implicit_hasher)]
pub fn find_duplicates_with(
    items: &[Item],
    extras: &HashMap<String, ItemExtras>,
) -> Vec<DuplicateGroup> {
    Finder::new(items, extras).groups()
}

fn owner_of(item: &Item) -> &str {
    item.shared
        .as_ref()
        .map_or("", |s| s.organization_id.as_str())
}

/// Clé d'une carte ou d'une note : (sorte, valeur, valeur, coffre).
type ExactKey<'a> = (u8, String, String, &'a str);

/// Un lien « à vérifier » qui ne tient qu'à un identifiant manquant (autre
/// mot de passe) : l'élément sans identifiant ressemble à tous les comptes
/// du site. Il ne s'y rattache que s'il n'y en a qu'un.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vague {
    No,
    /// Cet élément (position dans `items`) n'a pas d'identifiant.
    From(usize),
    /// Aucun des deux n'en a.
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
    /// Position dans `items` → position dans `signals`.
    login_of: HashMap<usize, usize>,
    /// Ressemblances (positions dans `items`).
    edges: Vec<Edge>,
}

impl<'a> Finder<'a> {
    fn new(items: &'a [Item], extras: &'a HashMap<String, ItemExtras>) -> Self {
        let mut logins = Vec::new();
        let mut signals = Vec::new();
        let mut login_of = HashMap::new();
        let mut edges = Vec::new();
        // Cartes et notes : même clé, même élément.
        let mut first: HashMap<ExactKey, usize> = HashMap::new();
        for (index, item) in items.iter().enumerate() {
            // Archives et corbeille : déjà rangés à l'écart. Un élément partagé
            // en lecture seule ne peut pas partir à la corbeille.
            if !item.is_active() || !item.is_writable() {
                continue;
            }
            // Une copie personnelle et une copie partagée ne sont pas des
            // doublons à nettoyer : on ne compare que dans un même coffre.
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
        let mut pairs: Vec<(usize, usize)> = buckets.pairs(&signals).into_iter().collect();
        pairs.sort_unstable();
        for (a, b) in pairs {
            if let Some(relation) = relate(&signals[a], &signals[b]) {
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
        }
    }

    /// La ressemblance de `other` avec `kept`, et sa raison.
    fn describe(&self, kept: usize, other: usize) -> Option<(Confidence, String)> {
        match self.items[kept].kind {
            ItemKind::Login => {
                let (a, b) = (self.login_of.get(&kept)?, self.login_of.get(&other)?);
                relate(&self.signals[*a], &self.signals[*b]).map(|r| (r.confidence, r.reason()))
            }
            ItemKind::Card => Some((Confidence::Certain, SAME_CARD.to_owned())),
            _ => Some((Confidence::Certain, SAME_NOTE.to_owned())),
        }
    }

    /// Ordre de préférence de l'élément à garder : ce qui ne se fusionne
    /// pas (passkeys, pièces jointes), le code à usage unique, le plus
    /// récent, une adresse, le plus complet, le plus d'historique.
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
        // D'abord les liens forts (certain, probable). Un lien « à vérifier »
        // ne réunit jamais deux groupes déjà formés : il rattache un élément
        // isolé à un groupe, ou deux éléments isolés entre eux.
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
        // Enfin, un élément isolé sans identifiant rejoint le seul groupe (ou
        // le seul élément) qui lui ressemble ; s'il y en a plusieurs, rien.
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
                // L'élément gardé vient du cœur du groupe (liens forts),
                // pas d'un élément rattaché « à vérifier ».
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

    /// Un groupe, l'élément à garder en tête.
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
                // Relié à l'élément gardé par un autre élément seulement.
                let via = neighbours
                    .get(&other)
                    .into_iter()
                    .flatten()
                    .filter(|(n, _)| members.contains(n))
                    .max_by_key(|(_, level)| *level)
                    .map_or("", |(n, _)| self.items[*n].title.as_str());
                (Confidence::Review, format!("proche de « {via} »"))
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
            // Même numéro, même note : regroupés parce qu'identiques.
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
