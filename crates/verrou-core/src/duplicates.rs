//! Doublons : entre un import et le coffre, et à l'intérieur du coffre.
//!
//! Deux identifiants désignent le même compte s'ils partagent un site et le
//! même identifiant (sans tenir compte de la casse ni des espaces). Le site
//! est l'hôte, aux préfixes de connexion près (`www.`, `login.`,
//! `accounts.`… : `login.github.com` et `github.com` sont le même site),
//! et non le domaine enregistrable du remplissage : `cloud.exemple.fr` et
//! `vault.exemple.fr` sont deux services distincts, souvent avec le même
//! identifiant. Sans site, c'est le titre qui sert de site. Les mots de
//! passe sont comparés ici, dans Rust : l'interface ne reçoit que le verdict.

use std::collections::HashMap;

use crate::import::{ImportKind, ImportedItem};
use crate::matching::{host_of, registrable_domain};
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
    /// Même site, même identifiant, même mot de passe : déjà présent.
    Exact(Existing),
    /// Déjà présent, mais l'import apporte un code à usage unique que
    /// l'élément du coffre n'a pas.
    AddsTotp(String),
    /// Même site et même identifiant, autre mot de passe.
    NewPassword(Existing),
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
}

/// Premiers niveaux d'un hôte qui désignent la page de connexion d'un site,
/// pas un service à part.
const LOGIN_PREFIXES: [&str; 12] = [
    "login", "signin", "auth", "account", "accounts", "id", "sso", "secure", "m", "mobile", "my",
    "app",
];

/// Site d'une adresse : son hôte sans `www.` ni préfixe de connexion, jamais
/// plus court que le domaine enregistrable.
pub fn site_of(url: &str) -> Option<String> {
    let host = host_of(url)?;
    let domain = registrable_domain(&host)?;
    let mut site = host.as_str();
    while site.len() > domain.len() {
        match site.split_once('.') {
            Some((label, rest)) if LOGIN_PREFIXES.contains(&label) => site = rest,
            _ => break,
        }
    }
    Some(site.to_owned())
}

/// Sites d'un élément ; à défaut, son titre.
fn sites(urls: &[String], title: &str) -> Vec<String> {
    let mut sites: Vec<String> = urls.iter().filter_map(|u| site_of(u)).collect();
    sites.sort();
    sites.dedup();
    if sites.is_empty() {
        sites.push(format!("titre:{}", fold(title.trim())));
    }
    sites
}

fn normalize_username(username: Option<&str>) -> String {
    username.unwrap_or_default().trim().to_lowercase()
}

fn keys(urls: &[String], title: &str, username: Option<&str>) -> Vec<(String, String)> {
    let user = normalize_username(username);
    sites(urls, title)
        .into_iter()
        .map(|site| (site, user.clone()))
        .collect()
}

fn vault_username(item: &Item) -> Option<&str> {
    item.field("username").map(|f| f.value.expose())
}

fn vault_password(item: &Item) -> &str {
    item.field("password").map_or("", |f| f.value.expose())
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

fn notes_key(title: &str, notes: Option<&str>) -> Option<(String, String)> {
    let notes = notes.map(str::trim).filter(|n| !n.is_empty())?;
    Some((fold(title.trim()), notes.to_owned()))
}

/// Classe chaque élément importé par rapport au coffre et aux éléments
/// importés avant lui.
pub fn classify(imported: &[ImportedItem], vault: &[Item]) -> Vec<Classification> {
    let mut classifier = Classifier::new(imported, vault);
    imported
        .iter()
        .enumerate()
        .map(|(position, item)| match item.kind {
            ImportKind::Login => classifier.login(position, item),
            ImportKind::Card => classifier.card(position, item),
            ImportKind::SecureNote => classifier.note(position, item),
        })
        .collect()
}

/// Index du coffre, et des éléments importés déjà vus.
struct Classifier<'a> {
    imported: &'a [ImportedItem],
    vault: &'a [Item],
    logins: HashMap<(String, String), Vec<usize>>,
    cards: HashMap<String, usize>,
    notes: HashMap<(String, String), usize>,
    seen_logins: HashMap<(String, String), usize>,
    seen_cards: HashMap<String, usize>,
    seen_notes: HashMap<(String, String), usize>,
}

const NEW: Classification = Classification {
    status: Status::New,
    decision: Decision::Create,
};

fn exact(existing: Existing) -> Classification {
    Classification {
        status: Status::Exact(existing),
        decision: Decision::Skip,
    }
}

impl<'a> Classifier<'a> {
    fn new(imported: &'a [ImportedItem], vault: &'a [Item]) -> Self {
        let mut classifier = Self {
            imported,
            vault,
            logins: HashMap::new(),
            cards: HashMap::new(),
            notes: HashMap::new(),
            seen_logins: HashMap::new(),
            seen_cards: HashMap::new(),
            seen_notes: HashMap::new(),
        };
        for (index, item) in vault.iter().enumerate() {
            // Un élément à la corbeille ne compte pas : il va disparaître.
            if item.state == ItemState::Trashed {
                continue;
            }
            match item.kind {
                ItemKind::Login => {
                    for key in keys(&item.urls, &item.title, vault_username(item)) {
                        classifier.logins.entry(key).or_default().push(index);
                    }
                }
                ItemKind::Card => {
                    let digits = vault_card_digits(item);
                    if !digits.is_empty() {
                        classifier.cards.entry(digits).or_insert(index);
                    }
                }
                ItemKind::SecureNote => {
                    if let Some(key) =
                        notes_key(&item.title, item.notes.as_ref().map(SecretString::expose))
                    {
                        classifier.notes.entry(key).or_insert(index);
                    }
                }
                ItemKind::Identity | ItemKind::SshKey => {}
            }
        }
        classifier
    }

    fn login(&mut self, position: usize, item: &ImportedItem) -> Classification {
        let item_keys = keys(&item.urls, &item.title, item.username.as_deref());
        let mut candidates: Vec<usize> = item_keys
            .iter()
            .filter_map(|k| self.logins.get(k))
            .flatten()
            .copied()
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        // Le plus récent d'abord.
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.vault[i].modified));
        if let Some(&first) = candidates.first() {
            let password = imported_password(item);
            if let Some(&same) = candidates
                .iter()
                .find(|&&i| vault_password(&self.vault[i]) == password)
            {
                let existing = &self.vault[same];
                if item.totp.is_some() && !existing.has_totp() {
                    return Classification {
                        status: Status::AddsTotp(existing.id.clone()),
                        decision: Decision::Update,
                    };
                }
                return exact(Existing::Vault(existing.id.clone()));
            }
            let existing = &self.vault[first];
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
            };
        }
        if let Some(&earlier) = item_keys.iter().find_map(|k| self.seen_logins.get(k)) {
            if imported_password(&self.imported[earlier]) == imported_password(item) {
                return exact(Existing::Import(earlier));
            }
            return Classification {
                status: Status::NewPassword(Existing::Import(earlier)),
                decision: Decision::Create,
            };
        }
        for key in item_keys {
            self.seen_logins.entry(key).or_insert(position);
        }
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
            return exact(Existing::Vault(self.vault[index].id.clone()));
        }
        if let Some(&earlier) = self.seen_cards.get(&digits) {
            return exact(Existing::Import(earlier));
        }
        self.seen_cards.insert(digits, position);
        NEW
    }

    fn note(&mut self, position: usize, item: &ImportedItem) -> Classification {
        let Some(key) = notes_key(&item.title, item.notes.as_ref().map(SecretString::expose))
        else {
            return NEW;
        };
        if let Some(&index) = self.notes.get(&key) {
            return exact(Existing::Vault(self.vault[index].id.clone()));
        }
        if let Some(&earlier) = self.seen_notes.get(&key) {
            return exact(Existing::Import(earlier));
        }
        self.seen_notes.insert(key, position);
        NEW
    }
}

/// Des éléments du coffre qui désignent le même compte (ou la même carte,
/// la même note).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// Site commun (ou titre, pour une carte ou une note).
    pub label: String,
    /// Identifiant commun, tel que l'élément suggéré l'écrit.
    pub username: String,
    /// Identifiants des éléments, le premier étant celui qu'il est suggéré
    /// de garder : le code à usage unique d'abord, puis le plus récemment
    /// modifié, puis le plus complet (sites, champs, notes).
    pub items: Vec<String>,
    /// Tous les éléments ont le même mot de passe (la même valeur, pour une
    /// carte ou une note).
    pub same_password: bool,
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

    fn join(&mut self, a: usize, b: usize) {
        let (a, b) = (self.root(a), self.root(b));
        if a != b {
            self.0[b.max(a)] = a.min(b);
        }
    }
}

fn richness(item: &Item) -> usize {
    item.urls.len() + item.fields.len() + usize::from(item.notes.is_some())
}

/// Les groupes de doublons du coffre, triés par site.
pub fn find_duplicates(items: &[Item]) -> Vec<DuplicateGroup> {
    let mut groups = Groups((0..items.len()).collect());
    let mut first: HashMap<(u8, String, String), usize> = HashMap::new();
    for (index, item) in items.iter().enumerate() {
        // Archives et corbeille : déjà rangés à l'écart.
        if !item.is_active() {
            continue;
        }
        let item_keys: Vec<(u8, String, String)> = match item.kind {
            ItemKind::Login => keys(&item.urls, &item.title, vault_username(item))
                .into_iter()
                .map(|(site, user)| (0, site, user))
                .collect(),
            ItemKind::Card => {
                let digits = vault_card_digits(item);
                if digits.is_empty() {
                    continue;
                }
                vec![(1, digits, String::new())]
            }
            ItemKind::SecureNote => {
                match notes_key(&item.title, item.notes.as_ref().map(SecretString::expose)) {
                    Some((title, notes)) => vec![(2, title, notes)],
                    None => continue,
                }
            }
            ItemKind::Identity | ItemKind::SshKey => continue,
        };
        for key in item_keys {
            match first.get(&key) {
                Some(&other) => groups.join(other, index),
                None => {
                    first.insert(key, index);
                }
            }
        }
    }

    let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
    for index in 0..items.len() {
        let root = groups.root(index);
        members.entry(root).or_default().push(index);
    }
    let mut result: Vec<DuplicateGroup> = members
        .into_values()
        .filter(|m| m.len() > 1)
        .map(|mut m| {
            m.sort_by(|&a, &b| {
                let (a, b) = (&items[a], &items[b]);
                b.has_totp()
                    .cmp(&a.has_totp())
                    .then(b.modified.cmp(&a.modified))
                    .then(richness(b).cmp(&richness(a)))
            });
            let keep = &items[m[0]];
            let same_password = match keep.kind {
                ItemKind::Login => m
                    .iter()
                    .all(|&i| vault_password(&items[i]) == vault_password(keep)),
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
            DuplicateGroup {
                label,
                username: vault_username(keep).unwrap_or_default().trim().to_owned(),
                items: m.iter().map(|&i| items[i].id.clone()).collect(),
                same_password,
            }
        })
        .collect();
    result.sort_by(|a, b| {
        fold(&a.label)
            .cmp(&fold(&b.label))
            .then_with(|| a.username.cmp(&b.username))
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, FieldKind};

    fn login(id: &str, url: &str, username: &str, password: &str, modified: i64) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: username.to_owned(),
            urls: if url.is_empty() {
                Vec::new()
            } else {
                vec![url.to_owned()]
            },
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Username, username),
                Field::new("password", "Mot de passe", FieldKind::Password, password),
            ],
            notes: None,
            reprompt: false,
            state: ItemState::Active,
        }
    }

    fn imported(url: &str, username: &str, password: &str) -> ImportedItem {
        ImportedItem {
            kind: ImportKind::Login,
            title: "importé".to_owned(),
            username: Some(username.to_owned()),
            password: Some(SecretString::new(password)),
            urls: vec![url.to_owned()],
            totp: None,
            notes: None,
            folder: None,
            favorite: false,
            card: None,
            fields: Vec::new(),
            modified: None,
        }
    }

    #[test]
    fn imported_logins_are_classified() {
        let vault = vec![
            login("gh", "https://github.com", "Camille", "un", 100),
            login(
                "bank",
                "https://www.banque.fr/espace",
                "camille",
                "deux",
                100,
            ),
        ];
        let mut with_totp = imported("https://github.com/login", "camille", "un");
        with_totp.totp = Some(SecretString::new("JBSWY3DPEHPK3PXP"));
        let mut old = imported("https://banque.fr", "camille", "ancien");
        old.modified = Some(50);
        let items = vec![
            imported("https://login.github.com", " CAMILLE ", "un"),
            imported("https://banque.fr", "camille", "trois"),
            with_totp,
            old,
            imported("https://forum.fr", "cam", "x"),
            imported("https://forum.fr", "cam", "x"),
            imported("https://www.forum.fr", "cam", "y"),
            imported("https://github.io", "camille", "un"),
        ];
        let result = classify(&items, &vault);
        let statuses: Vec<&Status> = result.iter().map(|c| &c.status).collect();
        assert_eq!(statuses[0], &Status::Exact(Existing::Vault("gh".into())));
        assert_eq!(
            result[1],
            Classification {
                status: Status::NewPassword(Existing::Vault("bank".into())),
                decision: Decision::Update,
            }
        );
        assert_eq!(statuses[2], &Status::AddsTotp("gh".into()));
        assert_eq!(
            result[3].decision,
            Decision::Skip,
            "plus ancien que le coffre"
        );
        assert_eq!(statuses[4], &Status::New);
        assert_eq!(statuses[5], &Status::Exact(Existing::Import(4)));
        assert_eq!(statuses[6], &Status::NewPassword(Existing::Import(4)));
        assert_eq!(statuses[7], &Status::New, "github.io n'est pas github.com");
    }

    #[test]
    fn sites_keep_services_apart() {
        assert_eq!(
            site_of("https://login.github.com/x").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            site_of("https://www.github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            site_of("https://id.github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            site_of("https://cloud.example.net").as_deref(),
            Some("cloud.example.net")
        );
        // Jamais plus court que le domaine enregistrable.
        assert_eq!(site_of("https://app.co.uk").as_deref(), Some("app.co.uk"));
        let mut trashed = login("Nextcloud", "https://cloud.example.net", "camille", "a", 0);
        trashed.state = ItemState::Trashed;
        let items = vec![
            login("Nextcloud", "https://cloud.example.net", "camille", "a", 1),
            login("Vaultwarden", "https://vault.example.net", "camille", "b", 2),
            trashed,
        ];
        assert_eq!(
            find_duplicates(&items),
            Vec::new(),
            "la corbeille ne compte pas"
        );
        let mut import = imported("https://cloud.example.net", "camille", "a");
        import.title = "Nextcloud".to_owned();
        assert_eq!(classify(&[import], &items[2..])[0].status, Status::New);
    }

    #[test]
    fn logins_without_site_compare_titles() {
        let vault = vec![login("Routeur", "", "admin", "a", 0)];
        let mut item = imported("", "admin", "a");
        item.urls.clear();
        item.title = "routeur".to_owned();
        assert_eq!(
            classify(&[item], &vault)[0].status,
            Status::Exact(Existing::Vault("Routeur".into()))
        );
    }

    #[test]
    fn duplicates_in_the_vault_suggest_the_best_item() {
        let mut with_totp = login("ancien", "https://github.com", "camille", "a", 10);
        with_totp.fields.push(Field::new(
            "totp",
            "Code",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        let items = vec![
            login("récent", "https://accounts.github.com", "Camille", "b", 20),
            with_totp,
            login("autre", "https://github.com", "dominique", "a", 30),
            login("b1", "https://banque.fr", "camille", "same", 1),
            login("b2", "https://www.banque.fr", "camille", "same", 2),
        ];
        let groups = find_duplicates(&items);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "banque.fr");
        assert_eq!(groups[0].items, vec!["b2", "b1"]);
        assert!(groups[0].same_password);
        assert_eq!(groups[1].label, "github.com");
        assert_eq!(
            groups[1].items,
            vec!["ancien", "récent"],
            "le code TOTP d'abord"
        );
        assert!(!groups[1].same_password);
    }
}
