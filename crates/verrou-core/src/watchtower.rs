//! Compléments de l'audit : double authentification disponible mais absente,
//! cartes expirées ou bientôt expirées, mots de passe anciens, et repérage des
//! mots de passe nouveaux (pour les vérifier dans les fuites connues).
//!
//! Comme `audit`, tout se calcule ici sans réseau : la liste des sites qui
//! proposent la double authentification (2fa.directory) est téléchargée et
//! mise en cache par `verrou-vaultwarden` (`two_factor_directory`), puis
//! analysée par `TwoFactorDirectory::parse`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::audit::password_of;
use crate::matching::{host_of, registrable_domain};
use crate::{FieldKind, Item, ItemKind, Vault};

/// Une carte expire dans moins de ce nombre de jours : à renouveler.
pub const CARD_WARNING_DAYS: i64 = 60;
/// Un mot de passe que rien n'a changé depuis ce nombre de jours (3 ans).
pub const OLD_PASSWORD_DAYS: i64 = 3 * 365;

const DAY: i64 = 24 * 60 * 60;

// MARK: Double authentification

/// Un site de 2fa.directory qui propose la double authentification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorSite {
    pub name: String,
    /// Domaine principal, normalisé (minuscules, sans `www.`).
    pub domain: String,
    /// Méthodes proposées, telles que la liste les nomme (`totp`, `sms`,
    /// `u2f`, `call`, `email`, `custom-software`, `custom-hardware`).
    pub methods: Vec<String>,
    /// Page d'aide du site pour activer la double authentification.
    pub documentation: Option<String>,
}

impl TwoFactorSite {
    /// Codes à usage unique (TOTP) : Verrou peut les garder et les remplir.
    pub fn supports_totp(&self) -> bool {
        self.methods.iter().any(|m| m == "totp")
    }
}

/// Entrée brute de `tfa.json` (format v3 : `[nom, {domain, tfa, …}]`).
#[derive(Deserialize)]
struct RawSite {
    domain: String,
    #[serde(default, rename = "additional-domains")]
    additional_domains: Vec<String>,
    #[serde(default)]
    tfa: Vec<String>,
    #[serde(default)]
    documentation: Option<String>,
}

/// Liste des sites qui proposent la double authentification, indexée par
/// domaine (principal et secondaires).
#[derive(Clone, Debug, Default)]
pub struct TwoFactorDirectory {
    sites: Vec<TwoFactorSite>,
    by_domain: HashMap<String, usize>,
}

impl TwoFactorDirectory {
    /// Analyse `https://api.2fa.directory/v3/tfa.json`. Les entrées
    /// illisibles sont ignorées : une évolution du format ne doit pas priver
    /// l'audit de toute la liste.
    pub fn parse(json: &[u8]) -> Result<Self, serde_json::Error> {
        let entries: Vec<(String, serde_json::Value)> = serde_json::from_slice(json)?;
        let mut directory = Self::default();
        for (name, value) in entries {
            let Ok(raw) = serde_json::from_value::<RawSite>(value) else {
                continue;
            };
            let Some(domain) = host_of(&raw.domain) else {
                continue;
            };
            if raw.tfa.is_empty() {
                continue;
            }
            // Seules les pages d'aide en HTTPS sont proposées à l'ouverture.
            let documentation = raw
                .documentation
                .filter(|d| d.trim().starts_with("https://"))
                .map(|d| d.trim().to_owned());
            let index = directory.sites.len();
            for extra in std::iter::once(domain.clone())
                .chain(raw.additional_domains.iter().filter_map(|d| host_of(d)))
            {
                directory.by_domain.entry(extra).or_insert(index);
            }
            directory.sites.push(TwoFactorSite {
                name,
                domain,
                methods: raw.tfa,
                documentation,
            });
        }
        Ok(directory)
    }

    pub fn len(&self) -> usize {
        self.sites.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Le site dont relève `url` : l'hôte lui-même, puis ses domaines
    /// parents jusqu'au domaine enregistrable (`login.github.com` →
    /// `github.com`), jamais au-delà (`co.uk` n'est pas un site).
    /// `amazon.com` ne relève pas d'une entrée `aws.amazon.com`.
    pub fn lookup(&self, url: &str) -> Option<&TwoFactorSite> {
        let host = host_of(url)?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let floor = registrable_domain(&host)?;
        let mut candidate = host.as_str();
        loop {
            if let Some(&index) = self.by_domain.get(candidate) {
                return Some(&self.sites[index]);
            }
            if candidate == floor {
                return None;
            }
            candidate = candidate.split_once('.')?.1;
        }
    }
}

/// Identifiants (actifs, avec un mot de passe) dont un site propose la double
/// authentification, mais qui n'ont pas de code à usage unique dans Verrou.
/// Triés par titre.
pub fn missing_two_factor<'d>(
    vault: &Vault,
    directory: &'d TwoFactorDirectory,
) -> Vec<(String, &'d TwoFactorSite)> {
    let mut found: Vec<(&Item, &TwoFactorSite)> = vault
        .items()
        .iter()
        .filter(|i| i.kind == ItemKind::Login && i.is_active() && !i.has_totp())
        .filter(|i| password_of(i).is_some())
        .filter_map(|i| {
            i.urls
                .iter()
                .find_map(|u| directory.lookup(u))
                .map(|site| (i, site))
        })
        .collect();
    found.sort_by_key(|(i, _)| i.title.to_lowercase());
    found
        .into_iter()
        .map(|(i, site)| (i.id.clone(), site))
        .collect()
}

// MARK: Cartes

/// Échéance d'une carte bancaire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardExpiry {
    pub year: i32,
    /// 1 à 12.
    pub month: u32,
}

impl CardExpiry {
    /// Lit `MM/AA`, `MM/AAAA`, `M/AA`, `MM-AA`, `MM / AAAA`… Une année à
    /// deux chiffres est de ce siècle (`29` → 2029).
    pub fn parse(text: &str) -> Option<Self> {
        let (month, year) = text.split_once(['/', '-', '.'])?;
        let month: u32 = month.trim().parse().ok()?;
        let year = year.trim();
        if !(1..=12).contains(&month) || !year.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let year: i32 = match year.len() {
            2 => 2000 + year.parse::<i32>().ok()?,
            4 => year.parse().ok()?,
            _ => return None,
        };
        Some(Self { year, month })
    }

    /// Jours entre `now` (horodatage Unix, UTC) et la fin du mois
    /// d'expiration, compris : une carte « 09/29 » vaut jusqu'au 30 septembre
    /// 2029 inclus. Négatif : expirée.
    pub fn days_left(self, now: i64) -> i64 {
        let (next_year, next_month) = if self.month == 12 {
            (self.year + 1, 1)
        } else {
            (self.year, self.month + 1)
        };
        // Premier jour du mois suivant, moins aujourd'hui.
        days_from_civil(next_year, next_month, 1) - now.div_euclid(DAY) - 1
    }
}

/// Jours depuis le 1er janvier 1970 (algorithme de Howard Hinnant).
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Une carte expirée, ou qui expire dans moins de `CARD_WARNING_DAYS` jours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiringCard {
    pub id: String,
    pub expiry: CardExpiry,
    /// Négatif : expirée depuis autant de jours.
    pub days_left: i64,
}

impl ExpiringCard {
    pub fn expired(&self) -> bool {
        self.days_left < 0
    }
}

/// Cartes actives expirées ou bientôt expirées, la plus ancienne échéance
/// d'abord. `now` : horodatage Unix.
pub fn expiring_cards(vault: &Vault, now: i64) -> Vec<ExpiringCard> {
    let mut cards: Vec<ExpiringCard> = vault
        .items()
        .iter()
        .filter(|i| i.kind == ItemKind::Card && i.is_active())
        .filter_map(|i| {
            let expiry = CardExpiry::parse(i.field_of_kind(FieldKind::Expiry)?.value.expose())?;
            let days_left = expiry.days_left(now);
            (days_left <= CARD_WARNING_DAYS).then(|| ExpiringCard {
                id: i.id.clone(),
                expiry,
                days_left,
            })
        })
        .collect();
    cards.sort_by_key(|c| c.days_left);
    cards
}

// MARK: Mots de passe anciens

/// Identifiants dont l'élément n'a pas été modifié depuis plus de
/// `OLD_PASSWORD_DAYS` jours, le plus ancien d'abord, avec leur âge en jours.
///
/// La date de modification de l'élément borne celle du mot de passe : si
/// l'élément n'a pas bougé depuis 3 ans, son mot de passe non plus. Un
/// élément retouché récemment (titre, dossier) sans changer de mot de passe
/// échappe donc à la liste : jamais de fausse alerte, quelques oublis.
pub fn old_passwords(vault: &Vault, now: i64) -> Vec<(String, i64)> {
    let mut old: Vec<(String, i64)> = vault
        .items()
        .iter()
        .filter(|i| i.kind == ItemKind::Login && i.is_active() && i.modified > 0)
        .filter(|i| password_of(i).is_some())
        .map(|i| (i.id.clone(), (now - i.modified).div_euclid(DAY)))
        .filter(|(_, days)| *days > OLD_PASSWORD_DAYS)
        .collect();
    old.sort_by_key(|(_, days)| std::cmp::Reverse(*days));
    old
}

// MARK: Nouveaux mots de passe

/// Identifiants actifs parmi `after` dont le mot de passe est nouveau : absent
/// de `before` (élément créé) ou différent. Sert à vérifier dans les fuites
/// connues les mots de passe que l'on vient d'enregistrer.
pub fn changed_passwords(before: Option<&Vault>, after: &[Item]) -> Vec<String> {
    after
        .iter()
        .filter(|i| i.is_active())
        .filter_map(|i| {
            let password = password_of(i)?;
            let previous = before.and_then(|b| b.get(&i.id)).and_then(password_of);
            (previous != Some(password)).then(|| i.id.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Field, ItemState};

    fn item(id: &str, kind: ItemKind, url: &str, fields: Vec<Field>) -> Item {
        Item {
            id: id.to_owned(),
            kind,
            title: id.to_owned(),
            subtitle: String::new(),
            urls: if url.is_empty() {
                Vec::new()
            } else {
                vec![url.to_owned()]
            },
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields,
            notes: None,
            reprompt: false,
            state: ItemState::Active,
        }
    }

    fn login(id: &str, url: &str, password: &str) -> Item {
        item(
            id,
            ItemKind::Login,
            url,
            vec![Field::new(
                "password",
                "Mot de passe",
                FieldKind::Password,
                password,
            )],
        )
    }

    fn card(id: &str, expiry: &str) -> Item {
        item(
            id,
            ItemKind::Card,
            "",
            vec![Field::new(
                "expiry",
                "Expiration",
                FieldKind::Expiry,
                expiry,
            )],
        )
    }

    /// Extrait de `tfa.json` (format v3), avec des entrées que l'analyse doit
    /// ignorer sans échouer.
    const FIXTURE: &str = r#"[
        ["GitHub", {"domain": "github.com", "tfa": ["totp", "u2f", "sms"],
                    "documentation": "https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa"}],
        ["Amazon Web Services", {"domain": "aws.amazon.com", "tfa": ["totp", "u2f"],
                    "documentation": "https://aws.amazon.com/iam/features/mfa/"}],
        ["1Password", {"domain": "1password.com", "additional-domains": ["1password.ca", "1password.eu"],
                    "tfa": ["totp"], "documentation": "https://support.1password.com/two-factor-authentication/",
                    "keywords": ["identity"]}],
        ["Banque", {"domain": "WWW.Banque.co.uk", "tfa": ["sms", "custom-software"],
                    "custom-software": ["App"], "documentation": "http://banque.co.uk/2fa"}],
        ["Sans méthode", {"domain": "rien.fr", "tfa": []}],
        ["Cassé", {"tfa": ["totp"]}],
        ["Inconnu", 42]
    ]"#;

    fn directory() -> TwoFactorDirectory {
        TwoFactorDirectory::parse(FIXTURE.as_bytes()).unwrap()
    }

    #[test]
    fn parses_the_dataset() {
        let dir = directory();
        assert_eq!(dir.len(), 4);
        let github = dir.lookup("https://github.com").unwrap();
        assert_eq!(github.name, "GitHub");
        assert!(github.supports_totp());
        assert!(
            github
                .documentation
                .as_deref()
                .unwrap()
                .starts_with("https://docs.github.com")
        );
        // Domaine normalisé ; page d'aide en HTTP écartée.
        let bank = dir.lookup("banque.co.uk").unwrap();
        assert_eq!(bank.domain, "banque.co.uk");
        assert!(!bank.supports_totp());
        assert_eq!(bank.documentation, None);
        assert!(TwoFactorDirectory::parse(b"{}").is_err());
    }

    #[test]
    fn lookup_normalises_hosts_and_walks_up_to_the_registrable_domain() {
        let dir = directory();
        for url in [
            "https://www.github.com/login",
            "https://GITHUB.com",
            "github.com",
            "https://gist.github.com/x",
            "https://a.b.github.com:8443/",
            "https://1password.eu/signin",
            "https://my.1password.ca",
            "https://console.aws.amazon.com/",
            "https://shop.banque.co.uk",
        ] {
            assert!(dir.lookup(url).is_some(), "{url}");
        }
        for url in [
            // Le domaine parent n'hérite pas d'une entrée plus précise.
            "https://amazon.com",
            "https://www.amazon.com/gp/cart",
            "https://github.io",
            "https://evilgithub.com",
            "https://github.com.evil.fr",
            "https://co.uk",
            "https://192.168.1.10",
            "",
        ] {
            assert!(dir.lookup(url).is_none(), "{url}");
        }
    }

    #[test]
    fn flags_logins_without_a_one_time_code() {
        let dir = directory();
        let mut with_totp = login("avec code", "https://github.com", "x");
        with_totp.fields.push(Field::new(
            "totp",
            "Code",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        let mut archived = login("archivé", "https://github.com", "x");
        archived.state = ItemState::Archived;
        let vault = Vault::new(vec![
            login("GitHub perso", "https://github.com/login", "x"),
            with_totp,
            archived,
            login("sans mot de passe", "https://github.com", ""),
            login("AWS", "https://console.aws.amazon.com", "x"),
            login("Amazon", "https://www.amazon.com", "x"),
            login("Inconnu", "https://exemple.fr", "x"),
        ]);
        let found: Vec<(String, String)> = missing_two_factor(&vault, &dir)
            .into_iter()
            .map(|(id, site)| (id, site.name.clone()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("AWS".to_owned(), "Amazon Web Services".to_owned()),
                ("GitHub perso".to_owned(), "GitHub".to_owned()),
            ]
        );
    }

    #[test]
    fn reads_card_expiry_formats() {
        let cases = [
            ("09/29", Some((2029, 9))),
            ("9/29", Some((2029, 9))),
            ("12/2031", Some((2031, 12))),
            ("01 / 27", Some((2027, 1))),
            ("03-28", Some((2028, 3))),
            ("13/29", None),
            ("00/29", None),
            ("09/029", None),
            ("09/2x", None),
            ("0929", None),
            ("", None),
        ];
        for (text, expected) in cases {
            assert_eq!(
                CardExpiry::parse(text).map(|e| (e.year, e.month)),
                expected,
                "{text}"
            );
        }
    }

    /// Horodatage Unix de minuit UTC, le jour donné.
    fn at(year: i32, month: u32, day: u32) -> i64 {
        days_from_civil(year, month, day) * DAY
    }

    #[test]
    fn card_expiry_boundaries() {
        assert_eq!(at(1970, 1, 1), 0);
        assert_eq!(at(2000, 3, 1), 951_868_800);
        let sept = CardExpiry::parse("09/26").unwrap();
        // Valable jusqu'au dernier jour du mois, compris.
        assert_eq!(sept.days_left(at(2026, 9, 30) + 23 * 3600), 0);
        assert_eq!(sept.days_left(at(2026, 10, 1)), -1);
        assert_eq!(sept.days_left(at(2026, 9, 1)), 29);
        // Décembre : la fin du mois passe à l'année suivante.
        let dec = CardExpiry::parse("12/26").unwrap();
        assert_eq!(dec.days_left(at(2026, 12, 31)), 0);
        assert_eq!(dec.days_left(at(2027, 1, 1)), -1);
        // Février d'une année bissextile.
        let feb = CardExpiry::parse("02/28").unwrap();
        assert_eq!(feb.days_left(at(2028, 2, 1)), 28);
    }

    #[test]
    fn lists_expired_and_soon_expired_cards() {
        let now = at(2026, 10, 14);
        let mut trashed = card("corbeille", "01/20");
        trashed.state = ItemState::Trashed;
        let vault = Vault::new(vec![
            card("expirée", "09/26"),
            card("ce mois-ci", "10/26"),
            card("le mois prochain", "11/2026"),
            card("dans 78 jours", "12/2026"),
            card("lointaine", "09/29"),
            card("illisible", "bientôt"),
            trashed,
            item("sans échéance", ItemKind::Card, "", Vec::new()),
        ]);
        let cards = expiring_cards(&vault, now);
        let ids: Vec<&str> = cards.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["expirée", "ce mois-ci", "le mois prochain"]);
        assert!(cards[0].expired());
        assert_eq!(cards[0].days_left, -14);
        assert!(!cards[1].expired());
        assert_eq!(cards[1].days_left, 17);
        assert_eq!(cards[2].days_left, 47);
    }

    #[test]
    fn finds_old_passwords() {
        let now = at(2026, 10, 14);
        let mut old = login("ancien", "https://a.fr", "x");
        old.modified = at(2022, 1, 1);
        let mut recent = login("récent", "https://b.fr", "x");
        recent.modified = at(2025, 1, 1);
        let mut unknown = login("date inconnue", "https://c.fr", "x");
        unknown.modified = 0;
        let vault = Vault::new(vec![recent, old, unknown]);
        let found = old_passwords(&vault, now);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "ancien");
        assert!(found[0].1 > OLD_PASSWORD_DAYS);
    }

    #[test]
    fn spots_new_and_changed_passwords() {
        let before = Vault::new(vec![
            login("même", "https://a.fr", "un"),
            login("changé", "https://b.fr", "deux"),
        ]);
        let mut note = item("note", ItemKind::SecureNote, "", Vec::new());
        note.notes = Some(crate::SecretString::new("texte"));
        let after = [
            login("même", "https://a.fr", "un"),
            login("changé", "https://b.fr", "trois"),
            login("créé", "https://c.fr", "quatre"),
            login("vide", "https://d.fr", ""),
            note,
        ];
        assert_eq!(
            changed_passwords(Some(&before), &after),
            vec!["changé".to_owned(), "créé".to_owned()]
        );
        assert_eq!(changed_passwords(None, before.items()).len(), 2);
    }
}
