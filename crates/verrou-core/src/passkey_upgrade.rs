//! « Passer aux passkeys » : les identifiants dont le site accepte les
//! passkeys, mais qui n'en ont pas encore dans Verrou.
//!
//! Comme `watchtower`, tout se calcule ici sans réseau : l'annuaire des sites
//! qui acceptent les passkeys (passkeys.2fa.directory) est téléchargé en
//! entier et mis en cache par `verrou-vaultwarden` (`passkey_directory`),
//! puis analysé par `PasskeyDirectory::parse`. Aucune requête par site.
//!
//! La page où créer la passkey (« Créer une passkey ») se cherche, elle,
//! seulement sur demande et pour un seul élément : norme du W3C « Passkey
//! Endpoints » (`/.well-known/passkey-endpoints`), vérifiée par
//! `verrou_vaultwarden::passkey_setup`, puis une courte table de grands
//! sites (`known_setup_url`), puis l'adresse de l'annuaire ou l'accueil.

use std::collections::HashMap;

use serde::Deserialize;

use crate::audit::password_of;
use crate::matching::{host_of, registrable_domain};
use crate::watchtower::lookup_domain;
use crate::{FieldKind, Item, ItemKind, Vault};

/// Chemin normalisé des adresses de passkeys d'un site (W3C).
pub const ENDPOINTS_PATH: &str = "/.well-known/passkey-endpoints";

/// Longueur maximale des notes de l'annuaire gardées pour l'affichage.
const MAX_NOTES: usize = 300;

/// Ce que le site permet avec une passkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Proposée, facultative.
    Allowed,
    /// Imposée par le site.
    Required,
}

impl Support {
    fn parse(text: Option<&str>) -> Option<Self> {
        match text?.trim() {
            "allowed" => Some(Self::Allowed),
            "required" => Some(Self::Required),
            _ => None,
        }
    }
}

/// Un site de l'annuaire qui accepte les passkeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeySite {
    /// Domaine de l'annuaire, normalisé (minuscules, sans `www.`).
    pub domain: String,
    /// Connexion sans mot de passe : la passkey remplace le mot de passe.
    pub passwordless: Option<Support>,
    /// Passkey en second facteur, après le mot de passe.
    pub mfa: Option<Support>,
    /// Page d'aide du site sur les passkeys (HTTPS).
    pub documentation: Option<String>,
    /// Adresse du site quand ce n'est pas `https://<domaine>` (HTTPS).
    pub url: Option<String>,
    /// Remarque de l'annuaire (en anglais), courte.
    pub notes: Option<String>,
}

impl PasskeySite {
    /// La passkey peut remplacer le mot de passe à la connexion.
    pub fn passwordless(&self) -> bool {
        self.passwordless.is_some()
    }
}

/// Entrée brute de l'annuaire (`v1/supported.json` ou `v1/all.json` :
/// `{ "<domaine>": { passwordless, mfa, documentation, … } }`).
#[derive(Deserialize)]
struct RawSite {
    #[serde(default)]
    passwordless: Option<String>,
    #[serde(default)]
    mfa: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default, rename = "additional-domains")]
    additional_domains: Vec<String>,
}

fn https(text: Option<String>) -> Option<String> {
    text.map(|t| t.trim().to_owned())
        .filter(|t| t.starts_with("https://") && t.len() > "https://".len())
}

/// Annuaire des sites qui acceptent les passkeys, indexé par domaine
/// (principal et secondaires) et par domaine enregistrable.
#[derive(Clone, Debug, Default)]
pub struct PasskeyDirectory {
    sites: Vec<PasskeySite>,
    by_domain: HashMap<String, usize>,
    /// Domaine enregistrable → premier site (sans mot de passe d'abord),
    /// pour les sites listés seulement par sous-domaine (`mail.google.com`).
    by_registrable: HashMap<String, usize>,
}

impl PasskeyDirectory {
    /// Analyse l'annuaire. Les entrées illisibles, ou sans passkey (le
    /// fichier complet liste aussi les sites à démarcher), sont ignorées :
    /// une évolution du format ne doit pas priver l'audit de toute la liste.
    pub fn parse(json: &[u8]) -> Result<Self, serde_json::Error> {
        let entries: HashMap<String, serde_json::Value> = serde_json::from_slice(json)?;
        // Ordre stable (le JSON est un objet) : par domaine.
        let mut entries: Vec<(String, serde_json::Value)> = entries.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut directory = Self::default();
        for (key, value) in entries {
            let Ok(raw) = serde_json::from_value::<RawSite>(value) else {
                continue;
            };
            let Some(domain) = host_of(&key) else {
                continue;
            };
            if domain.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let passwordless = Support::parse(raw.passwordless.as_deref());
            let mfa = Support::parse(raw.mfa.as_deref());
            if passwordless.is_none() && mfa.is_none() {
                continue;
            }
            let notes = raw
                .notes
                .map(|n| n.trim().chars().take(MAX_NOTES).collect::<String>())
                .filter(|n| !n.is_empty());
            let index = directory.sites.len();
            for extra in std::iter::once(domain.clone())
                .chain(raw.additional_domains.iter().filter_map(|d| host_of(d)))
            {
                if let Some(registrable) = registrable_domain(&extra) {
                    directory
                        .by_registrable
                        .entry(registrable)
                        .and_modify(|current| {
                            // Un site sans mot de passe passe devant.
                            if passwordless.is_some()
                                && directory.sites[*current].passwordless.is_none()
                            {
                                *current = index;
                            }
                        })
                        .or_insert(index);
                }
                directory.by_domain.entry(extra).or_insert(index);
            }
            directory.sites.push(PasskeySite {
                domain,
                passwordless,
                mfa,
                documentation: https(raw.documentation),
                url: https(raw.url),
                notes,
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

    /// Le site dont relève `url` : d'abord comme l'audit de la double
    /// authentification (l'hôte, puis ses domaines parents jusqu'au domaine
    /// enregistrable), sinon un site du même domaine enregistrable : les
    /// comptes sont communs à tout le domaine (`accounts.google.com` relève
    /// de `mail.google.com`, seul listé). Jamais au-delà (`co.uk`).
    pub fn lookup(&self, url: &str) -> Option<&PasskeySite> {
        if let Some(index) = lookup_domain(&self.by_domain, url) {
            return Some(&self.sites[index]);
        }
        let host = host_of(url)?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let registrable = registrable_domain(&host)?;
        // Un nom sans suffixe public (`routeur`) n'est pas un site.
        psl::domain_str(&registrable)?;
        self.by_registrable
            .get(&registrable)
            .map(|&index| &self.sites[index])
    }
}

/// Nom d'utilisateur (ou e-mail) d'un identifiant, en minuscules.
fn user_of(item: &Item) -> Option<String> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose().trim().to_lowercase())
        .filter(|u| !u.is_empty())
}

/// L'identifiant a-t-il déjà une passkey : la sienne (`fido2Credentials`),
/// ou une passkey du même compte rangée dans un autre identifiant actif
/// (même domaine enregistrable, même nom d'utilisateur) ?
fn has_passkey(vault: &Vault, item: &Item) -> bool {
    if !vault.passkeys_of(&item.id).is_empty() {
        return true;
    }
    let domains: Vec<String> = item
        .urls
        .iter()
        .filter_map(|u| registrable_domain(u))
        .collect();
    let Some(user) = user_of(item) else {
        return false;
    };
    vault.passkeys().iter().any(|p| {
        vault
            .get(&p.item)
            .is_some_and(|owner| owner.kind == ItemKind::Login && owner.is_active())
            && registrable_domain(&p.rp_id).is_some_and(|d| domains.contains(&d))
            && p.user_name
                .as_deref()
                .is_some_and(|name| name.trim().to_lowercase() == user)
    })
}

/// Identifiants actifs, avec un mot de passe, dont le site accepte les
/// passkeys mais qui n'en ont pas encore. Triés par titre.
pub fn passkey_candidates<'d>(
    vault: &Vault,
    directory: &'d PasskeyDirectory,
) -> Vec<(String, &'d PasskeySite)> {
    let mut found: Vec<(&Item, &PasskeySite)> = vault
        .items()
        .iter()
        .filter(|i| i.kind == ItemKind::Login && i.is_active())
        .filter(|i| password_of(i).is_some())
        .filter_map(|i| {
            i.urls
                .iter()
                .find_map(|u| directory.lookup(u))
                .map(|site| (i, site))
        })
        .filter(|(i, _)| !has_passkey(vault, i))
        .collect();
    found.sort_by_key(|(i, _)| i.title.to_lowercase());
    found
        .into_iter()
        .map(|(i, site)| (i.id.clone(), site))
        .collect()
}

// MARK: Page de création

/// Grands sites qui ne publient pas `/.well-known/passkey-endpoints`, et
/// leur page de passkeys (ou de sécurité du compte), par domaine
/// enregistrable. Liste courte, à garder à jour à la main.
const KNOWN: &[(&[&str], &str)] = &[
    (
        &["google.com", "youtube.com", "gmail.com"],
        "https://myaccount.google.com/signinoptions/passkeys",
    ),
    (&["github.com"], "https://github.com/settings/security"),
    (
        &[
            "microsoft.com",
            "live.com",
            "outlook.com",
            "hotmail.com",
            "xbox.com",
            "office.com",
            "microsoft365.com",
        ],
        "https://account.microsoft.com/security",
    ),
    (
        &["paypal.com"],
        "https://www.paypal.com/myaccount/security/",
    ),
];

/// Page de passkeys connue d'avance pour l'hôte d'un élément.
pub fn known_setup_url(host: &str) -> Option<String> {
    let domain = registrable_domain(host)?;
    KNOWN
        .iter()
        .find(|(domains, _)| domains.contains(&domain.as_str()))
        .map(|(_, url)| (*url).to_owned())
}

/// Adresses publiées par un site (`/.well-known/passkey-endpoints`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Page où créer une passkey.
    pub enroll: Option<String>,
    /// Page où gérer ses passkeys.
    pub manage: Option<String>,
}

impl Endpoints {
    /// La page à ouvrir pour créer une passkey : `enroll`, sinon `manage`.
    pub fn setup(&self) -> Option<&str> {
        self.enroll.as_deref().or(self.manage.as_deref())
    }
}

#[derive(Deserialize)]
struct RawEndpoints {
    #[serde(default)]
    enroll: Option<String>,
    #[serde(default)]
    manage: Option<String>,
}

/// Lit la réponse de `/.well-known/passkey-endpoints`. Seules les adresses
/// HTTPS du même domaine enregistrable que `host` sont gardées : le fichier
/// ne doit pas pouvoir envoyer l'utilisateur ailleurs.
pub fn parse_endpoints(json: &[u8], host: &str) -> Option<Endpoints> {
    let raw: RawEndpoints = serde_json::from_slice(json).ok()?;
    let site = registrable_domain(host)?;
    let same_site = |url: Option<String>| {
        https(url).filter(|u| registrable_domain(u).as_deref() == Some(site.as_str()))
    };
    let endpoints = Endpoints {
        enroll: same_site(raw.enroll),
        manage: same_site(raw.manage),
    };
    endpoints.setup().is_some().then_some(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::Passkey;
    use crate::{Field, ItemState, SecretString};

    /// Extrait de `https://passkeys-api.2fa.directory/v1/supported.json`
    /// (octobre 2026), avec des entrées que l'analyse doit ignorer.
    const FIXTURE: &str = r#"{
        "github.com": {"mfa": "allowed", "passwordless": "allowed",
            "documentation": "https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys",
            "recovery": "https://docs.github.com/en/github/authenticating-to-github/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials"},
        "amazon.com": {"passwordless": "allowed",
            "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p",
            "notes": "Passkeys must be activated individually on different regional Amazon sites, such as UK and DE."},
        "aws.amazon.com": {"mfa": "allowed", "passwordless": "allowed",
            "documentation": "https://aws.amazon.com/iam/features/mfa/"},
        "mail.google.com": {"mfa": "allowed", "passwordless": "allowed",
            "documentation": "https://safety.google/authentication/passkey/"},
        "nest.google.com": {"mfa": "allowed",
            "documentation": "https://support.google.com/googlenest/answer/9295081"},
        "1password.com": {"mfa": "allowed",
            "documentation": "https://support.1password.com/two-factor-authentication/"},
        "xbox.com": {"passwordless": "allowed", "url": "https://www.xbox.com/live",
            "documentation": "http://learn.microsoft.com/passwordless"},
        "WWW.Exemple.co.uk": {"passwordless": "required", "additional-domains": ["exemple.fr"]},
        "2k.com": {"contact": {"form": "https://support.2k.com/", "twitter": "2K"}},
        "banque.fr": {"passwordless": "peut-être"},
        "cassé.fr": 42,
        "192.168.1.1": {"passwordless": "allowed"}
    }"#;

    fn directory() -> PasskeyDirectory {
        PasskeyDirectory::parse(FIXTURE.as_bytes()).unwrap()
    }

    fn login(id: &str, url: &str, user: &str, password: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: String::new(),
            urls: vec![url.to_owned()],
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Username, user),
                Field::new("password", "Mot de passe", FieldKind::Password, password),
            ],
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        }
    }

    fn passkey(item: &str, rp_id: &str, user: &str) -> Passkey {
        Passkey {
            item: item.to_owned(),
            credential_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            rp_id: rp_id.to_owned(),
            rp_name: None,
            user_handle: Some("dXNlcg".to_owned()),
            user_name: Some(user.to_owned()),
            user_display_name: None,
            counter: 0,
            discoverable: true,
            created: 0,
            key: SecretString::new("clé"),
        }
    }

    #[test]
    fn parses_the_directory() {
        let dir = directory();
        // github, amazon, aws, mail.google, nest.google, 1password, xbox, exemple.
        assert_eq!(dir.len(), 8);
        let github = dir.lookup("https://github.com").unwrap();
        assert_eq!(github.domain, "github.com");
        assert!(github.passwordless());
        assert_eq!(github.mfa, Some(Support::Allowed));
        assert!(
            github
                .documentation
                .as_deref()
                .unwrap()
                .starts_with("https://docs.github.com/")
        );
        // Second facteur seulement.
        let onepassword = dir.lookup("1password.com").unwrap();
        assert!(!onepassword.passwordless());
        assert_eq!(onepassword.mfa, Some(Support::Allowed));
        // Adresse du site gardée, aide en HTTP écartée.
        let xbox = dir.lookup("https://www.xbox.com").unwrap();
        assert_eq!(xbox.url.as_deref(), Some("https://www.xbox.com/live"));
        assert_eq!(xbox.documentation, None);
        // Domaine normalisé, domaine secondaire, « required ».
        let exemple = dir.lookup("https://exemple.fr/connexion").unwrap();
        assert_eq!(exemple.domain, "exemple.co.uk");
        assert_eq!(exemple.passwordless, Some(Support::Required));
        assert!(
            dir.lookup("https://amazon.com")
                .unwrap()
                .notes
                .as_deref()
                .unwrap()
                .starts_with("Passkeys must")
        );
        // Sans passkey (contact seulement), valeur inconnue, IP : ignorés.
        for url in ["2k.com", "banque.fr", "https://192.168.1.1"] {
            assert!(dir.lookup(url).is_none(), "{url}");
        }
        assert!(PasskeyDirectory::parse(b"[]").is_err());
        assert!(PasskeyDirectory::parse(b"{}").unwrap().is_empty());
    }

    #[test]
    fn lookup_matches_by_registrable_domain() {
        let dir = directory();
        let site = |url: &str| dir.lookup(url).map(|s| s.domain.clone());
        // Hôte exact et sous-domaines.
        assert_eq!(
            site("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            site("https://gist.github.com").as_deref(),
            Some("github.com")
        );
        // L'entrée la plus précise gagne ; le parent garde la sienne.
        assert_eq!(
            site("https://console.aws.amazon.com").as_deref(),
            Some("aws.amazon.com")
        );
        assert_eq!(
            site("https://www.amazon.com/gp/cart").as_deref(),
            Some("amazon.com")
        );
        // Site listé seulement par sous-domaines : même domaine enregistrable,
        // et la connexion sans mot de passe passe devant le second facteur.
        assert_eq!(
            site("https://accounts.google.com/signin").as_deref(),
            Some("mail.google.com")
        );
        assert_eq!(site("google.com").as_deref(), Some("mail.google.com"));
        for url in [
            "https://amazon.fr",
            "https://github.io",
            "https://evilgithub.com",
            "https://github.com.evil.fr",
            "https://co.uk",
            "https://google.co.uk",
            "routeur",
            "",
            "macapp://com.github.app",
        ] {
            assert!(dir.lookup(url).is_none(), "{url}");
        }
    }

    #[test]
    fn lists_logins_that_could_use_a_passkey() {
        let dir = directory();
        let mut archived = login("archivé", "https://github.com", "lea", "x");
        archived.state = ItemState::Archived;
        let mut note = login("note", "https://github.com", "", "");
        note.kind = ItemKind::SecureNote;
        let vault = Vault::new(vec![
            login("GitHub perso", "https://github.com/login", "lea.perso", "x"),
            login("GitHub pro", "https://github.com", "lea-pro", "x"),
            login("Avec passkey", "https://github.com", "lea", "x"),
            login("Gmail", "https://accounts.google.com", "lea@gmail.com", "x"),
            login(
                "Google (passkey ailleurs)",
                "https://google.com",
                "LEA@gmail.com ",
                "x",
            ),
            login(
                "Passkey Google",
                "https://accounts.google.com",
                "lea@gmail.com",
                "",
            ),
            login("sans mot de passe", "https://amazon.com", "lea", ""),
            login("AWS", "https://console.aws.amazon.com", "root", "x"),
            login("Inconnu", "https://exemple.org", "lea", "x"),
            archived,
            note,
        ])
        .with_passkeys(vec![
            passkey("Avec passkey", "github.com", "lea"),
            // Passkey du même compte Google, rangée dans un autre élément.
            passkey("Passkey Google", "google.com", "lea@gmail.com"),
        ]);
        let found: Vec<(String, String)> = passkey_candidates(&vault, &dir)
            .into_iter()
            .map(|(id, site)| (id, site.domain.clone()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("AWS".to_owned(), "aws.amazon.com".to_owned()),
                ("GitHub perso".to_owned(), "github.com".to_owned()),
                ("GitHub pro".to_owned(), "github.com".to_owned()),
            ]
        );
    }

    #[test]
    fn a_passkey_in_a_trashed_item_does_not_count() {
        let dir = directory();
        let mut trashed = login("corbeille", "https://github.com", "lea", "");
        trashed.state = ItemState::Trashed;
        let vault = Vault::new(vec![
            login("GitHub", "https://github.com", "lea", "x"),
            trashed,
        ])
        .with_passkeys(vec![passkey("corbeille", "github.com", "lea")]);
        assert_eq!(passkey_candidates(&vault, &dir).len(), 1);
    }

    #[test]
    fn known_setup_pages() {
        assert_eq!(
            known_setup_url("accounts.google.com").as_deref(),
            Some("https://myaccount.google.com/signinoptions/passkeys")
        );
        assert_eq!(
            known_setup_url("login.live.com").as_deref(),
            Some("https://account.microsoft.com/security")
        );
        assert_eq!(known_setup_url("google.fr"), None);
        assert_eq!(known_setup_url("github.com.evil.fr"), None);
        for (_, url) in KNOWN {
            assert!(url.starts_with("https://"), "{url}");
        }
    }

    #[test]
    fn endpoints_stay_on_the_same_site() {
        let json = br#"{"enroll": "https://exemple.fr/compte/passkeys/nouvelle",
                        "manage": "https://exemple.fr/compte/passkeys"}"#;
        let endpoints = parse_endpoints(json, "login.exemple.fr").unwrap();
        assert_eq!(
            endpoints.setup(),
            Some("https://exemple.fr/compte/passkeys/nouvelle")
        );
        // Gestion seulement.
        let manage = parse_endpoints(
            br#"{"manage": "https://id.exemple.fr/passkeys"}"#,
            "exemple.fr",
        );
        assert_eq!(
            manage.unwrap().setup(),
            Some("https://id.exemple.fr/passkeys")
        );
        // Ailleurs, en HTTP, vide ou illisible : rien.
        for json in [
            &br#"{"enroll": "https://hameconnage.fr/passkeys"}"#[..],
            br#"{"enroll": "http://exemple.fr/passkeys"}"#,
            br#"{"enroll": "javascript:alert(1)"}"#,
            b"{}",
            b"<html>",
        ] {
            assert_eq!(parse_endpoints(json, "exemple.fr"), None);
        }
    }
}
