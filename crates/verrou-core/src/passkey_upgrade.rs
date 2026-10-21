//! "Switch to passkeys": the logins whose site accepts passkeys, but that
//! don't have one in Verrou yet.
//!
//! Like `watchtower`, everything is computed here without network: the
//! directory of sites that accept passkeys (passkeys.2fa.directory) is
//! downloaded whole and cached by `verrou-vaultwarden` (`passkey_directory`),
//! then parsed by `PasskeyDirectory::parse`. No request per site.
//!
//! The page where to create the passkey ("Create a passkey") is looked up
//! only on demand and for a single item: the W3C "Passkey Endpoints"
//! standard (`/.well-known/passkey-endpoints`), checked by
//! `verrou_vaultwarden::passkey_setup`, then a short table of big sites
//! (`known_setup_url`), then the directory's address or the home page.

use std::collections::HashMap;

use serde::Deserialize;

use crate::audit::password_of;
use crate::matching::{host_of, registrable_domain};
use crate::watchtower::lookup_domain;
use crate::{FieldKind, Item, ItemKind, Vault};

/// Standard path of a site's passkey addresses (W3C).
pub const ENDPOINTS_PATH: &str = "/.well-known/passkey-endpoints";

/// Maximum length of the directory notes kept for display.
const MAX_NOTES: usize = 300;

/// What the site allows with a passkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Offered, optional.
    Allowed,
    /// Enforced by the site.
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

/// A directory site that accepts passkeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeySite {
    /// Directory domain, normalised (lowercase, no `www.`).
    pub domain: String,
    /// Passwordless sign-in: the passkey replaces the password.
    pub passwordless: Option<Support>,
    /// Passkey as a second factor, after the password.
    pub mfa: Option<Support>,
    /// The site's help page on passkeys (HTTPS).
    pub documentation: Option<String>,
    /// Site address when it is not `https://<domain>` (HTTPS).
    pub url: Option<String>,
    /// Directory remark (in English), short.
    pub notes: Option<String>,
}

impl PasskeySite {
    /// The passkey can replace the password at sign-in.
    pub fn passwordless(&self) -> bool {
        self.passwordless.is_some()
    }
}

/// Raw directory entry (`v1/supported.json` or `v1/all.json`:
/// `{ "<domain>": { passwordless, mfa, documentation, … } }`).
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

/// Directory of sites that accept passkeys, indexed by domain
/// (main and additional) and by registrable domain.
#[derive(Clone, Debug, Default)]
pub struct PasskeyDirectory {
    sites: Vec<PasskeySite>,
    by_domain: HashMap<String, usize>,
    /// Registrable domain → first site (passwordless first),
    /// for sites listed only by subdomain (`mail.google.com`).
    by_registrable: HashMap<String, usize>,
}

impl PasskeyDirectory {
    /// Parses the directory. Unreadable entries, or entries without passkeys
    /// (the full file also lists sites to reach out to), are ignored: a change
    /// in the format must not deprive the audit of the whole list.
    pub fn parse(json: &[u8]) -> Result<Self, serde_json::Error> {
        let entries: HashMap<String, serde_json::Value> = serde_json::from_slice(json)?;
        // Stable order (the JSON is an object): by domain.
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
                            // A passwordless site goes first.
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

    /// The site `url` belongs to: first like the two-factor audit (the host,
    /// then its parent domains up to the registrable domain), otherwise a site
    /// of the same registrable domain: accounts are shared across the whole
    /// domain (`accounts.google.com` belongs to `mail.google.com`, the only one
    /// listed). Never beyond (`co.uk`).
    pub fn lookup(&self, url: &str) -> Option<&PasskeySite> {
        if let Some(index) = lookup_domain(&self.by_domain, url) {
            return Some(&self.sites[index]);
        }
        let host = host_of(url)?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let registrable = registrable_domain(&host)?;
        // A name without a public suffix (`routeur`) is not a site.
        psl::domain_str(&registrable)?;
        self.by_registrable
            .get(&registrable)
            .map(|&index| &self.sites[index])
    }
}

/// Username (or email) of a login, lowercased.
fn user_of(item: &Item) -> Option<String> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose().trim().to_lowercase())
        .filter(|u| !u.is_empty())
}

/// Does the login already have a passkey: its own (`fido2Credentials`),
/// or a passkey of the same account stored in another active login
/// (same registrable domain, same username)?
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

/// Active logins, with a password, whose site accepts passkeys but that
/// don't have one yet. Sorted by title.
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

// MARK: Setup page

/// Big sites that don't publish `/.well-known/passkey-endpoints`, and
/// their passkeys page (or account security page), by registrable
/// domain. Short list, to keep up to date by hand.
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

/// Passkeys page known in advance for an item's host.
pub fn known_setup_url(host: &str) -> Option<String> {
    let domain = registrable_domain(host)?;
    KNOWN
        .iter()
        .find(|(domains, _)| domains.contains(&domain.as_str()))
        .map(|(_, url)| (*url).to_owned())
}

/// Addresses published by a site (`/.well-known/passkey-endpoints`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Page where to create a passkey.
    pub enroll: Option<String>,
    /// Page where to manage one's passkeys.
    pub manage: Option<String>,
}

impl Endpoints {
    /// The page to open to create a passkey: `enroll`, otherwise `manage`.
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

/// Reads the response of `/.well-known/passkey-endpoints`. Only HTTPS
/// addresses on the same registrable domain as `host` are kept: the file
/// must not be able to send the user elsewhere.
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

    /// Excerpt of `https://passkeys-api.2fa.directory/v1/supported.json`
    /// (October 2026), with entries the parser must ignore.
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
            url_matches: Vec::new(),
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
        // Second factor only.
        let onepassword = dir.lookup("1password.com").unwrap();
        assert!(!onepassword.passwordless());
        assert_eq!(onepassword.mfa, Some(Support::Allowed));
        // Site address kept, HTTP help page dropped.
        let xbox = dir.lookup("https://www.xbox.com").unwrap();
        assert_eq!(xbox.url.as_deref(), Some("https://www.xbox.com/live"));
        assert_eq!(xbox.documentation, None);
        // Normalised domain, additional domain, "required".
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
        // Without passkeys (contact only), unknown value, IP: ignored.
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
        // Exact host and subdomains.
        assert_eq!(
            site("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            site("https://gist.github.com").as_deref(),
            Some("github.com")
        );
        // The most specific entry wins; the parent keeps its own.
        assert_eq!(
            site("https://console.aws.amazon.com").as_deref(),
            Some("aws.amazon.com")
        );
        assert_eq!(
            site("https://www.amazon.com/gp/cart").as_deref(),
            Some("amazon.com")
        );
        // Site listed only by subdomains: same registrable domain,
        // and passwordless sign-in goes ahead of the second factor.
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
            // Passkey of the same Google account, stored in another item.
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
        // Manage only.
        let manage = parse_endpoints(
            br#"{"manage": "https://id.exemple.fr/passkeys"}"#,
            "exemple.fr",
        );
        assert_eq!(
            manage.unwrap().setup(),
            Some("https://id.exemple.fr/passkeys")
        );
        // Elsewhere, over HTTP, empty or unreadable: nothing.
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
