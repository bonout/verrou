//! Ce que l'extension a le droit d'obtenir du coffre.
//!
//! Règle : un mot de passe ne sort que pour un identifiant qui correspond à
//! la page demandée (même domaine enregistrable, comme Bitwarden), et
//! seulement vers une page en HTTPS. Une extension appairée ne peut donc pas
//! vider le coffre : elle ne voit que ce que la page en cours justifie.
//!
//! Écrire suit la même règle : l'extension n'enregistre un identifiant, ou
//! n'en modifie un, que pour le site de la page, après un clic de
//! l'utilisateur dans le bandeau de Verrou.

use url::Url;
use verrou_core::matching::host_of;
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Item, ItemKind, SecretString, Vault};

use crate::protocol::{Credentials, SaveAction, Suggestion};

/// Longueurs maximales acceptées depuis une page.
const MAX_USERNAME: usize = 512;
const MAX_PASSWORD: usize = 1024;
const MAX_TOTP: usize = 2048;

/// HTTPS, ou HTTP vers la machine elle-même (développement).
pub fn page_allowed(page_url: &str) -> bool {
    let Ok(url) = Url::parse(page_url) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

pub fn suggestions(vault: &Vault, page_url: &str) -> Vec<Suggestion> {
    if !page_allowed(page_url) {
        return Vec::new();
    }
    vault
        .suggestions_for(page_url)
        .into_iter()
        .map(suggestion)
        .collect()
}

fn suggestion(item: &Item) -> Suggestion {
    Suggestion {
        id: item.id.clone(),
        title: item.title.clone(),
        username: username_of(item).unwrap_or_default().to_owned(),
        has_totp: item.has_totp(),
    }
}

fn username_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose())
        .filter(|u| !u.is_empty())
}

fn password_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Password)
        .map(|f| f.value.expose())
}

/// Identifiants de la page, seulement les connexions.
fn logins_for<'v>(vault: &'v Vault, page_url: &str) -> Vec<&'v Item> {
    vault
        .suggestions_for(page_url)
        .into_iter()
        .filter(|item| item.kind == ItemKind::Login)
        .collect()
}

/// Ce que l'extension doit proposer après l'envoi d'un formulaire.
///
/// - Même identifiant et même mot de passe : rien (`Known`).
/// - Même identifiant, autre mot de passe : mise à jour.
/// - Identifiant absent (connexion en deux étapes, changement de mot de
///   passe) : l'élément dont le mot de passe est l'ancien (`current`), ou le
///   seul identifiant du site.
/// - Sinon : un nouvel élément.
pub fn check_save(
    vault: &Vault,
    page_url: &str,
    username: &str,
    password: &str,
    current: Option<&str>,
) -> Result<(SaveAction, Option<Suggestion>), String> {
    check_input(page_url, username, password)?;
    let logins = logins_for(vault, page_url);
    let username = username.trim();
    let same_password = |item: &Item| password_of(item) == Some(password);
    let by_current = || {
        current.filter(|c| !c.is_empty()).and_then(|c| {
            logins
                .iter()
                .copied()
                .find(|item| password_of(item) == Some(c))
        })
    };
    let found = if username.is_empty() {
        logins
            .iter()
            .copied()
            .find(|item| same_password(item))
            .or_else(by_current)
            .or(if logins.len() == 1 {
                logins.first().copied()
            } else {
                None
            })
    } else {
        logins
            .iter()
            .copied()
            .find(|item| username_of(item).is_some_and(|u| u.eq_ignore_ascii_case(username)))
            .or_else(by_current)
    };
    Ok(match found {
        Some(item) if same_password(item) => (SaveAction::Known, Some(suggestion(item))),
        Some(item) => (SaveAction::Update, Some(suggestion(item))),
        None => (SaveAction::New, None),
    })
}

fn check_input(page_url: &str, username: &str, password: &str) -> Result<(), String> {
    if !page_allowed(page_url) {
        return Err("page non sécurisée (HTTPS exigé)".to_owned());
    }
    if password.is_empty() {
        return Err("mot de passe vide".to_owned());
    }
    if username.len() > MAX_USERNAME || password.len() > MAX_PASSWORD {
        return Err("identifiant ou mot de passe trop long".to_owned());
    }
    Ok(())
}

/// Écriture demandée par l'extension, vérifiée : l'app n'a plus qu'à
/// l'exécuter.
#[derive(Debug)]
pub enum Write {
    Create {
        title: String,
        uri: String,
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
    },
    Update {
        item: String,
        /// Seulement si l'élément n'en a pas.
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
    },
}

/// L'élément `item` s'il correspond à la page.
fn matching_login<'v>(vault: &'v Vault, page_url: &str, item: &str) -> Result<&'v Item, String> {
    logins_for(vault, page_url)
        .into_iter()
        .find(|i| i.id == item)
        .ok_or_else(|| "cet identifiant ne correspond pas à ce site".to_owned())
}

/// Titre et adresse d'un nouvel élément pour la page : le site, sans chemin.
fn new_site(page_url: &str) -> Result<(String, String), String> {
    let url = Url::parse(page_url).map_err(|_| "adresse de page invalide".to_owned())?;
    let title = host_of(page_url).ok_or_else(|| "adresse de page invalide".to_owned())?;
    Ok((title, url.origin().ascii_serialization()))
}

pub fn plan_save(
    vault: &Vault,
    page_url: &str,
    username: &str,
    password: &str,
    item: Option<&str>,
) -> Result<Write, String> {
    check_input(page_url, username, password)?;
    let username = username.trim();
    let username = (!username.is_empty()).then(|| username.to_owned());
    let password = Some(SecretString::new(password));
    if let Some(id) = item {
        let item = matching_login(vault, page_url, id)?;
        return Ok(Write::Update {
            item: item.id.clone(),
            username: username.filter(|_| username_of(item).is_none()),
            password,
            totp: None,
        });
    }
    let (title, uri) = new_site(page_url)?;
    Ok(Write::Create {
        title,
        uri,
        username,
        password,
        totp: None,
    })
}

/// Graine TOTP lue sur la page (QR code ou clé collée).
pub fn plan_totp(
    vault: &Vault,
    page_url: &str,
    totp: &str,
    item: Option<&str>,
) -> Result<Write, String> {
    if !page_allowed(page_url) {
        return Err("page non sécurisée (HTTPS exigé)".to_owned());
    }
    let totp = totp.trim();
    if totp.len() > MAX_TOTP {
        return Err("code trop long".to_owned());
    }
    Totp::parse(totp).map_err(|e| e.to_string())?;
    let seed = Some(SecretString::new(totp));
    if let Some(id) = item {
        return Ok(Write::Update {
            item: matching_login(vault, page_url, id)?.id.clone(),
            username: None,
            password: None,
            totp: seed,
        });
    }
    let (title, uri) = new_site(page_url)?;
    Ok(Write::Create {
        title,
        uri,
        username: otpauth_account(totp),
        password: None,
        totp: seed,
    })
}

/// Le compte annoncé par une URI `otpauth://totp/Émetteur:compte`.
fn otpauth_account(totp: &str) -> Option<String> {
    let url = Url::parse(totp).ok().filter(|u| u.scheme() == "otpauth")?;
    let label = url.path().trim_start_matches('/');
    let label = url::form_urlencoded::parse(format!("l={label}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())?;
    let account = label.rsplit(':').next()?.trim();
    (!account.is_empty()).then(|| account.to_owned())
}

/// Identifiant, mot de passe et code du moment, si l'élément correspond à
/// la page. `Err` : la raison du refus, à afficher.
/// L'élément `item` demande-t-il une confirmation avant de livrer ses secrets ?
pub fn needs_confirmation(vault: &Vault, item: &str) -> bool {
    vault.get(item).is_some_and(|i| i.reprompt)
}

pub fn credentials(
    vault: &Vault,
    item_id: &str,
    page_url: &str,
    unix_time: u64,
) -> Result<Credentials, String> {
    if !page_allowed(page_url) {
        return Err("page non sécurisée (HTTPS exigé)".to_owned());
    }
    let item = vault
        .suggestions_for(page_url)
        .into_iter()
        .find(|item| item.id == item_id)
        .filter(|item| item.kind == ItemKind::Login)
        .ok_or_else(|| "cet identifiant ne correspond pas à ce site".to_owned())?;
    let value = |kind| {
        item.field_of_kind(kind)
            .map(|f| f.value.expose().to_owned())
    };
    let totp = value(FieldKind::Totp)
        .and_then(|seed| Totp::parse(&seed).ok())
        .map(|totp| totp.generate(unix_time).code);
    Ok(Credentials {
        username: value(FieldKind::Username).or_else(|| value(FieldKind::Email)),
        password: value(FieldKind::Password),
        totp,
    })
}

/// Exécute l'écriture sur un coffre en mémoire : pour les faux coffres (tests
/// et serveur de test de l'extension). L'app, elle, écrit sur le serveur.
pub fn apply_in_memory(vault: &Vault, write: Write, new_id: &str) -> (Vault, String) {
    use verrou_core::Field;
    let mut items = vault.items().to_vec();
    let set = |item: &mut Item, kind: FieldKind, id: &str, label: &str, value: Option<String>| {
        let Some(value) = value else { return };
        match item.fields.iter_mut().find(|f| f.kind == kind) {
            Some(field) => *field = Field::new(id, label, kind, value),
            None => item.fields.push(Field::new(id, label, kind, value)),
        }
    };
    let expose = |s: Option<SecretString>| s.map(|s| s.expose().to_owned());
    match write {
        Write::Create {
            title,
            uri,
            username,
            password,
            totp,
        } => {
            let mut item = Item {
                id: new_id.to_owned(),
                kind: ItemKind::Login,
                subtitle: username.clone().unwrap_or_default(),
                title,
                urls: vec![uri],
                folder: None,
                tags: Vec::new(),
                favorite: false,
                created: 0,
                modified: 0,
                fields: Vec::new(),
                notes: None,
                reprompt: false,
            };
            set(
                &mut item,
                FieldKind::Username,
                "username",
                "Identifiant",
                username,
            );
            set(
                &mut item,
                FieldKind::Password,
                "password",
                "Mot de passe",
                expose(password),
            );
            set(&mut item, FieldKind::Totp, "totp", "Code", expose(totp));
            items.push(item);
            (Vault::new(items), new_id.to_owned())
        }
        Write::Update {
            item: id,
            username,
            password,
            totp,
        } => {
            if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                set(
                    item,
                    FieldKind::Username,
                    "username",
                    "Identifiant",
                    username,
                );
                set(
                    item,
                    FieldKind::Password,
                    "password",
                    "Mot de passe",
                    expose(password),
                );
                set(item, FieldKind::Totp, "totp", "Code", expose(totp));
            }
            (Vault::new(items), id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_core::{Field, Item};

    fn item(id: &str, url: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: "camille".to_owned(),
            urls: vec![url.to_owned()],
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Username, "camille"),
                Field::new("password", "Mot de passe", FieldKind::Password, "secret"),
                Field::new("totp", "Code", FieldKind::Totp, "JBSWY3DPEHPK3PXP"),
            ],
            notes: None,
            reprompt: false,
        }
    }

    fn vault() -> Vault {
        Vault::new(vec![
            item("github", "https://github.com"),
            item("banque", "https://banque.fr"),
        ])
    }

    #[test]
    fn only_secure_pages() {
        assert!(page_allowed("https://github.com/login"));
        assert!(page_allowed("http://localhost:8000/"));
        assert!(!page_allowed("http://github.com/login"));
        assert!(!page_allowed("file:///etc/passwd"));
        assert!(!page_allowed("chrome://settings"));
        assert_eq!(suggestions(&vault(), "http://github.com/login"), []);
    }

    #[test]
    fn suggestions_match_the_page() {
        let found = suggestions(&vault(), "https://gist.github.com/");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "github");
        assert_eq!(found[0].username, "camille");
        assert!(found[0].has_totp);
    }

    #[test]
    fn check_save_tells_known_update_and_new() {
        let v = vault();
        let page = "https://github.com/login";
        let check = |u: &str, p: &str, c: Option<&str>| check_save(&v, page, u, p, c).unwrap();
        assert_eq!(check("camille", "secret", None).0, SaveAction::Known);
        assert_eq!(check("Camille ", "secret", None).0, SaveAction::Known);
        let (action, item) = check("camille", "nouveau", None);
        assert_eq!(action, SaveAction::Update);
        assert_eq!(item.unwrap().id, "github");
        assert_eq!(check("dominique", "x", None).0, SaveAction::New);
        // Changement de mot de passe sans identifiant : l'ancien désigne l'élément.
        assert_eq!(check("", "nouveau", Some("secret")).0, SaveAction::Update);
        // Seul identifiant du site, deuxième étape d'une connexion.
        assert_eq!(check("", "nouveau", None).0, SaveAction::Update);
        assert!(check_save(&v, "http://github.com/", "camille", "x", None).is_err());
        assert!(check_save(&v, page, "camille", "", None).is_err());
    }

    #[test]
    fn writes_only_for_the_page_site() {
        let v = vault();
        let Write::Update {
            item,
            username,
            password,
            ..
        } = plan_save(
            &v,
            "https://github.com/",
            "autre",
            "nouveau",
            Some("github"),
        )
        .unwrap()
        else {
            panic!("mise à jour attendue");
        };
        assert_eq!(item, "github");
        assert_eq!(username, None, "l'identifiant existant est gardé");
        assert_eq!(password.unwrap().expose(), "nouveau");
        assert!(plan_save(&v, "https://github.com/", "c", "x", Some("banque")).is_err());
        let Write::Create { title, uri, .. } =
            plan_save(&v, "https://www.exemple.fr/inscription?x=1", "c", "x", None).unwrap()
        else {
            panic!("création attendue");
        };
        assert_eq!(
            (title.as_str(), uri.as_str()),
            ("exemple.fr", "https://www.exemple.fr")
        );
    }

    #[test]
    fn totp_from_a_qr_code() {
        let v = vault();
        let uri =
            "otpauth://totp/Exemple:camille%40exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Exemple";
        let Write::Create { username, totp, .. } =
            plan_totp(&v, "https://exemple.fr/2fa", uri, None).unwrap()
        else {
            panic!("création attendue");
        };
        assert_eq!(username.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(totp.unwrap().expose(), uri);
        assert!(matches!(
            plan_totp(
                &v,
                "https://github.com/settings",
                "JBSWY3DPEHPK3PXP",
                Some("github")
            ),
            Ok(Write::Update { .. })
        ));
        assert!(
            plan_totp(
                &v,
                "https://github.com/",
                "pas une graine !",
                Some("github")
            )
            .is_err()
        );
        assert!(plan_totp(&v, "https://github.com/", uri, Some("banque")).is_err());
    }

    #[test]
    fn credentials_only_for_the_matching_site() {
        let creds = credentials(&vault(), "github", "https://github.com/login", 59).unwrap();
        assert_eq!(creds.password.as_deref(), Some("secret"));
        assert_eq!(creds.totp.as_deref().map(str::len), Some(6));
        assert!(credentials(&vault(), "banque", "https://github.com/login", 59).is_err());
        assert!(credentials(&vault(), "github", "https://github.com.evil.fr/", 59).is_err());
        assert!(credentials(&vault(), "github", "http://github.com/", 59).is_err());
        assert!(credentials(&vault(), "inconnu", "https://github.com/", 59).is_err());
    }
}
