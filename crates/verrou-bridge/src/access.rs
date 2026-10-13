//! Ce que l'extension a le droit d'obtenir du coffre.
//!
//! Règle : un mot de passe ne sort que pour un identifiant qui correspond à
//! la page demandée (même domaine enregistrable, comme Bitwarden), et
//! seulement vers une page en HTTPS. Une extension appairée ne peut donc pas
//! vider le coffre : elle ne voit que ce que la page en cours justifie.

use url::Url;
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, ItemKind, Vault};

use crate::protocol::{Credentials, Suggestion};

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
        .map(|item| Suggestion {
            id: item.id.clone(),
            title: item.title.clone(),
            username: item
                .field_of_kind(FieldKind::Username)
                .or_else(|| item.field_of_kind(FieldKind::Email))
                .map(|f| f.value.expose().to_owned())
                .unwrap_or_default(),
            has_totp: item.has_totp(),
        })
        .collect()
}

/// Identifiant, mot de passe et code du moment, si l'élément correspond à
/// la page. `Err` : la raison du refus, à afficher.
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
