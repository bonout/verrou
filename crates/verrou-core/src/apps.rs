//! Remplissage dans les applications du Mac (⌘\).
//!
//! Un identifiant se relie à une application par une adresse
//! `macapp://<identifiant de paquet>` rangée parmi ses sites : elle se
//! synchronise avec le reste de l'élément, comme les `androidapp://` et
//! `iosapp://` des apps Bitwarden. Ces adresses ne désignent jamais un site
//! web : `matching::host_of` les ignore.
//!
//! Le remplissage lui-même est une suite de frappes (identifiant, Tab, mot
//! de passe, Retour en option) que l'app joue au clavier ; elle se calcule
//! ici pour être testée.

use crate::model::{FieldKind, Item, ItemKind};
use crate::secret::SecretString;

/// Schéma des adresses d'application macOS.
pub const MAC_APP_SCHEME: &str = "macapp";

/// Schémas d'application connus (Bitwarden et Verrou) : jamais un site web.
const APP_SCHEMES: [&str; 3] = [MAC_APP_SCHEME, "iosapp", "androidapp"];

/// Longueur maximale d'un identifiant de paquet (`CFBundleIdentifier`).
const MAX_BUNDLE_ID: usize = 255;

/// Schéma d'une adresse (`macapp` dans `macapp://…`), en minuscules.
fn scheme(uri: &str) -> Option<String> {
    let (scheme, _) = uri.trim().split_once("://")?;
    let valid = !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// L'adresse désigne une application (macOS, iOS ou Android), pas un site.
pub fn is_app_uri(uri: &str) -> bool {
    scheme(uri).is_some_and(|s| APP_SCHEMES.contains(&s.as_str()))
}

/// Identifiant de paquet valide : lettres ASCII, chiffres, `.` et `-`
/// (règle d'Apple pour `CFBundleIdentifier`), sans point au bord ni vide.
fn valid_bundle_id(bundle_id: &str) -> bool {
    !bundle_id.is_empty()
        && bundle_id.len() <= MAX_BUNDLE_ID
        && !bundle_id.starts_with('.')
        && !bundle_id.ends_with('.')
        && !bundle_id.contains("..")
        && bundle_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

/// `com.apple.Terminal` → `macapp://com.apple.Terminal`. `None` pour un
/// identifiant de paquet invalide.
pub fn mac_app_uri(bundle_id: &str) -> Option<String> {
    let bundle_id = bundle_id.trim();
    valid_bundle_id(bundle_id).then(|| format!("{MAC_APP_SCHEME}://{bundle_id}"))
}

/// `macapp://com.apple.Terminal` → `com.apple.Terminal` (casse d'origine).
/// Une barre finale est tolérée ; tout autre chemin, une requête ou un
/// identifiant invalide rendent `None`.
pub fn mac_app_bundle_id(uri: &str) -> Option<&str> {
    let uri = uri.trim();
    let (scheme_part, rest) = uri.split_once("://")?;
    if !scheme_part.eq_ignore_ascii_case(MAC_APP_SCHEME) {
        return None;
    }
    let bundle_id = rest.strip_suffix('/').unwrap_or(rest);
    valid_bundle_id(bundle_id).then_some(bundle_id)
}

/// L'élément est relié à cette application. Les identifiants de paquet se
/// comparent sans tenir compte de la casse, comme le fait macOS.
pub fn matches_app(item_urls: &[String], bundle_id: &str) -> bool {
    let bundle_id = bundle_id.trim();
    !bundle_id.is_empty()
        && item_urls
            .iter()
            .filter_map(|u| mac_app_bundle_id(u))
            .any(|id| id.eq_ignore_ascii_case(bundle_id))
}

/// Une frappe du remplissage. Le texte se tape en caractères Unicode, pas en
/// codes de touches : la disposition du clavier n'y change rien.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keystroke {
    Text(SecretString),
    Tab,
    Return,
}

/// Frappes qui remplissent un identifiant : l'identifiant, Tab, le mot de
/// passe, puis Retour si `submit`. Sans identifiant, seulement le mot de
/// passe (le curseur est déjà dans son champ) ; sans mot de passe, seulement
/// l'identifiant. Rien à taper : aucune frappe, pas même Retour.
pub fn keystrokes(username: Option<&str>, password: Option<&str>, submit: bool) -> Vec<Keystroke> {
    let username = username.filter(|u| !u.is_empty());
    let password = password.filter(|p| !p.is_empty());
    let mut keys = Vec::with_capacity(4);
    if let Some(username) = username {
        keys.push(Keystroke::Text(SecretString::new(username)));
    }
    if let Some(password) = password {
        if username.is_some() {
            keys.push(Keystroke::Tab);
        }
        keys.push(Keystroke::Text(SecretString::new(password)));
    }
    if submit && !keys.is_empty() {
        keys.push(Keystroke::Return);
    }
    keys
}

/// Frappes d'un élément : seulement un identifiant (le reste n'a pas de
/// sens dans un champ d'application).
pub fn item_keystrokes(item: &Item, submit: bool) -> Option<Vec<Keystroke>> {
    if item.kind != ItemKind::Login {
        return None;
    }
    let username = item
        .field("username")
        .or_else(|| item.field_of_kind(FieldKind::Username))
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose());
    let password = item
        .field("password")
        .or_else(|| item.field_of_kind(FieldKind::Password))
        .map(|f| f.value.expose());
    Some(keystrokes(username, password, submit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, ItemState};

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|&u| u.to_owned()).collect()
    }

    fn text(value: &str) -> Keystroke {
        Keystroke::Text(SecretString::new(value))
    }

    #[test]
    fn app_uris_are_built_and_parsed() {
        assert_eq!(
            mac_app_uri(" com.apple.Terminal ").as_deref(),
            Some("macapp://com.apple.Terminal")
        );
        assert_eq!(
            mac_app_bundle_id("macapp://com.apple.Terminal"),
            Some("com.apple.Terminal")
        );
        assert_eq!(
            mac_app_bundle_id("MacApp://com.tinyspeck.slackmacgap/"),
            Some("com.tinyspeck.slackmacgap")
        );
        assert_eq!(mac_app_bundle_id("https://com.apple.Terminal"), None);
        assert_eq!(mac_app_bundle_id("iosapp://com.apple.Terminal"), None);
        assert_eq!(mac_app_bundle_id("macapp://"), None);
        assert_eq!(mac_app_bundle_id("macapp://com.apple.Terminal/x"), None);
        assert_eq!(mac_app_bundle_id("macapp://com..apple"), None);
        assert_eq!(mac_app_bundle_id("macapp://com.apple?x=1"), None);
        assert_eq!(mac_app_uri(""), None);
        assert_eq!(mac_app_uri("com.apple Terminal"), None);
        assert_eq!(mac_app_uri("com/apple"), None);
        assert_eq!(mac_app_uri(&"a".repeat(256)), None);
    }

    #[test]
    fn app_schemes_are_recognised() {
        assert!(is_app_uri("macapp://com.apple.Terminal"));
        assert!(is_app_uri("androidapp://com.github.android"));
        assert!(is_app_uri("IOSAPP://com.github.ios"));
        assert!(!is_app_uri("https://github.com"));
        assert!(!is_app_uri("github.com"));
        assert!(!is_app_uri("ssh://git@github.com"));
    }

    #[test]
    fn apps_match_their_bundle_id_only() {
        let item = urls(&["https://slack.com", "macapp://com.tinyspeck.slackmacgap"]);
        assert!(matches_app(&item, "com.tinyspeck.slackmacgap"));
        assert!(matches_app(&item, "COM.TinySpeck.SlackMacGap"));
        assert!(!matches_app(&item, "com.tinyspeck"));
        assert!(!matches_app(&item, "com.tinyspeck.slackmacgap.helper"));
        assert!(!matches_app(&item, ""));
        // Un site ou une app d'une autre plateforme ne relie pas une app du Mac.
        assert!(!matches_app(&urls(&["https://slack.com"]), "slack.com"));
        assert!(!matches_app(
            &urls(&["iosapp://com.tinyspeck.slackmacgap"]),
            "com.tinyspeck.slackmacgap"
        ));
    }

    #[test]
    fn keystrokes_follow_the_login_form() {
        assert_eq!(
            keystrokes(Some("camille"), Some("s3cret"), false),
            vec![text("camille"), Keystroke::Tab, text("s3cret")]
        );
        assert_eq!(
            keystrokes(Some("camille"), Some("s3cret"), true),
            vec![
                text("camille"),
                Keystroke::Tab,
                text("s3cret"),
                Keystroke::Return
            ]
        );
        assert_eq!(
            keystrokes(None, Some("s3cret"), false),
            vec![text("s3cret")]
        );
        assert_eq!(
            keystrokes(Some(""), Some("s3cret"), true),
            vec![text("s3cret"), Keystroke::Return]
        );
        assert_eq!(
            keystrokes(Some("camille"), None, false),
            vec![text("camille")]
        );
        assert_eq!(keystrokes(None, Some(""), true), Vec::new());
    }

    #[test]
    fn unicode_text_is_kept_whole() {
        // Le texte n'est pas traduit en touches : accents et emoji passent tels quels.
        let keys = keystrokes(Some("élodie"), Some("ñ€🔒ß"), false);
        assert_eq!(keys[2], text("ñ€🔒ß"));
    }

    #[test]
    fn only_logins_are_typed() {
        let mut item = Item {
            id: "1".to_owned(),
            kind: ItemKind::Login,
            title: "Slack".to_owned(),
            subtitle: "camille".to_owned(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Email, "c@exemple.fr"),
                Field::new("password", "Mot de passe", FieldKind::Password, "pw"),
            ],
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        };
        assert_eq!(
            item_keystrokes(&item, false),
            Some(vec![text("c@exemple.fr"), Keystroke::Tab, text("pw")])
        );
        item.kind = ItemKind::SecureNote;
        assert_eq!(item_keystrokes(&item, false), None);
    }
}
