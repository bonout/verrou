//! Modèles d'éléments à la 1Password (licence, Wi-Fi, passeport…), sur les
//! seuls types que Bitwarden connaît.
//!
//! Un modèle est une note sécurisée, ou un identifiant quand il a un site, un
//! identifiant et un mot de passe (serveur, base de données, clé API), avec
//! des champs personnalisés prédéfinis. Il est reconnu grâce à un champ
//! personnalisé texte réservé, `verrou:type`, dont la valeur désigne le
//! modèle (`wifi`, `passport`…) : il se synchronise et survit au coffre web
//! (qui le montre comme un champ ordinaire). Verrou ne l'affiche jamais et le
//! garde intact à chaque modification, comme les morceaux d'adresse `part:…`.

use crate::model::{Field, Item, ItemKind};
use crate::search::fold;

/// Nom du champ personnalisé qui désigne le modèle.
pub const MARKER: &str = "verrou:type";

/// Préfixe des champs personnalisés réservés à Verrou : jamais affichés ni
/// proposés à la modification, toujours conservés.
pub const RESERVED_PREFIX: &str = "verrou:";

/// Un champ personnalisé est-il réservé à Verrou ?
pub fn is_reserved(name: &str) -> bool {
    name.starts_with(RESERVED_PREFIX)
}

/// Libellés des champs de Wi-Fi, lus par le QR code.
pub const WIFI_SSID: &str = "Nom du réseau (SSID)";
pub const WIFI_PASSWORD: &str = "Mot de passe";
pub const WIFI_SECURITY: &str = "Sécurité";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Template {
    SoftwareLicense,
    Wifi,
    BankAccount,
    Passport,
    DriversLicense,
    IdCard,
    Server,
    Database,
    ApiKey,
    Membership,
}

/// Un champ prédéfini : libellé, et s'il est masqué (champ « caché » de
/// Bitwarden).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateField {
    pub label: &'static str,
    pub hidden: bool,
}

const fn text(label: &'static str) -> TemplateField {
    TemplateField {
        label,
        hidden: false,
    }
}

const fn hidden(label: &'static str) -> TemplateField {
    TemplateField {
        label,
        hidden: true,
    }
}

impl Template {
    pub const ALL: [Self; 10] = [
        Self::SoftwareLicense,
        Self::Wifi,
        Self::BankAccount,
        Self::Passport,
        Self::DriversLicense,
        Self::IdCard,
        Self::Server,
        Self::Database,
        Self::ApiKey,
        Self::Membership,
    ];

    /// Valeur du champ `verrou:type` : stable, jamais traduite.
    pub fn key(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "software-license",
            Self::Wifi => "wifi",
            Self::BankAccount => "bank-account",
            Self::Passport => "passport",
            Self::DriversLicense => "drivers-license",
            Self::IdCard => "id-card",
            Self::Server => "server",
            Self::Database => "database",
            Self::ApiKey => "api-key",
            Self::Membership => "membership",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        let key = key.trim();
        Self::ALL
            .into_iter()
            .find(|t| t.key().eq_ignore_ascii_case(key))
    }

    /// Nom de la catégorie dans la barre latérale.
    pub fn label(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "Licences logicielles",
            Self::Wifi => "Réseaux Wi-Fi",
            Self::BankAccount => "Comptes bancaires",
            Self::Passport => "Passeports",
            Self::DriversLicense => "Permis de conduire",
            Self::IdCard => "Cartes d'identité",
            Self::Server => "Serveurs",
            Self::Database => "Bases de données",
            Self::ApiKey => "Clés API",
            Self::Membership => "Adhésions et abonnements",
        }
    }

    pub fn singular(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "Licence logicielle",
            Self::Wifi => "Réseau Wi-Fi",
            Self::BankAccount => "Compte bancaire",
            Self::Passport => "Passeport",
            Self::DriversLicense => "Permis de conduire",
            Self::IdCard => "Carte d'identité",
            Self::Server => "Serveur",
            Self::Database => "Base de données",
            Self::ApiKey => "Clé API",
            Self::Membership => "Adhésion ou abonnement",
        }
    }

    /// Mot-clé de la recherche (`type:wifi`).
    pub fn keyword(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "licence",
            Self::Wifi => "wifi",
            Self::BankAccount => "banque",
            Self::Passport => "passeport",
            Self::DriversLicense => "permis",
            Self::IdCard => "cni",
            Self::Server => "serveur",
            Self::Database => "bdd",
            Self::ApiKey => "api",
            Self::Membership => "adhesion",
        }
    }

    /// Type Bitwarden de l'élément : un identifiant quand le modèle a un
    /// site, un identifiant et un mot de passe à remplir.
    pub fn kind(self) -> ItemKind {
        match self {
            Self::Server | Self::Database | Self::ApiKey => ItemKind::Login,
            _ => ItemKind::SecureNote,
        }
    }

    /// Champs personnalisés prédéfinis, dans l'ordre de l'écran.
    // Une table, pas de la logique : la découper n'aiderait pas à la lire.
    #[allow(clippy::too_many_lines)]
    pub fn fields(self) -> &'static [TemplateField] {
        match self {
            Self::SoftwareLicense => {
                const F: &[TemplateField] = &[
                    text("Version"),
                    hidden("Clé de licence"),
                    text("Licencié à"),
                    text("E-mail"),
                    text("Éditeur"),
                    text("Date d'achat"),
                    text("Numéro de commande"),
                ];
                F
            }
            Self::Wifi => {
                const F: &[TemplateField] =
                    &[text(WIFI_SSID), hidden(WIFI_PASSWORD), text(WIFI_SECURITY)];
                F
            }
            Self::BankAccount => {
                const F: &[TemplateField] = &[
                    text("Banque"),
                    text("Titulaire"),
                    text("Type de compte"),
                    hidden("IBAN"),
                    text("BIC"),
                    hidden("Numéro de compte"),
                    hidden("Code PIN"),
                ];
                F
            }
            Self::Passport => {
                const F: &[TemplateField] = &[
                    hidden("Numéro"),
                    text("Nom"),
                    text("Prénoms"),
                    text("Nationalité"),
                    text("Date de naissance"),
                    text("Lieu de naissance"),
                    text("Sexe"),
                    text("Date de délivrance"),
                    text("Date d'expiration"),
                    text("Autorité de délivrance"),
                ];
                F
            }
            Self::DriversLicense => {
                const F: &[TemplateField] = &[
                    hidden("Numéro"),
                    text("Nom"),
                    text("Prénoms"),
                    text("Date de naissance"),
                    text("Catégories"),
                    text("Date de délivrance"),
                    text("Date d'expiration"),
                    text("Pays ou région"),
                ];
                F
            }
            Self::IdCard => {
                const F: &[TemplateField] = &[
                    hidden("Numéro"),
                    text("Nom"),
                    text("Prénoms"),
                    text("Date de naissance"),
                    text("Lieu de naissance"),
                    text("Nationalité"),
                    text("Date de délivrance"),
                    text("Date d'expiration"),
                    text("Autorité de délivrance"),
                ];
                F
            }
            Self::Server => {
                const F: &[TemplateField] = &[
                    text("Hébergeur"),
                    text("Console d'administration"),
                    text("Identifiant de la console"),
                    hidden("Mot de passe de la console"),
                ];
                F
            }
            Self::Database => {
                const F: &[TemplateField] = &[
                    text("Type"),
                    text("Port"),
                    text("Base"),
                    text("Options de connexion"),
                ];
                F
            }
            Self::ApiKey => {
                const F: &[TemplateField] = &[text("Type"), text("Date d'expiration")];
                F
            }
            Self::Membership => {
                const F: &[TemplateField] = &[
                    text("Organisation"),
                    text("Membre"),
                    text("Numéro de membre"),
                    text("Membre depuis"),
                    text("Date d'expiration"),
                    hidden("Code PIN"),
                    text("Téléphone"),
                ];
                F
            }
        }
    }

    /// Exemple de titre pour l'écran de création.
    pub fn title_prompt(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "Logiciel",
            Self::Wifi => "Wi-Fi maison",
            Self::BankAccount => "Compte courant",
            Self::Passport => "Passeport",
            Self::DriversLicense => "Permis de conduire",
            Self::IdCard => "Carte d'identité",
            Self::Server => "Serveur web",
            Self::Database => "Base de production",
            Self::ApiKey => "Clé API",
            Self::Membership => "Abonnement",
        }
    }
}

impl Item {
    /// Le modèle de l'élément, d'après son champ `verrou:type`.
    pub fn template(&self) -> Option<Template> {
        self.field(MARKER)
            .and_then(|f| Template::from_key(f.value.expose()))
    }

    /// Premier champ (non réservé) portant ce libellé, casse et accents
    /// ignorés.
    pub fn field_labelled(&self, label: &str) -> Option<&Field> {
        let wanted = fold(label);
        self.fields
            .iter()
            .filter(|f| f.id.starts_with("custom-"))
            .find(|f| fold(f.label.trim()) == wanted)
    }
}

/// Contenu du QR code d'un réseau Wi-Fi (format reconnu par l'appareil
/// photo d'iOS et d'Android) : `WIFI:T:WPA;S:<ssid>;P:<mot de passe>;;`.
pub fn wifi_qr_payload(ssid: &str, password: &str, security: &str) -> String {
    let auth = wifi_auth(security, password);
    let mut payload = format!("WIFI:T:{auth};S:{};", wifi_escape(ssid));
    if auth != "nopass" {
        payload.push_str("P:");
        payload.push_str(&wifi_escape(password));
        payload.push(';');
    }
    payload.push(';');
    payload
}

/// `WPA`, `WEP` ou `nopass`, d'après le champ « Sécurité » : WPA par défaut
/// (WPA2 et WPA3 s'annoncent aussi « WPA »).
fn wifi_auth(security: &str, password: &str) -> &'static str {
    let security = fold(security);
    if security.contains("wep") {
        "WEP"
    } else if password.is_empty()
        || ["aucun", "ouvert", "none", "open", "nopass"]
            .iter()
            .any(|w| security.contains(w))
    {
        "nopass"
    } else {
        "WPA"
    }
}

/// Caractères spéciaux du format `WIFI:` : `\`, `;`, `,`, `:` et `"`.
fn wifi_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldKind, ItemState};

    fn item(fields: Vec<Field>) -> Item {
        Item {
            id: "1".to_owned(),
            kind: ItemKind::SecureNote,
            title: "Wi-Fi".to_owned(),
            subtitle: String::new(),
            urls: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields,
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        }
    }

    #[test]
    fn keys_round_trip_and_are_unique() {
        for template in Template::ALL {
            assert_eq!(Template::from_key(template.key()), Some(template));
            assert_ne!(template.fields().len(), 0);
        }
        assert_eq!(Template::from_key(" WIFI "), Some(Template::Wifi));
        assert_eq!(Template::from_key("routeur"), None);
        let mut keys: Vec<_> = Template::ALL.iter().map(|t| t.key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), Template::ALL.len());
    }

    #[test]
    fn template_is_read_from_the_marker_field() {
        assert_eq!(item(Vec::new()).template(), None);
        let wifi = item(vec![
            Field::new("custom-0", WIFI_SSID, FieldKind::Text, "Maison"),
            Field::new(MARKER, MARKER, FieldKind::Text, "wifi"),
        ]);
        assert_eq!(wifi.template(), Some(Template::Wifi));
        assert_eq!(
            wifi.field_labelled("nom du reseau (ssid)")
                .unwrap()
                .value
                .expose(),
            "Maison"
        );
        assert!(wifi.field_labelled(MARKER).is_none());
        let unknown = item(vec![Field::new(MARKER, MARKER, FieldKind::Text, "?")]);
        assert_eq!(unknown.template(), None);
        assert!(is_reserved(MARKER) && !is_reserved("Version"));
    }

    #[test]
    fn templates_have_a_filter_a_keyword_and_a_count() {
        use crate::search::{Filter, Sort};
        use crate::vault::Vault;

        let mut wifi = item(vec![Field::new(MARKER, MARKER, FieldKind::Text, "wifi")]);
        wifi.title = "Maison".to_owned();
        let mut note = item(Vec::new());
        note.id = "2".to_owned();
        note.title = "Digicode".to_owned();
        let vault = Vault::new(vec![wifi, note]);
        let titles = |query: &str, filter: &Filter| -> Vec<String> {
            vault
                .search(query, filter, Sort::Title)
                .iter()
                .map(|h| vault.items()[h.index].title.clone())
                .collect()
        };
        assert_eq!(titles("", &Filter::Template(Template::Wifi)), ["Maison"]);
        assert_eq!(titles("type:wifi", &Filter::All), ["Maison"]);
        assert_eq!(titles("réseaux wi-fi", &Filter::All), ["Maison"]);
        assert_eq!(
            titles("", &Filter::Kind(ItemKind::SecureNote)).len(),
            2,
            "un modèle reste une note"
        );
        assert_eq!(vault.counts().templates, [(Template::Wifi, 1)]);
    }

    #[test]
    fn wifi_payload_is_escaped() {
        assert_eq!(
            wifi_qr_payload("Maison", "secret", "WPA2"),
            "WIFI:T:WPA;S:Maison;P:secret;;"
        );
        assert_eq!(
            wifi_qr_payload(r#"Café;"5G""#, r"a:b,c\d", ""),
            r#"WIFI:T:WPA;S:Café\;\"5G\";P:a\:b\,c\\d;;"#
        );
        assert_eq!(
            wifi_qr_payload("Vieux", "12345", "WEP"),
            "WIFI:T:WEP;S:Vieux;P:12345;;"
        );
        assert_eq!(
            wifi_qr_payload("Invités", "", "WPA2"),
            "WIFI:T:nopass;S:Invités;;"
        );
        assert_eq!(
            wifi_qr_payload("Gare", "x", "Aucune"),
            "WIFI:T:nopass;S:Gare;;"
        );
    }
}
