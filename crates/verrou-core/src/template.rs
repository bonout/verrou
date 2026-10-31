//! 1Password-style item templates (license, Wi-Fi, passport…), built only on
//! the types Bitwarden knows.
//!
//! A template is a secure note, or a login when it has a site, a username
//! and a password (server, database, API key), with predefined custom
//! fields. It is recognised by a reserved text custom field, `verrou:type`,
//! whose value names the template (`wifi`, `passport`…): it syncs and
//! survives the web vault (which shows it as an ordinary field). Verrou never
//! displays it and keeps it intact on every edit, like the `part:…` address
//! pieces.

use crate::model::{Field, Item, ItemKind};
use crate::search::fold;

/// Name of the custom field that names the template.
pub const MARKER: &str = "verrou:type";

/// Prefix of the custom fields reserved to Verrou: never displayed nor
/// offered for editing, always kept.
pub const RESERVED_PREFIX: &str = "verrou:";

/// Is a custom field reserved to Verrou?
pub fn is_reserved(name: &str) -> bool {
    name.starts_with(RESERVED_PREFIX)
}

/// Labels of the Wi-Fi fields, read for the QR code.
pub const WIFI_SSID: &str = "Network name (SSID)";
pub const WIFI_PASSWORD: &str = "Password";
pub const WIFI_SECURITY: &str = "Security";

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

/// A predefined field: label, and whether it is concealed (Bitwarden's
/// "hidden" field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateField {
    /// Label written into new items.
    pub label: &'static str,
    /// Label earlier versions of Verrou wrote (in French), still
    /// recognised when reading; the same as `label` when it did not change.
    pub legacy: &'static str,
    pub hidden: bool,
}

const fn text(label: &'static str, legacy: &'static str) -> TemplateField {
    TemplateField {
        label,
        legacy,
        hidden: false,
    }
}

const fn hidden(label: &'static str, legacy: &'static str) -> TemplateField {
    TemplateField {
        label,
        legacy,
        hidden: true,
    }
}

/// The other spelling of a template field label: the legacy French label
/// for an English one, the English label for a legacy French one.
fn label_alias(label: &str) -> Option<&'static str> {
    let label = fold(label.trim());
    Template::ALL.iter().flat_map(|t| t.fields()).find_map(|f| {
        if fold(f.label) == label {
            Some(f.legacy)
        } else if fold(f.legacy) == label {
            Some(f.label)
        } else {
            None
        }
    })
}

/// Does a field labelled `field_label` stand for `wanted`? Ignores case and
/// accents, and treats a template field's English label and its legacy
/// French label as the same, so that items created by earlier versions
/// are still recognised.
pub fn matches_label(field_label: &str, wanted: &str) -> bool {
    let field = fold(field_label.trim());
    field == fold(wanted.trim()) || label_alias(wanted).is_some_and(|alias| fold(alias) == field)
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

    /// Value of the `verrou:type` field: stable, never translated.
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

    /// Name of the category in the sidebar.
    pub fn label(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "Software Licenses",
            Self::Wifi => "Wi-Fi Networks",
            Self::BankAccount => "Bank Accounts",
            Self::Passport => "Passports",
            Self::DriversLicense => "Driver's Licenses",
            Self::IdCard => "ID Cards",
            Self::Server => "Servers",
            Self::Database => "Databases",
            Self::ApiKey => "API Keys",
            Self::Membership => "Memberships and Subscriptions",
        }
    }

    /// French name of the category, still found by search.
    pub fn french_label(self) -> &'static str {
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
            Self::SoftwareLicense => "Software License",
            Self::Wifi => "Wi-Fi Network",
            Self::BankAccount => "Bank Account",
            Self::Passport => "Passport",
            Self::DriversLicense => "Driver's License",
            Self::IdCard => "ID Card",
            Self::Server => "Server",
            Self::Database => "Database",
            Self::ApiKey => "API Key",
            Self::Membership => "Membership or Subscription",
        }
    }

    /// Search keyword (`type:wifi`).
    pub fn keyword(self) -> &'static str {
        self.keywords()[0]
    }

    /// Search keywords: the English one first, then the French aliases.
    pub fn keywords(self) -> &'static [&'static str] {
        match self {
            Self::SoftwareLicense => &["license", "licence"],
            Self::Wifi => &["wifi"],
            Self::BankAccount => &["bank", "banque"],
            Self::Passport => &["passport", "passeport"],
            Self::DriversLicense => &["driver", "permis"],
            Self::IdCard => &["idcard", "cni"],
            Self::Server => &["server", "serveur"],
            Self::Database => &["database", "db", "bdd"],
            Self::ApiKey => &["api"],
            Self::Membership => &["membership", "adhesion"],
        }
    }

    /// Bitwarden type of the item: a login when the template has a site, a
    /// username and a password to fill.
    pub fn kind(self) -> ItemKind {
        match self {
            Self::Server | Self::Database | Self::ApiKey => ItemKind::Login,
            _ => ItemKind::SecureNote,
        }
    }

    /// Predefined custom fields, in screen order.
    // A table, not logic: splitting it would not make it easier to read.
    #[allow(clippy::too_many_lines)]
    pub fn fields(self) -> &'static [TemplateField] {
        match self {
            Self::SoftwareLicense => {
                const F: &[TemplateField] = &[
                    text("Version", "Version"),
                    hidden("License key", "Clé de licence"),
                    text("Licensed to", "Licencié à"),
                    text("Email", "E-mail"),
                    text("Publisher", "Éditeur"),
                    text("Purchase date", "Date d'achat"),
                    text("Order number", "Numéro de commande"),
                ];
                F
            }
            Self::Wifi => {
                const F: &[TemplateField] = &[
                    text(WIFI_SSID, "Nom du réseau (SSID)"),
                    hidden(WIFI_PASSWORD, "Mot de passe"),
                    text(WIFI_SECURITY, "Sécurité"),
                ];
                F
            }
            Self::BankAccount => {
                const F: &[TemplateField] = &[
                    text("Bank", "Banque"),
                    text("Account holder", "Titulaire"),
                    text("Account type", "Type de compte"),
                    hidden("IBAN", "IBAN"),
                    text("BIC", "BIC"),
                    hidden("Account number", "Numéro de compte"),
                    hidden("PIN", "Code PIN"),
                ];
                F
            }
            Self::Passport => {
                const F: &[TemplateField] = &[
                    hidden("Number", "Numéro"),
                    text("Surname", "Nom"),
                    text("Given names", "Prénoms"),
                    text("Nationality", "Nationalité"),
                    text("Date of birth", "Date de naissance"),
                    text("Place of birth", "Lieu de naissance"),
                    text("Sex", "Sexe"),
                    text("Issue date", "Date de délivrance"),
                    text("Expiry date", "Date d'expiration"),
                    text("Issuing authority", "Autorité de délivrance"),
                ];
                F
            }
            Self::DriversLicense => {
                const F: &[TemplateField] = &[
                    hidden("Number", "Numéro"),
                    text("Surname", "Nom"),
                    text("Given names", "Prénoms"),
                    text("Date of birth", "Date de naissance"),
                    text("Categories", "Catégories"),
                    text("Issue date", "Date de délivrance"),
                    text("Expiry date", "Date d'expiration"),
                    text("Country or region", "Pays ou région"),
                ];
                F
            }
            Self::IdCard => {
                const F: &[TemplateField] = &[
                    hidden("Number", "Numéro"),
                    text("Surname", "Nom"),
                    text("Given names", "Prénoms"),
                    text("Date of birth", "Date de naissance"),
                    text("Place of birth", "Lieu de naissance"),
                    text("Nationality", "Nationalité"),
                    text("Issue date", "Date de délivrance"),
                    text("Expiry date", "Date d'expiration"),
                    text("Issuing authority", "Autorité de délivrance"),
                ];
                F
            }
            Self::Server => {
                const F: &[TemplateField] = &[
                    text("Hosting provider", "Hébergeur"),
                    text("Admin console", "Console d'administration"),
                    text("Console username", "Nom d'utilisateur de la console"),
                    hidden("Console password", "Mot de passe de la console"),
                ];
                F
            }
            Self::Database => {
                const F: &[TemplateField] = &[
                    text("Type", "Type"),
                    text("Port", "Port"),
                    text("Database", "Base"),
                    text("Connection options", "Options de connexion"),
                ];
                F
            }
            Self::ApiKey => {
                const F: &[TemplateField] = &[
                    text("Type", "Type"),
                    text("Expiry date", "Date d'expiration"),
                ];
                F
            }
            Self::Membership => {
                const F: &[TemplateField] = &[
                    text("Organization", "Organisation"),
                    text("Member", "Membre"),
                    text("Member number", "Numéro de membre"),
                    text("Member since", "Membre depuis"),
                    text("Expiry date", "Date d'expiration"),
                    hidden("PIN", "Code PIN"),
                    text("Phone", "Téléphone"),
                ];
                F
            }
        }
    }

    /// Sample title for the creation screen.
    pub fn title_prompt(self) -> &'static str {
        match self {
            Self::SoftwareLicense => "Software",
            Self::Wifi => "Home Wi-Fi",
            Self::BankAccount => "Checking account",
            Self::Passport => "Passport",
            Self::DriversLicense => "Driver's license",
            Self::IdCard => "ID card",
            Self::Server => "Web server",
            Self::Database => "Production database",
            Self::ApiKey => "API key",
            Self::Membership => "Subscription",
        }
    }
}

impl Item {
    /// The item's template, from its `verrou:type` field.
    pub fn template(&self) -> Option<Template> {
        self.field(MARKER)
            .and_then(|f| Template::from_key(f.value.expose()))
    }

    /// First (non-reserved) field with this label, ignoring case and
    /// accents; a template field is also found under its legacy French
    /// label (see [`matches_label`]).
    pub fn field_labelled(&self, label: &str) -> Option<&Field> {
        self.fields
            .iter()
            .filter(|f| f.id.starts_with("custom-"))
            .find(|f| matches_label(&f.label, label))
    }
}

/// Content of a Wi-Fi network's QR code (format recognised by the iOS and
/// Android cameras): `WIFI:T:WPA;S:<ssid>;P:<password>;;`.
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

/// `WPA`, `WEP` or `nopass`, from the "Security" field: WPA by default
/// (WPA2 and WPA3 also announce themselves as "WPA").
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

/// Special characters of the `WIFI:` format: `\`, `;`, `,`, `:` and `"`.
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
            url_matches: Vec::new(),
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
    fn items_with_the_legacy_french_labels_are_still_recognised() {
        let old = item(vec![
            Field::new(
                "custom-0",
                "Nom du réseau (SSID)",
                FieldKind::Text,
                "Maison",
            ),
            Field::new("custom-1", "Mot de passe", FieldKind::Concealed, "secret"),
            Field::new("custom-2", "Sécurité", FieldKind::Text, "Aucun"),
            Field::new(MARKER, MARKER, FieldKind::Text, "wifi"),
        ]);
        let value = |label: &str| old.field_labelled(label).unwrap().value.expose().to_owned();
        assert_eq!(value(WIFI_SSID), "Maison");
        assert_eq!(value(WIFI_PASSWORD), "secret");
        assert_eq!(value(WIFI_SECURITY), "Aucun");
        let new = item(vec![Field::new(
            "custom-0",
            "Console password",
            FieldKind::Concealed,
            "x",
        )]);
        assert!(new.field_labelled("Mot de passe de la console").is_some());
        assert!(matches_label("Date d'expiration", "Expiry date"));
        assert!(matches_label("expiry date", "Expiry Date"));
        assert!(!matches_label("Nom", "Given names"));
        // Every template field: the English and French labels are the same field.
        for template in Template::ALL {
            for f in template.fields() {
                assert!(matches_label(f.legacy, f.label), "{}", f.label);
                assert!(matches_label(f.label, f.legacy), "{}", f.label);
            }
        }
    }

    #[test]
    fn a_label_has_a_single_legacy_form() {
        let fields: Vec<_> = Template::ALL.iter().flat_map(|t| t.fields()).collect();
        for a in &fields {
            for b in &fields {
                assert!(
                    (fold(a.label) == fold(b.label)) == (fold(a.legacy) == fold(b.legacy)),
                    "{} / {}",
                    a.label,
                    b.label
                );
            }
        }
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
        assert_eq!(titles("wi-fi networks", &Filter::All), ["Maison"]);
        assert_eq!(titles("type:passeport", &Filter::All).len(), 0);
        assert_eq!(
            titles("", &Filter::Kind(ItemKind::SecureNote)).len(),
            2,
            "a template stays a note"
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
