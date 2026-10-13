//! Modèle des éléments du coffre, indépendant de leur source (Vaultwarden ou
//! données fictives).

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Catégorie d'un élément, dans l'ordre où la barre latérale les présente.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ItemKind {
    Login,
    Card,
    Identity,
    SecureNote,
    SshKey,
}

impl ItemKind {
    pub const ALL: [Self; 5] = [
        Self::Login,
        Self::Card,
        Self::Identity,
        Self::SecureNote,
        Self::SshKey,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Identifiants",
            Self::Card => "Cartes bancaires",
            Self::Identity => "Identités",
            Self::SecureNote => "Notes sécurisées",
            Self::SshKey => "Clés SSH",
        }
    }

    /// Mot-clé reconnu par la recherche (`kind:carte`, etc.).
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Login => "identifiant",
            Self::Card => "carte",
            Self::Identity => "identité",
            Self::SecureNote => "note",
            Self::SshKey => "ssh",
        }
    }
}

/// Nature d'un champ : décide de son affichage et de son caractère secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldKind {
    Text,
    Username,
    Email,
    Password,
    Concealed,
    Url,
    Phone,
    Totp,
    CardNumber,
    Expiry,
    Pin,
    Date,
    Address,
    Multiline,
}

impl FieldKind {
    /// Un champ secret est masqué à l'écran et n'est révélé qu'à la demande.
    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::Password | Self::Concealed | Self::Totp | Self::CardNumber | Self::Pin
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Identifiant stable à l'intérieur de l'élément (`password`, `totp`…).
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub value: SecretString,
}

impl Field {
    pub fn new(id: &str, label: &str, kind: FieldKind, value: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            kind,
            value: SecretString::new(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    /// Ligne secondaire de la liste : identifiant, fin du numéro de carte…
    /// Jamais un secret.
    pub subtitle: String,
    pub urls: Vec<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// Horodatages Unix, en secondes.
    pub created: i64,
    pub modified: i64,
    pub fields: Vec<Field>,
    pub notes: Option<SecretString>,
    /// « Redemander le mot de passe principal » (réglage Bitwarden) : ses
    /// secrets ne sortent qu'après une nouvelle confirmation.
    pub reprompt: bool,
}

impl Item {
    pub fn field(&self, id: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.id == id)
    }

    pub fn field_of_kind(&self, kind: FieldKind) -> Option<&Field> {
        self.fields.iter().find(|f| f.kind == kind)
    }

    /// Hôte du premier site, sans `www.` : sert à l'icône et à la recherche.
    pub fn primary_host(&self) -> Option<String> {
        self.urls.iter().find_map(|u| crate::matching::host_of(u))
    }

    pub fn has_totp(&self) -> bool {
        self.field_of_kind(FieldKind::Totp).is_some()
    }
}
