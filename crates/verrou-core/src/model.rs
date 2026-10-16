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

/// Où se trouve un élément : seuls les éléments actifs apparaissent dans la
/// liste principale, la recherche, le remplissage et l'audit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemState {
    #[default]
    Active,
    /// Rangé à l'écart (archives de Bitwarden) : gardé, mais hors du chemin.
    Archived,
    /// À la corbeille du serveur, restaurable pendant 30 jours.
    Trashed,
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
    /// Règle de correspondance de chaque site, dans l'ordre de `urls`
    /// (`None` : règle par défaut). Peut être plus courte que `urls`.
    pub url_matches: Vec<Option<crate::matching::UriMatch>>,
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
    pub state: ItemState,
    /// Élément d'une organisation (coffre partagé) ; `None` : coffre personnel.
    pub shared: Option<Sharing>,
}

/// Où un élément partagé est rangé, et ce que le compte a le droit d'en
/// faire. Les organisations de Vaultwarden jouent le rôle des coffres
/// partagés de 1Password ; leurs collections, celui des sous-coffres.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sharing {
    pub organization_id: String,
    pub organization: String,
    /// Collections de l'élément visibles par ce compte : (identifiant, nom),
    /// triées par nom.
    pub collections: Vec<(String, String)>,
    /// Le compte ne peut pas le modifier (collections en lecture seule).
    pub read_only: bool,
    /// L'organisation cache ses mots de passe à ce compte (« masquer les
    /// mots de passe ») : le remplissage reste permis, l'affichage, la
    /// copie et l'export non.
    pub hide_passwords: bool,
}

impl Item {
    pub fn is_active(&self) -> bool {
        self.state == ItemState::Active
    }

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

    /// L'organisation de l'élément interdit-elle de montrer ce champ ? Comme
    /// les apps Bitwarden : mot de passe, graine TOTP (le code du moment
    /// reste visible), champs personnalisés masqués et anciens mots de passe.
    pub fn hides(&self, field: &Field) -> bool {
        self.shared.as_ref().is_some_and(|s| s.hide_passwords)
            && (matches!(field.kind, FieldKind::Password | FieldKind::Totp)
                || field.id.starts_with("history-")
                || (field.id.starts_with("custom-") && field.kind == FieldKind::Concealed))
    }

    /// Le compte peut-il modifier l'élément (coffre personnel, ou collection
    /// où il a le droit d'écrire) ?
    pub fn is_writable(&self) -> bool {
        self.shared.as_ref().is_none_or(|s| !s.read_only)
    }
}
