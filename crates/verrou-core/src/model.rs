//! Model of the vault's items, independent of their source (Vaultwarden or
//! mock data).

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// An item's category, in the order the sidebar presents them.
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
            Self::Login => "Logins",
            Self::Card => "Payment Cards",
            Self::Identity => "Identities",
            Self::SecureNote => "Secure Notes",
            Self::SshKey => "SSH Keys",
        }
    }

    /// French name of the category, still found by search.
    pub fn french_label(self) -> &'static str {
        match self {
            Self::Login => "Identifiants",
            Self::Card => "Cartes bancaires",
            Self::Identity => "Identités",
            Self::SecureNote => "Notes sécurisées",
            Self::SshKey => "Clés SSH",
        }
    }

    /// Keyword recognized by search (`type:card`, etc.).
    pub fn keyword(self) -> &'static str {
        self.keywords()[0]
    }

    /// Search keywords: the English one first, then the French aliases
    /// (`type:carte`).
    pub fn keywords(self) -> &'static [&'static str] {
        match self {
            Self::Login => &["login", "identifiant"],
            Self::Card => &["card", "carte"],
            Self::Identity => &["identity", "identité"],
            Self::SecureNote => &["note"],
            Self::SshKey => &["ssh"],
        }
    }
}

/// Where an item is: only active items appear in the
/// main list, search, autofill and the audit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemState {
    #[default]
    Active,
    /// Put aside (Bitwarden's archive): kept, but out of the way.
    Archived,
    /// In the server's trash, restorable for 30 days.
    Trashed,
}

/// A field's kind: decides how it is displayed and whether it is secret.
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
    /// A secret field is masked on screen and only revealed on request.
    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::Password | Self::Concealed | Self::Totp | Self::CardNumber | Self::Pin
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Stable id within the item (`password`, `totp`…).
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
    /// Secondary line in the list: username, end of the card number…
    /// Never a secret.
    pub subtitle: String,
    pub urls: Vec<String>,
    /// Match rule of each site, in the order of `urls`
    /// (`None`: default rule). May be shorter than `urls`.
    pub url_matches: Vec<Option<crate::matching::UriMatch>>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// Unix timestamps, in seconds.
    pub created: i64,
    pub modified: i64,
    pub fields: Vec<Field>,
    pub notes: Option<SecretString>,
    /// "Master password re-prompt" (Bitwarden setting): its
    /// secrets only come out after a new confirmation.
    pub reprompt: bool,
    pub state: ItemState,
    /// Item of an organization (shared vault); `None`: personal vault.
    pub shared: Option<Sharing>,
}

/// Where a shared item is stored, and what the account is allowed to do
/// with it. Vaultwarden's organizations play the role of 1Password's shared
/// vaults; their collections, that of sub-vaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sharing {
    pub organization_id: String,
    pub organization: String,
    /// The item's collections visible to this account: (id, name),
    /// sorted by name.
    pub collections: Vec<(String, String)>,
    /// The account cannot edit it (read-only collections).
    pub read_only: bool,
    /// The organization hides its passwords from this account ("hide
    /// passwords"): filling is still allowed, display,
    /// copy and export are not.
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

    /// Host of the first site, without `www.`: used for the icon and search.
    pub fn primary_host(&self) -> Option<String> {
        self.urls.iter().find_map(|u| crate::matching::host_of(u))
    }

    pub fn has_totp(&self) -> bool {
        self.field_of_kind(FieldKind::Totp).is_some()
    }

    /// Does the item's organization forbid showing this field? Like
    /// the Bitwarden apps: password, TOTP seed (the current code
    /// stays visible), hidden custom fields and old passwords.
    pub fn hides(&self, field: &Field) -> bool {
        self.shared.as_ref().is_some_and(|s| s.hide_passwords)
            && (matches!(field.kind, FieldKind::Password | FieldKind::Totp)
                || field.id.starts_with("history-")
                || (field.id.starts_with("custom-") && field.kind == FieldKind::Concealed))
    }

    /// Can the account edit the item (personal vault, or a collection
    /// it is allowed to write to)?
    pub fn is_writable(&self) -> bool {
        self.shared.as_ref().is_none_or(|s| !s.read_only)
    }
}
