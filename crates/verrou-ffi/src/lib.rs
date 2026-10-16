//! Interface exposée aux applications Apple par `UniFFI`.
//!
//! Principe : Swift ne reçoit jamais un secret sans l'avoir demandé
//! explicitement. Les résumés (titre, identifiant affiché, site) arrivent une
//! fois au déverrouillage ; chaque frappe de recherche ne renvoie que des
//! positions et des surlignages ; un mot de passe ne traverse la frontière que
//! par `reveal`, au moment où l'utilisateur l'affiche ou le copie.
//!
//! Exceptions documentées : `user_key`, qui rend la clé de l'utilisateur pour
//! que l'app la confie au Secure Enclave (déverrouillage par Touch ID),
//! `edit_draft`, qui rend les secrets d'un élément quand l'utilisateur ouvre
//! l'écran de modification, `autofill_keystrokes`, qui rend l'identifiant
//! et le mot de passe à taper quand l'utilisateur choisit de remplir une app
//! (⌘\), et `wifi_qr_code`, qui rend le contenu du QR code d'un réseau
//! Wi-Fi (mot de passe compris) quand l'utilisateur l'affiche. De même pour
//! les envois (`send`) : `send_link` (le lien porte la clé de l'envoi),
//! `send_fields` et `send_fields_for_field`, à l'ouverture de l'écran d'un
//! envoi.
//!
//! Le coffre d'un concédant (accès d'urgence, `emergency`) suit les mêmes
//! règles, dans un objet à part (`EmergencyVault`) qui se vide au
//! verrouillage.
//!
//! Le déverrouillage par clé de sécurité, lui, reste entièrement dans Rust :
//! seuls le code PIN (saisi par l'utilisateur) et les étapes de l'échange
//! traversent la frontière.

// UniFFI exige des arguments possédés (`String`, énumérations) : la règle
// pédantique qui voudrait des références ne s'applique pas à une frontière FFI.
#![allow(clippy::needless_pass_by_value)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use verrou_bridge::access::Write;
use verrou_bridge::protocol::{CONFIRM_IN_APP, ClientKind, Credentials, SaveAction, Suggestion};
use verrou_bridge::{Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan};
use verrou_core::apps;
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Filter, Item, ItemKind, ItemState, SecretString, Sort, Vault, mock};

pub use preferences::{FolderMatchRule, MatchSettingsView, UriMatchRule};
use verrou_vaultwarden::security_key::{SecurityKeyStatus, SigningSession};
use verrou_vaultwarden::unlock_keys::{self, EnrolledKey};
use verrou_vaultwarden::{
    CardDraft, Closer, Connection, Decrypted, Draft, IdentityDraft, LoginDraft, LoginStep,
    Organization, PendingLogin, Store, Synced, TwoFactorAnswer, TwoFactorMethod, Unlocked,
};

uniffi::setup_scaffolding!();

mod activity;
mod attachments;
mod autofill;
mod bulk;
mod emergency;
mod import;
mod members;
mod otp_scan;
mod passphrase;
mod preferences;
mod send;
mod sharing;
mod ssh;
mod templates;
mod watchtower;

pub use bulk::{
    BulkItemAction, BulkProgress, BulkResult, ItemSelection, SelectionGesture, select_items,
};
pub use emergency::{
    EmergencyContact, EmergencyOverview, EmergencyState, EmergencyType, EmergencyVault,
};
pub use members::{
    MemberCollectionAccess, NewAccountKdfChoice, NewAccountRequest, OrganizationMember,
    OrganizationMemberRole, OrganizationMemberStatus, SignupLinkInfo, master_password_strength,
    parse_signup_link,
};
pub use otp_scan::{OtpScanResult, OtpTarget, ScannedOtp, totp_preview};
pub use passphrase::{
    GeneratedPassphrase, PassphraseLanguage, PassphraseSeparator, PassphraseSettings,
    generate_passphrase,
};
pub use send::{CreatedSend, SendContent, SendFields, SendSummary};
pub use sharing::{
    AccessGrant, CollectionAccessList, InvitationInfo, OrganizationGroup, PendingConfirmations,
    PendingMembershipView, ShareResult,
};

pub use attachments::{AttachmentContent, AttachmentEntry};
pub use autofill::{
    AutofillIdentity, AutofillIdentityKind, AutofillPasskey, AutofillPassword,
    PasskeyAssertionResult, PasskeyCreationRequest, PasskeyRegistrationResult,
};
pub use import::{
    DuplicateConfidence, DuplicateGroupView, DuplicateMemberView, ImportChoice, ImportDestination,
    ImportEntry, ImportFormat, ImportOutcome, ImportReview, ImportSkipped, ImportStatus,
    MergeReport, demo_duplicates,
};
pub use templates::{
    CustomField, CustomFieldType, ItemTemplate, ItemTemplateCount, template_draft,
};
pub use watchtower::{
    ExpiringCard, MissingTwoFactor, OldPassword, TwoFactorReport, WatchtowerReport,
};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VerrouError {
    #[error("le coffre est verrouillé")]
    Locked,
    #[error("élément introuvable")]
    NotFound,
    #[error("code à usage unique invalide : {message}")]
    InvalidTotp { message: String },
    #[error("mot de passe principal incorrect")]
    WrongPassword,
    #[error("second facteur refusé : {message}")]
    TwoFactorRejected { message: String },
    #[error("aucun compte n'est configuré")]
    NoAccount,
    #[error("la session a expiré : reconnectez-vous")]
    SessionExpired,
    #[error("{message}")]
    InvalidServer { message: String },
    #[error("serveur injoignable : {message}")]
    Network { message: String },
    #[error("réponse du serveur : {message}")]
    Server { message: String },
    #[error("déchiffrement impossible : {message}")]
    Crypto { message: String },
    #[error("stockage local : {message}")]
    Storage { message: String },
    #[error("aucune connexion en cours")]
    NoPendingLogin,
    #[error("clé de sécurité : {message}")]
    SecurityKey { message: String },
    #[error("cet élément ne peut pas être modifié depuis ce compte")]
    ReadOnly,
    #[error("{message}")]
    Invalid { message: String },
    #[error("l'élément a changé sur le serveur")]
    Conflict,
    /// L'élément demande une nouvelle confirmation (Touch ID ou mot de passe
    /// principal) avant de livrer ses secrets : `authorize_item` après coup.
    #[error("confirmation requise pour cet élément")]
    RepromptRequired,
}

impl From<verrou_vaultwarden::Error> for VerrouError {
    fn from(error: verrou_vaultwarden::Error) -> Self {
        use verrou_vaultwarden::Error as E;
        match error {
            E::WrongPassword => Self::WrongPassword,
            E::TwoFactorRejected(message) => Self::TwoFactorRejected { message },
            E::NoAccount => Self::NoAccount,
            E::SessionExpired => Self::SessionExpired,
            E::InvalidServer(message) => Self::InvalidServer { message },
            E::Network(message) => Self::Network { message },
            E::Server(message) => Self::Server { message },
            E::Crypto(message) => Self::Crypto { message },
            E::Storage(message) => Self::Storage { message },
            E::SecurityKey(message) => Self::SecurityKey { message },
            E::NotFound => Self::NotFound,
            E::ReadOnly => Self::ReadOnly,
            E::Invalid(message) => Self::Invalid { message },
            E::Conflict => Self::Conflict,
        }
    }
}

/// Le compte Vaultwarden enregistré sur ce Mac.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountInfo {
    pub server: String,
    pub email: String,
    /// Horodatage Unix de la dernière synchronisation réussie.
    pub synced_at: Option<i64>,
}

/// Méthode de second facteur proposée par le serveur.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TwoFactorOption {
    /// Clé de sécurité (`YubiKey` en FIDO2). `challenge` est à transmettre à
    /// la page de connexion `WebAuthn` du serveur.
    SecurityKey {
        challenge: String,
    },
    Authenticator,
    YubiKeyOtp,
    Email,
}

impl From<&TwoFactorMethod> for TwoFactorOption {
    fn from(method: &TwoFactorMethod) -> Self {
        match method {
            TwoFactorMethod::WebAuthn { challenge } => Self::SecurityKey {
                challenge: challenge.clone(),
            },
            TwoFactorMethod::Authenticator => Self::Authenticator,
            TwoFactorMethod::YubiKeyOtp => Self::YubiKeyOtp,
            TwoFactorMethod::Email => Self::Email,
        }
    }
}

impl TwoFactorOption {
    fn provider(&self) -> u8 {
        match self {
            Self::SecurityKey { challenge } => TwoFactorMethod::WebAuthn {
                challenge: challenge.clone(),
            },
            Self::Authenticator => TwoFactorMethod::Authenticator,
            Self::YubiKeyOtp => TwoFactorMethod::YubiKeyOtp,
            Self::Email => TwoFactorMethod::Email,
        }
        .provider()
    }
}

/// Une clé de sécurité enrôlée pour déverrouiller. Aucun secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnlockKey {
    /// Identifiant de l'accréditation (base64url), pour la retirer.
    pub id: String,
    pub label: String,
    /// Horodatage Unix de l'enrôlement.
    pub created: i64,
}

impl From<&EnrolledKey> for UnlockKey {
    fn from(key: &EnrolledKey) -> Self {
        Self {
            id: key.id.clone(),
            label: key.label.clone(),
            created: key.created,
        }
    }
}

/// Ce que la clé de sécurité attend de l'utilisateur.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityKeyPrompt {
    /// La toucher.
    Touch,
    /// Saisir son code PIN, à passer à `submit_security_key_pin`. `retry` : le
    /// précédent était faux ; `attempts_left` : essais restants, si la clé le
    /// dit.
    Pin {
        retry: bool,
        attempts_left: Option<u8>,
    },
}

impl From<SecurityKeyStatus> for SecurityKeyPrompt {
    fn from(status: SecurityKeyStatus) -> Self {
        match status {
            SecurityKeyStatus::TouchRequired => Self::Touch,
            SecurityKeyStatus::PinRequired { retry, attempts } => Self::Pin {
                retry,
                attempts_left: attempts,
            },
        }
    }
}

/// L'app affiche les étapes de l'échange avec la clé de sécurité. Appelé
/// depuis le fil de l'échange : répondre vite.
#[uniffi::export(callback_interface)]
pub trait SecurityKeyObserver: Send + Sync {
    fn prompt(&self, prompt: SecurityKeyPrompt);
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum LoginResult {
    /// Coffre ouvert. `failures` : éléments que le SDK n'a pas su déchiffrer.
    Unlocked {
        failures: u32,
    },
    TwoFactorRequired {
        options: Vec<TwoFactorOption>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ItemCategory {
    Login,
    Card,
    Identity,
    SecureNote,
    SshKey,
}

impl From<ItemKind> for ItemCategory {
    fn from(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => Self::Login,
            ItemKind::Card => Self::Card,
            ItemKind::Identity => Self::Identity,
            ItemKind::SecureNote => Self::SecureNote,
            ItemKind::SshKey => Self::SshKey,
        }
    }
}

impl From<ItemCategory> for ItemKind {
    fn from(category: ItemCategory) -> Self {
        match category {
            ItemCategory::Login => Self::Login,
            ItemCategory::Card => Self::Card,
            ItemCategory::Identity => Self::Identity,
            ItemCategory::SecureNote => Self::SecureNote,
            ItemCategory::SshKey => Self::SshKey,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SidebarFilter {
    All,
    Favorites,
    WithTotp,
    Category {
        category: ItemCategory,
    },
    /// Éléments d'un modèle (Wi-Fi, passeport…).
    Template {
        template: ItemTemplate,
    },
    Folder {
        name: String,
    },
    Tag {
        name: String,
    },
    Archived,
    Trash,
    /// Coffre partagé : une organisation, ou une de ses collections.
    Organization {
        id: String,
    },
    Collection {
        id: String,
    },
    /// Identifiants qui portent une passkey.
    Passkeys,
}

impl From<SidebarFilter> for Filter {
    fn from(filter: SidebarFilter) -> Self {
        match filter {
            SidebarFilter::All => Self::All,
            SidebarFilter::Favorites => Self::Favorites,
            SidebarFilter::WithTotp => Self::WithTotp,
            SidebarFilter::Category { category } => Self::Kind(category.into()),
            SidebarFilter::Template { template } => Self::Template(template.into()),
            SidebarFilter::Folder { name } => Self::Folder(name),
            SidebarFilter::Tag { name } => Self::Tag(name),
            SidebarFilter::Archived => Self::Archived,
            SidebarFilter::Trash => Self::Trash,
            SidebarFilter::Organization { id } => Self::Organization(id),
            SidebarFilter::Collection { id } => Self::Collection(id),
            SidebarFilter::Passkeys => Self::Passkeys,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ResultOrder {
    Relevance,
    Title,
    RecentlyModified,
    /// Création, du plus récent au plus ancien.
    Created,
    /// Dernière utilisation sur cet appareil.
    LastUsed,
}

impl From<ResultOrder> for Sort {
    fn from(order: ResultOrder) -> Self {
        match order {
            ResultOrder::Relevance => Self::Relevance,
            ResultOrder::Title => Self::Title,
            ResultOrder::RecentlyModified => Self::RecentlyModified,
            ResultOrder::Created => Self::Created,
            ResultOrder::LastUsed => Self::LastUsed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FieldType {
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

impl From<FieldKind> for FieldType {
    fn from(kind: FieldKind) -> Self {
        match kind {
            FieldKind::Text => Self::Text,
            FieldKind::Username => Self::Username,
            FieldKind::Email => Self::Email,
            FieldKind::Password => Self::Password,
            FieldKind::Concealed => Self::Concealed,
            FieldKind::Url => Self::Url,
            FieldKind::Phone => Self::Phone,
            FieldKind::Totp => Self::Totp,
            FieldKind::CardNumber => Self::CardNumber,
            FieldKind::Expiry => Self::Expiry,
            FieldKind::Pin => Self::Pin,
            FieldKind::Date => Self::Date,
            FieldKind::Address => Self::Address,
            FieldKind::Multiline => Self::Multiline,
        }
    }
}

/// Ce que la liste affiche d'un élément. Aucun secret.
// Un enregistrement UniFFI : des champs plats, lus tels quels par Swift.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub category: ItemCategory,
    pub title: String,
    pub subtitle: String,
    pub host: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub modified: i64,
    /// « Redemander le mot de passe principal » : confirmer avant tout secret.
    pub reprompt: bool,
    pub state: ItemStatus,
    /// Coffre partagé (organisation) ; `None` : coffre personnel.
    pub sharing: Option<ItemSharing>,
    /// Modèle de Verrou (Wi-Fi, passeport…), d'après le champ `verrou:type`.
    pub template: Option<ItemTemplate>,
    /// Modifié hors ligne : la modification attend le serveur.
    pub pending_sync: bool,
    /// Création (horodatage Unix).
    pub created: i64,
    /// Dernière utilisation sur cet appareil (remplissage, copie, secret
    /// affiché), si connue.
    pub last_used: Option<i64>,
    /// Première passkey de l'identifiant : son site (`rpId`)…
    pub passkey_rp_id: Option<String>,
    /// … et le nom d'utilisateur qu'elle porte.
    pub passkey_user_name: Option<String>,
}

/// Où se trouve l'élément (voir `verrou_core::ItemState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ItemStatus {
    Active,
    Archived,
    Trashed,
}

impl From<ItemState> for ItemStatus {
    fn from(state: ItemState) -> Self {
        match state {
            ItemState::Active => Self::Active,
            ItemState::Archived => Self::Archived,
            ItemState::Trashed => Self::Trashed,
        }
    }
}

/// Un résultat de recherche : position dans `summaries()`, identifiant de
/// l'élément (pour vérifier que la position désigne toujours le même : une
/// synchronisation ou une écriture remplace le coffre) et caractères du titre
/// à surligner.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SearchHit {
    pub position: u32,
    pub id: String,
    pub highlights: Vec<u32>,
}

/// Un champ tel que l'écran de détail le présente. `value` est absent pour
/// un champ secret : il faut passer par `reveal`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub field_type: FieldType,
    pub secret: bool,
    pub value: Option<String>,
    /// L'organisation de l'élément masque ce champ à ce compte : ni
    /// affichage ni copie (le remplissage par l'extension reste permis).
    pub hidden: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemDetail {
    pub summary: ItemSummary,
    pub urls: Vec<String>,
    /// Règle de correspondance de chaque site (`None` : règle par défaut).
    pub url_matches: Vec<Option<UriMatchRule>>,
    pub fields: Vec<FieldView>,
    pub has_notes: bool,
    pub created: i64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TotpView {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NamedCount {
    pub name: String,
    pub count: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemCategoryCount {
    pub category: ItemCategory,
    pub count: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SidebarCounts {
    /// Éléments actifs, comme les effectifs qui suivent (hors archives et corbeille).
    pub all: u32,
    pub archived: u32,
    pub trashed: u32,
    pub favorites: u32,
    pub with_totp: u32,
    /// Identifiants qui portent une passkey.
    pub passkeys: u32,
    pub categories: Vec<ItemCategoryCount>,
    /// Modèles présents dans le coffre, dans l'ordre de `ItemTemplate`.
    pub templates: Vec<ItemTemplateCount>,
    pub folders: Vec<NamedCount>,
    pub tags: Vec<NamedCount>,
}

/// Un dossier où ranger un élément.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderOption {
    pub id: String,
    pub name: String,
}

/// L'écran de modification. Avec `login` : un identifiant ; avec `card` :
/// une carte ; avec `identity` : une identité ; sans aucun : une note
/// sécurisée. Pour les autres types (clé SSH), seuls le titre, le dossier,
/// le favori, les notes et les champs personnalisés se modifient.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct ItemDraft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<String>,
    pub login: Option<LoginFields>,
    /// Champs personnalisés, dans l'ordre (sans les champs réservés).
    pub fields: Vec<CustomField>,
    /// Modèle : choisi à la création, conservé ensuite.
    pub template: Option<ItemTemplate>,
    /// Carte bancaire (valeur par défaut côté Swift : les appels existants
    /// n'ont pas à la nommer).
    #[uniffi(default = None)]
    pub card: Option<CardFields>,
    /// Identité.
    #[uniffi(default = None)]
    pub identity: Option<IdentityFields>,
}

/// Les champs modifiables d'une carte bancaire.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct CardFields {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

/// Les champs modifiables d'une identité.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct IdentityFields {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub ssn: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

fn secret(value: Option<String>) -> Option<SecretString> {
    value.map(SecretString::new)
}

fn exposed(value: Option<SecretString>) -> Option<String> {
    value.map(|v| v.expose().to_owned())
}

impl From<CardFields> for CardDraft {
    fn from(card: CardFields) -> Self {
        Self {
            cardholder_name: card.cardholder_name,
            brand: card.brand,
            number: secret(card.number),
            exp_month: card.exp_month,
            exp_year: card.exp_year,
            code: secret(card.code),
        }
    }
}

impl From<CardDraft> for CardFields {
    fn from(card: CardDraft) -> Self {
        Self {
            cardholder_name: card.cardholder_name,
            brand: card.brand,
            number: exposed(card.number),
            exp_month: card.exp_month,
            exp_year: card.exp_year,
            code: exposed(card.code),
        }
    }
}

impl From<IdentityFields> for IdentityDraft {
    fn from(i: IdentityFields) -> Self {
        Self {
            title: i.title,
            first_name: i.first_name,
            middle_name: i.middle_name,
            last_name: i.last_name,
            company: i.company,
            email: i.email,
            phone: i.phone,
            username: i.username,
            address1: i.address1,
            address2: i.address2,
            address3: i.address3,
            postal_code: i.postal_code,
            city: i.city,
            state: i.state,
            country: i.country,
            ssn: secret(i.ssn),
            passport_number: secret(i.passport_number),
            license_number: secret(i.license_number),
        }
    }
}

impl From<IdentityDraft> for IdentityFields {
    fn from(i: IdentityDraft) -> Self {
        Self {
            title: i.title,
            first_name: i.first_name,
            middle_name: i.middle_name,
            last_name: i.last_name,
            company: i.company,
            email: i.email,
            phone: i.phone,
            username: i.username,
            address1: i.address1,
            address2: i.address2,
            address3: i.address3,
            postal_code: i.postal_code,
            city: i.city,
            state: i.state,
            country: i.country,
            ssn: exposed(i.ssn),
            passport_number: exposed(i.passport_number),
            license_number: exposed(i.license_number),
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct LoginFields {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Graine TOTP (`otpauth://…` ou base32).
    pub totp: Option<String>,
    pub urls: Vec<String>,
    /// Règle de chaque site, dans l'ordre de `urls` (`None` dans la liste :
    /// règle par défaut). `None` : chaque site gardé garde la sienne.
    #[uniffi(default = None)]
    pub url_matches: Option<Vec<Option<UriMatchRule>>>,
}

impl From<ItemDraft> for Draft {
    fn from(draft: ItemDraft) -> Self {
        Self {
            name: draft.name,
            folder_id: draft.folder_id,
            favorite: draft.favorite,
            notes: draft.notes.map(SecretString::new),
            login: draft.login.map(|login| LoginDraft {
                username: login.username,
                password: login.password.map(SecretString::new),
                totp: login.totp.map(SecretString::new),
                uris: login.urls,
                uri_matches: login
                    .url_matches
                    .map(|list| list.into_iter().map(|m| m.map(Into::into)).collect()),
            }),
            fields: Some(draft.fields.into_iter().map(Into::into).collect()),
            template: draft.template.map(Into::into),
            card: draft.card.map(Into::into),
            identity: draft.identity.map(Into::into),
        }
    }
}

impl From<Draft> for ItemDraft {
    fn from(draft: Draft) -> Self {
        Self {
            name: draft.name,
            folder_id: draft.folder_id,
            favorite: draft.favorite,
            notes: draft.notes.map(|n| n.expose().to_owned()),
            login: draft.login.map(|login| LoginFields {
                username: login.username,
                password: login.password.map(|p| p.expose().to_owned()),
                totp: login.totp.map(|t| t.expose().to_owned()),
                urls: login.uris,
                url_matches: login
                    .uri_matches
                    .map(|list| list.into_iter().map(|m| m.map(Into::into)).collect()),
            }),
            fields: draft
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            template: draft.template.map(Into::into),
            card: draft.card.map(Into::into),
            identity: draft.identity.map(Into::into),
        }
    }
}

fn summary(item: &Item) -> ItemSummary {
    ItemSummary {
        id: item.id.clone(),
        category: item.kind.into(),
        title: item.title.clone(),
        subtitle: item.subtitle.clone(),
        host: item.primary_host(),
        folder: item.folder.clone(),
        tags: item.tags.clone(),
        favorite: item.favorite,
        has_totp: item.has_totp(),
        modified: item.modified,
        reprompt: item.reprompt,
        state: item.state.into(),
        sharing: item.shared.as_ref().map(|s| ItemSharing {
            organization_id: s.organization_id.clone(),
            organization: s.organization.clone(),
            collection_ids: s.collections.iter().map(|(id, _)| id.clone()).collect(),
            collections: s.collections.iter().map(|(_, name)| name.clone()).collect(),
            read_only: s.read_only,
            hide_passwords: s.hide_passwords,
        }),
        template: item.template().map(Into::into),
        pending_sync: false,
        created: item.created,
        last_used: None,
        passkey_rp_id: None,
        passkey_user_name: None,
    }
}

/// L'écran de détail d'un élément : les champs secrets sans leur valeur.
fn detail(item: &Item) -> ItemDetail {
    let fields = item
        .fields
        .iter()
        // Morceaux d'adresse (pour remplir les formulaires) et champs
        // réservés à Verrou (`verrou:type`) : pas à afficher.
        .filter(|f| !templates::is_reserved_field(&f.id))
        .map(|f| {
            let secret = f.kind.is_secret();
            FieldView {
                id: f.id.clone(),
                label: f.label.clone(),
                field_type: f.kind.into(),
                secret,
                value: (!secret).then(|| f.value.expose().to_owned()),
                hidden: item.hides(f),
            }
        })
        .collect();
    ItemDetail {
        summary: summary(item),
        urls: item.urls.clone(),
        url_matches: (0..item.urls.len())
            .map(|i| item.url_matches.get(i).copied().flatten().map(Into::into))
            .collect(),
        fields,
        has_notes: item.notes.is_some(),
        created: item.created,
    }
}

/// Une frappe du remplissage dans une app (voir `verrou_core::apps`). Le
/// texte se tape en caractères Unicode, quelle que soit la disposition du
/// clavier.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillKeystroke {
    Text { value: String },
    Tab,
    Return,
}

impl From<apps::Keystroke> for AutofillKeystroke {
    fn from(key: apps::Keystroke) -> Self {
        match key {
            apps::Keystroke::Text(text) => Self::Text {
                value: text.expose().to_owned(),
            },
            apps::Keystroke::Tab => Self::Tab,
            apps::Keystroke::Return => Self::Return,
        }
    }
}

/// Audit du coffre (calculé localement) : voir `verrou_core::audit`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditReport {
    /// Groupes d'éléments partageant un même mot de passe.
    pub reused: Vec<Vec<ItemSummary>>,
    pub weak: Vec<WeakPassword>,
    /// Identifiants dont un site est en HTTP.
    pub insecure: Vec<ItemSummary>,
    /// Identifiants examinés (ceux qui ont un mot de passe).
    pub checked: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct WeakPassword {
    pub item: ItemSummary,
    /// Entropie estimée, en bits.
    pub bits: f64,
}

/// Un identifiant dont le mot de passe figure dans des fuites connues.
#[derive(Clone, Debug, uniffi::Record)]
pub struct BreachedPassword {
    pub item: ItemSummary,
    /// Nombre d'apparitions dans les fuites recensées par Have I Been Pwned.
    pub count: u64,
}

/// Durée pendant laquelle une confirmation vaut pour un élément protégé.
const REPROMPT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Session du coffre. Verrouiller libère le coffre, ce qui efface ses
/// secrets de la mémoire (`SecretString` est mis à zéro à la libération), et
/// la connexion, qui porte la clé de l'utilisateur.
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: RwLock<Option<Vault>>,
    folders: RwLock<Vec<FolderOption>>,
    /// Organisations (coffres partagés) et collections du coffre ouvert.
    organizations: RwLock<Vec<Organization>>,
    store: Option<Store>,
    /// Coffre Vaultwarden ouvert. Le verrou extérieur n'est tenu qu'un
    /// instant : `lock()` ne doit jamais attendre une synchronisation en cours.
    connection: Mutex<Option<Arc<tokio::sync::Mutex<Connection>>>>,
    pending: Mutex<Option<PendingLogin>>,
    /// Échange en cours avec une clé de sécurité (second facteur,
    /// enrôlement ou déverrouillage), pour l'annuler ou lui passer le code PIN.
    security_key: Mutex<Option<SigningSession>>,
    /// Pont vers l'extension de navigateur et le terminal, s'il est activé.
    bridge: Mutex<Option<Bridge>>,
    /// Éléments protégés confirmés récemment (Touch ID ou mot de passe
    /// principal), effacés au verrouillage.
    authorized: Mutex<HashMap<String, Instant>>,
    /// Demandes d'accord du terminal en attente de l'utilisateur.
    confirmations: Arc<Confirmations>,
    /// Export lu, en attente de confirmation (secrets compris).
    pending_import: Mutex<Option<import::PendingImport>>,
    /// Identifiants dont le mot de passe vient d'être enregistré depuis
    /// Verrou, en attente de `check_new_passwords`.
    new_passwords: Mutex<Vec<String>>,
    /// Empreinte (SHA-256) du mot de passe de chaque identifiant trouvé dans
    /// des fuites, au moment de la vérification : un mot de passe changé
    /// depuis sort de la liste (`still_breached`). Effacé au verrouillage.
    breached: Mutex<HashMap<String, [u8; 32]>>,
    /// Éléments dont une modification faite hors ligne attend le serveur.
    pending_items: RwLock<HashSet<String>>,
    /// Éléments créés hors ligne : identifiant provisoire → serveur.
    remapped: RwLock<HashMap<String, String>>,
    /// Invitation d'une organisation à accepter une fois connecté, après la
    /// création du compte (`members`).
    pending_invite: Mutex<Option<verrou_vaultwarden::register::InviteLink>>,
    /// Version du coffre affiché (`Decrypted::version`) : un coffre plus
    /// ancien (synchronisation finie après une écriture locale) ne le
    /// remplace pas. Tenu pendant toute l'installation.
    installed: Mutex<u64>,
    /// Arrête l'envoi en cours de la dernière connexion (verrouillage), et
    /// ses écritures sur le disque (déconnexion), même s'il la garde en vie.
    closer: Mutex<Option<Closer>>,
    /// Canal des mises à jour en direct (`wait_for_server_change`).
    hub: tokio::sync::Mutex<Option<verrou_vaultwarden::hub::Hub>>,
    /// Incrémenté au verrouillage : l'attente en cours du canal s'arrête.
    hub_epoch: tokio::sync::watch::Sender<u64>,
    /// Dernière utilisation des éléments sur l'appareil (`preferences`).
    usage: Mutex<verrou_core::usage::UsageLog>,
    /// Règles de correspondance de l'appareil (`preferences`).
    match_settings: RwLock<verrou_core::matching::DeviceMatchSettings>,
    /// Domaines équivalents du compte, de la dernière synchronisation.
    equivalent_domains: RwLock<Vec<Vec<String>>>,
}

/// Demandes d'accord en cours : l'app répond par
/// `answer_bridge_confirmation`, depuis le fil principal.
#[derive(Default)]
struct Confirmations {
    next: AtomicU64,
    pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
}

impl Confirmations {
    fn answer(&self, id: &str, approved: bool) {
        let sender = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if let Some(sender) = sender {
            let _ = sender.send(approved);
        }
    }
}

/// Retire la demande quand on cesse de l'attendre (réponse, délai écoulé).
struct PendingConfirmation<'a> {
    confirmations: &'a Confirmations,
    id: String,
}

impl Drop for PendingConfirmation<'_> {
    fn drop(&mut self) {
        self.confirmations
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl VaultSession {
    /// Session reliée au dossier du compte (`with_storage`), ou ouverte en
    /// invitée par l'extension de remplissage (`for_autofill`).
    fn with_store(store: Store) -> Arc<Self> {
        Arc::new(Self {
            vault: RwLock::new(None),
            folders: RwLock::new(Vec::new()),
            organizations: RwLock::new(Vec::new()),
            store: Some(store),
            connection: Mutex::new(None),
            pending: Mutex::new(None),
            security_key: Mutex::new(None),
            bridge: Mutex::new(None),
            authorized: Mutex::new(HashMap::new()),
            confirmations: Arc::default(),
            pending_import: Mutex::new(None),
            new_passwords: Mutex::new(Vec::new()),
            breached: Mutex::new(HashMap::new()),
            pending_items: RwLock::new(HashSet::new()),
            remapped: RwLock::new(HashMap::new()),
            pending_invite: Mutex::new(None),
            installed: Mutex::new(0),
            closer: Mutex::new(None),
            hub: tokio::sync::Mutex::new(None),
            hub_epoch: tokio::sync::watch::Sender::new(0),
            usage: Mutex::new(verrou_core::usage::UsageLog::default()),
            match_settings: RwLock::new(verrou_core::matching::DeviceMatchSettings::default()),
            equivalent_domains: RwLock::new(Vec::new()),
        })
    }

    fn with_vault<T>(
        &self,
        f: impl FnOnce(&Vault) -> Result<T, VerrouError>,
    ) -> Result<T, VerrouError> {
        let guard = self.vault.read().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map_or(Err(VerrouError::Locked), f)
    }

    fn item<'v>(vault: &'v Vault, id: &str) -> Result<&'v Item, VerrouError> {
        vault.get(id).ok_or(VerrouError::NotFound)
    }

    fn store(&self) -> Result<&Store, VerrouError> {
        self.store.as_ref().ok_or(VerrouError::NoAccount)
    }

    fn current_connection(&self) -> Option<Arc<tokio::sync::Mutex<Connection>>> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn install_vault(&self, decrypted: Decrypted) -> u32 {
        let failures = decrypted.failures as u32;
        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if decrypted.version < *installed {
            return failures;
        }
        *installed = decrypted.version;
        // Réglages de l'appareil relus à chaque fois : l'app et l'extension
        // de remplissage de l'iPhone partagent le dossier.
        let settings = self.load_match_settings();
        let rules = Self::match_rules(
            &settings,
            &decrypted.folders,
            decrypted.equivalent_domains.clone(),
        );
        *self
            .match_settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = settings;
        *self
            .equivalent_domains
            .write()
            .unwrap_or_else(PoisonError::into_inner) = decrypted.equivalent_domains;
        self.reload_usage();
        for (from, to) in &decrypted.remapped {
            self.rename_use(from, to);
        }
        *self.folders.write().unwrap_or_else(PoisonError::into_inner) = decrypted
            .folders
            .into_iter()
            .map(|(id, name)| FolderOption { id, name })
            .collect();
        *self
            .organizations
            .write()
            .unwrap_or_else(PoisonError::into_inner) = decrypted.organizations;
        *self
            .pending_items
            .write()
            .unwrap_or_else(PoisonError::into_inner) =
            decrypted.pending_items.into_iter().collect();
        self.remapped
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(decrypted.remapped);
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) = Some(
            Vault::new(decrypted.items)
                .with_passkeys(decrypted.passkeys)
                .with_match_rules(rules),
        );
        failures
    }

    /// Verrouillé pendant l'échange avec le serveur : ne pas rouvrir le coffre.
    fn install_if_current(
        &self,
        connection: &Arc<tokio::sync::Mutex<Connection>>,
        decrypted: Decrypted,
    ) -> Result<(), VerrouError> {
        let still_current = self
            .current_connection()
            .is_some_and(|current| Arc::ptr_eq(&current, connection));
        if !still_current {
            return Err(VerrouError::Locked);
        }
        self.install_vault(decrypted);
        Ok(())
    }

    fn install(&self, unlocked: Unlocked) -> u32 {
        *self.closer.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(unlocked.connection.closer());
        // Nouvelle connexion : ses versions repartent de zéro.
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 0;
        *self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            Some(Arc::new(tokio::sync::Mutex::new(unlocked.connection)));
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.install_vault(unlocked.vault)
    }

    fn login_result(&self, step: LoginStep) -> LoginResult {
        match step {
            LoginStep::Unlocked(unlocked) => LoginResult::Unlocked {
                failures: self.install(*unlocked),
            },
            LoginStep::TwoFactor(pending) => {
                let options = pending.methods().iter().map(Into::into).collect();
                *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(*pending);
                LoginResult::TwoFactorRequired { options }
            }
        }
    }

    /// Écriture venue de l'extension, déjà vérifiée par
    /// `verrou_bridge::access` : dans le coffre affiché et la file, sans
    /// attendre le réseau (l'app envoie ensuite, `push_changes`). Seules
    /// les passkeys vont au serveur avant de répondre (le site en dépend).
    async fn perform_write(
        &self,
        connection: &Arc<tokio::sync::Mutex<Connection>>,
        write: Write,
    ) -> Result<String, VerrouError> {
        let mut open = connection.lock().await;
        let (id, decrypted) = match write {
            Write::Create {
                title,
                uri,
                username,
                password,
                totp,
            } => {
                open.create(Draft {
                    name: title,
                    login: Some(LoginDraft {
                        uri_matches: None,
                        username,
                        password,
                        totp,
                        uris: vec![uri],
                    }),
                    ..Draft::default()
                })
                .await?
            }
            Write::Update {
                item,
                username,
                password,
                totp,
                uri,
            } => {
                let decrypted = open
                    .amend_login(&item, username, password, totp, uri)
                    .await?;
                (item, decrypted)
            }
            Write::Passkey {
                item,
                title,
                uri,
                username,
                passkey,
            } => {
                open.save_passkey(item.as_deref(), title, uri, username, &passkey)
                    .await?
            }
            Write::PasskeyCounter {
                item,
                credential_id,
                counter,
            } => match open
                .set_passkey_counter(&item, &credential_id, counter)
                .await
            {
                Ok(decrypted) => (item, decrypted),
                // Partagé en lecture seule : la passkey sert, mais son
                // compteur ne peut pas avancer sur le serveur.
                Err(verrou_vaultwarden::Error::ReadOnly) => return Ok(item),
                Err(error) => return Err(error.into()),
            },
        };
        drop(open);
        self.install_written(connection, decrypted)?;
        Ok(id)
    }

    async fn sync_shared(&self, patient: bool) -> Result<SyncOutcome, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let Synced::Changed(decrypted) =
            verrou_vaultwarden::sync_shared(&connection, patient).await?
        else {
            return Ok(SyncOutcome {
                changed: false,
                failures: 0,
            });
        };
        let failures = decrypted.failures as u32;
        self.install_if_current(&connection, decrypted)?;
        Ok(SyncOutcome {
            changed: true,
            failures,
        })
    }

    /// Le résumé, marqué s'il attend le serveur.
    fn summary_of(&self, item: &Item) -> ItemSummary {
        ItemSummary {
            pending_sync: self
                .pending_items
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&item.id),
            last_used: self.last_used(&item.id),
            ..summary(item)
        }
    }

    /// Comme `summary_of`, avec la première passkey de l'identifiant.
    fn summary_in(&self, vault: &Vault, item: &Item) -> ItemSummary {
        let passkey = vault.passkeys_of(&item.id).into_iter().next();
        ItemSummary {
            passkey_rp_id: passkey.map(|p| p.rp_id.clone()),
            passkey_user_name: passkey
                .and_then(|p| p.user_name.clone().or_else(|| p.user_display_name.clone())),
            ..self.summary_of(item)
        }
    }

    fn is_authorized(&self, item: &Item) -> bool {
        !item.reprompt
            || self
                .authorized
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&item.id)
                .is_some_and(|at| at.elapsed() < REPROMPT_WINDOW)
    }

    /// Les secrets d'un élément protégé ne sortent qu'après confirmation.
    fn require_authorized(&self, item: &Item) -> Result<(), VerrouError> {
        if self.is_authorized(item) {
            Ok(())
        } else {
            Err(VerrouError::RepromptRequired)
        }
    }

    fn pending(&self) -> Result<PendingLogin, VerrouError> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(VerrouError::NoPendingLogin)
    }

    /// Un échange avec la clé de sécurité, sur un fil à part (il bloque
    /// jusqu'au contact), annulable par `cancel_security_key`.
    async fn with_security_key<T: Send + 'static>(
        &self,
        exchange: impl FnOnce(&SigningSession) -> Result<T, verrou_vaultwarden::Error> + Send + 'static,
    ) -> Result<T, VerrouError> {
        let session = SigningSession::new();
        *self
            .security_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(session.clone());
        let result = tokio::task::spawn_blocking(move || exchange(&session)).await;
        self.security_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        result
            .map_err(|e| VerrouError::SecurityKey {
                message: e.to_string(),
            })?
            .map_err(Into::into)
    }
}

/// Connexion à Vaultwarden. Ces méthodes sont asynchrones côté Swift : le
/// réseau et la dérivation du mot de passe (des centaines de millisecondes)
/// ne bloquent jamais l'interface.
#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Session reliée à un compte, dont les fichiers vivent dans `data_dir`.
    #[uniffi::constructor]
    pub fn with_storage(data_dir: String) -> Arc<Self> {
        Self::with_store(Store::new(data_dir))
    }

    /// Le compte enregistré, s'il y en a un.
    pub fn account(&self) -> Option<AccountInfo> {
        let account = self.store.as_ref()?.load_account().ok()??;
        Some(AccountInfo {
            server: account.server,
            email: account.email,
            synced_at: account.synced_at,
        })
    }

    pub async fn login(
        &self,
        server: String,
        email: String,
        password: String,
    ) -> Result<LoginResult, VerrouError> {
        let store = self.store()?.clone();
        let step =
            verrou_vaultwarden::login(&store, &server, &email, SecretString::new(password)).await?;
        Ok(self.login_result(step))
    }

    /// Signe le défi avec une clé de sécurité branchée en USB, sans
    /// navigateur. Rend le jeton à passer à `answer_two_factor`. Bloque
    /// jusqu'au contact sur la clé, au délai, ou à `cancel_security_key`.
    pub async fn sign_with_security_key(&self, challenge: String) -> Result<String, VerrouError> {
        let pending = self.pending()?;
        let request =
            verrou_vaultwarden::security_key::assertion_request(pending.server(), &challenge)?;
        let signer = request.clone();
        let response = self
            .with_security_key(move |session| session.sign(&signer, |_| {}))
            .await?;
        Ok(verrou_vaultwarden::security_key::token(&request, &response))
    }

    /// Interrompt l'attente de la clé de sécurité.
    pub fn cancel_security_key(&self) {
        if let Some(session) = self
            .security_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            session.cancel();
        }
    }

    /// Le code PIN que la clé de sécurité attend (`SecurityKeyPrompt::Pin`).
    /// Il ne fait que passer : la bibliothèque USB le transmet à la clé.
    pub fn submit_security_key_pin(&self, pin: String) {
        if let Some(session) = self
            .security_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            session.submit_pin(&pin);
        }
    }

    /// Enrôle la clé de sécurité branchée pour déverrouiller ce coffre
    /// (coffre ouvert) : une accréditation `hmac-secret` est créée sur la
    /// clé, puis son secret scelle la clé de l'utilisateur, qui ne quitte
    /// pas Rust. Deux contacts ; le code PIN de la clé est exigé.
    pub async fn enroll_security_key(
        &self,
        label: String,
        observer: Box<dyn SecurityKeyObserver>,
    ) -> Result<UnlockKey, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let existing = self.store()?.load_security_keys()?;
        let exclude = existing
            .iter()
            .map(EnrolledKey::credential_id)
            .collect::<Result<Vec<_>, _>>()?;
        let salt = unlock_keys::new_salt();
        let (credential_id, secret) = self
            .with_security_key(move |session| {
                session.enroll_for_unlock(&salt, &exclude, |status| observer.prompt(status.into()))
            })
            .await?;
        let label = match label.trim() {
            "" => format!("Clé de sécurité {}", existing.len() + 1),
            label => label.to_owned(),
        };
        let key = connection
            .lock()
            .await
            .enroll_security_key(&label, &credential_id, &salt, &secret)
            .await?;
        Ok(UnlockKey::from(&key))
    }

    /// Déverrouille avec l'une des clés de sécurité enrôlées : attend la
    /// clé, son code PIN et un contact. Une clé périmée (la clé du coffre a
    /// changé) retire toutes les clés enrôlées.
    pub async fn unlock_with_security_key(
        &self,
        observer: Box<dyn SecurityKeyObserver>,
    ) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let keys = store.load_security_keys()?;
        if keys.is_empty() {
            return Err(VerrouError::SecurityKey {
                message: "aucune clé de sécurité n'est enregistrée".to_owned(),
            });
        }
        let credentials = unlock_keys::credentials(&keys)?;
        let (credential_id, secret) = self
            .with_security_key(move |session| {
                session.unlock_secret(&credentials, |status| observer.prompt(status.into()))
            })
            .await?;
        let unlocked =
            verrou_vaultwarden::unlock_with_security_key(&store, credential_id.as_deref(), &secret)
                .await?;
        Ok(self.install(unlocked))
    }

    /// Nouveau défi de second facteur (après un refus de la clé de sécurité).
    pub async fn restart_two_factor(&self) -> Result<LoginResult, VerrouError> {
        let step = self.pending()?.restart().await?;
        Ok(self.login_result(step))
    }

    /// Envoie le code de second facteur par e-mail.
    pub async fn send_email_code(&self) -> Result<(), VerrouError> {
        Ok(self.pending()?.send_email_code().await?)
    }

    /// Réponse au second facteur : code saisi, ou JSON rendu par la page
    /// `WebAuthn` pour une clé de sécurité.
    pub async fn answer_two_factor(
        &self,
        option: TwoFactorOption,
        token: String,
    ) -> Result<LoginResult, VerrouError> {
        let pending = self.pending()?;
        let answer = TwoFactorAnswer {
            provider: option.provider(),
            token: token.trim().to_owned(),
        };
        let unlocked = pending.answer(&answer).await?;
        Ok(LoginResult::Unlocked {
            failures: self.install(unlocked),
        })
    }

    /// Déverrouillage hors ligne, sur le cache, par le mot de passe principal.
    pub async fn unlock_with_password(&self, password: String) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let unlocked =
            verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(password)).await?;
        Ok(self.install(unlocked))
    }

    /// Déverrouillage par la clé de l'utilisateur que Touch ID a libérée.
    pub async fn unlock_with_user_key(&self, user_key: String) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let unlocked =
            verrou_vaultwarden::unlock_with_user_key(&store, &SecretString::new(user_key)).await?;
        Ok(self.install(unlocked))
    }

    /// Envoie les écritures en attente, télécharge le coffre et, s'il a
    /// changé, remplace le contenu affiché : les positions de `summaries()`
    /// changent, l'app recharge tout après coup. Le réseau et le
    /// déchiffrement se font sans bloquer les écritures locales ; les
    /// demandes simultanées sont regroupées (une en cours, une après).
    pub async fn sync(&self) -> Result<SyncOutcome, VerrouError> {
        self.sync_shared(false).await
    }

    /// Comme `sync`, après une écriture locale : si le serveur était
    /// injoignable il y a peu, ne retente pas tout de suite (erreur réseau ;
    /// la synchronisation périodique s'en charge).
    pub async fn push_changes(&self) -> Result<SyncOutcome, VerrouError> {
        self.sync_shared(true).await
    }

    /// ⚠️ Brouillon prérempli pour modifier un élément, secrets compris :
    /// seulement quand l'utilisateur ouvre l'écran de modification.
    pub async fn edit_draft(&self, id: String) -> Result<ItemDraft, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if !item.is_writable() {
                return Err(VerrouError::ReadOnly);
            }
            if item.shared.as_ref().is_some_and(|s| s.hide_passwords) {
                return Err(hidden_by_organization());
            }
            self.require_authorized(item)
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let draft = connection.lock().await.draft(&id).await?;
        Ok(draft.into())
    }

    /// Crée l'élément dans le coffre personnel, sans attendre le serveur
    /// (`push_changes` l'envoie) ; rend son identifiant, provisoire jusqu'à
    /// l'envoi (`resolve_item_id`). Les positions de `summaries()` changent.
    pub async fn create_item(&self, draft: ItemDraft) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, decrypted) = connection.lock().await.create(draft.into()).await?;
        self.install_written(&connection, decrypted)?;
        Ok(id)
    }

    pub async fn update_item(&self, id: String, draft: ItemDraft) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.update(&id, draft.into()).await?;
        self.install_written(&connection, decrypted)
    }

    /// Met l'élément à la corbeille du serveur (restaurable depuis le coffre web).
    pub async fn trash_item(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.trash(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Sort l'élément de la corbeille.
    pub async fn restore_item(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.restore(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Archive l'élément (ou le sort des archives).
    pub async fn set_archived(&self, id: String, archived: bool) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.set_archived(&id, archived).await?;
        self.install_if_current(&connection, decrypted)
    }

    pub async fn set_favorite(&self, id: String, favorite: bool) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.set_favorite(&id, favorite).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Relie l'identifiant à une app du Mac : ajoute `macapp://<bundle_id>` à
    /// ses sites, synchronisé comme le reste. Rend `false` s'il l'était déjà.
    pub async fn link_to_app(&self, id: String, bundle_id: String) -> Result<bool, VerrouError> {
        let uri = apps::mac_app_uri(&bundle_id).ok_or_else(|| VerrouError::Invalid {
            message: "identifiant d'app invalide".to_owned(),
        })?;
        let already = self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login {
                return Err(VerrouError::Invalid {
                    message: "seul un identifiant se relie à une app".to_owned(),
                });
            }
            Ok(apps::matches_app(&item.urls, &bundle_id))
        })?;
        if already {
            return Ok(false);
        }
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .amend_login(&id, None, None, None, Some(uri))
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(true)
    }

    /// Mots de passe fuités, par Have I Been Pwned (k-anonymat : seuls les 5
    /// premiers caractères du SHA-1 de chaque mot de passe partent). Seulement
    /// sur demande explicite de l'utilisateur.
    pub async fn check_breaches(&self) -> Result<Vec<BreachedPassword>, VerrouError> {
        let candidates: Vec<(String, SecretString)> = self.with_vault(|v| {
            Ok(v.items()
                .iter()
                .filter(|i| i.is_active())
                .filter_map(|i| {
                    verrou_core::audit::password_of(i).map(|p| (i.id.clone(), SecretString::new(p)))
                })
                .collect())
        })?;
        let passwords: Vec<&str> = candidates.iter().map(|(_, p)| p.expose()).collect();
        let counts = verrou_vaultwarden::breach::pwned_counts(&passwords).await?;
        let mut breached: Vec<BreachedPassword> = self.with_vault(|v| {
            Ok(candidates
                .iter()
                .zip(counts)
                .filter(|(_, count)| *count > 0)
                .filter_map(|((id, _), count)| {
                    v.get(id).map(|i| BreachedPassword {
                        item: summary(i),
                        count,
                    })
                })
                .collect())
        })?;
        self.remember_breached(&candidates, &breached);
        breached.sort_by_key(|b| std::cmp::Reverse(b.count));
        Ok(breached)
    }

    /// Vérifie le mot de passe principal (confirmation d'un élément protégé
    /// sans Touch ID). Hors ligne, sur le cache.
    pub async fn verify_master_password(&self, password: String) -> Result<bool, VerrouError> {
        let store = self.store()?.clone();
        match verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(password)).await {
            Ok(_) => Ok(true),
            Err(verrou_vaultwarden::Error::WrongPassword) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// ⚠️ Clé de l'utilisateur (base64), à confier immédiatement au Secure
    /// Enclave pour Touch ID. Ne jamais l'écrire ni la journaliser.
    pub async fn user_key(&self) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let key = connection.lock().await.user_key().await?;
        Ok(key.expose().to_owned())
    }

    /// Clés de sécurité enrôlées pour déverrouiller ce coffre (un fichier
    /// illisible compte pour aucune : le mot de passe reste possible).
    pub fn security_keys(&self) -> Vec<UnlockKey> {
        self.store
            .as_ref()
            .and_then(|store| store.load_security_keys().ok())
            .unwrap_or_default()
            .iter()
            .map(UnlockKey::from)
            .collect()
    }

    /// Retire une clé de sécurité enrôlée (son accréditation reste sur la
    /// clé, inutile sans ce fichier).
    pub fn remove_security_key(&self, id: String) -> Result<(), VerrouError> {
        Ok(unlock_keys::remove(self.store()?, &id)?)
    }

    /// Retire toutes les clés de sécurité enrôlées : une reconnexion change
    /// la clé du coffre, comme pour Touch ID.
    pub fn remove_security_keys(&self) -> Result<(), VerrouError> {
        Ok(self.store()?.delete_security_keys()?)
    }

    /// Modifications faites hors ligne qui attendent le serveur. Lisible
    /// coffre verrouillé (pour prévenir avant une déconnexion, qui les perd).
    pub fn pending_changes(&self) -> u32 {
        self.store.as_ref().map_or(0, Store::pending_changes)
    }

    /// Identifiant actuel d'un élément : celui que le serveur a donné à un
    /// élément créé hors ligne, une fois envoyé (pour garder la sélection).
    pub fn resolve_item_id(&self, id: String) -> String {
        self.remapped
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
            .unwrap_or(id)
    }

    /// Bilan de l'envoi des modifications hors ligne depuis le dernier appel
    /// (après une synchronisation ou une écriture).
    pub async fn take_sync_report(&self) -> SyncReport {
        let Some(connection) = self.current_connection() else {
            return SyncReport::default();
        };
        let report = connection.lock().await.take_report();
        SyncReport {
            sent: u32::try_from(report.sent).unwrap_or(u32::MAX),
            conflicts: report.conflicts,
            rejected: report
                .rejected
                .into_iter()
                .map(|(title, reason)| format!("« {title} » : {reason}"))
                .collect(),
            remapped: report
                .remapped
                .into_iter()
                .map(|(temporary, server)| IdMapping { temporary, server })
                .collect(),
        }
    }

    /// Oublie le compte de ce Mac (jetons, cache, modifications hors ligne
    /// pas encore envoyées) et verrouille.
    pub fn logout(&self) -> Result<(), VerrouError> {
        // Un envoi en cours ne doit pas réécrire la file effacée.
        if let Some(closer) = self
            .closer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            closer.close();
        }
        self.lock();
        verrou_vaultwarden::logout(self.store()?)?;
        Ok(())
    }
}

#[uniffi::export]
impl VaultSession {
    /// Session sans compte : seulement le coffre fictif (démonstration).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            vault: RwLock::new(None),
            folders: RwLock::new(Vec::new()),
            organizations: RwLock::new(Vec::new()),
            store: None,
            connection: Mutex::new(None),
            pending: Mutex::new(None),
            security_key: Mutex::new(None),
            bridge: Mutex::new(None),
            authorized: Mutex::new(HashMap::new()),
            confirmations: Arc::default(),
            pending_import: Mutex::new(None),
            new_passwords: Mutex::new(Vec::new()),
            breached: Mutex::new(HashMap::new()),
            pending_items: RwLock::new(HashSet::new()),
            remapped: RwLock::new(HashMap::new()),
            pending_invite: Mutex::new(None),
            installed: Mutex::new(0),
            closer: Mutex::new(None),
            hub: tokio::sync::Mutex::new(None),
            hub_epoch: tokio::sync::watch::Sender::new(0),
            usage: Mutex::new(verrou_core::usage::UsageLog::default()),
            match_settings: RwLock::new(verrou_core::matching::DeviceMatchSettings::default()),
            equivalent_domains: RwLock::new(Vec::new()),
        })
    }

    /// Ouvre le coffre fictif (`size` = 0 : seulement les éléments soignés).
    pub fn unlock_mock(&self, size: u32, seed: u64) {
        let items = mock::vault_items(size as usize, seed);
        let passkeys = mock::passkeys(&items);
        // Dossiers fictifs, par nom (pour les règles de correspondance).
        let mut folders: Vec<(String, String)> = items
            .iter()
            .filter_map(|i| i.folder.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|name| {
                (
                    format!("dossier-{}", verrou_core::search::fold(&name)),
                    name,
                )
            })
            .collect();
        folders.sort_by_key(|(_, name)| verrou_core::search::fold(name));
        let settings = self
            .match_settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let rules = Self::match_rules(&settings, &folders, Vec::new());
        *self.folders.write().unwrap_or_else(PoisonError::into_inner) = folders
            .into_iter()
            .map(|(id, name)| FolderOption { id, name })
            .collect();
        let vault = Vault::new(items)
            .with_passkeys(passkeys)
            .with_match_rules(rules);
        *self
            .organizations
            .write()
            .unwrap_or_else(PoisonError::into_inner) = vec![mock_organization()];
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) = Some(vault);
    }

    pub fn lock(&self) {
        // Le canal des mises à jour (et son jeton) ne survit pas au verrouillage.
        self.stop_server_changes();
        // Les accords donnés au terminal ne survivent pas au verrouillage.
        if let Some(bridge) = self
            .bridge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            bridge.forget_approvals();
        }
        self.vault
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.folders
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.organizations
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.pending_items
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.remapped
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // Un envoi en cours s'arrête après sa requête : la connexion (et la
        // clé de l'utilisateur) n'ont pas à lui survivre plus longtemps.
        if let Some(closer) = self
            .closer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            closer.stop();
        }
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.authorized
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.cancel_import();
        self.forget_new_passwords();
        self.breached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        // Relu du disque à la prochaine ouverture (autre compte possible).
        *self.usage.lock().unwrap_or_else(PoisonError::into_inner) =
            verrou_core::usage::UsageLog::default();
    }

    /// L'élément est protégé et n'a pas été confirmé récemment : ses secrets
    /// attendent une confirmation (`authorize_item`).
    pub fn needs_confirmation(&self, id: String) -> bool {
        self.with_vault(|v| Ok(!self.is_authorized(Self::item(v, &id)?)))
            .unwrap_or(false)
    }

    /// L'utilisateur vient de confirmer (Touch ID ou mot de passe principal)
    /// pour cet élément protégé : ses secrets sont accessibles 5 minutes.
    pub fn authorize_item(&self, id: String) {
        self.authorized
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Instant::now());
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Tous les résumés, dans l'ordre du coffre. Appelé une fois après le
    /// déverrouillage ; la recherche renvoie ensuite des positions.
    pub fn summaries(&self) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| Ok(v.items().iter().map(|i| self.summary_in(v, i)).collect()))
    }

    pub fn search(
        &self,
        query: String,
        filter: SidebarFilter,
        order: ResultOrder,
    ) -> Result<Vec<SearchHit>, VerrouError> {
        let last_used = if order == ResultOrder::LastUsed {
            self.last_used_map()
        } else {
            HashMap::new()
        };
        self.with_vault(|v| {
            Ok(
                v.search_with_usage(&query, &filter.into(), order.into(), &last_used)
                    .into_iter()
                    .map(|hit| SearchHit {
                        position: hit.index as u32,
                        id: v.items()[hit.index].id.clone(),
                        highlights: hit.title_indices,
                    })
                    .collect(),
            )
        })
    }

    pub fn detail(&self, id: String) -> Result<ItemDetail, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            Ok(ItemDetail {
                summary: self.summary_in(v, item),
                ..detail(item)
            })
        })
    }

    /// Valeur d'un champ secret (ou `notes`), à la demande de l'utilisateur.
    pub fn reveal(&self, id: String, field_id: String) -> Result<String, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            self.require_authorized(item)?;
            if field_id == "notes" {
                return item
                    .notes
                    .as_ref()
                    .map(|n| n.expose().to_owned())
                    .ok_or(VerrouError::NotFound);
            }
            let field = item.field(&field_id).ok_or(VerrouError::NotFound)?;
            if item.hides(field) {
                return Err(hidden_by_organization());
            }
            self.record_use(&item.id);
            Ok(field.value.expose().to_owned())
        })
    }

    pub fn totp(&self, id: String, unix_time: u64) -> Result<TotpView, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            self.require_authorized(item)?;
            let field = item
                .field_of_kind(FieldKind::Totp)
                .ok_or(VerrouError::NotFound)?;
            let totp = Totp::parse(field.value.expose()).map_err(|e| VerrouError::InvalidTotp {
                message: e.to_string(),
            })?;
            let code = totp.generate(unix_time);
            Ok(TotpView {
                code: code.code,
                period: code.period,
                remaining: code.remaining,
            })
        })
    }

    pub fn counts(&self) -> Result<SidebarCounts, VerrouError> {
        self.with_vault(|v| {
            let c = v.counts();
            let named = |list: Vec<(String, usize)>| {
                list.into_iter()
                    .map(|(name, count)| NamedCount {
                        name,
                        count: count as u32,
                    })
                    .collect()
            };
            Ok(SidebarCounts {
                all: c.all as u32,
                archived: c.archived as u32,
                trashed: c.trashed as u32,
                favorites: c.favorites as u32,
                with_totp: c.with_totp as u32,
                passkeys: c.passkeys as u32,
                categories: c
                    .kinds
                    .into_iter()
                    .map(|(k, n)| ItemCategoryCount {
                        category: k.into(),
                        count: n as u32,
                    })
                    .collect(),
                templates: c
                    .templates
                    .into_iter()
                    .map(|(t, n)| ItemTemplateCount {
                        template: t.into(),
                        count: n as u32,
                    })
                    .collect(),
                folders: named(c.folders),
                tags: named(c.tags),
            })
        })
    }

    /// Dossiers du coffre, triés par nom.
    pub fn folders(&self) -> Vec<FolderOption> {
        self.folders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Audit du coffre : réutilisés, faibles, sites en HTTP. Aucun secret ne
    /// sort, seulement des résumés.
    pub fn audit(&self) -> Result<AuditReport, VerrouError> {
        self.with_vault(|v| {
            let report = verrou_core::audit::audit(v);
            let summaries = |ids: &[String]| -> Vec<ItemSummary> {
                ids.iter().filter_map(|id| v.get(id)).map(summary).collect()
            };
            Ok(AuditReport {
                reused: report.reused.iter().map(|g| summaries(g)).collect(),
                weak: report
                    .weak
                    .iter()
                    .filter_map(|(id, bits)| {
                        v.get(id).map(|i| WeakPassword {
                            item: summary(i),
                            bits: *bits,
                        })
                    })
                    .collect(),
                insecure: summaries(&report.insecure),
                checked: report.checked as u32,
            })
        })
    }

    /// Identifiants correspondant à une page, du plus précis au moins précis.
    pub fn suggestions(&self, page_url: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&page_url)
                .into_iter()
                .map(summary)
                .collect())
        })
    }

    // MARK: Remplissage dans les apps (⌘\)

    /// Identifiants reliés à une app du Mac (`macapp://<identifiant de paquet>`).
    pub fn app_suggestions(&self, bundle_id: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.app_suggestions(&bundle_id)
                .into_iter()
                .map(summary)
                .collect())
        })
    }

    /// L'élément est déjà relié à cette app.
    pub fn is_linked_to_app(&self, id: String, bundle_id: String) -> bool {
        self.with_vault(|v| Ok(apps::matches_app(&Self::item(v, &id)?.urls, &bundle_id)))
            .unwrap_or(false)
    }

    /// ⚠️ Frappes qui remplissent l'identifiant `id` dans l'app au premier
    /// plan : son identifiant et son mot de passe, en clair. Seulement quand
    /// l'utilisateur vient de le choisir ; un élément protégé doit avoir été
    /// confirmé (`authorize_item`).
    pub fn autofill_keystrokes(
        &self,
        id: String,
        submit: bool,
    ) -> Result<Vec<AutofillKeystroke>, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            self.require_authorized(item)?;
            let keys = apps::item_keystrokes(item, submit).ok_or_else(|| VerrouError::Invalid {
                message: "seul un identifiant se remplit dans une app".to_owned(),
            })?;
            self.record_use(&item.id);
            Ok(keys.into_iter().map(Into::into).collect())
        })
    }
}

// MARK: Coffres partagés (organisations)

/// Où se trouve un élément partagé, et ce que le compte peut en faire.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ItemSharing {
    pub organization_id: String,
    pub organization: String,
    /// Collections visibles par ce compte, dans l'ordre de leurs noms.
    pub collection_ids: Vec<String>,
    pub collections: Vec<String>,
    /// Lecture seule : ni modification, ni corbeille.
    pub read_only: bool,
    /// Mots de passe masqués par l'organisation (remplissage permis).
    pub hide_passwords: bool,
}

/// Une organisation de la barre latérale, avec ses collections.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
#[allow(clippy::struct_excessive_bools)] // des droits, lus tels quels par Swift
pub struct OrganizationView {
    pub id: String,
    pub name: String,
    /// Éléments actifs de l'organisation.
    pub count: u32,
    /// Propriétaire ou administrateur.
    pub admin: bool,
    /// Le compte peut y ranger un élément (une collection au moins).
    pub writable: bool,
    /// Page de l'organisation dans le coffre web (membres, collections).
    pub manage_url: Option<String>,
    pub collections: Vec<CollectionView>,
    /// Rôle du compte (`None` : inconnu).
    pub role: Option<OrganizationMemberRole>,
    /// Voir les membres (propriétaire, administrateur, gestionnaire avec
    /// accès à toutes les collections).
    pub can_view_members: bool,
    /// Inviter, confirmer, modifier, retirer (propriétaire, administrateur).
    pub can_manage_members: bool,
    /// Propriétaire : rôles au-dessus d'« utilisateur » aussi.
    pub is_owner: bool,
    /// Créer des collections.
    pub can_create_collections: bool,
    /// Une collection au moins à gérer, ou le droit d'en créer.
    pub manages_collections: bool,
    /// Renommer l'organisation (propriétaire).
    pub can_rename: bool,
    /// Groupes activés sur le serveur.
    pub use_groups: bool,
    /// Créer et modifier les groupes (propriétaire, administrateur).
    pub can_manage_groups: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
#[allow(clippy::struct_excessive_bools)] // des droits, lus tels quels par Swift
pub struct CollectionView {
    pub id: String,
    pub name: String,
    pub count: u32,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    /// Le compte peut renommer, supprimer et ouvrir cette collection.
    pub can_manage: bool,
}

fn hidden_by_organization() -> VerrouError {
    VerrouError::Invalid {
        message: "l'organisation masque ce mot de passe pour votre compte".to_owned(),
    }
}

/// L'organisation du coffre fictif (démonstration).
fn mock_organization() -> Organization {
    Organization {
        id: mock::MOCK_ORGANIZATION.0.to_owned(),
        name: mock::MOCK_ORGANIZATION.1.to_owned(),
        admin: true,
        role: Some(verrou_vaultwarden::members::MemberRole::Owner),
        collections: vec![verrou_vaultwarden::Collection {
            id: mock::MOCK_COLLECTION.0.to_owned(),
            name: mock::MOCK_COLLECTION.1.to_owned(),
            read_only: false,
            hide_passwords: false,
            manage: true,
        }],
        use_groups: false,
        can_create_collections: true,
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Organisations dont le compte est membre confirmé, avec leurs
    /// collections et le nombre d'éléments actifs de chacune.
    pub fn organizations(&self) -> Vec<OrganizationView> {
        let organizations = self
            .organizations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let counts = self.with_vault(|v| Ok(v.counts())).unwrap_or_default();
        let count = |list: &[(String, usize)], id: &str| {
            list.iter()
                .find(|(i, _)| i == id)
                .map_or(0, |(_, n)| *n as u32)
        };
        let server = self.account().map(|a| a.server);
        organizations
            .into_iter()
            .map(|org| OrganizationView {
                count: count(&counts.organizations, &org.id),
                role: org.role.map(Into::into),
                can_view_members: org.member_rights().view,
                can_manage_members: org.member_rights().manage,
                is_owner: org.member_rights().owner,
                writable: org.is_writable(),
                admin: org.admin,
                manage_url: server
                    .as_ref()
                    .map(|s| format!("{s}/#/organizations/{}/members", org.id)),
                can_create_collections: org.can_create_collections,
                manages_collections: org.manages_collections(),
                can_rename: org.can_rename(),
                use_groups: org.use_groups,
                can_manage_groups: org.can_manage_groups(),
                collections: org
                    .collections
                    .iter()
                    .map(|c| CollectionView {
                        id: c.id.clone(),
                        name: c.name.clone(),
                        count: count(&counts.collections, &c.id),
                        read_only: c.read_only,
                        hide_passwords: c.hide_passwords,
                        manage: c.manage,
                        can_manage: org.can_manage_collection(c),
                    })
                    .collect(),
                id: org.id,
                name: org.name,
            })
            .collect()
    }

    /// Crée l'élément directement dans des collections d'une organisation ;
    /// rend son identifiant.
    pub async fn create_shared_item(
        &self,
        draft: ItemDraft,
        organization_id: String,
        collection_ids: Vec<String>,
    ) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, decrypted) = connection
            .lock()
            .await
            .create_shared(draft.into(), &organization_id, &collection_ids)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        // Créé ici : pas une nouvelle à annoncer à ce compte.
        if let Some(store) = &self.store {
            let user_id = connection.lock().await.account().user_id.clone();
            let _ = verrou_vaultwarden::activity::acknowledge_items(
                store,
                &user_id,
                std::slice::from_ref(&id),
            );
        }
        Ok(id)
    }

    /// « Partager… » : déplace un élément personnel dans des collections
    /// d'une organisation (rechiffré sous la clé de l'organisation).
    pub async fn share_item(
        &self,
        id: String,
        organization_id: String,
        collection_ids: Vec<String>,
    ) -> Result<(), VerrouError> {
        self.with_vault(|v| self.require_authorized(Self::item(v, &id)?))?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .share(&id, &organization_id, &collection_ids)
            .await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Change les collections d'un élément partagé (même organisation).
    pub async fn set_item_collections(
        &self,
        id: String,
        collection_ids: Vec<String>,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .set_collections(&id, &collection_ids)
            .await?;
        self.install_if_current(&connection, decrypted)
    }
}

// MARK: Pont vers l'extension de navigateur et le terminal

/// Nature d'un client du pont.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BridgeClientKind {
    /// L'extension de navigateur (Brave, Firefox).
    Browser,
    /// Le terminal (`verrou`, et son agent SSH).
    Cli,
}

impl From<ClientKind> for BridgeClientKind {
    fn from(kind: ClientKind) -> Self {
        match kind {
            ClientKind::Browser => Self::Browser,
            ClientKind::Cli => Self::Cli,
        }
    }
}

/// Ce que le terminal demande à faire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AccessPurpose {
    /// Lire un secret de l'élément (mot de passe, notes, code…).
    Reveal,
    /// Signer avec la clé SSH de l'élément.
    Ssh,
    /// Le navigateur : utiliser ou créer une passkey (le site demande la
    /// vérification de l'utilisateur). `item` est l'élément, ou
    /// `passkey:<site>` pour un nouvel identifiant.
    Passkey,
    /// Signer un commit git avec la clé SSH de l'élément.
    GitSign,
}

impl From<Purpose> for AccessPurpose {
    fn from(purpose: Purpose) -> Self {
        match purpose {
            Purpose::Reveal => Self::Reveal,
            Purpose::Ssh => Self::Ssh,
            Purpose::Passkey => Self::Passkey,
            Purpose::GitSign => Self::GitSign,
        }
    }
}

/// Ce que l'app fait pour le pont : demander l'accord d'appairage, amener le
/// coffre au déverrouillage, faire confirmer un accès du terminal. Appelé
/// depuis le fil du pont : répondre vite.
#[uniffi::export(callback_interface)]
pub trait BridgeDelegate: Send + Sync {
    /// Afficher `code` et demander l'accord ; répondre par
    /// `answer_bridge_pairing(id, …)`. `kind` : ce qui sera relié.
    fn pairing_requested(&self, id: String, name: String, code: String, kind: BridgeClientKind);
    /// Le terminal `client_name` veut lire un secret de l'élément `item`
    /// (titre `title`), ou signer avec sa clé SSH : demander Touch ID (ou le
    /// mot de passe de la session ; pour un élément protégé, la confirmation
    /// de `needs_confirmation`), puis répondre par
    /// `answer_bridge_confirmation(id, …)`.
    fn confirm_requested(
        &self,
        id: String,
        client_name: String,
        purpose: AccessPurpose,
        item: String,
        title: String,
    );
    fn unlock_requested(&self);
    /// L'extension a enregistré un identifiant (ou un code) : le coffre a
    /// été resynchronisé, l'app recharge sa liste. `title` : pour le signaler.
    fn vault_changed(&self, item: String, title: String);
    /// L'extension veut remplir un élément protégé : demander la
    /// confirmation (Touch ID ou mot de passe principal), puis `authorize_item`.
    fn reprompt_requested(&self, item: String, title: String);
}

/// Bilan de l'envoi des modifications faites hors ligne.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct SyncReport {
    /// Modifications acceptées par le serveur.
    pub sent: u32,
    /// Éléments modifiés ailleurs entre-temps : titre de la copie qui garde
    /// la version locale (« … (conflit hors ligne) »).
    pub conflicts: Vec<String>,
    /// Modifications refusées par le serveur, retirées : « titre » : raison.
    pub rejected: Vec<String>,
    /// Éléments créés hors ligne, et leur identifiant sur le serveur.
    pub remapped: Vec<IdMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct IdMapping {
    pub temporary: String,
    pub server: String,
}

/// Résultat d'une synchronisation.
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct SyncOutcome {
    /// `false` : le serveur n'a rien de nouveau, le coffre affiché est à jour.
    pub changed: bool,
    /// Éléments que le SDK n'a pas su déchiffrer.
    pub failures: u32,
}

/// Un client appairé (extension ou terminal).
#[derive(Clone, Debug, uniffi::Record)]
pub struct BridgeClient {
    pub id: String,
    pub name: String,
    /// Horodatage Unix de l'appairage.
    pub created: i64,
    pub kind: BridgeClientKind,
}

/// Le coffre de la session, vu par le pont : seulement ce que
/// `verrou_bridge::access` autorise.
struct SessionBackend {
    session: Weak<VaultSession>,
    delegate: Box<dyn BridgeDelegate>,
    confirmations: Arc<Confirmations>,
}

impl Backend for SessionBackend {
    fn is_unlocked(&self) -> bool {
        self.session.upgrade().is_some_and(|s| s.is_unlocked())
    }

    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>> {
        let session = self.session.upgrade()?;
        session
            .with_vault(|v| Ok(verrou_bridge::access::suggestions(v, page_url)))
            .ok()
    }

    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>> {
        let session = self.session.upgrade()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut confirm = None;
        let outcome = session
            .with_vault(|v| {
                Ok(
                    verrou_bridge::access::credentials(v, item, page_url, now).and_then(
                        |credentials| {
                            // Élément protégé : la vérification du site passe
                            // d'abord, puis Verrou demande la confirmation ;
                            // l'extension réessaie.
                            if let Some(protected) =
                                v.get(item).filter(|i| !session.is_authorized(i))
                            {
                                confirm = Some(protected.title.clone());
                                Err(CONFIRM_IN_APP.to_owned())
                            } else {
                                session.record_use(item);
                                Ok(credentials)
                            }
                        },
                    ),
                )
            })
            .ok();
        if let Some(title) = confirm {
            self.delegate.reprompt_requested(item.to_owned(), title);
        }
        outcome
    }

    fn check_save(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        current: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>> {
        let session = self.session.upgrade()?;
        session
            .with_vault(|v| {
                Ok(verrou_bridge::access::check_save(
                    v, page_url, username, password, current,
                ))
            })
            .ok()
    }

    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
        Box::pin(async move {
            let session = self.session.upgrade()?;
            let write = match session.with_vault(|v| Ok(plan(v))).ok()? {
                Ok(write) => write,
                Err(reason) => return Some(Err(reason)),
            };
            let Some(connection) = session.current_connection() else {
                // Coffre fictif : rien à écrire.
                return Some(Err("coffre en lecture seule".to_owned()));
            };
            // Le compteur d'une passkey avance à chaque connexion : rien à
            // annoncer à l'utilisateur.
            let quiet = matches!(write, Write::PasskeyCounter { .. });
            match session.perform_write(&connection, write).await {
                Ok(id) if quiet => {
                    // Une passkey vient de servir.
                    session.record_use(&id);
                    Some(Ok(id))
                }
                Ok(id) => {
                    let title = session
                        .with_vault(|v| Ok(v.get(&id).map(|i| i.title.clone())))
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    self.delegate.vault_changed(id.clone(), title);
                    Some(Ok(id))
                }
                Err(VerrouError::Locked) => None,
                Err(error) => Some(Err(error.to_string())),
            }
        })
    }

    fn request_unlock(&self) {
        self.delegate.unlock_requested();
    }

    fn pairing_requested(&self, request: PairingRequest) {
        self.delegate.pairing_requested(
            request.id,
            request.name,
            request.code,
            request.kind.into(),
        );
    }

    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
        self.session.upgrade().is_some_and(|session| {
            session
                .with_vault(|vault| {
                    reader(vault);
                    Ok(())
                })
                .is_ok()
        })
    }

    fn gate(&self, item: &Item) -> bool {
        let Some(session) = self.session.upgrade() else {
            return false;
        };
        if session.is_authorized(item) {
            // Ses secrets partent vers le navigateur (formulaire, passkey).
            session.record_use(&item.id);
            return true;
        }
        self.delegate
            .reprompt_requested(item.id.clone(), item.title.clone());
        false
    }

    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool> {
        let id = self
            .confirmations
            .next
            .fetch_add(1, Ordering::Relaxed)
            .to_string();
        let (sender, answer) = tokio::sync::oneshot::channel();
        self.confirmations
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), sender);
        let item = request.item.clone();
        self.delegate.confirm_requested(
            id.clone(),
            request.client_name,
            request.purpose.into(),
            request.item,
            request.title,
        );
        let pending = PendingConfirmation {
            confirmations: &self.confirmations,
            id,
        };
        Box::pin(async move {
            let approved = answer.await.unwrap_or(false);
            drop(pending);
            // Élément protégé (« redemander le mot de passe principal ») :
            // l'accord ne vaut que si l'app l'a confirmé comme tel.
            approved
                && self.session.upgrade().is_some_and(|session| {
                    session
                        .with_vault(|v| Ok(v.get(&item).is_none_or(|i| session.is_authorized(i))))
                        .unwrap_or(false)
                })
        })
    }
}

#[uniffi::export]
impl VaultSession {
    /// Démarre le pont (port `VERROU_BRIDGE_PORT`, sinon le port de Verrou).
    /// Les clients appairés sont gardés dans le dossier du compte.
    pub fn start_bridge(
        self: Arc<Self>,
        delegate: Box<dyn BridgeDelegate>,
    ) -> Result<u16, VerrouError> {
        let file = self.store()?.dir().join("bridge-clients.json");
        let mut slot = self.bridge.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(bridge) = slot.as_ref() {
            return Ok(bridge.port());
        }
        let backend = SessionBackend {
            session: Arc::downgrade(&self),
            delegate,
            confirmations: Arc::clone(&self.confirmations),
        };
        let bridge = Bridge::start(verrou_bridge::port_from_env(), file, Arc::new(backend))
            .map_err(|e| VerrouError::Storage {
                message: format!("pont vers le navigateur et le terminal : {e}"),
            })?;
        // Version de l'extension livrée avec l'app : l'extension se recharge
        // d'elle-même quand l'app a été mise à jour.
        bridge.set_extension_manifest(verrou_bridge::bundled_extension_manifest());
        let port = bridge.port();
        *slot = Some(bridge);
        Ok(port)
    }

    pub fn stop_bridge(&self) {
        let bridge = self
            .bridge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(bridge);
    }

    pub fn answer_bridge_pairing(&self, id: String, approved: bool) {
        if let Some(bridge) = self
            .bridge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            bridge.answer_pairing(&id, approved);
        }
    }

    /// Réponse de l'utilisateur à une demande d'accord du terminal.
    pub fn answer_bridge_confirmation(&self, id: String, approved: bool) {
        self.confirmations.answer(&id, approved);
    }

    pub fn bridge_clients(&self) -> Vec<BridgeClient> {
        self.bridge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|b| {
                b.clients()
                    .into_iter()
                    .map(|c| BridgeClient {
                        id: c.id,
                        name: c.name,
                        created: c.created,
                        kind: c.kind.into(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn revoke_bridge_client(&self, id: String) {
        if let Some(bridge) = self
            .bridge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            bridge.revoke(&id);
        }
    }
}

#[uniffi::export]
pub fn generate_password(length: u32, digits: bool, symbols: bool) -> String {
    generator::password(&PasswordOptions {
        length: length as usize,
        digits,
        symbols,
        avoid_ambiguous: true,
    })
}

/// Entropie estimée, en bits.
#[uniffi::export]
pub fn password_strength(password: String) -> f64 {
    generator::entropy_bits(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<VaultSession> {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        session
    }

    #[test]
    fn secrets_never_appear_in_detail() {
        let session = session();
        let github = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == "GitHub")
            .unwrap();
        let detail = session.detail(github.id.clone()).unwrap();
        let password = detail.fields.iter().find(|f| f.id == "password").unwrap();
        assert!(password.secret);
        assert!(password.value.is_none());
        assert!(
            session
                .reveal(github.id.clone(), "password".into())
                .unwrap()
                .chars()
                .count()
                >= 16
        );
        assert_eq!(session.totp(github.id, 59).unwrap().code.len(), 6);
    }

    #[test]
    fn protected_items_need_a_fresh_confirmation() {
        let session = session();
        let card = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.reprompt)
            .expect("une carte protégée dans le coffre fictif");
        assert!(matches!(
            session.reveal(card.id.clone(), "number".to_owned()),
            Err(VerrouError::RepromptRequired)
        ));
        session.authorize_item(card.id.clone());
        assert!(session.reveal(card.id.clone(), "number".to_owned()).is_ok());
        // Verrouiller oublie les confirmations.
        session.lock();
        session.unlock_mock(0, 42);
        assert!(matches!(
            session.reveal(card.id, "number".to_owned()),
            Err(VerrouError::RepromptRequired)
        ));
    }

    #[test]
    fn app_autofill_types_the_login_and_respects_reprompt() {
        let session = session();
        let slack = session
            .app_suggestions("com.tinyspeck.slackmacgap".to_owned())
            .unwrap();
        assert_eq!(slack.len(), 1);
        let id = slack[0].id.clone();
        assert!(session.is_linked_to_app(id.clone(), "COM.tinyspeck.SlackMacGap".to_owned()));
        assert!(!session.is_linked_to_app(id.clone(), "com.apple.Terminal".to_owned()));
        let keys = session.autofill_keystrokes(id.clone(), true).unwrap();
        let password = session.reveal(id.clone(), "password".to_owned()).unwrap();
        assert_eq!(
            keys,
            vec![
                AutofillKeystroke::Text {
                    value: slack[0].subtitle.clone()
                },
                AutofillKeystroke::Tab,
                AutofillKeystroke::Text { value: password },
                AutofillKeystroke::Return,
            ]
        );

        // Élément protégé : rien sans confirmation.
        let mut items = mock::vault_items(0, 42);
        let protected = items.iter_mut().find(|i| i.id == id).unwrap();
        protected.reprompt = true;
        *session.vault.write().unwrap() = Some(Vault::new(items));
        assert!(matches!(
            session.autofill_keystrokes(id.clone(), false),
            Err(VerrouError::RepromptRequired)
        ));
        session.authorize_item(id.clone());
        assert_eq!(session.autofill_keystrokes(id, false).unwrap().len(), 3);

        // Une note ne se tape pas.
        let note = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.category == ItemCategory::SecureNote && !s.reprompt)
            .unwrap();
        assert!(matches!(
            session.autofill_keystrokes(note.id, false),
            Err(VerrouError::Invalid { .. })
        ));
    }

    #[test]
    fn linking_to_an_app_needs_a_valid_bundle_id_and_a_connection() {
        let session = session();
        let github = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == "GitHub")
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(session.link_to_app(github.id.clone(), "pas valide".to_owned())),
            Err(VerrouError::Invalid { .. })
        ));
        // Coffre fictif : pas de serveur où écrire.
        assert!(matches!(
            runtime.block_on(session.link_to_app(github.id, "com.github.GitHubClient".to_owned())),
            Err(VerrouError::Locked)
        ));
    }

    #[test]
    fn audit_reports_without_secrets() {
        let report = session().audit().unwrap();
        assert!(report.checked > 0);
        let issues = report.reused.iter().map(Vec::len).sum::<usize>()
            + report.weak.len()
            + report.insecure.len();
        assert!(issues > 0, "le coffre fictif a des faiblesses à montrer");
    }

    #[test]
    fn locking_forgets_the_vault() {
        let session = session();
        assert!(session.is_unlocked());
        session.lock();
        assert!(matches!(session.summaries(), Err(VerrouError::Locked)));
        assert!(matches!(
            session.search(String::new(), SidebarFilter::All, ResultOrder::Title),
            Err(VerrouError::Locked)
        ));
    }

    #[test]
    fn search_positions_index_into_summaries() {
        let session = session();
        let summaries = session.summaries().unwrap();
        let hits = session
            .search(
                "boursorama".into(),
                SidebarFilter::All,
                ResultOrder::Relevance,
            )
            .unwrap();
        assert_eq!(summaries[hits[0].position as usize].title, "Boursorama");
    }

    /// Délégué qui accepte toute demande d'accord du terminal, aussitôt.
    struct Approver(Arc<Confirmations>);

    impl BridgeDelegate for Approver {
        fn pairing_requested(&self, _: String, _: String, _: String, _: BridgeClientKind) {}
        fn confirm_requested(&self, id: String, _: String, _: AccessPurpose, _: String, _: String) {
            self.0.answer(&id, true);
        }
        fn unlock_requested(&self) {}
        fn vault_changed(&self, _: String, _: String) {}
        fn reprompt_requested(&self, _: String, _: String) {}
    }

    #[test]
    fn terminal_approval_of_a_protected_item_needs_the_app_confirmation() {
        let session = session();
        let backend = SessionBackend {
            session: Arc::downgrade(&session),
            delegate: Box::new(Approver(Arc::clone(&session.confirmations))),
            confirmations: Arc::clone(&session.confirmations),
        };
        let summaries = session.summaries().unwrap();
        let protected = summaries.iter().find(|s| s.reprompt).unwrap().id.clone();
        let plain = summaries.iter().find(|s| !s.reprompt).unwrap().id.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let confirm = |item: &str| {
            runtime.block_on(backend.confirm(Confirmation {
                client: "cli".to_owned(),
                client_name: "verrou".to_owned(),
                purpose: Purpose::Reveal,
                item: item.to_owned(),
                title: String::new(),
            }))
        };
        assert!(confirm(&plain));
        // Accordé par une simple confirmation : pas assez pour un élément protégé.
        assert!(!confirm(&protected));
        session.authorize_item(protected.clone());
        assert!(confirm(&protected));
        assert!(session.confirmations.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn shared_vaults_in_the_sidebar_and_hidden_passwords() {
        let session = session();
        let organizations = session.organizations();
        assert_eq!(organizations.len(), 1);
        let famille = &organizations[0];
        assert_eq!(famille.name, "Famille Martin");
        assert_eq!(famille.count, 1);
        assert_eq!(famille.collections[0].count, 1);
        assert!(famille.writable && famille.manage_url.is_none());
        let hits = session
            .search(
                String::new(),
                SidebarFilter::Collection {
                    id: famille.collections[0].id.clone(),
                },
                ResultOrder::Title,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        let summary = &session.summaries().unwrap()[hits[0].position as usize];
        let sharing = summary.sharing.as_ref().unwrap();
        assert_eq!(sharing.collections, ["Comptes communs"]);
        assert!(
            !session
                .detail(summary.id.clone())
                .unwrap()
                .fields
                .iter()
                .any(|f| f.hidden)
        );
        assert!(
            session
                .reveal(summary.id.clone(), "password".to_owned())
                .is_ok()
        );

        // Mots de passe masqués par l'organisation : ni reveal ni brouillon.
        let mut items = mock::vault_items(0, 42);
        for item in &mut items {
            if let Some(shared) = item.shared.as_mut() {
                shared.hide_passwords = true;
            }
        }
        *session.vault.write().unwrap() = Some(Vault::new(items));
        let detail = session.detail(summary.id.clone()).unwrap();
        assert!(detail.fields.iter().any(|f| f.id == "password" && f.hidden));
        assert!(matches!(
            session.reveal(summary.id.clone(), "password".to_owned()),
            Err(VerrouError::Invalid { .. })
        ));
        assert!(
            session
                .reveal(summary.id.clone(), "username".to_owned())
                .is_ok()
        );
        session.lock();
        assert_eq!(session.organizations().len(), 0);
    }
}

// MARK: Passkeys

/// Une passkey d'un élément, telle que l'app la montre : jamais sa clé.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyInfo {
    /// Identifiant au format de Bitwarden, pour la supprimer.
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    /// Horodatage Unix de création.
    pub created: i64,
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Les passkeys de l'élément (site, utilisateur, date), sans clé privée.
    pub fn passkeys(&self, id: String) -> Vec<PasskeyInfo> {
        self.with_vault(|v| {
            Ok(v.passkeys_of(&id)
                .into_iter()
                .map(|p| PasskeyInfo {
                    credential_id: p.credential_id.clone(),
                    rp_id: p.rp_id.clone(),
                    rp_name: p.rp_name.clone(),
                    user_name: p.user_name.clone().or_else(|| p.user_display_name.clone()),
                    created: p.created,
                })
                .collect())
        })
        .unwrap_or_default()
    }

    /// Retire une passkey de l'élément (sur le serveur), puis resynchronise.
    pub async fn delete_passkey(
        &self,
        id: String,
        credential_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .delete_passkey(&id, &credential_id)
            .await?;
        self.install_if_current(&connection, decrypted)
    }
}

/// Les outils des tests d'intégration (`tests/common`), pour les tests du
/// pont ci-dessous, qui ont besoin des internes de la session.
#[cfg(test)]
extern crate self as verrou_ffi;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_server;

#[cfg(test)]
mod optimistic_tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::test_server::{register, server, signed_in, slow};

    /// Un coffre de `items` éléments fictifs, à la version `version`.
    fn decrypted(items: usize, version: u64) -> Decrypted {
        Decrypted {
            items: mock::vault_items(0, 42).into_iter().take(items).collect(),
            failures: 0,
            folders: Vec::new(),
            passkeys: Vec::new(),
            organizations: Vec::new(),
            equivalent_domains: Vec::new(),
            pending_items: Vec::new(),
            pending_changes: 0,
            remapped: Vec::new(),
            version,
        }
    }

    /// Une synchronisation qui finit après une écriture locale (son coffre
    /// date d'avant l'écriture) ne remplace pas le coffre affiché.
    #[test]
    fn an_older_vault_does_not_replace_the_displayed_one() {
        let session = VaultSession::new();
        session.install_vault(decrypted(3, 7));
        session.install_vault(decrypted(1, 6));
        assert_eq!(session.summaries().unwrap().len(), 3);
        session.install_vault(decrypted(2, 8));
        assert_eq!(session.summaries().unwrap().len(), 2);
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl BridgeDelegate for Arc<Recorder> {
        fn pairing_requested(&self, _: String, _: String, _: String, _: BridgeClientKind) {}
        fn confirm_requested(&self, _: String, _: String, _: AccessPurpose, _: String, _: String) {}
        fn unlock_requested(&self) {}
        fn vault_changed(&self, item: String, _: String) {
            self.0.lock().unwrap().push(item);
        }
        fn reprompt_requested(&self, _: String, _: String) {}
    }

    /// Un identifiant enregistré depuis Brave ou Firefox : la réponse part
    /// dès l'écriture locale, bien avant celle du serveur ; l'app l'envoie
    /// ensuite (`push_changes`, sur `vault_changed`).
    #[tokio::test(flavor = "multi_thread")]
    async fn an_extension_save_answers_before_the_server_does() {
        let Some(server) = server() else { return };
        let latency = Duration::from_millis(600);
        let email = register(&server).await;
        let session = signed_in(slow(&server, latency).await, &email).await;
        let recorder = Arc::new(Recorder::default());
        let backend = SessionBackend {
            session: Arc::downgrade(&session),
            delegate: Box::new(Arc::clone(&recorder)),
            confirmations: Arc::clone(&session.confirmations),
        };

        let start = Instant::now();
        let reply = backend
            .write(Box::new(|_| {
                Ok(Write::Create {
                    title: "exemple.fr".to_owned(),
                    uri: "https://exemple.fr/connexion".to_owned(),
                    username: Some("camille".to_owned()),
                    password: Some(SecretString::new("depuis-brave")),
                    totp: None,
                })
            }))
            .await;
        let elapsed = start.elapsed();
        let temporary = reply.expect("coffre ouvert").expect("enregistré");
        assert!(elapsed < latency / 2, "réponse après {elapsed:?}");
        assert_eq!(
            *recorder.0.lock().unwrap(),
            std::slice::from_ref(&temporary)
        );
        let pending = |id: &str| {
            session
                .summaries()
                .unwrap()
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.pending_sync)
        };
        assert_eq!(pending(&temporary), Some(true));

        // L'envoi : au moins trois allers-retours (jeton, création, coffre).
        let start = Instant::now();
        assert!(session.push_changes().await.unwrap().changed);
        assert!(start.elapsed() >= latency * 3);
        let id = session.resolve_item_id(temporary);
        assert_eq!(pending(&id), Some(false));
        let seen = signed_in(server, &email).await;
        assert!(seen.summaries().unwrap().iter().any(|s| s.id == id));
    }
}
