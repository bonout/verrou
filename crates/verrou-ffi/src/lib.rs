//! Interface exposed to the Apple apps through `UniFFI`.
//!
//! Principle: Swift never receives a secret without asking for it
//! explicitly. Summaries (title, displayed username, site) arrive once at
//! unlock; each search keystroke returns only positions and highlights; a
//! password crosses the boundary only through `reveal`, when the user shows
//! or copies it.
//!
//! Documented exceptions: `user_key`, which returns the user's key so the
//! app can hand it to the Secure Enclave (Touch ID unlock), `edit_draft`,
//! which returns an item's secrets when the user opens the edit screen,
//! `autofill_keystrokes`, which returns the username and password to type
//! when the user chooses to fill an app (⌘\), and `wifi_qr_code`, which
//! returns the QR code content of a Wi-Fi network (password included) when
//! the user shows it. Likewise for Sends (`send`): `send_link` (the link
//! carries the Send's key), `send_fields` and `send_fields_for_field`, when
//! a Send's screen opens.
//!
//! A grantor's vault (emergency access, `emergency`) follows the same
//! rules, in a separate object (`EmergencyVault`) that is cleared on
//! lock.
//!
//! Security key unlock stays entirely in Rust: only the PIN (typed by the
//! user) and the steps of the exchange cross the boundary.

// UniFFI requires owned arguments (`String`, enums): the pedantic lint that
// wants references does not apply to an FFI boundary.
#![allow(clippy::needless_pass_by_value)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use verrou_bridge::access::Write;
use verrou_bridge::protocol::{
    CONFIRM_IN_APP, ClientKind, Credentials, SaveAction, Suggestion, UnlockIntent,
};
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
mod conditional;
mod emergency;
mod import;
mod members;
mod otp_scan;
mod passphrase;
mod preferences;
mod prf;
mod send;
mod sharing;
mod signals;
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
pub use prf::PasskeyPrfOutput;
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
    #[error("the vault is locked")]
    Locked,
    #[error("item not found")]
    NotFound,
    #[error("invalid one-time code: {message}")]
    InvalidTotp { message: String },
    #[error("wrong master password")]
    WrongPassword,
    #[error("second factor rejected: {message}")]
    TwoFactorRejected { message: String },
    #[error("no account is set up")]
    NoAccount,
    #[error("the session has expired: sign in again")]
    SessionExpired,
    #[error("{message}")]
    InvalidServer { message: String },
    #[error("server unreachable: {message}")]
    Network { message: String },
    #[error("server response: {message}")]
    Server { message: String },
    #[error("decryption failed: {message}")]
    Crypto { message: String },
    #[error("local storage: {message}")]
    Storage { message: String },
    #[error("no login in progress")]
    NoPendingLogin,
    #[error("security key: {message}")]
    SecurityKey { message: String },
    #[error("this item cannot be edited from this account")]
    ReadOnly,
    #[error("{message}")]
    Invalid { message: String },
    #[error("the item changed on the server")]
    Conflict,
    /// The item asks for a new confirmation (Touch ID or master password)
    /// before handing over its secrets: `authorize_item` afterwards.
    #[error("confirmation required for this item")]
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

/// The Vaultwarden account registered on this Mac.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountInfo {
    pub server: String,
    pub email: String,
    /// Unix timestamp of the last successful sync.
    pub synced_at: Option<i64>,
}

/// Second-factor method offered by the server.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TwoFactorOption {
    /// Security key (`YubiKey` as FIDO2). `challenge` is to be passed to the
    /// server's `WebAuthn` login page.
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

/// A security key enrolled for unlocking. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnlockKey {
    /// Credential id (base64url), to remove it.
    pub id: String,
    pub label: String,
    /// Unix timestamp of the enrollment.
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

/// Language of the mock vault's words: the app's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum MockLanguage {
    #[default]
    English,
    French,
    German,
    Spanish,
    Italian,
}

impl From<MockLanguage> for mock::MockLanguage {
    fn from(language: MockLanguage) -> Self {
        match language {
            MockLanguage::English => Self::En,
            MockLanguage::French => Self::Fr,
            MockLanguage::German => Self::De,
            MockLanguage::Spanish => Self::Es,
            MockLanguage::Italian => Self::It,
        }
    }
}

/// The mock vault's language for a language code (`fr-FR`, `de`, `en`…):
/// French for `fr…`, German for `de…`, Spanish for `es…`, Italian for
/// `it…`, English otherwise.
#[uniffi::export]
pub fn mock_language(code: String) -> MockLanguage {
    match mock::MockLanguage::from_code(&code) {
        mock::MockLanguage::Fr => MockLanguage::French,
        mock::MockLanguage::De => MockLanguage::German,
        mock::MockLanguage::Es => MockLanguage::Spanish,
        mock::MockLanguage::It => MockLanguage::Italian,
        mock::MockLanguage::En => MockLanguage::English,
    }
}

/// What the security key expects from the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityKeyPrompt {
    /// Touch it.
    Touch,
    /// Enter its PIN, to pass to `submit_security_key_pin`. `retry`: the
    /// previous one was wrong; `attempts_left`: remaining attempts, if the key
    /// says.
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

/// The app shows the steps of the exchange with the security key. Called
/// from the exchange's thread: answer quickly.
#[uniffi::export(callback_interface)]
pub trait SecurityKeyObserver: Send + Sync {
    fn prompt(&self, prompt: SecurityKeyPrompt);
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum LoginResult {
    /// Vault open. `failures`: items the SDK could not decrypt.
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
    /// Items of a template (Wi-Fi, passport…).
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
    /// Shared vault: an organization, or one of its collections.
    Organization {
        id: String,
    },
    Collection {
        id: String,
    },
    /// Logins that carry a passkey.
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
    /// Creation, newest first.
    Created,
    /// Last use on this device.
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

/// What the list shows of an item. No secret.
// A UniFFI record: flat fields, read as is by Swift.
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
    /// "Master password re-prompt": confirm before any secret.
    pub reprompt: bool,
    pub state: ItemStatus,
    /// Shared vault (organization); `None`: personal vault.
    pub sharing: Option<ItemSharing>,
    /// Verrou template (Wi-Fi, passport…), from the `verrou:type` field.
    pub template: Option<ItemTemplate>,
    /// Modified offline: the change is waiting for the server.
    pub pending_sync: bool,
    /// Creation (Unix timestamp).
    pub created: i64,
    /// Last use on this device (fill, copy, secret shown), if known.
    pub last_used: Option<i64>,
    /// The login's first passkey: its site (`rpId`)…
    pub passkey_rp_id: Option<String>,
    /// … and the username it carries.
    pub passkey_user_name: Option<String>,
}

/// Where the item is (see `verrou_core::ItemState`).
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

/// A search result: position in `summaries()`, item id (to check that the
/// position still points at the same one: a sync or a write replaces the
/// vault) and title characters to highlight.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SearchHit {
    pub position: u32,
    pub id: String,
    pub highlights: Vec<u32>,
}

/// A field as the detail screen shows it. `value` is absent for a secret
/// field: go through `reveal`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub field_type: FieldType,
    pub secret: bool,
    pub value: Option<String>,
    /// The item's organization hides this field from this account: no
    /// display and no copy (filling by the extension stays allowed).
    pub hidden: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemDetail {
    pub summary: ItemSummary,
    pub urls: Vec<String>,
    /// Match rule of each site (`None`: default rule).
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
    /// Active items, like the counts that follow (excluding archive and trash).
    pub all: u32,
    pub archived: u32,
    pub trashed: u32,
    pub favorites: u32,
    pub with_totp: u32,
    /// Logins that carry a passkey.
    pub passkeys: u32,
    pub categories: Vec<ItemCategoryCount>,
    /// Templates present in the vault, in `ItemTemplate` order.
    pub templates: Vec<ItemTemplateCount>,
    pub folders: Vec<NamedCount>,
    pub tags: Vec<NamedCount>,
}

/// A folder to file an item in.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderOption {
    pub id: String,
    pub name: String,
}

/// The edit screen. With `login`: a login; with `card`: a card; with
/// `identity`: an identity; with none: a secure note. For other types (SSH
/// key), only the title, folder, favorite, notes and custom fields can be
/// edited.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct ItemDraft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<String>,
    pub login: Option<LoginFields>,
    /// Custom fields, in order (without the reserved fields).
    pub fields: Vec<CustomField>,
    /// Template: chosen at creation, kept afterwards.
    pub template: Option<ItemTemplate>,
    /// Payment card (default value on the Swift side: existing calls don't
    /// have to name it).
    #[uniffi(default = None)]
    pub card: Option<CardFields>,
    /// Identity.
    #[uniffi(default = None)]
    pub identity: Option<IdentityFields>,
}

/// The editable fields of a payment card.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct CardFields {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

/// The editable fields of an identity.
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
    /// TOTP seed (`otpauth://…` or base32).
    pub totp: Option<String>,
    pub urls: Vec<String>,
    /// Rule of each site, in `urls` order (`None` in the list: default
    /// rule). `None`: each kept site keeps its own.
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

/// An item's detail screen: secret fields without their value.
fn detail(item: &Item) -> ItemDetail {
    let fields = item
        .fields
        .iter()
        // Address parts (for filling forms) and fields reserved for Verrou
        // (`verrou:type`): not to be shown.
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

/// A keystroke of app filling (see `verrou_core::apps`). The text is typed
/// as Unicode characters, whatever the keyboard layout.
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

/// Vault audit (computed locally): see `verrou_core::audit`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditReport {
    /// Groups of items sharing the same password.
    pub reused: Vec<Vec<ItemSummary>>,
    pub weak: Vec<WeakPassword>,
    /// Logins with a site over HTTP.
    pub insecure: Vec<ItemSummary>,
    /// Logins examined (those that have a password).
    pub checked: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct WeakPassword {
    pub item: ItemSummary,
    /// Estimated entropy, in bits.
    pub bits: f64,
}

/// A login whose password appears in known breaches.
#[derive(Clone, Debug, uniffi::Record)]
pub struct BreachedPassword {
    pub item: ItemSummary,
    /// Number of appearances in the breaches listed by Have I Been Pwned.
    pub count: u64,
}

/// How long a confirmation holds for a protected item.
const REPROMPT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Vault session. Locking drops the vault, which wipes its secrets from
/// memory (`SecretString` is zeroed on drop), and the connection, which
/// carries the user's key.
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: RwLock<Option<Vault>>,
    folders: RwLock<Vec<FolderOption>>,
    /// Organizations (shared vaults) and collections of the open vault.
    organizations: RwLock<Vec<Organization>>,
    store: Option<Store>,
    /// Open Vaultwarden vault. The outer lock is held only for an instant:
    /// `lock()` must never wait for a sync in progress.
    connection: Mutex<Option<Arc<tokio::sync::Mutex<Connection>>>>,
    pending: Mutex<Option<PendingLogin>>,
    /// Exchange in progress with a security key (second factor, enrollment
    /// or unlock), to cancel it or pass it the PIN.
    security_key: Mutex<Option<SigningSession>>,
    /// Bridge to the browser extension and the terminal, if enabled.
    bridge: Mutex<Option<Bridge>>,
    /// Protected items confirmed recently (Touch ID or master password),
    /// cleared on lock.
    authorized: Mutex<HashMap<String, Instant>>,
    /// Terminal approval requests waiting for the user.
    confirmations: Arc<Confirmations>,
    /// Export read, waiting for confirmation (secrets included).
    pending_import: Mutex<Option<import::PendingImport>>,
    /// Logins whose password was just saved from Verrou, waiting for
    /// `check_new_passwords`.
    new_passwords: Mutex<Vec<String>>,
    /// Fingerprint (SHA-256) of the password of each login found in
    /// breaches, at check time: a password changed since then leaves the
    /// list (`still_breached`). Cleared on lock.
    breached: Mutex<HashMap<String, [u8; 32]>>,
    /// Items with an offline change waiting for the server.
    pending_items: RwLock<HashSet<String>>,
    /// Items created offline: temporary id → server.
    remapped: RwLock<HashMap<String, String>>,
    /// An organization invitation to accept once signed in, after the
    /// account creation (`members`).
    pending_invite: Mutex<Option<verrou_vaultwarden::register::InviteLink>>,
    /// Version of the displayed vault (`Decrypted::version`): an older vault
    /// (sync finished after a local write) does not replace it. Held during
    /// the whole installation.
    installed: Mutex<u64>,
    /// Stops the last connection's push in progress (lock), and its disk
    /// writes (log out), even if it keeps the connection alive.
    closer: Mutex<Option<Closer>>,
    /// Live updates channel (`wait_for_server_change`).
    hub: tokio::sync::Mutex<Option<verrou_vaultwarden::hub::Hub>>,
    /// Incremented on lock: the channel's pending wait stops.
    hub_epoch: tokio::sync::watch::Sender<u64>,
    /// Last use of the items on the device (`preferences`).
    usage: Mutex<verrou_core::usage::UsageLog>,
    /// Device match rules (`preferences`).
    match_settings: RwLock<verrou_core::matching::DeviceMatchSettings>,
    /// Account's equivalent domains, from the last sync.
    equivalent_domains: RwLock<Vec<Vec<String>>>,
}

/// Pending approval requests: the app answers with
/// `answer_bridge_confirmation`, from the main thread.
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

/// Removes the request when we stop waiting for it (answer, timeout).
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
    /// Session tied to the account folder (`with_storage`), or opened as a
    /// guest by the autofill extension (`for_autofill`).
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
        // Device settings reread every time: the app and the iPhone's
        // autofill extension share the folder.
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

    /// Locked during the exchange with the server: don't reopen the vault.
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
        // New connection: its versions restart from zero.
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

    /// Write coming from the extension, already checked by
    /// `verrou_bridge::access`: into the displayed vault and the queue,
    /// without waiting for the network (the app pushes afterwards,
    /// `push_changes`). Only passkeys go to the server before answering
    /// (the site depends on it).
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
                // Shared read-only: the passkey works, but its counter
                // cannot move forward on the server.
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

    /// The summary, marked if it is waiting for the server.
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

    /// Like `summary_of`, with the login's first passkey.
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

    /// A protected item's secrets come out only after confirmation.
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

    /// An exchange with the security key, on a separate thread (it blocks
    /// until the touch), cancellable by `cancel_security_key`.
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

/// Vaultwarden connection. These methods are async on the Swift side: the
/// network and password derivation (hundreds of milliseconds) never block
/// the interface.
#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Session tied to an account, whose files live in `data_dir`.
    #[uniffi::constructor]
    pub fn with_storage(data_dir: String) -> Arc<Self> {
        Self::with_store(Store::new(data_dir))
    }

    /// The registered account, if there is one.
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

    /// Signs the challenge with a security key plugged in over USB, without
    /// a browser. Returns the token to pass to `answer_two_factor`. Blocks
    /// until the touch on the key, the timeout, or `cancel_security_key`.
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

    /// Stops waiting for the security key.
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

    /// The PIN the security key expects (`SecurityKeyPrompt::Pin`). It only
    /// passes through: the USB library hands it to the key.
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

    /// Enrolls the plugged-in security key to unlock this vault (vault
    /// open): an `hmac-secret` credential is created on the key, then its
    /// secret seals the user's key, which never leaves Rust. Two touches;
    /// the key's PIN is required.
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
            "" => format!("Security key {}", existing.len() + 1),
            label => label.to_owned(),
        };
        let key = connection
            .lock()
            .await
            .enroll_security_key(&label, &credential_id, &salt, &secret)
            .await?;
        Ok(UnlockKey::from(&key))
    }

    /// Unlocks with one of the enrolled security keys: waits for the key,
    /// its PIN and a touch. A stale key (the vault key changed) removes all
    /// enrolled keys.
    pub async fn unlock_with_security_key(
        &self,
        observer: Box<dyn SecurityKeyObserver>,
    ) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let keys = store.load_security_keys()?;
        if keys.is_empty() {
            return Err(VerrouError::SecurityKey {
                message: "no security key is registered".to_owned(),
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

    /// New second-factor challenge (after the security key was rejected).
    pub async fn restart_two_factor(&self) -> Result<LoginResult, VerrouError> {
        let step = self.pending()?.restart().await?;
        Ok(self.login_result(step))
    }

    /// Sends the second-factor code by email.
    pub async fn send_email_code(&self) -> Result<(), VerrouError> {
        Ok(self.pending()?.send_email_code().await?)
    }

    /// Second-factor answer: typed code, or JSON returned by the `WebAuthn`
    /// page for a security key.
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

    /// Offline unlock, from the cache, with the master password.
    pub async fn unlock_with_password(&self, password: String) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let unlocked =
            verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(password)).await?;
        Ok(self.install(unlocked))
    }

    /// Unlock with the user key that Touch ID released.
    pub async fn unlock_with_user_key(&self, user_key: String) -> Result<u32, VerrouError> {
        let store = self.store()?.clone();
        let unlocked =
            verrou_vaultwarden::unlock_with_user_key(&store, &SecretString::new(user_key)).await?;
        Ok(self.install(unlocked))
    }

    /// Pushes pending writes, downloads the vault and, if it changed,
    /// replaces the displayed content: the positions of `summaries()`
    /// change, the app reloads everything afterwards. Network and
    /// decryption run without blocking local writes; simultaneous requests
    /// are coalesced (one in progress, one after).
    pub async fn sync(&self) -> Result<SyncOutcome, VerrouError> {
        self.sync_shared(false).await
    }

    /// Like `sync`, after a local write: if the server was unreachable a
    /// short while ago, don't retry right away (network error; the
    /// periodic sync takes care of it).
    pub async fn push_changes(&self) -> Result<SyncOutcome, VerrouError> {
        self.sync_shared(true).await
    }

    /// ⚠️ Prefilled draft to edit an item, secrets included: only when the
    /// user opens the edit screen.
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

    /// Creates the item in the personal vault, without waiting for the
    /// server (`push_changes` sends it); returns its id, temporary until the
    /// push (`resolve_item_id`). The positions of `summaries()` change.
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

    /// Moves the item to the server's trash (restorable from the web vault).
    pub async fn trash_item(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.trash(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Takes the item out of the trash.
    pub async fn restore_item(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.restore(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Archives the item (or takes it out of the archive).
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

    /// Links the login to a Mac app: adds `macapp://<bundle_id>` to its
    /// sites, synced like the rest. Returns `false` if it already was.
    pub async fn link_to_app(&self, id: String, bundle_id: String) -> Result<bool, VerrouError> {
        let uri = apps::mac_app_uri(&bundle_id).ok_or_else(|| VerrouError::Invalid {
            message: "invalid app identifier".to_owned(),
        })?;
        let already = self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login {
                return Err(VerrouError::Invalid {
                    message: "only a login can be linked to an app".to_owned(),
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

    /// Breached passwords, through Have I Been Pwned (k-anonymity: only the
    /// first 5 characters of each password's SHA-1 are sent). Only on the
    /// user's explicit request.
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

    /// Checks the master password (confirmation of a protected item without
    /// Touch ID). Offline, from the cache.
    pub async fn verify_master_password(&self, password: String) -> Result<bool, VerrouError> {
        let store = self.store()?.clone();
        match verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(password)).await {
            Ok(_) => Ok(true),
            Err(verrou_vaultwarden::Error::WrongPassword) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// ⚠️ The user's key (base64), to hand to the Secure Enclave right away
    /// for Touch ID. Never write or log it.
    pub async fn user_key(&self) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let key = connection.lock().await.user_key().await?;
        Ok(key.expose().to_owned())
    }

    /// Security keys enrolled to unlock this vault (an unreadable file
    /// counts as none: the password stays possible).
    pub fn security_keys(&self) -> Vec<UnlockKey> {
        self.store
            .as_ref()
            .and_then(|store| store.load_security_keys().ok())
            .unwrap_or_default()
            .iter()
            .map(UnlockKey::from)
            .collect()
    }

    /// Removes an enrolled security key (its credential stays on the key,
    /// useless without this file).
    pub fn remove_security_key(&self, id: String) -> Result<(), VerrouError> {
        Ok(unlock_keys::remove(self.store()?, &id)?)
    }

    /// Removes all enrolled security keys: signing in again changes the
    /// vault key, as for Touch ID.
    pub fn remove_security_keys(&self) -> Result<(), VerrouError> {
        Ok(self.store()?.delete_security_keys()?)
    }

    /// Offline changes waiting for the server. Readable while the vault is
    /// locked (to warn before a log out, which loses them).
    pub fn pending_changes(&self) -> u32 {
        self.store.as_ref().map_or(0, Store::pending_changes)
    }

    /// An item's current id: the one the server gave to an item created
    /// offline, once pushed (to keep the selection).
    pub fn resolve_item_id(&self, id: String) -> String {
        self.remapped
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
            .unwrap_or(id)
    }

    /// Report of the push of offline changes since the last call (after a
    /// sync or a write).
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
                .map(|(title, reason)| format!("\"{title}\": {reason}"))
                .collect(),
            remapped: report
                .remapped
                .into_iter()
                .map(|(temporary, server)| IdMapping { temporary, server })
                .collect(),
        }
    }

    /// Forgets this Mac's account (tokens, cache, offline changes not yet
    /// pushed) and locks.
    pub fn logout(&self) -> Result<(), VerrouError> {
        // A push in progress must not rewrite the erased queue.
        if let Some(closer) = self
            .closer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            closer.close();
        }
        self.lock();
        let store = self.store()?;
        verrou_vaultwarden::logout(store)?;
        // Device settings and log: specific to this account.
        for name in [preferences::USAGE_FILE, preferences::MATCH_RULES_FILE] {
            let _ = std::fs::remove_file(store.dir().join(name));
        }
        *self
            .match_settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) =
            verrou_core::matching::DeviceMatchSettings::default();
        Ok(())
    }
}

#[uniffi::export]
impl VaultSession {
    /// Session without an account: only the mock vault (demo).
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

    /// Opens the mock vault (`size` = 0: only the curated items), its
    /// words in `language`.
    pub fn unlock_mock(&self, size: u32, seed: u64, language: MockLanguage) {
        let language = mock::MockLanguage::from(language);
        let items = mock::vault_items(size as usize, seed, language);
        let passkeys = mock::passkeys(&items, language);
        // Mock folders, by name (for the match rules).
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
            .unwrap_or_else(PoisonError::into_inner) = vec![mock_organization(language)];
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) = Some(vault);
    }

    pub fn lock(&self) {
        // The updates channel (and its token) does not survive locking.
        self.stop_server_changes();
        // Approvals given to the terminal do not survive locking.
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
        // A push in progress stops after its request: the connection (and
        // the user's key) need not outlive it any longer.
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
        // Reread from disk at the next opening (possibly another account).
        *self.usage.lock().unwrap_or_else(PoisonError::into_inner) =
            verrou_core::usage::UsageLog::default();
    }

    /// The item is protected and was not confirmed recently: its secrets
    /// wait for a confirmation (`authorize_item`).
    pub fn needs_confirmation(&self, id: String) -> bool {
        self.with_vault(|v| Ok(!self.is_authorized(Self::item(v, &id)?)))
            .unwrap_or(false)
    }

    /// The user just confirmed (Touch ID or master password) for this
    /// protected item: its secrets are accessible for 5 minutes.
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

    /// All summaries, in vault order. Called once after unlocking; search
    /// then returns positions.
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

    /// Value of a secret field (or `notes`), at the user's request.
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

    /// Vault folders, sorted by name.
    pub fn folders(&self) -> Vec<FolderOption> {
        self.folders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Vault audit: reused, weak, HTTP sites. No secret comes out, only
    /// summaries.
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

    /// Logins matching a page, from most to least specific.
    pub fn suggestions(&self, page_url: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&page_url)
                .into_iter()
                .map(summary)
                .collect())
        })
    }

    // MARK: Filling in apps (⌘\)

    /// Logins linked to a Mac app (`macapp://<bundle identifier>`).
    pub fn app_suggestions(&self, bundle_id: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.app_suggestions(&bundle_id)
                .into_iter()
                .map(summary)
                .collect())
        })
    }

    /// The item is already linked to this app.
    pub fn is_linked_to_app(&self, id: String, bundle_id: String) -> bool {
        self.with_vault(|v| Ok(apps::matches_app(&Self::item(v, &id)?.urls, &bundle_id)))
            .unwrap_or(false)
    }

    /// ⚠️ Keystrokes that fill login `id` into the frontmost app: its
    /// username and password, in clear. Only when the user just chose it; a
    /// protected item must have been confirmed (`authorize_item`).
    pub fn autofill_keystrokes(
        &self,
        id: String,
        submit: bool,
    ) -> Result<Vec<AutofillKeystroke>, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            self.require_authorized(item)?;
            let keys = apps::item_keystrokes(item, submit).ok_or_else(|| VerrouError::Invalid {
                message: "only a login can be filled into an app".to_owned(),
            })?;
            self.record_use(&item.id);
            Ok(keys.into_iter().map(Into::into).collect())
        })
    }
}

// MARK: Shared vaults (organizations)

/// Where a shared item is, and what the account can do with it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ItemSharing {
    pub organization_id: String,
    pub organization: String,
    /// Collections visible to this account, ordered by name.
    pub collection_ids: Vec<String>,
    pub collections: Vec<String>,
    /// Read-only: no edit, no trash.
    pub read_only: bool,
    /// Passwords hidden by the organization (filling allowed).
    pub hide_passwords: bool,
}

/// A sidebar organization, with its collections.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
#[allow(clippy::struct_excessive_bools)] // permissions, read as is by Swift
pub struct OrganizationView {
    pub id: String,
    pub name: String,
    /// Active items of the organization.
    pub count: u32,
    /// Owner or admin.
    pub admin: bool,
    /// The account can file an item there (at least one collection).
    pub writable: bool,
    /// The organization's page in the web vault (members, collections).
    pub manage_url: Option<String>,
    pub collections: Vec<CollectionView>,
    /// The account's role (`None`: unknown).
    pub role: Option<OrganizationMemberRole>,
    /// View the members (owner, admin, manager with access to all
    /// collections).
    pub can_view_members: bool,
    /// Invite, confirm, edit, remove (owner, admin).
    pub can_manage_members: bool,
    /// Owner: roles above "user" too.
    pub is_owner: bool,
    /// Create collections.
    pub can_create_collections: bool,
    /// At least one collection to manage, or the right to create some.
    pub manages_collections: bool,
    /// Rename the organization (owner).
    pub can_rename: bool,
    /// Groups enabled on the server.
    pub use_groups: bool,
    /// Create and edit groups (owner, admin).
    pub can_manage_groups: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
#[allow(clippy::struct_excessive_bools)] // permissions, read as is by Swift
pub struct CollectionView {
    pub id: String,
    pub name: String,
    pub count: u32,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    /// The account can rename, delete and open this collection.
    pub can_manage: bool,
}

fn hidden_by_organization() -> VerrouError {
    VerrouError::Invalid {
        message: "the organization hides this password from your account".to_owned(),
    }
}

/// The mock vault's organization (demo).
fn mock_organization(language: mock::MockLanguage) -> Organization {
    Organization {
        id: mock::MOCK_ORGANIZATION_ID.to_owned(),
        name: mock::organization_name(language).to_owned(),
        admin: true,
        role: Some(verrou_vaultwarden::members::MemberRole::Owner),
        collections: vec![verrou_vaultwarden::Collection {
            id: mock::MOCK_COLLECTION_ID.to_owned(),
            name: mock::collection_name(language).to_owned(),
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
    /// Organizations the account is a confirmed member of, with their
    /// collections and the number of active items in each.
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

    /// Creates the item directly in collections of an organization; returns
    /// its id.
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
        // Created here: not news to announce to this account.
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

    /// "Share…": moves a personal item into collections of an organization
    /// (re-encrypted under the organization's key).
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

    /// Changes the collections of a shared item (same organization).
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

// MARK: Bridge to the browser extension and the terminal

/// Kind of bridge client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BridgeClientKind {
    /// The browser extension (Brave, Firefox).
    Browser,
    /// The terminal (`verrou`, and its SSH agent).
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

/// What the terminal asks to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AccessPurpose {
    /// Read a secret of the item (password, notes, code…).
    Reveal,
    /// Sign with the item's SSH key.
    Ssh,
    /// The browser: use or create a passkey (the site asks for user
    /// verification). `item` is the item, or `passkey:<site>` for a new
    /// login.
    Passkey,
    /// Sign a git commit with the item's SSH key.
    GitSign,
    /// The browser: link a site to a login. `title` says which to which
    /// ("the site exemple.fr to "GitHub"").
    LinkSite,
    /// The browser: fill a form with a payment card.
    Card,
    /// The browser: one more item, after many items requested in a short
    /// time.
    Bulk,
}

impl From<Purpose> for AccessPurpose {
    fn from(purpose: Purpose) -> Self {
        match purpose {
            Purpose::Reveal => Self::Reveal,
            Purpose::Ssh => Self::Ssh,
            Purpose::Passkey => Self::Passkey,
            Purpose::GitSign => Self::GitSign,
            Purpose::LinkSite => Self::LinkSite,
            Purpose::Card => Self::Card,
            Purpose::Bulk => Self::Bulk,
        }
    }
}

/// What the app does for the bridge: ask for pairing approval, bring the
/// vault to unlock, have a terminal access confirmed. Called from the
/// bridge's thread: answer quickly.
#[uniffi::export(callback_interface)]
pub trait BridgeDelegate: Send + Sync {
    /// Show `code` and ask for approval; answer with
    /// `answer_bridge_pairing(id, …)`. `kind`: what will be linked.
    fn pairing_requested(&self, id: String, name: String, code: String, kind: BridgeClientKind);
    /// Terminal `client_name` wants to read a secret of item `item` (title
    /// `title`), or sign with its SSH key: ask for Touch ID (or the session
    /// password; for a protected item, the `needs_confirmation`
    /// confirmation), then answer with `answer_bridge_confirmation(id, …)`.
    /// `site`: for `LinkSite`, the host of the site to link to the item
    /// (empty otherwise). `reason`: why the terminal asks, as it declares
    /// it (empty if it didn't say).
    #[allow(clippy::too_many_arguments)]
    fn confirm_requested(
        &self,
        id: String,
        client_name: String,
        purpose: AccessPurpose,
        item: String,
        title: String,
        site: String,
        reason: String,
    );
    /// A client found the vault locked. `kind`: the terminal may be
    /// unlocked from the iPhone, the browser brings Verrou forward.
    /// `reason`: the terminal's, as for `confirm_requested`. `then_item`,
    /// `then_field`: what the terminal will read once unlocked (empty if it
    /// didn't say): shown in the iPhone's request, whose approval then
    /// covers that item.
    fn unlock_requested(
        &self,
        kind: BridgeClientKind,
        reason: String,
        then_item: String,
        then_field: String,
    );
    /// The extension saved a login (or a code): the vault was synced again,
    /// the app reloads its list. `title`: to announce it.
    fn vault_changed(&self, item: String, title: String);
    /// The extension wants to fill a protected item: ask for confirmation
    /// (Touch ID or master password), then `authorize_item`.
    fn reprompt_requested(&self, item: String, title: String);
}

/// Report of the push of changes made offline.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct SyncReport {
    /// Changes accepted by the server.
    pub sent: u32,
    /// Items changed elsewhere in the meantime: title of the copy that
    /// keeps the local version ("… (offline conflict)").
    pub conflicts: Vec<String>,
    /// Changes rejected by the server, removed: "title": reason.
    pub rejected: Vec<String>,
    /// Items created offline, and their id on the server.
    pub remapped: Vec<IdMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct IdMapping {
    pub temporary: String,
    pub server: String,
}

/// Result of a sync.
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct SyncOutcome {
    /// `false`: the server has nothing new, the displayed vault is up to date.
    pub changed: bool,
    /// Items the SDK could not decrypt.
    pub failures: u32,
}

/// A paired client (extension or terminal).
#[derive(Clone, Debug, uniffi::Record)]
pub struct BridgeClient {
    pub id: String,
    pub name: String,
    /// Unix timestamp of the pairing.
    pub created: i64,
    pub kind: BridgeClientKind,
}

/// The session's vault, as the bridge sees it: only what
/// `verrou_bridge::access` allows.
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
                            // Protected item: the site check comes first,
                            // then Verrou asks for confirmation; the
                            // extension retries.
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
                // Mock vault: nothing to write.
                return Some(Err("read-only vault".to_owned()));
            };
            // A passkey's counter moves forward on every sign-in: nothing to
            // announce to the user.
            let quiet = matches!(write, Write::PasskeyCounter { .. });
            match session.perform_write(&connection, write).await {
                Ok(id) if quiet => {
                    // A passkey was just used.
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

    fn request_unlock(&self, kind: ClientKind, reason: &str, then: Option<&UnlockIntent>) {
        let (item, field) =
            then.map_or_else(Default::default, |t| (t.item.clone(), t.field.clone()));
        self.delegate
            .unlock_requested(kind.into(), reason.to_owned(), item, field);
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
            // Its secrets go to the browser (form, passkey).
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
            request.site,
            request.reason,
        );
        let pending = PendingConfirmation {
            confirmations: &self.confirmations,
            id,
        };
        Box::pin(async move {
            let approved = answer.await.unwrap_or(false);
            drop(pending);
            // Protected item ("master password re-prompt"): the approval
            // only counts if the app confirmed it as such.
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
    /// Starts the bridge (port `VERROU_BRIDGE_PORT`, else Verrou's port).
    /// Paired clients are kept in the account folder.
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
                message: format!("bridge to the browser and the terminal: {e}"),
            })?;
        // Version of the extension shipped with the app: the extension
        // reloads itself when the app was updated.
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

    /// The user's answer to a terminal approval request.
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

/// Estimated entropy, in bits.
#[uniffi::export]
pub fn password_strength(password: String) -> f64 {
    generator::entropy_bits(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<VaultSession> {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
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
            .expect("a protected card in the mock vault");
        assert!(matches!(
            session.reveal(card.id.clone(), "number".to_owned()),
            Err(VerrouError::RepromptRequired)
        ));
        session.authorize_item(card.id.clone());
        assert!(session.reveal(card.id.clone(), "number".to_owned()).is_ok());
        // Locking forgets the confirmations.
        session.lock();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
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

        // Protected item: nothing without confirmation.
        let mut items = mock::vault_items(0, 42, mock::MockLanguage::En);
        let protected = items.iter_mut().find(|i| i.id == id).unwrap();
        protected.reprompt = true;
        *session.vault.write().unwrap() = Some(Vault::new(items));
        assert!(matches!(
            session.autofill_keystrokes(id.clone(), false),
            Err(VerrouError::RepromptRequired)
        ));
        session.authorize_item(id.clone());
        assert_eq!(session.autofill_keystrokes(id, false).unwrap().len(), 3);

        // A note is not typed.
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
            runtime.block_on(session.link_to_app(github.id.clone(), "not valid".to_owned())),
            Err(VerrouError::Invalid { .. })
        ));
        // Mock vault: no server to write to.
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
        assert!(issues > 0, "the mock vault has weaknesses to show");
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
            .search("chase".into(), SidebarFilter::All, ResultOrder::Relevance)
            .unwrap();
        assert_eq!(summaries[hits[0].position as usize].title, "Chase");
    }

    /// Delegate that approves any terminal approval request, right away.
    struct Approver(Arc<Confirmations>);

    impl BridgeDelegate for Approver {
        fn pairing_requested(&self, _: String, _: String, _: String, _: BridgeClientKind) {}
        fn confirm_requested(
            &self,
            id: String,
            _: String,
            _: AccessPurpose,
            _: String,
            _: String,
            _: String,
            _: String,
        ) {
            self.0.answer(&id, true);
        }
        fn unlock_requested(&self, _kind: BridgeClientKind, _reason: String, _: String, _: String) {
        }
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
                site: String::new(),
                reason: String::new(),
            }))
        };
        assert!(confirm(&plain));
        // Granted by a simple confirmation: not enough for a protected item.
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
        assert_eq!(famille.name, "Parker Family");
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
        assert_eq!(sharing.collections, ["Shared accounts"]);
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

        // Passwords hidden by the organization: no reveal, no draft.
        let mut items = mock::vault_items(0, 42, mock::MockLanguage::En);
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

/// A passkey of an item, as the app shows it: never its key.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyInfo {
    /// Id in Bitwarden's format, to delete it.
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    /// Unix timestamp of creation.
    pub created: i64,
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// The item's passkeys (site, user, date), without private key.
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

    /// Removes a passkey from the item (on the server), then syncs again.
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

/// The integration test tools (`tests/common`), for the bridge tests
/// below, which need the session's internals.
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

    /// A vault of `items` mock items, at version `version`.
    fn decrypted(items: usize, version: u64) -> Decrypted {
        Decrypted {
            items: mock::vault_items(0, 42, mock::MockLanguage::En)
                .into_iter()
                .take(items)
                .collect(),
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

    /// A sync that finishes after a local write (its vault predates the
    /// write) does not replace the displayed vault.
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
        fn confirm_requested(
            &self,
            _: String,
            _: String,
            _: AccessPurpose,
            _: String,
            _: String,
            _: String,
            _: String,
        ) {
        }
        fn unlock_requested(&self, _kind: BridgeClientKind, _reason: String, _: String, _: String) {
        }
        fn vault_changed(&self, item: String, _: String) {
            self.0.lock().unwrap().push(item);
        }
        fn reprompt_requested(&self, _: String, _: String) {}
    }

    /// A login saved from Brave or Firefox: the reply goes out as soon as
    /// the local write is done, well before the server's; the app pushes it
    /// afterwards (`push_changes`, on `vault_changed`).
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
        let temporary = reply.expect("vault open").expect("saved");
        assert!(elapsed < latency / 2, "reply after {elapsed:?}");
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

        // The push: at least three round trips (token, creation, vault).
        let start = Instant::now();
        assert!(session.push_changes().await.unwrap().changed);
        assert!(start.elapsed() >= latency * 3);
        let id = session.resolve_item_id(temporary);
        assert_eq!(pending(&id), Some(false));
        let seen = signed_in(server, &email).await;
        assert!(seen.summaries().unwrap().iter().any(|s| s.id == id));
    }
}
