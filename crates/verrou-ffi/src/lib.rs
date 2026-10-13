//! Interface exposée aux applications Apple par `UniFFI`.
//!
//! Principe : Swift ne reçoit jamais un secret sans l'avoir demandé
//! explicitement. Les résumés (titre, identifiant affiché, site) arrivent une
//! fois au déverrouillage ; chaque frappe de recherche ne renvoie que des
//! positions et des surlignages ; un mot de passe ne traverse la frontière que
//! par `reveal`, au moment où l'utilisateur l'affiche ou le copie.
//!
//! Exceptions documentées : `user_key`, qui rend la clé de l'utilisateur pour
//! que l'app la confie au Secure Enclave (déverrouillage par Touch ID), et
//! `edit_draft`, qui rend les secrets d'un élément quand l'utilisateur ouvre
//! l'écran de modification.

// UniFFI exige des arguments possédés (`String`, énumérations) : la règle
// pédantique qui voudrait des références ne s'applique pas à une frontière FFI.
#![allow(clippy::needless_pass_by_value)]

use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use verrou_bridge::protocol::{Credentials, Suggestion};
use verrou_bridge::{Backend, Bridge, PairingRequest};
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Filter, Item, ItemKind, SecretString, Sort, Vault, mock};
use verrou_vaultwarden::{
    Connection, Decrypted, Draft, LoginDraft, LoginStep, PendingLogin, Store, TwoFactorAnswer,
    TwoFactorMethod, Unlocked,
};

uniffi::setup_scaffolding!();

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
    Category { category: ItemCategory },
    Folder { name: String },
    Tag { name: String },
}

impl From<SidebarFilter> for Filter {
    fn from(filter: SidebarFilter) -> Self {
        match filter {
            SidebarFilter::All => Self::All,
            SidebarFilter::Favorites => Self::Favorites,
            SidebarFilter::WithTotp => Self::WithTotp,
            SidebarFilter::Category { category } => Self::Kind(category.into()),
            SidebarFilter::Folder { name } => Self::Folder(name),
            SidebarFilter::Tag { name } => Self::Tag(name),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ResultOrder {
    Relevance,
    Title,
    RecentlyModified,
}

impl From<ResultOrder> for Sort {
    fn from(order: ResultOrder) -> Self {
        match order {
            ResultOrder::Relevance => Self::Relevance,
            ResultOrder::Title => Self::Title,
            ResultOrder::RecentlyModified => Self::RecentlyModified,
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
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemDetail {
    pub summary: ItemSummary,
    pub urls: Vec<String>,
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
    pub all: u32,
    pub favorites: u32,
    pub with_totp: u32,
    pub categories: Vec<ItemCategoryCount>,
    pub folders: Vec<NamedCount>,
    pub tags: Vec<NamedCount>,
}

/// Un dossier où ranger un élément.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderOption {
    pub id: String,
    pub name: String,
}

/// L'écran de modification. Sans `login` : une note sécurisée (seuls le
/// titre, le dossier, le favori et les notes se modifient pour les autres
/// types).
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct ItemDraft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<String>,
    pub login: Option<LoginFields>,
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct LoginFields {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Graine TOTP (`otpauth://…` ou base32).
    pub totp: Option<String>,
    pub urls: Vec<String>,
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
            }),
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
            }),
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
    }
}

/// Session du coffre. Verrouiller libère le coffre, ce qui efface ses
/// secrets de la mémoire (`SecretString` est mis à zéro à la libération), et
/// la connexion, qui porte la clé de l'utilisateur.
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: RwLock<Option<Vault>>,
    folders: RwLock<Vec<FolderOption>>,
    store: Option<Store>,
    /// Coffre Vaultwarden ouvert. Le verrou extérieur n'est tenu qu'un
    /// instant : `lock()` ne doit jamais attendre une synchronisation en cours.
    connection: Mutex<Option<Arc<tokio::sync::Mutex<Connection>>>>,
    pending: Mutex<Option<PendingLogin>>,
    #[cfg(target_os = "macos")]
    security_key: Mutex<Option<verrou_vaultwarden::security_key::SigningSession>>,
    /// Pont vers l'extension de navigateur, s'il est activé.
    bridge: Mutex<Option<Bridge>>,
}

impl VaultSession {
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
        *self.folders.write().unwrap_or_else(PoisonError::into_inner) = decrypted
            .folders
            .into_iter()
            .map(|(id, name)| FolderOption { id, name })
            .collect();
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) =
            Some(Vault::new(decrypted.items));
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

    fn pending(&self) -> Result<PendingLogin, VerrouError> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(VerrouError::NoPendingLogin)
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
        Arc::new(Self {
            vault: RwLock::new(None),
            folders: RwLock::new(Vec::new()),
            store: Some(Store::new(data_dir)),
            connection: Mutex::new(None),
            pending: Mutex::new(None),
            #[cfg(target_os = "macos")]
            security_key: Mutex::new(None),
            bridge: Mutex::new(None),
        })
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
        #[cfg(target_os = "macos")]
        {
            let session = verrou_vaultwarden::security_key::SigningSession::new();
            *self
                .security_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(session.clone());
            let signer = request.clone();
            let response = tokio::task::spawn_blocking(move || session.sign(&signer, |_| {}))
                .await
                .map_err(|e| VerrouError::SecurityKey {
                    message: e.to_string(),
                })??;
            self.security_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            Ok(verrou_vaultwarden::security_key::token(&request, &response))
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Pas d'USB hors macOS ; la fonction reste asynchrone pour Swift.
            tokio::task::yield_now().await;
            let _ = request;
            Err(VerrouError::SecurityKey {
                message: "clé de sécurité en USB : macOS seulement".to_owned(),
            })
        }
    }

    /// Interrompt l'attente de la clé de sécurité.
    pub fn cancel_security_key(&self) {
        #[cfg(target_os = "macos")]
        if let Some(session) = self
            .security_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            session.cancel();
        }
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

    /// Télécharge le coffre et remplace le contenu affiché. Les positions de
    /// `summaries()` changent : l'app recharge tout après coup.
    pub async fn sync(&self) -> Result<u32, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.sync().await?;
        let failures = decrypted.failures as u32;
        self.install_if_current(&connection, decrypted)?;
        Ok(failures)
    }

    /// ⚠️ Brouillon prérempli pour modifier un élément, secrets compris :
    /// seulement quand l'utilisateur ouvre l'écran de modification.
    pub async fn edit_draft(&self, id: String) -> Result<ItemDraft, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let draft = connection.lock().await.draft(&id).await?;
        Ok(draft.into())
    }

    /// Crée l'élément dans le coffre personnel et resynchronise ; rend son
    /// identifiant. Les positions de `summaries()` changent.
    pub async fn create_item(&self, draft: ItemDraft) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, decrypted) = connection.lock().await.create(draft.into()).await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(id)
    }

    pub async fn update_item(&self, id: String, draft: ItemDraft) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.update(&id, draft.into()).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Met l'élément à la corbeille du serveur (restaurable depuis le coffre web).
    pub async fn trash_item(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.trash(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    /// ⚠️ Clé de l'utilisateur (base64), à confier immédiatement au Secure
    /// Enclave pour Touch ID. Ne jamais l'écrire ni la journaliser.
    pub async fn user_key(&self) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let key = connection.lock().await.user_key().await?;
        Ok(key.expose().to_owned())
    }

    /// Oublie le compte de ce Mac (jetons, cache) et verrouille.
    pub fn logout(&self) -> Result<(), VerrouError> {
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
            store: None,
            connection: Mutex::new(None),
            pending: Mutex::new(None),
            #[cfg(target_os = "macos")]
            security_key: Mutex::new(None),
            bridge: Mutex::new(None),
        })
    }

    /// Ouvre le coffre fictif (`size` = 0 : seulement les éléments soignés).
    pub fn unlock_mock(&self, size: u32, seed: u64) {
        let vault = Vault::new(mock::vault_items(size as usize, seed));
        *self.vault.write().unwrap_or_else(PoisonError::into_inner) = Some(vault);
    }

    pub fn lock(&self) {
        self.vault
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.folders
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
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
        self.with_vault(|v| Ok(v.items().iter().map(summary).collect()))
    }

    pub fn search(
        &self,
        query: String,
        filter: SidebarFilter,
        order: ResultOrder,
    ) -> Result<Vec<SearchHit>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.search(&query, &filter.into(), order.into())
                .into_iter()
                .map(|hit| SearchHit {
                    position: hit.index as u32,
                    id: v.items()[hit.index].id.clone(),
                    highlights: hit.title_indices,
                })
                .collect())
        })
    }

    pub fn detail(&self, id: String) -> Result<ItemDetail, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            let fields = item
                .fields
                .iter()
                .map(|f| {
                    let secret = f.kind.is_secret();
                    FieldView {
                        id: f.id.clone(),
                        label: f.label.clone(),
                        field_type: f.kind.into(),
                        secret,
                        value: (!secret).then(|| f.value.expose().to_owned()),
                    }
                })
                .collect();
            Ok(ItemDetail {
                summary: summary(item),
                urls: item.urls.clone(),
                fields,
                has_notes: item.notes.is_some(),
                created: item.created,
            })
        })
    }

    /// Valeur d'un champ secret (ou `notes`), à la demande de l'utilisateur.
    pub fn reveal(&self, id: String, field_id: String) -> Result<String, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if field_id == "notes" {
                return item
                    .notes
                    .as_ref()
                    .map(|n| n.expose().to_owned())
                    .ok_or(VerrouError::NotFound);
            }
            item.field(&field_id)
                .map(|f| f.value.expose().to_owned())
                .ok_or(VerrouError::NotFound)
        })
    }

    pub fn totp(&self, id: String, unix_time: u64) -> Result<TotpView, VerrouError> {
        self.with_vault(|v| {
            let item = Self::item(v, &id)?;
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
                favorites: c.favorites as u32,
                with_totp: c.with_totp as u32,
                categories: c
                    .kinds
                    .into_iter()
                    .map(|(k, n)| ItemCategoryCount {
                        category: k.into(),
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

    /// Identifiants correspondant à une page, du plus précis au moins précis.
    pub fn suggestions(&self, page_url: String) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| {
            Ok(v.suggestions_for(&page_url)
                .into_iter()
                .map(summary)
                .collect())
        })
    }
}

// MARK: Pont vers l'extension de navigateur

/// Ce que l'app fait pour le pont : demander l'accord d'appairage, amener le
/// coffre au déverrouillage. Appelé depuis le fil du pont : répondre vite.
#[uniffi::export(callback_interface)]
pub trait BridgeDelegate: Send + Sync {
    /// Afficher `code` et demander l'accord ; répondre par
    /// `answer_bridge_pairing(id, …)`.
    fn pairing_requested(&self, id: String, name: String, code: String);
    fn unlock_requested(&self);
}

/// Une extension appairée.
#[derive(Clone, Debug, uniffi::Record)]
pub struct BridgeClient {
    pub id: String,
    pub name: String,
    /// Horodatage Unix de l'appairage.
    pub created: i64,
}

/// Le coffre de la session, vu par le pont : seulement ce que
/// `verrou_bridge::access` autorise.
struct SessionBackend {
    session: Weak<VaultSession>,
    delegate: Box<dyn BridgeDelegate>,
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
        session
            .with_vault(|v| Ok(verrou_bridge::access::credentials(v, item, page_url, now)))
            .ok()
    }

    fn request_unlock(&self) {
        self.delegate.unlock_requested();
    }

    fn pairing_requested(&self, request: PairingRequest) {
        self.delegate
            .pairing_requested(request.id, request.name, request.code);
    }
}

#[uniffi::export]
impl VaultSession {
    /// Démarre le pont (port `VERROU_BRIDGE_PORT`, sinon le port de Verrou).
    /// Les extensions appairées sont gardées dans le dossier du compte.
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
        };
        let bridge = Bridge::start(verrou_bridge::port_from_env(), file, Arc::new(backend))
            .map_err(|e| VerrouError::Storage {
                message: format!("pont vers le navigateur : {e}"),
            })?;
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
}
