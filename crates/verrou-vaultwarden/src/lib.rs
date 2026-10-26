//! Connects Verrou to a Vaultwarden server.
//!
//! Division of roles:
//! - the **Bitwarden Rust SDK** does all the cryptography: master password
//!   derivation, decryption of the user key, of folders and of items;
//! - this crate does the rest: HTTP (`api`), local cache (`store`) and
//!   conversion to Verrou's model (`convert`).
//!
//! Writing (`edit`): creation, edits and trash, encrypted by the SDK before
//! being sent; in bulk (`import`): import of another manager's export,
//! trashing several items; grouped actions on a selection (`bulk`); merging
//! duplicates (`merge`). Item writes go through an encrypted queue
//! (`outbox`), applied right away to the displayed vault then sent in the
//! background (`sync_shared`), or when the network comes back.
//!
//! Emergency access (`emergency`): entrust one's vault to someone close, or
//! open read-only the one someone close entrusted to us.
//!
//! Organization members (`members`): invite, confirm (fingerprint
//! verified), roles and collections. Account creation from an invitation
//! (`register`).
//!
//! News to notify (`activity`, without key or secret) and live updates
//! from the server (`hub`, Vaultwarden's `WebSocket` channel).
//!
//! Sends (`send`): Bitwarden Send, sharing a text through an encrypted link.
//!
//! Security key unlock (`unlock_keys`): the user key sealed by a `YubiKey`'s
//! `hmac-secret` secret.

pub mod accounts;
pub mod activity;
mod api;
mod attachments;
pub mod breach;
mod bulk;
pub mod change_password;
pub mod collections;
mod convert;
pub mod device_login;
mod directory_cache;
mod domains;
mod edit;
pub mod emergency;
mod error;
pub mod hub;
mod import;
pub mod members;
mod merge;
mod organizations;
mod outbox;
pub mod passkey_directory;
pub mod passkey_setup;
mod passkeys;
pub mod register;
pub mod security_key;
pub mod send;
pub mod ssh_key;
mod store;
pub mod two_factor_directory;
pub mod unlock_keys;
mod unshare;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitwarden_api_api::models::{CipherDetailsResponseModel, SyncResponseModel};
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{
    AuthRequestMethod, InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::{Kdf, UnsignedSharedKey};
use bitwarden_vault::{Cipher, Folder, VaultClientExt};
use verrou_core::{Item, SecretString};

pub use api::{TwoFactorAnswer, TwoFactorMethod};
pub use attachments::AttachmentInfo;
pub use bulk::{BulkAction, BulkOutcome, Progress, Skipped};
pub use edit::{CardDraft, CustomFieldDraft, CustomFieldKind, Draft, IdentityDraft, LoginDraft};
pub use error::Error;
pub use import::{Destination, ImportPlan, ImportReport};
pub use merge::{MergeOutcome, MergeSummary};
pub use organizations::{Collection, Organization, PendingMembership, ShareOutcome};
pub use outbox::{CONFLICT_SUFFIX, Closer, SyncReport, Synced, sync_shared};
pub use store::{Account, KdfSettings, Store};
pub use unshare::UnshareOutcome;

use api::{Api, PasswordGrant, Prelogin, TokenOutcome, Tokens};

/// The decrypted vault, ready to index.
pub struct Decrypted {
    pub items: Vec<Item>,
    /// Items the SDK could not decrypt (missing organization key, unknown
    /// format). They are ignored, but the interface reports it.
    pub failures: usize,
    /// Folders (id, name), sorted by name: to file an item.
    pub folders: Vec<(String, String)>,
    /// Passkeys of the logins (private key included): for
    /// `Vault::with_passkeys`.
    pub passkeys: Vec<verrou_core::Passkey>,
    /// Organizations (shared vaults) and their collections, sorted by name.
    pub organizations: Vec<Organization>,
    /// The account's equivalent domains (Bitwarden settings), for the
    /// "domain" match rule.
    pub equivalent_domains: Vec<Vec<String>>,
    /// Items with an offline change waiting for the server.
    pub pending_items: Vec<String>,
    /// Changes made offline, not sent yet.
    pub pending_changes: usize,
    /// Items created offline then sent: (provisional id, server id), since
    /// the vault was opened.
    pub remapped: Vec<(String, String)>,
    /// State of the connection (queue and cache) this vault reflects:
    /// increasing. A vault older than the displayed one does not replace it
    /// (a sync that finished after a local write).
    pub version: u64,
}

/// An open vault: the SDK holds the user key in memory.
/// Dropping it (locking) erases that key.
pub struct Connection {
    api: Api,
    sdk: Client,
    store: Store,
    account: Account,
    /// Changes made offline (see `outbox`).
    outbox: outbox::Outbox,
    /// Last network error: writes that follow closely go straight into the
    /// queue.
    offline_at: Option<Instant>,
    /// Report of the queue's sends, waiting to be read.
    report: SyncReport,
    /// Provisional ids of items created offline → server.
    remapped: outbox::Remapped,
    /// Background sends (`sync_shared`), shared outside the lock.
    courier: std::sync::Arc<outbox::Courier>,
    /// Syncs saved as cache.
    generation: u64,
    /// Changes to the queue or the cache (see `Decrypted::version`).
    version: u64,
}

pub struct Unlocked {
    pub connection: Connection,
    pub vault: Decrypted,
}

pub enum LoginStep {
    Unlocked(Box<Unlocked>),
    /// The server asks for a second factor. Answer with
    /// [`PendingLogin::answer`]; retrying after a rejection is allowed.
    TwoFactor(Box<PendingLogin>),
}

/// Login waiting for the second factor. Keeps the master password (in a
/// `SecretString`), or the key received from another device, for the
/// duration of the exchange: the user key still has to be decrypted once the
/// token is obtained.
#[derive(Clone)]
pub struct PendingLogin {
    api: Api,
    store: Store,
    email: String,
    secret: LoginSecret,
    prelogin: Prelogin,
    /// Authentication hash, or access code of an approved request.
    auth_hash: String,
    /// Login approved by another device: the request.
    auth_request: Option<String>,
    device_id: String,
    methods: Vec<TwoFactorMethod>,
}

/// What opens the user key once logged in.
#[derive(Clone)]
enum LoginSecret {
    Password(SecretString),
    /// Approved by another device (`device_login`).
    Device(device_login::Approval),
}

/// First login (or login again after the session expired).
pub async fn login(
    store: &Store,
    server: &str,
    email: &str,
    password: SecretString,
) -> Result<LoginStep, Error> {
    let api = Api::new(server)?;
    let email = email.trim().to_owned();
    let prelogin = api.prelogin(&email).await?;
    let auth =
        MasterPasswordAuthenticationData::derive(password.expose(), &prelogin.kdf, &prelogin.salt)
            .map_err(Error::crypto)?;
    let pending = PendingLogin {
        api,
        store: store.clone(),
        email,
        secret: LoginSecret::Password(password),
        prelogin,
        auth_hash: auth.master_password_authentication_hash.to_string(),
        auth_request: None,
        device_id: store.device_id()?,
        methods: Vec::new(),
    };
    pending.request(None).await
}

impl PendingLogin {
    pub fn methods(&self) -> &[TwoFactorMethod] {
        &self.methods
    }

    pub fn server(&self) -> &str {
        self.api.server()
    }

    /// Asks for the second factor methods again. The server allows only one
    /// attempt per security key challenge: after a rejection, a new one is
    /// needed.
    pub async fn restart(&self) -> Result<LoginStep, Error> {
        self.request(None).await
    }

    /// Sends the code by email (`Email` method).
    pub async fn send_email_code(&self) -> Result<(), Error> {
        self.api
            .send_email_code(
                &self.email,
                &self.auth_hash,
                self.auth_request.as_deref(),
                &self.device_id,
            )
            .await
    }

    /// Login approved by another device (no master password typed).
    pub fn is_device_login(&self) -> bool {
        self.auth_request.is_some()
    }

    /// Sends the answer to the second factor. On rejection
    /// (`Error::TwoFactorRejected`), the login stays pending.
    pub async fn answer(&self, answer: &TwoFactorAnswer) -> Result<Unlocked, Error> {
        match self.request(Some(answer)).await? {
            LoginStep::Unlocked(unlocked) => Ok(*unlocked),
            LoginStep::TwoFactor(_) => Err(Error::TwoFactorRejected(
                "the server asks for a second factor again".to_owned(),
            )),
        }
    }

    async fn request(&self, answer: Option<&TwoFactorAnswer>) -> Result<LoginStep, Error> {
        let grant = PasswordGrant {
            email: &self.email,
            auth_hash: &self.auth_hash,
            auth_request: self.auth_request.as_deref(),
            device_id: &self.device_id,
            two_factor: answer,
        };
        match self.api.password_token(&grant).await? {
            TokenOutcome::Granted(tokens) => {
                let unlocked = self.complete(tokens).await?;
                Ok(LoginStep::Unlocked(Box::new(unlocked)))
            }
            TokenOutcome::TwoFactorRequired(methods) => {
                if methods.is_empty() {
                    return Err(Error::Server(
                        "second factor required, but no supported method \
                         (security key, TOTP app, YubiKey OTP or email)"
                            .to_owned(),
                    ));
                }
                Ok(LoginStep::TwoFactor(Box::new(PendingLogin {
                    methods,
                    ..self.clone()
                })))
            }
        }
    }

    /// Tokens obtained: sync, open the vault with the password, then save
    /// the account.
    async fn complete(&self, tokens: Tokens) -> Result<Unlocked, Error> {
        let sync_json = self.api.sync(&tokens.access).await?;
        let sync: serde_json::Value = serde_json::from_str(&sync_json)
            .map_err(|e| Error::Server(format!("unreadable sync ({e})")))?;
        let profile_text = |key: &str| {
            sync.pointer(&format!("/profile/{key}"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let unlock = tokens.unlock.unwrap_or_else(|| self.prelogin.clone());
        let mut account = Account {
            version: Account::new_version(),
            server: self.api.server().to_owned(),
            email: self.email.clone(),
            user_id: profile_text("id")
                .ok_or_else(|| Error::Server("profile without an id".to_owned()))?,
            kdf: KdfSettings::from(&unlock.kdf),
            salt: unlock.salt,
            wrapped_user_key: tokens
                .wrapped_user_key
                .or_else(|| profile_text("key"))
                .ok_or_else(|| Error::Server("missing user key".to_owned()))?,
            private_key: tokens
                .private_key
                .or_else(|| profile_text("privateKey"))
                .ok_or_else(|| Error::Server("missing private key".to_owned()))?,
            refresh_token: String::new(),
            synced_at: Some(now()),
            sync: Some(sync_json),
            // Read at login: the first sync doesn't have to decrypt
            // everything again for them.
            equivalent_domains: domains::fetch(&self.api, &tokens.access).await?,
        };
        let sdk = sdk_client(&account.server);
        match &self.secret {
            LoginSecret::Password(password) => init_with_password(&sdk, &account, password).await?,
            LoginSecret::Device(approval) => init_with_approval(&sdk, &account, approval).await?,
        }
        account.refresh_token = sdk
            .crypto()
            .encrypt_with_local_user_data_key(tokens.refresh)
            .map_err(Error::crypto)?;
        self.store.save_account(&account)?;
        // Logging in again (expired session) keeps the changes made
        // offline: they go out at the next sync.
        let outbox = outbox::load(&self.store, &account.user_id, &sdk);
        let connection =
            Connection::new(self.api.clone(), sdk, self.store.clone(), account, outbox);
        let vault = connection.decrypt_cache().await?;
        Ok(Unlocked { connection, vault })
    }
}

/// Offline unlock with the master password, on the cache.
pub async fn unlock_with_password(
    store: &Store,
    password: &SecretString,
) -> Result<Unlocked, Error> {
    let account = store.load_account()?.ok_or(Error::NoAccount)?;
    let sdk = sdk_client(&account.server);
    init_with_password(&sdk, &account, password).await?;
    open(store, account, sdk).await
}

/// Unlock with the user key, returned by Touch ID.
pub async fn unlock_with_user_key(
    store: &Store,
    user_key: &SecretString,
) -> Result<Unlocked, Error> {
    let account = store.load_account()?.ok_or(Error::NoAccount)?;
    let sdk = sdk_client(&account.server);
    init_with_user_key(&sdk, &account, user_key)
        .await
        // A rejected key comes from a stale Touch ID enrollment (password
        // changed, new login): the password is needed again.
        .map_err(|_| Error::Crypto("stale Touch ID key".to_owned()))?;
    open(store, account, sdk).await
}

/// Unlock with an enrolled security key: `secret` is what the key returned
/// (`hmac-secret`), `credential_id` the credential that answered, if it said
/// so. The user key does not leave Rust.
pub async fn unlock_with_security_key(
    store: &Store,
    credential_id: Option<&[u8]>,
    secret: &unlock_keys::HmacSecret,
) -> Result<Unlocked, Error> {
    let account = store.load_account()?.ok_or(Error::NoAccount)?;
    let keys = store.load_security_keys()?;
    let user_key = unlock_keys::unseal(&keys, credential_id, secret)?;
    let sdk = sdk_client(&account.server);
    if init_with_user_key(&sdk, &account, &user_key).await.is_err() {
        // Unsealed but rejected: the vault key changed since enrollment.
        // The enrolled keys are worthless now.
        store.delete_security_keys()?;
        return Err(Error::Crypto(
            "stale security key, register it again".to_owned(),
        ));
    }
    open(store, account, sdk).await
}

async fn init_with_user_key(
    sdk: &Client,
    account: &Account,
    user_key: &SecretString,
) -> Result<(), Error> {
    init(
        sdk,
        account,
        InitUserCryptoMethod::DecryptedKey {
            decrypted_user_key: user_key.expose().to_owned(),
        },
    )
    .await?;
    // The SDK accepts any well-formed key (the vault then decrypts to zero
    // items): it is checked against the refresh token, encrypted with it.
    sdk.crypto()
        .decrypt_with_local_user_data_key(account.refresh_token.clone())
        .map(drop)
        .map_err(Error::crypto)
}

/// Forgets the account: tokens, cache, encrypted keys, enrolled security
/// keys and offline changes not sent yet.
pub fn logout(store: &Store) -> Result<(), Error> {
    activity::forget(store)?;
    store.delete_security_keys()?;
    store.delete_outbox()?;
    store.delete_account()
}

async fn open(store: &Store, account: Account, sdk: Client) -> Result<Unlocked, Error> {
    let outbox = outbox::load(store, &account.user_id, &sdk);
    let connection = Connection::new(
        Api::new(&account.server)?,
        sdk,
        store.clone(),
        account,
        outbox,
    );
    let vault = connection.decrypt_cache().await?;
    Ok(Unlocked { connection, vault })
}

impl Connection {
    fn new(api: Api, sdk: Client, store: Store, account: Account, outbox: outbox::Outbox) -> Self {
        Self {
            api,
            sdk,
            store,
            account,
            outbox,
            offline_at: None,
            report: SyncReport::default(),
            remapped: outbox::Remapped::new(),
            courier: std::sync::Arc::default(),
            generation: 0,
            version: 0,
        }
    }

    /// A copy of the state to decrypt outside the connection's lock (same
    /// SDK, so same keys).
    pub(crate) fn snapshot(&self) -> Self {
        Self {
            api: self.api.clone(),
            sdk: self.sdk.clone(),
            store: self.store.clone(),
            account: self.account.clone(),
            outbox: self.outbox.clone(),
            offline_at: self.offline_at,
            report: SyncReport::default(),
            remapped: self.remapped.clone(),
            courier: std::sync::Arc::clone(&self.courier),
            generation: self.generation,
            version: self.version,
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Renews the access token, sends the queue (report:
    /// `take_report`), downloads the vault, saves it as cache and decrypts
    /// it, all under `&mut self` (the app goes through `sync_shared`,
    /// which doesn't hold the connection during the network). `None`: nothing changed since the cache,
    /// the vault already decrypted stays valid (the common case: no
    /// decryption nor reload of the display for nothing).
    pub async fn sync(&mut self) -> Result<Option<Decrypted>, Error> {
        let access = match self.access_token().await {
            Err(Error::Network(message)) => {
                self.mark_offline();
                return Err(Error::Network(message));
            }
            other => other?,
        };
        self.offline_at = None;
        let before = self.report.clone();
        let had_outbox = !self.outbox.is_empty();
        if self.outbox.has_unsent() && !self.store.is_guest() {
            self.replay(&access).await?;
        }
        let sync_json = match self.api.sync(&access).await {
            Err(Error::Network(message)) => {
                self.mark_offline();
                return Err(Error::Network(message));
            }
            other => other?,
        };
        let domains_changed = match self.refresh_domains(&access).await {
            Err(Error::Network(message)) => {
                self.mark_offline();
                return Err(Error::Network(message));
            }
            other => other?,
        };
        let unchanged =
            self.store_sync(sync_json)? && self.report == before && !had_outbox && !domains_changed;
        if unchanged {
            return Ok(None);
        }
        self.decrypt_cache().await.map(Some)
    }

    /// Saves a sync as cache; what the queue had sent is now in it. Returns
    /// `true` if nothing changed.
    fn store_sync(&mut self, sync_json: String) -> Result<bool, Error> {
        self.generation += 1;
        self.version += 1;
        let unchanged = self.account.sync.as_deref() == Some(sync_json.as_str());
        self.account.sync = Some(sync_json);
        self.account.synced_at = Some(now());
        self.store.save_account(&self.account)?;
        if self.outbox.purge_sent() {
            self.persist_outbox()?;
        }
        Ok(unchanged)
    }

    /// Fresh access token, obtained with the refresh token (saved right
    /// away if the server gives a new one).
    async fn access_token(&mut self) -> Result<String, Error> {
        let refresh = self.refresh_token()?;
        let tokens = match self.api.refresh(refresh.expose()).await {
            Err(Error::Network(message)) => return Err(Error::Network(message)),
            // Rejected: the other process (app or extension) may have received
            // and saved a new token in the meantime; take it over once.
            Err(error) => {
                if !self.adopt_saved_refresh_token() {
                    return Err(error);
                }
                let refresh = self.refresh_token()?;
                let tokens = self.api.refresh(refresh.expose()).await?;
                self.keep_refresh_token(&refresh, tokens.refresh)?;
                return Ok(tokens.access);
            }
            Ok(tokens) => tokens,
        };
        self.keep_refresh_token(&refresh, tokens.refresh)?;
        Ok(tokens.access)
    }

    /// The refresh token saved on disk, if it differs from the one in
    /// memory (same account): returns `true` if it was taken over.
    pub(crate) fn adopt_saved_refresh_token(&mut self) -> bool {
        let Ok(Some(saved)) = self.store.load_account() else {
            return false;
        };
        if saved.user_id != self.account.user_id
            || saved.refresh_token == self.account.refresh_token
        {
            return false;
        }
        self.account.refresh_token = saved.refresh_token;
        true
    }

    /// The refresh token, decrypted with the user key.
    fn refresh_token(&self) -> Result<SecretString, Error> {
        self.sdk
            .crypto()
            .decrypt_with_local_user_data_key(self.account.refresh_token.clone())
            .map(SecretString::new)
            .map_err(Error::crypto)
    }

    /// Encrypts `text` with the account's local key (the one of the change
    /// queue): the result can only be read back with the vault open
    /// (`open_local`). Used for the keys of passkeys created in the background.
    pub fn seal_local(&self, text: String) -> Result<String, Error> {
        self.sdk
            .crypto()
            .encrypt_with_local_user_data_key(text)
            .map_err(Error::crypto)
    }

    /// Decrypts a text sealed by `seal_local`.
    pub fn open_local(&self, sealed: String) -> Result<SecretString, Error> {
        self.sdk
            .crypto()
            .decrypt_with_local_user_data_key(sealed)
            .map(SecretString::new)
            .map_err(Error::crypto)
    }

    /// Saves the refresh token the server just gave, if it changed.
    fn keep_refresh_token(&mut self, previous: &SecretString, fresh: String) -> Result<(), Error> {
        if fresh == previous.expose() {
            return Ok(());
        }
        self.account.refresh_token = self
            .sdk
            .crypto()
            .encrypt_with_local_user_data_key(fresh)
            .map_err(Error::crypto)?;
        self.store.save_account(&self.account)
    }

    pub(crate) async fn sync_with(&mut self, access: &str) -> Result<Decrypted, Error> {
        let sync_json = self.api.sync(access).await?;
        self.store_sync(sync_json)?;
        self.decrypt_cache().await
    }

    /// The user key (base64), for Touch ID enrollment. It must only be
    /// handed to the Secure Enclave, never written in the clear.
    pub async fn user_key(&self) -> Result<SecretString, Error> {
        self.sdk
            .crypto()
            .get_user_encryption_key()
            .await
            .map(|key| SecretString::new(key.to_string()))
            .map_err(Error::crypto)
    }

    /// Enrolls a security key: seals the user key with what the key returned
    /// for `salt`, and adds it to `security-keys.json`. The user key does not
    /// leave Rust.
    pub async fn enroll_security_key(
        &self,
        label: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        secret: &unlock_keys::HmacSecret,
    ) -> Result<unlock_keys::EnrolledKey, Error> {
        let user_key = self.user_key().await?;
        let key = unlock_keys::seal(&user_key, secret, credential_id, salt, label, now())?;
        // Checks the seal before writing it.
        key.open(secret)?;
        unlock_keys::add(&self.store, key.clone())?;
        Ok(key)
    }

    async fn decrypt_cache(&self) -> Result<Decrypted, Error> {
        let mut sync: SyncResponseModel = match &self.account.sync {
            Some(json) => serde_json::from_str(json)
                .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?,
            None => SyncResponseModel::default(),
        };
        self.init_organizations(&sync).await?;
        let directory = self.decrypt_directory(&sync);
        let (ciphers, mut failures) = self.overlay(sync.ciphers.take());
        let folder_names = self.decrypt_folders(sync.folders)?;

        let mut items = Vec::new();
        let mut passkeys = Vec::new();
        for cipher in ciphers {
            match self.sdk.vault().ciphers().decrypt(cipher).await {
                Ok(view) => {
                    passkeys.extend(convert::passkeys(&view));
                    items.extend(convert::item(&view, &folder_names).map(|mut item| {
                        item.shared = directory.sharing(&view);
                        item
                    }));
                }
                Err(_) => failures += 1,
            }
        }
        let mut folders: Vec<(String, String)> = folder_names.into_iter().collect();
        folders.sort_by_key(|(_, name)| name.to_lowercase());
        Ok(Decrypted {
            items,
            failures,
            folders,
            passkeys,
            organizations: directory.organizations,
            equivalent_domains: self.equivalent_domains(),
            pending_items: self.outbox.pending_items(),
            pending_changes: self.outbox.pending_changes(),
            remapped: self
                .remapped
                .iter()
                .map(|(from, to)| (from.clone(), to.clone()))
                .collect(),
            version: self.version,
        })
    }

    /// The cache's encrypted items, offline changes included (see
    /// `outbox`), and the number of those the SDK cannot read.
    fn overlay(&self, models: Option<Vec<CipherDetailsResponseModel>>) -> (Vec<Cipher>, usize) {
        let mut failures = 0;
        let mut ciphers: Vec<Cipher> = models
            .unwrap_or_default()
            .into_iter()
            .filter_map(|model| Cipher::try_from(model).inspect_err(|_| failures += 1).ok())
            .collect();
        self.outbox.apply(&mut ciphers);
        (ciphers, failures)
    }

    /// The encrypted items of the displayed vault: cache and queue overlaid.
    pub(crate) fn cached_ciphers(&self) -> Result<Vec<Cipher>, Error> {
        let models = match &self.account.sync {
            Some(json) => {
                serde_json::from_str::<SyncResponseModel>(json)
                    .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?
                    .ciphers
            }
            None => None,
        };
        Ok(self.overlay(models).0)
    }

    /// The encrypted item, as the displayed vault knows it.
    pub(crate) fn cached_cipher(&self, id: &str) -> Result<Cipher, Error> {
        self.cached_ciphers()?
            .into_iter()
            .find(|c| c.id.is_some_and(|c| c.to_string() == id))
            .ok_or(Error::NotFound)
    }

    /// Folders of the sync: id → name.
    fn decrypt_folders(
        &self,
        folders: Option<Vec<bitwarden_api_api::models::FolderResponseModel>>,
    ) -> Result<HashMap<String, String>, Error> {
        let folders: Vec<Folder> = folders
            .unwrap_or_default()
            .into_iter()
            .filter_map(|f| Folder::try_from(f).ok())
            .collect();
        // The SDK's "high-level" methods go through its state storage,
        // which Verrou doesn't use (it keeps its own cache).
        #[allow(deprecated)]
        let names = self
            .sdk
            .vault()
            .folders()
            .decrypt_list(folders)
            .map_err(Error::crypto)?
            .into_iter()
            .filter_map(|f| Some((f.id?.to_string(), f.name)))
            .collect();
        Ok(names)
    }

    /// Folders of the cache, without decrypting the items.
    pub(crate) fn cached_folders(&self) -> Result<HashMap<String, String>, Error> {
        let Some(json) = &self.account.sync else {
            return Ok(HashMap::new());
        };
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?;
        self.decrypt_folders(sync.folders)
    }

    async fn init_organizations(&self, sync: &SyncResponseModel) -> Result<(), Error> {
        let organizations = sync
            .profile
            .as_ref()
            .and_then(|p| p.organizations.as_ref())
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut keys = HashMap::new();
        for org in organizations {
            let (Some(id), Some(key)) = (org.id, &org.key) else {
                continue;
            };
            let (Ok(id), Ok(key)) = (id.to_string().parse(), key.parse::<UnsignedSharedKey>())
            else {
                continue;
            };
            keys.insert(id, key);
        }
        if keys.is_empty() {
            return Ok(());
        }
        self.sdk
            .crypto()
            .initialize_org_crypto(InitOrgCryptoRequest {
                organization_keys: keys,
            })
            .await
            .map_err(Error::crypto)
    }
}

pub(crate) fn sdk_client(server: &str) -> Client {
    // The SDK makes no request for Verrou: these addresses only fill in
    // its configuration.
    Client::new(Some(ClientSettings {
        identity_url: format!("{server}/identity"),
        api_url: format!("{server}/api"),
        user_agent: concat!("Verrou/", env!("CARGO_PKG_VERSION")).to_owned(),
        device_type: DeviceType::MacOsDesktop,
        device_identifier: None,
        bitwarden_client_version: None,
        bitwarden_package_type: None,
    }))
}

async fn init_with_password(
    sdk: &Client,
    account: &Account,
    password: &SecretString,
) -> Result<(), Error> {
    let unlock = MasterPasswordUnlockData {
        kdf: Kdf::try_from(&account.kdf)?,
        master_key_wrapped_user_key: account.wrapped_user_key.parse().map_err(Error::crypto)?,
        salt: account.salt.clone(),
        contained_key_id: None,
    };
    init(
        sdk,
        account,
        InitUserCryptoMethod::MasterPasswordUnlock {
            password: password.expose().to_owned(),
            master_password_unlock: unlock,
        },
    )
    .await
    // The user key only decrypts with the right password: any failure here
    // means "wrong password".
    .map_err(|_| Error::WrongPassword)
}

/// Key received from another device (`device_login`), encrypted for the
/// request's RSA private key: the SDK decrypts it, like the official app.
async fn init_with_approval(
    sdk: &Client,
    account: &Account,
    approval: &device_login::Approval,
) -> Result<(), Error> {
    let protected: UnsignedSharedKey = approval.key.parse().map_err(Error::crypto)?;
    let method = if approval.master_key {
        AuthRequestMethod::MasterKey {
            protected_master_key: protected,
            auth_request_key: account.wrapped_user_key.parse().map_err(Error::crypto)?,
        }
    } else {
        AuthRequestMethod::UserKey {
            protected_user_key: protected,
        }
    };
    init(
        sdk,
        account,
        InitUserCryptoMethod::AuthRequest {
            request_private_key: approval
                .private_key
                .expose()
                .parse()
                .map_err(Error::crypto)?,
            method,
        },
    )
    .await
    .map_err(|_| Error::Crypto("the key received from the other device does not open".to_owned()))
}

async fn init(sdk: &Client, account: &Account, method: InitUserCryptoMethod) -> Result<(), Error> {
    sdk.crypto()
        .initialize_user_crypto(InitUserCryptoRequest {
            user_id: Some(account.user_id.parse().map_err(Error::crypto)?),
            kdf_params: Kdf::try_from(&account.kdf)?,
            email: account.email.clone(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: account.private_key.parse().map_err(Error::crypto)?,
            },
            method,
            upgrade_token: None,
        })
        .await
        .map_err(Error::crypto)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl From<&Kdf> for KdfSettings {
    fn from(kdf: &Kdf) -> Self {
        match kdf {
            Kdf::PBKDF2 { iterations } => Self::Pbkdf2 {
                iterations: iterations.get(),
            },
            Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => Self::Argon2id {
                iterations: iterations.get(),
                memory: memory.get(),
                parallelism: parallelism.get(),
            },
        }
    }
}

impl TryFrom<&KdfSettings> for Kdf {
    type Error = Error;

    fn try_from(settings: &KdfSettings) -> Result<Self, Error> {
        let nonzero = |n: u32| {
            NonZeroU32::new(n).ok_or_else(|| Error::Storage("invalid key derivation".into()))
        };
        Ok(match *settings {
            KdfSettings::Pbkdf2 { iterations } => Self::PBKDF2 {
                iterations: nonzero(iterations)?,
            },
            KdfSettings::Argon2id {
                iterations,
                memory,
                parallelism,
            } => Self::Argon2id {
                iterations: nonzero(iterations)?,
                memory: nonzero(memory)?,
                parallelism: nonzero(parallelism)?,
            },
        })
    }
}
