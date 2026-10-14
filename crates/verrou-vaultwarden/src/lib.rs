//! Connexion de Verrou à un serveur Vaultwarden.
//!
//! Répartition des rôles :
//! - le **SDK Rust de Bitwarden** fait toute la cryptographie : dérivation du
//!   mot de passe principal, déchiffrement de la clé de l'utilisateur, des
//!   dossiers et des éléments ;
//! - ce crate fait le reste : HTTP (`api`), cache local (`store`) et
//!   conversion vers le modèle de Verrou (`convert`).
//!
//! Écriture (`edit`) : création, modification et corbeille, chiffrées par le
//! SDK avant d'être envoyées ; en masse (`import`) : import d'un export
//! d'un autre gestionnaire, corbeille de plusieurs éléments.
//!
//! Déverrouillage par clé de sécurité (`unlock_keys`) : la clé de
//! l'utilisateur scellée par le secret `hmac-secret` d'une `YubiKey`.

mod api;
pub mod breach;
mod convert;
mod edit;
mod error;
mod import;
mod passkeys;
pub mod security_key;
pub mod ssh_key;
mod store;
pub mod two_factor_directory;
pub mod unlock_keys;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{
    InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::{Kdf, UnsignedSharedKey};
use bitwarden_vault::{Cipher, Folder, VaultClientExt};
use verrou_core::{Item, SecretString};

pub use api::{TwoFactorAnswer, TwoFactorMethod};
pub use edit::{Draft, LoginDraft};
pub use error::Error;
pub use import::{Destination, ImportPlan, ImportReport};
pub use store::{Account, KdfSettings, Store};

use api::{Api, PasswordGrant, Prelogin, TokenOutcome, Tokens};

/// Le coffre déchiffré, prêt à indexer.
pub struct Decrypted {
    pub items: Vec<Item>,
    /// Éléments que le SDK n'a pas su déchiffrer (clé d'organisation absente,
    /// format inconnu). Ils sont ignorés, mais l'interface le signale.
    pub failures: usize,
    /// Dossiers (identifiant, nom), triés par nom : pour ranger un élément.
    pub folders: Vec<(String, String)>,
    /// Passkeys des identifiants (clé privée comprise) : pour
    /// `Vault::with_passkeys`.
    pub passkeys: Vec<verrou_core::Passkey>,
}

/// Un coffre ouvert : le SDK porte la clé de l'utilisateur en mémoire.
/// Le libérer (verrouiller) efface cette clé.
pub struct Connection {
    api: Api,
    sdk: Client,
    store: Store,
    account: Account,
}

pub struct Unlocked {
    pub connection: Connection,
    pub vault: Decrypted,
}

pub enum LoginStep {
    Unlocked(Box<Unlocked>),
    /// Le serveur demande un second facteur. Répondre avec
    /// [`PendingLogin::answer`] ; on peut réessayer après un refus.
    TwoFactor(Box<PendingLogin>),
}

/// Connexion en attente du second facteur. Garde le mot de passe principal
/// (dans un `SecretString`) le temps de l'échange : il faut encore déchiffrer
/// la clé de l'utilisateur une fois le jeton obtenu.
#[derive(Clone)]
pub struct PendingLogin {
    api: Api,
    store: Store,
    email: String,
    password: SecretString,
    prelogin: Prelogin,
    auth_hash: String,
    device_id: String,
    methods: Vec<TwoFactorMethod>,
}

/// Première connexion (ou reconnexion après expiration de la session).
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
        password,
        prelogin,
        auth_hash: auth.master_password_authentication_hash.to_string(),
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

    /// Redemande les méthodes de second facteur. Le serveur ne laisse qu'une
    /// tentative par défi de clé de sécurité : après un refus, il en faut un
    /// nouveau.
    pub async fn restart(&self) -> Result<LoginStep, Error> {
        self.request(None).await
    }

    /// Envoie le code par e-mail (méthode `Email`).
    pub async fn send_email_code(&self) -> Result<(), Error> {
        self.api
            .send_email_code(&self.email, &self.auth_hash, &self.device_id)
            .await
    }

    /// Envoie la réponse au second facteur. En cas de refus
    /// (`Error::TwoFactorRejected`), la connexion reste en attente.
    pub async fn answer(&self, answer: &TwoFactorAnswer) -> Result<Unlocked, Error> {
        match self.request(Some(answer)).await? {
            LoginStep::Unlocked(unlocked) => Ok(*unlocked),
            LoginStep::TwoFactor(_) => Err(Error::TwoFactorRejected(
                "le serveur redemande un second facteur".to_owned(),
            )),
        }
    }

    async fn request(&self, answer: Option<&TwoFactorAnswer>) -> Result<LoginStep, Error> {
        let grant = PasswordGrant {
            email: &self.email,
            auth_hash: &self.auth_hash,
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
                        "second facteur demandé, mais aucune méthode prise en charge \
                         (clé de sécurité, application TOTP, YubiKey OTP ou e-mail)"
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

    /// Jetons obtenus : synchroniser, ouvrir le coffre avec le mot de passe,
    /// puis enregistrer le compte.
    async fn complete(&self, tokens: Tokens) -> Result<Unlocked, Error> {
        let sync_json = self.api.sync(&tokens.access).await?;
        let sync: serde_json::Value = serde_json::from_str(&sync_json)
            .map_err(|e| Error::Server(format!("synchronisation illisible ({e})")))?;
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
                .ok_or_else(|| Error::Server("profil sans identifiant".to_owned()))?,
            kdf: KdfSettings::from(&unlock.kdf),
            salt: unlock.salt,
            wrapped_user_key: tokens
                .wrapped_user_key
                .or_else(|| profile_text("key"))
                .ok_or_else(|| Error::Server("clé de l'utilisateur absente".to_owned()))?,
            private_key: tokens
                .private_key
                .or_else(|| profile_text("privateKey"))
                .ok_or_else(|| Error::Server("clé privée absente".to_owned()))?,
            refresh_token: String::new(),
            synced_at: Some(now()),
            sync: Some(sync_json),
        };
        let sdk = sdk_client(&account.server);
        init_with_password(&sdk, &account, &self.password).await?;
        account.refresh_token = sdk
            .crypto()
            .encrypt_with_local_user_data_key(tokens.refresh)
            .map_err(Error::crypto)?;
        self.store.save_account(&account)?;
        let connection = Connection {
            api: self.api.clone(),
            sdk,
            store: self.store.clone(),
            account,
        };
        let vault = connection.decrypt_cache().await?;
        Ok(Unlocked { connection, vault })
    }
}

/// Déverrouillage hors ligne par le mot de passe principal, sur le cache.
pub async fn unlock_with_password(
    store: &Store,
    password: &SecretString,
) -> Result<Unlocked, Error> {
    let account = store.load_account()?.ok_or(Error::NoAccount)?;
    let sdk = sdk_client(&account.server);
    init_with_password(&sdk, &account, password).await?;
    open(store, account, sdk).await
}

/// Déverrouillage par la clé de l'utilisateur, rendue par Touch ID.
pub async fn unlock_with_user_key(
    store: &Store,
    user_key: &SecretString,
) -> Result<Unlocked, Error> {
    let account = store.load_account()?.ok_or(Error::NoAccount)?;
    let sdk = sdk_client(&account.server);
    init_with_user_key(&sdk, &account, user_key)
        .await
        // Une clé refusée vient d'un enrôlement Touch ID périmé (mot de passe
        // changé, reconnexion) : il faut repasser par le mot de passe.
        .map_err(|_| Error::Crypto("clé Touch ID périmée".to_owned()))?;
    open(store, account, sdk).await
}

/// Déverrouillage par une clé de sécurité enrôlée : `secret` est ce que la
/// clé a rendu (`hmac-secret`), `credential_id` l'accréditation qui a
/// répondu, si elle l'a dit. La clé de l'utilisateur ne quitte pas Rust.
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
        // Descellée mais refusée : la clé du coffre a changé depuis
        // l'enrôlement. Les clés enrôlées ne valent plus rien.
        store.delete_security_keys()?;
        return Err(Error::Crypto(
            "clé de sécurité périmée, à enregistrer de nouveau".to_owned(),
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
    // Le SDK accepte n'importe quelle clé bien formée (le coffre se
    // déchiffre alors en zéro élément) : on la vérifie sur le jeton de
    // renouvellement, chiffré avec elle.
    sdk.crypto()
        .decrypt_with_local_user_data_key(account.refresh_token.clone())
        .map(drop)
        .map_err(Error::crypto)
}

/// Oublie le compte : jetons, cache, clés chiffrées et clés de sécurité
/// enrôlées.
pub fn logout(store: &Store) -> Result<(), Error> {
    store.delete_security_keys()?;
    store.delete_account()
}

async fn open(store: &Store, account: Account, sdk: Client) -> Result<Unlocked, Error> {
    let connection = Connection {
        api: Api::new(&account.server)?,
        sdk,
        store: store.clone(),
        account,
    };
    let vault = connection.decrypt_cache().await?;
    Ok(Unlocked { connection, vault })
}

impl Connection {
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Renouvelle le jeton d'accès, télécharge le coffre, l'enregistre comme
    /// cache et le déchiffre. `None` : rien n'a changé sur le serveur depuis
    /// le cache, le coffre déjà déchiffré reste valable (le cas courant : pas
    /// de déchiffrement ni de rechargement de l'affichage pour rien).
    pub async fn sync(&mut self) -> Result<Option<Decrypted>, Error> {
        let access = self.access_token().await?;
        let sync_json = self.api.sync(&access).await?;
        let unchanged = self.account.sync.as_deref() == Some(sync_json.as_str());
        self.account.sync = Some(sync_json);
        self.account.synced_at = Some(now());
        self.store.save_account(&self.account)?;
        if unchanged {
            return Ok(None);
        }
        self.decrypt_cache().await.map(Some)
    }

    /// Jeton d'accès neuf, obtenu par le jeton de renouvellement (enregistré
    /// aussitôt si le serveur en donne un nouveau).
    async fn access_token(&mut self) -> Result<String, Error> {
        let refresh = self
            .sdk
            .crypto()
            .decrypt_with_local_user_data_key(self.account.refresh_token.clone())
            .map_err(Error::crypto)?;
        let tokens = self.api.refresh(&refresh).await?;
        if tokens.refresh != refresh {
            self.account.refresh_token = self
                .sdk
                .crypto()
                .encrypt_with_local_user_data_key(tokens.refresh)
                .map_err(Error::crypto)?;
            self.store.save_account(&self.account)?;
        }
        Ok(tokens.access)
    }

    async fn sync_with(&mut self, access: &str) -> Result<Decrypted, Error> {
        let sync_json = self.api.sync(access).await?;
        self.account.sync = Some(sync_json);
        self.account.synced_at = Some(now());
        self.store.save_account(&self.account)?;
        self.decrypt_cache().await
    }

    /// Clé de l'utilisateur (base64), pour l'enrôlement Touch ID. Elle ne doit
    /// être confiée qu'au Secure Enclave, jamais écrite en clair.
    pub async fn user_key(&self) -> Result<SecretString, Error> {
        self.sdk
            .crypto()
            .get_user_encryption_key()
            .await
            .map(|key| SecretString::new(key.to_string()))
            .map_err(Error::crypto)
    }

    /// Enrôle une clé de sécurité : scelle la clé de l'utilisateur avec ce que
    /// la clé a rendu pour `salt`, et l'ajoute à `security-keys.json`. La clé
    /// de l'utilisateur ne quitte pas Rust.
    pub async fn enroll_security_key(
        &self,
        label: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        secret: &unlock_keys::HmacSecret,
    ) -> Result<unlock_keys::EnrolledKey, Error> {
        let user_key = self.user_key().await?;
        let key = unlock_keys::seal(&user_key, secret, credential_id, salt, label, now())?;
        // Vérifie le scellement avant de l'écrire.
        key.open(secret)?;
        unlock_keys::add(&self.store, key.clone())?;
        Ok(key)
    }

    async fn decrypt_cache(&self) -> Result<Decrypted, Error> {
        let Some(json) = &self.account.sync else {
            return Ok(Decrypted {
                items: Vec::new(),
                failures: 0,
                folders: Vec::new(),
                passkeys: Vec::new(),
            });
        };
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        self.init_organizations(&sync).await?;
        let folder_names = self.decrypt_folders(sync.folders)?;

        let mut items = Vec::new();
        let mut passkeys = Vec::new();
        let mut failures = 0;
        for model in sync.ciphers.unwrap_or_default() {
            let Ok(cipher) = Cipher::try_from(model) else {
                failures += 1;
                continue;
            };
            match self.sdk.vault().ciphers().decrypt(cipher).await {
                Ok(view) => {
                    passkeys.extend(convert::passkeys(&view));
                    items.extend(convert::item(&view, &folder_names));
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
        })
    }

    /// Dossiers de la synchronisation : identifiant → nom.
    fn decrypt_folders(
        &self,
        folders: Option<Vec<bitwarden_api_api::models::FolderResponseModel>>,
    ) -> Result<HashMap<String, String>, Error> {
        let folders: Vec<Folder> = folders
            .unwrap_or_default()
            .into_iter()
            .filter_map(|f| Folder::try_from(f).ok())
            .collect();
        // Les méthodes « de haut niveau » du SDK passent par son stockage
        // d'état, que Verrou n'utilise pas (il garde son propre cache).
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

    /// Dossiers du cache, sans déchiffrer les éléments.
    pub(crate) fn cached_folders(&self) -> Result<HashMap<String, String>, Error> {
        let Some(json) = &self.account.sync else {
            return Ok(HashMap::new());
        };
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
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

fn sdk_client(server: &str) -> Client {
    // Le SDK ne fait aucune requête pour Verrou : ces adresses ne servent
    // qu'à remplir sa configuration.
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
    // La clé de l'utilisateur ne se déchiffre qu'avec le bon mot de passe :
    // tout échec ici veut dire « mauvais mot de passe ».
    .map_err(|_| Error::WrongPassword)
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
        let nonzero =
            |n: u32| NonZeroU32::new(n).ok_or_else(|| Error::Storage("dérivation invalide".into()));
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
