//! Tests contre un vrai Vaultwarden, jetable :
//!
//! ```sh
//! docker run -d --rm --name verrou-vw -p 127.0.0.1:8099:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=true \
//!   -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
//!   -e DOMAIN=http://localhost:8099 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   vaultwarden/server:1.37.4
//! VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden --test server
//! ```
//!
//! Sans `VERROU_TEST_SERVER`, les tests ne font rien (et le disent).
//! Chaque test crée son propre compte : ils peuvent tourner en parallèle.

use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{InitUserCryptoMethod, InitUserCryptoRequest};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::Kdf;
use bitwarden_vault::{CipherView, FolderView, VaultClientExt};
use serde_json::{Value, json};
use verrou_core::ItemState;
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, ItemKind, SecretString};
use verrou_vaultwarden::security_key::{
    self, AssertionRequest, AssertionResponse, assertion_request,
};
use verrou_vaultwarden::unlock_keys::{self, HmacSecret};
use verrou_vaultwarden::{
    CustomFieldDraft, CustomFieldKind, Draft, Error, LoginDraft, LoginStep, Store, TwoFactorAnswer,
    TwoFactorMethod, Unlocked, login, logout, unlock_with_password, unlock_with_security_key,
    unlock_with_user_key,
};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
    }
    server
}

fn kdf() -> Kdf {
    Kdf::PBKDF2 {
        iterations: NonZeroU32::new(ITERATIONS).unwrap(),
    }
}

fn unique_email() -> String {
    format!("{}@verrou.test", uuid::Uuid::new_v4().simple())
}

fn temp_store() -> Store {
    Store::new(std::env::temp_dir().join(format!("verrou-it-{}", uuid::Uuid::new_v4())))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn auth_hash(email: &str) -> String {
    MasterPasswordAuthenticationData::derive(PASSWORD, &kdf(), email)
        .unwrap()
        .master_password_authentication_hash
        .to_string()
}

/// Compte de test, connecté par un client SDK distinct de celui de Verrou :
/// c'est lui qui remplit le coffre, comme le ferait l'app officielle.
struct Seeder {
    http: reqwest::Client,
    server: String,
    access: String,
    sdk: Client,
}

impl Seeder {
    async fn register(server: &str, email: &str) -> Self {
        let http = reqwest::Client::new();
        let keys = Client::new(None)
            .auth()
            .make_register_keys(email.into(), PASSWORD.into(), kdf())
            .unwrap();
        let token = http
            .post(format!(
                "{server}/identity/accounts/register/send-verification-email"
            ))
            .json(&json!({ "email": email, "name": "Camille" }))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let response = http
            .post(format!("{server}/identity/accounts/register/finish"))
            .json(&json!({
                "email": email,
                "emailVerificationToken": token,
                "masterPasswordHash": keys.master_password_hash.to_string(),
                "userSymmetricKey": keys.encrypted_user_key.to_string(),
                "kdf": 0,
                "kdfIterations": ITERATIONS,
                "userAsymmetricKeys": {
                    "publicKey": keys.keys.public.to_string(),
                    "encryptedPrivateKey": keys.keys.private.to_string(),
                },
            }))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "inscription refusée");
        Self::connect(http, server, email).await
    }

    async fn connect(http: reqwest::Client, server: &str, email: &str) -> Self {
        let token: Value = http
            .post(format!("{server}/identity/connect/token"))
            .form(&[
                ("grant_type", "password"),
                ("username", email),
                ("password", &auth_hash(email)),
                ("scope", "api offline_access"),
                ("client_id", "web"),
                ("deviceType", "9"),
                ("deviceIdentifier", &uuid::Uuid::new_v4().to_string()),
                ("deviceName", "seeder"),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let sdk = Client::new(Some(ClientSettings {
            identity_url: format!("{server}/identity"),
            api_url: format!("{server}/api"),
            user_agent: "verrou-tests".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));
        let access = token["access_token"].as_str().unwrap().to_owned();
        let profile: Value = http
            .get(format!("{server}/api/accounts/profile"))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        sdk.crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: Some(profile["id"].as_str().unwrap().parse().unwrap()),
                kdf_params: kdf(),
                email: email.into(),
                account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                    private_key: token["PrivateKey"].as_str().unwrap().parse().unwrap(),
                },
                method: InitUserCryptoMethod::MasterPasswordUnlock {
                    password: PASSWORD.into(),
                    master_password_unlock: MasterPasswordUnlockData {
                        kdf: kdf(),
                        master_key_wrapped_user_key: token["Key"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                        salt: email.into(),
                        contained_key_id: None,
                    },
                },
                upgrade_token: None,
            })
            .await
            .unwrap();
        Self {
            http,
            server: server.to_owned(),
            access,
            sdk,
        }
    }

    #[allow(deprecated)]
    async fn folder(&self, name: &str) -> String {
        let view: FolderView = serde_json::from_value(json!({
            "id": null, "name": name, "revisionDate": "2024-01-01T00:00:00Z",
        }))
        .unwrap();
        let folder = self.sdk.vault().folders().encrypt(view).unwrap();
        let created: Value = self
            .http
            .post(format!("{}/api/folders", self.server))
            .bearer_auth(&self.access)
            .json(&json!({ "name": folder.name.to_string() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        created["id"].as_str().unwrap().to_owned()
    }

    async fn cipher(&self, view: Value) -> String {
        let mut base = json!({
            "id": null, "organizationId": null, "folderId": null, "collectionIds": [],
            "key": null, "notes": null, "login": null, "identity": null, "card": null,
            "secureNote": null, "sshKey": null, "favorite": false, "reprompt": 0,
            "organizationUseTotp": false, "edit": true, "permissions": null,
            "viewPassword": true, "localData": null, "attachments": null, "fields": null,
            "passwordHistory": null, "creationDate": "2024-01-01T00:00:00Z",
            "deletedDate": null, "revisionDate": "2024-01-01T00:00:00Z", "archivedDate": null,
        });
        for (k, v) in view.as_object().unwrap() {
            base[k] = v.clone();
        }
        let view: CipherView = serde_json::from_value(base).unwrap();
        let encrypted = self.sdk.vault().ciphers().encrypt(view).await.unwrap();
        let request: bitwarden_api_api::models::CipherRequestModel = encrypted.into();
        let created: Value = self
            .http
            .post(format!("{}/api/ciphers", self.server))
            .bearer_auth(&self.access)
            .json(&request)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        created["id"].as_str().unwrap().to_owned()
    }

    async fn trash(&self, id: &str) {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{id}/delete", self.server))
            .bearer_auth(&self.access)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    /// Active le second facteur TOTP et renvoie sa graine.
    async fn enable_totp(&self, email: &str) -> String {
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let code = Totp::parse(secret).unwrap().generate(now()).code;
        let response = self
            .http
            .put(format!("{}/api/two-factor/authenticator", self.server))
            .bearer_auth(&self.access)
            .json(&json!({ "key": secret, "token": code, "masterPasswordHash": auth_hash(email) }))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "activation TOTP refusée");
        secret.to_owned()
    }

    async fn fill(&self) {
        let travail = self.folder("Travail").await;
        self.cipher(json!({
            "name": "GitHub", "type": 1, "favorite": true, "folderId": travail,
            "notes": "codes de secours dans le coffre",
            "login": {
                "username": "camille", "password": "hunter2-hunter2",
                "passwordRevisionDate": null, "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{ "uri": "https://github.com", "match": null, "uriChecksum": null }],
                "autofillOnPageLoad": null, "fido2Credentials": null,
            },
            "fields": [
                { "name": "PIN", "value": "1234", "type": 1, "linkedId": null },
                { "name": "2FA", "value": "true", "type": 2, "linkedId": null },
            ],
        }))
        .await;
        self.cipher(json!({
            "name": "Visa", "type": 3,
            "card": {
                "cardholderName": "CAMILLE MARTIN", "expMonth": "9", "expYear": "2029",
                "code": "123", "brand": "Visa", "number": "4242424242424242",
            },
        }))
        .await;
        self.cipher(json!({
            "name": "Moi", "type": 4,
            "identity": {
                "title": null, "firstName": "Camille", "middleName": null, "lastName": "Martin",
                "address1": "12 rue des Lilas", "address2": null, "address3": null,
                "city": "Annecy", "state": null, "postalCode": "74000", "country": "France",
                "company": null, "email": "camille@exemple.fr", "phone": null, "ssn": null,
                "username": null, "passportNumber": null, "licenseNumber": null,
            },
        }))
        .await;
        self.cipher(json!({
            "name": "Wi-Fi", "type": 2, "notes": "mot de passe : appelez Camille",
            "secureNote": { "type": 0 },
        }))
        .await;
        let old = self
            .cipher(json!({
                "name": "Ancien compte", "type": 1,
                "login": {
                    "username": "old", "password": "x", "passwordRevisionDate": null,
                    "totp": null, "uris": null, "autofillOnPageLoad": null,
                    "fido2Credentials": null,
                },
            }))
            .await;
        self.trash(&old).await;
    }
}

/// Envoie la file, comme l'app juste après une écriture (sans attendre en
/// arrière-plan) : rien n'est refusé. Rend l'identifiant de `id` sur le
/// serveur (une création porte d'abord un identifiant provisoire).
async fn sent(connection: &mut verrou_vaultwarden::Connection, id: &str) -> String {
    connection.sync().await.unwrap();
    let report = connection.take_report();
    assert!(
        report.rejected.is_empty() && report.conflicts.is_empty(),
        "{report:?}"
    );
    assert_eq!(connection.pending_changes(), 0);
    connection.resolve(id)
}

fn unlocked(step: LoginStep) -> verrou_vaultwarden::Unlocked {
    match step {
        LoginStep::Unlocked(unlocked) => *unlocked,
        LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
    }
}

#[tokio::test]
async fn login_decrypts_the_vault_and_unlocks_offline() {
    let Some(server) = server() else { return };
    let email = unique_email();
    Seeder::register(&server, &email).await.fill().await;
    let store = temp_store();

    let first = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    assert_eq!(first.vault.failures, 0);
    let items = &first.vault.items;
    assert_eq!(
        items.iter().filter(|i| i.is_active()).count(),
        4,
        "l'élément à la corbeille est à part"
    );

    let github = items.iter().find(|i| i.title == "GitHub").unwrap();
    assert_eq!(github.kind, ItemKind::Login);
    assert_eq!(github.subtitle, "camille");
    assert_eq!(github.folder.as_deref(), Some("Travail"));
    assert!(github.favorite);
    assert_eq!(github.urls, ["https://github.com"]);
    assert_eq!(
        github.field("password").unwrap().value.expose(),
        "hunter2-hunter2"
    );
    assert!(github.has_totp());
    assert_eq!(
        github.notes.as_ref().unwrap().expose(),
        "codes de secours dans le coffre"
    );
    let pin = github.fields.iter().find(|f| f.label == "PIN").unwrap();
    assert_eq!(pin.kind, FieldKind::Concealed);
    assert_eq!(pin.value.expose(), "1234");

    let card = items.iter().find(|i| i.kind == ItemKind::Card).unwrap();
    assert_eq!(card.subtitle, "Visa •••• 4242");
    assert_eq!(
        card.field("number").unwrap().value.expose(),
        "4242 4242 4242 4242"
    );
    assert_eq!(card.field("expiry").unwrap().value.expose(), "09/29");

    let me = items.iter().find(|i| i.kind == ItemKind::Identity).unwrap();
    assert_eq!(
        me.field("address").unwrap().value.expose(),
        "12 rue des Lilas\n74000 Annecy\nFrance"
    );

    // Le fichier du compte ne contient aucun secret en clair.
    let file = std::fs::read_to_string(store.dir().join("account.json")).unwrap();
    for secret in ["hunter2", "camille", "4242", PASSWORD] {
        assert!(
            !file.contains(secret),
            "« {secret} » en clair sur le disque"
        );
    }

    let user_key = first.connection.user_key().await.unwrap();
    drop(first);

    // Hors ligne : mauvais puis bon mot de passe.
    assert!(matches!(
        unlock_with_password(&store, &SecretString::new("pas le bon")).await,
        Err(Error::WrongPassword)
    ));
    let mut again = unlock_with_password(&store, &SecretString::new(PASSWORD))
        .await
        .unwrap();
    assert_eq!(
        again.vault.items.iter().filter(|i| i.is_active()).count(),
        4
    );

    // Synchronisation par le jeton de renouvellement : rien n'a changé
    // depuis le cache, rien à déchiffrer de nouveau.
    assert!(again.connection.sync().await.unwrap().is_none());
    drop(again);

    // Chemin de Touch ID : la clé de l'utilisateur suffit.
    let by_key = unlock_with_user_key(&store, &user_key).await.unwrap();
    assert_eq!(
        by_key.vault.items.iter().filter(|i| i.is_active()).count(),
        4
    );
    assert!(matches!(
        unlock_with_user_key(&store, &SecretString::new("AAAA")).await,
        Err(Error::Crypto(_))
    ));

    security_key_unlock(&store, by_key, &user_key).await;

    logout(&store).unwrap();
    assert_eq!(store.load_security_keys().unwrap(), []);
    assert!(matches!(
        unlock_with_password(&store, &SecretString::new(PASSWORD)).await,
        Err(Error::NoAccount)
    ));
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Chemin de la clé de sécurité, avec de fausses réponses `hmac-secret` :
/// une clé principale et une de secours. Laisse une clé enrôlée, que la
/// déconnexion doit effacer.
async fn security_key_unlock(store: &Store, by_key: Unlocked, user_key: &SecretString) {
    let store = store.clone();
    let main = HmacSecret::from_bytes([1; 32]);
    let backup = HmacSecret::from_bytes([2; 32]);
    let main_salt = unlock_keys::new_salt();
    let backup_salt = unlock_keys::new_salt();
    by_key
        .connection
        .enroll_security_key("Principale", &[1, 1], &main_salt, &main)
        .await
        .unwrap();
    by_key
        .connection
        .enroll_security_key("Secours", &[2, 2], &backup_salt, &backup)
        .await
        .unwrap();
    drop(by_key);
    let keys = store.load_security_keys().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        unlock_keys::credentials(&keys).unwrap()[1],
        unlock_keys::UnlockCredential {
            credential_id: vec![2, 2],
            salt: backup_salt,
        }
    );
    let by_backup = unlock_with_security_key(&store, Some(&[2, 2]), &backup)
        .await
        .unwrap();
    assert_eq!(
        by_backup
            .vault
            .items
            .iter()
            .filter(|i| i.is_active())
            .count(),
        4
    );
    drop(by_backup);
    let by_main = unlock_with_security_key(&store, None, &main).await.unwrap();
    drop(by_main);
    assert!(matches!(
        unlock_with_security_key(&store, None, &HmacSecret::from_bytes([3; 32])).await,
        Err(Error::SecurityKey(_))
    ));
    let file = std::fs::read_to_string(store.dir().join("security-keys.json")).unwrap();
    assert!(!file.contains(user_key.expose()));

    // Copie scellée d'une autre clé de coffre (la clé a changé depuis
    // l'enrôlement) : périmée, toutes les clés enrôlées sont retirées.
    let other_key = SecretString::new(data_encoding::BASE64.encode(&[7; 64]));
    let stale = unlock_keys::seal(&other_key, &main, &[1, 1], &main_salt, "Principale", 0).unwrap();
    unlock_keys::add(&store, stale).unwrap();
    assert!(matches!(
        unlock_with_security_key(&store, Some(&[1, 1]), &main).await,
        Err(Error::Crypto(_))
    ));
    // Le SDK accepterait cette clé bien formée (et un coffre vide) : Verrou
    // la vérifie, pour Touch ID aussi.
    assert!(matches!(
        unlock_with_user_key(&store, &other_key).await,
        Err(Error::Crypto(_))
    ));
    assert_eq!(store.load_security_keys().unwrap(), []);

    // Pour la déconnexion, qui doit l'oublier.
    let again = unlock_keys::seal(user_key, &main, &[1, 1], &main_salt, "Principale", 0).unwrap();
    unlock_keys::add(&store, again).unwrap();
}

#[tokio::test]
async fn wrong_password_is_reported_at_login() {
    let Some(server) = server() else { return };
    let email = unique_email();
    Seeder::register(&server, &email).await;
    let result = login(&temp_store(), &server, &email, SecretString::new("faux")).await;
    assert!(matches!(result, Err(Error::WrongPassword)));
}

#[tokio::test]
async fn totp_second_factor() {
    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    let secret = seeder.enable_totp(&email).await;
    let store = temp_store();

    let LoginStep::TwoFactor(pending) = login(&store, &server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    else {
        panic!("le second facteur aurait dû être demandé");
    };
    assert_eq!(pending.methods(), [TwoFactorMethod::Authenticator]);

    let wrong = TwoFactorAnswer {
        provider: TwoFactorMethod::Authenticator.provider(),
        token: "000000".into(),
    };
    assert!(matches!(
        pending.answer(&wrong).await,
        Err(Error::TwoFactorRejected(_))
    ));

    // Le code de l'activation est déjà consommé (le serveur refuse qu'on le
    // rejoue) : on prend celui de la période suivante, toléré par le serveur.
    let code = Totp::parse(&secret).unwrap().generate(now() + 30).code;
    let right = TwoFactorAnswer {
        provider: TwoFactorMethod::Authenticator.provider(),
        token: code,
    };
    let unlocked = pending.answer(&right).await.unwrap();
    assert_eq!(unlocked.vault.items.len(), 0);
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Clé de sécurité logicielle : produit, pour la même requête, exactement ce
/// que produirait une `YubiKey` (attestation « none », signatures P-256).
struct SoftwareKey {
    signing: p256::ecdsa::SigningKey,
    credential_id: Vec<u8>,
    rp_id: String,
}

impl SoftwareKey {
    fn new(rp_id: &str) -> Self {
        use rand::RngCore as _;
        let mut credential_id = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut credential_id);
        Self {
            signing: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            credential_id,
            rp_id: rp_id.to_owned(),
        }
    }

    fn rp_hash(&self) -> Vec<u8> {
        use sha2::Digest as _;
        sha2::Sha256::digest(self.rp_id.as_bytes()).to_vec()
    }

    /// Données d'authentification d'un enregistrement, avec la clé publique COSE.
    fn attestation_object(&self) -> Vec<u8> {
        use ciborium::Value as C;
        let point = self.signing.verifying_key().to_encoded_point(false);
        let cose = C::Map(vec![
            (C::Integer(1.into()), C::Integer(2.into())),
            (C::Integer(3.into()), C::Integer((-7).into())),
            (C::Integer((-1).into()), C::Integer(1.into())),
            (
                C::Integer((-2).into()),
                C::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                C::Integer((-3).into()),
                C::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::into_writer(&cose, &mut cose_bytes).unwrap();
        let mut auth_data = self.rp_hash();
        auth_data.push(0x41); // présence + données attestées
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .unwrap()
                .to_be_bytes(),
        );
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&cose_bytes);
        let object = C::Map(vec![
            (C::Text("fmt".into()), C::Text("none".into())),
            (C::Text("attStmt".into()), C::Map(Vec::new())),
            (C::Text("authData".into()), C::Bytes(auth_data)),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&object, &mut bytes).unwrap();
        bytes
    }

    /// Ce que fait la `YubiKey` quand on la touche.
    fn sign(&self, request: &AssertionRequest) -> AssertionResponse {
        use p256::ecdsa::signature::Signer as _;
        assert_eq!(request.rp_id, self.rp_id);
        assert!(request.allow_credentials.contains(&self.credential_id));
        let mut auth_data = self.rp_hash();
        auth_data.push(0x01); // présence de l'utilisateur
        auth_data.extend_from_slice(&1u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&request.client_data_hash);
        let signature: p256::ecdsa::Signature = self.signing.sign(&signed);
        AssertionResponse {
            credential_id: self.credential_id.clone(),
            authenticator_data: auth_data,
            signature: signature.to_der().as_bytes().to_vec(),
            used_app_id: false,
        }
    }
}

impl Seeder {
    /// Enregistre la clé logicielle comme second facteur `WebAuthn`.
    async fn enable_security_key(&self, email: &str) -> SoftwareKey {
        let options: Value = self
            .http
            .post(format!(
                "{}/api/two-factor/get-webauthn-challenge",
                self.server
            ))
            .bearer_auth(&self.access)
            .json(&json!({ "masterPasswordHash": auth_hash(email) }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let rp_id = options["rp"]["id"].as_str().expect("rp.id").to_owned();
        let key = SoftwareKey::new(&rp_id);
        let origin = reqwest::Url::parse(&self.server)
            .unwrap()
            .origin()
            .ascii_serialization();
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap();
        let b64 = |bytes: &[u8]| data_encoding::BASE64URL_NOPAD.encode(bytes);
        let id = b64(&key.credential_id);
        let response = self
            .http
            .put(format!("{}/api/two-factor/webauthn", self.server))
            .bearer_auth(&self.access)
            .json(&json!({
                "id": 1,
                "name": "Clé logicielle",
                "masterPasswordHash": auth_hash(email),
                "deviceResponse": {
                    "id": id,
                    "rawId": id,
                    "type": "public-key",
                    "response": {
                        "attestationObject": b64(&key.attestation_object()),
                        "clientDataJson": b64(&client_data),
                    },
                },
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        assert!(
            status.is_success(),
            "enregistrement refusé : {}",
            response.text().await.unwrap()
        );
        key
    }
}

#[tokio::test]
async fn security_key_second_factor() {
    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    let key = seeder.enable_security_key(&email).await;
    let store = temp_store();

    let LoginStep::TwoFactor(pending) = login(&store, &server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    else {
        panic!("le second facteur aurait dû être demandé");
    };
    let Some(TwoFactorMethod::WebAuthn { challenge }) = pending.methods().first().cloned() else {
        panic!(
            "clé de sécurité absente des méthodes : {:?}",
            pending.methods()
        );
    };

    // La requête vient du code de Verrou ; seule la signature est logicielle.
    let request = assertion_request(pending.server(), &challenge).unwrap();
    let mut forged = key.sign(&request);
    forged.signature[10] ^= 0xff;
    let rejected = TwoFactorAnswer {
        provider: 7,
        token: security_key::token(&request, &forged),
    };
    assert!(
        matches!(
            pending.answer(&rejected).await,
            Err(Error::TwoFactorRejected(_))
        ),
        "une signature altérée doit être refusée"
    );

    // Le serveur a consommé le défi : on en redemande un.
    let LoginStep::TwoFactor(pending) = login(&store, &server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    else {
        panic!("le second facteur aurait dû être redemandé");
    };
    let Some(TwoFactorMethod::WebAuthn { challenge }) = pending.methods().first().cloned() else {
        panic!("clé de sécurité absente");
    };
    let request = assertion_request(pending.server(), &challenge).unwrap();
    let answer = TwoFactorAnswer {
        provider: 7,
        token: security_key::token(&request, &key.sign(&request)),
    };
    let unlocked = pending.answer(&answer).await.unwrap();
    assert_eq!(unlocked.vault.items.len(), 0);
    std::fs::remove_dir_all(store.dir()).unwrap();
}

impl Seeder {
    /// L'élément tel que le serveur le garde, déchiffré par un autre client.
    async fn fetch(&self, id: &str) -> CipherView {
        let model: bitwarden_api_api::models::CipherDetailsResponseModel = self
            .http
            .get(format!("{}/api/ciphers/{id}", self.server))
            .bearer_auth(&self.access)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let cipher = bitwarden_vault::Cipher::try_from(model).unwrap();
        self.sdk.vault().ciphers().decrypt(cipher).await.unwrap()
    }
}

/// Crée un identifiant rangé et favori, puis une note ; rend l'identifiant
/// de l'identifiant créé et le coffre.
async fn create_login_and_note(
    connection: &mut verrou_vaultwarden::Connection,
    travail: &str,
) -> (String, verrou_vaultwarden::Decrypted) {
    // Création d'un identifiant, rangé et favori.
    let (id, vault) = connection
        .create(Draft {
            name: "Doctolib".to_owned(),
            folder_id: Some(travail.to_owned()),
            favorite: true,
            notes: Some(SecretString::new("rdv annuel")),
            login: Some(LoginDraft {
                username: Some("camille@exemple.fr".to_owned()),
                password: Some(SecretString::new("premier-mot-de-passe")),
                totp: None,
                uris: vec!["https://www.doctolib.fr".to_owned()],
            }),
            ..Draft::default()
        })
        .await
        .unwrap();
    let created = vault.items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(created.folder.as_deref(), Some("Travail"));
    assert!(created.favorite);
    assert_eq!(
        created.field("password").unwrap().value.expose(),
        "premier-mot-de-passe"
    );
    assert_eq!(vault.items.iter().filter(|i| i.is_active()).count(), 5);

    // Une note sécurisée : un brouillon sans identifiant.
    let (note, vault) = connection
        .create(Draft {
            name: "Digicode".to_owned(),
            notes: Some(SecretString::new("4521B")),
            ..Draft::default()
        })
        .await
        .unwrap();
    let note = vault.items.iter().find(|i| i.id == note).unwrap();
    assert_eq!(note.kind, ItemKind::SecureNote);
    let id = sent(connection, &id).await;
    (id, vault)
}

#[tokio::test]
async fn create_edit_and_trash() {
    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    seeder.fill().await;
    let store = temp_store();
    let first = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    let mut connection = first.connection;
    let travail = first
        .vault
        .folders
        .iter()
        .find(|(_, name)| name == "Travail")
        .map(|(id, _)| id.clone())
        .unwrap();
    // Une seconde session, ouverte avant les modifications : son cache vieillira.
    let mut stale = unlock_with_password(&store, &SecretString::new(PASSWORD))
        .await
        .unwrap()
        .connection;

    let (id, vault) = create_login_and_note(&mut connection, &travail).await;

    // Modification de GitHub : le mot de passe change, le reste est intact.
    let github = vault.items.iter().find(|i| i.title == "GitHub").unwrap();
    let github_id = github.id.clone();
    let mut draft = connection.draft(&github_id).await.unwrap();
    assert_eq!(draft.folder_id.as_deref(), Some(travail.as_str()));
    let login_draft = draft.login.as_mut().unwrap();
    assert_eq!(
        login_draft.password.as_ref().unwrap().expose(),
        "hunter2-hunter2"
    );
    login_draft.password = Some(SecretString::new("nouveau-mot-de-passe"));
    login_draft.uris.push("https://gist.github.com".to_owned());
    draft.name = "GitHub perso".to_owned();
    // Vaultwarden tolère une seconde d'écart sur la date de révision.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection.update(&github_id, draft.clone()).await.unwrap();
    let github = vault.items.iter().find(|i| i.id == github_id).unwrap();
    assert_eq!(github.title, "GitHub perso");
    assert_eq!(github.urls.len(), 2);
    assert!(github.has_totp(), "la graine TOTP est gardée");
    assert!(
        github.fields.iter().any(|f| f.label == "PIN"),
        "champs personnalisés gardés"
    );
    sent(&mut connection, &github_id).await;
    let stored = seeder.fetch(&github_id).await;
    let history = stored.password_history.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].password, "hunter2-hunter2");
    assert!(stored.login.unwrap().password_revision_date.is_some());

    stale_edit_becomes_a_copy(&mut stale, &github_id, draft).await;
    connection.sync().await.unwrap();

    amend_like_the_extension(&mut connection, &seeder, &github_id).await;
    link_to_a_mac_app(&mut connection, &seeder, &github_id).await;

    // Un autre type : seul le titre change, la carte reste entière.
    let visa = vault
        .items
        .iter()
        .find(|i| i.title == "Visa")
        .unwrap()
        .id
        .clone();
    let mut card_draft = connection.draft(&visa).await.unwrap();
    assert!(card_draft.login.is_none());
    card_draft.name = "Visa Premier".to_owned();
    let vault = connection.update(&visa, card_draft).await.unwrap();
    let card = vault.items.iter().find(|i| i.id == visa).unwrap();
    assert_eq!(card.title, "Visa Premier");
    assert!(matches!(
        connection
            .amend_login(&visa, None, Some(SecretString::new("x")), None, None)
            .await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        card.field("number").unwrap().value.expose(),
        "4242 4242 4242 4242"
    );

    // Corbeille : l'élément y passe, le serveur le garde (restaurable).
    let vault = connection.trash(&id).await.unwrap();
    assert_eq!(
        vault.items.iter().find(|i| i.id == id).map(|i| i.state),
        Some(ItemState::Trashed)
    );
    sent(&mut connection, &id).await;
    assert!(seeder.fetch(&id).await.deleted_date.is_some());
    assert!(matches!(
        connection.draft(&id).await,
        Err(Error::NotFound | Error::ReadOnly)
    ));

    archive_restore_and_favorite(&mut connection, &id, &github_id).await;

    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Une copie périmée ne peut pas écraser la modification : elle devient
/// une copie, la version du serveur reste.
async fn stale_edit_becomes_a_copy(
    stale: &mut verrou_vaultwarden::Connection,
    github_id: &str,
    mut draft: Draft,
) {
    "GitHub ailleurs".clone_into(&mut draft.name);
    stale.update(github_id, draft).await.unwrap();
    let refreshed = stale.sync().await.unwrap().expect("le serveur a changé");
    assert_eq!(
        stale.take_report().conflicts,
        [format!(
            "GitHub ailleurs{}",
            verrou_vaultwarden::CONFLICT_SUFFIX
        )]
    );
    assert!(refreshed.items.iter().any(|i| i.title == "GitHub perso"));
}

/// Ce que l'extension écrit : nouveau mot de passe et graine TOTP d'un
/// identifiant existant ; son identifiant n'est pas remplacé.
async fn amend_like_the_extension(
    connection: &mut verrou_vaultwarden::Connection,
    seeder: &Seeder,
    github_id: &str,
) {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection
        .amend_login(
            github_id,
            Some("autre".to_owned()),
            Some(SecretString::new("depuis-brave")),
            Some(SecretString::new(
                "otpauth://totp/GitHub:camille?secret=GEZDGNBVGY3TQOJQ",
            )),
            Some("https://github.example".to_owned()),
        )
        .await
        .unwrap();
    let github = vault.items.iter().find(|i| i.id == github_id).unwrap();
    assert_eq!(
        github.field("password").unwrap().value.expose(),
        "depuis-brave"
    );
    assert!(github.urls.iter().any(|u| u == "https://github.example"));
    assert_eq!(
        github
            .field_of_kind(verrou_core::FieldKind::Username)
            .unwrap()
            .value
            .expose(),
        "camille"
    );
    sent(connection, github_id).await;
    let stored = seeder.fetch(github_id).await;
    assert_eq!(
        stored.password_history.unwrap()[0].password,
        "nouveau-mot-de-passe"
    );
    assert!(
        stored
            .login
            .unwrap()
            .totp
            .unwrap()
            .contains("GEZDGNBVGY3TQOJQ")
    );
}

/// Remplissage dans les apps (⌘\) : l'app se relie par une adresse
/// `macapp://`, gardée sur le serveur avec la règle « jamais » (les
/// extensions Bitwarden ne la proposent sur aucune page).
async fn link_to_a_mac_app(
    connection: &mut verrou_vaultwarden::Connection,
    seeder: &Seeder,
    github_id: &str,
) {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let uri = verrou_core::apps::mac_app_uri("com.github.GitHubClient").unwrap();
    let vault = connection
        .amend_login(github_id, None, None, None, Some(uri.clone()))
        .await
        .unwrap();
    let github = vault.items.iter().find(|i| i.id == github_id).unwrap();
    assert!(verrou_core::apps::matches_app(
        &github.urls,
        "com.github.githubclient"
    ));
    assert_eq!(github.primary_host().as_deref(), Some("github.com"));
    sent(connection, github_id).await;
    let stored = seeder.fetch(github_id).await;
    let uris = stored.login.unwrap().uris.unwrap();
    let app = uris
        .iter()
        .find(|u| u.uri.as_deref() == Some(&uri))
        .unwrap();
    assert_eq!(app.r#match, Some(bitwarden_vault::UriMatchType::Never));
}

/// Corbeille → restauration, archives aller-retour, favori, historique visible.
async fn archive_restore_and_favorite(
    connection: &mut verrou_vaultwarden::Connection,
    trashed: &str,
    github_id: &str,
) {
    let state = |vault: &verrou_vaultwarden::Decrypted, id: &str| {
        vault.items.iter().find(|i| i.id == id).map(|i| i.state)
    };
    // L'élément à la corbeille revient.
    let vault = connection.restore(trashed).await.unwrap();
    assert_eq!(state(&vault, trashed), Some(ItemState::Active));

    // Archives : hors de la liste et du remplissage, puis de retour.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection.set_archived(github_id, true).await.unwrap();
    assert_eq!(state(&vault, github_id), Some(ItemState::Archived));
    let index = verrou_core::Vault::new(vault.items);
    // (La copie de conflit faite plus haut reste proposée.)
    assert!(
        index
            .suggestions_for("https://github.com")
            .iter()
            .all(|i| i.id != github_id)
    );
    let vault = connection.set_archived(github_id, false).await.unwrap();
    assert_eq!(state(&vault, github_id), Some(ItemState::Active));

    // Favori, et anciens mots de passe lisibles dans l'élément.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection.set_favorite(github_id, false).await.unwrap();
    let github = vault.items.iter().find(|i| i.id == github_id).unwrap();
    assert!(!github.favorite);
    let history = github
        .field("history-0")
        .expect("historique des mots de passe");
    assert_eq!(history.value.expose(), "nouveau-mot-de-passe");
    assert_eq!(
        github
            .field_of_kind(verrou_core::FieldKind::Password)
            .unwrap()
            .value
            .expose(),
        "depuis-brave"
    );
    // Restauration, archives aller-retour et favori : acceptés dans l'ordre.
    sent(connection, github_id).await;
}

/// Modèle Wi-Fi et champs personnalisés : le champ `verrou:type` part au
/// serveur comme un champ texte ordinaire, revient comme modèle, et survit à
/// la modification des autres champs.
#[tokio::test]
async fn templates_and_custom_fields() {
    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    let store = temp_store();
    let mut connection = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    )
    .connection;
    let field = |name: &str, value: &str, kind| CustomFieldDraft {
        name: name.to_owned(),
        value: Some(SecretString::new(value)),
        kind,
        linked_id: None,
    };
    let (id, vault) = connection
        .create(Draft {
            name: "Wi-Fi maison".to_owned(),
            template: Some(verrou_core::Template::Wifi),
            fields: Some(vec![
                field("Nom du réseau (SSID)", "Martin-5G", CustomFieldKind::Text),
                field("Mot de passe", "lilas-27", CustomFieldKind::Hidden),
                field("Sécurité", "WPA2", CustomFieldKind::Text),
            ]),
            ..Draft::default()
        })
        .await
        .unwrap();
    let wifi = vault.items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(wifi.kind, ItemKind::SecureNote);
    let id = sent(&mut connection, &id).await;
    assert_eq!(wifi.template(), Some(verrou_core::Template::Wifi));
    assert_eq!(wifi.subtitle, "Martin-5G");
    let password = wifi.field_labelled("Mot de passe").unwrap();
    assert_eq!(password.kind, FieldKind::Concealed);
    assert_eq!(password.value.expose(), "lilas-27");

    // Ce que voit un autre client (le coffre web) : un champ texte de plus.
    let stored = seeder.fetch(&id).await;
    let marker = stored
        .fields
        .unwrap()
        .into_iter()
        .find(|f| f.name.as_deref() == Some("verrou:type"))
        .expect("champ du modèle sur le serveur");
    assert_eq!(marker.value.as_deref(), Some("wifi"));
    assert_eq!(marker.r#type, bitwarden_vault::FieldType::Text);

    // Renommer, supprimer, ajouter une case à cocher : le modèle reste.
    let mut draft = connection.draft(&id).await.unwrap();
    assert_eq!(draft.template, Some(verrou_core::Template::Wifi));
    let mut fields = draft.fields.take().unwrap();
    assert_eq!(fields.len(), 3, "le champ réservé n'est pas proposé");
    fields.remove(2);
    "Clé WPA".clone_into(&mut fields[1].name);
    fields.push(field("Réseau invité", "true", CustomFieldKind::Boolean));
    draft.fields = Some(fields);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection.update(&id, draft).await.unwrap();
    let wifi = vault.items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(wifi.template(), Some(verrou_core::Template::Wifi));
    let labels: Vec<&str> = wifi
        .fields
        .iter()
        .filter(|f| f.id.starts_with("custom-"))
        .map(|f| f.label.as_str())
        .collect();
    assert_eq!(labels, ["Nom du réseau (SSID)", "Clé WPA", "Réseau invité"]);
    assert_eq!(
        wifi.field_labelled("Réseau invité").unwrap().value.expose(),
        "Oui"
    );
    sent(&mut connection, &id).await;
    let stored = seeder.fetch(&id).await;
    assert_eq!(stored.fields.unwrap().len(), 4);
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Export des Mots de passe d'Apple : déjà présent, nouveau mot de passe,
/// nouveaux éléments.
const APPLE_EXPORT: &str = "Title,URL,Username,Password,Notes,OTPAuth\n\
    github.com (camille),https://github.com/,camille,hunter2-hunter2,,\n\
    github.com (camille),https://github.com/login,Camille,nouveau-gh,,\n\
    Doctolib,https://www.doctolib.fr/,camille@exemple.fr,d0ct0,,\n\
    Forum,https://forum.fr/,cam,f0rum,\"ligne 1\nligne 2\",otpauth://totp/Forum:cam?secret=GEZDGNBVGY3TQOJQ\n";

#[tokio::test]
async fn import_in_bulk_then_clean_duplicates() {
    use verrou_core::duplicates::{Decision, Existing, Status, classify};
    use verrou_core::import::parse;
    use verrou_vaultwarden::{Destination, ImportPlan};

    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    seeder.fill().await;
    let store = temp_store();
    let first = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    let mut connection = first.connection;
    let github_id = first
        .vault
        .items
        .iter()
        .find(|i| i.title == "GitHub")
        .unwrap()
        .id
        .clone();

    let parsed = parse(APPLE_EXPORT.as_bytes(), None).unwrap();
    let classified = classify(&parsed.items, &first.vault.items);
    let statuses: Vec<&Status> = classified.iter().map(|c| &c.status).collect();
    assert_eq!(
        statuses,
        [
            &Status::Exact(Existing::Vault(github_id.clone())),
            &Status::NewPassword(Existing::Vault(github_id.clone())),
            &Status::New,
            &Status::New,
        ]
    );
    let mut plan = ImportPlan {
        create: Vec::new(),
        update: Vec::new(),
        destination: Destination::Folder("Import Apple".to_owned()),
    };
    for (item, class) in parsed.items.iter().zip(&classified) {
        match (class.decision, &class.status) {
            (Decision::Create, _) => plan.create.push(item.clone()),
            (Decision::Update, Status::NewPassword(Existing::Vault(id))) => {
                plan.update.push((id.clone(), item.clone()));
            }
            _ => {}
        }
    }
    // Vaultwarden tolère une seconde d'écart sur la date de révision.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let report = connection.import(plan).await.unwrap();
    assert_eq!((report.created, report.updated), (2, 1));
    assert_eq!(report.failures, Vec::new());
    let vault = report.vault;
    assert_eq!(vault.items.iter().filter(|i| i.is_active()).count(), 6);
    let forum = vault.items.iter().find(|i| i.title == "Forum").unwrap();
    assert_eq!(forum.folder.as_deref(), Some("Import Apple"));
    assert!(forum.has_totp());
    assert_eq!(forum.notes.as_ref().unwrap().expose(), "ligne 1\nligne 2");
    let doctolib = vault.items.iter().find(|i| i.title == "Doctolib").unwrap();
    assert_eq!(doctolib.folder.as_deref(), Some("Import Apple"));
    assert_eq!(doctolib.field("password").unwrap().value.expose(), "d0ct0");

    // Le nouveau mot de passe remplace l'ancien, gardé dans l'historique ;
    // le reste de l'élément (code TOTP, sites) est intact.
    let stored = seeder.fetch(&github_id).await;
    assert_eq!(
        stored.password_history.unwrap()[0].password,
        "hunter2-hunter2"
    );
    let github_login = stored.login.unwrap();
    assert_eq!(github_login.password.as_deref(), Some("nouveau-gh"));
    assert!(github_login.totp.is_some());
    assert_eq!(
        github_login.uris.unwrap().len(),
        1,
        "même hôte : pas de site en plus"
    );

    import_again_then_trash_duplicates(&mut connection, &seeder).await;
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Un second import crée un doublon, que la corbeille en masse retire.
async fn import_again_then_trash_duplicates(
    connection: &mut verrou_vaultwarden::Connection,
    seeder: &Seeder,
) {
    use verrou_core::duplicates::find_duplicates;
    use verrou_core::import::parse;
    use verrou_vaultwarden::{Destination, ImportPlan};

    // Vers un dossier existant : il n'est pas recréé.
    let mut again = parse(APPLE_EXPORT.as_bytes(), None).unwrap();
    let duplicate = again.items.remove(3);
    let report = connection
        .import(ImportPlan {
            create: vec![duplicate],
            update: Vec::new(),
            destination: Destination::Folder("Travail".to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(report.created, 1);
    assert_eq!(report.vault.folders.len(), 2, "Travail et Import Apple");

    // Les doublons : Forum, deux fois ; un seul part à la corbeille, en une
    // requête.
    let groups = find_duplicates(&report.vault.items);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].label, "forum.fr");
    assert!(groups[0].same_password);
    assert!(groups[0].members[1].preselected, "certain : coché d'office");
    let extra = groups[0].ids()[1..].to_vec();
    let vault = connection.trash_many(&extra).await.unwrap();
    assert_eq!(find_duplicates(&vault.items), Vec::new());
    assert_eq!(vault.items.iter().filter(|i| i.is_active()).count(), 6);
    assert!(seeder.fetch(&extra[0]).await.deleted_date.is_some());
    // Un élément introuvable : rien n'est envoyé.
    assert!(matches!(
        connection
            .trash_many(&[uuid::Uuid::new_v4().to_string()])
            .await,
        Err(Error::NotFound)
    ));
}

// MARK: Fusion de doublons

/// Le même compte, importé trois fois : fusionné dans l'élément gardé, les
/// copies à la corbeille.
#[tokio::test]
async fn merge_duplicates_into_the_kept_item() {
    use verrou_core::duplicates::{Confidence, find_duplicates};

    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    let (stale, plain, with_totp) = seed_maif(&seeder).await;
    let store = temp_store();
    let first = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    let mut connection = first.connection;
    let groups = find_duplicates(&first.vault.items);
    assert_eq!(groups.len(), 1, "{groups:#?}");
    let group = &groups[0];
    assert_eq!(group.kept(), with_totp, "le code à usage unique d'abord");
    assert_eq!(group.confidence, Confidence::Certain);
    let level = |id: &str| {
        group
            .members
            .iter()
            .find(|m| m.id == id)
            .unwrap()
            .confidence
    };
    assert_eq!(level(&plain), Some(Confidence::Certain));
    assert_eq!(level(&stale), Some(Confidence::Probable));

    // Vaultwarden tolère une seconde d'écart sur la date de révision.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let outcome = connection
        .merge_duplicates(group.kept(), &group.ids()[1..])
        .await
        .unwrap();
    assert_eq!(outcome.trashed, 2);
    assert_eq!(
        outcome.summary.uris, 1,
        "www.maif.fr ; connect.maif.fr déjà là"
    );
    assert_eq!(outcome.summary.notes, 2);
    assert_eq!(outcome.summary.fields, 1);
    assert_eq!(outcome.summary.history, 1);
    assert!(!outcome.summary.newer_password);
    assert_eq!(find_duplicates(&outcome.vault.items), Vec::new());

    let stored = seeder.fetch(&with_totp).await;
    let stored_login = stored.login.clone().unwrap();
    assert_eq!(stored_login.password.as_deref(), Some("lilas"));
    assert_eq!(stored_login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    let uris: Vec<String> = stored_login
        .uris
        .unwrap()
        .into_iter()
        .filter_map(|u| u.uri)
        .collect();
    assert_eq!(
        uris,
        [
            "https://connect.maif.fr/espace-perso",
            "https://www.maif.fr"
        ]
    );
    assert_eq!(
        stored.password_history.unwrap()[0].password,
        "ancien-maif",
        "le mot de passe périmé, gardé dans l'historique"
    );
    let notes = stored.notes.unwrap();
    assert!(notes.contains("Contrat habitation") && notes.contains("Contrat auto"));
    assert!(notes.contains("— Fusionné depuis « "));
    assert_eq!(stored.fields.unwrap()[0].name.as_deref(), Some("Agence"));
    for id in [&plain, &stale] {
        assert!(
            seeder.fetch(id).await.deleted_date.is_some(),
            "{id} à la corbeille"
        );
    }
    merging_is_refused(&mut connection, &seeder, &with_totp, &plain).await;
    std::fs::remove_dir_all(store.dir()).unwrap();
}

fn seeded_login(username: &str, password: &str, uri: Option<&str>, totp: Option<&str>) -> Value {
    json!({
        "username": username, "password": password, "passwordRevisionDate": null,
        "totp": totp,
        "uris": uri.map(|u| vec![json!({ "uri": u, "match": null, "uriChecksum": null })]),
        "autofillOnPageLoad": null, "fido2Credentials": null,
    })
}

/// Le même compte, trois fois (le plus ancien d'abord : son mot de passe
/// est périmé), et deux services d'un même domaine, qui ne sont pas des
/// doublons. Rend (périmé, simple, avec code).
async fn seed_maif(seeder: &Seeder) -> (String, String, String) {
    let stale = seeder
        .cipher(json!({
            "name": "maif.fr", "type": 1, "notes": "Contrat auto",
            "login": seeded_login("camille@exemple.fr", "ancien-maif", None, None),
        }))
        .await;
    let plain = seeder
        .cipher(json!({
            "name": "Maif", "type": 1, "notes": "Contrat habitation",
            "login": seeded_login("Camille@exemple.fr", "lilas", Some("https://www.maif.fr"), None),
            "fields": [{ "name": "Agence", "value": "Niort", "type": 0, "linkedId": null }],
        }))
        .await;
    let with_totp = seeder
        .cipher(json!({
            "name": "MAIF - Espace sociétaire", "type": 1,
            "login": seeded_login(
                "camille@exemple.fr", "lilas",
                Some("https://connect.maif.fr/espace-perso"), Some("JBSWY3DPEHPK3PXP"),
            ),
        }))
        .await;
    for (name, password, uri) in [
        ("Nextcloud", "nc", "https://cloud.exemple.fr"),
        ("Vaultwarden", "vw", "https://vault.exemple.fr"),
    ] {
        seeder
            .cipher(json!({
                "name": name, "type": 1,
                "login": seeded_login("camille", password, Some(uri), None),
            }))
            .await;
    }
    (stale, plain, with_totp)
}

/// Une copie à la corbeille ne se fusionne plus ; une carte non plus.
async fn merging_is_refused(
    connection: &mut verrou_vaultwarden::Connection,
    seeder: &Seeder,
    with_totp: &str,
    plain: &str,
) {
    assert!(matches!(
        connection
            .merge_duplicates(with_totp, &[plain.to_owned()])
            .await,
        Err(Error::ReadOnly | Error::NotFound)
    ));
    let card = seeder
        .cipher(json!({
            "name": "Visa", "type": 3,
            "card": {
                "cardholderName": "CAMILLE", "expMonth": "9", "expYear": "2029",
                "code": "123", "brand": "Visa", "number": "4242424242424242",
            },
        }))
        .await;
    connection.sync().await.unwrap();
    assert!(matches!(
        connection.merge_duplicates(with_totp, &[card]).await,
        Err(Error::Invalid(_))
    ));
}

// MARK: Passkeys

/// Vérifie une assertion `WebAuthn` (ES256) avec une clé publique SPKI.
fn verify_assertion(public_key: &[u8], assertion: &verrou_core::passkey::Assertion) {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;
    use sha2::Digest as _;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(public_key).unwrap();
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&sha2::Sha256::digest(&assertion.client_data_json));
    let signature = p256::ecdsa::DerSignature::try_from(assertion.signature.as_slice()).unwrap();
    key.verify(&message, &signature).expect("signature valide");
}

fn assertion_for(passkey: &verrou_core::Passkey, page: &str) -> verrou_core::passkey::Assertion {
    verrou_core::passkey::assert(
        passkey,
        &verrou_core::passkey::AssertionRequest {
            page_url: page,
            rp_id: None,
            challenge: &[42; 32],
            user_verified: false,
        },
    )
    .unwrap()
}

/// Une passkey écrite par un client Bitwarden est utilisable dans Verrou, et
/// celle que Verrou crée se relit, champ par champ, avec le SDK des apps
/// officielles ; le compteur avance et la suppression ne touche qu'à elle.
#[tokio::test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
async fn passkeys_round_trip_with_bitwarden() {
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    use verrou_core::passkey::{RegistrationRequest, b64url, register};

    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;

    // Comme le ferait l'extension Bitwarden : clé PKCS#8 P-256, identifiant UUID.
    let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let bitwarden_id = seeder
        .cipher(json!({
            "name": "WebAuthn.io", "type": 1,
            "login": {
                "username": "camille", "password": null, "passwordRevisionDate": null,
                "totp": null, "autofillOnPageLoad": null,
                "uris": [{ "uri": "https://webauthn.io", "match": null, "uriChecksum": null }],
                "fido2Credentials": [{
                    "credentialId": "1d5d8a2f-0f4e-4c3b-9a55-8d7a1b3c2e10",
                    "keyType": "public-key", "keyAlgorithm": "ECDSA", "keyCurve": "P-256",
                    "keyValue": b64url(key.to_pkcs8_der().unwrap().as_bytes()),
                    "rpId": "webauthn.io", "userHandle": "YWJj", "userName": "camille",
                    "counter": "0", "rpName": "WebAuthn.io", "userDisplayName": "Camille",
                    "discoverable": "true", "creationDate": "2024-01-01T00:00:00Z",
                }],
            },
        }))
        .await;
    let github_id = seeder
        .cipher(json!({
            "name": "GitHub", "type": 1,
            "login": {
                "username": "camille", "password": "hunter2-hunter2",
                "passwordRevisionDate": null, "totp": null, "autofillOnPageLoad": null,
                "uris": [{ "uri": "https://github.com", "match": null, "uriChecksum": null }],
                "fido2Credentials": null,
            },
        }))
        .await;

    let store = temp_store();
    let mut opened = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    let theirs = opened
        .vault
        .passkeys
        .iter()
        .find(|p| p.item == bitwarden_id)
        .unwrap()
        .clone();
    assert_eq!(theirs.rp_id, "webauthn.io");
    assert_eq!(theirs.user_name.as_deref(), Some("camille"));
    assert_eq!(theirs.counter, 0);
    assert!(theirs.discoverable);
    // Verrou signe avec la passkey de Bitwarden, puis enregistre le compteur.
    let assertion = assertion_for(&theirs, "https://webauthn.io/");
    verify_assertion(
        key.verifying_key().to_public_key_der().unwrap().as_bytes(),
        &assertion,
    );
    assert_eq!(assertion.user_handle.as_deref(), Some(&b"abc"[..]));
    let connection = &mut opened.connection;
    let vault = connection
        .set_passkey_counter(&bitwarden_id, &theirs.credential_id, assertion.counter)
        .await
        .unwrap();
    assert_eq!(vault.passkeys[0].counter, 1);
    let stored = seeder.fetch(&bitwarden_id).await;
    let credentials = stored.login.unwrap().fido2_credentials.unwrap();
    assert_eq!(credentials[0].counter, "1");
    assert_eq!(credentials[0].user_display_name.as_deref(), Some("Camille"));

    // Verrou crée une passkey dans l'identifiant GitHub…
    let (ours, registration) = register(
        &RegistrationRequest {
            page_url: "https://github.com/settings/security",
            rp_id: Some("github.com"),
            rp_name: Some("GitHub"),
            user_id: b"id-github-camille",
            user_name: Some("camille"),
            user_display_name: Some("Camille Martin"),
            challenge: &[1; 32],
            user_verified: true,
            self_attestation: false,
        },
        &github_id,
        1_760_000_000,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let (id, vault) = connection
        .save_passkey(Some(&github_id), String::new(), String::new(), None, &ours)
        .await
        .unwrap();
    assert_eq!(id, github_id);
    let github = vault.items.iter().find(|i| i.id == github_id).unwrap();
    assert_eq!(
        github.field("password").unwrap().value.expose(),
        "hunter2-hunter2",
        "le reste de l'élément est gardé"
    );
    // … que le SDK de Bitwarden relit tel quel.
    let stored = seeder.fetch(&github_id).await;
    let credential = &stored.login.unwrap().fido2_credentials.unwrap()[0];
    assert_eq!(credential.credential_id, ours.credential_id);
    assert_eq!(credential.key_type, "public-key");
    assert_eq!(credential.key_algorithm, "ECDSA");
    assert_eq!(credential.key_curve, "P-256");
    assert_eq!(credential.key_value, ours.key.expose());
    assert_eq!(credential.rp_id, "github.com");
    assert_eq!(credential.rp_name.as_deref(), Some("GitHub"));
    assert_eq!(
        credential.user_handle.as_deref(),
        Some(b64url(b"id-github-camille").as_str())
    );
    assert_eq!(credential.user_name.as_deref(), Some("camille"));
    assert_eq!(
        credential.user_display_name.as_deref(),
        Some("Camille Martin")
    );
    assert_eq!(credential.counter, "0");
    assert_eq!(credential.discoverable, "true");
    assert_eq!(credential.creation_date.timestamp(), 1_760_000_000);

    // Relue du cache (hors ligne), elle signe pour GitHub.
    let reopened = unlock_with_password(&store, &SecretString::new(PASSWORD))
        .await
        .unwrap();
    let read_back = reopened
        .vault
        .passkeys
        .iter()
        .find(|p| p.item == github_id)
        .unwrap();
    assert_eq!(read_back, &ours);
    verify_assertion(
        &registration.public_key,
        &assertion_for(read_back, "https://github.com/login"),
    );

    // Une passkey dans un nouvel identifiant, pour un site inconnu.
    let (fresh, _) = register(
        &RegistrationRequest {
            page_url: "https://exemple.fr/inscription",
            rp_id: None,
            rp_name: None,
            user_id: b"dominique",
            user_name: Some("dominique"),
            user_display_name: None,
            challenge: &[2; 32],
            user_verified: false,
            self_attestation: false,
        },
        "",
        1_760_000_000,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let (created, vault) = connection
        .save_passkey(
            None,
            "exemple.fr".to_owned(),
            "https://exemple.fr".to_owned(),
            Some("dominique".to_owned()),
            &fresh,
        )
        .await
        .unwrap();
    let item = vault.items.iter().find(|i| i.id == created).unwrap();
    assert_eq!(item.title, "exemple.fr");
    assert_eq!(item.urls, ["https://exemple.fr"]);
    assert_eq!(item.subtitle, "dominique");
    assert!(vault.passkeys.iter().any(|p| p.item == created));

    // Suppression : seule la passkey part.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let vault = connection
        .delete_passkey(&github_id, &ours.credential_id)
        .await
        .unwrap();
    assert!(vault.passkeys.iter().all(|p| p.item != github_id));
    sent(connection, &github_id).await;
    let stored = seeder.fetch(&github_id).await;
    let login = stored.login.unwrap();
    assert!(login.fido2_credentials.is_none_or(|c| c.is_empty()));
    assert_eq!(login.password.as_deref(), Some("hunter2-hunter2"));
    assert!(matches!(
        connection
            .delete_passkey(&github_id, &ours.credential_id)
            .await,
        Err(Error::NotFound)
    ));
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Une clé SSH générée par Verrou : un élément « clé SSH » (type 5) tel que
/// les apps Bitwarden le lisent, la clé privée au format OpenSSH.
#[tokio::test]
async fn generated_ssh_key_is_a_bitwarden_ssh_item() {
    use bitwarden_vault::CipherType;
    use verrou_vaultwarden::ssh_key::{SshKeyAlgorithm, generate};

    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    let store = temp_store();
    let mut connection = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    )
    .connection;

    let key = generate(SshKeyAlgorithm::Ed25519).unwrap();
    let public_key = key.public_key.clone();
    let fingerprint = key.fingerprint.clone();
    let (id, vault) = connection
        .create_ssh_key("Signature git".to_owned(), None, key)
        .await
        .unwrap();
    let item = vault.items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(item.kind, ItemKind::SshKey);
    assert_eq!(item.title, "Signature git");
    assert_eq!(item.subtitle, fingerprint);
    assert_eq!(item.field("public_key").unwrap().value.expose(), public_key);
    assert_eq!(
        item.field("fingerprint").unwrap().value.expose(),
        fingerprint
    );
    let private = item.field("private_key").unwrap();
    assert_eq!(private.kind, FieldKind::Concealed);
    let parsed = ssh_key::PrivateKey::from_openssh(private.value.expose()).unwrap();
    assert_eq!(parsed.public_key().to_openssh().unwrap(), public_key);

    // Ce qu'un autre client Bitwarden lit sur le serveur.
    let id = sent(&mut connection, &id).await;
    let stored = seeder.fetch(&id).await;
    assert_eq!(stored.r#type, CipherType::SshKey);
    assert!(stored.secure_note.is_none() && stored.login.is_none());
    let stored_key = stored.ssh_key.unwrap();
    assert_eq!(stored_key.public_key, public_key);
    assert_eq!(stored_key.fingerprint, fingerprint);
    assert!(
        stored_key
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );

    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Contenu de test : assez gros pour plusieurs blocs, avec un repère qu'on
/// ne doit jamais retrouver en clair sur le disque ni sur le serveur.
fn sample_file(size: usize) -> Vec<u8> {
    let marker = b"REPERE-EN-CLAIR-";
    let mut bytes: Vec<u8> = marker.iter().copied().cycle().take(size).collect();
    // De la variété après le repère, pour que les blocs diffèrent.
    for (i, byte) in bytes.iter_mut().enumerate().skip(marker.len()) {
        *byte = byte.wrapping_add((i / 7) as u8);
    }
    bytes
}

/// Pièces jointes : ajout (v2), synchronisation, lecture par Verrou et par le
/// SDK officiel, conservation après modification de l'élément, suppression ;
/// puis un document (note + fichier) et un import avec fichier.
#[tokio::test]
async fn attachments_upload_download_and_delete() {
    let Some(server) = server() else { return };
    let email = unique_email();
    let seeder = Seeder::register(&server, &email).await;
    seeder.fill().await;
    let store = temp_store();
    let first = unlocked(
        login(&store, &server, &email, SecretString::new(PASSWORD))
            .await
            .unwrap(),
    );
    let mut connection = first.connection;
    let github = first
        .vault
        .items
        .iter()
        .find(|i| i.title == "GitHub")
        .unwrap()
        .id
        .clone();
    assert_eq!(connection.attachments(&github).await.unwrap(), Vec::new());

    // Ajout : le serveur ne reçoit que du chiffré.
    let contents = sample_file(300_000);
    connection
        .add_attachment(&github, " relevé de compte.pdf ", &contents)
        .await
        .unwrap();
    let list = connection.attachments(&github).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].file_name.as_deref(), Some("relevé de compte.pdf"));
    assert!(list[0].size > contents.len() as u64, "taille du chiffré");
    let attachment = list[0].id.clone();

    // Lecture : mêmes octets.
    let (name, downloaded) = connection
        .download_attachment(&github, &attachment)
        .await
        .unwrap();
    assert_eq!(name, "relevé de compte.pdf");
    assert_eq!(downloaded.as_slice(), contents.as_slice());

    // Rien en clair dans le cache (ni le nom, ni le contenu).
    let mut on_disk = Vec::new();
    for entry in std::fs::read_dir(store.dir()).unwrap() {
        on_disk.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    let haystack = String::from_utf8_lossy(&on_disk);
    assert!(!haystack.contains("relevé de compte"));
    assert!(!haystack.contains("REPERE-EN-CLAIR"));

    official_sdk_reads(&seeder, &github, &contents).await;

    // Modifier l'élément garde sa pièce jointe, lisible.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut draft = connection.draft(&github).await.unwrap();
    draft.name = "GitHub (pièces)".to_owned();
    connection.update(&github, draft).await.unwrap();
    let (_, again) = connection
        .download_attachment(&github, &attachment)
        .await
        .unwrap();
    assert_eq!(again.as_slice(), contents.as_slice());

    // Une autre session la voit après synchronisation.
    let mut other = unlock_with_password(&store, &SecretString::new(PASSWORD))
        .await
        .unwrap()
        .connection;
    other.sync().await.unwrap();
    assert_eq!(other.attachments(&github).await.unwrap().len(), 1);

    // Suppression.
    connection
        .delete_attachment(&github, &attachment)
        .await
        .unwrap();
    assert_eq!(connection.attachments(&github).await.unwrap(), Vec::new());
    assert!(matches!(
        Box::pin(connection.download_attachment(&github, &attachment)).await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        seeder.fetch(&github).await.attachments.unwrap_or_default(),
        Vec::new()
    );

    document_and_import(&mut connection).await;
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Le SDK officiel, comme une app Bitwarden, relit le fichier envoyé par
/// Verrou.
async fn official_sdk_reads(seeder: &Seeder, id: &str, contents: &[u8]) {
    let model: bitwarden_api_api::models::CipherDetailsResponseModel = seeder
        .http
        .get(format!("{}/api/ciphers/{id}", seeder.server))
        .bearer_auth(&seeder.access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cipher = bitwarden_vault::Cipher::try_from(model).unwrap();
    let view = Box::pin(seeder.sdk.vault().ciphers().decrypt(cipher.clone()))
        .await
        .unwrap();
    let official = view.attachments.unwrap().remove(0);
    assert_eq!(official.file_name.as_deref(), Some("relevé de compte.pdf"));
    let url = official.url.clone().unwrap();
    let encrypted = seeder
        .http
        .get(&url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(encrypted[0], 2, "EncArrayBuffer de type 2");
    assert!(!String::from_utf8_lossy(&encrypted).contains("REPERE-EN-CLAIR"));
    let plain = seeder
        .sdk
        .vault()
        .attachments()
        .decrypt_buffer(cipher, official, &encrypted)
        .unwrap();
    assert_eq!(plain, contents);
}

/// Un document (note + fichier), puis un import avec fichier.
async fn document_and_import(connection: &mut verrou_vaultwarden::Connection) {
    use verrou_core::import::{ImportKind, ImportedFile, ImportedItem};
    use verrou_vaultwarden::{Destination, ImportPlan};

    // Un document : une note au nom du fichier, le fichier joint.
    let scan = sample_file(4_096);
    let (document, vault) = connection
        .create_document("Passeport.pdf", &scan, None)
        .await
        .unwrap();
    let note = vault.items.iter().find(|i| i.id == document).unwrap();
    assert_eq!(note.title, "Passeport");
    assert_eq!(note.kind, ItemKind::SecureNote);
    let files = connection.attachments(&document).await.unwrap();
    assert_eq!(files[0].file_name.as_deref(), Some("Passeport.pdf"));
    let (_, read) = connection
        .download_attachment(&document, &files[0].id)
        .await
        .unwrap();
    assert_eq!(read.as_slice(), scan.as_slice());

    // Import d'un élément avec fichier (comme un document de 1Password).
    let imported = ImportedItem {
        kind: ImportKind::SecureNote,
        title: "Bail".to_owned(),
        username: None,
        password: None,
        urls: Vec::new(),
        totp: None,
        notes: None,
        folder: Some("Papiers".to_owned()),
        favorite: false,
        card: None,
        identity: None,
        template: None,
        fields: Vec::new(),
        modified: None,
        attachments: vec![ImportedFile::new("bail.txt", b"loyer : 800".to_vec())],
    };
    let report = connection
        .import(ImportPlan {
            create: vec![imported],
            update: Vec::new(),
            destination: Destination::Original,
        })
        .await
        .unwrap();
    assert_eq!(report.created, 1);
    assert_eq!(report.failures, Vec::new());
    let lease = report
        .vault
        .items
        .iter()
        .find(|i| i.title == "Bail")
        .unwrap();
    assert_eq!(lease.folder.as_deref(), Some("Papiers"));
    let files = connection.attachments(&lease.id).await.unwrap();
    let (name, read) = connection
        .download_attachment(&lease.id, &files[0].id)
        .await
        .unwrap();
    assert_eq!(name, "bail.txt");
    assert_eq!(read.as_slice(), b"loyer : 800");
}

/// Compte du parcours de bout en bout des apps (`scripts/e2e.sh`,
/// `scripts/ios-e2e.sh`) : pas un test, un outil, lancé à la main.
///
/// ```sh
/// VERROU_TEST_SERVER=http://localhost:8118 VERROU_SEED_EMAIL=camille@verrou.test \
///   cargo test -p verrou-vaultwarden --test server -- --ignored --nocapture seed_walkthrough_account
/// ```
///
/// 9 éléments actifs (identifiants, carte, identité, notes, réseau Wi-Fi,
/// un élément protégé), 1 à la corbeille, les dossiers « Personnel » et
/// « Travail », second facteur TOTP. Affiche `SEED_EMAIL`, `SEED_PASSWORD`
/// et `SEED_TOTP`.
#[tokio::test]
#[ignore = "outil : prépare le compte du parcours de bout en bout"]
async fn seed_walkthrough_account() {
    let Some(server) = server() else { return };
    let email = std::env::var("VERROU_SEED_EMAIL").unwrap_or_else(|_| unique_email());
    let seeder = Seeder::register(&server, &email).await;
    seeder.fill().await;
    let personnel = seeder.folder("Personnel").await;
    let login = |name: &str, username: &str, password: &str, uri: &str| {
        json!({
            "name": name, "type": 1, "folderId": personnel,
            "login": {
                "username": username, "password": password, "passwordRevisionDate": null,
                "totp": null, "uris": [{ "uri": uri, "match": null, "uriChecksum": null }],
                "autofillOnPageLoad": null, "fido2Credentials": null,
            },
        })
    };
    seeder
        .cipher(login(
            "Amazon",
            "camille@exemple.fr",
            "colibri-Tempete-42",
            "https://www.amazon.fr",
        ))
        .await;
    seeder
        .cipher(login(
            "Netflix",
            "camille@exemple.fr",
            "netflix",
            "https://www.netflix.com",
        ))
        .await;
    let mut bank = login(
        "Banque",
        "12345678",
        "7391-ronce-Ardoise",
        "https://www.banque.fr",
    );
    // Élément protégé : ses secrets demandent une confirmation.
    bank["reprompt"] = json!(1);
    seeder.cipher(bank).await;
    seeder
        .cipher(json!({
            "name": "Wi-Fi maison", "type": 2, "secureNote": { "type": 0 },
            "fields": [
                { "name": "verrou:type", "value": "wifi", "type": 0, "linkedId": null },
                { "name": "Nom du réseau (SSID)", "value": "Maison-5G", "type": 0, "linkedId": null },
                { "name": "Mot de passe", "value": "lilas-annecy-2024", "type": 1, "linkedId": null },
                { "name": "Sécurité", "value": "WPA2", "type": 0, "linkedId": null },
            ],
        }))
        .await;
    seeder
        .cipher(json!({
            "name": "Digicode", "type": 2, "folderId": personnel,
            "notes": "Porte de l'immeuble : 4B21", "secureNote": { "type": 0 },
        }))
        .await;
    let secret = seeder.enable_totp(&email).await;
    println!("SEED_EMAIL={email}");
    println!("SEED_PASSWORD={PASSWORD}");
    println!("SEED_TOTP={secret}");
}
