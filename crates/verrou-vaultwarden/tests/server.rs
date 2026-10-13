//! Tests contre un vrai Vaultwarden, jetable :
//!
//! ```sh
//! docker run -d --rm --name verrou-vw -p 127.0.0.1:8099:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=true \
//!   -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
//!   -e DOMAIN=http://localhost:8099 \
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
use verrou_vaultwarden::{
    Draft, Error, LoginDraft, LoginStep, Store, TwoFactorAnswer, TwoFactorMethod, login, logout,
    unlock_with_password, unlock_with_user_key,
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

    logout(&store).unwrap();
    assert!(matches!(
        unlock_with_password(&store, &SecretString::new(PASSWORD)).await,
        Err(Error::NoAccount)
    ));
    std::fs::remove_dir_all(store.dir()).unwrap();
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
    let stored = seeder.fetch(&github_id).await;
    let history = stored.password_history.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].password, "hunter2-hunter2");
    assert!(stored.login.unwrap().password_revision_date.is_some());

    // Une copie périmée ne peut pas écraser la modification.
    assert!(matches!(
        stale.update(&github_id, draft).await,
        Err(Error::Conflict)
    ));
    let refreshed = stale.sync().await.unwrap().expect("le serveur a changé");
    assert!(refreshed.items.iter().any(|i| i.title == "GitHub perso"));

    amend_like_the_extension(&mut connection, &seeder, &github_id).await;

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
    assert!(seeder.fetch(&id).await.deleted_date.is_some());
    assert!(matches!(
        connection.draft(&id).await,
        Err(Error::NotFound | Error::ReadOnly)
    ));

    archive_restore_and_favorite(&mut connection, &id, &github_id).await;

    std::fs::remove_dir_all(store.dir()).unwrap();
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
    assert_eq!(index.suggestions_for("https://github.com").len(), 0);
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
}
