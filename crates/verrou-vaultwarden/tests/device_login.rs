//! Connexion avec un appareil (« auth requests »), contre un vrai
//! Vaultwarden 1.37.4 jetable :
//!
//! ```sh
//! docker run -d --rm --name verrou-vw-devlogin -p 127.0.0.1:8201:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=true \
//!   -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
//!   -e DOMAIN=http://localhost:8201 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   vaultwarden/server:1.37.4
//! VERROU_TEST_SERVER=http://localhost:8201 cargo test -p verrou-vaultwarden --test device_login
//! # L'expiration (plus de 5 minutes) :
//! VERROU_TEST_SERVER=http://localhost:8201 cargo test -p verrou-vaultwarden \
//!   --test device_login -- --ignored a_request_expires
//! ```
//!
//! Deux sessions du même compte : l'une, ouverte, approuve ou refuse ;
//! l'autre (un appareil qui s'est déjà connecté une fois, comme l'exige
//! Vaultwarden) demande, attend la réponse sur le canal anonyme, puis se
//! connecte sans mot de passe principal. Un client du SDK de Bitwarden,
//! indépendant de Verrou, déchiffre lui aussi la clé approuvée par Verrou.

use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitwarden_core::Client;
use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{
    AuthRequestMethod, InitUserCryptoMethod, InitUserCryptoRequest,
};
use bitwarden_crypto::Kdf;
use serde_json::{Value, json};
use verrou_core::SecretString;
use verrou_core::totp::Totp;
use verrou_vaultwarden::device_login::{self, Answer};
use verrou_vaultwarden::register::{self, NewAccount, NewAccountKdf};
use verrou_vaultwarden::{
    Draft, Error, LoginDraft, LoginStep, Store, TwoFactorAnswer, Unlocked, login, logout,
};

const PASSWORD: &str = "cheval correct pile agrafe";

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
    }
    server
}

fn temp_store() -> Store {
    Store::new(std::env::temp_dir().join(format!("verrou-devlogin-{}", uuid::Uuid::new_v4())))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Un compte neuf (PBKDF2), avec son adresse.
async fn account(server: &str) -> String {
    let email = format!(
        "devlogin-{}@verrou.test",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    register::register(&NewAccount {
        server: server.to_owned(),
        email: email.clone(),
        name: Some("Camille".to_owned()),
        password: SecretString::new(PASSWORD),
        hint: None,
        kdf: NewAccountKdf::Pbkdf2,
        link: None,
    })
    .await
    .unwrap();
    email
}

async fn sign_in(server: &str, store: &Store, email: &str) -> Unlocked {
    match login(store, server, email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => *unlocked,
        LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
    }
}

/// Un appareil que le serveur connaît déjà (une connexion par mot de passe,
/// puis déconnexion : l'identifiant d'appareil reste), comme l'exige
/// Vaultwarden pour créer une demande.
async fn known_device(server: &str, email: &str) -> Store {
    let store = temp_store();
    drop(sign_in(server, &store, email).await);
    logout(&store).unwrap();
    assert!(store.load_account().unwrap().is_none());
    store
}

/// Attend que la demande `id` apparaisse dans les demandes en attente de
/// la session ouverte.
async fn pending(unlocked: &mut Unlocked, id: &str) -> device_login::AuthRequest {
    for _ in 0..20 {
        let requests = unlocked.connection.auth_requests().await.unwrap();
        if let Some(request) = requests.into_iter().find(|r| r.id == id) {
            return request;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("demande {id} absente");
}

#[tokio::test]
async fn a_known_device_logs_in_after_approval() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    approver
        .connection
        .create(Draft {
            name: "Banque".to_owned(),
            login: Some(LoginDraft {
                username: Some("camille".to_owned()),
                password: Some(SecretString::new("tr3s-secret")),
                totp: None,
                uris: vec!["https://banque.example".to_owned()],
            }),
            ..Draft::default()
        })
        .await
        .unwrap();
    // L'élément part au serveur (file des modifications).
    approver.connection.sync().await.unwrap();
    let store = known_device(&server, &email).await;

    // L'adresse saisie avec des majuscules : même phrase des deux côtés.
    let request = device_login::begin(&store, &server, &email.to_uppercase())
        .await
        .unwrap();
    assert_eq!(request.answer_now().await.unwrap(), Answer::Pending);
    let shown = pending(&mut approver, request.id()).await;
    assert_eq!(shown.fingerprint, request.fingerprint());
    assert_eq!(shown.fingerprint.split('-').count(), 5);
    assert_eq!(shown.device, "Mac (app de bureau)", "{shown:?}");
    assert_ne!(shown.ip, "");
    assert!(shown.created_at.abs_diff(now().cast_signed()) < 60);

    // Approuver pendant que l'autre appareil attend sur le canal anonyme.
    let waiting = tokio::spawn(async move {
        let answer = request
            .wait_for_answer(Duration::from_secs(30))
            .await
            .unwrap();
        (request, answer)
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    approver
        .connection
        .answer_auth_request(&shown.id, &shown.fingerprint, true)
        .await
        .unwrap();
    let (request, answer) = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("le canal anonyme n'a rien dit")
        .unwrap();
    assert_eq!(answer, Answer::Approved);

    // Plus en attente côté approbateur.
    assert!(
        approver
            .connection
            .auth_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != shown.id)
    );

    let LoginStep::Unlocked(unlocked) = request.login().await.unwrap() else {
        panic!("second facteur inattendu");
    };
    let titles: Vec<_> = unlocked
        .vault
        .items
        .iter()
        .map(|i| i.title.clone())
        .collect();
    assert_eq!(titles, ["Banque"]);
    assert_eq!(
        unlocked.connection.user_key().await.unwrap().expose(),
        approver.connection.user_key().await.unwrap().expose()
    );
    // Le compte est enregistré : le mot de passe principal l'ouvre ensuite.
    drop(unlocked);
    let reopened = verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(PASSWORD))
        .await
        .unwrap();
    assert_eq!(reopened.vault.items.len(), 1);

    // Une demande ne sert qu'une fois.
    assert!(request.login().await.is_err());
}

#[tokio::test]
async fn a_denied_request_cannot_log_in() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    let store = known_device(&server, &email).await;
    let request = device_login::begin(&store, &server, &email).await.unwrap();
    let shown = pending(&mut approver, request.id()).await;
    approver
        .connection
        .answer_auth_request(&shown.id, &shown.fingerprint, false)
        .await
        .unwrap();
    assert_eq!(request.answer_now().await.unwrap(), Answer::Denied);
    assert_eq!(
        request
            .wait_for_answer(Duration::from_secs(2))
            .await
            .unwrap(),
        Answer::Denied
    );
    assert!(matches!(request.login().await, Err(Error::Invalid(_))));
    // Refusée : effacée, plus rien à approuver.
    assert!(
        approver
            .connection
            .answer_auth_request(&shown.id, &shown.fingerprint, true)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn approval_checks_the_fingerprint_shown() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    let store = known_device(&server, &email).await;
    let request = device_login::begin(&store, &server, &email).await.unwrap();
    let shown = pending(&mut approver, request.id()).await;
    let error = approver
        .connection
        .answer_auth_request(&shown.id, "autre-phrase-que-celle-montree", true)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Invalid(_)), "{error:?}");
    assert_eq!(request.answer_now().await.unwrap(), Answer::Pending);
}

#[tokio::test]
async fn a_new_device_is_refused_by_vaultwarden() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    // Jamais connecté avec ce compte : Vaultwarden refuse la demande.
    let error = device_login::begin(&temp_store(), &server, &email)
        .await
        .err()
        .expect("demande acceptée d'un appareil inconnu");
    assert!(error.to_string().contains("jamais connecté"), "{error}");
}

#[tokio::test]
async fn second_factor_still_applies() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    let secret = enable_totp(&server, &email).await;
    let store = known_device_with_totp(&server, &email, &secret).await;
    let request = device_login::begin(&store, &server, &email).await.unwrap();
    let shown = pending(&mut approver, request.id()).await;
    approver
        .connection
        .answer_auth_request(&shown.id, &shown.fingerprint, true)
        .await
        .unwrap();
    let LoginStep::TwoFactor(pending) = request.login().await.unwrap() else {
        panic!("Vaultwarden n'a pas demandé le second facteur");
    };
    assert!(pending.is_device_login());
    // Le pas suivant (le code courant a servi à la connexion précédente).
    let code = Totp::parse(&secret).unwrap().generate(now() + 30).code;
    let unlocked = pending
        .answer(&TwoFactorAnswer {
            provider: 0,
            token: code,
        })
        .await
        .unwrap();
    assert_eq!(
        unlocked.connection.user_key().await.unwrap().expose(),
        approver.connection.user_key().await.unwrap().expose()
    );
}

/// Un client indépendant de Verrou, comme l'app officielle : clés et
/// phrase par le SDK de Bitwarden (`new_auth_request`), requêtes HTTP à la
/// main, puis la clé approuvée par Verrou ouverte par le SDK
/// (`InitUserCryptoMethod::AuthRequest`) dans un client neuf.
#[tokio::test]
async fn an_independent_sdk_client_decrypts_the_approved_key() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    let store = known_device(&server, &email).await;
    let device_id = store.device_id().unwrap();
    let keys = Client::new(None).auth().new_auth_request(&email).unwrap();
    let http = reqwest::Client::new();
    let created: Value = http
        .post(format!("{server}/api/auth-requests"))
        .header("device-type", "7")
        .json(&json!({
            "email": email,
            "publicKey": keys.public_key.to_string(),
            "deviceIdentifier": device_id,
            "accessCode": keys.access_code,
            "type": 0,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    let shown = pending(&mut approver, &id).await;
    assert_eq!(shown.fingerprint, keys.fingerprint);
    approver
        .connection
        .answer_auth_request(&shown.id, &shown.fingerprint, true)
        .await
        .unwrap();
    let response: Value = http
        .get(format!("{server}/api/auth-requests/{id}/response"))
        .header("device-type", "7")
        .query(&[("code", keys.access_code.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["requestApproved"], json!(true));
    assert_eq!(response["masterPasswordHash"], Value::Null);
    // Connexion par le code d'accès : le serveur l'accepte.
    let token: Value = http
        .post(format!("{server}/identity/connect/token"))
        .header("device-type", "7")
        .form(&[
            ("grant_type", "password"),
            ("username", email.as_str()),
            ("password", keys.access_code.as_str()),
            ("authRequest", id.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "desktop"),
            ("deviceType", "7"),
            ("deviceIdentifier", device_id.as_str()),
            ("deviceName", "sdk"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let private_key = token["PrivateKey"].as_str().expect("connexion refusée");
    let sdk = Client::new(None);
    sdk.crypto()
        .initialize_user_crypto(InitUserCryptoRequest {
            user_id: Some(approver.connection.account().user_id.parse().unwrap()),
            kdf_params: Kdf::PBKDF2 {
                iterations: NonZeroU32::new(600_000).unwrap(),
            },
            email: email.clone(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: private_key.parse().unwrap(),
            },
            method: InitUserCryptoMethod::AuthRequest {
                request_private_key: keys.private_key,
                method: AuthRequestMethod::UserKey {
                    protected_user_key: response["key"].as_str().unwrap().parse().unwrap(),
                },
            },
            upgrade_token: None,
        })
        .await
        .unwrap();
    assert_eq!(
        sdk.crypto()
            .get_user_encryption_key()
            .await
            .unwrap()
            .to_string(),
        approver.connection.user_key().await.unwrap().expose()
    );
}

/// Plus de 5 minutes : Vaultwarden refuse le code d'accès, même approuvé,
/// et Verrou ne propose plus la connexion.
#[tokio::test]
#[ignore = "attend 5 minutes : lancer avec --ignored"]
async fn a_request_expires() {
    let Some(server) = server() else { return };
    let email = account(&server).await;
    let mut approver = sign_in(&server, &temp_store(), &email).await;
    let store = known_device(&server, &email).await;
    let request = device_login::begin(&store, &server, &email).await.unwrap();
    let shown = pending(&mut approver, request.id()).await;
    assert!(!request.is_expired());
    tokio::time::sleep(device_login::LOGIN_WINDOW + Duration::from_secs(5)).await;
    assert!(request.is_expired());
    assert_eq!(request.answer_now().await.unwrap(), Answer::Denied);
    // L'approbation passe encore côté serveur (15 minutes), mais la
    // connexion est refusée.
    approver
        .connection
        .answer_auth_request(&shown.id, &shown.fingerprint, true)
        .await
        .unwrap();
    let error = request.login().await.err().expect("connexion acceptée");
    assert!(matches!(error, Error::WrongPassword), "{error:?}");
}

/// Jeton d'accès par mot de passe (avec le code TOTP si `totp`).
async fn token(server: &str, email: &str, device_id: &str, totp: Option<&str>) -> String {
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(600_000).unwrap(),
    };
    let hash = MasterPasswordAuthenticationData::derive(PASSWORD, &kdf, email)
        .unwrap()
        .master_password_authentication_hash
        .to_string();
    let mut form = vec![
        ("grant_type", "password".to_owned()),
        ("username", email.to_owned()),
        ("password", hash),
        ("scope", "api offline_access".to_owned()),
        ("client_id", "desktop".to_owned()),
        ("deviceType", "7".to_owned()),
        ("deviceIdentifier", device_id.to_owned()),
        ("deviceName", "test".to_owned()),
    ];
    if let Some(secret) = totp {
        form.push(("twoFactorProvider", "0".to_owned()));
        form.push((
            "twoFactorToken",
            Totp::parse(secret).unwrap().generate(now()).code,
        ));
    }
    let body: Value = reqwest::Client::new()
        .post(format!("{server}/identity/connect/token"))
        .header("device-type", "7")
        .form(&form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned()
}

async fn enable_totp(server: &str, email: &str) -> String {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let access = token(server, email, &uuid::Uuid::new_v4().to_string(), None).await;
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(600_000).unwrap(),
    };
    let hash = MasterPasswordAuthenticationData::derive(PASSWORD, &kdf, email)
        .unwrap()
        .master_password_authentication_hash
        .to_string();
    let response = reqwest::Client::new()
        .put(format!("{server}/api/two-factor/authenticator"))
        .bearer_auth(access)
        .json(&json!({
            "key": secret,
            "token": Totp::parse(secret).unwrap().generate(now()).code,
            "masterPasswordHash": hash,
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "activation TOTP refusée");
    secret.to_owned()
}

/// Appareil connu d'un compte à second facteur : une connexion complète
/// (mot de passe et code), sans enregistrer de compte local.
async fn known_device_with_totp(server: &str, email: &str, secret: &str) -> Store {
    let store = temp_store();
    // Le code courant a servi à l'activation : attendre le pas suivant.
    let wait = 30 - now() % 30 + 1;
    tokio::time::sleep(Duration::from_secs(wait)).await;
    token(server, email, &store.device_id().unwrap(), Some(secret)).await;
    store
}
