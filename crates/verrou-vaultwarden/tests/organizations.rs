//! Organisations (coffres partagés) contre un vrai Vaultwarden, jetable :
//! même serveur que `tests/server.rs` (voir son en-tête).
//!
//! ```sh
//! VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden --test organizations
//! ```
//!
//! Le scénario complet : une propriétaire crée une organisation (clé
//! d'organisation chiffrée avec sa clé publique, comme le coffre web) et deux
//! collections, invite un membre (Vaultwarden sans SMTP l'accepte d'office)
//! puis le confirme (clé de l'organisation chiffrée avec la clé publique du
//! membre). Verrou partage, crée, modifie et range ; le membre relit tout
//! avec ses droits (lecture seule, mots de passe masqués).

use std::num::NonZeroU32;

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{InitUserCryptoMethod, InitUserCryptoRequest};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::{
    Kdf, KeyEncryptable, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    UnsignedSharedKey, UserKey,
};
use bitwarden_vault::VaultClientExt;
use serde_json::{Value, json};
use verrou_core::SecretString;
use verrou_vaultwarden::{Decrypted, Draft, Error, LoginDraft, LoginStep, Store, Unlocked, login};

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
    Store::new(std::env::temp_dir().join(format!("verrou-org-{}", uuid::Uuid::new_v4())))
}

/// Un compte inscrit et connecté hors de Verrou, comme le coffre web.
struct Member {
    http: reqwest::Client,
    server: String,
    email: String,
    access: String,
    user_id: String,
    /// Clé publique du compte (base64 du DER).
    public_key: String,
}

impl Member {
    async fn register(server: &str) -> Self {
        let email = unique_email();
        let http = reqwest::Client::new();
        let keys = Client::new(None)
            .auth()
            .make_register_keys(email.clone(), PASSWORD.into(), kdf())
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
        let auth = MasterPasswordAuthenticationData::derive(PASSWORD, &kdf(), &email)
            .unwrap()
            .master_password_authentication_hash
            .to_string();
        let token: Value = http
            .post(format!("{server}/identity/connect/token"))
            .form(&[
                ("grant_type", "password"),
                ("username", email.as_str()),
                ("password", auth.as_str()),
                ("scope", "api offline_access"),
                ("client_id", "web"),
                ("deviceType", "9"),
                ("deviceIdentifier", &uuid::Uuid::new_v4().to_string()),
                ("deviceName", "membre"),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let access = token["access_token"].as_str().unwrap().to_owned();
        let mut member = Self {
            http,
            server: server.to_owned(),
            email,
            access,
            user_id: String::new(),
            public_key: keys.keys.public.to_string(),
        };
        member.get("/api/accounts/profile").await["id"]
            .as_str()
            .unwrap()
            .clone_into(&mut member.user_id);
        member
    }

    async fn get(&self, path: &str) -> Value {
        self.http
            .get(format!("{}{path}", self.server))
            .bearer_auth(&self.access)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn post(&self, path: &str, body: &Value) -> Value {
        let response = self
            .http
            .post(format!("{}{path}", self.server))
            .bearer_auth(&self.access)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "{path} : {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    /// Ouvre le coffre avec Verrou.
    async fn verrou(&self) -> Unlocked {
        match login(
            &temp_store(),
            &self.server,
            &self.email,
            SecretString::new(PASSWORD),
        )
        .await
        .unwrap()
        {
            LoginStep::Unlocked(unlocked) => *unlocked,
            LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
        }
    }

    /// Un client SDK du compte, pour relire ce que le serveur garde.
    async fn sdk(&self) -> Client {
        let sdk = Client::new(Some(ClientSettings {
            identity_url: format!("{}/identity", self.server),
            api_url: format!("{}/api", self.server),
            user_agent: "verrou-tests".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));
        let profile = self.get("/api/accounts/profile").await;
        sdk.crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: Some(self.user_id.parse().unwrap()),
                kdf_params: kdf(),
                email: self.email.clone(),
                account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                    private_key: profile["privateKey"].as_str().unwrap().parse().unwrap(),
                },
                method: InitUserCryptoMethod::MasterPasswordUnlock {
                    password: PASSWORD.into(),
                    master_password_unlock: MasterPasswordUnlockData {
                        kdf: kdf(),
                        master_key_wrapped_user_key: profile["key"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                        salt: self.email.clone(),
                        contained_key_id: None,
                    },
                },
                upgrade_token: None,
            })
            .await
            .unwrap();
        sdk
    }
}

/// La clé de l'organisation chiffrée pour un compte (RSA-OAEP, sa clé publique).
#[allow(deprecated)]
fn wrap_for(org_key: &SymmetricCryptoKey, public_key: &str) -> String {
    let der = data_encoding::BASE64.decode(public_key.as_bytes()).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).unwrap();
    UnsignedSharedKey::encapsulate_key_unsigned(org_key, &public)
        .unwrap()
        .to_string()
}

/// Une organisation créée comme le fait le coffre web.
struct Org {
    id: String,
    key: SymmetricCryptoKey,
}

impl Org {
    async fn create(owner: &Member, name: &str, first_collection: &str) -> Self {
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let pair = UserKey::new(key.clone()).make_key_pair().unwrap();
        let created = owner
            .post(
                "/api/organizations",
                &json!({
                    "name": name,
                    "billingEmail": owner.email,
                    "collectionName": first_collection
                        .encrypt_with_key(&key)
                        .unwrap()
                        .to_string(),
                    "key": wrap_for(&key, &owner.public_key),
                    "keys": {
                        "publicKey": pair.public.to_string(),
                        "encryptedPrivateKey": pair.private.to_string(),
                    },
                    "planType": 0,
                }),
            )
            .await;
        Self {
            id: created["id"].as_str().unwrap().to_owned(),
            key,
        }
    }

    async fn collection(&self, owner: &Member, name: &str) -> String {
        let created = owner
            .post(
                &format!("/api/organizations/{}/collections", self.id),
                &json!({
                    "name": name.encrypt_with_key(&self.key).unwrap().to_string(),
                    "groups": [],
                    "users": [],
                    "externalId": null,
                }),
            )
            .await;
        created["id"].as_str().unwrap().to_owned()
    }

    /// Invite `member` comme simple utilisateur avec ces droits sur les
    /// collections, puis le confirme (sans SMTP, Vaultwarden accepte
    /// l'invitation d'un compte existant d'office).
    async fn add_member(&self, owner: &Member, member: &Member, collections: Value) {
        owner
            .post(
                &format!("/api/organizations/{}/users/invite", self.id),
                &json!({
                    "emails": [member.email],
                    "type": 2,
                    "collections": collections,
                    "groups": [],
                    "accessAll": false,
                    "permissions": {},
                }),
            )
            .await;
        let users = owner
            .get(&format!("/api/organizations/{}/users", self.id))
            .await;
        let membership = users["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["userId"].as_str() == Some(member.user_id.as_str()))
            .expect("membre invité");
        assert_eq!(membership["status"], 1, "invitation acceptée d'office");
        let public = owner
            .get(&format!("/api/users/{}/public-key", member.user_id))
            .await;
        owner
            .post(
                &format!(
                    "/api/organizations/{}/users/{}/confirm",
                    self.id,
                    membership["id"].as_str().unwrap()
                ),
                &json!({ "key": wrap_for(&self.key, public["publicKey"].as_str().unwrap()) }),
            )
            .await;
    }
}

fn find<'v>(vault: &'v Decrypted, title: &str) -> &'v verrou_core::Item {
    vault
        .items
        .iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("« {title} » absent"))
}

fn login_draft(name: &str, password: &str) -> Draft {
    Draft {
        name: name.to_owned(),
        notes: Some(SecretString::new("partagé avec la famille")),
        login: Some(LoginDraft {
            uri_matches: None,
            username: Some("famille@exemple.fr".to_owned()),
            password: Some(SecretString::new(password)),
            totp: None,
            uris: vec!["https://www.netflix.com".to_owned()],
        }),
        ..Draft::default()
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
async fn organizations_share_create_edit_and_permissions() {
    let Some(server) = server() else { return };
    let owner = Member::register(&server).await;
    let org = Org::create(&owner, "Famille Martin", "Comptes communs").await;
    let archives = org.collection(&owner, "Archives (lecture seule)").await;

    // Verrou voit l'organisation et ses deux collections, noms déchiffrés.
    let mut connection = owner.verrou().await.connection;
    let (personal_id, _) = connection
        .create(login_draft("Netflix", "mot-de-passe-perso"))
        .await
        .unwrap();
    // Envoyé en arrière-plan dans l'app : ici, tout de suite.
    let vault = connection.sync().await.unwrap().unwrap();
    let personal_id = connection.resolve(&personal_id);
    assert_eq!(vault.failures, 0);
    let [famille] = vault.organizations.as_slice() else {
        panic!("une organisation attendue : {:?}", vault.organizations);
    };
    assert_eq!(famille.id, org.id);
    assert_eq!(famille.name, "Famille Martin");
    assert!(famille.admin && famille.is_writable());
    let names: Vec<&str> = famille
        .collections
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, ["Archives (lecture seule)", "Comptes communs"]);
    let communs = famille.collections[1].id.clone();
    assert!(find(&vault, "Netflix").shared.is_none());

    // « Partager… » : l'élément personnel passe dans « Comptes communs ».
    // Une pièce jointe, chiffrée sous la clé personnelle : partager la
    // rechiffre (sa clé) sans retélécharger son contenu.
    let contrat = b"contrat Netflix famille, 4 profils".to_vec();
    connection
        .add_attachment(&personal_id, "contrat.txt", &contrat)
        .await
        .unwrap();
    let destinations = [communs.clone()];
    assert!(matches!(
        connection.share(&personal_id, &org.id, &[]).await,
        Err(Error::Invalid(_))
    ));
    let vault = connection
        .share(&personal_id, &org.id, &destinations)
        .await
        .unwrap();
    let shared = find(&vault, "Netflix");
    assert_eq!(shared.id, personal_id, "partager garde l'identifiant");
    let sharing = shared.shared.as_ref().unwrap();
    assert_eq!(sharing.organization, "Famille Martin");
    assert_eq!(
        sharing.collections,
        [(communs.clone(), "Comptes communs".to_owned())]
    );
    assert!(!sharing.read_only && !sharing.hide_passwords);
    assert_eq!(
        shared.field("password").unwrap().value.expose(),
        "mot-de-passe-perso"
    );
    let files = connection.attachments(&personal_id).await.unwrap();
    assert_eq!(files.len(), 1, "la pièce jointe suit l'élément");
    let attachment_id = files[0].id.clone();
    let (name, bytes) = connection
        .download_attachment(&personal_id, &attachment_id)
        .await
        .unwrap();
    assert_eq!(name, "contrat.txt");
    assert_eq!(bytes.as_slice(), contrat.as_slice());
    // Rechiffré sous la clé de l'organisation : plus question de le repartager.
    assert!(matches!(
        connection.share(&personal_id, &org.id, &destinations).await,
        Err(Error::Invalid(_))
    ));

    // Modifier un élément partagé : rechiffré avec la clé de l'organisation.
    let mut draft = connection.draft(&personal_id).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("nouveau-partagé"));
    let vault = connection.update(&personal_id, draft).await.unwrap();
    let edited = find(&vault, "Netflix");
    assert_eq!(
        edited.field("password").unwrap().value.expose(),
        "nouveau-partagé"
    );
    assert_eq!(
        edited.field("history-0").unwrap().value.expose(),
        "mot-de-passe-perso"
    );
    assert!(edited.shared.is_some(), "toujours dans l'organisation");

    // Créer directement dans une collection, puis le ranger dans les deux.
    let (wifi_id, _) = connection
        .create_shared(
            Draft {
                name: "Wi-Fi maison".to_owned(),
                notes: Some(SecretString::new("clé WPA : 1234-5678")),
                ..Draft::default()
            },
            &org.id,
            std::slice::from_ref(&archives),
        )
        .await
        .unwrap();
    let vault = connection
        .set_collections(&wifi_id, &[archives.clone(), communs.clone()])
        .await
        .unwrap();
    assert_eq!(
        find(&vault, "Wi-Fi maison")
            .shared
            .as_ref()
            .unwrap()
            .collections
            .len(),
        2
    );
    let vault = connection
        .set_collections(&wifi_id, std::slice::from_ref(&archives))
        .await
        .unwrap();
    let wifi = find(&vault, "Wi-Fi maison");
    assert_eq!(
        wifi.shared.as_ref().unwrap().collections,
        [(archives.clone(), "Archives (lecture seule)".to_owned())]
    );

    // Un autre client (le coffre web) relit l'élément avec la clé de
    // l'organisation : le serveur garde bien la version de Verrou.
    let owner_sdk = owner.sdk().await;
    let profile = owner.get("/api/sync?excludeDomains=true").await;
    let org_key = profile["profile"]["organizations"][0]["key"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    owner_sdk
        .crypto()
        .initialize_org_crypto(
            bitwarden_core::key_management::crypto::InitOrgCryptoRequest {
                organization_keys: [(org.id.parse().unwrap(), org_key)].into(),
            },
        )
        .await
        .unwrap();
    let model: bitwarden_api_api::models::CipherDetailsResponseModel =
        serde_json::from_value(owner.get(&format!("/api/ciphers/{personal_id}")).await).unwrap();
    let view = owner_sdk
        .vault()
        .ciphers()
        .decrypt(bitwarden_vault::Cipher::try_from(model).unwrap())
        .await
        .unwrap();
    assert_eq!(view.organization_id.unwrap().to_string(), org.id);
    assert_eq!(
        view.login.unwrap().password.as_deref(),
        Some("nouveau-partagé")
    );

    // Un membre : écriture dans « Comptes communs », lecture seule et
    // mots de passe masqués dans les archives.
    let member = Member::register(&server).await;
    org.add_member(
        &owner,
        &member,
        json!([
            { "id": communs, "readOnly": false, "hidePasswords": false, "manage": false },
            { "id": archives, "readOnly": true, "hidePasswords": true, "manage": false },
        ]),
    )
    .await;
    let unlocked = member.verrou().await;
    let mut member_connection = unlocked.connection;
    let vault = unlocked.vault;
    assert_eq!(vault.failures, 0);
    let famille = &vault.organizations[0];
    assert!(!famille.admin);
    assert!(
        famille
            .collections
            .iter()
            .any(|c| c.read_only && c.hide_passwords)
    );
    let netflix = find(&vault, "Netflix");
    assert_eq!(
        netflix.field("password").unwrap().value.expose(),
        "nouveau-partagé",
        "le membre déchiffre avec la clé de l'organisation"
    );
    // La pièce jointe aussi : sa clé est chiffrée par celle de l'organisation.
    let (_, bytes) = member_connection
        .download_attachment(&personal_id, &attachment_id)
        .await
        .unwrap();
    assert_eq!(bytes.as_slice(), contrat.as_slice());
    assert!(netflix.is_writable());
    let wifi = find(&vault, "Wi-Fi maison");
    let sharing = wifi.shared.as_ref().unwrap();
    assert!(sharing.read_only && sharing.hide_passwords);
    assert_eq!(wifi.notes.as_ref().unwrap().expose(), "clé WPA : 1234-5678");

    // Lecture seule : ni modification, ni création dans les archives.
    let draft = member_connection.draft(&wifi_id).await;
    assert!(matches!(draft, Err(Error::ReadOnly)), "{:?}", draft.err());
    let created = member_connection
        .create_shared(
            login_draft("Disney+", "x"),
            &org.id,
            std::slice::from_ref(&archives),
        )
        .await;
    assert!(matches!(created, Err(Error::ReadOnly)));
    // Action groupée : l'élément en lecture seule est écarté, l'autre archivé.
    let ids = [personal_id.clone(), wifi_id.clone()];
    let outcome = member_connection
        .bulk(&ids, &verrou_vaultwarden::BulkAction::Archive, &|_, _| {})
        .await
        .unwrap();
    assert_eq!(outcome.done, 1);
    assert_eq!(
        outcome.skipped,
        [(wifi_id.clone(), verrou_vaultwarden::Skipped::ReadOnly)]
    );
    assert_eq!(
        find(&outcome.vault, "Netflix").state,
        verrou_core::ItemState::Archived
    );
    let outcome = member_connection
        .bulk(&ids, &verrou_vaultwarden::BulkAction::Unarchive, &|_, _| {})
        .await
        .unwrap();
    assert_eq!(outcome.done, 1);
    // Écriture permise dans « Comptes communs ».
    let mut draft = member_connection.draft(&personal_id).await.unwrap();
    draft.notes = Some(SecretString::new("modifié par le membre"));
    let vault = member_connection.update(&personal_id, draft).await.unwrap();
    assert_eq!(
        find(&vault, "Netflix").notes.as_ref().unwrap().expose(),
        "modifié par le membre"
    );
    let (disney, vault) = member_connection
        .create_shared(
            login_draft("Disney+", "y"),
            &org.id,
            std::slice::from_ref(&communs),
        )
        .await
        .unwrap();
    assert!(
        vault
            .items
            .iter()
            .any(|i| i.id == disney && i.shared.is_some())
    );

    // La propriétaire voit les écritures du membre après synchronisation.
    let vault = connection.sync().await.unwrap().unwrap();
    assert_eq!(
        find(&vault, "Netflix").notes.as_ref().unwrap().expose(),
        "modifié par le membre"
    );
    assert!(vault.items.iter().any(|i| i.id == disney));
}
