//! Notifications locales et mises à jour en direct, contre un vrai
//! Vaultwarden 1.37.4 jetable, avec ou sans courriel :
//!
//! - ce que l'invité voit d'une invitation (rien, tant qu'elle n'est pas
//!   acceptée, sur un serveur qui envoie des courriels) ;
//! - accepter sans le jeton du courriel (refusé ; sans courriel, le serveur
//!   accepte d'office l'invitation d'un compte existant) ;
//! - aucune route ne rend le lien ni le jeton à l'administrateur
//!   (« renvoyer » renvoie seulement le courriel) ;
//! - le canal `/notifications/hub` (`SignalR`) pousse la confirmation et les
//!   éléments partagés en quelques secondes ;
//! - ce que `activity` en tire : les nouvelles, une seule fois.
//!
//! ```sh
//! docker network create verrou-vw-notify-net
//! docker run -d --name verrou-vw-notify-mailpit --network verrou-vw-notify-net \
//!   -p 127.0.0.1:8142:8025 axllent/mailpit:v1.21.8
//! docker run -d --name verrou-vw-notify-mail --network verrou-vw-notify-net \
//!   -p 127.0.0.1:8140:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
//!   -e SIGNUPS_ALLOWED=false -e INVITATIONS_ALLOWED=true -e DISABLE_ADMIN_TOKEN=true \
//!   -e DOMAIN=http://localhost:8140 -e LOGIN_RATELIMIT_MAX_BURST=1000 \
//!   -e LOGIN_RATELIMIT_SECONDS=1 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   -e SMTP_HOST=verrou-vw-notify-mailpit -e SMTP_PORT=1025 -e SMTP_SECURITY=off \
//!   -e SMTP_FROM=vault@verrou.test vaultwarden/server:1.37.4
//! VERROU_TEST_NOTIFY_SERVER=http://localhost:8140 VERROU_TEST_MAILPIT=http://localhost:8142 \
//!   cargo test -p verrou-vaultwarden --test notifications
//! ```
//!
//! Sans courriel : le même conteneur sans les variables `SMTP_*` (port
//! 8141), et `VERROU_TEST_NOTIFY_SERVER=http://localhost:8141` seul.
//! `DISABLE_ADMIN_TOKEN=true` n'amorce que les comptes de ce serveur jetable.

use std::collections::HashSet;
use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use bitwarden_crypto::{
    Kdf, KeyEncryptable, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    UnsignedSharedKey, UserKey,
};
use serde_json::{Value, json};
use verrou_core::SecretString;
use verrou_vaultwarden::activity::{self, Notice, NoticeKind, Remote, Snapshot};
use verrou_vaultwarden::hub::{Hub, UpdateKind};
use verrou_vaultwarden::members::{CollectionAccess, MemberRole, MemberStatus};
use verrou_vaultwarden::register::{self, NewAccount, NewAccountKdf, SignupLink};
use verrou_vaultwarden::{Connection, Draft, LoginDraft, LoginStep, Store, login};

const PASSWORD: &str = "cheval correct pile agrafe";

struct Server {
    url: String,
    mailpit: Option<String>,
    http: reqwest::Client,
}

impl Server {
    fn from_env() -> Option<Self> {
        let Ok(url) = std::env::var("VERROU_TEST_NOTIFY_SERVER") else {
            eprintln!("VERROU_TEST_NOTIFY_SERVER absent : test ignoré");
            return None;
        };
        Some(Self {
            url,
            mailpit: std::env::var("VERROU_TEST_MAILPIT").ok(),
            http: reqwest::Client::new(),
        })
    }

    async fn mails(&self, email: &str) -> Vec<Value> {
        let Some(mailpit) = &self.mailpit else {
            return Vec::new();
        };
        let found: Value = self
            .http
            .get(format!("{mailpit}/api/v1/search"))
            .query(&[("query", format!("to:\"{email}\""))])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        found["messages"].as_array().cloned().unwrap_or_default()
    }

    /// Le lien du plus récent courriel reçu après `after` autres.
    async fn link(&self, email: &str, after: usize, marker: &str) -> Option<String> {
        let mailpit = self.mailpit.as_ref()?;
        for _ in 0..50 {
            let messages = self.mails(email).await;
            if messages.len() > after {
                let id = messages[0]["ID"].as_str().unwrap();
                let message: Value = self
                    .http
                    .get(format!("{mailpit}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                return message["Text"]
                    .as_str()
                    .unwrap_or_default()
                    .split_whitespace()
                    .find(|w| w.contains(marker))
                    .map(str::to_owned);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("aucun courriel pour {email}");
    }

    /// Un compte existant : invité au serveur (amorçage), puis créé.
    async fn account(&self, prefix: &str) -> String {
        let email = format!(
            "{prefix}-{}@verrou.test",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        );
        let invited = self
            .http
            .post(format!("{}/admin/invite", self.url))
            .json(&json!({ "email": email }))
            .send()
            .await
            .unwrap();
        assert!(invited.status().is_success(), "DISABLE_ADMIN_TOKEN=true ?");
        let link = self.link(&email, 0, "#/").await;
        register::register(&NewAccount {
            server: self.url.clone(),
            email: email.clone(),
            name: Some(prefix.to_owned()),
            password: SecretString::new(PASSWORD),
            hint: None,
            kdf: NewAccountKdf::Pbkdf2,
            link: link.map(|l| register::parse_link(&l).unwrap()),
        })
        .await
        .unwrap();
        email
    }

    async fn verrou(&self, email: &str) -> (Connection, Store) {
        let store = Store::new(
            std::env::temp_dir().join(format!("verrou-notify-{}", uuid::Uuid::new_v4())),
        );
        match login(&store, &self.url, email, SecretString::new(PASSWORD))
            .await
            .unwrap()
        {
            LoginStep::Unlocked(unlocked) => (unlocked.connection, store),
            LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
        }
    }

    async fn token(&self, email: &str) -> String {
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(register::PBKDF2_ITERATIONS).unwrap(),
        };
        let auth = MasterPasswordAuthenticationData::derive(PASSWORD, &kdf, email)
            .unwrap()
            .master_password_authentication_hash
            .to_string();
        let token: Value = self
            .http
            .post(format!("{}/identity/connect/token", self.url))
            .form(&[
                ("grant_type", "password"),
                ("username", email),
                ("password", auth.as_str()),
                ("scope", "api offline_access"),
                ("client_id", "web"),
                ("deviceType", "9"),
                ("deviceIdentifier", &uuid::Uuid::new_v4().to_string()),
                ("deviceName", "coffre web"),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        token["access_token"].as_str().unwrap().to_owned()
    }

    /// Requête brute ; rend le statut et le corps.
    async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        access: &str,
        body: &Value,
    ) -> (u16, String) {
        let response = self
            .http
            .request(method, format!("{}{path}", self.url))
            .bearer_auth(access)
            .json(body)
            .send()
            .await
            .unwrap();
        (response.status().as_u16(), response.text().await.unwrap())
    }

    async fn api(&self, method: reqwest::Method, path: &str, access: &str, body: &Value) -> Value {
        let (status, text) = self.raw(method, path, access, body).await;
        assert!((200..300).contains(&status), "{path} : {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }
}

#[allow(deprecated)]
fn wrap_for(org_key: &SymmetricCryptoKey, public_key: &str) -> String {
    let der = data_encoding::BASE64.decode(public_key.as_bytes()).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).unwrap();
    UnsignedSharedKey::encapsulate_key_unsigned(org_key, &public)
        .unwrap()
        .to_string()
}

/// L'organisation et sa collection, créées comme le fait le coffre web.
async fn create_organization(server: &Server, owner: &str) -> (String, String) {
    let access = server.token(owner).await;
    let profile = server
        .api(
            reqwest::Method::GET,
            "/api/accounts/profile",
            &access,
            &Value::Null,
        )
        .await;
    let user_id = profile["id"].as_str().unwrap();
    let public = server
        .api(
            reqwest::Method::GET,
            &format!("/api/users/{user_id}/public-key"),
            &access,
            &Value::Null,
        )
        .await;
    let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let pair = UserKey::new(key.clone()).make_key_pair().unwrap();
    let created = server
        .api(
            reqwest::Method::POST,
            "/api/organizations",
            &access,
            &json!({
                "name": "Famille Martin",
                "billingEmail": owner,
                "collectionName": "Comptes communs".encrypt_with_key(&key).unwrap().to_string(),
                "key": wrap_for(&key, public["publicKey"].as_str().unwrap()),
                "keys": {
                    "publicKey": pair.public.to_string(),
                    "encryptedPrivateKey": pair.private.to_string(),
                },
                "planType": 0,
            }),
        )
        .await;
    let org = created["id"].as_str().unwrap().to_owned();
    let collections = server
        .api(
            reqwest::Method::GET,
            &format!("/api/organizations/{org}/collections"),
            &access,
            &Value::Null,
        )
        .await;
    let collection = collections["data"][0]["id"].as_str().unwrap().to_owned();
    (org, collection)
}

/// La réponse brute de `/api/sync` du compte.
async fn raw_sync(server: &Server, access: &str) -> Value {
    server
        .api(
            reqwest::Method::GET,
            "/api/sync?excludeDomains=true",
            access,
            &Value::Null,
        )
        .await
}

fn lists_org(sync: &Value, field: &str, org: &str) -> Option<i64> {
    sync["profile"][field]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == org)
        .and_then(|o| o["status"].as_i64())
}

/// Ce que la connexion sait du compte, comme l'app le fait après chaque
/// synchronisation.
async fn observe(
    connection: &mut Connection,
    store: &Store,
    to_confirm: Option<Vec<(String, String, String)>>,
) -> Vec<NoticeKind> {
    connection.sync().await.unwrap();
    let snapshot = Snapshot::from_sync(connection.account().sync.as_deref().unwrap()).unwrap();
    let remote = Remote {
        to_confirm,
        emergency: None,
    };
    activity::observe(store, &snapshot, &remote, &HashSet::new(), true)
        .unwrap()
        .into_iter()
        .map(|n| n.kind)
        .collect()
}

/// Attend un changement du genre voulu (au plus 10 s).
async fn expect_update(hub: &mut Hub, kind: UpdateKind) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let update = tokio::time::timeout_at(deadline, hub.next())
            .await
            .unwrap_or_else(|_| panic!("aucune mise à jour {kind:?} en 10 s"))
            .unwrap();
        if update.kind == kind {
            assert!(!update.from_this_device);
            return;
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
async fn invitations_hub_and_activity() {
    let Some(server) = Server::from_env() else {
        return;
    };
    let with_mail = server.mailpit.is_some();

    let owner = server.account("proprietaire").await;
    let (org, collection) = create_organization(&server, &owner).await;
    let (mut admin, admin_store) = server.verrou(&owner).await;
    // Un compte existant, qui ouvre Verrou avant d'être invité.
    let guest = server.account("lea").await;
    let (mut lea, lea_store) = server.verrou(&guest).await;
    let lea_access = server.token(&guest).await;
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [] as [NoticeKind; 0],
        "point de départ silencieux"
    );
    assert_eq!(
        observe(&mut admin, &admin_store, Some(vec![])).await,
        [] as [NoticeKind; 0]
    );
    let mut hub = lea.open_hub().await.unwrap();

    // (d) Le canal refuse qui n'a pas de jeton.
    let anonymous = tokio_tungstenite::connect_async(format!(
        "{}/notifications/hub",
        server.url.replace("http://", "ws://")
    ))
    .await;
    assert!(anonymous.is_err(), "canal ouvert sans jeton");

    let before = server.mails(&guest).await.len();
    admin
        .invite_members(
            &org,
            &guest,
            MemberRole::User,
            &[CollectionAccess {
                id: collection.clone(),
                read_only: false,
                hide_passwords: false,
                manage: false,
            }],
        )
        .await
        .unwrap();
    let member = admin
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == guest)
        .unwrap();

    let sync = raw_sync(&server, &lea_access).await;
    if with_mail {
        // (a) Invitée, compte existant, serveur avec courriel : l'invitation
        // n'apparaît nulle part dans sa synchronisation.
        assert_eq!(member.status, MemberStatus::Invited);
        assert_eq!(lists_org(&sync, "organizations", &org), None);
        assert_eq!(lists_org(&sync, "organizationsNew", &org), None);
        assert!(
            !sync.to_string().contains(&org),
            "aucune trace de l'organisation"
        );
        assert_eq!(
            observe(&mut lea, &lea_store, None).await,
            [] as [NoticeKind; 0]
        );

        // (b) Accepter sans le jeton du courriel : refusé.
        let accept = format!("/api/organizations/{org}/users/{}/accept", member.id);
        for token in ["", "eyJ0eXAiOiJKV1QifQ.e30.c2ln"] {
            let (status, text) = server
                .raw(
                    reqwest::Method::POST,
                    &accept,
                    &lea_access,
                    &json!({ "token": token }),
                )
                .await;
            assert!(status >= 400, "accepté sans jeton valide : {status} {text}");
        }

        // (c) Rien ne rend le lien à l'administratrice : la fiche du membre
        // n'a pas de jeton, « renvoyer » ne rend rien et envoie un courriel.
        let owner_access = server.token(&owner).await;
        let details = server
            .api(
                reqwest::Method::GET,
                &format!("/api/organizations/{org}/users/{}", member.id),
                &owner_access,
                &Value::Null,
            )
            .await;
        assert!(!details.to_string().contains("token"), "{details}");
        let (status, body) = server
            .raw(
                reqwest::Method::POST,
                &format!("/api/organizations/{org}/users/{}/reinvite", member.id),
                &owner_access,
                &Value::Null,
            )
            .await;
        assert_eq!((status, body.as_str()), (200, ""), "renvoyer ne rend rien");
        let link = server
            .link(&guest, before + 1, "#/accept-organization/")
            .await
            .unwrap();
        assert!(
            server.mails(&guest).await.len() >= before + 2,
            "deux courriels"
        );

        // Avec le lien, Léa accepte (dans Verrou : « Rejoindre »).
        let SignupLink::Invite(invite) = register::parse_link(&link).unwrap() else {
            panic!("lien d'invitation attendu");
        };
        lea.accept_invitation(&invite).await.unwrap();
    } else {
        // (b) Sans courriel, un compte existant est accepté d'office.
        assert_eq!(member.status, MemberStatus::Accepted);
    }

    // Acceptée : l'invitée la voit (organizationsNew, état 1)…
    let sync = raw_sync(&server, &lea_access).await;
    assert_eq!(lists_org(&sync, "organizationsNew", &org), Some(1));
    assert_eq!(lists_org(&sync, "organizations", &org), None, "pas de clé");
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [NoticeKind::MembershipPending]
    );
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [] as [NoticeKind; 0],
        "une seule fois"
    );
    // … et l'administratrice a un membre à confirmer (pas poussé par le canal).
    let waiting = vec![(org.clone(), "Famille Martin".to_owned(), member.id.clone())];
    assert_eq!(
        observe(&mut admin, &admin_store, Some(waiting.clone())).await,
        [NoticeKind::MembersToConfirm]
    );
    assert_eq!(
        observe(&mut admin, &admin_store, Some(waiting)).await,
        [] as [NoticeKind; 0]
    );

    // (d) Confirmée : le canal le dit à Léa en quelques secondes.
    let fingerprint = admin.member_fingerprint(&org, &member.id).await.unwrap();
    admin
        .confirm_member(&org, &member.id, &fingerprint)
        .await
        .unwrap();
    expect_update(&mut hub, UpdateKind::Organizations).await;
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [NoticeKind::MembershipConfirmed]
    );

    // Un élément partagé par l'administratrice : poussé aussi.
    let (shared, _) = admin
        .create_shared(
            Draft {
                name: "Netflix".to_owned(),
                login: Some(LoginDraft {
                    uri_matches: None,
                    username: Some("famille@exemple.fr".to_owned()),
                    password: Some(SecretString::new("secret-partagé")),
                    totp: None,
                    uris: vec![],
                }),
                ..Draft::default()
            },
            &org,
            std::slice::from_ref(&collection),
        )
        .await
        .unwrap();
    expect_update(&mut hub, UpdateKind::Items).await;
    let notices = {
        lea.sync().await.unwrap();
        let snapshot = Snapshot::from_sync(lea.account().sync.as_deref().unwrap()).unwrap();
        activity::observe(
            &lea_store,
            &snapshot,
            &Remote::default(),
            &HashSet::new(),
            true,
        )
        .unwrap()
    };
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, NoticeKind::ItemsShared);
    assert_eq!(notices[0].count, 1);
    assert_eq!(notices[0].organization.as_deref(), Some("Famille Martin"));
    // Rien de secret dans ce qui part vers la notification.
    assert!(!format!("{notices:?}").contains("secret-partagé"));
    assert!(!format!("{notices:?}").contains("famille@exemple.fr"));

    // Pour l'administratrice, son propre élément n'est pas une nouvelle.
    activity::acknowledge_items(&admin_store, &admin_user_id(&admin), &[shared]).unwrap();
    assert_eq!(
        observe(&mut admin, &admin_store, Some(vec![])).await,
        [] as [NoticeKind; 0]
    );

    // Coffre verrouillé : seul le cache parle, sans clé ni réseau.
    let (mut other, other_store) = server.verrou(&guest).await;
    assert_eq!(
        observe(&mut other, &other_store, None).await,
        [] as [NoticeKind; 0]
    );
    drop(other);
    assert_eq!(
        activity::observe_cache(&other_store).unwrap(),
        [] as [Notice; 0]
    );

    hub.close().await;
}

fn admin_user_id(connection: &Connection) -> String {
    connection.account().user_id.clone()
}
