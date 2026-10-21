//! Local notifications and live updates, against a real throwaway
//! Vaultwarden 1.37.4, with or without email:
//!
//! - what the invitee sees of an invitation (nothing, until it is
//!   accepted, on a server that sends emails);
//! - accepting without the email token (refused; without email, the server
//!   automatically accepts the invitation of an existing account);
//! - no route returns the link or the token to the administrator
//!   ("resend" only resends the email);
//! - the `/notifications/hub` channel (`SignalR`) pushes the confirmation and
//!   the shared items within a few seconds;
//! - what `activity` makes of it: the news, only once.
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
//! Without email: the same container without the `SMTP_*` variables (port
//! 8141), and `VERROU_TEST_NOTIFY_SERVER=http://localhost:8141` alone.
//! `DISABLE_ADMIN_TOKEN=true` only bootstraps the accounts of this throwaway server.

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
            eprintln!("VERROU_TEST_NOTIFY_SERVER not set: test skipped");
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

    /// The link of the most recent email received after `after` others.
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
        panic!("no email for {email}");
    }

    /// An existing account: invited to the server (bootstrap), then created.
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
        assert!(invited.status().is_success(), "DISABLE_ADMIN_TOKEN=true?");
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
            LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
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

    /// Raw request; returns the status and the body.
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
        assert!((200..300).contains(&status), "{path}: {status} {text}");
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

/// The organization and its collection, created the way the web vault does.
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

/// The account's raw `/api/sync` response.
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

/// What the connection knows about the account, as the app does after
/// each sync.
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

/// Waits for a change of the wanted kind (10 s at most).
async fn expect_update(hub: &mut Hub, kind: UpdateKind) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let update = tokio::time::timeout_at(deadline, hub.next())
            .await
            .unwrap_or_else(|_| panic!("no {kind:?} update within 10 s"))
            .unwrap();
        if update.kind == kind {
            assert!(!update.from_this_device);
            return;
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // a full walkthrough, readable in one go
async fn invitations_hub_and_activity() {
    let Some(server) = Server::from_env() else {
        return;
    };
    let with_mail = server.mailpit.is_some();

    let owner = server.account("proprietaire").await;
    let (org, collection) = create_organization(&server, &owner).await;
    let (mut admin, admin_store) = server.verrou(&owner).await;
    // An existing account, which opens Verrou before being invited.
    let guest = server.account("lea").await;
    let (mut lea, lea_store) = server.verrou(&guest).await;
    let lea_access = server.token(&guest).await;
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [] as [NoticeKind; 0],
        "silent starting point"
    );
    assert_eq!(
        observe(&mut admin, &admin_store, Some(vec![])).await,
        [] as [NoticeKind; 0]
    );
    let mut hub = lea.open_hub().await.unwrap();

    // (d) The channel refuses anyone without a token.
    let anonymous = tokio_tungstenite::connect_async(format!(
        "{}/notifications/hub",
        server.url.replace("http://", "ws://")
    ))
    .await;
    assert!(anonymous.is_err(), "channel open without a token");

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
        // (a) Invited, existing account, server with email: the invitation
        // appears nowhere in her sync.
        assert_eq!(member.status, MemberStatus::Invited);
        assert_eq!(lists_org(&sync, "organizations", &org), None);
        assert_eq!(lists_org(&sync, "organizationsNew", &org), None);
        assert!(
            !sync.to_string().contains(&org),
            "no trace of the organization"
        );
        assert_eq!(
            observe(&mut lea, &lea_store, None).await,
            [] as [NoticeKind; 0]
        );

        // (b) Accepting without the email token: refused.
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
            assert!(
                status >= 400,
                "accepted without a valid token: {status} {text}"
            );
        }

        // (c) Nothing returns the link to the admin: the member's details have
        // no token, "resend" returns nothing and sends an email.
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
        assert_eq!((status, body.as_str()), (200, ""), "resend returns nothing");
        let link = server
            .link(&guest, before + 1, "#/accept-organization/")
            .await
            .unwrap();
        assert!(server.mails(&guest).await.len() >= before + 2, "two emails");

        // With the link, Léa accepts (in Verrou: "Join").
        let SignupLink::Invite(invite) = register::parse_link(&link).unwrap() else {
            panic!("invitation link expected");
        };
        lea.accept_invitation(&invite).await.unwrap();
    } else {
        // (b) Without email, an existing account is accepted automatically.
        assert_eq!(member.status, MemberStatus::Accepted);
    }

    // Accepted: the invitee sees it (organizationsNew, status 1)…
    let sync = raw_sync(&server, &lea_access).await;
    assert_eq!(lists_org(&sync, "organizationsNew", &org), Some(1));
    assert_eq!(lists_org(&sync, "organizations", &org), None, "no key");
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [NoticeKind::MembershipPending]
    );
    assert_eq!(
        observe(&mut lea, &lea_store, None).await,
        [] as [NoticeKind; 0],
        "only once"
    );
    // … and the admin has a member to confirm (not pushed by the channel).
    let waiting = vec![(org.clone(), "Famille Martin".to_owned(), member.id.clone())];
    assert_eq!(
        observe(&mut admin, &admin_store, Some(waiting.clone())).await,
        [NoticeKind::MembersToConfirm]
    );
    assert_eq!(
        observe(&mut admin, &admin_store, Some(waiting)).await,
        [] as [NoticeKind; 0]
    );

    // (d) Confirmed: the channel tells Léa within a few seconds.
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

    // An item shared by the admin: pushed too.
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
    // Nothing secret in what goes to the notification.
    assert!(!format!("{notices:?}").contains("secret-partagé"));
    assert!(!format!("{notices:?}").contains("famille@exemple.fr"));

    // For the admin, her own item is not news.
    activity::acknowledge_items(&admin_store, &admin_user_id(&admin), &[shared]).unwrap();
    assert_eq!(
        observe(&mut admin, &admin_store, Some(vec![])).await,
        [] as [NoticeKind; 0]
    );

    // Vault locked: only the cache speaks, without key or network.
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
