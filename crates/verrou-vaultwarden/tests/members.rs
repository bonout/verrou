//! Organization members and account creation by invitation, against a
//! real throwaway Vaultwarden configured like a family server: sign-ups
//! closed, invitations allowed.
//!
//! ```sh
//! docker run -d --name verrou-vw-members -p 127.0.0.1:8119:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=false \
//!   -e INVITATIONS_ALLOWED=true -e DOMAIN=http://localhost:8119 \
//!   -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
//!   -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   -e DISABLE_ADMIN_TOKEN=true vaultwarden/server:1.37.4
//! VERROU_TEST_MEMBERS_SERVER=http://localhost:8119 \
//!   cargo test -p verrou-vaultwarden --test members
//! ```
//!
//! With email (like a real server), a Mailpit receives the invitations
//! and the test reads the link there: add `SMTP_HOST=<mailpit> SMTP_PORT=1025
//! SMTP_SECURITY=off SMTP_FROM=vault@verrou.test` to the container (same
//! Docker network as `axllent/mailpit`, web port published on 8125) and
//! `VERROU_TEST_MAILPIT=http://localhost:8125` to the test.
//!
//! `DISABLE_ADMIN_TOKEN=true` is only there to **bootstrap** this
//! throwaway server: the first account (the owner) cannot sign up on its
//! own, sign-ups being closed; the test invites it through the admin API
//! (`POST /admin/invite`), then everything else goes through Verrou's
//! code, without admin. Never on a real server.

use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use bitwarden_crypto::{
    Kdf, KeyEncryptable, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    UnsignedSharedKey, UserKey,
};
use serde_json::{Value, json};
use verrou_core::SecretString;
use verrou_vaultwarden::members::{CollectionAccess, MemberRole, MemberStatus};
use verrou_vaultwarden::register::{self, NewAccount, NewAccountKdf, SignupLink};
use verrou_vaultwarden::{
    Connection, Decrypted, Draft, Error, LoginDraft, LoginStep, Store, login,
};

const OWNER_PASSWORD: &str = "cheval correct pile agrafe";
const MEMBER_PASSWORD: &str = "pivoine-monceaux-couteau-fixe";

struct Server {
    url: String,
    /// Test inbox (Mailpit), if the server sends emails.
    mailpit: Option<String>,
    http: reqwest::Client,
}

impl Server {
    fn from_env() -> Option<Self> {
        let Ok(url) = std::env::var("VERROU_TEST_MEMBERS_SERVER") else {
            eprintln!("VERROU_TEST_MEMBERS_SERVER not set: test skipped");
            return None;
        };
        Some(Self {
            url,
            mailpit: std::env::var("VERROU_TEST_MAILPIT").ok(),
            http: reqwest::Client::new(),
        })
    }

    /// Bootstrap only: server invitation through the admin API.
    async fn admin_invite(&self, email: &str) {
        let response = self
            .http
            .post(format!("{}/admin/invite", self.url))
            .json(&json!({ "email": email }))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "bootstrap invitation refused: does the container have DISABLE_ADMIN_TOKEN=true?"
        );
    }

    /// The "Join" link of the last email received by this address.
    async fn invite_link(&self, email: &str, after: usize) -> Option<String> {
        let mailpit = self.mailpit.as_ref()?;
        for _ in 0..50 {
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
            let messages = found["messages"].as_array().cloned().unwrap_or_default();
            if messages.len() > after {
                // Most recent first.
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
                let text = message["Text"].as_str().unwrap_or_default();
                return text
                    .split_whitespace()
                    .find(|word| word.contains("#/accept-organization/"))
                    .map(str::to_owned);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("no invitation email for {email}");
    }

    async fn mails_for(&self, email: &str) -> usize {
        let Some(mailpit) = &self.mailpit else {
            return 0;
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
        found["messages"].as_array().map_or(0, Vec::len)
    }

    /// Creates the account with Verrou's sign-up code, like the "Create an
    /// account" screen: with the link if there is one (server with email),
    /// otherwise with the verification token that the server without email
    /// returns to invited addresses.
    async fn register(
        &self,
        email: &str,
        password: &str,
        kdf: NewAccountKdf,
        link: Option<&str>,
    ) -> Result<(), Error> {
        register::register(&NewAccount {
            server: self.url.clone(),
            email: email.to_owned(),
            name: Some(email.split('@').next().unwrap().to_owned()),
            password: SecretString::new(password),
            hint: Some("une phrase".to_owned()),
            kdf,
            link: link.map(|l| register::parse_link(l).unwrap()),
        })
        .await
    }

    async fn verrou(&self, email: &str, password: &str) -> (Connection, Decrypted) {
        let store = Store::new(
            std::env::temp_dir().join(format!("verrou-members-{}", uuid::Uuid::new_v4())),
        );
        match login(&store, &self.url, email, SecretString::new(password))
            .await
            .unwrap()
        {
            LoginStep::Unlocked(unlocked) => (unlocked.connection, unlocked.vault),
            LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
        }
    }

    /// Access token outside Verrou (organization creation, like the web
    /// vault).
    async fn token(&self, email: &str, password: &str, kdf: &Kdf) -> String {
        let auth = MasterPasswordAuthenticationData::derive(password, kdf, email)
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

    async fn api(&self, method: reqwest::Method, path: &str, access: &str, body: &Value) -> Value {
        let response = self
            .http
            .request(method, format!("{}{path}", self.url))
            .bearer_auth(access)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "{path}: {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }
}

fn unique_email(prefix: &str) -> String {
    format!(
        "{prefix}-{}@verrou.test",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

/// The organization key encrypted for an account (RSA-OAEP).
#[allow(deprecated)]
fn wrap_for(org_key: &SymmetricCryptoKey, public_key: &str) -> String {
    let der = data_encoding::BASE64.decode(public_key.as_bytes()).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).unwrap();
    UnsignedSharedKey::encapsulate_key_unsigned(org_key, &public)
        .unwrap()
        .to_string()
}

/// An organization and two collections, created the way the web vault does.
async fn create_organization(server: &Server, owner: &str) -> (String, String, String) {
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(register::PBKDF2_ITERATIONS).unwrap(),
    };
    let access = server.token(owner, OWNER_PASSWORD, &kdf).await;
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
    let archives = server
        .api(
            reqwest::Method::POST,
            &format!("/api/organizations/{org}/collections"),
            &access,
            &json!({
                "name": "Archives".encrypt_with_key(&key).unwrap().to_string(),
                "groups": [], "users": [], "externalId": null,
            }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let collections = server
        .api(
            reqwest::Method::GET,
            &format!("/api/organizations/{org}/collections"),
            &access,
            &Value::Null,
        )
        .await;
    let communs = collections["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .find(|id| *id != archives)
        .unwrap();
    (org, communs, archives)
}

fn access(id: &str, read_only: bool, hide_passwords: bool) -> CollectionAccess {
    CollectionAccess {
        id: id.to_owned(),
        read_only,
        hide_passwords,
        manage: false,
    }
}

async fn status_of(connection: &mut Connection, org: &str, email: &str) -> Option<MemberStatus> {
    connection
        .organization_members(org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == email)
        .map(|m| m.status)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // a full walkthrough, readable in one go
async fn invite_register_confirm_and_manage_members() {
    let Some(server) = Server::from_env() else {
        return;
    };
    let with_mail = server.mailpit.is_some();

    // Bootstrap: the owner, invited to the server, creates her account with
    // Verrou's code (email link, or verification token).
    let owner = unique_email("proprietaire");
    server.admin_invite(&owner).await;
    let link = server.invite_link(&owner, 0).await;
    server
        .register(
            &owner,
            OWNER_PASSWORD,
            NewAccountKdf::Pbkdf2,
            link.as_deref(),
        )
        .await
        .unwrap();
    let (org, communs, archives) = create_organization(&server, &owner).await;
    let (mut admin, vault) = server.verrou(&owner, OWNER_PASSWORD).await;
    let famille = vault.organizations.iter().find(|o| o.id == org).unwrap();
    assert_eq!(famille.role, Some(MemberRole::Owner));
    let rights = famille.member_rights();
    assert!(rights.view && rights.manage && rights.owner);
    let (netflix, _) = admin
        .create_shared(
            Draft {
                name: "Netflix".to_owned(),
                login: Some(LoginDraft {
                    uri_matches: None,
                    username: Some("famille@exemple.fr".to_owned()),
                    password: Some(SecretString::new("mot-de-passe-partagé")),
                    totp: None,
                    uris: vec!["https://www.netflix.com".to_owned()],
                }),
                ..Draft::default()
            },
            &org,
            std::slice::from_ref(&communs),
        )
        .await
        .unwrap();

    // Sign-ups closed: no invitation, no account.
    let stranger = unique_email("inconnu");
    let refused = server
        .register(&stranger, MEMBER_PASSWORD, NewAccountKdf::Pbkdf2, None)
        .await;
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("does not accept")),
        "{refused:?}"
    );

    // The owner invites an address unknown to the server.
    let newcomer = unique_email("lea");
    let invited = admin
        .invite_members(
            &org,
            &format!(" {} ", newcomer.to_uppercase()),
            MemberRole::User,
            &[
                access(&communs, false, false),
                access(&archives, true, true),
            ],
        )
        .await
        .unwrap();
    assert_eq!(invited, std::slice::from_ref(&newcomer));
    let members = admin.organization_members(&org).await.unwrap();
    let pending = members.iter().find(|m| m.email == newcomer).unwrap();
    assert_eq!(pending.status, MemberStatus::Invited);
    assert_eq!(pending.role, MemberRole::User);
    assert!(!pending.has_account, "no account yet");
    assert_eq!(pending.collections.len(), 2);
    let member_id = pending.id.clone();
    // Already a member: refused by the server.
    assert!(
        admin
            .invite_members(&org, &newcomer, MemberRole::User, &[])
            .await
            .is_err()
    );

    // Lea creates her account in Verrou (Argon2id), with the received link.
    let link = server.invite_link(&newcomer, 0).await;
    if with_mail {
        // The link is only valid for her address.
        let wrong = server
            .register(
                &stranger,
                MEMBER_PASSWORD,
                NewAccountKdf::Pbkdf2,
                link.as_deref(),
            )
            .await;
        assert!(matches!(wrong, Err(Error::Invalid(_))), "{wrong:?}");
    }
    server
        .register(
            &newcomer,
            MEMBER_PASSWORD,
            NewAccountKdf::Argon2id,
            link.as_deref(),
        )
        .await
        .unwrap();
    // A second sign-up is refused.
    assert!(
        server
            .register(
                &newcomer,
                MEMBER_PASSWORD,
                NewAccountKdf::Pbkdf2,
                link.as_deref()
            )
            .await
            .is_err()
    );
    let (mut lea, _) = server.verrou(&newcomer, MEMBER_PASSWORD).await;
    if let Some(link) = &link {
        let SignupLink::Invite(invite) = register::parse_link(link).unwrap() else {
            panic!("invitation link expected");
        };
        assert_eq!(invite.organization_id, org);
        // The server with email only accepts her with the token.
        assert_eq!(
            status_of(&mut admin, &org, &newcomer).await,
            Some(MemberStatus::Invited)
        );
        lea.accept_invitation(&invite).await.unwrap();
    }
    // Without email, signing up an invited address accepts it automatically.
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Accepted),
        "to be confirmed"
    );
    // A plain user does not see the members.
    lea.sync().await.unwrap();
    assert!(matches!(
        lea.organization_members(&org).await,
        Err(Error::Invalid(_) | Error::NotFound)
    ));

    // Confirmation: the fingerprint the owner sees is the one Lea reads in
    // her account (Settings → Verrou account).
    let fingerprint = admin.member_fingerprint(&org, &member_id).await.unwrap();
    assert_eq!(fingerprint, lea.own_fingerprint().unwrap());
    assert_eq!(fingerprint.split('-').count(), 5);
    // Another fingerprint (key swapped in the meantime): nothing is sent.
    let refused = admin
        .confirm_member(&org, &member_id, "turban-deftly-anime-chatroom-unselfish")
        .await;
    assert!(matches!(refused, Err(Error::Crypto(_))), "{refused:?}");
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Accepted)
    );
    admin
        .confirm_member(&org, &member_id, &fingerprint)
        .await
        .unwrap();
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Confirmed)
    );
    // Already confirmed: no fingerprint left to check.
    assert!(admin.member_fingerprint(&org, &member_id).await.is_err());

    // Lea decrypts the shared item with the organization key.
    let vault = lea.sync().await.unwrap().unwrap();
    assert_eq!(vault.failures, 0);
    let shared = vault.items.iter().find(|i| i.id == netflix).unwrap();
    assert_eq!(
        shared.field("password").unwrap().value.expose(),
        "mot-de-passe-partagé"
    );
    assert!(shared.is_writable());

    // Role and collections: only the archives, read-only.
    admin
        .edit_member(
            &org,
            &member_id,
            MemberRole::User,
            &[access(&archives, true, false)],
        )
        .await
        .unwrap();
    let edited = admin
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.id == member_id)
        .unwrap();
    assert_eq!(edited.collections, [access(&archives, true, false)]);
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(
        !vault.items.iter().any(|i| i.id == netflix),
        "no more access to \"Comptes communs\""
    );
    // Manager, then admin (all collections).
    admin
        .edit_member(&org, &member_id, MemberRole::Admin, &[])
        .await
        .unwrap();
    let promoted = admin
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.id == member_id)
        .unwrap();
    assert_eq!(promoted.role, MemberRole::Admin);
    assert!(promoted.access_all);
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.items.iter().any(|i| i.id == netflix));
    let as_admin = vault.organizations.iter().find(|o| o.id == org).unwrap();
    let rights = as_admin.member_rights();
    assert!(rights.view && rights.manage && !rights.owner);
    // Admin: she sees the members, but does not remove the owner.
    let owner_member = lea
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == owner)
        .unwrap();
    assert!(matches!(
        lea.remove_member(&org, &owner_member.id).await,
        Err(Error::Invalid(_))
    ));
    admin
        .edit_member(
            &org,
            &member_id,
            MemberRole::User,
            &[access(&communs, false, false)],
        )
        .await
        .unwrap();

    // Revoke, then restore.
    admin.revoke_member(&org, &member_id).await.unwrap();
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Revoked)
    );
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(
        !vault.items.iter().any(|i| i.id == netflix),
        "access removed"
    );
    assert!(admin.revoke_member(&org, &member_id).await.is_err());
    admin.restore_member(&org, &member_id).await.unwrap();
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Confirmed),
        "restored to its previous state"
    );
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.items.iter().any(|i| i.id == netflix));

    // Resend an invitation: only to someone who has not accepted it.
    assert!(matches!(
        admin.reinvite_member(&org, &member_id).await,
        Err(Error::Invalid(_))
    ));
    let later = unique_email("tom");
    admin
        .invite_members(
            &org,
            &later,
            MemberRole::User,
            &[access(&communs, true, false)],
        )
        .await
        .unwrap();
    let before = server.mails_for(&later).await;
    let tom = admin
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == later)
        .unwrap();
    admin.reinvite_member(&org, &tom.id).await.unwrap();
    if with_mail {
        // A second email, with a link that works too.
        let link = server.invite_link(&later, before).await.unwrap();
        assert!(register::parse_link(&link).is_ok());
    }

    // Remove: the member disappears from the list, their account stays.
    admin.remove_member(&org, &tom.id).await.unwrap();
    admin.remove_member(&org, &member_id).await.unwrap();
    let left = admin.organization_members(&org).await.unwrap();
    assert!(left.iter().all(|m| m.email != newcomer && m.email != later));
    assert_eq!(left.len(), 1, "the owner alone");
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.organizations.iter().all(|o| o.id != org));
}
