//! Membres d'une organisation et création de compte sur invitation, contre
//! un vrai Vaultwarden jetable configuré comme un serveur familial :
//! inscriptions fermées, invitations permises.
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
//! Avec courriel (comme un vrai serveur), un Mailpit reçoit les invitations
//! et le test y lit le lien : ajouter `SMTP_HOST=<mailpit> SMTP_PORT=1025
//! SMTP_SECURITY=off SMTP_FROM=vault@verrou.test` au conteneur (même réseau
//! Docker que `axllent/mailpit`, port web publié en 8125) et
//! `VERROU_TEST_MAILPIT=http://localhost:8125` au test.
//!
//! `DISABLE_ADMIN_TOKEN=true` n'est là que pour **amorcer** ce serveur
//! jetable : le premier compte (la propriétaire) ne peut pas s'inscrire
//! seul, inscriptions fermées ; le test l'invite par l'API
//! d'administration (`POST /admin/invite`), puis tout le reste passe par
//! le code de Verrou, sans administration. Jamais sur un vrai serveur.

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
    /// Boîte de réception de test (Mailpit), si le serveur envoie des courriels.
    mailpit: Option<String>,
    http: reqwest::Client,
}

impl Server {
    fn from_env() -> Option<Self> {
        let Ok(url) = std::env::var("VERROU_TEST_MEMBERS_SERVER") else {
            eprintln!("VERROU_TEST_MEMBERS_SERVER absent : test ignoré");
            return None;
        };
        Some(Self {
            url,
            mailpit: std::env::var("VERROU_TEST_MAILPIT").ok(),
            http: reqwest::Client::new(),
        })
    }

    /// Amorçage seulement : invitation au serveur par l'API d'administration.
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
            "invitation d'amorçage refusée : le conteneur a-t-il DISABLE_ADMIN_TOKEN=true ?"
        );
    }

    /// Le lien « Rejoindre » du dernier courriel reçu par cette adresse.
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
                // Le plus récent d'abord.
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
        panic!("aucun courriel d'invitation pour {email}");
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

    /// Crée le compte avec le code d'inscription de Verrou, comme l'écran
    /// « Créer un compte » : avec le lien s'il y en a un (serveur avec
    /// courriel), sinon par le jeton de vérification que le serveur sans
    /// courriel rend aux adresses invitées.
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
            LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
        }
    }

    /// Jeton d'accès hors de Verrou (création de l'organisation, comme le
    /// coffre web).
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
        assert!(status.is_success(), "{path} : {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }
}

fn unique_email(prefix: &str) -> String {
    format!(
        "{prefix}-{}@verrou.test",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

/// La clé de l'organisation chiffrée pour un compte (RSA-OAEP).
#[allow(deprecated)]
fn wrap_for(org_key: &SymmetricCryptoKey, public_key: &str) -> String {
    let der = data_encoding::BASE64.decode(public_key.as_bytes()).unwrap();
    let public = PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).unwrap();
    UnsignedSharedKey::encapsulate_key_unsigned(org_key, &public)
        .unwrap()
        .to_string()
}

/// Une organisation et deux collections, créées comme le fait le coffre web.
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
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
async fn invite_register_confirm_and_manage_members() {
    let Some(server) = Server::from_env() else {
        return;
    };
    let with_mail = server.mailpit.is_some();

    // Amorçage : la propriétaire, invitée au serveur, crée son compte avec
    // le code de Verrou (lien du courriel, ou jeton de vérification).
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

    // Inscriptions fermées : sans invitation, pas de compte.
    let stranger = unique_email("inconnu");
    let refused = server
        .register(&stranger, MEMBER_PASSWORD, NewAccountKdf::Pbkdf2, None)
        .await;
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("n'accepte pas")),
        "{refused:?}"
    );

    // La propriétaire invite une adresse inconnue du serveur.
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
    assert!(!pending.has_account, "pas encore de compte");
    assert_eq!(pending.collections.len(), 2);
    let member_id = pending.id.clone();
    // Déjà membre : refusé par le serveur.
    assert!(
        admin
            .invite_members(&org, &newcomer, MemberRole::User, &[])
            .await
            .is_err()
    );

    // Lea crée son compte dans Verrou (Argon2id), avec le lien reçu.
    let link = server.invite_link(&newcomer, 0).await;
    if with_mail {
        // Le lien ne vaut que pour son adresse.
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
    // Une seconde inscription est refusée.
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
            panic!("lien d'invitation attendu");
        };
        assert_eq!(invite.organization_id, org);
        // Le serveur avec courriel ne l'accepte qu'avec le jeton.
        assert_eq!(
            status_of(&mut admin, &org, &newcomer).await,
            Some(MemberStatus::Invited)
        );
        lea.accept_invitation(&invite).await.unwrap();
    }
    // Sans courriel, l'inscription d'une adresse invitée l'accepte d'office.
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Accepted),
        "à confirmer"
    );
    // Un simple utilisateur ne voit pas les membres.
    lea.sync().await.unwrap();
    assert!(matches!(
        lea.organization_members(&org).await,
        Err(Error::Invalid(_) | Error::NotFound)
    ));

    // Confirmation : l'empreinte que voit la propriétaire est celle que Lea
    // lit dans son compte (Réglages → Compte de Verrou).
    let fingerprint = admin.member_fingerprint(&org, &member_id).await.unwrap();
    assert_eq!(fingerprint, lea.own_fingerprint().unwrap());
    assert_eq!(fingerprint.split('-').count(), 5);
    // Une autre empreinte (clé substituée entre-temps) : rien n'est envoyé.
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
    // Déjà confirmée : plus d'empreinte à vérifier.
    assert!(admin.member_fingerprint(&org, &member_id).await.is_err());

    // Lea déchiffre l'élément partagé avec la clé de l'organisation.
    let vault = lea.sync().await.unwrap().unwrap();
    assert_eq!(vault.failures, 0);
    let shared = vault.items.iter().find(|i| i.id == netflix).unwrap();
    assert_eq!(
        shared.field("password").unwrap().value.expose(),
        "mot-de-passe-partagé"
    );
    assert!(shared.is_writable());

    // Rôle et collections : seulement les archives, en lecture seule.
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
        "plus d'accès à « Comptes communs »"
    );
    // Gestionnaire, puis administratrice (toutes les collections).
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
    // Administratrice : elle voit les membres, mais ne retire pas la propriétaire.
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

    // Révoquer, puis restaurer.
    admin.revoke_member(&org, &member_id).await.unwrap();
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Revoked)
    );
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(!vault.items.iter().any(|i| i.id == netflix), "accès retiré");
    assert!(admin.revoke_member(&org, &member_id).await.is_err());
    admin.restore_member(&org, &member_id).await.unwrap();
    assert_eq!(
        status_of(&mut admin, &org, &newcomer).await,
        Some(MemberStatus::Confirmed),
        "restauré dans son état d'avant"
    );
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.items.iter().any(|i| i.id == netflix));

    // Renvoyer une invitation : seulement à qui ne l'a pas acceptée.
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
        // Un second courriel, avec un lien qui marche aussi.
        let link = server.invite_link(&later, before).await.unwrap();
        assert!(register::parse_link(&link).is_ok());
    }

    // Retirer : le membre disparaît de la liste, son compte reste.
    admin.remove_member(&org, &tom.id).await.unwrap();
    admin.remove_member(&org, &member_id).await.unwrap();
    let left = admin.organization_members(&org).await.unwrap();
    assert!(left.iter().all(|m| m.email != newcomer && m.email != later));
    assert_eq!(left.len(), 1, "la propriétaire seule");
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.organizations.iter().all(|o| o.id != org));
}
