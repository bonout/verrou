//! Partage de bout en bout, tout par le code de Verrou, contre un vrai
//! Vaultwarden jetable : une propriétaire crée l'organisation et ses
//! collections, partage des éléments (un par un et en lot, pièce jointe
//! comprise), invite un membre existant et une nouvelle personne, les
//! confirme après vérification de l'empreinte, règle les droits de chaque
//! collection, révoque, restaure, retire ; le membre quitte l'organisation.
//! Le format reste celui de Bitwarden : un client du SDK monté à part (comme
//! le coffre web) relit l'organisation créée par Verrou et ses éléments.
//!
//! Le serveur des tests d'intégration suffit (inscriptions ouvertes, sans
//! courriel : Vaultwarden accepte alors d'office l'invitation d'un compte
//! existant) :
//!
//! ```sh
//! VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden --test sharing
//! ```
//!
//! Avec courriel, l'invitation part avec un lien à jeton que l'invité colle
//! dans « Rejoindre une organisation » ; un Mailpit la reçoit et le test y
//! lit le lien. Les groupes se testent si le serveur les active :
//!
//! ```sh
//! docker network create verrou-net
//! docker run -d --name verrou-mailpit --network verrou-net -p 127.0.0.1:8125:8025 axllent/mailpit
//! docker run -d --name verrou-vw-sharing --network verrou-net -p 127.0.0.1:8133:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=true \
//!   -e ORG_GROUPS_ENABLED=true -e DOMAIN=http://localhost:8133 \
//!   -e SMTP_HOST=verrou-mailpit -e SMTP_PORT=1025 -e SMTP_SECURITY=off \
//!   -e SMTP_FROM=vault@verrou.test -e LOGIN_RATELIMIT_MAX_BURST=1000 \
//!   -e LOGIN_RATELIMIT_SECONDS=1 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   vaultwarden/server:1.37.4
//! VERROU_TEST_SHARING_SERVER=http://localhost:8133 VERROU_TEST_MAILPIT=http://localhost:8125 \
//!   cargo test -p verrou-vaultwarden --test sharing
//! ```

use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{
    InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::Kdf;
use bitwarden_vault::VaultClientExt;
use serde_json::Value;
use verrou_core::SecretString;
use verrou_vaultwarden::collections::CollectionMembers;
use verrou_vaultwarden::members::{CollectionAccess, MemberRole, MemberStatus};
use verrou_vaultwarden::register::{self, NewAccount, NewAccountKdf};
use verrou_vaultwarden::{
    Connection, Decrypted, Draft, Error, LoginDraft, LoginStep, Skipped, Store, login,
};

const PASSWORD: &str = "cheval correct pile agrafe";

struct Server {
    url: String,
    mailpit: Option<String>,
    http: reqwest::Client,
}

impl Server {
    fn from_env() -> Option<Self> {
        let url = std::env::var("VERROU_TEST_SHARING_SERVER")
            .or_else(|_| std::env::var("VERROU_TEST_SERVER"));
        let Ok(url) = url else {
            eprintln!("VERROU_TEST_SHARING_SERVER et VERROU_TEST_SERVER absents : test ignoré");
            return None;
        };
        Some(Self {
            url,
            mailpit: std::env::var("VERROU_TEST_MAILPIT").ok(),
            http: reqwest::Client::new(),
        })
    }

    /// Crée un compte avec le code d'inscription de Verrou (« Créer un
    /// compte »), avec le lien d'invitation s'il y en a un.
    async fn register(&self, email: &str, link: Option<&str>) {
        register::register(&NewAccount {
            server: self.url.clone(),
            email: email.to_owned(),
            name: Some(email.split('-').next().unwrap().to_owned()),
            password: SecretString::new(PASSWORD),
            hint: None,
            kdf: NewAccountKdf::Pbkdf2,
            link: link.map(|l| register::parse_link(l).unwrap()),
        })
        .await
        .unwrap();
    }

    async fn verrou(&self, email: &str) -> (Connection, Decrypted) {
        let store = Store::new(
            std::env::temp_dir().join(format!("verrou-sharing-{}", uuid::Uuid::new_v4())),
        );
        match login(&store, &self.url, email, SecretString::new(PASSWORD))
            .await
            .unwrap()
        {
            LoginStep::Unlocked(unlocked) => (unlocked.connection, unlocked.vault),
            LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
        }
    }

    /// Le nombre de courriels reçus par cette adresse.
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

    /// Le lien « Rejoindre » du courriel d'invitation le plus récent (après
    /// les `after` premiers), si le serveur envoie des courriels.
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
                    .find(|w| w.contains("#/accept-organization/"))
                    .map(str::to_owned);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("aucun courriel d'invitation pour {email}");
    }

    /// Un client du SDK monté hors de Verrou, comme le coffre web :
    /// jeton, profil, clés du compte puis des organisations.
    async fn official_client(&self, email: &str) -> (Client, Value) {
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
        let access = token["access_token"].as_str().unwrap();
        let sync: Value = self
            .http
            .get(format!("{}/api/sync?excludeDomains=true", self.url))
            .bearer_auth(access)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let profile = &sync["profile"];
        let sdk = Client::new(Some(ClientSettings {
            identity_url: format!("{}/identity", self.url),
            api_url: format!("{}/api", self.url),
            user_agent: "verrou-tests".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));
        sdk.crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: Some(profile["id"].as_str().unwrap().parse().unwrap()),
                kdf_params: kdf.clone(),
                email: email.to_owned(),
                account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                    private_key: profile["privateKey"].as_str().unwrap().parse().unwrap(),
                },
                method: InitUserCryptoMethod::MasterPasswordUnlock {
                    password: PASSWORD.into(),
                    master_password_unlock: MasterPasswordUnlockData {
                        kdf,
                        master_key_wrapped_user_key: profile["key"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                        salt: email.to_owned(),
                        contained_key_id: None,
                    },
                },
                upgrade_token: None,
            })
            .await
            .unwrap();
        let organization_keys = profile["organizations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                (
                    o["id"].as_str().unwrap().parse().unwrap(),
                    o["key"].as_str().unwrap().parse().unwrap(),
                )
            })
            .collect();
        sdk.crypto()
            .initialize_org_crypto(InitOrgCryptoRequest { organization_keys })
            .await
            .unwrap();
        (sdk, sync)
    }
}

fn unique_email(prefix: &str) -> String {
    format!(
        "{prefix}-{}@verrou.test",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
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
        login: Some(LoginDraft {
            username: Some("famille@exemple.fr".to_owned()),
            password: Some(SecretString::new(password)),
            totp: None,
            uris: vec![format!("https://{}.exemple.fr", name.to_lowercase())],
        }),
        ..Draft::default()
    }
}

fn access(id: &str, read_only: bool, hide_passwords: bool) -> CollectionAccess {
    CollectionAccess {
        id: id.to_owned(),
        read_only,
        hide_passwords,
        manage: false,
    }
}

/// Invite `email` (rôle utilisateur) ; avec courriel, l'invité accepte avec
/// le lien reçu, sans courriel le serveur l'a déjà accepté. Rend
/// l'identifiant d'adhésion.
async fn invite_and_accept(
    server: &Server,
    owner: &mut Connection,
    invitee: &mut Connection,
    org: &str,
    email: &str,
    collections: &[CollectionAccess],
) -> String {
    let before = server.mails_for(email).await;
    owner
        .invite_members(org, email, MemberRole::User, collections)
        .await
        .unwrap();
    if let Some(link) = server.invite_link(email, before).await {
        // L'invitation attend son jeton.
        assert_eq!(status_of(owner, org, email).await, MemberStatus::Invited);
        let (name, _) = invitee.join_organization(&link).await.unwrap();
        assert_eq!(name, "Famille Martin");
    }
    assert_eq!(status_of(owner, org, email).await, MemberStatus::Accepted);
    member_id(owner, org, email).await
}

async fn status_of(connection: &mut Connection, org: &str, email: &str) -> MemberStatus {
    connection
        .organization_members(org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == email)
        .map(|m| m.status)
        .unwrap()
}

async fn member_id(connection: &mut Connection, org: &str, email: &str) -> String {
    connection
        .organization_members(org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == email)
        .unwrap()
        .id
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
async fn share_invite_confirm_permissions_and_leave() {
    let Some(server) = Server::from_env() else {
        return;
    };

    // La propriétaire crée son compte et son organisation dans Verrou.
    let owner_email = unique_email("proprietaire");
    server.register(&owner_email, None).await;
    let (mut owner, _) = server.verrou(&owner_email).await;
    assert!(matches!(
        owner.create_organization("  ", "x").await,
        Err(Error::Invalid(_))
    ));
    let (org, vault) = owner
        .create_organization("Famille Martine", "Comptes communs")
        .await
        .unwrap();
    let famille = vault.organizations.iter().find(|o| o.id == org).unwrap();
    assert_eq!(famille.role, Some(MemberRole::Owner));
    assert!(famille.can_create_collections && famille.can_rename());
    assert_eq!(famille.collections.len(), 1);
    assert_eq!(famille.collections[0].name, "Comptes communs");
    let communs = famille.collections[0].id.clone();
    // Renommer (propriétaire).
    let vault = owner
        .rename_organization(&org, "Famille Martin")
        .await
        .unwrap();
    assert_eq!(vault.organizations[0].name, "Famille Martin");

    // Une deuxième collection, puis renommée.
    let (archives, _) = owner
        .create_collection(&org, "Archives", &CollectionMembers::default())
        .await
        .unwrap();
    let vault = owner
        .update_collection(
            &org,
            &archives,
            "Archives familiales",
            &CollectionMembers::default(),
        )
        .await
        .unwrap();
    let names: Vec<&str> = vault.organizations[0]
        .collections
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, ["Archives familiales", "Comptes communs"]);

    // Des éléments personnels, dont un avec pièce jointe.
    let mut personal = Vec::new();
    for (name, password) in [
        ("Netflix", "netflix-partagé"),
        ("Wifi", "wpa-1234-5678"),
        ("Banque", "banque-secrète"),
    ] {
        let (id, _) = owner.create(login_draft(name, password)).await.unwrap();
        personal.push(id);
    }
    owner.sync().await.unwrap();
    let personal: Vec<String> = personal.iter().map(|id| owner.resolve(id)).collect();
    let contrat = b"contrat Netflix famille, 4 profils".to_vec();
    owner
        .add_attachment(&personal[0], "contrat.txt", &contrat)
        .await
        .unwrap();
    let (cadenas, _) = owner.create(login_draft("Cadenas", "0000")).await.unwrap();
    owner.sync().await.unwrap();
    let cadenas = owner.resolve(&cadenas);

    // Partage groupé : Netflix (pièce jointe), Wi-Fi, Banque ; doublon et
    // inconnu écartés ; aucune collection, refusé.
    assert!(matches!(
        owner.share_many(&personal, &org, &[], &|_, _| {}).await,
        Err(Error::Invalid(_))
    ));
    let mut ids = personal.clone();
    ids.push(personal[0].clone());
    ids.push("00000000-0000-0000-0000-000000000000".to_owned());
    let seen = std::sync::Mutex::new(Vec::new());
    let outcome = owner
        .share_many(
            &ids,
            &org,
            std::slice::from_ref(&communs),
            &|done, total| {
                seen.lock().unwrap().push((done, total));
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.shared, 3);
    assert_eq!(outcome.failed.len(), 0, "{:?}", outcome.failed);
    assert_eq!(
        outcome.skipped,
        [(
            "00000000-0000-0000-0000-000000000000".to_owned(),
            Skipped::NotFound
        )]
    );
    assert_eq!(seen.into_inner().unwrap().last(), Some(&(3, 3)));
    for title in ["Netflix", "Wifi", "Banque"] {
        let item = find(&outcome.vault, title);
        let sharing = item.shared.as_ref().unwrap();
        assert_eq!(sharing.organization, "Famille Martin");
        assert_eq!(
            sharing.collections,
            [(communs.clone(), "Comptes communs".to_owned())]
        );
    }
    // La pièce jointe suit, lisible avec la clé de l'organisation.
    let files = owner.attachments(&personal[0]).await.unwrap();
    assert_eq!(files.len(), 1);
    let attachment_id = files[0].id.clone();
    let (_, bytes) = owner
        .download_attachment(&personal[0], &attachment_id)
        .await
        .unwrap();
    assert_eq!(bytes.as_slice(), contrat.as_slice());
    // Déjà partagés : écartés, sans envoi.
    let again = owner
        .share_many(&personal, &org, std::slice::from_ref(&communs), &|_, _| {})
        .await
        .unwrap();
    assert_eq!(again.shared, 0);
    assert!(
        again
            .skipped
            .iter()
            .all(|(_, reason)| *reason == Skipped::AlreadyShared)
    );
    // Un par un, dans les archives.
    owner
        .share(&cadenas, &org, std::slice::from_ref(&archives))
        .await
        .unwrap();

    // Le format de Bitwarden : un client du SDK hors de Verrou relit
    // l'organisation créée par Verrou et ce qui y a été partagé.
    let (official, sync) = server.official_client(&owner_email).await;
    let netflix_model = sync["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"].as_str() == Some(personal[0].as_str()))
        .unwrap()
        .clone();
    assert_eq!(netflix_model["organizationId"].as_str(), Some(org.as_str()));
    let model: bitwarden_api_api::models::CipherDetailsResponseModel =
        serde_json::from_value(netflix_model).unwrap();
    let view = official
        .vault()
        .ciphers()
        .decrypt(bitwarden_vault::Cipher::try_from(model).unwrap())
        .await
        .unwrap();
    assert_eq!(view.name, "Netflix");
    assert_eq!(
        view.login.unwrap().password.as_deref(),
        Some("netflix-partagé")
    );
    assert!(
        view.attachments.unwrap().iter().all(|a| a.key.is_some()),
        "clé de pièce jointe rechiffrée pour l'organisation"
    );

    // Un membre existant : invité, il accepte (lien ou d'office), attend la
    // confirmation, puis la reçoit après vérification de l'empreinte.
    let member_email = unique_email("camille");
    server.register(&member_email, None).await;
    let (mut member, _) = server.verrou(&member_email).await;
    let (own, _) = member
        .create(login_draft("Disney", "disney-perso"))
        .await
        .unwrap();
    member.sync().await.unwrap();
    let own = member.resolve(&own);
    let camille = invite_and_accept(
        &server,
        &mut owner,
        &mut member,
        &org,
        &member_email,
        &[
            access(&communs, false, false),
            access(&archives, true, true),
        ],
    )
    .await;
    member.sync().await.unwrap();
    let pending = member.pending_memberships();
    assert_eq!(pending.len(), 1, "en attente de confirmation");
    assert_eq!(pending[0].organization_id, org);
    assert_eq!(pending[0].name, "Famille Martin");
    // Sans clé, pas d'organisation à afficher.
    let vault = member.sync().await.unwrap();
    assert!(vault.is_none_or(|v| v.organizations.is_empty()));
    let fingerprint = owner.member_fingerprint(&org, &camille).await.unwrap();
    assert_eq!(fingerprint, member.own_fingerprint().unwrap());
    owner
        .confirm_member(&org, &camille, &fingerprint)
        .await
        .unwrap();
    let vault = member.sync().await.unwrap().unwrap();
    assert_eq!(vault.failures, 0);
    assert_eq!(member.pending_memberships().len(), 0);
    let shared = find(&vault, "Netflix");
    assert_eq!(
        shared.field("password").unwrap().value.expose(),
        "netflix-partagé",
        "le membre déchiffre avec la clé de l'organisation"
    );
    let (_, bytes) = member
        .download_attachment(&personal[0], &attachment_id)
        .await
        .unwrap();
    assert_eq!(bytes.as_slice(), contrat.as_slice());

    // Droits par collection : lecture seule et mots de passe masqués dans
    // les archives, écriture dans « Comptes communs ».
    let cadenas_item = find(&vault, "Cadenas");
    let sharing = cadenas_item.shared.as_ref().unwrap();
    assert!(sharing.read_only && sharing.hide_passwords);
    assert!(matches!(member.draft(&cadenas).await, Err(Error::ReadOnly)));
    let famille = vault.organizations.iter().find(|o| o.id == org).unwrap();
    assert!(!famille.manages_collections() && !famille.can_rename());
    assert!(matches!(
        member
            .update_collection(&org, &archives, "x", &CollectionMembers::default())
            .await,
        Err(Error::Invalid(_))
    ));
    // Partager dans une collection en lecture seule : refusé ; dans
    // l'autre, permis.
    assert!(matches!(
        member
            .share_many(
                std::slice::from_ref(&own),
                &org,
                std::slice::from_ref(&archives),
                &|_, _| {}
            )
            .await,
        Err(Error::ReadOnly)
    ));
    let outcome = member
        .share_many(
            std::slice::from_ref(&own),
            &org,
            std::slice::from_ref(&communs),
            &|_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(outcome.shared, 1);
    let vault = owner.sync().await.unwrap().unwrap();
    assert_eq!(
        find(&vault, "Disney")
            .field("password")
            .unwrap()
            .value
            .expose(),
        "disney-perso",
        "la propriétaire lit ce que le membre a partagé"
    );
    // Les accès de la collection, vus et changés par la propriétaire :
    // les archives deviennent accessibles en écriture au membre.
    let members = owner.collection_members(&org, &archives).await.unwrap();
    assert!(
        members
            .users
            .iter()
            .any(|u| u.id == camille && u.read_only && u.hide_passwords)
    );
    owner
        .update_collection(
            &org,
            &archives,
            "Archives familiales",
            &CollectionMembers {
                users: vec![CollectionAccess {
                    id: camille.clone(),
                    read_only: false,
                    hide_passwords: false,
                    manage: false,
                }],
                groups: Vec::new(),
            },
        )
        .await
        .unwrap();
    let vault = member.sync().await.unwrap().unwrap();
    let sharing = find(&vault, "Cadenas").shared.clone().unwrap();
    assert!(!sharing.read_only && !sharing.hide_passwords);
    // Changer les collections d'un élément partagé.
    let vault = member
        .set_collections(&cadenas, &[archives.clone(), communs.clone()])
        .await
        .unwrap();
    assert_eq!(
        find(&vault, "Cadenas")
            .shared
            .as_ref()
            .unwrap()
            .collections
            .len(),
        2
    );

    // Une nouvelle personne : invitée avant d'avoir un compte, elle le crée
    // (avec le lien, s'il y a des courriels), accepte, puis est confirmée.
    let newcomer_email = unique_email("lea");
    owner
        .invite_members(
            &org,
            &newcomer_email,
            MemberRole::User,
            &[access(&communs, true, false)],
        )
        .await
        .unwrap();
    assert_eq!(
        status_of(&mut owner, &org, &newcomer_email).await,
        MemberStatus::Invited
    );
    let link = server.invite_link(&newcomer_email, 0).await;
    server.register(&newcomer_email, link.as_deref()).await;
    let (mut lea, _) = server.verrou(&newcomer_email).await;
    if let Some(link) = &link {
        lea.join_organization(link).await.unwrap();
    }
    let lea_id = member_id(&mut owner, &org, &newcomer_email).await;
    assert_eq!(
        status_of(&mut owner, &org, &newcomer_email).await,
        MemberStatus::Accepted
    );
    // Une empreinte qui ne correspond pas : rien n'est envoyé.
    assert!(matches!(
        owner
            .confirm_member(&org, &lea_id, "turban-deftly-anime-chatroom-unselfish")
            .await,
        Err(Error::Crypto(_))
    ));
    let fingerprint = owner.member_fingerprint(&org, &lea_id).await.unwrap();
    assert_eq!(fingerprint, lea.own_fingerprint().unwrap());
    owner
        .confirm_member(&org, &lea_id, &fingerprint)
        .await
        .unwrap();
    let vault = lea.sync().await.unwrap().unwrap();
    let netflix = find(&vault, "Netflix");
    assert!(netflix.shared.as_ref().unwrap().read_only);
    // Rangé dans les deux collections : elle ne voit que celle qui lui est
    // ouverte, en lecture seule.
    let cadenas_seen = find(&vault, "Cadenas").shared.clone().unwrap();
    assert_eq!(
        cadenas_seen.collections,
        [(communs.clone(), "Comptes communs".to_owned())],
        "pas d'accès aux archives"
    );
    assert!(cadenas_seen.read_only);
    assert!(matches!(lea.draft(&cadenas).await, Err(Error::ReadOnly)));

    // Révoquer, restaurer, retirer.
    owner.revoke_member(&org, &lea_id).await.unwrap();
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(!vault.items.iter().any(|i| i.title == "Netflix"));
    owner.restore_member(&org, &lea_id).await.unwrap();
    let vault = lea.sync().await.unwrap().unwrap();
    assert!(vault.items.iter().any(|i| i.title == "Netflix"));
    owner.remove_member(&org, &lea_id).await.unwrap();
    let vault = lea.sync().await.unwrap().unwrap();
    assert_eq!(vault.organizations.len(), 0);

    // Groupes, si le serveur les active.
    if famille_uses_groups(&owner, &org) {
        eprintln!("groupes activés sur le serveur : testés");
        let group = owner
            .save_group(
                &org,
                None,
                "Parents",
                std::slice::from_ref(&camille),
                &[access(&communs, true, false)],
            )
            .await
            .unwrap();
        let groups = owner.organization_groups(&org).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Parents");
        assert_eq!(groups[0].members, std::slice::from_ref(&camille));
        let collection = owner.collection_members(&org, &communs).await.unwrap();
        assert!(
            collection
                .groups
                .iter()
                .any(|g| g.id == group && g.read_only)
        );
        owner.delete_group(&org, &group).await.unwrap();
        assert_eq!(owner.organization_groups(&org).await.unwrap().len(), 0);
    } else {
        assert_eq!(owner.organization_groups(&org).await.unwrap().len(), 0);
    }

    // Supprimer une collection : ses éléments restent dans l'organisation.
    let vault = owner.delete_collection(&org, &archives).await.unwrap();
    assert_eq!(vault.organizations[0].collections.len(), 1);
    let cadenas_item = find(&vault, "Cadenas");
    assert_eq!(
        cadenas_item.shared.as_ref().unwrap().collections,
        [(communs.clone(), "Comptes communs".to_owned())]
    );

    // Le membre quitte l'organisation ; la dernière propriétaire, non.
    let vault = member.leave_organization(&org).await.unwrap();
    assert_eq!(vault.organizations.len(), 0);
    assert!(!vault.items.iter().any(|i| i.title == "Netflix"));
    let refused = owner.leave_organization(&org).await;
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("dernier propriétaire")),
        "{:?}",
        refused.err()
    );
}

fn famille_uses_groups(owner: &Connection, org: &str) -> bool {
    owner
        .account()
        .sync
        .as_deref()
        .and_then(|json| serde_json::from_str::<Value>(json).ok())
        .and_then(|sync| {
            sync["profile"]["organizations"]
                .as_array()?
                .iter()
                .find(|o| o["id"].as_str() == Some(org))?
                .get("useGroups")?
                .as_bool()
        })
        .unwrap_or(false)
}
