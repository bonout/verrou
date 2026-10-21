//! "Unshare" end to end, against a real throwaway Vaultwarden: an
//! organization item (password history, passkey, TOTP, fields, match
//! rules, attachment) comes back to the personal vault; an SDK client set
//! up outside Verrou (like the web vault) sees the personal copy, readable
//! with the user's key alone, and no longer the organization item. A
//! read-only member, or one whose organization hides passwords, cannot.
//!
//! ```sh
//! VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden --test unshare
//! ```

use std::num::NonZeroU32;

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{InitUserCryptoMethod, InitUserCryptoRequest};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_core::{Client, ClientSettings, DeviceType};
use bitwarden_crypto::Kdf;
use bitwarden_vault::{UriMatchType, VaultClientExt};
use serde_json::Value;
use verrou_core::passkey::{RegistrationRequest, register};
use verrou_core::{SecretString, UriMatch};
use verrou_vaultwarden::members::{CollectionAccess, MemberRole};
use verrou_vaultwarden::register::{self as signup, NewAccount, NewAccountKdf};
use verrou_vaultwarden::{
    Connection, CustomFieldDraft, CustomFieldKind, Decrypted, Draft, LoginDraft, LoginStep,
    Skipped, Store, login,
};

const PASSWORD: &str = "cheval correct pile agrafe";

fn server() -> Option<String> {
    let url = std::env::var("VERROU_TEST_SERVER").ok();
    if url.is_none() {
        eprintln!("VERROU_TEST_SERVER not set: test skipped");
    }
    url
}

fn unique_email(prefix: &str) -> String {
    format!(
        "{prefix}-{}@verrou.test",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

async fn account(server: &str, email: &str) -> Connection {
    signup::register(&NewAccount {
        server: server.to_owned(),
        email: email.to_owned(),
        name: Some("Camille".to_owned()),
        password: SecretString::new(PASSWORD),
        hint: None,
        kdf: NewAccountKdf::Pbkdf2,
        link: None,
    })
    .await
    .unwrap();
    let store =
        Store::new(std::env::temp_dir().join(format!("verrou-unshare-{}", uuid::Uuid::new_v4())));
    match login(&store, server, email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => unlocked.connection,
        LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
    }
}

fn find<'v>(vault: &'v Decrypted, title: &str) -> &'v verrou_core::Item {
    vault
        .items
        .iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("\"{title}\" missing"))
}

/// An SDK client set up outside Verrou, with the user's key alone (not
/// the organizations' keys): also returns the raw sync and the access
/// token.
async fn official_client(server: &str, email: &str) -> (Client, Value, String) {
    let http = reqwest::Client::new();
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(signup::PBKDF2_ITERATIONS).unwrap(),
    };
    let auth = MasterPasswordAuthenticationData::derive(PASSWORD, &kdf, email)
        .unwrap()
        .master_password_authentication_hash
        .to_string();
    let token: Value = http
        .post(format!("{server}/identity/connect/token"))
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
    let access = token["access_token"].as_str().unwrap().to_owned();
    let sync: Value = http
        .get(format!("{server}/api/sync?excludeDomains=true"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let profile = &sync["profile"];
    let sdk = Client::new(Some(ClientSettings {
        identity_url: format!("{server}/identity"),
        api_url: format!("{server}/api"),
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
                    master_key_wrapped_user_key: profile["key"].as_str().unwrap().parse().unwrap(),
                    salt: email.to_owned(),
                    contained_key_id: None,
                },
            },
            upgrade_token: None,
        })
        .await
        .unwrap();
    (sdk, sync, access)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // a full walkthrough, readable in one go
async fn unshare_moves_an_item_back_to_the_personal_vault() {
    let Some(server) = server() else {
        return;
    };
    let owner_email = unique_email("unshare");
    let mut owner = account(&server, &owner_email).await;
    let (org, vault) = owner
        .create_organization("Famille Martin", "Comptes communs")
        .await
        .unwrap();
    let communs = vault.organizations[0].collections[0].id.clone();

    // A complete login: TOTP, two sites with their rule, fields, notes,
    // old password, passkey, attachment.
    let (id, _) = owner
        .create(Draft {
            name: "Banque".to_owned(),
            notes: Some(SecretString::new("code agence 0042")),
            login: Some(LoginDraft {
                username: Some("camille".to_owned()),
                password: Some(SecretString::new("ancien-secret")),
                totp: Some(SecretString::new("JBSWY3DPEHPK3PXP")),
                uris: vec![
                    "https://banque.exemple.fr".to_owned(),
                    "https://app.banque.exemple.fr/connexion".to_owned(),
                ],
                uri_matches: Some(vec![Some(UriMatch::Host), Some(UriMatch::StartsWith)]),
            }),
            fields: Some(vec![
                CustomFieldDraft {
                    name: "Agence".to_owned(),
                    value: Some(SecretString::new("Lyon")),
                    kind: CustomFieldKind::Text,
                    linked_id: None,
                },
                CustomFieldDraft {
                    name: "Code".to_owned(),
                    value: Some(SecretString::new("9876")),
                    kind: CustomFieldKind::Hidden,
                    linked_id: None,
                },
            ]),
            ..Draft::default()
        })
        .await
        .unwrap();
    owner.sync().await.unwrap();
    let id = owner.resolve(&id);
    owner
        .amend_login(
            &id,
            None,
            Some(SecretString::new("nouveau-secret")),
            None,
            None,
        )
        .await
        .unwrap();
    owner.sync().await.unwrap();
    let (passkey, _) = register(
        &RegistrationRequest {
            page_url: "https://banque.exemple.fr/securite",
            rp_id: Some("banque.exemple.fr"),
            rp_name: Some("Banque"),
            user_id: b"id-banque-camille",
            user_name: Some("camille"),
            user_display_name: Some("Camille Martin"),
            challenge: &[7; 32],
            user_verified: true,
            self_attestation: false,
        },
        &id,
        1_760_000_000,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    owner
        .save_passkey(Some(&id), String::new(), String::new(), None, &passkey)
        .await
        .unwrap();
    let contrat = b"contrat de compte joint".to_vec();
    owner
        .add_attachment(&id, "contrat.txt", &contrat)
        .await
        .unwrap();
    // A second shared item, and a personal one.
    let (other, _) = owner
        .create(Draft {
            name: "Netflix".to_owned(),
            login: Some(LoginDraft {
                password: Some(SecretString::new("netflix")),
                ..LoginDraft::default()
            }),
            ..Draft::default()
        })
        .await
        .unwrap();
    let (personal, _) = owner
        .create(Draft {
            name: "Perso".to_owned(),
            ..Draft::default()
        })
        .await
        .unwrap();
    owner.sync().await.unwrap();
    let (other, personal) = (owner.resolve(&other), owner.resolve(&personal));
    let outcome = owner
        .share_many(
            &[id.clone(), other.clone()],
            &org,
            std::slice::from_ref(&communs),
            &|_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(outcome.shared, 2);
    let shared = find(&outcome.vault, "Banque");
    assert!(shared.shared.is_some());

    // A read-only member, then with passwords hidden: refused.
    let member_email = unique_email("membre");
    let mut member = account(&server, &member_email).await;
    owner
        .invite_members(
            &org,
            &member_email,
            MemberRole::User,
            &[CollectionAccess {
                id: communs.clone(),
                read_only: true,
                hide_passwords: false,
                manage: false,
            }],
        )
        .await
        .unwrap();
    let membership = owner
        .organization_members(&org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.email == member_email)
        .unwrap()
        .id;
    let fingerprint = owner.member_fingerprint(&org, &membership).await.unwrap();
    owner
        .confirm_member(&org, &membership, &fingerprint)
        .await
        .unwrap();
    member.sync().await.unwrap();
    let refused = member
        .unshare(std::slice::from_ref(&id), &|_, _| {})
        .await
        .unwrap();
    assert_eq!(refused.skipped, [(id.clone(), Skipped::ReadOnly)]);
    assert_eq!(refused.moved.len(), 0);
    owner
        .update_collection(
            &org,
            &communs,
            "Comptes communs",
            &verrou_vaultwarden::collections::CollectionMembers {
                users: vec![CollectionAccess {
                    id: membership.clone(),
                    read_only: false,
                    hide_passwords: true,
                    manage: false,
                }],
                groups: Vec::new(),
            },
        )
        .await
        .unwrap();
    member.sync().await.unwrap();
    let refused = member
        .unshare(std::slice::from_ref(&id), &|_, _| {})
        .await
        .unwrap();
    assert_eq!(refused.skipped, [(id.clone(), Skipped::PasswordsHidden)]);

    // The owner unshares "Banque"; duplicate, personal and unknown items
    // are skipped.
    let unknown = "00000000-0000-0000-0000-000000000000".to_owned();
    let seen = std::sync::Mutex::new(Vec::new());
    let outcome = owner
        .unshare(
            &[id.clone(), id.clone(), personal.clone(), unknown.clone()],
            &|done, total| seen.lock().unwrap().push((done, total)),
        )
        .await
        .unwrap();
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert_eq!(outcome.moved.len(), 1);
    let (from, new_id) = outcome.moved[0].clone();
    assert_eq!(from, id);
    assert_ne!(new_id, id);
    assert_eq!(
        outcome.skipped,
        [
            (personal.clone(), Skipped::NotShared),
            (unknown, Skipped::NotFound)
        ]
    );
    assert_eq!(seen.into_inner().unwrap().last(), Some(&(3, 3)));

    // In Verrou: the personal copy, complete.
    let vault = &outcome.vault;
    assert!(
        vault.items.iter().all(|i| i.id != id),
        "organization copy deleted"
    );
    let banque = find(vault, "Banque");
    assert_eq!(banque.id, new_id);
    assert!(banque.shared.is_none());
    assert_eq!(
        banque.field("password").unwrap().value.expose(),
        "nouveau-secret"
    );
    assert_eq!(
        banque.field("totp").unwrap().value.expose(),
        "JBSWY3DPEHPK3PXP"
    );
    assert_eq!(
        banque.field("history-0").unwrap().value.expose(),
        "ancien-secret"
    );
    assert_eq!(banque.notes.as_ref().unwrap().expose(), "code agence 0042");
    assert_eq!(
        banque.url_matches,
        [Some(UriMatch::Host), Some(UriMatch::StartsWith)]
    );
    let custom: Vec<(&str, &str)> = banque
        .fields
        .iter()
        .filter(|f| f.id.starts_with("custom-"))
        .map(|f| (f.label.as_str(), f.value.expose()))
        .collect();
    assert_eq!(custom, [("Agence", "Lyon"), ("Code", "9876")]);
    let passkeys: Vec<_> = vault.passkeys.iter().filter(|p| p.item == new_id).collect();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].credential_id, passkey.credential_id);
    assert_eq!(passkeys[0].key.expose(), passkey.key.expose());
    let files = owner.attachments(&new_id).await.unwrap();
    assert_eq!(files.len(), 1);
    let (name, bytes) = owner
        .download_attachment(&new_id, &files[0].id)
        .await
        .unwrap();
    assert_eq!(
        (name.as_str(), bytes.as_slice()),
        ("contrat.txt", contrat.as_slice())
    );
    // "Netflix" stays shared.
    assert!(find(vault, "Netflix").shared.is_some());

    // An SDK client, with the user's key alone: the copy is personal and
    // readable, the organization item is gone.
    let (official, sync, access) = official_client(&server, &owner_email).await;
    let ciphers = sync["ciphers"].as_array().unwrap();
    assert!(
        ciphers
            .iter()
            .all(|c| c["id"].as_str() != Some(id.as_str()))
    );
    let model = ciphers
        .iter()
        .find(|c| c["id"].as_str() == Some(new_id.as_str()))
        .expect("personal copy seen by the official client")
        .clone();
    assert!(model["organizationId"].is_null());
    assert!(model["collectionIds"].as_array().is_none_or(Vec::is_empty));
    let model: bitwarden_api_api::models::CipherDetailsResponseModel =
        serde_json::from_value(model).unwrap();
    let cipher = bitwarden_vault::Cipher::try_from(model).unwrap();
    let view = official
        .vault()
        .ciphers()
        .decrypt(cipher.clone())
        .await
        .unwrap();
    assert_eq!(view.name, "Banque");
    assert!(view.organization_id.is_none());
    let login = view.login.clone().unwrap();
    assert_eq!(login.password.as_deref(), Some("nouveau-secret"));
    assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    let rules: Vec<_> = login.uris.unwrap().iter().map(|u| u.r#match).collect();
    assert_eq!(
        rules,
        [Some(UriMatchType::Host), Some(UriMatchType::StartsWith)]
    );
    assert_eq!(login.fido2_credentials.unwrap().len(), 1);
    assert_eq!(view.password_history.as_ref().unwrap().len(), 1);
    assert_eq!(view.fields.as_ref().unwrap().len(), 2);
    // The attachment, downloaded and decrypted by the official client.
    let attachment = view.attachments.clone().unwrap().remove(0);
    let http = reqwest::Client::new();
    let meta: Value = http
        .get(format!(
            "{server}/api/ciphers/{new_id}/attachment/{}",
            attachment.id.clone().unwrap()
        ))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut url = meta["url"].as_str().unwrap().to_owned();
    if url.starts_with('/') {
        url = format!("{server}{url}");
    }
    let encrypted = http.get(url).send().await.unwrap().bytes().await.unwrap();
    let plain = official
        .vault()
        .attachments()
        .decrypt_buffer(cipher, attachment, &encrypted)
        .unwrap();
    assert_eq!(plain, contrat);

    // The member no longer sees the item (out of the organization).
    let vault = member.sync().await.unwrap().unwrap();
    assert!(vault.items.iter().all(|i| i.title != "Banque"));
}

/// The account's equivalent domains (`/api/settings/domains`): read at
/// sync, excluded groups included, and honoured by the "domain"
/// rule.
#[tokio::test]
async fn equivalent_domains_are_read_and_honoured() {
    let Some(server) = server() else {
        return;
    };
    let email = unique_email("domaines");
    let mut connection = account(&server, &email).await;
    let (_, _, access) = official_client(&server, &email).await;
    let http = reqwest::Client::new();
    let current: Value = http
        .get(format!("{server}/api/settings/domains"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let globals = current["globalEquivalentDomains"].as_array().unwrap();
    let google = globals
        .iter()
        .find(|g| {
            g["domains"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d == "youtube.com")
        })
        .unwrap();
    http.post(format!("{server}/api/settings/domains"))
        .bearer_auth(&access)
        .json(&serde_json::json!({
            "equivalentDomains": [["exemple.fr", "exemple-banque.com"]],
            "excludedGlobalEquivalentDomains": [google["type"]],
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let (_, vault) = connection
        .create(Draft {
            name: "Exemple".to_owned(),
            login: Some(LoginDraft {
                uris: vec!["https://compte.exemple.fr".to_owned()],
                ..LoginDraft::default()
            }),
            ..Draft::default()
        })
        .await
        .unwrap();
    // Read at login (global groups), read again at sync.
    assert!(
        vault
            .equivalent_domains
            .iter()
            .all(|g| !g.contains(&"exemple.fr".to_owned())),
        "not read again yet"
    );
    assert!(!vault.equivalent_domains.is_empty(), "read at login");
    let vault = connection.sync().await.unwrap().expect("domains changed");
    let groups = &vault.equivalent_domains;
    assert_eq!(groups[0], ["exemple.fr", "exemple-banque.com"]);
    assert!(
        groups.iter().all(|g| !g.iter().any(|d| d == "youtube.com")),
        "global group excluded"
    );
    assert!(groups.len() > 10, "server global groups");
    let rules = verrou_core::MatchRules {
        equivalent_domains: vault.equivalent_domains.clone(),
        ..verrou_core::MatchRules::default()
    };
    let items = vault.items.clone();
    let core = verrou_core::Vault::new(items).with_match_rules(rules);
    let found: Vec<&str> = core
        .suggestions_for("https://www.exemple-banque.com/login")
        .iter()
        .map(|i| i.title.as_str())
        .collect();
    assert_eq!(found, ["Exemple"]);
    // Nothing new: the next sync does not decrypt again.
    assert!(connection.sync().await.unwrap().is_none());
}
