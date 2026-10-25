//! Emergency access against a real Vaultwarden: see `server.rs` to start
//! the server. Without `VERROU_TEST_SERVER`, the tests do nothing.
//!
//! The test server has no mail: Vaultwarden then accepts the invitation
//! of an existing account immediately.

use std::num::NonZeroU32;

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use verrou_core::SecretString;
use verrou_vaultwarden::emergency::{EmergencyKind, EmergencyStatus};
use verrou_vaultwarden::{Connection, Draft, Error, LoginDraft, LoginStep, Store, login};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER not set: test skipped");
    }
    server
}

/// A new account, opened by Verrou; also returns its address.
async fn account(server: &str, name: &str) -> (Connection, String) {
    let email = format!("{}@verrou.test", uuid::Uuid::new_v4().simple());
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(ITERATIONS).unwrap(),
    };
    let keys = Client::new(None)
        .auth()
        .make_register_keys(email.clone(), PASSWORD.into(), kdf)
        .unwrap();
    let http = reqwest::Client::new();
    let token = http
        .post(format!(
            "{server}/identity/accounts/register/send-verification-email"
        ))
        .json(&json!({ "email": email, "name": name }))
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
    assert!(response.status().is_success(), "registration refused");
    let store =
        Store::new(std::env::temp_dir().join(format!("verrou-it-{}", uuid::Uuid::new_v4())));
    let connection = match login(&store, server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => unlocked.connection,
        LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
    };
    (connection, email)
}

/// A login in the vault, and an item in the trash.
async fn fill(camille: &mut Connection) {
    let (_, _) = camille
        .create(Draft {
            name: "Banque".to_owned(),
            notes: Some(SecretString::new("code agence 0042")),
            login: Some(LoginDraft {
                uri_matches: None,
                username: Some("camille".to_owned()),
                password: Some(SecretString::new("mot-de-passe-banque")),
                totp: None,
                uris: vec!["https://banque.exemple.fr".to_owned()],
            }),
            ..Draft::default()
        })
        .await
        .unwrap();
    let (trashed, _) = camille
        .create(Draft {
            name: "Ancien".to_owned(),
            ..Draft::default()
        })
        .await
        .unwrap();
    camille.trash(&trashed).await.unwrap();
    // Writes go out in the background: here, right away.
    camille.sync().await.unwrap();
}

#[tokio::test]
async fn invite_confirm_request_approve_and_view() {
    let Some(server) = server() else { return };
    let (mut camille, camille_email) = account(&server, "Camille").await;
    let (mut antonin, antonin_email) = account(&server, "Antonin").await;

    fill(&mut camille).await;

    // Invitation: without mail, accepted immediately.
    assert!(matches!(
        camille
            .invite_emergency_contact(&camille_email, EmergencyKind::View, 1)
            .await,
        Err(Error::Invalid(_))
    ));
    camille
        .invite_emergency_contact(&antonin_email, EmergencyKind::View, 1)
        .await
        .unwrap();
    let trusted = camille.emergency_access().await.unwrap().trusted;
    assert_eq!(trusted.len(), 1);
    let contact = &trusted[0];
    assert_eq!(contact.email.as_deref(), Some(antonin_email.as_str()));
    assert_eq!(contact.status, EmergencyStatus::Accepted);
    assert_eq!(contact.kind, EmergencyKind::View);
    assert_eq!(contact.wait_time_days, 1);
    let grantee_id = contact.user_id.clone().expect("contact accepted");
    assert_eq!(grantee_id, antonin.account().user_id);

    // Not confirmed yet: no request possible.
    let granted = antonin.emergency_access().await.unwrap().granted;
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].email.as_deref(), Some(camille_email.as_str()));
    assert!(
        antonin
            .request_emergency_access(&granted[0].id)
            .await
            .is_err()
    );

    // Confirmation, after checking the fingerprint. Another fingerprint is
    // refused without sending anything.
    let fingerprint = camille
        .emergency_contact_fingerprint(&grantee_id)
        .await
        .unwrap();
    // Five words, some of which have a hyphen of their own ("felt-tip").
    assert!(fingerprint.split('-').count() >= 5, "{fingerprint}");
    assert!(matches!(
        camille
            .confirm_emergency_contact(&contact.id, &grantee_id, "faux-faux-faux-faux-faux")
            .await,
        Err(Error::Crypto(_))
    ));
    assert_eq!(
        camille.emergency_access().await.unwrap().trusted[0].status,
        EmergencyStatus::Accepted
    );
    camille
        .confirm_emergency_contact(&contact.id, &grantee_id, &fingerprint)
        .await
        .unwrap();

    // Request, rejected by Camille; new request, approved.
    let id = granted[0].id.clone();
    antonin.request_emergency_access(&id).await.unwrap();
    assert_eq!(
        camille.emergency_access().await.unwrap().trusted[0].status,
        EmergencyStatus::RecoveryInitiated
    );
    assert!(
        antonin.open_grantor_vault(&id).await.is_err(),
        "not granted yet"
    );
    camille.reject_emergency_access(&id).await.unwrap();
    assert_eq!(
        antonin.emergency_access().await.unwrap().granted[0].status,
        EmergencyStatus::Confirmed
    );
    antonin.request_emergency_access(&id).await.unwrap();
    camille.approve_emergency_access(&id).await.unwrap();
    assert_eq!(
        antonin.emergency_access().await.unwrap().granted[0].status,
        EmergencyStatus::RecoveryApproved
    );

    // Read only: Camille's items, decrypted by Antonin.
    let vault = antonin.open_grantor_vault(&id).await.unwrap();
    assert_eq!(vault.failures, 0);
    assert_eq!(vault.items.len(), 1, "the trash stays with Camille");
    let item = &vault.items[0];
    assert_eq!(item.title, "Banque");
    assert_eq!(
        item.field("password").unwrap().value.expose(),
        "mot-de-passe-banque"
    );
    assert_eq!(
        item.notes.as_ref().map(SecretString::expose),
        Some("code agence 0042")
    );

    // Camille removes the access: Antonin has nothing left.
    camille.delete_emergency_access(&id).await.unwrap();
    assert!(antonin.emergency_access().await.unwrap().granted.is_empty());
    assert!(antonin.open_grantor_vault(&id).await.is_err());
}

#[tokio::test]
async fn takeover_contact_cannot_view_and_settings_change() {
    let Some(server) = server() else { return };
    let (mut camille, _) = account(&server, "Camille").await;
    let (mut lea, lea_email) = account(&server, "Léa").await;

    camille
        .invite_emergency_contact(&lea_email, EmergencyKind::Takeover, 7)
        .await
        .unwrap();
    let contact = camille.emergency_access().await.unwrap().trusted.remove(0);
    let grantee = contact.user_id.clone().unwrap();
    let fingerprint = camille
        .emergency_contact_fingerprint(&grantee)
        .await
        .unwrap();
    camille
        .confirm_emergency_contact(&contact.id, &grantee, &fingerprint)
        .await
        .unwrap();
    lea.request_emergency_access(&contact.id).await.unwrap();
    camille.approve_emergency_access(&contact.id).await.unwrap();
    // Takeover granted: read only is not part of it (Vaultwarden), and
    // Verrou does not do the takeover.
    assert!(lea.open_grantor_vault(&contact.id).await.is_err());

    // The grantor changes the type and the wait time.
    camille
        .update_emergency_contact(&contact.id, EmergencyKind::View, 3)
        .await
        .unwrap();
    let updated = camille.emergency_access().await.unwrap().trusted.remove(0);
    assert_eq!(updated.kind, EmergencyKind::View);
    assert_eq!(updated.wait_time_days, 3);
    assert!(
        camille
            .update_emergency_contact(&contact.id, EmergencyKind::View, 0)
            .await
            .is_err()
    );
}
