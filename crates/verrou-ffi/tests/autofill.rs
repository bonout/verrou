//! The iOS `AutoFill` extension (guest session) against a real Vaultwarden,
//! next to the app that shares its folder. Without `VERROU_TEST_SERVER`,
//! the tests do nothing.

mod common;

use common::{PASSWORD, register, server};
use sha2::{Digest as _, Sha256};
use verrou_ffi::{
    AutofillIdentityKind, ItemDraft, LoginFields, LoginResult, PasskeyCreationRequest, VaultSession,
};

fn login(name: &str, url: &str) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        login: Some(LoginFields {
            url_matches: None,
            username: Some("camille@exemple.fr".to_owned()),
            password: Some("mot-de-passe-du-site".to_owned()),
            totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
            urls: vec![url.to_owned()],
        }),
        ..ItemDraft::default()
    }
}

async fn guest(dir: &str) -> std::sync::Arc<VaultSession> {
    let guest = VaultSession::for_autofill(dir.to_owned());
    guest
        .unlock_with_password(PASSWORD.to_owned())
        .await
        .unwrap();
    guest
}

/// The extension sees the app's changes not yet sent, creates and uses a
/// passkey directly on the server, and never touches the app's queue: the
/// app then sends it only once.
#[tokio::test(flavor = "multi_thread")]
async fn the_extension_writes_passkeys_without_touching_the_app_outbox() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let dir = std::env::temp_dir().join(format!("verrou-autofill-{}", uuid::Uuid::new_v4()));
    let dir = dir.display().to_string();
    let app = VaultSession::with_storage(dir.clone());
    let result = app.login(server, email, PASSWORD.to_owned()).await.unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));

    // A change from the app, in its queue, not yet sent.
    let pending = app
        .create_item(login("Exemple", "https://www.exemple.fr/connexion"))
        .await
        .unwrap();
    assert_eq!(app.pending_changes(), 1);
    let outbox = std::path::Path::new(&dir).join("outbox.json");
    let before = std::fs::read(&outbox).unwrap();

    // The extension sees it and fills it.
    let extension = guest(&dir).await;
    let matches = extension
        .autofill_matches(vec!["exemple.fr".to_owned()])
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, pending);
    let password = extension.autofill_password(pending.clone()).unwrap();
    assert_eq!(password.username, "camille@exemple.fr");
    assert_eq!(password.password, "mot-de-passe-du-site");
    let identities = extension.autofill_identities().unwrap();
    assert!(
        identities
            .iter()
            .any(|i| i.kind == AutofillIdentityKind::OneTimeCode)
    );

    // Creating a passkey for `localhost`, in a new login.
    let hash = Sha256::digest(b"clientDataJSON de la creation").to_vec();
    let created = extension
        .passkey_registration(PasskeyCreationRequest {
            rp_id: "localhost".to_owned(),
            user_name: "camille".to_owned(),
            user_handle: b"utilisateur-7".to_vec(),
            client_data_hash: hash,
            user_verified: true,
            item_id: None,
            excluded_credentials: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(created.credential_id.len(), 16);
    assert!(
        created
            .attestation_object
            .starts_with(b"\xa3\x63fmt\x64none")
    );

    // The app's queue hasn't moved (neither sent nor rewritten).
    assert_eq!(std::fs::read(&outbox).unwrap(), before);

    // Excluded by the site: no second passkey.
    let refused = extension
        .passkey_registration(PasskeyCreationRequest {
            rp_id: "localhost".to_owned(),
            user_name: "camille".to_owned(),
            user_handle: b"utilisateur-7".to_vec(),
            client_data_hash: vec![1; 32],
            user_verified: true,
            item_id: None,
            excluded_credentials: vec![created.credential_id.clone()],
        })
        .await;
    assert!(refused.is_err());

    // Sign-in with the passkey: counter 1, saved before the response.
    let sign = |session: std::sync::Arc<VaultSession>, n: u8| {
        let credential = created.credential_id.clone();
        async move {
            session
                .passkey_assertion("localhost".to_owned(), credential, vec![n; 32], true)
                .await
                .unwrap()
        }
    };
    let first = sign(std::sync::Arc::clone(&extension), 1).await;
    assert_eq!(&first.authenticator_data[33..37], &1u32.to_be_bytes());
    assert_eq!(first.user_handle, b"utilisateur-7");
    assert_eq!(first.item_id, created.item_id);

    // A new extension (new process) starts from the saved cache: the
    // counter goes on.
    let next = guest(&dir).await;
    let second = sign(next, 2).await;
    assert_eq!(&second.authenticator_data[33..37], &2u32.to_be_bytes());
    assert_eq!(std::fs::read(&outbox).unwrap(), before);

    // The app sends its queue once, then sees the extension's passkey.
    app.sync().await.unwrap();
    assert_eq!(app.pending_changes(), 0);
    let titles: Vec<String> = app
        .summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(
        titles.iter().filter(|t| *t == "Exemple").count(),
        1,
        "{titles:?}"
    );
    let passkeys = app.passkeys(created.item_id.clone());
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].rp_id, "localhost");

    // After the app's sync, the extension still sees the counter.
    let third = sign(guest(&dir).await, 3).await;
    assert_eq!(&third.authenticator_data[33..37], &3u32.to_be_bytes());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Conditional creation: the key is prepared during the fill (extension,
/// vault open), the background request arrives in a new process with the
/// vault closed, then the app files the passkey into the login on its next
/// sync. The password stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_conditional_passkey_joins_the_filled_login_later() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let dir = std::env::temp_dir().join(format!("verrou-conditional-{}", uuid::Uuid::new_v4()));
    let dir = dir.display().to_string();
    let app = VaultSession::with_storage(dir.clone());
    let result = app.login(server, email, PASSWORD.to_owned()).await.unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));
    app.create_item(login("Banc d'essai", "http://localhost:8080/"))
        .await
        .unwrap();
    app.sync().await.unwrap();
    // Id given by the server when the queue is sent.
    let id = app
        .summaries()
        .unwrap()
        .into_iter()
        .find(|s| s.title == "Banc d'essai")
        .unwrap()
        .id;

    // 1. Fill in the extension: the key is prepared.
    let extension = guest(&dir).await;
    extension.autofill_password(id.clone()).unwrap();
    assert!(extension.prepare_passkey_upgrade(id.clone()).await.unwrap());
    extension.lock();

    // 2. Background request, vault closed (new process).
    let background = VaultSession::for_autofill(dir.clone());
    let hash = Sha256::digest(b"clientDataJSON conditionnel").to_vec();
    let request = |user: &str| PasskeyCreationRequest {
        rp_id: "localhost".to_owned(),
        user_name: user.to_owned(),
        user_handle: b"utilisateur-9".to_vec(),
        client_data_hash: hash.clone(),
        user_verified: false,
        item_id: None,
        excluded_credentials: Vec::new(),
    };
    let created = background
        .conditional_passkey_registration(request("Camille@exemple.fr"))
        .unwrap();
    assert_eq!(created.item_id, id);
    // Neither presence nor verification in the flags.
    let auth_data_flags = created
        .attestation_object
        .windows(32)
        .position(|w| w == Sha256::digest(b"localhost").as_slice())
        .map(|at| created.attestation_object[at + 32])
        .unwrap();
    assert_eq!(auth_data_flags & 0x05, 0);
    assert_eq!(background.pending_passkeys(), 1);
    // Ticket consumed: a second request is refused.
    assert!(
        background
            .conditional_passkey_registration(request("camille@exemple.fr"))
            .is_err()
    );

    // 3. The app, vault open: the passkey joins the login.
    let titles = Box::pin(app.finish_pending_passkeys()).await.unwrap();
    assert_eq!(titles, vec!["Banc d'essai".to_owned()]);
    assert_eq!(app.pending_passkeys(), 0);
    let passkeys = app.passkeys(id.clone());
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].rp_id, "localhost");
    assert_eq!(passkeys[0].user_name.as_deref(), Some("Camille@exemple.fr"));
    // The password is still there.
    let filler = guest(&dir).await;
    assert_eq!(
        filler.autofill_password(id.clone()).unwrap().password,
        "mot-de-passe-du-site"
    );
    // The passkey signs, with the key whose public part the site received.
    let signed = filler
        .passkey_assertion(
            "localhost".to_owned(),
            created.credential_id.clone(),
            vec![4; 32],
            true,
        )
        .await
        .unwrap();
    assert_eq!(signed.user_handle, b"utilisateur-9");
    // The login now has a passkey: no more prepared key.
    assert!(!filler.prepare_passkey_upgrade(id).await.unwrap());
}
