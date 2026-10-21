//! Offline edits against a real Vaultwarden: see `server.rs` to start the
//! server. Without `VERROU_TEST_SERVER`, the tests do nothing.
//!
//! "Offline": the saved account points at a closed port on the machine,
//! then the vault is reopened (as after a lock). The network coming back
//! restores the right address and reopens the vault: the outbox must have
//! survived, encrypted, and go out on sync.

use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use verrou_core::{ItemState, SecretString};
use verrou_vaultwarden::{
    CONFLICT_SUFFIX, Connection, Decrypted, Draft, Error, LoginDraft, LoginStep, Store, login,
    unlock_with_password,
};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER not set: test skipped");
    }
    server
}

fn temp_store() -> Store {
    Store::new(std::env::temp_dir().join(format!("verrou-it-{}", uuid::Uuid::new_v4())))
}

async fn register(server: &str) -> String {
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
    assert!(response.status().is_success(), "registration refused");
    email
}

/// The account, signed in by Verrou in `store`.
async fn sign_in(store: &Store, server: &str, email: &str) -> (Connection, Decrypted) {
    match login(store, server, email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => (unlocked.connection, unlocked.vault),
        LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
    }
}

/// An address where nothing listens: connection refused right away.
fn dead_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// Reopens the vault (as after a lock), pointing at `server`.
async fn reopen(store: &Store, server: &str) -> (Connection, Decrypted) {
    let mut account = store.load_account().unwrap().unwrap();
    server.clone_into(&mut account.server);
    store.save_account(&account).unwrap();
    let unlocked = unlock_with_password(store, &SecretString::new(PASSWORD))
        .await
        .unwrap();
    (unlocked.connection, unlocked.vault)
}

fn login_draft(name: &str, password: &str) -> Draft {
    Draft {
        name: name.to_owned(),
        login: Some(LoginDraft {
            uri_matches: None,
            username: Some("camille".to_owned()),
            password: Some(SecretString::new(password)),
            totp: None,
            uris: vec!["https://exemple.fr".to_owned()],
        }),
        ..Draft::default()
    }
}

/// Sends the outbox, like the app right after a write; returns the
/// server ids of `ids` (created under a temporary id).
async fn sent<const N: usize>(connection: &mut Connection, ids: [&str; N]) -> [String; N] {
    connection.sync().await.unwrap();
    let report = connection.take_report();
    assert!(report.rejected.is_empty() && report.conflicts.is_empty());
    assert_eq!(connection.pending_changes(), 0);
    ids.map(|id| connection.resolve(id))
}

fn password(vault: &Decrypted, id: &str) -> String {
    vault
        .items
        .iter()
        .find(|i| i.id == id)
        .unwrap()
        .field("password")
        .unwrap()
        .value
        .expose()
        .to_owned()
}

#[tokio::test]
async fn offline_edits_wait_encrypted_then_reach_the_server() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut online, _) = sign_in(&store, &server, &email).await;
    let (github, _) = online
        .create(login_draft("GitHub", "en-ligne"))
        .await
        .unwrap();
    let (notes, _) = online
        .create(Draft {
            name: "Digicode".to_owned(),
            notes: Some(SecretString::new("4521B")),
            ..Draft::default()
        })
        .await
        .unwrap();
    let [github, notes] = sent(&mut online, [&github, &notes]).await;
    drop(online);

    // Offline: edit, create, trash, favorite.
    let (mut offline, _) = reopen(&store, &dead_server()).await;
    let mut draft = offline.draft(&github).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("hors-ligne-1"));
    let vault = offline.update(&github, draft).await.unwrap();
    assert_eq!(password(&vault, &github), "hors-ligne-1");
    assert_eq!(vault.pending_items, std::slice::from_ref(&github));

    let (temporary, vault) = offline
        .create(login_draft("Créé hors ligne", "secret-du-train"))
        .await
        .unwrap();
    assert_eq!(password(&vault, &temporary), "secret-du-train");
    let vault = offline.trash(&notes).await.unwrap();
    let state =
        |vault: &Decrypted, id: &str| vault.items.iter().find(|i| i.id == id).map(|i| i.state);
    assert_eq!(state(&vault, &notes), Some(ItemState::Trashed));
    let vault = offline.set_favorite(&temporary, true).await.unwrap();
    assert!(
        vault
            .items
            .iter()
            .find(|i| i.id == temporary)
            .unwrap()
            .favorite
    );
    // The creation and its favorite make a single pending change.
    assert_eq!(vault.pending_changes, 3);
    assert_eq!(offline.pending_changes(), 3);
    assert_eq!(store.pending_changes(), 3, "readable without unlocking");

    // What only works with the server is refused clearly.
    match offline.add_attachment(&github, "a.txt", b"x").await {
        Err(Error::Invalid(message)) => assert!(message.contains("offline"), "{message}"),
        other => panic!("unexpected: {:?}", other.err()),
    }
    assert!(matches!(offline.sync().await, Err(Error::Network(_))));

    // The outbox is on disk, encrypted.
    let file = std::fs::read_to_string(store.dir().join("outbox.json")).unwrap();
    for secret in [
        "hors-ligne-1",
        "secret-du-train",
        "Créé hors ligne",
        "GitHub",
        "camille",
    ] {
        assert!(
            !file.contains(secret),
            "`{secret}` in plain text in the outbox"
        );
    }
    drop(offline);

    // Locked then reopened, still offline: nothing is lost.
    let (offline, vault) = reopen(&store, &dead_server()).await;
    assert_eq!(password(&vault, &github), "hors-ligne-1");
    assert_eq!(offline.pending_changes(), 3);
    drop(offline);

    // Network back: the outbox goes out before the vault is read.
    let (mut reconnected, _) = reopen(&store, &server).await;
    let vault = reconnected
        .sync()
        .await
        .unwrap()
        .expect("the vault changed");
    let report = reconnected.take_report();
    assert_eq!(report.sent, 3);
    assert!(report.conflicts.is_empty() && report.rejected.is_empty());
    let [(from, created)] = report.remapped.as_slice() else {
        panic!("one creation expected: {:?}", report.remapped)
    };
    assert_eq!(from, &temporary);
    assert_ne!(created, &temporary);
    assert_eq!(reconnected.resolve(&temporary), *created);
    assert_eq!(vault.pending_changes, 0);
    assert_eq!(vault.pending_items, Vec::<String>::new());
    assert!(!store.dir().join("outbox.json").exists());
    assert_eq!(password(&vault, created), "secret-du-train");
    assert!(vault.items.iter().all(|i| i.id != temporary));

    seen_elsewhere(&server, &email, &github, created, &notes).await;
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Another device sees everything done offline.
async fn seen_elsewhere(server: &str, email: &str, github: &str, created: &str, notes: &str) {
    let other = temp_store();
    let (_, seen) = sign_in(&other, server, email).await;
    assert_eq!(password(&seen, github), "hors-ligne-1");
    assert_eq!(password(&seen, created), "secret-du-train");
    let item = |id: &str| seen.items.iter().find(|i| i.id == id).unwrap();
    assert!(item(created).favorite);
    assert_eq!(item(notes).state, ItemState::Trashed);
    // The old password went into the history, as online.
    assert!(
        item(github)
            .field("history-0")
            .is_some_and(|f| f.value.expose() == "en-ligne")
    );
    std::fs::remove_dir_all(other.dir()).unwrap();
}

#[tokio::test]
async fn an_item_changed_elsewhere_meanwhile_keeps_both_versions() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut online, _) = sign_in(&store, &server, &email).await;
    let (bank, _) = online.create(login_draft("Banque", "avant")).await.unwrap();
    let [bank] = sent(&mut online, [&bank]).await;
    drop(online);
    let other = temp_store();
    let (mut elsewhere, _) = sign_in(&other, &server, &email).await;

    let (mut offline, _) = reopen(&store, &dead_server()).await;
    let mut draft = offline.draft(&bank).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("version-locale"));
    offline.update(&bank, draft).await.unwrap();
    drop(offline);

    // Meanwhile, another device edits the same item.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut draft = elsewhere.draft(&bank).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("version-serveur"));
    elsewhere.update(&bank, draft).await.unwrap();
    sent(&mut elsewhere, []).await;

    let (mut reconnected, _) = reopen(&store, &server).await;
    let vault = reconnected.sync().await.unwrap().unwrap();
    let report = reconnected.take_report();
    let copy_title = format!("Banque{CONFLICT_SUFFIX}");
    assert_eq!(report.conflicts, std::slice::from_ref(&copy_title));
    assert_eq!(
        password(&vault, &bank),
        "version-serveur",
        "the server version comes back"
    );
    let copy = vault.items.iter().find(|i| i.title == copy_title).unwrap();
    assert_eq!(
        password(&vault, &copy.id),
        "version-locale",
        "the local version is kept"
    );
    assert_eq!(vault.pending_changes, 0);

    // On the server too.
    let seen = elsewhere.sync().await.unwrap().unwrap();
    assert_eq!(password(&seen, &copy.id), "version-locale");
    assert_eq!(password(&seen, &bank), "version-serveur");

    std::fs::remove_dir_all(store.dir()).unwrap();
    std::fs::remove_dir_all(other.dir()).unwrap();
}

/// An offline creation edited before it is sent goes in one go, with
/// its edit; the archive follows, under the server id.
#[tokio::test]
async fn a_creation_edited_before_it_is_sent_goes_as_one() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    drop(sign_in(&store, &server, &email).await);

    let (mut offline, _) = reopen(&store, &dead_server()).await;
    let (temporary, _) = offline
        .create(login_draft("Wi-Fi du gîte", "lilas"))
        .await
        .unwrap();
    let vault = offline.set_archived(&temporary, true).await.unwrap();
    assert_eq!(vault.pending_changes, 2);
    drop(offline);

    let (mut reconnected, vault) = reopen(&store, &server).await;
    assert_eq!(vault.pending_items, std::slice::from_ref(&temporary));
    // The editor was opened on the temporary id.
    let mut draft = reconnected.draft(&temporary).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("glycine"));
    let vault = reconnected.update(&temporary, draft).await.unwrap();
    assert_eq!(password(&vault, &temporary), "glycine", "right away");
    assert_eq!(vault.pending_changes, 2, "the creation keeps its edit");

    let vault = reconnected.sync().await.unwrap().unwrap();
    let id = reconnected.resolve(&temporary);
    assert_ne!(id, temporary);
    let item = vault.items.iter().find(|i| i.id == id).unwrap();
    assert_eq!(item.state, ItemState::Archived);
    assert_eq!(password(&vault, &id), "glycine");
    assert_eq!(vault.pending_changes, 0);
    let report = reconnected.take_report();
    assert_eq!(report.remapped, [(temporary, id)]);
    assert_eq!(report.sent, 2, "they had waited for the server");

    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Offline merge: the kept item and the trash wait in the outbox, then
/// go out when the network is back.
#[tokio::test]
async fn merging_duplicates_offline_waits_then_reaches_the_server() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut online, _) = sign_in(&store, &server, &email).await;
    let (kept, _) = online
        .create(login_draft("Exemple", "commun"))
        .await
        .unwrap();
    let mut copy = login_draft("exemple.fr", "commun");
    copy.notes = Some(SecretString::new("question secrète : Lilas"));
    copy.login.as_mut().unwrap().uris = vec!["https://login.exemple.fr/".to_owned()];
    let (other, _) = online.create(copy).await.unwrap();
    let [kept, other] = sent(&mut online, [&kept, &other]).await;
    drop(online);

    let (mut offline, _) = reopen(&store, &dead_server()).await;
    let outcome = offline
        .merge_duplicates(&kept, std::slice::from_ref(&other))
        .await
        .unwrap();
    assert_eq!(outcome.summary.notes, 1);
    let state =
        |vault: &Decrypted, id: &str| vault.items.iter().find(|i| i.id == id).map(|i| i.state);
    assert_eq!(state(&outcome.vault, &other), Some(ItemState::Trashed));
    let merged = outcome.vault.items.iter().find(|i| i.id == kept).unwrap();
    assert_eq!(
        merged.notes.as_ref().map(SecretString::expose),
        Some("question secrète : Lilas")
    );
    assert_eq!(offline.pending_changes(), 2);
    drop(offline);

    let (mut reconnected, _) = reopen(&store, &server).await;
    let vault = reconnected
        .sync()
        .await
        .unwrap()
        .expect("the vault changed");
    let report = reconnected.take_report();
    assert_eq!(report.sent, 2);
    assert!(report.conflicts.is_empty() && report.rejected.is_empty());
    assert_eq!(state(&vault, &other), Some(ItemState::Trashed));
    let merged = vault.items.iter().find(|i| i.id == kept).unwrap();
    assert!(merged.notes.is_some());
    std::fs::remove_dir_all(store.dir()).unwrap();
}
