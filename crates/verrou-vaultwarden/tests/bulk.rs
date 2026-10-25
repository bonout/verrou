//! Bulk actions (selection of several items) against a real Vaultwarden:
//! see `server.rs` to start the server. Without `VERROU_TEST_SERVER`, the
//! tests do nothing.
//!
//! "Offline": the saved account points at a closed port on the machine,
//! then the vault is reopened (as after a lock). The network coming back
//! restores the right address and reopens the vault: the outbox must have
//! survived, encrypted, and go out on sync.

use std::num::NonZeroU32;
use std::sync::Mutex;

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use verrou_core::{ItemState, SecretString};
use verrou_vaultwarden::{
    BulkAction, BulkOutcome, Connection, Decrypted, Draft, Error, LoginDraft, LoginStep, Skipped,
    Store, login, unlock_with_password,
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

fn item<'a>(vault: &'a Decrypted, id: &str) -> &'a verrou_core::Item {
    vault.items.iter().find(|i| i.id == id).unwrap()
}

fn state(vault: &Decrypted, id: &str) -> ItemState {
    item(vault, id).state
}

/// The bulk action, with the progress recorded.
async fn bulk(
    connection: &mut Connection,
    ids: &[&String],
    action: BulkAction,
) -> (BulkOutcome, Vec<(usize, usize)>) {
    let steps = Mutex::new(Vec::new());
    let ids: Vec<String> = ids.iter().map(|id| (*id).clone()).collect();
    let outcome = connection
        .bulk(&ids, &action, &|done, total| {
            steps.lock().unwrap().push((done, total));
        })
        .await
        .unwrap();
    (outcome, steps.into_inner().unwrap())
}

/// Four items, sent: their ids on the server.
async fn four_items(connection: &mut Connection) -> [String; 4] {
    let mut ids = Vec::new();
    for name in ["Banque", "GitHub", "Impôts", "Mutuelle"] {
        ids.push(connection.create(login_draft(name, "x")).await.unwrap().0);
    }
    sent(connection).await;
    ids.iter()
        .map(|id| connection.resolve(id))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Sends the outbox (what the app does right after a write): everything
/// goes, nothing is refused.
async fn sent(connection: &mut Connection) -> Decrypted {
    let vault = connection
        .sync()
        .await
        .unwrap()
        .expect("the outbox was sent");
    let report = connection.take_report();
    assert!(
        report.conflicts.is_empty() && report.rejected.is_empty(),
        "{report:?}"
    );
    assert_eq!(vault.pending_changes, 0);
    vault
}

#[tokio::test]
async fn bulk_actions_use_the_grouped_routes_and_skip_what_does_not_apply() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut connection, _) = sign_in(&store, &server, &email).await;
    let [a, b, c, d] = four_items(&mut connection).await;

    // Archive three items: right away in the displayed vault, then one
    // request and a sync.
    let (outcome, steps) = bulk(&mut connection, &[&a, &b, &c, &b], BulkAction::Archive).await;
    assert_eq!(outcome.done, 3, "the duplicate counts only once");
    assert!(outcome.skipped.is_empty() && outcome.failed.is_empty());
    assert_eq!(outcome.queued, 3);
    assert_eq!(steps.last(), Some(&(3, 3)));
    for id in [&a, &b, &c] {
        assert_eq!(state(&outcome.vault, id), ItemState::Archived);
    }
    assert_eq!(state(&outcome.vault, &d), ItemState::Active);
    let vault = sent(&mut connection).await;
    assert_eq!(state(&vault, &b), ItemState::Archived);

    // Unarchive: already active, `d` counts as done without a request.
    let (outcome, _) = bulk(&mut connection, &[&a, &d], BulkAction::Unarchive).await;
    assert_eq!((outcome.done, outcome.queued), (2, 1));
    assert_eq!(state(&outcome.vault, &a), ItemState::Active);
    assert_eq!(state(&outcome.vault, &b), ItemState::Archived);
    sent(&mut connection).await;

    // Favorites: one item at a time (no bulk route).
    let (outcome, steps) = bulk(&mut connection, &[&a, &c, &d], BulkAction::Favorite(true)).await;
    assert_eq!(outcome.done, 3);
    assert_eq!(steps, [(1, 3), (2, 3), (3, 3)]);
    assert!(
        [&a, &c, &d]
            .iter()
            .all(|id| item(&outcome.vault, id).favorite)
    );
    sent(&mut connection).await;

    // Folder: created, then three items moved in one request.
    let (folder, _) = connection.create_folder(" Administratif ").await.unwrap();
    let (outcome, _) = bulk(
        &mut connection,
        &[&a, &b, &c],
        BulkAction::MoveToFolder(Some(folder.clone())),
    )
    .await;
    assert_eq!(outcome.done, 3);
    for id in [&a, &b, &c] {
        assert_eq!(
            item(&outcome.vault, id).folder.as_deref(),
            Some("Administratif")
        );
    }
    let vault = sent(&mut connection).await;
    assert_eq!(item(&vault, &b).folder.as_deref(), Some("Administratif"));
    let (outcome, _) = bulk(&mut connection, &[&c], BulkAction::MoveToFolder(None)).await;
    assert_eq!(item(&outcome.vault, &c).folder, None);
    sent(&mut connection).await;
    let unknown = connection
        .bulk(
            std::slice::from_ref(&a),
            &BulkAction::MoveToFolder(Some(uuid::Uuid::new_v4().to_string())),
            &|_, _| {},
        )
        .await;
    assert!(matches!(unknown, Err(Error::Invalid(_))));

    // Trash, then archive: the trashed item is skipped.
    let (outcome, _) = bulk(&mut connection, &[&a, &b], BulkAction::Trash).await;
    assert_eq!(outcome.done, 2);
    assert_eq!(state(&outcome.vault, &a), ItemState::Trashed);
    assert_eq!(state(&outcome.vault, &b), ItemState::Trashed);
    sent(&mut connection).await;
    let gone = uuid::Uuid::new_v4().to_string();
    let (outcome, _) = bulk(&mut connection, &[&a, &c, &gone], BulkAction::Archive).await;
    assert_eq!(outcome.done, 1);
    assert_eq!(
        outcome.skipped,
        [
            (a.clone(), Skipped::InTrash),
            (gone.clone(), Skipped::NotFound)
        ]
    );
    assert_eq!(state(&outcome.vault, &c), ItemState::Archived);
    assert_eq!(outcome.queued, 0, "already archived: nothing to send");

    // Restore both in one request.
    let (outcome, _) = bulk(&mut connection, &[&a, &b], BulkAction::Restore).await;
    assert_eq!(outcome.done, 2);
    assert_ne!(state(&outcome.vault, &a), ItemState::Trashed);
    assert_ne!(state(&outcome.vault, &b), ItemState::Trashed);
    let vault = sent(&mut connection).await;
    assert_ne!(state(&vault, &b), ItemState::Trashed);

    // Another device sees the same vault.
    let other = temp_store();
    let (_, seen) = sign_in(&other, &server, &email).await;
    assert_eq!(state(&seen, &c), ItemState::Archived);
    assert!(item(&seen, &d).favorite);
    assert_eq!(item(&seen, &a).folder.as_deref(), Some("Administratif"));
    std::fs::remove_dir_all(store.dir()).unwrap();
    std::fs::remove_dir_all(other.dir()).unwrap();
}

#[tokio::test]
async fn offline_bulk_actions_wait_in_the_outbox_then_reach_the_server() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut online, _) = sign_in(&store, &server, &email).await;
    let [a, b, c, d] = four_items(&mut online).await;
    let (folder, _) = online.create_folder("Maison").await.unwrap();
    drop(online);

    let (mut offline, _) = reopen(&store, &dead_server()).await;
    let (outcome, _) = bulk(&mut offline, &[&a, &b], BulkAction::Archive).await;
    assert_eq!((outcome.done, outcome.queued), (2, 2));
    assert_eq!(state(&outcome.vault, &a), ItemState::Archived);
    let (outcome, _) = bulk(&mut offline, &[&c, &d], BulkAction::Favorite(true)).await;
    assert_eq!(outcome.queued, 2);
    let (outcome, _) = bulk(
        &mut offline,
        &[&c],
        BulkAction::MoveToFolder(Some(folder.clone())),
    )
    .await;
    assert_eq!(outcome.queued, 1);
    assert_eq!(item(&outcome.vault, &c).folder.as_deref(), Some("Maison"));
    assert!(item(&outcome.vault, &c).favorite, "both changes");
    let (outcome, _) = bulk(&mut offline, &[&d], BulkAction::Trash).await;
    assert_eq!(state(&outcome.vault, &d), ItemState::Trashed);
    // Archives (2), favorites (2), folder, trash.
    assert_eq!(offline.pending_changes(), 6);
    let file = std::fs::read_to_string(store.dir().join("outbox.json")).unwrap();
    assert!(!file.contains("Mutuelle") && !file.contains("Impôts"));
    drop(offline);

    let (mut reconnected, _) = reopen(&store, &server).await;
    let vault = reconnected.sync().await.unwrap().unwrap();
    let report = reconnected.take_report();
    assert_eq!(report.sent, 6);
    assert!(report.conflicts.is_empty() && report.rejected.is_empty());
    assert_eq!(vault.pending_changes, 0);

    let other = temp_store();
    let (_, seen) = sign_in(&other, &server, &email).await;
    assert_eq!(state(&seen, &a), ItemState::Archived);
    assert_eq!(state(&seen, &b), ItemState::Archived);
    assert!(item(&seen, &c).favorite);
    assert_eq!(item(&seen, &c).folder.as_deref(), Some("Maison"));
    assert_eq!(state(&seen, &d), ItemState::Trashed);
    std::fs::remove_dir_all(store.dir()).unwrap();
    std::fs::remove_dir_all(other.dir()).unwrap();
}

fn folder_names(vault: &Decrypted) -> Vec<&str> {
    vault
        .folders
        .iter()
        .map(|(_, name)| name.as_str())
        .collect()
}

#[tokio::test]
async fn folders_are_created_renamed_with_their_subfolders_and_deleted() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut connection, _) = sign_in(&store, &server, &email).await;
    let [a, b, ..] = four_items(&mut connection).await;

    // An empty folder exists right away; bad names are refused.
    let (work, vault) = connection.create_folder("Work").await.unwrap();
    assert_eq!(folder_names(&vault), ["Work"]);
    for bad in ["", "a//b", "/a", "a/"] {
        assert!(matches!(
            connection.create_folder(bad).await,
            Err(Error::Invalid(_))
        ));
    }
    let (clients, _) = connection.create_folder("Work/Clients").await.unwrap();
    let (home, _) = connection.create_folder("Home").await.unwrap();
    let (outcome, _) = bulk(
        &mut connection,
        &[&a],
        BulkAction::MoveToFolder(Some(work.clone())),
    )
    .await;
    assert_eq!(item(&outcome.vault, &a).folder.as_deref(), Some("Work"));
    sent(&mut connection).await;
    let (outcome, _) = bulk(
        &mut connection,
        &[&b],
        BulkAction::MoveToFolder(Some(clients.clone())),
    )
    .await;
    assert_eq!(
        item(&outcome.vault, &b).folder.as_deref(),
        Some("Work/Clients")
    );
    sent(&mut connection).await;

    // Refusals: a taken name, an unknown folder, an empty name.
    let taken = connection.rename_folder(&work, "Home").await;
    assert!(matches!(&taken, Err(Error::Invalid(m)) if m.contains("already exists")));
    assert!(matches!(
        connection.rename_folder(&work, " ").await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        connection
            .rename_folder(&uuid::Uuid::new_v4().to_string(), "X")
            .await,
        Err(Error::NotFound)
    ));

    // Renaming the parent renames the subfolder, items stay filed.
    let vault = connection.rename_folder(&work, "Job").await.unwrap();
    assert_eq!(folder_names(&vault), ["Home", "Job", "Job/Clients"]);
    assert_eq!(item(&vault, &a).folder.as_deref(), Some("Job"));
    assert_eq!(item(&vault, &b).folder.as_deref(), Some("Job/Clients"));

    // Deleting without the subfolders keeps them; the items are unfiled.
    let (unfiled, vault) = connection.delete_folder(&work, false).await.unwrap();
    assert_eq!(unfiled, 1);
    assert_eq!(folder_names(&vault), ["Home", "Job/Clients"]);
    assert_eq!(item(&vault, &a).folder, None);
    assert_eq!(item(&vault, &b).folder.as_deref(), Some("Job/Clients"));

    // With the subfolders: gone too, items kept.
    let (job, _) = connection.create_folder("Job").await.unwrap();
    let (unfiled, vault) = connection.delete_folder(&job, true).await.unwrap();
    assert_eq!(unfiled, 1);
    assert_eq!(folder_names(&vault), ["Home"]);
    assert_eq!(item(&vault, &b).folder, None);
    assert!(matches!(
        connection.delete_folder(&job, true).await,
        Err(Error::NotFound)
    ));
    let (unfiled, _) = connection.delete_folder(&home, false).await.unwrap();
    assert_eq!(unfiled, 0);

    // Another device sees the same folders.
    let other = temp_store();
    let (_, seen) = sign_in(&other, &server, &email).await;
    assert_eq!(folder_names(&seen).len(), 0);
    std::fs::remove_dir_all(store.dir()).unwrap();
    std::fs::remove_dir_all(other.dir()).unwrap();
}
