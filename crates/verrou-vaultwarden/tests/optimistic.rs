//! Écritures locales d'abord, envoyées ensuite, contre un vrai Vaultwarden
//! (voir `server.rs` pour lancer le serveur ; sans `VERROU_TEST_SERVER`, les
//! tests ne font rien).
//!
//! Le serveur est joint à travers un mandataire qui ajoute de la latence à
//! chaque aller-retour : une écriture doit rendre la main sans l'attendre,
//! l'envoi (`sync_shared`) la paie en arrière-plan.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use verrou_core::{ItemState, SecretString};
use verrou_vaultwarden::{
    CONFLICT_SUFFIX, Connection, Decrypted, Draft, LoginDraft, LoginStep, Store, Synced, login,
    sync_shared,
};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;
/// Latence ajoutée à chaque aller-retour avec le serveur.
const LATENCY: Duration = Duration::from_millis(400);
/// Une écriture locale : bien moins qu'un aller-retour.
const LOCAL: Duration = Duration::from_millis(250);

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
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
    assert!(response.status().is_success(), "inscription refusée");
    email
}

async fn sign_in(store: &Store, server: &str, email: &str) -> (Connection, Decrypted) {
    match login(store, server, email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => (unlocked.connection, unlocked.vault),
        LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
    }
}

/// Ce qu'un autre appareil voit sur le serveur.
async fn seen_elsewhere(server: &str, email: &str) -> Decrypted {
    let other = temp_store();
    let (_, seen) = sign_in(&other, server, email).await;
    std::fs::remove_dir_all(other.dir()).unwrap();
    seen
}

/// Un mandataire TCP vers `server` qui retarde chaque octet de `delay / 2`
/// dans chaque sens : `delay` de plus par aller-retour.
async fn slow(server: &str, delay: Duration) -> String {
    let port: u16 = server.rsplit(':').next().unwrap().parse().unwrap();
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(target).await else {
                    return;
                };
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::spawn(pipe(client_read, server_write, delay / 2));
                tokio::spawn(pipe(server_read, client_write, delay / 2));
            });
        }
    });
    format!("http://{address}")
}

async fn pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (sender, mut receiver) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, bytes)) = receiver.recv().await {
            tokio::time::sleep_until(at + delay).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = to.shutdown().await;
    });
    let mut buffer = vec![0; 64 * 1024];
    while let Ok(read) = from.read(&mut buffer).await {
        if read == 0
            || sender
                .send((tokio::time::Instant::now(), buffer[..read].to_vec()))
                .is_err()
        {
            break;
        }
    }
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

fn find<'a>(vault: &'a Decrypted, id: &str) -> Option<&'a verrou_core::Item> {
    vault.items.iter().find(|i| i.id == id)
}

fn password(vault: &Decrypted, id: &str) -> String {
    find(vault, id)
        .unwrap()
        .field("password")
        .unwrap()
        .value
        .expose()
        .to_owned()
}

/// L'envoi en arrière-plan, comme l'app après une écriture.
async fn drained(connection: &Arc<Mutex<Connection>>) -> Decrypted {
    match sync_shared(connection, false).await.unwrap() {
        Synced::Changed(vault) => vault,
        Synced::Unchanged | Synced::Joined => panic!("le coffre aurait dû changer"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_apply_at_once_and_reach_the_server_in_the_background() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (connection, _) = sign_in(&store, &slow(&server, LATENCY).await, &email).await;
    let connection = Arc::new(Mutex::new(connection));

    // Créer : un identifiant provisoire, tout de suite dans le coffre affiché.
    let start = Instant::now();
    let (temporary, vault) = connection
        .lock()
        .await
        .create(login_draft("Banque", "premier"))
        .await
        .unwrap();
    assert!(start.elapsed() < LOCAL, "{:?}", start.elapsed());
    assert_eq!(password(&vault, &temporary), "premier");
    assert_eq!(vault.pending_items, std::slice::from_ref(&temporary));
    assert_eq!(seen_elsewhere(&server, &email).await.items.len(), 0);

    // L'envoi : l'identifiant du serveur remplace le provisoire.
    let vault = drained(&connection).await;
    let mut open = connection.lock().await;
    let id = open.resolve(&temporary);
    assert_ne!(id, temporary);
    assert!(find(&vault, &temporary).is_none());
    assert_eq!(password(&vault, &id), "premier");
    assert_eq!(vault.pending_changes, 0);
    assert!(vault.remapped.contains(&(temporary.clone(), id.clone())));
    let report = open.take_report();
    assert_eq!(report.remapped, [(temporary.clone(), id.clone())]);
    assert_eq!(report.sent, 0, "envoyée aussitôt : rien à annoncer");
    // L'identifiant provisoire reste utilisable (éditeur ouvert avant).
    let mut draft = open.draft(&temporary).await.unwrap();
    draft.login.as_mut().unwrap().password = Some(SecretString::new("second"));

    // Modifier, archiver, modifier encore : appliqué tout de suite, envoyé
    // dans l'ordre (les modifications avant l'archive).
    let start = Instant::now();
    open.update(&temporary, draft).await.unwrap();
    open.set_archived(&id, true).await.unwrap();
    let mut draft = open.draft(&id).await.unwrap();
    draft.notes = Some(SecretString::new("agence 0042"));
    let vault = open.update(&id, draft).await.unwrap();
    assert!(start.elapsed() < LOCAL * 3, "{:?}", start.elapsed());
    assert_eq!(find(&vault, &id).unwrap().state, ItemState::Archived);
    assert_eq!(password(&vault, &id), "second");
    assert_eq!(vault.pending_changes, 2, "une modification, une archive");
    drop(open);

    let vault = drained(&connection).await;
    assert_eq!(vault.pending_changes, 0);
    let report = connection.lock().await.take_report();
    assert!(report.conflicts.is_empty() && report.rejected.is_empty());
    let seen = seen_elsewhere(&server, &email).await;
    let item = find(&seen, &id).unwrap();
    assert_eq!(item.state, ItemState::Archived);
    assert_eq!(password(&seen, &id), "second");
    assert_eq!(item.notes.as_ref().unwrap().expose(), "agence 0042");
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Une écriture faite pendant l'envoi de la précédente n'attend pas le
/// réseau, et ne passe pas pour périmée : elle repart de la date de
/// révision que le serveur vient de rendre (modification, puis archive).
#[tokio::test(flavor = "multi_thread")]
async fn a_write_made_during_a_send_neither_waits_nor_conflicts() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut connection, _) = sign_in(&store, &slow(&server, LATENCY).await, &email).await;
    let (id, _) = connection
        .create(login_draft("GitHub", "v0"))
        .await
        .unwrap();
    connection.sync().await.unwrap();
    let id = connection.resolve(&id);
    let connection = Arc::new(Mutex::new(connection));

    for step in 1..=2 {
        // 1 : une modification part ; 2 : une archive part.
        {
            let mut open = connection.lock().await;
            if step == 1 {
                let mut draft = open.draft(&id).await.unwrap();
                draft.login.as_mut().unwrap().password = Some(SecretString::new("v1"));
                open.update(&id, draft).await.unwrap();
            } else {
                open.set_archived(&id, true).await.unwrap();
            }
        }
        let sending = tokio::spawn({
            let connection = Arc::clone(&connection);
            async move { sync_shared(&connection, false).await.map(|_| ()) }
        });
        // Jeton renouvelé (un aller-retour), la requête est en route.
        tokio::time::sleep(LATENCY + LATENCY / 2).await;
        let start = Instant::now();
        let mut open = connection.lock().await;
        let mut draft = open.draft(&id).await.unwrap();
        let next = format!("v{}", step + 1);
        draft.login.as_mut().unwrap().password = Some(SecretString::new(&next));
        let vault = open.update(&id, draft).await.unwrap();
        drop(open);
        assert!(start.elapsed() < LOCAL, "{:?}", start.elapsed());
        assert_eq!(password(&vault, &id), next);
        assert_eq!(
            vault.pending_changes, 2,
            "pas fusionnée avec l'écriture en cours d'envoi"
        );
        assert!(!sending.is_finished(), "l'envoi était toujours en cours");
        // L'envoi en cours emporte aussi la nouvelle modification, derrière.
        sending.await.unwrap().unwrap();
        assert_eq!(connection.lock().await.pending_changes(), 0);
        let report = connection.lock().await.take_report();
        assert!(
            report.conflicts.is_empty() && report.rejected.is_empty(),
            "étape {step} : {report:?}"
        );
        let seen = seen_elsewhere(&server, &email).await;
        assert_eq!(password(&seen, &id), next);
        assert_eq!(seen.items.len(), 1, "aucune copie de conflit");
    }
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Refusé par le serveur (pas une erreur réseau) : la modification est
/// retirée, signalée, et le coffre affiché revient à la version du serveur.
#[tokio::test]
async fn a_refused_write_is_rolled_back_and_reported() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (connection, _) = sign_in(&store, &server, &email).await;
    let connection = Arc::new(Mutex::new(connection));
    let mut open = connection.lock().await;
    let (kept, _) = open.create(login_draft("Gardé", "x")).await.unwrap();
    drop(open);
    drained(&connection).await;
    let mut open = connection.lock().await;
    let kept = open.resolve(&kept);
    open.take_report();

    // Un dossier qui n'existe pas sur le serveur : il refuse la création,
    // puis la modification (et sa copie).
    let nowhere = uuid::Uuid::new_v4().to_string();
    let (refused, vault) = open
        .create(Draft {
            folder_id: Some(nowhere.clone()),
            ..login_draft("Refusé", "y")
        })
        .await
        .unwrap();
    assert!(find(&vault, &refused).is_some(), "affiché tout de suite");
    let mut draft = open.draft(&kept).await.unwrap();
    draft.name = "Gardé, renommé".to_owned();
    draft.folder_id = Some(nowhere);
    let vault = open.update(&kept, draft).await.unwrap();
    assert_eq!(find(&vault, &kept).unwrap().title, "Gardé, renommé");
    drop(open);

    let vault = drained(&connection).await;
    assert!(find(&vault, &refused).is_none(), "création retirée");
    assert_eq!(
        find(&vault, &kept).unwrap().title,
        "Gardé",
        "version du serveur"
    );
    assert_eq!(vault.pending_changes, 0);
    assert!(
        !vault
            .items
            .iter()
            .any(|i| i.title.ends_with(CONFLICT_SUFFIX))
    );
    let report = connection.lock().await.take_report();
    let titles: Vec<&str> = report.rejected.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(titles, ["Refusé", "Gardé, renommé"]);
    assert!(report.rejected.iter().all(|(_, reason)| !reason.is_empty()));
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Des demandes de synchronisation simultanées : une en cours, une seule
/// après elle pour toutes les autres.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_syncs_are_coalesced() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (connection, _) = sign_in(&store, &slow(&server, LATENCY).await, &email).await;
    let connection = Arc::new(Mutex::new(connection));
    connection
        .lock()
        .await
        .create(login_draft("Banque", "x"))
        .await
        .unwrap();

    let start = Instant::now();
    let requests: Vec<_> = (0..6)
        .map(|_| {
            let connection = Arc::clone(&connection);
            tokio::spawn(async move { sync_shared(&connection, false).await.unwrap() })
        })
        .collect();
    let mut ran = 0;
    for request in requests {
        if !matches!(request.await.unwrap(), Synced::Joined) {
            ran += 1;
        }
    }
    assert!(
        (1..=2).contains(&ran),
        "{ran} synchronisations pour 6 demandes"
    );
    // Une synchronisation : jeton, envoi, téléchargement ; deux au plus.
    assert!(start.elapsed() < LATENCY * 8, "{:?}", start.elapsed());
    assert_eq!(seen_elsewhere(&server, &email).await.items.len(), 1);
    std::fs::remove_dir_all(store.dir()).unwrap();
}

/// Déconnecté pendant un envoi : plus rien n'est écrit sur le disque, la
/// file effacée ne revient pas.
#[tokio::test]
async fn nothing_is_written_after_logout() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut connection, _) = sign_in(&store, &server, &email).await;
    connection.create(login_draft("Banque", "x")).await.unwrap();
    assert_eq!(store.pending_changes(), 1);
    connection.closer().close();
    verrou_vaultwarden::logout(&store).unwrap();
    connection.create(login_draft("Après", "y")).await.unwrap();
    assert_eq!(store.pending_changes(), 0);
    assert!(!store.dir().join("outbox.json").exists());
    let _ = std::fs::remove_dir_all(store.dir());
}

/// Verrouillé : l'envoi s'arrête, la file attend le déverrouillage suivant.
#[tokio::test]
async fn locking_stops_the_send() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let store = temp_store();
    let (mut connection, _) = sign_in(&store, &server, &email).await;
    connection.create(login_draft("Banque", "x")).await.unwrap();
    connection.closer().stop();
    let connection = Arc::new(Mutex::new(connection));
    assert!(matches!(
        sync_shared(&connection, false).await.unwrap(),
        Synced::Unchanged
    ));
    assert_eq!(connection.lock().await.pending_changes(), 1);
    assert_eq!(store.pending_changes(), 1, "gardée sur le disque");
    assert_eq!(seen_elsewhere(&server, &email).await.items.len(), 0);
    std::fs::remove_dir_all(store.dir()).unwrap();
}
