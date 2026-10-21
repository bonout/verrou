//! Sends (Bitwarden Send) against a real Vaultwarden: see `server.rs` to
//! start the server. Without `VERROU_TEST_SERVER`, the tests do nothing.
//!
//! A single account and few link openings: sign-up, prelogin and a send's
//! access token draw from the same Vaultwarden limit for anonymous
//! requests (50 in a row per IP address), shared with the other tests.

use std::num::NonZeroU32;

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use chrono::{Duration, Utc};
use serde_json::json;
use verrou_core::SecretString;
use verrou_vaultwarden::send::{self, SendDraft, SendKind};
use verrou_vaultwarden::{Connection, Error, LoginStep, Store, login};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER not set: test skipped");
    }
    server
}

/// A new account, opened by Verrou.
async fn account(server: &str) -> Connection {
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
    assert!(response.status().is_success(), "sign-up refused");
    let store =
        Store::new(std::env::temp_dir().join(format!("verrou-it-{}", uuid::Uuid::new_v4())));
    match login(&store, server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => unlocked.connection,
        LoginStep::TwoFactor(_) => panic!("unexpected second factor"),
    }
}

#[tokio::test]
async fn create_receive_edit_and_delete_sends() {
    let Some(server) = server() else { return };
    let mut connection = account(&server).await;
    assert!(connection.sends().unwrap().is_empty());

    // Creation, with a password and two accesses at most.
    let now = Utc::now();
    let mut draft = SendDraft::text(
        "Wi-Fi du chalet",
        SecretString::new("mot de passe du Wi-Fi"),
        now,
    );
    draft.hidden = true;
    draft.notes = Some("pour Antonin".to_owned());
    draft.max_access_count = Some(2);
    draft.password = Some(SecretString::new("ouvre-toi"));
    let (id, link, _) = connection.create_send(draft).await.unwrap();
    let link = link.expose().to_owned();
    assert!(link.starts_with(&format!("{server}/#/send/")), "{link}");

    // The list (from the sync) carries neither text nor link.
    let sends = connection.sends().unwrap();
    assert_eq!(sends.len(), 1);
    let info = &sends[0];
    assert_eq!(info.id, id);
    assert_eq!(info.name, "Wi-Fi du chalet");
    assert_eq!(info.kind, SendKind::Text);
    assert!(info.has_password);
    assert_eq!(info.access_count, 0);
    assert_eq!(info.max_access_count, Some(2));
    assert!((info.deletion_date - (now + Duration::days(7)).timestamp()).abs() <= 1);
    assert_eq!(connection.send_link(&id).unwrap().expose(), link);

    // The recipient: wrong password, refused; the right one, the text,
    // decrypted with the link key.
    assert!(matches!(
        send::receive(&link, Some(&SecretString::new("faux"))).await,
        Err(Error::Invalid(_))
    ));
    let received = send::receive(&link, Some(&SecretString::new("ouvre-toi")))
        .await
        .unwrap();
    assert_eq!(received.name.as_deref(), Some("Wi-Fi du chalet"));
    assert_eq!(
        received.text.as_ref().map(SecretString::expose),
        Some("mot de passe du Wi-Fi")
    );
    assert!(received.hidden);
    assert!(received.creator.is_some(), "address visible by default");

    // Edit: the text changes, the password stays, the address is hidden.
    // The link does not change.
    let mut edited = connection.send_draft(&id).unwrap();
    assert_eq!(edited.text.expose(), "mot de passe du Wi-Fi");
    assert_eq!(edited.notes.as_deref(), Some("pour Antonin"));
    edited.text = SecretString::new("nouveau mot de passe");
    edited.hide_email = true;
    connection.update_send(&id, edited).await.unwrap();
    assert_eq!(connection.send_link(&id).unwrap().expose(), link);
    let info = &connection.sends().unwrap()[0];
    assert!(info.has_password, "password kept");
    assert!(info.hide_email);
    assert_eq!(info.access_count, 1);
    let received = send::receive(&link, Some(&SecretString::new("ouvre-toi")))
        .await
        .unwrap();
    assert_eq!(
        received.text.as_ref().map(SecretString::expose),
        Some("nouveau mot de passe")
    );
    assert!(received.creator.is_none());

    // Two accesses used: the link no longer leads anywhere.
    assert!(
        send::receive(&link, Some(&SecretString::new("ouvre-toi")))
            .await
            .is_err()
    );

    // Password removal, then deletion.
    connection.remove_send_password(&id).await.unwrap();
    let info = &connection.sends().unwrap()[0];
    assert!(!info.has_password);
    assert!(
        !info.is_available(Utc::now().timestamp()),
        "accesses used up"
    );
    connection.delete_send(&id).await.unwrap();
    assert!(connection.sends().unwrap().is_empty());

    open_send_forged_key_and_invalid_drafts(&mut connection).await;
}

/// A send without a password; a tampered key; disabled; a date refused
/// before anything is sent.
async fn open_send_forged_key_and_invalid_drafts(connection: &mut Connection) {
    let now = Utc::now();
    let (id, link, _) = connection
        .create_send(SendDraft::text("Digicode", SecretString::new("4521B"), now))
        .await
        .unwrap();
    let received = send::receive(link.expose(), None).await.unwrap();
    assert_eq!(
        received.text.as_ref().map(SecretString::expose),
        Some("4521B")
    );
    assert!(!received.hidden);

    // A link with a tampered key does not decrypt.
    let (base, _) = link.expose().rsplit_once('/').unwrap();
    let forged = format!("{base}/AAAAAAAAAAAAAAAAAAAAAA");
    assert!(matches!(
        send::receive(&forged, None).await,
        Err(Error::Crypto(_))
    ));

    // Disabled: it stays in the list, marked as such.
    let mut draft = connection.send_draft(&id).unwrap();
    draft.disabled = true;
    connection.update_send(&id, draft).await.unwrap();
    let info = &connection.sends().unwrap()[0];
    assert!(info.disabled);
    assert!(!info.is_available(Utc::now().timestamp()));

    let mut too_far = SendDraft::text("Loin", SecretString::new("x"), now);
    too_far.deletion_date = now + Duration::days(45);
    assert!(matches!(
        connection.create_send(too_far).await,
        Err(Error::Invalid(_))
    ));
    connection.delete_send(&id).await.unwrap();
}

/// Recognizable binary content (all bytes, not just text).
fn file_contents(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
        .collect()
}

#[tokio::test]
async fn file_sends_round_trip() {
    let Some(server) = server() else { return };
    let mut connection = account(&server).await;

    // Creation, with a password and three accesses at most.
    let contents = file_contents(300 * 1024 + 7);
    let mut draft = SendDraft::file("Bail signé", Utc::now());
    draft.max_access_count = Some(3);
    draft.password = Some(SecretString::new("ouvre-toi"));
    draft.notes = Some("pour Antonin".to_owned());
    let (id, link, _) = connection
        .create_file_send(draft, "bail signé.pdf", &contents)
        .await
        .unwrap();
    let link = link.expose().to_owned();
    assert!(link.starts_with(&format!("{server}/#/send/")), "{link}");

    let info = &connection.sends().unwrap()[0];
    assert_eq!(info.id, id);
    assert_eq!(info.kind, SendKind::File);
    assert_eq!(info.file_name.as_deref(), Some("bail signé.pdf"));
    let encrypted_size = info.file_size.expect("file size");
    assert!(encrypted_size > contents.len() as u64);
    assert!(encrypted_size <= contents.len() as u64 + 65);
    assert!(info.has_password);
    assert_eq!(info.access_count, 0);

    // The recipient: without password, refused; with it, the identical
    // file, decrypted with the link key. One access counted.
    assert!(matches!(
        send::receive_file(&link, None).await,
        Err(Error::Invalid(_))
    ));
    let (received, bytes) = send::receive_file(&link, Some(&SecretString::new("ouvre-toi")))
        .await
        .unwrap();
    assert_eq!(received.name.as_deref(), Some("Bail signé"));
    assert_eq!(received.file_name.as_deref(), Some("bail signé.pdf"));
    assert_eq!(received.file_size, Some(encrypted_size));
    assert!(received.text.is_none());
    assert_eq!(bytes.as_slice(), contents.as_slice());
    connection.sync().await.unwrap();
    assert_eq!(connection.sends().unwrap()[0].access_count, 1);

    // Settings edit: the file does not change, nor does the link.
    let mut edited = connection.send_draft(&id).unwrap();
    assert_eq!(edited.notes.as_deref(), Some("pour Antonin"));
    edited.name = "Bail (copie)".to_owned();
    edited.hide_email = true;
    edited.max_access_count = Some(2);
    connection.update_send(&id, edited).await.unwrap();
    assert_eq!(connection.send_link(&id).unwrap().expose(), link);
    let info = &connection.sends().unwrap()[0];
    assert_eq!(info.name, "Bail (copie)");
    assert_eq!(info.file_name.as_deref(), Some("bail signé.pdf"));
    assert_eq!(info.file_size, Some(encrypted_size));
    assert!(info.has_password && info.hide_email);

    // Second download: identical, address hidden; then the link is used
    // up (two accesses at most).
    let (received, bytes) = send::receive_file(&link, Some(&SecretString::new("ouvre-toi")))
        .await
        .unwrap();
    assert_eq!(bytes.as_slice(), contents.as_slice());
    assert!(received.creator.is_none());
    assert!(
        send::receive_file(&link, Some(&SecretString::new("ouvre-toi")))
            .await
            .is_err()
    );
    connection.sync().await.unwrap();
    let info = &connection.sends().unwrap()[0];
    assert_eq!(info.access_count, 2);
    assert!(!info.is_available(Utc::now().timestamp()));

    connection.delete_send(&id).await.unwrap();
    assert!(connection.sends().unwrap().is_empty());
    assert!(send::receive(&link, None).await.is_err(), "deleted");

    open_file_send_and_send_an_attachment(&mut connection).await;
}

/// A file send without a password; a text has no file; an attachment
/// sent as is; an empty file refused.
async fn open_file_send_and_send_an_attachment(connection: &mut Connection) {
    let contents = file_contents(4096);
    let (id, link, _) = connection
        .create_file_send(SendDraft::file("Plan", Utc::now()), "plan.png", &contents)
        .await
        .unwrap();
    let (_, bytes) = send::receive_file(link.expose(), None).await.unwrap();
    assert_eq!(bytes.as_slice(), contents.as_slice());
    // `receive` does not download: no access counted.
    let received = send::receive(link.expose(), None).await.unwrap();
    assert_eq!(received.file_name.as_deref(), Some("plan.png"));
    connection.sync().await.unwrap();
    assert_eq!(connection.sends().unwrap()[0].access_count, 1);
    connection.delete_send(&id).await.unwrap();

    let (text_id, text_link, _) = connection
        .create_send(SendDraft::text(
            "Digicode",
            SecretString::new("4521B"),
            Utc::now(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        send::receive_file(text_link.expose(), None).await,
        Err(Error::Invalid(_))
    ));
    connection.delete_send(&text_id).await.unwrap();

    // An item's attachment: decrypted then encrypted with the send key,
    // the recipient gets the same bytes.
    let attachment = file_contents(70_000);
    let (item_id, _) = connection
        .create_document("passeport.pdf", &attachment, None)
        .await
        .unwrap();
    let attachment_id = connection.attachments(&item_id).await.unwrap()[0]
        .id
        .clone();
    let (id, link, _) = connection
        .create_send_from_attachment(
            SendDraft::file("Passeport", Utc::now()),
            &item_id,
            &attachment_id,
        )
        .await
        .unwrap();
    let (received, bytes) = send::receive_file(link.expose(), None).await.unwrap();
    assert_eq!(received.file_name.as_deref(), Some("passeport.pdf"));
    assert_eq!(bytes.as_slice(), attachment.as_slice());
    connection.delete_send(&id).await.unwrap();

    assert!(matches!(
        connection
            .create_file_send(SendDraft::file("Vide", Utc::now()), "vide.txt", b"")
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(connection.sends().unwrap().is_empty());
}
