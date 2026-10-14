//! Envois (Bitwarden Send) contre un vrai Vaultwarden : voir `server.rs`
//! pour lancer le serveur. Sans `VERROU_TEST_SERVER`, les tests ne font rien.
//!
//! Un seul compte et peu d'ouvertures de lien : inscription, prélogin et
//! jeton d'accès à un envoi puisent dans la même limite de Vaultwarden pour
//! les requêtes anonymes (50 d'affilée par adresse IP), partagée avec les
//! autres tests.

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
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
    }
    server
}

/// Un compte neuf, ouvert par Verrou.
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
    assert!(response.status().is_success(), "inscription refusée");
    let store =
        Store::new(std::env::temp_dir().join(format!("verrou-it-{}", uuid::Uuid::new_v4())));
    match login(&store, server, &email, SecretString::new(PASSWORD))
        .await
        .unwrap()
    {
        LoginStep::Unlocked(unlocked) => unlocked.connection,
        LoginStep::TwoFactor(_) => panic!("second facteur inattendu"),
    }
}

#[tokio::test]
async fn create_receive_edit_and_delete_sends() {
    let Some(server) = server() else { return };
    let mut connection = account(&server).await;
    assert!(connection.sends().unwrap().is_empty());

    // Création, avec un mot de passe et deux accès au plus.
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

    // La liste (depuis la synchronisation) ne porte ni texte ni lien.
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

    // Le destinataire : mauvais mot de passe, refusé ; le bon, le texte,
    // déchiffré avec la clé du lien.
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
    assert!(received.creator.is_some(), "adresse visible par défaut");

    // Modification : le texte change, le mot de passe reste, l'adresse est
    // masquée. Le lien ne change pas.
    let mut edited = connection.send_draft(&id).unwrap();
    assert_eq!(edited.text.expose(), "mot de passe du Wi-Fi");
    assert_eq!(edited.notes.as_deref(), Some("pour Antonin"));
    edited.text = SecretString::new("nouveau mot de passe");
    edited.hide_email = true;
    connection.update_send(&id, edited).await.unwrap();
    assert_eq!(connection.send_link(&id).unwrap().expose(), link);
    let info = &connection.sends().unwrap()[0];
    assert!(info.has_password, "mot de passe gardé");
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

    // Deux accès consommés : le lien ne mène plus à rien.
    assert!(
        send::receive(&link, Some(&SecretString::new("ouvre-toi")))
            .await
            .is_err()
    );

    // Retrait du mot de passe, puis suppression.
    connection.remove_send_password(&id).await.unwrap();
    let info = &connection.sends().unwrap()[0];
    assert!(!info.has_password);
    assert!(!info.is_available(Utc::now().timestamp()), "accès épuisés");
    connection.delete_send(&id).await.unwrap();
    assert!(connection.sends().unwrap().is_empty());

    open_send_forged_key_and_invalid_drafts(&mut connection).await;
}

/// Un envoi sans mot de passe ; une clé altérée ; désactivé ; une date
/// refusée avant tout envoi.
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

    // Un lien à la clé altérée ne se déchiffre pas.
    let (base, _) = link.expose().rsplit_once('/').unwrap();
    let forged = format!("{base}/AAAAAAAAAAAAAAAAAAAAAA");
    assert!(matches!(
        send::receive(&forged, None).await,
        Err(Error::Crypto(_))
    ));

    // Désactivé : il reste dans la liste, marqué comme tel.
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

/// Un contenu binaire reconnaissable (tous les octets, pas que du texte).
fn file_contents(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
        .collect()
}

#[tokio::test]
async fn file_sends_round_trip() {
    let Some(server) = server() else { return };
    let mut connection = account(&server).await;

    // Création, avec un mot de passe et trois accès au plus.
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
    let encrypted_size = info.file_size.expect("taille du fichier");
    assert!(encrypted_size > contents.len() as u64);
    assert!(encrypted_size <= contents.len() as u64 + 65);
    assert!(info.has_password);
    assert_eq!(info.access_count, 0);

    // Le destinataire : sans mot de passe, refusé ; avec, le fichier
    // identique, déchiffré avec la clé du lien. Un accès compté.
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

    // Modification des réglages : le fichier ne change pas, le lien non plus.
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

    // Second téléchargement : identique, adresse masquée ; puis le lien est
    // épuisé (deux accès au plus).
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
    assert!(send::receive(&link, None).await.is_err(), "supprimé");

    open_file_send_and_send_an_attachment(&mut connection).await;
}

/// Un envoi de fichier sans mot de passe ; un texte n'a pas de fichier ;
/// une pièce jointe envoyée telle quelle ; un fichier vide refusé.
async fn open_file_send_and_send_an_attachment(connection: &mut Connection) {
    let contents = file_contents(4096);
    let (id, link, _) = connection
        .create_file_send(SendDraft::file("Plan", Utc::now()), "plan.png", &contents)
        .await
        .unwrap();
    let (_, bytes) = send::receive_file(link.expose(), None).await.unwrap();
    assert_eq!(bytes.as_slice(), contents.as_slice());
    // `receive` ne télécharge pas : pas d'accès compté.
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

    // Pièce jointe d'un élément : déchiffrée puis chiffrée par la clé de
    // l'envoi, le destinataire reçoit les mêmes octets.
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
