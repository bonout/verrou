//! Actions groupées à travers l'interface de l'app, contre un vrai
//! Vaultwarden. Sans `VERROU_TEST_SERVER`, le test ne fait rien.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use verrou_ffi::{
    BulkItemAction, BulkProgress, ItemDraft, ItemStatus, LoginFields, LoginResult, VaultSession,
};

const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

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

#[derive(Default)]
struct Steps(Mutex<Vec<(u32, u32)>>);

struct Recorder(Arc<Steps>);

impl BulkProgress for Recorder {
    fn progress(&self, done: u32, total: u32) {
        self.0.0.lock().unwrap().push((done, total));
    }
}

fn draft(name: &str) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: Some(LoginFields {
            username: Some("camille".to_owned()),
            password: Some("x".to_owned()),
            totp: None,
            urls: Vec::new(),
        }),
        fields: Vec::new(),
        template: None,
    }
}

#[tokio::test]
async fn bulk_actions_through_the_app_interface() {
    let Ok(server) = std::env::var("VERROU_TEST_SERVER") else {
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
        return;
    };
    let email = register(&server).await;
    let dir = std::env::temp_dir().join(format!("verrou-ffi-{}", uuid::Uuid::new_v4()));
    let session = VaultSession::with_storage(dir.display().to_string());
    let result = session
        .login(server, email, PASSWORD.to_owned())
        .await
        .unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));
    let mut ids = Vec::new();
    for name in ["Banque", "GitHub", "Impôts"] {
        ids.push(session.create_item(draft(name)).await.unwrap());
    }
    // Ce que fait l'app après une écriture : l'envoi, en arrière-plan.
    assert!(session.push_changes().await.unwrap().changed);
    let ids: Vec<String> = ids
        .into_iter()
        .map(|id| session.resolve_item_id(id))
        .collect();

    // Favoris : appliqués tout de suite, avancement signalé à chacun.
    let steps = Arc::new(Steps::default());
    let outcome = session
        .bulk_action(
            ids.clone(),
            BulkItemAction::Favorite { favorite: true },
            Box::new(Recorder(steps.clone())),
        )
        .await
        .unwrap();
    assert_eq!((outcome.done, outcome.queued), (3, 3));
    assert!(
        session
            .summaries()
            .unwrap()
            .iter()
            .all(|s| s.favorite && s.pending_sync)
    );
    assert_eq!(*steps.0.lock().unwrap(), [(1, 3), (2, 3), (3, 3)]);

    let folder = session.create_folder("Papiers".to_owned()).await.unwrap();
    assert!(session.folders().iter().any(|f| f.id == folder));
    let recorder = || Box::new(Recorder(Arc::new(Steps::default())));
    session
        .bulk_action(
            ids[..2].to_vec(),
            BulkItemAction::MoveToFolder {
                folder_id: Some(folder),
            },
            recorder(),
        )
        .await
        .unwrap();
    session
        .bulk_action(vec![ids[0].clone()], BulkItemAction::Trash, recorder())
        .await
        .unwrap();
    // L'élément à la corbeille est écarté et compté.
    let outcome = session
        .bulk_action(ids.clone(), BulkItemAction::Archive, recorder())
        .await
        .unwrap();
    assert_eq!((outcome.done, outcome.in_trash), (2, 1));
    assert_eq!(outcome.failures, Vec::<String>::new());
    session.push_changes().await.unwrap();
    let report = session.take_sync_report().await;
    assert!(report.rejected.is_empty() && report.conflicts.is_empty());

    let summaries = session.summaries().unwrap();
    let get = |id: &str| summaries.iter().find(|s| s.id == id).unwrap();
    assert_eq!(get(&ids[0]).state, ItemStatus::Trashed);
    assert_eq!(get(&ids[1]).state, ItemStatus::Archived);
    assert_eq!(get(&ids[1]).folder.as_deref(), Some("Papiers"));
    assert!(get(&ids[2]).favorite);
    assert_eq!(session.pending_changes(), 0);
    std::fs::remove_dir_all(dir).unwrap();
}
