//! L'extension de remplissage automatique d'iOS (session invitée) contre un
//! vrai Vaultwarden, à côté de l'app qui partage son dossier. Sans
//! `VERROU_TEST_SERVER`, les tests ne font rien.

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

/// L'extension voit les modifications pas encore envoyées de l'app, crée
/// et utilise une passkey directement sur le serveur, et ne touche jamais
/// la file de l'app : celle-ci l'envoie ensuite une seule fois.
#[tokio::test(flavor = "multi_thread")]
async fn the_extension_writes_passkeys_without_touching_the_app_outbox() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let dir = std::env::temp_dir().join(format!("verrou-autofill-{}", uuid::Uuid::new_v4()));
    let dir = dir.display().to_string();
    let app = VaultSession::with_storage(dir.clone());
    let result = app.login(server, email, PASSWORD.to_owned()).await.unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));

    // Une modification de l'app, dans sa file, pas encore envoyée.
    let pending = app
        .create_item(login("Exemple", "https://www.exemple.fr/connexion"))
        .await
        .unwrap();
    assert_eq!(app.pending_changes(), 1);
    let outbox = std::path::Path::new(&dir).join("outbox.json");
    let before = std::fs::read(&outbox).unwrap();

    // L'extension la voit et la remplit.
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

    // Création d'une passkey pour `localhost`, dans un nouvel identifiant.
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

    // La file de l'app n'a pas bougé (ni envoyée, ni réécrite).
    assert_eq!(std::fs::read(&outbox).unwrap(), before);

    // Exclue par le site : pas de seconde passkey.
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

    // Connexion avec la passkey : compteur 1, enregistré avant la réponse.
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

    // Une nouvelle extension (nouveau processus) repart du cache enregistré :
    // le compteur continue.
    let next = guest(&dir).await;
    let second = sign(next, 2).await;
    assert_eq!(&second.authenticator_data[33..37], &2u32.to_be_bytes());
    assert_eq!(std::fs::read(&outbox).unwrap(), before);

    // L'app envoie sa file une fois, puis voit la passkey de l'extension.
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

    // Après la synchronisation de l'app, l'extension voit toujours le compteur.
    let third = sign(guest(&dir).await, 3).await;
    assert_eq!(&third.authenticator_data[33..37], &3u32.to_be_bytes());
    let _ = std::fs::remove_dir_all(&dir);
}
