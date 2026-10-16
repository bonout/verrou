//! PRF des passkeys (fournisseur du système) contre un vrai Vaultwarden :
//! la passkey créée par l'extension, relue par une autre session (autre
//! processus, autre appareil), donne les mêmes sorties. Sans
//! `VERROU_TEST_SERVER`, le test ne fait rien.

mod common;

use common::{PASSWORD, register, server};
use verrou_ffi::{LoginResult, PasskeyCreationRequest, VaultSession};

#[tokio::test(flavor = "multi_thread")]
async fn prf_outputs_survive_the_server_round_trip() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let dir = std::env::temp_dir().join(format!("verrou-prf-{}", uuid::Uuid::new_v4()));
    let dir = dir.display().to_string();
    let app = VaultSession::with_storage(dir.clone());
    let result = app
        .login(server.clone(), email.clone(), PASSWORD.to_owned())
        .await
        .unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));

    let extension = VaultSession::for_autofill(dir.clone());
    extension
        .unlock_with_password(PASSWORD.to_owned())
        .await
        .unwrap();
    let created = extension
        .passkey_registration(PasskeyCreationRequest {
            rp_id: "localhost".to_owned(),
            user_name: "camille".to_owned(),
            user_handle: b"utilisateur-prf".to_vec(),
            client_data_hash: vec![7; 32],
            user_verified: true,
            item_id: None,
            excluded_credentials: Vec::new(),
        })
        .await
        .unwrap();

    // Juste après la création (PRF demandée à la création).
    let prf = |session: &VaultSession, first: &[u8], second: Option<&[u8]>| {
        session.passkey_prf(
            "localhost".to_owned(),
            created.credential_id.clone(),
            first.to_vec(),
            second.map(<[u8]>::to_vec),
            true,
        )
    };
    let at_creation = prf(&extension, b"sel-1", Some(b"sel-2")).unwrap();
    assert_eq!(at_creation.first.len(), 32);
    assert_ne!(Some(&at_creation.first), at_creation.second.as_ref());

    // Sans vérification de l'utilisateur : refusé.
    assert!(
        extension
            .passkey_prf(
                "localhost".to_owned(),
                created.credential_id.clone(),
                b"sel-1".to_vec(),
                None,
                false
            )
            .is_err()
    );
    // Autre site : introuvable.
    assert!(
        extension
            .passkey_prf(
                "exemple.fr".to_owned(),
                created.credential_id.clone(),
                b"sel-1".to_vec(),
                None,
                true
            )
            .is_err()
    );

    // Un autre appareil (nouveau dossier, synchronisé depuis le serveur) :
    // mêmes sorties, au format de Bitwarden relu.
    let other_dir = std::env::temp_dir().join(format!("verrou-prf-{}", uuid::Uuid::new_v4()));
    let other = VaultSession::with_storage(other_dir.display().to_string());
    other
        .login(server, email, PASSWORD.to_owned())
        .await
        .unwrap();
    let elsewhere = prf(&other, b"sel-1", Some(b"sel-2")).unwrap();
    assert_eq!(elsewhere.first, at_creation.first);
    assert_eq!(elsewhere.second, at_creation.second);
    assert_ne!(
        prf(&other, b"sel-3", None).unwrap().first,
        at_creation.first
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other_dir);
}
