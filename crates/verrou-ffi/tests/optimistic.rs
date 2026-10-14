//! Écritures de l'app sans attendre le réseau, contre un vrai Vaultwarden
//! joint à travers un mandataire lent. Sans `VERROU_TEST_SERVER`, les tests
//! ne font rien.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{register, server, signed_in, slow};
use verrou_ffi::{ItemDraft, LoginFields, VaultSession};

/// Latence ajoutée à chaque aller-retour avec le serveur.
const LATENCY: Duration = Duration::from_millis(400);
/// Une écriture locale : bien moins qu'un aller-retour.
const LOCAL: Duration = Duration::from_millis(250);

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

fn summary(session: &VaultSession, id: &str) -> Option<verrou_ffi::ItemSummary> {
    session
        .summaries()
        .unwrap()
        .into_iter()
        .find(|s| s.id == id)
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_show_at_once_and_the_send_follows() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let session = signed_in(slow(&server, LATENCY).await, &email).await;

    // « Créer » : dans la liste tout de suite, en attente du serveur.
    let start = Instant::now();
    let temporary = session.create_item(draft("Banque")).await.unwrap();
    assert!(start.elapsed() < LOCAL, "{:?}", start.elapsed());
    assert!(summary(&session, &temporary).unwrap().pending_sync);

    // L'envoi part ; une écriture faite pendant ce temps ne l'attend pas.
    let sending = tokio::spawn({
        let session = Arc::clone(&session);
        async move { session.push_changes().await }
    });
    tokio::time::sleep(LATENCY / 2).await;
    let start = Instant::now();
    session.set_favorite(temporary.clone(), true).await.unwrap();
    assert!(start.elapsed() < LOCAL, "{:?}", start.elapsed());
    assert!(!sending.is_finished());
    let shown = session
        .summaries()
        .unwrap()
        .into_iter()
        .find(|s| s.title == "Banque")
        .unwrap();
    assert!(shown.favorite, "visible malgré l'envoi en cours");
    assert!(sending.await.unwrap().unwrap().changed);
    session.push_changes().await.unwrap();

    // Confirmé : l'identifiant du serveur, plus rien en attente.
    let id = session.resolve_item_id(temporary.clone());
    assert_ne!(id, temporary);
    assert!(summary(&session, &temporary).is_none());
    let shown = summary(&session, &id).unwrap();
    assert!(shown.favorite && !shown.pending_sync);
    assert_eq!(session.pending_changes(), 0);
    let report = session.take_sync_report().await;
    assert!(report.rejected.is_empty() && report.conflicts.is_empty());
    assert_eq!(
        report.sent, 0,
        "rien n'a attendu le réseau : rien à annoncer"
    );
    assert!(
        report
            .remapped
            .iter()
            .any(|m| m.temporary == temporary && m.server == id)
    );

    // Ailleurs, la même chose.
    let other = signed_in(server, &email).await;
    let seen = summary(&other, &id).unwrap();
    assert!(seen.favorite);
}

/// Six demandes de synchronisation à la fois : une en cours, une seule
/// après elle pour toutes les autres.
#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_syncs_share_their_runs() {
    let Some(server) = server() else { return };
    let email = register(&server).await;
    let session = signed_in(slow(&server, LATENCY).await, &email).await;
    session.create_item(draft("Banque")).await.unwrap();
    let requests: Vec<_> = (0..6)
        .map(|n| {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                if n % 2 == 0 {
                    session.sync().await
                } else {
                    session.push_changes().await
                }
            })
        })
        .collect();
    let mut changed = 0;
    for request in requests {
        if request.await.unwrap().unwrap().changed {
            changed += 1;
        }
    }
    assert!((1..=2).contains(&changed), "{changed} coffres installés");
    assert_eq!(session.pending_changes(), 0);
}
