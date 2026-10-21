//! App writes without waiting for the network, against a real Vaultwarden
//! reached through a slow proxy. Without `VERROU_TEST_SERVER`, the tests do
//! nothing.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{register, server, signed_in, slow};
use verrou_ffi::{ItemDraft, LoginFields, VaultSession};

/// Latency added to every round trip with the server.
const LATENCY: Duration = Duration::from_millis(400);
/// A local write: well under a round trip.
const LOCAL: Duration = Duration::from_millis(250);

fn draft(name: &str) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: Some(LoginFields {
            url_matches: None,
            username: Some("camille".to_owned()),
            password: Some("x".to_owned()),
            totp: None,
            urls: Vec::new(),
        }),
        fields: Vec::new(),
        template: None,
        ..ItemDraft::default()
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

    // "Create": in the list right away, waiting for the server.
    let start = Instant::now();
    let temporary = session.create_item(draft("Banque")).await.unwrap();
    assert!(start.elapsed() < LOCAL, "{:?}", start.elapsed());
    assert!(summary(&session, &temporary).unwrap().pending_sync);

    // The upload starts; a write made meanwhile doesn't wait for it.
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
    assert!(shown.favorite, "visible despite the upload in progress");
    assert!(sending.await.unwrap().unwrap().changed);
    session.push_changes().await.unwrap();

    // Confirmed: the server's id, nothing pending anymore.
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
        "nothing waited for the network: nothing to announce"
    );
    assert!(
        report
            .remapped
            .iter()
            .any(|m| m.temporary == temporary && m.server == id)
    );

    // Elsewhere, the same.
    let other = signed_in(server, &email).await;
    let seen = summary(&other, &id).unwrap();
    assert!(seen.favorite);
}

/// Six sync requests at once: one running, a single one after it for all
/// the others.
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
    assert!((1..=2).contains(&changed), "{changed} vaults installed");
    assert_eq!(session.pending_changes(), 0);
}
