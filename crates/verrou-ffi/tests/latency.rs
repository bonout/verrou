//! Perceived time of a write, through the app interface, against a real
//! Vaultwarden: from "Save" (or a click on favorite, archive…) to the list
//! showing the change (`summaries()`, what the app reloads before closing
//! the sheet). Measured directly, then behind a proxy that adds 300 ms to
//! every round trip.
//!
//! A measurement, not a test: ignored by default. To run it:
//!
//! ```sh
//! VERROU_TEST_SERVER=http://localhost:8099 cargo test --release -p verrou-ffi \
//!     --test latency -- --ignored --nocapture
//! ```

mod common;

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use common::{register, signed_in, slow};
use verrou_ffi::{
    ImportChoice, ImportDestination, ImportFormat, ResultOrder, SidebarFilter, VaultSession,
};

/// Size of the measured vault (the user's has more than 825).
const ITEMS: usize = 900;
const ROUNDS: usize = 5;

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1000.0
}

/// What the app does after a write: reload the summaries.
fn shows(session: &VaultSession, check: impl Fn(&verrou_ffi::ItemSummary) -> bool) -> bool {
    session.summaries().unwrap().iter().any(check)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance measurement, run by hand"]
async fn write_latency() {
    let Ok(server) = std::env::var("VERROU_TEST_SERVER") else {
        eprintln!("VERROU_TEST_SERVER not set: measurement skipped");
        return;
    };
    let email = register(&server).await;

    // A vault the size of the user's, through the import.
    let seed = signed_in(server.clone(), &email).await;
    let mut csv = String::from("Title,URL,Username,Password,Notes,OTPAuth\n");
    for n in 0..ITEMS {
        writeln!(
            csv,
            "Site {n},https://site-{n}.exemple.fr,camille{n},mot-de-passe-{n},note {n},"
        )
        .unwrap();
    }
    let path = std::env::temp_dir().join(format!("verrou-latency-{}.csv", uuid::Uuid::new_v4()));
    std::fs::write(&path, csv).unwrap();
    let review = seed
        .prepare_import(
            path.display().to_string(),
            Some(ImportFormat::ApplePasswords),
        )
        .await
        .unwrap();
    let choices = vec![ImportChoice::Create; review.entries.len()];
    seed.commit_import(choices, ImportDestination::NoFolder)
        .await
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(seed.summaries().unwrap().len() >= ITEMS);
    drop(seed);

    for delay in [0, 300] {
        let session = signed_in(slow(&server, Duration::from_millis(delay)).await, &email).await;
        let ids: Vec<String> = session
            .summaries()
            .unwrap()
            .iter()
            .take(ROUNDS * 3)
            .map(|s| s.id.clone())
            .collect();

        let (mut save, mut favorite, mut create, mut confirmed) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for round in 0..ROUNDS {
            // "Save" in the editor.
            let id = ids[round].clone();
            let mut draft = session.edit_draft(id.clone()).await.unwrap();
            let title = format!("Modifié {round}");
            draft.name.clone_from(&title);
            let start = Instant::now();
            session.update_item(id.clone(), draft).await.unwrap();
            assert!(shows(&session, |s| s.id == id && s.title == title));
            save.push(start.elapsed());

            // A click on the star.
            let id = ids[ROUNDS + round].clone();
            let start = Instant::now();
            session.set_favorite(id.clone(), true).await.unwrap();
            assert!(shows(&session, |s| s.id == id && s.favorite));
            favorite.push(start.elapsed());

            // "Create".
            let mut draft = session
                .edit_draft(ids[2 * ROUNDS + round].clone())
                .await
                .unwrap();
            let title = format!("Créé {round}");
            draft.name.clone_from(&title);
            let start = Instant::now();
            let created = session.create_item(draft).await.unwrap();
            assert!(shows(&session, |s| s.title == title));
            create.push(start.elapsed());

            // Until the server's confirmation (sync included).
            session.sync().await.unwrap();
            let created = session.resolve_item_id(created);
            assert!(shows(&session, |s| s.id == created && !s.pending_sync));
            confirmed.push(start.elapsed());
        }
        if delay == 0 {
            // After a sync, the app rereads summaries, counts and
            // organizations (off the main thread), then searches (on the
            // main thread): their cost in the core, without the conversion
            // to Swift.
            let start = Instant::now();
            let count = session.summaries().unwrap().len();
            session.counts().unwrap();
            session.organizations();
            let read = start.elapsed();
            let start = Instant::now();
            session
                .search(String::new(), SidebarFilter::All, ResultOrder::Title)
                .unwrap();
            println!(
                "list reload ({count} items): read {:.1} ms, search {:.1} ms",
                read.as_secs_f64() * 1000.0,
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
        println!(
            "added latency {delay} ms, {ITEMS} items: save {:.0} ms, favorite {:.0} ms, \
             create {:.0} ms, create until server confirmation {:.0} ms (medians over {ROUNDS})",
            median(save),
            median(favorite),
            median(create),
            median(confirmed),
        );
    }
}
