//! Temps ressenti d'une écriture, à travers l'interface de l'app, contre un
//! vrai Vaultwarden : de « Enregistrer » (ou d'un clic sur favori,
//! archiver…) à la liste qui montre le changement (`summaries()`, ce que
//! l'app recharge avant de fermer la feuille). Mesuré directement, puis
//! derrière un mandataire qui ajoute 300 ms à chaque aller-retour.
//!
//! Mesure, pas un test : ignoré par défaut. Pour le lancer :
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

/// Taille du coffre mesuré (celui de l'utilisateur en a plus de 825).
const ITEMS: usize = 900;
const ROUNDS: usize = 5;

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1000.0
}

/// Ce que fait l'app après une écriture : recharger les résumés.
fn shows(session: &VaultSession, check: impl Fn(&verrou_ffi::ItemSummary) -> bool) -> bool {
    session.summaries().unwrap().iter().any(check)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mesure de performance, à lancer à la main"]
async fn write_latency() {
    let Ok(server) = std::env::var("VERROU_TEST_SERVER") else {
        eprintln!("VERROU_TEST_SERVER absent : mesure ignorée");
        return;
    };
    let email = register(&server).await;

    // Un coffre de la taille de celui de l'utilisateur, par l'import.
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
            // « Enregistrer » dans l'éditeur.
            let id = ids[round].clone();
            let mut draft = session.edit_draft(id.clone()).await.unwrap();
            let title = format!("Modifié {round}");
            draft.name.clone_from(&title);
            let start = Instant::now();
            session.update_item(id.clone(), draft).await.unwrap();
            assert!(shows(&session, |s| s.id == id && s.title == title));
            save.push(start.elapsed());

            // Un clic sur l'étoile.
            let id = ids[ROUNDS + round].clone();
            let start = Instant::now();
            session.set_favorite(id.clone(), true).await.unwrap();
            assert!(shows(&session, |s| s.id == id && s.favorite));
            favorite.push(start.elapsed());

            // « Créer ».
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

            // Jusqu'à la confirmation du serveur (synchronisation comprise).
            session.sync().await.unwrap();
            let created = session.resolve_item_id(created);
            assert!(shows(&session, |s| s.id == created && !s.pending_sync));
            confirmed.push(start.elapsed());
        }
        if delay == 0 {
            // Après une synchronisation, l'app relit résumés, compteurs et
            // organisations (hors du fil principal), puis cherche (sur le
            // fil principal) : leur coût dans le cœur, sans la conversion
            // en Swift.
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
                "rechargement de la liste ({count} éléments) : lecture {:.1} ms, recherche {:.1} ms",
                read.as_secs_f64() * 1000.0,
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
        println!(
            "latence ajoutée {delay} ms, {ITEMS} éléments : enregistrer {:.0} ms, favori {:.0} ms, \
             créer {:.0} ms, créer jusqu'à la confirmation du serveur {:.0} ms (médianes sur {ROUNDS})",
            median(save),
            median(favorite),
            median(create),
            median(confirmed),
        );
    }
}
