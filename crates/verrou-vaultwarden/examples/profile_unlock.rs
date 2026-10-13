//! Temps du déverrouillage sur un vrai serveur, étape par étape :
//! `cargo run --release -p verrou-vaultwarden --example profile_unlock -- <serveur> <e-mail> <mot de passe>`
//! (compte sans second facteur).
use std::time::Instant;

use bitwarden_api_api::models::SyncResponseModel;
use verrou_core::{SecretString, Vault};
use verrou_vaultwarden::{LoginStep, Store};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (server, email, password) = (&args[1], &args[2], &args[3]);
    let dir = std::env::temp_dir().join(format!("verrou-profile-{}", std::process::id()));
    let store = Store::new(&dir);

    let t = Instant::now();
    let LoginStep::Unlocked(unlocked) =
        verrou_vaultwarden::login(&store, server, email, SecretString::new(password.clone()))
            .await
            .expect("connexion")
    else {
        panic!("second facteur : prendre un compte sans");
    };
    println!("connexion (KDF + jeton + sync) : {:?}", t.elapsed());
    let user_key = unlocked.connection.user_key().await.unwrap();
    drop(unlocked);

    for round in 0..3 {
        let t = Instant::now();
        let account = store.load_account().unwrap().unwrap();
        let read = t.elapsed();
        let json = account.sync.clone().unwrap();
        let t = Instant::now();
        let sync: SyncResponseModel = serde_json::from_str(&json).unwrap();
        let parse = t.elapsed();
        let n = sync.ciphers.map_or(0, |c| c.len());

        let t = Instant::now();
        let unlocked = verrou_vaultwarden::unlock_with_user_key(&store, &user_key)
            .await
            .unwrap();
        let unlock = t.elapsed();
        let items = unlocked.vault.items;
        let t = Instant::now();
        let vault = Vault::new(items);
        let index = t.elapsed();
        let mut connection = unlocked.connection;
        let t = Instant::now();
        let synced = connection.sync().await.unwrap();
        let sync = t.elapsed();
        println!(
            "#{round} {n} éléments ({} Kio) : lecture du fichier {read:?}, analyse JSON {parse:?}, \
             déverrouillage par clé (lecture + JSON + déchiffrement) {unlock:?}, index {index:?}, \
             synchronisation sans changement {sync:?}",
            json.len() / 1024
        );
        assert!(synced.is_none(), "rien n'a changé : pas de déchiffrement");
        drop(vault);
    }
    let t = Instant::now();
    let unlocked =
        verrou_vaultwarden::unlock_with_password(&store, &SecretString::new(password.clone()))
            .await
            .unwrap();
    println!(
        "déverrouillage par mot de passe (KDF + tout) : {:?}",
        t.elapsed()
    );
    drop(unlocked);
    let _ = std::fs::remove_dir_all(dir);
}
