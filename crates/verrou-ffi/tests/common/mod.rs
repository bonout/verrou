//! Outils des tests contre un vrai Vaultwarden (`VERROU_TEST_SERVER`) :
//! compte jetable, session connectée, et un mandataire qui ajoute de la
//! latence à chaque aller-retour avec le serveur.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use bitwarden_core::Client;
use bitwarden_crypto::Kdf;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use verrou_ffi::{LoginResult, VaultSession};

pub const PASSWORD: &str = "cheval correct pile agrafe";
const ITERATIONS: u32 = 600_000;

/// Le serveur des tests, s'il y en a un.
pub fn server() -> Option<String> {
    let server = std::env::var("VERROU_TEST_SERVER").ok();
    if server.is_none() {
        eprintln!("VERROU_TEST_SERVER absent : test ignoré");
    }
    server
}

/// Un compte jetable ; rend son adresse e-mail.
pub async fn register(server: &str) -> String {
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

/// Une session de l'app, connectée à `server` dans un dossier jetable.
pub async fn signed_in(server: String, email: &str) -> Arc<VaultSession> {
    let dir = std::env::temp_dir().join(format!("verrou-ffi-{}", uuid::Uuid::new_v4()));
    let session = VaultSession::with_storage(dir.display().to_string());
    let result = session
        .login(server, email.to_owned(), PASSWORD.to_owned())
        .await
        .unwrap();
    assert!(matches!(result, LoginResult::Unlocked { .. }));
    session
}

/// Un mandataire TCP vers `server` (`http://hôte:port`) qui retarde chaque
/// octet de `delay / 2` dans chaque sens : `delay` de plus par aller-retour,
/// sans limiter le débit. Rend l'adresse à utiliser à la place.
pub async fn slow(server: &str, delay: Duration) -> String {
    let port: u16 = server.rsplit(':').next().unwrap().parse().unwrap();
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    if delay.is_zero() {
        return format!("http://{target}");
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(target).await else {
                    return;
                };
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::spawn(pipe(client_read, server_write, delay / 2));
                tokio::spawn(pipe(server_read, client_write, delay / 2));
            });
        }
    });
    format!("http://{address}")
}

async fn pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (sender, mut receiver) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, bytes)) = receiver.recv().await {
            tokio::time::sleep_until(at + delay).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = to.shutdown().await;
    });
    let mut buffer = vec![0; 64 * 1024];
    while let Ok(read) = from.read(&mut buffer).await {
        if read == 0
            || sender
                .send((tokio::time::Instant::now(), buffer[..read].to_vec()))
                .is_err()
        {
            break;
        }
    }
}
