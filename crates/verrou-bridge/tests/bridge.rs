//! Le pont de bout en bout, côté Verrou : un client qui fait ce que fait
//! l'extension, sur une vraie connexion TCP.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use verrou_bridge::crypto::{ChannelKey, Direction, KeyPair};
use verrou_bridge::protocol::{Credentials, SaveAction, Suggestion};
use verrou_bridge::{Backend, BoxFuture, Bridge, PairingRequest, WritePlan, access};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

struct FakeBackend {
    vault: Mutex<Vault>,
    unlocked: AtomicBool,
    unlock_requested: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
}

impl Backend for FakeBackend {
    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>> {
        self.is_unlocked()
            .then(|| access::suggestions(&self.vault.lock().unwrap(), page_url))
    }

    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>> {
        self.is_unlocked()
            .then(|| access::credentials(&self.vault.lock().unwrap(), item, page_url, 59))
    }

    fn check_save(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        current: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>> {
        self.is_unlocked().then(|| {
            access::check_save(
                &self.vault.lock().unwrap(),
                page_url,
                username,
                password,
                current,
            )
        })
    }

    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
        let outcome = self.is_unlocked().then(|| {
            let mut vault = self.vault.lock().unwrap();
            plan(&vault).map(|write| {
                let (updated, id) = access::apply_in_memory(&vault, write, "nouveau");
                *vault = updated;
                id
            })
        });
        Box::pin(async move { outcome })
    }

    fn request_unlock(&self) {
        self.unlock_requested.store(true, Ordering::SeqCst);
    }

    fn pairing_requested(&self, request: PairingRequest) {
        let _ = self.pairings.lock().unwrap().send(request);
    }
}

fn github() -> Item {
    Item {
        id: "github".to_owned(),
        kind: ItemKind::Login,
        title: "GitHub".to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://github.com".to_owned()],
        folder: None,
        tags: Vec::new(),
        favorite: true,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new("username", "Identifiant", FieldKind::Username, "camille"),
            Field::new("password", "Mot de passe", FieldKind::Password, "hunter2"),
        ],
        notes: None,
    }
}

fn start() -> (
    Bridge,
    Arc<FakeBackend>,
    mpsc::Receiver<PairingRequest>,
    std::path::PathBuf,
) {
    let (sender, receiver) = mpsc::channel();
    let backend = Arc::new(FakeBackend {
        vault: Mutex::new(Vault::new(vec![github()])),
        unlocked: AtomicBool::new(true),
        unlock_requested: AtomicBool::new(false),
        pairings: Mutex::new(sender),
    });
    let file = std::env::temp_dir().join(format!("verrou-bridge-{}.json", uuid::Uuid::new_v4()));
    let bridge = Bridge::start(0, file.clone(), backend.clone()).unwrap();
    (bridge, backend, receiver, file)
}

struct Client {
    stream: TcpStream,
    id: String,
    key: Option<ChannelKey>,
    next: u64,
}

impl Client {
    fn connect(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            stream,
            id: String::new(),
            key: None,
            next: 1,
        }
    }

    fn send(&mut self, message: &Value) {
        let body = serde_json::to_vec(message).unwrap();
        self.stream
            .write_all(&u32::try_from(body.len()).unwrap().to_le_bytes())
            .unwrap();
        self.stream.write_all(&body).unwrap();
    }

    fn receive(&mut self) -> Value {
        let mut length = [0u8; 4];
        self.stream.read_exact(&mut length).unwrap();
        let mut body = vec![0u8; u32::from_le_bytes(length) as usize];
        self.stream.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// Demande d'appairage ; rend le code calculé de notre côté.
    fn begin_pairing(&mut self) -> String {
        let ours = KeyPair::generate();
        self.send(&json!({ "type": "pair", "name": "Brave", "key": ours.public_base64() }));
        let pairing = self.receive();
        assert_eq!(pairing["type"], "pairing");
        pairing["client"].as_str().unwrap().clone_into(&mut self.id);
        let key = ours.agree(pairing["key"].as_str().unwrap(), false).unwrap();
        let code = key.pairing_code();
        self.key = Some(key);
        code
    }

    fn request_at(&mut self, command: &Value, ts: i64) -> Value {
        let mut payload = command.clone();
        payload["id"] = json!(self.next);
        payload["ts"] = json!(ts);
        self.next += 1;
        let key = self.key.clone().unwrap();
        let (iv, data) = key.seal(
            &self.id,
            Direction::Request,
            &serde_json::to_vec(&payload).unwrap(),
        );
        self.send(&json!({ "type": "request", "client": self.id, "iv": iv, "data": data }));
        let response = self.receive();
        if response["type"] != "response" {
            return response;
        }
        let plain = key
            .open(
                &self.id,
                Direction::Response,
                response["iv"].as_str().unwrap(),
                response["data"].as_str().unwrap(),
            )
            .unwrap();
        serde_json::from_slice(&plain).unwrap()
    }

    fn request(&mut self, command: &Value) -> Value {
        self.request_at(command, now_ms())
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn pairing_then_fill_for_the_matching_site_only() {
    let (bridge, backend, pairings, file) = start();
    let mut client = Client::connect(bridge.port());

    // Appairage : Verrou montre le même code que l'extension.
    let code = client.begin_pairing();
    let request = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.code, code);
    assert_eq!(request.name, "Brave");
    bridge.answer_pairing(&request.id, true);
    assert_eq!(client.receive()["type"], "paired");
    assert_eq!(bridge.clients().len(), 1);

    let status = client.request(&json!({ "cmd": "status" }));
    assert_eq!(status["result"], "status");
    assert_eq!(status["unlocked"], true);

    let suggestions =
        client.request(&json!({ "cmd": "suggest", "url": "https://github.com/login" }));
    assert_eq!(suggestions["items"][0]["id"], "github");
    assert_eq!(suggestions["items"][0]["username"], "camille");
    assert!(suggestions["items"][0].get("password").is_none());

    let filled = client
        .request(&json!({ "cmd": "fill", "url": "https://github.com/login", "item": "github" }));
    assert_eq!(filled["result"], "credentials");
    assert_eq!(filled["password"], "hunter2");

    // Un autre site, ou HTTP : refusé.
    let other =
        client.request(&json!({ "cmd": "fill", "url": "https://evil.example/", "item": "github" }));
    assert_eq!(other["result"], "denied");
    let http =
        client.request(&json!({ "cmd": "fill", "url": "http://github.com/", "item": "github" }));
    assert_eq!(http["result"], "denied");

    // Après l'envoi d'un formulaire : connu, mise à jour, nouveau.
    let check = |client: &mut Client, username: &str, password: &str| {
        client.request(&json!({ "cmd": "check", "url": "https://github.com/login",
            "username": username, "password": password }))
    };
    assert_eq!(check(&mut client, "camille", "hunter2")["action"], "known");
    let update = check(&mut client, "camille", "hunter3");
    assert_eq!(update["action"], "update");
    assert_eq!(update["item"]["id"], "github");
    assert_eq!(check(&mut client, "dominique", "x")["action"], "new");

    // Enregistrer : le nouveau mot de passe remplit ensuite le formulaire.
    let saved = client.request(&json!({ "cmd": "save", "url": "https://github.com/login",
        "username": "camille", "password": "hunter3", "item": "github" }));
    assert_eq!(saved["result"], "saved");
    assert_eq!(check(&mut client, "camille", "hunter3")["action"], "known");
    // Pas pour un élément d'un autre site.
    let elsewhere = client.request(&json!({ "cmd": "save", "url": "https://evil.example/",
        "username": "camille", "password": "x", "item": "github" }));
    assert_eq!(elsewhere["result"], "denied");

    // QR code de double authentification : la graine rejoint l'élément.
    let totp = client.request(
        &json!({ "cmd": "set_totp", "url": "https://github.com/settings",
        "totp": "otpauth://totp/GitHub:camille?secret=JBSWY3DPEHPK3PXP", "item": "github" }),
    );
    assert_eq!(totp["result"], "saved");
    let suggestions =
        client.request(&json!({ "cmd": "suggest", "url": "https://github.com/login" }));
    assert_eq!(suggestions["items"][0]["has_totp"], true);

    // Requête rejouée trop tard : refusée.
    let stale = client.request_at(&json!({ "cmd": "status" }), now_ms() - 10 * 60 * 1000);
    assert_eq!(stale["code"], "bad_request");

    // Coffre verrouillé : rien ne sort ; l'extension peut demander le déverrouillage.
    backend.unlocked.store(false, Ordering::SeqCst);
    let locked =
        client.request(&json!({ "cmd": "fill", "url": "https://github.com/", "item": "github" }));
    assert_eq!(locked["result"], "locked");
    assert_eq!(
        client.request(&json!({ "cmd": "unlock" }))["result"],
        "done"
    );
    assert!(backend.unlock_requested.load(Ordering::SeqCst));
    let save_locked = client.request(&json!({ "cmd": "save", "url": "https://github.com/",
        "username": "camille", "password": "x" }));
    assert_eq!(save_locked["result"], "locked");
    backend.unlocked.store(true, Ordering::SeqCst);

    // L'appairage survit à un redémarrage de Verrou…
    let id = client.id.clone();
    drop(bridge);
    let restarted = Bridge::start(0, file.clone(), backend.clone()).unwrap();
    let mut again = Client::connect(restarted.port());
    again.id = id.clone();
    again.key = client.key.take();
    assert_eq!(again.request(&json!({ "cmd": "status" }))["unlocked"], true);

    // … jusqu'à la révocation.
    restarted.revoke(&id);
    assert_eq!(
        again.request(&json!({ "cmd": "status" }))["code"],
        "unknown_client"
    );
    let _ = std::fs::remove_file(file);
}

#[test]
fn refused_or_forged_clients_get_nothing() {
    let (bridge, _backend, pairings, file) = start();

    let mut refused = Client::connect(bridge.port());
    refused.begin_pairing();
    let request = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
    bridge.answer_pairing(&request.id, false);
    assert_eq!(refused.receive()["type"], "refused");
    assert_eq!(bridge.clients(), []);
    assert_eq!(
        refused.request(&json!({ "cmd": "status" }))["code"],
        "unknown_client"
    );

    // Un client qui invente sa clé, pour un identifiant existant ou non.
    let mut forger = Client::connect(bridge.port());
    forger.id = request.id;
    forger.key = Some(ChannelKey::from_bytes([1; 32]));
    assert_eq!(
        forger.request(&json!({ "cmd": "status" }))["code"],
        "unknown_client"
    );

    // Une seconde demande d'appairage aussitôt après : refusée (anti-harcèlement).
    let mut spammer = Client::connect(bridge.port());
    spammer
        .send(&json!({ "type": "pair", "name": "x", "key": KeyPair::generate().public_base64() }));
    assert_eq!(spammer.receive()["code"], "busy");

    // Du bruit : la connexion répond « bad_request » sans tomber.
    spammer.send(&json!({ "type": "n'importe quoi" }));
    assert_eq!(spammer.receive()["code"], "bad_request");
    let _ = std::fs::remove_file(file);
}
