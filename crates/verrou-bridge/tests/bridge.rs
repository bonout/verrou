//! Le pont de bout en bout, côté Verrou : un client qui fait ce que fait
//! l'extension (ou le terminal), sur une vraie connexion TCP.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use serde_json::{Value, json};
use signature::Verifier as _;
use ssh_key::encoding::Decode as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};
use verrou_bridge::crypto::{ChannelKey, Direction, KeyPair};
use verrou_bridge::protocol::{ClientKind, Credentials, SaveAction, Suggestion};
use verrou_bridge::{
    Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan, access,
};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

struct FakeBackend {
    vault: Mutex<Vault>,
    unlocked: AtomicBool,
    unlock_requested: AtomicBool,
    /// L'utilisateur a confirmé les éléments protégés (Touch ID).
    confirmed: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    /// Réponse de l'« utilisateur » aux demandes d'accord.
    approve: AtomicBool,
    confirmations: Mutex<Vec<Confirmation>>,
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
        self.is_unlocked().then(|| {
            let vault = self.vault.lock().unwrap();
            access::credentials(&vault, item, page_url, 59).and_then(|c| {
                if access::needs_confirmation(&vault, item)
                    && !self.confirmed.load(Ordering::SeqCst)
                {
                    Err(verrou_bridge::protocol::CONFIRM_IN_APP.to_owned())
                } else {
                    Ok(c)
                }
            })
        })
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

    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        reader(&self.vault.lock().unwrap());
        true
    }

    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool> {
        self.confirmations.lock().unwrap().push(request);
        let approved = self.approve.load(Ordering::SeqCst);
        Box::pin(async move { approved })
    }
}

/// Un identifiant « redemander le mot de passe principal ».
fn protected_bank() -> Item {
    let mut item = github();
    "banque".clone_into(&mut item.id);
    "Banque".clone_into(&mut item.title);
    item.urls = vec!["https://banque.fr".to_owned()];
    item.reprompt = true;
    item
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
        reprompt: false,
    }
}

fn ssh_item(key: &PrivateKey) -> Item {
    Item {
        id: "cle-ssh".to_owned(),
        kind: ItemKind::SshKey,
        title: "Clé du N100".to_owned(),
        subtitle: String::new(),
        urls: Vec::new(),
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new(
                "public_key",
                "Clé publique",
                FieldKind::Multiline,
                key.public_key().to_openssh().unwrap(),
            ),
            Field::new(
                "private_key",
                "Clé privée",
                FieldKind::Concealed,
                key.to_openssh(LineEnding::LF).unwrap().as_str(),
            ),
        ],
        notes: None,
        reprompt: false,
    }
}

fn banque() -> Item {
    Item {
        id: "banque".to_owned(),
        kind: ItemKind::Login,
        title: "Banque".to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://banque.fr".to_owned()],
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new("username", "Identifiant", FieldKind::Username, "camille"),
            Field::new(
                "password",
                "Mot de passe",
                FieldKind::Password,
                "coffre-fort",
            ),
            Field::new("totp", "Code", FieldKind::Totp, "JBSWY3DPEHPK3PXP"),
        ],
        notes: Some(verrou_core::SecretString::new("question secrète : Médor")),
        reprompt: false,
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
        vault: Mutex::new(Vault::new(vec![github(), protected_bank()])),
        unlocked: AtomicBool::new(true),
        unlock_requested: AtomicBool::new(false),
        confirmed: AtomicBool::new(false),
        pairings: Mutex::new(sender),
        approve: AtomicBool::new(false),
        confirmations: Mutex::new(Vec::new()),
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
        self.begin_pairing_with(&json!({ "name": "Brave" }))
    }

    /// `extra` : le nom, et la nature du client s'il l'annonce.
    fn begin_pairing_with(&mut self, extra: &Value) -> String {
        let ours = KeyPair::generate();
        let mut message = extra.clone();
        message["type"] = json!("pair");
        message["key"] = json!(ours.public_base64());
        self.send(&message);
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

    // Élément protégé : Verrou demande confirmation, puis livre.
    let protected =
        client.request(&json!({ "cmd": "fill", "url": "https://banque.fr/", "item": "banque" }));
    assert_eq!(protected["result"], "confirm");
    assert!(protected.get("password").is_none());
    backend.confirmed.store(true, Ordering::SeqCst);
    let confirmed =
        client.request(&json!({ "cmd": "fill", "url": "https://banque.fr/", "item": "banque" }));
    assert_eq!(confirmed["result"], "credentials");

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

/// Appaire un client qui annonce `kind`, accepté d'office.
fn paired(bridge: &Bridge, pairings: &mpsc::Receiver<PairingRequest>, kind: &str) -> Client {
    let mut client = Client::connect(bridge.port());
    let code = client.begin_pairing_with(&json!({ "name": "verrou", "kind": kind }));
    let request = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.code, code);
    bridge.answer_pairing(&request.id, true);
    assert_eq!(client.receive()["type"], "paired");
    client
}

#[test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
fn terminal_searches_without_secrets_and_reveals_with_consent() {
    let (bridge, backend, pairings, file) = start();
    {
        let mut vault = backend.vault.lock().unwrap();
        *vault = Vault::new(vec![github(), banque()]);
    }
    let mut cli = Client::connect(bridge.port());
    let code = cli.begin_pairing_with(&json!({ "name": "verrou", "kind": "cli" }));
    let request = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        (request.code.as_str(), request.kind),
        (code.as_str(), ClientKind::Cli)
    );
    bridge.answer_pairing(&request.id, true);
    assert_eq!(cli.receive()["type"], "paired");
    assert_eq!(bridge.clients()[0].kind, ClientKind::Cli);

    // Les commandes de l'extension lui sont refusées.
    let filled =
        cli.request(&json!({ "cmd": "fill", "url": "https://github.com/", "item": "github" }));
    assert_eq!(filled["result"], "denied");
    let suggest = cli.request(&json!({ "cmd": "suggest", "url": "https://github.com/" }));
    assert_eq!(suggest["result"], "denied");

    // Recherche et élément : aucun secret.
    let found = cli.request(&json!({ "cmd": "vault_search", "query": "banq" }));
    assert_eq!(found["result"], "items");
    assert_eq!(found["items"][0]["id"], "banque");
    assert_eq!(found["items"][0]["has_totp"], true);
    let all = cli.request(&json!({ "cmd": "vault_search", "query": "", "limit": 1 }));
    assert_eq!(
        (
            all["items"].as_array().unwrap().len(),
            all["total"].as_u64()
        ),
        (1, Some(2))
    );
    let item = cli.request(&json!({ "cmd": "vault_item", "query": "Banque" }));
    assert_eq!(item["result"], "item");
    assert_eq!(item["item"]["id"], "banque");
    let text = item.to_string();
    for secret in ["coffre-fort", "JBSWY3DPEHPK3PXP", "Médor"] {
        assert!(!found.to_string().contains(secret));
        assert!(!text.contains(secret), "{text}");
    }
    assert_eq!(item["item"]["fields"][0]["value"], "camille");
    assert_eq!(item["item"]["fields"][1]["secret"], true);
    assert!(item["item"]["fields"][1].get("value").is_none());

    // Un champ non secret sort sans demande.
    let username = cli.request(&json!({ "cmd": "reveal", "item": "banque", "field": "username" }));
    assert_eq!(username["value"], "camille");
    assert!(backend.confirmations.lock().unwrap().is_empty());

    // Un secret attend l'accord : refusé, puis accordé (et gardé).
    let reveal = json!({ "cmd": "reveal", "item": "banque", "field": "password" });
    assert_eq!(cli.request(&reveal)["result"], "denied");
    backend.approve.store(true, Ordering::SeqCst);
    assert_eq!(cli.request(&reveal)["value"], "coffre-fort");
    {
        let asked = backend.confirmations.lock().unwrap();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1].purpose, Purpose::Reveal);
        assert_eq!(asked[1].title, "Banque");
        assert_eq!(asked[1].client_name, "verrou");
    }
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&reveal)["value"], "coffre-fort");
    let notes = cli.request(&json!({ "cmd": "reveal", "item": "banque", "field": "notes" }));
    assert_eq!(notes["value"], "question secrète : Médor");
    let totp = cli.request(&json!({ "cmd": "totp", "item": "banque" }));
    assert_eq!(totp["result"], "code");
    assert_eq!(totp["code"].as_str().unwrap().len(), 6);
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);

    // L'accord vaut pour cet élément seulement…
    let other = cli.request(&json!({ "cmd": "reveal", "item": "github", "field": "password" }));
    assert_eq!(other["result"], "denied");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 3);
    // … et se perd au verrouillage.
    bridge.forget_approvals();
    assert_eq!(cli.request(&reveal)["result"], "denied");
    // Pas de code : refusé sans rien demander.
    let none = cli.request(&json!({ "cmd": "totp", "item": "github" }));
    assert_eq!(none["result"], "denied");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 4);
    assert_eq!(
        cli.request(&json!({ "cmd": "reveal", "item": "banque", "field": "inconnu" }))["result"],
        "denied"
    );

    // Coffre verrouillé : rien, sinon la demande de déverrouillage.
    backend.unlocked.store(false, Ordering::SeqCst);
    assert_eq!(
        cli.request(&json!({ "cmd": "vault_search", "query": "" }))["result"],
        "locked"
    );
    assert_eq!(cli.request(&reveal)["result"], "locked");
    assert_eq!(cli.request(&json!({ "cmd": "unlock" }))["result"], "done");
    assert!(backend.unlock_requested.load(Ordering::SeqCst));
    backend.unlocked.store(true, Ordering::SeqCst);

    // L'extension, elle, ne peut pas chercher dans le coffre.
    // (Trois secondes au moins entre deux appairages.)
    std::thread::sleep(Duration::from_secs(3));
    let mut brave = paired(&bridge, &pairings, "browser");
    for command in [
        json!({ "cmd": "vault_search", "query": "" }),
        json!({ "cmd": "vault_item", "query": "banque" }),
        json!({ "cmd": "reveal", "item": "banque", "field": "password" }),
        json!({ "cmd": "totp", "item": "banque" }),
        json!({ "cmd": "ssh_keys" }),
        json!({ "cmd": "unlink" }),
    ] {
        assert_eq!(brave.request(&command)["result"], "denied", "{command}");
    }

    // `verrou unlink` : le terminal s'oublie lui-même.
    assert_eq!(cli.request(&json!({ "cmd": "unlink" }))["result"], "done");
    assert_eq!(
        cli.request(&json!({ "cmd": "status" }))["code"],
        "unknown_client"
    );
    assert_eq!(bridge.clients().len(), 1);
    let _ = std::fs::remove_file(file);
}

#[test]
fn ssh_agent_commands_sign_inside_verrou() {
    let (bridge, backend, pairings, file) = start();
    let key = PrivateKey::random(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    {
        let mut vault = backend.vault.lock().unwrap();
        *vault = Vault::new(vec![github(), ssh_item(&key)]);
    }
    let mut cli = paired(&bridge, &pairings, "cli");

    let keys = cli.request(&json!({ "cmd": "ssh_keys" }));
    assert_eq!(keys["result"], "ssh_keys");
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
    assert_eq!(keys["keys"][0]["title"], "Clé du N100");
    let blob = keys["keys"][0]["public_key"].as_str().unwrap().to_owned();
    assert_eq!(
        BASE64.decode(blob.as_bytes()).unwrap(),
        key.public_key().to_bytes().unwrap()
    );
    assert!(!keys.to_string().contains("PRIVATE"));

    let sign = json!({ "cmd": "ssh_sign", "public_key": blob,
        "data": BASE64.encode(b"session ssh"), "flags": 0 });
    assert_eq!(cli.request(&sign)["result"], "denied");
    backend.approve.store(true, Ordering::SeqCst);
    let signed = cli.request(&sign);
    assert_eq!(signed["result"], "signature", "{signed}");
    let bytes = BASE64
        .decode(signed["signature"].as_str().unwrap().as_bytes())
        .unwrap();
    let signature = Signature::decode(&mut &bytes[..]).unwrap();
    key.public_key()
        .key_data()
        .verify(b"session ssh", &signature)
        .unwrap();
    {
        let asked = backend.confirmations.lock().unwrap();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1].purpose, Purpose::Ssh);
        assert_eq!(asked[1].title, "Clé du N100");
    }
    // Accord gardé pour cette clé : pas de nouvelle demande.
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);

    // Une clé inconnue, ou une requête illisible : refusées sans demande.
    let other = PrivateKey::random(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    let unknown = json!({ "cmd": "ssh_sign",
        "public_key": BASE64.encode(&other.public_key().to_bytes().unwrap()),
        "data": BASE64.encode(b"x") });
    assert_eq!(cli.request(&unknown)["result"], "denied");
    let garbled = json!({ "cmd": "ssh_sign", "public_key": "!!", "data": "" });
    assert_eq!(cli.request(&garbled)["result"], "denied");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);

    // Coffre verrouillé : ni clés, ni signature.
    backend.unlocked.store(false, Ordering::SeqCst);
    assert_eq!(
        cli.request(&json!({ "cmd": "ssh_keys" }))["result"],
        "locked"
    );
    assert_eq!(cli.request(&sign)["result"], "locked");
    let _ = std::fs::remove_file(file);
}
