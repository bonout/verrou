//! The bridge end to end, on Verrou's side: a client that does what
//! the extension (or the terminal) does, over a real TCP connection.

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
    /// The user confirmed the protected items (Touch ID).
    confirmed: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    /// The "user"'s answer to approval requests.
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

    fn request_unlock(&self, _kind: ClientKind) {
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

fn visa() -> Item {
    let mut item = github();
    "visa".clone_into(&mut item.id);
    "Visa".clone_into(&mut item.title);
    item.kind = ItemKind::Card;
    item.urls.clear();
    item.fields = vec![
        Field::new("cardholder", "Titulaire", FieldKind::Text, "CAMILLE MARTIN"),
        Field::new(
            "number",
            "Numéro",
            FieldKind::CardNumber,
            "4242 4242 4242 4242",
        ),
        Field::new("expiry", "Expiration", FieldKind::Expiry, "09/29"),
        Field::new("code", "Cryptogramme", FieldKind::Pin, "123"),
    ];
    item
}

fn me() -> Item {
    let mut item = github();
    "moi".clone_into(&mut item.id);
    "Moi".clone_into(&mut item.title);
    item.kind = ItemKind::Identity;
    item.urls.clear();
    item.fields = vec![
        Field::new("first_name", "Prénom", FieldKind::Text, "Camille"),
        Field::new("last_name", "Nom", FieldKind::Text, "Martin"),
        Field::new("email", "E-mail", FieldKind::Email, "camille@exemple.fr"),
        Field::new("part:address1", "", FieldKind::Text, "12 rue des Lilas"),
        Field::new("part:postal_code", "", FieldKind::Text, "74000"),
        Field::new("part:city", "", FieldKind::Text, "Annecy"),
    ];
    item
}

/// A login with "master password re-prompt".
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
        url_matches: Vec::new(),
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
        state: verrou_core::ItemState::Active,
        shared: None,
    }
}

fn ssh_item(key: &PrivateKey) -> Item {
    Item {
        id: "cle-ssh".to_owned(),
        kind: ItemKind::SshKey,
        title: "Clé du N100".to_owned(),
        subtitle: String::new(),
        urls: Vec::new(),
        url_matches: Vec::new(),
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
        state: verrou_core::ItemState::Active,
        shared: None,
    }
}

fn banque() -> Item {
    Item {
        id: "banque".to_owned(),
        kind: ItemKind::Login,
        title: "Banque".to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://banque.fr".to_owned()],
        url_matches: Vec::new(),
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
        state: verrou_core::ItemState::Active,
        shared: None,
    }
}

fn start() -> (
    Bridge,
    Arc<FakeBackend>,
    mpsc::Receiver<PairingRequest>,
    std::path::PathBuf,
) {
    start_with(vec![github(), protected_bank(), visa(), me()])
}

fn start_with(
    items: Vec<Item>,
) -> (
    Bridge,
    Arc<FakeBackend>,
    mpsc::Receiver<PairingRequest>,
    std::path::PathBuf,
) {
    let (sender, receiver) = mpsc::channel();
    let backend = Arc::new(FakeBackend {
        vault: Mutex::new(Vault::new(items)),
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

    /// Pairing request; returns the code computed on our side.
    fn begin_pairing(&mut self) -> String {
        self.begin_pairing_with(&json!({ "name": "Brave" }))
    }

    /// `extra`: the name, and the client's kind if it announces one.
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

    // Pairing: Verrou shows the same code as the extension.
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

    // Another site, or HTTP: refused.
    let other =
        client.request(&json!({ "cmd": "fill", "url": "https://evil.example/", "item": "github" }));
    assert_eq!(other["result"], "denied");
    let http =
        client.request(&json!({ "cmd": "fill", "url": "http://github.com/", "item": "github" }));
    assert_eq!(http["result"], "denied");

    // After a form is submitted: known, update, new.
    let check = |client: &mut Client, username: &str, password: &str| {
        client.request(&json!({ "cmd": "check", "url": "https://github.com/login",
            "username": username, "password": password }))
    };
    assert_eq!(check(&mut client, "camille", "hunter2")["action"], "known");
    let update = check(&mut client, "camille", "hunter3");
    assert_eq!(update["action"], "update");
    assert_eq!(update["item"]["id"], "github");
    assert_eq!(check(&mut client, "dominique", "x")["action"], "new");

    // Save: the new password then fills the form.
    let saved = client.request(&json!({ "cmd": "save", "url": "https://github.com/login",
        "username": "camille", "password": "hunter3", "item": "github" }));
    assert_eq!(saved["result"], "saved");
    assert_eq!(check(&mut client, "camille", "hunter3")["action"], "known");
    // Not for an item of another site.
    let elsewhere = client.request(&json!({ "cmd": "save", "url": "https://evil.example/",
        "username": "camille", "password": "x", "item": "github" }));
    assert_eq!(elsewhere["result"], "denied");

    // Two-factor QR code: the seed joins the item.
    let totp = client.request(
        &json!({ "cmd": "set_totp", "url": "https://github.com/settings",
        "totp": "otpauth://totp/GitHub:camille?secret=JBSWY3DPEHPK3PXP", "item": "github" }),
    );
    assert_eq!(totp["result"], "saved");
    let suggestions =
        client.request(&json!({ "cmd": "suggest", "url": "https://github.com/login" }));
    assert_eq!(suggestions["items"][0]["has_totp"], true);

    forms_and_site_linking(&mut client, &backend);

    // Protected item: Verrou asks for confirmation, then releases it.
    let protected =
        client.request(&json!({ "cmd": "fill", "url": "https://banque.fr/", "item": "banque" }));
    assert_eq!(protected["result"], "confirm");
    assert!(protected.get("password").is_none());
    backend.confirmed.store(true, Ordering::SeqCst);
    let confirmed =
        client.request(&json!({ "cmd": "fill", "url": "https://banque.fr/", "item": "banque" }));
    assert_eq!(confirmed["result"], "credentials");

    // Request replayed too late: refused.
    let stale = client.request_at(&json!({ "cmd": "status" }), now_ms() - 10 * 60 * 1000);
    assert_eq!(stale["code"], "bad_request");

    // Vault locked: nothing leaves; the extension can ask for unlocking.
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

    // The pairing survives a restart of Verrou…
    let id = client.id.clone();
    drop(bridge);
    let restarted = Bridge::start(0, file.clone(), backend.clone()).unwrap();
    let mut again = Client::connect(restarted.port());
    again.id = id.clone();
    again.key = client.key.take();
    assert_eq!(again.request(&json!({ "cmd": "status" }))["unlocked"], true);

    // … until revocation.
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

    // A client that makes up its key, for an existing identifier or not.
    let mut forger = Client::connect(bridge.port());
    forger.id = request.id;
    forger.key = Some(ChannelKey::from_bytes([1; 32]));
    assert_eq!(
        forger.request(&json!({ "cmd": "status" }))["code"],
        "unknown_client"
    );

    // A second pairing request right after: refused (anti-harassment).
    let mut spammer = Client::connect(bridge.port());
    spammer
        .send(&json!({ "type": "pair", "name": "x", "key": KeyPair::generate().public_base64() }));
    assert_eq!(spammer.receive()["code"], "busy");

    // Noise: the connection answers "bad_request" without dropping.
    spammer.send(&json!({ "type": "n'importe quoi" }));
    assert_eq!(spammer.receive()["code"], "bad_request");
    let _ = std::fs::remove_file(file);
}

#[test]
fn status_announces_the_bundled_extension_version() {
    let (bridge, _backend, pairings, file) = start();
    let mut client = paired(&bridge, &pairings, "browser");

    // No shipped extension (tests, terminal): nothing announced.
    let status = client.request(&json!({ "cmd": "status" }));
    assert_eq!(status["result"], "status");
    assert!(status.get("extension_version").is_none());

    // The version of the shipped manifest, read again each time: an app
    // update shows without restarting the bridge.
    let manifest =
        std::env::temp_dir().join(format!("verrou-manifest-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(
        &manifest,
        r#"{ "name": "Verrou", "version": "0.3.0.1234" }"#,
    )
    .unwrap();
    bridge.set_extension_manifest(Some(manifest.clone()));
    let status = client.request(&json!({ "cmd": "status" }));
    assert_eq!(status["extension_version"], "0.3.0.1234");
    assert_eq!(status["unlocked"], true);
    std::fs::write(
        &manifest,
        r#"{ "name": "Verrou", "version": "0.3.0.4321" }"#,
    )
    .unwrap();
    let status = client.request(&json!({ "cmd": "status" }));
    assert_eq!(status["extension_version"], "0.3.0.4321");

    // An unreadable manifest or an invalid version: nothing rather than anything.
    std::fs::write(&manifest, r#"{ "version": "1.2.3.4.5" }"#).unwrap();
    assert!(
        client
            .request(&json!({ "cmd": "status" }))
            .get("extension_version")
            .is_none()
    );
    std::fs::remove_file(&manifest).unwrap();
    assert!(
        client
            .request(&json!({ "cmd": "status" }))
            .get("extension_version")
            .is_none()
    );
    let _ = std::fs::remove_file(file);
}

/// Pairs a client that announces `kind`, accepted automatically.
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
#[allow(clippy::too_many_lines)] // a complete walkthrough, readable in one go
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

    // The extension's commands are refused to it.
    let filled =
        cli.request(&json!({ "cmd": "fill", "url": "https://github.com/", "item": "github" }));
    assert_eq!(filled["result"], "denied");
    let suggest = cli.request(&json!({ "cmd": "suggest", "url": "https://github.com/" }));
    assert_eq!(suggest["result"], "denied");

    // Search and item: no secrets.
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

    // A non-secret field leaves without asking.
    let username = cli.request(&json!({ "cmd": "reveal", "item": "banque", "field": "username" }));
    assert_eq!(username["value"], "camille");
    assert!(backend.confirmations.lock().unwrap().is_empty());

    // A secret awaits approval: refused, then granted (and kept).
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

    // The approval holds for this item only…
    let other = cli.request(&json!({ "cmd": "reveal", "item": "github", "field": "password" }));
    assert_eq!(other["result"], "denied");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 3);
    // … and is lost on locking.
    bridge.forget_approvals();
    assert_eq!(cli.request(&reveal)["result"], "denied");
    // No code: refused without asking anything.
    let none = cli.request(&json!({ "cmd": "totp", "item": "github" }));
    assert_eq!(none["result"], "denied");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 4);
    assert_eq!(
        cli.request(&json!({ "cmd": "reveal", "item": "banque", "field": "inconnu" }))["result"],
        "denied"
    );

    // Vault locked: nothing, except the unlock request.
    backend.unlocked.store(false, Ordering::SeqCst);
    assert_eq!(
        cli.request(&json!({ "cmd": "vault_search", "query": "" }))["result"],
        "locked"
    );
    assert_eq!(cli.request(&reveal)["result"], "locked");
    assert_eq!(cli.request(&json!({ "cmd": "unlock" }))["result"], "done");
    assert!(backend.unlock_requested.load(Ordering::SeqCst));
    backend.unlocked.store(true, Ordering::SeqCst);

    // The extension, for its part, cannot search the vault.
    // (At least three seconds between two pairings.)
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

    // `verrou unlink`: the terminal forgets itself.
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
    // Approval kept for this key: no new request.
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);

    // An unknown key, or an unreadable request: refused without asking.
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

    // Vault locked: neither keys nor signature.
    backend.unlocked.store(false, Ordering::SeqCst);
    assert_eq!(
        cli.request(&json!({ "cmd": "ssh_keys" }))["result"],
        "locked"
    );
    assert_eq!(cli.request(&sign)["result"], "locked");
    let _ = std::fs::remove_file(file);
}

/// Cards, identities, and linking a site to a login. A card
/// and a linked site require the user's approval in Verrou.
fn forms_and_site_linking(client: &mut Client, backend: &FakeBackend) {
    let purposes = |backend: &FakeBackend| {
        backend
            .confirmations
            .lock()
            .unwrap()
            .iter()
            .map(|c| (c.purpose, c.title.clone()))
            .collect::<Vec<_>>()
    };
    // Payment and address forms: suggestions without secrets, then
    // the fields of the chosen item.
    let forms =
        client.request(&json!({ "cmd": "forms", "url": "https://boutique.example/paiement" }));
    assert_eq!(forms["cards"][0]["id"], "visa");
    assert!(forms["cards"][0].get("number").is_none());
    assert_eq!(forms["identities"][0]["id"], "moi");
    let fill_card =
        json!({ "cmd": "fill_form", "url": "https://boutique.example/", "item": "visa" });
    // Refused in Verrou: nothing leaves.
    let refused = client.request(&fill_card);
    assert_eq!(refused["result"], "denied");
    assert!(refused.get("number").is_none());
    assert_eq!(purposes(backend), [(Purpose::Card, "Visa".to_owned())]);
    backend.approve.store(true, Ordering::SeqCst);
    let card = client.request(&fill_card);
    assert_eq!(card["result"], "form");
    assert_eq!(card["number"], "4242424242424242");
    assert_eq!(
        (card["exp_month"].as_str(), card["exp_year"].as_str()),
        (Some("09"), Some("2029"))
    );
    let address = client
        .request(&json!({ "cmd": "fill_form", "url": "https://boutique.example/", "item": "moi" }));
    assert_eq!(address["full_name"], "Camille Martin");
    assert_eq!(address["city"], "Annecy");
    assert_eq!(
        client.request(&json!({ "cmd": "forms", "url": "http://boutique.example/" }))["cards"],
        json!([])
    );

    // A site without a login: the user links GitHub, which is then offered there.
    let found = client.request(&json!({ "cmd": "search_logins", "query": "git" }));
    assert_eq!(found["items"][0]["id"], "github");
    assert!(found["items"][0].get("password").is_none());
    let linked = client.request(
        &json!({ "cmd": "link_site", "url": "https://github.example/login", "item": "github" }),
    );
    assert_eq!(linked["result"], "saved");
    assert_eq!(
        purposes(backend).last(),
        Some(&(Purpose::LinkSite, "GitHub".to_owned()))
    );
    let last = backend
        .confirmations
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(last.site, "github.example");
    // Refused in Verrou: the site is not added.
    backend.approve.store(false, Ordering::SeqCst);
    let elsewhere = json!({ "cmd": "link_site", "url": "https://evil.example/", "item": "github" });
    assert_eq!(client.request(&elsewhere)["result"], "denied");
    let found = client.request(&json!({ "cmd": "suggest", "url": "https://evil.example/" }));
    assert_eq!(found["items"], json!([]));
    let found = client.request(&json!({ "cmd": "suggest", "url": "https://github.example/login" }));
    assert_eq!(found["items"][0]["id"], "github");
    let again = client.request(
        &json!({ "cmd": "link_site", "url": "https://github.example/", "item": "github" }),
    );
    assert_eq!(again["result"], "denied");
}

/// A stolen pairing key asserts whatever address it wants: beyond
/// a few different items in a short time, each further item
/// requires the user's approval.
#[test]
fn many_items_in_a_row_need_approval() {
    let items = (0..12)
        .map(|n| {
            let mut item = github();
            item.id = format!("site{n}");
            item.title = format!("Site {n}");
            item.urls = vec![format!("https://site{n}.example")];
            item
        })
        .collect();
    let (bridge, backend, pairings, file) = start_with(items);
    let mut client = paired(&bridge, &pairings, "browser");
    let fill_site = |client: &mut Client, n: u32| {
        client.request(
            &json!({ "cmd": "fill", "url": format!("https://site{n}.example/"),
            "item": format!("site{n}") }),
        )
    };
    for n in 0..8 {
        assert_eq!(
            fill_site(&mut client, n)["result"],
            "credentials",
            "site{n}"
        );
    }
    assert!(backend.confirmations.lock().unwrap().is_empty());
    // The ninth: refused in Verrou.
    let ninth = fill_site(&mut client, 8);
    assert_eq!(ninth["result"], "denied");
    assert!(ninth.get("password").is_none());
    assert_eq!(
        backend.confirmations.lock().unwrap()[0].purpose,
        Purpose::Bulk
    );
    // An item already released stays available without approval.
    assert_eq!(fill_site(&mut client, 3)["result"], "credentials");
    // Granted: released.
    backend.approve.store(true, Ordering::SeqCst);
    assert_eq!(fill_site(&mut client, 8)["result"], "credentials");
    let _ = std::fs::remove_file(file);
}
