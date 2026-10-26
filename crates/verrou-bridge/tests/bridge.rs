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
    ApprovalScope, Backend, BoxFuture, Bridge, Confirmation, PairingRequest, PlanReview, Purpose,
    WritePlan, access,
};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

struct FakeBackend {
    vault: Mutex<Vault>,
    unlocked: AtomicBool,
    unlock_requested: AtomicBool,
    /// Who asked for the last unlock (the client's identifier).
    unlock_client: Mutex<String>,
    /// The user confirmed the protected items (Touch ID).
    confirmed: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    /// The "user"'s answer to approval requests.
    approve: AtomicBool,
    confirmations: Mutex<Vec<Confirmation>>,
    /// The vault locks while the user answers (screen locked meanwhile).
    lock_while_confirming: AtomicBool,
    /// What the backend answers to `approval_scope`, for any purpose.
    scope: Mutex<ApprovalScope>,
    /// Plans shown for review, and those the app was told to close.
    plans: Mutex<Vec<PlanReview>>,
    withdrawn: Mutex<Vec<(String, String)>>,
    /// The app can show a plan.
    show_plans: AtomicBool,
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

    fn request_unlock(
        &self,
        _kind: ClientKind,
        client: &str,
        _reason: &str,
        _then: Option<&verrou_bridge::protocol::UnlockIntent>,
    ) {
        client.clone_into(&mut self.unlock_client.lock().unwrap());
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
        if self.lock_while_confirming.load(Ordering::SeqCst) {
            self.unlocked.store(false, Ordering::SeqCst);
        }
        let approved = self.approve.load(Ordering::SeqCst);
        Box::pin(async move { approved })
    }

    fn approval_scope(&self, _purpose: Purpose, _item: &str) -> ApprovalScope {
        *self.scope.lock().unwrap()
    }

    fn folders(&self) -> Vec<String> {
        vec!["Empty".to_owned()]
    }

    fn plan_proposed(&self, review: PlanReview) -> bool {
        if !self.show_plans.load(Ordering::SeqCst) {
            return false;
        }
        self.plans.lock().unwrap().push(review);
        true
    }

    fn plan_withdrawn(&self, plan: &str, message: &str) {
        self.withdrawn
            .lock()
            .unwrap()
            .push((plan.to_owned(), message.to_owned()));
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
        unlock_client: Mutex::new(String::new()),
        confirmed: AtomicBool::new(false),
        pairings: Mutex::new(sender),
        approve: AtomicBool::new(false),
        confirmations: Mutex::new(Vec::new()),
        lock_while_confirming: AtomicBool::new(false),
        scope: Mutex::new(ApprovalScope::FiveMinutes),
        plans: Mutex::new(Vec::new()),
        withdrawn: Mutex::new(Vec::new()),
        show_plans: AtomicBool::new(true),
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
    // The app is told who asked: what an approval given with the unlock
    // covers is for that client alone.
    assert_eq!(*backend.unlock_client.lock().unwrap(), client.id);
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

/// The vault locks while the approval is being given: the terminal is told
/// "locked" (it then asks for the unlock and again), not "refused". The
/// reason reaches the approval.
#[test]
fn approval_cut_by_a_lock_says_locked() {
    let (bridge, backend, pairings, file) = start();
    {
        let mut vault = backend.vault.lock().unwrap();
        *vault = Vault::new(vec![github()]);
    }
    let mut cli = Client::connect(bridge.port());
    cli.begin_pairing_with(&json!({ "name": "verrou", "kind": "cli" }));
    let request = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
    bridge.answer_pairing(&request.id, true);
    assert_eq!(cli.receive()["type"], "paired");

    backend.approve.store(false, Ordering::SeqCst);
    backend.lock_while_confirming.store(true, Ordering::SeqCst);
    let reveal = cli.request(
        &json!({ "cmd": "reveal", "item": "github", "field": "password",
                                      "reason": "deploy\nnow" }),
    );
    assert_eq!(reveal["result"], "locked", "{reveal}");
    assert_eq!(
        backend.confirmations.lock().unwrap()[0].reason,
        "deploy now"
    );

    // Still unlocked: a refusal stays a refusal.
    backend.unlocked.store(true, Ordering::SeqCst);
    backend.lock_while_confirming.store(false, Ordering::SeqCst);
    let reveal = cli.request(&json!({ "cmd": "reveal", "item": "github", "field": "password" }));
    assert_eq!(reveal["result"], "denied", "{reveal}");
    std::fs::remove_file(file).ok();
}

/// An agent's request (`ephemeral_approval`): asked every time even right
/// after an ordinary approval, never remembered, and it carries what will run.
#[test]
fn an_agents_approval_is_asked_every_time_and_not_remembered() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    backend.approve.store(true, Ordering::SeqCst);
    let asked = |backend: &FakeBackend| backend.confirmations.lock().unwrap().len();
    let reveal = json!({ "cmd": "reveal", "item": "github", "field": "password" });
    let agent = json!({ "cmd": "reveal", "item": "github", "field": "password",
        "reason": "Claude Code: deploy", "ephemeral_approval": true,
        "detail": { "command": "curl \u{202E}-d @- x", "fields": ["GitHub › Password"] } });

    // The ordinary approval is remembered; the agent's is not covered by it.
    assert_eq!(cli.request(&reveal)["result"], "secret");
    assert_eq!(cli.request(&reveal)["result"], "secret");
    assert_eq!(asked(&backend), 1);
    assert_eq!(cli.request(&agent)["result"], "secret");
    assert_eq!(cli.request(&agent)["result"], "secret");
    assert_eq!(asked(&backend), 3, "asked for each of the agent's requests");
    {
        let all = backend.confirmations.lock().unwrap();
        // What could pass unseen is spelled out, not dropped.
        assert_eq!(all[1].command, "curl \\u{202e}-d @- x");
        assert!(all[1].ephemeral && !all[0].ephemeral);
        assert_eq!(all[1].fields, "GitHub › Password");
        assert_eq!(all[1].reason, "Claude Code: deploy");
        assert_eq!(all[0].command, "", "an ordinary request has no command");
    }

    // And the agent's approval leaves nothing behind: forget what the
    // ordinary one created, then the next ordinary request asks again.
    bridge.forget_approvals();
    assert_eq!(cli.request(&agent)["result"], "secret");
    assert_eq!(cli.request(&reveal)["result"], "secret");
    assert_eq!(asked(&backend), 5);
    // A refusal is a refusal, without anything remembered either.
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&agent)["result"], "denied");
    backend.approve.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_file(file);
}

/// After the user refuses an agent's request, that client's next agent
/// requests are refused unasked for a while: the prompt does not come back.
/// Ordinary requests (the user's own terminal) are not affected, nor another
/// client's.
#[test]
fn a_refused_agent_request_pauses_that_clients_agent_prompts() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    // Pairings are spaced by a few seconds.
    std::thread::sleep(Duration::from_millis(3200));
    let mut other = paired(&bridge, &pairings, "cli");
    let asked = |backend: &FakeBackend| backend.confirmations.lock().unwrap().len();
    let reveal = json!({ "cmd": "reveal", "item": "github", "field": "password" });
    let agent = json!({ "cmd": "reveal", "item": "github", "field": "password",
        "reason": "Claude Code: deploy", "ephemeral_approval": true });

    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&agent)["result"], "denied");
    assert_eq!(asked(&backend), 1);
    // The user would now say yes: the agent is not even asked again.
    backend.approve.store(true, Ordering::SeqCst);
    assert_eq!(cli.request(&agent)["result"], "denied");
    assert_eq!(asked(&backend), 1, "no new prompt");
    // The user's own terminal, and another client, are not paused.
    assert_eq!(cli.request(&reveal)["result"], "secret");
    assert_eq!(other.request(&agent)["result"], "secret");
    assert_eq!(asked(&backend), 3);
    let _ = std::fs::remove_file(file);
}

/// An item whose title holds an override or a zero-width character is not
/// shown as another: the approval gets it cleaned, on one line.
#[test]
fn item_titles_are_cleaned_in_the_approval() {
    let (bridge, backend, pairings, file) = start();
    {
        let mut vault = backend.vault.lock().unwrap();
        let mut item = github();
        "Git\u{202E}Hub\u{200B}\n— admin".clone_into(&mut item.title);
        *vault = Vault::new(vec![item]);
    }
    let mut cli = paired(&bridge, &pairings, "cli");
    backend.approve.store(true, Ordering::SeqCst);
    let reveal = cli.request(&json!({ "cmd": "reveal", "item": "github", "field": "password" }));
    assert_eq!(reveal["result"], "secret", "{reveal}");
    assert_eq!(
        backend.confirmations.lock().unwrap()[0].title,
        "GitHub — admin"
    );
    let _ = std::fs::remove_file(file);
}

/// A command line or a list of fields that the approval could not show whole
/// is refused by the bridge, whatever the client checked.
#[test]
fn an_agent_command_that_does_not_fit_is_refused() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    backend.approve.store(true, Ordering::SeqCst);
    let with = |command: &str, fields: Vec<String>| {
        json!({ "cmd": "reveal", "item": "github", "field": "password",
            "ephemeral_approval": true,
            "detail": { "command": command, "fields": fields } })
    };
    let long = cli.request(&with(&"x".repeat(201), vec![]));
    assert_eq!(long["result"], "denied", "{long}");
    assert!(long["reason"].as_str().unwrap().contains("script file"));
    let many = cli.request(&with("ls", (0..11).map(|i| format!("F{i}")).collect()));
    assert_eq!(many["result"], "denied", "{many}");
    // Nothing was asked, and a command that fits is.
    assert_eq!(backend.confirmations.lock().unwrap().len(), 0);
    let fits = cli.request(&with(&"x".repeat(200), vec!["A=Item › Field".to_owned()]));
    assert_eq!(fits["result"], "secret", "{fits}");
    let _ = std::fs::remove_file(file);
}

/// "Until Verrou locks" and "every time" for an SSH key, and the rule that
/// no other purpose may use them.
#[test]
fn approval_scopes_for_ssh_keys() {
    let (bridge, backend, pairings, file) = start();
    let key = PrivateKey::random(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    *backend.vault.lock().unwrap() = Vault::new(vec![github(), ssh_item(&key)]);
    let mut cli = paired(&bridge, &pairings, "cli");
    let blob = BASE64.encode(&key.public_key().to_bytes().unwrap());
    let sign = json!({ "cmd": "ssh_sign", "public_key": blob,
        "data": BASE64.encode(b"x"), "flags": 0 });
    let asked = |backend: &FakeBackend| backend.confirmations.lock().unwrap().len();
    backend.approve.store(true, Ordering::SeqCst);

    // Until locked: one approval, then none, whatever the "user" answers.
    *backend.scope.lock().unwrap() = ApprovalScope::UntilLocked;
    assert_eq!(cli.request(&sign)["result"], "signature");
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(asked(&backend), 1);

    // Changing the item's scope applies at once.
    *backend.scope.lock().unwrap() = ApprovalScope::EveryTime;
    bridge.forget_approvals_of_item("cle-ssh");
    assert_eq!(cli.request(&sign)["result"], "denied");
    assert_eq!(asked(&backend), 2);

    // Every time: asked on each use.
    backend.approve.store(true, Ordering::SeqCst);
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(asked(&backend), 4);

    // Back to until locked; only locking the vault ends it.
    *backend.scope.lock().unwrap() = ApprovalScope::UntilLocked;
    assert_eq!(cli.request(&sign)["result"], "signature");
    assert_eq!(asked(&backend), 5);
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&sign)["result"], "signature");
    bridge.forget_approvals();
    assert_eq!(cli.request(&sign)["result"], "denied");
    assert_eq!(asked(&backend), 6);

    // Any other purpose ignores the backend's scope: a secret is still
    // remembered for five minutes only, and never longer.
    backend.approve.store(true, Ordering::SeqCst);
    let reveal = json!({ "cmd": "reveal", "item": "github", "field": "password" });
    *backend.scope.lock().unwrap() = ApprovalScope::EveryTime;
    assert_eq!(cli.request(&reveal)["result"], "secret");
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(
        cli.request(&reveal)["result"],
        "secret",
        "EveryTime is ignored for a secret: the five-minute approval holds"
    );
    // The extension revoked: its approvals go with it.
    let _ = std::fs::remove_file(file);
}

// MARK: Catalog and plans

/// The agent session of these tests (what `verrou mcp` draws when it starts).
const SESSION: &str = "feedfacefeedface";
const OTHER_SESSION: &str = "0123456789abcdef0123456789abcdef";

fn plan_of(operations: &Value) -> Value {
    json!({ "cmd": "plan_propose", "session": SESSION, "plan": { "reason": "tidy the vault", "operations": operations } })
}

fn status_of(plan: &str, wait: u32) -> Value {
    json!({ "cmd": "plan_status", "session": SESSION, "plan": plan, "wait": wait })
}

/// The user approves this session reading the catalog (one Touch ID).
fn read_catalog(cli: &mut Client, backend: &FakeBackend) {
    backend.approve.store(true, Ordering::SeqCst);
    let reply = cli.request(&json!({ "cmd": "vault_overview", "session": SESSION }));
    assert_eq!(reply["result"], "overview", "{reply}");
}

fn rename_github() -> Value {
    json!([{ "op": "rename", "item": "github", "title": "GitHub (work)", "rationale": "say what it is" }])
}

/// One approval opens the whole catalog for half an hour for one agent
/// session, an agent's refusal pauses its prompts, and nothing a page of it
/// says is a secret.
#[test]
fn the_catalog_is_approved_once_per_session_and_carries_no_secret() {
    let (bridge, backend, pairings, file) = start();
    {
        let mut vault = backend.vault.lock().unwrap();
        let mut items = vault.items().to_vec();
        items.push(banque());
        *vault = Vault::new(items);
    }
    let mut cli = paired(&bridge, &pairings, "cli");
    let asked = |backend: &FakeBackend| backend.confirmations.lock().unwrap().len();
    let list = json!({ "cmd": "vault_list", "offset": 0, "limit": 2, "session": SESSION });
    let agent = json!({ "cmd": "vault_list", "limit": 2, "session": SESSION, "reason": "Coding Agent: tidy", "ephemeral_approval": true });

    // Refused: nothing is read, the agent's prompts pause.
    backend.approve.store(false, Ordering::SeqCst);
    assert_eq!(cli.request(&agent)["result"], "denied");
    backend.approve.store(true, Ordering::SeqCst);
    assert_eq!(cli.request(&agent)["result"], "denied");
    assert_eq!(asked(&backend), 1, "the declined prompt does not come back");

    // The user's own terminal is not paused; its approval holds.
    let page = cli.request(&list);
    assert_eq!(page["result"], "catalog");
    assert_eq!(asked(&backend), 2);
    {
        let first = &backend.confirmations.lock().unwrap()[1];
        assert_eq!(first.purpose, Purpose::Catalog);
        assert_eq!(first.item, format!("catalog:{SESSION}"));
        assert!(!first.ephemeral, "an approval an earlier one may cover");
        assert!(
            first.title.contains("catalog") && first.title.contains("no secret"),
            "an old iPhone approver shows something meaningful: {:?}",
            first.title
        );
    }
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["total"], 5);
    assert_eq!(cli.request(&list)["result"], "catalog");
    assert_eq!(
        cli.request(&json!({ "cmd": "vault_overview", "session": SESSION }))["result"],
        "overview"
    );
    assert_eq!(
        cli.request(&json!({ "cmd": "vault_duplicates", "session": SESSION }))["result"],
        "duplicates"
    );
    assert_eq!(asked(&backend), 2, "one approval for all three");

    // Another agent session of the same client is asked again.
    let mut other = list.clone();
    other["session"] = json!(OTHER_SESSION);
    assert_eq!(cli.request(&other)["result"], "catalog");
    assert_eq!(asked(&backend), 3);
    // A request without a session is asked on its own, every time.
    let alone = json!({ "cmd": "vault_list", "limit": 1 });
    assert_eq!(cli.request(&alone)["result"], "catalog");
    assert_eq!(cli.request(&alone)["result"], "catalog");
    assert_eq!(asked(&backend), 5);
    assert!(backend.confirmations.lock().unwrap()[4].ephemeral);

    // Never a secret, whatever the page.
    let mut everything = String::new();
    for offset in 0..5 {
        everything += &cli
            .request(
                &json!({ "cmd": "vault_list", "offset": offset, "limit": 1, "session": SESSION }),
            )
            .to_string();
    }
    everything += &cli
        .request(&json!({ "cmd": "vault_overview", "session": SESSION }))
        .to_string();
    for secret in [
        "hunter2",
        "coffre-fort",
        "JBSWY3DPEHPK3PXP",
        "question secrète",
        "4242 4242",
        "CAMILLE MARTIN",
    ] {
        assert!(!everything.contains(secret), "{secret} leaked");
    }
    assert!(
        everything.contains("Empty"),
        "the folders the app knows, empty ones too"
    );

    // It ends with the vault's lock, and the browser never has it.
    bridge.forget_approvals();
    assert_eq!(cli.request(&list)["result"], "catalog");
    assert_eq!(asked(&backend), 6);
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_browser_cannot_read_the_catalog_or_propose_a_plan() {
    let (bridge, backend, pairings, file) = start();
    let mut browser = paired(&bridge, &pairings, "browser");
    backend.approve.store(true, Ordering::SeqCst);
    for command in [
        json!({ "cmd": "vault_list" }),
        json!({ "cmd": "vault_overview" }),
        json!({ "cmd": "vault_duplicates" }),
        plan_of(&rename_github()),
        json!({ "cmd": "plan_status", "plan": "x" }),
        json!({ "cmd": "plan_cancel", "plan": "x" }),
    ] {
        assert_eq!(browser.request(&command)["result"], "denied", "{command}");
    }
    assert!(backend.confirmations.lock().unwrap().is_empty());
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_plan_needs_the_catalog_read_in_the_same_session_and_asks_nothing() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    backend.approve.store(true, Ordering::SeqCst);
    // Not read yet: refused, and the user is not asked anything.
    let refused = cli.request(&plan_of(&rename_github()));
    assert_eq!(refused["result"], "denied");
    assert!(
        refused["reason"]
            .as_str()
            .unwrap()
            .contains("verrou_list_items"),
        "{refused}"
    );
    assert!(backend.confirmations.lock().unwrap().is_empty());
    assert!(backend.plans.lock().unwrap().is_empty());
    // Read by another session of the client: not this one's.
    let other = json!({ "cmd": "vault_overview", "session": OTHER_SESSION });
    assert_eq!(cli.request(&other)["result"], "overview");
    assert_eq!(cli.request(&plan_of(&rename_github()))["result"], "denied");
    // Read in this session: it goes through, with no new approval.
    read_catalog(&mut cli, &backend);
    let asked = backend.confirmations.lock().unwrap().len();
    assert_eq!(cli.request(&plan_of(&rename_github()))["result"], "plan");
    assert_eq!(backend.confirmations.lock().unwrap().len(), asked);
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_plan_is_checked_then_shown_and_the_agent_follows_it() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    let asked = backend.confirmations.lock().unwrap().len();
    let proposed = cli.request(&plan_of(&json!([
        { "op": "rename", "item": "github", "title": "GitHub (work)", "rationale": "clearer" },
        { "op": "rename", "item": "nope", "title": "x", "rationale": "y" },
        { "op": "move", "item": "visa", "folder": "Empty", "rationale": "money" },
        { "op": "set_tags", "item": "visa", "tags": ["a"] },
    ])));
    assert_eq!(proposed["result"], "plan", "{proposed}");
    assert_eq!(proposed["state"], "awaiting_review");
    assert_eq!(proposed["expires_in"], 600);
    let rejected = proposed["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 2);
    assert_eq!(rejected[0]["index"], 1);
    assert!(
        !rejected[0]["reason"].as_str().unwrap().contains("nope"),
        "an unknown id is not repeated"
    );
    assert!(
        rejected[1]["reason"]
            .as_str()
            .unwrap()
            .contains("use folders")
    );
    assert_eq!(
        backend.confirmations.lock().unwrap().len(),
        asked,
        "the review is the user's decision"
    );
    let id = proposed["plan"].as_str().unwrap().to_owned();
    {
        let shown = backend.plans.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(
            (
                shown[0].id.as_str(),
                shown[0].ops.len(),
                shown[0].refused.len()
            ),
            (id.as_str(), 2, 2)
        );
        assert_eq!(shown[0].reason, "tidy the vault");
        assert_eq!(shown[0].client_name, "verrou");
    }

    // A second one while this one waits, from anyone, is refused.
    let again = cli.request(&plan_of(&rename_github()));
    assert_eq!(again["result"], "denied");
    assert!(again["reason"].as_str().unwrap().contains(&id));

    // Another session of the client does not see it.
    let mut stranger = status_of(&id, 0);
    stranger["session"] = json!(OTHER_SESSION);
    assert_eq!(cli.request(&stranger)["result"], "denied");

    // The agent waits for the answer; the user applies from the app.
    let started = std::time::Instant::now();
    let done = std::thread::scope(|scope| {
        let applying = scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(400));
            let taken = bridge.take_plan(&id, &[0, 2]).unwrap();
            assert_eq!(taken.ops.len(), 2);
            bridge.finish_plan(
                &id,
                verrou_bridge::protocol::PlanReport {
                    applied: 2,
                    ..Default::default()
                },
            );
        });
        let reply = cli.request(&status_of(&id, 5));
        applying.join().unwrap();
        reply
    });
    let waited = started.elapsed();
    assert_eq!(done["state"], "applied", "{done}");
    assert_eq!(done["report"]["applied"], 2);
    assert_eq!(done["report"]["unchanged"], 0);
    assert!(
        waited >= Duration::from_millis(300) && waited < Duration::from_secs(4),
        "{waited:?}"
    );

    // While the user can still undo it, the agent proposes nothing else:
    // the result sheet is open. Closing the sheet frees it.
    let held = cli.request(&plan_of(&rename_github()));
    assert_eq!(held["result"], "denied");
    assert!(
        held["reason"].as_str().unwrap().contains("still reviewing"),
        "{held}"
    );
    bridge.plan_closed(&id);
    assert_eq!(cli.request(&plan_of(&rename_github()))["result"], "plan");

    // The user undoes the first one.
    bridge.mark_undone(&id);
    assert_eq!(cli.request(&status_of(&id, 0))["state"], "undone");
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_plan_that_stopped_halfway_ends_interrupted_with_its_report() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    let proposed = cli.request(&plan_of(&rename_github()));
    let id = proposed["plan"].as_str().unwrap().to_owned();
    bridge.take_plan(&id, &[0]).unwrap();
    bridge.interrupt_plan(
        &id,
        verrou_bridge::protocol::PlanReport {
            applied: 1,
            ..Default::default()
        },
        "stopped before the end",
    );
    let status = cli.request(&status_of(&id, 0));
    assert_eq!(status["state"], "interrupted", "{status}");
    assert_eq!(status["report"]["applied"], 1);
    assert_eq!(status["message"], "stopped before the end");
    // Nothing to undo: another plan may come.
    assert_eq!(cli.request(&plan_of(&rename_github()))["result"], "plan");
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_declined_plan_pauses_proposals_and_a_withdrawn_one_closes_the_review() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    let first = cli.request(&plan_of(&rename_github()));
    let id = first["plan"].as_str().unwrap().to_owned();
    bridge.decline_plan(&id, "the user declined the plan");
    let status = cli.request(&status_of(&id, 0));
    assert_eq!(status["state"], "declined");
    assert_eq!(status["message"], "the user declined the plan");
    let paused = cli.request(&plan_of(&rename_github()));
    assert_eq!(paused["result"], "denied");
    assert!(paused["reason"].as_str().unwrap().contains("declined"));

    // A plan the app cannot take is refused, and does not count.
    let (bridge, backend2, pairings, file2) = start();
    backend2.show_plans.store(false, Ordering::SeqCst);
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend2);
    let refused = cli.request(&plan_of(&rename_github()));
    assert_eq!(refused["result"], "denied");
    let reason = refused["reason"].as_str().unwrap();
    assert!(reason.contains("cannot show"), "{reason}");
    assert!(
        !reason.contains("open Verrou"),
        "nothing says whether the user is there: {reason}"
    );
    backend2.show_plans.store(true, Ordering::SeqCst);
    let shown = cli.request(&plan_of(&rename_github()));
    assert_eq!(shown["result"], "plan");
    let id = shown["plan"].as_str().unwrap();
    // Withdrawn by the agent: the app is told to close its sheet.
    let cancelled = cli.request(&json!({ "cmd": "plan_cancel", "session": SESSION, "plan": id }));
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(backend2.withdrawn.lock().unwrap()[0].0, id);
    // Applying it now is refused.
    assert!(bridge.take_plan(id, &[0]).unwrap_err().contains("withdrew"));
    assert!(backend.withdrawn.lock().unwrap().is_empty());
    let _ = std::fs::remove_file(file);
    let _ = std::fs::remove_file(file2);
}

#[test]
fn locking_drops_the_plans_awaiting_review() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    let proposed = cli.request(&plan_of(&rename_github()));
    let id = proposed["plan"].as_str().unwrap().to_owned();
    bridge.drop_plans();
    let status = cli.request(&status_of(&id, 0));
    assert_eq!(status["state"], "cancelled");
    assert!(status["message"].as_str().unwrap().contains("locked"));
    assert!(bridge.take_plan(&id, &[0]).is_err());
    let _ = std::fs::remove_file(file);
}

#[test]
fn a_whole_plan_that_is_wrong_is_refused_with_its_reason() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    for (operations, needle) in [
        (json!([]), "no operation"),
        (
            json!([{ "op": "rename", "item": "github", "title": "x" }]),
            "rationale is required",
        ),
        (
            json!([{ "op": "trash", "item": "nope", "rationale": "x" }]),
            "none of the operations",
        ),
    ] {
        let reply = cli.request(&plan_of(&operations));
        assert_eq!(reply["result"], "denied");
        assert!(
            reply["reason"].as_str().unwrap().contains(needle),
            "{reply}"
        );
    }
    assert!(
        backend.plans.lock().unwrap().is_empty(),
        "nothing reached the user"
    );
    let _ = std::fs::remove_file(file);
}

/// Every proposal counts toward the hourly cap, those Verrou refused too.
#[test]
fn refused_proposals_count_toward_the_hourly_cap() {
    let (bridge, backend, pairings, file) = start();
    let mut cli = paired(&bridge, &pairings, "cli");
    read_catalog(&mut cli, &backend);
    let wrong = plan_of(&json!([{ "op": "trash", "item": "nope", "rationale": "x" }]));
    for _ in 0..30 {
        assert_eq!(cli.request(&wrong)["result"], "denied");
    }
    let reply = cli.request(&rename_proposal());
    assert_eq!(reply["result"], "denied");
    assert!(reply["reason"].as_str().unwrap().contains("at most 30"));
    let _ = std::fs::remove_file(file);
}

fn rename_proposal() -> Value {
    plan_of(&rename_github())
}
