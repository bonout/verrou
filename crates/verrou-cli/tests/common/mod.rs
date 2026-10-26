//! What the integration tests of the terminal share: a bridge with a fake
//! vault and a linked terminal.
#![allow(dead_code)] // each test file uses part of it

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use verrou_bridge::protocol::{Credentials, SaveAction, Suggestion};
use verrou_bridge::{Backend, BoxFuture, Bridge, Confirmation, PairingRequest, WritePlan};
use verrou_cli::config::Config;
use verrou_cli::remote::{self, Endpoint};
use verrou_core::{Field, FieldKind, Item, ItemKind, ItemState, Vault};

/// Never to be seen in the server's output.
pub const GITHUB_PASSWORD: &str = "hunter2-s3cret-GH";
pub const DEPLOY_PASSWORD: &str = "other-pw-777-DEPLOY";
pub const TWIN_PASSWORD: &str = "twin-pw-4242-TWIN";
pub const API_TOKEN: &str = "tok_live_51Hxyz-API";
/// A hidden field labelled "password" next to the real password.
pub const SHADOW_VALUE: &str = "shadow-value-zzz-SHADOW";
pub const NOTES: &str = "recovery codes: 1234-5678-9999";

pub struct Fake {
    pub vault: Mutex<Vault>,
    pub pairings: Mutex<mpsc::Sender<PairingRequest>>,
    /// Each approval asked.
    pub asked: Mutex<Vec<Confirmation>>,
    pub refuse: AtomicBool,
}

impl Backend for Fake {
    fn is_unlocked(&self) -> bool {
        true
    }

    fn suggestions(&self, _: &str) -> Option<Vec<Suggestion>> {
        None
    }

    fn credentials(&self, _: &str, _: &str) -> Option<Result<Credentials, String>> {
        None
    }

    fn check_save(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>> {
        None
    }

    fn write(&self, _: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
        Box::pin(async { None })
    }

    fn request_unlock(
        &self,
        _: verrou_bridge::protocol::ClientKind,
        _: &str,
        _: &str,
        _: Option<&verrou_bridge::protocol::UnlockIntent>,
    ) {
    }

    fn pairing_requested(&self, request: PairingRequest) {
        let _ = self.pairings.lock().unwrap().send(request);
    }

    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
        reader(&self.vault.lock().unwrap());
        true
    }

    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool> {
        self.asked.lock().unwrap().push(request);
        let granted = !self.refuse.load(Ordering::SeqCst);
        Box::pin(async move { granted })
    }
}

pub fn login(id: &str, title: &str, password: &str) -> Item {
    Item {
        id: id.to_owned(),
        kind: ItemKind::Login,
        title: title.to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://example.com".to_owned()],
        url_matches: Vec::new(),
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new("username", "Username", FieldKind::Username, "camille"),
            Field::new("password", "Password", FieldKind::Password, password),
            Field::new("custom-0", "API token", FieldKind::Concealed, API_TOKEN),
        ],
        notes: Some(verrou_core::SecretString::new(NOTES)),
        reprompt: false,
        state: ItemState::Active,
        shared: None,
    }
}

pub fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vm-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A bridge with a fake vault and a linked terminal.
pub struct Base {
    pub backend: Arc<Fake>,
    pub bridge: Arc<Bridge>,
    pub dir: PathBuf,
    pub config: Config,
    /// The link file: `VERROU_CLI_CONFIG` of the programs under test.
    pub config_path: PathBuf,
}

impl Base {
    pub fn new() -> Self {
        let (sender, pairings) = mpsc::channel();
        let mut github = login("github", "GitHub", GITHUB_PASSWORD);
        github.fields.push(Field::new(
            "custom-1",
            "password",
            FieldKind::Concealed,
            SHADOW_VALUE,
        ));
        let backend = Arc::new(Fake {
            vault: Mutex::new(Vault::new(vec![
                github,
                login("deploy", "Deploy key", DEPLOY_PASSWORD),
                login("twin-a", "Twin", TWIN_PASSWORD),
                login("twin-b", "Twin", TWIN_PASSWORD),
            ])),
            pairings: Mutex::new(sender),
            asked: Mutex::new(Vec::new()),
            refuse: AtomicBool::new(false),
        });
        let dir = temp_dir();
        let bridge = Arc::new(Bridge::start(0, dir.join("clients.json"), backend.clone()).unwrap());
        let endpoint = Endpoint {
            port: bridge.port(),
            launch: false,
        };
        let approver = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                let request: PairingRequest =
                    pairings.recv_timeout(Duration::from_secs(5)).unwrap();
                bridge.answer_pairing(&request.id, true);
            })
        };
        let config = remote::link(endpoint, "terminal (verrou)", |_| {}).unwrap();
        approver.join().unwrap();
        let config_path = dir.join("cli.json");
        config.save(&config_path).unwrap();
        Self {
            backend,
            bridge,
            dir,
            config,
            config_path,
        }
    }

    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            port: self.bridge.port(),
            launch: false,
        }
    }

    /// How many approvals were asked so far.
    pub fn asked(&self) -> usize {
        self.backend.asked.lock().unwrap().len()
    }
}
