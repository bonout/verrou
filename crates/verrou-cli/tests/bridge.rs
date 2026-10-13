//! La CLI et son agent SSH contre un vrai pont (en mémoire, faux coffre) :
//! appairage, déverrouillage demandé, secrets, et un client SSH qui parle à
//! l'agent par un socket Unix.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use signature::Verifier as _;
use ssh_key::encoding::Decode as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};
use verrou_bridge::protocol::{
    ClientKind, Command, Credentials, ReplyResult, SaveAction, Suggestion,
};
use verrou_bridge::{Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan};
use verrou_cli::agent::{self, BridgeKeys, Keys};
use verrou_cli::config::Config;
use verrou_cli::remote::{self, Endpoint, Error, Remote};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

struct Fake {
    vault: Vault,
    unlocked: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    confirmations: Mutex<Vec<(Purpose, String)>>,
}

impl Backend for Fake {
    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
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

    /// Comme Touch ID qui réussit un instant plus tard.
    fn request_unlock(&self) {
        std::thread::sleep(Duration::from_millis(300));
        self.unlocked.store(true, Ordering::SeqCst);
    }

    fn pairing_requested(&self, request: PairingRequest) {
        let _ = self.pairings.lock().unwrap().send(request);
    }

    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        reader(&self.vault);
        true
    }

    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool> {
        self.confirmations
            .lock()
            .unwrap()
            .push((request.purpose, request.title));
        Box::pin(async { true })
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
        fields: vec![Field::new(
            "private_key",
            "Clé privée",
            FieldKind::Concealed,
            key.to_openssh(LineEnding::LF).unwrap().as_str(),
        )],
        notes: None,
        reprompt: false,
        state: verrou_core::ItemState::Active,
    }
}

fn login() -> Item {
    Item {
        id: "github".to_owned(),
        kind: ItemKind::Login,
        title: "GitHub".to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://github.com".to_owned()],
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new("username", "Identifiant", FieldKind::Username, "camille"),
            Field::new("password", "Mot de passe", FieldKind::Password, "hunter2"),
        ],
        notes: None,
        reprompt: false,
        state: verrou_core::ItemState::Active,
    }
}

/// Un dossier temporaire au chemin court (les sockets Unix sont limités à
/// une centaine d'octets).
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vc-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn agent_call(stream: &mut UnixStream, body: &[u8]) -> Vec<u8> {
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).unwrap();
    let mut answer = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut answer).unwrap();
    answer
}

fn ssh_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
}

/// Lit un `string` SSH en tête de `bytes`.
fn take_string(bytes: &mut &[u8]) -> Vec<u8> {
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let value = bytes[4..4 + length].to_vec();
    *bytes = &bytes[4 + length..];
    value
}

#[test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
fn link_then_ssh_agent_signs_through_verrou() {
    let key = PrivateKey::random(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    let (sender, pairings) = mpsc::channel();
    let backend = Arc::new(Fake {
        vault: Vault::new(vec![login(), ssh_item(&key)]),
        unlocked: AtomicBool::new(false),
        pairings: Mutex::new(sender),
        confirmations: Mutex::new(Vec::new()),
    });
    let dir = temp_dir();
    let bridge = Arc::new(Bridge::start(0, dir.join("clients.json"), backend.clone()).unwrap());
    let endpoint = Endpoint {
        port: bridge.port(),
        launch: false,
    };

    // `verrou link` : Verrou voit un terminal, avec le même code.
    let approver = {
        let bridge = Arc::clone(&bridge);
        std::thread::spawn(move || {
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(request.kind, ClientKind::Cli);
            assert_eq!(request.name, "le terminal (verrou)");
            bridge.answer_pairing(&request.id, true);
            request.code
        })
    };
    let mut shown = String::new();
    let config = remote::link(endpoint, "le terminal (verrou)", |code| {
        shown = code.to_owned();
    })
    .unwrap();
    assert_eq!(approver.join().unwrap(), shown);
    let path = dir.join("cli.json");
    config.save(&path).unwrap();
    let config = Config::load(&path).unwrap().unwrap();

    // Coffre verrouillé : la CLI demande le déverrouillage et attend.
    let mut remote = Remote::connect(&config, endpoint).unwrap();
    assert!(!remote.unlocked().unwrap());
    let found = remote
        .ask(&Command::VaultSearch {
            query: "git".to_owned(),
            kind: None,
            favorites: false,
            limit: None,
        })
        .unwrap();
    let ReplyResult::Items { items, total } = found else {
        panic!("résultats attendus : {found:?}");
    };
    assert_eq!((items[0].id.as_str(), total), ("github", 1));
    let secret = remote
        .ask(&Command::Reveal {
            item: "github".to_owned(),
            field: "password".to_owned(),
        })
        .unwrap();
    assert!(matches!(secret, ReplyResult::Secret(ref s) if s.value == "hunter2"));
    // Une commande de l'extension : refusée.
    let fill = remote.ask(&Command::Fill {
        url: "https://github.com/".to_owned(),
        item: "github".to_owned(),
    });
    assert!(matches!(fill, Err(Error::Denied(_))), "{fill:?}");

    // L'agent SSH, sur un socket Unix, signe par Verrou.
    let socket = dir.join("a.sock");
    let listener = agent::bind(&socket, false).unwrap();
    let keys: Arc<dyn Keys> = Arc::new(BridgeKeys {
        config: Config::load(&path).unwrap().unwrap(),
        endpoint,
    });
    std::thread::spawn(move || agent::serve(&listener, &keys));
    let mut ssh = UnixStream::connect(&socket).unwrap();
    ssh.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let answer = agent_call(&mut ssh, &[agent::SSH_AGENTC_REQUEST_IDENTITIES]);
    assert_eq!(answer[0], agent::SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(answer[1..5], [0, 0, 0, 1]);
    let mut rest = &answer[5..];
    let blob = take_string(&mut rest);
    assert_eq!(blob, key.public_key().to_bytes().unwrap());
    assert_eq!(take_string(&mut rest), "Clé du N100".as_bytes());

    let mut request = vec![agent::SSH_AGENTC_SIGN_REQUEST];
    ssh_string(&mut request, &blob);
    ssh_string(&mut request, b"donnees de session");
    request.extend_from_slice(&0u32.to_be_bytes());
    let answer = agent_call(&mut ssh, &request);
    assert_eq!(answer[0], agent::SSH_AGENT_SIGN_RESPONSE);
    let mut rest = &answer[1..];
    let encoded = take_string(&mut rest);
    let signature = Signature::decode(&mut &encoded[..]).unwrap();
    key.public_key()
        .key_data()
        .verify(b"donnees de session", &signature)
        .unwrap();
    assert_eq!(
        *backend.confirmations.lock().unwrap(),
        [
            (Purpose::Reveal, "GitHub".to_owned()),
            (Purpose::Ssh, "Clé du N100".to_owned())
        ]
    );

    // Ce que l'agent ne fait pas : échec, sans couper la connexion.
    assert_eq!(agent_call(&mut ssh, &[17, 0, 0, 0, 0]), agent::failure());
    let mut unknown = vec![agent::SSH_AGENTC_SIGN_REQUEST];
    ssh_string(&mut unknown, b"cle inconnue");
    ssh_string(&mut unknown, b"x");
    unknown.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(agent_call(&mut ssh, &unknown), agent::failure());

    // Délié dans Verrou : la CLI le dit, l'agent échoue.
    bridge.revoke(&config.client);
    assert_eq!(remote.call(&Command::Status), Err(Error::UnknownClient));
    assert_eq!(
        agent_call(&mut ssh, &[agent::SSH_AGENTC_REQUEST_IDENTITIES]),
        agent::failure()
    );
    let _ = std::fs::remove_dir_all(dir);
}
