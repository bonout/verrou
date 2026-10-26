//! The CLI and its SSH agent against a real bridge (in memory, fake vault):
//! pairing, requested unlock, secrets, and an SSH client talking to the
//! agent over a Unix socket; finally `ssh-keygen -Y sign` and a git commit
//! signed by that agent.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use signature::Verifier as _;
use ssh_key::encoding::Decode as _;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};
use verrou_bridge::protocol::{
    ClientKind, Command, Credentials, FieldChange, ItemChanges, ItemMove, ReplyResult, SaveAction,
    Suggestion,
};
use verrou_bridge::{Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan};
use verrou_cli::agent::{self, BridgeKeys, Keys};
use verrou_cli::config::Config;
use verrou_cli::git_signing::{Plan, Scope, SigningKey, choose};
use verrou_cli::remote::{self, Endpoint, Error, Remote};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

struct Fake {
    vault: Vault,
    unlocked: AtomicBool,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    confirmations: Mutex<Vec<(Purpose, String)>>,
    reasons: Mutex<Vec<String>>,
    /// What each unlock request announced.
    intents: Mutex<Vec<Option<verrou_bridge::protocol::UnlockIntent>>>,
    /// The writes the app was asked to carry out, checked.
    writes: Mutex<Vec<String>>,
    /// What each approval said a write changes.
    changes: Mutex<Vec<String>>,
    /// Each approval asked, whole.
    asked: Mutex<Vec<Confirmation>>,
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

    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
        let outcome = plan(&self.vault).map(|write| {
            let id = match &write {
                verrou_bridge::access::Write::EditItem { item, .. }
                | verrou_bridge::access::Write::MoveItem { item, .. } => item.clone(),
                _ => "new".to_owned(),
            };
            self.writes.lock().unwrap().push(format!("{write:?}"));
            id
        });
        Box::pin(async { Some(outcome) })
    }

    /// Like Touch ID succeeding a moment later.
    fn request_unlock(
        &self,
        _kind: verrou_bridge::protocol::ClientKind,
        _client: &str,
        _reason: &str,
        then: Option<&verrou_bridge::protocol::UnlockIntent>,
    ) {
        self.intents.lock().unwrap().push(then.cloned());
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
            .push((request.purpose, request.title.clone()));
        self.reasons.lock().unwrap().push(request.reason.clone());
        self.changes.lock().unwrap().push(request.changes.clone());
        self.asked.lock().unwrap().push(request);
        Box::pin(async { true })
    }
}

fn ssh_item(key: &PrivateKey) -> Item {
    named_ssh_item("cle-ssh", "Clé du N100", key)
}

fn named_ssh_item(id: &str, title: &str, key: &PrivateKey) -> Item {
    Item {
        id: id.to_owned(),
        kind: ItemKind::SshKey,
        title: title.to_owned(),
        subtitle: String::new(),
        urls: Vec::new(),
        url_matches: Vec::new(),
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
        shared: None,
    }
}

fn login() -> Item {
    Item {
        id: "github".to_owned(),
        kind: ItemKind::Login,
        title: "GitHub".to_owned(),
        subtitle: "camille".to_owned(),
        urls: vec!["https://github.com".to_owned()],
        url_matches: Vec::new(),
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
        shared: None,
    }
}

/// A temporary directory with a short path (Unix sockets are limited to
/// about a hundred bytes).
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

/// Reads an SSH `string` at the start of `bytes`.
fn take_string(bytes: &mut &[u8]) -> Vec<u8> {
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let value = bytes[4..4 + length].to_vec();
    *bytes = &bytes[4 + length..];
    value
}

#[test]
#[allow(clippy::too_many_lines)] // a complete walkthrough, readable in one go
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
        reasons: Mutex::new(Vec::new()),
        intents: Mutex::new(Vec::new()),
        writes: Mutex::new(Vec::new()),
        changes: Mutex::new(Vec::new()),
        asked: Mutex::new(Vec::new()),
    });
    let dir = temp_dir();
    let bridge = Arc::new(Bridge::start(0, dir.join("clients.json"), backend.clone()).unwrap());
    let endpoint = Endpoint {
        port: bridge.port(),
        launch: false,
    };

    // `verrou link`: Verrou sees a terminal, with the same code.
    let approver = {
        let bridge = Arc::clone(&bridge);
        std::thread::spawn(move || {
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(request.kind, ClientKind::Cli);
            assert_eq!(request.name, "terminal (verrou)");
            bridge.answer_pairing(&request.id, true);
            request.code
        })
    };
    let mut shown = String::new();
    let config = remote::link(endpoint, "terminal (verrou)", |code| {
        shown = code.to_owned();
    })
    .unwrap();
    assert_eq!(approver.join().unwrap(), shown);
    let path = dir.join("cli.json");
    config.save(&path).unwrap();
    let config = Config::load(&path).unwrap().unwrap();

    // Vault locked: the CLI asks for unlocking and waits.
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
        panic!("expected results: {found:?}");
    };
    assert_eq!((items[0].id.as_str(), total), ("github", 1));
    let secret = remote
        .ask(&Command::Reveal {
            item: "github".to_owned(),
            field: "password".to_owned(),
        })
        .unwrap();
    assert!(matches!(secret, ReplyResult::Secret(ref s) if s.value == "hunter2"));
    // An extension command: refused.
    let fill = remote.ask(&Command::Fill {
        url: "https://github.com/".to_owned(),
        item: "github".to_owned(),
    });
    assert!(matches!(fill, Err(Error::Denied(_))), "{fill:?}");

    // The SSH agent, on a Unix socket, signs through Verrou.
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

    // What the agent does not do: failure, without closing the connection.
    assert_eq!(agent_call(&mut ssh, &[17, 0, 0, 0, 0]), agent::failure());
    let mut unknown = vec![agent::SSH_AGENTC_SIGN_REQUEST];
    ssh_string(&mut unknown, b"cle inconnue");
    ssh_string(&mut unknown, b"x");
    unknown.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(agent_call(&mut ssh, &unknown), agent::failure());

    // Writes: checked, approved in Verrou, then carried out by the app.
    let created = remote.ask(&Command::ItemCreate {
        changes: ItemChanges {
            title: Some("Stripe".to_owned()),
            fields: vec![FieldChange {
                name: "API key".to_owned(),
                value: Some("sk_live".to_owned()),
                hidden: true,
            }],
            ..ItemChanges::default()
        },
    });
    assert_eq!(
        created,
        Ok(ReplyResult::Saved {
            item: "new".to_owned()
        })
    );
    // Each edit asks: approving one change is not approving the next.
    for changes in [
        ItemChanges {
            favorite: Some(true),
            ..ItemChanges::default()
        },
        ItemChanges {
            fields: vec![FieldChange {
                name: "password".to_owned(),
                value: Some("new-secret".to_owned()),
                hidden: false,
            }],
            ..ItemChanges::default()
        },
    ] {
        let edited = remote.ask(&Command::ItemEdit {
            item: "github".to_owned(),
            changes,
        });
        assert_eq!(
            edited,
            Ok(ReplyResult::Saved {
                item: "github".to_owned()
            })
        );
    }
    let trashed = remote.ask(&Command::ItemMove {
        item: "GitHub".to_owned(),
        to: ItemMove::Trash,
    });
    assert_eq!(
        trashed,
        Ok(ReplyResult::Saved {
            item: "github".to_owned()
        })
    );
    // Refused before any approval: an active item is not restored.
    let restored = remote.ask(&Command::ItemMove {
        item: "github".to_owned(),
        to: ItemMove::Restore,
    });
    assert!(matches!(restored, Err(Error::Denied(_))), "{restored:?}");
    assert_eq!(
        backend.confirmations.lock().unwrap()[2..],
        [
            (Purpose::Create, "Stripe".to_owned()),
            (Purpose::Edit, "GitHub".to_owned()),
            (Purpose::Edit, "GitHub".to_owned()),
            (Purpose::Delete, "GitHub".to_owned()),
        ]
    );
    // The approval names what changes, never a value.
    assert_eq!(
        backend.changes.lock().unwrap()[2..],
        ["API key", "favorite", "password", ""]
    );
    assert_eq!(backend.writes.lock().unwrap().len(), 4);
    assert!(
        !backend.writes.lock().unwrap()[0].contains("sk_live"),
        "a write's debug output shows no secret"
    );

    // Unlinked in Verrou: the CLI says so, the agent fails.
    bridge.revoke(&config.client);
    assert_eq!(remote.call(&Command::Status), Err(Error::UnknownClient));
    assert_eq!(
        agent_call(&mut ssh, &[agent::SSH_AGENTC_REQUEST_IDENTITIES]),
        agent::failure()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A system program (`ssh-keygen`, `git`), with a throwaway `HOME`:
/// nothing of the user's configuration is read or written.
fn tool(program: &str, home: &Path, socket: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command
        .env("HOME", home)
        .env("SSH_AUTH_SOCK", socket)
        .env_remove("SSH_AGENT_PID")
        .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

/// `arg` must do nothing but print the help or the version (`ssh-keygen`
/// without arguments would create a key in `~/.ssh`).
fn installed(program: &str, arg: &str) -> bool {
    std::process::Command::new(program)
        .arg(arg)
        .output()
        .is_ok()
}

fn check(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `ssh-keygen -Y sign` (what git calls with `gpg.format=ssh`) then
/// `ssh-keygen -Y verify`, through Verrou's agent on a throwaway socket;
/// then a real signed commit, verified by `git verify-commit`. Ed25519 and
/// RSA (the agent then receives the SHA-512 flag). Without `ssh-keygen` on
/// the machine, the test does nothing.
#[test]
#[allow(clippy::too_many_lines)] // a complete walkthrough, readable in one go
fn git_signs_through_the_agent() {
    if !installed("ssh-keygen", "-?") {
        eprintln!("ssh-keygen missing: test skipped");
        return;
    }
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let ed25519 = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let rsa = PrivateKey::new(
        KeypairData::from(RsaKeypair::random(&mut rng, 2048).unwrap()),
        "",
    )
    .unwrap();
    let (sender, pairings) = mpsc::channel();
    let backend = Arc::new(Fake {
        vault: Vault::new(vec![
            named_ssh_item("ed", "Signature git", &ed25519),
            named_ssh_item("rsa", "Vieille clé RSA", &rsa),
        ]),
        unlocked: AtomicBool::new(true),
        pairings: Mutex::new(sender),
        confirmations: Mutex::new(Vec::new()),
        reasons: Mutex::new(Vec::new()),
        intents: Mutex::new(Vec::new()),
        writes: Mutex::new(Vec::new()),
        changes: Mutex::new(Vec::new()),
        asked: Mutex::new(Vec::new()),
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
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            bridge.answer_pairing(&request.id, true);
        })
    };
    let config = remote::link(endpoint, "terminal (verrou)", |_| {}).unwrap();
    approver.join().unwrap();
    let config_path = dir.join("cli.json");
    config.save(&config_path).unwrap();

    // The keys, as `verrou git-signing` sees them.
    let mut remote = Remote::connect(&config, endpoint).unwrap();
    let ReplyResult::SshKeys { keys } = remote.ask(&Command::SshKeys).unwrap() else {
        panic!("expected SSH keys");
    };
    let keys: Vec<SigningKey> = keys.iter().filter_map(SigningKey::from_identity).collect();
    assert_eq!(keys.len(), 2);
    for (key, private) in [(&keys[0], &ed25519), (&keys[1], &rsa)] {
        assert_eq!(
            key.public_key,
            private.public_key().to_openssh().unwrap(),
            "OpenSSH public key, without comment"
        );
        assert_eq!(
            key.fingerprint,
            private.fingerprint(ssh_key::HashAlg::Sha256).to_string()
        );
    }

    // The agent, on a throwaway socket (never ~/.verrou/agent.sock).
    let socket = dir.join("a.sock");
    let listener = agent::bind(&socket, false).unwrap();
    let agent_keys: Arc<dyn Keys> = Arc::new(BridgeKeys {
        config: Config::load(&config_path).unwrap().unwrap(),
        endpoint,
    });
    std::thread::spawn(move || agent::serve(&listener, &agent_keys));

    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let message = dir.join("message.txt");
    std::fs::write(&message, "tree 4b825dc\nauthor Camille\n\nPremier commit\n").unwrap();
    for (index, key) in keys.iter().enumerate() {
        let public = dir.join(format!("cle-{index}.pub"));
        std::fs::write(&public, format!("{}\n", key.public_key)).unwrap();
        let signed = tool("ssh-keygen", &home, &socket)
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&public)
            .arg(&message)
            .output()
            .unwrap();
        check(&signed, &format!("ssh-keygen -Y sign ({})", key.title));
        let signature = dir.join("message.txt.sig");
        assert!(
            std::fs::read_to_string(&signature)
                .unwrap()
                .starts_with("-----BEGIN SSH SIGNATURE-----")
        );
        let signers = dir.join("allowed_signers");
        std::fs::write(
            &signers,
            format!("camille@exemple.fr namespaces=\"git\" {}\n", key.public_key),
        )
        .unwrap();
        let verify = |namespace: &str| {
            tool("ssh-keygen", &home, &socket)
                .args(["-Y", "verify", "-f"])
                .arg(&signers)
                .args(["-I", "camille@exemple.fr", "-n", namespace, "-s"])
                .arg(&signature)
                .stdin(std::fs::File::open(&message).unwrap())
                .output()
                .unwrap()
        };
        check(
            &verify("git"),
            &format!("ssh-keygen -Y verify ({})", key.title),
        );
        assert!(!verify("file").status.success(), "other namespace: refused");
        std::fs::remove_file(&signature).unwrap();
    }
    // The approval request says "git commit", once per key (then 5 minutes).
    assert_eq!(
        *backend.confirmations.lock().unwrap(),
        [
            (Purpose::GitSign, "Signature git".to_owned()),
            (Purpose::GitSign, "Vieille clé RSA".to_owned())
        ]
    );

    // A real commit: `verrou git-signing --apply`, on a throwaway global git
    // configuration (`GIT_CONFIG_GLOBAL`).
    if !installed("git", "--version") {
        eprintln!("git missing: signed commit not tested");
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    let plan = Plan {
        key: choose(&keys, "signature").unwrap().clone(),
        email: "camille@exemple.fr".to_owned(),
        allowed_signers: home.join(".config/verrou/allowed_signers"),
        scope: Scope::Global,
    };
    plan.apply(|| tool("git", &home, &socket)).unwrap();
    plan.apply(|| tool("git", &home, &socket)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&plan.allowed_signers).unwrap(),
        format!("{}\n", plan.allowed_signers_line()),
        "applying twice does not add the key twice"
    );
    let global = std::fs::read_to_string(home.join("gitconfig")).unwrap();
    assert!(global.contains("format = ssh"), "{global}");
    let repo = dir.join("depot");
    let git = |args: &[&str]| {
        let output = tool("git", &home, &socket)
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .unwrap();
        check(&output, &format!("git {}", args.join(" ")));
        String::from_utf8(output.stdout).unwrap()
    };
    std::fs::create_dir_all(&repo).unwrap();
    git(&["init", "-q"]);
    git(&["config", "user.name", "Camille"]);
    git(&["config", "user.email", "camille@exemple.fr"]);
    git(&[
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "Commit signé par Verrou",
    ]);
    git(&["verify-commit", "HEAD"]);
    let shown = git(&["log", "-1", "--format=%G?"]);
    assert_eq!(shown.trim(), "G", "good and trusted signature");
    // Still within the approval's 5 minutes: no new request.
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}

/// `verrou run`: the command gets the password in its environment, after
/// the approval; its output has it masked.
#[test]
fn run_hands_a_secret_to_a_command_masked() {
    let (sender, pairings) = mpsc::channel();
    let backend = Arc::new(Fake {
        vault: Vault::new(vec![login()]),
        // Locked: the unlock request says what will be read.
        unlocked: AtomicBool::new(false),
        pairings: Mutex::new(sender),
        confirmations: Mutex::new(Vec::new()),
        reasons: Mutex::new(Vec::new()),
        intents: Mutex::new(Vec::new()),
        writes: Mutex::new(Vec::new()),
        changes: Mutex::new(Vec::new()),
        asked: Mutex::new(Vec::new()),
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
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            bridge.answer_pairing(&request.id, true);
        })
    };
    let config = remote::link(endpoint, "terminal (verrou)", |_| {}).unwrap();
    approver.join().unwrap();
    let path = dir.join("cli.json");
    config.save(&path).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_verrou"))
        .args(["run", "--", "sh", "-c"])
        .arg(r#"[ "$TOKEN" = hunter2 ] && echo "got it: $TOKEN"; echo "$PLAIN" >&2"#)
        .env("VERROU_CLI_CONFIG", &path)
        .env("VERROU_BRIDGE_PORT", bridge.port().to_string())
        .env("TOKEN", "verrou://GitHub/password")
        .env("PLAIN", "nothing to hide")
        .env("VERROU_REASON", "deploy\nto production")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert_eq!(stdout, "got it: <concealed by Verrou>\n");
    assert_eq!(
        stderr,
        "verrou: vault locked, unlock it in Verrou…\nnothing to hide\n"
    );
    assert_eq!(
        backend.confirmations.lock().unwrap().as_slice(),
        [(Purpose::Reveal, "GitHub".to_owned())]
    );
    assert_eq!(
        backend.intents.lock().unwrap().as_slice(),
        [Some(verrou_bridge::protocol::UnlockIntent {
            item: "GitHub".to_owned(),
            field: "password".to_owned(),
        })]
    );
    // The reason reaches the approval, on one line.
    assert_eq!(
        backend.reasons.lock().unwrap().as_slice(),
        ["deploy to production".to_owned()]
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A command line driven by a coding agent (`CLAUDECODE`, or no terminal on
/// its input): `read`, `inject` and `run` ask for each approval on its own,
/// never remembered, and show the user what they will do: the command line,
/// and the references. One that would not fit in the approval is refused
/// before anything is asked.
#[test]
#[allow(clippy::too_many_lines)] // one walk through the three commands
fn an_agent_driven_terminal_asks_each_time_and_shows_the_command() {
    let (sender, pairings) = mpsc::channel();
    let backend = Arc::new(Fake {
        vault: Vault::new(vec![login()]),
        unlocked: AtomicBool::new(true),
        pairings: Mutex::new(sender),
        confirmations: Mutex::new(Vec::new()),
        reasons: Mutex::new(Vec::new()),
        intents: Mutex::new(Vec::new()),
        writes: Mutex::new(Vec::new()),
        changes: Mutex::new(Vec::new()),
        asked: Mutex::new(Vec::new()),
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
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            bridge.answer_pairing(&request.id, true);
        })
    };
    let config = remote::link(endpoint, "terminal (verrou)", |_| {}).unwrap();
    approver.join().unwrap();
    let path = dir.join("cli.json");
    config.save(&path).unwrap();
    let verrou = |args: &[&str]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_verrou"));
        command
            .args(args)
            .env("VERROU_CLI_CONFIG", &path)
            .env("VERROU_BRIDGE_PORT", bridge.port().to_string())
            .env("CLAUDECODE", "1");
        command
    };
    let asked = || backend.asked.lock().unwrap().clone();

    // `read` to a file, twice: asked twice, the approval of the first one
    // does not cover the second (nor is it remembered).
    let secret = dir.join("secret.txt");
    for round in 1..=2 {
        let output = verrou(&[
            "read",
            "verrou://GitHub/password",
            "-o",
            secret.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(asked().len(), round);
    }
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "hunter2\n");
    let first = &asked()[0];
    assert!(first.ephemeral);
    assert!(
        first
            .command
            .starts_with("verrou read verrou://GitHub/password -o "),
        "{}",
        first.command
    );
    assert!(first.command.contains("secret.txt"), "{}", first.command);
    assert_eq!(first.fields, "verrou://GitHub/password");

    // `inject`: the references of the template, the files.
    let template = dir.join("t.tpl");
    std::fs::write(
        &template,
        "pw={{ verrou://GitHub/password }} again={{ verrou://GitHub/password }}\n",
    )
    .unwrap();
    let output = verrou(&[
        "inject",
        "-i",
        template.to_str().unwrap(),
        "-o",
        dir.join("out.txt").to_str().unwrap(),
    ])
    .output()
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let inject = asked().pop().unwrap();
    assert!(inject.ephemeral);
    assert!(
        inject.command.starts_with("verrou inject -i "),
        "{}",
        inject.command
    );
    assert!(inject.command.contains(" -o "), "{}", inject.command);
    assert_eq!(inject.fields, "verrou://GitHub/password", "listed once");

    // `run`: the command line and each variable with its reference.
    let before = asked().len();
    let output = verrou(&["run", "--", "sh", "-c", "test \"$TOKEN\" = hunter2"])
        .env("TOKEN", "verrou://GitHub/password")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let run = asked().pop().unwrap();
    assert_eq!(asked().len(), before + 1);
    assert!(run.ephemeral);
    assert_eq!(
        run.command,
        "verrou run -- sh -c 'test \"$TOKEN\" = hunter2'"
    );
    assert_eq!(run.fields, "TOKEN=verrou://GitHub/password");

    // A command line the approval could not show whole: refused, and
    // nobody is asked.
    let before = asked().len();
    let long = "x".repeat(300);
    let output = verrou(&["run", "--", "echo", &long])
        .env("TOKEN", "verrou://GitHub/password")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("script file"), "{stderr}");
    assert_eq!(asked().len(), before);
    std::fs::remove_dir_all(&dir).ok();
}
