//! La CLI et son agent SSH contre un vrai pont (en mémoire, faux coffre) :
//! appairage, déverrouillage demandé, secrets, et un client SSH qui parle à
//! l'agent par un socket Unix ; enfin `ssh-keygen -Y sign` et un commit git
//! signés par cet agent.

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
    ClientKind, Command, Credentials, ReplyResult, SaveAction, Suggestion,
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
    named_ssh_item("cle-ssh", "Clé du N100", key)
}

fn named_ssh_item(id: &str, title: &str, key: &PrivateKey) -> Item {
    Item {
        id: id.to_owned(),
        kind: ItemKind::SshKey,
        title: title.to_owned(),
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

/// Un programme du système (`ssh-keygen`, `git`), avec un `HOME` jetable :
/// rien de la configuration de l'utilisateur n'est lu ni écrit.
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

/// `arg` ne doit rien faire d'autre qu'afficher l'aide ou la version
/// (`ssh-keygen` sans argument créerait une clé dans `~/.ssh`).
fn installed(program: &str, arg: &str) -> bool {
    std::process::Command::new(program)
        .arg(arg)
        .output()
        .is_ok()
}

fn check(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} : {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `ssh-keygen -Y sign` (ce que git appelle en `gpg.format=ssh`) puis
/// `ssh-keygen -Y verify`, par l'agent de Verrou sur un socket jetable ;
/// puis un vrai commit signé, vérifié par `git verify-commit`. Ed25519 et
/// RSA (l'agent reçoit alors le drapeau SHA-512). Sans `ssh-keygen` sur la
/// machine, le test ne fait rien.
#[test]
#[allow(clippy::too_many_lines)] // un parcours complet, lisible d'un trait
fn git_signs_through_the_agent() {
    if !installed("ssh-keygen", "-?") {
        eprintln!("ssh-keygen absent : test ignoré");
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
    let config = remote::link(endpoint, "le terminal (verrou)", |_| {}).unwrap();
    approver.join().unwrap();
    let config_path = dir.join("cli.json");
    config.save(&config_path).unwrap();

    // Les clés, comme les voit `verrou git-signing`.
    let mut remote = Remote::connect(&config, endpoint).unwrap();
    let ReplyResult::SshKeys { keys } = remote.ask(&Command::SshKeys).unwrap() else {
        panic!("clés SSH attendues");
    };
    let keys: Vec<SigningKey> = keys.iter().filter_map(SigningKey::from_identity).collect();
    assert_eq!(keys.len(), 2);
    for (key, private) in [(&keys[0], &ed25519), (&keys[1], &rsa)] {
        assert_eq!(
            key.public_key,
            private.public_key().to_openssh().unwrap(),
            "clé publique OpenSSH, sans commentaire"
        );
        assert_eq!(
            key.fingerprint,
            private.fingerprint(ssh_key::HashAlg::Sha256).to_string()
        );
    }

    // L'agent, sur un socket jetable (jamais ~/.verrou/agent.sock).
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
        assert!(
            !verify("file").status.success(),
            "autre espace de noms : refus"
        );
        std::fs::remove_file(&signature).unwrap();
    }
    // L'accord demandé dit « commit git », une fois par clé (puis 5 minutes).
    assert_eq!(
        *backend.confirmations.lock().unwrap(),
        [
            (Purpose::GitSign, "Signature git".to_owned()),
            (Purpose::GitSign, "Vieille clé RSA".to_owned())
        ]
    );

    // Un vrai commit : `verrou git-signing --apply`, sur une configuration
    // globale de git jetable (`GIT_CONFIG_GLOBAL`).
    if !installed("git", "--version") {
        eprintln!("git absent : commit signé non testé");
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
        "appliquer deux fois n'ajoute pas la clé deux fois"
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
    assert_eq!(shown.trim(), "G", "signature bonne et de confiance");
    // Toujours dans les 5 minutes de l'accord : pas de nouvelle demande.
    assert_eq!(backend.confirmations.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}
