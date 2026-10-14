//! Serveur du pont sur un faux coffre, pour tester l'extension ou le
//! terminal sans l'app :
//!
//! ```sh
//! VERROU_BRIDGE_PORT=41739 cargo run -p verrou-bridge --example test_server
//! VERROU_BRIDGE_PORT=41739 VERROU_CLI_CONFIG=/tmp/cli.json cargo run -p verrou-cli -- link
//! ```
//!
//! Les appairages sont acceptés d'office ; leur code est affiché (`CODE …`)
//! pour que le test le compare à celui de l'extension. Les demandes d'accord
//! du terminal aussi (`CONFIRM …`). Le coffre contient une clé SSH ed25519,
//! créée au démarrage, pour l'agent SSH.

use std::io::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_key::{Algorithm, LineEnding, PrivateKey};
use verrou_bridge::protocol::{Credentials, SaveAction, Suggestion};
use verrou_bridge::{
    Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan, access,
};
use verrou_core::{Field, FieldKind, Item, ItemKind, Vault};

static BRIDGE: OnceLock<Mutex<Option<Bridge>>> = OnceLock::new();

struct Fake {
    vault: Mutex<Vault>,
    created: AtomicU32,
}

impl Backend for Fake {
    fn is_unlocked(&self) -> bool {
        true
    }

    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>> {
        Some(access::suggestions(&self.vault.lock().unwrap(), page_url))
    }

    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Some(access::credentials(
            &self.vault.lock().unwrap(),
            item,
            page_url,
            now,
        ))
    }

    fn check_save(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        current: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>> {
        Some(access::check_save(
            &self.vault.lock().unwrap(),
            page_url,
            username,
            password,
            current,
        ))
    }

    /// Écrit dans le faux coffre et l'annonce (`SAVED <élément>`).
    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
        let mut vault = self.vault.lock().unwrap();
        let outcome = plan(&vault).map(|write| {
            let n = self.created.fetch_add(1, Ordering::SeqCst);
            let (updated, id) = access::apply_in_memory(&vault, write, &format!("nouveau-{n}"));
            *vault = updated;
            println!("SAVED {id}");
            let _ = std::io::stdout().flush();
            id
        });
        Box::pin(async move { Some(outcome) })
    }

    fn request_unlock(&self) {
        println!("UNLOCK");
    }

    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
        reader(&self.vault.lock().unwrap());
        true
    }

    /// Accord d'office, annoncé (`CONFIRM reveal|ssh|passkey|git <titre>`).
    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool> {
        let purpose = match request.purpose {
            Purpose::Reveal => "reveal",
            Purpose::Ssh => "ssh",
            Purpose::Passkey => "passkey",
            Purpose::GitSign => "git",
        };
        println!("CONFIRM {purpose} {}", request.title);
        let _ = std::io::stdout().flush();
        Box::pin(async { true })
    }

    fn pairing_requested(&self, request: PairingRequest) {
        println!("CODE {}", request.code);
        let _ = std::io::stdout().flush();
        // Accord d'office, hors du fil du serveur, après le temps de lire
        // le code (l'extension l'affiche en attendant).
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            if let Some(bridge) = BRIDGE
                .get()
                .and_then(|b| b.lock().ok())
                .as_deref()
                .and_then(Option::as_ref)
            {
                bridge.answer_pairing(&request.id, true);
            }
        });
    }
}

/// Une carte et une identité, pour les formulaires de paiement et d'adresse.
fn card() -> Item {
    let mut item = login("visa", "Visa perso", "", "", "");
    item.kind = ItemKind::Card;
    item.urls.clear();
    "Visa •••• 4242".clone_into(&mut item.subtitle);
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

fn identity() -> Item {
    let mut item = login("moi", "Moi", "", "", "");
    item.kind = ItemKind::Identity;
    item.urls.clear();
    "camille@exemple.fr".clone_into(&mut item.subtitle);
    item.fields = vec![
        Field::new("first_name", "Prénom", FieldKind::Text, "Camille"),
        Field::new("last_name", "Nom", FieldKind::Text, "Martin"),
        Field::new("email", "E-mail", FieldKind::Email, "camille@exemple.fr"),
        Field::new("part:address1", "", FieldKind::Text, "12 rue des Lilas"),
        Field::new("part:postal_code", "", FieldKind::Text, "74000"),
        Field::new("part:city", "", FieldKind::Text, "Annecy"),
        Field::new("part:country", "", FieldKind::Text, "France"),
    ];
    item
}

fn login(id: &str, title: &str, url: &str, username: &str, password: &str) -> Item {
    Item {
        id: id.to_owned(),
        kind: ItemKind::Login,
        title: title.to_owned(),
        subtitle: username.to_owned(),
        urls: vec![url.to_owned()],
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified: 0,
        fields: vec![
            Field::new("username", "Identifiant", FieldKind::Username, username),
            Field::new("password", "Mot de passe", FieldKind::Password, password),
            Field::new("totp", "Code", FieldKind::Totp, "JBSWY3DPEHPK3PXP"),
        ],
        notes: None,
        reprompt: false,
        state: verrou_core::ItemState::Active,
    }
}

/// Une clé SSH ed25519 neuve, au format que Vaultwarden garde.
fn ssh_key() -> Item {
    let key = PrivateKey::random(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    Item {
        id: "cle-ssh".to_owned(),
        kind: ItemKind::SshKey,
        title: "Clé SSH de test".to_owned(),
        subtitle: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
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
        state: verrou_core::ItemState::Active,
    }
}

fn main() {
    let vault = Vault::new(vec![
        login(
            "github",
            "GitHub",
            "https://github.com",
            "camille",
            "hunter2-hunter2",
        ),
        login(
            "local",
            "Site de test",
            "http://localhost",
            "camille@exemple.fr",
            "mot-de-passe-local",
        ),
        ssh_key(),
        card(),
        identity(),
    ]);
    let file = std::env::temp_dir().join(format!("verrou-bridge-test-{}.json", std::process::id()));
    let bridge = Bridge::start(
        verrou_bridge::port_from_env(),
        file,
        Arc::new(Fake {
            vault: Mutex::new(vault),
            created: AtomicU32::new(0),
        }),
    )
    .unwrap();
    println!("PORT {}", bridge.port());
    let _ = std::io::stdout().flush();
    BRIDGE.get_or_init(|| Mutex::new(Some(bridge)));
    loop {
        std::thread::park();
    }
}
