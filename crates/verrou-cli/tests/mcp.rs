//! `verrou mcp`, the real binary, against a real bridge with a fake vault:
//! the MCP handshake, search, running a command, and above
//! all that no password ever shows up in anything the server prints.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};
use verrou_bridge::protocol::{Credentials, SaveAction, Suggestion};
use verrou_bridge::{Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan};
use verrou_cli::remote::{self, Endpoint};
use verrou_core::{Field, FieldKind, Item, ItemKind, ItemState, Vault};

/// Never to be seen in the server's output.
const GITHUB_PASSWORD: &str = "hunter2-s3cret-GH";
const DEPLOY_PASSWORD: &str = "other-pw-777-DEPLOY";
const API_TOKEN: &str = "tok_live_51Hxyz-API";
const NOTES: &str = "recovery codes: 1234-5678-9999";

struct Fake {
    vault: Mutex<Vault>,
    pairings: Mutex<mpsc::Sender<PairingRequest>>,
    /// (purpose, title, field or site, reason) of each approval asked.
    asked: Mutex<Vec<(Purpose, String, String, String)>>,
    refuse: AtomicBool,
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
        self.asked.lock().unwrap().push((
            request.purpose,
            request.title,
            request.site,
            request.reason,
        ));
        let granted = !self.refuse.load(Ordering::SeqCst);
        Box::pin(async move { granted })
    }
}

fn login(id: &str, title: &str, password: &str) -> Item {
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

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vm-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A running `verrou mcp`, speaking line-delimited JSON-RPC.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next: u64,
    /// Every line the server printed, to look for secrets in.
    transcript: Vec<String>,
}

impl Mcp {
    fn start(config: &std::path::Path, port: u16) -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_verrou"))
            .arg("mcp")
            .env("VERROU_CLI_CONFIG", config)
            .env("VERROU_BRIDGE_PORT", port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next: 1,
            transcript: Vec::new(),
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "the server closed its output");
        let value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"));
        self.transcript.push(line);
        value
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let reply = self.read();
        assert_eq!(reply["id"], id);
        reply
    }

    /// A tool call: (`is_error`, parsed text if JSON, raw text).
    fn tool(&mut self, name: &str, arguments: &Value) -> (bool, Value, String) {
        let reply = self.request("tools/call", &json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        let text = result["content"][0]["text"].as_str().unwrap().to_owned();
        (
            result["isError"].as_bool().unwrap(),
            serde_json::from_str(&text).unwrap_or(Value::Null),
            text,
        )
    }
}

#[test]
#[allow(clippy::too_many_lines)] // a complete walkthrough, readable in one go
fn mcp_never_prints_a_secret_value() {
    let (sender, pairings) = mpsc::channel();
    let backend = Arc::new(Fake {
        vault: Mutex::new(Vault::new(vec![
            login("github", "GitHub", GITHUB_PASSWORD),
            login("deploy", "Deploy key", DEPLOY_PASSWORD),
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
            let request: PairingRequest = pairings.recv_timeout(Duration::from_secs(5)).unwrap();
            bridge.answer_pairing(&request.id, true);
        })
    };
    let config = remote::link(endpoint, "terminal (verrou)", |_| {}).unwrap();
    approver.join().unwrap();
    let config_path = dir.join("cli.json");
    config.save(&config_path).unwrap();

    let mut mcp = Mcp::start(&config_path, bridge.port());

    // Handshake, as a client does it.
    let init = mcp.request(
        "initialize",
        &json!({"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"Claude Code","version":"2"}}),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    mcp.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let tools = mcp.request("tools/list", &json!({}));
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 4);
    assert_eq!(mcp.request("ping", &json!({}))["result"], json!({}));

    let (error, status, _) = mcp.tool("verrou_status", &json!({}));
    assert!(!error);
    assert_eq!(
        (status["linked"].clone(), status["unlocked"].clone()),
        (json!(true), json!(true))
    );

    // Search: names and references, no value, no approval.
    let (error, found, text) = mcp.tool("verrou_search", &json!({"query": "github"}));
    assert!(!error, "{text}");
    let item = &found["items"][0];
    assert_eq!(item["title"], "GitHub");
    assert_eq!(item["username"], "camille");
    let references: Vec<&str> = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["reference"].as_str().unwrap())
        .collect();
    assert!(
        references.contains(&"verrou://GitHub/password"),
        "{references:?}"
    );
    assert!(
        references.contains(&"verrou://GitHub/notes"),
        "{references:?}"
    );
    assert!(backend.asked.lock().unwrap().is_empty());

    // Run: the command gets the value, the model gets it masked, the
    // approval carries the client's name and the reason.
    let script = format!(
        "echo \"login with $TOKEN\"; echo \"stderr $TOKEN\" >&2; test \"$TOKEN\" = '{GITHUB_PASSWORD}'"
    );
    let (error, ran, text) = mcp.tool(
        "verrou_run",
        &json!({
            "command": ["sh", "-c", script],
            "env": {"TOKEN": "verrou://GitHub/password"},
            "reason": "deploy to staging"
        }),
    );
    assert!(!error, "{text}");
    assert_eq!(ran["exit_code"], 0, "the command did get the real value");
    assert_eq!(ran["stdout"], "login with <concealed by Verrou>\n");
    assert_eq!(ran["stderr"], "stderr <concealed by Verrou>\n");
    assert_eq!(
        backend.asked.lock().unwrap().as_slice(),
        [(
            Purpose::Reveal,
            "GitHub".to_owned(),
            String::new(),
            "Claude Code: deploy to staging".to_owned()
        )]
    );

    // A refused approval: a tool error, no value, the command did not run.
    backend.refuse.store(true, Ordering::SeqCst);
    let marker = dir.join("ran");
    let (error, _, text) = mcp.tool(
        "verrou_run",
        &json!({
            "command": ["sh", "-c", format!("touch {}", marker.display())],
            "env": {"TOKEN": "verrou://Deploy key/password"},
            "reason": "deploy"
        }),
    );
    assert!(error);
    assert!(text.contains("refused"), "{text}");
    assert!(!marker.exists());
    backend.refuse.store(false, Ordering::SeqCst);

    // A custom hidden field is named by its label in a reference.
    let (error, ran, text) = mcp.tool(
        "verrou_run",
        &json!({
            "command": ["sh", "-c", "echo \"key=$STRIPE\""],
            "env": {"STRIPE": "verrou://GitHub/API%20token"},
            "reason": "call the API"
        }),
    );
    assert!(!error, "{text}");
    assert_eq!(ran["stdout"], "key=<concealed by Verrou>\n");
    assert_eq!(ran["exit_code"], 0);

    // A generated password is new, not the vault's: it may be returned.
    let (error, generated, _) = mcp.tool("verrou_generate_password", &json!({"length": 30}));
    assert!(!error);
    assert_eq!(generated["value"].as_str().unwrap().chars().count(), 30);

    // Not a reference: refused before anything is asked.
    let asked = backend.asked.lock().unwrap().len();
    let (error, _, _) = mcp.tool(
        "verrou_run",
        &json!({"command":["true"],"env":{"T":"literal"},"reason":"x"}),
    );
    assert!(error);
    assert_eq!(backend.asked.lock().unwrap().len(), asked);

    // The point of it all: nothing the server printed holds a secret.
    drop(mcp.stdin.take());
    assert!(mcp.child.wait().unwrap().success());
    let everything = mcp.transcript.join("\n");
    for secret in [GITHUB_PASSWORD, DEPLOY_PASSWORD, NOTES, API_TOKEN] {
        assert!(
            !everything.contains(secret),
            "a secret value appeared in the MCP output: {secret}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
