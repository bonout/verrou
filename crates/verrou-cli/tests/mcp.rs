//! `verrou mcp`, the real binary, against a real bridge with a fake vault:
//! the MCP handshake, search, running a command, how each approval is asked,
//! and above all that no password ever shows up in anything the server
//! prints.

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use verrou_bridge::Purpose;
use verrou_bridge::protocol::{Command, ReplyResult};
use verrou_cli::remote::Remote;
use verrou_core::Vault;

use common::{
    API_TOKEN, Base, DEPLOY_PASSWORD, GITHUB_PASSWORD, NOTES, SHADOW_VALUE, TWIN_PASSWORD, login,
};

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

    /// `verrou_run` of a shell script with these references, "Claude Code"
    /// asking.
    fn run(&mut self, script: &str, env: &Value) -> (bool, Value, String) {
        self.tool(
            "verrou_run",
            &json!({"command": ["sh", "-c", script], "env": env, "reason": "deploy to staging"}),
        )
    }
}

/// A bridge with a fake vault, a linked terminal, and `verrou mcp` started
/// and initialized as "Claude Code".
struct World {
    base: Base,
    mcp: Mcp,
}

impl std::ops::Deref for World {
    type Target = Base;

    fn deref(&self) -> &Base {
        &self.base
    }
}

impl World {
    fn new() -> Self {
        let base = Base::new();
        let mut mcp = Mcp::start(&base.config_path, base.bridge.port());
        let init = mcp.request(
            "initialize",
            &json!({"protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"Claude Code","version":"2"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        mcp.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        Self { base, mcp }
    }

    /// What `verrou get` or `verrou run` does: a request of the same
    /// client, with the usual five-minute approval.
    fn reveal_like_the_cli(&self, item: &str, field: &str) {
        let mut cli = Remote::connect(&self.config, self.endpoint()).unwrap();
        cli.reason = Some("verrou run".to_owned());
        let secret = cli
            .ask(&Command::Reveal {
                item: item.to_owned(),
                field: field.to_owned(),
            })
            .unwrap();
        assert!(matches!(secret, ReplyResult::Secret(_)));
    }

    fn asked(&self) -> usize {
        self.backend.asked.lock().unwrap().len()
    }

    /// Ends the session and checks that nothing it printed holds a secret.
    fn finish(mut self) {
        drop(self.mcp.stdin.take());
        assert!(self.mcp.child.wait().unwrap().success());
        let everything = self.mcp.transcript.join("\n");
        for secret in [
            GITHUB_PASSWORD,
            DEPLOY_PASSWORD,
            TWIN_PASSWORD,
            API_TOKEN,
            SHADOW_VALUE,
            NOTES,
        ] {
            assert!(
                !everything.contains(secret),
                "a secret value appeared in the MCP output: {secret}"
            );
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

#[test]
#[allow(clippy::too_many_lines)] // a complete walkthrough, readable in one go
fn mcp_never_prints_a_secret_value() {
    let mut world = World::new();
    let tools = world.mcp.request("tools/list", &json!({}));
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 4);
    assert_eq!(world.mcp.request("ping", &json!({}))["result"], json!({}));

    let (error, status, _) = world.mcp.tool("verrou_status", &json!({}));
    assert!(!error);
    assert_eq!(
        (status["linked"].clone(), status["unlocked"].clone()),
        (json!(true), json!(true))
    );

    // Search: names and identifier references, no value, no approval.
    let (error, found, text) = world.mcp.tool("verrou_search", &json!({"query": "github"}));
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
    for expected in [
        "verrou://github/password",
        "verrou://github/custom-0",
        "verrou://github/custom-1",
        "verrou://github/notes",
    ] {
        assert!(references.contains(&expected), "{references:?}");
    }
    assert_eq!(world.asked(), 0);

    // Run: the command gets the value, the model gets it masked, the
    // approval carries the client's name, the reason, and what will run.
    let script = format!(
        "echo \"login with $TOKEN\"; echo \"stderr $TOKEN\" >&2; test \"$TOKEN\" = '{GITHUB_PASSWORD}'"
    );
    let (error, ran, text) = world
        .mcp
        .run(&script, &json!({"TOKEN": "verrou://GitHub/password"}));
    assert!(!error, "{text}");
    assert_eq!(
        ran["exit_code"], 0,
        "the command got the real password, not the field labelled \"password\""
    );
    assert_eq!(ran["stdout"], "login with <concealed by Verrou>\n");
    assert_eq!(ran["stderr"], "stderr <concealed by Verrou>\n");
    {
        let asked = world.backend.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].purpose, Purpose::Reveal);
        assert_eq!(asked[0].title, "GitHub");
        assert_eq!(asked[0].reason, "Claude Code: deploy to staging");
        // What will run, apart from the reason.
        assert!(
            asked[0].command.starts_with("sh -c '"),
            "{}",
            asked[0].command
        );
        assert!(asked[0].command.contains("echo \"login with $TOKEN\""));
        assert_eq!(asked[0].fields, "TOKEN=GitHub › Password");
    }

    // A custom hidden field is named by its label, or by its identifier.
    let (error, ran, text) = world.mcp.run(
        "echo \"key=$A $B\"",
        &json!({"A": "verrou://GitHub/API%20token", "B": "verrou://github/custom-0"}),
    );
    assert!(!error, "{text}");
    assert_eq!(
        ran["stdout"],
        "key=<concealed by Verrou> <concealed by Verrou>\n"
    );

    // A refused approval: a tool error, no value, the command did not run.
    world.backend.refuse.store(true, Ordering::SeqCst);
    let marker = world.dir.join("ran");
    let (error, _, text) = world.mcp.tool(
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
    // And the tool waits before it asks again.
    let (error, _, text) = world
        .mcp
        .run("true", &json!({"TOKEN": "verrou://Deploy key/password"}));
    assert!(error);
    assert!(text.contains("a moment ago"), "{text}");
    world.finish();
}

#[test]
fn every_run_is_approved_on_its_own() {
    let mut world = World::new();
    // The usual way (`verrou get`, `verrou run`) approves GitHub's password
    // for five minutes, for this terminal.
    world.reveal_like_the_cli("github", "password");
    assert_eq!(world.asked(), 1);
    world.reveal_like_the_cli("github", "password");
    assert_eq!(world.asked(), 1, "the usual approval is still remembered");

    // The agent does not ride on it: its request asks again, each time.
    let (error, _, text) = world
        .mcp
        .run("true", &json!({"T": "verrou://github/password"}));
    assert!(!error, "{text}");
    assert_eq!(world.asked(), 2);
    let (error, _, _) = world.mcp.run(
        "echo another command",
        &json!({"T": "verrou://github/password"}),
    );
    assert!(!error);
    assert_eq!(world.asked(), 3);
    // One prompt per secret reference of a call.
    let (error, _, text) = world.mcp.run(
        "true",
        &json!({"A": "verrou://github/password", "B": "verrou://github/custom-0",
                "C": "verrou://github/notes"}),
    );
    assert!(!error, "{text}");
    assert_eq!(world.asked(), 6);
    {
        let asked = world.backend.asked.lock().unwrap();
        assert!(asked[1].command.contains("true"));
        assert_eq!(asked[1].fields, "T=GitHub › Password");
        assert!(
            asked[3].fields.contains("GitHub › Notes"),
            "{}",
            asked[3].fields
        );
        // The usual request carried no command at all.
        assert_eq!(asked[0].command, "");
    }

    // And what the agent's approval was is not remembered for the usual
    // way either: `verrou get` of Deploy key asks after the agent's run.
    let (error, _, _) = world
        .mcp
        .run("true", &json!({"T": "verrou://deploy/password"}));
    assert!(!error);
    assert_eq!(world.asked(), 7);
    world.reveal_like_the_cli("deploy", "password");
    assert_eq!(world.asked(), 8, "no approval was left behind");
    world.finish();
}

#[test]
fn a_plain_reference_alone_runs_nothing() {
    let mut world = World::new();
    let marker = world.dir.join("ran");
    let (error, _, text) = world.mcp.tool(
        "verrou_run",
        &json!({
            "command": ["touch", marker.to_str().unwrap()],
            "env": {"U": "verrou://GitHub/username"},
            "reason": "x"
        }),
    );
    assert!(error);
    assert!(text.contains("secret field"), "{text}");
    assert!(!marker.exists(), "the command did not run");
    assert_eq!(world.asked(), 0);
    // Next to a secret one, the username is just a value (not masked).
    let (error, ran, text) = world.mcp.run(
        "echo \"$U\"",
        &json!({"U": "verrou://GitHub/username", "P": "verrou://GitHub/password"}),
    );
    assert!(!error, "{text}");
    assert_eq!(ran["stdout"], "camille\n");
    assert_eq!(world.asked(), 1);
    world.finish();
}

/// A title is resolved by a search that returns its first results only: when
/// more items match than came back, a second one titled the same may be among
/// the others, so the title is not enough.
#[test]
fn a_title_is_refused_when_the_search_was_cut() {
    let mut world = World::new();
    {
        let mut vault = world.backend.vault.lock().unwrap();
        let mut items = vault.items().to_vec();
        items.push(login("mega", "Mega", GITHUB_PASSWORD));
        items
            .extend((0..210).map(|i| login(&format!("m{i}"), &format!("Mega {i}"), TWIN_PASSWORD)));
        *vault = Vault::new(items);
    }
    let (error, ran, text) = world
        .mcp
        .run("true", &json!({"T": "verrou://Mega/password"}));
    assert!(error, "{ran} {text}");
    assert!(text.contains("too many items"), "{text}");
    assert!(text.contains("identifier"), "{text}");
    assert_eq!(world.asked(), 0, "nothing was asked");
    // The identifier still works.
    let (error, _, text) = world
        .mcp
        .run("true", &json!({"T": "verrou://mega/password"}));
    assert!(!error, "{text}");
    assert_eq!(world.asked(), 1);
    world.finish();
}

#[test]
fn references_name_exactly_one_item() {
    let mut world = World::new();
    let message = |world: &mut World, reference: &str| {
        let (error, _, text) = world.mcp.run("true", &json!({"T": reference}));
        assert!(error, "{reference}: {text}");
        text
    };
    // Two items with one title: the identifier must say which.
    assert!(message(&mut world, "verrou://Twin/password").contains("several"));
    // No fuzzy match: "Gith" is not "GitHub".
    assert!(message(&mut world, "verrou://Gith/password").contains("no item"));
    // A field that is not there; a label shared by a built-in is not a way to it.
    assert!(message(&mut world, "verrou://GitHub/Password").contains("no field"));
    assert!(message(&mut world, "verrou://GitHub/nothing").contains("no field"));
    assert_eq!(world.asked(), 0, "nothing was asked for any of these");
    // The identifier works, whatever the title.
    let (error, ran, text) = world.mcp.run(
        &format!("test \"$T\" = '{TWIN_PASSWORD}'"),
        &json!({"T": "verrou://twin-b/password"}),
    );
    assert!(!error, "{text}");
    assert_eq!(ran["exit_code"], 0);
    let asked = world.backend.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].item, "twin-b");
    drop(asked);
    world.finish();
}
