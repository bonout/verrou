//! `verrou mcp`: Verrou as an MCP server (Model Context Protocol) for AI
//! coding agents, over stdio.
//!
//! The rule that shapes everything here: **a secret's value never reaches
//! the model on its own**. The agent gets titles, field names, `verrou://`
//! references and the masked output of a command; it asks Verrou to use a
//! secret (`verrou_run`), and a human approves each use in Verrou.
//!
//! What the approval is worth, said plainly: the user sees the **command
//! line** and the fields it receives (what will really happen), and apart
//! from them the agent's own reason, prefixed with the name the client gave
//! in its handshake ("Claude Code: deploy to staging"; self-declared, so
//! only as trustworthy as the client). The masker only hides exact values:
//! a command that prints a value encoded, reversed or split, or sends it
//! somewhere, gets it out, and so does the agent's next call if the user
//! approves it. **Approving a command the agent chose can hand the agent
//! the value**; the user should approve only commands they understand. What
//! the design guarantees is that nothing happens without that decision:
//! every `verrou_run` is approved on its own, never reusing an approval
//! given earlier to `verrou run` or `verrou get` ([`Remote::ephemeral`]),
//! needs at least one reference to a secret field, and a refusal pauses the
//! tool for a minute (a declined or unanswered unlock counts as one; the
//! bridge also stops asking for this client's agent requests for 30 seconds).
//! The command line is shown whole or not at all: one that does not fit in
//! the approval (200 characters, ten secrets) is refused, and the agent is
//! told to put it in a script file the user can read; control characters are
//! shown (`⏎` for a line break), not flattened into spaces. A client that
//! leaves while its approval is pending gets nothing run.
//!
//! This is a client of the bridge like `verrou run`, paired with `verrou
//! link`: the approvals (Touch ID, or the paired iPhone) are the app's, and
//! the CLI's own checks are a second line, not the first. Two layers keep a
//! value out of the output when nothing went wrong on purpose: the
//! command's output is masked as `verrou run` does, and every text sent to
//! the client goes once more through a masker holding the secret values
//! this session has handled (each string of a result, errors included).
//!
//! Transport: JSON-RPC 2.0, one message per line on stdin and stdout, as the
//! specification says for stdio (2025-06-18 and 2025-11-25); logs, if any,
//! go to stderr. The tools are the whole surface: no resources, no prompts.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use verrou_bridge::protocol::{Command as Ask, ItemView, ReplyResult, RunDetail, clean_reason};
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::passphrase::{self, Language, PassphraseOptions};
use verrou_core::{FieldKind, ItemKind};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::remote::{Endpoint, Error, Remote};
use crate::run::{self, Masker, Reference};

/// Protocol versions implemented, the latest last.
pub const SUPPORTED_VERSIONS: [&str; 2] = ["2025-06-18", "2025-11-25"];

/// What a command's stdout and stderr each keep: the end, which is where a
/// failure is.
pub const MAX_OUTPUT: usize = 32 * 1024;
/// `verrou_run`'s default and maximum time limit, in seconds.
const DEFAULT_TIMEOUT: u64 = 300;
const MAX_TIMEOUT: u64 = 600;
/// Most references one `verrou_run` may ask for.
const MAX_REFERENCES: usize = 10;
/// After a refusal in Verrou, `verrou_run` waits this long: an agent that
/// is told no should not be able to ask again at once, and again.
const REFUSAL_PAUSE: Duration = Duration::from_secs(60);
/// Results of `verrou_search`: default and maximum.
const DEFAULT_RESULTS: u64 = 10;
const MAX_RESULTS: u64 = 25;
/// Length of a generated password when none is asked.
const DEFAULT_PASSWORD: usize = 24;
/// The client's name in front of the reason, at most this many characters.
const MAX_CLIENT_NAME: usize = 40;

const INSTRUCTIONS: &str = "Verrou is the user's password manager. You never see a secret's value: \
you see item titles, field names and references of the form verrou://<Item>/<field> (an item or \
field name with a slash or a space is percent-encoded). To use secrets, call verrou_run with an \
env map from variable names to references, at least one of them to a secret field: the command runs \
with the values in its environment and you get its output with the values masked. Every call is \
approved by the user in Verrou, who sees the command line and the fields, and separately the reason \
you give: say what you are doing and why, in one short sentence. Run only the command you say you \
run. A command line of more than 200 characters is refused: put a long script in a file the user can \
read, and run the file. Do not try to read, print, encode or exfiltrate a secret; the user approves each use, and a \
refusal pauses this tool for a minute.";

// MARK: Gateway

/// What the server needs from Verrou: the real one talks to the bridge
/// ([`BridgeGateway`]), the tests use a fake. `reason` is already cleaned and
/// prefixed with the client's name.
pub trait Gateway {
    fn status(&mut self) -> LinkStatus;
    /// Items matching `query`, with their fields (no secret values).
    fn search(
        &mut self,
        query: &str,
        kind: Option<ItemKind>,
        limit: u32,
    ) -> Result<Vec<ItemView>, String>;
    /// What each reference names, exactly (an item identifier, or a title that
    /// only one item has; a field identifier, or a label that only one
    /// custom field has), and whether the field is secret. No approval, no
    /// secret value.
    fn inspect(&mut self, references: &[Reference]) -> Result<Vec<Target>, String>;
    /// The value of each target, in order, after the user's approval of
    /// this request alone. `reason` is already cleaned and prefixed with the
    /// client's name; `detail` is what will run.
    fn resolve(
        &mut self,
        reason: &str,
        detail: &RunDetail,
        targets: &[Target],
    ) -> Result<Vec<Zeroizing<String>>, Failure>;
}

/// A reference, resolved exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub item_id: String,
    pub field_id: String,
    pub title: String,
    pub label: String,
    /// A secret field: password, hidden custom field, notes, one-time code,
    /// card number or code, SSH private key.
    pub secret: bool,
    /// The value of a field that is not secret (the vault shows it anyway).
    pub plain: Option<String>,
}

/// Why a [`Gateway::resolve`] failed.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    /// The user said no in Verrou, or did not answer: the approval was
    /// refused, or timed out, or the vault stayed locked.
    pub refused: bool,
}

/// The state of the link, for `verrou_status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStatus {
    pub linked: bool,
    pub app_running: Option<bool>,
    pub unlocked: Option<bool>,
}

/// The bridge, through the link made by `verrou link`.
pub struct BridgeGateway {
    config_path: PathBuf,
    endpoint: Endpoint,
    remote: Option<Remote>,
}

impl BridgeGateway {
    pub fn new(config_path: PathBuf, endpoint: Endpoint) -> Self {
        Self {
            config_path,
            endpoint,
            remote: None,
        }
    }

    fn config(&self) -> Result<Config, String> {
        Config::load(&self.config_path)?.ok_or_else(|| Error::NotLinked.to_string())
    }

    /// The connection, opened when first needed and again after a failure.
    fn remote(&mut self, reason: Option<&str>) -> Result<&mut Remote, String> {
        if self.remote.is_none() {
            let config = self.config()?;
            self.remote = Some(Remote::connect(&config, self.endpoint).map_err(|e| e.to_string())?);
        }
        let remote = self.remote.as_mut().ok_or("not connected")?;
        remote.reason = reason.map(str::to_owned);
        // Never an unlock that also approves an item: the approval of an
        // agent's request is asked on its own, showing the command.
        remote.intent = None;
        remote.ephemeral = true;
        remote.detail = None;
        Ok(remote)
    }

    /// Runs `f` on the connection; a broken one is dropped, the next call
    /// opens another.
    fn with<T>(
        &mut self,
        reason: Option<&str>,
        f: impl FnOnce(&mut Remote) -> Result<T, Error>,
    ) -> Result<T, String> {
        let remote = self.remote(reason)?;
        let outcome = f(remote);
        if matches!(outcome, Err(Error::Protocol(_))) {
            self.remote = None;
        }
        outcome.map_err(|e| e.to_string())
    }
}

/// Only the kind of reply, never its content: a `Secret` reply must not
/// be printed anywhere.
fn unexpected(reply: &ReplyResult) -> Error {
    Error::Protocol(format!("unexpected reply from Verrou: {}", reply.kind()))
}

impl Gateway for BridgeGateway {
    fn status(&mut self) -> LinkStatus {
        let Ok(config) = self.config() else {
            return LinkStatus::default();
        };
        let endpoint = Endpoint {
            launch: false,
            ..self.endpoint
        };
        match Remote::connect(&config, endpoint).and_then(|mut r| r.unlocked()) {
            Ok(unlocked) => LinkStatus {
                linked: true,
                app_running: Some(true),
                unlocked: Some(unlocked),
            },
            Err(Error::UnknownClient) => LinkStatus {
                linked: false,
                app_running: Some(true),
                unlocked: None,
            },
            Err(_) => LinkStatus {
                linked: true,
                app_running: Some(false),
                unlocked: None,
            },
        }
    }

    fn search(
        &mut self,
        query: &str,
        kind: Option<ItemKind>,
        limit: u32,
    ) -> Result<Vec<ItemView>, String> {
        self.with(None, |remote| {
            let found = remote.ask(&Ask::VaultSearch {
                query: query.to_owned(),
                kind,
                favorites: false,
                limit: Some(limit),
            })?;
            let ReplyResult::Items { items, .. } = found else {
                return Err(unexpected(&found));
            };
            items
                .iter()
                .map(|summary| {
                    match remote.ask(&Ask::VaultItem {
                        query: summary.id.clone(),
                    })? {
                        ReplyResult::Item { item } => Ok(item),
                        other => Err(unexpected(&other)),
                    }
                })
                .collect()
        })
    }

    fn inspect(&mut self, references: &[Reference]) -> Result<Vec<Target>, String> {
        self.with(None, |remote| {
            references
                .iter()
                .map(|reference| target_of(remote, reference))
                .collect()
        })
    }

    fn resolve(
        &mut self,
        reason: &str,
        detail: &RunDetail,
        targets: &[Target],
    ) -> Result<Vec<Zeroizing<String>>, Failure> {
        let mut values = Vec::new();
        for target in targets {
            // A no in Verrou, an unlock that was declined or never came (the
            // vault stayed locked): the user did not say yes.
            let mut refused = false;
            let value = self.with(Some(reason), |remote| {
                remote.detail = Some(detail.clone());
                target_value(remote, target).inspect_err(|e| refused = is_refusal(e))
            });
            match value {
                Ok(value) => values.push(Zeroizing::new(value)),
                Err(message) => return Err(Failure { message, refused }),
            }
        }
        Ok(values)
    }
}

/// Did the user not say yes? A no in Verrou, an unlock that was declined or
/// never came (the vault stayed locked), an approval nobody answered: the
/// agent is told no, and the tool pauses ([`REFUSAL_PAUSE`]). A broken
/// connection or an app that is not there is not a refusal.
fn is_refusal(error: &Error) -> bool {
    matches!(error, Error::Denied(_) | Error::Locked)
}

/// The item a reference names, exactly: the identifier, otherwise the one
/// item with that title. No fuzzy match: what the user is shown and what
/// the agent gets must be the same item.
fn exact_item(remote: &mut Remote, name: &str) -> Result<ItemView, Error> {
    match remote.ask(&Ask::VaultItem {
        query: name.to_owned(),
    }) {
        // `find` falls back to a search: only the identifier counts.
        Ok(ReplyResult::Item { item }) if item.summary.id == name => return Ok(item),
        Ok(_) | Err(Error::Denied(_)) => {}
        Err(other) => return Err(other),
    }
    let found = remote.ask(&Ask::VaultSearch {
        query: name.to_owned(),
        kind: None,
        favorites: false,
        limit: None,
    })?;
    let ReplyResult::Items { items, total } = found else {
        return Err(unexpected(&found));
    };
    // Only the first results came back: a second item with this title may be
    // among the others. Only active items are searched: an archived or
    // trashed one is reachable by its identifier alone.
    if usize::try_from(total).unwrap_or(usize::MAX) > items.len() {
        return Err(Error::Denied(format!(
            "too many items match \"{name}\" to be sure only one is titled so: use the identifier from verrou_search"
        )));
    }
    let mut exact = items.iter().filter(|i| i.title == name);
    let (Some(first), None) = (exact.next(), exact.next()) else {
        let message = if items.iter().any(|i| i.title == name) {
            format!("several items are titled \"{name}\": use the identifier from verrou_search")
        } else {
            format!("no item with the identifier or exact title \"{name}\"")
        };
        return Err(Error::Denied(message));
    };
    match remote.ask(&Ask::VaultItem {
        query: first.id.clone(),
    })? {
        ReplyResult::Item { item } if item.summary.id == first.id => Ok(item),
        other => Err(unexpected(&other)),
    }
}

fn target_of(remote: &mut Remote, reference: &Reference) -> Result<Target, Error> {
    let item = exact_item(remote, &reference.item)?;
    let title = item.summary.title.clone();
    let missing = |what: &str| Error::Denied(format!("\"{title}\" has no {what}"));
    let (field_id, label, secret, plain) = match reference.field.as_str() {
        "totp" => {
            if !item.summary.has_totp {
                return Err(missing("one-time code"));
            }
            ("totp".to_owned(), "One-time code".to_owned(), true, None)
        }
        "notes" => {
            if !item.has_notes {
                return Err(missing("notes"));
            }
            ("notes".to_owned(), "Notes".to_owned(), true, None)
        }
        name => {
            let found = run::find_field(&item.fields, name)
                .ok_or_else(|| missing(&format!("field \"{name}\"")))?;
            (
                found.id.clone(),
                found.label.clone(),
                found.secret,
                found.value.clone().filter(|_| !found.secret),
            )
        }
    };
    Ok(Target {
        item_id: item.summary.id,
        field_id,
        title,
        label,
        secret,
        plain,
    })
}

/// A target's value: a plain field's as the vault shows it, a secret one
/// asked of Verrou, which asks the user (for this request alone).
fn target_value(remote: &mut Remote, target: &Target) -> Result<String, Error> {
    if let Some(value) = &target.plain {
        return Ok(value.clone());
    }
    let asked = match target.field_id.as_str() {
        "totp" => remote.ask(&Ask::Totp {
            item: target.item_id.clone(),
        })?,
        id => remote.ask(&Ask::Reveal {
            item: target.item_id.clone(),
            field: id.to_owned(),
        })?,
    };
    match asked {
        ReplyResult::Secret(secret) => Ok(secret.value.clone()),
        ReplyResult::Code { code, .. } => Ok(code),
        other => Err(unexpected(&other)),
    }
}

// MARK: Server

/// One MCP session. Holds the client's name (shown in approvals, declared by
/// the client itself: it proves nothing) and the secret values handled so
/// far, to scrub whatever is sent back.
pub struct Server<G: Gateway> {
    gateway: G,
    client: String,
    secrets: Vec<Zeroizing<String>>,
    /// `verrou_run` is paused until then, after a refusal.
    paused_until: Option<Instant>,
    /// The client closed its input ([`serve`]): a command it was waiting
    /// for is killed.
    gone: Arc<AtomicBool>,
}

/// A tool's outcome: what goes to the model, and whether it is an error.
struct Outcome {
    payload: Payload,
    error: bool,
}

enum Payload {
    Json(Value),
    Text(String),
}

impl Outcome {
    fn ok(value: &Value) -> Self {
        Self {
            payload: Payload::Json(value.clone()),
            error: false,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            payload: Payload::Text(message.into()),
            error: true,
        }
    }
}

impl<G: Gateway> Server<G> {
    pub fn new(gateway: G) -> Self {
        Self {
            gateway,
            client: String::new(),
            secrets: Vec::new(),
            paused_until: None,
            gone: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Handles one line; the answer to send back, if the message is a request.
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(_) => return Some(error_reply(&Value::Null, -32700, "parse error")),
        };
        if message.is_array() {
            // Batches left the protocol in 2025-06-18.
            return Some(error_reply(
                &Value::Null,
                -32600,
                "batches are not supported",
            ));
        }
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to something we never asked: nothing to do.
            return None;
        };
        // No `id`: a notification, which never gets an answer.
        let id = message.get("id")?.clone();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        Some(match self.dispatch(method, &params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string(),
            Err((code, text)) => error_reply(&id, code, &text),
        })
    }

    fn dispatch(&mut self, method: &str, params: &Value) -> Result<Value, (i32, String)> {
        match method {
            "initialize" => Ok(self.initialize(params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => self.call(params),
            other => Err((-32601, format!("method not found: {other}"))),
        }
    }

    fn initialize(&mut self, params: &Value) -> Value {
        let wanted = params.get("protocolVersion").and_then(Value::as_str);
        let version = wanted
            .filter(|v| SUPPORTED_VERSIONS.contains(v))
            .unwrap_or(SUPPORTED_VERSIONS[SUPPORTED_VERSIONS.len() - 1]);
        let name = params
            .pointer("/clientInfo/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.client = client_label(name);
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "verrou",
                "title": "Verrou",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": INSTRUCTIONS,
        })
    }

    fn call(&mut self, params: &Value) -> Result<Value, (i32, String)> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let empty = Value::Object(Map::new());
        let arguments = params.get("arguments").unwrap_or(&empty);
        let outcome = match name {
            "verrou_status" => self.status(),
            "verrou_search" => self.search(arguments),
            "verrou_run" => self.run(arguments),
            "verrou_generate_password" => generate(arguments),
            other => return Err((-32602, format!("unknown tool: {other}"))),
        };
        // Each string of a result is scrubbed before it is serialized: a value
        // JSON would escape (a quote, a backslash) is still found.
        let text = match outcome.payload {
            Payload::Text(text) => self.scrub(&text),
            Payload::Json(mut value) => {
                self.scrub_value(&mut value);
                value.to_string()
            }
        };
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "isError": outcome.error,
        }))
    }

    /// The reason as the approval shows it: "Claude Code: deploy to staging".
    fn reason(&self, arguments: &Value) -> Result<String, Outcome> {
        let reason = arguments
            .get("reason")
            .and_then(Value::as_str)
            .map(|r| clean_reason(Some(r)))
            .filter(|r| !r.is_empty())
            .ok_or_else(|| {
                Outcome::err("\"reason\" is required: say in one sentence what this is for")
            })?;
        let client = if self.client.is_empty() {
            "MCP client"
        } else {
            &self.client
        };
        Ok(clean_reason(Some(&format!("{client}: {reason}"))))
    }

    /// The text without any secret this session has handled.
    fn scrub(&self, text: &str) -> String {
        if self.secrets.is_empty() {
            return text.to_owned();
        }
        let mut masker = Masker::new(self.secrets.iter().map(|s| s.as_str()));
        let mut out = masker.feed(text.as_bytes());
        out.extend(masker.finish());
        String::from_utf8_lossy(&out).into_owned()
    }

    fn scrub_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.scrub(text),
            Value::Array(list) => list.iter_mut().for_each(|v| self.scrub_value(v)),
            Value::Object(map) => {
                let entries = std::mem::take(map);
                for (key, mut entry) in entries {
                    self.scrub_value(&mut entry);
                    map.insert(self.scrub(&key), entry);
                }
            }
            _ => {}
        }
    }

    fn status(&mut self) -> Outcome {
        let status = self.gateway.status();
        Outcome::ok(&json!({
            "linked": status.linked,
            "app_running": status.app_running,
            "unlocked": status.unlocked,
            "hint": if status.linked { Value::Null } else {
                json!("the user must run `verrou link` in a terminal, then accept the pairing in Verrou")
            },
        }))
    }

    fn search(&mut self, arguments: &Value) -> Outcome {
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kind = match arguments.get("kind").and_then(Value::as_str) {
            None => None,
            Some(kind) => match kind_of(kind) {
                Some(kind) => Some(kind),
                None => return Outcome::err("\"kind\" is login, card, identity, note or ssh"),
            },
        };
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_RESULTS)
            .clamp(1, MAX_RESULTS);
        let limit = u32::try_from(limit).unwrap_or(10);
        match self.gateway.search(query, kind, limit) {
            Ok(items) => Outcome::ok(&search_result(&items)),
            Err(e) => Outcome::err(e),
        }
    }

    fn run(&mut self, arguments: &Value) -> Outcome {
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return Outcome::err(format!(
                    "the user refused a request a moment ago: wait {} seconds before asking again, and ask the user what they want",
                    until.saturating_duration_since(Instant::now()).as_secs() + 1
                ));
            }
            self.paused_until = None;
        }
        let request = match RunRequest::parse(arguments) {
            Ok(request) => request,
            Err(message) => return Outcome::err(message),
        };
        let reason = match self.reason(arguments) {
            Ok(reason) => reason,
            Err(outcome) => return outcome,
        };
        let references: Vec<Reference> = request.env.iter().map(|(_, r)| r.clone()).collect();
        let targets = match self.gateway.inspect(&references) {
            Ok(targets) => targets,
            Err(e) => return Outcome::err(e),
        };
        if !targets.iter().any(|t| t.secret) {
            // A run with only plain values (a username, a site) would ask
            // nobody: this tool must not be a way to run a command unseen.
            return Outcome::err(
                "at least one reference must name a secret field (password, hidden field, notes, one-time code, card number…): a run with only plain values is not approved by anyone; run it in your own shell",
            );
        }
        // What the user will see: the command line (with the directory it
        // runs in), and each variable with the field it gets. A command that
        // would not fit whole is refused: half a command line approves the
        // other half blind.
        let fields = request
            .env
            .iter()
            .zip(&targets)
            .map(|((name, _), t)| format!("{name}={} › {}", t.title, t.label))
            .collect();
        let detail = match run::agent_detail(&request.command, request.cwd.as_deref(), fields) {
            Ok(detail) => detail,
            Err(message) => return Outcome::err(message),
        };
        let was_gone = self.gone.load(Ordering::SeqCst);
        let values = match self.gateway.resolve(&reason, &detail, &targets) {
            Ok(values) => values,
            Err(failure) => {
                if failure.refused {
                    self.paused_until = Some(Instant::now() + REFUSAL_PAUSE);
                }
                return Outcome::err(failure.message);
            }
        };
        // The client left while the user was being asked (an input already
        // closed when the request came, a script that sent it and went, is
        // not that): nobody is waiting for what this would do.
        if !was_gone && self.gone.load(Ordering::SeqCst) {
            return Outcome::err(
                "the client closed the connection while the approval was pending: the command was not run",
            );
        }
        let mut env = Vec::new();
        let mut masked = Vec::new();
        for (((name, _), target), value) in request.env.iter().zip(&targets).zip(values) {
            // Only secret values are masked: a username the command prints
            // is not a leak, and masking it would garble the output.
            if target.secret {
                masked.push(value.clone());
            }
            env.push((name.clone(), value));
        }
        self.secrets.extend(masked.iter().cloned());
        match execute(&request, &env, &masked, &self.gone) {
            Ok(result) => Outcome::ok(&result),
            Err(e) => Outcome::err(e),
        }
    }
}

/// `verrou_generate_password`: a new value, not one from the vault, so it
/// may be returned.
fn generate(arguments: &Value) -> Outcome {
    let number = |key: &str| arguments.get(key).and_then(Value::as_u64);
    let value = if let Some(words) = number("words") {
        passphrase::passphrase(&PassphraseOptions {
            words: usize::try_from(words.clamp(3, 20)).unwrap_or(6),
            language: Language::English,
            ..PassphraseOptions::default()
        })
    } else {
        generator::password(&PasswordOptions {
            length: number("length").map_or(DEFAULT_PASSWORD, |l| {
                usize::try_from(l.clamp(8, 128)).unwrap_or(DEFAULT_PASSWORD)
            }),
            avoid_ambiguous: true,
            ..PasswordOptions::default()
        })
    };
    Outcome::ok(&json!({ "value": value }))
}

fn kind_of(keyword: &str) -> Option<ItemKind> {
    match keyword {
        "login" => Some(ItemKind::Login),
        "card" => Some(ItemKind::Card),
        "identity" => Some(ItemKind::Identity),
        "note" => Some(ItemKind::SecureNote),
        "ssh" => Some(ItemKind::SshKey),
        _ => None,
    }
}

/// The client's name for the approval: one short line.
fn client_label(name: &str) -> String {
    clean_reason(Some(name))
        .chars()
        .take(MAX_CLIENT_NAME)
        .collect()
}

fn error_reply(id: &Value, code: i32, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

// MARK: Search

/// What `verrou_search` returns: titles, kinds, the username, the sites,
/// and each field's name with the reference to use it. Never a value other
/// than the username (which Verrou itself does not treat as secret).
fn search_result(items: &[ItemView]) -> Value {
    let list: Vec<Value> = items
        .iter()
        .map(|item| {
            let summary = &item.summary;
            let mut fields: Vec<Value> = item
                .fields
                .iter()
                .filter(|f| !f.id.starts_with("history-") && !f.id.starts_with("verrou:"))
                .map(|f| {
                    // Titles and labels are for reading; the reference names
                    // the item and the field by identifier, so that what the
                    // user approves is exactly what the agent got.
                    json!({
                        "name": f.label,
                        "secret": f.secret,
                        "reference": Reference { item: summary.id.clone(), field: f.id.clone() }.to_uri(),
                    })
                })
                .collect();
            if item.has_notes {
                fields.push(json!({
                    "name": "Notes",
                    "secret": true,
                    "reference": Reference { item: summary.id.clone(), field: "notes".to_owned() }.to_uri(),
                }));
            }
            let username = item
                .fields
                .iter()
                .find(|f| matches!(f.kind, FieldKind::Username | FieldKind::Email))
                .and_then(|f| f.value.clone());
            json!({
                "id": summary.id,
                "title": summary.title,
                "kind": summary.kind.keyword(),
                "username": username,
                "sites": summary.urls,
                "folder": summary.folder,
                "fields": fields,
            })
        })
        .collect();
    json!({ "items": list })
}

// MARK: Running a command

/// A checked `verrou_run` request.
struct RunRequest {
    command: Vec<String>,
    env: Vec<(String, Reference)>,
    cwd: Option<PathBuf>,
    timeout: Duration,
}

impl RunRequest {
    fn parse(arguments: &Value) -> Result<Self, String> {
        let command: Vec<String> = arguments
            .get("command")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or("\"command\" is an array: the program, then its arguments")?
            .ok_or("\"command\" holds strings only")?;
        if command.first().is_none_or(String::is_empty) {
            return Err("\"command\" is empty".to_owned());
        }
        let mut env = Vec::new();
        for (name, value) in arguments
            .get("env")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if name.is_empty()
                || name.starts_with(|c: char| c.is_ascii_digit())
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(format!("\"{name}\" is not a valid variable name"));
            }
            let value = value.as_str().unwrap_or_default();
            match Reference::parse(value) {
                Some(Ok(reference)) => env.push((name.clone(), reference)),
                Some(Err(e)) => return Err(format!("{name}: {e}")),
                // Plain values belong in the command itself; a secret
                // pasted here would travel through the model anyway.
                None => {
                    return Err(format!(
                        "{name}: env values must be verrou://<item>/<field> references; put other values in the command"
                    ));
                }
            }
        }
        if env.is_empty() {
            // Without a secret there is nothing to approve: this tool would
            // be a way around the agent's own command permissions.
            return Err(
                "\"env\" needs at least one verrou:// reference; run commands without secrets in your own shell"
                    .to_owned(),
            );
        }
        if env.len() > MAX_REFERENCES {
            return Err(format!("at most {MAX_REFERENCES} references per call"));
        }
        let timeout = arguments
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT)
            .clamp(1, MAX_TIMEOUT);
        let cwd = arguments
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(PathBuf::from);
        if cwd.as_ref().is_some_and(|c| !c.is_dir()) {
            return Err("\"cwd\" is not a directory".to_owned());
        }
        Ok(Self {
            command,
            env,
            cwd,
            timeout: Duration::from_secs(timeout),
        })
    }
}

/// The end of a stream, at most `cap` bytes.
struct Tail {
    bytes: Vec<u8>,
    cap: usize,
    truncated: bool,
}

impl Tail {
    fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::new(),
            cap,
            truncated: false,
        }
    }
}

impl Write for Tail {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(data);
        if self.bytes.len() > self.cap {
            let cut = self.bytes.len() - self.cap;
            self.bytes.drain(..cut);
            self.truncated = true;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A [`Tail`] shared with the thread that fills it.
#[derive(Clone)]
struct SharedTail(Arc<Mutex<Tail>>);

impl Write for SharedTail {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs the command with the secrets in its environment, no shell. Its
/// output goes through the same masker as `verrou run`, then is cut to its
/// end ([`MAX_OUTPUT`]). A command that outlives the time limit is killed.
#[allow(clippy::too_many_lines)] // spawn, pumps, wait, result: one story
fn execute(
    request: &RunRequest,
    env: &[(String, Zeroizing<String>)],
    masked: &[Zeroizing<String>],
    gone: &AtomicBool,
) -> Result<Value, String> {
    let (program, arguments) = request
        .command
        .split_first()
        .ok_or("\"command\" is empty")?;
    let mut child = std::process::Command::new(program);
    child
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &request.cwd {
        child.current_dir(cwd);
    }
    for (name, value) in env {
        child.env(name, value.as_str());
    }
    // Its own process group: what it starts goes down with it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        child.process_group(0);
    }
    let mut child = child.spawn().map_err(|e| format!("{program}: {e}"))?;
    let group = child.id();
    let (done, finished) = mpsc::channel();
    let tails = [
        SharedTail(Arc::new(Mutex::new(Tail::new(MAX_OUTPUT)))),
        SharedTail(Arc::new(Mutex::new(Tail::new(MAX_OUTPUT)))),
    ];
    let streams: [Option<Box<dyn io::Read + Send>>; 2] = [
        child.stdout.take().map(|s| Box::new(s) as _),
        child.stderr.take().map(|s| Box::new(s) as _),
    ];
    for (stream, tail) in streams.into_iter().zip(&tails) {
        let Some(stream) = stream else { continue };
        let scrubber = Masker::new(masked.iter().map(|v| v.as_str()));
        let (tail, done) = (tail.clone(), done.clone());
        std::thread::spawn(move || {
            let _ = run::pump(stream, tail, scrubber);
            let _ = done.send(());
        });
    }
    drop(done);
    let start = Instant::now();
    let mut timed_out = false;
    // An input already closed when the command starts (a script that sent
    // its request and left) is not "the client went away".
    let was_gone = gone.load(Ordering::SeqCst);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None)
                if start.elapsed() >= request.timeout
                    || (!was_gone && gone.load(Ordering::SeqCst)) =>
            {
                timed_out = start.elapsed() >= request.timeout;
                kill_group(group);
                let _ = child.kill();
                break child.wait().map_err(|e| format!("{program}: {e}"))?;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{program}: {e}")),
        }
    };
    // The pumps end with the pipes; a grandchild holding one open must not
    // hang the tool: take what was read after a short wait.
    let grace = Instant::now() + Duration::from_secs(2);
    for _ in 0..2 {
        let left = grace.saturating_duration_since(Instant::now());
        if finished.recv_timeout(left).is_err() {
            break;
        }
    }
    let read = |tail: &SharedTail| {
        let tail = tail.0.lock().unwrap_or_else(PoisonError::into_inner);
        (
            String::from_utf8_lossy(&tail.bytes).into_owned(),
            tail.truncated,
        )
    };
    let ((stdout, cut_out), (stderr, cut_err)) = (read(&tails[0]), read(&tails[1]));
    let truncated = cut_out || cut_err;
    let mut result = json!({
        "exit_code": status_code(status),
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated,
        "timed_out": timed_out,
    });
    let mut notes = Vec::new();
    if truncated {
        notes.push(format!(
            "only the last {} KB of each stream is kept",
            MAX_OUTPUT / 1024
        ));
    }
    if timed_out {
        notes.push(format!(
            "killed after {} seconds",
            request.timeout.as_secs()
        ));
    }
    if !was_gone && gone.load(Ordering::SeqCst) && !timed_out {
        notes.push("stopped: the client closed the connection".to_owned());
    }
    notes.push("secrets are replaced by <concealed by Verrou>".to_owned());
    result["note"] = Value::String(notes.join("; "));
    Ok(result)
}

/// Kills a whole process group (`kill -s KILL -- -PGID`: no unsafe code
/// here). Nothing to do where there are none.
fn kill_group(group: u32) {
    #[cfg(unix)]
    let _ = std::process::Command::new("kill")
        .args(["-s", "KILL", "--"])
        .arg(format!("-{group}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    #[cfg(not(unix))]
    let _ = group;
}

/// The exit code; killed by a signal: 128 + the signal, as a shell says it.
fn status_code(status: std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return Some(128 + signal);
        }
    }
    status.code()
}

// MARK: Tools

fn tools() -> Value {
    let reason = json!({
        "type": "string",
        "description": "One short sentence: what this is for. The user sees it in Verrou's approval, after your client's name."
    });
    json!([
        {
            "name": "verrou_status",
            "title": "Verrou status",
            "description": "Is this machine linked to Verrou, and is the vault unlocked? Call it first if another tool says Verrou is unavailable.",
            "inputSchema": { "type": "object", "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "verrou_search",
            "title": "Find items in the vault",
            "description": "Find vault items by title, username or site. Returns titles, kinds, usernames, sites and, for each item, its field names with a ready-to-use verrou:// reference. Never returns a secret value: pass references to verrou_run to use them.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Words to look for; empty lists items." },
                    "kind": { "type": "string", "enum": ["login", "card", "identity", "note", "ssh"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "description": "Results to return (default 10)." }
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "verrou_run",
            "title": "Run a command with secrets",
            "description": "Run a command (no shell) with secrets in its environment. env maps variable names to verrou://<item>/<field> references; the user approves in Verrou, seeing your reason. Returns exit_code, stdout and stderr with every secret value replaced by <concealed by Verrou>, the last 32 KB of each. At least one reference to a secret field is required; run other commands in your own shell. The user sees the command line (with its working directory) and each variable with its field in the approval, and approves each call on its own: run only what you say you run. A command line longer than 200 characters is refused: put it in a script file the user can read. A command that prints a value encoded, reversed or split is not masked. To use a shell, pass it as the program (for example [\"sh\", \"-c\", \"...\"]).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "The program and its arguments." },
                    "env": { "type": "object", "additionalProperties": { "type": "string", "pattern": "^verrou://" }, "description": "Variable name to verrou://<item>/<field> reference." },
                    "cwd": { "type": "string", "description": "Working directory (default: the server's)." },
                    "reason": reason,
                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT, "description": "Default 300, at most 600." }
                },
                "required": ["command", "env", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "verrou_generate_password",
            "title": "Generate a password",
            "description": "Generate a new random password, or a passphrase with words. It is new, not from the vault, so it is returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "length": { "type": "integer", "minimum": 8, "maximum": 128, "description": "Password length (default 24)." },
                    "words": { "type": "integer", "minimum": 3, "maximum": 20, "description": "Passphrase of this many words instead." }
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": false, "openWorldHint": false }
        }
    ])
}

// MARK: Loop

/// Serves one client: a line in, at most a line out, until the input ends
/// (the client closing its side is the shutdown). The input is read on a
/// thread of its own, so that a client that goes away while a command runs
/// is noticed and the command (with what it started) is killed.
pub fn serve<G: Gateway>(
    input: impl BufRead + Send + 'static,
    mut output: impl Write,
    server: &mut Server<G>,
) -> io::Result<()> {
    let (lines, incoming) = mpsc::channel();
    let gone = Arc::clone(&server.gone);
    std::thread::spawn(move || {
        for line in input.lines() {
            if lines.send(line).is_err() {
                return;
            }
        }
        gone.store(true, Ordering::SeqCst);
    });
    for line in incoming {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(answer) = server.handle_line(&line) {
            output.write_all(answer.as_bytes())?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_bridge::protocol::{FieldView, ItemSummary};

    /// A fake that records what it is asked, and "has" one password. A
    /// reference to a field named in `plain` is a plain one (a username).
    #[derive(Default)]
    struct Fake {
        /// (reason, detail) of each approval asked.
        asked: Vec<(String, RunDetail)>,
        items: Vec<ItemView>,
        plain: Vec<String>,
        fail: Option<Failure>,
        inspected: usize,
        /// Set while the user "answers": the client goes away meanwhile.
        leave_while_asking: Option<Arc<AtomicBool>>,
    }

    const PASSWORD: &str = "correct-horse-9!";

    impl Fake {
        fn refusing() -> Failure {
            Failure {
                message: "refused in Verrou".to_owned(),
                refused: true,
            }
        }
    }

    impl Gateway for Fake {
        fn status(&mut self) -> LinkStatus {
            LinkStatus {
                linked: true,
                app_running: Some(true),
                unlocked: Some(true),
            }
        }

        fn search(
            &mut self,
            _: &str,
            _: Option<ItemKind>,
            _: u32,
        ) -> Result<Vec<ItemView>, String> {
            Ok(self.items.clone())
        }

        fn inspect(&mut self, references: &[Reference]) -> Result<Vec<Target>, String> {
            self.inspected += 1;
            Ok(references
                .iter()
                .map(|r| {
                    let plain = self.plain.contains(&r.field);
                    Target {
                        item_id: r.item.clone(),
                        field_id: r.field.clone(),
                        title: format!("Item {}", r.item),
                        label: r.field.clone(),
                        secret: !plain,
                        plain: plain.then(|| "alice".to_owned()),
                    }
                })
                .collect())
        }

        fn resolve(
            &mut self,
            reason: &str,
            detail: &RunDetail,
            targets: &[Target],
        ) -> Result<Vec<Zeroizing<String>>, Failure> {
            self.asked.push((reason.to_owned(), detail.clone()));
            if let Some(gone) = &self.leave_while_asking {
                gone.store(true, Ordering::SeqCst);
            }
            if let Some(failure) = self.fail.take() {
                return Err(failure);
            }
            Ok(targets
                .iter()
                .map(|t| Zeroizing::new(t.plain.clone().unwrap_or_else(|| PASSWORD.to_owned())))
                .collect())
        }
    }

    fn item(id: &str, title: &str, fields: Vec<FieldView>) -> ItemView {
        ItemView {
            summary: ItemSummary {
                id: id.to_owned(),
                kind: ItemKind::Login,
                title: title.to_owned(),
                subtitle: String::new(),
                urls: vec!["https://example.com".to_owned()],
                folder: None,
                tags: Vec::new(),
                favorite: false,
                has_totp: false,
                shared: None,
            },
            fields,
            has_notes: false,
        }
    }

    fn field(id: &str, label: &str, kind: FieldKind, value: Option<&str>) -> FieldView {
        FieldView {
            id: id.to_owned(),
            label: label.to_owned(),
            kind,
            secret: kind.is_secret(),
            value: value.map(str::to_owned),
        }
    }

    fn ask(server: &mut Server<Fake>, message: &Value) -> Value {
        let answer = server.handle_line(&message.to_string()).unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    fn call(server: &mut Server<Fake>, tool: &str, arguments: &Value) -> Value {
        ask(
            server,
            &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":tool,"arguments":arguments}}),
        )
    }

    fn text(reply: &Value) -> &str {
        reply["result"]["content"][0]["text"].as_str().unwrap()
    }

    fn initialized(name: &str) -> Server<Fake> {
        let mut server = Server::new(Fake::default());
        ask(
            &mut server,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":name,"version":"1"}}}),
        );
        server
    }

    #[test]
    fn initialize_negotiates_the_version() {
        let mut server = Server::new(Fake::default());
        let ask_with = |server: &mut Server<Fake>, version: &str| {
            ask(
                server,
                &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"x"}}}),
            )
        };
        let reply = ask_with(&mut server, "2025-06-18");
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(reply["result"]["serverInfo"]["name"], "verrou");
        assert_eq!(
            reply["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(reply["result"]["capabilities"]["tools"].is_object());
        assert!(
            reply["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("verrou://")
        );
        assert_eq!(
            ask_with(&mut server, "2025-11-25")["result"]["protocolVersion"],
            "2025-11-25"
        );
        // A version we don't know: our latest.
        assert_eq!(
            ask_with(&mut server, "2030-01-01")["result"]["protocolVersion"],
            "2025-11-25"
        );
    }

    #[test]
    fn framing_follows_json_rpc() {
        let mut server = Server::new(Fake::default());
        // Notifications never get an answer.
        assert!(
            server
                .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none()
        );
        // Nor do stray responses.
        assert!(
            server
                .handle_line(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#)
                .is_none()
        );
        let reply = ask(
            &mut server,
            &json!({"jsonrpc":"2.0","id":"a","method":"ping"}),
        );
        assert_eq!(
            (reply["id"].as_str(), reply["result"].clone()),
            (Some("a"), json!({}))
        );
        let reply = ask(
            &mut server,
            &json!({"jsonrpc":"2.0","id":2,"method":"resources/list"}),
        );
        assert_eq!(reply["error"]["code"], -32601);
        // Malformed JSON.
        let answer: Value =
            serde_json::from_str(&server.handle_line("{not json").unwrap()).unwrap();
        assert_eq!(answer["error"]["code"], -32700);
        assert!(answer["id"].is_null());
        // A batch.
        let answer: Value = serde_json::from_str(&server.handle_line("[]").unwrap()).unwrap();
        assert_eq!(answer["error"]["code"], -32600);
    }

    #[test]
    fn serve_reads_lines_and_writes_lines() {
        let mut server = Server::new(Fake::default());
        let input = "\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let mut out = Vec::new();
        serve(
            std::io::Cursor::new(input.to_owned()),
            &mut out,
            &mut server,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| !l.contains('\r')));
    }

    #[test]
    fn tools_list_describes_every_tool_with_a_schema() {
        let mut server = Server::new(Fake::default());
        let reply = ask(
            &mut server,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        );
        let tools = reply["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "verrou_status",
                "verrou_search",
                "verrou_run",
                "verrou_generate_password"
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert_ne!(tool["description"].as_str().unwrap(), "");
            let valid = tool["name"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
            assert!(valid);
        }
        let run = &tools[2];
        assert_eq!(
            run["inputSchema"]["required"],
            json!(["command", "env", "reason"])
        );
    }

    #[test]
    fn unknown_tool_is_a_protocol_error() {
        let mut server = initialized("x");
        let reply = call(&mut server, "nope", &json!({}));
        assert_eq!(reply["error"]["code"], -32602);
    }

    #[test]
    fn search_gives_names_and_identifier_references_never_values() {
        let mut server = initialized("x");
        server.gateway.items = vec![
            item(
                "id-1",
                "GitHub/work",
                vec![
                    field("username", "Username", FieldKind::Username, Some("camille")),
                    field("password", "Password", FieldKind::Password, None),
                    field("custom-0", "API token", FieldKind::Concealed, None),
                ],
            ),
            item(
                "id-2",
                "Twin",
                vec![field("password", "Password", FieldKind::Password, None)],
            ),
            item(
                "id-3",
                "Twin",
                vec![field("password", "Password", FieldKind::Password, None)],
            ),
        ];
        let reply = call(&mut server, "verrou_search", &json!({"query": "git"}));
        assert_eq!(reply["result"]["isError"], false);
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        let first = &body["items"][0];
        assert_eq!(first["username"], "camille");
        assert_eq!(first["title"], "GitHub/work");
        let fields = first["fields"].as_array().unwrap();
        let references: Vec<&str> = fields
            .iter()
            .map(|f| f["reference"].as_str().unwrap())
            .collect();
        // By identifier: what is displayed (titles, labels) never names the target.
        assert_eq!(
            references,
            [
                "verrou://id-1/username",
                "verrou://id-1/password",
                "verrou://id-1/custom-0"
            ]
        );
        assert_eq!(fields[2]["name"], "API token");
        assert_eq!(
            body["items"][1]["fields"][0]["reference"],
            "verrou://id-2/password"
        );
        assert!(!text(&reply).contains(PASSWORD));
    }

    #[test]
    fn run_refuses_what_is_not_a_reference() {
        let mut server = initialized("x");
        let run = |server: &mut Server<Fake>, arguments: Value| {
            let reply = call(server, "verrou_run", &arguments);
            assert_eq!(reply["result"]["isError"], true, "{reply}");
            text(&reply).to_owned()
        };
        let message = run(
            &mut server,
            json!({"command":["true"],"env":{"TOKEN":"plain-value"},"reason":"x"}),
        );
        assert!(message.contains("references"), "{message}");
        // No reference at all: nothing to approve, so no way around the client's own permissions.
        let message = run(
            &mut server,
            json!({"command":["true"],"env":{},"reason":"x"}),
        );
        assert!(message.contains("at least one"), "{message}");
        // No reason.
        let message = run(
            &mut server,
            json!({"command":["true"],"env":{"T":"verrou://A/password"}}),
        );
        assert!(message.contains("reason"), "{message}");
        let message = run(
            &mut server,
            json!({"command":["true"],"env":{"1BAD":"verrou://A/password"},"reason":"x"}),
        );
        assert!(message.contains("variable name"), "{message}");
        // Too many references.
        let env: Map<String, Value> = (0..=MAX_REFERENCES)
            .map(|i| (format!("V{i}"), json!(format!("verrou://A/f{i}"))))
            .collect();
        let message = run(
            &mut server,
            json!({"command":["true"],"env":env,"reason":"x"}),
        );
        assert!(message.contains("at most"), "{message}");
        assert!(
            server.gateway.asked.is_empty(),
            "no approval was asked for any of these"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_run_needs_a_reference_to_a_secret_field() {
        // Only a username: nothing would be approved, so nothing runs.
        let mut server = initialized("x");
        server.gateway.plain = vec!["username".to_owned()];
        let marker = std::env::temp_dir().join(format!("vm-ran-{}", std::process::id()));
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({
                "command": ["touch", marker.to_str().unwrap()],
                "env": {"U": "verrou://GitHub/username"},
                "reason": "x"
            }),
        );
        assert_eq!(reply["result"]["isError"], true);
        assert!(text(&reply).contains("secret field"), "{}", text(&reply));
        assert!(!marker.exists(), "the command did not run");
        assert_eq!(server.gateway.asked.len(), 0);
        // With one secret reference next to it: asked, and run.
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({
                "command": ["touch", marker.to_str().unwrap()],
                "env": {"U": "verrou://GitHub/username", "P": "verrou://GitHub/password"},
                "reason": "x"
            }),
        );
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert!(marker.exists());
        assert_eq!(server.gateway.asked.len(), 1);
        std::fs::remove_file(&marker).ok();
    }

    #[cfg(unix)]
    #[test]
    fn run_masks_the_secret_and_asks_with_the_command() {
        let mut server = initialized("Claude Code");
        server.gateway.plain = vec!["username".to_owned()];
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({
                "command": ["sh", "-c", "echo token=$TOKEN user=$USER_NAME; echo err=$TOKEN >&2; exit 3"],
                "env": {"TOKEN": "verrou://Staging/token", "USER_NAME": "verrou://Staging/username"},
                "reason": "deploy to\nstaging"
            }),
        );
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert!(!text(&reply).contains(PASSWORD));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["exit_code"], 3);
        // A plain value (a username) is not masked, a secret is.
        assert_eq!(body["stdout"], "token=<concealed by Verrou> user=alice\n");
        assert_eq!(body["stderr"], "err=<concealed by Verrou>\n");
        assert_eq!(body["truncated"], false);
        // The approval says what will run, apart from the agent's reason.
        let (reason, detail) = &server.gateway.asked[0];
        assert_eq!(reason, "Claude Code: deploy to staging");
        assert!(detail.command.starts_with("sh -c '"), "{}", detail.command);
        assert!(detail.command.contains("echo token=$TOKEN"));
        // Each variable with the field it gets, so the user sees which
        // variable is the secret one.
        assert_eq!(
            detail.fields,
            [
                "TOKEN=Item Staging › token",
                "USER_NAME=Item Staging › username"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_keeps_the_end_of_a_long_output() {
        let mut server = initialized("x");
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({
                "command": ["sh", "-c", "i=0; while [ $i -lt 5000 ]; do echo line-$i-0123456789; i=$((i+1)); done"],
                "env": {"T": "verrou://A/password"},
                "reason": "x"
            }),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["truncated"], true);
        let out = body["stdout"].as_str().unwrap();
        assert!(out.len() <= MAX_OUTPUT);
        assert!(out.ends_with("line-4999-0123456789\n"));
        assert!(body["note"].as_str().unwrap().contains("last 32 KB"));
    }

    #[cfg(unix)]
    fn alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[cfg(unix)]
    #[test]
    fn run_kills_a_command_and_what_it_started_over_its_time_limit() {
        let mut server = initialized("x");
        let pidfile = std::env::temp_dir().join(format!("vm-pid-{}", std::process::id()));
        let script = format!("sleep 60 & echo $! > {}; wait", pidfile.display());
        let started = Instant::now();
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["sh","-c",script],"env":{"T":"verrou://A/password"},"reason":"x","timeout_seconds":1}),
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["timed_out"], true);
        // The `sleep` it started is gone with it (its own process group).
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!alive(pid.trim()), "the grandchild survived");
        std::fs::remove_file(&pidfile).ok();
    }

    #[cfg(unix)]
    #[test]
    fn run_is_killed_when_the_client_goes_away() {
        let mut server = initialized("x");
        let gone = Arc::clone(&server.gone);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            gone.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["sleep","60"],"env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert!(body["note"].as_str().unwrap().contains("client closed"));
    }

    #[cfg(unix)]
    #[test]
    fn an_input_closed_before_the_command_starts_does_not_kill_it() {
        // A script that sends its request and leaves still gets its answer.
        let mut server = initialized("x");
        server.gone.store(true, Ordering::SeqCst);
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["sh","-c","sleep 1; echo done"],"env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["stdout"], "done\n");
    }

    #[test]
    fn a_refusal_comes_back_as_a_tool_error_and_pauses_the_tool() {
        let mut server = initialized("x");
        server.gateway.fail = Some(Fake::refusing());
        let arguments = json!({"command":["true"],"env":{"T":"verrou://A/password"},"reason":"x"});
        let reply = call(&mut server, "verrou_run", &arguments);
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(text(&reply), "refused in Verrou");
        // Asked again at once: not even sent to Verrou.
        let reply = call(&mut server, "verrou_run", &arguments);
        assert_eq!(reply["result"]["isError"], true);
        assert!(text(&reply).contains("a moment ago"), "{}", text(&reply));
        assert_eq!(server.gateway.asked.len(), 1);
        // After the pause, it asks again.
        server.paused_until = Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        let reply = call(&mut server, "verrou_run", &arguments);
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(server.gateway.asked.len(), 2);
        // Another kind of failure does not pause anything.
        server.gateway.fail = Some(Failure {
            message: "the vault stayed locked".to_owned(),
            refused: false,
        });
        let reply = call(&mut server, "verrou_run", &arguments);
        assert_eq!(text(&reply), "the vault stayed locked");
        assert!(server.paused_until.is_none());
    }

    #[test]
    fn what_is_sent_back_is_scrubbed_of_known_secrets() {
        let mut server = initialized("x");
        server.secrets.push(Zeroizing::new(PASSWORD.to_owned()));
        let scrubbed = server.scrub(&format!("the server said {PASSWORD}, twice: {PASSWORD}"));
        assert_eq!(
            scrubbed,
            "the server said <concealed by Verrou>, twice: <concealed by Verrou>"
        );
    }

    #[test]
    fn a_secret_that_json_would_escape_is_still_scrubbed() {
        // A value with a quote and a backslash is written `\"` and `\\` in
        // JSON: scrubbing the text after serializing would miss it.
        let mut server = initialized("x");
        let secret = "pa\"ss\\word\n1";
        server.secrets.push(Zeroizing::new(secret.to_owned()));
        let mut value = json!({ (secret): [format!("before {secret} after")], "n": 1 });
        server.scrub_value(&mut value);
        let sent = value.to_string();
        assert!(!sent.contains("pa\\\"ss"), "{sent}");
        assert!(sent.contains("before <concealed by Verrou> after"));
        assert!(
            sent.contains("\"<concealed by Verrou>\""),
            "keys too: {sent}"
        );
    }

    #[test]
    fn an_unexpected_reply_is_named_never_shown() {
        let reply = ReplyResult::Secret(verrou_bridge::protocol::SecretValue {
            value: PASSWORD.to_owned(),
        });
        let message = unexpected(&reply).to_string();
        assert!(message.ends_with("secret"), "{message}");
        assert!(!message.contains(PASSWORD));
        // Nor does the reply's own `Debug` show it.
        assert!(!format!("{reply:?}").contains(PASSWORD));
    }

    #[test]
    fn a_no_or_an_unlock_that_never_came_is_a_refusal() {
        assert!(is_refusal(&Error::Denied("refused in Verrou".to_owned())));
        // The vault stayed locked: the unlock was declined or timed out.
        assert!(is_refusal(&Error::Locked));
        assert!(!is_refusal(&Error::Protocol("broken pipe".to_owned())));
        assert!(!is_refusal(&Error::AppUnavailable));
        assert!(!is_refusal(&Error::NotLinked));
    }

    #[cfg(unix)]
    #[test]
    fn a_client_that_left_during_the_approval_gets_no_command_run() {
        let mut server = initialized("x");
        server.gateway.leave_while_asking = Some(Arc::clone(&server.gone));
        let marker = std::env::temp_dir().join(format!("vm-left-{}", std::process::id()));
        std::fs::remove_file(&marker).ok();
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["touch", marker.to_str().unwrap()],
                "env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        assert!(text(&reply).contains("not run"), "{}", text(&reply));
        assert!(!marker.exists(), "the command must not start");
        assert_eq!(server.gateway.asked.len(), 1, "it was asked, then dropped");
    }

    #[test]
    fn a_command_line_the_approval_cannot_show_whole_is_refused() {
        let mut server = initialized("x");
        let long = "x".repeat(MAX_COMMAND_FOR_TEST);
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["echo", long],"env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        assert_eq!(reply["result"]["isError"], true);
        assert!(text(&reply).contains("script file"), "{}", text(&reply));
        assert_eq!(server.gateway.asked.len(), 0, "nobody was asked");
        // A directory is part of the line the user reads.
        let dir = std::env::temp_dir();
        let almost = "y".repeat(190);
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["echo", almost],"cwd": dir.to_str().unwrap(),
                "env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        assert_eq!(reply["result"]["isError"], true, "{}", text(&reply));
        // Too many or too long secret names are refused the same way.
        let mut env = serde_json::Map::new();
        for i in 0..10 {
            env.insert(
                format!("V{i}"),
                json!(format!("verrou://{}/password", "z".repeat(120))),
            );
        }
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["true"],"env":env,"reason":"x"}),
        );
        assert_eq!(reply["result"]["isError"], true);
        assert!(text(&reply).contains("too long"), "{}", text(&reply));
        assert_eq!(server.gateway.asked.len(), 0);
    }

    const MAX_COMMAND_FOR_TEST: usize = verrou_bridge::protocol::MAX_COMMAND + 1;

    #[cfg(unix)]
    #[test]
    fn the_approval_shows_the_directory_and_makes_control_characters_visible() {
        let mut server = initialized("x");
        let dir = std::env::temp_dir();
        let reply = call(
            &mut server,
            "verrou_run",
            &json!({"command":["printf", "a\nb\u{202e}"],"cwd": dir.to_str().unwrap(),
                "env":{"T":"verrou://A/password"},"reason":"x"}),
        );
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        let (_, detail) = &server.gateway.asked[0];
        assert!(detail.command.starts_with("cd "), "{}", detail.command);
        assert!(detail.command.contains(" && printf "), "{}", detail.command);
        // What the bridge then shows: the line break and the override are
        // spelled out, not flattened or dropped.
        let shown = detail.cleaned().command;
        assert!(shown.contains("a⏎b\\u{202e}"), "{shown}");
        assert!(!shown.contains('\n') && !shown.contains('\u{202e}'));
    }

    #[test]
    fn generate_password_returns_a_new_value() {
        let mut server = initialized("x");
        let reply = call(
            &mut server,
            "verrou_generate_password",
            &json!({"length": 30}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["value"].as_str().unwrap().chars().count(), 30);
        let reply = call(
            &mut server,
            "verrou_generate_password",
            &json!({"words": 4}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["value"].as_str().unwrap().split('-').count(), 4);
    }

    #[test]
    fn the_clients_name_is_kept_short_and_on_one_line() {
        assert_eq!(client_label("Claude\nCode"), "Claude Code");
        assert_eq!(
            client_label(&"x".repeat(100)).chars().count(),
            MAX_CLIENT_NAME
        );
    }

    #[test]
    fn status_reports_the_link() {
        let mut server = initialized("x");
        let reply = call(&mut server, "verrou_status", &json!({}));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["linked"], true);
        assert_eq!(body["unlocked"], true);
    }
}
