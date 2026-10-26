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
//! The other thing an agent does here is **organize**: it reads the vault's
//! catalog (titles, usernames, hosts, folders, flags and counts, never a
//! secret, a note or a field; one approval in Verrou covers it for half an
//! hour), and proposes a plan (`verrou_propose_plan`): folders to create,
//! items to move, rename, archive or trash, duplicates to merge, each with a
//! reason. It applies nothing. Verrou checks the plan against the vault, the
//! user reviews it in a sheet and applies the operations they check with one
//! Touch ID, and the agent only reads how that ended (`verrou_plan_status`).
//! A plan the agent made up of items it never saw is refused by those
//! checks, not by the agent's good manners.
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
use verrou_bridge::protocol::{
    CatalogItem, Command as Ask, DuplicateInfo, ItemView, Plan, PlanOp, PlanPhase, PlanState,
    ReplyResult, RunDetail, VaultOverview, clean_reason,
};
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
/// Items per page of `verrou_list_items`: default and maximum.
const DEFAULT_PAGE: u64 = 200;
const MAX_PAGE: u64 = 500;
/// `verrou_propose_plan` waits for the user this many times [`PLAN_WAIT`]
/// seconds before it says the plan still awaits them.
const PLAN_WAITS: usize = 2;
const PLAN_WAIT: u32 = 50;
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
refusal pauses this tool for a minute.

To reorganize the vault, read it with verrou_vault_overview, verrou_list_items (pages of up to 500; \
titles, usernames, sites, folders and flags, never a secret) and verrou_find_duplicates; the user \
approves reading the catalog once for this session, for half an hour. Then propose a plan with verrou_propose_plan: \
folders to create, items to move, rename, archive or trash, duplicates to merge, each operation with \
its own short rationale. Nothing is applied by you: Verrou checks the plan, the user reviews it in \
Verrou and applies what they check, and you read the outcome with verrou_plan_status. Propose \
conservatively: only what you are sure of, one plan at a time, never to delete what you cannot \
justify. There are no tags (Vaultwarden has none): use folders.";

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
    /// What the vault holds, counted: the catalog, which the user approves
    /// once for half an hour. `reason`: as for [`Self::resolve`].
    fn overview(&mut self, reason: &str) -> Result<VaultOverview, Failure>;
    /// A page of the catalog, and the number of items in all.
    fn list(
        &mut self,
        reason: &str,
        offset: u32,
        limit: u32,
        archived: bool,
    ) -> Result<(Vec<CatalogItem>, u32), Failure>;
    /// The logins' duplicate groups, and how many there are in all.
    fn duplicates(&mut self, reason: &str) -> Result<(Vec<DuplicateInfo>, u32), Failure>;
    /// A plan for the user to review. Answers at once.
    fn propose(&mut self, reason: &str, plan: Plan) -> Result<PlanState, Failure>;
    /// Where a plan stands, after waiting up to `wait` seconds for it to
    /// change.
    fn plan_status(&mut self, plan: &str, wait: u32) -> Result<PlanState, Failure>;
    /// Withdraws a plan awaiting review.
    fn plan_cancel(&mut self, plan: &str) -> Result<PlanState, Failure>;
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
    /// Drawn when this process starts: what the user approves for the
    /// catalog, and the plans, belong to this agent session and no other
    /// (the paired client is the same for every `verrou mcp` of the machine).
    session: String,
}

/// A session identifier: 122 random bits (a version 4 UUID), in hexadecimal.
fn new_session() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

impl BridgeGateway {
    pub fn new(config_path: PathBuf, endpoint: Endpoint) -> Self {
        Self {
            config_path,
            endpoint,
            remote: None,
            session: new_session(),
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
        remote.session = None;
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

impl BridgeGateway {
    /// Asks Verrou, telling a refusal (a no, a vault that stayed locked)
    /// from any other failure.
    fn ask_for(&mut self, reason: Option<&str>, command: &Ask) -> Result<ReplyResult, Failure> {
        let mut refused = false;
        let session = self.session.clone();
        self.with(reason, |remote| {
            // The catalog and the plans: this session's.
            remote.session = Some(session);
            remote.ask(command).inspect_err(|e| refused = is_refusal(e))
        })
        .map_err(|message| Failure { message, refused })
    }

    /// A plan's state: any other reply is not one.
    fn plan_state(&mut self, reason: Option<&str>, command: &Ask) -> Result<PlanState, Failure> {
        match self.ask_for(reason, command)? {
            ReplyResult::Plan(state) => Ok(state),
            other => Err(Failure {
                message: unexpected(&other).to_string(),
                refused: false,
            }),
        }
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

    fn overview(&mut self, reason: &str) -> Result<VaultOverview, Failure> {
        match self.ask_for(Some(reason), &Ask::VaultOverview)? {
            ReplyResult::Overview(overview) => Ok(overview),
            other => Err(Failure {
                message: unexpected(&other).to_string(),
                refused: false,
            }),
        }
    }

    fn list(
        &mut self,
        reason: &str,
        offset: u32,
        limit: u32,
        archived: bool,
    ) -> Result<(Vec<CatalogItem>, u32), Failure> {
        let command = Ask::VaultList {
            offset,
            limit: Some(limit),
            archived,
        };
        match self.ask_for(Some(reason), &command)? {
            ReplyResult::Catalog { items, total } => Ok((items, total)),
            other => Err(Failure {
                message: unexpected(&other).to_string(),
                refused: false,
            }),
        }
    }

    fn duplicates(&mut self, reason: &str) -> Result<(Vec<DuplicateInfo>, u32), Failure> {
        match self.ask_for(Some(reason), &Ask::VaultDuplicates)? {
            ReplyResult::Duplicates { groups, total } => Ok((groups, total)),
            other => Err(Failure {
                message: unexpected(&other).to_string(),
                refused: false,
            }),
        }
    }

    fn propose(&mut self, reason: &str, plan: Plan) -> Result<PlanState, Failure> {
        self.plan_state(Some(reason), &Ask::PlanPropose { plan })
    }

    fn plan_status(&mut self, plan: &str, wait: u32) -> Result<PlanState, Failure> {
        self.plan_state(
            None,
            &Ask::PlanStatus {
                plan: plan.to_owned(),
                wait,
            },
        )
    }

    fn plan_cancel(&mut self, plan: &str) -> Result<PlanState, Failure> {
        self.plan_state(
            None,
            &Ask::PlanCancel {
                plan: plan.to_owned(),
            },
        )
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
            "verrou_vault_overview" => self.overview(arguments),
            "verrou_list_items" => self.list_items(arguments),
            "verrou_find_duplicates" => self.find_duplicates(arguments),
            "verrou_propose_plan" => self.propose_plan(arguments),
            "verrou_plan_status" => self.plan_status(arguments),
            "verrou_plan_cancel" => self.plan_cancel(arguments),
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

    /// After a refusal, the tools that ask the user wait: the outcome to
    /// give instead, if it is not over.
    fn pause(&mut self) -> Option<Outcome> {
        let until = self.paused_until?;
        if Instant::now() < until {
            return Some(Outcome::err(format!(
                "the user refused a request a moment ago: wait {} seconds before asking again, and ask the user what they want",
                until.saturating_duration_since(Instant::now()).as_secs() + 1
            )));
        }
        self.paused_until = None;
        None
    }

    /// A refusal pauses the tools that ask the user, a minute.
    fn paused_after(&mut self, failure: Failure) -> Outcome {
        if failure.refused {
            self.paused_until = Some(Instant::now() + REFUSAL_PAUSE);
        }
        Outcome::err(failure.message)
    }

    fn overview(&mut self, arguments: &Value) -> Outcome {
        if let Some(paused) = self.pause() {
            return paused;
        }
        let reason = match self.reason(arguments) {
            Ok(reason) => reason,
            Err(outcome) => return outcome,
        };
        match self.gateway.overview(&reason) {
            Ok(overview) => Outcome::ok(&overview_json(&overview)),
            Err(failure) => self.paused_after(failure),
        }
    }

    fn list_items(&mut self, arguments: &Value) -> Outcome {
        if let Some(paused) = self.pause() {
            return paused;
        }
        let reason = match self.reason(arguments) {
            Ok(reason) => reason,
            Err(outcome) => return outcome,
        };
        let offset = arguments
            .get("offset")
            .and_then(Value::as_u64)
            .map_or(0, |o| u32::try_from(o).unwrap_or(u32::MAX));
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_PAGE)
            .clamp(1, MAX_PAGE);
        let limit = u32::try_from(limit).unwrap_or(200);
        let archived = arguments
            .get("include_archived")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match self.gateway.list(&reason, offset, limit, archived) {
            Ok((items, total)) => {
                // What came back may be fewer than asked (a page is cut to
                // fit a reply): the next page starts after what was given.
                let next = offset.saturating_add(u32::try_from(items.len()).unwrap_or(0));
                Outcome::ok(&json!({
                    "items": items.iter().map(catalog_json).collect::<Vec<_>>(),
                    "total": total,
                    "offset": offset,
                    "next_offset": (next < total && !items.is_empty()).then_some(next),
                }))
            }
            Err(failure) => self.paused_after(failure),
        }
    }

    fn find_duplicates(&mut self, arguments: &Value) -> Outcome {
        if let Some(paused) = self.pause() {
            return paused;
        }
        let reason = match self.reason(arguments) {
            Ok(reason) => reason,
            Err(outcome) => return outcome,
        };
        match self.gateway.duplicates(&reason) {
            Ok((groups, total)) => {
                let shown = groups.len();
                let mut result = json!({ "groups": groups, "total": total });
                if usize::try_from(total).unwrap_or(usize::MAX) > shown {
                    result["note"] = json!(format!("only the first {shown} groups are listed"));
                }
                Outcome::ok(&result)
            }
            Err(failure) => self.paused_after(failure),
        }
    }

    /// A plan: its reason is the one the user reads in the review, in the
    /// agent's own words (the client's name is shown apart, from Verrou's
    /// own knowledge of the client). The call waits for the user, up to
    /// [`PLAN_WAIT`], then says the plan still awaits them.
    fn propose_plan(&mut self, arguments: &Value) -> Outcome {
        let reason = match self.reason(arguments) {
            Ok(reason) => reason,
            Err(outcome) => return outcome,
        };
        let plan_reason = arguments
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(list) = arguments.get("operations").and_then(Value::as_array) else {
            return Outcome::err("\"operations\" is an array of operations");
        };
        let mut operations = Vec::with_capacity(list.len());
        for (index, operation) in list.iter().enumerate() {
            match serde_json::from_value::<PlanOp>(operation.clone()) {
                Ok(op) => operations.push(op),
                Err(e) => return Outcome::err(format!("operations[{index}]: {e}")),
            }
        }
        let plan = Plan {
            reason: plan_reason,
            operations,
        };
        let mut state = match self.gateway.propose(&reason, plan) {
            Ok(state) => state,
            Err(failure) => return self.paused_after(failure),
        };
        // The user reviews at their own pace: ask again, a little, not
        // forever (two waits of 50 seconds).
        for _ in 0..PLAN_WAITS {
            if state.state != PlanPhase::AwaitingReview {
                break;
            }
            state = match self.gateway.plan_status(&state.plan, PLAN_WAIT) {
                Ok(state) => state,
                // The plan is with the user: say so, and which one it is.
                Err(failure) => {
                    return Outcome::err(format!(
                        "{} (plan {} was proposed and may still be awaiting the user: call verrou_plan_status with it)",
                        failure.message, state.plan
                    ));
                }
            };
        }
        Outcome::ok(&plan_json(&state))
    }

    fn plan_id(arguments: &Value) -> Result<String, Outcome> {
        arguments
            .get("plan")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Outcome::err("\"plan\" is the identifier verrou_propose_plan gave"))
    }

    fn plan_status(&mut self, arguments: &Value) -> Outcome {
        let plan = match Self::plan_id(arguments) {
            Ok(plan) => plan,
            Err(outcome) => return outcome,
        };
        let wait = arguments
            .get("wait_seconds")
            .and_then(Value::as_u64)
            .map_or(PLAN_WAIT, |w| {
                u32::try_from(w.min(u64::from(PLAN_WAIT))).unwrap_or(0)
            });
        match self.gateway.plan_status(&plan, wait) {
            Ok(state) => Outcome::ok(&plan_json(&state)),
            Err(failure) => Outcome::err(failure.message),
        }
    }

    fn plan_cancel(&mut self, arguments: &Value) -> Outcome {
        let plan = match Self::plan_id(arguments) {
            Ok(plan) => plan,
            Err(outcome) => return outcome,
        };
        match self.gateway.plan_cancel(&plan) {
            Ok(state) => Outcome::ok(&plan_json(&state)),
            Err(failure) => Outcome::err(failure.message),
        }
    }

    fn run(&mut self, arguments: &Value) -> Outcome {
        if let Some(paused) = self.pause() {
            return paused;
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

// MARK: Organizing

fn count_kinds(kinds: &[verrou_bridge::protocol::KindCount]) -> Value {
    let mut map = Map::new();
    for entry in kinds {
        map.insert(entry.kind.keyword().to_owned(), json!(entry.count));
    }
    Value::Object(map)
}

/// The overview as the agent reads it: kinds by their keywords.
fn overview_json(overview: &VaultOverview) -> Value {
    let mut value = serde_json::to_value(overview).unwrap_or(Value::Null);
    value["kinds"] = count_kinds(&overview.kinds);
    value
}

/// An item of the catalog: the kind by its keyword (`note`, not
/// `SecureNote`), as `verrou_search` says it.
fn catalog_json(item: &CatalogItem) -> Value {
    let mut value = serde_json::to_value(item).unwrap_or(Value::Null);
    value["kind"] = json!(item.kind.keyword());
    value
}

/// A plan's state with what the agent should do about it.
fn plan_json(state: &PlanState) -> Value {
    let mut value = serde_json::to_value(state).unwrap_or(Value::Null);
    let hint = match state.state {
        PlanPhase::AwaitingReview => {
            "the user has not answered yet: call verrou_plan_status with this plan to wait longer; do not propose it again"
        }
        PlanPhase::Applying => "the user is applying the plan: call verrou_plan_status again",
        PlanPhase::Applied => {
            "applied: the report says what was done, what was left as it was and what failed; the user can still undo it for ten minutes"
        }
        PlanPhase::Declined => {
            "the user declined the plan: do not propose it again, ask them what they want instead"
        }
        PlanPhase::Expired => {
            "nobody reviewed it in time: nothing was applied; ask the user before proposing it again"
        }
        PlanPhase::Cancelled => "the plan was withdrawn: nothing was applied",
        PlanPhase::Undone => "the user undid the plan: do not propose it again",
        PlanPhase::Interrupted => {
            "applying stopped halfway (Verrou was locked, or the vault changed): the report says what was done before; read the vault again before proposing anything"
        }
    };
    value["hint"] = json!(hint);
    value
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
    let mut tools = json!([
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
    ]);
    if let Some(list) = tools.as_array_mut() {
        list.extend(organizing_tools(&reason));
    }
    tools
}

/// The tools to read the catalog and propose a reorganization.
fn organizing_tools(reason: &Value) -> Vec<Value> {
    let mut tools = catalog_tools(reason);
    tools.extend(plan_tools(reason));
    tools
}

fn catalog_tools(reason: &Value) -> Vec<Value> {
    vec![
        json!({
            "name": "verrou_vault_overview",
            "title": "What the vault holds",
            "description": "Counts of the vault's items by kind, its folders (empty ones too, with how many items each holds), and how many items are archived, shared, protected, with a one-time code or a passkey. No item and no value. The first catalog call asks the user once for this agent session, for half an hour (the same approval covers verrou_list_items and verrou_find_duplicates). Start here to plan a reorganization.",
            "inputSchema": {
                "type": "object",
                "properties": { "reason": reason },
                "required": ["reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        }),
        json!({
            "name": "verrou_list_items",
            "title": "List the vault's items",
            "description": "A page of the vault's catalog, by title: id, kind, title, username (logins), sites (host or application only, no path), folder, favorite, state, organization, read_only, protected, has_totp, has_passkey, attachments, has_notes, created, modified. Never a password, a one-time code, a note, a field's name or value, or a URL path. The trash is never listed. Follow next_offset until it is null. Item ids are what a plan names.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "offset": { "type": "integer", "minimum": 0, "description": "Items to skip (use next_offset from the previous page)." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "description": "Items per page (default 200)." },
                    "include_archived": { "type": "boolean", "description": "Archived items too (default false)." },
                    "reason": reason
                },
                "required": ["reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        }),
        json!({
            "name": "verrou_find_duplicates",
            "title": "Find duplicate logins",
            "description": "Groups of logins that look like the same account (by site, title and username: passwords and one-time codes are never compared for you), most certain first: group (the key a merge names), label, username, confidence (probable or review), the reason, the item Verrou would keep, and each member's id and title. Only logins, which are the only items a plan can merge. Needs the same approval as verrou_list_items.",
            "inputSchema": {
                "type": "object",
                "properties": { "reason": reason },
                "required": ["reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        }),
    ]
}

fn plan_tools(reason: &Value) -> Vec<Value> {
    vec![
        json!({
            "name": "verrou_propose_plan",
            "title": "Propose a reorganization",
            "description": "Propose a reorganization of the vault for the user to review in Verrou: nothing is applied by you. Each operation needs a short rationale (at most 120 characters). The user sees the plan in a sheet, checks what they accept and applies it with one Touch ID; Verrou has already refused operations that break its rules (an unknown or trashed item, a read-only shared item, an item that is both renamed and trashed, a merge that would lose an attachment or a passkey, a folder that does not exist), and says which in rejected. At most 1000 operations and one plan awaiting review at a time; the call waits up to 100 seconds for the user, then returns the plan's state: use verrou_plan_status to keep waiting. Operations: create_folder{name}; move{item, folder} (an empty folder takes the item out of its folder; the folder must exist or be created in the same plan); rename{item, title}; merge{group, keep} (merges the other items of a verrou_find_duplicates group into keep, then trashes them); archive{item}; trash{item} (restorable for 30 days). No tags: use folders.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reason": { "type": "string", "maxLength": 120, "description": "One short sentence: what this reorganization is for. The user reads it, in your words, at the top of the review." },
                    "operations": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 1000,
                        "items": {
                            "oneOf": [
                                { "type": "object", "properties": { "op": { "const": "create_folder" }, "name": { "type": "string", "maxLength": 100 }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "name", "rationale"], "additionalProperties": false },
                                { "type": "object", "properties": { "op": { "const": "move" }, "item": { "type": "string" }, "folder": { "type": "string", "maxLength": 100 }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "item", "folder", "rationale"], "additionalProperties": false },
                                { "type": "object", "properties": { "op": { "const": "rename" }, "item": { "type": "string" }, "title": { "type": "string", "maxLength": 200 }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "item", "title", "rationale"], "additionalProperties": false },
                                { "type": "object", "properties": { "op": { "const": "merge" }, "group": { "type": "string" }, "keep": { "type": "string" }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "group", "keep", "rationale"], "additionalProperties": false },
                                { "type": "object", "properties": { "op": { "const": "archive" }, "item": { "type": "string" }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "item", "rationale"], "additionalProperties": false },
                                { "type": "object", "properties": { "op": { "const": "trash" }, "item": { "type": "string" }, "rationale": { "type": "string", "maxLength": 120 } }, "required": ["op", "item", "rationale"], "additionalProperties": false }
                            ]
                        }
                    }
                },
                "required": ["reason", "operations"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false }
        }),
        json!({
            "name": "verrou_plan_status",
            "title": "Where a plan stands",
            "description": "The state of a plan: awaiting_review, applying, applied (with a report of what was applied, queued, left as it was and what failed), declined, expired, cancelled, undone or interrupted (applying stopped halfway: the report says what was done). Waits up to 50 seconds for a plan that is awaiting the user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": { "type": "string", "description": "The plan's identifier." },
                    "wait_seconds": { "type": "integer", "minimum": 0, "maximum": PLAN_WAIT, "description": "Longest wait for a change (default 50)." },
                    "reason": reason
                },
                "required": ["plan"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
        }),
        json!({
            "name": "verrou_plan_cancel",
            "title": "Withdraw a plan",
            "description": "Withdraw a plan that still awaits the user's review: it disappears from Verrou. A plan being applied cannot be withdrawn.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": { "type": "string", "description": "The plan's identifier." },
                    "reason": reason
                },
                "required": ["plan"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        }),
    ]
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
        /// What the catalog tools answer, and the reasons they were asked
        /// with.
        catalog: Vec<CatalogItem>,
        groups: Vec<DuplicateInfo>,
        catalog_asked: Vec<String>,
        /// The states `plan_status` answers in turn (the last one repeats),
        /// the plans proposed, and the waits asked.
        states: Vec<PlanState>,
        proposed: Vec<(String, Plan)>,
        waits: Vec<u32>,
        cancelled: Vec<String>,
        /// What the next `plan_status` fails with.
        poll_failure: Option<Failure>,
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

        fn overview(&mut self, reason: &str) -> Result<VaultOverview, Failure> {
            self.catalog_asked.push(reason.to_owned());
            self.fail.take().map_or_else(
                || {
                    Ok(VaultOverview {
                        items: 3,
                        kinds: vec![verrou_bridge::protocol::KindCount {
                            kind: ItemKind::SecureNote,
                            count: 1,
                        }],
                        ..VaultOverview::default()
                    })
                },
                Err,
            )
        }

        fn list(
            &mut self,
            reason: &str,
            offset: u32,
            limit: u32,
            _archived: bool,
        ) -> Result<(Vec<CatalogItem>, u32), Failure> {
            self.catalog_asked
                .push(format!("{reason} @{offset}+{limit}"));
            if let Some(failure) = self.fail.take() {
                return Err(failure);
            }
            let total = u32::try_from(self.catalog.len()).unwrap();
            let page = self
                .catalog
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .cloned()
                .collect();
            Ok((page, total))
        }

        fn duplicates(&mut self, reason: &str) -> Result<(Vec<DuplicateInfo>, u32), Failure> {
            self.catalog_asked.push(reason.to_owned());
            Ok((
                self.groups.clone(),
                u32::try_from(self.groups.len()).unwrap(),
            ))
        }

        fn propose(&mut self, reason: &str, plan: Plan) -> Result<PlanState, Failure> {
            self.proposed.push((reason.to_owned(), plan));
            if let Some(failure) = self.fail.take() {
                return Err(failure);
            }
            Ok(self
                .states
                .first()
                .cloned()
                .unwrap_or_else(|| state(PlanPhase::AwaitingReview)))
        }

        fn plan_status(&mut self, _: &str, wait: u32) -> Result<PlanState, Failure> {
            self.waits.push(wait);
            if let Some(failure) = self.poll_failure.take() {
                return Err(failure);
            }
            // `states[0]` answered the proposal: the polls read on from
            // there, the last one repeating.
            let poll = self.waits.len();
            Ok(self
                .states
                .get(poll)
                .or_else(|| self.states.last())
                .cloned()
                .unwrap_or_else(|| state(PlanPhase::AwaitingReview)))
        }

        fn plan_cancel(&mut self, plan: &str) -> Result<PlanState, Failure> {
            self.cancelled.push(plan.to_owned());
            Ok(state(PlanPhase::Cancelled))
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
                "verrou_generate_password",
                "verrou_vault_overview",
                "verrou_list_items",
                "verrou_find_duplicates",
                "verrou_propose_plan",
                "verrou_plan_status",
                "verrou_plan_cancel"
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
    fn the_organizing_tools_ask_for_the_reasons_that_prompt() {
        let mut server = Server::new(Fake::default());
        let reply = ask(
            &mut server,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        );
        let tools = reply["result"]["tools"].as_array().unwrap();
        let required = |name: &str| -> Vec<String> {
            let tool = tools.iter().find(|t| t["name"] == name).unwrap();
            tool["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        for tool in [
            "verrou_vault_overview",
            "verrou_list_items",
            "verrou_find_duplicates",
        ] {
            assert_eq!(required(tool), ["reason"], "{tool}");
        }
        assert_eq!(required("verrou_propose_plan"), ["reason", "operations"]);
        assert_eq!(required("verrou_plan_status"), ["plan"]);
        assert_eq!(required("verrou_plan_cancel"), ["plan"]);
        // The operations are a closed set, one schema each, the unsupported
        // ones (tags) not among them.
        let propose = tools
            .iter()
            .find(|t| t["name"] == "verrou_propose_plan")
            .unwrap();
        let ops: Vec<&str> = propose["inputSchema"]["properties"]["operations"]["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["properties"]["op"]["const"].as_str().unwrap())
            .collect();
        assert_eq!(
            ops,
            [
                "create_folder",
                "move",
                "rename",
                "merge",
                "archive",
                "trash"
            ]
        );
        assert!(
            server
                .handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#)
                .unwrap()
                .contains("verrou_propose_plan")
        );
    }

    fn catalog_item(id: &str, title: &str) -> CatalogItem {
        CatalogItem {
            id: id.to_owned(),
            kind: ItemKind::SecureNote,
            title: title.to_owned(),
            username: None,
            sites: vec!["example.com".to_owned()],
            folder: None,
            favorite: false,
            state: "active".to_owned(),
            shared: None,
            read_only: false,
            protected: false,
            has_totp: false,
            has_passkey: false,
            attachments: 0,
            has_notes: true,
            created: 1,
            modified: 2,
        }
    }

    fn state(phase: PlanPhase) -> PlanState {
        PlanState {
            plan: "p1".to_owned(),
            state: phase,
            message: String::new(),
            expires_in: None,
            rejected: Vec::new(),
            report: None,
        }
    }

    #[test]
    fn the_catalog_is_read_in_pages_with_the_kind_as_a_keyword() {
        let mut server = initialized("Coding Agent");
        server.gateway.catalog = (0..5)
            .map(|n| catalog_item(&format!("id{n}"), &format!("Item {n}")))
            .collect();
        let reply = call(
            &mut server,
            "verrou_list_items",
            &json!({"limit": 2, "reason": "tidy"}),
        );
        assert_eq!(reply["result"]["isError"], false, "{}", text(&reply));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
        assert_eq!(body["items"][0]["kind"], "note", "as verrou_search says it");
        assert_eq!(
            (body["total"].as_u64(), body["next_offset"].as_u64()),
            (Some(5), Some(2))
        );
        // The last page has no next one; the limit is clamped to a page.
        let reply = call(
            &mut server,
            "verrou_list_items",
            &json!({"offset": 4, "limit": 9999, "include_archived": true, "reason": "tidy"}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert!(body["next_offset"].is_null());
        // The reason the user reads, with the client's name.
        assert_eq!(
            server.gateway.catalog_asked,
            ["Coding Agent: tidy @0+2", "Coding Agent: tidy @4+500"]
        );
        // A reason is required: it is what the approval says.
        let reply = call(&mut server, "verrou_list_items", &json!({}));
        assert_eq!(reply["result"]["isError"], true);
        assert!(text(&reply).contains("reason"));
        let reply = call(
            &mut server,
            "verrou_vault_overview",
            &json!({"reason": "look"}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["items"], 3);
        assert_eq!(body["kinds"]["note"], 1);
    }

    #[test]
    fn duplicates_come_back_with_their_group_keys() {
        let mut server = initialized("x");
        server.gateway.groups = vec![DuplicateInfo {
            group: "key-1".to_owned(),
            label: "github.com".to_owned(),
            username: "camille".to_owned(),
            confidence: "certain".to_owned(),
            reason: "same site".to_owned(),
            mergeable: true,
            suggested_keep: "a".to_owned(),
            members: Vec::new(),
        }];
        let reply = call(
            &mut server,
            "verrou_find_duplicates",
            &json!({"reason": "merge"}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["groups"][0]["group"], "key-1");
        assert_eq!(body["total"], 1);
        assert!(body.get("note").is_none());
    }

    #[test]
    fn a_refused_catalog_pauses_the_tools_that_ask() {
        let mut server = initialized("x");
        server.gateway.fail = Some(Fake::refusing());
        let reply = call(&mut server, "verrou_list_items", &json!({"reason": "tidy"}));
        assert_eq!(reply["result"]["isError"], true);
        // Not asked again at once, by this tool or by `verrou_run`.
        for (tool, arguments) in [
            ("verrou_list_items", json!({"reason": "again"})),
            ("verrou_vault_overview", json!({"reason": "again"})),
            ("verrou_find_duplicates", json!({"reason": "again"})),
            (
                "verrou_run",
                json!({"command":["true"],"env":{"T":"verrou://A/password"},"reason":"x"}),
            ),
        ] {
            let reply = call(&mut server, tool, &arguments);
            assert_eq!(reply["result"]["isError"], true, "{tool}");
            assert!(
                text(&reply).contains("refused a request a moment ago"),
                "{tool}"
            );
        }
        assert_eq!(server.gateway.catalog_asked.len(), 1);
        assert_eq!(server.gateway.asked.len(), 0);
    }

    #[test]
    fn a_plan_is_proposed_in_the_agents_words_and_followed_twice() {
        let mut server = initialized("Coding Agent");
        let reply = call(
            &mut server,
            "verrou_propose_plan",
            &json!({"reason": "file the bank logins", "operations": [
                {"op": "create_folder", "name": "Bank", "rationale": "one place"},
                {"op": "move", "item": "id1", "folder": "Bank", "rationale": "it is a bank"},
                {"op": "set_tags", "item": "id1", "tags": ["a"]},
            ]}),
        );
        assert_eq!(reply["result"]["isError"], false, "{}", text(&reply));
        let (asked, plan) = &server.gateway.proposed[0];
        // The request's reason names the client; the plan's own reason is
        // the agent's alone (the review shows the client apart).
        assert_eq!(asked, "Coding Agent: file the bank logins");
        assert_eq!(plan.reason, "file the bank logins");
        assert_eq!(plan.operations.len(), 3);
        assert_eq!(plan.operations[2], PlanOp::Unsupported);
        // Nobody answered: two waits of 50 seconds, then it says so.
        assert_eq!(server.gateway.waits, [50, 50]);
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["state"], "awaiting_review");
        assert!(
            body["hint"]
                .as_str()
                .unwrap()
                .contains("verrou_plan_status")
        );
    }

    #[test]
    fn a_plan_answered_in_time_is_not_waited_for_again() {
        let mut server = initialized("x");
        server.gateway.states = vec![state(PlanPhase::AwaitingReview), state(PlanPhase::Applied)];
        let reply = call(
            &mut server,
            "verrou_propose_plan",
            &json!({"reason": "r", "operations": [{"op": "archive", "item": "a", "rationale": "old"}]}),
        );
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["state"], "applied");
        assert_eq!(server.gateway.waits.len(), 1);
        // A plan declined says not to propose it again.
        let mut declined = state(PlanPhase::Declined);
        "the user declined the plan".clone_into(&mut declined.message);
        let hint = plan_json(&declined);
        assert!(
            hint["hint"]
                .as_str()
                .unwrap()
                .contains("do not propose it again")
        );
        assert_eq!(hint["message"], "the user declined the plan");
    }

    #[test]
    fn an_error_after_the_plan_was_proposed_names_the_plan() {
        let mut server = initialized("x");
        server.gateway.states = vec![state(PlanPhase::AwaitingReview)];
        server.gateway.poll_failure = Some(Failure {
            message: "the connection to Verrou broke".to_owned(),
            refused: false,
        });
        let reply = call(
            &mut server,
            "verrou_propose_plan",
            &json!({"reason": "r", "operations": [{"op": "archive", "item": "a", "rationale": "old"}]}),
        );
        assert_eq!(reply["result"]["isError"], true);
        let message = text(&reply);
        assert!(
            message.contains("the connection to Verrou broke"),
            "{message}"
        );
        assert!(
            message.contains("p1") && message.contains("verrou_plan_status"),
            "the plan is with the user, and the agent can follow it: {message}"
        );
    }

    #[test]
    fn a_badly_formed_plan_is_told_where() {
        let mut server = initialized("x");
        for (arguments, needle) in [
            (json!({"operations": []}), "reason"),
            (json!({"reason": "r"}), "operations"),
            (
                json!({"reason": "r", "operations": [{"op": "rename", "item": 3, "title": "x", "rationale": "y"}]}),
                "operations[0]",
            ),
        ] {
            let reply = call(&mut server, "verrou_propose_plan", &arguments);
            assert_eq!(reply["result"]["isError"], true, "{arguments}");
            assert!(text(&reply).contains(needle), "{}", text(&reply));
        }
        assert!(server.gateway.proposed.is_empty(), "nothing reached Verrou");
    }

    #[test]
    fn a_plan_is_followed_and_withdrawn_by_its_identifier() {
        let mut server = initialized("x");
        let reply = call(
            &mut server,
            "verrou_plan_status",
            &json!({"plan": "p1", "wait_seconds": 7}),
        );
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(server.gateway.waits, [7]);
        // Never longer than 50 seconds, and by default 50.
        call(
            &mut server,
            "verrou_plan_status",
            &json!({"plan": "p1", "wait_seconds": 500}),
        );
        call(&mut server, "verrou_plan_status", &json!({"plan": "p1"}));
        assert_eq!(server.gateway.waits, [7, 50, 50]);
        let reply = call(&mut server, "verrou_plan_cancel", &json!({"plan": "p1"}));
        let body: Value = serde_json::from_str(text(&reply)).unwrap();
        assert_eq!(body["state"], "cancelled");
        assert_eq!(server.gateway.cancelled, ["p1"]);
        for tool in ["verrou_plan_status", "verrou_plan_cancel"] {
            assert_eq!(
                call(&mut server, tool, &json!({}))["result"]["isError"],
                true
            );
        }
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
