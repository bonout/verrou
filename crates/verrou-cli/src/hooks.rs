//! `verrou hook <agent>`: a guard rail for coding agents (Claude Code,
//! Cursor, Codex). Before the agent reads a file or runs a command, the
//! agent runs this hook, which refuses what would put a secret into the
//! model's context: reading `.env` files, private keys, cloud credentials,
//! or printing a token from the environment. The refusal tells the agent
//! what to do instead: `verrou_run` (MCP) or `verrou run`, with `verrou://`
//! references, so that the value goes to the command and never to the model.
//!
//! This is a guard rail, not a sandbox: it reads a command the way a person
//! skimming it would (programs and the paths next to them), and a determined
//! agent can get around it (`cat .e*`, a script that reads the file). What
//! actually protects the vault is that secrets only leave it through an
//! approval by the user; this hook keeps the *other* secrets, the ones lying
//! in the working directory, from being read by accident.
//!
//! Formats, from the agents' documentation:
//!
//! - Claude Code (<https://code.claude.com/docs/en/hooks>): a `PreToolUse`
//!   hook reads `{"tool_name", "tool_input"}` on stdin (`Bash`: `command`;
//!   `Read`: `file_path`; `Grep`: `pattern`, `path`, `glob`) and refuses with
//!   `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
//!   "permissionDecision": "deny", "permissionDecisionReason": …}}` on
//!   stdout, exit 0. No output and exit 0 leaves the decision to the normal
//!   permission flow. Configured in `~/.claude/settings.json` or
//!   `.claude/settings.json`: `hooks.PreToolUse[{matcher, hooks[{type,
//!   command}]}]`.
//! - Codex (<https://learn.chatgpt.com/docs/hooks>): the same `PreToolUse`
//!   input and output; it only offers shell commands (`Bash`) to hooks, not
//!   file reads. Configured in `~/.codex/hooks.json` or `.codex/hooks.json`
//!   (project hooks are loaded once the folder is trusted, and each hook is
//!   reviewed with `/hooks`).
//! - Cursor (<https://cursor.com/docs/agent/hooks>): `beforeShellExecution`
//!   reads `{"command", "cwd"}` and `beforeReadFile` reads `{"file_path", …}`;
//!   both answer `{"permission": "allow" | "deny", "user_message", …}`
//!   (shell only: `agent_message`, sent to the agent). The answer is always
//!   printed: Cursor blocks on anything it cannot parse. Configured in
//!   `~/.cursor/hooks.json` or `.cursor/hooks.json`:
//!   `{"version": 1, "hooks": {event: [{command}]}}`.

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

/// The agents we know the hook formats of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Cursor,
    Codex,
}

impl Agent {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "claude" | "claude-code" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "codex" => Some(Self::Codex),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
        }
    }

    /// The command written in the agent's configuration.
    pub fn command(self) -> String {
        format!("verrou hook {}", self.name())
    }
}

/// What the hook decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Refused, with what the agent is told.
    Deny(String),
}

impl Decision {
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny(_))
    }
}

const ADVICE: &str = "Use Verrou instead: call the verrou_run MCP tool (or `verrou run -- <command>` in a shell) with environment variables set to verrou://<item>/<field> references, for example API_KEY=verrou://Stripe/secret%20key. The user approves, the command gets the value, and the value never enters your context.";

fn deny_file(path: &str) -> Decision {
    Decision::Deny(format!(
        "Blocked by Verrou: {path} holds secrets and must not be read into your context. {ADVICE}"
    ))
}

// MARK: Paths

/// Suffixes of `.env.*` files that are templates, not secrets.
const ENV_TEMPLATES: [&str; 6] = ["example", "sample", "template", "dist", "tpl", "defaults"];

/// Is this a file that holds secrets? `~` and `$HOME` are expanded by the
/// agent or the shell before us in most cases; both are understood anyway.
pub fn is_secret_path(path: &str) -> bool {
    let path = path.trim().trim_matches(['"', '\'']);
    let path = path
        .strip_prefix("$HOME/")
        .or_else(|| path.strip_prefix("${HOME}/"))
        .or_else(|| path.strip_prefix("~/"))
        .unwrap_or(path);
    let components: Vec<&str> = path.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    let Some(name) = components.last().copied() else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let parent = components.len().checked_sub(2).map(|i| components[i]);

    // `.env`, `.env.production`, `production.env`, but not `.env.example`.
    if lower == ".env" || has_extension(&lower, "env") {
        return true;
    }
    if let Some(suffix) = lower.strip_prefix(".env.") {
        return !ENV_TEMPLATES.contains(&suffix);
    }
    // A glob for them (`.env*`, from a Grep tool).
    if lower.starts_with(".env") && lower.contains('*') {
        return true;
    }
    // Private keys and key stores.
    if ["pem", "p12", "pfx"]
        .iter()
        .any(|e| has_extension(&lower, e))
    {
        return true;
    }
    if lower.starts_with("id_") && !has_extension(&lower, "pub") {
        return true;
    }
    // Files that are credentials by their name.
    if matches!(lower.as_str(), ".netrc" | "_netrc" | ".git-credentials") {
        return true;
    }
    if lower == "credentials" && parent == Some(".aws") {
        return true;
    }
    // Everything in `~/.ssh` except what is public or harmless.
    if parent == Some(".ssh") {
        let harmless = has_extension(&lower, "pub")
            || lower.starts_with("known_hosts")
            || matches!(lower.as_str(), "config" | "authorized_keys");
        return !harmless;
    }
    // Token files: only if they hold one (the file is read here, by us).
    if matches!(lower.as_str(), ".npmrc" | ".pypirc") {
        return holds_token(path);
    }
    false
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(extension))
}

/// Does this `.npmrc` / `.pypirc` hold a token or a password? Unreadable or
/// missing: no, there is nothing to leak.
fn holds_token(path: &str) -> bool {
    let expanded = match path.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(rest)),
        None => Some(PathBuf::from(path)),
    };
    let Some(text) = expanded.and_then(|p| std::fs::read_to_string(p).ok()) else {
        return false;
    };
    text.lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .any(|l| {
            l.contains("authtoken")
                || l.contains("_auth")
                || l.contains("password")
                || l.contains("token")
        })
}

/// Is a variable name one that holds a secret (`GITHUB_TOKEN`, `DB_PASSWORD`,
/// `STRIPE_SECRET_KEY`, `API_KEY`)?
pub fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "CREDENTIAL",
        "PRIVATE_KEY",
    ]
    .iter()
    .any(|word| upper.contains(word))
        || upper.ends_with("_KEY")
        || upper.ends_with("APIKEY")
}

// MARK: Shell commands

/// A word of a shell command, with whether it was in single quotes (where
/// `$VAR` is just text).
#[derive(Debug)]
struct Word {
    text: String,
    literal: bool,
}

/// Cuts a command into simple commands and their words. Rough on purpose:
/// separators (`;`, `&`, `|`, newlines, parentheses, backticks, `$(`) end a
/// command; quotes group; `<` is a word of its own so that the file after it
/// is seen.
fn simple_commands(command: &str) -> Vec<Vec<Word>> {
    let mut commands: Vec<Vec<Word>> = Vec::new();
    let mut words: Vec<Word> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut literal = true;
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    let push =
        |words: &mut Vec<Word>, current: &mut String, started: &mut bool, literal: &mut bool| {
            if *started {
                words.push(Word {
                    text: std::mem::take(current),
                    literal: *literal,
                });
            }
            *started = false;
            *literal = true;
        };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
                if c == '"' {
                    literal = false;
                }
            }
            (None, '\\') => {
                started = true;
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, ' ' | '\t') => push(&mut words, &mut current, &mut started, &mut literal),
            (None, ';' | '&' | '|' | '\n' | '(' | ')' | '`') => {
                push(&mut words, &mut current, &mut started, &mut literal);
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
            }
            (None, '$') if chars.peek() == Some(&'(') => {
                push(&mut words, &mut current, &mut started, &mut literal);
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
                chars.next();
            }
            (None, '<') => {
                push(&mut words, &mut current, &mut started, &mut literal);
                words.push(Word {
                    text: "<".to_owned(),
                    literal: true,
                });
            }
            (None, '>') => {
                // Redirections out are not reads: the target is not a word to check.
                push(&mut words, &mut current, &mut started, &mut literal);
            }
            (None, c) => {
                started = true;
                if c == '$' {
                    literal = false;
                }
                current.push(c);
            }
        }
    }
    push(&mut words, &mut current, &mut started, &mut literal);
    if !words.is_empty() {
        commands.push(words);
    }
    commands
}

/// Programs that show what they are given: a secret file next to one of
/// them is a read.
const READERS: [&str; 44] = [
    "cat", "tac", "less", "more", "most", "head", "tail", "bat", "batcat", "nl", "xxd", "od",
    "hexdump", "strings", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "cut",
    "sort", "uniq", "base64", "source", ".", "cp", "scp", "rsync", "curl", "wget", "open", "vim",
    "vi", "nano", "emacs", "code", "jq", "yq", "diff", "tee",
];

/// Words that start a command without being the program.
const WRAPPERS: [&str; 15] = [
    "sudo", "command", "builtin", "exec", "nohup", "time", "nice", "xargs", "then", "do", "else",
    "!", "doas", "stdbuf", "ionice",
];

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The `$NAME` / `${NAME}` references in a word that are secret names.
fn secret_variables(word: &str) -> Option<String> {
    let mut rest = word;
    while let Some(at) = rest.find('$') {
        rest = &rest[at + 1..];
        let body = rest.strip_prefix('{').unwrap_or(rest);
        let name: String = body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && is_secret_name(&name) {
            return Some(name);
        }
    }
    None
}

/// Checks one command line.
pub fn check_shell(command: &str) -> Decision {
    for words in simple_commands(command) {
        if let Some(found) = check_simple(&words) {
            return found;
        }
    }
    Decision::Allow
}

fn check_simple(words: &[Word]) -> Option<Decision> {
    // Input redirected from a secret file, whatever reads it.
    if let Some(path) = words
        .windows(2)
        .find(|w| w[0].text == "<" && is_secret_path(&w[1].text))
        .map(|w| &w[1].text)
    {
        return Some(deny_file(path));
    }
    let mut args: Vec<&Word> = words.iter().filter(|w| w.text != "<").collect();
    // Leading assignments and wrappers.
    loop {
        match args.first() {
            Some(w) if is_assignment(&w.text) => {}
            Some(w) if WRAPPERS.contains(&basename(&w.text)) => {}
            Some(w) if basename(&w.text) == "env" => {
                // `env` alone prints the environment; `env A=1 cmd` runs cmd.
                let rest: Vec<&&Word> = args[1..]
                    .iter()
                    .filter(|w| !w.text.starts_with('-') && !is_assignment(&w.text))
                    .collect();
                if rest.is_empty() {
                    return Some(Decision::Deny(format!(
                        "Blocked by Verrou: printing the environment would put its secrets into your context. {ADVICE}"
                    )));
                }
            }
            _ => break,
        }
        args.remove(0);
    }
    let program = basename(&args.first()?.text).to_owned();
    let rest = &args[1..];
    match program.as_str() {
        "printenv" => {
            let names: Vec<&&Word> = rest.iter().filter(|w| !w.text.starts_with('-')).collect();
            if names.is_empty() || names.iter().any(|w| is_secret_name(&w.text)) {
                return Some(Decision::Deny(format!(
                    "Blocked by Verrou: printenv would show secrets from the environment. {ADVICE}"
                )));
            }
        }
        "export" | "declare" | "typeset" | "set" | "compgen" => {
            let flagged = rest
                .iter()
                .any(|w| ["-p", "-x", "-e"].contains(&w.text.as_str()));
            // `set`, `export` and `declare` alone list every variable.
            let prints = match program.as_str() {
                "set" => rest.is_empty(),
                "compgen" => flagged,
                _ => rest.is_empty() || flagged,
            };
            if prints {
                return Some(Decision::Deny(format!(
                    "Blocked by Verrou: listing the shell's variables would show secrets. {ADVICE}"
                )));
            }
        }
        "echo" | "printf" | "print" => {
            if let Some(name) = rest
                .iter()
                .filter(|w| !w.literal)
                .find_map(|w| secret_variables(&w.text))
            {
                return Some(Decision::Deny(format!(
                    "Blocked by Verrou: ${name} looks like a secret, and printing it would put it into your context. {ADVICE}"
                )));
            }
        }
        "verrou" => {
            // `verrou get --reveal` and `verrou totp` print a secret to the
            // terminal the agent reads. `verrou run` is the way.
            let sub = rest
                .iter()
                .find(|w| !w.text.starts_with('-'))
                .map(|w| w.text.as_str());
            let reveals = rest
                .iter()
                .any(|w| matches!(w.text.as_str(), "--reveal" | "-f" | "--field"));
            if sub == Some("totp") || (sub == Some("get") && reveals) {
                return Some(Decision::Deny(format!(
                    "Blocked by Verrou: this prints a secret into your context. {ADVICE}"
                )));
            }
        }
        reader if READERS.contains(&reader) => {
            if let Some(word) = rest.iter().find(|w| is_secret_path(&w.text)) {
                return Some(deny_file(&word.text));
            }
        }
        _ => {}
    }
    None
}

// MARK: Hook input and output

/// What the hook answers on stdout, and its exit code.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub stdout: String,
    pub exit: u8,
}

/// Decides from the agent's JSON, and words the answer in its format.
/// Anything unreadable is allowed: a hook that cannot read its input must
/// not wedge the agent.
pub fn run(agent: Agent, input: &str) -> Answer {
    let decision = decide(agent, input);
    answer(agent, input, &decision)
}

fn decide(agent: Agent, input: &str) -> Decision {
    let Ok(event) = serde_json::from_str::<Value>(input) else {
        return Decision::Allow;
    };
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    match agent {
        Agent::Claude | Agent::Codex => {
            let tool = text(&event, "tool_name").unwrap_or_default();
            let Some(input) = event.get("tool_input") else {
                return Decision::Allow;
            };
            match tool.as_str() {
                "Bash" => text(input, "command").map_or(Decision::Allow, |c| check_shell(&c)),
                // Codex offers no file-read event, so this is Claude's.
                "Read" if agent == Agent::Claude => text(input, "file_path")
                    .filter(|p| is_secret_path(p))
                    .map_or(Decision::Allow, |p| deny_file(&p)),
                "Grep" if agent == Agent::Claude => ["path", "glob"]
                    .iter()
                    .filter_map(|key| text(input, key))
                    .find(|p| is_secret_path(p))
                    .map_or(Decision::Allow, |p| deny_file(&p)),
                _ => Decision::Allow,
            }
        }
        Agent::Cursor => {
            if let Some(command) = text(&event, "command") {
                check_shell(&command)
            } else if let Some(path) = text(&event, "file_path") {
                if is_secret_path(&path) {
                    deny_file(&path)
                } else {
                    Decision::Allow
                }
            } else {
                Decision::Allow
            }
        }
    }
}

fn answer(agent: Agent, input: &str, decision: &Decision) -> Answer {
    match (agent, decision) {
        // No output, exit 0: the agent's normal permission flow applies.
        (Agent::Claude | Agent::Codex, Decision::Allow) => Answer {
            stdout: String::new(),
            exit: 0,
        },
        (Agent::Claude | Agent::Codex, Decision::Deny(reason)) => Answer {
            stdout: json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
            exit: 0,
        },
        // Cursor always needs a verdict it can parse.
        (Agent::Cursor, Decision::Allow) => Answer {
            stdout: json!({ "permission": "allow" }).to_string(),
            exit: 0,
        },
        (Agent::Cursor, Decision::Deny(reason)) => {
            let shell =
                serde_json::from_str::<Value>(input).is_ok_and(|e| e.get("command").is_some());
            let mut out = json!({ "permission": "deny", "user_message": reason });
            if shell {
                // Only the shell hook can speak to the agent.
                out["agent_message"] = Value::String(reason.clone());
            }
            Answer {
                stdout: out.to_string(),
                exit: 0,
            }
        }
    }
}

// MARK: Installation

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// For the current folder (`.claude/settings.json`…).
    Project,
    /// For the user (`~/.claude/settings.json`…).
    User,
}

/// The agent's configuration file.
pub fn config_path(agent: Agent, scope: Scope, home: &Path, project: &Path) -> PathBuf {
    let base = match scope {
        Scope::User => home,
        Scope::Project => project,
    };
    match agent {
        Agent::Claude => base.join(".claude/settings.json"),
        Agent::Codex => base.join(".codex/hooks.json"),
        Agent::Cursor => base.join(".cursor/hooks.json"),
    }
}

/// What `install` did.
#[derive(Debug, PartialEq, Eq)]
pub struct Installed {
    pub path: PathBuf,
    /// Hook events added (empty: already installed, nothing written).
    pub added: Vec<String>,
}

#[derive(Debug)]
pub struct InstallError(pub String);

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Adds the hook to the agent's configuration at `path`, keeping everything
/// else in it, and does nothing if it is already there. A file that is not
/// JSON is left alone and reported.
pub fn install(agent: Agent, path: &Path) -> Result<Installed, InstallError> {
    let fail =
        |what: &str, e: &dyn fmt::Display| InstallError(format!("{}: {what}: {e}", path.display()));
    let mut root = match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Value::Object(Map::new()),
        Ok(text) => serde_json::from_str::<Value>(&text)
            .map_err(|e| fail("not valid JSON, left untouched", &e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Object(Map::new()),
        Err(e) => return Err(fail("cannot read", &e)),
    };
    let Some(object) = root.as_object_mut() else {
        return Err(InstallError(format!(
            "{}: not a JSON object, left untouched",
            path.display()
        )));
    };
    let command = agent.command();
    let added = match agent {
        Agent::Claude => add_groups(object, &command, &[("PreToolUse", "Bash|Read|Grep")]),
        Agent::Codex => add_groups(object, &command, &[("PreToolUse", "Bash")]),
        Agent::Cursor => add_cursor(object, &command),
    }
    .map_err(|e| InstallError(format!("{}: {e}", path.display())))?;
    if added.is_empty() {
        return Ok(Installed {
            path: path.to_owned(),
            added,
        });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| fail("cannot create the folder", &e))?;
    }
    let mut text = serde_json::to_string_pretty(&root).map_err(|e| fail("cannot write", &e))?;
    text.push('\n');
    std::fs::write(path, text).map_err(|e| fail("cannot write", &e))?;
    Ok(Installed {
        path: path.to_owned(),
        added,
    })
}

/// The `hooks` object, created if missing.
fn hooks_of(root: &mut Map<String, Value>) -> Result<&mut Map<String, Value>, String> {
    root.entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "\"hooks\" is not an object, left untouched".to_owned())
}

/// The event's list, created if missing.
fn event_list<'a>(
    hooks: &'a mut Map<String, Value>,
    event: &str,
) -> Result<&'a mut Vec<Value>, String> {
    hooks
        .entry(event)
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| format!("\"{event}\" is not a list, left untouched"))
}

/// Claude Code and Codex: `hooks.<event>[{matcher, hooks[{type, command}]}]`.
fn add_groups(
    root: &mut Map<String, Value>,
    command: &str,
    events: &[(&str, &str)],
) -> Result<Vec<String>, String> {
    let hooks = hooks_of(root)?;
    let mut added = Vec::new();
    for (event, matcher) in events {
        let list = event_list(hooks, event)?;
        let present = list.iter().any(|group| {
            group
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|handlers| {
                    handlers
                        .iter()
                        .any(|h| h.get("command").and_then(Value::as_str) == Some(command))
                })
        });
        if !present {
            list.push(json!({
                "matcher": matcher,
                "hooks": [{ "type": "command", "command": command }],
            }));
            added.push(format!("{event} ({matcher})"));
        }
    }
    Ok(added)
}

/// Cursor: `{"version": 1, "hooks": {event: [{command}]}}`.
fn add_cursor(root: &mut Map<String, Value>, command: &str) -> Result<Vec<String>, String> {
    root.entry("version").or_insert_with(|| json!(1));
    let hooks = hooks_of(root)?;
    let mut added = Vec::new();
    for event in ["beforeShellExecution", "beforeReadFile"] {
        let list = event_list(hooks, event)?;
        let present = list
            .iter()
            .any(|h| h.get("command").and_then(Value::as_str) == Some(command));
        if !present {
            list.push(json!({ "command": command }));
            added.push(event.to_owned());
        }
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(command: &str) -> bool {
        check_shell(command).is_deny()
    }

    #[test]
    fn secret_files_are_recognised() {
        for path in [
            ".env",
            "/work/app/.env",
            ".env.local",
            ".env.production",
            "prod.env",
            "server.pem",
            "/etc/ssl/private/key.pem",
            "/home/me/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "id_ecdsa",
            "~/.ssh/some_deploy_key",
            "$HOME/.aws/credentials",
            "/home/me/.aws/credentials",
            ".netrc",
            ".env*",
            "store.p12",
        ] {
            assert!(is_secret_path(path), "{path} should be secret");
        }
        for path in [
            ".env.example",
            ".env.sample",
            ".env.template",
            "README.md",
            "src/environment.rs",
            "id_rsa.pub",
            "~/.ssh/id_ed25519.pub",
            "~/.ssh/known_hosts",
            "~/.ssh/config",
            "/home/me/.aws/config",
            "envelope.txt",
            "idea.txt",
            "",
        ] {
            assert!(!is_secret_path(path), "{path} should be fine");
        }
    }

    #[test]
    fn token_files_are_secret_only_with_a_token() {
        let dir = std::env::temp_dir().join(format!("vh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let with = dir.join("with/.npmrc");
        let without = dir.join("without/.npmrc");
        std::fs::create_dir_all(with.parent().unwrap()).unwrap();
        std::fs::create_dir_all(without.parent().unwrap()).unwrap();
        std::fs::write(&with, "//registry.npmjs.org/:_authToken=abc\n").unwrap();
        std::fs::write(
            &without,
            "registry=https://registry.npmjs.org/\n# token later\n",
        )
        .unwrap();
        assert!(is_secret_path(with.to_str().unwrap()));
        assert!(!is_secret_path(without.to_str().unwrap()));
        assert!(!is_secret_path(dir.join("absent/.npmrc").to_str().unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn secret_names() {
        for name in [
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "STRIPE_SECRET_KEY",
            "API_KEY",
            "aws_secret_access_key",
            "OPENAIAPIKEY",
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in ["PATH", "HOME", "KEYBOARD", "SHELL", "MONKEY_BUSINESS"] {
            assert!(!is_secret_name(name), "{name}");
        }
    }

    #[test]
    fn commands_that_read_secrets_are_blocked() {
        for command in [
            "cat .env",
            "cat ./config/.env.local",
            "less .env.production",
            "head -n 5 server.pem",
            "tail -f .env",
            "grep PASSWORD .env",
            "grep -r token ~/.aws/credentials",
            "cd app && cat .env",
            "sudo cat /home/me/.ssh/id_rsa",
            "cat 'my dir/.env'",
            "cat \"$HOME/.ssh/id_ed25519\"",
            "FOO=1 cat .env",
            "bat .env | head",
            "jq . .env.json.env",
            "while read l; do echo $l; done < .env",
            "echo $(<.env)",
            "xargs cat < .env",
            "source .env",
            ". .env",
            "base64 id_rsa",
            "printenv",
            "env",
            "env | sort",
            "printenv GITHUB_TOKEN",
            "echo $GITHUB_TOKEN",
            "echo \"token: ${STRIPE_SECRET_KEY}\"",
            "printf '%s' \"$DB_PASSWORD\"",
            "export -p",
            "set",
            "verrou get GitHub --reveal",
            "verrou get GitHub -f password",
            "verrou totp GitHub",
        ] {
            assert!(blocked(command), "{command} should be blocked");
        }
    }

    #[test]
    fn ordinary_commands_pass() {
        for command in [
            "cat README.md",
            "cat .env.example",
            "ls -la",
            "ls .env",
            "git status",
            "git add .env.example",
            "echo hello",
            "echo '$GITHUB_TOKEN'",
            "echo $HOME",
            "printenv HOME",
            "env FOO=bar make test",
            "env -i cargo build",
            "npm test && cargo build",
            "grep -rn TODO src",
            "cat package.json > out.txt",
            "verrou run -- gh repo list",
            "verrou run --env-file .env -- make deploy",
            "verrou get GitHub",
            "verrou search github",
            "export PATH=$PATH:/opt/bin",
            "cat id_rsa.pub",
            "echo done > .env.example",
        ] {
            assert!(!blocked(command), "{command} should pass");
        }
    }

    #[test]
    fn the_refusal_tells_the_agent_what_to_do() {
        let Decision::Deny(reason) = check_shell("cat .env") else {
            panic!("expected a refusal");
        };
        assert!(reason.contains(".env"));
        assert!(reason.contains("verrou_run"));
        assert!(reason.contains("verrou://"));
    }

    #[test]
    fn claude_input_and_output() {
        let deny = run(
            Agent::Claude,
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":"/x"}"#,
        );
        assert_eq!(deny.exit, 0);
        let out: Value = serde_json::from_str(&deny.stdout).unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            out["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("verrou_run")
        );
        // Allowed: nothing on stdout, the normal permission flow applies.
        let allow = run(
            Agent::Claude,
            r#"{"tool_name":"Bash","tool_input":{"command":"cat README.md"}}"#,
        );
        assert_eq!(
            allow,
            Answer {
                stdout: String::new(),
                exit: 0
            }
        );
        // Read and Grep.
        let read = run(
            Agent::Claude,
            r#"{"tool_name":"Read","tool_input":{"file_path":"/work/.env.local"}}"#,
        );
        assert!(read.stdout.contains("\"deny\""));
        let read = run(
            Agent::Claude,
            r#"{"tool_name":"Read","tool_input":{"file_path":"/work/src/main.rs"}}"#,
        );
        assert_eq!(read.stdout, "");
        let grep = run(
            Agent::Claude,
            r#"{"tool_name":"Grep","tool_input":{"pattern":"KEY","path":"/work","glob":".env*"}}"#,
        );
        assert!(grep.stdout.contains("\"deny\""));
        let grep = run(
            Agent::Claude,
            r#"{"tool_name":"Grep","tool_input":{"pattern":"TODO","path":"/work/src"}}"#,
        );
        assert_eq!(grep.stdout, "");
        // Other tools and garbage: allowed.
        let edit = run(
            Agent::Claude,
            r#"{"tool_name":"Edit","tool_input":{"file_path":".env"}}"#,
        );
        assert_eq!(edit.stdout, "");
        assert_eq!(run(Agent::Claude, "not json").stdout, "");
        assert_eq!(run(Agent::Claude, "{}").stdout, "");
    }

    #[test]
    fn codex_only_sees_shell_commands() {
        let deny = run(
            Agent::Codex,
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printenv"},"turn_id":"1"}"#,
        );
        let out: Value = serde_json::from_str(&deny.stdout).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        let read = run(
            Agent::Codex,
            r#"{"tool_name":"Read","tool_input":{"file_path":".env"}}"#,
        );
        assert_eq!(read.stdout, "");
    }

    #[test]
    fn cursor_input_and_output() {
        let deny = run(
            Agent::Cursor,
            r#"{"conversation_id":"c","workspace_roots":["/x"],"command":"cat .env","cwd":"/x"}"#,
        );
        let out: Value = serde_json::from_str(&deny.stdout).unwrap();
        assert_eq!(out["permission"], "deny");
        assert!(out["user_message"].as_str().unwrap().contains("verrou_run"));
        assert!(
            out["agent_message"]
                .as_str()
                .unwrap()
                .contains("verrou_run")
        );
        assert_eq!(deny.exit, 0);
        // A file read: no `agent_message` in that schema.
        let deny = run(
            Agent::Cursor,
            r#"{"file_path":"/x/.env","content":"A=1","attachments":[]}"#,
        );
        let out: Value = serde_json::from_str(&deny.stdout).unwrap();
        assert_eq!(out["permission"], "deny");
        assert!(out.get("agent_message").is_none());
        // Allowed: always an explicit verdict.
        for input in [
            r#"{"command":"ls","cwd":"/x"}"#,
            r#"{"file_path":"/x/main.rs","content":""}"#,
            "garbage",
        ] {
            let allow = run(Agent::Cursor, input);
            assert_eq!(allow.stdout, r#"{"permission":"allow"}"#);
            assert_eq!(allow.exit, 0);
        }
    }

    fn temp_home() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vi-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_paths() {
        let (home, project) = (Path::new("/h"), Path::new("/p"));
        assert_eq!(
            config_path(Agent::Claude, Scope::User, home, project),
            Path::new("/h/.claude/settings.json")
        );
        assert_eq!(
            config_path(Agent::Claude, Scope::Project, home, project),
            Path::new("/p/.claude/settings.json")
        );
        assert_eq!(
            config_path(Agent::Codex, Scope::User, home, project),
            Path::new("/h/.codex/hooks.json")
        );
        assert_eq!(
            config_path(Agent::Cursor, Scope::Project, home, project),
            Path::new("/p/.cursor/hooks.json")
        );
    }

    #[test]
    fn install_merges_without_clobbering_and_is_idempotent() {
        let home = temp_home();
        let path = config_path(Agent::Claude, Scope::User, &home, &home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"model":"opus","permissions":{"allow":["Bash(ls)"]},"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"./lint.sh"}]}],"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}"#,
        )
        .unwrap();
        let first = install(Agent::Claude, &path).unwrap();
        assert_eq!(first.added, ["PreToolUse (Bash|Read|Grep)"]);
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["model"], "opus");
        assert_eq!(written["permissions"]["allow"][0], "Bash(ls)");
        assert_eq!(
            written["hooks"]["Stop"][0]["hooks"][0]["command"],
            "say done"
        );
        let pre = written["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "./lint.sh");
        assert_eq!(pre[1]["matcher"], "Bash|Read|Grep");
        assert_eq!(pre[1]["hooks"][0]["type"], "command");
        assert_eq!(pre[1]["hooks"][0]["command"], "verrou hook claude");
        // Again: nothing added, file untouched.
        let before = std::fs::read_to_string(&path).unwrap();
        let second = install(Agent::Claude, &path).unwrap();
        assert_eq!(second.added, Vec::<String>::new());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn install_creates_missing_files_for_each_agent() {
        let home = temp_home();
        let codex = config_path(Agent::Codex, Scope::User, &home, &home);
        assert_eq!(
            install(Agent::Codex, &codex).unwrap().added,
            ["PreToolUse (Bash)"]
        );
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&codex).unwrap()).unwrap();
        assert_eq!(written["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        assert_eq!(
            written["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "verrou hook codex"
        );

        let cursor = config_path(Agent::Cursor, Scope::Project, &home, &home);
        std::fs::create_dir_all(cursor.parent().unwrap()).unwrap();
        std::fs::write(
            &cursor,
            r#"{"version":1,"hooks":{"afterFileEdit":[{"command":".cursor/hooks/format.sh"}],"beforeShellExecution":[{"command":"./audit.sh"}]}}"#,
        )
        .unwrap();
        let done = install(Agent::Cursor, &cursor).unwrap();
        assert_eq!(done.added, ["beforeShellExecution", "beforeReadFile"]);
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&cursor).unwrap()).unwrap();
        assert_eq!(written["version"], 1);
        assert_eq!(
            written["hooks"]["afterFileEdit"][0]["command"],
            ".cursor/hooks/format.sh"
        );
        assert_eq!(
            written["hooks"]["beforeShellExecution"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            written["hooks"]["beforeReadFile"][0]["command"],
            "verrou hook cursor"
        );
        assert_eq!(
            install(Agent::Cursor, &cursor).unwrap().added,
            Vec::<String>::new()
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn install_leaves_a_broken_file_alone() {
        let home = temp_home();
        let path = home.join("settings.json");
        std::fs::write(&path, "{ not json").unwrap();
        let error = install(Agent::Claude, &path).unwrap_err();
        assert!(error.to_string().contains("untouched"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        std::fs::write(&path, r#"{"hooks":{"PreToolUse":"oops"}}"#).unwrap();
        assert!(install(Agent::Claude, &path).is_err());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
