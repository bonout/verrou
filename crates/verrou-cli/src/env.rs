//! `verrou env mount`: a `.env` file whose secrets never touch the disk.
//!
//! The file is a FIFO (a named pipe): nothing is stored in it. Each time a
//! program opens it for reading, Verrou fills it with the current values,
//! after the usual approval (Touch ID, or the paired iPhone), and the
//! program reads them like any dotenv file. When it has read them they are
//! gone: the next open is a new request.
//!
//! What goes in is described by a **map**, a dotenv file whose values are
//! `verrou://<item>/<field>` references (`.env.verrou` by default; it holds
//! no secret and can be committed). It is read once, at the mount; a read
//! that finds it changed is refused, because what the user approved was the
//! map they mounted.
//!
//! What the approval is worth, said plainly:
//!
//! - the user sees **who opens the file**: the program and the chain of
//!   processes that started it (`cat ← zsh ← Terminal`), and the variables
//!   that are served. The readers are found from the kernel's list of who
//!   has the writer's own pipe open (by device and inode, not by a name), not
//!   from anything the program says about itself. This is advice to the
//!   person, never a reason to skip a question: the display is cut to fit,
//!   and what must not be cut (an agent among the ancestors, several readers,
//!   no reader found) always comes first;
//! - a read **never uses or creates** the five-minute approval of `verrou
//!   get` and `verrou run`: the bridge keys it apart ([`Reads::scope`]). **By
//!   default every read is approved on its own, every time.** With `--remember-reads`
//!   one reader that is a person's (single, not under an agent, with a
//!   terminal application such as Terminal, iTerm2 or sshd among its
//!   ancestors, and a controlling terminal) may have its own five minutes,
//!   for this file, this program, this terminal and this login shell (its
//!   process and when it started). Everything else (an agent above the reader,
//!   a mount an agent started, several readers, none that could be
//!   identified, no terminal application above it, no terminal) is approved on
//!   its own, every time, and never remembered. A code editor is not a
//!   terminal application: an agent can run inside it, and nothing tells it
//!   from a person;
//! - **whoever the approval is given to gets the values**: a program the
//!   user approves can read them and do what it likes. An agent can be
//!   missed (a renamed binary, a runtime Verrou does not look inside), and
//!   the link key of the terminal sits in `~/.config/verrou/cli.json`, which
//!   any process of the same user can read and use as the CLI: identification
//!   is best effort and the approval says what is asked, not who is asking.
//!   Verrou's hooks refuse an agent's read of a FIFO, and a program that
//!   merely walks the folder and opens files (an editor's indexer, a backup,
//!   `grep -r`) will raise an approval: refuse it.
//!
//! A read that is refused, or that cannot be served, gets one comment line,
//! `# verrou: not served (<reason>)`, never a value; after a refusal, the
//! next reads of the same kind (ephemeral, or a person's) get the same line
//! for [`REFUSAL_PAUSE`] without asking again.
//! A value is never logged and exists only in zeroized buffers, then in the
//! pipe.
//!
//! The mount refuses to replace a file, to follow a link, or to run on a
//! `.env` git would commit (tracked, or not ignored): those are the ways a
//! secret ends up in a repository.

pub mod command;
pub mod fifo;
pub mod proc;

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use verrou_bridge::protocol::RunDetail;
use zeroize::Zeroizing;

use crate::run::Reference;
use proc::Processes;

/// After a refusal, reads are answered without asking for this long: a
/// program that retries in a loop must not be able to make a prompt appear
/// every second.
pub const REFUSAL_PAUSE: Duration = Duration::from_secs(30);
/// Most reads served at once; the next one is told to try again.
pub const MAX_AT_ONCE: usize = 4;
/// How many ancestors of a reader are walked (loops are cut as well).
const MAX_CHAIN: usize = 64;
/// How many of them the approval shows, at most.
const MAX_SHOWN: usize = 12;
/// The longest program name shown, in characters.
const NAME_CAP: usize = 40;
/// Programs that are coding agents, by the name of the program or of a folder
/// it lives in (Claude Code's binary is `…/claude/versions/<number>`).
const AGENTS: [&str; 7] = [
    "claude",
    "codex",
    "cursor-agent",
    "gemini",
    "opencode",
    "aider",
    "goose",
];
/// Packages that are coding agents, found in the arguments of the runtime
/// that runs them (`node …/@anthropic-ai/claude-code/cli.js`).
const AGENT_PACKAGES: [(&str, &str); 8] = [
    ("claude-code", "claude-code"),
    ("gemini-cli", "gemini-cli"),
    ("@openai/codex", "codex"),
    ("codex-cli", "codex"),
    ("opencode-ai", "opencode"),
    ("@github/copilot", "copilot"),
    ("@sourcegraph/amp", "amp"),
    ("qwen-code", "qwen-code"),
];
/// Runtimes that host a program written in a script: their arguments say
/// which one.
const RUNTIMES: [&str; 5] = ["node", "nodejs", "bun", "deno", "python"];
/// Terminal applications: what a person's shell comes from. By the name of
/// the program or of the application it lives in. Never a code editor (VS
/// Code, Cursor…): an agent that runs inside one (an extension) cannot be
/// told from a person typing in its terminal.
const TERMINALS: &[&str] = &[
    "terminal.app",
    "iterm.app",
    "iterm2",
    "ghostty.app",
    "ghostty",
    "wezterm.app",
    "wezterm-gui",
    "alacritty.app",
    "alacritty",
    "kitty.app",
    "kitty",
    "sshd",
    "gnome-terminal-server",
    "konsole",
    "xterm",
    "xfce4-terminal",
    "tilix",
    "foot",
];

// MARK: The map and what is served

/// What a variable of the map is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Served as it is written in the map: not a secret.
    Plain(String),
    /// Read from the vault at each open.
    Secret(Reference),
}

/// The map of a mount: the variables to serve, in order, and a hash of the
/// file they came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub entries: Vec<(String, Value)>,
    pub hash: String,
}

/// The value of a `NAME=value` line as a dotenv loader reads it: inside
/// quotes up to the closing quote, whatever follows being a comment or
/// nothing; otherwise up to a `#` that starts the value or follows a space.
fn dotenv_value(raw: &str) -> String {
    let raw = raw.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = raw.strip_prefix(quote)
            && let Some(end) = inner.find(quote)
        {
            return inner[..end].to_owned();
        }
    }
    let mut end = raw.len();
    let mut previous_blank = true;
    for (at, c) in raw.char_indices() {
        if c == '#' && previous_blank {
            end = at;
            break;
        }
        previous_blank = c.is_whitespace();
    }
    raw[..end].trim_end().to_owned()
}

/// The `NAME=value` lines of a map: comments, blank lines and an `export `
/// prefix allowed; a value as [`dotenv_value`] reads it.
fn map_lines(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut vars = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected KEY=value", number + 1));
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "line {}: invalid variable name \"{key}\"",
                number + 1
            ));
        }
        vars.push((key.to_owned(), dotenv_value(value)));
    }
    Ok(vars)
}

impl Mapping {
    /// Reads a map: a dotenv file where a value `verrou://<item>/<field>` is
    /// a secret to fetch, and any other value is served as is (an inline `#
    /// comment` is not part of it). A name twice, or no reference at all
    /// (there would be nothing to protect), is an error.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries: Vec<(String, Value)> = Vec::new();
        for (name, value) in map_lines(text)? {
            if entries.iter().any(|(known, _)| *known == name) {
                return Err(format!("{name} is set twice"));
            }
            let value = match Reference::parse(&value) {
                Some(reference) => Value::Secret(reference.map_err(|e| format!("{name}: {e}"))?),
                None => Value::Plain(value),
            };
            entries.push((name, value));
        }
        if !entries.iter().any(|(_, v)| matches!(v, Value::Secret(_))) {
            return Err(
                "no verrou://<item>/<field> reference: there is nothing to serve".to_owned(),
            );
        }
        Ok(Self {
            entries,
            hash: hash_of(text.as_bytes()),
        })
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let bytes = read_map(path)?;
        let text = String::from_utf8(bytes).map_err(|_| format!("{}: not text", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The references, with the variable that gets each.
    pub fn references(&self) -> Vec<(String, Reference)> {
        self.entries
            .iter()
            .filter_map(|(name, value)| match value {
                Value::Secret(reference) => Some((name.clone(), reference.clone())),
                Value::Plain(_) => None,
            })
            .collect()
    }

    /// What the approval lists, in the map's order: `NAME=verrou://item/field`
    /// for a secret, `NAME=(plain)` for a variable served as written.
    pub fn fields(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(name, value)| match value {
                Value::Secret(reference) => format!("{name}={}", reference.to_uri()),
                Value::Plain(_) => format!("{name}=(plain)"),
            })
            .collect()
    }
}

fn hash_of(bytes: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bytes))
}

/// The longest map read.
const MAX_MAP: u64 = 1 << 20;

/// A map's bytes. The file is opened without following a link and without
/// waiting (a FIFO put in its place would otherwise hang the mount), and
/// must be a regular file.
pub fn read_map(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let error = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| error(&e))?;
    let meta = file.metadata().map_err(|e| error(&e))?;
    if !meta.is_file() {
        return Err(error(
            &"the map must be a regular file (not a link, a pipe or a folder)",
        ));
    }
    if meta.len() > MAX_MAP {
        return Err(error(&"the map is too big"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MAP)
        .read_to_end(&mut bytes)
        .map_err(|e| error(&e))?;
    Ok(bytes)
}

/// The hash of a map file as it is now.
pub fn map_hash(path: &Path) -> Result<String, String> {
    read_map(path).map(|bytes| hash_of(&bytes))
}

/// `bytes` random bytes, as hex: for names and tokens nobody should be able
/// to guess.
pub fn random_hex(bytes: usize) -> String {
    use std::io::Read as _;
    let mut buffer = vec![0_u8; bytes];
    let filled = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buffer));
    if filled.is_err() {
        // No random device: the clock, the process and an address, hashed.
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
                .to_le_bytes(),
        );
        hasher.update(std::process::id().to_le_bytes());
        hasher.update((&raw const buffer as usize).to_le_bytes());
        let digest = hasher.finalize();
        for (slot, byte) in buffer.iter_mut().zip(digest.iter().cycle()) {
            *slot = *byte;
        }
    }
    HEXLOWER.encode(&buffer)
}

/// Lets something happen at most once in a while: the application is opened
/// when it does not answer, but a program that reads the file in a loop must
/// not open it again at every read.
pub struct Throttle {
    every: Duration,
    last: Mutex<Option<Instant>>,
}

impl Throttle {
    pub fn new(every: Duration) -> Self {
        Self {
            every,
            last: Mutex::new(None),
        }
    }

    /// May it happen now? Says yes, and starts the wait, if the last time
    /// was long enough ago.
    pub fn allow(&self) -> bool {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_some_and(|at| at.elapsed() < self.every) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }
}

// MARK: Quoting

/// Appends a value as a dotenv file needs it, in the one form that every
/// loader Verrou documents (Node's `dotenv` and `--env-file`, Ruby's
/// `dotenv`, `godotenv`, Docker Compose) reads back the same:
///
/// - bare, when it is made of characters that none of them reads in a
///   special way;
/// - in single quotes, taken literally by all of them, when it holds no
///   single quote or line break and does not end with a backslash (Ruby
///   reads `\'` as an escaped quote);
/// - in double quotes with `\n` and `\r`, the only escapes all of them
///   unescape, when it holds a single quote or a line break (a PEM key)
///   and nothing that double quotes make special: a double quote, a
///   backslash (Node leaves `\\` and `\"` as they are), a dollar sign (Ruby
///   and Compose expand it) or a backtick.
///
/// A value that fits none of these is an error and the whole read is
/// refused: a quote that one loader reads differently is a wrong secret.
fn quote_into(out: &mut String, value: &str) -> Result<(), &'static str> {
    let bare = |c: char| c.is_ascii_alphanumeric() || "_-./:@%+,=".contains(c);
    if value.contains('\0') {
        return Err("holds a NUL byte, which a .env file cannot");
    }
    if value.is_empty() || value.chars().all(bare) {
        out.push_str(value);
    } else if !value.contains(['\'', '\n', '\r']) {
        if value.ends_with('\\') {
            return Err("ends with a backslash, which loaders read differently inside quotes");
        }
        out.push('\'');
        out.push_str(value);
        out.push('\'');
    } else if value.contains(['"', '\\', '$', '`']) {
        return Err(
            "needs double quotes (a single quote or a line break) and holds a double quote, backslash, dollar sign or backtick, which loaders read differently there",
        );
    } else {
        out.push('"');
        for c in value.chars() {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    Ok(())
}

const PAYLOAD_HEADER: &str =
    "# Served by Verrou for this read; nothing of it is stored in a file.\n";

/// Room for the whole payload, at the worst: a copy made by a buffer that
/// grew would leave values behind that nothing zeroizes.
pub fn payload_capacity(entries: &[(&str, &str)]) -> usize {
    PAYLOAD_HEADER.len()
        + entries
            .iter()
            .map(|(name, value)| name.len() + 1 + 2 * value.len() + 2 + 1)
            .sum::<usize>()
}

/// The file's content: a comment, then `NAME=value` for each variable. All
/// or nothing: a value that cannot be written (a NUL byte, which no loader
/// reads; a mix of characters no form carries safely, [`quote_into`])
/// refuses the whole read, not a half-filled file. The buffer is made at its
/// full size, so no earlier copy of the values is ever left behind.
pub fn format_payload(entries: &[(&str, &str)]) -> Result<Zeroizing<String>, String> {
    let mut out = Zeroizing::new(String::with_capacity(payload_capacity(entries)));
    out.push_str(PAYLOAD_HEADER);
    for (name, value) in entries {
        out.push_str(name);
        out.push('=');
        quote_into(&mut out, value).map_err(|reason| format!("{name} {reason}"))?;
        out.push('\n');
    }
    Ok(out)
}

/// What a refused read gets in place of the values: one line, with the
/// reason on one line and short.
pub fn refusal_line(reason: &str) -> String {
    let flat: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    let short: String = flat.chars().take(160).collect();
    format!("# verrou: not served ({short})\n")
}

// MARK: Git

/// What `git` answered to one question.
pub struct GitAnswer {
    pub code: Option<i32>,
    pub stdout: String,
}

/// Where the file stands for git.
#[derive(Debug, PartialEq, Eq)]
pub enum GitState {
    /// Ignored, by this rule (`.gitignore:3:.env`), in this repository.
    Ignored { root: PathBuf, rule: String },
    /// Not in a repository: nothing can commit it.
    NotARepository,
    /// `git` is not installed.
    Unavailable,
}

/// Is it safe for git that this file is there? A file git tracks, or does
/// not ignore, is one `git add -A` takes: refused, with the line to add.
/// `git` runs a command in a directory (injected: the tests give answers).
///
/// Whether the file is ignored is decided by the exit code of `check-ignore
/// -q` alone: `-v` also reports a rule that *un*-ignores it (`!.env`) with
/// the same exit code, so it is only asked for the rule to print.
pub fn git_check(
    file: &Path,
    git: &dyn Fn(&Path, &[&str]) -> io::Result<GitAnswer>,
) -> Result<GitState, String> {
    let dir = file.parent().ok_or("the file has no folder")?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file name is not text")?;
    let inside = match git(dir, &["rev-parse", "--show-toplevel"]) {
        Ok(answer) => answer,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(GitState::Unavailable),
        Err(e) => return Err(format!("git: {e}")),
    };
    if inside.code != Some(0) {
        return Ok(GitState::NotARepository);
    }
    let root = PathBuf::from(inside.stdout.trim());
    let ask = |args: &[&str]| git(dir, args).map_err(|e| format!("git: {e}"));
    if ask(&["ls-files", "--error-unmatch", "--", name])?.code == Some(0) {
        return Err(format!(
            "git tracks {name}: it would be committed with its secrets (`git rm --cached {name}`, then ignore it)"
        ));
    }
    match ask(&["check-ignore", "-q", "--", name])?.code {
        Some(0) => {
            let rule = ask(&["check-ignore", "-v", "--", name])?
                .stdout
                .lines()
                .next()
                .and_then(|line| line.split('\t').next())
                .unwrap_or_default()
                .to_owned();
            Ok(GitState::Ignored { root, rule })
        }
        Some(1) => Err(format!(
            "git does not ignore {name}: `git add -A` would take it. Add it to .gitignore first (`echo {name} >> .gitignore`)"
        )),
        _ => Err(format!("git could not say whether {name} is ignored")),
    }
}

/// `git <args>` in a folder, with what could change its answer removed:
/// the variables that point it elsewhere, and configuration passed in the
/// environment. The name given to `ls-files` is a name, not a pathspec
/// pattern (`check-ignore` takes paths, and refuses pathspec magic: a name
/// that has some is an error, which is a refusal). The user's own
/// configuration (`core.excludesFile`) stays: it is part of what git
/// ignores.
pub fn run_git(dir: &Path, args: &[&str]) -> io::Result<GitAnswer> {
    let mut command = std::process::Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_LITERAL_PATHSPECS");
    if args.first() == Some(&"ls-files") {
        command.env("GIT_LITERAL_PATHSPECS", "1");
    }
    let output = command
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()?;
    Ok(GitAnswer {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

// MARK: Who reads

/// A name that can be shown whatever the program is called: the characters
/// of `[A-Za-z0-9._+-]` as they are, anything else (control characters, a
/// right-to-left override, a space, a look-alike letter) as `?`, and at
/// most [`NAME_CAP`] of them, cut with `…`.
pub fn display_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .take(NAME_CAP)
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._+-".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect();
    if raw.chars().count() > NAME_CAP {
        name.push('…');
    }
    name
}

/// Is this program a coding agent? By its name, or by a folder of its path
/// (`~/.local/share/claude/versions/2.1.0`), or because it lives in
/// Cursor's application. Which one.
pub fn agent_of_exe(exe: &str) -> Option<String> {
    if exe.contains("Cursor") {
        return Some("Cursor".to_owned());
    }
    exe.to_ascii_lowercase().split('/').find_map(|part| {
        let part = part.strip_suffix(".exe").unwrap_or(part);
        AGENTS.contains(&part).then(|| part.to_owned())
    })
}

/// [`agent_of_exe`] as a yes or no.
pub fn is_agent_exe(exe: &str) -> bool {
    agent_of_exe(exe).is_some()
}

/// Which agent a runtime was given to run, from its command line: a package
/// that is one (`node …/@anthropic-ai/claude-code/cli.js`), or a program of
/// the paths on it.
pub fn agent_of_args(args: &str) -> Option<String> {
    let lower = args.to_ascii_lowercase();
    AGENT_PACKAGES
        .iter()
        .find(|(package, _)| lower.contains(package))
        .map(|(_, label)| (*label).to_owned())
        .or_else(|| args.split_whitespace().find_map(agent_of_exe))
}

/// Is this program one that hosts a script (and so tells nothing of what it
/// runs without its arguments)?
fn is_runtime(exe: &str) -> bool {
    let name = proc::basename(exe);
    RUNTIMES.iter().any(|r| {
        name == *r
            || name
                .strip_prefix(r)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// The terminal application a program is, by the name of the program or of
/// the application it lives in.
pub fn terminal_of_exe(exe: &str) -> Option<String> {
    exe.to_ascii_lowercase()
        .split('/')
        .find(|part| TERMINALS.contains(part))
        .map(|part| part.trim_end_matches(".app").to_owned())
}

/// A process that has the pipe open and where it comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reader {
    /// Every process that had the pipe open.
    pub pids: Vec<u32>,
    /// The first of them, then the process that started it, and so on
    /// (name, made showable, and identifier), as far as it could be followed.
    pub chain: Vec<(String, u32)>,
    /// What each reader is called.
    pub names: Vec<String>,
    /// A coding agent is among the ancestors of one of them: which.
    pub agent: Option<String>,
    /// A terminal application is among the first one's ancestors: which.
    pub terminal: Option<String>,
    /// The program of the first reader, as a path.
    pub exe: Option<String>,
    /// The terminal the first reader is attached to.
    pub tty: Option<String>,
    /// The first reader's login shell: the ancestor just below the terminal
    /// application (its identifier, and when it started). Another tab, or a
    /// shell started later with the same identifier, is another one.
    pub shell: Option<(u32, Option<u64>)>,
}

/// Who the readers are: each one's ancestry, walked to its end (at most
/// [`MAX_CHAIN`] levels, a loop cut), whether an agent is anywhere above any
/// of them (a JavaScript or Python runtime is asked for its arguments), and
/// which terminal application the first one comes from.
pub fn identify(readers: &[u32], procs: &dyn Processes) -> Reader {
    let mut found = Reader {
        pids: readers.to_vec(),
        chain: Vec::new(),
        names: Vec::new(),
        agent: None,
        terminal: None,
        exe: None,
        tty: None,
        shell: None,
    };
    for (index, first) in readers.iter().enumerate() {
        let mut pid = *first;
        let mut seen = vec![pid];
        for level in 0..MAX_CHAIN {
            let exe = procs.exe(pid);
            let agent = exe.as_deref().and_then(|exe| {
                agent_of_exe(exe).or_else(|| {
                    is_runtime(exe)
                        .then(|| procs.args(pid).and_then(|args| agent_of_args(&args)))
                        .flatten()
                })
            });
            if found.agent.is_none() {
                found.agent = agent;
            }
            let name = exe
                .as_deref()
                .map_or_else(|| "?".to_owned(), |e| display_name(proc::basename(e)));
            if index == 0 {
                if level == 0 {
                    found.exe.clone_from(&exe);
                    found.tty = procs.tty(pid);
                }
                if found.terminal.is_none() {
                    found.terminal = exe.as_deref().and_then(terminal_of_exe);
                    if found.terminal.is_some() {
                        // The one just below the application (the reader
                        // itself when it is that application's own child).
                        let below = found.chain.last().map_or(pid, |(_, below)| *below);
                        found.shell = Some((below, procs.start_time(below)));
                    }
                }
                found.chain.push((name.clone(), pid));
            }
            if level == 0 {
                found.names.push(name);
            }
            match procs.parent(pid) {
                Some(parent) if parent > 1 && !seen.contains(&parent) => {
                    seen.push(parent);
                    pid = parent;
                }
                _ => break,
            }
        }
    }
    found
}

impl Reader {
    /// One process, found.
    pub fn is_single(&self) -> bool {
        self.pids.len() == 1
    }

    /// A reader whose approval may be remembered (with `--remember-reads`):
    /// one process, whose ancestry (followed to its end) holds a known
    /// terminal application and no agent, attached to a terminal, with a
    /// login shell whose start is known. Anything else is approved on its
    /// own, every time.
    pub fn is_cacheable(&self) -> bool {
        self.is_single()
            && self.agent.is_none()
            && self.terminal.is_some()
            && self.tty.is_some()
            && self.shell.is_some_and(|(_, start)| start.is_some())
    }

    /// What the approval says of the reader, with `depth` ancestors at most.
    /// What must not be missed leads and is never cut: an agent among the
    /// ancestors, that no terminal application is above the reader, how many
    /// readers there are, or that none was found.
    /// `cat[4242] ← zsh ← login ← Terminal`.
    pub fn describe(&self, depth: usize) -> String {
        if self.pids.is_empty() {
            return "unidentified reader".to_owned();
        }
        let mut text = String::new();
        if let Some(agent) = &self.agent {
            let _ = write!(text, "agent ancestor: {}; ", display_name(agent));
        }
        if self.terminal.is_none() {
            text.push_str("no terminal; ");
        }
        if self.pids.len() > 1 {
            let shown: Vec<&str> = self.names.iter().take(4).map(String::as_str).collect();
            let _ = write!(
                text,
                "{} readers: {}{}",
                self.pids.len(),
                shown.join(", "),
                if self.names.len() > 4 { ", …" } else { "" }
            );
            return text;
        }
        for (index, (name, pid)) in self.chain.iter().take(depth + 1).enumerate() {
            if index == 0 {
                let _ = write!(text, "{name}[{pid}]");
            } else {
                let _ = write!(text, " ← {name}");
            }
        }
        if self.chain.len() > depth + 1 {
            text.push_str(" ← …");
        }
        text
    }
}

/// A path for the approval, shorter at each level: whole, then its last two
/// parts, then the name alone.
fn shorten(path: &Path, level: usize) -> String {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    match level {
        0 => path.display().to_string(),
        1 if parts.len() > 2 => format!("…/{}", parts[parts.len() - 2..].join("/")),
        _ => parts.last().cloned().unwrap_or_default(),
    }
}

/// What the approval shows: `read <file> by <reader>`, and the variables.
/// It is cut to fit, in this order: the file's path (to its last two parts,
/// then its name) and only then the reader's ancestry; the reader itself and
/// what must not be missed ([`Reader::describe`]) are never cut. If even that
/// does not fit, there is no read.
pub fn read_detail(file: &Path, reader: &Reader, fields: &[String]) -> Result<RunDetail, String> {
    let mut last = String::new();
    for depth in (0..=MAX_SHOWN).rev() {
        for level in 0..=2 {
            let detail = RunDetail {
                command: format!(
                    "read {} by {}",
                    shorten(file, level),
                    reader.describe(depth)
                ),
                fields: fields.to_owned(),
            };
            match detail.check() {
                Ok(()) => return Ok(detail),
                Err(reason) => reason.clone_into(&mut last),
            }
        }
    }
    Err(last)
}

// MARK: Reading values

/// What the bridge advertises (`capabilities` of its status) when it keeps
/// a remembered approval apart by [`ReadRequest::approval_scope`].
pub const SCOPE_CAPABILITY: &str = verrou_bridge::protocol::CAPABILITY_APPROVAL_SCOPE;

/// A read as the bridge can take it: a bridge that does not say it knows
/// the approval scope (an older one) would file a remembered read under the
/// item's ordinary approval, shared with `verrou get`: the read is then
/// asked on its own and never remembered.
pub fn for_bridge(
    ephemeral: bool,
    scope: Option<String>,
    capabilities: &[String],
) -> (bool, Option<String>) {
    if ephemeral || !capabilities.iter().any(|c| c == SCOPE_CAPABILITY) {
        (true, None)
    } else {
        (false, scope)
    }
}

/// What a read asks of the vault.
pub struct ReadRequest {
    /// In the order of the map.
    pub references: Vec<Reference>,
    /// Approved on its own, never remembered.
    pub ephemeral: bool,
    /// Keeps a remembered approval apart from `verrou get`'s ([`Reads::scope`]);
    /// only when the read is not ephemeral.
    pub approval_scope: Option<String>,
    pub detail: RunDetail,
}

/// Why values could not be had. `refusal`: the user (or Verrou) said no, or
/// the vault stayed locked: reads pause. Otherwise Verrou could not be
/// reached, or an item is gone: said, and asked again next time.
pub struct Failure {
    pub message: String,
    pub refusal: bool,
}

/// What the check of a map found.
#[derive(Debug, PartialEq, Eq)]
pub enum Checked {
    Verified,
    /// The vault is locked: nothing could be checked.
    VaultLocked,
}

/// Where values come from: Verrou, through the bridge (the binary gives it
/// that), or a stand-in in the tests. Each read uses a connection of its
/// own.
pub trait Values: Send + Sync {
    /// The values of `request.references`, in order; all of them or an
    /// error.
    fn fetch(&self, request: &ReadRequest) -> Result<Vec<Zeroizing<String>>, Failure>;

    /// Do these items and fields exist? An error lists what does not. No
    /// value is read and nothing is approved.
    fn check(&self, references: &[Reference]) -> Result<Checked, String>;
}

/// A mount as the serving needs it.
pub struct Mount {
    pub file: PathBuf,
    pub map: PathBuf,
    pub mapping: Mapping,
    /// `--remember-reads`: a person's read may be remembered (five minutes,
    /// its own scope). Off by default: every read is asked.
    pub remember_reads: bool,
    /// The mount was started by a coding agent: everything it serves is
    /// approved on its own.
    pub agent_driven: bool,
}

/// Answers the reads of one mount.
pub struct Reads {
    mount: Mount,
    values: Box<dyn Values>,
    procs: Box<dyn Processes>,
    /// Until when each kind of read is answered without asking, after a
    /// refusal: a person's (identified) reads, and the others.
    paused_until: Mutex<[Option<Instant>; 2]>,
}

impl Reads {
    pub fn new(mount: Mount, values: Box<dyn Values>, procs: Box<dyn Processes>) -> Self {
        Self {
            mount,
            values,
            procs,
            paused_until: Mutex::new([None, None]),
        }
    }

    pub fn mount(&self) -> &Mount {
        &self.mount
    }

    pub fn processes(&self) -> &dyn Processes {
        self.procs.as_ref()
    }

    /// Does this read need an approval of its own? Always, unless the mount
    /// was given `--remember-reads`, no agent started it, and the reader is
    /// one that can be remembered ([`Reader::is_cacheable`]).
    pub fn ephemeral(&self, reader: &Reader) -> bool {
        !self.mount.remember_reads || self.mount.agent_driven || !reader.is_cacheable()
    }

    /// The key of this read's five minutes at the bridge: the mounted file,
    /// the program that reads it, its terminal and its login shell (identifier
    /// and start). It is never `verrou get`'s approval, and another program,
    /// file, terminal or shell is another approval. It separates approvals,
    /// not clients: whoever holds the terminal's link key can present it.
    /// `None` for a read that is not remembered.
    pub fn scope(&self, reader: &Reader) -> Option<String> {
        if self.ephemeral(reader) {
            return None;
        }
        let (shell, start) = reader.shell?;
        Some(format!(
            "env:{}:{}:{}:{shell}:{}",
            self.mount.file.display(),
            reader.exe.as_deref().unwrap_or("?"),
            reader.tty.as_deref()?,
            start?,
        ))
    }

    fn pause_slot(ephemeral: bool) -> usize {
        usize::from(ephemeral)
    }

    /// The content for a read by these processes, or why there is none.
    /// `again` lists who has the pipe open now: asked a second time just
    /// before anything is written, and a different answer means nothing is.
    pub fn answer(
        &self,
        readers: &[u32],
        again: &dyn Fn() -> Vec<u32>,
    ) -> Result<Zeroizing<String>, String> {
        let reader = identify(readers, self.procs.as_ref());
        let ephemeral = self.ephemeral(&reader);
        let slot = Self::pause_slot(ephemeral);
        if let Some(until) = self
            .paused_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[slot]
        {
            let left = until.saturating_duration_since(Instant::now());
            if !left.is_zero() {
                return Err(format!(
                    "a read was refused a moment ago: try again in {} s",
                    left.as_secs() + 1
                ));
            }
        }
        // What the user approved is the map they mounted.
        let hash = map_hash(&self.mount.map)?;
        if hash != self.mount.mapping.hash {
            return Err("the map changed since the mount: unmount and mount again".to_owned());
        }
        let references = self.mount.mapping.references();
        let detail = read_detail(&self.mount.file, &reader, &self.mount.mapping.fields())?;
        let request = ReadRequest {
            references: references.iter().map(|(_, r)| r.clone()).collect(),
            ephemeral,
            approval_scope: self.scope(&reader),
            detail,
        };
        let fetched = self.values.fetch(&request).map_err(|failure| {
            if failure.refusal {
                self.paused_until
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)[slot] =
                    Some(Instant::now() + REFUSAL_PAUSE);
            }
            failure.message
        })?;
        let mut values = fetched.iter();
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for (name, value) in &self.mount.mapping.entries {
            match value {
                Value::Plain(text) => entries.push((name, text)),
                Value::Secret(_) => {
                    let secret = values.next().ok_or("Verrou gave fewer values than asked")?;
                    entries.push((name, secret));
                }
            }
        }
        let payload = format_payload(&entries)?;
        // Who was shown to the user is who gets the values.
        let mut now = again();
        let mut before = readers.to_vec();
        now.sort_unstable();
        before.sort_unstable();
        if now != before {
            return Err(
                "the programs that have the file open changed while Verrou was asked".to_owned(),
            );
        }
        Ok(payload)
    }

    /// What is written to the FIFO for this read: the values, or the line
    /// that says why not. The second is whether it was served.
    pub fn reply(
        &self,
        readers: &[u32],
        again: &dyn Fn() -> Vec<u32>,
    ) -> (Zeroizing<String>, Result<(), String>) {
        match self.answer(readers, again) {
            Ok(payload) => (payload, Ok(())),
            Err(reason) => (Zeroizing::new(refusal_line(&reason)), Err(reason)),
        }
    }
}

// MARK: Records

/// What `unmount` and `status` know of a mount, kept in `~/.verrou/env`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MountRecord {
    pub pid: u32,
    pub file: String,
    pub map: String,
    /// The git repository the file is in, if any.
    pub project_root: Option<String>,
    /// Unix time of the mount.
    pub started: u64,
    /// `--remember-reads`.
    #[serde(default)]
    pub remember_reads: bool,
    /// When the process started (the system's own unit): an identifier that
    /// was reused by another program is not this mount.
    #[serde(default)]
    pub process_start: Option<u64>,
    /// The identity (device, inode) of the FIFO that is at `file` and of the
    /// one about to take its place: a FIFO is only ever removed on the
    /// strength of this.
    #[serde(default)]
    pub fifos: Vec<(u64, u64)>,
}

/// Where the records are: `~/.verrou/env`.
pub fn records_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".verrou/env"))
}

/// A folder only this user can enter: made so if it is not there, and if
/// it is, checked (not a link, ours) and made so. Opened first, so that
/// what is checked and fixed is the folder and not a name that was swapped.
pub fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
    let error = |e: &dyn std::fmt::Display| format!("{}: {e}", dir.display());
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| error(&e))?;
        }
        Err(e) => return Err(error(&e)),
        Ok(_) => {}
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| error(&format!("not a folder of this user's, or a link ({e})")))?;
    let meta = opened.metadata().map_err(|e| error(&e))?;
    if meta.uid() != nix::unistd::getuid().as_raw() {
        return Err(error(&"belongs to another user"));
    }
    if meta.mode() & 0o077 != 0 {
        use std::os::unix::fs::PermissionsExt as _;
        opened
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|e| error(&e))?;
    }
    Ok(())
}

/// The record's name: the first 16 hex digits of the hash of the file's
/// absolute path.
pub fn record_id(file: &Path) -> String {
    hash_of(file.as_os_str().as_encoded_bytes())[..16].to_owned()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl MountRecord {
    pub fn path_for(dir: &Path, file: &Path) -> PathBuf {
        dir.join(format!("{}.json", record_id(file)))
    }

    /// The log of a mount that runs in the background, next to its record.
    pub fn log_for(dir: &Path, file: &Path) -> PathBuf {
        dir.join(format!("{}.log", record_id(file)))
    }

    /// Written atomically, readable by this user alone, in a folder that is
    /// theirs alone: the temporary file is new (`O_EXCL`), never a link
    /// followed, and its name is not one to guess.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let error = |e: io::Error| format!("{}: {e}", path.display());
        if let Some(dir) = path.parent() {
            private_dir(dir)?;
        }
        let temp = path.with_extension(format!("{}.tmp", random_hex(6)));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)
            .map_err(error)?;
        let written = file
            .write_all(&serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?)
            .and_then(|()| file.sync_all());
        drop(file);
        written
            .and_then(|()| std::fs::rename(&temp, path))
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&temp);
            })
            .map_err(error)
    }

    /// Every record of the folder, with its path; one that cannot be read is
    /// left out.
    pub fn load_all(dir: &Path) -> Vec<(PathBuf, Self)> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found: Vec<(PathBuf, Self)> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "json"))
            .filter_map(|path| {
                let record = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
                Some((path, record))
            })
            .collect();
        found.sort_by(|a, b| a.1.file.cmp(&b.1.file));
        found
    }

    /// Is the file at `file` (not followed) a FIFO this mount made?
    pub fn made(&self, file: &Path) -> bool {
        std::fs::symlink_metadata(file).is_ok_and(|m| {
            use std::os::unix::fs::FileTypeExt as _;
            m.file_type().is_fifo() && self.fifos.contains(&proc::identity_of(&m))
        })
    }
}

/// How a mount stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Running, and its file is a FIFO.
    Mounted,
    /// The process is gone: the FIFO, if any, serves nothing.
    Stale,
    /// Running, but its file is not a FIFO any more.
    Missing,
}

pub fn is_fifo(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_fifo())
}

pub fn state_of(record: &MountRecord, procs: &dyn Processes) -> State {
    if !proc::is_verrou(procs, record.pid, record.process_start) {
        State::Stale
    } else if is_fifo(Path::new(&record.file)) {
        State::Mounted
    } else {
        State::Missing
    }
}

/// What is left of a mount whose process is gone: its FIFO, if it is the
/// one the record says it made, and what a swap left beside it. A FIFO that
/// is not that is left alone, and said. Returns what was done, in words.
pub fn clean_up_stale(record: &MountRecord) -> Result<String, String> {
    let file = Path::new(&record.file);
    let mut said = String::new();
    if is_fifo(file) {
        if record.made(file) {
            std::fs::remove_file(file).map_err(|e| format!("{}: {e}", file.display()))?;
        } else {
            said = format!(
                " ({} is a FIFO this mount did not make: left alone)",
                file.display()
            );
        }
    }
    fifo::remove_leftovers(file, record.pid);
    Ok(said)
}

/// Stops a mount: the process is asked to end (it removes its FIFO and its
/// record), after checking that the identifier is still this very `verrou`
/// (the program, and when it started); a mount whose process is gone is
/// cleaned up here. What was done, in words.
pub fn unmount(path: &Path, record: &MountRecord, procs: &dyn Processes) -> Result<String, String> {
    use nix::sys::signal::{Signal, kill};
    if state_of(record, procs) == State::Stale {
        let said = clean_up_stale(record)?;
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("log"));
        return Ok(format!(
            "{}: the mount had stopped; cleaned up{said}",
            record.file
        ));
    }
    let pid = i32::try_from(record.pid).map_err(|_| "invalid process identifier".to_owned())?;
    kill(nix::unistd::Pid::from_raw(pid), Signal::SIGTERM).map_err(|e| {
        format!(
            "{}: could not stop process {}: {e}",
            record.file, record.pid
        )
    })?;
    // The process removes its record last.
    for _ in 0..100 {
        if !path.exists() {
            return Ok(format!("{}: unmounted", record.file));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "{}: process {} did not stop within 5 seconds",
        record.file, record.pid
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mapping(text: &str) -> Mapping {
        Mapping::parse(text).unwrap()
    }

    #[test]
    fn a_map_has_references_and_plain_values() {
        let map = mapping(
            "# map\nDB_URL=verrou://Database/url\nexport PORT=8080\nTOKEN=\"verrou://GitHub/API%20token\"\n",
        );
        assert_eq!(map.entries.len(), 3);
        assert_eq!(
            map.entries[1],
            ("PORT".to_owned(), Value::Plain("8080".to_owned()))
        );
        // The approval lists every variable served, in the map's order: a
        // plain one by name, so that nothing is served unseen.
        assert_eq!(
            map.fields(),
            [
                "DB_URL=verrou://Database/url",
                "PORT=(plain)",
                "TOKEN=verrou://GitHub/API%20token"
            ]
        );
        assert_eq!(map.references().len(), 2);
        // The hash follows the text.
        assert_ne!(map.hash, mapping("A=verrou://X/y\n").hash);
        assert_eq!(
            mapping("A=verrou://X/y\n").hash,
            mapping("A=verrou://X/y\n").hash
        );
    }

    #[test]
    fn a_bad_map_is_refused_with_its_reason() {
        assert!(
            Mapping::parse("A=verrou://X/y\nA=verrou://X/z\n")
                .unwrap_err()
                .contains("twice")
        );
        assert!(
            Mapping::parse("A=1\n")
                .unwrap_err()
                .contains("nothing to serve")
        );
        assert!(Mapping::parse("").is_err());
        assert!(
            Mapping::parse("A=verrou://nofield\n")
                .unwrap_err()
                .starts_with("A:")
        );
        assert!(
            Mapping::parse("A verrou://x/y\n")
                .unwrap_err()
                .contains("line 1")
        );
    }

    #[test]
    fn an_inline_comment_is_not_part_of_a_plain_value() {
        let plain = |line: &str| match mapping(&format!("S=verrou://X/y\n{line}\n")).entries[1]
            .1
            .clone()
        {
            Value::Plain(text) => text,
            Value::Secret(_) => panic!("{line} is a secret"),
        };
        assert_eq!(plain("PORT=8080 # the port"), "8080");
        assert_eq!(plain("PORT=8080\t# tab"), "8080");
        assert_eq!(plain("PORT=8080 #"), "8080");
        // A `#` with no space before it is part of the value, as in dotenv.
        assert_eq!(plain("COLOR=a#b"), "a#b");
        assert_eq!(plain("URL=http://x/#frag"), "http://x/#frag");
        // Inside quotes it is a character; after the quotes it is a comment.
        assert_eq!(plain("NAME=\"a # b\""), "a # b");
        assert_eq!(plain("NAME='a # b' # why"), "a # b");
        // Nothing but a comment is an empty value.
        assert_eq!(plain("EMPTY= # nothing"), "");
        assert_eq!(plain("EMPTY=#x"), "");
        // A reference followed by a comment is still a reference.
        let map = mapping("A=verrou://X/y # the key\nB=\"verrou://X/z\" # quoted\n");
        assert_eq!(map.references().len(), 2);
        assert_eq!(map.fields(), ["A=verrou://X/y", "B=verrou://X/z"]);
    }

    #[test]
    fn values_are_quoted_so_that_loaders_read_them_back() {
        let line = |value: &str| {
            let mut out = String::new();
            quote_into(&mut out, value).map(|()| out)
        };
        // Bare when nothing can be misread (base64 included, with its `=`).
        assert_eq!(line("abc-123_X.y/z:@%+,=").unwrap(), "abc-123_X.y/z:@%+,=");
        assert_eq!(line("c2VjcmV0cw==").unwrap(), "c2VjcmV0cw==");
        assert_eq!(line("a=b").unwrap(), "a=b");
        assert_eq!(line("").unwrap(), "");
        // Per character: a space, `#`, `$`, a backslash in the middle, a
        // double quote, a backtick: single quotes, taken as they are.
        assert_eq!(line("two words").unwrap(), "'two words'");
        assert_eq!(line("a#b").unwrap(), "'a#b'");
        assert_eq!(line("a #b").unwrap(), "'a #b'");
        assert_eq!(line("$HOME").unwrap(), "'$HOME'");
        assert_eq!(line("C:\\path").unwrap(), "'C:\\path'");
        assert_eq!(line("say \"hi\"").unwrap(), "'say \"hi\"'");
        assert_eq!(line("a`b`").unwrap(), "'a`b`'");
        assert_eq!(line("a=b c").unwrap(), "'a=b c'");
        // A single quote or a line break: double quotes, with `\n` and `\r`.
        assert_eq!(line("it's").unwrap(), "\"it's\"");
        assert_eq!(line("a\nb\rc").unwrap(), "\"a\\nb\\rc\"");
        assert_eq!(
            line("-----BEGIN KEY-----\nMIIE+/=\n-----END KEY-----\n").unwrap(),
            "\"-----BEGIN KEY-----\\nMIIE+/=\\n-----END KEY-----\\n\""
        );
        // What double quotes would make loaders disagree on is refused: a
        // double quote, a backslash, `$` or a backtick next to a quote or
        // a line break.
        for value in [
            "it's \"x\"",
            "it's \\ x",
            "line\nbreak $HOME",
            "line\nbreak `id`",
            "line\nbreak \"q\"",
            "a\\\nb",
        ] {
            assert!(line(value).is_err(), "{value:?}");
        }
        // A trailing backslash would meet the closing quote (Ruby reads `\'`).
        assert!(line("path\\").unwrap_err().contains("backslash"));
        assert!(line("\\").is_err());
        // NUL, always.
        assert!(line("a\0b").unwrap_err().contains("NUL"));
        // And what is not refused is never changed by the quoting: the value
        // comes back from the form it was put in.
        for value in [
            "plain",
            "two words",
            "it's",
            "a\nb",
            "x=y",
            "q\"q",
            "$x",
            "a#b",
        ] {
            let text = line(value).unwrap();
            let back = if let Some(inner) = text.strip_prefix('\'') {
                inner.strip_suffix('\'').unwrap().to_owned()
            } else if let Some(inner) = text.strip_prefix('"') {
                inner
                    .strip_suffix('"')
                    .unwrap()
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
            } else {
                text
            };
            assert_eq!(back, value);
        }
    }

    #[test]
    fn the_payload_is_all_or_nothing() {
        let payload = format_payload(&[("A", "one"), ("B", "two words")]).unwrap();
        assert_eq!(
            payload.as_str(),
            "# Served by Verrou for this read; nothing of it is stored in a file.\nA=one\nB='two words'\n"
        );
        let error = format_payload(&[("A", "fine"), ("B", "bad\0value")]).unwrap_err();
        assert!(error.contains('B') && !error.contains("bad"), "{error}");
        // A value no form carries safely refuses the read, without being said.
        let error = format_payload(&[("A", "fine"), ("B", "it's \"secret\"")]).unwrap_err();
        assert!(error.starts_with("B "), "{error}");
        assert!(!error.contains("secret"), "{error}");
    }

    #[test]
    fn the_payload_is_made_at_its_full_size_and_never_copied() {
        let long = "x y\n".repeat(500);
        for entries in [
            vec![("A", "short")],
            vec![("A", "two words"), ("B", "it's"), ("KEY", long.as_str())],
            vec![("A", "\n\n\n\r\r\r"), ("B", "")],
        ] {
            let capacity = payload_capacity(&entries);
            let payload = format_payload(&entries).unwrap();
            assert_eq!(payload.capacity(), capacity, "the buffer grew");
            assert!(payload.len() <= capacity);
        }
    }

    #[test]
    fn a_refusal_is_one_comment_line() {
        assert_eq!(
            refusal_line("refused in Verrou"),
            "# verrou: not served (refused in Verrou)\n"
        );
        let line = refusal_line("two\nlines\tand\r\n  spaces");
        assert_eq!(line, "# verrou: not served (two lines and spaces)\n");
        assert_eq!(refusal_line(&"x".repeat(500)).lines().count(), 1);
        assert!(refusal_line(&"x".repeat(500)).len() < 200);
    }

    type Answers = HashMap<&'static str, (i32, &'static str)>;

    fn git_with(answers: Answers) -> impl Fn(&Path, &[&str]) -> io::Result<GitAnswer> {
        move |_, args| {
            let (code, stdout) = answers
                .iter()
                .find(|(prefix, _)| args.join(" ").starts_with(**prefix))
                .map_or((128, ""), |(_, answer)| *answer);
            Ok(GitAnswer {
                code: Some(code),
                stdout: stdout.to_owned(),
            })
        }
    }

    #[test]
    fn git_must_ignore_the_file() {
        let file = Path::new("/work/app/.env");
        let ignored = git_with(Answers::from([
            ("rev-parse", (0, "/work/app\n")),
            ("ls-files", (1, "")),
            ("check-ignore -q", (0, "")),
            ("check-ignore -v", (0, ".gitignore:3:.env\t.env\n")),
        ]));
        assert_eq!(
            git_check(file, &ignored).unwrap(),
            GitState::Ignored {
                root: PathBuf::from("/work/app"),
                rule: ".gitignore:3:.env".to_owned()
            }
        );
        let tracked = git_with(Answers::from([
            ("rev-parse", (0, "/work/app\n")),
            ("ls-files", (0, ".env\n")),
        ]));
        let error = git_check(file, &tracked).unwrap_err();
        assert!(
            error.contains("tracks .env") && error.contains("rm --cached"),
            "{error}"
        );
        let not_ignored = git_with(Answers::from([
            ("rev-parse", (0, "/work/app\n")),
            ("ls-files", (1, "")),
            ("check-ignore -q", (1, "")),
        ]));
        let error = git_check(file, &not_ignored).unwrap_err();
        assert!(
            error.contains("does not ignore .env") && error.contains(">> .gitignore"),
            "{error}"
        );
        let broken = git_with(Answers::from([
            ("rev-parse", (0, "/work/app\n")),
            ("ls-files", (1, "")),
            ("check-ignore -q", (128, "")),
        ]));
        assert!(git_check(file, &broken).is_err());
    }

    #[test]
    fn ignored_is_decided_by_the_exit_code_of_the_quiet_question() {
        // `check-ignore -v` answers 0 and prints a rule for a file that a
        // `!.env` line un-ignores: only `-q` says whether it is ignored.
        let asked = Mutex::new(Vec::<String>::new());
        let git = |_: &Path, args: &[&str]| {
            asked.lock().unwrap().push(args.join(" "));
            let (code, stdout) = match args {
                ["rev-parse", ..] => (0, "/work/app\n"),
                ["ls-files", ..] | ["check-ignore", "-q", ..] => (1, ""),
                ["check-ignore", "-v", ..] => (0, ".gitignore:2:!.env\t.env\n"),
                _ => (128, ""),
            };
            Ok(GitAnswer {
                code: Some(code),
                stdout: stdout.to_owned(),
            })
        };
        let error = git_check(Path::new("/work/app/.env"), &git).unwrap_err();
        assert!(error.contains("does not ignore .env"), "{error}");
        let asked = asked.lock().unwrap();
        assert!(
            asked.contains(&"check-ignore -q -- .env".to_owned()),
            "{asked:?}"
        );
        assert!(!asked.iter().any(|q| q.contains("-v")), "{asked:?}");
    }

    #[test]
    fn outside_a_repository_or_without_git_the_mount_is_allowed() {
        let file = Path::new("/tmp/x/.env");
        let outside = git_with(Answers::from([("rev-parse", (128, ""))]));
        assert_eq!(git_check(file, &outside).unwrap(), GitState::NotARepository);
        let no_git = |_: &Path, _: &[&str]| Err(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(git_check(file, &no_git).unwrap(), GitState::Unavailable);
    }

    /// A process tree: pid → (parent, program), and the arguments of some.
    struct Tree {
        procs: HashMap<u32, (u32, &'static str)>,
        args: HashMap<u32, &'static str>,
        /// No process has a controlling terminal.
        ttyless: bool,
    }

    impl Processes for Tree {
        fn holders(&self, _: proc::Identity) -> Vec<u32> {
            Vec::new()
        }
        fn parent(&self, pid: u32) -> Option<u32> {
            self.procs.get(&pid).map(|(parent, _)| *parent)
        }
        fn exe(&self, pid: u32) -> Option<String> {
            self.procs.get(&pid).map(|(_, exe)| (*exe).to_owned())
        }
        fn args(&self, pid: u32) -> Option<String> {
            self.args.get(&pid).map(|a| (*a).to_owned())
        }
        fn tty(&self, pid: u32) -> Option<String> {
            (self.procs.contains_key(&pid) && !self.ttyless).then(|| "7".to_owned())
        }
        fn start_time(&self, pid: u32) -> Option<u64> {
            self.procs.contains_key(&pid).then(|| u64::from(pid) * 10)
        }
    }

    fn tree(entries: &[(u32, u32, &'static str)]) -> Tree {
        Tree {
            procs: entries
                .iter()
                .map(|(pid, parent, exe)| (*pid, (*parent, *exe)))
                .collect(),
            args: HashMap::new(),
            ttyless: false,
        }
    }

    const TERMINAL: &str = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal";

    #[test]
    fn agents_are_known_by_program_or_folder() {
        for exe in [
            "/usr/local/bin/claude",
            "/Users/me/.local/share/claude/versions/2.1.0",
            "/opt/homebrew/bin/codex",
            "/usr/bin/cursor-agent",
            "/usr/local/bin/gemini",
            "/usr/local/bin/opencode",
            "/usr/bin/aider",
            "/usr/bin/goose",
            "/Applications/Cursor.app/Contents/MacOS/Cursor",
            "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper",
        ] {
            assert!(is_agent_exe(exe), "{exe}");
        }
        for exe in [
            "/bin/cat",
            "/bin/zsh",
            "/usr/bin/node",
            TERMINAL,
            "/usr/bin/claudette",
            "/Users/me/bin/my-gooseberry",
        ] {
            assert!(!is_agent_exe(exe), "{exe}");
        }
        assert_eq!(
            agent_of_exe("/Users/me/.local/share/claude/versions/2.1.0").as_deref(),
            Some("claude")
        );
    }

    #[test]
    fn an_agent_hosted_by_node_is_found_in_its_arguments() {
        for args in [
            "node /Users/me/.nvm/versions/node/v22/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            "node /usr/local/lib/node_modules/@google/gemini-cli/dist/index.js --yolo",
            "node /opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js",
            "/usr/local/bin/node /usr/local/lib/node_modules/opencode-ai/bin/opencode",
            "python3 /usr/local/bin/aider --model x",
        ] {
            assert!(agent_of_args(args).is_some(), "{args}");
        }
        for args in [
            "node server.js",
            "node /Users/me/app/node_modules/.bin/next dev",
            "python3 manage.py runserver",
        ] {
            assert_eq!(agent_of_args(args), None, "{args}");
        }
        assert!(is_runtime("/usr/local/bin/node"));
        assert!(is_runtime("/usr/bin/python3.12"));
        assert!(is_runtime("/opt/bun"));
        assert!(!is_runtime("/bin/zsh"));
        assert!(!is_runtime("/usr/bin/bundle"));

        // Above a reader, through the whole chain: `cat ← zsh ← node(claude-code) ← zsh ← Terminal`.
        let mut procs = tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 200, "/usr/local/bin/node"),
            (200, 100, "/bin/zsh"),
            (100, 1, TERMINAL),
        ]);
        procs.args.insert(
            300,
            "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        );
        let reader = identify(&[500], &procs);
        assert_eq!(reader.agent.as_deref(), Some("claude-code"));
        assert!(
            !reader.is_cacheable(),
            "an agent's reader is not a person's"
        );
        // A node that runs something else is not an agent.
        procs.args.insert(300, "node build.js");
        assert_eq!(identify(&[500], &procs).agent, None);
        assert!(identify(&[500], &procs).is_cacheable());
    }

    #[test]
    fn a_person_is_a_single_reader_under_a_terminal_application() {
        let person = tree(&[
            (500, 400, "/bin/cat"),
            (400, 350, "/bin/zsh"),
            (350, 300, "/usr/bin/login"),
            (300, 1, TERMINAL),
        ]);
        let reader = identify(&[500], &person);
        assert!(reader.is_cacheable());
        assert_eq!(reader.terminal.as_deref(), Some("terminal"));
        assert_eq!(reader.exe.as_deref(), Some("/bin/cat"));
        assert_eq!(reader.tty.as_deref(), Some("7"));
        assert_eq!(reader.describe(12), "cat[500] ← zsh ← login ← Terminal");
        assert_eq!(reader.describe(1), "cat[500] ← zsh ← …");
        assert_eq!(reader.describe(0), "cat[500] ← …");

        // Other terminals and sshd count; launchd alone does not.
        for exe in [
            "/Applications/iTerm.app/Contents/MacOS/iTerm2",
            "/Applications/Ghostty.app/Contents/MacOS/ghostty",
            "/Applications/WezTerm.app/Contents/MacOS/wezterm-gui",
            "/Applications/Alacritty.app/Contents/MacOS/alacritty",
            "/Applications/kitty.app/Contents/MacOS/kitty",
            "/usr/sbin/sshd",
        ] {
            let procs = tree(&[
                (500, 400, "/bin/cat"),
                (400, 300, "/bin/zsh"),
                (300, 1, exe),
            ]);
            assert!(identify(&[500], &procs).is_cacheable(), "{exe}");
        }
        // Ending at launchd without one is not a person's terminal: a daemon,
        // a `tmux` server, a detached job.
        let daemon = tree(&[(500, 400, "/bin/cat"), (400, 1, "/bin/zsh")]);
        let reader = identify(&[500], &daemon);
        assert!(!reader.is_cacheable());
        assert_eq!(reader.terminal, None);
        // A reader that cannot be followed, or none, is not identified.
        assert!(!identify(&[999], &tree(&[])).is_cacheable());
        assert!(!identify(&[], &person).is_cacheable());
        // Two processes are not one person.
        assert!(!identify(&[500, 501], &person).is_cacheable());
    }

    #[test]
    fn an_editor_is_not_a_terminal_and_a_missing_terminal_leads_the_description() {
        // VS Code's (or Cursor's) integrated terminal: an agent that runs in
        // the editor cannot be told from a person typing there.
        for exe in [
            "/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
            "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
            "/usr/share/code/code",
        ] {
            assert_eq!(terminal_of_exe(exe), None, "{exe}");
            let procs = tree(&[
                (500, 400, "/bin/cat"),
                (400, 300, "/bin/zsh"),
                (300, 1, exe),
            ]);
            let reader = identify(&[500], &procs);
            assert!(!reader.is_cacheable(), "{exe}");
            assert_eq!(
                reader.describe(12),
                format!(
                    "no terminal; cat[500] ← zsh ← {}",
                    display_name(proc::basename(exe))
                ),
            );
        }
        // The marker leads, and survives every cut of the approval.
        let procs = tree(&[(500, 400, "/bin/cat"), (400, 1, "/bin/zsh")]);
        let reader = identify(&[500], &procs);
        let fields = vec!["A=verrou://X/y".to_owned()];
        for path in [
            PathBuf::from("/work/.env"),
            PathBuf::from(format!("/{}/.env", "d".repeat(180))),
            PathBuf::from(format!("/a/{}", "n".repeat(140))),
        ] {
            let detail = read_detail(&path, &reader, &fields).unwrap();
            assert!(
                detail.command.contains(" by no terminal; cat[500]"),
                "{}",
                detail.command
            );
        }
        // Under a terminal application there is no such marker.
        assert!(
            !identify(&[500], &person())
                .describe(12)
                .contains("no terminal")
        );
    }

    struct NoStart(Tree);
    impl Processes for NoStart {
        fn holders(&self, f: proc::Identity) -> Vec<u32> {
            self.0.holders(f)
        }
        fn parent(&self, p: u32) -> Option<u32> {
            self.0.parent(p)
        }
        fn exe(&self, p: u32) -> Option<String> {
            self.0.exe(p)
        }
        fn args(&self, p: u32) -> Option<String> {
            self.0.args(p)
        }
        fn tty(&self, p: u32) -> Option<String> {
            self.0.tty(p)
        }
        fn start_time(&self, _: u32) -> Option<u64> {
            None
        }
    }

    #[test]
    fn a_read_is_remembered_only_for_a_person_with_a_tty_and_a_known_shell() {
        // A terminal application above, but no controlling terminal: never.
        let mut no_tty = person();
        no_tty.ttyless = true;
        let reader = identify(&[500], &no_tty);
        assert!(reader.terminal.is_some() && reader.tty.is_none());
        assert!(!reader.is_cacheable());
        let s = setup(true, false, no_tty);
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_ok());
        let asked = s.fake.asked.lock().unwrap();
        assert!(asked[0].0 && asked[0].1.is_none(), "asked on its own");
        drop(asked);
        std::fs::remove_dir_all(&s.dir).ok();
        // A shell whose start is unknown cannot be told from a later one.
        assert!(!identify(&[500], &NoStart(person())).is_cacheable());
    }

    #[test]
    fn reads_are_asked_every_time_unless_remembering_was_asked_for() {
        // Default: a person's read is asked on its own, with no scope.
        let s = setup(false, false, person());
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_ok());
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_ok());
        let asked = s.fake.asked.lock().unwrap();
        assert_eq!(asked.len(), 2);
        assert!(asked.iter().all(|a| a.0 && a.1.is_none()));
        drop(asked);
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn the_scope_binds_the_login_shell_and_when_it_started() {
        let s = setup(true, false, person());
        let reader = identify(&[500], s.reads.processes());
        // `cat ← zsh ← Terminal`: the shell is the process just below the
        // application, here `zsh` (400), started at 4000.
        assert_eq!(reader.shell, Some((400, Some(4000))));
        let scope = s.reads.scope(&reader).unwrap();
        assert!(scope.ends_with(":/bin/cat:7:400:4000"), "{scope}");
        // The same shell, started again with the same identifier (a later
        // start time), is another key.
        let mut later = reader.clone();
        later.shell = Some((400, Some(4001)));
        assert_ne!(s.reads.scope(&later), Some(scope.clone()));
        // Another tab (another shell under the application) is another key.
        let other = tree(&[
            (500, 410, "/bin/cat"),
            (410, 310, "/bin/zsh"),
            (310, 1, TERMINAL),
        ]);
        let other = identify(&[500], &other);
        assert_ne!(s.reads.scope(&other), Some(scope));
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_bridge_that_does_not_know_the_scope_gets_every_read_asked() {
        let scope = Some("env:/x/.env:/bin/cat:7:300:3000".to_owned());
        let known = vec![SCOPE_CAPABILITY.to_owned()];
        // An up to date bridge: a remembered read keeps its scope.
        assert_eq!(
            for_bridge(false, scope.clone(), &known),
            (false, scope.clone())
        );
        // An older one (no capability): on its own, no scope, so that it
        // cannot be filed under `verrou get`'s approval.
        assert_eq!(for_bridge(false, scope.clone(), &[]), (true, None));
        assert_eq!(
            for_bridge(false, scope.clone(), &["something".to_owned()]),
            (true, None)
        );
        // What was asked on its own stays so.
        assert_eq!(for_bridge(true, None, &known), (true, None));
        assert_eq!(for_bridge(true, scope, &known), (true, None));
    }

    #[test]
    fn a_reader_is_followed_to_the_end_and_loops_are_cut() {
        let agent = tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 200, "/Users/me/.local/share/claude/versions/2.1.0"),
            (200, 1, "/bin/zsh"),
        ]);
        let reader = identify(&[500], &agent);
        assert_eq!(reader.agent.as_deref(), Some("claude"));
        assert_eq!(
            reader.describe(12),
            "agent ancestor: claude; no terminal; cat[500] ← zsh ← 2.1.0 ← zsh"
        );
        // An agent far above is still found: thirty shells deep.
        let mut entries = vec![(1000_u32, 999_u32, "/bin/cat")];
        for i in 0..41_u32 {
            entries.push((999 - i, 998 - i, "/bin/zsh"));
        }
        entries.push((958, 1, "/usr/local/bin/codex"));
        let found = identify(&[1000], &tree(&entries));
        assert_eq!(found.agent.as_deref(), Some("codex"));
        // The display is cut; what is found is not.
        assert!(found.chain.len() > 12);
        let shown = found.describe(12);
        assert!(
            shown.starts_with("agent ancestor: codex; no terminal; cat[1000]"),
            "{shown}"
        );
        assert!(shown.ends_with("← …"), "{shown}");

        // A program that cannot be found is shown as unknown, not skipped.
        let gone = identify(&[999], &tree(&[]));
        assert_eq!(gone.describe(3), "no terminal; ?[999]");
        assert_eq!(identify(&[], &agent).describe(3), "unidentified reader");
        // A loop in the parents does not loop here.
        let looped = identify(
            &[1000],
            &tree(&[(1000, 1001, "/bin/a"), (1001, 1000, "/bin/b")]),
        );
        assert_eq!(looped.describe(12), "no terminal; a[1000] ← b");
    }

    #[test]
    fn several_readers_are_counted_and_any_agent_among_them_counts() {
        let procs = tree(&[
            (10, 2, "/bin/cat"),
            (2, 1, "/bin/zsh"),
            (20, 3, "/bin/grep"),
            (3, 1, "/opt/homebrew/bin/codex"),
        ]);
        let reader = identify(&[10, 20], &procs);
        assert_eq!(reader.agent.as_deref(), Some("codex"));
        assert!(!reader.is_single());
        assert_eq!(
            reader.describe(12),
            "agent ancestor: codex; no terminal; 2 readers: cat, grep"
        );
        let many = identify(&[10, 10, 10, 10, 10, 10], &procs);
        assert_eq!(
            many.describe(12),
            "no terminal; 6 readers: cat, cat, cat, cat, …"
        );
    }

    #[test]
    fn what_a_program_is_called_is_made_showable() {
        assert_eq!(display_name("cat"), "cat");
        assert_eq!(display_name("node-22.1_x+y"), "node-22.1_x+y");
        // Control characters, bidirectional overrides, spaces and look-alikes.
        assert_eq!(display_name("a\u{202e}b\nc d"), "a?b?c?d");
        assert_eq!(display_name("cаt"), "c?t");
        let long = display_name(&"x".repeat(100));
        assert_eq!(long.chars().count(), NAME_CAP + 1);
        assert!(long.ends_with('…'));
        // Through the chain: a hostile name cannot hide an ancestor or pose
        // as a marker.
        let procs = tree(&[
            (500, 400, "/tmp/agent ancestor: nobody\n"),
            (400, 300, "/bin/zsh"),
            (300, 1, TERMINAL),
        ]);
        let reader = identify(&[500], &procs);
        assert_eq!(
            reader.describe(12),
            "agent?ancestor??nobody?[500] ← zsh ← Terminal"
        );
        assert_eq!(reader.agent, None);
    }

    #[test]
    fn the_approval_shows_the_file_the_reader_and_the_variables() {
        let procs = tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 1, TERMINAL),
        ]);
        let reader = identify(&[500], &procs);
        let fields = vec!["A=verrou://X/y".to_owned(), "PORT=(plain)".to_owned()];
        let detail = read_detail(Path::new("/work/app/.env"), &reader, &fields).unwrap();
        assert_eq!(
            detail.command,
            "read /work/app/.env by cat[500] ← zsh ← Terminal"
        );
        assert_eq!(detail.fields, fields);
        // Too long a path: the path is shortened first, the ancestry kept.
        let long = PathBuf::from(format!("/{}/app/.env", "d".repeat(180)));
        let detail = read_detail(&long, &reader, &fields).unwrap();
        assert!(detail.command.chars().count() <= 200, "{}", detail.command);
        assert_eq!(
            detail.command,
            "read …/app/.env by cat[500] ← zsh ← Terminal"
        );
        // A path that is long even shortened: the name alone.
        let very_long = PathBuf::from(format!("/{}/{}", "d".repeat(400), ".env"));
        let detail = read_detail(&very_long, &reader, &fields).unwrap();
        assert!(
            detail.command.starts_with("read .env by cat[500]"),
            "{}",
            detail.command
        );
        // Too long even for that: the ancestry is cut, never what is marked.
        let wide = PathBuf::from(format!("/a/{}", "n".repeat(170)));
        let detail = read_detail(&wide, &reader, &fields).unwrap();
        assert!(detail.command.chars().count() <= 200, "{}", detail.command);
        assert!(detail.command.contains("cat[500]"), "{}", detail.command);
        assert!(detail.command.ends_with("← …"), "{}", detail.command);
        // Eleven variables do not fit in the approval: no read.
        let many: Vec<String> = (0..11).map(|i| format!("V{i}=verrou://A/f{i}")).collect();
        assert!(read_detail(Path::new(".env"), &reader, &many).is_err());
    }

    #[test]
    fn the_markers_lead_and_survive_every_cut() {
        let agent = tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 1, "/opt/homebrew/bin/codex"),
        ]);
        let reader = identify(&[500], &agent);
        let fields = vec!["A=verrou://X/y".to_owned()];
        // However long the path, the marker is in what the user reads.
        for path in [
            PathBuf::from("/work/.env"),
            PathBuf::from(format!("/{}/.env", "d".repeat(150))),
            PathBuf::from(format!("/a/{}", "n".repeat(130))),
        ] {
            let detail = read_detail(&path, &reader, &fields).unwrap();
            assert!(
                detail
                    .command
                    .contains(" by agent ancestor: codex; no terminal; cat[500]"),
                "{}",
                detail.command
            );
        }
        let two = identify(&[500, 501], &agent);
        let detail = read_detail(
            &PathBuf::from(format!("/{}/.env", "d".repeat(300))),
            &two,
            &fields,
        )
        .unwrap();
        assert!(detail.command.contains("2 readers:"), "{}", detail.command);
        let none = identify(&[], &agent);
        let detail = read_detail(Path::new("/work/.env"), &none, &fields).unwrap();
        assert_eq!(detail.command, "read /work/.env by unidentified reader");
    }

    /// Values for a test: what was asked, and what to answer.
    struct Fake {
        asked: Mutex<Vec<(bool, Option<String>, RunDetail)>>,
        outcome: Mutex<Result<Vec<&'static str>, (&'static str, bool)>>,
    }

    impl Values for std::sync::Arc<Fake> {
        fn fetch(&self, request: &ReadRequest) -> Result<Vec<Zeroizing<String>>, Failure> {
            self.asked.lock().unwrap().push((
                request.ephemeral,
                request.approval_scope.clone(),
                request.detail.clone(),
            ));
            match &*self.outcome.lock().unwrap() {
                Ok(values) => Ok(values
                    .iter()
                    .map(|v| Zeroizing::new((*v).to_owned()))
                    .collect()),
                Err((message, refusal)) => Err(Failure {
                    message: (*message).to_owned(),
                    refusal: *refusal,
                }),
            }
        }
        fn check(&self, _: &[Reference]) -> Result<Checked, String> {
            Ok(Checked::Verified)
        }
    }

    struct Setup {
        reads: Reads,
        fake: std::sync::Arc<Fake>,
        dir: PathBuf,
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn setup(remember_reads: bool, agent_driven: bool, procs: Tree) -> Setup {
        let dir = temp_dir("ve");
        let map = dir.join(".env.verrou");
        std::fs::write(&map, "A=verrou://X/y\nPORT=8080\nB=verrou://X/z\n").unwrap();
        let fake = std::sync::Arc::new(Fake {
            asked: Mutex::new(Vec::new()),
            outcome: Mutex::new(Ok(vec!["secret one", "two"])),
        });
        let mount = Mount {
            file: dir.join(".env"),
            mapping: Mapping::read(&map).unwrap(),
            map,
            remember_reads,
            agent_driven,
        };
        let reads = Reads::new(mount, Box::new(fake.clone()), Box::new(procs));
        Setup { reads, fake, dir }
    }

    fn person() -> Tree {
        tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 1, TERMINAL),
        ])
    }

    /// The readers as they are when the values are about to be written.
    fn still(readers: &[u32]) -> impl Fn() -> Vec<u32> + '_ {
        move || readers.to_vec()
    }

    #[test]
    fn a_read_is_served_with_the_values_in_the_maps_order() {
        let s = setup(true, false, person());
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert!(served.is_ok());
        assert_eq!(
            payload.as_str(),
            "# Served by Verrou for this read; nothing of it is stored in a file.\nA='secret one'\nPORT=8080\nB=two\n"
        );
        let asked = s.fake.asked.lock().unwrap();
        assert!(!asked[0].0, "a person's read is not ephemeral");
        assert!(
            asked[0].2.command.ends_with("by cat[500] ← zsh ← Terminal"),
            "{}",
            asked[0].2.command
        );
        // Every variable is listed, the plain one by name.
        assert_eq!(
            asked[0].2.fields,
            ["A=verrou://X/y", "PORT=(plain)", "B=verrou://X/z"]
        );
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn who_is_asked_every_time_and_who_has_a_scope_of_their_own() {
        let agent = tree(&[
            (500, 400, "/bin/cat"),
            (400, 300, "/bin/zsh"),
            (300, 200, "/usr/local/bin/claude"),
            (200, 100, "/bin/zsh"),
            (100, 1, TERMINAL),
        ]);
        let no_terminal = tree(&[(500, 400, "/bin/cat"), (400, 1, "/bin/zsh")]);
        for (remember_reads, agent_driven, procs, readers, ephemeral) in [
            (true, false, person(), vec![500], false),
            // The default: asked every time.
            (false, false, person(), vec![500], true),
            (true, true, person(), vec![500], true),
            (true, false, agent, vec![500], true),
            // No terminal application above it: not identified.
            (true, false, no_terminal, vec![500], true),
            // Two processes, or none that could be found.
            (true, false, person(), vec![500, 501], true),
            (true, false, person(), vec![], true),
        ] {
            let s = setup(remember_reads, agent_driven, procs);
            assert!(s.reads.reply(&readers, &still(&readers)).1.is_ok());
            let asked = s.fake.asked.lock().unwrap();
            assert_eq!(asked[0].0, ephemeral);
            // Only a read that is remembered carries a key; it is never
            // empty, so it never meets the item's ordinary approval.
            assert_eq!(asked[0].1.is_some(), !ephemeral);
            drop(asked);
            std::fs::remove_dir_all(&s.dir).ok();
        }
    }

    #[test]
    fn the_scope_names_the_file_the_program_and_the_terminal() {
        let s = setup(true, false, person());
        let reader = identify(&[500], s.reads.processes());
        let scope = s.reads.scope(&reader).unwrap();
        assert_eq!(
            scope,
            format!("env:{}:/bin/cat:7:400:4000", s.reads.mount().file.display())
        );
        // Another program, or another terminal, is another key.
        let other = tree(&[
            (500, 400, "/usr/bin/grep"),
            (400, 300, "/bin/zsh"),
            (300, 1, TERMINAL),
        ]);
        let grep = identify(&[500], &other);
        assert_ne!(s.reads.scope(&grep), Some(scope));
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_refusal_gets_a_comment_then_a_pause_without_asking() {
        let s = setup(true, false, person());
        *s.fake.outcome.lock().unwrap() = Err(("refused in Verrou", true));
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert_eq!(
            payload.as_str(),
            "# verrou: not served (refused in Verrou)\n"
        );
        assert!(served.is_err());
        // The next read does not ask.
        *s.fake.outcome.lock().unwrap() = Ok(vec!["a", "b"]);
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert!(served.is_err());
        assert!(payload.contains("a moment ago"), "{}", payload.as_str());
        assert_eq!(s.fake.asked.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_refusal_pauses_only_reads_of_its_own_kind() {
        let s = setup(true, false, person());
        // An unidentified read (two processes) is refused: those pause ...
        *s.fake.outcome.lock().unwrap() = Err(("refused in Verrou", true));
        assert!(s.reads.reply(&[500, 501], &still(&[500, 501])).1.is_err());
        *s.fake.outcome.lock().unwrap() = Ok(vec!["a", "b"]);
        let (payload, served) = s.reads.reply(&[500, 501], &still(&[500, 501]));
        assert!(served.is_err() && payload.contains("a moment ago"));
        // ... a person's identified read is not paused, and is asked.
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_ok());
        assert_eq!(s.fake.asked.lock().unwrap().len(), 2);
        // And the other way round: the person's refusal does not pause the
        // others.
        *s.fake.outcome.lock().unwrap() = Err(("no", true));
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_err());
        let (payload, _) = s.reads.reply(&[500], &still(&[500]));
        assert!(payload.contains("a moment ago"));
        *s.fake.outcome.lock().unwrap() = Ok(vec!["a", "b"]);
        // (the earlier ephemeral pause still holds for ephemeral reads)
        let (payload, _) = s.reads.reply(&[500, 501], &still(&[500, 501]));
        assert!(payload.contains("a moment ago"));
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn an_unreachable_vault_is_said_and_does_not_pause() {
        let s = setup(true, false, person());
        *s.fake.outcome.lock().unwrap() = Err(("Verrou does not answer", false));
        let (payload, _) = s.reads.reply(&[500], &still(&[500]));
        assert_eq!(
            payload.as_str(),
            "# verrou: not served (Verrou does not answer)\n"
        );
        *s.fake.outcome.lock().unwrap() = Ok(vec!["a", "b"]);
        assert!(
            s.reads.reply(&[500], &still(&[500])).1.is_ok(),
            "asked again at once"
        );
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn nothing_is_written_if_the_readers_changed_while_asking() {
        let s = setup(true, false, person());
        // Someone else opened the pipe while the user was deciding.
        let (payload, served) = s.reads.reply(&[500], &|| vec![500, 777]);
        assert!(served.is_err());
        assert!(
            payload.contains("changed while Verrou was asked"),
            "{}",
            payload.as_str()
        );
        for secret in ["secret one", "two"] {
            assert!(!payload.contains(secret));
        }
        // The reader went away: the same.
        assert!(s.reads.reply(&[500], &Vec::new).1.is_err());
        // Nobody found at first, somebody there at the end: refused too.
        assert!(s.reads.reply(&[], &|| vec![500]).1.is_err());
        // In another order is the same set.
        assert!(s.reads.reply(&[500, 501], &|| vec![501, 500]).1.is_ok());
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn an_edited_map_is_not_served() {
        let s = setup(true, false, person());
        std::fs::write(
            &s.reads.mount().map,
            "A=verrou://X/y\nEXTRA=verrou://Other/token\n",
        )
        .unwrap();
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert!(served.is_err());
        assert!(payload.contains("map changed"), "{}", payload.as_str());
        assert!(s.fake.asked.lock().unwrap().is_empty(), "nothing was asked");
        std::fs::remove_file(&s.reads.mount().map).unwrap();
        assert!(s.reads.reply(&[500], &still(&[500])).1.is_err());
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_map_that_is_a_link_or_a_pipe_is_refused_without_waiting() {
        let dir = temp_dir("vm");
        let real = dir.join("real.verrou");
        std::fs::write(&real, "A=verrou://X/y\n").unwrap();
        assert!(read_map(&real).is_ok());
        let link = dir.join("link.verrou");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_map(&link).is_err(), "a link is not followed");
        assert!(Mapping::read(&link).is_err());
        let fifo = dir.join("pipe.verrou");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        // Nobody writes to it: opening it for reading would wait for ever.
        let error = read_map(&fifo).unwrap_err();
        assert!(error.contains("regular file"), "{error}");
        assert!(map_hash(&fifo).is_err());
        assert!(read_map(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_wrong_number_of_values_is_an_error_not_a_short_file() {
        let s = setup(true, false, person());
        *s.fake.outcome.lock().unwrap() = Ok(vec!["only one"]);
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert!(served.is_err());
        assert!(!payload.contains("only one"), "{}", payload.as_str());
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_value_no_form_carries_refuses_the_read_without_saying_it() {
        let s = setup(true, false, person());
        *s.fake.outcome.lock().unwrap() = Ok(vec!["it's \"hers\"", "two"]);
        let (payload, served) = s.reads.reply(&[500], &still(&[500]));
        assert!(served.is_err());
        assert!(
            payload.starts_with("# verrou: not served (A "),
            "{}",
            payload.as_str()
        );
        assert!(!payload.contains("hers") && !payload.contains("two"));
        std::fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn records_are_kept_per_file_and_read_back() {
        let dir = temp_dir("vr").join("env");
        let file = Path::new("/work/app/.env");
        let path = MountRecord::path_for(&dir, file);
        assert_ne!(
            path,
            MountRecord::path_for(&dir, Path::new("/work/other/.env"))
        );
        let record = MountRecord {
            pid: 4242,
            file: file.display().to_string(),
            map: "/work/app/.env.verrou".to_owned(),
            project_root: Some("/work/app".to_owned()),
            started: 1_700_000_000,
            remember_reads: false,
            process_start: Some(123),
            fifos: vec![(1, 2), (1, 3)],
        };
        record.save(&path).unwrap();
        assert_eq!(MountRecord::load_all(&dir), vec![(path.clone(), record)]);
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700,
                "the folder is made private"
            );
        }
        // Saved again: no temporary file stays.
        MountRecord::load_all(&dir)[0].1.save(&path).unwrap();
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // An older record, without the new fields, is still read.
        std::fs::write(
            &path,
            r#"{"pid":1,"file":"/x/.env","map":"/x/.env.verrou","project_root":null,"started":5,"ask_every_read":false}"#,
        )
        .unwrap();
        let old = &MountRecord::load_all(&dir)[0].1;
        assert!(old.fifos.is_empty() && old.process_start.is_none());
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }

    #[test]
    fn the_records_folder_is_made_private_and_a_link_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = temp_dir("vd");
        // Made with 0700, parents included.
        let dir = base.join(".verrou/env");
        private_dir(&dir).unwrap();
        for folder in [&dir, &base.join(".verrou")] {
            assert_eq!(
                std::fs::metadata(folder).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        // One that exists with looser rights is fixed (it is ours).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A link to a folder is not followed.
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        assert!(private_dir(&link).is_err());
        assert_eq!(
            std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
            0o755,
            "what the link points at was left alone"
        );
        // A file is not a folder.
        let file = base.join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(private_dir(&file).is_err());
        // And a record is never written through a link left in its place.
        let path = dir.join("0123456789abcdef.json");
        let target = base.join("target");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let record = MountRecord::default();
        record.save(&path).unwrap();
        assert!(!target.exists(), "the link was replaced, not followed");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_stale_mount_only_removes_a_fifo_it_made() {
        use std::os::unix::fs::FileTypeExt as _;
        let dir = temp_dir("vs");
        let file = dir.join(".env");
        nix::unistd::mkfifo(&file, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let identity = proc::identity_at_link(&file).unwrap();
        let mut record = MountRecord {
            pid: 999_999,
            file: file.display().to_string(),
            ..MountRecord::default()
        };
        // Not in the record: a FIFO of someone else's, left alone and said.
        assert!(!record.made(&file));
        let said = clean_up_stale(&record).unwrap();
        assert!(said.contains("did not make"), "{said}");
        assert!(
            std::fs::symlink_metadata(&file)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        // In the record: removed.
        record.fifos = vec![identity];
        assert!(record.made(&file));
        clean_up_stale(&record).unwrap();
        assert!(!file.exists());
        // A regular file with the same name is never touched, whatever the
        // record says.
        std::fs::write(&file, "precious").unwrap();
        clean_up_stale(&record).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "precious");
        // Leftovers of a dead mount: only FIFOs, only that process's.
        let leftover = dir.join("..env.verrou-999999-abcd");
        let other = dir.join("..env.verrou-1234-abcd");
        let regular = dir.join("..env.verrou-999999-regular");
        for fifo in [&leftover, &other] {
            nix::unistd::mkfifo(fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        }
        std::fs::write(&regular, "x").unwrap();
        clean_up_stale(&record).unwrap();
        assert!(!leftover.exists());
        assert!(other.exists() && regular.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every process is a `verrou` that started at 5.
    struct Verrou;

    impl Processes for Verrou {
        fn holders(&self, _: proc::Identity) -> Vec<u32> {
            Vec::new()
        }
        fn parent(&self, _: u32) -> Option<u32> {
            None
        }
        fn exe(&self, _: u32) -> Option<String> {
            Some("/usr/local/bin/verrou".to_owned())
        }
        fn args(&self, _: u32) -> Option<String> {
            None
        }
        fn tty(&self, _: u32) -> Option<String> {
            None
        }
        fn start_time(&self, _: u32) -> Option<u64> {
            Some(5)
        }
    }

    #[test]
    fn a_process_that_started_later_is_not_the_mount() {
        // This very process stands for a mount whose identifier was reused.
        let me = std::process::id();
        assert!(proc::is_verrou(&Verrou, me, Some(5)));
        assert!(proc::is_verrou(&Verrou, me, None), "an old record has none");
        assert!(!proc::is_verrou(&Verrou, me, Some(6)));
        assert!(!proc::is_verrou(&Verrou, 999_999, Some(5)), "not running");
        let record = MountRecord {
            pid: me,
            file: "/nowhere/.env".to_owned(),
            process_start: Some(6),
            ..MountRecord::default()
        };
        assert_eq!(state_of(&record, &Verrou), State::Stale);
        // Unmounting it cleans up and signals nobody (this test survives).
        let dir = temp_dir("vu");
        let path = dir.join("0123456789abcdef.json");
        record.save(&path).unwrap();
        let said = unmount(&path, &record, &Verrou).unwrap();
        assert!(said.contains("had stopped"), "{said}");
        assert!(!path.exists());
        let same = MountRecord {
            process_start: Some(5),
            ..record
        };
        assert_eq!(state_of(&same, &Verrou), State::Missing);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_application_is_opened_at_most_once_in_a_while() {
        let throttle = Throttle::new(Duration::from_millis(150));
        assert!(throttle.allow(), "the first time");
        assert!(!throttle.allow() && !throttle.allow());
        std::thread::sleep(Duration::from_millis(200));
        assert!(throttle.allow(), "again once the wait is over");
        assert!(!throttle.allow());
        assert!(Throttle::new(Duration::from_secs(60)).allow());
    }

    #[test]
    fn random_names_are_long_and_do_not_repeat() {
        let one = random_hex(8);
        assert_eq!(one.len(), 16);
        assert!(one.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(one, random_hex(8));
        assert_eq!(random_hex(16).len(), 32);
    }
}
