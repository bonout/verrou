//! `verrou`: the vault from the terminal.
//!
//! The vault is only decrypted in the app: the CLI, linked once with
//! `verrou link`, asks it its questions through the bridge (TCP
//! `127.0.0.1`, encrypted channel). Secrets require the user's approval in
//! Verrou (Touch ID). `--mock` works on the mock vault, without the app.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use verrou_bridge::access;
use verrou_bridge::protocol::{Command as Ask, ItemSummary, ItemView, ReplyResult};
use verrou_cli::agent::{self, BridgeKeys, Keys};
use verrou_cli::config::Config;
use verrou_cli::git_signing;
use verrou_cli::remote::{self, Endpoint, Error, Remote};
use verrou_cli::run;
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::passphrase::{self, Language, PassphraseOptions, Separator};
use verrou_core::{FieldKind, Filter, ItemKind, Sort, Vault, mock};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "verrou", version, about = "Password manager for Vaultwarden")]
struct Cli {
    /// Work on the mock vault, without the app.
    #[arg(long, global = true)]
    mock: bool,

    /// Size of the mock vault (with `--mock`).
    #[arg(long, global = true, env = "VERROU_MOCK_SIZE", default_value_t = 0)]
    mock_size: usize,

    /// JSON output (for scripts).
    #[arg(long, global = true)]
    json: bool,

    /// Why you ask: shown in Verrou's approval, on the Mac and the iPhone
    /// ("deploy to production"). Declared, never checked.
    #[arg(long, global = true, env = "VERROU_REASON")]
    reason: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Link this terminal to Verrou (once): a code to compare in the app.
    Link {
        /// Name shown in Verrou.
        #[arg(long, default_value = "terminal (verrou)")]
        name: String,
    },
    /// Unlink this terminal from Verrou.
    Unlink,
    /// State of the link and the vault.
    Status,
    /// Search items (no query: list everything). No secrets.
    #[command(visible_alias = "ls")]
    Search {
        query: Vec<String>,
        #[arg(long, value_enum)]
        kind: Option<KindArg>,
        #[arg(long)]
        favorites: bool,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Show an item (title or id). Secrets stay hidden without `--reveal` or
    /// `--field`; Verrou then asks for your approval.
    Get {
        query: Vec<String>,
        /// Print only this field (`password`, `username`, `totp`, `notes`…), raw.
        #[arg(short, long)]
        field: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// One-time code of the item found (approval asked in Verrou).
    Totp { query: Vec<String> },
    /// Run a command with secrets in its environment: each variable set to
    /// `verrou://<item>/<field>` (here or in `--env-file`) gets the field's
    /// value, after your approval in Verrou. The secrets never go through
    /// the terminal; the command's output has them masked.
    Run {
        /// Dotenv file (`KEY=value`, values may be `verrou://` references).
        #[arg(long)]
        env_file: Option<PathBuf>,
        /// Don't mask the secrets in the command's output (it then writes
        /// straight to the terminal: interactive programs).
        #[arg(long)]
        no_masking: bool,
        /// The command and its arguments, after `--`.
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },
    /// Generate a password, or a passphrase with `--words` (locally,
    /// without the app).
    Generate {
        #[arg(short, long, default_value_t = 20, conflicts_with = "words")]
        length: usize,
        #[arg(long, conflicts_with = "words")]
        no_symbols: bool,
        #[arg(long, conflicts_with = "words")]
        no_digits: bool,
        /// Passphrase of N words (3 to 20), drawn from a list of 7,776
        /// words.
        #[arg(short, long, value_parser = clap::value_parser!(u8).range(3..=20))]
        words: Option<u8>,
        /// Word separator: `-`, `' '` (or `space`), `.`, `_`, `,` or
        /// `digit` (a random digit).
        #[arg(long, default_value = "-", requires = "words", value_parser = parse_separator)]
        separator: Separator,
        /// Capitalize the first letter of each word.
        #[arg(long, requires = "words")]
        capitalize: bool,
        /// Add a digit at the end of one of the words.
        #[arg(long, requires = "words")]
        number: bool,
        /// Language of the words.
        #[arg(long, value_enum, default_value_t = LangArg::Fr, requires = "words")]
        lang: LangArg,
    },
    /// SSH agent: the vault's SSH keys, signed by Verrou. Runs in the
    /// foreground and prints the `export SSH_AUTH_SOCK=…` line.
    SshAgent {
        /// Unix socket (default: `~/.verrou/agent.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Sign your git commits with an SSH key from the vault, through
    /// Verrou's agent. Prints the git settings; `--apply` writes them.
    GitSigning {
        /// Title or fingerprint of the key (not needed if there is only one).
        query: Vec<String>,
        /// Commit address (default: `git config user.email`).
        #[arg(long)]
        email: Option<String>,
        /// Allowed signers, to verify signatures (default:
        /// `~/.config/verrou/allowed_signers`).
        #[arg(long)]
        allowed_signers: Option<PathBuf>,
        /// Agent socket (default: `~/.verrou/agent.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Write the settings (global git configuration) and add the key to
        /// the allowed signers.
        #[arg(long)]
        apply: bool,
        /// Current repository's configuration rather than the global one.
        #[arg(long)]
        local: bool,
    },
    /// Benchmark search on a large mock vault.
    Bench {
        #[arg(long, default_value_t = 10_000)]
        items: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum LangArg {
    Fr,
    En,
}

fn parse_separator(value: &str) -> Result<Separator, String> {
    Separator::parse(value)
        .ok_or_else(|| format!("unknown separator \"{value}\": -, ' ', ., _, , or digit"))
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Login,
    Card,
    Identity,
    Note,
    Ssh,
}

impl From<KindArg> for ItemKind {
    fn from(value: KindArg) -> Self {
        match value {
            KindArg::Login => Self::Login,
            KindArg::Card => Self::Card,
            KindArg::Identity => Self::Identity,
            KindArg::Note => Self::SecureNote,
            KindArg::Ssh => Self::SshKey,
        }
    }
}

#[derive(Serialize)]
struct ItemJson<'a> {
    id: &'a str,
    kind: &'static str,
    title: &'a str,
    subtitle: &'a str,
    urls: &'a [String],
    folder: Option<&'a str>,
    tags: &'a [String],
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared: Option<&'a str>,
}

impl<'a> From<&'a ItemSummary> for ItemJson<'a> {
    fn from(item: &'a ItemSummary) -> Self {
        Self {
            id: &item.id,
            kind: item.kind.keyword(),
            title: &item.title,
            subtitle: &item.subtitle,
            urls: &item.urls,
            folder: item.folder.as_deref(),
            tags: &item.tags,
            favorite: item.favorite,
            shared: item.shared.as_deref(),
        }
    }
}

/// `verrou get --json`: the item and its fields, without secret values.
#[derive(Serialize)]
struct ItemDetailJson<'a> {
    #[serde(flatten)]
    item: ItemJson<'a>,
    fields: &'a [verrou_bridge::protocol::FieldView],
    has_notes: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Run { .. }) {
        // The command's exit code becomes ours.
        return run_command(&cli).unwrap_or_else(|message| {
            eprintln!("verrou: {message}");
            ExitCode::FAILURE
        });
    }
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("verrou: {message}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where items come from: the app (through the bridge) or the mock vault.
enum Source {
    Mock(Vault),
    App(Remote),
}

impl Source {
    fn open(cli: &Cli) -> Result<Self, String> {
        if cli.mock {
            eprintln!("\x1b[2m(mock vault, --mock)\x1b[0m");
            return Ok(Self::Mock(Vault::new(mock::vault_items(
                cli.mock_size,
                42,
                mock::MockLanguage::En,
            ))));
        }
        let path = Config::default_path()?;
        let config = Config::load(&path)?.ok_or_else(|| Error::NotLinked.to_string())?;
        let mut remote =
            Remote::connect(&config, Endpoint::from_env()).map_err(|e| e.to_string())?;
        remote.reason.clone_from(&cli.reason);
        Ok(Self::App(remote))
    }

    fn ask(remote: &mut Remote, command: &Ask) -> Result<ReplyResult, String> {
        remote.ask(command).map_err(|e| e.to_string())
    }

    fn search(
        &mut self,
        query: &str,
        kind: Option<ItemKind>,
        favorites: bool,
        limit: usize,
    ) -> Result<(Vec<ItemSummary>, usize), String> {
        let limit = u32::try_from(limit).ok();
        match self {
            Self::Mock(vault) => Ok(access::search(vault, query, kind, favorites, limit)),
            Self::App(remote) => {
                let command = Ask::VaultSearch {
                    query: query.to_owned(),
                    kind,
                    favorites,
                    limit,
                };
                match Self::ask(remote, &command)? {
                    ReplyResult::Items { items, total } => Ok((items, total as usize)),
                    other => Err(unexpected(&other)),
                }
            }
        }
    }

    fn item(&mut self, query: &str) -> Result<ItemView, String> {
        match self {
            Self::Mock(vault) => access::find(vault, query).map(access::item_view),
            Self::App(remote) => match Self::ask(
                remote,
                &Ask::VaultItem {
                    query: query.to_owned(),
                },
            )? {
                ReplyResult::Item { item } => Ok(item),
                other => Err(unexpected(&other)),
            },
        }
    }

    fn reveal(&mut self, item: &str, field: &str) -> Result<String, String> {
        match self {
            Self::Mock(vault) => access::field_value(vault, item, field),
            Self::App(remote) => match Self::ask(
                remote,
                &Ask::Reveal {
                    item: item.to_owned(),
                    field: field.to_owned(),
                },
            )? {
                ReplyResult::Secret(secret) => Ok(secret.value.clone()),
                other => Err(unexpected(&other)),
            },
        }
    }

    /// Code, period, seconds remaining.
    fn totp(&mut self, item: &str) -> Result<(String, u64, u64), String> {
        match self {
            Self::Mock(vault) => access::totp_code(vault, item, now()),
            Self::App(remote) => match Self::ask(
                remote,
                &Ask::Totp {
                    item: item.to_owned(),
                },
            )? {
                ReplyResult::Code {
                    code,
                    period,
                    remaining,
                } => Ok((code, period, remaining)),
                other => Err(unexpected(&other)),
            },
        }
    }

    /// The vault's SSH keys: public keys only, no approval needed.
    fn ssh_keys(&mut self) -> Result<Vec<git_signing::SigningKey>, String> {
        let identities = match self {
            Self::Mock(vault) => verrou_bridge::ssh::identities(vault),
            Self::App(remote) => match Self::ask(remote, &Ask::SshKeys)? {
                ReplyResult::SshKeys { keys } => keys,
                other => return Err(unexpected(&other)),
            },
        };
        Ok(identities
            .iter()
            .filter_map(git_signing::SigningKey::from_identity)
            .collect())
    }
}

fn unexpected(reply: &ReplyResult) -> String {
    format!("unexpected reply from Verrou: {reply:?}")
}

fn run(cli: &Cli) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    match &cli.command {
        Command::Link { name } => link(name)?,
        Command::Unlink => unlink()?,
        Command::Status => status(&mut out, cli.json)?,
        Command::Search {
            query,
            kind,
            favorites,
            limit,
        } => {
            let mut source = Source::open(cli)?;
            let (items, total) =
                source.search(&query.join(" "), kind.map(Into::into), *favorites, *limit)?;
            print_results(&mut out, &items, total, cli.json)?;
        }
        Command::Get {
            query,
            field,
            reveal,
        } => {
            let mut source = Source::open(cli)?;
            let item = source.item(&query.join(" "))?;
            if let Some(field_id) = field {
                let value = field_value(&mut source, &item, field_id)?;
                // A field asked for explicitly is printed raw, for `| pbcopy`.
                writeln!(out, "{value}").ok();
                return Ok(());
            }
            if cli.json {
                let json = ItemDetailJson {
                    item: ItemJson::from(&item.summary),
                    fields: &item.fields,
                    has_notes: item.has_notes,
                };
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
                )
                .ok();
                return Ok(());
            }
            print_item(&mut out, &mut source, &item, *reveal)?;
        }
        Command::Totp { query } => {
            let mut source = Source::open(cli)?;
            let item = source.item(&query.join(" "))?;
            if !item.summary.has_totp {
                return Err(format!("\"{}\" has no one-time code", item.summary.title));
            }
            let (code, period, remaining) = source.totp(&item.summary.id)?;
            if cli.json {
                writeln!(
                    out,
                    "{}",
                    serde_json::json!({ "code": code, "remaining": remaining, "period": period })
                )
                .ok();
            } else {
                writeln!(out, "{code}").ok();
            }
        }
        Command::Run { .. } => {}
        Command::Generate { .. } => generate(cli, &mut out),
        Command::SshAgent { socket } => ssh_agent(socket.as_deref())?,
        Command::GitSigning { .. } => git_signing_setup(cli, &mut out)?,
        Command::Bench { items } => bench(&mut out, *items),
    }
    Ok(())
}

/// `verrou generate`: password, or passphrase with `--words`.
fn generate(cli: &Cli, out: &mut impl std::io::Write) {
    let Command::Generate {
        length,
        no_symbols,
        no_digits,
        words,
        separator,
        capitalize,
        number,
        lang,
    } = &cli.command
    else {
        return;
    };
    let (value, bits) = if let Some(words) = words {
        let options = PassphraseOptions {
            words: usize::from(*words),
            separator: *separator,
            capitalize: *capitalize,
            include_number: *number,
            language: match lang {
                LangArg::Fr => Language::French,
                LangArg::En => Language::English,
            },
        };
        (
            passphrase::passphrase(&options),
            passphrase::entropy_bits(&options),
        )
    } else {
        let password = generator::password(&PasswordOptions {
            length: *length,
            symbols: !no_symbols,
            digits: !no_digits,
            avoid_ambiguous: true,
        });
        let bits = generator::entropy_bits(&password);
        (password, bits)
    };
    if cli.json {
        writeln!(
            out,
            "{}",
            serde_json::json!({ "value": value, "entropy_bits": bits })
        )
        .ok();
    } else {
        writeln!(out, "{value}").ok();
    }
}

/// `verrou git-signing`: prints (or, with `--apply`, writes) the git
/// settings to sign with an SSH key from the vault.
fn git_signing_setup(cli: &Cli, out: &mut impl std::io::Write) -> Result<(), String> {
    let Command::GitSigning {
        query,
        email,
        allowed_signers,
        socket,
        apply,
        local,
    } = &cli.command
    else {
        return Ok(());
    };
    let keys = Source::open(cli)?.ssh_keys()?;
    let key = git_signing::choose(&keys, &query.join(" "))?.clone();
    let git = || std::process::Command::new("git");
    let email = email
        .clone()
        .or_else(|| git_signing::git_email(git))
        .ok_or("commit address unknown: --email, or `git config user.email`")?;
    let plan = git_signing::Plan {
        key,
        email,
        allowed_signers: match allowed_signers {
            Some(path) => path.clone(),
            None => git_signing::default_allowed_signers()?,
        },
        scope: if *local {
            git_signing::Scope::Local
        } else {
            git_signing::Scope::Global
        },
    };
    let socket = match socket {
        Some(path) => path.clone(),
        None => agent::default_socket()?,
    };
    if *apply {
        plan.apply(git)?;
        eprintln!(
            "git will sign with \"{}\" ({}); key added to {}.\nIn each terminal: export SSH_AUTH_SOCK={} (with `verrou ssh-agent` running).",
            plan.key.title,
            plan.key.fingerprint,
            plan.allowed_signers.display(),
            git_signing::shell_quote(&socket.to_string_lossy()),
        );
    } else {
        write!(out, "{}", plan.script(&socket)).ok();
        eprintln!("(nothing written: run again with --apply to apply these settings)");
    }
    Ok(())
}

/// `verrou run`: resolves the `verrou://` references, then runs the
/// command with them, its output masked (see `verrou_cli::run`).
fn run_command(cli: &Cli) -> Result<ExitCode, String> {
    let Command::Run {
        env_file,
        no_masking,
        command,
    } = &cli.command
    else {
        return Ok(ExitCode::FAILURE);
    };
    let file = match env_file {
        Some(path) => run::parse_env_file(
            &std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
        )
        .map_err(|e| format!("{}: {e}", path.display()))?,
        None => Vec::new(),
    };
    let references = run::references(std::env::vars(), &file)?;
    let mut secrets: Vec<(String, Zeroizing<String>)> = Vec::new();
    if !references.is_empty() {
        let mut source = Source::open(cli)?;
        let mut items: HashMap<String, ItemView> = HashMap::new();
        for (name, reference) in &references {
            if !items.contains_key(&reference.item) {
                let item = source
                    .item(&reference.item)
                    .map_err(|e| format!("{name}: {e}"))?;
                items.insert(reference.item.clone(), item);
            }
            let item = &items[&reference.item];
            let value = field_value(&mut source, item, &reference.field)
                .map_err(|e| format!("{name}: {e}"))?;
            secrets.push((name.clone(), Zeroizing::new(value)));
        }
    }
    let (program, arguments) = command.split_first().ok_or("missing command")?;
    let mut child = std::process::Command::new(program);
    child.args(arguments);
    for (name, value) in &file {
        if run::Reference::parse(value).is_none() {
            child.env(name, value);
        }
    }
    for (name, value) in &secrets {
        child.env(name, value.as_str());
    }
    let masking = !no_masking && !secrets.is_empty();
    if masking {
        child.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = child.spawn().map_err(|e| format!("{program}: {e}"))?;
    let pumps: Vec<std::thread::JoinHandle<()>> = if masking {
        let masker = || run::Masker::new(secrets.iter().map(|(_, value)| value.as_str()));
        let out = child.stdout.take().map(|from| {
            let masker = masker();
            std::thread::spawn(move || {
                let _ = run::pump(from, std::io::stdout(), masker);
            })
        });
        let err = child.stderr.take().map(|from| {
            let masker = masker();
            std::thread::spawn(move || {
                let _ = run::pump(from, std::io::stderr(), masker);
            })
        });
        out.into_iter().chain(err).collect()
    } else {
        Vec::new()
    };
    // The values only stay in the command's environment.
    drop(secrets);
    let status = child.wait().map_err(|e| format!("{program}: {e}"))?;
    for pump in pumps {
        let _ = pump.join();
    }
    Ok(exit_code(status))
}

/// The command's code; killed by a signal: 128 + the signal, as a shell
/// says it.
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return ExitCode::from(u8::try_from(128 + signal).unwrap_or(u8::MAX));
        }
    }
    status.code().map_or(ExitCode::FAILURE, |code| {
        ExitCode::from(u8::try_from(code).unwrap_or(1))
    })
}

/// A field's value: visible in the item, or asked of Verrou.
fn field_value(source: &mut Source, item: &ItemView, field_id: &str) -> Result<String, String> {
    let title = &item.summary.title;
    if field_id == "totp" {
        if !item.summary.has_totp {
            return Err(format!("\"{title}\" has no one-time code"));
        }
        return source.totp(&item.summary.id).map(|(code, _, _)| code);
    }
    if field_id == "notes" {
        if !item.has_notes {
            return Err(format!("\"{title}\" has no notes"));
        }
        return source.reveal(&item.summary.id, "notes");
    }
    let field = item
        .fields
        .iter()
        .find(|f| f.id == field_id)
        .ok_or_else(|| format!("\"{title}\" has no field \"{field_id}\""))?;
    match &field.value {
        Some(value) => Ok(value.clone()),
        None => source.reveal(&item.summary.id, field_id),
    }
}

fn link(name: &str) -> Result<(), String> {
    let path = Config::default_path()?;
    if Config::load(&path)?.is_some() {
        eprintln!(
            "verrou: this terminal was already linked; the new link replaces the old one (unlink the old one in Verrou's settings)."
        );
    }
    eprintln!("Request sent to Verrou…");
    let config = remote::link(Endpoint::from_env(), name, |code| {
        eprintln!(
            "Verification code: \x1b[1m{code}\x1b[0m\nAccept in Verrou only if it shows exactly this code."
        );
    })
    .map_err(|e| e.to_string())?;
    config.save(&path)?;
    eprintln!("Terminal linked to Verrou ({}).", path.display());
    Ok(())
}

fn unlink() -> Result<(), String> {
    let path = Config::default_path()?;
    let Some(config) = Config::load(&path)? else {
        eprintln!("This terminal was not linked.");
        return Ok(());
    };
    // Tell Verrou if it is open; otherwise, the link stays in its settings,
    // to be unlinked by hand.
    let endpoint = Endpoint {
        launch: false,
        ..Endpoint::from_env()
    };
    let told = Remote::connect(&config, endpoint)
        .and_then(|mut remote| remote.call(&Ask::Unlink))
        .is_ok_and(|reply| reply == ReplyResult::Done);
    Config::remove(&path)?;
    if told {
        eprintln!("Terminal unlinked.");
    } else {
        eprintln!(
            "Link removed from this terminal. Verrou does not answer: also unlink the terminal in its settings."
        );
    }
    Ok(())
}

fn status(out: &mut impl std::io::Write, json: bool) -> Result<(), String> {
    let path = Config::default_path()?;
    let config = Config::load(&path)?;
    let (linked, reachable, unlocked) = match &config {
        None => (false, None, None),
        Some(config) => {
            let endpoint = Endpoint {
                launch: false,
                ..Endpoint::from_env()
            };
            match Remote::connect(config, endpoint).and_then(|mut r| r.unlocked()) {
                Ok(unlocked) => (true, Some(true), Some(unlocked)),
                Err(Error::UnknownClient) => (false, Some(true), None),
                Err(_) => (true, Some(false), None),
            }
        }
    };
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "linked": linked,
                "app_running": reachable,
                "unlocked": unlocked,
                "config": path,
            })
        )
        .ok();
        return Ok(());
    }
    let line = match (config.is_some(), linked, reachable, unlocked) {
        (false, ..) => "not linked: `verrou link`".to_owned(),
        (true, false, ..) => "link revoked in Verrou: `verrou link`".to_owned(),
        (true, true, Some(false), _) => "linked; Verrou is not open".to_owned(),
        (true, true, _, Some(true)) => "linked; vault unlocked".to_owned(),
        _ => "linked; vault locked".to_owned(),
    };
    writeln!(out, "{line}").ok();
    Ok(())
}

fn ssh_agent(socket: Option<&std::path::Path>) -> Result<(), String> {
    let config =
        Config::load(&Config::default_path()?)?.ok_or_else(|| Error::NotLinked.to_string())?;
    let (path, default) = match socket {
        Some(path) => (path.to_owned(), false),
        None => (agent::default_socket()?, true),
    };
    let listener = agent::bind(&path, default)?;
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    println!(
        "export SSH_AUTH_SOCK={}",
        shell_quote(&path.to_string_lossy())
    );
    let _ = std::io::stdout().flush();
    eprintln!(
        "Verrou SSH agent listening (Ctrl-C to stop it). Each key asks for your approval in Verrou."
    );
    let keys: Arc<dyn Keys> = Arc::new(BridgeKeys {
        config,
        endpoint: Endpoint::from_env(),
    });
    agent::serve(&listener, &keys);
    Ok(())
}

/// In single quotes if needed, to paste the line into a shell.
fn shell_quote(text: &str) -> String {
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-~+@".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

fn print_results(
    out: &mut impl std::io::Write,
    items: &[ItemSummary],
    total: usize,
    json: bool,
) -> Result<(), String> {
    if json {
        let json: Vec<ItemJson> = items.iter().map(ItemJson::from).collect();
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
        )
        .ok();
        return Ok(());
    }
    for item in items {
        let star = if item.favorite { "★" } else { " " };
        writeln!(
            out,
            "{star} {:<36} \x1b[2m{:<34} {}\x1b[0m",
            truncate(&item.title, 36),
            truncate(&item.subtitle, 34),
            item.kind.label()
        )
        .ok();
    }
    if total > items.len() {
        writeln!(out, "\x1b[2m… and {} more\x1b[0m", total - items.len()).ok();
    }
    Ok(())
}

fn print_item(
    out: &mut impl std::io::Write,
    source: &mut Source,
    item: &ItemView,
    reveal: bool,
) -> Result<(), String> {
    const PAD: &str = "\n                         ";
    let summary = &item.summary;
    writeln!(
        out,
        "\x1b[1m{}\x1b[0m  \x1b[2m{}\x1b[0m",
        summary.title,
        summary.kind.label()
    )
    .ok();
    for url in &summary.urls {
        writeln!(out, "  {:<22} {url}", "Site").ok();
    }
    for f in &item.fields {
        let shown = match (&f.value, f.kind) {
            (Some(value), _) => value.replace('\n', PAD),
            (None, FieldKind::Totp) if reveal => {
                let (code, _, remaining) = source.totp(&summary.id)?;
                let (a, b) = code.split_at(code.len() / 2);
                format!("{a} {b}  ({remaining} s)")
            }
            (None, _) if reveal => source.reveal(&summary.id, &f.id)?.replace('\n', PAD),
            (None, _) => "••••••••••••".to_owned(),
        };
        writeln!(out, "  {:<22} {shown}", f.label).ok();
    }
    if item.has_notes {
        let shown = if reveal {
            source.reveal(&summary.id, "notes")?
        } else {
            "•••• (--reveal)".to_owned()
        };
        writeln!(out, "  {:<22} {}", "Notes", shown.replace('\n', PAD)).ok();
    }
    if let Some(folder) = &summary.folder {
        writeln!(out, "  {:<22} \x1b[2m{folder}\x1b[0m", "Folder").ok();
    }
    if let Some(shared) = &summary.shared {
        writeln!(out, "  {:<22} \x1b[2m{shared}\x1b[0m", "Shared vault").ok();
    }
    Ok(())
}

fn bench(out: &mut impl std::io::Write, items: usize) {
    let start = Instant::now();
    let vault = Vault::new(mock::vault_items(items, 7, mock::MockLanguage::En));
    let built = start.elapsed();
    let queries = [
        "g",
        "gi",
        "git",
        "gith",
        "githu",
        "github",
        "github pro",
        "société",
        "zzzz",
        "tag:banque",
    ];
    let mut times: Vec<Duration> = Vec::new();
    for _ in 0..20 {
        for q in queries {
            let t = Instant::now();
            std::hint::black_box(vault.search(q, &Filter::All, Sort::Relevance));
            times.push(t.elapsed());
        }
    }
    times.sort();
    let p50 = times[times.len() / 2];
    let p99 = times[times.len() * 99 / 100];
    writeln!(out, "{} items — index built in {built:.2?}", vault.len()).ok();
    writeln!(
        out,
        "search per keystroke: median {p50:.2?}, p99 {p99:.2?} ({} samples)",
        times.len()
    )
    .ok();
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(width - 1).collect::<String>())
    }
}
