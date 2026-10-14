//! `verrou` : le coffre depuis le terminal.
//!
//! Le coffre n'est déchiffré que dans l'app : la CLI, reliée une fois par
//! `verrou link`, lui pose ses questions par le pont (TCP `127.0.0.1`, canal
//! chiffré). Les secrets demandent l'accord de l'utilisateur dans Verrou
//! (Touch ID). `--mock` travaille sur le coffre fictif, sans l'app.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
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
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::passphrase::{self, Language, PassphraseOptions, Separator};
use verrou_core::{FieldKind, Filter, ItemKind, Sort, Vault, mock};

#[derive(Parser)]
#[command(
    name = "verrou",
    version,
    about = "Gestionnaire de mots de passe pour Vaultwarden"
)]
struct Cli {
    /// Travailler sur le coffre fictif, sans l'app.
    #[arg(long, global = true)]
    mock: bool,

    /// Taille du coffre fictif (avec `--mock`).
    #[arg(long, global = true, env = "VERROU_MOCK_SIZE", default_value_t = 0)]
    mock_size: usize,

    /// Sortie JSON (pour les scripts).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Relier ce terminal à Verrou (une fois) : un code à comparer dans l'app.
    Link {
        /// Nom montré dans Verrou.
        #[arg(long, default_value = "le terminal (verrou)")]
        name: String,
    },
    /// Délier ce terminal de Verrou.
    Unlink,
    /// État de la liaison et du coffre.
    Status,
    /// Chercher des éléments (sans requête : tout lister). Aucun secret.
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
    /// Afficher un élément (titre ou identifiant). Les secrets restent masqués
    /// sans `--reveal` ou `--field` ; Verrou demande alors votre accord.
    Get {
        query: Vec<String>,
        /// N'afficher que ce champ (`password`, `username`, `totp`, `notes`…), brut.
        #[arg(short, long)]
        field: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// Code à usage unique de l'élément trouvé (accord demandé dans Verrou).
    Totp { query: Vec<String> },
    /// Générer un mot de passe, ou une phrase de passe avec `--words`
    /// (sur place, sans l'app).
    Generate {
        #[arg(short, long, default_value_t = 20, conflicts_with = "words")]
        length: usize,
        #[arg(long, conflicts_with = "words")]
        no_symbols: bool,
        #[arg(long, conflicts_with = "words")]
        no_digits: bool,
        /// Phrase de passe de N mots (3 à 20), tirés dans une liste de
        /// 7 776 mots.
        #[arg(short, long, value_parser = clap::value_parser!(u8).range(3..=20))]
        words: Option<u8>,
        /// Séparateur des mots : `-`, `' '` (ou `space`), `.`, `_`, `,` ou
        /// `digit` (un chiffre au hasard).
        #[arg(long, default_value = "-", requires = "words", value_parser = parse_separator)]
        separator: Separator,
        /// Initiale de chaque mot en majuscule.
        #[arg(long, requires = "words")]
        capitalize: bool,
        /// Ajouter un chiffre à la fin d'un des mots.
        #[arg(long, requires = "words")]
        number: bool,
        /// Langue des mots.
        #[arg(long, value_enum, default_value_t = LangArg::Fr, requires = "words")]
        lang: LangArg,
    },
    /// Agent SSH : les clés SSH du coffre, signées par Verrou. Tourne au
    /// premier plan et affiche la ligne `export SSH_AUTH_SOCK=…`.
    SshAgent {
        /// Socket Unix (défaut : `~/.verrou/agent.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Signer ses commits git avec une clé SSH du coffre, par l'agent de
    /// Verrou. Affiche les réglages de git ; `--apply` les écrit.
    GitSigning {
        /// Titre ou empreinte de la clé (inutile s'il n'y en a qu'une).
        query: Vec<String>,
        /// Adresse des commits (défaut : `git config user.email`).
        #[arg(long)]
        email: Option<String>,
        /// Signataires autorisés, pour vérifier les signatures (défaut :
        /// `~/.config/verrou/allowed_signers`).
        #[arg(long)]
        allowed_signers: Option<PathBuf>,
        /// Socket de l'agent (défaut : `~/.verrou/agent.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Écrire les réglages (configuration globale de git) et ajouter la
        /// clé aux signataires autorisés.
        #[arg(long)]
        apply: bool,
        /// Configuration du dépôt courant plutôt que la globale.
        #[arg(long)]
        local: bool,
    },
    /// Mesurer la recherche sur un gros coffre fictif.
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
        .ok_or_else(|| format!("séparateur inconnu « {value} » : -, ' ', ., _, , ou digit"))
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

/// `verrou get --json` : l'élément et ses champs, valeurs secrètes absentes.
#[derive(Serialize)]
struct ItemDetailJson<'a> {
    #[serde(flatten)]
    item: ItemJson<'a>,
    fields: &'a [verrou_bridge::protocol::FieldView],
    has_notes: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("verrou : {message}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// D'où viennent les éléments : l'app (par le pont) ou le coffre fictif.
enum Source {
    Mock(Vault),
    App(Remote),
}

impl Source {
    fn open(cli: &Cli) -> Result<Self, String> {
        if cli.mock {
            eprintln!("\x1b[2m(coffre fictif, --mock)\x1b[0m");
            return Ok(Self::Mock(Vault::new(mock::vault_items(cli.mock_size, 42))));
        }
        let path = Config::default_path()?;
        let config = Config::load(&path)?.ok_or_else(|| Error::NotLinked.to_string())?;
        Remote::connect(&config, Endpoint::from_env())
            .map(Self::App)
            .map_err(|e| e.to_string())
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

    /// Code, période, secondes restantes.
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

    /// Les clés SSH du coffre : clés publiques seulement, sans accord à donner.
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
    format!("réponse inattendue de Verrou : {reply:?}")
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
                // Un champ demandé explicitement sort brut, pour `| pbcopy`.
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
                return Err(format!(
                    "« {} » n'a pas de code à usage unique",
                    item.summary.title
                ));
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
        Command::Generate { .. } => generate(cli, &mut out),
        Command::SshAgent { socket } => ssh_agent(socket.as_deref())?,
        Command::GitSigning { .. } => git_signing_setup(cli, &mut out)?,
        Command::Bench { items } => bench(&mut out, *items),
    }
    Ok(())
}

/// `verrou generate` : mot de passe, ou phrase de passe avec `--words`.
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

/// `verrou git-signing` : affiche (ou, avec `--apply`, écrit) les réglages
/// de git pour signer avec une clé SSH du coffre.
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
        .ok_or("adresse des commits inconnue : --email, ou « git config user.email »")?;
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
            "git signera avec « {} » ({}) ; clé ajoutée à {}.\nDans chaque terminal : export SSH_AUTH_SOCK={} (et « verrou ssh-agent » lancé).",
            plan.key.title,
            plan.key.fingerprint,
            plan.allowed_signers.display(),
            git_signing::shell_quote(&socket.to_string_lossy()),
        );
    } else {
        write!(out, "{}", plan.script(&socket)).ok();
        eprintln!("(rien n'est écrit : relancez avec --apply pour appliquer ces réglages)");
    }
    Ok(())
}

/// Valeur d'un champ : visible dans l'élément, ou demandée à Verrou.
fn field_value(source: &mut Source, item: &ItemView, field_id: &str) -> Result<String, String> {
    let title = &item.summary.title;
    if field_id == "totp" {
        if !item.summary.has_totp {
            return Err(format!("« {title} » n'a pas de code à usage unique"));
        }
        return source.totp(&item.summary.id).map(|(code, _, _)| code);
    }
    if field_id == "notes" {
        if !item.has_notes {
            return Err(format!("« {title} » n'a pas de notes"));
        }
        return source.reveal(&item.summary.id, "notes");
    }
    let field = item
        .fields
        .iter()
        .find(|f| f.id == field_id)
        .ok_or_else(|| format!("« {title} » n'a pas de champ « {field_id} »"))?;
    match &field.value {
        Some(value) => Ok(value.clone()),
        None => source.reveal(&item.summary.id, field_id),
    }
}

fn link(name: &str) -> Result<(), String> {
    let path = Config::default_path()?;
    if Config::load(&path)?.is_some() {
        eprintln!(
            "verrou : ce terminal était déjà relié ; le nouveau lien remplace l'ancien (déliez l'ancien dans les réglages de Verrou)."
        );
    }
    eprintln!("Demande envoyée à Verrou…");
    let config = remote::link(Endpoint::from_env(), name, |code| {
        eprintln!(
            "Code de vérification : \x1b[1m{code}\x1b[0m\nAcceptez dans Verrou seulement s'il affiche exactement ce code."
        );
    })
    .map_err(|e| e.to_string())?;
    config.save(&path)?;
    eprintln!("Terminal relié à Verrou ({}).", path.display());
    Ok(())
}

fn unlink() -> Result<(), String> {
    let path = Config::default_path()?;
    let Some(config) = Config::load(&path)? else {
        eprintln!("Ce terminal n'était pas relié.");
        return Ok(());
    };
    // Prévenir Verrou s'il est ouvert ; sinon, le lien reste dans ses
    // réglages, à délier à la main.
    let endpoint = Endpoint {
        launch: false,
        ..Endpoint::from_env()
    };
    let told = Remote::connect(&config, endpoint)
        .and_then(|mut remote| remote.call(&Ask::Unlink))
        .is_ok_and(|reply| reply == ReplyResult::Done);
    Config::remove(&path)?;
    if told {
        eprintln!("Terminal délié.");
    } else {
        eprintln!(
            "Lien effacé de ce terminal. Verrou ne répond pas : déliez aussi « le terminal » dans ses réglages."
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
        (false, ..) => "non relié : « verrou link »".to_owned(),
        (true, false, ..) => "lien révoqué dans Verrou : « verrou link »".to_owned(),
        (true, true, Some(false), _) => "relié ; Verrou n'est pas ouvert".to_owned(),
        (true, true, _, Some(true)) => "relié ; coffre déverrouillé".to_owned(),
        _ => "relié ; coffre verrouillé".to_owned(),
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
        "Agent SSH de Verrou à l'écoute (Ctrl-C pour l'arrêter). Chaque clé demande votre accord dans Verrou."
    );
    let keys: Arc<dyn Keys> = Arc::new(BridgeKeys {
        config,
        endpoint: Endpoint::from_env(),
    });
    agent::serve(&listener, &keys);
    Ok(())
}

/// Entre apostrophes si besoin, pour coller la ligne dans un shell.
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
        writeln!(out, "\x1b[2m… et {} autres\x1b[0m", total - items.len()).ok();
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
        writeln!(out, "  {:<22} \x1b[2m{folder}\x1b[0m", "Dossier").ok();
    }
    if let Some(shared) = &summary.shared {
        writeln!(out, "  {:<22} \x1b[2m{shared}\x1b[0m", "Coffre partagé").ok();
    }
    Ok(())
}

fn bench(out: &mut impl std::io::Write, items: usize) {
    let start = Instant::now();
    let vault = Vault::new(mock::vault_items(items, 7));
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
    writeln!(
        out,
        "{} éléments — index construit en {built:.2?}",
        vault.len()
    )
    .ok();
    writeln!(
        out,
        "recherche par frappe : médiane {p50:.2?}, p99 {p99:.2?} ({} mesures)",
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
