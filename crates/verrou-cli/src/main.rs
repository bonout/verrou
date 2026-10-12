//! `verrou` : le coffre depuis le terminal.
//!
//! Tant que la connexion à Vaultwarden n'existe pas, la CLI travaille sur le
//! coffre fictif et le signale sur stderr à chaque commande.

use std::io::Write as _;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use verrou_core::generator::{self, PasswordOptions};
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Filter, Item, ItemKind, Sort, Vault, mock};

#[derive(Parser)]
#[command(
    name = "verrou",
    version,
    about = "Gestionnaire de mots de passe pour Vaultwarden"
)]
struct Cli {
    /// Taille du coffre fictif.
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
    /// Chercher des éléments (sans requête : tout lister).
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
    /// Afficher un élément. Les secrets restent masqués sans `--reveal`.
    Get {
        query: Vec<String>,
        /// N'afficher que ce champ (`password`, `username`, `totp`…), brut.
        #[arg(short, long)]
        field: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// Code à usage unique de l'élément trouvé.
    Totp { query: Vec<String> },
    /// Générer un mot de passe.
    Generate {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        no_digits: bool,
    },
    /// Mesurer la recherche sur un gros coffre fictif.
    Bench {
        #[arg(long, default_value_t = 10_000)]
        items: usize,
    },
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
}

impl<'a> From<&'a Item> for ItemJson<'a> {
    fn from(item: &'a Item) -> Self {
        Self {
            id: &item.id,
            kind: item.kind.keyword(),
            title: &item.title,
            subtitle: &item.subtitle,
            urls: &item.urls,
            folder: item.folder.as_deref(),
            tags: &item.tags,
            favorite: item.favorite,
        }
    }
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

fn open_vault(size: usize) -> Vault {
    eprintln!(
        "\x1b[2m(coffre fictif — la connexion à Vaultwarden arrive dans la prochaine version)\x1b[0m"
    );
    Vault::new(mock::vault_items(size, 42))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn find<'v>(vault: &'v Vault, query: &[String]) -> Result<&'v Item, String> {
    let query = query.join(" ");
    if let Some(item) = vault.get(&query) {
        return Ok(item);
    }
    let hits = vault.search(&query, &Filter::All, Sort::Relevance);
    hits.first()
        .map(|h| &vault.items()[h.index])
        .ok_or_else(|| format!("aucun élément pour « {query} »"))
}

#[allow(clippy::too_many_lines)] // un `match` par sous-commande, lisible d'un trait
fn run(cli: &Cli) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    match &cli.command {
        Command::Search {
            query,
            kind,
            favorites,
            limit,
        } => {
            let vault = open_vault(cli.mock_size);
            let filter = match (kind, favorites) {
                (Some(k), _) => Filter::Kind((*k).into()),
                (None, true) => Filter::Favorites,
                (None, false) => Filter::All,
            };
            let hits = vault.search(&query.join(" "), &filter, Sort::Relevance);
            let items: Vec<&Item> = hits
                .iter()
                .take(*limit)
                .map(|h| &vault.items()[h.index])
                .collect();
            if cli.json {
                let json: Vec<ItemJson> = items.iter().map(|i| ItemJson::from(*i)).collect();
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
                )
                .ok();
            } else {
                for item in &items {
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
                if hits.len() > items.len() {
                    writeln!(
                        out,
                        "\x1b[2m… et {} autres\x1b[0m",
                        hits.len() - items.len()
                    )
                    .ok();
                }
            }
        }
        Command::Get {
            query,
            field,
            reveal,
        } => {
            let vault = open_vault(cli.mock_size);
            let item = find(&vault, query)?;
            if let Some(field_id) = field {
                let value = match field_id.as_str() {
                    "notes" => item.notes.as_ref().map(|n| n.expose().to_owned()),
                    "totp" => item
                        .field_of_kind(FieldKind::Totp)
                        .map(|f| Totp::parse(f.value.expose()).map(|t| t.generate(now()).code))
                        .transpose()
                        .map_err(|e| e.to_string())?,
                    other => item.field(other).map(|f| f.value.expose().to_owned()),
                };
                let value = value
                    .ok_or_else(|| format!("« {} » n'a pas de champ « {field_id} »", item.title))?;
                // Un champ demandé explicitement sort brut, pour `| pbcopy`.
                writeln!(out, "{value}").ok();
                return Ok(());
            }
            if cli.json {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&ItemJson::from(item))
                        .map_err(|e| e.to_string())?
                )
                .ok();
                return Ok(());
            }
            print_item(&mut out, item, *reveal);
        }
        Command::Totp { query } => {
            let vault = open_vault(cli.mock_size);
            let item = find(&vault, query)?;
            let field = item
                .field_of_kind(FieldKind::Totp)
                .ok_or_else(|| format!("« {} » n'a pas de code à usage unique", item.title))?;
            let code = Totp::parse(field.value.expose())
                .map_err(|e| e.to_string())?
                .generate(now());
            if cli.json {
                writeln!(
                    out,
                    r#"{{"code":"{}","remaining":{},"period":{}}}"#,
                    code.code, code.remaining, code.period
                )
                .ok();
            } else {
                writeln!(out, "{}", code.code).ok();
            }
        }
        Command::Generate {
            length,
            no_symbols,
            no_digits,
        } => {
            let password = generator::password(&PasswordOptions {
                length: *length,
                symbols: !no_symbols,
                digits: !no_digits,
                avoid_ambiguous: true,
            });
            writeln!(out, "{password}").ok();
        }
        Command::Bench { items } => bench(&mut out, *items),
    }
    Ok(())
}

fn print_item(out: &mut impl std::io::Write, item: &Item, reveal: bool) {
    const PAD: &str = "\n                         ";
    writeln!(
        out,
        "\x1b[1m{}\x1b[0m  \x1b[2m{}\x1b[0m",
        item.title,
        item.kind.label()
    )
    .ok();
    for url in &item.urls {
        writeln!(out, "  {:<22} {url}", "Site").ok();
    }
    for f in &item.fields {
        let shown = if f.kind == FieldKind::Totp {
            Totp::parse(f.value.expose()).map_or_else(
                |e| e.to_string(),
                |t| {
                    let c = t.generate(now());
                    format!("{} {}  ({} s)", &c.code[..3], &c.code[3..], c.remaining)
                },
            )
        } else if f.kind.is_secret() && !reveal {
            "••••••••••••".to_owned()
        } else {
            f.value.expose().replace('\n', PAD)
        };
        writeln!(out, "  {:<22} {shown}", f.label).ok();
    }
    if let Some(notes) = &item.notes {
        let shown = if reveal {
            notes.expose().to_owned()
        } else {
            "•••• (--reveal)".to_owned()
        };
        writeln!(out, "  {:<22} {}", "Notes", shown.replace('\n', PAD)).ok();
    }
    if let Some(folder) = &item.folder {
        writeln!(out, "  {:<22} \x1b[2m{folder}\x1b[0m", "Dossier").ok();
    }
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
