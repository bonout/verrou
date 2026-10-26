//! The three commands of `verrou env`: `mount`, `unmount` and `status`.

use std::io::Write;
use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use super::fifo::{self, Cleanup, Fifo};
use super::proc::{self, Processes, System};
use super::{
    Checked, GitState, Mapping, Mount, MountRecord, Reads, State, Values, clean_up_stale,
    git_check, identify, is_fifo, now, private_dir, random_hex, read_detail, records_dir, run_git,
    state_of, unmount,
};
use crate::remote;

/// How long `--background` waits for the mount to come up.
const START_WITHIN: Duration = Duration::from_secs(10);
/// The variable through which a background mount's parent hands it a token
/// that it also wrote to a file of the records folder: `--detached` without
/// both is refused. `--detached` skips nothing, but it is Verrou's own way of
/// starting itself, not an option for a program to pick. It is **not a
/// security boundary**: any process of the same user can read the token file
/// and set the variable. It only keeps `--detached` from being typed (or put
/// in a script) by mistake; what a detached mount does is no more than a
/// foreground one does (git check, approval of every read).
pub const DETACH_TOKEN: &str = "VERROU_ENV_DETACH_TOKEN";

/// Where the parent of a background mount leaves its token.
fn token_path(dir: &Path, file: &Path) -> PathBuf {
    dir.join(format!("{}.token", super::record_id(file)))
}

/// Takes the token of a background start: the one in the environment must be
/// the one in the file, which is removed (used once).
fn take_token(dir: &Path, file: &Path) -> Result<(), String> {
    let refused = || {
        "--detached is how `--background` starts the mount again: it is not an option to use by hand"
            .to_owned()
    };
    let path = token_path(dir, file);
    let given = std::env::var(DETACH_TOKEN).map_err(|_| refused())?;
    let written = std::fs::read_to_string(&path).map_err(|_| refused())?;
    let _ = std::fs::remove_file(&path);
    // Equal length and content, compared without stopping at the first
    // difference.
    let same = given.len() == written.len()
        && given
            .bytes()
            .zip(written.bytes())
            .fold(0_u8, |all, (a, b)| all | (a ^ b))
            == 0;
    if given.len() < 32 || !same {
        return Err(refused());
    }
    Ok(())
}

/// What `verrou env mount` was given.
pub struct MountOptions {
    pub file: PathBuf,
    pub map: Option<PathBuf>,
    pub background: bool,
    pub remember_reads: bool,
    /// The process `--background` started: a hang-up does not end it, and
    /// what it says goes to its log. Only accepted with the token its parent
    /// handed it ([`DETACH_TOKEN`]).
    pub detached: bool,
    /// Options of `verrou` itself to pass on to a background mount
    /// (`--mock`, `--reason`…).
    pub global_args: Vec<String>,
}

/// The absolute path of a file that may not exist: its folder, resolved,
/// and its name.
fn absolute(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{}: not a file name", path.display()))?;
    let cwd = std::env::current_dir().map_err(|e| format!("current folder: {e}"))?;
    let folder = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let folder = std::fs::canonicalize(cwd.join(folder))
        .map_err(|e| format!("{}: {e}", folder.display()))?;
    Ok(folder.join(name))
}

/// What is at the place of the file, if anything: a mount that stopped
/// leaves a FIFO that is cleaned up; anything else is refused. `dir`: the
/// records.
fn clear_the_way(file: &Path, dir: &Path, procs: &dyn Processes) -> Result<(), String> {
    let meta = match std::fs::symlink_metadata(file) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    let kind = meta.file_type();
    if !kind.is_fifo() {
        let what = if kind.is_symlink() {
            "a link"
        } else if kind.is_dir() {
            "a folder"
        } else if kind.is_file() {
            "a file"
        } else {
            "not a file Verrou can mount over"
        };
        return Err(format!(
            "{} already exists and is {what}: Verrou never replaces it (if it holds secrets, put them in the vault and delete it)",
            file.display()
        ));
    }
    let path = MountRecord::path_for(dir, file);
    match MountRecord::load_all(dir)
        .into_iter()
        .find(|(p, _)| *p == path)
    {
        Some((_, record)) if proc::is_verrou(procs, record.pid, record.process_start) => {
            Err(format!(
                "{} is already mounted (process {}): `verrou env unmount` first",
                file.display(),
                record.pid
            ))
        }
        Some((_, record)) if record.made(file) => {
            // The mount that made it is gone.
            clean_up_stale(&record)?;
            let _ = std::fs::remove_file(&path);
            eprintln!("verrou: removed the FIFO of a mount that had stopped");
            Ok(())
        }
        _ => Err(format!(
            "{} is a FIFO that Verrou did not make: remove it yourself if you want it replaced",
            file.display()
        )),
    }
}

/// Where the file stands for git: refused if it would be committed; the
/// repository's root if it is ignored; a warning if there is no repository
/// or no git.
fn check_git(file: &Path) -> Result<Option<PathBuf>, String> {
    match git_check(file, &run_git)? {
        GitState::Ignored { root, rule } => {
            eprintln!("verrou: ignored by git ({rule})");
            Ok(Some(root))
        }
        GitState::NotARepository => {
            eprintln!(
                "verrou: warning: {} is not in a git repository: nothing keeps it out of one you create later",
                file.display()
            );
            Ok(None)
        }
        GitState::Unavailable => {
            eprintln!(
                "verrou: warning: git is not installed: could not check that {} is ignored",
                file.display()
            );
            Ok(None)
        }
    }
}

/// `verrou env mount`.
pub fn mount(options: &MountOptions, values: Box<dyn Values>) -> Result<(), String> {
    let procs = System;
    let dir = records_dir()?;
    let file = absolute(&options.file)?;
    let map = if let Some(map) = &options.map {
        absolute(map)?
    } else {
        let name = file.file_name().map(|n| n.to_string_lossy().into_owned());
        file.with_file_name(format!("{}.verrou", name.unwrap_or_default()))
    };
    if std::fs::symlink_metadata(&map).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Err(format!(
            "{}: the map is not there. It is a dotenv file whose values are verrou://<item>/<field> references (`--map` to name another)",
            map.display()
        ));
    }
    let mapping = Mapping::read(&map)?;
    // The approval has to be able to show every variable, whoever reads.
    read_detail(
        &file,
        &identify(&[std::process::id()], &procs),
        &mapping.fields(),
    )
    .map_err(|reason| format!("{}: {reason}", map.display()))?;

    if options.detached {
        take_token(&dir, &file)?;
    }
    // Every mount checks git, the background one again: nothing it was told
    // is taken for granted.
    let project_root = check_git(&file)?;
    clear_the_way(&file, &dir, &procs)?;
    if !options.detached {
        let references: Vec<_> = mapping.references().into_iter().map(|(_, r)| r).collect();
        match values.check(&references)? {
            Checked::Verified => {}
            Checked::VaultLocked => eprintln!(
                "verrou: warning: the vault is locked: the references could not be checked"
            ),
        }
    }
    if options.background && !options.detached {
        return start_in_background(options, &file, &map, &dir);
    }

    let record_path = MountRecord::path_for(&dir, &file);
    let secrets = mapping.references().len();
    let mount = Mount {
        file: file.clone(),
        map: map.clone(),
        mapping,
        remember_reads: options.remember_reads,
        agent_driven: remote::driven_by_agent(),
    };
    // Signals first, then the record, then the FIFO: whatever ends the
    // process in between leaves nothing the next mount refuses.
    fifo::block_signals()?;
    let record = MountRecord {
        pid: std::process::id(),
        file: file.display().to_string(),
        map: map.display().to_string(),
        project_root: project_root.map(|p| p.display().to_string()),
        started: now(),
        remember_reads: options.remember_reads,
        process_start: procs.start_time(std::process::id()),
        fifos: Vec::new(),
    };
    record.save(&record_path)?;
    // The record says which FIFOs are this mount's, before each is put in
    // place: a stale mount is only ever cleaned up on that strength.
    let record = Arc::new(Mutex::new(record));
    let remember = {
        let (record, path) = (Arc::clone(&record), record_path.clone());
        move |here: (u64, u64), next: (u64, u64)| {
            let mut record = record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            record.fifos = vec![here, next];
            if let Err(e) = record.save(&path) {
                eprintln!("verrou: could not update the record of the mount ({e})");
            }
        }
    };
    let fifo = match Fifo::create(&file, remember) {
        Ok(fifo) => fifo,
        Err(e) => {
            let _ = std::fs::remove_file(&record_path);
            return Err(e);
        }
    };
    let cleanup = Cleanup {
        fifo: fifo.clone(),
        record: record_path,
        log: options.detached.then(|| MountRecord::log_for(&dir, &file)),
    };
    fifo::end_on_signals(cleanup.clone(), !options.detached)?;
    eprintln!(
        "verrou: mounted {} ({secrets} from {}). Stop it with Ctrl-C or `verrou env unmount`.",
        file.display(),
        map.display()
    );
    let reads = Arc::new(Reads::new(mount, values, Box::new(procs)));
    let ended = fifo::serve(&reads, &fifo);
    cleanup.run();
    ended
}

/// `--background`: starts this same command again, detached from the
/// terminal, its words going to a log next to the record; returns when the
/// FIFO is there, or says why the mount did not start.
fn start_in_background(
    options: &MountOptions,
    file: &Path,
    map: &Path,
    dir: &Path,
) -> Result<(), String> {
    let log_path = MountRecord::log_for(dir, file);
    private_dir(dir)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&log_path)
        .map_err(|e| format!("{}: {e}", log_path.display()))?;
    // The token that tells the child it was started by this process.
    let token = random_hex(16);
    let token_file = token_path(dir, file);
    let _ = std::fs::remove_file(&token_file);
    {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&token_file)
            .and_then(|mut f| f.write_all(token.as_bytes()))
            .map_err(|e| format!("{}: {e}", token_file.display()))?;
    }
    let mut command = std::process::Command::new(
        std::env::current_exe().map_err(|e| format!("this program's path: {e}"))?,
    );
    command
        .args(&options.global_args)
        .args(["env", "mount", "--file"]);
    command
        .arg(file)
        .arg("--map")
        .arg(map)
        .arg("--detached")
        .env(DETACH_TOKEN, &token);
    if options.remember_reads {
        command.arg("--remember-reads");
    }
    // Its own process group: not stopped by the terminal's interrupt. The
    // standard input stays ours, which is how it knows if an agent drives it.
    command
        .process_group(0)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log));
    let mut child = command.spawn().map_err(|e| {
        let _ = std::fs::remove_file(&token_file);
        format!("could not start: {e}")
    })?;
    let record_path = MountRecord::path_for(dir, file);
    let start = Instant::now();
    while start.elapsed() < START_WITHIN {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            let _ = std::fs::remove_file(&token_file);
            let said = std::fs::read_to_string(&log_path).unwrap_or_default();
            let _ = std::fs::remove_file(&log_path);
            let said = said
                .lines()
                .map(|l| l.strip_prefix("verrou: ").unwrap_or(l))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(if said.is_empty() {
                "the mount did not start".to_owned()
            } else {
                said
            });
        }
        let up = MountRecord::load_all(dir)
            .iter()
            .any(|(p, r)| *p == record_path && r.pid == child.id())
            && is_fifo(file);
        if up {
            let _ = std::fs::remove_file(&token_file);
            eprintln!(
                "verrou: mounted {} in the background (process {}). Stop it with `verrou env unmount`.",
                file.display(),
                child.id()
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(&token_file);
    Err(format!(
        "the mount did not come up within {} seconds (see {})",
        START_WITHIN.as_secs(),
        log_path.display()
    ))
}

/// `verrou env unmount`: this file's mount (`.env` by default), or all.
pub fn unmount_command(file: Option<&Path>, all: bool, out: &mut impl Write) -> Result<(), String> {
    let dir = records_dir()?;
    let procs = System;
    let records = MountRecord::load_all(&dir);
    let chosen: Vec<_> = if all {
        records
    } else {
        let file = absolute(file.unwrap_or(Path::new(".env")))?;
        let path = MountRecord::path_for(&dir, &file);
        let found: Vec<_> = records.into_iter().filter(|(p, _)| *p == path).collect();
        if found.is_empty() {
            return Err(format!(
                "{} is not mounted (`verrou env status` lists the mounts)",
                file.display()
            ));
        }
        found
    };
    if chosen.is_empty() {
        writeln!(out, "Nothing is mounted.").ok();
    }
    let mut failed = Vec::new();
    for (path, record) in &chosen {
        match unmount(path, record, &procs) {
            Ok(line) => {
                writeln!(out, "{line}").ok();
            }
            Err(e) => failed.push(e),
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("\n"))
    }
}

fn since(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min", seconds / 60),
        3600..=86_399 => format!("{} h", seconds / 3600),
        _ => format!("{} days", seconds / 86_400),
    }
}

/// `verrou env status`: the mounts, and whether each one is running.
pub fn status(json: bool, out: &mut impl Write) -> Result<(), String> {
    let dir = records_dir()?;
    let procs = System;
    let records = MountRecord::load_all(&dir);
    if json {
        let list: Vec<_> = records
            .iter()
            .map(|(_, r)| {
                json!({
                    "file": r.file,
                    "state": state_of(r, &procs),
                    "pid": r.pid,
                    "map": r.map,
                    "project_root": r.project_root,
                    "started": r.started,
                    "remember_reads": r.remember_reads,
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
        writeln!(out, "{text}").ok();
        return Ok(());
    }
    if records.is_empty() {
        writeln!(out, "No .env file is mounted.").ok();
        return Ok(());
    }
    for (_, record) in &records {
        let state = state_of(record, &procs);
        let (word, note) = match state {
            State::Mounted => ("mounted", String::new()),
            State::Stale => (
                "stale",
                " (the process is gone: `verrou env unmount` cleans up)".to_owned(),
            ),
            State::Missing => ("missing", " (the file is not a FIFO any more)".to_owned()),
        };
        writeln!(
            out,
            "{word}  {}  map {}  process {}, {} ago{}{note}",
            record.file,
            record.map,
            record.pid,
            since(now().saturating_sub(record.started)),
            if record.remember_reads {
                ", remembers a person's reads for five minutes"
            } else {
                ", asks on every read"
            },
        )
        .ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_short_words() {
        assert_eq!(since(5), "5 s");
        assert_eq!(since(125), "2 min");
        assert_eq!(since(7300), "2 h");
        assert_eq!(since(200_000), "2 days");
    }
}
