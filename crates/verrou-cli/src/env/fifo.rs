//! The FIFO of a mount and the loop that serves it.
//!
//! A reader opens the FIFO and waits; Verrou opens it for writing (the open
//! returns when a reader is there), puts a **fresh FIFO** in its place so the
//! next reader waits for a new round, looks at who has the old one open, and
//! only then asks for the values. The first reader holds the old pipe, so it
//! reads this round's answer and nothing else, however long the approval
//! takes.
//!
//! The readers are found by the identity (device and inode) of the writer's
//! own descriptor, through the kernel's list of open files, never through a
//! name. Just before the values are written the same question is asked
//! again, and a different answer means no values; and once they are
//! written it is asked a last time: a program that now has the pipe open
//! and was not shown to the user may have read the values, which is said
//! loudly and ends the mount (nothing more is served until it is mounted
//! again).
//!
//! The kernel can lose the end-of-file wake-up when two programs opened a
//! pipe together, and a reader then waits for ever (measured: with the old
//! pipe left without any name and nothing to say it again, a reader hung in
//! 14 runs out of 15 of the two-readers test). Two things say it again: a
//! second writer, opened (without waiting) before the swap and closed after
//! the main one; and, once a reader is still there after that, writers opened
//! for a moment on the old pipe through a second name. That name lives in a
//! folder of its own for the round (random name, inside a folder of the mount
//! that is itself inside the project folder, so that it is on the same disk),
//! **closed to everyone (mode 000) from the swap on** and opened (mode 700)
//! only for those moments, never during the approval nor the write: it is
//! no path for a program that does not know it, but the same user can always
//! change the mode of a folder of theirs, which is an inherent residual.
//! Every writer opened that way is checked, once open, to be the very pipe
//! the round is about (the device and inode), and nothing is ever written to
//! it.
//!
//! The FIFO is only ever created with `mkfifo` where nothing is: a file, a
//! link or a folder in the way is an error, never replaced. Opening it for
//! writing checks, once open, that it is still the FIFO Verrou made (the
//! device and inode), so a file swapped in meanwhile is never written to.
//!
//! Signals (interrupt, terminate, hang-up) are not handled with handlers
//! but waited for by a thread of their own: they are blocked everywhere,
//! which needs no unsafe code. That thread removes the FIFO and the record,
//! and ends the process.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

use super::proc::{Identity, identity_of};
use super::{MAX_AT_ONCE, Reads, random_hex, refusal_line};

/// How long to wait for the kernel to show who opened the FIFO: a reader's
/// `open` returns a moment before its file shows up in the process list.
const FIND_READERS_FOR: Duration = Duration::from_millis(300);
/// Once someone is seen, how long to wait for a second one that opened the
/// same pipe in the same instant.
const SETTLE: Duration = Duration::from_millis(40);
/// Swaps that may fail one after the other before the mount ends.
const MAX_SWAP_FAILURES: u32 = 20;

/// Called with the identity of the FIFO that is there and of the one about to
/// take its place, before the swap (the record of the mount keeps both).
type OnSwap = Arc<dyn Fn(Identity, Identity) + Send + Sync>;

/// The FIFO a mount made, and the identity of the one that is there now.
#[derive(Clone)]
pub struct Fifo {
    path: PathBuf,
    /// The folder of the mount's own, where the pipes of the next rounds are
    /// made and the old ones are kept, each in a folder of its round, under
    /// a second name until their round is over (never in the project folder
    /// itself).
    hold: PathBuf,
    current: Arc<Mutex<Identity>>,
    on_swap: Option<OnSwap>,
}

/// A reader arrived: the pipe's writing end, and a second one for the end
/// of file ([`serve`]).
pub struct Accepted {
    pub writer: File,
    pub spare: Option<File>,
    /// The pipe's identity: who has it open is asked by this.
    pub id: Identity,
}

/// Why a new FIFO could not be put in place.
#[derive(Debug)]
pub enum SwapError {
    /// What is at the path is not the FIFO we made: the mount is over.
    Replaced(String),
    /// A system call failed: worth another try.
    Failed(String),
}

impl Fifo {
    /// Makes the FIFO at `path`, readable and writable by this user alone.
    /// Whatever is there already is an error (nothing is replaced). It is
    /// made under a private name first, so that `on_swap` (the record of the
    /// mount) knows its identity before it appears at `path`: a mount killed
    /// at any moment leaves a FIFO its record accounts for. `on_swap` is also
    /// called before every swap, with the identity of the FIFO that is there
    /// and of the one about to take its place.
    pub fn create(
        path: &Path,
        on_swap: impl Fn(Identity, Identity) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let error = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("env");
        let hold = path.with_file_name(format!(
            ".{name}.verrou-{}-{}",
            std::process::id(),
            random_hex(8)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&hold)
            .map_err(|e| error(&e))?;
        let temp = hold.join(format!("first-{}", random_hex(8)));
        let undo = |e: String| {
            let _ = std::fs::remove_file(&temp);
            let _ = std::fs::remove_dir(&hold);
            e
        };
        mkfifo(&temp, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| undo(error(&e)))?;
        let meta = std::fs::symlink_metadata(&temp).map_err(|e| undo(error(&e)))?;
        if !meta.file_type().is_fifo() {
            return Err(undo(error(&"not a FIFO after mkfifo")));
        }
        let id = identity_of(&meta);
        on_swap(id, id);
        // A hard link does not replace what is there.
        std::fs::hard_link(&temp, path).map_err(|e| undo(error(&e)))?;
        let _ = std::fs::remove_file(&temp);
        Ok(Self {
            path: path.to_owned(),
            hold,
            current: Arc::new(Mutex::new(id)),
            on_swap: Some(Arc::new(on_swap)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The identity of the FIFO that is there now.
    pub fn current(&self) -> Identity {
        *self.current.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens the FIFO for writing: waits for a reader. `Err` if what is at
    /// the path is no longer the FIFO we made.
    pub fn accept(&self) -> Result<Accepted, String> {
        let flags = OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = open(&self.path, OFlag::O_WRONLY | flags, Mode::empty())
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        let writer = File::from(fd);
        let meta = writer
            .metadata()
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        if !meta.file_type().is_fifo() || identity_of(&meta) != self.current() {
            return Err(format!(
                "{} is no longer the FIFO Verrou made: it was replaced",
                self.path.display()
            ));
        }
        let id = identity_of(&meta);
        // The second writer, before the swap, of the very same pipe.
        let spare = open(
            &self.path,
            OFlag::O_WRONLY | OFlag::O_NONBLOCK | flags,
            Mode::empty(),
        )
        .ok()
        .map(File::from)
        .filter(|f| f.metadata().is_ok_and(|m| identity_of(&m) == id));
        Ok(Accepted { writer, spare, id })
    }

    /// Puts a new FIFO in the place of the old one, atomically: a reader
    /// that opens the path finds one or the other, never nothing. The old
    /// one gets a second name, in a folder of its round, until the round is
    /// over ([`Retired`], closed with [`Retired::seal`]). The time between the
    /// reader's arrival and this
    /// swap is what decides whether a second reader shares the first one's
    /// pipe, so it is kept to a few system calls.
    pub fn renew(&self) -> Result<Retired, SwapError> {
        let failed =
            |e: &dyn std::fmt::Display| SwapError::Failed(format!("{}: {e}", self.path.display()));
        // Names nobody can guess; one that exists is not used.
        let mut temp = None;
        for _ in 0..8 {
            let candidate = self.hold.join(format!("new-{}", random_hex(8)));
            match mkfifo(&candidate, Mode::S_IRUSR | Mode::S_IWUSR) {
                Ok(()) => {
                    temp = Some(candidate);
                    break;
                }
                Err(Errno::EEXIST) => {}
                Err(e) => return Err(failed(&e)),
            }
        }
        let temp = temp.ok_or_else(|| failed(&"no free name for the next FIFO"))?;
        let round = self.hold.join(format!("round-{}", random_hex(8)));
        let old = round.join("old");
        let cleanup = |e: SwapError| {
            let _ = std::fs::remove_file(&temp);
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::remove_dir(&round);
            e
        };
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&round)
            .map_err(|e| cleanup(failed(&e)))?;
        let meta = std::fs::symlink_metadata(&temp).map_err(|e| cleanup(failed(&e)))?;
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        // Only a FIFO of ours is replaced.
        let there = std::fs::symlink_metadata(&self.path).map_err(|e| cleanup(failed(&e)))?;
        if !there.file_type().is_fifo() || identity_of(&there) != *current {
            return Err(cleanup(SwapError::Replaced(format!(
                "{} is no longer the FIFO Verrou made: it was replaced",
                self.path.display()
            ))));
        }
        let next = identity_of(&meta);
        if let Some(on_swap) = &self.on_swap {
            on_swap(*current, next);
        }
        std::fs::hard_link(&self.path, &old).map_err(|e| cleanup(failed(&e)))?;
        std::fs::rename(&temp, &self.path).map_err(|e| cleanup(failed(&e)))?;
        let retired = Retired {
            round,
            path: old,
            id: *current,
        };
        *current = next;
        Ok(retired)
    }

    /// Removes the FIFO, if the path still holds the one we made, and the
    /// temporary names a swap in progress may have left.
    pub fn remove(&self) {
        let current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && meta.file_type().is_fifo()
            && identity_of(&meta) == *current
        {
            let _ = std::fs::remove_file(&self.path);
        }
        remove_leftovers(&self.path, std::process::id());
    }
}

/// The pipe a read was served through, under its second name, until the
/// round is over.
pub struct Retired {
    /// The folder of the round, which holds the name.
    round: PathBuf,
    path: PathBuf,
    id: Identity,
}

impl Retired {
    /// Closes the folder of the second name to everyone: from here on no
    /// path leads to the old pipe, for a program that opens it (the user
    /// can still change the mode of their own folder).
    fn seal(&self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.round, std::fs::Permissions::from_mode(0o000));
    }

    fn open_up(&self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.round, std::fs::Permissions::from_mode(0o700));
    }

    /// Opens a writer on the old pipe for a moment, without waiting, and
    /// closes it again: a reader whose wake-up was lost gets another. The
    /// folder is open only for that moment. Only the pipe of this round is
    /// of interest: a writer opened on anything else (the name was swapped)
    /// is closed at once, untouched, and nothing is ever written through
    /// any.
    fn nudge(&self) {
        self.open_up();
        let opened = open(
            &self.path,
            OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from);
        if let Ok(file) = opened
            && file.metadata().is_ok_and(|m| identity_of(&m) == self.id)
        {
            // Closed as it goes out of scope: that is the nudge.
            drop(file);
        }
        self.seal();
    }

    /// Removes the second name and the folder of the round.
    pub fn remove(self) {
        self.open_up();
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.round);
    }
}

/// Removes the temporary FIFOs (`.<name>.verrou-<pid>-…`) a mount of this
/// process identifier left beside `file`: only FIFOs, only that identifier.
pub fn remove_leftovers(file: &Path, pid: u32) {
    use std::os::unix::fs::FileTypeExt as _;
    let (Some(name), Some(folder)) = (file.file_name().and_then(|n| n.to_str()), file.parent())
    else {
        return;
    };
    let prefix = format!(".{name}.verrou-{pid}-");
    for entry in std::fs::read_dir(folder).into_iter().flatten().flatten() {
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_fifo() {
            let _ = std::fs::remove_file(entry.path());
        } else if kind.is_dir() {
            remove_folder(&entry.path(), 0);
        }
    }
}

/// The folder a mount kept its pipes in: its FIFOs, and the folders of its
/// rounds (closed to everyone, opened first), then it.
fn remove_folder(folder: &Path, depth: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700));
    for inner in std::fs::read_dir(folder).into_iter().flatten().flatten() {
        let Ok(kind) = inner.file_type() else {
            continue;
        };
        if kind.is_fifo() {
            let _ = std::fs::remove_file(inner.path());
        } else if kind.is_dir() && depth < 2 {
            remove_folder(&inner.path(), depth + 1);
        }
    }
    let _ = std::fs::remove_dir(folder);
}

/// What the end of a mount removes: the FIFO, the record, the log.
#[derive(Clone)]
pub struct Cleanup {
    pub fifo: Fifo,
    pub record: PathBuf,
    pub log: Option<PathBuf>,
}

impl Cleanup {
    pub fn run(&self) {
        self.fifo.remove();
        let _ = std::fs::remove_file(&self.record);
        if let Some(log) = &self.log {
            let _ = std::fs::remove_file(log);
        }
    }
}

/// Blocks interrupt, terminate and hang-up in this thread, and so in every
/// thread started after: call it before anything else starts one, and
/// before the FIFO exists, so that no signal can end the process with the
/// FIFO left behind. A signal that arrives meanwhile waits to be taken by
/// [`end_on_signals`].
pub fn block_signals() -> Result<(), String> {
    let mut blocked = SigSet::empty();
    for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        blocked.add(signal);
    }
    blocked.thread_block().map_err(|e| format!("signals: {e}"))
}

/// Starts the thread that waits for the signals [`block_signals`] blocked,
/// and on one removes the FIFO and the record and ends the process.
/// `hang_up_ends`: a mount in a terminal ends when it closes; one that runs
/// in the background does not.
pub fn end_on_signals(cleanup: Cleanup, hang_up_ends: bool) -> Result<(), String> {
    let mut waited = SigSet::empty();
    waited.add(Signal::SIGINT);
    waited.add(Signal::SIGTERM);
    if hang_up_ends {
        waited.add(Signal::SIGHUP);
    }
    std::thread::Builder::new()
        .name("signals".to_owned())
        .spawn(move || {
            loop {
                if waited.wait().is_ok() {
                    cleanup.run();
                    std::process::exit(0);
                }
            }
        })
        .map_err(|e| format!("signals: {e}"))?;
    Ok(())
}

/// The processes that have the pipe open, once the kernel shows them (a
/// moment), and a second look a moment later for one that came in the same
/// instant; excludes this one.
fn find_readers(reads: &Reads, id: Identity) -> Vec<u32> {
    let start = Instant::now();
    let mut found = loop {
        let found = reads.processes().holders(id);
        if !found.is_empty() || start.elapsed() >= FIND_READERS_FOR {
            break found;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !found.is_empty() {
        std::thread::sleep(SETTLE);
        for pid in reads.processes().holders(id) {
            if !found.contains(&pid) {
                found.push(pid);
            }
        }
        found.sort_unstable();
    }
    found
}

/// Programs that have the pipe open now and were not there when the user was
/// asked: they may have read what was written.
pub fn unseen(readers: &[u32], now: &[u32]) -> Vec<u32> {
    now.iter()
        .copied()
        .filter(|pid| !readers.contains(pid))
        .collect()
}

/// What ends the mount when the values may have gone to a program the user
/// was not shown: said by the round that saw it, taken by [`serve`].
type Tainted = Arc<Mutex<Option<String>>>;

/// Serves reads until the process ends: each open of the FIFO gets the
/// values (or the line that says why not), and a new FIFO takes its place.
/// Only returns on an error, which is the reason the mount ended: the last
/// check of a round found a program that was not shown to the user with the
/// pipe open ([`unseen`]) ends it too.
pub fn serve(reads: &Arc<Reads>, fifo: &Fifo) -> Result<(), String> {
    let active = Arc::new(AtomicUsize::new(0));
    let tainted: Tainted = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicBool::new(false));
    let result = serve_rounds(reads, fifo, &active, &tainted, &ended);
    ended.store(true, Ordering::SeqCst);
    result
}

fn taint_of(tainted: &Tainted) -> Option<String> {
    tainted
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn serve_rounds(
    reads: &Arc<Reads>,
    fifo: &Fifo,
    active: &Arc<AtomicUsize>,
    tainted: &Tainted,
    ended: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut failures = 0_u32;
    loop {
        if let Some(reason) = taint_of(tainted) {
            return Err(reason);
        }
        let Accepted {
            mut writer,
            spare,
            id,
        } = fifo.accept()?;
        if let Some(reason) = taint_of(tainted) {
            // Woken by the round that saw it: nothing is written.
            return Err(reason);
        }
        // The next reader finds a new FIFO, and this one has no name: it is
        // looked at by the identity of the writer's descriptor.
        let retired = match fifo.renew() {
            Ok(retired) => {
                failures = 0;
                // The way to the old pipe is closed to everyone until the
                // round has written (and only opened for a moment to wake
                // a reader that is stuck).
                retired.seal();
                retired
            }
            Err(SwapError::Replaced(reason)) => return Err(reason),
            Err(SwapError::Failed(reason)) => {
                failures += 1;
                if failures > MAX_SWAP_FAILURES {
                    return Err(reason);
                }
                eprintln!("verrou: could not prepare the next read ({reason}): trying again");
                let _ = writer.write_all(refusal_line("try again in a moment").as_bytes());
                drop(writer);
                drop(spare);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let readers = find_readers(reads, id);
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_AT_ONCE {
            active.fetch_sub(1, Ordering::SeqCst);
            let line = refusal_line("too many reads at once: try again");
            let _ = writer.write_all(line.as_bytes());
            end_round(reads, id, writer, spare, retired);
            continue;
        }
        let reads = Arc::clone(reads);
        let active = Arc::clone(active);
        let tainted = Arc::clone(tainted);
        let ended = Arc::clone(ended);
        let path = fifo.path().to_owned();
        std::thread::spawn(move || {
            // Named now: a reader that has read its values may be gone.
            let who = super::identify(&readers, reads.processes()).describe(12);
            let again = || reads.processes().holders(id);
            let (payload, served) = reads.reply(&readers, &again);
            let name = reads.mount().file.display().to_string();
            let written = writer
                .write_all(payload.as_bytes())
                .and_then(|()| writer.flush());
            // The last look, with the values in the pipe and the writer still
            // open (so nobody has seen the end of file yet): a program that
            // was not shown to the user has the pipe open.
            let late = if served.is_ok() {
                unseen(&readers, &reads.processes().holders(id))
            } else {
                Vec::new()
            };
            drop(payload);
            end_round(&reads, id, writer, spare, retired);
            if !late.is_empty() {
                let found = super::identify(&late, reads.processes());
                let by = late
                    .iter()
                    .zip(&found.names)
                    .map(|(pid, name)| format!("{name}[{pid}]"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let reason = format!(
                    "the values of {name} may have been read by {by}, which was not the program shown in the approval ({who}). Nothing more is served: check what runs on this machine, then mount again"
                );
                eprintln!("verrou: WARNING: {reason}");
                *tainted.lock().unwrap_or_else(PoisonError::into_inner) = Some(reason);
                wake(&path, &ended);
            }
            match (served, written) {
                (Ok(()), Ok(())) => eprintln!("verrou: {name}: served to {who}"),
                (Ok(()), Err(e)) => {
                    eprintln!(
                        "verrou: {name}: {who} went away before the values were read ({})",
                        describe(&e)
                    );
                }
                (Err(reason), _) => eprintln!("verrou: {name}: not served to {who} ({reason})"),
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Opens the FIFO for reading, again and again until the loop of the mount
/// has noticed that it must end: what it is blocked on is the open for
/// writing, which a reader's open lets through. Nothing is ever read.
fn wake(path: &Path, ended: &AtomicBool) {
    for _ in 0..200 {
        if ended.load(Ordering::SeqCst) {
            return;
        }
        let _ = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The end of a round: the main writer closes, and the second one right
/// after, so that the end of file is signalled twice; then readers still on
/// the old pipe a moment later (the kernel can lose the wake-up when two
/// programs opened it together, and one then waits for ever) get it said once
/// more by a writer opened and closed again through the second name. A
/// reader that is merely slow still has its data first.
fn end_round(reads: &Reads, id: Identity, writer: File, spare: Option<File>, retired: Retired) {
    drop(writer);
    drop(spare);
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(30));
        if reads.processes().holders(id).is_empty() {
            break;
        }
        retired.nudge();
    }
    retired.remove();
}

fn describe(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::BrokenPipe => "broken pipe".to_owned(),
        _ => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn dir() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vfifo-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        found
    }

    #[test]
    fn a_swap_puts_a_new_fifo_in_place_under_names_nobody_can_guess() {
        let folder = dir();
        let path = folder.join(".env");
        let swaps = Arc::new(Mutex::new(Vec::new()));
        let fifo = {
            let swaps = Arc::clone(&swaps);
            Fifo::create(&path, move |here, next| {
                swaps.lock().unwrap().push((here, next));
            })
            .unwrap()
        };
        let first = fifo.current();
        let mut seen = Vec::new();
        for _ in 0..3 {
            let before = fifo.current();
            let retired = fifo.renew().unwrap();
            assert_ne!(fifo.current(), before, "a new FIFO is in place");
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_fifo()
            );
            // The old one has a second name, in a folder of its round inside
            // the mount's folder, random; never beside the file.
            assert_eq!(retired.path.parent().unwrap(), retired.round);
            assert_eq!(retired.round.parent().unwrap(), fifo.hold);
            assert!(!seen.contains(&retired.path));
            seen.push(retired.path.clone());
            assert_eq!(retired.id, before);
            assert_eq!(names(&folder).len(), 2, "{:?}", names(&folder));
            // Sealed: no path leads to it, for a program that opens it; open
            // only for a nudge; and gone with the round.
            retired.seal();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&retired.round), 0);
            assert!(
                open(
                    &retired.path,
                    OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                    Mode::empty()
                )
                .is_err()
            );
            retired.nudge();
            assert_eq!(mode(&retired.round), 0, "closed again after a nudge");
            retired.remove();
        }
        // The record was told of each, before it happened.
        let told = swaps.lock().unwrap().clone();
        assert_eq!(told.len(), 4, "once at the start, then before each swap");
        assert_eq!(told[0], (first, first));
        assert_eq!(told[1].0, first);
        assert_eq!(told[2].0, told[1].1);
        // The folder of the mount's own is private, and nothing is left in
        // it, nor beside the file, but the FIFO.
        let meta = std::fs::metadata(&fifo.hold).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert!(std::fs::read_dir(&fifo.hold).unwrap().next().is_none());
        assert_eq!(names(&folder).len(), 2, "{:?}", names(&folder));
        // The names carry the process and a random part.
        let hold = fifo
            .hold
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(hold.starts_with(&format!("..env.verrou-{}-", std::process::id())));
        assert!(hold.len() > "..env.verrou-1-".len() + 15, "{hold}");
        fifo.remove();
        assert!(names(&folder).is_empty(), "{:?}", names(&folder));
        std::fs::remove_dir_all(&folder).ok();
    }

    #[test]
    fn a_fifo_that_was_replaced_ends_the_mount_and_is_not_overwritten() {
        let folder = dir();
        let path = folder.join(".env");
        let fifo = Fifo::create(&path, |_, _| {}).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "precious").unwrap();
        assert!(matches!(fifo.renew(), Err(SwapError::Replaced(_))));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "precious");
        assert!(
            fifo.accept().is_err(),
            "a file in its place is not written to"
        );
        // Nor a different FIFO.
        std::fs::remove_file(&path).unwrap();
        mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert!(matches!(fifo.renew(), Err(SwapError::Replaced(_))));
        // `remove` leaves what is not its own.
        fifo.remove();
        assert!(path.exists(), "a FIFO that is not ours stays");
        assert_eq!(names(&folder), [".env"], "its own leftovers are gone");
        std::fs::remove_dir_all(&folder).ok();
    }

    #[test]
    fn a_failing_swap_is_a_failure_to_retry_not_the_end() {
        let folder = dir();
        let path = folder.join(".env");
        let fifo = Fifo::create(&path, |_, _| {}).unwrap();
        // The mount's folder is gone: the swap fails, in a way worth trying
        // again (and the next try, with its folder back, works).
        std::fs::remove_dir(&fifo.hold).unwrap();
        assert!(matches!(fifo.renew(), Err(SwapError::Failed(_))));
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        std::fs::create_dir(&fifo.hold).unwrap();
        fifo.renew().unwrap();
        fifo.remove();
        std::fs::remove_dir_all(&folder).ok();
    }

    #[test]
    fn the_writer_is_the_pipe_a_reader_opened_and_a_second_one_with_it() {
        let folder = dir();
        let path = folder.join(".env");
        let fifo = Fifo::create(&path, |_, _| {}).unwrap();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut File::open(reader_path).unwrap(), &mut text)
                .unwrap();
            text
        });
        let mut accepted = fifo.accept().unwrap();
        assert_eq!(accepted.id, fifo.current());
        assert!(accepted.spare.is_some(), "the second writer is open");
        let retired = fifo.renew().unwrap();
        accepted.writer.write_all(b"hello").unwrap();
        drop(accepted.writer);
        // The reader waits for the second writer too.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!reader.is_finished(), "end of file only once both closed");
        drop(accepted.spare);
        assert_eq!(reader.join().unwrap(), "hello");
        // A nudge on a round that is over harms nothing.
        retired.nudge();
        retired.remove();
        fifo.remove();
        std::fs::remove_dir_all(&folder).ok();
    }

    // MARK: Who has the pipe once the values are written

    use crate::env::proc::Processes;
    use crate::env::{Checked, Failure, Mapping, Mount, ReadRequest, Values};
    use std::collections::VecDeque;
    use zeroize::Zeroizing;

    /// Gives `secret` for every reference, whoever asks.
    struct Secret;

    impl Values for Secret {
        fn fetch(&self, request: &ReadRequest) -> Result<Vec<Zeroizing<String>>, Failure> {
            Ok(request
                .references
                .iter()
                .map(|_| Zeroizing::new("s3cret".to_owned()))
                .collect())
        }
        fn check(&self, _: &[crate::run::Reference]) -> Result<Checked, String> {
            Ok(Checked::Verified)
        }
    }

    /// Who has each pipe open, as a script: one list of answers per pipe, in
    /// the order the pipes first come up (the first round's, the second's…).
    /// When a list is used up, nobody has it.
    type Rounds = (Vec<Identity>, Vec<VecDeque<Vec<u32>>>);

    struct Script {
        rounds: Mutex<Rounds>,
    }

    impl Processes for Script {
        fn holders(&self, file: Identity) -> Vec<u32> {
            let mut rounds = self.rounds.lock().unwrap();
            let at = rounds
                .0
                .iter()
                .position(|id| *id == file)
                .unwrap_or_else(|| {
                    rounds.0.push(file);
                    rounds.0.len() - 1
                });
            rounds
                .1
                .get_mut(at)
                .and_then(VecDeque::pop_front)
                .unwrap_or_default()
        }
        fn parent(&self, _: u32) -> Option<u32> {
            None
        }
        fn exe(&self, pid: u32) -> Option<String> {
            Some(
                if pid == 1000 {
                    "/bin/cat"
                } else {
                    "/usr/bin/stranger"
                }
                .to_owned(),
            )
        }
        fn args(&self, _: u32) -> Option<String> {
            None
        }
        fn tty(&self, _: u32) -> Option<String> {
            None
        }
        fn start_time(&self, _: u32) -> Option<u64> {
            None
        }
    }

    fn reads_with(folder: &Path, rounds: Vec<Vec<Vec<u32>>>) -> Arc<Reads> {
        let map = folder.join(".env.verrou");
        std::fs::write(&map, "A=verrou://X/y\n").unwrap();
        let mount = Mount {
            file: folder.join(".env"),
            mapping: Mapping::read(&map).unwrap(),
            map,
            remember_reads: false,
            agent_driven: false,
        };
        let script = Script {
            rounds: Mutex::new((Vec::new(), rounds.into_iter().map(VecDeque::from).collect())),
        };
        Arc::new(Reads::new(mount, Box::new(Secret), Box::new(script)))
    }

    fn read_once(path: &Path) -> String {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut File::open(path).unwrap(), &mut text).unwrap();
        text
    }

    #[test]
    fn what_was_not_shown_is_what_appeared_after_the_question() {
        assert_eq!(unseen(&[1000], &[1000]), Vec::<u32>::new());
        assert_eq!(
            unseen(&[1000, 1001], &[1001]),
            Vec::<u32>::new(),
            "a reader that left"
        );
        assert_eq!(unseen(&[1000], &[]), Vec::<u32>::new());
        assert_eq!(unseen(&[1000], &[1000, 2000, 3000]), [2000, 3000]);
        assert_eq!(unseen(&[], &[7]), [7]);
    }

    #[test]
    fn a_program_that_has_the_pipe_after_the_write_ends_the_mount_loudly() {
        let folder = dir();
        let path = folder.join(".env");
        let fifo = Fifo::create(&path, |_, _| {}).unwrap();
        // First round: the reader alone each time (find, settle, before the
        // write, after it), and none at the end. Second round: another
        // program has the pipe after the values were written.
        let reads = reads_with(
            &folder,
            vec![
                vec![vec![1000], vec![1000], vec![1000], vec![1000]],
                vec![vec![1000], vec![1000], vec![1000], vec![1000, 2000]],
            ],
        );
        let serving = {
            let (reads, fifo) = (Arc::clone(&reads), fifo.clone());
            std::thread::spawn(move || serve(&reads, &fifo))
        };
        // The first round is served and the mount goes on.
        assert!(read_once(&path).contains("A=s3cret"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !serving.is_finished(),
            "a clean round does not end the mount"
        );
        // The second is served too (the values were already in the pipe) and
        // then the mount ends, saying who.
        assert!(read_once(&path).contains("A=s3cret"));
        let ended = serving.join().unwrap().unwrap_err();
        assert!(
            ended.contains("may have been read by stranger[2000]") && ended.contains("mount again"),
            "{ended}"
        );
        assert!(!ended.contains("s3cret"), "{ended}");
        fifo.remove();
        assert!(
            names(&folder).iter().all(|n| n == ".env.verrou"),
            "{:?}",
            names(&folder)
        );
        std::fs::remove_dir_all(&folder).ok();
    }

    #[test]
    fn a_refused_read_does_not_taint_the_mount() {
        // Nobody was served: whoever shows up after the refusal got a
        // comment line and nothing else.
        let folder = dir();
        let path = folder.join(".env");
        let fifo = Fifo::create(&path, |_, _| {}).unwrap();
        // The pipe changed hands before the write: refused ("changed while
        // Verrou was asked"), and a stranger there at the end is no leak.
        let reads = reads_with(
            &folder,
            vec![vec![
                vec![1000],
                vec![1000],
                vec![1000, 2000],
                vec![1000, 2000],
            ]],
        );
        let serving = {
            let (reads, fifo) = (Arc::clone(&reads), fifo.clone());
            std::thread::spawn(move || serve(&reads, &fifo))
        };
        let text = read_once(&path);
        assert!(text.contains("changed while Verrou was asked"), "{text}");
        assert!(!text.contains("s3cret"));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!serving.is_finished());
        // Ended by hand: the next reader (a nobody) gets the next round.
        drop(serving);
        fifo.remove();
        std::fs::remove_dir_all(&folder).ok();
    }
}
