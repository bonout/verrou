//! `verrou env mount`, the real binary, against a real bridge with a fake
//! vault: what a reader of the FIFO gets and what the approval shows, a
//! refusal, two readers at once, what the mount will not do (replace a file,
//! run on a `.env` git would take), and what is left after it ends however
//! it ends. Every FIFO and every process started here is removed, even when
//! a test fails.
#![cfg(unix)]

mod common;

use std::io::Read as _;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use verrou_bridge::Purpose;

use common::{API_TOKEN, Base, GITHUB_PASSWORD, NOTES, SHADOW_VALUE, TWIN_PASSWORD};

const MAP: &str = "TOKEN=verrou://github/password\nKEY=verrou://GitHub/API%20token\nPORT=8080\n";

/// A bridge, a project folder (a git repository that ignores `.env`) and a
/// home folder, all in one temporary folder.
struct World {
    base: Base,
    home: PathBuf,
    work: PathBuf,
}

fn git_works() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

impl World {
    fn new() -> Self {
        let base = Base::new();
        let home = base.dir.join("home");
        let work = base.dir.join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        if git_works() {
            git(&work, &["init", "-q"]);
            std::fs::write(work.join(".gitignore"), ".env\none.env\n").unwrap();
        }
        std::fs::write(work.join(".env.verrou"), MAP).unwrap();
        Self { base, home, work }
    }

    fn env(&self) -> PathBuf {
        self.work.join(".env")
    }

    /// `verrou <args>` in the project folder, as a terminal: the link, the
    /// bridge, and a home folder of its own.
    fn verrou(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_verrou"));
        command
            .args(args)
            .current_dir(&self.work)
            .env("HOME", &self.home)
            .env("VERROU_CLI_CONFIG", &self.base.config_path)
            .env("VERROU_BRIDGE_PORT", self.base.bridge.port().to_string())
            .env_remove("VERROU_AGENT")
            .stdin(Stdio::null());
        command
    }

    /// Runs a `verrou` that ends: its exit status, standard output and error.
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let output = self.verrou(args).output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Starts `verrou env mount` in the foreground and waits for the FIFO.
    fn mount(&mut self, extra: &[&str]) -> Mount {
        let mut args = vec!["env", "mount"];
        args.extend_from_slice(extra);
        let mut child = self
            .verrou(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let said = Arc::new(Mutex::new(String::new()));
        let mut pipes = Vec::new();
        for mut stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let said = Arc::clone(&said);
            pipes.push(std::thread::spawn(move || {
                let mut buffer = [0_u8; 1024];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    said.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
            }));
        }
        // Up: its record is there, and its file is a FIFO (an old one, left
        // by a mount that was killed, does not count).
        let pid = child.id();
        let up = wait_for(|| {
            recorded(&self.home)
                .iter()
                .any(|(file, p)| u32::try_from(*p) == Ok(pid) && is_fifo(Path::new(file)))
                || child.try_wait().unwrap().is_some()
        });
        assert!(up, "the mount did not come up: {}", said.lock().unwrap());
        assert!(
            child.try_wait().unwrap().is_none(),
            "the mount ended: {}",
            said.lock().unwrap()
        );
        Mount { child, said, pipes }
    }

    fn secrets_in_the_folder(&self) {
        // No regular file of the project (or of the home folder) holds a
        // value: the FIFO holds none and is not read here.
        for root in [&self.work, &self.home] {
            for path in files_under(root) {
                let text = std::fs::read(&path).unwrap_or_default();
                let text = String::from_utf8_lossy(&text);
                for secret in [GITHUB_PASSWORD, API_TOKEN, SHADOW_VALUE, NOTES] {
                    assert!(
                        !text.contains(secret),
                        "{} holds a secret value",
                        path.display()
                    );
                }
            }
        }
    }

    fn finish(self) {
        // A background mount is not our child: its record says who it is.
        for (_, pid) in recorded(&self.home) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        std::fs::remove_dir_all(&self.base.dir).ok();
    }
}

/// A mount in the foreground; ended with SIGTERM when dropped, so that a
/// failing test leaves nothing behind.
struct Mount {
    child: Child,
    said: Arc<Mutex<String>>,
    /// The threads that collect what it says; done when it has ended.
    pipes: Vec<std::thread::JoinHandle<()>>,
}

impl Mount {
    fn said(&self) -> String {
        self.said.lock().unwrap().clone()
    }

    /// Ends it as `unmount` or Ctrl-C would, and waits.
    fn terminate(&mut self) {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).unwrap());
        kill(pid, Signal::SIGTERM).unwrap();
        let status = self.child.wait().unwrap();
        assert!(status.success(), "{status:?}");
        for pipe in self.pipes.drain(..) {
            pipe.join().unwrap();
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = kill(
                Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
                Signal::SIGTERM,
            );
            let _ = self.child.wait();
        }
    }
}

fn is_fifo(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_fifo())
}

fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                found.push(entry.path());
            }
        }
    }
    found
}

/// The records of the mounts of a home folder: (file, process).
fn recorded(home: &Path) -> Vec<(String, i32)> {
    let dir = home.join(".verrou/env");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry.path().extension().is_some_and(|e| e == "json") {
            let record: Value =
                serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
            found.push((
                record["file"].as_str().unwrap().to_owned(),
                i32::try_from(record["pid"].as_u64().unwrap()).unwrap(),
            ));
        }
    }
    found
}

/// What a program that reads the file gets: `cat`, which waits at most
/// twenty seconds.
fn read(path: &Path) -> String {
    let mut child = Command::new("cat")
        .arg(path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        let _ = sender.send(text);
    });
    if let Ok(text) = receiver.recv_timeout(Duration::from_secs(20)) {
        let _ = child.wait();
        text
    } else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the read of {} never ended", path.display());
    }
}

#[test]
fn a_reader_gets_the_values_and_the_approval_names_the_file_and_the_reader() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    assert!(is_fifo(&world.env()), "the file is a FIFO, not a file");

    let text = read(&world.env());
    assert!(text.starts_with("# Served by Verrou"), "{text}");
    assert!(
        text.contains(&format!("TOKEN={GITHUB_PASSWORD}\n")),
        "{text}"
    );
    assert!(text.contains(&format!("KEY={API_TOKEN}\n")), "{text}");
    assert!(text.contains("PORT=8080\n"), "{text}");
    // The shadow field labelled "password" is not what `password` means.
    assert!(!text.contains(SHADOW_VALUE));
    assert!(
        is_fifo(&world.env()),
        "a new FIFO is waiting for the next reader"
    );

    {
        let asked = world.base.backend.asked.lock().unwrap();
        assert_eq!(asked.len(), 2, "one approval per reference");
        for confirmation in asked.iter() {
            assert_eq!(confirmation.purpose, Purpose::Reveal);
            assert_eq!(confirmation.item, "github");
            // Who opens which file, and the variables served.
            assert!(
                confirmation.command.starts_with("read "),
                "{}",
                confirmation.command
            );
            // (An agent above this test run is named first: `by agent
            // ancestor: …; cat[…`.)
            assert!(
                confirmation.command.contains(".env by ") && confirmation.command.contains("cat["),
                "{}",
                confirmation.command
            );
            assert!(
                confirmation
                    .fields
                    .contains("TOKEN=verrou://github/password"),
                "{}",
                confirmation.fields
            );
            assert!(
                confirmation
                    .fields
                    .contains("KEY=verrou://GitHub/API%20token"),
                "{}",
                confirmation.fields
            );
            // A variable served as written is listed too, by name.
            assert!(
                confirmation.fields.contains("PORT=(plain)"),
                "{}",
                confirmation.fields
            );
            // Run by a program with no terminal: asked on its own.
            assert!(confirmation.ephemeral);
        }
    }

    // Another reader, another round.
    assert!(read(&world.env()).contains("PORT=8080"));
    assert_eq!(world.base.asked(), 4);
    world.secrets_in_the_folder();

    mount.terminate();
    assert!(
        !world.env().exists(),
        "the FIFO is removed when the mount ends"
    );
    assert!(recorded(&world.home).is_empty(), "and so is its record");
    // Nothing it used while swapping FIFOs is left in the folder either.
    let leftovers: Vec<String> = std::fs::read_dir(&world.work)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("..env.verrou-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let said = mount.said();
    for secret in [
        GITHUB_PASSWORD,
        API_TOKEN,
        SHADOW_VALUE,
        NOTES,
        TWIN_PASSWORD,
    ] {
        assert!(!said.contains(secret), "the mount said a value: {said}");
    }
    assert!(
        said.contains("served to ") && said.contains("cat["),
        "{said}"
    );
    world.finish();
}

#[test]
fn a_refused_read_gets_a_comment_and_the_next_ones_wait_without_asking() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    world.base.backend.refuse.store(true, Ordering::SeqCst);
    let text = read(&world.env());
    assert!(text.starts_with("# verrou: not served ("), "{text}");
    assert_eq!(text.lines().count(), 1, "{text}");
    for secret in [GITHUB_PASSWORD, API_TOKEN, "8080"] {
        assert!(!text.contains(secret), "{text}");
    }
    let asked = world.base.asked();
    assert!(asked >= 1);

    // Even if the user would say yes now, the pause holds, and nothing is asked.
    world.base.backend.refuse.store(false, Ordering::SeqCst);
    let again = read(&world.env());
    assert!(again.contains("a moment ago"), "{again}");
    assert!(!again.contains(GITHUB_PASSWORD));
    assert_eq!(world.base.asked(), asked);
    mount.terminate();
    world.finish();
}

#[test]
fn two_readers_at_once_are_each_asked_and_each_get_the_values() {
    let mut world = World::new();
    std::fs::write(
        world.work.join("one.verrou"),
        "ONLY=verrou://github/password\n",
    )
    .unwrap();
    let mut mount = world.mount(&["--file", "one.env", "--map", "one.verrou"]);
    // Both open the FIFO before either is served.
    let path = world.work.join("one.env");
    let (first, second) = (path.clone(), path);
    let one = std::thread::spawn(move || read(&first));
    let two = std::thread::spawn(move || read(&second));
    let (one, two) = (one.join().unwrap(), two.join().unwrap());
    for text in [&one, &two] {
        // A reader that lost the race to a pipe shared by two may get
        // nothing at all (the other process got it): but each approval
        // was for one process, so what is served is whole.
        assert!(
            text.is_empty() || text.contains(&format!("ONLY={GITHUB_PASSWORD}\n")),
            "{text}"
        );
    }
    assert!(
        one.contains(GITHUB_PASSWORD) || two.contains(GITHUB_PASSWORD),
        "someone got the value"
    );
    assert!(world.base.asked() >= 1);
    // Whatever came of it, the next read works and asks again.
    let before = world.base.asked();
    assert!(read(&world.work.join("one.env")).contains(GITHUB_PASSWORD));
    assert_eq!(world.base.asked(), before + 1);
    mount.terminate();
    assert!(!world.work.join("one.env").exists());
    world.finish();
}

#[test]
fn a_file_git_tracks_or_does_not_ignore_is_refused() {
    if !git_works() {
        eprintln!("git is not installed: skipped");
        return;
    }
    let world = World::new();
    // Not ignored.
    std::fs::write(world.work.join(".gitignore"), "something-else\n").unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("does not ignore .env"), "{error}");
    assert!(error.contains(">> .gitignore"), "{error}");
    assert!(!world.env().exists(), "nothing was created");
    // Tracked: whatever .gitignore says.
    std::fs::write(world.work.join(".gitignore"), ".env\n").unwrap();
    std::fs::write(world.env(), "PORT=1\n").unwrap();
    git(&world.work, &["add", "-f", ".env"]);
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("git tracks .env"), "{error}");
    assert_eq!(std::fs::read_to_string(world.env()).unwrap(), "PORT=1\n");
    world.finish();
}

#[test]
fn outside_a_repository_the_mount_works_with_a_warning() {
    let mut world = World::new();
    let loose = world.base.dir.join("loose");
    std::fs::create_dir_all(&loose).unwrap();
    std::fs::write(loose.join(".env.verrou"), MAP).unwrap();
    let file = loose.join(".env");
    let mut mount = world.mount(&[
        "--file",
        file.to_str().unwrap(),
        "--map",
        loose.join(".env.verrou").to_str().unwrap(),
    ]);
    assert!(is_fifo(&file));
    assert!(read(&file).contains("PORT=8080"));
    mount.terminate();
    let said = mount.said();
    assert!(said.contains("not in a git repository"), "{said}");
    assert!(!file.exists());
    world.finish();
}

#[test]
fn a_file_a_link_or_a_folder_in_the_way_is_never_replaced() {
    let world = World::new();
    // A file with a secret in it: it stays, as it was.
    std::fs::write(world.env(), "OLD=precious\n").unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("already exists and is a file"), "{error}");
    assert_eq!(
        std::fs::read_to_string(world.env()).unwrap(),
        "OLD=precious\n"
    );
    std::fs::remove_file(world.env()).unwrap();
    // A link, even to nowhere.
    std::os::unix::fs::symlink(world.work.join("elsewhere"), world.env()).unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("a link"), "{error}");
    assert!(!world.work.join("elsewhere").exists());
    std::fs::remove_file(world.env()).unwrap();
    // A folder.
    std::fs::create_dir(world.env()).unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("a folder"), "{error}");
    std::fs::remove_dir(world.env()).unwrap();
    // A FIFO that is not Verrou's.
    nix::unistd::mkfifo(&world.env(), nix::sys::stat::Mode::S_IRWXU).unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("did not make"), "{error}");
    assert!(is_fifo(&world.env()));
    std::fs::remove_file(world.env()).unwrap();
    // A map that is not there, or that names nothing.
    let (ok, _, error) = world.run(&["env", "mount", "--map", "nothing.verrou"]);
    assert!(!ok && error.contains("the map is not there"), "{error}");
    std::fs::write(world.work.join("plain.verrou"), "PORT=1\n").unwrap();
    let (ok, _, error) = world.run(&["env", "mount", "--map", "plain.verrou"]);
    assert!(!ok && error.contains("nothing to serve"), "{error}");
    // A reference to a field the item does not have.
    std::fs::write(
        world.work.join("typo.verrou"),
        "A=verrou://GitHub/passwrd\n",
    )
    .unwrap();
    let (ok, _, error) = world.run(&["env", "mount", "--map", "typo.verrou"]);
    assert!(!ok && error.contains("has no field \"passwrd\""), "{error}");
    assert!(!world.env().exists());
    world.finish();
}

#[test]
fn sigterm_cleans_up_and_a_killed_mount_is_found_stale_then_cleaned() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    assert_eq!(recorded(&world.home).len(), 1);
    // `status` sees it, and refuses a second mount of the same file.
    let (ok, out, _) = world.run(&["env", "status", "--json"]);
    assert!(ok);
    let status: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status[0]["state"], "mounted");
    assert!(status[0]["file"].as_str().unwrap().ends_with("/.env"));
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok && error.contains("already mounted"), "{error}");
    mount.terminate();
    assert!(!world.env().exists());
    assert_eq!(recorded(&world.home).len(), 0);

    // Killed without a chance to clean up: the FIFO and the record stay (and
    // the record knows the FIFO of the round that was waiting, not the first).
    let mut mount = world.mount(&[]);
    assert!(read(&world.env()).contains("PORT=8080"));
    mount.child.kill().unwrap();
    mount.child.wait().unwrap();
    assert!(is_fifo(&world.env()));
    let (_, out, _) = world.run(&["env", "status", "--json"]);
    let status: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status[0]["state"], "stale");
    let (_, text, _) = world.run(&["env", "status"]);
    assert!(text.starts_with("stale  "), "{text}");
    // Unmount cleans it up.
    let (ok, out, error) = world.run(&["env", "unmount"]);
    assert!(ok, "{error}");
    assert!(out.contains("cleaned up"), "{out}");
    assert!(!world.env().exists() && recorded(&world.home).is_empty());

    // Or a new mount takes the place of the dead one.
    let mut mount = world.mount(&[]);
    mount.child.kill().unwrap();
    mount.child.wait().unwrap();
    let mut mount = world.mount(&[]);
    assert!(read(&world.env()).contains("PORT=8080"));
    mount.terminate();
    assert!(!world.env().exists());
    // Nothing is mounted any more.
    let (ok, out, _) = world.run(&["env", "status"]);
    assert!(ok && out.contains("No .env file is mounted"), "{out}");
    let (ok, _, error) = world.run(&["env", "unmount"]);
    assert!(!ok && error.contains("is not mounted"), "{error}");
    world.finish();
}

#[test]
fn an_edited_map_is_not_served_until_it_is_mounted_again() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    // The map asks for one more secret after the mount.
    std::fs::write(
        world.work.join(".env.verrou"),
        format!("{MAP}EXTRA=verrou://Deploy%20key/password\n"),
    )
    .unwrap();
    let text = read(&world.env());
    assert!(text.contains("the map changed since the mount"), "{text}");
    assert!(!text.contains(GITHUB_PASSWORD));
    assert_eq!(world.base.asked(), 0, "nothing was asked");
    mount.terminate();
    // Mounted again, the new map is the one in force.
    let mut mount = world.mount(&[]);
    let text = read(&world.env());
    assert!(text.contains("EXTRA="), "{text}");
    mount.terminate();
    world.finish();
}

#[test]
fn a_background_mount_serves_and_unmount_ends_it() {
    let world = World::new();
    let (ok, _, error) = world.run(&["env", "mount", "--background"]);
    assert!(ok, "{error}");
    assert!(error.contains("in the background"), "{error}");
    assert!(is_fifo(&world.env()));
    let records = recorded(&world.home);
    assert_eq!(records.len(), 1);
    let pid = records[0].1;

    assert!(read(&world.env()).contains(&format!("TOKEN={GITHUB_PASSWORD}")));
    let (_, out, _) = world.run(&["env", "status"]);
    assert!(out.starts_with("mounted  "), "{out}");

    let (ok, out, error) = world.run(&["env", "unmount", "--all"]);
    assert!(ok, "{error}");
    assert!(out.contains("unmounted"), "{out}");
    assert!(!world.env().exists());
    // The process is gone (a zombie only if its parent had not reaped it).
    assert!(
        wait_for(|| kill(Pid::from_raw(pid), None).is_err()),
        "the background mount is still running"
    );
    assert_eq!(recorded(&world.home).len(), 0);
    // A background mount that cannot start says why, and leaves nothing.
    std::fs::write(world.env(), "x\n").unwrap();
    let (ok, _, error) = world.run(&["env", "mount", "--background"]);
    assert!(!ok && error.contains("already exists"), "{error}");
    world.finish();
}

#[test]
fn a_negated_ignore_rule_does_not_ignore_the_file() {
    if !git_works() {
        eprintln!("git is not installed: skipped");
        return;
    }
    let world = World::new();
    // `.env` is ignored, then un-ignored: `git add -A` would take it. The
    // rule that says so makes `check-ignore -v` answer 0 all the same.
    std::fs::write(world.work.join(".gitignore"), ".env\n!.env\n").unwrap();
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok);
    assert!(error.contains("does not ignore .env"), "{error}");
    assert!(!world.env().exists(), "nothing was created");
    world.finish();
}

#[test]
fn detached_is_only_for_the_background_start() {
    let world = World::new();
    // By hand, with nothing, or with a token that is made up.
    let (ok, _, error) = world.run(&["env", "mount", "--detached"]);
    assert!(
        !ok && error.contains("not an option to use by hand"),
        "{error}"
    );
    assert!(!world.env().exists());
    let output = world
        .verrou(&["env", "mount", "--detached"])
        .env("VERROU_ENV_DETACH_TOKEN", "0".repeat(32))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!world.env().exists());
    // With a token in the environment and a different one in the file.
    let dir = world.home.join(".verrou/env");
    std::fs::create_dir_all(&dir).unwrap();
    let id = {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(world.env().as_os_str().as_encoded_bytes());
        data_encoding::HEXLOWER.encode(&digest)[..16].to_owned()
    };
    // The folder of the project is canonical (`/private/var` on macOS), so
    // the file the mount looks at is the canonical one.
    let canonical = std::fs::canonicalize(&world.work).unwrap().join(".env");
    let id = if canonical == world.env() {
        id
    } else {
        use sha2::{Digest as _, Sha256};
        data_encoding::HEXLOWER.encode(&Sha256::digest(canonical.as_os_str().as_encoded_bytes()))
            [..16]
            .to_owned()
    };
    std::fs::write(dir.join(format!("{id}.token")), "1".repeat(32)).unwrap();
    let output = world
        .verrou(&["env", "mount", "--detached"])
        .env("VERROU_ENV_DETACH_TOKEN", "2".repeat(32))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!world.env().exists());
    world.finish();
}

#[test]
fn a_map_that_is_a_pipe_or_a_link_is_refused_at_once() {
    let world = World::new();
    nix::unistd::mkfifo(
        &world.work.join("pipe.verrou"),
        nix::sys::stat::Mode::S_IRWXU,
    )
    .unwrap();
    let (ok, _, error) = world.run(&["env", "mount", "--map", "pipe.verrou"]);
    assert!(!ok && error.contains("regular file"), "{error}");
    std::os::unix::fs::symlink(
        world.work.join(".env.verrou"),
        world.work.join("link.verrou"),
    )
    .unwrap();
    let (ok, _, error) = world.run(&["env", "mount", "--map", "link.verrou"]);
    assert!(!ok, "{error}");
    assert!(!world.env().exists());
    world.finish();
}

#[test]
fn the_records_folder_is_private_even_if_it_was_not() {
    use std::os::unix::fs::PermissionsExt as _;
    let mut world = World::new();
    let dir = world.home.join(".verrou/env");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut mount = world.mount(&[]);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    let records: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
    assert!(!records.is_empty());
    for record in records {
        assert_eq!(mode(&record.path()), 0o600, "{}", record.path().display());
    }
    mount.terminate();
    // No temporary file of the record is left.
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.is_empty(), "{names:?}");
    world.finish();
}

#[test]
fn a_fifo_that_the_mount_did_not_make_is_left_alone_when_it_is_stale() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    mount.child.kill().unwrap();
    mount.child.wait().unwrap();
    // The dead mount's FIFO is replaced by another FIFO, someone else's.
    std::fs::remove_file(world.env()).unwrap();
    nix::unistd::mkfifo(&world.env(), nix::sys::stat::Mode::S_IRWXU).unwrap();
    let (ok, out, error) = world.run(&["env", "unmount"]);
    assert!(ok, "{error}");
    assert!(out.contains("did not make"), "{out}");
    assert!(is_fifo(&world.env()), "it was left alone");
    assert!(recorded(&world.home).is_empty(), "the record is gone");
    // A new mount does not take its place either.
    let (ok, _, error) = world.run(&["env", "mount"]);
    assert!(!ok && error.contains("did not make"), "{error}");
    std::fs::remove_file(world.env()).unwrap();
    world.finish();
}

#[test]
fn the_reader_is_found_by_the_pipe_it_holds_not_by_the_name_it_used() {
    let mut world = World::new();
    let mut mount = world.mount(&[]);
    // A second name for the very FIFO that is waiting.
    let alias = world.work.join("alias.txt");
    std::fs::hard_link(world.env(), &alias).unwrap();
    let text = read(&alias);
    assert!(
        text.contains(&format!("TOKEN={GITHUB_PASSWORD}\n")),
        "{text}"
    );
    {
        let asked = world.base.backend.asked.lock().unwrap();
        assert!(asked[0].command.contains("cat["), "{}", asked[0].command);
    }
    std::fs::remove_file(&alias).unwrap();
    mount.terminate();
    world.finish();
}

/// Does this test run have a controlling terminal?
fn has_a_tty() -> bool {
    let output = Command::new("ps")
        .args(["-o", "tty=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    let tty = String::from_utf8_lossy(&output.stdout);
    !matches!(tty.trim(), "" | "?" | "??")
}

#[test]
fn every_read_is_asked_by_default_and_remembering_needs_a_terminal() {
    let mut world = World::new();
    // The default: asked on its own, every time, nothing remembered.
    let mut mount = world.mount(&[]);
    let (_, out, _) = world.run(&["env", "status", "--json"]);
    let status: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status[0]["remember_reads"], false);
    let (_, text, _) = world.run(&["env", "status"]);
    assert!(text.contains("asks on every read"), "{text}");
    for _ in 0..2 {
        assert!(read(&world.env()).contains("PORT=8080"));
    }
    {
        let asked = world.base.backend.asked.lock().unwrap();
        assert_eq!(asked.len(), 4);
        assert!(asked.iter().all(|c| c.ephemeral));
    }
    mount.terminate();

    // With `--remember-reads`: a reader with no terminal (a test run, a
    // daemon, a script) is still asked every time.
    world.base.backend.asked.lock().unwrap().clear();
    let mut mount = world.mount(&["--remember-reads"]);
    let (_, out, _) = world.run(&["env", "status", "--json"]);
    let status: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status[0]["remember_reads"], true);
    let (_, text, _) = world.run(&["env", "status"]);
    assert!(text.contains("remembers"), "{text}");
    for _ in 0..2 {
        assert!(read(&world.env()).contains("PORT=8080"));
    }
    if has_a_tty() {
        // Run from a terminal, `cat` has one: what is remembered is then
        // up to the unit tests (a test run cannot be told from a person).
        eprintln!("this run has a terminal: the remembering is not checked here");
    } else {
        let asked = world.base.backend.asked.lock().unwrap();
        assert_eq!(asked.len(), 4);
        assert!(asked.iter().all(|c| c.ephemeral));
    }
    mount.terminate();
    // The old flag is gone.
    let (ok, _, error) = world.run(&["env", "mount", "--ask-every-read"]);
    assert!(!ok && error.contains("--ask-every-read"), "{error}");
    world.finish();
}
