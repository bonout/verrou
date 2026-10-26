//! The accounts signed in on this device, and where their files live.
//!
//! ```text
//! <root>                    the folder the apps always used
//!   accounts.json           the registry (mode 600), written last by the
//!                           migration: it marks the migration as done
//!   bridge-clients.json     device level: pairing is per device
//!   remote-approval.json    device level (Mac)
//!   cache/                  public lists downloaded (2fa.directory, passkeys)
//!   .verrou.lock            root lock: registry and migration only
//!   accounts/<tag>/         one folder per account (mode 700):
//!     account.json outbox.json device-id security-keys.json activity.json
//!     usage.json match-rules.json ssh-approvals.json passkey-upgrade.json
//!     passkeys-pending.json credential-signals.json touchid.json
//!     touchid-autofill.json .verrou.lock
//! ```
//!
//! Before this layout, the account's files sat directly in `<root>`.
//! `Registry::open` moves them into `accounts/<tag>/` the first time, under
//! the root lock, so that the app and its `AutoFill` extension (two
//! processes) can both call it, in any order, and exactly one migrates.
//!
//! The migration only ever renames files (same volume, so each rename is
//! atomic), never copies or deletes. It is resumable: `accounts/<tag>/.migrating`
//! says one is in progress, and the next opener continues it. `accounts.json`
//! is written last (temporary file, then rename): that is the commit point.
//! Files it doesn't know are left where they are.
//!
//! A fresh root gets no registry: only the first account saved
//! (`commit`) creates one. The `AutoFill` extension opens the root as a guest
//! (`Registry::open_guest`): on a root that has neither a registry nor a
//! legacy account it creates nothing at all, and it never cleans up.
//!
//! Locks: root first, then an account's, never the other way; none is held
//! during a network call. A root `account.json` that shows up next to
//! `accounts.json` (a downgrade, then an upgrade) is a leftover: when it is
//! the same account as a registered one and newer than the folder's, the
//! folder's files go into `accounts/<tag>/superseded-<stamp>/` (never
//! deleted) and the root's move in; otherwise it stays where it is and is
//! reported in `Registry::notices`, with the count of unsent changes of a
//! root `outbox.json`.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::store::{Account, lock_dir};

/// The registry, at the root.
pub const REGISTRY_FILE: &str = "accounts.json";
/// Folder of the accounts, under the root.
pub const ACCOUNTS_DIR: &str = "accounts";
/// Public lists downloaded, under the root.
pub const CACHE_DIR: &str = "cache";
/// Present in an account folder while the legacy files are being moved in.
const MIGRATING: &str = ".migrating";
const REGISTRY_VERSION: u32 = 1;
/// A folder of a sign-in that never finished is removed after this long.
const PENDING_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// What belongs to an account, in its folder. Moved from the root by the
/// migration; `account.json` goes last so that the root keeps looking like
/// an account until everything else has moved.
pub const ACCOUNT_FILES: [&str; 13] = [
    "outbox.json",
    "device-id",
    "security-keys.json",
    "activity.json",
    "usage.json",
    "match-rules.json",
    "ssh-approvals.json",
    "passkey-upgrade.json",
    "passkeys-pending.json",
    "credential-signals.json",
    // Written by the Swift side (`BiometricVault`): the seal is not bound to
    // a path, so moving the file keeps Touch ID and Face ID working.
    "touchid.json",
    "touchid-autofill.json",
    "account.json",
];

/// Public lists, device level: moved from the root into `cache/`.
pub const CACHE_FILES: [&str; 2] = ["2fa-directory.json", "passkeys-directory.json"];

/// Colors given to accounts in turn (a device-only display setting).
const COLORS: [&str; 6] = ["blue", "green", "orange", "purple", "red", "teal"];

/// One account in the registry. `server`, `email` and `user_id` are copied
/// from `account.json` (which keeps them in clear too), so a lock screen or
/// a switcher can be drawn without reading the large file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Six random lowercase base32 characters, local to this device and not
    /// derived from anything of the account. Names the folder.
    pub tag: String,
    pub server: String,
    pub email: String,
    pub user_id: String,
    /// Device-only display setting, never sent to a server.
    pub label: String,
    /// Device-only display setting, never sent to a server.
    pub color: String,
    /// Unix timestamp.
    pub created: i64,
    pub order: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegistryFile {
    version: u32,
    accounts: Vec<Entry>,
    #[serde(default)]
    default: Option<String>,
}

impl RegistryFile {
    fn empty() -> Self {
        Self {
            version: REGISTRY_VERSION,
            accounts: Vec::new(),
            default: None,
        }
    }
}

/// The registry of one root, as read at `open` (`reload` re-reads it).
#[derive(Debug)]
pub struct Registry {
    root: PathBuf,
    guest: bool,
    file: RegistryFile,
    notices: Vec<String>,
    unsent_legacy_changes: u32,
}

impl Registry {
    /// Opens the root: migrates the legacy single account if needed (under
    /// the root lock), finishes an interrupted migration, removes the folders
    /// of sign-ins that never finished. Safe to call from several processes
    /// at once.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::open_with(root.into(), false, None, SystemTime::now())
    }

    /// The `AutoFill` extension's open: reads the registry as it is. On a
    /// root with neither a registry nor a legacy account it creates nothing
    /// (no folder, no lock file) and returns an empty registry; it never
    /// cleans up and never reconciles leftovers. Only a legacy account (or an
    /// interrupted migration, or a lost registry) makes it take the lock and
    /// do that work.
    pub fn open_guest(root: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::open_with(root.into(), true, None, SystemTime::now())
    }

    fn open_with(
        root: PathBuf,
        guest: bool,
        crash: Option<usize>,
        now: SystemTime,
    ) -> Result<Self, Error> {
        let mut notices = Vec::new();
        let mut unsent = 0;
        let file = open_locked(
            &root,
            guest,
            &mut Steps::new(crash),
            &mut notices,
            &mut unsent,
            now,
        )?;
        for notice in &notices {
            eprintln!("verrou: {notice}");
        }
        Ok(Self {
            root,
            guest,
            file,
            notices,
            unsent_legacy_changes: unsent,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// What `open` found worth reporting: a root `account.json` left by an
    /// older version and kept, how many unsent changes its `outbox.json`
    /// holds, files that exist in both places.
    pub fn notices(&self) -> &[String] {
        &self.notices
    }

    /// Unsent offline changes of an older Verrou's `outbox.json`, left at
    /// the root next to an account that was not superseded (0 if none): the
    /// apps tell the user once.
    pub fn unsent_legacy_changes(&self) -> u32 {
        self.unsent_legacy_changes
    }

    /// The accounts, in display order.
    pub fn list(&self) -> Vec<Entry> {
        let mut list = self.file.accounts.clone();
        list.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.tag.cmp(&b.tag)));
        list
    }

    pub fn entry(&self, tag: &str) -> Option<&Entry> {
        self.file.accounts.iter().find(|e| e.tag == tag)
    }

    pub fn default_tag(&self) -> Option<&str> {
        self.file.default.as_deref()
    }

    /// The default account, or else the first one: the one the apps show
    /// while they show a single account.
    pub fn primary(&self) -> Option<Entry> {
        self.default_tag()
            .and_then(|tag| self.entry(tag).cloned())
            .or_else(|| self.list().into_iter().next())
    }

    /// The folder of an account (it may not exist yet for a sign-in in
    /// progress).
    pub fn account_dir(&self, tag: &str) -> Result<PathBuf, Error> {
        account_dir(&self.root, tag)
    }

    /// Re-reads the registry (another process may have changed it).
    pub fn reload(&mut self) -> Result<(), Error> {
        // Never repairs: only `open` (under the root lock) sets a bad file aside.
        self.file = read_registry(&self.root)?.unwrap_or_else(RegistryFile::empty);
        Ok(())
    }

    /// Folder for an account about to sign in, with its tag. The account only
    /// enters the registry once `account.json` is saved there (`commit`,
    /// which `Store::save_account` calls). A folder left by a sign-out that
    /// still holds this device's `device-id` is reused, so that signing in
    /// again doesn't register a new device with the server.
    pub fn add_pending(&mut self) -> Result<String, Error> {
        create_root(&self.root)?;
        let _lock = lock_dir(&self.root)?;
        let registry = read_registry(&self.root)?.unwrap_or_else(RegistryFile::empty);
        let tag = if let Some(tag) = reusable_folder(&self.root, &registry) {
            tag
        } else {
            let tag = fresh_tag(&self.root, &registry)?;
            create_private_dir(&self.root.join(ACCOUNTS_DIR))?;
            create_private_dir(&self.root.join(ACCOUNTS_DIR).join(&tag))?;
            tag
        };
        self.file = registry;
        Ok(tag)
    }

    /// Records the account of folder `tag` (just saved there), or refreshes
    /// its entry. Refused when another entry has the same server and
    /// `user_id`.
    pub fn commit(&mut self, tag: &str, account: &Account) -> Result<(), Error> {
        self.file = commit_at(&self.root, tag, account)?;
        Ok(())
    }

    /// Takes the account out of the registry and keeps its files (a sign-out:
    /// the folder keeps the device id, see `add_pending`).
    pub fn unregister(&mut self, tag: &str) -> Result<(), Error> {
        self.file = unregister_at(&self.root, tag)?;
        Ok(())
    }

    /// Signs the account out (`logout`: queue, security keys, account) then
    /// removes its entry and its folder. Only files Verrou knows are deleted:
    /// a folder holding anything else is kept, unregistered.
    pub fn remove(&mut self, tag: &str) -> Result<(), Error> {
        let dir = account_dir(&self.root, tag)?;
        if dir.is_dir() {
            let store = crate::Store::new(&dir);
            crate::logout(&store)?;
        }
        self.file = unregister_at(&self.root, tag)?;
        let _lock = lock_dir(&self.root)?;
        remove_known_files(&dir)
    }

    pub fn set_label(&mut self, tag: &str, label: &str) -> Result<(), Error> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 64 {
            return Err(Error::Invalid(
                "the label must be 1 to 64 characters".into(),
            ));
        }
        self.change(tag, |e| label.clone_into(&mut e.label))
    }

    pub fn set_color(&mut self, tag: &str, color: &str) -> Result<(), Error> {
        let color = color.trim();
        if color.is_empty() || color.chars().count() > 16 {
            return Err(Error::Invalid(
                "the color must be 1 to 16 characters".into(),
            ));
        }
        self.change(tag, |e| color.clone_into(&mut e.color))
    }

    pub fn set_order(&mut self, tag: &str, order: u32) -> Result<(), Error> {
        self.change(tag, |e| e.order = order)
    }

    pub fn set_default(&mut self, tag: &str) -> Result<(), Error> {
        let tag = tag.to_owned();
        self.file = mutate(&self.root, |file| {
            if !file.accounts.iter().any(|e| e.tag == tag) {
                return Err(Error::NotFound);
            }
            file.default = Some(tag);
            Ok(())
        })?;
        Ok(())
    }

    fn change(&mut self, tag: &str, apply: impl FnOnce(&mut Entry)) -> Result<(), Error> {
        self.file = mutate(&self.root, |file| {
            let entry = file
                .accounts
                .iter_mut()
                .find(|e| e.tag == tag)
                .ok_or(Error::NotFound)?;
            apply(entry);
            Ok(())
        })?;
        Ok(())
    }

    /// Removes the folders of sign-ins that never finished (no entry, no
    /// `account.json`, untouched for 24 hours), keeping the newest one that
    /// holds a `device-id`. Returns how many were removed.
    pub fn cleanup(&self) -> Result<usize, Error> {
        if self.guest {
            return Ok(0);
        }
        let _lock = lock_dir(&self.root)?;
        let registry = read_registry(&self.root)?.unwrap_or_else(RegistryFile::empty);
        cleanup_pending(&self.root, &registry, SystemTime::now())
    }
}

/// Everything that can fail halfway is a numbered step: tests stop before
/// step `n` to simulate a crash, then check that the next opener resumes.
struct Steps {
    crash: Option<usize>,
    done: usize,
}

impl Steps {
    fn new(crash: Option<usize>) -> Self {
        Self { crash, done: 0 }
    }

    fn next(&mut self) -> Result<(), Error> {
        if self.crash == Some(self.done) {
            return Err(Error::Storage("interrupted (test)".into()));
        }
        self.done += 1;
        Ok(())
    }
}

// MARK: Opening and migration

fn open_locked(
    root: &Path,
    guest: bool,
    steps: &mut Steps,
    notices: &mut Vec<String>,
    unsent: &mut u32,
    now: SystemTime,
) -> Result<RegistryFile, Error> {
    if guest && let Some(file) = guest_shortcut(root)? {
        return Ok(file);
    }
    create_root(root)?;
    let _lock = lock_dir(root)?;
    let registry = read_registry_repairing(root)?;
    let marker = find_marker(root);
    let legacy = root.join("account.json").is_file();
    let mut file = match (registry, marker) {
        (Some(file), None) => file,
        (Some(file), Some(tag)) => {
            // Interrupted between the commit and the removal of the marker:
            // the migration is done, nothing moves any more.
            steps.next()?;
            remove_marker(root, &tag)?;
            file
        }
        (None, Some(tag)) => finish_migration(root, &tag, steps, notices)?,
        (None, None) => {
            if let Some(file) = rebuild_from_folders(root, notices) {
                steps.next()?;
                write_registry(root, &file)?;
                file
            } else if legacy {
                let tag = fresh_tag(root, &RegistryFile::empty())?;
                steps.next()?;
                create_private_dir(&root.join(ACCOUNTS_DIR))?;
                let dir = root.join(ACCOUNTS_DIR).join(&tag);
                create_private_dir(&dir)?;
                steps.next()?;
                write_private(&dir.join(MIGRATING), b"")?;
                finish_migration(root, &tag, steps, notices)?
            } else {
                adopt_device_id(root, steps, notices)?;
                // No registry: the first account saved writes it.
                RegistryFile::empty()
            }
        }
    };
    if !guest {
        if root.join("account.json").is_file() {
            handle_leftovers(root, &mut file, notices, unsent, now)?;
        }
        sweep_cache(root);
        cleanup_pending(root, &file, now)?;
    }
    Ok(file)
}

/// A guest's open when there is nothing to do under the lock: the registry
/// as it is, or an empty one for a root with no registry, no legacy account,
/// no interrupted migration and no account folder (nothing is created).
fn guest_shortcut(root: &Path) -> Result<Option<RegistryFile>, Error> {
    match read_registry_raw(root)? {
        Read::Found(file) => Ok(Some(file)),
        Read::Corrupt => Ok(None),
        Read::Missing => {
            let nothing = !root.join("account.json").is_file()
                && find_marker(root).is_none()
                && account_folders(root).is_empty();
            Ok(nothing.then(RegistryFile::empty))
        }
    }
}

/// Moves the files not moved yet, then writes the registry (the commit
/// point), then removes the marker.
fn finish_migration(
    root: &Path,
    tag: &str,
    steps: &mut Steps,
    notices: &mut Vec<String>,
) -> Result<RegistryFile, Error> {
    move_legacy_files(root, tag, steps, notices)?;
    let dir = root.join(ACCOUNTS_DIR).join(tag);
    let mut file = RegistryFile::empty();
    let entry = entry_from_folder(&dir, tag, 0);
    file.default = Some(tag.to_owned());
    file.accounts.push(entry);
    steps.next()?;
    write_registry(root, &file)?;
    steps.next()?;
    remove_marker(root, tag)?;
    Ok(file)
}

/// The tags of the folders that hold an account, sorted.
fn account_folders(root: &Path) -> Vec<String> {
    let folders = root.join(ACCOUNTS_DIR);
    let mut tags: Vec<String> = fs::read_dir(&folders)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| valid_tag(name) && folders.join(name).join("account.json").is_file())
        .collect();
    tags.sort();
    tags
}

/// A registry that was lost or unreadable: rebuilt from the folders that
/// hold an account (`None` when there is none). Written by the caller.
fn rebuild_from_folders(root: &Path, notices: &mut Vec<String>) -> Option<RegistryFile> {
    let tags = account_folders(root);
    if tags.is_empty() {
        return None;
    }
    let folders = root.join(ACCOUNTS_DIR);
    let mut file = RegistryFile::empty();
    for (order, tag) in tags.iter().enumerate() {
        file.accounts
            .push(entry_from_folder(&folders.join(tag), tag, order as u32));
    }
    notices.push(format!(
        "accounts.json was missing: rebuilt from {} account folder(s)",
        tags.len()
    ));
    file.default = file.accounts.first().map(|e| e.tag.clone());
    Some(file)
}

/// A `device-id` left at the root by a signed-out older version goes into a
/// folder of its own, for the next sign-in to find.
fn adopt_device_id(root: &Path, steps: &mut Steps, notices: &mut Vec<String>) -> Result<(), Error> {
    let device_id = root.join("device-id");
    if device_id.is_file() {
        let folders = root.join(ACCOUNTS_DIR);
        let tag = fresh_tag(root, &RegistryFile::empty())?;
        create_private_dir(&folders)?;
        let dir = folders.join(&tag);
        create_private_dir(&dir)?;
        steps.next()?;
        rename_if_free(&device_id, &dir.join("device-id"), notices)?;
    }
    steps.next()?;
    Ok(())
}

/// A root `account.json` next to a registry: left by an older version run
/// after the update (a downgrade, then an upgrade). The same account as a
/// registered one and newer than the folder's: the folder's conflicting
/// files are set aside in `superseded-<stamp>/` (never deleted) and the
/// root's move in, under the account's lock (root lock held by the caller).
/// Anything else stays where it is, reported.
fn handle_leftovers(
    root: &Path,
    file: &mut RegistryFile,
    notices: &mut Vec<String>,
    unsent: &mut u32,
    now: SystemTime,
) -> Result<(), Error> {
    let root_account = root.join("account.json");
    let value: serde_json::Value = fs::read(&root_account)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or(serde_json::Value::Null);
    let text = |key: &str| value.get(key).and_then(|v| v.as_str()).unwrap_or_default();
    let (server, user_id) = (normalized_server(text("server")), text("user_id"));
    let same = (!user_id.is_empty())
        .then(|| {
            file.accounts.iter().position(|e| {
                normalized_server(&e.server) == server && e.user_id.eq_ignore_ascii_case(user_id)
            })
        })
        .flatten();
    if let Some(index) = same {
        let tag = file.accounts[index].tag.clone();
        let dir = root.join(ACCOUNTS_DIR).join(&tag);
        let modified = |path: PathBuf| fs::metadata(path).and_then(|m| m.modified()).ok();
        let newer = match (
            modified(root_account.clone()),
            modified(dir.join("account.json")),
        ) {
            (Some(root_time), Some(folder_time)) => root_time > folder_time,
            // The folder lost its account (an interrupted swap): finish it.
            (Some(_), None) => true,
            _ => false,
        };
        if newer {
            supersede(root, &dir, now)?;
            let fresh = entry_from_folder(&dir, &tag, file.accounts[index].order);
            let entry = &mut file.accounts[index];
            if !fresh.email.is_empty() && fresh.email != entry.email {
                if entry.label == entry.email {
                    entry.label.clone_from(&fresh.email);
                }
                entry.email = fresh.email;
                write_registry(root, file)?;
            }
            notices.push(
                "an account.json left at the root by an older version replaced the account's \
                 files (the previous ones are in its superseded folder)"
                    .into(),
            );
            return Ok(());
        }
    }
    notices.push(
        "an account.json next to accounts.json was ignored (left by an older version)".into(),
    );
    let pending = fs::read(root.join("outbox.json"))
        .ok()
        .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
        .and_then(|v| v.get("pending").and_then(serde_json::Value::as_u64))
        .unwrap_or(0);
    if pending > 0 {
        *unsent = u32::try_from(pending).unwrap_or(u32::MAX);
        notices.push(format!(
            "{pending} changes from an older Verrou were not sent"
        ));
    }
    Ok(())
}

fn supersede(root: &Path, dir: &Path, now: SystemTime) -> Result<(), Error> {
    create_private_dir_all(dir)?;
    let _lock = lock_dir(dir)?;
    let conflicting: Vec<&str> = ACCOUNT_FILES
        .iter()
        .copied()
        .filter(|name| root.join(name).is_file() && dir.join(name).exists())
        .collect();
    if !conflicting.is_empty() {
        let stamp = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut aside = dir.join(format!("superseded-{stamp}"));
        let mut n = 1;
        while aside.exists() {
            aside = dir.join(format!("superseded-{stamp}-{n}"));
            n += 1;
        }
        create_private_dir(&aside)?;
        // `account.json` is last in the list: until it moves, the folder
        // still holds the account.
        for name in &conflicting {
            fs::rename(dir.join(name), aside.join(name)).map_err(Error::storage)?;
        }
    }
    for name in ACCOUNT_FILES {
        let from = root.join(name);
        if from.is_file() && !dir.join(name).exists() {
            fs::rename(&from, dir.join(name)).map_err(Error::storage)?;
        }
    }
    Ok(())
}

/// Renames the known files of the root into the account folder, under the
/// account's lock (root, then account). A file already there wins: the one
/// at the root stays, reported.
fn move_legacy_files(
    root: &Path,
    tag: &str,
    steps: &mut Steps,
    notices: &mut Vec<String>,
) -> Result<(), Error> {
    let dir = root.join(ACCOUNTS_DIR).join(tag);
    create_private_dir(&dir)?;
    let _lock = lock_dir(&dir)?;
    for name in ACCOUNT_FILES {
        let from = root.join(name);
        if !from.is_file() {
            continue;
        }
        steps.next()?;
        rename_if_free(&from, &dir.join(name), notices)?;
    }
    Ok(())
}

fn rename_if_free(from: &Path, to: &Path, notices: &mut Vec<String>) -> Result<(), Error> {
    if to.exists() {
        notices.push(format!(
            "{} exists in both places: the one at the root was left in place",
            to.file_name().and_then(|n| n.to_str()).unwrap_or("a file")
        ));
        return Ok(());
    }
    fs::rename(from, to).map_err(Error::storage)
}

/// The public lists move from the root into `cache/` (they can be downloaded
/// again, so a failure here is not worth failing the open).
fn sweep_cache(root: &Path) {
    let cache = root.join(CACHE_DIR);
    for name in CACHE_FILES {
        let from = root.join(name);
        if from.is_file() && !cache.join(name).exists() {
            let _ = create_private_dir(&cache);
            let _ = fs::rename(&from, cache.join(name));
        }
    }
}

fn find_marker(root: &Path) -> Option<String> {
    let mut tags: Vec<String> = fs::read_dir(root.join(ACCOUNTS_DIR))
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            valid_tag(name) && root.join(ACCOUNTS_DIR).join(name).join(MIGRATING).exists()
        })
        .collect();
    tags.sort();
    tags.into_iter().next()
}

fn remove_marker(root: &Path, tag: &str) -> Result<(), Error> {
    match fs::remove_file(root.join(ACCOUNTS_DIR).join(tag).join(MIGRATING)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::storage(e)),
    }
}

// MARK: Registry file

enum Read {
    Missing,
    Found(RegistryFile),
    Corrupt,
}

/// The registry as it is on disk. An unknown version is `NewerFormat`
/// (written by a newer Verrou, never touched).
fn read_registry_raw(root: &Path) -> Result<Read, Error> {
    let data = match fs::read(root.join(REGISTRY_FILE)) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Read::Missing),
        Err(e) => return Err(Error::storage(e)),
    };
    match serde_json::from_slice::<RegistryFile>(&data) {
        Ok(file) if file.version == REGISTRY_VERSION => Ok(Read::Found(file)),
        Ok(_) => Err(Error::NewerFormat),
        Err(_) => {
            // A newer version may have changed the shape but not its number:
            // only a readable `version` above ours is "newer".
            let newer = serde_json::from_slice::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| v.get("version").and_then(serde_json::Value::as_u64))
                .is_some_and(|v| v > u64::from(REGISTRY_VERSION));
            if newer {
                Err(Error::NewerFormat)
            } else {
                Ok(Read::Corrupt)
            }
        }
    }
}

/// Reads the registry without ever repairing it: an unreadable file is an
/// error. Only `read_registry_repairing` (called by `open_locked`, under the
/// root lock) sets a bad file aside.
fn read_registry(root: &Path) -> Result<Option<RegistryFile>, Error> {
    match read_registry_raw(root)? {
        Read::Missing => Ok(None),
        Read::Found(file) => Ok(Some(file)),
        Read::Corrupt => Err(Error::Storage(
            "accounts.json is unreadable: restart Verrou to repair it".into(),
        )),
    }
}

/// Under the root lock only: an unreadable registry is set aside (never
/// deleted) and the caller rebuilds from the folders.
fn read_registry_repairing(root: &Path) -> Result<Option<RegistryFile>, Error> {
    match read_registry_raw(root)? {
        Read::Missing => Ok(None),
        Read::Found(file) => Ok(Some(file)),
        Read::Corrupt => {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let aside = root.join(format!("{REGISTRY_FILE}.corrupt-{stamp}"));
            fs::rename(root.join(REGISTRY_FILE), aside).map_err(Error::storage)?;
            Ok(None)
        }
    }
}

fn write_registry(root: &Path, file: &RegistryFile) -> Result<(), Error> {
    let data = serde_json::to_vec_pretty(file).map_err(Error::storage)?;
    write_private(&root.join(REGISTRY_FILE), &data)?;
    // The rename itself survives a crash only once the folder is on disk.
    if let Ok(dir) = fs::File::open(root) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Temporary file, then rename: a reader sees the old file or the new one.
fn write_private(target: &Path, data: &[u8]) -> Result<(), Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let temp = target.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options
        .open(&temp)
        .and_then(|mut file| file.write_all(data).and_then(|()| file.sync_all()))
        .and_then(|()| fs::rename(&temp, target));
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(Error::storage(error));
    }
    Ok(())
}

/// Reads the registry under the root lock, applies `change`, writes it back
/// if it changed, and returns the result.
fn mutate(
    root: &Path,
    change: impl FnOnce(&mut RegistryFile) -> Result<(), Error>,
) -> Result<RegistryFile, Error> {
    create_root(root)?;
    let _lock = lock_dir(root)?;
    let mut file = read_registry(root)?.unwrap_or_else(RegistryFile::empty);
    let before = file.clone();
    change(&mut file)?;
    if file != before {
        write_registry(root, &file)?;
    }
    Ok(file)
}

/// `Store::save_account` calls this before writing `account.json`: the
/// duplicate check, then the entry. Nothing is locked when the entry is
/// already up to date, which is almost every call (each sync saves the
/// account).
pub(crate) fn commit_at(root: &Path, tag: &str, account: &Account) -> Result<RegistryFile, Error> {
    account_dir(root, tag)?;
    if let Ok(Some(file)) = read_registry(root)
        && file
            .accounts
            .iter()
            .any(|e| e.tag == tag && same_identity(e, account))
    {
        return Ok(file);
    }
    mutate(root, |file| {
        if !account.user_id.is_empty()
            && let Some(other) = file.accounts.iter().find(|e| {
                e.tag != tag
                    && normalized_server(&e.server) == normalized_server(&account.server)
                    && e.user_id.eq_ignore_ascii_case(&account.user_id)
            })
        {
            return Err(Error::AlreadySignedIn(other.label.clone()));
        }
        if let Some(entry) = file.accounts.iter_mut().find(|e| e.tag == tag) {
            // The label is the email until the user renames the account.
            if entry.label == entry.email {
                entry.label.clone_from(&account.email);
            }
            entry.server.clone_from(&account.server);
            entry.email.clone_from(&account.email);
            entry.user_id.clone_from(&account.user_id);
        } else {
            let order = file.accounts.iter().map(|e| e.order + 1).max().unwrap_or(0);
            file.accounts.push(Entry {
                tag: tag.to_owned(),
                server: account.server.clone(),
                email: account.email.clone(),
                user_id: account.user_id.clone(),
                label: account.email.clone(),
                color: COLORS[order as usize % COLORS.len()].to_owned(),
                created: unix_now(),
                order,
            });
            if file.default.is_none() {
                file.default = Some(tag.to_owned());
            }
        }
        Ok(())
    })
}

/// `Store::delete_account` (sign-out): the entry goes, the folder stays.
pub(crate) fn unregister_at(root: &Path, tag: &str) -> Result<RegistryFile, Error> {
    account_dir(root, tag)?;
    mutate(root, |file| {
        file.accounts.retain(|e| e.tag != tag);
        if file.default.as_deref() == Some(tag) {
            file.default = file
                .accounts
                .iter()
                .min_by_key(|e| e.order)
                .map(|e| e.tag.clone());
        }
        Ok(())
    })
}

fn same_identity(entry: &Entry, account: &Account) -> bool {
    entry.server == account.server
        && entry.email == account.email
        && entry.user_id == account.user_id
}

fn normalized_server(server: &str) -> String {
    server.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// The entry of a migrated or rebuilt account, from its own `account.json`
/// (the fields the registry copies; an unreadable file gives empty ones, the
/// next `save_account` fills them).
fn entry_from_folder(dir: &Path, tag: &str, order: u32) -> Entry {
    let value: serde_json::Value = fs::read(dir.join("account.json"))
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or(serde_json::Value::Null);
    let text = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let email = text("email");
    Entry {
        tag: tag.to_owned(),
        server: text("server"),
        user_id: text("user_id"),
        label: email.clone(),
        email,
        color: COLORS[order as usize % COLORS.len()].to_owned(),
        created: unix_now(),
        order,
    }
}

// MARK: Folders

/// Tags are 6 characters of `a-z2-7`: anything else never becomes a path.
pub fn valid_tag(tag: &str) -> bool {
    tag.len() == 6 && tag.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn account_dir(root: &Path, tag: &str) -> Result<PathBuf, Error> {
    if !valid_tag(tag) {
        return Err(Error::NotFound);
    }
    Ok(root.join(ACCOUNTS_DIR).join(tag))
}

fn fresh_tag(root: &Path, registry: &RegistryFile) -> Result<String, Error> {
    use rand::Rng as _;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut random = rand::rngs::OsRng;
    for _ in 0..32 {
        let tag: String = (0..6)
            .map(|_| ALPHABET[random.gen_range(0..ALPHABET.len())] as char)
            .collect();
        if !registry.accounts.iter().any(|e| e.tag == tag)
            && !root.join(ACCOUNTS_DIR).join(&tag).exists()
        {
            return Ok(tag);
        }
    }
    Err(Error::Storage("no free account tag".into()))
}

fn create_root(root: &Path) -> Result<(), Error> {
    fs::create_dir_all(root).map_err(Error::storage)
}

/// Creates the folder (and only it) with mode 700.
fn create_private_dir(dir: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::storage(e)),
    }
}

/// Creates the folder and its missing parents, all with mode 700.
pub(crate) fn create_private_dir_all(dir: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(Error::storage)
}

/// Unregistered folders, newest first, with whether they are a sign-in that
/// never finished (no `account.json`, no migration marker).
fn pending_folders(root: &Path, registry: &RegistryFile) -> Vec<(String, SystemTime)> {
    let folders = root.join(ACCOUNTS_DIR);
    let mut found: Vec<(String, SystemTime)> = fs::read_dir(&folders)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let tag = e.file_name().into_string().ok()?;
            let dir = folders.join(&tag);
            let free = valid_tag(&tag)
                && dir.is_dir()
                && !registry.accounts.iter().any(|a| a.tag == tag)
                && !dir.join("account.json").exists()
                && !dir.join(MIGRATING).exists();
            let modified = fs::metadata(&dir).and_then(|m| m.modified()).ok()?;
            free.then_some((tag, modified))
        })
        .collect();
    found.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    found
}

/// The newest abandoned folder that still holds a `device-id`.
fn reusable_folder(root: &Path, registry: &RegistryFile) -> Option<String> {
    pending_folders(root, registry)
        .into_iter()
        .map(|(tag, _)| tag)
        .find(|tag| {
            root.join(ACCOUNTS_DIR)
                .join(tag)
                .join("device-id")
                .is_file()
        })
}

fn cleanup_pending(root: &Path, registry: &RegistryFile, now: SystemTime) -> Result<usize, Error> {
    let keep = reusable_folder(root, registry);
    let mut removed = 0;
    for (tag, modified) in pending_folders(root, registry) {
        let stale = now
            .duration_since(modified)
            .is_ok_and(|age| age >= PENDING_TTL);
        if !stale || keep.as_deref() == Some(tag.as_str()) {
            continue;
        }
        let dir = root.join(ACCOUNTS_DIR).join(&tag);
        remove_known_files(&dir)?;
        if !dir.exists() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Deletes the files Verrou itself puts in an account folder, then the
/// folder if nothing else is in it. Never a recursive delete: an unknown
/// file keeps its folder.
fn remove_known_files(dir: &Path) -> Result<(), Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::storage(e)),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let known = ACCOUNT_FILES.contains(&name.as_str())
            || name == ".verrou.lock"
            || name == MIGRATING
            || (name.starts_with('.')
                && Path::new(&name)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("tmp")));
        if known && entry.path().is_file() {
            fs::remove_file(entry.path()).map_err(Error::storage)?;
        }
    }
    // Fails (and is fine) when something unknown remains.
    let _ = fs::remove_dir(dir);
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests;
