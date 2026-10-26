//! What Verrou keeps on disk between two launches.
//!
//! Nothing there is readable without the master password: the user key is
//! encrypted by their master key (as on the server), the vault cache is the
//! sync response as the server sends it (encrypted), and the refresh token
//! is encrypted by Verrou with the user key. The enrolled security keys
//! (`security-keys.json`) only keep the user key sealed by a secret that
//! never leaves the physical key. Edits made offline (`outbox.json`, see
//! `outbox`) wait there for the server, encrypted as a whole by the user
//! key.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::unlock_keys::EnrolledKey;

const ACCOUNT_FILE: &str = "account.json";
const DEVICE_FILE: &str = "device-id";
/// Security keys enrolled for unlocking (see `unlock_keys`).
pub(crate) const SECURITY_KEYS_FILE: &str = "security-keys.json";
/// Queue of edits made offline (see `outbox`).
const OUTBOX_FILE: &str = "outbox.json";
const OUTBOX_VERSION: u32 = 1;
const FORMAT_VERSION: u32 = 1;
const SECURITY_KEYS_VERSION: u32 = 1;

/// Contents of `security-keys.json`.
#[derive(Serialize, Deserialize)]
struct SecurityKeysFile {
    version: u32,
    keys: Vec<EnrolledKey>,
}

/// Contents of `outbox.json`: the whole queue, encrypted by the user key
/// (`data`). In clear: the account it belongs to and the number of pending
/// edits, to warn before a sign-out without unlocking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OutboxFile {
    pub version: u32,
    pub user_id: String,
    pub pending: u32,
    pub data: String,
}

/// Master password derivation parameters, in a format of Verrou's own: the
/// file doesn't depend on the SDK's serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum KdfSettings {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory: u32,
        parallelism: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub version: u32,
    pub server: String,
    pub email: String,
    pub user_id: String,
    pub kdf: KdfSettings,
    pub salt: String,
    /// The user key, encrypted by the key derived from the password.
    pub wrapped_user_key: String,
    /// The user's RSA private key, encrypted by their key.
    pub private_key: String,
    /// Refresh token, encrypted by the user key.
    pub refresh_token: String,
    /// Unix timestamp of the last successful sync.
    pub synced_at: Option<i64>,
    /// Raw response of `/api/sync`, encrypted by Bitwarden.
    pub sync: Option<String>,
    /// The account's equivalent domains (`/api/settings/domains`, in clear on
    /// the server too); `None`: not read yet.
    #[serde(default)]
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

impl Account {
    pub(crate) fn new_version() -> u32 {
        FORMAT_VERSION
    }
}

/// Inter-process lock (`flock`) for the folder's writes: the iPhone app and
/// its autofill extension share the account folder.
const LOCK_FILE: &str = ".verrou.lock";

/// The account registry a store reports to (see `accounts`): the root, and
/// the tag of the account whose folder this store is.
#[derive(Clone, Debug)]
struct Binding {
    root: PathBuf,
    tag: String,
}

/// An account's folder (in the sandboxed app's container).
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
    /// Set for a store made by `Store::for_account`: saving the account
    /// records it in the registry, signing out takes it out.
    binding: Option<Binding>,
    /// Opened by a process other than the app (iOS autofill extension): the
    /// edit queue belongs to the app, it never touches it (neither sending
    /// nor writing). See `Store::guest`.
    guest: bool,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            binding: None,
            guest: false,
        }
    }

    /// The folder of account `tag` under `root` (`accounts/<tag>`), tied to
    /// the registry: the account enters it when its `account.json` is first
    /// saved (the duplicate check happens then), and leaves it on sign-out.
    /// The device-level files (`device_dir`, `cache_dir`) are the root's.
    pub fn for_account(root: impl Into<PathBuf>, tag: &str) -> Result<Self, Error> {
        let root = root.into();
        let dir = root.join(crate::accounts::ACCOUNTS_DIR);
        if !crate::accounts::valid_tag(tag) {
            return Err(Error::NotFound);
        }
        Ok(Self {
            dir: dir.join(tag),
            binding: Some(Binding {
                root,
                tag: tag.to_owned(),
            }),
            guest: false,
        })
    }

    /// Where the files shared by every account live: the root, or this
    /// folder for a store that isn't tied to a registry (tests, the CLI).
    pub fn device_dir(&self) -> &Path {
        self.binding.as_ref().map_or(&self.dir, |b| &b.root)
    }

    /// Where the public lists downloaded are kept (`cache/` under the root,
    /// or the folder itself without a registry).
    pub fn cache_dir(&self) -> PathBuf {
        self.binding.as_ref().map_or_else(
            || self.dir.clone(),
            |b| b.root.join(crate::accounts::CACHE_DIR),
        )
    }

    /// The account's tag in the registry, if tied to one.
    pub fn tag(&self) -> Option<&str> {
        self.binding.as_ref().map(|b| b.tag.as_str())
    }

    /// The same folder, opened as a guest: by the autofill extension, while
    /// the app may be running. The guest reads the cache and the app's queue
    /// (to show its edits not sent yet), writes directly to the server
    /// (passkeys) then saves the resynced cache; it never sends nor writes
    /// the queue (the app keeps it in memory: rewriting or sending it from
    /// another process would lose or duplicate edits).
    #[must_use]
    pub fn guest(mut self) -> Self {
        self.guest = true;
        self
    }

    pub fn is_guest(&self) -> bool {
        self.guest
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A small device file (settings, usage log), as is; `None` if it
    /// doesn't exist or can't be read.
    pub fn read_file(&self, name: &str) -> Option<Vec<u8>> {
        fs::read(self.dir.join(name)).ok()
    }

    /// Writes a small device file, atomically and readable by the user only.
    /// Allowed for the guest (autofill extension): it is not the edit
    /// queue.
    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        self.write_private(name, data)
    }

    pub fn load_account(&self) -> Result<Option<Account>, Error> {
        let path = self.dir.join(ACCOUNT_FILE);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::storage(e)),
        };
        let account: Account = serde_json::from_slice(&data).map_err(Error::storage)?;
        if account.version != FORMAT_VERSION {
            return Err(Error::Storage(format!(
                "unknown account format {}",
                account.version
            )));
        }
        Ok(Some(account))
    }

    pub fn save_account(&self, account: &Account) -> Result<(), Error> {
        let data = serde_json::to_vec(account).map_err(Error::storage)?;
        // Registry first (root lock, released before the account's own):
        // a second sign-in to the same account is refused before anything is
        // written. A guest only refreshes the cache of a registered account.
        if let (Some(binding), false) = (&self.binding, self.guest) {
            crate::accounts::commit_at(&binding.root, &binding.tag, account)?;
        }
        self.write_private(ACCOUNT_FILE, &data)
    }

    pub fn delete_account(&self) -> Result<(), Error> {
        match fs::remove_file(self.dir.join(ACCOUNT_FILE)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::storage(e)),
        }
        if let (Some(binding), false) = (&self.binding, self.guest) {
            crate::accounts::unregister_at(&binding.root, &binding.tag)?;
        }
        Ok(())
    }

    /// The offline edit queue, as written (encrypted). A file in another
    /// format counts as missing.
    pub(crate) fn load_outbox(&self) -> Result<Option<OutboxFile>, Error> {
        let data = match fs::read(self.dir.join(OUTBOX_FILE)) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::storage(e)),
        };
        Ok(serde_json::from_slice::<OutboxFile>(&data)
            .ok()
            .filter(|f| f.version == OUTBOX_VERSION))
    }

    /// Replaces the queue; empty (`None`), the file is deleted.
    pub(crate) fn save_outbox(&self, file: Option<OutboxFile>) -> Result<(), Error> {
        if self.guest {
            return Ok(());
        }
        let Some(mut file) = file else {
            return self.delete_outbox();
        };
        file.version = OUTBOX_VERSION;
        let data = serde_json::to_vec(&file).map_err(Error::storage)?;
        self.write_private(OUTBOX_FILE, &data)
    }

    pub(crate) fn delete_outbox(&self) -> Result<(), Error> {
        if self.guest {
            return Ok(());
        }
        match fs::remove_file(self.dir.join(OUTBOX_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::storage(e)),
        }
    }

    /// Edits made offline still waiting for the server (readable while the
    /// vault is locked: to warn before a sign-out).
    pub fn pending_changes(&self) -> u32 {
        self.load_outbox().ok().flatten().map_or(0, |f| f.pending)
    }

    /// The security keys enrolled for unlocking (none if the file doesn't
    /// exist).
    pub fn load_security_keys(&self) -> Result<Vec<EnrolledKey>, Error> {
        let data = match fs::read(self.dir.join(SECURITY_KEYS_FILE)) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::storage(e)),
        };
        let file: SecurityKeysFile = serde_json::from_slice(&data).map_err(Error::storage)?;
        if file.version != SECURITY_KEYS_VERSION {
            return Err(Error::Storage(format!(
                "unknown security keys format {}",
                file.version
            )));
        }
        Ok(file.keys)
    }

    /// Replaces the list; an empty list deletes the file.
    pub fn save_security_keys(&self, keys: &[EnrolledKey]) -> Result<(), Error> {
        if keys.is_empty() {
            return self.delete_security_keys();
        }
        let file = SecurityKeysFile {
            version: SECURITY_KEYS_VERSION,
            keys: keys.to_vec(),
        };
        let data = serde_json::to_vec(&file).map_err(Error::storage)?;
        self.write_private(SECURITY_KEYS_FILE, &data)
    }

    pub fn delete_security_keys(&self) -> Result<(), Error> {
        match fs::remove_file(self.dir.join(SECURITY_KEYS_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::storage(e)),
        }
    }

    /// This device's id with the server, created when first needed and kept
    /// afterwards: signing in again doesn't add a new device.
    pub fn device_id(&self) -> Result<String, Error> {
        let path = self.dir.join(DEVICE_FILE);
        if let Ok(id) = fs::read_to_string(&path) {
            let id = id.trim();
            if uuid::Uuid::parse_str(id).is_ok() {
                return Ok(id.to_owned());
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.write_private(DEVICE_FILE, id.as_bytes())?;
        Ok(id)
    }

    /// Small file shared by the app and its extension (conditional passkey
    /// creation, site signals): read, transformed by `change` and rewritten
    /// under the folder lock, so that a write from the other process isn't
    /// lost between the read and the write. `change` returns `None`: the
    /// file is deleted. The lock is only held for this local work, never
    /// during network calls.
    pub fn update_file<T>(
        &self,
        name: &str,
        change: impl FnOnce(Option<Vec<u8>>) -> (Option<Vec<u8>>, T),
    ) -> Result<T, Error> {
        crate::accounts::create_private_dir_all(&self.dir)?;
        let _lock = self.lock()?;
        let target = self.dir.join(name);
        let (data, result) = change(fs::read(&target).ok());
        match data {
            None => match fs::remove_file(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::storage(e)),
            },
            Some(data) => {
                let temp = self.dir.join(format!(".{name}.{}.tmp", std::process::id()));
                let mut options = fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let written = options
                    .open(&temp)
                    .and_then(|mut file| file.write_all(&data).and_then(|()| file.sync_all()))
                    .and_then(|()| fs::rename(&temp, &target));
                if let Err(error) = written {
                    let _ = fs::remove_file(&temp);
                    return Err(Error::storage(error));
                }
            }
        }
        Ok(result)
    }

    /// Atomic write (temporary file then rename), readable by the user only.
    /// The temporary file is specific to the process and to the write, and
    /// the rename happens under the folder lock (`flock`, held a few
    /// milliseconds, never during network calls: iOS terminates a suspended
    /// app that holds a file lock in a shared container). A reader sees the
    /// old file or the new one, never a mix.
    pub(crate) fn write_private(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static WRITES: AtomicU64 = AtomicU64::new(0);
        crate::accounts::create_private_dir_all(&self.dir)?;
        let target = self.dir.join(name);
        let temp = self.dir.join(format!(
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
        let mut file = options.open(&temp).map_err(Error::storage)?;
        let written = file
            .write_all(data)
            .and_then(|()| file.sync_all())
            .map_err(Error::storage)
            .and_then(|()| {
                let _lock = self.lock()?;
                fs::rename(&temp, &target).map_err(Error::storage)
            });
        if written.is_err() {
            let _ = fs::remove_file(&temp);
        }
        written
    }

    /// Exclusive inter-process lock of the folder, released at the end of
    /// the scope (closing the descriptor).
    fn lock(&self) -> Result<DirLock, Error> {
        lock_dir(&self.dir)
    }
}

/// Exclusive inter-process lock (`flock`) of a folder: its `.verrou.lock`.
/// The root's lock guards the registry and the migration; an account's
/// guards its files. Always root first, then account.
pub(crate) fn lock_dir(dir: &Path) -> Result<DirLock, Error> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))
        .map_err(Error::storage)?;
    #[cfg(unix)]
    loop {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(Error::storage(std::io::Error::from(error))),
        }
    }
    Ok(DirLock(file))
}

/// Held lock (`lock_dir`): closing the file releases it.
pub(crate) struct DirLock(#[allow(dead_code)] fs::File);

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!("verrou-store-{}", uuid::Uuid::new_v4()));
        Store::new(dir)
    }

    #[test]
    fn device_id_is_stable() {
        let store = temp_store();
        let first = store.device_id().unwrap();
        assert_eq!(store.device_id().unwrap(), first);
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn account_round_trips_and_is_private() {
        let store = temp_store();
        assert!(store.load_account().unwrap().is_none());
        let account = Account {
            version: FORMAT_VERSION,
            server: "https://vault.exemple.fr".into(),
            email: "camille@exemple.fr".into(),
            user_id: "00000000-0000-0000-0000-000000000000".into(),
            kdf: KdfSettings::Argon2id {
                iterations: 3,
                memory: 64,
                parallelism: 4,
            },
            salt: "camille@exemple.fr".into(),
            wrapped_user_key: "2.a|b|c".into(),
            private_key: "2.d|e|f".into(),
            refresh_token: "2.g|h|i".into(),
            synced_at: Some(1),
            equivalent_domains: None,
            sync: None,
        };
        store.save_account(&account).unwrap();
        let loaded = store.load_account().unwrap().unwrap();
        assert_eq!(loaded.kdf, account.kdf);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(store.dir().join(ACCOUNT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.delete_account().unwrap();
        assert!(store.load_account().unwrap().is_none());
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn concurrent_writers_never_tear_a_file() {
        let store = temp_store();
        let guest = store.clone().guest();
        let writers: Vec<_> = (0..8u8)
            .map(|n| {
                let store = if n % 2 == 0 {
                    store.clone()
                } else {
                    guest.clone()
                };
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        store.write_private("shared.json", &[n; 4096]).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let data = fs::read(store.dir().join("shared.json")).unwrap();
        assert_eq!(data.len(), 4096);
        assert!(data.iter().all(|b| *b == data[0]));
        // No temporary file left behind.
        let leftovers = fs::read_dir(store.dir())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn a_guest_never_writes_the_outbox() {
        let store = temp_store();
        let file = OutboxFile {
            version: 0,
            user_id: "u".into(),
            pending: 2,
            data: "2.a|b|c".into(),
        };
        store.save_outbox(Some(file.clone())).unwrap();
        let guest = store.clone().guest();
        guest.save_outbox(None).unwrap();
        guest.delete_outbox().unwrap();
        guest
            .save_outbox(Some(OutboxFile { pending: 9, ..file }))
            .unwrap();
        assert_eq!(store.pending_changes(), 2);
        assert_eq!(guest.pending_changes(), 2);
        fs::remove_dir_all(store.dir()).unwrap();
    }
}
