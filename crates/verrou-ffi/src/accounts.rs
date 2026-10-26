//! The accounts signed in on this device (`verrou_vaultwarden::accounts`).
//!
//! `Accounts::open(root)` is the first thing every process does with the
//! folder the apps always used (the app, the `AutoFill` extension, the Mac
//! `AutoFill` extension): it migrates the legacy single account under the
//! root lock, so whichever process runs first after an update does it, once.
//! The apps then ask for the session of an account by its tag; each session
//! is rooted at `accounts/<tag>`.
//!
//! The apps still show a single account (`primary_tag`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use verrou_vaultwarden::Store;
use verrou_vaultwarden::accounts::{Entry, Registry};

use crate::{VaultSession, VerrouError};

/// An account of the registry: enough to draw a lock screen or a switcher
/// without reading the account's (large) file. The label and the color are
/// local display settings.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AccountEntry {
    pub tag: String,
    pub server: String,
    pub email: String,
    pub user_id: String,
    pub label: String,
    pub color: String,
    /// Unix timestamp.
    pub created: i64,
    pub order: u32,
    pub is_default: bool,
}

/// The registry of one root, and the sessions opened on its accounts.
#[derive(uniffi::Object)]
pub struct Accounts {
    guest: bool,
    registry: Mutex<Registry>,
    sessions: Mutex<HashMap<String, Arc<VaultSession>>>,
}

impl Accounts {
    fn new(root: String, guest: bool) -> Result<Arc<Self>, VerrouError> {
        let root = PathBuf::from(root);
        let registry = if guest {
            Registry::open_guest(root)?
        } else {
            Registry::open(root)?
        };
        Ok(Arc::new(Self {
            guest,
            registry: Mutex::new(registry),
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// The registry, re-read: another process (the app, the extension) may
    /// have changed it.
    fn fresh(&self) -> Result<std::sync::MutexGuard<'_, Registry>, VerrouError> {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry.reload()?;
        Ok(registry)
    }
}

#[uniffi::export]
impl Accounts {
    /// Opens the root folder, migrating the legacy account if needed.
    #[uniffi::constructor]
    pub fn open(root: String) -> Result<Arc<Self>, VerrouError> {
        Self::new(root, false)
    }

    /// The `AutoFill` extension's view: the same registry (and the same
    /// migration of a legacy account, which the extension may be the first
    /// to run), sessions opened as a guest. On a root with neither a registry
    /// nor a legacy account it creates nothing, and it never creates a folder
    /// for a new sign-in or cleans up.
    #[uniffi::constructor]
    pub fn for_autofill(root: String) -> Result<Arc<Self>, VerrouError> {
        Self::new(root, true)
    }

    /// The accounts, in display order.
    pub fn list(&self) -> Result<Vec<AccountEntry>, VerrouError> {
        let registry = self.fresh()?;
        let default = registry.default_tag().map(str::to_owned);
        Ok(registry
            .list()
            .into_iter()
            .map(|e| entry(e, default.as_deref()))
            .collect())
    }

    pub fn default_tag(&self) -> Result<Option<String>, VerrouError> {
        Ok(self.fresh()?.default_tag().map(str::to_owned))
    }

    /// The account the apps show while they show a single one: the default
    /// account, or else the first. Without any, the app gets the tag of a
    /// folder to sign in to (the account enters the registry when its
    /// sign-in saves it); the extension gets `None`.
    pub fn primary_tag(&self) -> Result<Option<String>, VerrouError> {
        let mut registry = self.fresh()?;
        if let Some(primary) = registry.primary() {
            return Ok(Some(primary.tag));
        }
        if self.guest {
            return Ok(None);
        }
        Ok(Some(registry.add_pending()?))
    }

    /// The folder of an account (for the files the Swift side keeps in it:
    /// the Touch ID and Face ID seals).
    pub fn directory(&self, tag: String) -> Result<String, VerrouError> {
        let dir = self.fresh()?.account_dir(&tag)?;
        Ok(dir.to_string_lossy().into_owned())
    }

    /// The session of an account (the same object each time).
    pub fn session(&self, tag: String) -> Result<Arc<VaultSession>, VerrouError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(session) = sessions.get(&tag) {
            return Ok(Arc::clone(session));
        }
        let root = self
            .registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .root()
            .to_path_buf();
        let store = Store::for_account(root, &tag)?;
        let session = VaultSession::with_store(if self.guest { store.guest() } else { store });
        sessions.insert(tag, Arc::clone(&session));
        Ok(session)
    }

    /// Unsent offline changes an older Verrou left in a root `outbox.json`
    /// (0 if none): the apps tell the user once.
    pub fn unsent_legacy_changes(&self) -> u32 {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unsent_legacy_changes()
    }

    /// What opening the root found worth logging: for example an
    /// `account.json` left at the root by an older version, kept.
    pub fn notices(&self) -> Vec<String> {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .notices()
            .to_vec()
    }
}

fn entry(e: Entry, default: Option<&str>) -> AccountEntry {
    AccountEntry {
        is_default: default == Some(e.tag.as_str()),
        tag: e.tag,
        server: e.server,
        email: e.email,
        user_id: e.user_id,
        label: e.label,
        color: e.color,
        created: e.created,
        order: e.order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("verrou-ffi-accounts-{}", uuid::Uuid::new_v4()))
    }

    fn legacy_account() -> Vec<u8> {
        br#"{"version":1,"server":"https://vault.example","email":"me@example.org","user_id":"uid-1",
            "kdf":{"type":"pbkdf2","iterations":600000},"salt":"s","wrapped_user_key":"w",
            "private_key":"p","refresh_token":"r","synced_at":7,"sync":null}"#
            .to_vec()
    }

    #[test]
    fn the_legacy_account_opens_from_its_new_folder() {
        let root = temp_root();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("account.json"), legacy_account()).unwrap();
        std::fs::write(root.join("outbox.json"), "queue").unwrap();

        let accounts = Accounts::open(root.to_string_lossy().into_owned()).unwrap();
        let list = accounts.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].is_default);
        let tag = accounts.primary_tag().unwrap().unwrap();
        assert_eq!(tag, list[0].tag);
        let session = accounts.session(tag.clone()).unwrap();
        let info = session.account().expect("the account survives the update");
        assert_eq!(info.email, "me@example.org");
        assert_eq!(info.synced_at, Some(7));
        assert!(Arc::ptr_eq(
            &session,
            &accounts.session(tag.clone()).unwrap()
        ));
        assert_eq!(
            std::fs::read_to_string(accounts.directory(tag).unwrap() + "/outbox.json").unwrap(),
            "queue"
        );
        assert!(!root.join("account.json").exists());

        // The extension sees the same account, as a guest.
        let extension = Accounts::for_autofill(root.to_string_lossy().into_owned()).unwrap();
        let tag = extension.primary_tag().unwrap().unwrap();
        assert!(extension.session(tag).unwrap().account().is_some());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Every file and folder under `dir`, relative, sorted.
    fn listing(dir: &std::path::Path) -> Vec<String> {
        fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                out.push(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
                if path.is_dir() {
                    walk(base, &path, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    #[test]
    fn a_fresh_root_gives_the_app_a_folder_and_the_extension_none() {
        let root = temp_root();
        let extension = Accounts::for_autofill(root.to_string_lossy().into_owned()).unwrap();
        assert_eq!(extension.primary_tag().unwrap(), None);
        assert_eq!(extension.list().unwrap().len(), 0);
        assert!(
            !root.exists(),
            "the extension creates nothing, not even the root"
        );

        std::fs::create_dir_all(&root).unwrap();
        let extension = Accounts::for_autofill(root.to_string_lossy().into_owned()).unwrap();
        assert_eq!(extension.primary_tag().unwrap(), None);
        assert_eq!(
            listing(&root),
            Vec::<String>::new(),
            "nor any file in an empty one"
        );

        let app = Accounts::open(root.to_string_lossy().into_owned()).unwrap();
        let tag = app.primary_tag().unwrap().unwrap();
        assert!(root.join("accounts").join(&tag).is_dir());
        assert!(app.session(tag.clone()).unwrap().account().is_none());
        assert_eq!(app.list().unwrap().len(), 0);
        // The app made a folder for the sign-in, but still no registry, and
        // nothing that looks like an account.
        let files = listing(&root);
        assert!(
            !files.iter().any(|f| f.ends_with("accounts.json")),
            "{files:?}"
        );
        assert!(
            !files.iter().any(|f| f.ends_with("account.json")),
            "{files:?}"
        );
        assert_eq!(app.unsent_legacy_changes(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unknown_tags_are_refused() {
        let root = temp_root();
        let app = Accounts::open(root.to_string_lossy().into_owned()).unwrap();
        assert!(app.session("../..".into()).is_err());
        assert!(app.directory("nope".into()).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
