use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::Store;
use crate::store::KdfSettings;

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!("verrou-accounts-{}", uuid::Uuid::new_v4()))
}

fn account(server: &str, email: &str, user_id: &str) -> Account {
    Account {
        version: Account::new_version(),
        server: server.into(),
        email: email.into(),
        user_id: user_id.into(),
        kdf: KdfSettings::Pbkdf2 {
            iterations: 600_000,
        },
        salt: "salt".into(),
        wrapped_user_key: "wrapped".into(),
        private_key: "private".into(),
        refresh_token: "refresh".into(),
        synced_at: None,
        sync: None,
        equivalent_domains: None,
    }
}

/// What 0.5 left at the root for one account: every file the layout moves,
/// each with its own content, plus files that are not the account's.
fn legacy_files() -> BTreeMap<&'static str, Vec<u8>> {
    let mut files: BTreeMap<&'static str, Vec<u8>> = ACCOUNT_FILES
        .iter()
        .map(|name| (*name, format!("content of {name}").into_bytes()))
        .collect();
    let account =
        serde_json::to_vec(&account("https://vault.example", "me@example.org", "uid-1")).unwrap();
    files.insert("account.json", account);
    files
}

const DEVICE_FILES: [&str; 4] = [
    "bridge-clients.json",
    "remote-approval.json",
    "remote-escrow.json",
    "migration.json",
];

fn make_legacy(root: &Path) -> BTreeMap<&'static str, Vec<u8>> {
    fs::create_dir_all(root).unwrap();
    let files = legacy_files();
    for (name, data) in &files {
        fs::write(root.join(name), data).unwrap();
    }
    for name in DEVICE_FILES {
        fs::write(root.join(name), format!("device {name}")).unwrap();
    }
    for name in CACHE_FILES {
        fs::write(root.join(name), format!("public {name}")).unwrap();
    }
    fs::write(root.join("notes.txt"), "not Verrou's").unwrap();
    files
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn only_tag(root: &Path) -> String {
    let registry = Registry::open(root).unwrap();
    let list = registry.list();
    assert_eq!(list.len(), 1, "{list:?}");
    list[0].tag.clone()
}

fn assert_migrated(root: &Path, files: &BTreeMap<&'static str, Vec<u8>>) -> String {
    let registry = Registry::open(root).unwrap();
    let list = registry.list();
    assert_eq!(list.len(), 1, "{list:?}");
    let entry = &list[0];
    assert!(valid_tag(&entry.tag));
    assert_eq!(entry.server, "https://vault.example");
    assert_eq!(entry.email, "me@example.org");
    assert_eq!(entry.label, "me@example.org");
    assert_eq!(entry.user_id, "uid-1");
    assert_eq!(registry.default_tag(), Some(entry.tag.as_str()));
    let dir = registry.account_dir(&entry.tag).unwrap();
    for (name, data) in files {
        assert_eq!(
            &fs::read(dir.join(name)).unwrap(),
            data,
            "{name} moved intact"
        );
        assert!(!root.join(name).exists(), "{name} left the root");
    }
    assert!(!dir.join(MIGRATING).exists());
    entry.tag.clone()
}

#[test]
fn fresh_install_writes_no_registry() {
    let root = temp_root();
    let registry = Registry::open(&root).unwrap();
    assert_eq!(registry.list().len(), 0);
    assert_eq!(registry.primary(), None);
    assert_eq!(registry.notices().len(), 0);
    // Only the first account saved creates the registry.
    assert!(!root.join(REGISTRY_FILE).exists());
    assert_eq!(names(&root), vec![".verrou.lock".to_owned()]);
    Registry::open(&root).unwrap();
    assert!(!root.join(REGISTRY_FILE).exists());

    let mut registry = registry;
    let tag = registry.add_pending().unwrap();
    assert!(!root.join(REGISTRY_FILE).exists());
    registry
        .commit(
            &tag,
            &account("https://vault.example", "me@example.org", "u"),
        )
        .unwrap();
    assert!(root.join(REGISTRY_FILE).is_file());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn for_autofill_on_a_missing_or_empty_root_writes_nothing() {
    // Missing root: not even created.
    let root = temp_root();
    let guest = Registry::open_guest(&root).unwrap();
    assert_eq!(guest.list().len(), 0);
    assert_eq!(guest.primary(), None);
    assert!(!root.exists());

    // Empty root: still empty, whole listing.
    fs::create_dir_all(&root).unwrap();
    let guest = Registry::open_guest(&root).unwrap();
    assert_eq!(guest.list().len(), 0);
    assert_eq!(guest.cleanup().unwrap(), 0);
    assert_eq!(names(&root), Vec::<String>::new());

    // A root with only device files and a stale device-id: untouched too.
    fs::write(root.join("bridge-clients.json"), "x").unwrap();
    fs::write(root.join("device-id"), "d").unwrap();
    Registry::open_guest(&root).unwrap();
    assert_eq!(
        names(&root),
        vec!["bridge-clients.json".to_owned(), "device-id".to_owned()]
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_guest_never_cleans_up_and_leaves_an_existing_registry_alone() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let abandoned = registry.add_pending().unwrap();
    let dir = root.join(ACCOUNTS_DIR).join(&abandoned);
    let later = SystemTime::now() + Duration::from_secs(3 * 24 * 60 * 60);
    registry
        .commit(
            &dirless_tag(&root),
            &account("https://v.example", "a@b.c", "u"),
        )
        .unwrap();
    let before = fs::read(root.join(REGISTRY_FILE)).unwrap();
    Registry::open_with(root.clone(), true, None, later).unwrap();
    assert!(dir.exists(), "no cleanup in a guest open");
    assert_eq!(fs::read(root.join(REGISTRY_FILE)).unwrap(), before);
    // A root account.json next to the registry is not the guest's business.
    fs::write(root.join("account.json"), "{}").unwrap();
    Registry::open_guest(&root).unwrap();
    assert!(root.join("account.json").exists());
    fs::remove_dir_all(&root).unwrap();
}

/// A fresh folder tag whose folder exists (so that `commit` has a place).
fn dirless_tag(root: &Path) -> String {
    let tag = fresh_tag(root, &RegistryFile::empty()).unwrap();
    create_private_dir(&root.join(ACCOUNTS_DIR).join(&tag)).unwrap();
    tag
}

#[test]
fn a_guest_migrates_a_legacy_account() {
    let root = temp_root();
    let files = make_legacy(&root);
    let guest = Registry::open_guest(&root).unwrap();
    assert_eq!(guest.list().len(), 1);
    assert_migrated(&root, &files);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn existing_account_moves_without_a_new_sign_in() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);

    // Device files stay at the root, the public lists move to cache/.
    for name in DEVICE_FILES {
        assert_eq!(
            fs::read_to_string(root.join(name)).unwrap(),
            format!("device {name}")
        );
    }
    for name in CACHE_FILES {
        assert!(!root.join(name).exists());
        assert_eq!(
            fs::read_to_string(root.join(CACHE_DIR).join(name)).unwrap(),
            format!("public {name}")
        );
    }
    // The root only has what belongs to it.
    let mut expected: Vec<String> = DEVICE_FILES
        .iter()
        .map(|n| (*n).to_owned())
        .chain([
            REGISTRY_FILE.to_owned(),
            ACCOUNTS_DIR.to_owned(),
            CACHE_DIR.to_owned(),
            ".verrou.lock".to_owned(),
            "notes.txt".to_owned(),
        ])
        .collect();
    expected.sort();
    assert_eq!(names(&root), expected);

    // The account is readable through a Store on its folder.
    let store = Store::for_account(&root, &tag).unwrap();
    assert_eq!(store.load_account().unwrap().unwrap().user_id, "uid-1");

    // A second open is a no-op.
    let registry_bytes = fs::read(root.join(REGISTRY_FILE)).unwrap();
    assert_eq!(only_tag(&root), tag);
    assert_eq!(fs::read(root.join(REGISTRY_FILE)).unwrap(), registry_bytes);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn permissions_are_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = temp_root();
    make_legacy(&root);
    let tag = only_tag(&root);
    let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(root.join(REGISTRY_FILE)), 0o600);
    assert_eq!(mode(root.join(ACCOUNTS_DIR)), 0o700);
    assert_eq!(mode(root.join(ACCOUNTS_DIR).join(&tag)), 0o700);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unknown_files_stay_where_they_are() {
    let root = temp_root();
    let files = make_legacy(&root);
    fs::write(root.join("notes.txt"), "mine").unwrap();
    fs::create_dir_all(root.join("backups")).unwrap();
    fs::write(root.join("backups/old.json"), "old").unwrap();
    assert_migrated(&root, &files);
    assert_eq!(fs::read_to_string(root.join("notes.txt")).unwrap(), "mine");
    assert_eq!(
        fs::read_to_string(root.join("backups/old.json")).unwrap(),
        "old"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn interrupted_at_every_step_then_resumed() {
    let mut steps_seen = 0;
    for crash in 0..64 {
        let root = temp_root();
        let files = make_legacy(&root);
        let crashed = Registry::open_with(root.clone(), false, Some(crash), SystemTime::now());
        if crashed.is_ok() {
            // `crash` is past the last step: the whole migration ran.
            assert_migrated(&root, &files);
            fs::remove_dir_all(&root).unwrap();
            steps_seen = crash;
            break;
        }
        // Nothing is lost: each file is at the root or in the one folder.
        let folders = names(&root.join(ACCOUNTS_DIR));
        for (name, data) in &files {
            let at_root = fs::read(root.join(name)).ok();
            let moved = folders
                .iter()
                .find_map(|tag| fs::read(root.join(ACCOUNTS_DIR).join(tag).join(name)).ok());
            assert_eq!(
                at_root.or(moved).as_ref(),
                Some(data),
                "{name} after a crash before step {crash}"
            );
        }
        // The next opener finishes it, whatever the step.
        assert_migrated(&root, &files);
        // Exactly one account folder holds the account; a crash right after a
        // folder was created may leave an empty one, which `cleanup` removes.
        let holding: Vec<_> = names(&root.join(ACCOUNTS_DIR))
            .into_iter()
            .filter(|tag| {
                root.join(ACCOUNTS_DIR)
                    .join(tag)
                    .join("account.json")
                    .exists()
            })
            .collect();
        assert_eq!(holding.len(), 1, "crash {crash}: {holding:?}");
        fs::remove_dir_all(&root).unwrap();
    }
    // marker + 13 files... + registry + marker removal.
    assert!(steps_seen >= ACCOUNT_FILES.len() + 3, "{steps_seen}");
}

#[test]
fn a_crash_before_the_marker_leaves_nothing_behind() {
    let root = temp_root();
    let files = make_legacy(&root);
    assert!(Registry::open_with(root.clone(), false, Some(0), SystemTime::now()).is_err());
    // Everything is still at the root; no registry yet.
    for name in files.keys() {
        assert!(root.join(name).exists());
    }
    assert!(!root.join(REGISTRY_FILE).exists());
    assert_migrated(&root, &files);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn resume_never_overwrites_a_file_already_in_the_folder() {
    let root = temp_root();
    let files = make_legacy(&root);
    // Crash after the first rename, then a second copy appears at the root
    // (a downgrade ran in between).
    assert!(Registry::open_with(root.clone(), false, Some(3), SystemTime::now()).is_err());
    let tag = names(&root.join(ACCOUNTS_DIR)).remove(0);
    let moved = ACCOUNT_FILES
        .iter()
        .find(|n| root.join(ACCOUNTS_DIR).join(&tag).join(n).exists())
        .unwrap();
    fs::write(root.join(moved), "newer, from an older version").unwrap();
    let registry = Registry::open(&root).unwrap();
    assert_eq!(
        fs::read(root.join(ACCOUNTS_DIR).join(&tag).join(moved)).unwrap(),
        files[moved]
    );
    assert_eq!(
        fs::read_to_string(root.join(moved)).unwrap(),
        "newer, from an older version"
    );
    assert!(registry.notices().iter().any(|n| n.contains(moved)));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn concurrent_threads_migrate_once() {
    let root = temp_root();
    let files = Arc::new(make_legacy(&root));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            std::thread::spawn(move || Registry::open(&root).unwrap().list())
        })
        .collect();
    let lists: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(lists.windows(2).all(|w| w[0] == w[1]), "{lists:?}");
    assert_eq!(names(&root.join(ACCOUNTS_DIR)).len(), 1);
    assert_migrated(&root, &files);
    fs::remove_dir_all(&root).unwrap();
}

/// Run by `concurrent_processes_migrate_once` in child processes.
#[test]
fn child_opener() {
    if let Ok(root) = std::env::var("VERROU_ACCOUNTS_TEST_ROOT") {
        Registry::open(root).unwrap();
    }
}

#[test]
fn concurrent_processes_migrate_once() {
    let root = temp_root();
    let files = make_legacy(&root);
    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(&exe)
                .args(["accounts::tests::child_opener", "--exact", "--nocapture"])
                .env("VERROU_ACCOUNTS_TEST_ROOT", &root)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(names(&root.join(ACCOUNTS_DIR)).len(), 1);
    assert_migrated(&root, &files);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_root_account_after_the_migration_is_ignored_and_reported() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    let registry_bytes = fs::read(root.join(REGISTRY_FILE)).unwrap();
    // An older version, run after the update, asks to sign in and writes
    // its account at the root.
    let other = serde_json::to_vec(&account("https://other.example", "x@y.z", "uid-9")).unwrap();
    fs::write(root.join("account.json"), &other).unwrap();

    let registry = Registry::open(&root).unwrap();
    assert_eq!(registry.list().len(), 1);
    assert_eq!(registry.list()[0].tag, tag);
    assert_eq!(registry.list()[0].user_id, "uid-1");
    assert_eq!(fs::read(root.join(REGISTRY_FILE)).unwrap(), registry_bytes);
    assert_eq!(
        fs::read(root.join("account.json")).unwrap(),
        other,
        "left in place"
    );
    assert_eq!(
        fs::read(root.join(ACCOUNTS_DIR).join(&tag).join("account.json")).unwrap(),
        files["account.json"]
    );
    assert!(
        registry
            .notices()
            .iter()
            .any(|n| n.contains("account.json")),
        "{:?}",
        registry.notices()
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_same_account_twice_is_refused() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let first = registry.add_pending().unwrap();
    registry
        .commit(
            &first,
            &account("https://vault.example", "me@example.org", "UID-1"),
        )
        .unwrap();
    // Not an empty folder any more: a second sign-in gets its own.
    let other = registry.add_pending().unwrap();
    assert_ne!(first, other);
    let duplicate = account("HTTPS://Vault.Example/", "other@example.org", "uid-1");
    match registry.commit(&other, &duplicate) {
        Err(Error::AlreadySignedIn(label)) => assert_eq!(label, "me@example.org"),
        other => panic!("{other:?}"),
    }
    assert_eq!(registry.list().len(), 1);
    // Same user id on another server, and same email with another id: fine.
    registry
        .commit(
            &other,
            &account("https://elsewhere.example", "me@example.org", "uid-1"),
        )
        .unwrap();
    assert_eq!(registry.list().len(), 2);
    // Refreshing an entry is not a duplicate of itself.
    registry
        .commit(
            &first,
            &account("https://vault.example", "new@example.org", "UID-1"),
        )
        .unwrap();
    assert_eq!(registry.entry(&first).unwrap().email, "new@example.org");
    assert_eq!(registry.entry(&first).unwrap().label, "new@example.org");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn saving_and_deleting_the_account_keep_the_registry_in_step() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let tag = registry.add_pending().unwrap();
    let store = Store::for_account(&root, &tag).unwrap();
    assert_eq!(store.tag(), Some(tag.as_str()));
    let device = store.device_id().unwrap();

    store
        .save_account(&account("https://vault.example", "me@example.org", "uid-1"))
        .unwrap();
    registry.reload().unwrap();
    assert_eq!(registry.primary().unwrap().tag, tag);
    assert_eq!(registry.default_tag(), Some(tag.as_str()));

    // A rename survives the account's refresh at the next sync.
    registry.set_label(&tag, "Personal").unwrap();
    store
        .save_account(&account("https://vault.example", "me@example.org", "uid-1"))
        .unwrap();
    registry.reload().unwrap();
    assert_eq!(registry.entry(&tag).unwrap().label, "Personal");

    // Signing out: the entry goes, the folder keeps the device id.
    store.delete_account().unwrap();
    registry.reload().unwrap();
    assert_eq!(registry.list().len(), 0);
    assert_eq!(registry.default_tag(), None);

    // Signing in again reuses it, with the same device id.
    let mut reopened = Registry::open(&root).unwrap();
    assert_eq!(reopened.add_pending().unwrap(), tag);
    let again = Store::for_account(&root, &tag).unwrap();
    assert_eq!(again.device_id().unwrap(), device);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_guest_never_writes_the_registry() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let tag = registry.add_pending().unwrap();
    Store::for_account(&root, &tag)
        .unwrap()
        .guest()
        .save_account(&account("https://vault.example", "me@example.org", "uid-1"))
        .unwrap();
    registry.reload().unwrap();
    assert_eq!(registry.list().len(), 0);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_store_only_touches_its_own_folder() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let a = registry.add_pending().unwrap();
    let store_a = Store::for_account(&root, &a).unwrap();
    store_a
        .save_account(&account("https://vault.example", "a@example.org", "uid-a"))
        .unwrap();
    let b = registry.add_pending().unwrap();
    let store_b = Store::for_account(&root, &b).unwrap();
    store_b
        .save_account(&account("https://vault.example", "b@example.org", "uid-b"))
        .unwrap();
    let snapshot = |tag: &str| names(&root.join(ACCOUNTS_DIR).join(tag));
    let before_a = snapshot(&a);
    let before_root = names(&root);
    store_b.device_id().unwrap();
    store_b.write_file("usage.json", b"{}").unwrap();
    store_b.delete_outbox().unwrap();
    assert_eq!(snapshot(&a), before_a, "B never writes in A's folder");
    assert_eq!(names(&root), before_root, "nor at the root");
    assert_eq!(store_a.load_account().unwrap().unwrap().user_id, "uid-a");
    assert_eq!(store_b.load_account().unwrap().unwrap().user_id, "uid-b");
    // Device files and caches belong to the root.
    assert_eq!(store_b.device_dir(), root);
    assert_eq!(store_b.cache_dir(), root.join(CACHE_DIR));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn stale_pending_folders_are_cleaned() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let abandoned = registry.add_pending().unwrap();
    let with_device = {
        let tag = fresh_tag(&root, &RegistryFile::empty()).unwrap();
        let dir = root.join(ACCOUNTS_DIR).join(&tag);
        create_private_dir(&dir).unwrap();
        fs::write(dir.join("device-id"), uuid::Uuid::new_v4().to_string()).unwrap();
        tag
    };
    let unknown_content = {
        let tag = fresh_tag(&root, &RegistryFile::empty()).unwrap();
        let dir = root.join(ACCOUNTS_DIR).join(&tag);
        create_private_dir(&dir).unwrap();
        fs::write(dir.join("notes.txt"), "mine").unwrap();
        fs::write(dir.join("usage.json"), "{}").unwrap();
        tag
    };
    let dir_of = |tag: &str| root.join(ACCOUNTS_DIR).join(tag);

    // Within 24 hours: nothing goes.
    Registry::open_with(
        root.clone(),
        false,
        None,
        SystemTime::now() + Duration::from_secs(23 * 60 * 60),
    )
    .unwrap();
    assert!(dir_of(&abandoned).exists());

    // After it: the empty one goes, the one with a device id stays, the one
    // with a file Verrou doesn't know keeps that file.
    let later = SystemTime::now() + Duration::from_secs(25 * 60 * 60);
    Registry::open_with(root.clone(), false, None, later).unwrap();
    assert!(!dir_of(&abandoned).exists());
    assert!(dir_of(&with_device).join("device-id").exists());
    assert_eq!(
        fs::read_to_string(dir_of(&unknown_content).join("notes.txt")).unwrap(),
        "mine"
    );
    assert!(!dir_of(&unknown_content).join("usage.json").exists());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_signed_out_device_id_at_the_root_is_kept() {
    let root = temp_root();
    fs::create_dir_all(&root).unwrap();
    let device = uuid::Uuid::new_v4().to_string();
    fs::write(root.join("device-id"), &device).unwrap();
    let mut registry = Registry::open(&root).unwrap();
    assert_eq!(registry.list().len(), 0);
    assert!(!root.join("device-id").exists());
    let tag = registry.add_pending().unwrap();
    assert_eq!(
        Store::for_account(&root, &tag)
            .unwrap()
            .device_id()
            .unwrap(),
        device
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_lost_registry_is_rebuilt_from_the_folders() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    fs::write(root.join(REGISTRY_FILE), "{ not json").unwrap();
    let registry = Registry::open(&root).unwrap();
    assert_eq!(registry.list().len(), 1);
    assert_eq!(registry.list()[0].tag, tag);
    assert_eq!(registry.list()[0].user_id, "uid-1");
    assert!(registry.notices().iter().any(|n| n.contains("rebuilt")));
    assert!(
        names(&root)
            .iter()
            .any(|n| n.starts_with("accounts.json.corrupt-")),
        "the bad file is set aside, not deleted"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_unknown_registry_version_is_refused_and_untouched() {
    let root = temp_root();
    fs::create_dir_all(&root).unwrap();
    let future = br#"{"version":2,"accounts":[],"default":null}"#;
    fs::write(root.join(REGISTRY_FILE), future).unwrap();
    assert!(matches!(Registry::open(&root), Err(Error::NewerFormat)));
    assert!(matches!(
        Registry::open_guest(&root),
        Err(Error::NewerFormat)
    ));
    let mut app = Registry {
        root: root.clone(),
        guest: false,
        file: RegistryFile::empty(),
        notices: Vec::new(),
        unsent_legacy_changes: 0,
    };
    assert!(matches!(app.reload(), Err(Error::NewerFormat)));
    assert_eq!(fs::read(root.join(REGISTRY_FILE)).unwrap(), future);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn remove_signs_out_and_deletes_only_what_is_known() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    let dir = root.join(ACCOUNTS_DIR).join(&tag);
    fs::write(dir.join("keep-me.txt"), "mine").unwrap();
    let mut registry = Registry::open(&root).unwrap();
    registry.remove(&tag).unwrap();
    assert_eq!(registry.list().len(), 0);
    assert!(!dir.join("account.json").exists());
    assert!(!dir.join("outbox.json").exists());
    assert_eq!(fs::read_to_string(dir.join("keep-me.txt")).unwrap(), "mine");
    fs::remove_file(dir.join("keep-me.txt")).unwrap();
    assert!(registry.remove(&tag).is_ok());
    assert!(!dir.exists());
    // The device-level files are untouched.
    assert!(root.join("bridge-clients.json").exists());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn display_settings_and_default() {
    let root = temp_root();
    let mut registry = Registry::open(&root).unwrap();
    let mut tags = Vec::new();
    for n in 0..2 {
        let tag = registry.add_pending().unwrap();
        registry
            .commit(
                &tag,
                &account(
                    "https://vault.example",
                    &format!("u{n}@x.y"),
                    &format!("uid-{n}"),
                ),
            )
            .unwrap();
        tags.push(tag);
    }
    assert_eq!(registry.default_tag(), Some(tags[0].as_str()));
    registry.set_default(&tags[1]).unwrap();
    registry.set_order(&tags[1], 0).unwrap();
    registry.set_order(&tags[0], 1).unwrap();
    registry.set_color(&tags[1], "teal").unwrap();
    assert!(registry.set_label(&tags[1], "  ").is_err());
    assert!(registry.set_default("zzzzzz").is_err());
    assert!(registry.set_label("../etc", "x").is_err());
    let reopened = Registry::open(&root).unwrap();
    assert_eq!(reopened.default_tag(), Some(tags[1].as_str()));
    assert_eq!(reopened.list()[0].tag, tags[1]);
    assert_eq!(reopened.list()[0].color, "teal");
    // Unregistering the default moves it to the next account.
    let mut reopened = reopened;
    reopened.unregister(&tags[1]).unwrap();
    assert_eq!(reopened.default_tag(), Some(tags[0].as_str()));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn tags_never_become_paths() {
    assert!(valid_tag("k3f7qa"));
    for bad in ["", "abc", "ABCDEF", "k3f8q1", "../..", "k3f7qa/", "k3f7qaa"] {
        assert!(!valid_tag(bad), "{bad}");
        assert!(Store::for_account("/tmp", bad).is_err());
    }
}

// MARK: Leftovers at the root

fn set_mtime(path: &Path, when: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// A migrated root with a leftover `account.json` (and files) of the same
/// account, written by an older version.
fn migrated_with_leftover(newer: bool) -> (PathBuf, String, PathBuf) {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    let dir = root.join(ACCOUNTS_DIR).join(&tag);
    let mut older = account("https://VAULT.example/", "renamed@example.org", "UID-1");
    older.refresh_token = "from the older version".into();
    fs::write(
        root.join("account.json"),
        serde_json::to_vec(&older).unwrap(),
    )
    .unwrap();
    fs::write(root.join("outbox.json"), "older outbox").unwrap();
    fs::write(root.join("usage.json"), "older usage").unwrap();
    let now = SystemTime::now();
    let (root_time, folder_time) = if newer {
        (now, now - Duration::from_secs(3600))
    } else {
        (now - Duration::from_secs(3600), now)
    };
    set_mtime(&root.join("account.json"), root_time);
    set_mtime(&dir.join("account.json"), folder_time);
    (root, tag, dir)
}

#[test]
fn a_newer_root_account_of_the_same_user_supersedes_the_folder() {
    let (root, tag, dir) = migrated_with_leftover(true);
    let before_account = fs::read(dir.join("account.json")).unwrap();
    let registry = Registry::open(&root).unwrap();

    // The root's files moved in.
    assert!(!root.join("account.json").exists());
    assert!(!root.join("outbox.json").exists());
    assert_eq!(
        fs::read_to_string(dir.join("outbox.json")).unwrap(),
        "older outbox"
    );
    assert!(
        fs::read_to_string(dir.join("account.json"))
            .unwrap()
            .contains("from the older version")
    );
    // The folder's own are set aside, never deleted.
    let aside: Vec<String> = names(&dir)
        .into_iter()
        .filter(|n| n.starts_with("superseded-"))
        .collect();
    assert_eq!(aside.len(), 1, "{:?}", names(&dir));
    let aside = dir.join(&aside[0]);
    assert_eq!(
        fs::read(aside.join("account.json")).unwrap(),
        before_account
    );
    assert_eq!(
        fs::read_to_string(aside.join("outbox.json")).unwrap(),
        "content of outbox.json"
    );
    assert_eq!(
        fs::read_to_string(aside.join("usage.json")).unwrap(),
        "content of usage.json"
    );
    // Files the root didn't have stay.
    assert_eq!(
        fs::read_to_string(dir.join("device-id")).unwrap(),
        "content of device-id"
    );
    // The entry follows the account; one account, same tag.
    assert_eq!(registry.list().len(), 1);
    assert_eq!(registry.list()[0].tag, tag);
    assert_eq!(registry.list()[0].email, "renamed@example.org");
    assert_eq!(registry.list()[0].label, "renamed@example.org");
    assert_eq!(registry.unsent_legacy_changes(), 0);
    // A second open finds nothing to do.
    let again = Registry::open(&root).unwrap();
    assert_eq!(again.notices().len(), 0);
    assert_eq!(
        names(&dir)
            .iter()
            .filter(|n| n.starts_with("superseded-"))
            .count(),
        1
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_older_root_account_stays_and_reports_its_unsent_changes() {
    let (root, _tag, dir) = migrated_with_leftover(false);
    fs::write(
        root.join("outbox.json"),
        br#"{"version":1,"user_id":"uid-1","pending":3,"data":"x"}"#,
    )
    .unwrap();
    let account_before = fs::read(dir.join("account.json")).unwrap();
    let registry = Registry::open(&root).unwrap();
    assert!(root.join("account.json").exists());
    assert!(root.join("outbox.json").exists());
    assert_eq!(fs::read(dir.join("account.json")).unwrap(), account_before);
    assert!(!names(&dir).iter().any(|n| n.starts_with("superseded-")));
    assert_eq!(registry.unsent_legacy_changes(), 3);
    assert!(
        registry
            .notices()
            .iter()
            .any(|n| n == "3 changes from an older Verrou were not sent"),
        "{:?}",
        registry.notices()
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_leftover_of_another_account_stays_without_a_count_when_it_has_no_outbox() {
    let root = temp_root();
    let files = make_legacy(&root);
    assert_migrated(&root, &files);
    let other = serde_json::to_vec(&account("https://vault.example", "x@y.z", "uid-9")).unwrap();
    fs::write(root.join("account.json"), other).unwrap();
    let registry = Registry::open(&root).unwrap();
    assert_eq!(registry.unsent_legacy_changes(), 0);
    assert!(registry.notices().iter().all(|n| !n.contains("not sent")));
    fs::remove_dir_all(&root).unwrap();
}

// MARK: Repairs

#[test]
fn only_open_repairs_a_corrupt_registry() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    let mut registry = Registry::open(&root).unwrap();
    fs::write(root.join(REGISTRY_FILE), "{ not json").unwrap();

    // reload, commit's fast path, mutations and the guest's open: errors (or
    // a repair under the lock for the guest), never a silent set-aside.
    assert!(registry.reload().is_err());
    assert!(registry.set_label(&tag, "x").is_err());
    assert!(registry.add_pending().is_err());
    assert!(
        registry
            .commit(
                &tag,
                &account("https://vault.example", "me@example.org", "uid-1")
            )
            .is_err()
    );
    assert!(read_registry(&root).is_err());
    assert!(
        !names(&root)
            .iter()
            .any(|n| n.starts_with("accounts.json.corrupt-")),
        "{:?}",
        names(&root)
    );
    assert_eq!(
        fs::read_to_string(root.join(REGISTRY_FILE)).unwrap(),
        "{ not json"
    );

    // `open` takes the lock, sets it aside and rebuilds.
    let reopened = Registry::open(&root).unwrap();
    assert_eq!(reopened.list().len(), 1);
    assert!(
        names(&root)
            .iter()
            .any(|n| n.starts_with("accounts.json.corrupt-"))
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_lost_registry_with_a_root_account_rebuilds_from_the_folders_first() {
    for lost in ["missing", "corrupt"] {
        let (root, tag, dir) = migrated_with_leftover(true);
        match lost {
            "missing" => fs::remove_file(root.join(REGISTRY_FILE)).unwrap(),
            _ => fs::write(root.join(REGISTRY_FILE), "garbage").unwrap(),
        }
        let registry = Registry::open(&root).unwrap();
        // The folder is the account: no second account from the root file.
        assert_eq!(registry.list().len(), 1, "{lost}");
        assert_eq!(registry.list()[0].tag, tag, "{lost}");
        assert_eq!(names(&root.join(ACCOUNTS_DIR)).len(), 1, "{lost}");
        // Then the root files are leftovers, under the same rules (newer: swapped in).
        assert!(!root.join("account.json").exists(), "{lost}");
        assert!(
            fs::read_to_string(dir.join("account.json"))
                .unwrap()
                .contains("from the older version"),
            "{lost}"
        );
        assert!(names(&dir).iter().any(|n| n.starts_with("superseded-")));
        assert!(root.join(REGISTRY_FILE).is_file());
        fs::remove_dir_all(&root).unwrap();
    }
}

#[test]
fn resuming_with_a_registry_moves_nothing_and_only_removes_the_marker() {
    let root = temp_root();
    let files = make_legacy(&root);
    let tag = assert_migrated(&root, &files);
    let dir = root.join(ACCOUNTS_DIR).join(&tag);
    // Crashed between the commit and the marker's removal, then an older
    // version left a file at the root.
    fs::write(dir.join(MIGRATING), "").unwrap();
    fs::write(root.join("usage.json"), "left by an older version").unwrap();
    Registry::open(&root).unwrap();
    assert!(!dir.join(MIGRATING).exists());
    assert_eq!(
        fs::read_to_string(root.join("usage.json")).unwrap(),
        "left by an older version"
    );
    assert_eq!(
        fs::read_to_string(dir.join("usage.json")).unwrap(),
        "content of usage.json"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn account_folders_made_by_a_store_are_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let root = temp_root();
    // Without the registry having made the folder first.
    let store = Store::for_account(&root, "abcdef").unwrap();
    store.write_file("usage.json", b"{}").unwrap();
    assert_eq!(mode(&root.join(ACCOUNTS_DIR)), 0o700);
    assert_eq!(mode(&root.join(ACCOUNTS_DIR).join("abcdef")), 0o700);
    let other = Store::for_account(&root, "ghijkl").unwrap();
    other
        .update_file("match-rules.json", |_| (Some(b"{}".to_vec()), ()))
        .unwrap();
    assert_eq!(mode(&root.join(ACCOUNTS_DIR).join("ghijkl")), 0o700);
    fs::remove_dir_all(&root).unwrap();
}
