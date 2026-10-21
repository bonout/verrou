//! Item writes: the queue ("outbox") and its sending.
//!
//! Every creation, edit, trashing, restore, archive, favorite or move to a
//! folder goes through this queue, online as well as offline: it applies
//! right away to the displayed vault, and the interface doesn't wait for the
//! network. The item is kept there **encrypted by the SDK**, exactly as it
//! will be sent (same known revision date); the whole queue is also
//! encrypted by the user key (`outbox.json`, see `store`). Nothing in it is
//! in the clear.
//!
//! The displayed vault is the server's cache, with the queue overlaid on it
//! (`Outbox::apply`): locking, relaunching the app or reopening the session
//! loses nothing.
//!
//! Sending follows right away, in the background (`sync_shared`), then a
//! sync; offline, it waits for the network to come back. In order: first
//! creations and edits, then trash, archives and folders, in batches (they
//! change the item's revision date on the server: sent before an edit, they
//! would make it look stale). A created item carries a provisional id,
//! replaced by the server's.
//!
//! Without blocking: an entry is taken under the connection's lock
//! (`begin`), sent without holding it (the network can take seconds, and the
//! next write must not wait for it), then the lock is taken again to record
//! the response (`finish`). An entry being sent is no longer merged with a
//! later edit of the same item: that one goes behind it, and starts again
//! from the revision date returned by the server (`Outbox::rebase`) instead
//! of looking stale.
//!
//! Conflict: the item changed (or disappeared) on the server in the
//! meantime. The server rejects the edit (revision date); Verrou keeps both
//! versions: the local version becomes a copy, "title (offline conflict)",
//! and the server's version comes back with the sync. Nothing is lost
//! silently: an edit the server rejects for another reason (and whose copy
//! is rejected too) is removed from the queue (the displayed vault goes back
//! to the server's version) and reported.
//!
//! A sent edit stays in the queue (`sent`) until the next sync: if the
//! network drops in between, the displayed vault still shows it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use bitwarden_api_api::models::{CipherCreateRequestModel, CipherRequestModel};
use bitwarden_vault::{Cipher, EncryptionContext, VaultClientExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::Api;
use crate::import::BATCH;
use crate::store::OutboxFile;
use crate::{Connection, Decrypted, Error};

/// After a network error, sends triggered by a write wait this long before
/// trying the network again. The sync (periodic or ⌘R) always retries.
const RETRY_AFTER: Duration = Duration::from_secs(20);

/// Suffix of the title of the copy kept on conflict.
pub const CONFLICT_SUFFIX: &str = " (offline conflict)";

/// The suffix earlier versions wrote (in French): still recognised in an
/// outbox saved by them.
const LEGACY_CONFLICT_SUFFIX: &str = " (conflit hors ligne)";

/// The title of a conflict copy without its suffix, current or legacy.
fn strip_conflict_suffix(title: &str) -> Option<&str> {
    title
        .strip_suffix(CONFLICT_SUFFIX)
        .or_else(|| title.strip_suffix(LEGACY_CONFLICT_SUFFIX))
}

/// Trash, restore, archives: `PUT /api/ciphers/{id}/{action}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Trash,
    Restore,
    Archive,
    Unarchive,
}

impl Action {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Trash => "delete",
            Self::Restore => "restore",
            Self::Archive => "archive",
            Self::Unarchive => "unarchive",
        }
    }

    fn inverse(self) -> Self {
        match self {
            Self::Trash => Self::Restore,
            Self::Restore => Self::Trash,
            Self::Archive => Self::Unarchive,
            Self::Unarchive => Self::Archive,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Change {
    /// Item created or edited, encrypted by the SDK as it will be sent.
    Save {
        /// Created: `id` is provisional, the send is a `POST`.
        created: bool,
        cipher: Box<EncryptionContext>,
        /// Copy kept after a conflict: if it is rejected too, the edit is
        /// reported and removed.
        #[serde(default)]
        conflict: bool,
    },
    Action {
        action: Action,
        at: DateTime<Utc>,
        /// Revision date returned by the server, once sent.
        #[serde(default)]
        revision: Option<DateTime<Utc>>,
    },
    /// Moved to this folder (`None`: none), `PUT /api/ciphers/move`: the
    /// folder belongs to the account, the item is not rewritten.
    Move { folder: Option<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Item id (provisional for a creation not sent yet).
    pub id: String,
    /// Title, for the send report (the whole queue is encrypted).
    pub title: String,
    pub change: Change,
    /// Accepted by the server, kept until the next sync.
    #[serde(default)]
    pub sent: bool,
    /// Sequence number in the session (not saved).
    #[serde(skip)]
    seq: u64,
    /// Waited for the server (offline, or since a previous session): its
    /// sending is announced in the report.
    #[serde(skip)]
    deferred: bool,
}

impl Entry {
    fn new(id: String, title: String, change: Change) -> Self {
        Self {
            id,
            title,
            change,
            sent: false,
            seq: 0,
            deferred: false,
        }
    }

    fn is_save(&self) -> bool {
        matches!(self.change, Change::Save { .. })
    }

    /// The batch the entry can be part of (trash, archives, folders).
    fn batch(&self) -> Option<Batch> {
        match &self.change {
            Change::Save { .. } => None,
            Change::Action { action, .. } => Some(Batch::Action(*action)),
            Change::Move { folder } => Some(Batch::Move(folder.clone())),
        }
    }
}

/// What goes out in one grouped request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Batch {
    Action(Action),
    Move(Option<String>),
}

/// The queue, in the order of the changes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Outbox {
    entries: Vec<Entry>,
    /// Next sequence number.
    #[serde(skip)]
    next: u64,
    /// Entries being sent: not merged, cancelled or taken again.
    #[serde(skip)]
    in_flight: HashSet<u64>,
    /// Entries of a rejected batch: sent again one by one, to find out which one.
    #[serde(skip)]
    singles: HashSet<u64>,
}

impl Outbox {
    fn unsent(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| !e.sent)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_unsent(&self) -> bool {
        self.unsent().next().is_some()
    }

    /// Changes not yet accepted by the server.
    pub fn pending_changes(&self) -> usize {
        self.unsent().count()
    }

    /// Items waiting for the server, without duplicates.
    pub fn pending_items(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.unsent()
            .filter(|e| seen.insert(e.id.as_str()))
            .map(|e| e.id.clone())
            .collect()
    }

    /// Numbers a queue read back from disk: everything in it has waited for
    /// the server.
    fn renumber(&mut self) {
        for entry in &mut self.entries {
            entry.seq = self.next;
            entry.deferred = !entry.sent;
            self.next += 1;
        }
    }

    fn push(&mut self, mut entry: Entry) {
        entry.seq = self.next;
        self.next += 1;
        self.entries.push(entry);
    }

    fn position(&self, seq: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.seq == seq)
    }

    /// Can still be merged or cancelled: neither sent nor in flight.
    fn is_open(&self, entry: &Entry) -> bool {
        !entry.sent && !self.in_flight.contains(&entry.seq)
    }

    /// Adds a creation or an edit. Only one edit per item waits: the new
    /// one replaces the previous one (it builds on it, since it is made on
    /// the displayed vault), and a creation stays a creation. The one being
    /// sent is not touched.
    pub fn push_save(
        &mut self,
        id: String,
        title: String,
        created: bool,
        cipher: EncryptionContext,
    ) {
        let previous = self
            .entries
            .iter()
            .position(|e| e.id == id && e.is_save() && self.is_open(e));
        if let Some(index) = previous {
            let entry = &mut self.entries[index];
            let was_created = matches!(entry.change, Change::Save { created: true, .. });
            entry.title = title;
            entry.change = Change::Save {
                created: created || was_created,
                cipher: Box::new(cipher),
                conflict: false,
            };
            return;
        }
        self.push(Entry::new(
            id,
            title,
            Change::Save {
                created,
                cipher: Box::new(cipher),
                conflict: false,
            },
        ));
    }

    /// Adds an action. One that undoes the item's previous pending action
    /// (restoring what was just trashed, unarchiving) simply cancels it, if
    /// it hasn't gone out already.
    pub fn push_action(&mut self, id: String, title: String, action: Action, at: DateTime<Utc>) {
        let last = self
            .entries
            .iter()
            .rposition(|e| !e.sent && e.id == id && matches!(e.change, Change::Action { .. }));
        if let Some(index) = last
            && self.is_open(&self.entries[index])
            && matches!(self.entries[index].change, Change::Action { action: a, .. } if a == action.inverse())
        {
            self.entries.remove(index);
            return;
        }
        self.push(Entry::new(
            id,
            title,
            Change::Action {
                action,
                at,
                revision: None,
            },
        ));
    }

    /// Moves the item to a folder; a pending move of the same item is
    /// replaced.
    pub fn push_move(&mut self, id: String, title: String, folder: Option<String>) {
        let previous = self
            .entries
            .iter()
            .position(|e| e.id == id && matches!(e.change, Change::Move { .. }) && self.is_open(e));
        if let Some(index) = previous {
            self.entries[index].change = Change::Move { folder };
            return;
        }
        self.push(Entry::new(id, title, Change::Move { folder }));
    }

    /// Overlays the queue on the cache's items: replaces (or adds) the
    /// edited (or created) items, dates trash and archives, moves into
    /// folders.
    pub fn apply(&self, ciphers: &mut Vec<Cipher>) {
        let mut positions: HashMap<_, usize> = ciphers
            .iter()
            .enumerate()
            .filter_map(|(index, c)| Some((c.id?, index)))
            .collect();
        for entry in &self.entries {
            let Ok(id) = entry.id.parse() else { continue };
            match &entry.change {
                Change::Save { cipher, .. } => {
                    let mut cipher = cipher.cipher.clone();
                    cipher.id = Some(id);
                    if let Some(&index) = positions.get(&id) {
                        ciphers[index] = cipher;
                    } else {
                        positions.insert(id, ciphers.len());
                        ciphers.push(cipher);
                    }
                }
                Change::Action {
                    action,
                    at,
                    revision,
                } => {
                    let Some(cipher) = positions.get(&id).map(|&index| &mut ciphers[index]) else {
                        continue;
                    };
                    match action {
                        Action::Trash => cipher.deleted_date = Some(*at),
                        Action::Restore => cipher.deleted_date = None,
                        Action::Archive => cipher.archived_date = Some(*at),
                        Action::Unarchive => cipher.archived_date = None,
                    }
                    if let Some(revision) = revision {
                        cipher.revision_date = *revision;
                    }
                }
                Change::Move { folder } => {
                    let Some(cipher) = positions.get(&id).map(|&index| &mut ciphers[index]) else {
                        continue;
                    };
                    cipher.folder_id = folder.as_deref().and_then(|f| f.parse().ok());
                }
            }
        }
    }

    /// Provisional id replaced by the server's.
    fn remap(&mut self, from: &str, to: &str) {
        let parsed = to.parse().ok();
        for entry in self.entries.iter_mut().filter(|e| e.id == from) {
            to.clone_into(&mut entry.id);
            if let Change::Save { cipher, .. } = &mut entry.change {
                cipher.cipher.id = parsed;
            }
        }
    }

    /// The server gave the item a new revision date (through a Verrou
    /// write): the edits waiting behind start again from it. They were made
    /// on the displayed vault, which already showed that write.
    fn rebase(&mut self, id: &str, revision: DateTime<Utc>) {
        let in_flight = &self.in_flight;
        for entry in self
            .entries
            .iter_mut()
            .filter(|e| !e.sent && e.id == id && !in_flight.contains(&e.seq))
        {
            if let Change::Save { cipher, .. } = &mut entry.change {
                cipher.cipher.revision_date = revision;
            }
        }
    }

    /// The network is missing: what waits will be announced once sent.
    fn mark_deferred(&mut self) {
        for entry in self.entries.iter_mut().filter(|e| !e.sent) {
            entry.deferred = true;
        }
    }

    /// Forgets what the server accepted: the sync that just arrived
    /// contains it. Returns `true` if the queue changed.
    pub fn purge_sent(&mut self) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !e.sent);
        self.entries.len() != before
    }

    /// The next request, marked as being sent: creations and edits first,
    /// in order, then trash, archives and folders, in batches. `None`:
    /// nothing to send, or a send already in progress. An edit the SDK
    /// cannot turn into a request is removed and reported in `rejected`.
    fn begin(&mut self, rejected: &mut Vec<(String, String)>) -> Option<Job> {
        if !self.in_flight.is_empty() {
            return None;
        }
        loop {
            let Some(entry) = self.entries.iter().find(|e| !e.sent && e.is_save()) else {
                return self.begin_batch();
            };
            let Change::Save {
                created, cipher, ..
            } = &entry.change
            else {
                unreachable!("an edit");
            };
            let (seq, id, created) = (entry.seq, entry.id.clone(), *created);
            let collections = cipher.cipher.organization_id.map(|_| {
                cipher
                    .cipher
                    .collection_ids
                    .iter()
                    .map(|c| (*c).into())
                    .collect()
            });
            match request_of((**cipher).clone()) {
                Ok(request) => {
                    self.in_flight.insert(seq);
                    return Some(Job::Save {
                        seq,
                        id,
                        created,
                        request: Box::new(request),
                        collections,
                    });
                }
                Err(error) => {
                    let index = self.position(seq).expect("the entry was just read");
                    let entry = self.entries.remove(index);
                    rejected.push((entry.title, error.to_string()));
                }
            }
        }
    }

    /// The next batch of actions (or moves) of the same kind, in order. An
    /// item with an action of another kind waiting before is not part of
    /// it: each item keeps the order of its actions.
    fn begin_batch(&mut self) -> Option<Job> {
        let mut candidates = self.entries.iter().filter(|e| !e.sent && !e.is_save());
        let first = candidates.next()?;
        let batch = first.batch()?;
        let mut entries = vec![(first.seq, first.id.clone())];
        if !self.singles.contains(&first.seq) {
            let mut taken: HashSet<&str> = HashSet::from([first.id.as_str()]);
            let mut blocked: HashSet<&str> = HashSet::new();
            for entry in candidates {
                if entries.len() >= BATCH {
                    break;
                }
                let fits = entry.batch().as_ref() == Some(&batch)
                    && !self.singles.contains(&entry.seq)
                    && !blocked.contains(entry.id.as_str())
                    && !taken.contains(entry.id.as_str());
                if fits {
                    taken.insert(&entry.id);
                    entries.push((entry.seq, entry.id.clone()));
                } else {
                    blocked.insert(&entry.id);
                }
            }
        }
        self.in_flight.extend(entries.iter().map(|(seq, _)| *seq));
        Some(Job::Batch { batch, entries })
    }
}

/// A request to send, prepared under the connection's lock and sent
/// without it (`Job::send`).
pub(crate) enum Job {
    Save {
        seq: u64,
        id: String,
        created: bool,
        request: Box<CipherRequestModel>,
        /// Creation in a shared vault: its collections.
        collections: Option<Vec<uuid::Uuid>>,
    },
    Batch {
        batch: Batch,
        /// (sequence number, item).
        entries: Vec<(u64, String)>,
    },
}

impl Job {
    /// The send itself: only the network, no shared state.
    pub(crate) async fn send(&self, api: &Api, access: &str) -> Result<Value, Error> {
        match self {
            Self::Save {
                created: true,
                request,
                collections: None,
                ..
            } => api.post_cipher(access, request).await,
            Self::Save {
                created: true,
                request,
                collections: Some(collections),
                ..
            } => {
                let mut create = CipherCreateRequestModel::new((**request).clone());
                create.collection_ids = Some(collections.clone());
                api.send_json(
                    reqwest::Method::POST,
                    "/api/ciphers/create",
                    access,
                    &create,
                )
                .await
            }
            Self::Save { id, request, .. } => api.put_cipher(access, id, request).await,
            Self::Batch { batch, entries } => {
                let ids: Vec<String> = entries.iter().map(|(_, id)| id.clone()).collect();
                match batch {
                    Batch::Action(action) if ids.len() == 1 => {
                        api.cipher_action(access, &ids[0], action.path()).await
                    }
                    Batch::Action(action) => {
                        api.bulk_cipher_action(access, &ids, action.path()).await
                    }
                    Batch::Move(folder) => api
                        .move_ciphers(access, &ids, folder.as_deref())
                        .await
                        .map(|()| Value::Null),
                }
            }
        }
    }
}

/// Report of the sending of changes, since the last report read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Changes that had waited for the server (offline) and that it just
    /// accepted.
    pub sent: usize,
    /// Items edited (or deleted) elsewhere in the meantime: title of the
    /// copy that keeps the local version.
    pub conflicts: Vec<String>,
    /// Changes rejected by the server, removed from the queue (the
    /// displayed vault goes back to the server's version): (title, reason).
    pub rejected: Vec<(String, String)>,
    /// Created items: (provisional id, server id).
    pub remapped: Vec<(String, String)>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Coordination of a connection's sends, shared outside its lock.
#[derive(Default)]
pub(crate) struct Courier {
    /// Only one send (and sync) at a time.
    gate: tokio::sync::Mutex<()>,
    /// Sync requests received, and the last one served: a request that
    /// arrives during a send is served by the next one, which also serves
    /// all those that arrived in the meantime.
    requested: AtomicU64,
    served: AtomicU64,
    /// Failure of the last send, returned to the requests it served.
    failure: std::sync::Mutex<Option<Error>>,
    /// Vault locked: sending stops after the current request (the queue
    /// waits for the next unlock).
    stopped: AtomicBool,
    /// Account logged out: nothing more is written to disk.
    closed: AtomicBool,
}

impl Courier {
    fn halted(&self) -> bool {
        self.stopped.load(Ordering::SeqCst) || self.closed.load(Ordering::SeqCst)
    }
}

/// Stops the current send of a connection being dropped, even if it keeps
/// it alive for the duration of a request.
#[derive(Clone)]
pub struct Closer(Arc<Courier>);

impl Closer {
    /// Locking: sending stops after the current request.
    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    /// Logout: sending stops, and nothing more is written to disk (the
    /// erased queue doesn't come back).
    pub fn close(&self) {
        self.stop();
        self.0.closed.store(true, Ordering::SeqCst);
    }
}

/// What a shared sync produced.
pub enum Synced {
    /// The vault changed: here it is, decrypted.
    Changed(Decrypted),
    /// Nothing new since the displayed vault.
    Unchanged,
    /// Served by another request's send, which returned the vault.
    Joined,
}

/// The queue saved for this account, decrypted by the user key. One from
/// another account (or unreadable: key changed) is deleted.
pub(crate) fn load(store: &crate::Store, user_id: &str, sdk: &bitwarden_core::Client) -> Outbox {
    let Ok(Some(file)) = store.load_outbox() else {
        return Outbox::default();
    };
    if file.user_id != user_id {
        let _ = store.delete_outbox();
        return Outbox::default();
    }
    let outbox = sdk
        .crypto()
        .decrypt_with_local_user_data_key(file.data)
        .ok()
        .and_then(|json| serde_json::from_str::<Outbox>(&json).ok());
    let Some(mut outbox) = outbox else {
        // Encrypted by another key (password changed with key rotation):
        // unreadable forever, and its counter would mislead.
        let _ = store.delete_outbox();
        return Outbox::default();
    };
    outbox.renumber();
    outbox
}

/// Sends the queue then syncs, without holding the connection during the
/// network: local writes (`create`, `update`…) go through meanwhile.
/// Simultaneous requests are grouped: one send in progress, and a single
/// one after it for all those that arrived in the meantime.
///
/// `patient`: triggered by a write; if the server was unreachable a moment
/// ago, don't retry right away (the periodic sync takes care of it).
pub async fn sync_shared(
    connection: &Arc<tokio::sync::Mutex<Connection>>,
    patient: bool,
) -> Result<Synced, Error> {
    let connection = Arc::clone(connection);
    let courier = Arc::clone(&connection.lock().await.courier);
    let ticket = courier.requested.fetch_add(1, Ordering::SeqCst) + 1;
    // In a separate task: no longer waiting (app task cancelled) doesn't
    // interrupt a send halfway, which would leave an entry marked
    // "in flight" forever.
    let run = tokio::spawn(async move {
        let _gate = courier.gate.lock().await;
        if courier.served.load(Ordering::SeqCst) >= ticket {
            let failure = courier
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            return failure.map_or(Ok(Synced::Joined), Err);
        }
        let start = courier.requested.load(Ordering::SeqCst);
        let result = drain(&connection, &courier, patient).await;
        *courier
            .failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = result.as_ref().err().cloned();
        courier.served.store(start, Ordering::SeqCst);
        result
    });
    run.await
        .map_err(|e| Error::Storage(format!("send interrupted ({e})")))?
}

/// One send, gate held (`Courier::gate`).
async fn drain(
    connection: &tokio::sync::Mutex<Connection>,
    courier: &Courier,
    patient: bool,
) -> Result<Synced, Error> {
    if courier.halted() {
        return Ok(Synced::Unchanged);
    }
    let (api, refresh) = {
        let open = connection.lock().await;
        if patient && open.offline_at.is_some_and(|at| at.elapsed() < RETRY_AFTER) {
            return Err(Error::Network("server unreachable a moment ago".to_owned()));
        }
        (open.api.clone(), open.refresh_token()?)
    };
    let mut refresh = refresh;
    let mut tokens = api.refresh(refresh.expose()).await;
    if matches!(&tokens, Err(error) if !matches!(error, Error::Network(_))) {
        // Token rejected: the autofill extension may have saved a new one in
        // the meantime (see `Connection::access_token`).
        let saved = {
            let mut open = connection.lock().await;
            if open.adopt_saved_refresh_token() {
                Some(open.refresh_token()?)
            } else {
                None
            }
        };
        if let Some(saved) = saved {
            refresh = saved;
            tokens = api.refresh(refresh.expose()).await;
        }
    }
    let access = {
        let mut open = connection.lock().await;
        match tokens {
            Ok(tokens) => {
                open.offline_at = None;
                open.keep_refresh_token(&refresh, tokens.refresh)?;
                tokens.access
            }
            Err(error) => return Err(open.network_failure(error)),
        }
    };
    let mut wrote = false;
    loop {
        if courier.halted() {
            return Ok(Synced::Unchanged);
        }
        let Some(job) = connection.lock().await.begin() else {
            break;
        };
        wrote = true;
        let result = job.send(&api, &access).await;
        connection.lock().await.finish(job, result).await?;
    }
    if courier.halted() {
        return Ok(Synced::Unchanged);
    }
    let generation = connection.lock().await.generation;
    let sync = api.sync(&access).await;
    let snapshot = {
        let mut open = connection.lock().await;
        let json = match sync {
            Ok(json) => json,
            Err(error) => return Err(open.network_failure(error)),
        };
        let had_outbox = !open.outbox.is_empty();
        // Another, more recent sync was saved during the download: keep
        // it.
        let unchanged = open.generation == generation && open.store_sync(json)?;
        if unchanged && !wrote && !had_outbox {
            return Ok(Synced::Unchanged);
        }
        open.snapshot()
    };
    // Decrypting the whole vault, outside the lock.
    snapshot.decrypt_cache().await.map(Synced::Changed)
}

impl Connection {
    /// Changes not yet accepted by the server.
    pub fn pending_changes(&self) -> usize {
        self.outbox.pending_changes()
    }

    /// The send report since the last call.
    pub fn take_report(&mut self) -> SyncReport {
        std::mem::take(&mut self.report)
    }

    /// To stop writes to disk at logout.
    pub fn closer(&self) -> Closer {
        Closer(Arc::clone(&self.courier))
    }

    /// Current id of an item: the server's for an item created and sent
    /// since.
    pub fn resolve(&self, id: &str) -> String {
        self.remapped
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned())
    }

    /// Saves the queue (encrypted), or deletes it if it is empty.
    pub(crate) fn persist_outbox(&mut self) -> Result<(), Error> {
        self.version += 1;
        if self.courier.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.outbox.is_empty() {
            return self.store.save_outbox(None);
        }
        let json = serde_json::to_string(&self.outbox).map_err(Error::storage)?;
        let data = self
            .sdk
            .crypto()
            .encrypt_with_local_user_data_key(json)
            .map_err(Error::crypto)?;
        self.store.save_outbox(Some(OutboxFile {
            version: 0,
            user_id: self.account.user_id.clone(),
            pending: u32::try_from(self.outbox.pending_changes()).unwrap_or(u32::MAX),
            data,
        }))
    }

    pub(crate) fn mark_offline(&mut self) {
        self.offline_at = Some(Instant::now());
        self.outbox.mark_deferred();
    }

    /// A send error: the network is missing (noted, the queue waits), or
    /// something else.
    fn network_failure(&mut self, error: Error) -> Error {
        if matches!(error, Error::Network(_)) {
            self.mark_offline();
            let _ = self.persist_outbox();
        }
        error
    }

    /// An access token if the server answers, after sending the queue (and
    /// resyncing, to start again from the server's revision dates); `None`
    /// offline. For what doesn't go through the queue (attachments,
    /// sharing, import, passkey counter).
    pub(crate) async fn online(&mut self) -> Result<Option<String>, Error> {
        if self.offline_at.is_some_and(|at| at.elapsed() < RETRY_AFTER) {
            return Ok(None);
        }
        let access = match self.access_token().await {
            Ok(access) => access,
            Err(Error::Network(_)) => {
                self.mark_offline();
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.offline_at = None;
        // The (guest) extension never sends the app's queue.
        if self.outbox.has_unsent() && !self.store.is_guest() {
            if !self.replay(&access).await? {
                // A send is in progress (`sync_shared`): it takes care of
                // the queue, the direct write goes alongside.
                return Ok(Some(access));
            }
            if self.outbox.has_unsent() {
                return Ok(None);
            }
            match self.api.sync(&access).await {
                Ok(json) => {
                    self.store_sync(json)?;
                }
                Err(Error::Network(_)) => {
                    self.mark_offline();
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Some(access))
    }

    /// For what only makes sense with the server (attachments, sharing,
    /// import…): the queue sent, an access token, or a clear refusal.
    pub(crate) async fn require_online(&mut self, what: &str) -> Result<String, Error> {
        // An explicit action: retry the network without waiting.
        self.offline_at = None;
        self.online()
            .await?
            .ok_or_else(|| Error::Invalid(offline_refusal(what)))
    }

    /// Encrypts `view` and puts it in the queue (`id`: edit, otherwise
    /// creation, under a provisional id): applied right away to the
    /// displayed vault, sent by `sync_shared`. Returns the id and the
    /// vault.
    pub(crate) async fn queue_save(
        &mut self,
        id: Option<&str>,
        view: bitwarden_vault::CipherView,
    ) -> Result<(String, Decrypted), Error> {
        let title = view.name.clone();
        // On the heap: encrypting then decrypting the vault is a task of
        // more than 20 KB.
        let encrypted = Box::pin(self.encrypt_context(view)).await?;
        let (id, created) = match id {
            Some(id) => (id.to_owned(), false),
            None => (uuid::Uuid::new_v4().to_string(), true),
        };
        self.outbox.push_save(id.clone(), title, created, encrypted);
        self.persist_outbox()?;
        Ok((id, Box::pin(self.decrypt_cache()).await?))
    }

    /// Trash, restore or archives, in the queue.
    pub(crate) async fn queue_action(
        &mut self,
        id: &str,
        title: String,
        action: Action,
    ) -> Result<Decrypted, Error> {
        self.outbox
            .push_action(id.to_owned(), title, action, Utc::now());
        self.persist_outbox()?;
        Box::pin(self.decrypt_cache()).await
    }

    /// Encrypts `view` then sends it right away if `access` (and resyncs);
    /// otherwise into the queue. For what must be on the server before
    /// answering (a passkey's counter).
    pub(crate) async fn save_cipher(
        &mut self,
        id: Option<&str>,
        view: bitwarden_vault::CipherView,
        access: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        let Some(access) = access else {
            if self.store.is_guest() {
                // The extension has no queue: without a server, no write.
                return Err(Error::Network("server unreachable".to_owned()));
            }
            return self.queue_save(id, view).await;
        };
        let title = view.name.clone();
        let encrypted = Box::pin(self.encrypt_context(view)).await?;
        let request = request_of(encrypted.clone())?;
        let sent = match id {
            Some(id) => self.api.put_cipher(&access, id, &request).await,
            None => self.api.post_cipher(&access, &request).await,
        };
        let body = match sent {
            Ok(body) => body,
            Err(Error::Network(message)) if self.store.is_guest() => {
                return Err(Error::Network(message));
            }
            Err(Error::Network(_)) => {
                self.mark_offline();
                let (id, created) = match id {
                    Some(id) => (id.to_owned(), false),
                    None => (uuid::Uuid::new_v4().to_string(), true),
                };
                self.outbox.push_save(id.clone(), title, created, encrypted);
                self.persist_outbox()?;
                return Ok((id, Box::pin(self.decrypt_cache()).await?));
            }
            Err(error) => return Err(error),
        };
        let id = match id {
            Some(id) => id.to_owned(),
            None => body_id(&body)?,
        };
        let entry = sent_save(id.clone(), title, encrypted, &body);
        let vault = Box::pin(self.pull_after_write(&access, entry)).await?;
        Ok((id, vault))
    }

    /// After an accepted direct write: resyncs. If the network drops just
    /// before, the write stays visible (sent, in the queue) until the next
    /// sync.
    async fn pull_after_write(&mut self, access: &str, entry: Entry) -> Result<Decrypted, Error> {
        match self.sync_with(access).await {
            Err(Error::Network(_)) => {
                self.mark_offline();
                self.outbox.push(entry);
                self.persist_outbox()?;
                self.decrypt_cache().await
            }
            other => other,
        }
    }

    /// Title of an item of the displayed vault (for the send report).
    pub(crate) async fn cached_title(&self, id: &str) -> Result<String, Error> {
        let cipher = self.cached_cipher(id)?;
        Ok(self.decrypt_view(cipher).await?.name)
    }

    pub(crate) async fn encrypt_context(
        &self,
        view: bitwarden_vault::CipherView,
    ) -> Result<EncryptionContext, Error> {
        // On the heap: the SDK's task is large (more than 20 KB).
        Box::pin(self.sdk.vault().ciphers().encrypt(view))
            .await
            .map_err(Error::crypto)
    }

    /// Sends the queue under the connection's lock (before a direct write).
    /// Returns `false` without doing anything if a shared send is in
    /// progress. Stops without error at the first network problem (the rest
    /// waits); an expired session interrupts everything.
    pub(crate) async fn replay(&mut self, access: &str) -> Result<bool, Error> {
        let courier = Arc::clone(&self.courier);
        let Ok(_gate) = courier.gate.try_lock() else {
            return Ok(false);
        };
        while let Some(job) = self.begin() {
            let result = job.send(&self.api, access).await;
            match self.finish(job, result).await {
                Ok(()) => {}
                Err(Error::Network(_)) => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    /// The queue's next request (see `Outbox::begin`).
    pub(crate) fn begin(&mut self) -> Option<Job> {
        if self.store.is_guest() {
            return None;
        }
        self.outbox.begin(&mut self.report.rejected)
    }

    /// Records the server's response to `job`, and saves the queue. `Err`:
    /// sending stops (network lost, session expired), the rest waits.
    pub(crate) async fn finish(
        &mut self,
        job: Job,
        result: Result<Value, Error>,
    ) -> Result<(), Error> {
        self.outbox.in_flight.clear();
        match result {
            Err(Error::Network(message)) => {
                self.mark_offline();
                self.persist_outbox()?;
                return Err(Error::Network(message));
            }
            Err(Error::SessionExpired) => {
                self.persist_outbox()?;
                return Err(Error::SessionExpired);
            }
            result => match job {
                Job::Save { seq, .. } => self.finish_save(seq, result).await,
                Job::Batch { entries, .. } => self.finish_batch(&entries, result),
            },
        }
        self.persist_outbox()
    }

    async fn finish_save(&mut self, seq: u64, result: Result<Value, Error>) {
        let Some(index) = self.outbox.position(seq) else {
            return;
        };
        let entry = self.outbox.entries[index].clone();
        let Change::Save {
            created,
            cipher,
            conflict,
        } = entry.change
        else {
            return;
        };
        let result = result.and_then(|body| {
            let id = if created {
                body_id(&body)?
            } else {
                entry.id.clone()
            };
            Ok((id, body))
        });
        match result {
            Ok((id, body)) => {
                if created {
                    self.outbox.remap(&entry.id, &id);
                    self.remapped.insert(entry.id.clone(), id.clone());
                    self.report.remapped.push((entry.id.clone(), id.clone()));
                }
                if conflict {
                    self.report.conflicts.push(entry.title.clone());
                }
                if entry.deferred {
                    self.report.sent += 1;
                }
                let mut sent = sent_save(id.clone(), entry.title, *cipher, &body);
                sent.seq = seq;
                let revision = match &sent.change {
                    Change::Save { cipher, .. } => cipher.cipher.revision_date,
                    _ => unreachable!("an edit"),
                };
                self.outbox.entries[index] = sent;
                self.outbox.rebase(&id, revision);
            }
            // Edited, deleted or made inaccessible in the meantime: the
            // local version becomes a copy.
            Err(error) if !created && !conflict => {
                if let Ok((title, copy)) = self.conflict_copy(&cipher).await {
                    let entry = &mut self.outbox.entries[index];
                    entry.id = uuid::Uuid::new_v4().to_string();
                    entry.title = title;
                    entry.change = Change::Save {
                        created: true,
                        cipher: Box::new(copy),
                        conflict: true,
                    };
                } else {
                    self.outbox.entries.remove(index);
                    self.report.rejected.push((entry.title, error.to_string()));
                }
            }
            Err(error) => {
                self.outbox.entries.remove(index);
                // A copy rejected in turn: the original's title.
                let title = match strip_conflict_suffix(&entry.title) {
                    Some(original) if conflict => original.to_owned(),
                    _ => entry.title,
                };
                self.report.rejected.push((title, error.to_string()));
            }
        }
    }

    fn finish_batch(&mut self, entries: &[(u64, String)], result: Result<Value, Error>) {
        match result {
            Ok(body) => {
                let revisions = revisions(&body, entries);
                for (seq, id) in entries {
                    let Some(index) = self.outbox.position(*seq) else {
                        continue;
                    };
                    let entry = &mut self.outbox.entries[index];
                    entry.sent = true;
                    if entry.deferred {
                        self.report.sent += 1;
                    }
                    let known = revisions.get(id.as_str()).copied();
                    if let Change::Action { revision, .. } = &mut entry.change {
                        *revision = known;
                    }
                    if let Some(known) = known {
                        self.outbox.rebase(id, known);
                    }
                }
            }
            // Vaultwarden stops at the first rejected item (those before
            // stay done): one by one, to find out which.
            Err(_) if entries.len() > 1 => {
                self.outbox
                    .singles
                    .extend(entries.iter().map(|(seq, _)| *seq));
            }
            Err(error) => {
                let Some(&(seq, _)) = entries.first() else {
                    return;
                };
                self.outbox.singles.remove(&seq);
                let Some(index) = self.outbox.position(seq) else {
                    return;
                };
                let entry = self.outbox.entries.remove(index);
                // The item no longer exists: nothing to trash.
                let gone = matches!(&error, Error::NotFound)
                    || matches!(&error, Error::Server(m) if m.contains("doesn't exist"));
                if !gone {
                    self.report.rejected.push((entry.title, error.to_string()));
                }
            }
        }
    }

    /// The local version of an item the server refuses to replace, as a
    /// copy to create: "title (offline conflict)", in the same place
    /// (personal vault, or same collections), without its attachments,
    /// which stay on the original.
    async fn conflict_copy(
        &self,
        cipher: &EncryptionContext,
    ) -> Result<(String, EncryptionContext), Error> {
        let mut view = self.decrypt_view(cipher.cipher.clone()).await?;
        view.id = None;
        view.name = format!("{}{CONFLICT_SUFFIX}", view.name);
        view.attachments = None;
        view.attachment_decryption_failures = None;
        let title = view.name.clone();
        Ok((title, self.encrypt_context(view).await?))
    }
}

/// Revision dates returned by an action: the item (`PUT
/// …/{id}/{action}`), or the list (`{ "data": […] }`) of a grouped action.
fn revisions<'a>(body: &Value, entries: &'a [(u64, String)]) -> HashMap<&'a str, DateTime<Utc>> {
    let date = |item: &Value| {
        item.get("revisionDate")
            .and_then(Value::as_str)
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc))
    };
    let items: Vec<&Value> = match body.get("data").and_then(Value::as_array) {
        Some(list) => list.iter().collect(),
        None => vec![body],
    };
    let mut found = HashMap::new();
    for item in items {
        let Some(revision) = date(item) else { continue };
        let id = item.get("id").and_then(Value::as_str);
        let entry = match id {
            Some(id) => entries.iter().find(|(_, e)| e == id),
            // A single item: the response is its own.
            None if entries.len() == 1 => entries.first(),
            None => None,
        };
        if let Some((_, id)) = entry {
            found.insert(id.as_str(), revision);
        }
    }
    found
}

/// The message for an action that is impossible offline.
pub(crate) fn offline_refusal(what: &str) -> String {
    format!("{what} is not possible offline: try again when the server is reachable")
}

/// The API request of an item encrypted by the SDK.
pub(crate) fn request_of(encrypted: EncryptionContext) -> Result<CipherRequestModel, Error> {
    let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
    request.encrypted_for = Some(encrypted.encrypted_for.into());
    request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
    Ok(request)
}

fn body_id(body: &Value) -> Result<String, Error> {
    body.get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Server("item created without an id".to_owned()))
}

/// An accepted edit: the item now carries the server's id and revision
/// date (a later edit, made before the sync, won't look stale).
pub(crate) fn sent_save(
    id: String,
    title: String,
    mut cipher: EncryptionContext,
    body: &Value,
) -> Entry {
    cipher.cipher.id = id.parse().ok();
    if let Some(revision) = body
        .get("revisionDate")
        .and_then(Value::as_str)
        .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
    {
        cipher.cipher.revision_date = revision.with_timezone(&Utc);
    }
    let mut entry = Entry::new(
        id,
        title,
        Change::Save {
            created: false,
            cipher: Box::new(cipher),
            conflict: false,
        },
    );
    entry.sent = true;
    entry
}

/// The provisional ids replaced since the session was opened.
pub(crate) type Remapped = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "00000000-0000-4000-8000-000000000001";

    fn context(id: Option<&str>, favorite: bool) -> EncryptionContext {
        serde_json::from_value(serde_json::json!({
            "encryptedFor": USER,
            "encryptedByKeyId": null,
            "cipher": {
                "id": id, "organizationId": null, "folderId": null, "collectionIds": [],
                "key": null, "name": null, "notes": null, "type": 2, "login": null,
                "identity": null, "card": null, "secureNote": { "type": 0 }, "sshKey": null,
                "favorite": favorite, "reprompt": 0, "organizationUseTotp": false, "edit": true,
                "permissions": null, "viewPassword": true, "localData": null,
                "attachments": null, "fields": null, "passwordHistory": null,
                "creationDate": "2026-01-01T00:00:00Z", "deletedDate": null,
                "revisionDate": "2026-01-01T00:00:00Z", "archivedDate": null, "data": null,
            },
        }))
        .unwrap()
    }

    fn id(n: u8) -> String {
        format!("00000000-0000-4000-8000-0000000000{n:02}")
    }

    fn at() -> DateTime<Utc> {
        "2026-10-14T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn edits_of_one_item_coalesce_and_creations_stay_creations() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(10), "Brouillon".into(), true, context(None, false));
        outbox.push_save(
            id(11),
            "GitHub".into(),
            false,
            context(Some(&id(11)), false),
        );
        outbox.push_save(id(10), "Créé".into(), false, context(Some(&id(10)), true));
        outbox.push_save(
            id(11),
            "GitHub perso".into(),
            false,
            context(Some(&id(11)), true),
        );
        assert_eq!(outbox.pending_changes(), 2);
        assert_eq!(outbox.pending_items(), [id(10), id(11)]);
        assert!(matches!(
            &outbox.entries[0].change,
            Change::Save { created: true, cipher, .. } if cipher.cipher.favorite
        ));
        assert_eq!(outbox.entries[0].title, "Créé");
        assert_eq!(outbox.entries[1].title, "GitHub perso");
    }

    #[test]
    fn an_action_undone_offline_leaves_nothing_to_send() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_action(id(2), "B".into(), Action::Archive, at());
        outbox.push_action(id(1), "A".into(), Action::Restore, at());
        assert_eq!(outbox.pending_items(), [id(2)]);
        // Not the inverse: both stay, in order.
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        assert_eq!(outbox.pending_changes(), 2);
    }

    #[test]
    fn overlay_replaces_adds_and_dates_items() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), true));
        outbox.push_save(id(9), "Nouveau".into(), true, context(None, false));
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        let mut ciphers = vec![
            context(Some(&id(1)), false).cipher,
            context(Some(&id(2)), false).cipher,
        ];
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers.len(), 3);
        assert!(
            ciphers[0].favorite,
            "the local version replaces the cached one"
        );
        assert_eq!(ciphers[0].archived_date, Some(at()));
        assert_eq!(ciphers[1].deleted_date, Some(at()));
        assert_eq!(ciphers[2].id.map(|i| i.to_string()), Some(id(9)));
    }

    #[test]
    fn server_ids_replace_temporary_ones() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(50), "Nouveau".into(), true, context(None, false));
        outbox.push_action(id(50), "Nouveau".into(), Action::Archive, at());
        outbox.remap(&id(50), &id(77));
        assert!(outbox.entries.iter().all(|e| e.id == id(77)));
        let mut ciphers = Vec::new();
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers[0].id.map(|i| i.to_string()), Some(id(77)));
        assert_eq!(ciphers[0].archived_date, Some(at()));
    }

    #[test]
    fn sent_entries_wait_for_the_next_sync_then_go() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), false));
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        let body =
            serde_json::json!({ "id": id(1), "revisionDate": "2026-10-14T12:30:00.123456Z" });
        outbox.entries[0] = sent_save(id(1), "A".into(), context(Some(&id(1)), false), &body);
        assert_eq!(outbox.pending_changes(), 1);
        assert_eq!(outbox.pending_items(), [id(2)]);
        // Once sent, the edit keeps the server's revision date.
        let Change::Save { cipher, .. } = &outbox.entries[0].change else {
            panic!()
        };
        assert_eq!(
            cipher.cipher.revision_date.to_rfc3339(),
            "2026-10-14T12:30:00.123456+00:00"
        );
        assert!(outbox.purge_sent());
        assert_eq!(outbox.entries.len(), 1);
        assert!(!outbox.purge_sent());
    }

    #[test]
    fn the_outbox_round_trips_through_json_in_order() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(3), "C".into(), true, context(None, false));
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_save(id(2), "B".into(), false, context(Some(&id(2)), true));
        let json = serde_json::to_string(&outbox).unwrap();
        let back: Outbox = serde_json::from_str(&json).unwrap();
        let order: Vec<_> = back.entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(order, [id(3), id(1), id(2)]);
        assert!(matches!(
            back.entries[0].change,
            Change::Save { created: true, .. }
        ));
        assert!(matches!(
            back.entries[1].change,
            Change::Action {
                action: Action::Trash,
                ..
            }
        ));
    }

    #[test]
    fn an_edit_made_while_the_previous_one_is_sent_waits_behind_it() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), false));
        let Some(Job::Save { seq, .. }) = outbox_begin(&mut outbox) else {
            panic!("an edit to send")
        };
        // During the send, a new edit of the same item.
        outbox.push_save(id(1), "A bis".into(), false, context(Some(&id(1)), true));
        assert_eq!(outbox.entries.len(), 2, "not merged with the one in flight");
        assert_eq!(outbox.entries[0].title, "A");
        // The server accepts the first: the second starts again from its date.
        outbox.in_flight.clear();
        let body = serde_json::json!({ "id": id(1), "revisionDate": "2026-10-14T13:00:00Z" });
        let mut sent = sent_save(id(1), "A".into(), context(Some(&id(1)), false), &body);
        sent.seq = seq;
        let index = outbox.position(seq).unwrap();
        outbox.entries[index] = sent;
        outbox.rebase(&id(1), "2026-10-14T13:00:00Z".parse().unwrap());
        let Change::Save { cipher, .. } = &outbox.entries[1].change else {
            panic!()
        };
        assert_eq!(
            cipher.cipher.revision_date.to_rfc3339(),
            "2026-10-14T13:00:00+00:00"
        );
        assert_eq!(outbox.pending_items(), [id(1)]);
    }

    #[test]
    fn an_action_in_flight_is_not_cancelled_by_its_inverse() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        assert!(matches!(outbox_begin(&mut outbox), Some(Job::Batch { .. })));
        outbox.push_action(id(1), "A".into(), Action::Unarchive, at());
        assert_eq!(outbox.pending_changes(), 2, "both go out, in order");
    }

    #[test]
    fn saves_go_first_then_actions_by_batches_keeping_each_item_in_order() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        outbox.push_action(id(3), "C".into(), Action::Archive, at());
        // B is trashed before being archived: its archive waits.
        outbox.push_action(id(2), "B".into(), Action::Archive, at());
        outbox.push_move(id(4), "D".into(), Some(id(90)));
        outbox.push_move(id(4), "D".into(), Some(id(91)));
        outbox.push_save(id(5), "E".into(), false, context(Some(&id(5)), true));

        let mut order = Vec::new();
        while let Some(job) = outbox_begin(&mut outbox) {
            let (label, seqs) = match &job {
                Job::Save { seq, id, .. } => (format!("save {id}"), vec![*seq]),
                Job::Batch { batch, entries } => (
                    format!(
                        "{batch:?} {:?}",
                        entries.iter().map(|(_, id)| id.clone()).collect::<Vec<_>>()
                    ),
                    entries.iter().map(|(seq, _)| *seq).collect(),
                ),
            };
            order.push(label);
            outbox.in_flight.clear();
            for seq in seqs {
                let index = outbox.position(seq).unwrap();
                outbox.entries[index].sent = true;
            }
        }
        assert_eq!(
            order,
            [
                format!("save {}", id(5)),
                format!("Action(Archive) {:?}", [id(1), id(3)]),
                format!("Action(Trash) {:?}", [id(2)]),
                format!("Action(Archive) {:?}", [id(2)]),
                format!("Move(Some({:?})) {:?}", id(91), [id(4)]),
            ]
        );
    }

    #[test]
    fn a_refused_batch_is_sent_again_one_by_one() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        let Some(Job::Batch { entries, .. }) = outbox_begin(&mut outbox) else {
            panic!()
        };
        assert_eq!(entries.len(), 2);
        outbox.in_flight.clear();
        outbox.singles.extend(entries.iter().map(|(seq, _)| *seq));
        let Some(Job::Batch { entries, .. }) = outbox_begin(&mut outbox) else {
            panic!()
        };
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn conflict_copies_of_earlier_versions_are_recognised() {
        assert_eq!(
            strip_conflict_suffix("Banque (offline conflict)"),
            Some("Banque")
        );
        assert_eq!(
            strip_conflict_suffix("Banque (conflit hors ligne)"),
            Some("Banque")
        );
        assert_eq!(strip_conflict_suffix("Banque"), None);
    }

    #[test]
    fn moves_and_sent_actions_show_in_the_overlay() {
        let mut outbox = Outbox::default();
        outbox.push_move(id(1), "A".into(), Some(id(90)));
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        let revision: DateTime<Utc> = "2026-10-14T14:00:00Z".parse().unwrap();
        if let Change::Action { revision: r, .. } = &mut outbox.entries[1].change {
            *r = Some(revision);
        }
        let mut ciphers = vec![context(Some(&id(1)), false).cipher];
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers[0].folder_id.map(|f| f.to_string()), Some(id(90)));
        assert_eq!(ciphers[0].revision_date, revision);
    }

    #[test]
    fn action_responses_give_the_new_revision_dates() {
        let entries = vec![(0, id(1)), (1, id(2))];
        let bulk = serde_json::json!({ "data": [
            { "id": id(2), "revisionDate": "2026-10-14T15:00:00Z" },
            { "id": id(1), "revisionDate": "2026-10-14T15:00:01Z" },
        ]});
        let found = revisions(&bulk, &entries);
        assert_eq!(
            found[id(1).as_str()].to_rfc3339(),
            "2026-10-14T15:00:01+00:00"
        );
        assert_eq!(found.len(), 2);
        let single = serde_json::json!({ "revisionDate": "2026-10-14T15:00:00Z" });
        assert_eq!(revisions(&single, &entries[..1]).len(), 1);
        assert!(revisions(&Value::Null, &entries).is_empty());
    }

    fn outbox_begin(outbox: &mut Outbox) -> Option<Job> {
        let mut rejected = Vec::new();
        let job = outbox.begin(&mut rejected);
        assert_eq!(rejected, Vec::<(String, String)>::new());
        job
    }
}
