//! The bridge server, in the app: listens on `127.0.0.1` only.
//!
//! The macOS sandbox denies the app Unix sockets outside its container;
//! the local port is reachable by any program on the machine, hence
//! pairing and the encryption of every message: without a client key, one
//! can only ask for a pairing, which the user must accept in
//! Verrou after comparing the code.
//!
//! Two kinds of clients: the browser extension and the terminal
//! (`verrou`). Each only has its own commands ([`crate::access::allowed`]).
//! For the terminal, a secret or an SSH signature awaits the user's
//! approval ([`Backend::confirm`]), kept [`APPROVAL_TTL`] for this
//! client and this item.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;
use url::Url;
use verrou_core::{ItemKind, Vault};
use zeroize::Zeroize as _;

use crate::access::{self, Write};
use crate::clients::{ClientInfo, ClientStore};
use crate::crypto::{Direction, KeyPair};
use crate::passkeys;
use crate::protocol::{
    CONFIRM_IN_APP, ClientKind, Command, Credentials, ErrorCode, Incoming, MAX_CLOCK_SKEW_MS,
    MAX_FRAME, Outgoing, Reply, ReplyResult, Request, SaveAction, SecretValue, Suggestion,
};
use crate::ssh;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A write request from the extension, to check against the unlocked vault.
pub type WritePlan = Box<dyn FnOnce(&verrou_core::Vault) -> Result<Write, String> + Send>;

/// The time given to the user to accept a pairing.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// Minimum gap between two pairing requests: a program cannot
/// flood the user with windows.
const PAIRING_INTERVAL: Duration = Duration::from_secs(3);
/// How long the user's approval holds for a client and
/// an item: `verrou get` then `verrou totp`, or several SSH connections
/// in a row, without asking for Touch ID again.
pub const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
/// The time given to the user to answer an approval request.
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(90);
/// Extension: beyond `BULK_ITEMS` different items released to a
/// client within `BULK_WINDOW`, each further item requires the user's
/// approval ([`Purpose::Bulk`]). The client itself asserts the page's
/// address: a stolen pairing key could claim each login
/// for its own site, and silently empty the vault without this limit.
const BULK_ITEMS: usize = 8;
const BULK_WINDOW: Duration = Duration::from_secs(10 * 60);

/// What the app provides to the bridge.
pub trait Backend: Send + Sync + 'static {
    fn is_unlocked(&self) -> bool;
    /// `None`: vault locked.
    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>>;
    /// `None`: vault locked; `Err`: refusal, with its reason.
    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>>;
    /// `None`: vault locked; `Err`: refusal. See [`crate::access::check_save`].
    fn check_save(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        current: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>>;
    /// Checks the write request against the vault ([`crate::access::plan_save`],
    /// [`crate::access::plan_totp`]), then carries it out. `None`: vault
    /// locked; `Ok`: the identifier of the written item.
    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>>;
    /// The extension asks to unlock: bring Verrou to the foreground.
    fn request_unlock(&self);
    /// Pairing request: show `code` and ask for approval, then
    /// answer with [`Bridge::answer_pairing`].
    fn pairing_requested(&self, request: PairingRequest);
    /// Reads the unlocked vault, for the terminal: `reader` is
    /// called once. `false`: vault locked.
    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool;
    /// Ask the user to allow an access from the terminal (Touch ID,
    /// or the session password). `true`: granted.
    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool>;
    /// Can the secrets of `item` leave for the browser? A
    /// protected item ("master password re-prompt") awaits a
    /// confirmation: the app asks for it, and the answer is `false` until then.
    fn gate(&self, item: &verrou_core::Item) -> bool {
        !item.reprompt
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRequest {
    pub id: String,
    /// Name announced by the client ("Brave"). Declarative: only the code
    /// proves anything.
    pub name: String,
    pub code: String,
    /// What the client will be able to do once linked.
    pub kind: ClientKind,
}

/// What the terminal asks for, to be confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Read a secret of the item (concealed field, notes, one-time code).
    Reveal,
    /// Sign with the item's SSH key.
    Ssh,
    /// Extension: use or create a passkey when the site asks for
    /// user verification (the item, or `passkey:<site>` for a
    /// new login).
    Passkey,
    /// Sign a git commit or tag with the item's SSH key
    /// (`ssh-keygen -Y sign -n git`). Approval separate from [`Purpose::Ssh`]:
    /// accepting a connection is not approval to sign, nor the reverse.
    GitSign,
    /// Extension: link the page's site to a login (written to
    /// the vault and synced). `item` also carries the site: the approval only
    /// holds for that site.
    LinkSite,
    /// Extension: fill a form with a payment card.
    Card,
    /// Extension: release one more item, beyond `BULK_ITEMS` in a short
    /// time.
    Bulk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub client: String,
    pub client_name: String,
    pub purpose: Purpose,
    pub item: String,
    /// The item's title, to show.
    pub title: String,
    /// [`Purpose::LinkSite`]: the host of the site to link to the item
    /// (empty otherwise). The app words the request itself.
    pub site: String,
}

/// Approvals still valid: (client, purpose, item) → time of the approval.
type Approvals = HashMap<(String, Purpose, String), Instant>;

struct Shared {
    backend: Arc<dyn Backend>,
    clients: Mutex<ClientStore>,
    pending: Mutex<Option<(String, oneshot::Sender<bool>)>>,
    last_pairing: Mutex<Option<Instant>>,
    approvals: Mutex<Approvals>,
    /// Extension: items released recently, per client ([`within_limits`]).
    releases: Mutex<HashMap<String, Vec<(String, Instant)>>>,
    /// `manifest.json` of the extension shipped with the app: read again on every
    /// `status`, to announce its version to the extension.
    extension_manifest: Mutex<Option<PathBuf>>,
}

/// The running bridge. Dropping it stops it.
pub struct Bridge {
    shared: Arc<Shared>,
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Listens on `127.0.0.1:port` (`0`: a free port, for tests).
    pub fn start(port: u16, clients_file: PathBuf, backend: Arc<dyn Backend>) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", port))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Shared {
            backend,
            clients: Mutex::new(ClientStore::open(clients_file)),
            pending: Mutex::new(None),
            last_pairing: Mutex::new(None),
            approvals: Mutex::new(HashMap::new()),
            releases: Mutex::new(HashMap::new()),
            extension_manifest: Mutex::new(None),
        });
        let (shutdown, mut stop) = oneshot::channel::<()>();
        let state = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("verrou-bridge".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(listener) else {
                        return;
                    };
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                if let Ok((stream, _)) = accepted {
                                    let (reader, writer) = stream.into_split();
                                    tokio::spawn(serve(Arc::clone(&state), reader, writer));
                                }
                            }
                        }
                    }
                });
                runtime.shutdown_background();
            })?;
        Ok(Self {
            shared,
            port,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The user's answer to a pairing request.
    pub fn answer_pairing(&self, id: &str, approved: bool) {
        let mut pending = lock(&self.shared.pending);
        if pending
            .as_ref()
            .is_some_and(|(pending_id, _)| pending_id == id)
            && let Some((_, answer)) = pending.take()
        {
            let _ = answer.send(approved);
        }
    }

    pub fn clients(&self) -> Vec<ClientInfo> {
        lock(&self.shared.clients).list()
    }

    pub fn revoke(&self, id: &str) {
        lock(&self.shared.clients).remove(id);
        lock(&self.shared.approvals).retain(|(client, _, _), _| client != id);
    }

    /// The `manifest.json` of the extension shipped with the app (see
    /// [`crate::bundled_extension_manifest`]): its version is announced in
    /// the response to `status`, so the extension reloads when the app has
    /// been updated.
    pub fn set_extension_manifest(&self, path: Option<PathBuf>) {
        *lock(&self.shared.extension_manifest) = path;
    }

    /// Forgets the approvals given to the terminal (when the vault locks).
    pub fn forget_approvals(&self) {
        lock(&self.shared.approvals).clear();
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Native Messaging frame: length on 4 bytes (native byte order,
/// little-endian on Mac), then the JSON. The host relays the bytes as is.
async fn read_frame(reader: &mut OwnedReadHalf) -> Option<Vec<u8>> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await.ok()?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return None;
    }
    let mut frame = vec![0u8; length];
    reader.read_exact(&mut frame).await.ok()?;
    Some(frame)
}

async fn write_frame(writer: &mut OwnedWriteHalf, message: &Outgoing) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

async fn serve(shared: Arc<Shared>, mut reader: OwnedReadHalf, mut writer: OwnedWriteHalf) {
    while let Some(frame) = read_frame(&mut reader).await {
        let reply = match serde_json::from_slice::<Incoming>(&frame) {
            Ok(Incoming::Pair { name, key, kind }) => {
                if pair(&shared, &name, &key, kind, &mut writer).await.is_err() {
                    return;
                }
                continue;
            }
            Ok(Incoming::Request { client, iv, data }) => {
                answer(&shared, &client, &iv, &data).await
            }
            Err(_) => Outgoing::Error {
                code: ErrorCode::BadRequest,
            },
        };
        if write_frame(&mut writer, &reply).await.is_err() {
            return;
        }
    }
}

async fn pair(
    shared: &Shared,
    name: &str,
    peer_key: &str,
    kind: ClientKind,
    writer: &mut OwnedWriteHalf,
) -> io::Result<()> {
    let busy = {
        let mut last = lock(&shared.last_pairing);
        let busy =
            lock(&shared.pending).is_some() || last.is_some_and(|t| t.elapsed() < PAIRING_INTERVAL);
        if !busy {
            *last = Some(Instant::now());
        }
        busy
    };
    if busy {
        return write_frame(
            writer,
            &Outgoing::Error {
                code: ErrorCode::Busy,
            },
        )
        .await;
    }
    let ours = KeyPair::generate();
    let Ok(key) = ours.agree(peer_key, true) else {
        return write_frame(
            writer,
            &Outgoing::Error {
                code: ErrorCode::BadRequest,
            },
        )
        .await;
    };
    let id = uuid::Uuid::new_v4().to_string();
    let name: String = name.chars().filter(|c| !c.is_control()).take(40).collect();
    write_frame(
        writer,
        &Outgoing::Pairing {
            client: id.clone(),
            key: ours.public_base64(),
        },
    )
    .await?;

    let (answer, decision) = oneshot::channel();
    *lock(&shared.pending) = Some((id.clone(), answer));
    shared.backend.pairing_requested(PairingRequest {
        id: id.clone(),
        name: name.clone(),
        code: key.pairing_code(),
        kind,
    });
    let approved = tokio::time::timeout(PAIRING_TIMEOUT, decision)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    {
        let mut pending = lock(&shared.pending);
        if pending
            .as_ref()
            .is_some_and(|(pending_id, _)| *pending_id == id)
        {
            pending.take();
        }
    }
    if approved {
        lock(&shared.clients).add(id, name, kind, &key, now_ms() / 1000);
        write_frame(writer, &Outgoing::Paired).await
    } else {
        write_frame(writer, &Outgoing::Refused).await
    }
}

async fn answer(shared: &Shared, client: &str, iv: &str, data: &str) -> Outgoing {
    let bad = Outgoing::Error {
        code: ErrorCode::BadRequest,
    };
    let found = lock(&shared.clients).get(client);
    let Some((key, info)) = found else {
        return Outgoing::Error {
            code: ErrorCode::UnknownClient,
        };
    };
    let Ok(mut plain) = key.open(client, Direction::Request, iv, data) else {
        return bad;
    };
    let request = serde_json::from_slice::<Request>(&plain);
    plain.zeroize();
    let Ok(request) = request else {
        return bad;
    };
    if (now_ms() - request.ts).abs() > MAX_CLOCK_SKEW_MS {
        return bad;
    }
    let backend = &shared.backend;
    let result = match request.command {
        command if !access::allowed(info.kind, &command) => ReplyResult::Denied {
            reason: "command not allowed for this client".to_owned(),
        },
        Command::Status => ReplyResult::Status {
            unlocked: backend.is_unlocked(),
            extension_version: lock(&shared.extension_manifest)
                .as_deref()
                .and_then(crate::extension_version_at),
        },
        Command::Suggest { url } => match backend.suggestions(&url) {
            None => ReplyResult::Locked,
            Some(items) => ReplyResult::Suggestions { items },
        },
        Command::Fill { url, item } => fill(shared, &info, &url, &item).await,
        command @ (Command::Forms { .. }
        | Command::FillForm { .. }
        | Command::LinkSite { .. }
        | Command::SearchLogins { .. }) => forms(shared, &info, command).await,
        command @ (Command::PasskeyList(_)
        | Command::PasskeyGet(_)
        | Command::PasskeyTargets(_)
        | Command::PasskeyCreate(_)) => passkey(shared, &info, command).await,
        Command::Unlock => {
            backend.request_unlock();
            ReplyResult::Done
        }
        Command::Check {
            url,
            username,
            password,
            current,
        } => match backend.check_save(&url, &username, &password, current.as_deref()) {
            None => ReplyResult::Locked,
            Some(Ok((action, item))) => ReplyResult::Check { action, item },
            Some(Err(reason)) => ReplyResult::Denied { reason },
        },
        Command::Save {
            url,
            username,
            password,
            item,
        } => written(
            backend
                .write(Box::new(move |vault| {
                    crate::access::plan_save(vault, &url, &username, &password, item.as_deref())
                }))
                .await,
        ),
        Command::SetTotp { url, totp, item } => written(
            backend
                .write(Box::new(move |vault| {
                    crate::access::plan_totp(vault, &url, &totp, item.as_deref())
                }))
                .await,
        ),
        command => terminal(shared, &info, command).await,
    };
    let Ok(mut body) = serde_json::to_vec(&Reply {
        id: request.id,
        result,
    }) else {
        return bad;
    };
    let (iv, data) = key.seal(client, Direction::Response, &body);
    body.zeroize();
    Outgoing::Response { iv, data }
}

/// Reads the unlocked vault; `None`: locked.
fn read<T>(backend: &dyn Backend, f: impl FnOnce(&Vault) -> T) -> Option<T> {
    let mut f = Some(f);
    let mut out = None;
    let unlocked = backend.read(&mut |vault| {
        if let Some(f) = f.take() {
            out = Some(f(vault));
        }
    });
    if unlocked { out } else { None }
}

/// Does the user allow this client this use of the item? A
/// recent approval for the same triple is enough.
async fn approved(
    shared: &Shared,
    client: &ClientInfo,
    purpose: Purpose,
    item: &str,
    title: &str,
) -> bool {
    approved_for_site(shared, client, purpose, item, title, "").await
}

/// [`approved`], with the site the request is about (`LinkSite`).
async fn approved_for_site(
    shared: &Shared,
    client: &ClientInfo,
    purpose: Purpose,
    item: &str,
    title: &str,
    site: &str,
) -> bool {
    let entry = (client.id.clone(), purpose, item.to_owned());
    {
        let mut approvals = lock(&shared.approvals);
        approvals.retain(|_, at| at.elapsed() < APPROVAL_TTL);
        if approvals.contains_key(&entry) {
            return true;
        }
    }
    let request = Confirmation {
        client: client.id.clone(),
        client_name: client.name.clone(),
        purpose,
        item: item.to_owned(),
        title: title.to_owned(),
        site: site.to_owned(),
    };
    let granted = tokio::time::timeout(CONFIRMATION_TIMEOUT, shared.backend.confirm(request))
        .await
        .unwrap_or(false);
    if granted {
        lock(&shared.approvals).insert(entry, Instant::now());
    }
    granted
}

/// The login `item` for the page `url` (the extension), within the limit
/// of items released in a short time ([`within_limits`]).
async fn fill(shared: &Shared, client: &ClientInfo, url: &str, item: &str) -> ReplyResult {
    let backend = &*shared.backend;
    match backend.credentials(item, url) {
        None => ReplyResult::Locked,
        Some(Ok(credentials)) => {
            if within_limits(shared, client, item, &title_of(backend, item)).await {
                ReplyResult::Credentials(credentials)
            } else {
                refused()
            }
        }
        Some(Err(reason)) if reason == CONFIRM_IN_APP => ReplyResult::Confirm,
        Some(Err(reason)) => ReplyResult::Denied { reason },
    }
}

/// The item's title, for an approval request (empty if it is gone).
fn title_of(backend: &dyn Backend, item: &str) -> String {
    read(backend, |v| v.get(item).map(|i| i.title.clone()))
        .flatten()
        .unwrap_or_default()
}

/// Can the extension receive `item`? Yes if it is among the items
/// released to this client within `BULK_WINDOW`, or if there is room left;
/// beyond that, the user must approve it in Verrou ([`Purpose::Bulk`]).
async fn within_limits(shared: &Shared, client: &ClientInfo, item: &str, title: &str) -> bool {
    let room = {
        let mut releases = lock(&shared.releases);
        let recent = releases.entry(client.id.clone()).or_default();
        recent.retain(|(_, at)| at.elapsed() < BULK_WINDOW);
        if recent.iter().any(|(id, _)| id == item) {
            return true;
        }
        recent.len() < BULK_ITEMS
    };
    if !room && !approved(shared, client, Purpose::Bulk, item, title).await {
        return false;
    }
    released(shared, client, item);
    true
}

/// Records the item among those released to this client ([`within_limits`]).
fn released(shared: &Shared, client: &ClientInfo, item: &str) {
    lock(&shared.releases)
        .entry(client.id.clone())
        .or_default()
        .push((item.to_owned(), Instant::now()));
}

fn refused() -> ReplyResult {
    ReplyResult::Denied {
        reason: "refused in Verrou".to_owned(),
    }
}

/// Terminal commands (already filtered by [`access::allowed`]).
#[allow(clippy::too_many_lines)] // one branch per command, readable in one go
async fn terminal(shared: &Shared, client: &ClientInfo, command: Command) -> ReplyResult {
    let backend = &*shared.backend;
    let denied = |reason: String| ReplyResult::Denied { reason };
    match command {
        Command::VaultSearch {
            query,
            kind,
            favorites,
            limit,
        } => match read(backend, |v| {
            access::search(v, &query, kind, favorites, limit)
        }) {
            None => ReplyResult::Locked,
            Some((items, total)) => ReplyResult::Items {
                items,
                total: u32::try_from(total).unwrap_or(u32::MAX),
            },
        },
        Command::VaultItem { query } => {
            match read(backend, |v| access::find(v, &query).map(access::item_view)) {
                None => ReplyResult::Locked,
                Some(Ok(item)) => ReplyResult::Item { item },
                Some(Err(reason)) => denied(reason),
            }
        }
        Command::Reveal { item, field } => {
            let check = read(backend, |v| {
                access::field_needs_confirmation(v, &item, &field)
                    .map(|needed| (needed, access::title_of(v, &item).unwrap_or_default()))
            });
            match check {
                None => return ReplyResult::Locked,
                Some(Err(reason)) => return denied(reason),
                Some(Ok((true, title))) => {
                    if !approved(shared, client, Purpose::Reveal, &item, &title).await {
                        return refused();
                    }
                }
                Some(Ok((false, _))) => {}
            }
            match read(backend, |v| access::field_value(v, &item, &field)) {
                None => ReplyResult::Locked,
                Some(Ok(value)) => ReplyResult::Secret(SecretValue { value }),
                Some(Err(reason)) => denied(reason),
            }
        }
        Command::Totp { item } => {
            let found = read(backend, |v| {
                v.get(&item).map(|i| (i.title.clone(), i.has_totp()))
            });
            let title = match found {
                None => return ReplyResult::Locked,
                Some(None) => return denied("item not found".to_owned()),
                Some(Some((title, false))) => {
                    return denied(format!("\"{title}\" has no one-time code"));
                }
                Some(Some((title, true))) => title,
            };
            if !approved(shared, client, Purpose::Reveal, &item, &title).await {
                return refused();
            }
            let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
            match read(backend, |v| access::totp_code(v, &item, now)) {
                None => ReplyResult::Locked,
                Some(Ok((code, period, remaining))) => ReplyResult::Code {
                    code,
                    period,
                    remaining,
                },
                Some(Err(reason)) => denied(reason),
            }
        }
        Command::Unlink => {
            lock(&shared.clients).remove(&client.id);
            lock(&shared.approvals).retain(|(id, _, _), _| *id != client.id);
            ReplyResult::Done
        }
        Command::SshKeys => match read(backend, ssh::identities) {
            None => ReplyResult::Locked,
            Some(keys) => ReplyResult::SshKeys { keys },
        },
        Command::SshSign {
            public_key,
            data,
            flags,
        } => {
            let (Ok(blob), Ok(mut data)) = (
                BASE64.decode(public_key.as_bytes()),
                BASE64.decode(data.as_bytes()),
            ) else {
                return denied("unreadable SSH request".to_owned());
            };
            let found = read(backend, |v| {
                ssh::key_item(v, &blob).map(|i| (i.id.clone(), i.title.clone()))
            });
            let (item, title) = match found {
                None => return ReplyResult::Locked,
                Some(None) => return denied("unknown SSH key".to_owned()),
                Some(Some(found)) => found,
            };
            // `ssh-keygen -Y sign -n git` (git with `gpg.format=ssh`): the
            // approval request says so.
            let purpose = if ssh::is_git_signature(&data) {
                Purpose::GitSign
            } else {
                Purpose::Ssh
            };
            if !approved(shared, client, purpose, &item, &title).await {
                return refused();
            }
            let signed = read(backend, |v| ssh::sign(v, &blob, &data, flags));
            data.zeroize();
            match signed {
                None => ReplyResult::Locked,
                Some(Ok(signature)) => ReplyResult::Signature {
                    signature: BASE64.encode(&signature),
                },
                Some(Err(reason)) => denied(reason),
            }
        }
        // Extension commands: already handled, or refused by `allowed`.
        _ => denied("command not allowed for this client".to_owned()),
    }
}

fn written(outcome: Option<Result<String, String>>) -> ReplyResult {
    match outcome {
        None => ReplyResult::Locked,
        Some(Ok(item)) => ReplyResult::Saved { item },
        Some(Err(reason)) => ReplyResult::Denied { reason },
    }
}

/// Cards, identities and linking a site (browser).
/// Cards, identities and linking a site (the extension). A card, or
/// a site added to a login, always requires the user's approval
/// in Verrou.
async fn forms(shared: &Shared, client: &ClientInfo, command: Command) -> ReplyResult {
    let backend = &*shared.backend;
    match command {
        Command::Forms { url } => match read(backend, |v| access::form_suggestions(v, &url)) {
            None => ReplyResult::Locked,
            Some((cards, identities)) => ReplyResult::Forms { cards, identities },
        },
        Command::FillForm { url, item } => {
            let found = read(backend, |v| {
                access::form_data(v, &item, &url).map(|data| {
                    let found = v.get(&item);
                    let card = found.is_some_and(|i| i.kind == ItemKind::Card);
                    (
                        data,
                        card,
                        found.map(|i| i.title.clone()).unwrap_or_default(),
                    )
                })
            });
            let (data, card, title) = match found {
                None => return ReplyResult::Locked,
                Some(Err(reason)) => return ReplyResult::Denied { reason },
                Some(Ok(found)) => found,
            };
            // Approval for a card also confirms a protected item (the app
            // allows it): a single request.
            let allowed = if card {
                let ok = approved(shared, client, Purpose::Card, &item, &title).await;
                if ok {
                    released(shared, client, &item);
                }
                ok
            } else {
                within_limits(shared, client, &item, &title).await
            };
            if !allowed {
                return refused();
            }
            match read(backend, |v| v.get(&item).is_some_and(|i| backend.gate(i))) {
                None => ReplyResult::Locked,
                Some(false) => ReplyResult::Confirm,
                Some(true) => ReplyResult::Form(Box::new(data)),
            }
        }
        Command::LinkSite { url, item } => {
            // Checked first: no approval request for a write
            // that would be refused.
            let checked = read(backend, |v| {
                access::plan_link_site(v, &url, &item)
                    .map(|_| v.get(&item).map(|i| i.title.clone()).unwrap_or_default())
            });
            let title = match checked {
                None => return ReplyResult::Locked,
                Some(Err(reason)) => return ReplyResult::Denied { reason },
                Some(Ok(title)) => title,
            };
            let host = Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_default();
            if !approved_for_site(
                shared,
                client,
                Purpose::LinkSite,
                &format!("{item} {host}"),
                &title,
                &host,
            )
            .await
            {
                return refused();
            }
            written(
                backend
                    .write(Box::new(move |vault| {
                        access::plan_link_site(vault, &url, &item)
                    }))
                    .await,
            )
        }
        Command::SearchLogins { query } => {
            match read(backend, |v| access::search_logins(v, &query)) {
                None => ReplyResult::Locked,
                Some(items) => ReplyResult::Suggestions { items },
            }
        }
        _ => ReplyResult::Denied {
            reason: "unexpected command".to_owned(),
        },
    }
}

// MARK: Passkeys

/// The page's passkeys ([`crate::passkeys`]). User verification
/// requested by the site goes through Verrou's approval (Touch
/// ID); otherwise, a protected item awaits its confirmation, as when
/// filling.
async fn passkey(shared: &Shared, client: &ClientInfo, command: Command) -> ReplyResult {
    let backend = &*shared.backend;
    let denied = |reason: String| ReplyResult::Denied { reason };
    match command {
        Command::PasskeyList(query) => match read(backend, |v| passkeys::list(v, &query)) {
            None => ReplyResult::Locked,
            Some(Ok(items)) => ReplyResult::Passkeys { items },
            Some(Err(reason)) => denied(reason),
        },
        Command::PasskeyTargets(query) => match read(backend, |v| passkeys::targets(v, &query)) {
            None => ReplyResult::Locked,
            Some(Ok((excluded, logins))) => ReplyResult::PasskeyTargets { excluded, logins },
            Some(Err(reason)) => denied(reason),
        },
        Command::PasskeyGet(request) => {
            let found = read(backend, |v| {
                passkeys::find(v, &request).map(|(item, _)| (item.id.clone(), item.title.clone()))
            });
            let (item, title) = match found {
                None => return ReplyResult::Locked,
                Some(Err(reason)) => return denied(reason),
                Some(Ok(found)) => found,
            };
            if request.uv {
                // Verrou's approval also covers a protected item.
                if !approved(shared, client, Purpose::Passkey, &item, &title).await {
                    return refused();
                }
                released(shared, client, &item);
            } else {
                if !within_limits(shared, client, &item, &title).await {
                    return refused();
                }
                match read(backend, |v| v.get(&item).is_some_and(|i| backend.gate(i))) {
                    None => return ReplyResult::Locked,
                    Some(false) => return ReplyResult::Confirm,
                    Some(true) => {}
                }
            }
            let uv = request.uv;
            let slot = Arc::new(Mutex::new(None));
            let out = Arc::clone(&slot);
            let outcome = backend
                .write(Box::new(move |vault| {
                    let (write, assertion) = passkeys::plan_assertion(vault, &request, uv)?;
                    *lock(&out) = Some(assertion);
                    Ok(write)
                }))
                .await;
            let assertion = lock(&slot).take();
            match (written(outcome), assertion) {
                (ReplyResult::Saved { .. }, Some(assertion)) => ReplyResult::Assertion(assertion),
                (ReplyResult::Saved { .. }, None) => denied("passkey unavailable".to_owned()),
                (other, _) => other,
            }
        }
        Command::PasskeyCreate(request) => {
            let (key, title) = match read(backend, |v| passkeys::check_creation(v, &request)) {
                None => return ReplyResult::Locked,
                Some(Err(reason)) => return denied(reason),
                Some(Ok(found)) => found,
            };
            if request.uv && !approved(shared, client, Purpose::Passkey, &key, &title).await {
                return refused();
            }
            let uv = request.uv;
            let now = now_ms() / 1000;
            let slot = Arc::new(Mutex::new(None));
            let out = Arc::clone(&slot);
            let outcome = backend
                .write(Box::new(move |vault| {
                    let (write, registration) = passkeys::plan_creation(vault, &request, uv, now)?;
                    *lock(&out) = Some(registration);
                    Ok(write)
                }))
                .await;
            let registration = lock(&slot).take();
            match (written(outcome), registration) {
                (ReplyResult::Saved { item }, Some(mut registration)) => {
                    registration.item = item;
                    ReplyResult::Registration(registration)
                }
                (ReplyResult::Saved { .. }, None) => denied("passkey unavailable".to_owned()),
                (other, _) => other,
            }
        }
        _ => denied("unexpected command".to_owned()),
    }
}
