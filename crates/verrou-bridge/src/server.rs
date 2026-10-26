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
//! client and this item, or until the vault locks for an SSH key whose
//! owner chose [`ApprovalScope::UntilLocked`].
//!
//! An agent can also read the vault's catalog (one approval per agent session,
//! half an hour, [`Purpose::Catalog`]) and propose a reorganization plan, which the user
//! reviews and applies in Verrou ([`crate::plans`], [`crate::organize`]).

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
use verrou_core::duplicates::DuplicateGroup;
use verrou_core::{ItemKind, Vault};
use zeroize::Zeroize as _;

use crate::access::{self, Write};
use crate::clients::{ClientInfo, ClientStore};
use crate::crypto::{Direction, KeyPair};
use crate::organize::{self, Context, PlanReview};
use crate::passkeys;
use crate::plans::{self, ApprovedPlan, Plans};
use crate::protocol::{
    CONFIRM_IN_APP, ClientKind, Command, Credentials, ErrorCode, Incoming, MAX_CLOCK_SKEW_MS,
    MAX_FRAME, Outgoing, Plan, PlanReport, Reply, ReplyResult, Request, RunDetail, SaveAction,
    SecretValue, Suggestion, UnlockIntent, clean_reason, clean_session, clean_text,
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
/// How long the approval to read the vault's catalog holds for a client: an
/// agent that plans a reorganization reads it in several pages.
pub const CATALOG_TTL: Duration = Duration::from_secs(30 * 60);
/// How long an approval holds, chosen by the user per SSH key.
///
/// Only [`Purpose::Ssh`] and [`Purpose::GitSign`] honour anything but the
/// default: a developer signing commits all day should not face Touch ID
/// every five minutes, but a secret revealed to the terminal should.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApprovalScope {
    /// Ask for every use: the approval is never remembered.
    EveryTime,
    /// Ask again after [`APPROVAL_TTL`].
    #[default]
    FiveMinutes,
    /// Ask once: the approval holds until the vault locks
    /// ([`Bridge::forget_approvals`]), which is the only thing that ends it.
    UntilLocked,
    /// Ask again after [`CATALOG_TTL`]: only [`Purpose::Catalog`].
    HalfHour,
}

/// The time given to the user to answer an approval request.
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(90);
/// The longest title, folder or client name shown in an approval, and the
/// longest list of changed fields, in characters.
const MAX_SHOWN: usize = 120;
const MAX_CHANGES: usize = 300;
/// After an agent's request is refused (or left unanswered), this client's
/// next agent requests are refused unasked for this long: a prompt the user
/// just declined must not come back, and back again.
const REFUSAL_PAUSE: Duration = Duration::from_secs(30);
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
    /// A client asks to unlock: bring Verrou to the foreground (the
    /// browser), or ask the paired iPhone if the user is away from the Mac
    /// (the terminal). `reason`: the terminal's, cleaned (empty if none);
    /// `then`: what it will read once unlocked, cleaned.
    /// `client`: the identifier of the client that asks, for what the
    /// approval may then cover ([`Confirmation::client`]).
    fn request_unlock(
        &self,
        kind: ClientKind,
        client: &str,
        reason: &str,
        then: Option<&UnlockIntent>,
    );
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
    /// How long an approval for this purpose and item holds. The default
    /// keeps the historical five minutes; the server ignores any other
    /// answer for a purpose other than SSH or signing.
    fn approval_scope(&self, _purpose: Purpose, _item: &str) -> ApprovalScope {
        ApprovalScope::FiveMinutes
    }
    /// The account's folders, the empty ones too (the vault's items only
    /// tell the folders that hold one).
    fn folders(&self) -> Vec<String> {
        Vec::new()
    }
    /// How many attachments each item has, by identifier (counted in the
    /// cache, nothing is decrypted); the items without any are missing.
    fn attachment_counts(&self) -> BoxFuture<'_, HashMap<String, usize>> {
        Box::pin(async { HashMap::new() })
    }
    /// When each login's password last changed (Unix seconds), by item,
    /// from the cache (nothing is decrypted): for the review of a merge.
    /// Items missing are dated by their creation.
    fn password_dates(&self) -> BoxFuture<'_, HashMap<String, i64>> {
        Box::pin(async { HashMap::new() })
    }
    /// The vault's duplicate groups, as an agent may read them
    /// ([`organize::scan_duplicates`]). `None`: vault locked.
    fn duplicates(&self) -> BoxFuture<'_, Option<Vec<DuplicateGroup>>> {
        Box::pin(async move {
            let attachments = self.attachment_counts().await;
            let mut groups = None;
            self.read(&mut |vault| groups = Some(organize::scan_duplicates(vault, &attachments)));
            groups
        })
    }
    /// An agent's plan awaits the user's review: show it, then answer with
    /// [`Bridge::take_plan`] and [`Bridge::finish_plan`] (apply) or
    /// [`Bridge::decline_plan`]. `false`: it cannot be shown, and the plan
    /// is refused.
    fn plan_proposed(&self, _review: PlanReview) -> bool {
        false
    }
    /// The plan can no longer be reviewed (it expired, or the agent
    /// withdrew it): close its review. `message`: why, for the user.
    fn plan_withdrawn(&self, _plan: &str, _message: &str) {}
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
    /// Terminal: create an item (`item`: its title).
    Create,
    /// Terminal: modify, archive or restore an item.
    Edit,
    /// Terminal: move an item to the trash.
    Delete,
    /// An agent reads the catalog of the vault: titles, usernames, sites,
    /// folders and counts of every item, never a secret. One approval per
    /// agent session covers it for [`CATALOG_TTL`] (`item` is
    /// `catalog:<session>`; a request without a session is asked on its own).
    Catalog,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub client: String,
    pub client_name: String,
    pub purpose: Purpose,
    pub item: String,
    /// The item's title, to show.
    pub title: String,
    /// [`Purpose::LinkSite`]: the host of the site to link to the item;
    /// [`Purpose::Create`], [`Purpose::Edit`]: the folder the item goes to
    /// (empty otherwise). The app words the request itself.
    pub site: String,
    /// Why the terminal asks, as it declares it ([`crate::protocol::clean_reason`]);
    /// empty if it didn't say.
    pub reason: String,
    /// [`Purpose::Create`], [`Purpose::Edit`]: what the write changes, names
    /// only, never a value (`password, url, −Old token`: `−` for a field
    /// removed; [`crate::items::summary`]); empty otherwise.
    pub changes: String,
    /// An agent's command line and the fields it gets
    /// ([`crate::protocol::RunDetail`], cleaned); empty if the request came
    /// without. Unlike the reason, this is what will actually run.
    pub command: String,
    pub fields: String,
    /// An agent's request ([`crate::protocol::Request::ephemeral_approval`]):
    /// it is approved on its own, and nothing the user said earlier (the
    /// iPhone's unlock, a recent approval) covers it.
    pub ephemeral: bool,
}

/// Approvals still valid: (client, purpose, item) → time of the approval
/// and the scope it was given with.
type Approvals = HashMap<(String, Purpose, String), (Instant, ApprovalScope)>;

struct Shared {
    backend: Arc<dyn Backend>,
    clients: Mutex<ClientStore>,
    pending: Mutex<Option<(String, oneshot::Sender<bool>)>>,
    last_pairing: Mutex<Option<Instant>>,
    approvals: Mutex<Approvals>,
    /// When each client's last agent request was refused ([`REFUSAL_PAUSE`]).
    refusals: Mutex<HashMap<String, Instant>>,
    /// Extension: items released recently, per client ([`within_limits`]).
    releases: Mutex<HashMap<String, Vec<(String, Instant)>>>,
    /// `manifest.json` of the extension shipped with the app: read again on every
    /// `status`, to announce its version to the extension.
    extension_manifest: Mutex<Option<PathBuf>>,
    /// Plans an agent proposed, awaiting the user or recently answered.
    plans: Mutex<Plans>,
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
            refusals: Mutex::new(HashMap::new()),
            releases: Mutex::new(HashMap::new()),
            extension_manifest: Mutex::new(None),
            plans: Mutex::new(Plans::default()),
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
    /// This is what ends an [`ApprovalScope::UntilLocked`] approval.
    pub fn forget_approvals(&self) {
        lock(&self.shared.approvals).clear();
    }

    /// Forgets the approvals given for one item, so a change of its scope
    /// (from "until locked" to "every time") applies at once.
    pub fn forget_approvals_of_item(&self, item: &str) {
        lock(&self.shared.approvals).retain(|(_, _, id), _| id != item);
    }

    /// The user applies a plan ([`Backend::plan_proposed`]): the operations
    /// at `accepted` (their positions in the plan) are to be carried out, by
    /// the app, which checks them once more
    /// ([`organize::check_ops`]) and answers with [`Self::finish_plan`].
    /// `Err`: the plan expired, was withdrawn or answered already.
    pub fn take_plan(&self, id: &str, accepted: &[usize]) -> Result<ApprovedPlan, String> {
        lock(&self.shared.plans).take(id, accepted, tokio::time::Instant::now())
    }

    /// The plan was applied: what came of it, for the agent.
    pub fn finish_plan(&self, id: &str, report: PlanReport) {
        lock(&self.shared.plans).finish(id, report, tokio::time::Instant::now());
    }

    /// The user declined the plan (`message`: what the agent is told). The
    /// client's next proposal waits a minute.
    pub fn decline_plan(&self, id: &str, message: &str) {
        lock(&self.shared.plans).decline(id, message, tokio::time::Instant::now());
    }

    /// The user undid an applied plan.
    pub fn mark_undone(&self, id: &str) {
        lock(&self.shared.plans).undone(id, tokio::time::Instant::now());
    }

    /// Applying stopped halfway (`message`: why, for the agent): what was
    /// done before is in `report`. There is nothing to undo.
    pub fn interrupt_plan(&self, id: &str, report: PlanReport, message: &str) {
        lock(&self.shared.plans).interrupt(id, report, message, tokio::time::Instant::now());
    }

    /// The user closed the sheet of this plan (applied, declined, undone…):
    /// the agent may propose another.
    pub fn plan_closed(&self, id: &str) {
        lock(&self.shared.plans).closed(id);
    }

    /// The vault locked: plans awaiting review are dropped.
    pub fn drop_plans(&self) {
        lock(&self.shared.plans).drop_all(tokio::time::Instant::now());
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

#[allow(clippy::too_many_lines)] // one arm per command, readable in one go
async fn answer(shared: &Arc<Shared>, client: &str, iv: &str, data: &str) -> Outgoing {
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
    let reason = crate::protocol::clean_reason(request.reason.as_deref());
    let terminal_ask = Terminal::of(&request, &reason);
    let result = match request.command {
        command if !access::allowed(info.kind, &command) => ReplyResult::Denied {
            reason: "command not allowed for this client".to_owned(),
        },
        // An agent's command that does not fit in the approval is not
        // approved half shown (the client refuses it first; this is for one
        // that does not).
        _ if request.detail.as_ref().is_some_and(|d| !d.fits()) => ReplyResult::Denied {
            reason: request
                .detail
                .as_ref()
                .and_then(|d| d.check().err())
                .unwrap_or(crate::protocol::COMMAND_TOO_LONG)
                .to_owned(),
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
        Command::Unlock { then } => {
            let then = then.map(|intent| intent.cleaned());
            backend.request_unlock(info.kind, &info.id, &reason, then.as_ref());
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
        command => terminal(shared, &info, command, &terminal_ask).await,
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
    approved_for_site(shared, client, purpose, item, title, "", "").await
}

/// Does an approval given at `at` with `scope` still hold at `now`?
fn approval_holds(at: Instant, scope: ApprovalScope, now: Instant) -> bool {
    match scope {
        ApprovalScope::UntilLocked => true,
        ApprovalScope::FiveMinutes => now.saturating_duration_since(at) < APPROVAL_TTL,
        ApprovalScope::HalfHour => now.saturating_duration_since(at) < CATALOG_TTL,
        // Never inserted; dropped if one ever got there.
        ApprovalScope::EveryTime => false,
    }
}

/// The scope the user chose for this use. Defence in depth: whatever the
/// backend says, only SSH and signing may be remembered longer than five
/// minutes or not at all; a secret, a card or a passkey keeps the default.
/// A write from the terminal is never remembered: approving one change to
/// an item is not approving the next.
fn effective_scope(shared: &Shared, purpose: Purpose, item: &str) -> ApprovalScope {
    match purpose {
        Purpose::Ssh | Purpose::GitSign => shared.backend.approval_scope(purpose, item),
        Purpose::Create | Purpose::Edit | Purpose::Delete => ApprovalScope::EveryTime,
        Purpose::Catalog => ApprovalScope::HalfHour,
        _ => ApprovalScope::FiveMinutes,
    }
}

/// [`approved`], with the site the request is about (`LinkSite`) and the
/// terminal's reason.
async fn approved_for_site(
    shared: &Shared,
    client: &ClientInfo,
    purpose: Purpose,
    item: &str,
    title: &str,
    site: &str,
    reason: &str,
) -> bool {
    let ask = Terminal {
        reason,
        ..Terminal::default()
    };
    approve(
        shared,
        ask.confirmation(client, purpose, item, title, site),
        false,
    )
    .await
}

/// What the terminal said about a request, for its approval.
#[derive(Default)]
struct Terminal<'a> {
    reason: &'a str,
    /// An agent's request: asked on its own, never remembered
    /// ([`Request::ephemeral_approval`]).
    ephemeral: bool,
    detail: RunDetail,
    /// The agent session ([`clean_session`]), if it said which.
    session: Option<String>,
}

impl<'a> Terminal<'a> {
    /// From the request, with its reason already cleaned and its detail
    /// cleaned here: nothing the client sent is shown as it came.
    fn of(request: &Request, reason: &'a str) -> Self {
        Self {
            reason,
            ephemeral: request.ephemeral_approval,
            detail: request
                .detail
                .as_ref()
                .map(RunDetail::cleaned)
                .unwrap_or_default(),
            session: clean_session(request.session.as_deref()),
        }
    }

    /// The confirmation the user is asked: the reason and the agent's detail
    /// as the terminal gave them; no write changes.
    fn confirmation(
        &self,
        client: &ClientInfo,
        purpose: Purpose,
        item: &str,
        title: &str,
        site: &str,
    ) -> Confirmation {
        Confirmation {
            client: client.id.clone(),
            client_name: clean_text(&client.name, MAX_SHOWN),
            purpose,
            item: item.to_owned(),
            title: clean_text(title, MAX_SHOWN),
            site: clean_text(site, MAX_SHOWN),
            reason: self.reason.to_owned(),
            changes: String::new(),
            command: self.detail.command.clone(),
            fields: self.detail.fields_line(),
            ephemeral: self.ephemeral,
        }
    }
}

/// Asks the user for `request`, unless an approval for the same client,
/// purpose and item still holds. `ephemeral`: an agent's request, asked on
/// its own and never remembered.
async fn approve(shared: &Shared, request: Confirmation, ephemeral: bool) -> bool {
    approve_with(shared, request, !ephemeral, ephemeral).await
}

/// [`approve`], with its two halves apart. `remember`: an approval given
/// earlier covers this request, and this one is kept. `agent`: an agent
/// asks, so a refusal pauses its next prompts ([`REFUSAL_PAUSE`]). The
/// catalog is both an agent's and remembered (half an hour): one approval
/// for the pages an agent reads.
async fn approve_with(shared: &Shared, request: Confirmation, remember: bool, agent: bool) -> bool {
    let (purpose, item) = (request.purpose, request.item.clone());
    let entry = (request.client.clone(), purpose, item.clone());
    if agent {
        // A prompt the user just declined for this client does not come back.
        let mut refusals = lock(&shared.refusals);
        refusals.retain(|_, at| at.elapsed() < REFUSAL_PAUSE);
        if refusals.contains_key(&request.client) {
            return false;
        }
    }
    if remember {
        let mut approvals = lock(&shared.approvals);
        approvals.retain(|_, (at, scope)| approval_holds(*at, *scope, Instant::now()));
        if approvals.contains_key(&entry) {
            return true;
        }
    }
    let granted = tokio::time::timeout(CONFIRMATION_TIMEOUT, shared.backend.confirm(request))
        .await
        .unwrap_or(false);
    if !granted && agent && shared.backend.is_unlocked() {
        // Declined or left unanswered (a vault that locked meanwhile is
        // neither).
        lock(&shared.refusals).insert(entry.0.clone(), Instant::now());
    }
    if granted && remember {
        let scope = effective_scope(shared, purpose, &item);
        if scope != ApprovalScope::EveryTime {
            lock(&shared.approvals).insert(entry, (Instant::now(), scope));
        }
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

/// Terminal: an approval that couldn't hold because the vault locked
/// meanwhile (screen locked while the iPhone was asked) is not a refusal:
/// the terminal asks for the unlock, then again.
fn refused_or_locked(backend: &dyn Backend) -> ReplyResult {
    if backend.is_unlocked() {
        refused()
    } else {
        ReplyResult::Locked
    }
}

fn refused() -> ReplyResult {
    ReplyResult::Denied {
        reason: "refused in Verrou".to_owned(),
    }
}

/// Terminal commands (already filtered by [`access::allowed`]).
#[allow(clippy::too_many_lines)] // one branch per command, readable in one go
async fn terminal(
    shared: &Arc<Shared>,
    client: &ClientInfo,
    command: Command,
    ask: &Terminal<'_>,
) -> ReplyResult {
    let reason = ask.reason;
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
                    if !approve(
                        shared,
                        ask.confirmation(client, Purpose::Reveal, &item, &title, ""),
                        ask.ephemeral,
                    )
                    .await
                    {
                        return refused_or_locked(backend);
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
            if !approve(
                shared,
                ask.confirmation(client, Purpose::Reveal, &item, &title, ""),
                ask.ephemeral,
            )
            .await
            {
                return refused_or_locked(backend);
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
        command @ (Command::ItemCreate { .. }
        | Command::ItemEdit { .. }
        | Command::ItemMove { .. }) => item_write(shared, client, command, ask).await,
        command @ (Command::VaultOverview
        | Command::VaultList { .. }
        | Command::VaultDuplicates) => catalog(shared, client, command, ask).await,
        command @ (Command::PlanPropose { .. }
        | Command::PlanStatus { .. }
        | Command::PlanCancel { .. }) => plan_command(shared, client, command, ask).await,
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
            if !approved_for_site(shared, client, purpose, &item, &title, "", reason).await {
                return refused_or_locked(backend);
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

/// The terminal writes an item ([`crate::items`]): checked first (a write
/// that would be refused asks nothing), approved by the user in Verrou,
/// then carried out by the app, which checks it again.
async fn item_write(
    shared: &Shared,
    client: &ClientInfo,
    command: Command,
    ask: &Terminal<'_>,
) -> ReplyResult {
    let backend = &*shared.backend;
    // Built twice: to ask for the approval, then for the app to carry out.
    let plan = |command: Command| -> Option<WritePlan> {
        Some(match command {
            Command::ItemCreate { changes } => {
                Box::new(move |_: &Vault| crate::items::plan_create(changes))
            }
            Command::ItemEdit { item, changes } => {
                Box::new(move |v: &Vault| crate::items::plan_edit(v, &item, changes))
            }
            Command::ItemMove { item, to } => Box::new(move |v: &Vault| {
                crate::items::plan_move(v, &item, to).map(|(write, _)| write)
            }),
            _ => return None,
        })
    };
    let Some(check) = plan(command.clone()) else {
        return ReplyResult::Denied {
            reason: "unexpected command".to_owned(),
        };
    };
    // What the approval says: the purpose, the item, its title, and the
    // folder it goes to (created if missing), in `site`.
    let checked = read(backend, |v| {
        let title_of = |item: &str| v.get(item).map(|i| i.title.clone()).unwrap_or_default();
        let folder = |changes: &crate::protocol::ItemChanges| {
            changes
                .folder
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .to_owned()
        };
        check(v).map(|write| match &write {
            access::Write::NewItem { changes } => {
                let title = changes.title.clone().unwrap_or_default();
                let summary = crate::items::summary(changes, true);
                (
                    Purpose::Create,
                    title.clone(),
                    title,
                    folder(changes),
                    summary,
                )
            }
            access::Write::EditItem { item, changes } => {
                let summary = crate::items::summary(changes, false);
                (
                    Purpose::Edit,
                    item.clone(),
                    title_of(item),
                    folder(changes),
                    summary,
                )
            }
            access::Write::MoveItem { item, to } => (
                if *to == crate::items::StateChange::Trash {
                    Purpose::Delete
                } else {
                    Purpose::Edit
                },
                item.clone(),
                title_of(item),
                String::new(),
                String::new(),
            ),
            _ => (
                Purpose::Edit,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        })
    });
    let (purpose, item, title, folder, changes) = match checked {
        None => return ReplyResult::Locked,
        Some(Err(reason)) => return ReplyResult::Denied { reason },
        Some(Ok(found)) => found,
    };
    // Never remembered (`effective_scope`): each write asks.
    let request = Confirmation {
        changes: clean_text(&changes, MAX_CHANGES),
        ..ask.confirmation(client, purpose, &item, &title, &folder)
    };
    if !approve(shared, request, ask.ephemeral).await {
        return refused_or_locked(backend);
    }
    match plan(command) {
        Some(write) => written(backend.write(write).await),
        None => refused(),
    }
}

// MARK: Organizing

/// What the user approves to let an agent session read the catalog.
const CATALOG_TITLE: &str =
    "the vault's catalog: titles, usernames, sites, folders and counts, no secret";

/// The item an approval to read the catalog is kept under: one per agent
/// session, so that an approval given to one agent run is not another run's
/// (every `verrou mcp` of a terminal is the same paired client).
fn catalog_item(session: &str) -> String {
    format!("catalog:{session}")
}

/// Does this agent session hold an approval to read the catalog? Looked up,
/// never asked: a plan is proposed by an agent that has read the vault.
fn catalog_held(shared: &Shared, client: &ClientInfo, session: Option<&str>) -> bool {
    let Some(session) = session else {
        return false;
    };
    let entry = (client.id.clone(), Purpose::Catalog, catalog_item(session));
    lock(&shared.approvals)
        .get(&entry)
        .is_some_and(|(at, scope)| approval_holds(*at, *scope, Instant::now()))
}

/// An agent reads the vault's catalog ([`crate::organize`]): the user
/// approves it once for [`CATALOG_TTL`] for this agent session, then every
/// page is free. A request without a session is asked on its own and not
/// remembered. A refusal still pauses that agent's prompts.
async fn catalog(
    shared: &Shared,
    client: &ClientInfo,
    command: Command,
    ask: &Terminal<'_>,
) -> ReplyResult {
    let backend = &*shared.backend;
    if !backend.is_unlocked() {
        return ReplyResult::Locked;
    }
    let remembered = ask.session.is_some();
    let item = catalog_item(ask.session.as_deref().unwrap_or("once"));
    let request = Confirmation {
        ephemeral: !remembered,
        ..ask.confirmation(client, Purpose::Catalog, &item, CATALOG_TITLE, "")
    };
    if !approve_with(shared, request, remembered, ask.ephemeral).await {
        return refused_or_locked(backend);
    }
    match command {
        Command::VaultOverview => {
            let folders = backend.folders();
            read(backend, |v| organize::overview(v, &folders))
                .map_or(ReplyResult::Locked, ReplyResult::Overview)
        }
        Command::VaultList {
            offset,
            limit,
            archived,
        } => {
            let attachments = backend.attachment_counts().await;
            read(backend, |v| {
                organize::catalog(v, &attachments, offset, limit, archived)
            })
            .map_or(ReplyResult::Locked, |(items, total)| ReplyResult::Catalog {
                items,
                total: u32::try_from(total).unwrap_or(u32::MAX),
            })
        }
        Command::VaultDuplicates => {
            let Some(groups) = backend.duplicates().await else {
                return ReplyResult::Locked;
            };
            read(backend, |v| organize::duplicate_infos(&groups, v)).map_or(
                ReplyResult::Locked,
                |(groups, total)| ReplyResult::Duplicates {
                    groups,
                    total: u32::try_from(total).unwrap_or(u32::MAX),
                },
            )
        }
        _ => ReplyResult::Denied {
            reason: "unexpected command".to_owned(),
        },
    }
}

/// The longest an agent's `plan_status` may wait, in seconds.
const MAX_WAIT: u32 = 60;

/// An agent's plan: proposed, followed, withdrawn.
async fn plan_command(
    shared: &Arc<Shared>,
    client: &ClientInfo,
    command: Command,
    ask: &Terminal<'_>,
) -> ReplyResult {
    let denied = |reason: &str| ReplyResult::Denied {
        reason: reason.to_owned(),
    };
    let session = ask.session.clone().unwrap_or_default();
    match command {
        Command::PlanPropose { plan } => plan_propose(shared, client, &session, plan).await,
        Command::PlanStatus { plan, wait } => {
            let Some(mut changes) = lock(&shared.plans).subscribe(&client.id, &session, &plan)
            else {
                return denied("no such plan (a finished plan is kept ten minutes)");
            };
            // Wait for the plan to leave review and application, or for the
            // time asked: the user reviews at their pace.
            let wait = Duration::from_secs(u64::from(wait.min(MAX_WAIT)));
            let _ = tokio::time::timeout(wait, async {
                while changes.borrow_and_update().state.is_open() {
                    if changes.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
            match lock(&shared.plans).state(
                &client.id,
                &session,
                &plan,
                tokio::time::Instant::now(),
            ) {
                Some(state) => ReplyResult::Plan(state),
                None => denied("no such plan (a finished plan is kept ten minutes)"),
            }
        }
        Command::PlanCancel { plan } => {
            let now = tokio::time::Instant::now();
            let cancelled = lock(&shared.plans).cancel(&client.id, &session, &plan, now);
            match cancelled {
                Err(reason) => ReplyResult::Denied { reason },
                Ok(was_waiting) => {
                    if was_waiting {
                        shared
                            .backend
                            .plan_withdrawn(&plan, "the agent withdrew the plan");
                    }
                    match lock(&shared.plans).state(&client.id, &session, &plan, now) {
                        Some(state) => ReplyResult::Plan(state),
                        None => denied("no such plan"),
                    }
                }
            }
        }
        _ => denied("unexpected command"),
    }
}

/// Checks the plan against the unlocked vault, then hands it to the app for
/// the user to review. It answers at once: the user answers later, and the
/// agent follows with `plan_status`.
async fn plan_propose(
    shared: &Arc<Shared>,
    client: &ClientInfo,
    session: &str,
    plan: Plan,
) -> ReplyResult {
    let backend = &*shared.backend;
    let denied = |reason: String| ReplyResult::Denied { reason };
    if !backend.is_unlocked() {
        return ReplyResult::Locked;
    }
    // Every proposal counts, whatever becomes of it.
    if let Err(reason) = lock(&shared.plans).attempt(&client.id, tokio::time::Instant::now()) {
        return denied(reason);
    }
    // A plan comes from an agent that has read the vault, with the user's
    // approval for this session: looked up, never asked.
    if !catalog_held(shared, client, (!session.is_empty()).then_some(session)) {
        return denied(
            "the user has not let this session read the vault: read it with verrou_list_items first, then propose the plan"
                .to_owned(),
        );
    }
    if let Err(reason) = lock(&shared.plans).admit(&client.id, tokio::time::Instant::now()) {
        return denied(reason);
    }
    let folders = backend.folders();
    let attachments = backend.attachment_counts().await;
    let password_dates = backend.password_dates().await;
    let Some(groups) = backend.duplicates().await else {
        return ReplyResult::Locked;
    };
    let checked = read(backend, |v| {
        organize::validate(
            &plan,
            v,
            &Context {
                groups: &groups,
                attachments: &attachments,
                folders: &folders,
                password_dates: &password_dates,
            },
        )
    });
    let checked = match checked {
        None => return ReplyResult::Locked,
        Some(Err(reason)) => return denied(reason),
        Some(Ok(checked)) => checked,
    };
    let reason = clean_reason(Some(&plan.reason));
    // Admitted again, under the lock that registers the plan: a proposal
    // that was admitted while this one was being checked may have got there
    // first.
    let registered = lock(&shared.plans).register(
        &client.id,
        session,
        &reason,
        (
            checked.ops.clone(),
            checked.refused.clone(),
            checked.unchanged,
        ),
        tokio::time::Instant::now(),
    );
    let (id, state) = match registered {
        Ok(registered) => registered,
        Err(reason) => return denied(reason),
    };
    let review = PlanReview {
        id: id.clone(),
        client: client.id.clone(),
        client_name: clean_text(&client.name, MAX_SHOWN),
        reason,
        ops: checked.ops,
        refused: checked.refused,
        expires_in: plans::REVIEW_TTL.as_secs(),
    };
    if !backend.plan_proposed(review) {
        lock(&shared.plans).discard(&id, &client.id);
        return denied(
            "Verrou cannot show the plan for review right now: try again later".to_owned(),
        );
    }
    tokio::spawn(expire_later(Arc::clone(shared), id));
    ReplyResult::Plan(state)
}

/// Nobody reviewed the plan in time: it expires, and the app closes it.
async fn expire_later(shared: Arc<Shared>, id: String) {
    tokio::time::sleep(plans::REVIEW_TTL).await;
    let waiting = lock(&shared.plans).expire(&id, tokio::time::Instant::now());
    if waiting {
        shared
            .backend
            .plan_withdrawn(&id, "nobody reviewed the plan in time: nothing was applied");
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
                "",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approvals_hold_according_to_their_scope() {
        let at = Instant::now();
        let later = at + APPROVAL_TTL + Duration::from_secs(1);
        // Five minutes: fresh holds, stale does not.
        assert!(approval_holds(at, ApprovalScope::FiveMinutes, at));
        assert!(!approval_holds(at, ApprovalScope::FiveMinutes, later));
        // Until locked: no timer at all.
        assert!(approval_holds(at, ApprovalScope::UntilLocked, later));
        // Every time: never.
        assert!(!approval_holds(at, ApprovalScope::EveryTime, at));
        // The catalog: half an hour, and no longer.
        assert!(approval_holds(
            at,
            ApprovalScope::HalfHour,
            at + CATALOG_TTL.checked_sub(Duration::from_secs(1)).unwrap()
        ));
        assert!(!approval_holds(
            at,
            ApprovalScope::HalfHour,
            at + CATALOG_TTL
        ));
        // Only the catalog gets it, whatever the backend says.
        assert_eq!(CATALOG_TTL, Duration::from_secs(30 * 60));
    }

    fn item(id: &str, title: &str) -> verrou_core::Item {
        verrou_core::Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: String::new(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: Vec::new(),
            notes: None,
            reprompt: false,
            state: verrou_core::ItemState::Active,
            shared: None,
        }
    }

    /// A backend that records the plans it is told were withdrawn, and how
    /// many approvals it was asked for.
    #[derive(Default)]
    struct Recorder {
        withdrawn: Mutex<Vec<(String, String)>>,
        confirmed: std::sync::atomic::AtomicUsize,
        proposed: Mutex<Vec<String>>,
        /// Held by the checks of a proposal: two proposals meet here.
        meeting: Option<Arc<tokio::sync::Barrier>>,
    }

    impl Backend for Recorder {
        fn is_unlocked(&self) -> bool {
            true
        }
        fn suggestions(&self, _: &str) -> Option<Vec<Suggestion>> {
            None
        }
        fn credentials(&self, _: &str, _: &str) -> Option<Result<Credentials, String>> {
            None
        }
        fn check_save(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Option<Result<(SaveAction, Option<Suggestion>), String>> {
            None
        }
        fn write(&self, _: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>> {
            Box::pin(async { None })
        }
        fn request_unlock(&self, _: ClientKind, _: &str, _: &str, _: Option<&UnlockIntent>) {}
        fn pairing_requested(&self, _: PairingRequest) {}
        fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool {
            reader(&Vault::new(vec![item("a", "Alpha"), item("b", "Beta")]));
            true
        }
        fn confirm(&self, _: Confirmation) -> BoxFuture<'_, bool> {
            self.confirmed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { true })
        }
        fn attachment_counts(&self) -> BoxFuture<'_, HashMap<String, usize>> {
            Box::pin(async move {
                if let Some(meeting) = &self.meeting {
                    meeting.wait().await;
                }
                HashMap::new()
            })
        }
        fn plan_proposed(&self, review: PlanReview) -> bool {
            lock(&self.proposed).push(review.id);
            true
        }
        fn plan_withdrawn(&self, plan: &str, message: &str) {
            lock(&self.withdrawn).push((plan.to_owned(), message.to_owned()));
        }
    }

    fn shared(backend: Arc<Recorder>) -> Arc<Shared> {
        let file =
            std::env::temp_dir().join(format!("verrou-server-{}.json", uuid::Uuid::new_v4()));
        Arc::new(Shared {
            backend,
            clients: Mutex::new(ClientStore::open(file)),
            pending: Mutex::new(None),
            last_pairing: Mutex::new(None),
            approvals: Mutex::new(HashMap::new()),
            refusals: Mutex::new(HashMap::new()),
            releases: Mutex::new(HashMap::new()),
            extension_manifest: Mutex::new(None),
            plans: Mutex::new(Plans::default()),
        })
    }

    fn waiting_plan(shared: &Shared, client: &str) -> String {
        let op = organize::CheckedOp {
            index: 0,
            op: crate::protocol::PlanOp::Archive {
                item: "a".to_owned(),
                rationale: "r".to_owned(),
            },
            rationale: "r".to_owned(),
            flags: Vec::new(),
            depends_on: None,
            display: organize::Display::default(),
            others: Vec::new(),
        };
        lock(&shared.plans)
            .register(
                client,
                SESSION,
                "tidy",
                (vec![op], Vec::new(), 0),
                tokio::time::Instant::now(),
            )
            .unwrap()
            .0
    }

    const SESSION: &str = "0123456789abcdef";

    fn agent() -> ClientInfo {
        ClientInfo {
            id: "agent".to_owned(),
            name: "verrou".to_owned(),
            created: 0,
            kind: ClientKind::Cli,
        }
    }

    fn ask_in(session: Option<&str>) -> Terminal<'static> {
        Terminal {
            ephemeral: true,
            session: session.map(str::to_owned),
            ..Terminal::default()
        }
    }

    fn one_plan() -> Plan {
        Plan {
            reason: "tidy".to_owned(),
            operations: vec![crate::protocol::PlanOp::Archive {
                item: "a".to_owned(),
                rationale: "old".to_owned(),
            }],
        }
    }

    /// Ten minutes of paused time: the review expires on its own, the app is
    /// told to close it, and the agent reads why.
    #[tokio::test(start_paused = true)]
    async fn a_plan_nobody_reviews_expires_and_the_app_is_told() {
        let backend = Arc::new(Recorder::default());
        let shared = shared(Arc::clone(&backend));
        let id = waiting_plan(&shared, "agent");
        let timer = tokio::spawn(expire_later(Arc::clone(&shared), id.clone()));
        tokio::time::sleep(
            plans::REVIEW_TTL
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        assert!(lock(&backend.withdrawn).is_empty(), "not yet");
        tokio::time::sleep(Duration::from_secs(2)).await;
        timer.await.unwrap();
        assert_eq!(lock(&backend.withdrawn).len(), 1);
        let state = lock(&shared.plans)
            .state("agent", SESSION, &id, tokio::time::Instant::now())
            .unwrap();
        assert_eq!(state.state, crate::protocol::PlanPhase::Expired);
        assert!(state.message.contains("in time"));
    }

    /// A plan the user answered before the timer fires is not "withdrawn".
    #[tokio::test(start_paused = true)]
    async fn an_answered_plan_does_not_expire() {
        let backend = Arc::new(Recorder::default());
        let shared = shared(Arc::clone(&backend));
        let id = waiting_plan(&shared, "agent");
        let timer = tokio::spawn(expire_later(Arc::clone(&shared), id.clone()));
        lock(&shared.plans).decline(&id, "no", tokio::time::Instant::now());
        tokio::time::sleep(plans::REVIEW_TTL + Duration::from_secs(1)).await;
        timer.await.unwrap();
        assert!(lock(&backend.withdrawn).is_empty());
        // Still declined, not expired (the entry itself is forgotten ten
        // minutes after the answer).
        let mut plans = lock(&shared.plans);
        let state = plans.state("agent", SESSION, &id, tokio::time::Instant::now());
        assert!(state.is_none_or(|s| s.state == crate::protocol::PlanPhase::Declined));
    }

    /// `plan_status` waits for the answer, but never longer than asked.
    #[tokio::test(start_paused = true)]
    async fn a_status_waits_for_the_answer_up_to_the_time_asked() {
        let backend = Arc::new(Recorder::default());
        let shared = shared(Arc::clone(&backend));
        let id = waiting_plan(&shared, "agent");
        let client = agent();
        let ask = ask_in(Some(SESSION));
        let status = |wait: u32| {
            plan_command(
                &shared,
                &client,
                Command::PlanStatus {
                    plan: id.clone(),
                    wait,
                },
                &ask,
            )
        };
        // Nobody answers: it comes back after the wait, still awaiting.
        let started = tokio::time::Instant::now();
        let ReplyResult::Plan(state) = status(50).await else {
            panic!("a plan state");
        };
        assert_eq!(state.state, crate::protocol::PlanPhase::AwaitingReview);
        assert_eq!(started.elapsed(), Duration::from_secs(50));
        // Asked for more than a minute: a minute.
        let started = tokio::time::Instant::now();
        let _ = status(3600).await;
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        // The user declines meanwhile: it comes back at once.
        let (shared2, id2) = (Arc::clone(&shared), id.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            lock(&shared2.plans).decline(&id2, "no", tokio::time::Instant::now());
        });
        let started = tokio::time::Instant::now();
        let ReplyResult::Plan(state) = status(50).await else {
            panic!("a plan state");
        };
        assert_eq!(state.state, crate::protocol::PlanPhase::Declined);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        // Not someone else's plan.
        let stranger = ClientInfo {
            id: "stranger".to_owned(),
            ..client.clone()
        };
        let reply = plan_command(
            &shared,
            &stranger,
            Command::PlanStatus {
                plan: id.clone(),
                wait: 0,
            },
            &ask_in(Some(SESSION)),
        )
        .await;
        assert!(matches!(reply, ReplyResult::Denied { .. }));
        // Nor another session's of the same client.
        let reply = plan_command(
            &shared,
            &client,
            Command::PlanStatus { plan: id, wait: 0 },
            &ask_in(Some("fedcba9876543210")),
        )
        .await;
        assert!(matches!(reply, ReplyResult::Denied { .. }));
    }

    /// The approval to read the catalog belongs to the agent session: the
    /// next session is asked again, a request without a session is asked
    /// every time.
    #[tokio::test]
    async fn the_catalog_approval_belongs_to_the_agent_session() {
        let backend = Arc::new(Recorder::default());
        let shared = shared(Arc::clone(&backend));
        let client = agent();
        let asked = || backend.confirmed.load(std::sync::atomic::Ordering::SeqCst);
        let read = |session: Option<&'static str>| {
            let (shared, client) = (Arc::clone(&shared), client.clone());
            async move { catalog(&shared, &client, Command::VaultOverview, &ask_in(session)).await }
        };
        assert!(matches!(
            read(Some(SESSION)).await,
            ReplyResult::Overview(_)
        ));
        assert_eq!(asked(), 1);
        let _ = read(Some(SESSION)).await;
        assert_eq!(asked(), 1, "remembered for the session");
        let _ = read(Some("fedcba9876543210")).await;
        assert_eq!(asked(), 2, "another session is asked again");
        let _ = read(None).await;
        let _ = read(None).await;
        assert_eq!(asked(), 4, "without a session, asked every time");
        let held = |session| catalog_held(&shared, &client, Some(session));
        assert!(held(SESSION) && held("fedcba9876543210"));
        assert!(!held("00000000ffffffff"));
        assert!(!catalog_held(&shared, &client, None));
    }

    /// A plan comes from a session that read the vault: never asked for
    /// here, refused with what to do. Refused proposals count too.
    #[tokio::test]
    async fn a_plan_needs_the_catalog_read_in_the_same_session() {
        let backend = Arc::new(Recorder::default());
        let shared = shared(Arc::clone(&backend));
        let client = agent();
        let refused = plan_propose(&shared, &client, SESSION, one_plan()).await;
        let ReplyResult::Denied { reason } = refused else {
            panic!("refused");
        };
        assert!(reason.contains("verrou_list_items"), "{reason}");
        assert_eq!(
            backend.confirmed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "nothing was asked"
        );
        assert!(lock(&backend.proposed).is_empty(), "the user saw nothing");
        // Another session's approval does not count.
        let _ = catalog(
            &shared,
            &client,
            Command::VaultOverview,
            &ask_in(Some("fedcba9876543210")),
        )
        .await;
        assert!(matches!(
            plan_propose(&shared, &client, SESSION, one_plan()).await,
            ReplyResult::Denied { .. }
        ));
        // Every proposal is counted, up to the cap.
        for _ in 2..plans::MAX_ATTEMPTS {
            let _ = plan_propose(&shared, &client, SESSION, one_plan()).await;
        }
        let ReplyResult::Denied { reason } =
            plan_propose(&shared, &client, SESSION, one_plan()).await
        else {
            panic!("refused");
        };
        assert!(reason.contains("at most 30"), "{reason}");
    }

    /// Two proposals admitted while their plans were being checked: only the
    /// first reaches the user.
    #[tokio::test]
    async fn two_concurrent_proposals_do_not_both_reach_the_user() {
        let backend = Arc::new(Recorder {
            meeting: Some(Arc::new(tokio::sync::Barrier::new(2))),
            ..Recorder::default()
        });
        let shared = shared(Arc::clone(&backend));
        let client = agent();
        lock(&shared.approvals).insert(
            (client.id.clone(), Purpose::Catalog, catalog_item(SESSION)),
            (Instant::now(), ApprovalScope::HalfHour),
        );
        let (first, second) = tokio::join!(
            plan_propose(&shared, &client, SESSION, one_plan()),
            plan_propose(&shared, &client, SESSION, one_plan()),
        );
        let reached = [&first, &second]
            .iter()
            .filter(|r| matches!(r, ReplyResult::Plan(_)))
            .count();
        assert_eq!(reached, 1, "{first:?} {second:?}");
        assert_eq!(lock(&backend.proposed).len(), 1);
        let refused = [&first, &second]
            .into_iter()
            .find_map(|r| match r {
                ReplyResult::Denied { reason } => Some(reason.clone()),
                _ => None,
            })
            .unwrap();
        assert!(refused.contains("awaiting"), "{refused}");
    }
}
