//! Serveur du pont, dans l'app : écoute sur `127.0.0.1` seulement.
//!
//! Le sandbox de macOS refuse à l'app les sockets Unix hors de son conteneur ;
//! le port local est joignable par tout programme de la machine, d'où
//! l'appairage et le chiffrement de chaque message : sans clé de client, on ne
//! peut que demander un appairage, que l'utilisateur doit accepter dans
//! Verrou après avoir comparé le code.
//!
//! Deux natures de clients : l'extension de navigateur et le terminal
//! (`verrou`). Chacune n'a que ses commandes ([`crate::access::allowed`]).
//! Pour le terminal, un secret ou une signature SSH attend l'accord de
//! l'utilisateur ([`Backend::confirm`]), gardé [`APPROVAL_TTL`] pour ce
//! client et cet élément.

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
use verrou_core::Vault;
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

/// Demande d'écriture de l'extension, à vérifier sur le coffre déverrouillé.
pub type WritePlan = Box<dyn FnOnce(&verrou_core::Vault) -> Result<Write, String> + Send>;

/// Le temps laissé à l'utilisateur pour accepter un appairage.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// Écart minimal entre deux demandes d'appairage : un programme ne peut pas
/// noyer l'utilisateur sous les fenêtres.
const PAIRING_INTERVAL: Duration = Duration::from_secs(3);
/// Durée pendant laquelle l'accord de l'utilisateur vaut pour un client et
/// un élément : `verrou get` puis `verrou totp`, ou plusieurs connexions SSH
/// de suite, sans redemander Touch ID.
pub const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
/// Le temps laissé à l'utilisateur pour répondre à une demande d'accord.
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(90);

/// Ce que l'app fournit au pont.
pub trait Backend: Send + Sync + 'static {
    fn is_unlocked(&self) -> bool;
    /// `None` : coffre verrouillé.
    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>>;
    /// `None` : coffre verrouillé ; `Err` : refus, avec sa raison.
    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>>;
    /// `None` : coffre verrouillé ; `Err` : refus. Voir [`crate::access::check_save`].
    fn check_save(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        current: Option<&str>,
    ) -> Option<Result<(SaveAction, Option<Suggestion>), String>>;
    /// Vérifie la demande d'écriture sur le coffre ([`crate::access::plan_save`],
    /// [`crate::access::plan_totp`]), puis l'exécute. `None` : coffre
    /// verrouillé ; `Ok` : l'identifiant de l'élément écrit.
    fn write(&self, plan: WritePlan) -> BoxFuture<'_, Option<Result<String, String>>>;
    /// L'extension demande à déverrouiller : amener Verrou au premier plan.
    fn request_unlock(&self);
    /// Demande d'appairage : afficher `code` et demander l'accord, puis
    /// répondre par [`Bridge::answer_pairing`].
    fn pairing_requested(&self, request: PairingRequest);
    /// Lecture du coffre déverrouillé, pour le terminal : `reader` est
    /// appelé une fois. `false` : coffre verrouillé.
    fn read(&self, reader: &mut dyn FnMut(&Vault)) -> bool;
    /// Demander à l'utilisateur d'autoriser un accès du terminal (Touch ID,
    /// ou le mot de passe de la session). `true` : accordé.
    fn confirm(&self, request: Confirmation) -> BoxFuture<'_, bool>;
    /// Les secrets de `item` peuvent-ils sortir vers le navigateur ? Un
    /// élément protégé (« redemander le mot de passe principal ») attend une
    /// confirmation : l'app la demande, et la réponse est `false` d'ici là.
    fn gate(&self, item: &verrou_core::Item) -> bool {
        !item.reprompt
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRequest {
    pub id: String,
    /// Nom annoncé par le client (« Brave »). Déclaratif : seul le code
    /// prouve quelque chose.
    pub name: String,
    pub code: String,
    /// Ce que le client pourra faire une fois relié.
    pub kind: ClientKind,
}

/// Ce que le terminal demande, à faire confirmer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Lire un secret de l'élément (champ masqué, notes, code à usage unique).
    Reveal,
    /// Signer avec la clé SSH de l'élément.
    Ssh,
    /// Extension : utiliser ou créer une passkey quand le site demande la
    /// vérification de l'utilisateur (l'élément, ou `passkey:<site>` pour un
    /// nouvel identifiant).
    Passkey,
    /// Signer un commit ou une étiquette git avec la clé SSH de l'élément
    /// (`ssh-keygen -Y sign -n git`). Accord distinct de [`Purpose::Ssh`] :
    /// accepter une connexion ne vaut pas accord pour signer, ni l'inverse.
    GitSign,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub client: String,
    pub client_name: String,
    pub purpose: Purpose,
    pub item: String,
    /// Titre de l'élément, à montrer.
    pub title: String,
}

/// Accords en cours de validité : (client, objet, élément) → date de l'accord.
type Approvals = HashMap<(String, Purpose, String), Instant>;

struct Shared {
    backend: Arc<dyn Backend>,
    clients: Mutex<ClientStore>,
    pending: Mutex<Option<(String, oneshot::Sender<bool>)>>,
    last_pairing: Mutex<Option<Instant>>,
    approvals: Mutex<Approvals>,
}

/// Le pont en marche. Le libérer l'arrête.
pub struct Bridge {
    shared: Arc<Shared>,
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Écoute sur `127.0.0.1:port` (`0` : un port libre, pour les tests).
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

    /// Réponse de l'utilisateur à une demande d'appairage.
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

    /// Oublie les accords donnés au terminal (au verrouillage du coffre).
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

/// Trame Native Messaging : longueur sur 4 octets (ordre de la machine,
/// petit-boutiste sur Mac), puis le JSON. L'hôte relaie les octets tels quels.
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
            reason: "commande refusée à ce client".to_owned(),
        },
        Command::Status => ReplyResult::Status {
            unlocked: backend.is_unlocked(),
        },
        Command::Suggest { url } => match backend.suggestions(&url) {
            None => ReplyResult::Locked,
            Some(items) => ReplyResult::Suggestions { items },
        },
        Command::Fill { url, item } => match backend.credentials(&item, &url) {
            None => ReplyResult::Locked,
            Some(Ok(credentials)) => ReplyResult::Credentials(credentials),
            Some(Err(reason)) if reason == CONFIRM_IN_APP => ReplyResult::Confirm,
            Some(Err(reason)) => ReplyResult::Denied { reason },
        },
        command @ (Command::Forms { .. }
        | Command::FillForm { .. }
        | Command::LinkSite { .. }
        | Command::SearchLogins { .. }) => forms(&**backend, command).await,
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

/// Lit le coffre déverrouillé ; `None` : verrouillé.
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

/// L'utilisateur autorise-t-il ce client à cet usage de l'élément ? Un
/// accord récent pour le même trio suffit.
async fn approved(
    shared: &Shared,
    client: &ClientInfo,
    purpose: Purpose,
    item: &str,
    title: &str,
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
    };
    let granted = tokio::time::timeout(CONFIRMATION_TIMEOUT, shared.backend.confirm(request))
        .await
        .unwrap_or(false);
    if granted {
        lock(&shared.approvals).insert(entry, Instant::now());
    }
    granted
}

fn refused() -> ReplyResult {
    ReplyResult::Denied {
        reason: "refusé dans Verrou".to_owned(),
    }
}

/// Commandes du terminal (déjà filtrées par [`access::allowed`]).
#[allow(clippy::too_many_lines)] // une branche par commande, lisible d'un trait
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
                Some(None) => return denied("élément introuvable".to_owned()),
                Some(Some((title, false))) => {
                    return denied(format!("« {title} » n'a pas de code à usage unique"));
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
                return denied("requête SSH illisible".to_owned());
            };
            let found = read(backend, |v| {
                ssh::key_item(v, &blob).map(|i| (i.id.clone(), i.title.clone()))
            });
            let (item, title) = match found {
                None => return ReplyResult::Locked,
                Some(None) => return denied("clé SSH inconnue".to_owned()),
                Some(Some(found)) => found,
            };
            // `ssh-keygen -Y sign -n git` (git en `gpg.format=ssh`) : la
            // demande d'accord le dit.
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
        // Commandes de l'extension : déjà traitées, ou refusées par `allowed`.
        _ => denied("commande refusée à ce client".to_owned()),
    }
}

fn written(outcome: Option<Result<String, String>>) -> ReplyResult {
    match outcome {
        None => ReplyResult::Locked,
        Some(Ok(item)) => ReplyResult::Saved { item },
        Some(Err(reason)) => ReplyResult::Denied { reason },
    }
}

/// Cartes, identités et rattachement d'un site (navigateur).
async fn forms(backend: &dyn Backend, command: Command) -> ReplyResult {
    match command {
        Command::Forms { url } => match read(backend, |v| access::form_suggestions(v, &url)) {
            None => ReplyResult::Locked,
            Some((cards, identities)) => ReplyResult::Forms { cards, identities },
        },
        Command::FillForm { url, item } => {
            let outcome = read(backend, |v| {
                access::form_data(v, &item, &url).and_then(|data| {
                    let allowed = v.get(&item).is_some_and(|i| backend.gate(i));
                    if allowed {
                        Ok(data)
                    } else {
                        Err(CONFIRM_IN_APP.to_owned())
                    }
                })
            });
            match outcome {
                None => ReplyResult::Locked,
                Some(Ok(data)) => ReplyResult::Form(Box::new(data)),
                Some(Err(reason)) if reason == CONFIRM_IN_APP => ReplyResult::Confirm,
                Some(Err(reason)) => ReplyResult::Denied { reason },
            }
        }
        Command::LinkSite { url, item } => written(
            backend
                .write(Box::new(move |vault| {
                    access::plan_link_site(vault, &url, &item)
                }))
                .await,
        ),
        Command::SearchLogins { query } => {
            match read(backend, |v| access::search_logins(v, &query)) {
                None => ReplyResult::Locked,
                Some(items) => ReplyResult::Suggestions { items },
            }
        }
        _ => ReplyResult::Denied {
            reason: "commande inattendue".to_owned(),
        },
    }
}

// MARK: Passkeys

/// Passkeys de la page ([`crate::passkeys`]). La vérification de
/// l'utilisateur demandée par le site passe par l'accord de Verrou (Touch
/// ID) ; sinon, un élément protégé attend sa confirmation, comme au
/// remplissage.
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
                // L'accord de Verrou couvre aussi un élément protégé.
                if !approved(shared, client, Purpose::Passkey, &item, &title).await {
                    return refused();
                }
            } else {
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
                (ReplyResult::Saved { .. }, None) => denied("passkey indisponible".to_owned()),
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
                (ReplyResult::Saved { .. }, None) => denied("passkey indisponible".to_owned()),
                (other, _) => other,
            }
        }
        _ => denied("commande inattendue".to_owned()),
    }
}
