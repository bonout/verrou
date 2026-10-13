//! Serveur du pont, dans l'app : écoute sur `127.0.0.1` seulement.
//!
//! Le sandbox de macOS refuse à l'app les sockets Unix hors de son conteneur ;
//! le port local est joignable par tout programme de la machine, d'où
//! l'appairage et le chiffrement de chaque message : sans clé de client, on ne
//! peut que demander un appairage, que l'utilisateur doit accepter dans
//! Verrou après avoir comparé le code.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;
use zeroize::Zeroize as _;

use crate::clients::{ClientInfo, ClientStore};
use crate::crypto::{Direction, KeyPair};
use crate::protocol::{
    Command, Credentials, ErrorCode, Incoming, MAX_CLOCK_SKEW_MS, MAX_FRAME, Outgoing, Reply,
    ReplyResult, Request, Suggestion,
};

/// Le temps laissé à l'utilisateur pour accepter un appairage.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// Écart minimal entre deux demandes d'appairage : un programme ne peut pas
/// noyer l'utilisateur sous les fenêtres.
const PAIRING_INTERVAL: Duration = Duration::from_secs(3);

/// Ce que l'app fournit au pont.
pub trait Backend: Send + Sync + 'static {
    fn is_unlocked(&self) -> bool;
    /// `None` : coffre verrouillé.
    fn suggestions(&self, page_url: &str) -> Option<Vec<Suggestion>>;
    /// `None` : coffre verrouillé ; `Err` : refus, avec sa raison.
    fn credentials(&self, item: &str, page_url: &str) -> Option<Result<Credentials, String>>;
    /// L'extension demande à déverrouiller : amener Verrou au premier plan.
    fn request_unlock(&self);
    /// Demande d'appairage : afficher `code` et demander l'accord, puis
    /// répondre par [`Bridge::answer_pairing`].
    fn pairing_requested(&self, request: PairingRequest);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRequest {
    pub id: String,
    /// Nom annoncé par l'extension (« Brave »). Déclaratif : seul le code
    /// prouve quelque chose.
    pub name: String,
    pub code: String,
}

struct Shared {
    backend: Arc<dyn Backend>,
    clients: Mutex<ClientStore>,
    pending: Mutex<Option<(String, oneshot::Sender<bool>)>>,
    last_pairing: Mutex<Option<Instant>>,
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
            Ok(Incoming::Pair { name, key }) => {
                if pair(&shared, &name, &key, &mut writer).await.is_err() {
                    return;
                }
                continue;
            }
            Ok(Incoming::Request { client, iv, data }) => answer(&shared, &client, &iv, &data),
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
        lock(&shared.clients).add(id, name, &key, now_ms() / 1000);
        write_frame(writer, &Outgoing::Paired).await
    } else {
        write_frame(writer, &Outgoing::Refused).await
    }
}

fn answer(shared: &Shared, client: &str, iv: &str, data: &str) -> Outgoing {
    let bad = Outgoing::Error {
        code: ErrorCode::BadRequest,
    };
    let Some(key) = lock(&shared.clients).key(client) else {
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
            Some(Err(reason)) => ReplyResult::Denied { reason },
        },
        Command::Unlock => {
            backend.request_unlock();
            ReplyResult::Done
        }
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
