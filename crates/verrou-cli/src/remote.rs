//! Dialogue avec Verrou par son pont : TCP `127.0.0.1`, trames « longueur
//! (u32 petit-boutiste) + JSON », comme celles que l'hôte Native Messaging
//! relaie pour l'extension, et canal chiffré par la clé obtenue à
//! l'appairage.

use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use verrou_bridge::crypto::{ChannelKey, Direction, KeyPair};
use verrou_bridge::protocol::{
    ClientKind, Command, ErrorCode, Incoming, MAX_FRAME, Outgoing, Reply, ReplyResult, Request,
};
use zeroize::Zeroize as _;

use crate::config::Config;

/// Une réponse peut attendre l'accord de l'utilisateur (90 s au plus côté
/// Verrou) ; un appairage, deux minutes.
const READ_TIMEOUT: Duration = Duration::from_secs(150);
/// Le temps laissé à l'utilisateur pour déverrouiller le coffre.
const UNLOCK_WAIT: Duration = Duration::from_secs(60);

/// Où joindre Verrou.
#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub port: u16,
    /// Ouvrir Verrou s'il ne répond pas.
    pub launch: bool,
}

impl Endpoint {
    /// Le port de Verrou (`VERROU_BRIDGE_PORT` le remplace).
    pub fn from_env() -> Self {
        Self {
            port: verrou_bridge::port_from_env(),
            launch: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Pas de fichier de liaison.
    NotLinked,
    /// Verrou ne répond pas (fermé, ou pont désactivé).
    AppUnavailable,
    /// Lien révoqué dans Verrou.
    UnknownClient,
    /// Coffre resté verrouillé.
    Locked,
    /// Refus de Verrou ou de l'utilisateur, avec sa raison.
    Denied(String),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => write!(f, "ce terminal n'est pas relié à Verrou : « verrou link »"),
            Self::AppUnavailable => write!(
                f,
                "Verrou ne répond pas : ouvrez l'app et activez « Brave, Firefox et le terminal » dans ses réglages"
            ),
            Self::UnknownClient => write!(
                f,
                "ce terminal n'est plus relié à Verrou (lien révoqué) : « verrou link »"
            ),
            Self::Locked => write!(f, "le coffre est resté verrouillé"),
            Self::Denied(reason) => write!(f, "{reason}"),
            Self::Protocol(message) => write!(f, "dialogue avec Verrou : {message}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

fn write_frame(stream: &mut TcpStream, message: &impl Serialize) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream) -> Result<Outgoing, Error> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Protocol("trame invalide".to_owned()));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| Error::Protocol(e.to_string()))
}

fn open_stream(endpoint: Endpoint) -> Result<TcpStream, Error> {
    let stream = verrou_bridge::connect_to_app(endpoint.port, endpoint.launch)
        .ok_or(Error::AppUnavailable)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    Ok(stream)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Relie ce terminal à Verrou : demande l'appairage, montre le code par
/// `show_code`, attend l'accord de l'utilisateur dans Verrou.
pub fn link(endpoint: Endpoint, name: &str, show_code: impl FnOnce(&str)) -> Result<Config, Error> {
    let mut stream = open_stream(endpoint)?;
    let ours = KeyPair::generate();
    write_frame(
        &mut stream,
        &Incoming::Pair {
            name: name.to_owned(),
            key: ours.public_base64(),
            kind: ClientKind::Cli,
        },
    )?;
    let (client, key) = match read_frame(&mut stream)? {
        Outgoing::Pairing { client, key } => (client, key),
        Outgoing::Error {
            code: ErrorCode::Busy,
        } => {
            return Err(Error::Denied(
                "un appairage est déjà en cours dans Verrou : réessayez dans quelques secondes"
                    .to_owned(),
            ));
        }
        other => return Err(Error::Protocol(format!("réponse inattendue : {other:?}"))),
    };
    let channel = ours
        .agree(&key, false)
        .map_err(|e| Error::Protocol(e.to_string()))?;
    show_code(&channel.pairing_code());
    match read_frame(&mut stream)? {
        Outgoing::Paired => Ok(Config {
            client,
            key: channel.to_base64(),
            linked: now_ms() / 1000,
        }),
        Outgoing::Refused => Err(Error::Denied("appairage refusé dans Verrou".to_owned())),
        other => Err(Error::Protocol(format!("réponse inattendue : {other:?}"))),
    }
}

/// Une connexion de client relié.
pub struct Remote {
    stream: TcpStream,
    client: String,
    key: ChannelKey,
    next: u64,
}

impl Remote {
    pub fn connect(config: &Config, endpoint: Endpoint) -> Result<Self, Error> {
        let key = config.channel_key().map_err(Error::Protocol)?;
        Ok(Self {
            stream: open_stream(endpoint)?,
            client: config.client.clone(),
            key,
            next: 1,
        })
    }

    /// Envoie une commande et rend la réponse telle quelle.
    pub fn call(&mut self, command: &Command) -> Result<ReplyResult, Error> {
        let id = self.next;
        self.next += 1;
        let mut payload = serde_json::to_vec(&Request {
            id,
            ts: now_ms(),
            command: command.clone(),
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;
        let (iv, data) = self.key.seal(&self.client, Direction::Request, &payload);
        payload.zeroize();
        write_frame(
            &mut self.stream,
            &Incoming::Request {
                client: self.client.clone(),
                iv,
                data,
            },
        )?;
        match read_frame(&mut self.stream)? {
            Outgoing::Response { iv, data } => {
                let mut plain = self
                    .key
                    .open(&self.client, Direction::Response, &iv, &data)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                let reply = serde_json::from_slice::<Reply>(&plain);
                plain.zeroize();
                let reply = reply.map_err(|e| Error::Protocol(e.to_string()))?;
                if reply.id != id {
                    return Err(Error::Protocol("réponse à une autre requête".to_owned()));
                }
                Ok(reply.result)
            }
            Outgoing::Error {
                code: ErrorCode::UnknownClient,
            } => Err(Error::UnknownClient),
            other => Err(Error::Protocol(format!("réponse inattendue : {other:?}"))),
        }
    }

    /// Comme [`Self::call`], mais un refus devient une erreur, et un coffre
    /// verrouillé est d'abord déverrouillé : Verrou demande Touch ID, on
    /// attend jusqu'à une minute.
    pub fn ask(&mut self, command: &Command) -> Result<ReplyResult, Error> {
        let mut result = self.call(command)?;
        if result == ReplyResult::Locked {
            self.unlock()?;
            result = self.call(command)?;
        }
        match result {
            ReplyResult::Locked => Err(Error::Locked),
            ReplyResult::Denied { reason } => Err(Error::Denied(reason)),
            other => Ok(other),
        }
    }

    pub fn unlocked(&mut self) -> Result<bool, Error> {
        match self.call(&Command::Status)? {
            ReplyResult::Status { unlocked, .. } => Ok(unlocked),
            other => Err(Error::Protocol(format!("réponse inattendue : {other:?}"))),
        }
    }

    fn unlock(&mut self) -> Result<(), Error> {
        self.call(&Command::Unlock)?;
        eprintln!("verrou : coffre verrouillé, déverrouillez-le dans Verrou…");
        let start = Instant::now();
        while start.elapsed() < UNLOCK_WAIT {
            if self.unlocked()? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(Error::Locked)
    }
}
