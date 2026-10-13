//! Agent SSH (`verrou ssh-agent`) : parle le protocole de l'agent OpenSSH
//! (draft-miller-ssh-agent) sur un socket Unix, et fait signer Verrou.
//!
//! - `SSH_AGENTC_REQUEST_IDENTITIES` : les clés publiques des clés SSH du
//!   coffre, avec leur titre en commentaire.
//! - `SSH_AGENTC_SIGN_REQUEST` : Verrou signe, après l'accord de
//!   l'utilisateur (Touch ID) ; la clé privée ne quitte jamais l'app.
//! - Tout le reste (ajout, retrait, verrouillage de l'agent, extensions) :
//!   `SSH_AGENT_FAILURE`.
//!
//! Le socket est dans un dossier 700 et lui-même en 600 ; comme pour
//! `ssh-agent`, tout programme lancé par l'utilisateur peut s'en servir.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use data_encoding::BASE64;
use verrou_bridge::protocol::{Command, ReplyResult};

use crate::config::{Config, set_mode};
use crate::remote::{Endpoint, Error, Remote};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Taille maximale d'un message (OpenSSH en accepte 256 Kio).
const MAX_MESSAGE: usize = 256 * 1024;

/// Une requête de client SSH.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentRequest {
    Identities,
    Sign {
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Message que l'agent ne sait pas traiter : on répond par un échec.
    Unsupported(u8),
}

/// Une clé proposée par l'agent : forme binaire SSH et commentaire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub key: Vec<u8>,
    pub comment: String,
}

/// Ce qui fournit les clés et les signatures : Verrou, ou un faux pour les tests.
pub trait Keys: Send + Sync {
    fn identities(&self) -> Result<Vec<Identity>, String>;
    fn sign(&self, key: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, String>;
}

// MARK: Encodage

/// Lecteur des types de la RFC 4251 (`uint32`, `string`).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_at_checked(4)?;
        self.0 = rest;
        Some(u32::from_be_bytes(head.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, u32::try_from(value.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(value);
}

/// Lit le corps d'un message (sans sa longueur). `None` : message tronqué.
pub fn parse(message: &[u8]) -> Option<AgentRequest> {
    let mut reader = Reader(message);
    match reader.u8()? {
        SSH_AGENTC_REQUEST_IDENTITIES => Some(AgentRequest::Identities),
        SSH_AGENTC_SIGN_REQUEST => {
            let key = reader.string()?.to_vec();
            let data = reader.string()?.to_vec();
            let flags = reader.u32()?;
            Some(AgentRequest::Sign { key, data, flags })
        }
        other => Some(AgentRequest::Unsupported(other)),
    }
}

pub fn identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(&mut out, u32::try_from(identities.len()).unwrap_or(0));
    for identity in identities {
        put_string(&mut out, &identity.key);
        put_string(&mut out, identity.comment.as_bytes());
    }
    out
}

pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut out, signature);
    out
}

pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// La réponse à un message (corps sans longueur).
pub fn handle(keys: &dyn Keys, message: &[u8]) -> Vec<u8> {
    match parse(message) {
        Some(AgentRequest::Identities) => match keys.identities() {
            Ok(identities) => identities_answer(&identities),
            Err(error) => {
                eprintln!("verrou ssh-agent : {error}");
                failure()
            }
        },
        Some(AgentRequest::Sign { key, data, flags }) => match keys.sign(&key, &data, flags) {
            Ok(signature) => sign_response(&signature),
            Err(error) => {
                eprintln!("verrou ssh-agent : {error}");
                failure()
            }
        },
        Some(AgentRequest::Unsupported(_)) | None => failure(),
    }
}

/// Lit un message : `Ok(None)` à la fin de la connexion.
fn read_message(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message SSH invalide",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_message(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Sert une connexion de client SSH jusqu'à sa fermeture.
pub fn serve_connection(keys: &dyn Keys, mut stream: UnixStream) {
    while let Ok(Some(message)) = read_message(&mut stream) {
        if write_message(&mut stream, &handle(keys, &message)).is_err() {
            return;
        }
    }
}

/// Accepte les connexions, une par fil, sans fin.
pub fn serve(listener: &UnixListener, keys: &Arc<dyn Keys>) {
    for stream in listener.incoming().flatten() {
        let keys = Arc::clone(keys);
        std::thread::spawn(move || serve_connection(&*keys, stream));
    }
}

// MARK: Socket

/// `~/.verrou/agent.sock`.
pub fn default_socket() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME n'est pas défini")?;
    Ok(PathBuf::from(home).join(".verrou/agent.sock"))
}

/// Écoute sur `path` : dossier créé en 700 (et ramené à 700 pour le dossier
/// par défaut), socket en 600. Un socket laissé par un agent arrêté est
/// remplacé ; un agent qui répond encore, ou un fichier qui n'est pas un
/// socket, ne l'est pas.
pub fn bind(path: &Path, private_dir: bool) -> Result<UnixListener, String> {
    let error = |e: io::Error| format!("{} : {e}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let created = !dir.exists();
        if created {
            fs::create_dir_all(dir).map_err(error)?;
        }
        if created || private_dir {
            set_mode(dir, 0o700).map_err(error)?;
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "{} existe et n'est pas un socket : je n'y touche pas",
                path.display()
            ));
        }
        if UnixStream::connect(path).is_ok() {
            return Err(format!("un agent écoute déjà sur {}", path.display()));
        }
        fs::remove_file(path).map_err(error)?;
    }
    let listener = UnixListener::bind(path).map_err(error)?;
    set_mode(path, 0o600).map_err(error)?;
    Ok(listener)
}

// MARK: Verrou

/// Les clés de Verrou, par le pont : une connexion par requête.
pub struct BridgeKeys {
    pub config: Config,
    pub endpoint: Endpoint,
}

impl BridgeKeys {
    fn ask(&self, command: &Command) -> Result<ReplyResult, String> {
        let mut remote =
            Remote::connect(&self.config, self.endpoint).map_err(|e: Error| e.to_string())?;
        remote.ask(command).map_err(|e| e.to_string())
    }
}

impl Keys for BridgeKeys {
    fn identities(&self) -> Result<Vec<Identity>, String> {
        match self.ask(&Command::SshKeys)? {
            ReplyResult::SshKeys { keys } => Ok(keys
                .into_iter()
                .filter_map(|k| {
                    Some(Identity {
                        key: BASE64.decode(k.public_key.as_bytes()).ok()?,
                        comment: k.title,
                    })
                })
                .collect()),
            other => Err(format!("réponse inattendue : {other:?}")),
        }
    }

    fn sign(&self, key: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
        let command = Command::SshSign {
            public_key: BASE64.encode(key),
            data: BASE64.encode(data),
            flags,
        };
        match self.ask(&command)? {
            ReplyResult::Signature { signature } => BASE64
                .decode(signature.as_bytes())
                .map_err(|e| e.to_string()),
            other => Err(format!("réponse inattendue : {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;

    impl Keys for Fake {
        fn identities(&self) -> Result<Vec<Identity>, String> {
            Ok(vec![Identity {
                key: b"cle".to_vec(),
                comment: "Clé du N100".to_owned(),
            }])
        }

        fn sign(&self, key: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
            if key == b"cle" {
                Ok([data, &flags.to_be_bytes()].concat())
            } else {
                Err("clé SSH inconnue".to_owned())
            }
        }
    }

    fn sign_request(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut out = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut out, key);
        put_string(&mut out, data);
        put_u32(&mut out, flags);
        out
    }

    #[test]
    fn parses_requests() {
        assert_eq!(
            parse(&[SSH_AGENTC_REQUEST_IDENTITIES]),
            Some(AgentRequest::Identities)
        );
        assert_eq!(
            parse(&sign_request(b"k", b"donnees", 4)),
            Some(AgentRequest::Sign {
                key: b"k".to_vec(),
                data: b"donnees".to_vec(),
                flags: 4,
            })
        );
        // Ajout de clé (17), extension (27) : non pris en charge.
        assert_eq!(parse(&[17, 0, 0]), Some(AgentRequest::Unsupported(17)));
        assert_eq!(parse(&[27]), Some(AgentRequest::Unsupported(27)));
        // Tronqués : longueur annoncée plus grande que le reste, drapeaux absents.
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[SSH_AGENTC_SIGN_REQUEST, 0, 0, 0, 9, 1]), None);
        let mut no_flags = sign_request(b"k", b"d", 0);
        no_flags.truncate(no_flags.len() - 2);
        assert_eq!(parse(&no_flags), None);
    }

    #[test]
    fn encodes_answers() {
        let answer = handle(&Fake, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        let mut expected = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1, 0, 0, 0, 3];
        expected.extend_from_slice(b"cle");
        put_string(&mut expected, "Clé du N100".as_bytes());
        assert_eq!(answer, expected);

        let signed = handle(&Fake, &sign_request(b"cle", b"abc", 2));
        assert_eq!(
            signed,
            [
                &[SSH_AGENT_SIGN_RESPONSE, 0, 0, 0, 7][..],
                b"abc",
                &[0, 0, 0, 2]
            ]
            .concat()
        );
        assert_eq!(handle(&Fake, &sign_request(b"autre", b"abc", 0)), failure());
        assert_eq!(handle(&Fake, &[19]), failure());
        assert_eq!(handle(&Fake, &[SSH_AGENTC_SIGN_REQUEST]), failure());
    }

    #[test]
    fn socket_is_private_and_stale_sockets_are_replaced() {
        use std::os::unix::fs::PermissionsExt as _;
        // Chemin court : les sockets Unix sont limités à ~100 octets.
        let dir = std::env::temp_dir().join(format!("vra-{}", std::process::id()));
        let path = dir.join("a.sock");
        let listener = bind(&path, false).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        // Un agent écoute : pas question de lui voler son socket.
        assert!(bind(&path, false).unwrap_err().contains("écoute déjà"));
        drop(listener);
        // Agent arrêté : son socket est remplacé.
        let listener = bind(&path, false).unwrap();
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"pas un socket").unwrap();
        assert!(bind(&path, false).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn round_trip_over_a_unix_socket() {
        let dir = std::env::temp_dir().join(format!("vrb-{}", std::process::id()));
        let path = dir.join("a.sock");
        let listener = bind(&path, false).unwrap();
        let keys: Arc<dyn Keys> = Arc::new(Fake);
        std::thread::spawn(move || serve(&listener, &keys));
        let mut client = UnixStream::connect(&path).unwrap();
        write_message(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let answer = read_message(&mut client).unwrap().unwrap();
        assert_eq!(answer[0], SSH_AGENT_IDENTITIES_ANSWER);
        write_message(&mut client, &sign_request(b"cle", b"x", 0)).unwrap();
        assert_eq!(
            read_message(&mut client).unwrap().unwrap()[0],
            SSH_AGENT_SIGN_RESPONSE
        );
        write_message(&mut client, &[17]).unwrap();
        assert_eq!(read_message(&mut client).unwrap().unwrap(), failure());
        let _ = fs::remove_dir_all(dir);
    }
}
