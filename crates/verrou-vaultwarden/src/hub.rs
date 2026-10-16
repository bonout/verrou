//! Mises à jour en direct : le canal de notifications de Vaultwarden
//! (`/notifications/hub`), celui des apps Bitwarden.
//!
//! C'est du `SignalR` sur `WebSocket` : le client s'annonce
//! (`{"protocol":"messagepack","version":1}` suivi du séparateur 0x1E), le
//! serveur répond `{}` puis pousse des messages binaires, chacun précédé de
//! sa longueur (entier variable, 7 bits par octet) et codé en
//! `MessagePack` : `[1, {}, nil, "ReceiveMessage", [{ContextId, Type,
//! Payload}]]`. `Type` est le genre de changement (élément créé, clés des
//! organisations, réglages, déconnexion…), `ContextId` l'appareil qui l'a
//! fait. Aucun contenu du coffre ne passe par là : le client resynchronise.
//!
//! Le jeton d'accès n'est vérifié qu'à l'ouverture (il expire ensuite
//! sans fermer le canal). Le serveur envoie un ping toutes les 15 s : sans
//! nouvelles pendant `SILENCE`, le canal est tenu pour mort.
//!
//! Ce que Vaultwarden 1.37.4 pousse (src/api/notifications.rs) : éléments,
//! dossiers, envois, `SyncVault`, `SyncOrgKeys` (adhésion confirmée,
//! retirée), `SyncSettings`, `LogOut`, demandes de connexion. Rien quand
//! un membre accepte une invitation, ni pour l'accès d'urgence : ceux-là
//! restent à la synchronisation périodique. Le relais de notifications
//! poussées vers iOS (`PUSH_ENABLED`) ne sert qu'aux apps officielles de
//! Bitwarden : Verrou ne l'utilise pas.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rmpv::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::{Connection, Error};

/// Sans aucun message (le serveur pingue toutes les 15 s) : canal mort.
const SILENCE: Duration = Duration::from_secs(50);
const HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";

/// Le genre d'un changement annoncé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateKind {
    /// Éléments créés, modifiés, supprimés.
    Items,
    Folders,
    /// Tout le coffre (import, rotation…).
    Vault,
    /// Clés des organisations : adhésion confirmée, retirée.
    Organizations,
    /// Réglages du compte (domaines équivalents…).
    Settings,
    /// Le serveur ferme les sessions (mot de passe principal changé…).
    LogOut,
    Sends,
    /// Demande de connexion d'un autre appareil.
    AuthRequest,
    Other,
}

impl UpdateKind {
    fn from_code(code: i64) -> Self {
        match code {
            0..=2 | 4 => Self::Items,
            3 | 7 | 8 => Self::Folders,
            5 => Self::Vault,
            6 => Self::Organizations,
            10 => Self::Settings,
            11 => Self::LogOut,
            12..=14 => Self::Sends,
            15 | 16 => Self::AuthRequest,
            _ => Self::Other,
        }
    }
}

/// Un changement annoncé par le serveur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubUpdate {
    pub kind: UpdateKind,
    /// Fait par cet appareil (écriture de Verrou) : rien à relire.
    pub from_this_device: bool,
}

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Un canal ouvert.
pub struct Hub {
    socket: Socket,
    device_id: String,
    queue: VecDeque<HubUpdate>,
}

impl Connection {
    /// Ouvre le canal des mises à jour (jeton d'accès neuf). Un serveur
    /// qui ne l'a pas (`ENABLE_WEBSOCKET=false`) répond `NotFound`.
    pub async fn open_hub(&mut self) -> Result<Hub, Error> {
        let access = self.access_token().await?;
        let device_id = self.store.device_id()?;
        Hub::open(&self.api.base, &access, device_id).await
    }
}

impl Hub {
    async fn open(server: &str, access: &str, device_id: String) -> Result<Self, Error> {
        // Le jeton dans l'en-tête `Authorization` (Vaultwarden l'accepte
        // aussi dans l'adresse, qu'un mandataire peut journaliser).
        let mut request = hub_url(server)?
            .into_client_request()
            .map_err(socket_error)?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {access}")
                .parse()
                .map_err(|_| Error::Invalid("jeton d'accès illisible".to_owned()))?,
        );
        let (mut socket, _) = tokio::time::timeout(
            Duration::from_secs(20),
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                None,
                false,
                Some(connector()?),
            ),
        )
        .await
        .map_err(|_| Error::Network("canal des mises à jour : délai dépassé".to_owned()))?
        .map_err(socket_error)?;
        socket
            .send(Message::text(HANDSHAKE))
            .await
            .map_err(socket_error)?;
        // Le serveur accepte le protocole par `{}` + séparateur.
        loop {
            let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
                .await
                .map_err(|_| Error::Network("canal des mises à jour : pas de réponse".to_owned()))?
                .ok_or_else(closed)?
                .map_err(socket_error)?;
            match message {
                Message::Binary(data) if data.starts_with(b"{}") => break,
                Message::Text(text) if text.starts_with("{}") => break,
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => return Err(closed()),
                _ => {
                    return Err(Error::Server(
                        "canal des mises à jour : protocole refusé".to_owned(),
                    ));
                }
            }
        }
        Ok(Self {
            socket,
            device_id,
            queue: VecDeque::new(),
        })
    }

    /// Attend le prochain changement. Une erreur : le canal est perdu, il
    /// faut en ouvrir un autre (et resynchroniser : des changements ont pu
    /// passer entre-temps).
    pub async fn next(&mut self) -> Result<HubUpdate, Error> {
        loop {
            if let Some(update) = self.queue.pop_front() {
                return Ok(update);
            }
            let message = tokio::time::timeout(SILENCE, self.socket.next())
                .await
                .map_err(|_| Error::Network("canal des mises à jour : silence".to_owned()))?
                .ok_or_else(closed)?
                .map_err(socket_error)?;
            match message {
                Message::Binary(data) => {
                    for frame in frames(&data) {
                        if let Some(update) = parse_update(frame, &self.device_id) {
                            self.queue.push_back(update);
                        }
                    }
                }
                Message::Close(_) => return Err(closed()),
                // Pings (la réponse part toute seule), texte du protocole.
                _ => {}
            }
        }
    }

    /// Ferme le canal poliment.
    pub async fn close(mut self) {
        let _ = self.socket.close(None).await;
    }
}

/// `https://hôte/chemin` → `wss://hôte/chemin/notifications/hub`.
fn hub_url(server: &str) -> Result<String, Error> {
    let ws = if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(Error::InvalidServer(server.to_owned()));
    };
    Ok(format!("{}/notifications/hub", ws.trim_end_matches('/')))
}

fn connector() -> Result<Connector, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Network(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

fn closed() -> Error {
    Error::Network("canal des mises à jour fermé".to_owned())
}

fn socket_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
    use tokio_tungstenite::tungstenite::Error as E;
    match error {
        E::Http(response) => match response.status().as_u16() {
            401 | 403 => Error::SessionExpired,
            404 => Error::NotFound,
            status => Error::Server(format!("canal des mises à jour : {status}")),
        },
        other => Error::Network(format!("canal des mises à jour : {other}")),
    }
}

/// Découpe un message binaire en trames (longueur en entier variable).
fn frames(mut data: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    while !data.is_empty() {
        let mut length: usize = 0;
        let mut read = 0;
        loop {
            let Some(&byte) = data.get(read) else {
                return frames;
            };
            length |= usize::from(byte & 0x7f) << (7 * read);
            read += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if read == 5 {
                return frames;
            }
        }
        let Some(frame) = data.get(read..read + length) else {
            return frames;
        };
        frames.push(frame);
        data = &data[read + length..];
    }
    frames
}

/// `[1, {}, nil, "ReceiveMessage", [{ContextId, Type, Payload}]]`.
fn parse_update(frame: &[u8], device_id: &str) -> Option<HubUpdate> {
    let value = rmpv::decode::read_value(&mut &frame[..]).ok()?;
    let parts = value.as_array()?;
    if parts.first()?.as_i64()? != 1 || parts.get(3)?.as_str()? != "ReceiveMessage" {
        return None;
    }
    let argument = parts.get(4)?.as_array()?.first()?.as_map()?;
    let field = |name: &str| {
        argument
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let kind = UpdateKind::from_code(field("Type")?.as_i64()?);
    let from_this_device = field("ContextId")
        .and_then(Value::as_str)
        .is_some_and(|id| id.eq_ignore_ascii_case(device_id));
    Some(HubUpdate {
        kind,
        from_this_device,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un message comme Vaultwarden le code (`create_update`, puis la
    /// longueur en tête, `serialize`).
    fn message(kind: i64, context: Option<&str>) -> Vec<u8> {
        let value = Value::Array(vec![
            1.into(),
            Value::Map(vec![]),
            Value::Nil,
            "ReceiveMessage".into(),
            Value::Array(vec![Value::Map(vec![
                ("ContextId".into(), context.map_or(Value::Nil, Into::into)),
                ("Type".into(), kind.into()),
                (
                    "Payload".into(),
                    Value::Map(vec![("UserId".into(), "u".into())]),
                ),
            ])]),
        ]);
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &value).unwrap();
        let mut size = body.len();
        let mut out = Vec::new();
        loop {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if size == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    #[test]
    fn updates_are_decoded() {
        let mut data = message(6, None);
        data.extend(message(1, Some("APPAREIL")));
        let updates: Vec<HubUpdate> = frames(&data)
            .into_iter()
            .filter_map(|f| parse_update(f, "appareil"))
            .collect();
        assert_eq!(
            updates,
            [
                HubUpdate {
                    kind: UpdateKind::Organizations,
                    from_this_device: false
                },
                HubUpdate {
                    kind: UpdateKind::Items,
                    from_this_device: true
                }
            ]
        );
        // La réponse du protocole et un ping ne sont pas des changements.
        assert!(
            frames(b"{}\x1e")
                .into_iter()
                .all(|f| parse_update(f, "x").is_none())
        );
        let mut ping = Vec::new();
        rmpv::encode::write_value(&mut ping, &Value::Array(vec![6.into()])).unwrap();
        assert!(parse_update(&ping, "x").is_none());
    }

    #[test]
    fn a_long_message_has_a_two_byte_length() {
        let value = Value::String("x".repeat(300).into());
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &value).unwrap();
        let mut data = vec![(body.len() & 0x7f) as u8 | 0x80, (body.len() >> 7) as u8];
        data.extend(&body);
        assert_eq!(frames(&data), [body.as_slice()]);
        // Tronqué : rien.
        assert_eq!(frames(&data[..10]), [] as [&[u8]; 0]);
    }

    #[test]
    fn hub_urls() {
        assert_eq!(
            hub_url("https://vault.exemple.fr").unwrap(),
            "wss://vault.exemple.fr/notifications/hub"
        );
        assert_eq!(
            hub_url("http://localhost:8140/").unwrap(),
            "ws://localhost:8140/notifications/hub"
        );
        assert!(hub_url("ftp://x").is_err());
    }
}
