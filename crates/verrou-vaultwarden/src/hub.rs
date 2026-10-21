//! Live updates: Vaultwarden's notification channel
//! (`/notifications/hub`), the one the Bitwarden apps use.
//!
//! It is `SignalR` over `WebSocket`: the client announces itself
//! (`{"protocol":"messagepack","version":1}` followed by the 0x1E
//! separator), the server answers `{}` then pushes binary messages, each
//! preceded by its length (varint, 7 bits per byte) and encoded in
//! `MessagePack`: `[1, {}, nil, "ReceiveMessage", [{ContextId, Type,
//! Payload}]]`. `Type` is the kind of change (item created, organization
//! keys, settings, logout…), `ContextId` the device that made it. No vault
//! content goes through it: the client resyncs.
//!
//! The access token is only checked at opening (it then expires without
//! closing the channel). The server sends a ping every 15 s: without news
//! for `SILENCE`, the channel is considered dead.
//!
//! What Vaultwarden 1.37.4 pushes (src/api/notifications.rs): items,
//! folders, Sends, `SyncVault`, `SyncOrgKeys` (membership confirmed,
//! removed), `SyncSettings`, `LogOut`, login requests. Nothing when a
//! member accepts an invitation, nor for emergency access: those are left
//! to the periodic sync. The push notification relay to iOS
//! (`PUSH_ENABLED`) only serves the official Bitwarden apps: Verrou doesn't
//! use it.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rmpv::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::{Connection, Error};

/// Without any message (the server pings every 15 s): dead channel.
pub(crate) const SILENCE: Duration = Duration::from_secs(50);
const HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";

/// The kind of an announced change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateKind {
    /// Items created, edited, deleted.
    Items,
    Folders,
    /// The whole vault (import, rotation…).
    Vault,
    /// Organization keys: membership confirmed, removed.
    Organizations,
    /// Account settings (equivalent domains…).
    Settings,
    /// The server closes the sessions (master password changed…).
    LogOut,
    Sends,
    /// Login request from another device.
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

/// A change announced by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubUpdate {
    pub kind: UpdateKind,
    /// Made by this device (a Verrou write): nothing to reload.
    pub from_this_device: bool,
}

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// An open channel.
pub struct Hub {
    socket: Socket,
    device_id: String,
    queue: VecDeque<HubUpdate>,
}

impl Connection {
    /// Opens the updates channel (fresh access token). A server that doesn't
    /// have it (`ENABLE_WEBSOCKET=false`) answers `NotFound`.
    pub async fn open_hub(&mut self) -> Result<Hub, Error> {
        let access = self.access_token().await?;
        let device_id = self.store.device_id()?;
        Hub::open(&self.api.base, &access, device_id).await
    }
}

impl Hub {
    async fn open(server: &str, access: &str, device_id: String) -> Result<Self, Error> {
        // The token in the `Authorization` header (Vaultwarden also accepts
        // it in the address, which a proxy may log).
        let mut request = hub_url(server)?
            .into_client_request()
            .map_err(socket_error)?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {access}")
                .parse()
                .map_err(|_| Error::Invalid("unreadable access token".to_owned()))?,
        );
        let socket = connect(request).await?;
        Ok(Self {
            socket,
            device_id,
            queue: VecDeque::new(),
        })
    }

    /// Waits for the next change. An error: the channel is lost, another one
    /// must be opened (and a resync done: changes may have gone by in the
    /// meantime).
    pub async fn next(&mut self) -> Result<HubUpdate, Error> {
        loop {
            if let Some(update) = self.queue.pop_front() {
                return Ok(update);
            }
            let message = tokio::time::timeout(SILENCE, self.socket.next())
                .await
                .map_err(|_| Error::Network("updates channel: silence".to_owned()))?
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
                // Pings (the answer goes out by itself), protocol text.
                _ => {}
            }
        }
    }

    /// Closes the channel politely.
    pub async fn close(mut self) {
        let _ = self.socket.close(None).await;
    }
}

/// Opens a `SignalR` (`MessagePack`) connection: `WebSocket`, then the
/// protocol announcement and its `{}` answer.
async fn connect(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
) -> Result<Socket, Error> {
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector()?)),
    )
    .await
    .map_err(|_| Error::Network("updates channel: timed out".to_owned()))?
    .map_err(socket_error)?;
    socket
        .send(Message::text(HANDSHAKE))
        .await
        .map_err(socket_error)?;
    // The server accepts the protocol with `{}` + separator.
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .map_err(|_| Error::Network("updates channel: no answer".to_owned()))?
            .ok_or_else(closed)?
            .map_err(socket_error)?;
        match message {
            Message::Binary(data) if data.starts_with(b"{}") => break,
            Message::Text(text) if text.starts_with("{}") => break,
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => return Err(closed()),
            _ => {
                return Err(Error::Server(
                    "updates channel: protocol refused".to_owned(),
                ));
            }
        }
    }
    Ok(socket)
}

/// Anonymous channel (`/notifications/anonymous-hub?Token=<id>`): waits for
/// the login request `id` to get an answer, until `deadline`. Without a
/// channel on the server: `NotFound`.
pub(crate) async fn wait_for_auth_response(
    server: &str,
    id: &str,
    deadline: tokio::time::Instant,
) -> Result<(), Error> {
    let url = format!(
        "{}?Token={}",
        hub_url(server)?.replace("/notifications/hub", "/notifications/anonymous-hub"),
        id
    );
    let request = url.into_client_request().map_err(socket_error)?;
    let mut socket = connect(request).await?;
    let result = crate::device_login::read_anonymous_hub(&mut socket, id, deadline).await;
    let _ = socket.close(None).await;
    result.map(drop)
}

/// `[1, {}, nil, "AuthRequestResponseRecieved", [{Type: 16, Payload: {Id}}]]`
/// (sic: Bitwarden's spelling) for the request `id`.
pub(crate) fn is_auth_response(frame: &[u8], id: &str) -> bool {
    let Ok(value) = rmpv::decode::read_value(&mut &frame[..]) else {
        return false;
    };
    let Some(parts) = value.as_array() else {
        return false;
    };
    if parts.first().and_then(Value::as_i64) != Some(1)
        || parts.get(3).and_then(Value::as_str) != Some("AuthRequestResponseRecieved")
    {
        return false;
    }
    let Some(argument) = parts
        .get(4)
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_map)
    else {
        return false;
    };
    let field = |map: &[(Value, Value)], name: &str| {
        map.iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value.clone())
    };
    let payload_id = field(argument, "Payload")
        .and_then(|p| p.as_map().and_then(|m| field(m, "Id")))
        .and_then(|v| v.as_str().map(str::to_owned));
    payload_id.is_some_and(|p| p.eq_ignore_ascii_case(id))
}

/// `https://host/path` → `wss://host/path/notifications/hub`.
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
    Error::Network("updates channel closed".to_owned())
}

fn socket_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
    use tokio_tungstenite::tungstenite::Error as E;
    match error {
        E::Http(response) => match response.status().as_u16() {
            401 | 403 => Error::SessionExpired,
            404 => Error::NotFound,
            status => Error::Server(format!("updates channel: {status}")),
        },
        other => Error::Network(format!("updates channel: {other}")),
    }
}

/// Splits a binary message into frames (varint length).
pub(crate) fn frames(mut data: &[u8]) -> Vec<&[u8]> {
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

    /// A message as Vaultwarden encodes it (`create_update`, then the
    /// leading length, `serialize`).
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
        // The protocol answer and a ping are not changes.
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
        // Truncated: nothing.
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
