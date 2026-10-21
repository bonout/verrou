//! Bitwarden Send: sharing a text or a file through a link, end-to-end
//! encrypted.
//!
//! All the cryptography comes from the SDK (`bitwarden-send`), as for the
//! vault items:
//! - each send has its own key, 16 random bytes; HKDF-SHA256 (salt
//!   `bitwarden-send`, info `send`) derives from it the 64-byte key that
//!   encrypts the name, the notes, the text, the file name and its contents;
//! - a file's contents form a single `EncArrayBuffer` (type 2, IV, MAC,
//!   ciphertext), like an attachment, but encrypted directly by the send's
//!   key: no separate file key;
//! - the send's key is kept on the server encrypted by the user key
//!   (`key`), and goes into the link, after the `#`: the recipient's
//!   browser never sends it to the server;
//! - an optional password is only sent hashed (PBKDF2-SHA256, 100,000
//!   iterations, salted by the send's key).
//!
//! Verrou does the transport (`/api/sends`) and the formatting.
//!
//! Sending a file (Vaultwarden 1.37): `POST /api/sends/file/v2` creates the
//! send (encrypted file name, size of the encrypted contents) and returns
//! the upload address for the bytes (`multipart/form-data`, named by the
//! encrypted name). If this second step fails, the send is deleted. Falls
//! back to the old `POST /api/sends/file` (all in one request) for a server
//! that doesn't know v2. A send's file never changes: an edit only touches
//! the settings.
//!
//! Receiving: anonymous token (`grant_type=send_access`), then
//! `POST /api/sends/access/file/{file}` returns a signed download address
//! (that is what counts an access).

use bitwarden_api_api::models::{
    SendAccessResponseModel, SendRequestModel, SendResponseModel, SendWithIdRequestModel,
    SyncResponseModel,
};
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::{EncString, KeyStore, OctetStreamBytes, PrimitiveEncryptable};
use bitwarden_send::{
    Send, SendAccessKey, SendAccessResponse, SendAddRequest, SendAuthType, SendClientExt,
    SendFileView, SendTextView, SendType, SendView, SendViewType,
};
use chrono::{DateTime, Duration, Utc};
use reqwest::Method;
use reqwest::multipart::Form;
use serde_json::Value;
use verrou_core::SecretString;
use verrou_core::import::MAX_ATTACHMENT_SIZE;
use zeroize::Zeroizing;

use crate::api::{Api, write_response};
use crate::attachments::{ENCRYPTION_OVERHEAD, TRANSFER_TIMEOUT, file_part};
use crate::{Connection, Decrypted, Error};

/// Lifetime of a new send, like the Bitwarden apps.
pub const DEFAULT_DELETION_DAYS: i64 = 7;
/// Vaultwarden rejects a deletion date more than 31 days away.
pub const MAX_DELETION_DAYS: i64 = 31;
/// Maximum size of a sent file, before encryption: the attachment limit
/// (the server may impose a lower one, its quota).
pub const MAX_SEND_FILE_SIZE: u64 = MAX_ATTACHMENT_SIZE;
/// Vaultwarden's cap for a received file (the Bitwarden apps' 500 MB,
/// plus 5%), encrypted.
const SERVER_MAX_SEND_FILE_SIZE: u64 = 550_502_400;

/// What a send's screen creates or edits.
#[derive(Clone, Debug)]
pub struct SendDraft {
    pub name: String,
    /// The shared text. Ignored for a file send.
    pub text: SecretString,
    /// Text hidden by default for the recipient.
    pub hidden: bool,
    /// Private notes, visible to the sender only.
    pub notes: Option<String>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub max_access_count: Option<u32>,
    /// New password. `None`: none (creation) or unchanged
    /// (edit; to remove it, `remove_send_password`).
    pub password: Option<SecretString>,
    pub hide_email: bool,
    pub disabled: bool,
}

impl SendDraft {
    /// A text send with the default settings (deleted in 7 days).
    pub fn text(name: impl Into<String>, text: SecretString, now: DateTime<Utc>) -> Self {
        Self {
            name: name.into(),
            text,
            hidden: false,
            notes: None,
            deletion_date: now + Duration::days(DEFAULT_DELETION_DAYS),
            expiration_date: None,
            max_access_count: None,
            password: None,
            hide_email: false,
            disabled: false,
        }
    }

    /// A file send with the default settings: the file is passed to
    /// `Connection::create_file_send`.
    pub fn file(name: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self::text(name, SecretString::default(), now)
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), Error> {
        if self.name.trim().is_empty() {
            return Err(Error::Invalid("the send's name is required".to_owned()));
        }
        if self.deletion_date <= now {
            return Err(Error::Invalid(
                "the deletion date must be in the future".to_owned(),
            ));
        }
        if self.deletion_date > now + Duration::days(MAX_DELETION_DAYS) {
            return Err(Error::Invalid(format!(
                "the deletion date cannot be more than {MAX_DELETION_DAYS} days away"
            )));
        }
        if self
            .expiration_date
            .is_some_and(|expiry| expiry > self.deletion_date)
        {
            return Err(Error::Invalid(
                "the expiration must come before the deletion".to_owned(),
            ));
        }
        if self.max_access_count == Some(0) {
            return Err(Error::Invalid(
                "the maximum access count must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendKind {
    Text,
    File,
}

/// What the list of sends shows. Neither the text nor the link (which
/// carries the key): they are requested separately.
#[derive(Clone, Debug)]
pub struct SendInfo {
    pub id: String,
    pub access_id: String,
    pub name: String,
    pub kind: SendKind,
    pub file_name: Option<String>,
    /// Size of the encrypted file, in bytes (file send).
    pub file_size: Option<u64>,
    pub has_password: bool,
    pub access_count: u32,
    pub max_access_count: Option<u32>,
    pub disabled: bool,
    pub hide_email: bool,
    /// Unix timestamps.
    pub deletion_date: i64,
    pub expiration_date: Option<i64>,
    pub revision_date: i64,
}

impl SendInfo {
    fn of(view: &SendView) -> Option<Self> {
        Some(Self {
            id: view.id?.to_string(),
            access_id: view.access_id.clone()?,
            name: view.name.clone(),
            kind: if view.r#type == SendType::File {
                SendKind::File
            } else {
                SendKind::Text
            },
            file_name: view.file.as_ref().map(|f| f.file_name.clone()),
            file_size: view
                .file
                .as_ref()
                .and_then(|f| f.size.as_deref())
                .and_then(|s| s.parse().ok()),
            has_password: view.has_password,
            access_count: view.access_count,
            max_access_count: view.max_access_count,
            disabled: view.disabled,
            hide_email: view.hide_email,
            deletion_date: view.deletion_date.timestamp(),
            expiration_date: view.expiration_date.map(|d| d.timestamp()),
            revision_date: view.revision_date.timestamp(),
        })
    }

    /// No longer accessible (disabled, expired, accesses used up): the link
    /// leads nowhere, but the send exists until it is deleted.
    pub fn is_available(&self, now: i64) -> bool {
        !self.disabled
            && self.expiration_date.is_none_or(|e| e > now)
            && self.deletion_date > now
            && self.max_access_count.is_none_or(|m| self.access_count < m)
    }
}

/// Share link, like the web vault: `<server>/#/send/<access>/<key>`.
/// The key follows the `#`: it never leaves the recipient's browser.
pub fn share_link(server: &str, access_id: &str, key_b64url: &str) -> String {
    format!(
        "{}/#/send/{access_id}/{key_b64url}",
        server.trim_end_matches('/')
    )
}

/// A send link split up: server, access id, key.
pub(crate) fn parse_link(link: &str) -> Result<(String, String, String), Error> {
    let invalid = || Error::Invalid("invalid send link".to_owned());
    let link = link.trim();
    let (server, rest) = link
        .split_once("/#/send/")
        .or_else(|| link.split_once("#/send/"))
        .ok_or_else(invalid)?;
    let mut parts = rest.trim_end_matches('/').split('/');
    let (Some(access_id), Some(key), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    if access_id.is_empty() || key.is_empty() {
        return Err(invalid());
    }
    Ok((
        server.trim_end_matches('/').to_owned(),
        access_id.to_owned(),
        key.to_owned(),
    ))
}

/// A send received through its link, decrypted.
#[derive(Clone, Debug)]
pub struct ReceivedSend {
    pub name: Option<String>,
    pub text: Option<SecretString>,
    pub hidden: bool,
    pub file_name: Option<String>,
    /// File id (file send), to download it.
    pub file_id: Option<String>,
    /// Size of the encrypted file, in bytes, announced by the server.
    pub file_size: Option<u64>,
    pub expiration_date: Option<i64>,
    /// The sender's address, unless they hid it.
    pub creator: Option<String>,
}

/// An opened send: the server, the anonymous token, the link's key.
struct Opened {
    api: Api,
    token: String,
    key: SendAccessKey,
    send: ReceivedSend,
}

/// Opens a send through its link, as the recipient would, without an
/// account: anonymous token (with the password hash if there is one),
/// encrypted contents, decrypted with the link's key. Counts an access for a
/// text; for a file, the download is what counts (`receive_file`).
pub async fn receive(link: &str, password: Option<&SecretString>) -> Result<ReceivedSend, Error> {
    Ok(open(link, password).await?.send)
}

/// ⚠️ Downloads a send's file through its link, like the recipient, and
/// decrypts it with the link's key (MAC checked first). Counts an access.
/// The contents only exist in memory, erased when dropped.
pub async fn receive_file(
    link: &str,
    password: Option<&SecretString>,
) -> Result<(ReceivedSend, Zeroizing<Vec<u8>>), Error> {
    let opened = open(link, password).await?;
    let file_id = opened
        .send
        .file_id
        .as_deref()
        .ok_or_else(|| Error::Invalid("this send contains no file".to_owned()))?;
    let url = opened.api.send_file_url(&opened.token, file_id).await?;
    let encrypted = opened
        .api
        .download(&url, SERVER_MAX_SEND_FILE_SIZE + ENCRYPTION_OVERHEAD)
        .await?;
    if opened
        .send
        .file_size
        .is_some_and(|size| size != encrypted.len() as u64)
    {
        return Err(Error::Crypto(
            "incomplete file (unexpected size)".to_owned(),
        ));
    }
    let plain = opened
        .key
        .decrypt_file_buffer(&encrypted)
        .map_err(|e| Error::Crypto(format!("tampered or unreadable file ({e})")))?;
    Ok((opened.send, Zeroizing::new(plain)))
}

async fn open(link: &str, password: Option<&SecretString>) -> Result<Opened, Error> {
    let (server, access_id, key) = parse_link(link)?;
    let key = SendAccessKey::from_url_b64(&key)
        .map_err(|_| Error::Invalid("invalid send link (key)".to_owned()))?;
    let api = Api::new(&server)?;
    let hash = password.map(|p| key.hash_password_b64(p.expose()));
    let token = api.send_access_token(&access_id, hash.as_deref()).await?;
    let body = api.send_access(&token).await?;
    let model: SendAccessResponseModel = serde_json::from_value(body)
        .map_err(|e| Error::Server(format!("unreadable send ({e})")))?;
    let response = SendAccessResponse::try_from(model).map_err(Error::crypto)?;
    let view = key.decrypt_response(response).map_err(Error::crypto)?;
    let file = view.file;
    let send = ReceivedSend {
        name: view.name,
        hidden: view.text.as_ref().is_some_and(|t| t.hidden),
        text: view.text.and_then(|t| t.text).map(SecretString::new),
        file_id: file.as_ref().and_then(|f| f.id.clone()),
        file_size: file
            .as_ref()
            .and_then(|f| f.size.as_deref())
            .and_then(|s| s.parse().ok()),
        file_name: file.and_then(|f| f.file_name),
        expiration_date: view.expiration_date.map(|d| d.timestamp()),
        creator: view.creator_identifier,
    };
    Ok(Opened {
        api,
        token,
        key,
        send,
    })
}

/// Name without surrounding spaces, not empty; file not empty, under the limit.
fn checked_file<'a>(file_name: &'a str, contents: &[u8]) -> Result<&'a str, Error> {
    let name = file_name.trim();
    if name.is_empty() {
        return Err(Error::Invalid("the file has no name".to_owned()));
    }
    if contents.is_empty() {
        return Err(Error::Invalid(format!("\"{name}\" is empty")));
    }
    if contents.len() as u64 > MAX_SEND_FILE_SIZE {
        return Err(Error::Invalid(format!(
            "\"{name}\" is larger than 100 MB, the maximum size of a send"
        )));
    }
    Ok(name)
}

/// The creation request, then encrypted by the SDK (which draws the send's
/// key and wraps it in the user's).
fn add_request(draft: SendDraft, view_type: SendViewType) -> SendAddRequest {
    SendAddRequest {
        name: draft.name.trim().to_owned(),
        notes: text(draft.notes),
        view_type,
        max_access_count: draft.max_access_count,
        disabled: draft.disabled,
        hide_email: draft.hide_email,
        deletion_date: draft.deletion_date,
        expiration_date: draft.expiration_date,
        auth: match draft.password.filter(|p| !p.is_empty()) {
            Some(password) => SendAuthType::Password {
                password: password.expose().to_owned(),
            },
            None => SendAuthType::None,
        },
    }
}

/// Encrypts a file's contents with the send's key, as the creation request
/// wraps it (`key`, encrypted by the user key): an `EncArrayBuffer`
/// (type 2, IV, MAC, ciphertext).
fn encrypt_file_with_send_key(
    store: &KeyStore<bitwarden_core::key_management::KeySlotIds>,
    wrapped_send_key: &str,
    contents: &[u8],
) -> Result<Vec<u8>, Error> {
    let wrapped: EncString = wrapped_send_key.parse().map_err(Error::crypto)?;
    let mut ctx = store.context();
    let key = Send::get_key(&mut ctx, &wrapped, SymmetricKeySlotId::User).map_err(Error::crypto)?;
    OctetStreamBytes::from(contents)
        .encrypt(&mut ctx, key)
        .and_then(|e| e.to_buffer())
        .map_err(Error::crypto)
}

impl Connection {
    fn key_store(&self) -> &KeyStore<bitwarden_core::key_management::KeySlotIds> {
        self.sdk.internal.get_key_store()
    }

    /// The cache's sends (last sync), newest first. Those that don't
    /// decrypt are ignored.
    pub fn sends(&self) -> Result<Vec<SendInfo>, Error> {
        let mut sends: Vec<SendInfo> = self
            .cached_sends()?
            .into_iter()
            .filter_map(|send| self.sdk.sends().decrypt(send).ok())
            .filter_map(|view| SendInfo::of(&view))
            .collect();
        sends.sort_by_key(|s| std::cmp::Reverse(s.revision_date));
        Ok(sends)
    }

    /// ⚠️ A send's share link: it carries the key, hence the contents.
    pub fn send_link(&self, id: &str) -> Result<SecretString, Error> {
        let view = self.send_view(id)?;
        let key = view.key.as_deref().ok_or(Error::NotFound)?;
        let access_id = view.access_id.as_deref().ok_or(Error::NotFound)?;
        Ok(SecretString::new(share_link(
            self.api.server(),
            access_id,
            key,
        )))
    }

    /// ⚠️ Prefilled draft to edit a send, text included.
    pub fn send_draft(&self, id: &str) -> Result<SendDraft, Error> {
        let view = self.send_view(id)?;
        let text = view.text.unwrap_or(SendTextView {
            text: None,
            hidden: false,
        });
        Ok(SendDraft {
            name: view.name,
            text: SecretString::new(text.text.unwrap_or_default()),
            hidden: text.hidden,
            notes: view.notes.filter(|n| !n.is_empty()),
            deletion_date: view.deletion_date,
            expiration_date: view.expiration_date,
            max_access_count: view.max_access_count,
            password: None,
            hide_email: view.hide_email,
            disabled: view.disabled,
        })
    }

    /// Creates a text send; returns its id, its link and the resynced
    /// vault.
    pub async fn create_send(
        &mut self,
        draft: SendDraft,
    ) -> Result<(String, SecretString, Decrypted), Error> {
        draft.validate(Utc::now())?;
        let text = SendTextView {
            text: Some(draft.text.expose().to_owned()),
            hidden: draft.hidden,
        };
        let request = add_request(draft, SendViewType::Text(text));
        let body: SendRequestModel = self.key_store().encrypt(request).map_err(Error::crypto)?;
        let body = serde_json::to_value(body).map_err(Error::crypto)?;
        let access = self.access_token().await?;
        let created = self
            .api
            .call(Method::POST, &access, "sends", Some(&body))
            .await?;
        let view = self.decrypt_response(created)?;
        let id = view.id.ok_or(Error::NotFound)?.to_string();
        let link = share_link(
            self.api.server(),
            view.access_id.as_deref().ok_or(Error::NotFound)?,
            view.key.as_deref().ok_or(Error::NotFound)?,
        );
        let vault = self.sync_with(&access).await?;
        Ok((id, SecretString::new(link), vault))
    }

    /// Creates a file send: name and contents encrypted by the send's key,
    /// then uploaded in two steps. If the contents don't go through, the
    /// send is deleted. Returns its id, its link and the resynced
    /// vault.
    pub async fn create_file_send(
        &mut self,
        draft: SendDraft,
        file_name: &str,
        contents: &[u8],
    ) -> Result<(String, SecretString, Decrypted), Error> {
        draft.validate(Utc::now())?;
        let file_name = checked_file(file_name, contents)?;
        let request = add_request(
            draft,
            SendViewType::File(SendFileView {
                id: None,
                file_name: file_name.to_owned(),
                size: None,
                size_name: None,
            }),
        );
        let mut body: SendRequestModel =
            self.key_store().encrypt(request).map_err(Error::crypto)?;
        let encrypted = encrypt_file_with_send_key(self.key_store(), &body.key, contents)?;
        body.file_length = Some(
            i64::try_from(encrypted.len())
                .map_err(|_| Error::Invalid("file too large".to_owned()))?,
        );
        let encrypted_name = body
            .file
            .as_ref()
            .and_then(|f| f.file_name.clone())
            .ok_or_else(|| Error::Crypto("file name not encrypted".to_owned()))?;
        let body = serde_json::to_value(body).map_err(Error::crypto)?;
        let access = self.access_token().await?;
        let created = self
            .api
            .create_file_send(&access, &body, &encrypted_name, encrypted)
            .await?;
        let view = self.decrypt_response(created)?;
        let id = view.id.ok_or(Error::NotFound)?.to_string();
        let link = share_link(
            self.api.server(),
            view.access_id.as_deref().ok_or(Error::NotFound)?,
            view.key.as_deref().ok_or(Error::NotFound)?,
        );
        let vault = self.sync_with(&access).await?;
        Ok((id, SecretString::new(link), vault))
    }

    /// Creates a file send from an item's attachment: downloaded and
    /// decrypted (attachment key), then encrypted again by the send's key.
    /// The plaintext contents don't leave Rust's memory, erased when
    /// dropped.
    pub async fn create_send_from_attachment(
        &mut self,
        draft: SendDraft,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(String, SecretString, Decrypted), Error> {
        draft.validate(Utc::now())?;
        let (file_name, contents) = self.download_attachment(item_id, attachment_id).await?;
        self.create_file_send(draft, &file_name, &contents).await
    }

    /// Edits a send: name, text (text send), notes, dates, limits, and the
    /// password if given. The key doesn't change: the link already shared
    /// stays valid. A file send's file doesn't change (the server ignores
    /// it, like Bitwarden).
    pub async fn update_send(&mut self, id: &str, draft: SendDraft) -> Result<Decrypted, Error> {
        draft.validate(Utc::now())?;
        let mut view = self.send_view(id)?;
        view.name = draft.name.trim().to_owned();
        view.notes = text(draft.notes);
        if view.r#type == SendType::Text {
            view.text = Some(SendTextView {
                text: Some(draft.text.expose().to_owned()),
                hidden: draft.hidden,
            });
        }
        view.deletion_date = draft.deletion_date;
        view.expiration_date = draft.expiration_date;
        view.max_access_count = draft.max_access_count;
        view.hide_email = draft.hide_email;
        view.disabled = draft.disabled;
        view.new_password = draft
            .password
            .filter(|p| !p.is_empty())
            .map(|p| p.expose().to_owned());
        let send = self.sdk.sends().encrypt(view).map_err(Error::crypto)?;
        let body =
            serde_json::to_value(SendWithIdRequestModel::from(send)).map_err(Error::crypto)?;
        let access = self.access_token().await?;
        self.api
            .call(Method::PUT, &access, &format!("sends/{id}"), Some(&body))
            .await?;
        self.sync_with(&access).await
    }

    /// Deletes the send from the server: the link leads nowhere anymore.
    pub async fn delete_send(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.send_view(id)?;
        let access = self.access_token().await?;
        self.api
            .call(Method::DELETE, &access, &format!("sends/{id}"), None)
            .await?;
        self.sync_with(&access).await
    }

    /// Removes a send's password.
    pub async fn remove_send_password(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.send_view(id)?;
        let access = self.access_token().await?;
        self.api
            .call(
                Method::PUT,
                &access,
                &format!("sends/{id}/remove-password"),
                None,
            )
            .await?;
        self.sync_with(&access).await
    }

    fn cached_sends(&self) -> Result<Vec<Send>, Error> {
        let Some(json) = &self.account.sync else {
            return Ok(Vec::new());
        };
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?;
        Ok(sync
            .sends
            .unwrap_or_default()
            .into_iter()
            .filter_map(|model| Send::try_from(model).ok())
            .collect())
    }

    fn send_view(&self, id: &str) -> Result<SendView, Error> {
        let send = self
            .cached_sends()?
            .into_iter()
            .find(|s| s.id.is_some_and(|sid| sid.to_string() == id))
            .ok_or(Error::NotFound)?;
        self.sdk.sends().decrypt(send).map_err(Error::crypto)
    }

    fn decrypt_response(&self, body: Value) -> Result<SendView, Error> {
        let model: SendResponseModel = serde_json::from_value(body)
            .map_err(|e| Error::Server(format!("unreadable send ({e})")))?;
        let send = Send::try_from(model).map_err(Error::crypto)?;
        self.sdk.sends().decrypt(send).map_err(Error::crypto)
    }
}

impl Api {
    /// Creates a file send: reservation (v2) then contents; the old
    /// one-shot upload if the server doesn't know v2. Returns the created
    /// send (encrypted).
    async fn create_file_send(
        &self,
        access_token: &str,
        body: &Value,
        encrypted_name: &str,
        contents: Vec<u8>,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .post(format!("{}/api/sends/file/v2", self.base))
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
        ) {
            return self
                .create_file_send_legacy(access_token, body, encrypted_name, contents)
                .await;
        }
        let reservation = write_response(response).await?;
        let send = reservation
            .get("sendResponse")
            .cloned()
            .ok_or_else(|| Error::Server("reservation without a send".to_owned()))?;
        let id = send
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("reservation without an id".to_owned()))?
            .to_owned();
        let uploaded = self
            .upload_reserved(access_token, &reservation, encrypted_name, contents)
            .await;
        if let Err(error) = uploaded {
            // No empty send left on the server.
            let _ = self
                .call(Method::DELETE, access_token, &format!("sends/{id}"), None)
                .await;
            return Err(error);
        }
        Ok(send)
    }

    /// Old upload, in one request: the description (`model`, JSON) and the
    /// contents together.
    async fn create_file_send_legacy(
        &self,
        access_token: &str,
        body: &Value,
        encrypted_name: &str,
        contents: Vec<u8>,
    ) -> Result<Value, Error> {
        let form = Form::new()
            .text("model", body.to_string())
            .part("data", file_part(encrypted_name, contents)?);
        let response = self
            .http
            .post(format!("{}/api/sends/file", self.base))
            .bearer_auth(access_token)
            .timeout(TRANSFER_TIMEOUT)
            .multipart(form)
            .send()
            .await?;
        write_response(response).await
    }

    /// Download address of a send's file, with the recipient's anonymous
    /// token. The server counts an access.
    async fn send_file_url(&self, token: &str, file_id: &str) -> Result<String, Error> {
        let response = self
            .http
            .post(format!("{}/api/sends/access/file/{file_id}", self.base))
            .bearer_auth(token)
            .send()
            .await?;
        let body = write_response(response).await?;
        let url = body
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("send without a file address".to_owned()))?;
        crate::attachments::resolve(url, &self.base)
    }
}

fn text(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::SymmetricKeySlotId;
    use bitwarden_crypto::{
        Decryptable, EncString, KeyStore, PrimitiveEncryptable, SymmetricCryptoKey,
        derive_shareable_key,
    };
    use data_encoding::BASE64URL_NOPAD;
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn links_round_trip() {
        let link = share_link("https://vault.exemple.fr/", "AbC-d_e", "a2V5");
        assert_eq!(link, "https://vault.exemple.fr/#/send/AbC-d_e/a2V5");
        let (server, access, key) = parse_link(&link).unwrap();
        assert_eq!(server, "https://vault.exemple.fr");
        assert_eq!(access, "AbC-d_e");
        assert_eq!(key, "a2V5");
        assert!(parse_link("https://vault.exemple.fr/#/send/seul").is_err());
        assert!(parse_link("https://vault.exemple.fr/").is_err());
    }

    #[test]
    fn drafts_are_checked() {
        let now = Utc::now();
        let draft = SendDraft::text("Wi-Fi", SecretString::new("secret"), now);
        assert_eq!(
            draft.deletion_date - now,
            Duration::days(DEFAULT_DELETION_DAYS)
        );
        assert!(draft.validate(now).is_ok());
        let too_far = SendDraft {
            deletion_date: now + Duration::days(40),
            ..draft.clone()
        };
        assert!(too_far.validate(now).is_err());
        let expires_after_deletion = SendDraft {
            expiration_date: Some(draft.deletion_date + Duration::hours(1)),
            ..draft.clone()
        };
        assert!(expires_after_deletion.validate(now).is_err());
        let unnamed = SendDraft {
            name: "  ".to_owned(),
            ..draft
        };
        assert!(unnamed.validate(now).is_err());
    }

    /// Bitwarden vector: a known send key and the text it encrypts
    /// (`Send::derive_shareable_key`, HKDF-SHA256, salt `bitwarden-send`,
    /// info `send`). Checks, independently of the SDK, the derivation the
    /// link imposes on the recipient.
    #[test]
    fn send_key_derivation_matches_the_bitwarden_recipe() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let raw = [7u8; 16];
        // HKDF-SHA256: extraction salted by "bitwarden-send", expansion
        // with info "send", 64 bytes (AES-256 key then HMAC key).
        let hkdf = Hkdf::<Sha256>::new(Some(b"bitwarden-send"), &raw);
        let mut expected = [0u8; 64];
        hkdf.expand(b"send", &mut expected).unwrap();

        let derived = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            Zeroizing::new(raw),
            "send",
            Some("send"),
        ));
        assert_eq!(derived.to_encoded().as_ref(), &expected[..]);

        // And the link's key (base64url) decrypts what the derived key encrypts.
        let store: KeyStore<bitwarden_core::key_management::KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let slot: SymmetricKeySlotId = ctx.add_local_symmetric_key(derived);
        let encrypted: EncString = "mot de passe du Wi-Fi".encrypt(&mut ctx, slot).unwrap();
        let plain: String = encrypted.decrypt(&mut ctx, slot).unwrap();
        assert_eq!(plain, "mot de passe du Wi-Fi");
        let access = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&raw)).unwrap();
        let response = SendAccessResponse {
            id: None,
            type_: Some(SendType::Text),
            name: Some(encrypted.to_string()),
            text: None,
            file: None,
            data: None,
            expiration_date: None,
            creator_identifier: None,
        };
        let view = access.decrypt_response(response).unwrap();
        assert_eq!(view.name.as_deref(), Some("mot de passe du Wi-Fi"));
    }

    /// User key from the Bitwarden SDK's tests.
    const USER_KEY: &str =
        "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";

    /// File send, end to end without a server: the creation request (send
    /// key wrapped by the user's, encrypted name), the contents encrypted
    /// by the send's key, then the recipient who only has the link. One
    /// altered byte gets everything rejected.
    #[test]
    fn file_send_round_trip_with_the_link_key() {
        let user_key: SymmetricCryptoKey = USER_KEY.to_owned().try_into().unwrap();
        let store = bitwarden_core::key_management::create_test_crypto_with_user_key(user_key);
        let now = Utc::now();
        let request = add_request(
            SendDraft::file("Bail", now),
            SendViewType::File(SendFileView {
                id: None,
                file_name: "bail signé.pdf".to_owned(),
                size: None,
                size_name: None,
            }),
        );
        let body: SendRequestModel = store.encrypt(request).unwrap();
        assert_eq!(body.r#type, Some(bitwarden_api_api::models::SendType::File));
        let contents = "Bail signé — page 1/3\n".repeat(700).into_bytes();
        let encrypted = encrypt_file_with_send_key(&store, &body.key, &contents).unwrap();

        // `EncArrayBuffer` format: type 2 | IV (16) | MAC (32) | ciphertext
        // (AES-CBC, PKCS#7 padding: at most one more block).
        assert_eq!(encrypted[0], 2, "AES-256-CBC + HMAC-SHA256");
        let padded = (contents.len() / 16 + 1) * 16;
        assert_eq!(encrypted.len(), 1 + 16 + 32 + padded);
        assert!(encrypted.len() as u64 <= contents.len() as u64 + ENCRYPTION_OVERHEAD);
        assert!(
            !encrypted.windows(4).any(|w| w == b"Bail"),
            "nothing in the clear"
        );

        // The link carries the send's raw key (16 bytes, base64url).
        let raw: Vec<u8> = {
            let wrapped: EncString = body.key.parse().unwrap();
            let mut ctx = store.context();
            wrapped.decrypt(&mut ctx, SymmetricKeySlotId::User).unwrap()
        };
        assert_eq!(raw.len(), 16);
        let access = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&raw)).unwrap();
        assert_eq!(access.decrypt_file_buffer(&encrypted).unwrap(), contents);
        let file_name = body.file.as_ref().unwrap().file_name.clone();
        let response = SendAccessResponse {
            id: None,
            type_: Some(SendType::File),
            name: body.name.clone(),
            text: None,
            file: Some(bitwarden_send::SendAccessFileResponse {
                id: Some("f1".to_owned()),
                file_name,
                size: Some(encrypted.len().to_string()),
                size_name: None,
            }),
            data: None,
            expiration_date: None,
            creator_identifier: None,
        };
        let view = access.decrypt_response(response).unwrap();
        assert_eq!(view.name.as_deref(), Some("Bail"));
        assert_eq!(
            view.file.and_then(|f| f.file_name).as_deref(),
            Some("bail signé.pdf")
        );

        for position in [0, 20, 60, encrypted.len() - 1] {
            let mut altered = encrypted.clone();
            altered[position] ^= 1;
            assert!(
                access.decrypt_file_buffer(&altered).is_err(),
                "byte {position} altered"
            );
        }
        assert!(
            access
                .decrypt_file_buffer(&encrypted[..encrypted.len() - 16])
                .is_err()
        );
        // Another link key decrypts nothing.
        let other = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&[9u8; 16])).unwrap();
        assert!(other.decrypt_file_buffer(&encrypted).is_err());
    }

    #[test]
    fn files_are_checked() {
        assert!(checked_file("  ", b"x").is_err());
        assert!(checked_file("vide.txt", b"").is_err());
        assert_eq!(checked_file(" a.txt ", b"x").unwrap(), "a.txt");
        let too_big = vec![0; MAX_SEND_FILE_SIZE as usize + 1];
        assert!(matches!(
            checked_file("gros.bin", &too_big),
            Err(Error::Invalid(_))
        ));
    }

    /// A send's password: PBKDF2-SHA256, 100,000 iterations, salted by the
    /// send's raw key, in base64 (what the server compares).
    #[test]
    fn send_password_hash_is_pbkdf2_of_the_send_key() {
        use data_encoding::BASE64;

        use hmac::{Hmac, Mac};

        // PBKDF2 over a single block (32 bytes): U1 = HMAC(pwd, salt ‖ 1),
        // Ui = HMAC(pwd, Ui-1), result = U1 ⊕ … ⊕ U100000.
        let raw = [42u8; 16];
        let hmac = |message: &[u8]| {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"ouvre-toi").unwrap();
            mac.update(message);
            mac.finalize().into_bytes()
        };
        let mut block = hmac(&[&raw[..], &1u32.to_be_bytes()].concat());
        let mut expected: [u8; 32] = block.into();
        for _ in 1..100_000 {
            block = hmac(&block);
            for (out, byte) in expected.iter_mut().zip(block.iter()) {
                *out ^= byte;
            }
        }
        let access = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&raw)).unwrap();
        assert_eq!(
            access.hash_password_b64("ouvre-toi"),
            BASE64.encode(&expected)
        );
    }
}
