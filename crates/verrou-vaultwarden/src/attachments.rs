//! Attachments, in Bitwarden's format.
//!
//! Each file has its own key (AES-256-CBC + HMAC-SHA256, 64 bytes), itself
//! encrypted by the item key (or, failing that, the user's or the
//! organization's). The file name is encrypted like a field of the item;
//! the contents form an "`EncArrayBuffer`": a type byte (2), the
//! initialisation vector (16), the MAC (32), then the ciphertext. The SDK
//! does all this cryptography, MAC checked before any decryption; this
//! module only does the transport.
//!
//! Exchanges with Vaultwarden (1.37):
//! - adding, in two steps ("v2"): `POST /api/ciphers/{id}/attachment/v2`
//!   (encrypted name and key, size of the encrypted contents) reserves the
//!   attachment and returns the upload address, where the encrypted bytes
//!   go (`multipart/form-data`). If the second step fails, the reservation
//!   is deleted. Falls back to the old one-shot upload
//!   (`POST /api/ciphers/{id}/attachment`) for a server that doesn't know
//!   v2;
//! - reading: `GET /api/ciphers/{id}/attachment/{attachment}` returns a
//!   download address (signed, valid for a few minutes);
//! - deletion: `DELETE /api/ciphers/{id}/attachment/{attachment}`.
//!
//! Nothing is kept offline: an attachment is downloaded at each opening,
//! and its decrypted contents are only returned in memory (wiped when
//! freed). The vault cache only holds the encrypted metadata, like the rest
//! of the sync.

use std::collections::HashMap;
use std::time::Duration;

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_vault::{
    AttachmentEncryptResult, AttachmentView, Cipher, CipherView, DecryptError, VaultClientExt,
};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use serde_json::{Value, json};
use verrou_core::import::{ImportedFile, MAX_ATTACHMENT_SIZE};
use zeroize::Zeroizing;

use crate::api::{Api, write_response};
use crate::edit::new_view;
use crate::{Connection, Decrypted, Draft, Error};

/// Upload or download of a big file: much longer than a write.
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Encryption overhead: type, IV, MAC and padding (at most one block).
pub(crate) const ENCRYPTION_OVERHEAD: u64 = 1 + 16 + 32 + 16;

/// An item's attachment, as the interface shows it. No secret: the name,
/// decrypted, and the size announced by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub id: String,
    /// File name; `None` if the SDK couldn't decrypt it.
    pub file_name: Option<String>,
    /// Size of the encrypted file, in bytes.
    pub size: u64,
    /// Readable size ("1.4 MB"), computed by the server.
    pub size_name: String,
}

impl Connection {
    /// An item's attachments, from the cache (without network).
    pub async fn attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>, Error> {
        let view = self.cached_view(item_id).await?;
        let readable = view
            .attachments
            .iter()
            .flatten()
            .map(|a| info(a, a.file_name.clone()));
        let unreadable = view
            .attachment_decryption_failures
            .iter()
            .flatten()
            .map(|a| info(a, None));
        Ok(readable
            .chain(unreadable)
            .filter(|a| !a.id.is_empty())
            .collect())
    }

    /// Number of attachments of each item that has some, from the cache and
    /// without decrypting anything: to choose which duplicate to keep.
    pub fn attachment_counts(&self) -> Result<HashMap<String, usize>, Error> {
        Ok(self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| {
                let count = c.attachments.as_ref().map_or(0, Vec::len);
                let id = c.id?;
                (count > 0).then(|| (id.to_string(), count))
            })
            .collect())
    }

    /// Downloads an attachment and decrypts it. The contents only exist in
    /// memory, wiped when freed.
    pub async fn download_attachment(
        &mut self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
        let cipher = self.cached_cipher(item_id)?;
        let view = self.decrypt_view(cipher.clone()).await?;
        let attachment = view
            .attachments
            .into_iter()
            .flatten()
            .find(|a| a.id.as_deref() == Some(attachment_id))
            .ok_or(Error::NotFound)?;
        let name = attachment
            .file_name
            .clone()
            .unwrap_or_else(|| "attachment".to_owned());
        let access = self.access_token().await?;
        let plain = Box::pin(self.fetch_attachment(&access, item_id, cipher, attachment)).await?;
        Ok((name, plain))
    }

    /// Downloads and decrypts an attachment of an encrypted item (`cipher`):
    /// checks its size, then decrypts it with the SDK.
    pub(crate) async fn fetch_attachment(
        &self,
        access: &str,
        item_id: &str,
        cipher: Cipher,
        attachment: AttachmentView,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let attachment_id = attachment.id.clone().ok_or(Error::NotFound)?;
        let expected = attachment
            .size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok());
        let url = self
            .api
            .attachment_url(access, item_id, &attachment_id)
            .await?;
        let encrypted = self
            .api
            .download(&url, MAX_ATTACHMENT_SIZE + ENCRYPTION_OVERHEAD)
            .await?;
        if expected.is_some_and(|size| size != encrypted.len() as u64) {
            return Err(Error::Crypto(
                "incomplete attachment (unexpected size)".to_owned(),
            ));
        }
        let plain = self
            .sdk
            .vault()
            .attachments()
            .decrypt_buffer(cipher, attachment, &encrypted)
            .map_err(|e| attachment_error(&e))?;
        Ok(Zeroizing::new(plain))
    }

    /// Adds a file to an editable item, then syncs.
    pub async fn add_attachment(
        &mut self,
        item_id: &str,
        file_name: &str,
        contents: &[u8],
    ) -> Result<Decrypted, Error> {
        let file_name = checked_name(file_name, contents)?;
        let access = self.require_online("Adding an attachment").await?;
        let item_id = &self.resolve(item_id);
        // Refuses a read-only or trashed item.
        self.editable_view(item_id).await?;
        let cipher = self.cached_cipher(item_id)?;
        let encrypted = self.encrypt_file(cipher, file_name, contents)?;
        self.api
            .upload_attachment(&access, item_id, encrypted)
            .await?;
        self.sync_with(&access).await
    }

    /// Removes an attachment (permanently), then syncs.
    pub async fn delete_attachment(
        &mut self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Decrypted, Error> {
        let access = self.require_online("Deleting an attachment").await?;
        let item_id = &self.resolve(item_id);
        let view = self.editable_view(item_id).await?;
        if !view
            .attachments
            .iter()
            .flatten()
            .chain(view.attachment_decryption_failures.iter().flatten())
            .any(|a| a.id.as_deref() == Some(attachment_id))
        {
            return Err(Error::NotFound);
        }
        self.api
            .delete_attachment(&access, item_id, attachment_id)
            .await?;
        self.sync_with(&access).await
    }

    /// "Document": a secure note named after the file (without its
    /// extension), with the file as an attachment. If the file upload fails,
    /// the note is deleted.
    pub async fn create_document(
        &mut self,
        file_name: &str,
        contents: &[u8],
        folder_id: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        let file_name = checked_name(file_name, contents)?;
        self.require_online("Adding a document").await?;
        let draft = Draft {
            name: document_title(file_name),
            folder_id,
            ..Draft::default()
        };
        let file = ImportedFile::new(file_name, contents.to_vec());
        let id = self
            .create_with_files(draft_view(draft)?, std::slice::from_ref(&file))
            .await?;
        let access = self.access_token().await?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Creates an item (encrypted by the SDK) then attaches `files` to it. If
    /// a file doesn't go through, the item is deleted and the error returned:
    /// no half-imported item. Doesn't sync.
    pub(crate) async fn create_with_files(
        &mut self,
        view: CipherView,
        files: &[ImportedFile],
    ) -> Result<String, Error> {
        for file in files {
            checked_name(&file.name, &file.data)?;
        }
        let encrypted = self
            .sdk
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .map_err(Error::crypto)?;
        let cipher = encrypted.cipher.clone();
        let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
        request.encrypted_for = Some(encrypted.encrypted_for.into());
        request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
        let access = self.access_token().await?;
        let id = self.api.create_cipher(&access, &request).await?;
        let mut sent = Ok(());
        for file in files {
            let attachment = self.encrypt_file(cipher.clone(), file.name.trim(), &file.data);
            sent = match attachment {
                Ok(attachment) => self.api.upload_attachment(&access, &id, attachment).await,
                Err(error) => Err(error),
            };
            if sent.is_err() {
                break;
            }
        }
        if let Err(error) = sent {
            let _ = self.api.delete_cipher(&access, &id).await;
            return Err(error);
        }
        Ok(id)
    }

    fn encrypt_file(
        &self,
        cipher: Cipher,
        file_name: &str,
        contents: &[u8],
    ) -> Result<AttachmentEncryptResult, Error> {
        self.sdk
            .vault()
            .attachments()
            .encrypt_buffer(cipher, new_attachment(file_name), contents)
            .map_err(Error::crypto)
    }

    async fn cached_view(&self, id: &str) -> Result<CipherView, Error> {
        let cipher = self.cached_cipher(id)?;
        self.decrypt_view(cipher).await
    }

    pub(crate) async fn decrypt_view(&self, cipher: Cipher) -> Result<CipherView, Error> {
        // On the heap: the SDK's future is large (over 20 KB).
        Box::pin(self.sdk.vault().ciphers().decrypt(cipher))
            .await
            .map_err(Error::crypto)
    }
}

fn info(attachment: &AttachmentView, file_name: Option<String>) -> AttachmentInfo {
    let size = attachment
        .size
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    AttachmentInfo {
        id: attachment.id.clone().unwrap_or_default(),
        file_name,
        size,
        size_name: attachment.size_name.clone().unwrap_or_default(),
    }
}

/// Attachment to create: the SDK draws its key when encrypting.
fn new_attachment(file_name: &str) -> AttachmentView {
    AttachmentView {
        id: None,
        url: None,
        size: None,
        size_name: None,
        file_name: Some(file_name.to_owned()),
        key: None,
    }
}

/// Name without surrounding spaces, non-empty; file under the limit.
fn checked_name<'a>(file_name: &'a str, contents: &[u8]) -> Result<&'a str, Error> {
    let name = file_name.trim();
    if name.is_empty() {
        return Err(Error::Invalid("the file has no name".to_owned()));
    }
    if contents.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err(Error::Invalid(format!(
            "\"{name}\" is over 100 MB, the maximum size of an attachment"
        )));
    }
    Ok(name)
}

/// `Passeport.pdf` → `Passeport` ; `.env` reste `.env`.
fn document_title(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, _)) if !stem.trim().is_empty() => stem.trim().to_owned(),
        _ => file_name.to_owned(),
    }
}

fn draft_view(draft: Draft) -> Result<CipherView, Error> {
    new_view(draft, Utc::now())
}

/// A wrong MAC or truncated contents: the file was tampered with (or the
/// key is not the right one). Nothing is returned.
fn attachment_error(error: &DecryptError) -> Error {
    Error::Crypto(format!("attachment tampered with or unreadable ({error})"))
}

/// Address given by the server: absolute, or relative to `base`.
pub(crate) fn resolve(url: &str, base: &str) -> Result<String, Error> {
    let absolute = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_owned()
    } else if url.starts_with('/') {
        format!("{base}{url}")
    } else {
        return Err(Error::Server(format!("unexpected file address ({url})")));
    };
    let parsed = reqwest::Url::parse(&absolute)
        .map_err(|e| Error::Server(format!("invalid file address ({e})")))?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !local {
        return Err(Error::Server(
            "plain-text (HTTP) file address refused".to_owned(),
        ));
    }
    Ok(absolute)
}

impl Api {
    /// Download address of an attachment (signed, short-lived).
    pub(crate) async fn attachment_url(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<String, Error> {
        let response = self
            .http
            .get(format!(
                "{}/api/ciphers/{cipher_id}/attachment/{attachment_id}",
                self.base
            ))
            .bearer_auth(access_token)
            .send()
            .await?;
        let body = write_response(response).await?;
        let url = body
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("attachment without an address".to_owned()))?;
        resolve(url, &self.base)
    }

    /// The encrypted file, without authentication header: the address
    /// carries its own signature (and may point to external storage).
    pub(crate) async fn download(&self, url: &str, limit: u64) -> Result<Vec<u8>, Error> {
        let mut response = self.http.get(url).timeout(TRANSFER_TIMEOUT).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(if status == reqwest::StatusCode::NOT_FOUND {
                Error::NotFound
            } else {
                Error::Server(status.to_string())
            });
        }
        if response.content_length().is_some_and(|l| l > limit) {
            return Err(Error::Server("attachment is too large".to_owned()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if (bytes.len() + chunk.len()) as u64 > limit {
                return Err(Error::Server("attachment is too large".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Uploads an encrypted attachment: reservation (v2) then contents; the
    /// old one-shot upload if the server doesn't know v2.
    pub(crate) async fn upload_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment: AttachmentEncryptResult,
    ) -> Result<(), Error> {
        let file_name = attachment
            .attachment
            .file_name
            .as_ref()
            .ok_or_else(|| Error::Crypto("file name not encrypted".to_owned()))?
            .to_string();
        let key = attachment
            .attachment
            .key
            .as_ref()
            .ok_or_else(|| Error::Crypto("attachment key missing".to_owned()))?
            .to_string();
        let contents = attachment.contents;
        let response = self
            .http
            .post(format!(
                "{}/api/ciphers/{cipher_id}/attachment/v2",
                self.base
            ))
            .bearer_auth(access_token)
            .json(&json!({
                "key": key,
                "fileName": file_name,
                "fileSize": contents.len(),
                "adminRequest": false,
            }))
            .send()
            .await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
        ) {
            return self
                .upload_legacy(access_token, cipher_id, &file_name, &key, contents)
                .await;
        }
        let body = write_response(response).await?;
        let attachment_id = body
            .get("attachmentId")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("reservation without an id".to_owned()))?
            .to_owned();
        let sent = self
            .upload_reserved(access_token, &body, &file_name, contents)
            .await;
        if sent.is_err() {
            // No empty attachment left on the server.
            let _ = self
                .delete_attachment(access_token, cipher_id, &attachment_id)
                .await;
        }
        sent
    }

    pub(crate) async fn upload_reserved(
        &self,
        access_token: &str,
        reservation: &Value,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<(), Error> {
        // 0: direct upload to the server; 1: Azure (official server only).
        if reservation.get("fileUploadType").and_then(Value::as_i64) != Some(0) {
            return Err(Error::Server(
                "upload to external storage is not supported".to_owned(),
            ));
        }
        let url = reservation
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("reservation without an address".to_owned()))?;
        // Vaultwarden returns an address relative to the API.
        let url = resolve(url, &format!("{}/api", self.base))?;
        if !url.starts_with(&self.base) {
            return Err(Error::Server(
                "upload address outside the account's server".to_owned(),
            ));
        }
        let form = Form::new().part("data", file_part(file_name, contents)?);
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .timeout(TRANSFER_TIMEOUT)
            .multipart(form)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Old upload, in one request: key and contents together.
    async fn upload_legacy(
        &self,
        access_token: &str,
        cipher_id: &str,
        file_name: &str,
        key: &str,
        contents: Vec<u8>,
    ) -> Result<(), Error> {
        let form = Form::new()
            .text("key", key.to_owned())
            .part("data", file_part(file_name, contents)?);
        let response = self
            .http
            .post(format!("{}/api/ciphers/{cipher_id}/attachment", self.base))
            .bearer_auth(access_token)
            .timeout(TRANSFER_TIMEOUT)
            .multipart(form)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    pub(crate) async fn delete_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<(), Error> {
        let response = self
            .http
            .delete(format!(
                "{}/api/ciphers/{cipher_id}/attachment/{attachment_id}",
                self.base
            ))
            .bearer_auth(access_token)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Deletes an item permanently (without going through the trash).
    pub(crate) async fn delete_cipher(&self, access_token: &str, id: &str) -> Result<(), Error> {
        let response = self
            .http
            .delete(format!("{}/api/ciphers/{id}", self.base))
            .bearer_auth(access_token)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }
}

/// The encrypted contents, named by the encrypted file name (like the
/// Bitwarden apps): the server never sees the real name.
pub(crate) fn file_part(encrypted_name: &str, contents: Vec<u8>) -> Result<Part, Error> {
    Part::bytes(contents)
        .file_name(encrypted_name.to_owned())
        .mime_str("application/octet-stream")
        .map_err(|e| Error::Server(e.to_string()))
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{EncString, SymmetricCryptoKey};
    use bitwarden_vault::{AttachmentFile, AttachmentFileView};

    use super::*;

    /// User key and vectors taken from the Bitwarden SDK's tests: a file
    /// encrypted by an official app, to be read back as is.
    const USER_KEY: &str =
        "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";
    const CIPHER_KEY: &str = "2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=";
    const ATTACHMENT_KEY: &str = "2.r288/AOSPiaLFkW07EBGBw==|SAmnnCbOLFjX5lnURvoualOetQwuyPc54PAmHDTRrhT0gwO9ailna9U09q9bmBfI5XrjNNEsuXssgzNygRkezoVQvZQggZddOwHB6KQW5EQ=|erIMUJp8j+aTcmhdE50zEX+ipv/eR1sZ7EwULJm/6DY=";
    const ENCRYPTED_FILE: &str = "Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=";
    const ORIGINAL: &str = "rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==";

    fn base64(text: &str) -> Vec<u8> {
        data_encoding::BASE64.decode(text.as_bytes()).unwrap()
    }

    fn cipher(key: Option<&str>) -> Cipher {
        serde_json::from_value(json!({
            "id": null, "organizationId": null, "folderId": null, "collectionIds": [],
            "key": key,
            "name": "2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM=",
            "notes": null, "type": 1, "login": null, "identity": null, "card": null,
            "secureNote": null, "sshKey": null, "favorite": false, "reprompt": 0,
            "organizationUseTotp": false, "edit": true, "permissions": null,
            "viewPassword": true, "localData": null, "attachments": null, "fields": null,
            "passwordHistory": null, "creationDate": "2023-07-24T12:05:09.466Z",
            "deletedDate": null, "revisionDate": "2023-07-27T19:28:05.240Z",
            "archivedDate": null, "data": null,
        }))
        .unwrap()
    }

    fn store() -> bitwarden_crypto::KeyStore<bitwarden_core::key_management::KeySlotIds> {
        let key: SymmetricCryptoKey = USER_KEY.to_owned().try_into().unwrap();
        create_test_crypto_with_user_key(key)
    }

    /// A file encrypted by Bitwarden (attachment key encrypted by the item
    /// key) reads back identically.
    #[test]
    fn known_bitwarden_file_decrypts() {
        let store = store();
        // The attachment key, as the sync gives it.
        let attachment = bitwarden_vault::Attachment {
            id: Some("a1".to_owned()),
            url: None,
            size: Some("161".to_owned()),
            size_name: Some("161 Bytes".to_owned()),
            file_name: Some(
                "2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM="
                    .parse()
                    .unwrap(),
            ),
            key: Some(ATTACHMENT_KEY.parse().unwrap()),
        };
        let encrypted = base64(ENCRYPTED_FILE);
        assert_eq!(encrypted[0], 2, "type 2: AES-CBC-256 + HMAC-SHA256");
        assert_eq!(
            encrypted.len(),
            1 + 16 + 32 + 112,
            "type | IV | MAC | ciphertext"
        );
        let cipher = cipher(Some(CIPHER_KEY));
        let view = attachment_view(&store, &cipher, &attachment);
        let plain = store
            .decrypt(&AttachmentFile {
                cipher,
                attachment: view,
                contents: EncString::from_buffer(&encrypted).unwrap(),
            })
            .unwrap();
        assert_eq!(plain, base64(ORIGINAL));
    }

    /// The attachment key decrypts with the item's, as `CipherView` does at
    /// sync.
    fn attachment_view(
        store: &bitwarden_crypto::KeyStore<bitwarden_core::key_management::KeySlotIds>,
        cipher: &Cipher,
        attachment: &bitwarden_vault::Attachment,
    ) -> AttachmentView {
        let mut with_attachment = cipher.clone();
        with_attachment.attachments = Some(vec![attachment.clone()]);
        let view: CipherView = store.decrypt(&with_attachment).unwrap();
        // Unreadable name (vector without a known encrypted name): the key
        // is still returned.
        view.attachments
            .into_iter()
            .chain(view.attachment_decryption_failures)
            .flatten()
            .next()
            .unwrap()
    }

    /// Round trip: encrypted with a fresh key, wrapped by the item key; one
    /// changed byte (contents or MAC) makes everything refused.
    #[test]
    fn round_trip_and_tampering() {
        let store = store();
        let contents = "Bail signé — page 1/3\n".repeat(500).into_bytes();
        for key in [Some(CIPHER_KEY), None] {
            let cipher = cipher(key);
            let result: AttachmentEncryptResult = store
                .encrypt(AttachmentFileView {
                    cipher: cipher.clone(),
                    attachment: new_attachment("bail.txt"),
                    contents: &contents,
                })
                .unwrap();
            assert_eq!(result.contents[0], 2);
            assert_eq!(
                result.attachment.size.as_deref(),
                Some(result.contents.len().to_string().as_str())
            );
            assert!(result.contents.len() as u64 <= contents.len() as u64 + ENCRYPTION_OVERHEAD);
            assert!(
                !result.contents.windows(4).any(|w| w == b"Bail"),
                "nothing in clear"
            );
            let view = attachment_view(&store, &cipher, &result.attachment);
            assert_eq!(view.file_name.as_deref(), Some("bail.txt"));
            let decrypt = |bytes: &[u8]| {
                store.decrypt(&AttachmentFile {
                    cipher: cipher.clone(),
                    attachment: view.clone(),
                    contents: EncString::from_buffer(bytes)?,
                })
            };
            assert_eq!(decrypt(&result.contents).unwrap(), contents);
            for position in [20, 60, result.contents.len() - 1] {
                let mut altered = result.contents.clone();
                altered[position] ^= 1;
                assert!(decrypt(&altered).is_err(), "byte {position} modified");
            }
            assert!(decrypt(&result.contents[..result.contents.len() - 16]).is_err());
        }
    }

    #[test]
    fn server_addresses_are_resolved() {
        assert_eq!(
            resolve("/ciphers/c/attachment/a", "https://vault.exemple.fr/api").unwrap(),
            "https://vault.exemple.fr/api/ciphers/c/attachment/a"
        );
        assert_eq!(
            resolve(
                "https://vault.exemple.fr/attachments/c/a?token=x",
                "https://vault.exemple.fr"
            )
            .unwrap(),
            "https://vault.exemple.fr/attachments/c/a?token=x"
        );
        assert!(resolve("http://vault.exemple.fr/attachments/c/a", "https://x").is_err());
        assert!(
            resolve(
                "http://localhost:8104/attachments/c/a",
                "http://localhost:8104"
            )
            .is_ok()
        );
        assert!(resolve("ftp://x", "https://x").is_err());
    }

    #[test]
    fn names_titles_and_limits() {
        assert_eq!(document_title("Passeport.pdf"), "Passeport");
        assert_eq!(document_title("archive.tar.gz"), "archive.tar");
        assert_eq!(document_title(".env"), ".env");
        assert_eq!(document_title("LISEZMOI"), "LISEZMOI");
        assert!(checked_name("  ", b"x").is_err());
        assert_eq!(checked_name(" a.txt ", b"x").unwrap(), "a.txt");
        let too_big = vec![0; MAX_ATTACHMENT_SIZE as usize + 1];
        assert!(matches!(
            checked_name("gros.bin", &too_big),
            Err(Error::Invalid(_))
        ));
    }
}
