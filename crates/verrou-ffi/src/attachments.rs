//! Attachments and documents.
//!
//! The list (names and sizes) comes from the cache, no network. A file's
//! content is downloaded on each open, decrypted in Rust, then crosses the
//! boundary to Swift (which opens it in Quick Look from a temporary file,
//! erased afterwards, or writes it where the user asked). Like the other
//! secrets, a protected item ("ask for the master password again") only
//! hands over its files after confirmation.
//! Known limit: the copy passed to Swift (`Data`) is not zeroed.

use verrou_vaultwarden::AttachmentInfo;

use crate::{VaultSession, VerrouError};

/// An attachment, as the item's page shows it. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentEntry {
    pub id: String,
    /// File name; empty if the SDK couldn't decrypt it.
    pub file_name: String,
    pub readable: bool,
    /// Size of the encrypted file, in bytes.
    pub size: u64,
}

impl From<AttachmentInfo> for AttachmentEntry {
    fn from(info: AttachmentInfo) -> Self {
        Self {
            id: info.id,
            readable: info.file_name.is_some(),
            file_name: info.file_name.unwrap_or_default(),
            size: info.size,
        }
    }
}

/// A decrypted file.
#[derive(Clone, uniffi::Record)]
pub struct AttachmentContent {
    pub file_name: String,
    pub data: Vec<u8>,
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// An item's attachments (empty for the mock vault).
    pub async fn attachments(&self, item_id: String) -> Result<Vec<AttachmentEntry>, VerrouError> {
        self.with_vault(|v| Self::item(v, &item_id).map(drop))?;
        let Some(connection) = self.current_connection() else {
            return Ok(Vec::new());
        };
        let list = connection.lock().await.attachments(&item_id).await?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// ⚠️ Downloads and decrypts an attachment, at the user's request
    /// (open, save as).
    pub async fn download_attachment(
        &self,
        item_id: String,
        attachment_id: String,
    ) -> Result<AttachmentContent, VerrouError> {
        self.with_vault(|v| self.require_authorized(Self::item(v, &item_id)?))?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (file_name, data) = connection
            .lock()
            .await
            .download_attachment(&item_id, &attachment_id)
            .await?;
        Ok(AttachmentContent {
            file_name,
            data: data.to_vec(),
        })
    }

    /// Adds a file to the item, then resyncs.
    pub async fn add_attachment(
        &self,
        item_id: String,
        file_name: String,
        data: Vec<u8>,
    ) -> Result<(), VerrouError> {
        let data = zeroize::Zeroizing::new(data);
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .add_attachment(&item_id, &file_name, &data)
            .await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Permanently deletes an attachment, then resyncs.
    pub async fn delete_attachment(
        &self,
        item_id: String,
        attachment_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .delete_attachment(&item_id, &attachment_id)
            .await?;
        self.install_if_current(&connection, decrypted)
    }

    /// New "document": a secure note named after the file, the file as an
    /// attachment. Returns the note's id.
    pub async fn create_document(
        &self,
        file_name: String,
        data: Vec<u8>,
        folder_id: Option<String>,
    ) -> Result<String, VerrouError> {
        let data = zeroize::Zeroizing::new(data);
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, decrypted) = connection
            .lock()
            .await
            .create_document(&file_name, &data, folder_id)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(id)
    }
}
