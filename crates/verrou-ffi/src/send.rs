//! Sends (Bitwarden Send): share a text or a file through an encrypted
//! link.
//!
//! The list carries neither the text nor the link (which contains the
//! key): Swift asks for them separately, when the user copies the link or
//! opens the edit screen. A file's content crosses the boundary only
//! once, from Swift to Rust, on creation; an attachment's content doesn't
//! cross it at all (decrypted then encrypted again in Rust).

use verrou_core::SecretString;
use verrou_vaultwarden::send::{SendDraft, SendInfo, SendKind};

use crate::{VaultSession, VerrouError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SendContent {
    Text,
    File,
}

/// A Send as the list shows it. No secret.
// A Bitwarden Send's options are booleans: the model keeps them as is.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, uniffi::Record)]
pub struct SendSummary {
    pub id: String,
    pub name: String,
    pub content: SendContent,
    pub file_name: Option<String>,
    /// Size of the encrypted file, in bytes (file Send).
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
    /// The link still leads to the content (not disabled, expired or used up).
    pub available: bool,
}

impl From<SendInfo> for SendSummary {
    fn from(info: SendInfo) -> Self {
        let available = info.is_available(now());
        Self {
            id: info.id,
            name: info.name,
            content: match info.kind {
                SendKind::Text => SendContent::Text,
                SendKind::File => SendContent::File,
            },
            file_name: info.file_name,
            file_size: info.file_size,
            has_password: info.has_password,
            access_count: info.access_count,
            max_access_count: info.max_access_count,
            disabled: info.disabled,
            hide_email: info.hide_email,
            deletion_date: info.deletion_date,
            expiration_date: info.expiration_date,
            revision_date: info.revision_date,
            available,
        }
    }
}

/// The create or edit screen of a Send.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SendFields {
    pub name: String,
    pub text: String,
    pub hidden: bool,
    pub notes: Option<String>,
    /// Unix timestamps.
    pub deletion_date: i64,
    pub expiration_date: Option<i64>,
    pub max_access_count: Option<u32>,
    /// New password; empty or absent: none (creation) or unchanged.
    pub password: Option<String>,
    pub hide_email: bool,
    pub disabled: bool,
}

/// A created Send: its identifier and its share link (which carries the key).
#[derive(Clone, Debug, uniffi::Record)]
pub struct CreatedSend {
    pub id: String,
    pub link: String,
}

/// A file Send prefilled for an attachment.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachmentSendFields {
    pub fields: SendFields,
    pub file_name: String,
    /// Size of the encrypted attachment, in bytes.
    pub size: u64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn date(timestamp: i64) -> Result<chrono::DateTime<chrono::Utc>, VerrouError> {
    chrono::DateTime::from_timestamp(timestamp, 0).ok_or_else(|| VerrouError::Invalid {
        message: "invalid date".to_owned(),
    })
}

impl TryFrom<SendFields> for SendDraft {
    type Error = VerrouError;

    fn try_from(fields: SendFields) -> Result<Self, VerrouError> {
        Ok(Self {
            name: fields.name,
            text: SecretString::new(fields.text),
            hidden: fields.hidden,
            notes: fields.notes,
            deletion_date: date(fields.deletion_date)?,
            expiration_date: fields.expiration_date.map(date).transpose()?,
            max_access_count: fields.max_access_count,
            password: fields
                .password
                .filter(|p| !p.is_empty())
                .map(SecretString::new),
            hide_email: fields.hide_email,
            disabled: fields.disabled,
        })
    }
}

impl From<SendDraft> for SendFields {
    fn from(draft: SendDraft) -> Self {
        Self {
            name: draft.name,
            text: draft.text.expose().to_owned(),
            hidden: draft.hidden,
            notes: draft.notes,
            deletion_date: draft.deletion_date.timestamp(),
            expiration_date: draft.expiration_date.map(|d| d.timestamp()),
            max_access_count: draft.max_access_count,
            password: None,
            hide_email: draft.hide_email,
            disabled: draft.disabled,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// The Sends of the last sync, newest first.
    pub async fn sends(&self) -> Result<Vec<SendSummary>, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let sends = connection.lock().await.sends()?;
        Ok(sends.into_iter().map(Into::into).collect())
    }

    /// ⚠️ Share link of a Send: it carries the key, hence the content.
    pub async fn send_link(&self, id: String) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let link = connection.lock().await.send_link(&id)?;
        Ok(link.expose().to_owned())
    }

    /// ⚠️ Prefilled draft to edit a Send, text included.
    pub async fn send_fields(&self, id: String) -> Result<SendFields, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let draft = connection.lock().await.send_draft(&id)?;
        Ok(draft.into())
    }

    /// Creates a text Send and syncs again; returns its identifier and
    /// its link. The positions of `summaries()` change.
    pub async fn create_send(&self, fields: SendFields) -> Result<CreatedSend, VerrouError> {
        let draft = SendDraft::try_from(fields)?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, link, decrypted) = connection.lock().await.create_send(draft).await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(CreatedSend {
            id,
            link: link.expose().to_owned(),
        })
    }

    /// Creates a file Send (name and content encrypted in Rust with the
    /// Send's key) and syncs again; returns its identifier and its link.
    pub async fn create_file_send(
        &self,
        fields: SendFields,
        file_name: String,
        data: Vec<u8>,
    ) -> Result<CreatedSend, VerrouError> {
        let data = zeroize::Zeroizing::new(data);
        let draft = SendDraft::try_from(fields)?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, link, decrypted) = connection
            .lock()
            .await
            .create_file_send(draft, &file_name, &data)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(CreatedSend {
            id,
            link: link.expose().to_owned(),
        })
    }

    /// A new file Send prefilled for an item's attachment: named after the
    /// item and the file, default settings. Also returns the file name.
    /// A protected item asks for its confirmation first.
    pub async fn send_fields_for_attachment(
        &self,
        item_id: String,
        attachment_id: String,
    ) -> Result<AttachmentSendFields, VerrouError> {
        let item_id = self.local_id(&item_id)?.to_owned();
        let title = self.with_vault(|v| {
            let item = Self::item(v, &item_id)?;
            self.require_authorized(item)?;
            Ok(item.title.clone())
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let attachment = connection
            .lock()
            .await
            .attachments(&item_id)
            .await?
            .into_iter()
            .find(|a| a.id == attachment_id)
            .ok_or(VerrouError::NotFound)?;
        let file_name = attachment.file_name.ok_or(VerrouError::NotFound)?;
        let draft = SendDraft::file(format!("{title} — {file_name}"), chrono::Utc::now());
        Ok(AttachmentSendFields {
            fields: draft.into(),
            file_name,
            size: attachment.size,
        })
    }

    /// ⚠️ Creates a file Send with an attachment: downloaded, decrypted
    /// then encrypted again with the Send's key, without going through
    /// Swift. A protected item asks for its confirmation first.
    pub async fn create_send_from_attachment(
        &self,
        fields: SendFields,
        item_id: String,
        attachment_id: String,
    ) -> Result<CreatedSend, VerrouError> {
        let item_id = self.local_id(&item_id)?.to_owned();
        self.with_vault(|v| self.require_authorized(Self::item(v, &item_id)?))?;
        let draft = SendDraft::try_from(fields)?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, link, decrypted) = connection
            .lock()
            .await
            .create_send_from_attachment(draft, &item_id, &attachment_id)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(CreatedSend {
            id,
            link: link.expose().to_owned(),
        })
    }

    pub async fn update_send(&self, id: String, fields: SendFields) -> Result<(), VerrouError> {
        let draft = SendDraft::try_from(fields)?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.update_send(&id, draft).await?;
        self.install_if_current(&connection, decrypted)
    }

    pub async fn delete_send(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.delete_send(&id).await?;
        self.install_if_current(&connection, decrypted)
    }

    pub async fn remove_send_password(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.remove_send_password(&id).await?;
        self.install_if_current(&connection, decrypted)
    }
}

#[uniffi::export]
impl VaultSession {
    /// ⚠️ A new Send prefilled with an item's field (the password, for
    /// example): named after the item, text hidden for the recipient,
    /// deletion in 7 days, a single access. A protected item asks for its
    /// confirmation first.
    pub fn send_fields_for_field(
        &self,
        item_id: String,
        field_id: String,
    ) -> Result<SendFields, VerrouError> {
        let item_id = self.local_id(&item_id)?.to_owned();
        self.with_vault(|v| {
            let item = Self::item(v, &item_id)?;
            self.require_authorized(item)?;
            let (label, value) = if field_id == "notes" {
                (
                    "Notes".to_owned(),
                    item.notes.as_ref().ok_or(VerrouError::NotFound)?.clone(),
                )
            } else {
                let field = item.field(&field_id).ok_or(VerrouError::NotFound)?;
                // Password hidden by the organization: it doesn't leave,
                // no more through a Send than through `reveal`.
                if item.hides(field) {
                    return Err(crate::hidden_by_organization());
                }
                (field.label.clone(), field.value.clone())
            };
            let mut draft = SendDraft::text(
                format!("{} — {label}", item.title),
                value,
                chrono::Utc::now(),
            );
            draft.hidden = true;
            draft.max_access_count = Some(1);
            Ok(draft.into())
        })
    }

    /// A new empty Send, with the default settings.
    pub fn new_send_fields(&self) -> SendFields {
        SendDraft::text(String::new(), SecretString::default(), chrono::Utc::now()).into()
    }

    /// Maximum size of a sent file, before encryption.
    pub fn max_send_file_size(&self) -> u64 {
        verrou_vaultwarden::send::MAX_SEND_FILE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use verrou_core::{Vault, mock};

    use super::*;

    #[test]
    fn send_from_a_field_is_prefilled_and_respects_hidden_passwords() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let shared = mock::vault_items(0, 42, mock::MockLanguage::En)
            .into_iter()
            .find(|i| i.shared.is_some() && i.field("password").is_some())
            .expect("shared item of the mock vault");
        let fields = session
            .send_fields_for_field(shared.id.clone(), "password".to_owned())
            .unwrap();
        assert!(fields.name.starts_with(&shared.title));
        assert_eq!(
            fields.text,
            shared.field("password").unwrap().value.expose()
        );
        assert!(fields.hidden);
        assert_eq!(fields.max_access_count, Some(1));

        // The organization hides passwords: no Send either.
        let mut items = mock::vault_items(0, 42, mock::MockLanguage::En);
        for item in &mut items {
            if let Some(sharing) = item.shared.as_mut() {
                sharing.hide_passwords = true;
            }
        }
        *session.vault.write().unwrap() = Some(Vault::new(items));
        assert!(matches!(
            session.send_fields_for_field(shared.id.clone(), "password".to_owned()),
            Err(VerrouError::Invalid { .. })
        ));
    }

    /// An attachment of a protected item doesn't leave without confirmation,
    /// neither to prefill the Send nor to create it.
    #[tokio::test]
    async fn attachment_sends_need_the_item_confirmation() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let protected = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.reprompt)
            .expect("protected item of the mock vault");
        assert!(matches!(
            session
                .send_fields_for_attachment(protected.id.clone(), "a1".to_owned())
                .await,
            Err(VerrouError::RepromptRequired)
        ));
        let fields = session.new_send_fields();
        assert!(matches!(
            session
                .create_send_from_attachment(fields.clone(), protected.id.clone(), "a1".to_owned())
                .await,
            Err(VerrouError::RepromptRequired)
        ));
        // Confirmed: the rest needs a Vaultwarden account (no mock vault).
        session.authorize_item(protected.id.clone());
        assert!(matches!(
            session
                .create_send_from_attachment(fields, protected.id, "a1".to_owned())
                .await,
            Err(VerrouError::Locked)
        ));
    }
}
