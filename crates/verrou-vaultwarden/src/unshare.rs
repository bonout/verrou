//! "Unshare": bring an organization item back into the personal vault.
//!
//! Bitwarden has no reverse path to sharing: the server refuses to change
//! the organization of an existing item ("Organization mismatch" in
//! Vaultwarden, `update_cipher_from_data`), and the official apps only offer
//! to clone the item to "My vault" then delete the original. Verrou does
//! the same, in one action:
//!
//! 1. the item is decrypted (organization key);
//! 2. its attachments are downloaded and decrypted, in memory;
//! 3. a personal copy is encrypted by the SDK under the user's key, with a
//!    **new** item key: the organization doesn't know the copy's key.
//!    Password history, passkeys, TOTP, fields and notes come along; the
//!    attachments are re-encrypted under new keys and uploaded again;
//! 4. the organization's copy is deleted permanently
//!    (`DELETE /api/ciphers/{id}`). If the deletion fails, the personal copy
//!    is removed: no duplicate.
//!
//! The item must be editable and deletable in the organization, and its
//! passwords visible: otherwise the copy would reveal what the organization
//! hides (Vaultwarden only lets a collection with hidden passwords be edited
//! with the "manage" right). The action needs the server: it doesn't go
//! through the offline queue (like sharing).

use std::collections::{HashMap, HashSet};

use bitwarden_vault::CipherView;
use verrou_core::import::ImportedFile;

use crate::{Connection, Decrypted, Error, Progress, Skipped};

/// Outcome of an unshare.
pub struct UnshareOutcome {
    /// Items brought back: (organization id, new personal id).
    pub moved: Vec<(String, String)>,
    /// Set aside before anything is sent: (id, reason).
    pub skipped: Vec<(String, Skipped)>,
    /// Refused (unreadable attachment, server): (title, reason).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// The personal copy of an organization item: without organization or
/// collections, without item key (the SDK draws a new one when encrypting),
/// without attachments (they are uploaded again separately).
pub(crate) fn personal_copy(mut view: CipherView) -> CipherView {
    view.id = None;
    view.organization_id = None;
    view.collection_ids = Vec::new();
    view.key = None;
    view.attachments = None;
    view.attachment_decryption_failures = None;
    view.edit = true;
    view.view_password = true;
    view.permissions = None;
    view.organization_use_totp = false;
    view.local_data = None;
    // An old date would be taken for a stale copy by the server
    // (`lastKnownRevisionDate`).
    view.revision_date = chrono::Utc::now();
    view
}

/// Why an item can't leave its organization (`None`: it can).
pub(crate) fn refusal(view: &CipherView) -> Option<Skipped> {
    if view.organization_id.is_none() {
        Some(Skipped::NotShared)
    } else if view.deleted_date.is_some() {
        Some(Skipped::InTrash)
    } else if !view.view_password {
        Some(Skipped::PasswordsHidden)
    } else if !view.edit || view.partial || view.permissions.as_ref().is_some_and(|p| !p.delete) {
        Some(Skipped::ReadOnly)
    } else {
        None
    }
}

impl Connection {
    /// Brings organization items back into the personal vault (see the
    /// module). One item at a time: each one succeeds or fails as a whole.
    pub async fn unshare(
        &mut self,
        ids: &[String],
        progress: Progress<'_>,
    ) -> Result<UnshareOutcome, Error> {
        let access = self.require_online("Unsharing").await?;
        let mut ciphers: HashMap<String, _> = self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut seen = HashSet::new();
        let (mut moved, mut skipped, mut failed) = (Vec::new(), Vec::new(), Vec::new());
        let ids: Vec<String> = ids
            .iter()
            .map(|id| self.resolve(id))
            .filter(|id| seen.insert(id.clone()))
            .collect();
        let total = ids.len();
        for (done, id) in ids.into_iter().enumerate() {
            progress(done, total);
            let Some(cipher) = ciphers.remove(&id) else {
                skipped.push((id, Skipped::NotFound));
                continue;
            };
            let view = Box::pin(self.decrypt_view(cipher.clone())).await?;
            if let Some(reason) = refusal(&view) {
                skipped.push((id, reason));
                continue;
            }
            let title = view.name.clone();
            if view
                .attachment_decryption_failures
                .as_ref()
                .is_some_and(|f| !f.is_empty())
            {
                failed.push((title, "an attachment is unreadable".to_owned()));
                continue;
            }
            // The attachments, decrypted in memory (wiped when freed).
            let mut files = Vec::new();
            let mut unreadable = None;
            for attachment in view.attachments.iter().flatten() {
                let name = attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| "attachment".to_owned());
                match Box::pin(self.fetch_attachment(
                    &access,
                    &id,
                    cipher.clone(),
                    attachment.clone(),
                ))
                .await
                {
                    Ok(plain) => files.push(ImportedFile::new(name, plain.to_vec())),
                    Err(Error::Network(message)) => {
                        self.mark_offline();
                        return Err(Error::Network(message));
                    }
                    Err(error) => {
                        unreadable = Some(format!("attachment \"{name}\": {error}"));
                        break;
                    }
                }
            }
            if let Some(reason) = unreadable {
                failed.push((title, reason));
                continue;
            }
            let new_id = match Box::pin(self.create_with_files(personal_copy(view), &files)).await {
                Ok(new_id) => new_id,
                Err(Error::Network(message)) => {
                    self.mark_offline();
                    return Err(Error::Network(message));
                }
                Err(error) => {
                    failed.push((title, error.to_string()));
                    continue;
                }
            };
            drop(files);
            match self.api.delete_cipher(&access, &id).await {
                Ok(()) => moved.push((id, new_id)),
                Err(error) => {
                    // No duplicate: the personal copy goes away.
                    let _ = self.api.delete_cipher(&access, &new_id).await;
                    failed.push((title, error.to_string()));
                }
            }
        }
        progress(total, total);
        let vault = Box::pin(self.sync_with(&access)).await?;
        Ok(UnshareOutcome {
            moved,
            skipped,
            failed,
            vault,
        })
    }
}
