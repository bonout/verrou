//! Bulk actions: several items selected in the list, archived, trashed,
//! restored, added to favorites or moved to a folder at once.
//!
//! Same write path as a single action: each item joins the queue
//! (`outbox`), applied right away to the displayed vault, and the upload
//! follows in the background. It groups what Vaultwarden 1.37 can do in one
//! request: trash (`PUT /api/ciphers/delete`), restore (`…/restore`),
//! archives (`…/archive`, `…/unarchive`) and folders (`…/move`), in batches
//! of 500; a refused batch (Vaultwarden stops at the first refused item) is
//! retried one by one, to find out which. No route for favorites: one
//! encrypted edit per item, as for a single one (known revision date,
//! conflict kept as a copy). A single sync at the end, not one per item.
//!
//! Items the action doesn't apply to are set aside before anything is sent
//! and counted: read-only, in the trash (except to restore), gone. Those
//! already in the wanted state count as done, without a request.

use std::collections::{BTreeSet, HashMap, HashSet};

use bitwarden_vault::CipherView;
use chrono::Utc;

use crate::edit::folder_id;
use crate::outbox::Action;
use crate::{Connection, Decrypted, Error};

/// What is done to the selected items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkAction {
    Trash,
    Restore,
    Archive,
    Unarchive,
    Favorite(bool),
    /// Moves to this folder (`None`: no folder).
    MoveToFolder(Option<String>),
}

/// Why an item was set aside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skipped {
    /// Shared read-only (or only partly visible).
    ReadOnly,
    /// In the trash: restore it first.
    InTrash,
    /// No longer in the vault (deleted elsewhere in the meantime).
    NotFound,
    /// Already in an organization (sharing only).
    AlreadyShared,
    /// Not in an organization (unsharing only).
    NotShared,
    /// The organization hides its passwords from this account (unsharing
    /// only: the copy would reveal them).
    PasswordsHidden,
}

/// An item refused before anything is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkFailure {
    pub id: String,
    pub title: String,
    pub reason: String,
}

/// Outcome of a bulk action.
pub struct BulkOutcome {
    /// Items handled: queued, or already in the wanted state.
    pub done: usize,
    /// Part of `done` waiting for the server (in the queue).
    pub queued: usize,
    /// Items set aside before anything is sent: (id, reason).
    pub skipped: Vec<(String, Skipped)>,
    /// Refused before anything is sent, by item. The server's refusals come
    /// later, in the upload report (`take_report`).
    pub failed: Vec<BulkFailure>,
    pub vault: Decrypted,
}

/// Progress: (items handled, items to handle).
pub type Progress<'a> = &'a (dyn Fn(usize, usize) + Send + Sync);

enum Fit {
    Write,
    Already,
    Skip(Skipped),
}

impl Connection {
    /// Applies `action` to these items (in this order, without duplicates):
    /// in the queue, then sent by `sync_shared`.
    pub async fn bulk(
        &mut self,
        ids: &[String],
        action: &BulkAction,
        progress: Progress<'_>,
    ) -> Result<BulkOutcome, Error> {
        if let BulkAction::MoveToFolder(Some(folder)) = action
            && !self.cached_folders()?.contains_key(folder)
        {
            return Err(Error::Invalid("this folder no longer exists".to_owned()));
        }
        if let BulkAction::MoveToFolder(folder) = action {
            folder_id(folder.clone())?;
        }
        let (writes, already, skipped) = self.plan_bulk(ids, action).await?;
        let total = writes.len();
        let mut failed = Vec::new();
        let now = Utc::now();
        for (index, (id, mut view)) in writes.into_iter().enumerate() {
            let title = view.name.clone();
            match action {
                BulkAction::Trash => self.outbox.push_action(id, title, Action::Trash, now),
                BulkAction::Restore => self.outbox.push_action(id, title, Action::Restore, now),
                BulkAction::Archive => self.outbox.push_action(id, title, Action::Archive, now),
                BulkAction::Unarchive => {
                    self.outbox.push_action(id, title, Action::Unarchive, now);
                }
                BulkAction::MoveToFolder(folder) => {
                    self.outbox.push_move(id, title, folder.clone());
                }
                BulkAction::Favorite(favorite) => {
                    view.favorite = *favorite;
                    match self.encrypt_context(view).await {
                        Ok(encrypted) => self.outbox.push_save(id, title, false, encrypted),
                        Err(error) => failed.push(BulkFailure {
                            id,
                            title,
                            reason: error.to_string(),
                        }),
                    }
                }
            }
            progress(index + 1, total);
        }
        self.persist_outbox()?;
        let queued = total - failed.len();
        Ok(BulkOutcome {
            done: already + queued,
            queued,
            skipped,
            failed,
            vault: self.decrypt_cache().await?,
        })
    }

    /// Gives these items their new titles (`(id, title)`, in this order,
    /// without duplicates): one encrypted edit per item, as a favorite is
    /// (no route renames in bulk), in the queue and then sent by
    /// `sync_shared`. Set aside and counted like the other bulk actions:
    /// read-only, in the trash, gone; an item that already has the title
    /// counts as done; an empty title is refused for that item alone.
    pub async fn bulk_rename(
        &mut self,
        renames: &[(String, String)],
        progress: Progress<'_>,
    ) -> Result<BulkOutcome, Error> {
        let mut ciphers: HashMap<String, _> = self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut seen = HashSet::new();
        let (mut writes, mut already, mut skipped, mut failed) =
            (Vec::new(), 0, Vec::new(), Vec::new());
        for (id, title) in renames {
            let id = self.resolve(id);
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(cipher) = ciphers.remove(&id) else {
                skipped.push((id, Skipped::NotFound));
                continue;
            };
            let mut view = self.decrypt_view(cipher).await?;
            let title = title.trim();
            if !view.edit || view.partial {
                skipped.push((id, Skipped::ReadOnly));
            } else if view.deleted_date.is_some() {
                skipped.push((id, Skipped::InTrash));
            } else if title.is_empty() {
                failed.push(BulkFailure {
                    id,
                    title: view.name.clone(),
                    reason: "the title is required".to_owned(),
                });
            } else if view.name == title {
                already += 1;
            } else {
                title.clone_into(&mut view.name);
                writes.push((id, view));
            }
        }
        let total = writes.len();
        let mut queued = 0;
        for (index, (id, view)) in writes.into_iter().enumerate() {
            let title = view.name.clone();
            match self.encrypt_context(view).await {
                Ok(encrypted) => {
                    self.outbox.push_save(id, title, false, encrypted);
                    queued += 1;
                }
                Err(error) => failed.push(BulkFailure {
                    id,
                    title,
                    reason: error.to_string(),
                }),
            }
            progress(index + 1, total);
        }
        self.persist_outbox()?;
        Ok(BulkOutcome {
            done: already + queued,
            queued,
            skipped,
            failed,
            vault: self.decrypt_cache().await?,
        })
    }

    /// Creates a folder (name encrypted by the SDK); returns its id and the
    /// resynced vault. A folder with the same name is reused.
    pub async fn create_folder(&mut self, name: &str) -> Result<(String, Decrypted), Error> {
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(Error::Invalid("the folder name is required".to_owned()));
        }
        let access = self.require_online("Creating a folder").await?;
        let folders = self
            .ensure_folders(&access, BTreeSet::from([name.clone()]))
            .await?;
        let id = folders
            .get(&name)
            .map(|(id, _)| id.clone())
            .ok_or(Error::NotFound)?;
        Ok((id, self.sync_with(&access).await?))
    }

    /// The items to write (decrypted, from the displayed vault), the number
    /// of those already in the wanted state, and the set-aside ones.
    #[allow(clippy::type_complexity)]
    async fn plan_bulk(
        &self,
        ids: &[String],
        action: &BulkAction,
    ) -> Result<(Vec<(String, CipherView)>, usize, Vec<(String, Skipped)>), Error> {
        let mut ciphers: HashMap<String, _> = self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut seen = HashSet::new();
        let (mut writes, mut already, mut skipped) = (Vec::new(), 0, Vec::new());
        for id in ids {
            let id = self.resolve(id);
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(cipher) = ciphers.remove(&id) else {
                skipped.push((id, Skipped::NotFound));
                continue;
            };
            let view = self.decrypt_view(cipher).await?;
            match fit(&view, action) {
                Fit::Write => writes.push((id, view)),
                Fit::Already => already += 1,
                Fit::Skip(reason) => skipped.push((id, reason)),
            }
        }
        Ok((writes, already, skipped))
    }
}

/// Does the action apply to this item?
fn fit(view: &CipherView, action: &BulkAction) -> Fit {
    if !view.edit || view.partial {
        return Fit::Skip(Skipped::ReadOnly);
    }
    let trashed = view.deleted_date.is_some();
    let archived = view.archived_date.is_some();
    let done = |already: bool| if already { Fit::Already } else { Fit::Write };
    match action {
        BulkAction::Trash => done(trashed),
        BulkAction::Restore => done(!trashed),
        _ if trashed => Fit::Skip(Skipped::InTrash),
        BulkAction::Archive => done(archived),
        BulkAction::Unarchive => done(!archived),
        BulkAction::Favorite(favorite) => done(view.favorite == *favorite),
        BulkAction::MoveToFolder(folder) => done(view.folder_id.map(|f| f.to_string()) == *folder),
    }
}
