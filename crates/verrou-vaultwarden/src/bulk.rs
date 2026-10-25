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

/// Outcome of a bulk action.
pub struct BulkOutcome {
    /// Items handled: queued, or already in the wanted state.
    pub done: usize,
    /// Part of `done` waiting for the server (in the queue).
    pub queued: usize,
    /// Items set aside before anything is sent: (id, reason).
    pub skipped: Vec<(String, Skipped)>,
    /// Refused before anything is sent: (title, reason). The server's
    /// refusals come later, in the upload report (`take_report`).
    pub failed: Vec<(String, String)>,
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
                        Err(error) => failed.push((title, error.to_string())),
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

    /// Creates a folder (name encrypted by the SDK); returns its id and the
    /// resynced vault. A folder with the same name is reused.
    pub async fn create_folder(&mut self, name: &str) -> Result<(String, Decrypted), Error> {
        let name = checked_folder_name(name)?;
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

    /// Renames a folder, and with it every subfolder (`Work/...` follows
    /// `Work`: nesting is only in the names). One request per folder, then
    /// one sync. The items are not rewritten: they point at the folder by
    /// its id. Refused if a folder already has the new name.
    pub async fn rename_folder(&mut self, id: &str, name: &str) -> Result<Decrypted, Error> {
        let name = checked_folder_name(name)?;
        let access = self.require_online("Renaming a folder").await?;
        let folders = self.cached_folders()?;
        let renames = rename_plan(&folders, id, &name)?;
        for (id, name) in &renames {
            let encrypted = self.encrypt_folder_name(name)?;
            self.api.rename_folder(&access, id, &encrypted).await?;
        }
        self.sync_with(&access).await
    }

    /// Deletes a folder, and its subfolders if `include_subfolders`. The
    /// items are kept, outside any folder. Returns the number of items
    /// that were filed there (trash included) and the resynced vault.
    pub async fn delete_folder(
        &mut self,
        id: &str,
        include_subfolders: bool,
    ) -> Result<(u32, Decrypted), Error> {
        let access = self.require_online("Deleting a folder").await?;
        let folders = self.cached_folders()?;
        let doomed = delete_plan(&folders, id, include_subfolders)?;
        let unfiled = self
            .cached_ciphers()?
            .iter()
            .filter(|c| c.folder_id.is_some_and(|f| doomed.contains(&f.to_string())))
            .count();
        for id in &doomed {
            self.api.delete_folder(&access, id).await?;
        }
        let vault = self.sync_with(&access).await?;
        Ok((u32::try_from(unfiled).unwrap_or(u32::MAX), vault))
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

/// The folder name without the surrounding spaces. Nested folders are
/// names with `/` (Bitwarden's convention): every segment must have a
/// name, or the web vault and the other clients draw a broken tree.
fn checked_folder_name(name: &str) -> Result<String, Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Invalid("the folder name is required".to_owned()));
    }
    if name.split('/').any(|segment| segment.trim().is_empty()) {
        return Err(Error::Invalid(format!(
            "\"{name}\" is not a valid folder name: each part between the slashes needs a name"
        )));
    }
    Ok(name.to_owned())
}

/// The folders to rename (`id`, new name) so that `id` becomes `name`
/// and its subfolders follow. Refuses an unknown folder and a new name
/// that is already taken by a folder that stays as it is.
fn rename_plan(
    folders: &HashMap<String, String>,
    id: &str,
    name: &str,
) -> Result<Vec<(String, String)>, Error> {
    let old = folders.get(id).ok_or(Error::NotFound)?;
    if old == name {
        return Ok(Vec::new());
    }
    let prefix = format!("{old}/");
    let mut renames: Vec<(String, String)> = folders
        .iter()
        .filter_map(|(other, other_name)| {
            let new = if other == id {
                name.to_owned()
            } else {
                format!("{name}/{}", other_name.strip_prefix(&prefix)?)
            };
            Some((other.clone(), new))
        })
        .collect();
    renames.sort();
    let moved: HashSet<&str> = renames.iter().map(|(id, _)| id.as_str()).collect();
    for (_, new) in &renames {
        let taken = folders
            .iter()
            .any(|(other, other_name)| !moved.contains(other.as_str()) && other_name == new);
        if taken {
            return Err(Error::Invalid(format!(
                "a folder named \"{new}\" already exists"
            )));
        }
    }
    Ok(renames)
}

/// The ids of the folders to delete: `id`, and its subfolders if asked.
fn delete_plan(
    folders: &HashMap<String, String>,
    id: &str,
    include_subfolders: bool,
) -> Result<Vec<String>, Error> {
    let name = folders.get(id).ok_or(Error::NotFound)?;
    let prefix = format!("{name}/");
    let mut doomed: Vec<String> = folders
        .iter()
        .filter(|(other, other_name)| {
            other.as_str() == id || (include_subfolders && other_name.starts_with(&prefix))
        })
        .map(|(other, _)| other.clone())
        .collect();
    doomed.sort();
    Ok(doomed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> HashMap<String, String> {
        [
            ("1", "Work"),
            ("2", "Work/Clients"),
            ("3", "Home"),
            ("4", "Workshop"),
        ]
        .into_iter()
        .map(|(id, name)| (id.to_owned(), name.to_owned()))
        .collect()
    }

    #[test]
    fn names_need_every_segment() {
        assert_eq!(
            checked_folder_name("  Work/Clients ").unwrap(),
            "Work/Clients"
        );
        for bad in ["", "   ", "a//b", "/a", "a/", "a/ /b"] {
            assert!(
                matches!(checked_folder_name(bad), Err(Error::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rename_carries_the_subfolders_only() {
        let renames = rename_plan(&tree(), "1", "Job").unwrap();
        // "Workshop" shares the prefix text but is not a subfolder.
        assert_eq!(
            renames,
            [
                ("1".into(), "Job".into()),
                ("2".into(), "Job/Clients".into())
            ]
        );
        assert_eq!(rename_plan(&tree(), "1", "Work").unwrap().len(), 0);
        assert!(matches!(
            rename_plan(&tree(), "9", "x"),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn rename_refuses_a_taken_name() {
        let taken = rename_plan(&tree(), "1", "Home");
        assert!(matches!(&taken, Err(Error::Invalid(m)) if m.contains("already exists")));
        // A subfolder landing on an existing folder is refused too.
        let mut folders = tree();
        folders.insert("5".into(), "Job/Clients".into());
        assert!(rename_plan(&folders, "1", "Job").is_err());
        // Renaming a subfolder alone.
        let renames = rename_plan(&tree(), "2", "Work/Accounts").unwrap();
        assert_eq!(renames, [("2".into(), "Work/Accounts".into())]);
    }

    #[test]
    fn delete_with_or_without_subfolders() {
        assert_eq!(delete_plan(&tree(), "1", false).unwrap(), ["1"]);
        assert_eq!(delete_plan(&tree(), "1", true).unwrap(), ["1", "2"]);
        assert!(matches!(
            delete_plan(&tree(), "9", true),
            Err(Error::NotFound)
        ));
    }
}
