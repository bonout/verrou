//! Actions groupées : plusieurs éléments sélectionnés dans la liste,
//! archivés, mis à la corbeille, restaurés, ajoutés aux favoris ou rangés
//! dans un dossier d'un coup.
//!
//! Même chemin d'écriture qu'une action seule : chaque élément rejoint la
//! file (`outbox`), appliquée tout de suite au coffre affiché, et l'envoi
//! suit en arrière-plan. Il regroupe ce que Vaultwarden 1.37 sait faire en
//! une requête : corbeille (`PUT /api/ciphers/delete`), restauration
//! (`…/restore`), archives (`…/archive`, `…/unarchive`) et dossiers
//! (`…/move`), par lots de 500 ; un lot refusé (Vaultwarden s'arrête au
//! premier élément refusé) est repris un par un, pour savoir lequel. Pas de
//! route pour les favoris : une modification chiffrée par élément, comme
//! pour un seul (date de révision connue, conflit gardé en copie). Une
//! seule synchronisation à la fin, pas une par élément.
//!
//! Les éléments auxquels l'action ne s'applique pas sont écartés avant tout
//! envoi et comptés : lecture seule, dans la corbeille (sauf pour
//! restaurer), disparus. Ceux qui sont déjà dans l'état voulu comptent
//! comme faits, sans requête.

use std::collections::{BTreeSet, HashMap, HashSet};

use bitwarden_vault::CipherView;
use chrono::Utc;

use crate::edit::folder_id;
use crate::outbox::Action;
use crate::{Connection, Decrypted, Error};

/// Ce qu'on fait aux éléments sélectionnés.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkAction {
    Trash,
    Restore,
    Archive,
    Unarchive,
    Favorite(bool),
    /// Range dans ce dossier (`None` : aucun dossier).
    MoveToFolder(Option<String>),
}

/// Pourquoi un élément a été écarté.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skipped {
    /// Partagé en lecture seule (ou visible seulement en partie).
    ReadOnly,
    /// Dans la corbeille : à restaurer d'abord.
    InTrash,
    /// Plus dans le coffre (supprimé ailleurs entre-temps).
    NotFound,
    /// Déjà dans une organisation (partage seulement).
    AlreadyShared,
    /// Pas dans une organisation (retrait du partage seulement).
    NotShared,
    /// L'organisation en masque les mots de passe à ce compte (retrait du
    /// partage seulement : la copie les révélerait).
    PasswordsHidden,
}

/// Bilan d'une action groupée.
pub struct BulkOutcome {
    /// Éléments traités : mis dans la file, ou déjà dans l'état voulu.
    pub done: usize,
    /// Partie de `done` qui attend le serveur (dans la file).
    pub queued: usize,
    /// Éléments écartés avant tout envoi : (identifiant, raison).
    pub skipped: Vec<(String, Skipped)>,
    /// Refusés avant tout envoi : (titre, raison). Les refus du serveur
    /// arrivent plus tard, dans le bilan des envois (`take_report`).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// Avancement : (éléments traités, éléments à traiter).
pub type Progress<'a> = &'a (dyn Fn(usize, usize) + Send + Sync);

enum Fit {
    Write,
    Already,
    Skip(Skipped),
}

impl Connection {
    /// Applique `action` à ces éléments (dans cet ordre, sans doublon) :
    /// dans la file, envoyée ensuite par `sync_shared`.
    pub async fn bulk(
        &mut self,
        ids: &[String],
        action: &BulkAction,
        progress: Progress<'_>,
    ) -> Result<BulkOutcome, Error> {
        if let BulkAction::MoveToFolder(Some(folder)) = action
            && !self.cached_folders()?.contains_key(folder)
        {
            return Err(Error::Invalid("ce dossier n'existe plus".to_owned()));
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

    /// Crée un dossier (nom chiffré par le SDK) ; rend son identifiant et
    /// le coffre resynchronisé. Un dossier du même nom est réutilisé.
    pub async fn create_folder(&mut self, name: &str) -> Result<(String, Decrypted), Error> {
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(Error::Invalid(
                "le nom du dossier est obligatoire".to_owned(),
            ));
        }
        let access = self.require_online("Créer un dossier").await?;
        let folders = self
            .ensure_folders(&access, BTreeSet::from([name.clone()]))
            .await?;
        let id = folders
            .get(&name)
            .map(|(id, _)| id.clone())
            .ok_or(Error::NotFound)?;
        Ok((id, self.sync_with(&access).await?))
    }

    /// Les éléments à écrire (déchiffrés, depuis le coffre affiché), le
    /// nombre de ceux déjà dans l'état voulu, et les écartés.
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

/// L'action s'applique-t-elle à cet élément ?
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
