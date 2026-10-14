//! Actions groupées : plusieurs éléments sélectionnés dans la liste,
//! archivés, mis à la corbeille, restaurés, ajoutés aux favoris ou rangés
//! dans un dossier d'un coup.
//!
//! Même chemin d'écriture qu'une action seule. Vaultwarden 1.37 a des
//! routes groupées pour la corbeille (`PUT /api/ciphers/delete`), la
//! restauration (`…/restore`), les archives (`…/archive`, `…/unarchive`)
//! et les dossiers (`…/move`) : une requête par lot de 500. Il s'arrête au
//! premier élément refusé : le lot est alors repris un par un, pour savoir
//! lequel. Pas de route pour les favoris : un `PUT /api/ciphers/{id}` par
//! élément, comme pour un seul (date de révision connue, conflit refusé).
//! Une seule synchronisation à la fin, pas une par élément.
//!
//! Hors ligne (ou réseau perdu en route), le reste attend dans la file
//! comme une action seule : corbeille et archives en actions, favoris et
//! dossiers en modifications chiffrées (conflit géré au retour).
//!
//! Les éléments auxquels l'action ne s'applique pas sont écartés avant tout
//! envoi et comptés : lecture seule, dans la corbeille (sauf pour
//! restaurer), disparus. Ceux qui sont déjà dans l'état voulu comptent
//! comme faits, sans requête.

use std::collections::{BTreeSet, HashMap, HashSet};

use bitwarden_vault::CipherView;
use chrono::Utc;

use crate::edit::folder_id;
use crate::import::BATCH;
use crate::outbox::{Action, Change, Entry, request_of, sent_save};
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
}

/// Bilan d'une action groupée.
pub struct BulkOutcome {
    /// Éléments traités : envoyés, en attente hors ligne, ou déjà dans
    /// l'état voulu.
    pub done: usize,
    /// Partie de `done` qui attend le serveur (hors ligne).
    pub queued: usize,
    /// Éléments écartés avant tout envoi : (identifiant, raison).
    pub skipped: Vec<(String, Skipped)>,
    /// Refusés par le serveur : (titre, raison).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// Avancement : (éléments envoyés, éléments à envoyer).
pub type Progress<'a> = &'a (dyn Fn(usize, usize) + Send + Sync);

enum Fit {
    Write,
    Already,
    Skip(Skipped),
}

#[derive(Default)]
struct Run {
    done: usize,
    queued: usize,
    failed: Vec<(String, String)>,
    /// Écritures acceptées : gardées en surimpression si la
    /// synchronisation finale échoue.
    sent: Vec<Entry>,
    /// Le serveur a changé quelque chose (même sans entrée à garder).
    wrote: bool,
}

impl Connection {
    /// Applique `action` à ces éléments (dans cet ordre, sans doublon),
    /// puis synchronise une fois.
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
        let mut access = self.online().await?;
        let (writes, already, skipped) = self.plan_bulk(ids, action).await?;
        let mut run = Run {
            done: already,
            ..Run::default()
        };
        let total = writes.len();
        let result = match action {
            BulkAction::Trash => {
                self.bulk_actions(&mut access, writes, Action::Trash, &mut run, progress)
                    .await
            }
            BulkAction::Restore => {
                self.bulk_actions(&mut access, writes, Action::Restore, &mut run, progress)
                    .await
            }
            BulkAction::Archive => {
                self.bulk_actions(&mut access, writes, Action::Archive, &mut run, progress)
                    .await
            }
            BulkAction::Unarchive => {
                self.bulk_actions(&mut access, writes, Action::Unarchive, &mut run, progress)
                    .await
            }
            BulkAction::Favorite(favorite) => {
                let favorite = *favorite;
                let change = move |view: &mut CipherView| {
                    view.favorite = favorite;
                    Ok(())
                };
                self.bulk_saves(&mut access, writes, &change, &mut run, (0, total), progress)
                    .await
            }
            BulkAction::MoveToFolder(folder) => {
                self.bulk_move(&mut access, writes, folder.clone(), &mut run, progress)
                    .await
            }
        };
        // Ce qui a été mis dans la file reste, même si la suite échoue.
        self.persist_outbox()?;
        result?;
        let vault = match access {
            Some(token) if run.wrote => self.pull_after_writes(&token, run.sent).await?,
            _ => {
                self.keep_sent(run.sent)?;
                self.decrypt_cache().await?
            }
        };
        Ok(BulkOutcome {
            done: run.done,
            queued: run.queued,
            skipped,
            failed: run.failed,
            vault,
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

    /// Corbeille, restauration, archives : par lots, un par un si le
    /// serveur refuse un lot.
    async fn bulk_actions(
        &mut self,
        access: &mut Option<String>,
        writes: Vec<(String, CipherView)>,
        action: Action,
        run: &mut Run,
        progress: Progress<'_>,
    ) -> Result<(), Error> {
        let total = writes.len();
        let mut handled = 0;
        let mut queue: Vec<(String, String)> = Vec::new();
        for chunk in writes.chunks(BATCH) {
            let Some(token) = access.clone() else {
                queue.extend(chunk.iter().map(|(id, v)| (id.clone(), v.name.clone())));
                continue;
            };
            let ids: Vec<String> = chunk.iter().map(|(id, _)| id.clone()).collect();
            match self
                .api
                .bulk_cipher_action(&token, &ids, action.path())
                .await
            {
                Ok(()) => {
                    for (id, view) in chunk {
                        run.sent.push(action_entry(id, &view.name, action));
                    }
                    run.done += chunk.len();
                    run.wrote = true;
                }
                Err(Error::Network(_)) => {
                    self.mark_offline();
                    *access = None;
                    queue.extend(chunk.iter().map(|(id, v)| (id.clone(), v.name.clone())));
                }
                Err(Error::SessionExpired) => return Err(Error::SessionExpired),
                // Un élément refusé (le reste du lot a pu passer) : un par
                // un, pour savoir lequel.
                Err(_) => {
                    run.wrote = true;
                    for (id, view) in chunk {
                        let Some(token) = access.clone() else {
                            queue.push((id.clone(), view.name.clone()));
                            continue;
                        };
                        match self.api.cipher_action(&token, id, action.path()).await {
                            Ok(()) => {
                                run.sent.push(action_entry(id, &view.name, action));
                                run.done += 1;
                            }
                            Err(Error::Network(_)) => {
                                self.mark_offline();
                                *access = None;
                                queue.push((id.clone(), view.name.clone()));
                            }
                            Err(Error::SessionExpired) => return Err(Error::SessionExpired),
                            Err(error) => run.failed.push((view.name.clone(), error.to_string())),
                        }
                    }
                }
            }
            handled += chunk.len();
            progress(handled, total);
        }
        let now = Utc::now();
        for (id, title) in queue {
            self.outbox.push_action(id, title, action, now);
            run.done += 1;
            run.queued += 1;
        }
        Ok(())
    }

    /// Une modification par élément (favoris ; dossiers en repli),
    /// chiffrée comme seule ; hors ligne, dans la file.
    async fn bulk_saves(
        &mut self,
        access: &mut Option<String>,
        writes: Vec<(String, CipherView)>,
        change: &(dyn Fn(&mut CipherView) -> Result<(), Error> + Send + Sync),
        run: &mut Run,
        (offset, total): (usize, usize),
        progress: Progress<'_>,
    ) -> Result<(), Error> {
        for (index, (id, mut view)) in writes.into_iter().enumerate() {
            change(&mut view)?;
            let title = view.name.clone();
            let encrypted = self.encrypt_context(view).await?;
            let sent = match access.clone() {
                Some(token) => {
                    let request = request_of(encrypted.clone())?;
                    Some(self.api.put_cipher(&token, &id, &request).await)
                }
                None => None,
            };
            match sent {
                Some(Ok(body)) => {
                    run.sent.push(sent_save(id, title, encrypted, &body));
                    run.done += 1;
                    run.wrote = true;
                }
                Some(Err(Error::SessionExpired)) => return Err(Error::SessionExpired),
                Some(Err(Error::Network(_))) | None => {
                    if access.is_some() {
                        self.mark_offline();
                        *access = None;
                    }
                    self.outbox.push_save(id, title, false, encrypted);
                    run.done += 1;
                    run.queued += 1;
                }
                Some(Err(error)) => run.failed.push((title, error.to_string())),
            }
            progress(offset + index + 1, total);
        }
        Ok(())
    }

    /// Dossiers : `PUT /api/ciphers/move` par lots. Lot refusé ou serveur
    /// injoignable : la modification de chaque élément, comme seul.
    async fn bulk_move(
        &mut self,
        access: &mut Option<String>,
        writes: Vec<(String, CipherView)>,
        folder: Option<String>,
        run: &mut Run,
        progress: Progress<'_>,
    ) -> Result<(), Error> {
        let total = writes.len();
        let target = folder_id(folder.clone())?;
        let change = move |view: &mut CipherView| {
            view.folder_id = target;
            Ok(())
        };
        let mut rest = Vec::new();
        let mut handled = 0;
        let mut chunks = writes.into_iter().peekable();
        while chunks.peek().is_some() {
            let chunk: Vec<_> = chunks.by_ref().take(BATCH).collect();
            let Some(token) = access.clone() else {
                rest.extend(chunk);
                continue;
            };
            let ids: Vec<String> = chunk.iter().map(|(id, _)| id.clone()).collect();
            match self.api.move_ciphers(&token, &ids, folder.as_deref()).await {
                // Le dossier est propre au compte, l'élément n'est pas
                // réécrit : rien à garder en surimpression (si la
                // synchronisation finale échoue, la suivante le montrera).
                Ok(()) => {
                    run.done += chunk.len();
                    run.wrote = true;
                    handled += chunk.len();
                    progress(handled, total);
                }
                Err(Error::Network(_)) => {
                    self.mark_offline();
                    *access = None;
                    rest.extend(chunk);
                }
                Err(Error::SessionExpired) => return Err(Error::SessionExpired),
                Err(_) => {
                    run.wrote = true;
                    rest.extend(chunk);
                }
            }
        }
        self.bulk_saves(access, rest, &change, run, (handled, total), progress)
            .await
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

fn action_entry(id: &str, title: &str, action: Action) -> Entry {
    Entry {
        id: id.to_owned(),
        title: title.to_owned(),
        change: Change::Action {
            action,
            at: Utc::now(),
        },
        sent: true,
    }
}
