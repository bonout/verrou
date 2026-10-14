//! Écritures d'éléments : la file d'attente (« outbox ») et son envoi.
//!
//! Toute création, modification, mise à la corbeille, restauration, archive,
//! favori ou rangement dans un dossier passe par cette file, en ligne comme
//! hors ligne : elle s'applique tout de suite au coffre affiché, et
//! l'interface n'attend pas le réseau. L'élément y est gardé **chiffré par
//! le SDK**, exactement comme il partira (même date de révision connue) ; la
//! file entière est en plus chiffrée par la clé de l'utilisateur
//! (`outbox.json`, voir `store`). Rien n'y est en clair.
//!
//! Le coffre affiché est le cache du serveur, auquel la file est
//! superposée (`Outbox::apply`) : verrouiller, relancer l'app ou rouvrir
//! la session ne perd rien.
//!
//! L'envoi suit aussitôt, en arrière-plan (`sync_shared`), puis une
//! synchronisation ; hors ligne, il attend le retour du réseau. Dans
//! l'ordre : d'abord les créations et modifications, puis la corbeille, les
//! archives et les dossiers, par lots (elles changent la date de révision
//! de l'élément sur le serveur : envoyées avant une modification, elles la
//! feraient passer pour périmée). Un élément créé porte un identifiant
//! provisoire, remplacé par celui du serveur.
//!
//! Sans bloquer : une entrée est prise sous le verrou de la connexion
//! (`begin`), envoyée sans le tenir (le réseau peut prendre des secondes, et
//! l'écriture suivante ne doit pas l'attendre), puis le verrou est repris
//! pour noter la réponse (`finish`). Une entrée en cours d'envoi n'est plus
//! fusionnée avec une modification suivante du même élément : celle-ci se
//! place derrière, et repart de la date de révision rendue par le serveur
//! (`Outbox::rebase`) au lieu de passer pour périmée.
//!
//! Conflit : l'élément a changé (ou disparu) sur le serveur entre-temps. Le
//! serveur refuse la modification (date de révision) ; Verrou garde les
//! deux versions : la version locale devient une copie, « titre (conflit
//! hors ligne) », et la version du serveur revient à la synchronisation.
//! Rien n'est perdu sans le dire : une modification que le serveur refuse
//! pour une autre raison (et dont la copie est refusée aussi) est retirée de
//! la file (le coffre affiché revient à la version du serveur) et signalée.
//!
//! Une modification envoyée reste dans la file (`sent`) jusqu'à la
//! synchronisation suivante : si le réseau tombe entre les deux, le coffre
//! affiché la montre toujours.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use bitwarden_api_api::models::{CipherCreateRequestModel, CipherRequestModel};
use bitwarden_vault::{Cipher, EncryptionContext, VaultClientExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::Api;
use crate::import::BATCH;
use crate::store::OutboxFile;
use crate::{Connection, Decrypted, Error};

/// Après une erreur réseau, les envois déclenchés par une écriture
/// attendent ce délai avant de retenter le réseau. La synchronisation
/// (périodique ou ⌘R), elle, réessaie toujours.
const RETRY_AFTER: Duration = Duration::from_secs(20);

/// Suffixe du titre de la copie gardée en cas de conflit.
pub const CONFLICT_SUFFIX: &str = " (conflit hors ligne)";

/// Corbeille, restauration, archives : `PUT /api/ciphers/{id}/{action}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Trash,
    Restore,
    Archive,
    Unarchive,
}

impl Action {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Trash => "delete",
            Self::Restore => "restore",
            Self::Archive => "archive",
            Self::Unarchive => "unarchive",
        }
    }

    fn inverse(self) -> Self {
        match self {
            Self::Trash => Self::Restore,
            Self::Restore => Self::Trash,
            Self::Archive => Self::Unarchive,
            Self::Unarchive => Self::Archive,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Change {
    /// Élément créé ou modifié, chiffré par le SDK tel qu'il partira.
    Save {
        /// Créé : `id` est provisoire, l'envoi est un `POST`.
        created: bool,
        cipher: Box<EncryptionContext>,
        /// Copie gardée après un conflit : refusée à son tour, la
        /// modification est signalée et retirée.
        #[serde(default)]
        conflict: bool,
    },
    Action {
        action: Action,
        at: DateTime<Utc>,
        /// Date de révision rendue par le serveur, une fois envoyée.
        #[serde(default)]
        revision: Option<DateTime<Utc>>,
    },
    /// Rangé dans ce dossier (`None` : aucun), `PUT /api/ciphers/move` : le
    /// dossier est propre au compte, l'élément n'est pas réécrit.
    Move { folder: Option<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Identifiant de l'élément (provisoire pour une création pas encore
    /// envoyée).
    pub id: String,
    /// Titre, pour le bilan de l'envoi (la file entière est chiffrée).
    pub title: String,
    pub change: Change,
    /// Accepté par le serveur, gardé jusqu'à la synchronisation suivante.
    #[serde(default)]
    pub sent: bool,
    /// Numéro d'ordre dans la session (pas enregistré).
    #[serde(skip)]
    seq: u64,
    /// A attendu le serveur (hors ligne, ou depuis une session précédente) :
    /// son envoi est annoncé dans le bilan.
    #[serde(skip)]
    deferred: bool,
}

impl Entry {
    fn new(id: String, title: String, change: Change) -> Self {
        Self {
            id,
            title,
            change,
            sent: false,
            seq: 0,
            deferred: false,
        }
    }

    fn is_save(&self) -> bool {
        matches!(self.change, Change::Save { .. })
    }

    /// Le lot dont l'entrée peut faire partie (corbeille, archives,
    /// dossiers).
    fn batch(&self) -> Option<Batch> {
        match &self.change {
            Change::Save { .. } => None,
            Change::Action { action, .. } => Some(Batch::Action(*action)),
            Change::Move { folder } => Some(Batch::Move(folder.clone())),
        }
    }
}

/// Ce qui part en une requête groupée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Batch {
    Action(Action),
    Move(Option<String>),
}

/// La file, dans l'ordre des modifications.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Outbox {
    entries: Vec<Entry>,
    /// Prochain numéro d'ordre.
    #[serde(skip)]
    next: u64,
    /// Entrées en cours d'envoi : ni fusionnées, ni annulées, ni reprises.
    #[serde(skip)]
    in_flight: HashSet<u64>,
    /// Entrées d'un lot refusé : renvoyées une à une, pour savoir laquelle.
    #[serde(skip)]
    singles: HashSet<u64>,
}

impl Outbox {
    fn unsent(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| !e.sent)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_unsent(&self) -> bool {
        self.unsent().next().is_some()
    }

    /// Modifications pas encore acceptées par le serveur.
    pub fn pending_changes(&self) -> usize {
        self.unsent().count()
    }

    /// Éléments qui attendent le serveur, sans doublon.
    pub fn pending_items(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.unsent()
            .filter(|e| seen.insert(e.id.as_str()))
            .map(|e| e.id.clone())
            .collect()
    }

    /// Numérote une file relue du disque : tout ce qu'elle contient a
    /// attendu le serveur.
    fn renumber(&mut self) {
        for entry in &mut self.entries {
            entry.seq = self.next;
            entry.deferred = !entry.sent;
            self.next += 1;
        }
    }

    fn push(&mut self, mut entry: Entry) {
        entry.seq = self.next;
        self.next += 1;
        self.entries.push(entry);
    }

    fn position(&self, seq: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.seq == seq)
    }

    /// Peut encore être fusionnée ou annulée : ni envoyée, ni en cours.
    fn is_open(&self, entry: &Entry) -> bool {
        !entry.sent && !self.in_flight.contains(&entry.seq)
    }

    /// Ajoute une création ou une modification. Une seule modification par
    /// élément attend : la nouvelle remplace la précédente (elle en part,
    /// puisqu'elle est faite sur le coffre affiché), et une création reste
    /// une création. Celle qui est en cours d'envoi n'est pas touchée.
    pub fn push_save(
        &mut self,
        id: String,
        title: String,
        created: bool,
        cipher: EncryptionContext,
    ) {
        let previous = self
            .entries
            .iter()
            .position(|e| e.id == id && e.is_save() && self.is_open(e));
        if let Some(index) = previous {
            let entry = &mut self.entries[index];
            let was_created = matches!(entry.change, Change::Save { created: true, .. });
            entry.title = title;
            entry.change = Change::Save {
                created: created || was_created,
                cipher: Box::new(cipher),
                conflict: false,
            };
            return;
        }
        self.push(Entry::new(
            id,
            title,
            Change::Save {
                created,
                cipher: Box::new(cipher),
                conflict: false,
            },
        ));
    }

    /// Ajoute une action. Celle qui défait la précédente action en attente
    /// sur l'élément (restaurer ce qu'on vient de mettre à la corbeille,
    /// sortir des archives) l'annule simplement, si elle n'est pas déjà
    /// partie.
    pub fn push_action(&mut self, id: String, title: String, action: Action, at: DateTime<Utc>) {
        let last = self
            .entries
            .iter()
            .rposition(|e| !e.sent && e.id == id && matches!(e.change, Change::Action { .. }));
        if let Some(index) = last
            && self.is_open(&self.entries[index])
            && matches!(self.entries[index].change, Change::Action { action: a, .. } if a == action.inverse())
        {
            self.entries.remove(index);
            return;
        }
        self.push(Entry::new(
            id,
            title,
            Change::Action {
                action,
                at,
                revision: None,
            },
        ));
    }

    /// Range l'élément dans un dossier ; un rangement en attente du même
    /// élément est remplacé.
    pub fn push_move(&mut self, id: String, title: String, folder: Option<String>) {
        let previous = self
            .entries
            .iter()
            .position(|e| e.id == id && matches!(e.change, Change::Move { .. }) && self.is_open(e));
        if let Some(index) = previous {
            self.entries[index].change = Change::Move { folder };
            return;
        }
        self.push(Entry::new(id, title, Change::Move { folder }));
    }

    /// Superpose la file aux éléments du cache : remplace (ou ajoute) les
    /// éléments modifiés (ou créés), date la corbeille et les archives,
    /// range dans les dossiers.
    pub fn apply(&self, ciphers: &mut Vec<Cipher>) {
        let mut positions: HashMap<_, usize> = ciphers
            .iter()
            .enumerate()
            .filter_map(|(index, c)| Some((c.id?, index)))
            .collect();
        for entry in &self.entries {
            let Ok(id) = entry.id.parse() else { continue };
            match &entry.change {
                Change::Save { cipher, .. } => {
                    let mut cipher = cipher.cipher.clone();
                    cipher.id = Some(id);
                    if let Some(&index) = positions.get(&id) {
                        ciphers[index] = cipher;
                    } else {
                        positions.insert(id, ciphers.len());
                        ciphers.push(cipher);
                    }
                }
                Change::Action {
                    action,
                    at,
                    revision,
                } => {
                    let Some(cipher) = positions.get(&id).map(|&index| &mut ciphers[index]) else {
                        continue;
                    };
                    match action {
                        Action::Trash => cipher.deleted_date = Some(*at),
                        Action::Restore => cipher.deleted_date = None,
                        Action::Archive => cipher.archived_date = Some(*at),
                        Action::Unarchive => cipher.archived_date = None,
                    }
                    if let Some(revision) = revision {
                        cipher.revision_date = *revision;
                    }
                }
                Change::Move { folder } => {
                    let Some(cipher) = positions.get(&id).map(|&index| &mut ciphers[index]) else {
                        continue;
                    };
                    cipher.folder_id = folder.as_deref().and_then(|f| f.parse().ok());
                }
            }
        }
    }

    /// Identifiant provisoire remplacé par celui du serveur.
    fn remap(&mut self, from: &str, to: &str) {
        let parsed = to.parse().ok();
        for entry in self.entries.iter_mut().filter(|e| e.id == from) {
            to.clone_into(&mut entry.id);
            if let Change::Save { cipher, .. } = &mut entry.change {
                cipher.cipher.id = parsed;
            }
        }
    }

    /// Le serveur a donné une nouvelle date de révision à l'élément (par
    /// une écriture de Verrou) : les modifications qui attendent derrière
    /// en repartent. Elles ont été faites sur le coffre affiché, qui montrait
    /// déjà cette écriture.
    fn rebase(&mut self, id: &str, revision: DateTime<Utc>) {
        let in_flight = &self.in_flight;
        for entry in self
            .entries
            .iter_mut()
            .filter(|e| !e.sent && e.id == id && !in_flight.contains(&e.seq))
        {
            if let Change::Save { cipher, .. } = &mut entry.change {
                cipher.cipher.revision_date = revision;
            }
        }
    }

    /// Le réseau manque : ce qui attend sera annoncé une fois parti.
    fn mark_deferred(&mut self) {
        for entry in self.entries.iter_mut().filter(|e| !e.sent) {
            entry.deferred = true;
        }
    }

    /// Oublie ce que le serveur a accepté : la synchronisation qui vient
    /// d'arriver le contient. Rend `true` si la file a changé.
    pub fn purge_sent(&mut self) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !e.sent);
        self.entries.len() != before
    }

    /// La prochaine requête, marquée en cours d'envoi : créations et
    /// modifications d'abord, dans l'ordre, puis corbeille, archives et
    /// dossiers, par lots. `None` : rien à envoyer, ou un envoi déjà en
    /// cours. Une modification que le SDK ne sait pas mettre en requête est
    /// retirée et signalée dans `rejected`.
    fn begin(&mut self, rejected: &mut Vec<(String, String)>) -> Option<Job> {
        if !self.in_flight.is_empty() {
            return None;
        }
        loop {
            let Some(entry) = self.entries.iter().find(|e| !e.sent && e.is_save()) else {
                return self.begin_batch();
            };
            let Change::Save {
                created, cipher, ..
            } = &entry.change
            else {
                unreachable!("une modification");
            };
            let (seq, id, created) = (entry.seq, entry.id.clone(), *created);
            let collections = cipher.cipher.organization_id.map(|_| {
                cipher
                    .cipher
                    .collection_ids
                    .iter()
                    .map(|c| (*c).into())
                    .collect()
            });
            match request_of((**cipher).clone()) {
                Ok(request) => {
                    self.in_flight.insert(seq);
                    return Some(Job::Save {
                        seq,
                        id,
                        created,
                        request: Box::new(request),
                        collections,
                    });
                }
                Err(error) => {
                    let index = self.position(seq).expect("l'entrée vient d'être lue");
                    let entry = self.entries.remove(index);
                    rejected.push((entry.title, error.to_string()));
                }
            }
        }
    }

    /// Le prochain lot d'actions (ou de rangements) du même genre, dans
    /// l'ordre. Un élément dont une action d'un autre genre attend avant
    /// n'en fait pas partie : chaque élément garde l'ordre de ses actions.
    fn begin_batch(&mut self) -> Option<Job> {
        let mut candidates = self.entries.iter().filter(|e| !e.sent && !e.is_save());
        let first = candidates.next()?;
        let batch = first.batch()?;
        let mut entries = vec![(first.seq, first.id.clone())];
        if !self.singles.contains(&first.seq) {
            let mut taken: HashSet<&str> = HashSet::from([first.id.as_str()]);
            let mut blocked: HashSet<&str> = HashSet::new();
            for entry in candidates {
                if entries.len() >= BATCH {
                    break;
                }
                let fits = entry.batch().as_ref() == Some(&batch)
                    && !self.singles.contains(&entry.seq)
                    && !blocked.contains(entry.id.as_str())
                    && !taken.contains(entry.id.as_str());
                if fits {
                    taken.insert(&entry.id);
                    entries.push((entry.seq, entry.id.clone()));
                } else {
                    blocked.insert(&entry.id);
                }
            }
        }
        self.in_flight.extend(entries.iter().map(|(seq, _)| *seq));
        Some(Job::Batch { batch, entries })
    }
}

/// Une requête à envoyer, préparée sous le verrou de la connexion et
/// envoyée sans lui (`Job::send`).
pub(crate) enum Job {
    Save {
        seq: u64,
        id: String,
        created: bool,
        request: Box<CipherRequestModel>,
        /// Création dans un coffre partagé : ses collections.
        collections: Option<Vec<uuid::Uuid>>,
    },
    Batch {
        batch: Batch,
        /// (numéro d'ordre, élément).
        entries: Vec<(u64, String)>,
    },
}

impl Job {
    /// L'envoi lui-même : seulement le réseau, aucun état partagé.
    pub(crate) async fn send(&self, api: &Api, access: &str) -> Result<Value, Error> {
        match self {
            Self::Save {
                created: true,
                request,
                collections: None,
                ..
            } => api.post_cipher(access, request).await,
            Self::Save {
                created: true,
                request,
                collections: Some(collections),
                ..
            } => {
                let mut create = CipherCreateRequestModel::new((**request).clone());
                create.collection_ids = Some(collections.clone());
                api.send_json(
                    reqwest::Method::POST,
                    "/api/ciphers/create",
                    access,
                    &create,
                )
                .await
            }
            Self::Save { id, request, .. } => api.put_cipher(access, id, request).await,
            Self::Batch { batch, entries } => {
                let ids: Vec<String> = entries.iter().map(|(_, id)| id.clone()).collect();
                match batch {
                    Batch::Action(action) if ids.len() == 1 => {
                        api.cipher_action(access, &ids[0], action.path()).await
                    }
                    Batch::Action(action) => {
                        api.bulk_cipher_action(access, &ids, action.path()).await
                    }
                    Batch::Move(folder) => api
                        .move_ciphers(access, &ids, folder.as_deref())
                        .await
                        .map(|()| Value::Null),
                }
            }
        }
    }
}

/// Bilan de l'envoi des modifications, depuis le dernier bilan lu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Modifications qui avaient attendu le serveur (hors ligne) et qu'il
    /// vient d'accepter.
    pub sent: usize,
    /// Éléments modifiés (ou supprimés) ailleurs entre-temps : titre de la
    /// copie qui garde la version locale.
    pub conflicts: Vec<String>,
    /// Modifications refusées par le serveur, retirées de la file (le
    /// coffre affiché revient à la version du serveur) : (titre, raison).
    pub rejected: Vec<(String, String)>,
    /// Éléments créés : (identifiant provisoire, identifiant du serveur).
    pub remapped: Vec<(String, String)>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Coordination des envois d'une connexion, partagée hors de son verrou.
#[derive(Default)]
pub(crate) struct Courier {
    /// Un seul envoi (et synchronisation) à la fois.
    gate: tokio::sync::Mutex<()>,
    /// Demandes de synchronisation reçues, et la dernière servie : une
    /// demande arrivée pendant un envoi est servie par le suivant, qui sert
    /// aussi toutes celles arrivées entre-temps.
    requested: AtomicU64,
    served: AtomicU64,
    /// Échec du dernier envoi, rendu aux demandes qu'il a servies.
    failure: std::sync::Mutex<Option<Error>>,
    /// Coffre verrouillé : l'envoi s'arrête après la requête en cours (la
    /// file attend le prochain déverrouillage).
    stopped: AtomicBool,
    /// Compte déconnecté : plus rien n'est écrit sur le disque.
    closed: AtomicBool,
}

impl Courier {
    fn halted(&self) -> bool {
        self.stopped.load(Ordering::SeqCst) || self.closed.load(Ordering::SeqCst)
    }
}

/// Arrête l'envoi en cours d'une connexion qu'on lâche, même s'il la garde
/// en vie le temps d'une requête.
#[derive(Clone)]
pub struct Closer(Arc<Courier>);

impl Closer {
    /// Verrouillage : l'envoi s'arrête après la requête en cours.
    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    /// Déconnexion : l'envoi s'arrête, et plus rien n'est écrit sur le
    /// disque (la file effacée ne revient pas).
    pub fn close(&self) {
        self.stop();
        self.0.closed.store(true, Ordering::SeqCst);
    }
}

/// Ce qu'a donné une synchronisation partagée.
pub enum Synced {
    /// Le coffre a changé : le voici, déchiffré.
    Changed(Decrypted),
    /// Rien de nouveau depuis le coffre affiché.
    Unchanged,
    /// Servie par l'envoi d'une autre demande, qui a rendu le coffre.
    Joined,
}

/// La file enregistrée pour ce compte, déchiffrée par la clé de
/// l'utilisateur. Celle d'un autre compte (ou illisible : clé changée) est
/// supprimée.
pub(crate) fn load(store: &crate::Store, user_id: &str, sdk: &bitwarden_core::Client) -> Outbox {
    let Ok(Some(file)) = store.load_outbox() else {
        return Outbox::default();
    };
    if file.user_id != user_id {
        let _ = store.delete_outbox();
        return Outbox::default();
    }
    let outbox = sdk
        .crypto()
        .decrypt_with_local_user_data_key(file.data)
        .ok()
        .and_then(|json| serde_json::from_str::<Outbox>(&json).ok());
    let Some(mut outbox) = outbox else {
        // Chiffrée par une autre clé (mot de passe changé avec rotation de
        // la clé) : illisible pour toujours, et son compteur tromperait.
        let _ = store.delete_outbox();
        return Outbox::default();
    };
    outbox.renumber();
    outbox
}

/// Envoie la file puis synchronise, sans tenir la connexion pendant le
/// réseau : les écritures locales (`create`, `update`…) passent pendant ce
/// temps. Les demandes simultanées sont regroupées : un envoi en cours, et
/// un seul après lui pour toutes celles arrivées entre-temps.
///
/// `patient` : déclenché par une écriture ; si le serveur était injoignable
/// il y a peu, ne pas retenter tout de suite (la synchronisation périodique
/// s'en charge).
pub async fn sync_shared(
    connection: &Arc<tokio::sync::Mutex<Connection>>,
    patient: bool,
) -> Result<Synced, Error> {
    let connection = Arc::clone(connection);
    let courier = Arc::clone(&connection.lock().await.courier);
    let ticket = courier.requested.fetch_add(1, Ordering::SeqCst) + 1;
    // Dans une tâche à part : cesser d'attendre (tâche de l'app annulée)
    // n'interrompt pas un envoi à mi-chemin, qui laisserait une entrée
    // marquée « en cours » pour toujours.
    let run = tokio::spawn(async move {
        let _gate = courier.gate.lock().await;
        if courier.served.load(Ordering::SeqCst) >= ticket {
            let failure = courier
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            return failure.map_or(Ok(Synced::Joined), Err);
        }
        let start = courier.requested.load(Ordering::SeqCst);
        let result = drain(&connection, &courier, patient).await;
        *courier
            .failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = result.as_ref().err().cloned();
        courier.served.store(start, Ordering::SeqCst);
        result
    });
    run.await
        .map_err(|e| Error::Storage(format!("envoi interrompu ({e})")))?
}

/// Un envoi, porte tenue (`Courier::gate`).
async fn drain(
    connection: &tokio::sync::Mutex<Connection>,
    courier: &Courier,
    patient: bool,
) -> Result<Synced, Error> {
    if courier.halted() {
        return Ok(Synced::Unchanged);
    }
    let (api, refresh) = {
        let open = connection.lock().await;
        if patient && open.offline_at.is_some_and(|at| at.elapsed() < RETRY_AFTER) {
            return Err(Error::Network("serveur injoignable il y a peu".to_owned()));
        }
        (open.api.clone(), open.refresh_token()?)
    };
    let tokens = api.refresh(refresh.expose()).await;
    let access = {
        let mut open = connection.lock().await;
        match tokens {
            Ok(tokens) => {
                open.offline_at = None;
                open.keep_refresh_token(&refresh, tokens.refresh)?;
                tokens.access
            }
            Err(error) => return Err(open.network_failure(error)),
        }
    };
    let mut wrote = false;
    loop {
        if courier.halted() {
            return Ok(Synced::Unchanged);
        }
        let Some(job) = connection.lock().await.begin() else {
            break;
        };
        wrote = true;
        let result = job.send(&api, &access).await;
        connection.lock().await.finish(job, result).await?;
    }
    if courier.halted() {
        return Ok(Synced::Unchanged);
    }
    let generation = connection.lock().await.generation;
    let sync = api.sync(&access).await;
    let snapshot = {
        let mut open = connection.lock().await;
        let json = match sync {
            Ok(json) => json,
            Err(error) => return Err(open.network_failure(error)),
        };
        let had_outbox = !open.outbox.is_empty();
        // Une autre synchronisation, plus récente, a été enregistrée
        // pendant le téléchargement : la garder.
        let unchanged = open.generation == generation && open.store_sync(json)?;
        if unchanged && !wrote && !had_outbox {
            return Ok(Synced::Unchanged);
        }
        open.snapshot()
    };
    // Le déchiffrement du coffre entier, hors du verrou.
    snapshot.decrypt_cache().await.map(Synced::Changed)
}

impl Connection {
    /// Modifications pas encore acceptées par le serveur.
    pub fn pending_changes(&self) -> usize {
        self.outbox.pending_changes()
    }

    /// Le bilan des envois depuis le dernier appel.
    pub fn take_report(&mut self) -> SyncReport {
        std::mem::take(&mut self.report)
    }

    /// Pour arrêter les écritures sur le disque à la déconnexion.
    pub fn closer(&self) -> Closer {
        Closer(Arc::clone(&self.courier))
    }

    /// Identifiant actuel d'un élément : celui du serveur pour un élément
    /// créé et envoyé depuis.
    pub fn resolve(&self, id: &str) -> String {
        self.remapped
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned())
    }

    /// Enregistre la file (chiffrée), ou la supprime si elle est vide.
    pub(crate) fn persist_outbox(&mut self) -> Result<(), Error> {
        self.version += 1;
        if self.courier.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.outbox.is_empty() {
            return self.store.save_outbox(None);
        }
        let json = serde_json::to_string(&self.outbox).map_err(Error::storage)?;
        let data = self
            .sdk
            .crypto()
            .encrypt_with_local_user_data_key(json)
            .map_err(Error::crypto)?;
        self.store.save_outbox(Some(OutboxFile {
            version: 0,
            user_id: self.account.user_id.clone(),
            pending: u32::try_from(self.outbox.pending_changes()).unwrap_or(u32::MAX),
            data,
        }))
    }

    pub(crate) fn mark_offline(&mut self) {
        self.offline_at = Some(Instant::now());
        self.outbox.mark_deferred();
    }

    /// Une erreur d'envoi : le réseau manque (noté, la file attend), ou
    /// autre chose.
    fn network_failure(&mut self, error: Error) -> Error {
        if matches!(error, Error::Network(_)) {
            self.mark_offline();
            let _ = self.persist_outbox();
        }
        error
    }

    /// Un jeton d'accès si le serveur répond, après avoir envoyé la file
    /// (et resynchronisé, pour repartir des dates de révision du serveur) ;
    /// `None` hors ligne. Pour ce qui ne passe pas par la file (pièces
    /// jointes, partage, import, compteur des passkeys).
    pub(crate) async fn online(&mut self) -> Result<Option<String>, Error> {
        if self.offline_at.is_some_and(|at| at.elapsed() < RETRY_AFTER) {
            return Ok(None);
        }
        let access = match self.access_token().await {
            Ok(access) => access,
            Err(Error::Network(_)) => {
                self.mark_offline();
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.offline_at = None;
        if self.outbox.has_unsent() {
            if !self.replay(&access).await? {
                // Un envoi est en cours (`sync_shared`) : il s'occupe de la
                // file, l'écriture directe passe à côté.
                return Ok(Some(access));
            }
            if self.outbox.has_unsent() {
                return Ok(None);
            }
            match self.api.sync(&access).await {
                Ok(json) => {
                    self.store_sync(json)?;
                }
                Err(Error::Network(_)) => {
                    self.mark_offline();
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Some(access))
    }

    /// Pour ce qui n'a de sens qu'avec le serveur (pièces jointes, partage,
    /// import…) : la file envoyée, un jeton d'accès, ou un refus clair.
    pub(crate) async fn require_online(&mut self, what: &str) -> Result<String, Error> {
        // Une action explicite : on réessaie le réseau sans attendre.
        self.offline_at = None;
        self.online()
            .await?
            .ok_or_else(|| Error::Invalid(offline_refusal(what)))
    }

    /// Chiffre `view` et le met dans la file (`id` : modification, sinon
    /// création, sous un identifiant provisoire) : appliqué tout de suite
    /// au coffre affiché, envoyé par `sync_shared`. Rend l'identifiant et le
    /// coffre.
    pub(crate) async fn queue_save(
        &mut self,
        id: Option<&str>,
        view: bitwarden_vault::CipherView,
    ) -> Result<(String, Decrypted), Error> {
        let title = view.name.clone();
        // Sur le tas : chiffrer puis déchiffrer le coffre, c'est plus de
        // 20 Ko de tâche.
        let encrypted = Box::pin(self.encrypt_context(view)).await?;
        let (id, created) = match id {
            Some(id) => (id.to_owned(), false),
            None => (uuid::Uuid::new_v4().to_string(), true),
        };
        self.outbox.push_save(id.clone(), title, created, encrypted);
        self.persist_outbox()?;
        Ok((id, Box::pin(self.decrypt_cache()).await?))
    }

    /// Corbeille, restauration ou archives, dans la file.
    pub(crate) async fn queue_action(
        &mut self,
        id: &str,
        title: String,
        action: Action,
    ) -> Result<Decrypted, Error> {
        self.outbox
            .push_action(id.to_owned(), title, action, Utc::now());
        self.persist_outbox()?;
        Box::pin(self.decrypt_cache()).await
    }

    /// Chiffre `view` puis l'envoie tout de suite si `access` (et
    /// resynchronise) ; sinon dans la file. Pour ce qui doit être sur le
    /// serveur avant de répondre (compteur d'une passkey).
    pub(crate) async fn save_cipher(
        &mut self,
        id: Option<&str>,
        view: bitwarden_vault::CipherView,
        access: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        let Some(access) = access else {
            return self.queue_save(id, view).await;
        };
        let title = view.name.clone();
        let encrypted = Box::pin(self.encrypt_context(view)).await?;
        let request = request_of(encrypted.clone())?;
        let sent = match id {
            Some(id) => self.api.put_cipher(&access, id, &request).await,
            None => self.api.post_cipher(&access, &request).await,
        };
        let body = match sent {
            Ok(body) => body,
            Err(Error::Network(_)) => {
                self.mark_offline();
                let (id, created) = match id {
                    Some(id) => (id.to_owned(), false),
                    None => (uuid::Uuid::new_v4().to_string(), true),
                };
                self.outbox.push_save(id.clone(), title, created, encrypted);
                self.persist_outbox()?;
                return Ok((id, Box::pin(self.decrypt_cache()).await?));
            }
            Err(error) => return Err(error),
        };
        let id = match id {
            Some(id) => id.to_owned(),
            None => body_id(&body)?,
        };
        let entry = sent_save(id.clone(), title, encrypted, &body);
        let vault = Box::pin(self.pull_after_write(&access, entry)).await?;
        Ok((id, vault))
    }

    /// Après une écriture directe acceptée : resynchronise. Si le réseau
    /// tombe juste avant, l'écriture reste visible (envoyée, dans la file)
    /// jusqu'à la synchronisation suivante.
    async fn pull_after_write(&mut self, access: &str, entry: Entry) -> Result<Decrypted, Error> {
        match self.sync_with(access).await {
            Err(Error::Network(_)) => {
                self.mark_offline();
                self.outbox.push(entry);
                self.persist_outbox()?;
                self.decrypt_cache().await
            }
            other => other,
        }
    }

    /// Titre d'un élément du coffre affiché (pour le bilan des envois).
    pub(crate) async fn cached_title(&self, id: &str) -> Result<String, Error> {
        let cipher = self.cached_cipher(id)?;
        Ok(self.decrypt_view(cipher).await?.name)
    }

    pub(crate) async fn encrypt_context(
        &self,
        view: bitwarden_vault::CipherView,
    ) -> Result<EncryptionContext, Error> {
        // Sur le tas : la tâche du SDK est volumineuse (plus de 20 Ko).
        Box::pin(self.sdk.vault().ciphers().encrypt(view))
            .await
            .map_err(Error::crypto)
    }

    /// Envoie la file sous le verrou de la connexion (avant une écriture
    /// directe). Rend `false` sans rien faire si un envoi partagé est en
    /// cours. S'arrête sans erreur au premier problème de réseau (la suite
    /// attend) ; une session expirée interrompt tout.
    pub(crate) async fn replay(&mut self, access: &str) -> Result<bool, Error> {
        let courier = Arc::clone(&self.courier);
        let Ok(_gate) = courier.gate.try_lock() else {
            return Ok(false);
        };
        while let Some(job) = self.begin() {
            let result = job.send(&self.api, access).await;
            match self.finish(job, result).await {
                Ok(()) => {}
                Err(Error::Network(_)) => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    /// La prochaine requête de la file (voir `Outbox::begin`).
    pub(crate) fn begin(&mut self) -> Option<Job> {
        self.outbox.begin(&mut self.report.rejected)
    }

    /// Note la réponse du serveur à `job`, et enregistre la file. `Err` :
    /// l'envoi s'arrête (réseau perdu, session expirée), le reste attend.
    pub(crate) async fn finish(
        &mut self,
        job: Job,
        result: Result<Value, Error>,
    ) -> Result<(), Error> {
        self.outbox.in_flight.clear();
        match result {
            Err(Error::Network(message)) => {
                self.mark_offline();
                self.persist_outbox()?;
                return Err(Error::Network(message));
            }
            Err(Error::SessionExpired) => {
                self.persist_outbox()?;
                return Err(Error::SessionExpired);
            }
            result => match job {
                Job::Save { seq, .. } => self.finish_save(seq, result).await,
                Job::Batch { entries, .. } => self.finish_batch(&entries, result),
            },
        }
        self.persist_outbox()
    }

    async fn finish_save(&mut self, seq: u64, result: Result<Value, Error>) {
        let Some(index) = self.outbox.position(seq) else {
            return;
        };
        let entry = self.outbox.entries[index].clone();
        let Change::Save {
            created,
            cipher,
            conflict,
        } = entry.change
        else {
            return;
        };
        let result = result.and_then(|body| {
            let id = if created {
                body_id(&body)?
            } else {
                entry.id.clone()
            };
            Ok((id, body))
        });
        match result {
            Ok((id, body)) => {
                if created {
                    self.outbox.remap(&entry.id, &id);
                    self.remapped.insert(entry.id.clone(), id.clone());
                    self.report.remapped.push((entry.id.clone(), id.clone()));
                }
                if conflict {
                    self.report.conflicts.push(entry.title.clone());
                }
                if entry.deferred {
                    self.report.sent += 1;
                }
                let mut sent = sent_save(id.clone(), entry.title, *cipher, &body);
                sent.seq = seq;
                let revision = match &sent.change {
                    Change::Save { cipher, .. } => cipher.cipher.revision_date,
                    _ => unreachable!("une modification"),
                };
                self.outbox.entries[index] = sent;
                self.outbox.rebase(&id, revision);
            }
            // Modifié, supprimé ou devenu inaccessible entre-temps : la
            // version locale devient une copie.
            Err(error) if !created && !conflict => {
                if let Ok((title, copy)) = self.conflict_copy(&cipher).await {
                    let entry = &mut self.outbox.entries[index];
                    entry.id = uuid::Uuid::new_v4().to_string();
                    entry.title = title;
                    entry.change = Change::Save {
                        created: true,
                        cipher: Box::new(copy),
                        conflict: true,
                    };
                } else {
                    self.outbox.entries.remove(index);
                    self.report.rejected.push((entry.title, error.to_string()));
                }
            }
            Err(error) => {
                self.outbox.entries.remove(index);
                // Une copie refusée à son tour : le titre de l'original.
                let title = match entry.title.strip_suffix(CONFLICT_SUFFIX) {
                    Some(original) if conflict => original.to_owned(),
                    _ => entry.title,
                };
                self.report.rejected.push((title, error.to_string()));
            }
        }
    }

    fn finish_batch(&mut self, entries: &[(u64, String)], result: Result<Value, Error>) {
        match result {
            Ok(body) => {
                let revisions = revisions(&body, entries);
                for (seq, id) in entries {
                    let Some(index) = self.outbox.position(*seq) else {
                        continue;
                    };
                    let entry = &mut self.outbox.entries[index];
                    entry.sent = true;
                    if entry.deferred {
                        self.report.sent += 1;
                    }
                    let known = revisions.get(id.as_str()).copied();
                    if let Change::Action { revision, .. } = &mut entry.change {
                        *revision = known;
                    }
                    if let Some(known) = known {
                        self.outbox.rebase(id, known);
                    }
                }
            }
            // Vaultwarden s'arrête au premier élément refusé (ceux d'avant
            // restent faits) : un par un, pour savoir lequel.
            Err(_) if entries.len() > 1 => {
                self.outbox
                    .singles
                    .extend(entries.iter().map(|(seq, _)| *seq));
            }
            Err(error) => {
                let Some(&(seq, _)) = entries.first() else {
                    return;
                };
                self.outbox.singles.remove(&seq);
                let Some(index) = self.outbox.position(seq) else {
                    return;
                };
                let entry = self.outbox.entries.remove(index);
                // L'élément n'existe plus : rien à mettre à la corbeille.
                let gone = matches!(&error, Error::NotFound)
                    || matches!(&error, Error::Server(m) if m.contains("doesn't exist"));
                if !gone {
                    self.report.rejected.push((entry.title, error.to_string()));
                }
            }
        }
    }

    /// La version locale d'un élément que le serveur refuse de remplacer,
    /// en copie à créer : « titre (conflit hors ligne) », au même endroit
    /// (coffre personnel, ou mêmes collections), sans ses pièces jointes,
    /// qui restent sur l'original.
    async fn conflict_copy(
        &self,
        cipher: &EncryptionContext,
    ) -> Result<(String, EncryptionContext), Error> {
        let mut view = self.decrypt_view(cipher.cipher.clone()).await?;
        view.id = None;
        view.name = format!("{}{CONFLICT_SUFFIX}", view.name);
        view.attachments = None;
        view.attachment_decryption_failures = None;
        let title = view.name.clone();
        Ok((title, self.encrypt_context(view).await?))
    }
}

/// Dates de révision rendues par une action : l'élément (`PUT
/// …/{id}/{action}`), ou la liste (`{ "data": […] }`) d'une action groupée.
fn revisions<'a>(body: &Value, entries: &'a [(u64, String)]) -> HashMap<&'a str, DateTime<Utc>> {
    let date = |item: &Value| {
        item.get("revisionDate")
            .and_then(Value::as_str)
            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&Utc))
    };
    let items: Vec<&Value> = match body.get("data").and_then(Value::as_array) {
        Some(list) => list.iter().collect(),
        None => vec![body],
    };
    let mut found = HashMap::new();
    for item in items {
        let Some(revision) = date(item) else { continue };
        let id = item.get("id").and_then(Value::as_str);
        let entry = match id {
            Some(id) => entries.iter().find(|(_, e)| e == id),
            // Un seul élément : la réponse est la sienne.
            None if entries.len() == 1 => entries.first(),
            None => None,
        };
        if let Some((_, id)) = entry {
            found.insert(id.as_str(), revision);
        }
    }
    found
}

/// Le message d'une action impossible hors ligne.
pub(crate) fn offline_refusal(what: &str) -> String {
    format!("{what} n'est pas possible hors ligne : réessayez quand le serveur sera joignable")
}

/// La requête d'API d'un élément chiffré par le SDK.
pub(crate) fn request_of(encrypted: EncryptionContext) -> Result<CipherRequestModel, Error> {
    let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
    request.encrypted_for = Some(encrypted.encrypted_for.into());
    request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
    Ok(request)
}

fn body_id(body: &Value) -> Result<String, Error> {
    body.get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Server("élément créé sans identifiant".to_owned()))
}

/// Une modification acceptée : l'élément porte désormais l'identifiant et
/// la date de révision du serveur (une modification suivante, faite avant
/// la synchronisation, ne passera pas pour périmée).
pub(crate) fn sent_save(
    id: String,
    title: String,
    mut cipher: EncryptionContext,
    body: &Value,
) -> Entry {
    cipher.cipher.id = id.parse().ok();
    if let Some(revision) = body
        .get("revisionDate")
        .and_then(Value::as_str)
        .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
    {
        cipher.cipher.revision_date = revision.with_timezone(&Utc);
    }
    let mut entry = Entry::new(
        id,
        title,
        Change::Save {
            created: false,
            cipher: Box::new(cipher),
            conflict: false,
        },
    );
    entry.sent = true;
    entry
}

/// Les identifiants provisoires remplacés depuis l'ouverture de la session.
pub(crate) type Remapped = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "00000000-0000-4000-8000-000000000001";

    fn context(id: Option<&str>, favorite: bool) -> EncryptionContext {
        serde_json::from_value(serde_json::json!({
            "encryptedFor": USER,
            "encryptedByKeyId": null,
            "cipher": {
                "id": id, "organizationId": null, "folderId": null, "collectionIds": [],
                "key": null, "name": null, "notes": null, "type": 2, "login": null,
                "identity": null, "card": null, "secureNote": { "type": 0 }, "sshKey": null,
                "favorite": favorite, "reprompt": 0, "organizationUseTotp": false, "edit": true,
                "permissions": null, "viewPassword": true, "localData": null,
                "attachments": null, "fields": null, "passwordHistory": null,
                "creationDate": "2026-01-01T00:00:00Z", "deletedDate": null,
                "revisionDate": "2026-01-01T00:00:00Z", "archivedDate": null, "data": null,
            },
        }))
        .unwrap()
    }

    fn id(n: u8) -> String {
        format!("00000000-0000-4000-8000-0000000000{n:02}")
    }

    fn at() -> DateTime<Utc> {
        "2026-10-14T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn edits_of_one_item_coalesce_and_creations_stay_creations() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(10), "Brouillon".into(), true, context(None, false));
        outbox.push_save(
            id(11),
            "GitHub".into(),
            false,
            context(Some(&id(11)), false),
        );
        outbox.push_save(id(10), "Créé".into(), false, context(Some(&id(10)), true));
        outbox.push_save(
            id(11),
            "GitHub perso".into(),
            false,
            context(Some(&id(11)), true),
        );
        assert_eq!(outbox.pending_changes(), 2);
        assert_eq!(outbox.pending_items(), [id(10), id(11)]);
        assert!(matches!(
            &outbox.entries[0].change,
            Change::Save { created: true, cipher, .. } if cipher.cipher.favorite
        ));
        assert_eq!(outbox.entries[0].title, "Créé");
        assert_eq!(outbox.entries[1].title, "GitHub perso");
    }

    #[test]
    fn an_action_undone_offline_leaves_nothing_to_send() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_action(id(2), "B".into(), Action::Archive, at());
        outbox.push_action(id(1), "A".into(), Action::Restore, at());
        assert_eq!(outbox.pending_items(), [id(2)]);
        // Pas l'inverse : les deux restent, dans l'ordre.
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        assert_eq!(outbox.pending_changes(), 2);
    }

    #[test]
    fn overlay_replaces_adds_and_dates_items() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), true));
        outbox.push_save(id(9), "Nouveau".into(), true, context(None, false));
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        let mut ciphers = vec![
            context(Some(&id(1)), false).cipher,
            context(Some(&id(2)), false).cipher,
        ];
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers.len(), 3);
        assert!(
            ciphers[0].favorite,
            "la version locale remplace celle du cache"
        );
        assert_eq!(ciphers[0].archived_date, Some(at()));
        assert_eq!(ciphers[1].deleted_date, Some(at()));
        assert_eq!(ciphers[2].id.map(|i| i.to_string()), Some(id(9)));
    }

    #[test]
    fn server_ids_replace_temporary_ones() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(50), "Nouveau".into(), true, context(None, false));
        outbox.push_action(id(50), "Nouveau".into(), Action::Archive, at());
        outbox.remap(&id(50), &id(77));
        assert!(outbox.entries.iter().all(|e| e.id == id(77)));
        let mut ciphers = Vec::new();
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers[0].id.map(|i| i.to_string()), Some(id(77)));
        assert_eq!(ciphers[0].archived_date, Some(at()));
    }

    #[test]
    fn sent_entries_wait_for_the_next_sync_then_go() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), false));
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        let body =
            serde_json::json!({ "id": id(1), "revisionDate": "2026-10-14T12:30:00.123456Z" });
        outbox.entries[0] = sent_save(id(1), "A".into(), context(Some(&id(1)), false), &body);
        assert_eq!(outbox.pending_changes(), 1);
        assert_eq!(outbox.pending_items(), [id(2)]);
        // Envoyée, la modification garde la date de révision du serveur.
        let Change::Save { cipher, .. } = &outbox.entries[0].change else {
            panic!()
        };
        assert_eq!(
            cipher.cipher.revision_date.to_rfc3339(),
            "2026-10-14T12:30:00.123456+00:00"
        );
        assert!(outbox.purge_sent());
        assert_eq!(outbox.entries.len(), 1);
        assert!(!outbox.purge_sent());
    }

    #[test]
    fn the_outbox_round_trips_through_json_in_order() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(3), "C".into(), true, context(None, false));
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_save(id(2), "B".into(), false, context(Some(&id(2)), true));
        let json = serde_json::to_string(&outbox).unwrap();
        let back: Outbox = serde_json::from_str(&json).unwrap();
        let order: Vec<_> = back.entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(order, [id(3), id(1), id(2)]);
        assert!(matches!(
            back.entries[0].change,
            Change::Save { created: true, .. }
        ));
        assert!(matches!(
            back.entries[1].change,
            Change::Action {
                action: Action::Trash,
                ..
            }
        ));
    }

    #[test]
    fn an_edit_made_while_the_previous_one_is_sent_waits_behind_it() {
        let mut outbox = Outbox::default();
        outbox.push_save(id(1), "A".into(), false, context(Some(&id(1)), false));
        let Some(Job::Save { seq, .. }) = outbox_begin(&mut outbox) else {
            panic!("une modification à envoyer")
        };
        // Pendant l'envoi, une nouvelle modification du même élément.
        outbox.push_save(id(1), "A bis".into(), false, context(Some(&id(1)), true));
        assert_eq!(outbox.entries.len(), 2, "pas fusionnée avec celle en vol");
        assert_eq!(outbox.entries[0].title, "A");
        // Le serveur accepte la première : la seconde repart de sa date.
        outbox.in_flight.clear();
        let body = serde_json::json!({ "id": id(1), "revisionDate": "2026-10-14T13:00:00Z" });
        let mut sent = sent_save(id(1), "A".into(), context(Some(&id(1)), false), &body);
        sent.seq = seq;
        let index = outbox.position(seq).unwrap();
        outbox.entries[index] = sent;
        outbox.rebase(&id(1), "2026-10-14T13:00:00Z".parse().unwrap());
        let Change::Save { cipher, .. } = &outbox.entries[1].change else {
            panic!()
        };
        assert_eq!(
            cipher.cipher.revision_date.to_rfc3339(),
            "2026-10-14T13:00:00+00:00"
        );
        assert_eq!(outbox.pending_items(), [id(1)]);
    }

    #[test]
    fn an_action_in_flight_is_not_cancelled_by_its_inverse() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        assert!(matches!(outbox_begin(&mut outbox), Some(Job::Batch { .. })));
        outbox.push_action(id(1), "A".into(), Action::Unarchive, at());
        assert_eq!(
            outbox.pending_changes(),
            2,
            "les deux partent, dans l'ordre"
        );
    }

    #[test]
    fn saves_go_first_then_actions_by_batches_keeping_each_item_in_order() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        outbox.push_action(id(3), "C".into(), Action::Archive, at());
        // B est mis à la corbeille avant d'être archivé : son archive attend.
        outbox.push_action(id(2), "B".into(), Action::Archive, at());
        outbox.push_move(id(4), "D".into(), Some(id(90)));
        outbox.push_move(id(4), "D".into(), Some(id(91)));
        outbox.push_save(id(5), "E".into(), false, context(Some(&id(5)), true));

        let mut order = Vec::new();
        while let Some(job) = outbox_begin(&mut outbox) {
            let (label, seqs) = match &job {
                Job::Save { seq, id, .. } => (format!("save {id}"), vec![*seq]),
                Job::Batch { batch, entries } => (
                    format!(
                        "{batch:?} {:?}",
                        entries.iter().map(|(_, id)| id.clone()).collect::<Vec<_>>()
                    ),
                    entries.iter().map(|(seq, _)| *seq).collect(),
                ),
            };
            order.push(label);
            outbox.in_flight.clear();
            for seq in seqs {
                let index = outbox.position(seq).unwrap();
                outbox.entries[index].sent = true;
            }
        }
        assert_eq!(
            order,
            [
                format!("save {}", id(5)),
                format!("Action(Archive) {:?}", [id(1), id(3)]),
                format!("Action(Trash) {:?}", [id(2)]),
                format!("Action(Archive) {:?}", [id(2)]),
                format!("Move(Some({:?})) {:?}", id(91), [id(4)]),
            ]
        );
    }

    #[test]
    fn a_refused_batch_is_sent_again_one_by_one() {
        let mut outbox = Outbox::default();
        outbox.push_action(id(1), "A".into(), Action::Trash, at());
        outbox.push_action(id(2), "B".into(), Action::Trash, at());
        let Some(Job::Batch { entries, .. }) = outbox_begin(&mut outbox) else {
            panic!()
        };
        assert_eq!(entries.len(), 2);
        outbox.in_flight.clear();
        outbox.singles.extend(entries.iter().map(|(seq, _)| *seq));
        let Some(Job::Batch { entries, .. }) = outbox_begin(&mut outbox) else {
            panic!()
        };
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn moves_and_sent_actions_show_in_the_overlay() {
        let mut outbox = Outbox::default();
        outbox.push_move(id(1), "A".into(), Some(id(90)));
        outbox.push_action(id(1), "A".into(), Action::Archive, at());
        let revision: DateTime<Utc> = "2026-10-14T14:00:00Z".parse().unwrap();
        if let Change::Action { revision: r, .. } = &mut outbox.entries[1].change {
            *r = Some(revision);
        }
        let mut ciphers = vec![context(Some(&id(1)), false).cipher];
        outbox.apply(&mut ciphers);
        assert_eq!(ciphers[0].folder_id.map(|f| f.to_string()), Some(id(90)));
        assert_eq!(ciphers[0].revision_date, revision);
    }

    #[test]
    fn action_responses_give_the_new_revision_dates() {
        let entries = vec![(0, id(1)), (1, id(2))];
        let bulk = serde_json::json!({ "data": [
            { "id": id(2), "revisionDate": "2026-10-14T15:00:00Z" },
            { "id": id(1), "revisionDate": "2026-10-14T15:00:01Z" },
        ]});
        let found = revisions(&bulk, &entries);
        assert_eq!(
            found[id(1).as_str()].to_rfc3339(),
            "2026-10-14T15:00:01+00:00"
        );
        assert_eq!(found.len(), 2);
        let single = serde_json::json!({ "revisionDate": "2026-10-14T15:00:00Z" });
        assert_eq!(revisions(&single, &entries[..1]).len(), 1);
        assert!(revisions(&Value::Null, &entries).is_empty());
    }

    fn outbox_begin(outbox: &mut Outbox) -> Option<Job> {
        let mut rejected = Vec::new();
        let job = outbox.begin(&mut rejected);
        assert_eq!(rejected, Vec::<(String, String)>::new());
        job
    }
}
