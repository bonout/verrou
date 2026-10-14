//! Modifications hors ligne : la file d'attente (« outbox ») et son envoi.
//!
//! Serveur injoignable (erreur réseau, pas un refus du serveur) : une
//! création, une modification, la corbeille, la restauration, les archives
//! ou un favori s'appliquent tout de suite au coffre affiché et attendent le
//! serveur dans une file persistante. L'élément y est gardé **chiffré par le
//! SDK**, exactement comme il serait parti (même date de révision connue) ;
//! la file entière est en plus chiffrée par la clé de l'utilisateur
//! (`outbox.json`, voir `store`). Rien n'y est en clair.
//!
//! Le coffre affiché est le cache du serveur, auquel la file est
//! superposée (`Outbox::apply`) : verrouiller, relancer l'app ou rouvrir
//! la session ne perd rien.
//!
//! Au retour du réseau (synchronisation, ou écriture suivante), la file part
//! avant la lecture du coffre : d'abord les créations et modifications, dans
//! l'ordre, puis la corbeille et les archives (elles changent la date de
//! révision de l'élément sur le serveur : envoyées avant une modification,
//! elles la feraient passer pour périmée). Un élément créé hors ligne porte
//! un identifiant provisoire, remplacé par celui du serveur.
//!
//! Conflit : l'élément a changé (ou disparu) sur le serveur entre-temps. Le
//! serveur refuse la modification (date de révision) ; Verrou garde les
//! deux versions : la version locale devient une copie, « titre (conflit
//! hors ligne) », et la version du serveur revient à la synchronisation.
//! Rien n'est perdu sans le dire : une modification que le serveur refuse
//! pour une autre raison (et dont la copie est refusée aussi) est retirée de
//! la file et signalée.
//!
//! Une modification envoyée reste dans la file (`sent`) jusqu'à la
//! synchronisation suivante : si le réseau tombe entre les deux, le coffre
//! affiché la montre toujours.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bitwarden_api_api::models::{CipherCreateRequestModel, CipherRequestModel};
use bitwarden_vault::{Cipher, CipherView, EncryptionContext, VaultClientExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::OutboxFile;
use crate::{Connection, Decrypted, Error};

/// Après une erreur réseau, les écritures suivantes vont directement dans la
/// file pendant ce délai, sans attendre le réseau à chaque fois. La
/// synchronisation (périodique ou ⌘R), elle, réessaie toujours.
const RETRY_AFTER: Duration = Duration::from_secs(20);

/// Suffixe du titre de la copie gardée en cas de conflit.
pub const CONFLICT_SUFFIX: &str = " (conflit hors ligne)";

/// Corbeille, restauration, archives : `PUT /api/ciphers/{id}/{action}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Trash,
    Restore,
    Archive,
    Unarchive,
}

impl Action {
    fn path(self) -> &'static str {
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
        /// Créé hors ligne : `id` est provisoire, l'envoi est un `POST`.
        created: bool,
        cipher: Box<EncryptionContext>,
    },
    Action {
        action: Action,
        at: DateTime<Utc>,
    },
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
}

impl Entry {
    fn is_save(&self) -> bool {
        matches!(self.change, Change::Save { .. })
    }
}

/// La file, dans l'ordre des modifications.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Outbox {
    entries: Vec<Entry>,
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

    /// Modifications pas encore envoyées.
    pub fn pending_changes(&self) -> usize {
        self.unsent().count()
    }

    /// Éléments qui attendent le serveur, sans doublon.
    pub fn pending_items(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        for entry in self.unsent() {
            if !ids.contains(&entry.id) {
                ids.push(entry.id.clone());
            }
        }
        ids
    }

    /// Ajoute une création ou une modification. Une seule modification par
    /// élément attend : la nouvelle remplace la précédente (elle en part,
    /// puisqu'elle est faite sur le coffre affiché), et une création reste
    /// une création.
    pub fn push_save(
        &mut self,
        id: String,
        title: String,
        created: bool,
        cipher: EncryptionContext,
    ) {
        let previous = self
            .entries
            .iter_mut()
            .find(|e| !e.sent && e.id == id && e.is_save());
        if let Some(entry) = previous {
            let was_created = matches!(entry.change, Change::Save { created: true, .. });
            entry.title = title;
            entry.change = Change::Save {
                created: created || was_created,
                cipher: Box::new(cipher),
            };
            return;
        }
        self.entries.push(Entry {
            id,
            title,
            change: Change::Save {
                created,
                cipher: Box::new(cipher),
            },
            sent: false,
        });
    }

    /// Ajoute une action. Celle qui défait la précédente action en attente
    /// sur l'élément (restaurer ce qu'on vient de mettre à la corbeille,
    /// sortir des archives) l'annule simplement.
    pub fn push_action(&mut self, id: String, title: String, action: Action, at: DateTime<Utc>) {
        let last = self
            .entries
            .iter()
            .rposition(|e| !e.sent && e.id == id && matches!(e.change, Change::Action { .. }));
        if let Some(index) = last
            && matches!(self.entries[index].change, Change::Action { action: a, .. } if a == action.inverse())
        {
            self.entries.remove(index);
            return;
        }
        self.entries.push(Entry {
            id,
            title,
            change: Change::Action { action, at },
            sent: false,
        });
    }

    /// Superpose la file aux éléments du cache : remplace (ou ajoute) les
    /// éléments modifiés (ou créés), date la corbeille et les archives.
    pub fn apply(&self, ciphers: &mut Vec<Cipher>) {
        for entry in &self.entries {
            let Ok(id) = entry.id.parse() else { continue };
            let position = ciphers.iter().position(|c| c.id == Some(id));
            match &entry.change {
                Change::Save { cipher, .. } => {
                    let mut cipher = cipher.cipher.clone();
                    cipher.id = Some(id);
                    match position {
                        Some(index) => ciphers[index] = cipher,
                        None => ciphers.push(cipher),
                    }
                }
                Change::Action { action, at } => {
                    let Some(cipher) = position.map(|index| &mut ciphers[index]) else {
                        continue;
                    };
                    match action {
                        Action::Trash => cipher.deleted_date = Some(*at),
                        Action::Restore => cipher.deleted_date = None,
                        Action::Archive => cipher.archived_date = Some(*at),
                        Action::Unarchive => cipher.archived_date = None,
                    }
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

    /// Oublie ce que le serveur a accepté : la synchronisation qui vient
    /// d'arriver le contient. Rend `true` si la file a changé.
    pub fn purge_sent(&mut self) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !e.sent);
        self.entries.len() != before
    }
}

/// Bilan de l'envoi des modifications hors ligne, depuis le dernier bilan lu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Modifications acceptées par le serveur.
    pub sent: usize,
    /// Éléments modifiés (ou supprimés) ailleurs entre-temps : titre de la
    /// copie qui garde la version locale.
    pub conflicts: Vec<String>,
    /// Modifications refusées par le serveur, retirées de la file : (titre,
    /// raison).
    pub rejected: Vec<(String, String)>,
    /// Éléments créés hors ligne : (identifiant provisoire, identifiant du
    /// serveur).
    pub remapped: Vec<(String, String)>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Ce qu'est devenue une entrée envoyée.
enum Step {
    /// Acceptée (éventuellement sous la forme d'une copie) : elle reste dans
    /// la file, envoyée, jusqu'à la synchronisation.
    Sent(Entry),
    /// Sans objet (l'élément n'existe plus) : retirée sans bruit.
    Dropped,
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
        .and_then(|json| serde_json::from_str(&json).ok());
    outbox.unwrap_or_else(|| {
        // Chiffrée par une autre clé (mot de passe changé avec rotation de
        // la clé) : illisible pour toujours, et son compteur tromperait.
        let _ = store.delete_outbox();
        Outbox::default()
    })
}

impl Connection {
    /// Modifications faites hors ligne, pas encore envoyées.
    pub fn pending_changes(&self) -> usize {
        self.outbox.pending_changes()
    }

    /// Le bilan des envois depuis le dernier appel.
    pub fn take_report(&mut self) -> SyncReport {
        std::mem::take(&mut self.report)
    }

    /// Identifiant actuel d'un élément : celui du serveur pour un élément
    /// créé hors ligne et envoyé depuis.
    pub fn resolve(&self, id: &str) -> String {
        self.remapped
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned())
    }

    /// Enregistre la file (chiffrée), ou la supprime si elle est vide.
    pub(crate) fn persist_outbox(&self) -> Result<(), Error> {
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
    }

    /// Un jeton d'accès si le serveur répond, après avoir envoyé la file
    /// (et resynchronisé, pour repartir des dates de révision du serveur) ;
    /// `None` hors ligne.
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
            self.replay(&access).await?;
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

    /// Chiffre `view` puis l'envoie (`id` : modification, sinon création) ;
    /// hors ligne, l'applique au coffre affiché et le met dans la file.
    /// Rend l'identifiant de l'élément (provisoire pour une création hors
    /// ligne) et le coffre.
    pub(crate) async fn save_cipher(
        &mut self,
        id: Option<&str>,
        view: CipherView,
        access: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        // Sur le tas : chiffrer puis déchiffrer le coffre, c'est plus de 20 Ko
        // de tâche.
        Box::pin(self.write_cipher(id, view, access)).await
    }

    async fn write_cipher(
        &mut self,
        id: Option<&str>,
        view: CipherView,
        access: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        let title = view.name.clone();
        let encrypted = self.encrypt_context(view).await?;
        if let Some(access) = access {
            let request = request_of(encrypted.clone())?;
            let sent = match id {
                Some(id) => self.api.put_cipher(&access, id, &request).await,
                None => self.api.post_cipher(&access, &request).await,
            };
            match sent {
                Ok(body) => {
                    let id = match id {
                        Some(id) => id.to_owned(),
                        None => body_id(&body)?,
                    };
                    let entry = sent_save(id.clone(), title, encrypted, &body);
                    let vault = self.pull_after_write(&access, entry).await?;
                    return Ok((id, vault));
                }
                Err(Error::Network(_)) => self.mark_offline(),
                Err(error) => return Err(error),
            }
        }
        let (id, created) = match id {
            Some(id) => (id.to_owned(), false),
            None => (uuid::Uuid::new_v4().to_string(), true),
        };
        self.outbox.push_save(id.clone(), title, created, encrypted);
        self.persist_outbox()?;
        Ok((id, self.decrypt_cache().await?))
    }

    /// Corbeille, restauration ou archives ; hors ligne, dans la file.
    pub(crate) async fn cipher_action(
        &mut self,
        id: &str,
        title: String,
        action: Action,
        access: Option<String>,
    ) -> Result<Decrypted, Error> {
        if let Some(access) = access {
            match self.api.cipher_action(&access, id, action.path()).await {
                Ok(()) => {
                    let entry = Entry {
                        id: id.to_owned(),
                        title,
                        change: Change::Action {
                            action,
                            at: Utc::now(),
                        },
                        sent: true,
                    };
                    return self.pull_after_write(&access, entry).await;
                }
                Err(Error::Network(_)) => self.mark_offline(),
                Err(error) => return Err(error),
            }
        }
        self.outbox
            .push_action(id.to_owned(), title, action, Utc::now());
        self.persist_outbox()?;
        self.decrypt_cache().await
    }

    /// Après une écriture acceptée : resynchronise. Si le réseau tombe
    /// juste avant, l'écriture reste visible (envoyée, dans la file) jusqu'à
    /// la synchronisation suivante.
    async fn pull_after_write(&mut self, access: &str, entry: Entry) -> Result<Decrypted, Error> {
        match self.sync_with(access).await {
            Err(Error::Network(_)) => {
                self.mark_offline();
                self.outbox.entries.push(entry);
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
        view: CipherView,
    ) -> Result<EncryptionContext, Error> {
        // Sur le tas : la tâche du SDK est volumineuse (plus de 20 Ko).
        Box::pin(self.sdk.vault().ciphers().encrypt(view))
            .await
            .map_err(Error::crypto)
    }

    /// Envoie la file : créations et modifications d'abord, dans l'ordre,
    /// puis corbeille et archives. S'arrête sans erreur au premier problème
    /// de réseau (la suite attend) ; une session expirée interrompt tout.
    pub(crate) async fn replay(&mut self, access: &str) -> Result<(), Error> {
        for saves in [true, false] {
            while let Some(index) = self
                .outbox
                .entries
                .iter()
                .position(|e| !e.sent && e.is_save() == saves)
            {
                let entry = self.outbox.entries[index].clone();
                let step = if saves {
                    self.replay_save(access, entry.clone()).await
                } else {
                    self.replay_action(access, entry.clone()).await
                };
                match step {
                    Ok(Step::Sent(sent)) => {
                        self.outbox.entries[index] = sent;
                        self.report.sent += 1;
                    }
                    Ok(Step::Dropped) => {
                        self.outbox.entries.remove(index);
                    }
                    Err(Error::Network(_)) => {
                        self.mark_offline();
                        return self.persist_outbox();
                    }
                    Err(Error::SessionExpired) => {
                        self.persist_outbox()?;
                        return Err(Error::SessionExpired);
                    }
                    Err(error) => {
                        self.outbox.entries.remove(index);
                        self.report.rejected.push((entry.title, error.to_string()));
                    }
                }
                self.persist_outbox()?;
            }
        }
        Ok(())
    }

    async fn replay_save(&mut self, access: &str, entry: Entry) -> Result<Step, Error> {
        let Change::Save { created, cipher } = &entry.change else {
            return Ok(Step::Dropped);
        };
        let request = request_of((**cipher).clone())?;
        if *created {
            let body = self.post(access, cipher, request).await?;
            let id = body_id(&body)?;
            self.outbox.remap(&entry.id, &id);
            self.remapped.insert(entry.id.clone(), id.clone());
            self.report.remapped.push((entry.id.clone(), id.clone()));
            return Ok(Step::Sent(sent_save(
                id,
                entry.title,
                (**cipher).clone(),
                &body,
            )));
        }
        match self.api.put_cipher(access, &entry.id, &request).await {
            Ok(body) => Ok(Step::Sent(sent_save(
                entry.id,
                entry.title,
                (**cipher).clone(),
                &body,
            ))),
            Err(error @ (Error::Network(_) | Error::SessionExpired)) => Err(error),
            // Modifié, supprimé ou devenu inaccessible entre-temps : la
            // version locale devient une copie.
            Err(_) => self.conflict_copy(access, cipher).await,
        }
    }

    /// Garde la version locale d'un élément que le serveur refuse de
    /// remplacer : une copie, « titre (conflit hors ligne) », au même
    /// endroit (coffre personnel, ou mêmes collections). Sans ses pièces
    /// jointes, qui restent sur l'original.
    async fn conflict_copy(
        &mut self,
        access: &str,
        cipher: &EncryptionContext,
    ) -> Result<Step, Error> {
        let mut view = self.decrypt_view(cipher.cipher.clone()).await?;
        view.id = None;
        view.name = format!("{}{CONFLICT_SUFFIX}", view.name);
        view.attachments = None;
        view.attachment_decryption_failures = None;
        let title = view.name.clone();
        let copy = self.encrypt_context(view).await?;
        let request = request_of(copy.clone())?;
        let body = self.post(access, &copy, request).await?;
        let id = body_id(&body)?;
        self.report.conflicts.push(title.clone());
        Ok(Step::Sent(sent_save(id, title, copy, &body)))
    }

    /// Crée l'élément : dans le coffre personnel, ou dans ses collections.
    async fn post(
        &self,
        access: &str,
        cipher: &EncryptionContext,
        request: CipherRequestModel,
    ) -> Result<Value, Error> {
        if cipher.cipher.organization_id.is_none() {
            return self.api.post_cipher(access, &request).await;
        }
        let mut create = CipherCreateRequestModel::new(request);
        create.collection_ids = Some(
            cipher
                .cipher
                .collection_ids
                .iter()
                .map(|c| (*c).into())
                .collect(),
        );
        self.api
            .send_json(
                reqwest::Method::POST,
                "/api/ciphers/create",
                access,
                &create,
            )
            .await
    }

    async fn replay_action(&self, access: &str, mut entry: Entry) -> Result<Step, Error> {
        let Change::Action { action, .. } = entry.change else {
            return Ok(Step::Dropped);
        };
        match self
            .api
            .cipher_action(access, &entry.id, action.path())
            .await
        {
            Ok(()) => {
                entry.sent = true;
                Ok(Step::Sent(entry))
            }
            // L'élément n'existe plus : rien à mettre à la corbeille.
            Err(Error::NotFound) => Ok(Step::Dropped),
            Err(Error::Server(message)) if message.contains("doesn't exist") => Ok(Step::Dropped),
            Err(error) => Err(error),
        }
    }
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
fn sent_save(id: String, title: String, mut cipher: EncryptionContext, body: &Value) -> Entry {
    cipher.cipher.id = id.parse().ok();
    if let Some(revision) = body
        .get("revisionDate")
        .and_then(Value::as_str)
        .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
    {
        cipher.cipher.revision_date = revision.with_timezone(&Utc);
    }
    Entry {
        id,
        title,
        change: Change::Save {
            created: false,
            cipher: Box::new(cipher),
        },
        sent: true,
    }
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
            Change::Save { created: true, cipher } if cipher.cipher.favorite
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
}
