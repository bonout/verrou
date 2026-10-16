//! « Retirer du partage » : ramener un élément d'organisation dans le coffre
//! personnel.
//!
//! Bitwarden n'a pas de chemin inverse au partage : le serveur refuse de
//! changer l'organisation d'un élément existant (« Organization mismatch »
//! dans Vaultwarden, `update_cipher_from_data`), et les apps officielles ne
//! proposent que de cloner l'élément vers « Mon coffre » puis de supprimer
//! l'original. Verrou fait la même chose, en une action :
//!
//! 1. l'élément est déchiffré (clé de l'organisation) ;
//! 2. ses pièces jointes sont téléchargées et déchiffrées, en mémoire ;
//! 3. une copie personnelle est chiffrée par le SDK sous la clé de
//!    l'utilisateur, avec une **nouvelle** clé d'élément : l'organisation ne
//!    connaît pas la clé de la copie. Historique des mots de passe,
//!    passkeys, TOTP, champs et notes suivent ; les pièces jointes sont
//!    rechiffrées sous de nouvelles clés et envoyées à nouveau ;
//! 4. la copie de l'organisation est supprimée définitivement
//!    (`DELETE /api/ciphers/{id}`). Si la suppression échoue, la copie
//!    personnelle est retirée : pas de doublon.
//!
//! Il faut pouvoir modifier et supprimer l'élément dans l'organisation, et
//! en voir les mots de passe : sinon la copie révélerait ce que
//! l'organisation cache (Vaultwarden ne laisse modifier une collection où
//! les mots de passe sont masqués qu'avec le droit « gérer »). L'action
//! demande le serveur : elle ne passe pas par la file hors ligne (comme le
//! partage).

use std::collections::{HashMap, HashSet};

use bitwarden_vault::CipherView;
use verrou_core::import::ImportedFile;

use crate::{Connection, Decrypted, Error, Progress, Skipped};

/// Bilan d'un retrait du partage.
pub struct UnshareOutcome {
    /// Éléments ramenés : (identifiant d'organisation, nouvel identifiant
    /// personnel).
    pub moved: Vec<(String, String)>,
    /// Écartés avant tout envoi : (identifiant, raison).
    pub skipped: Vec<(String, Skipped)>,
    /// Refusés (pièce jointe illisible, serveur) : (titre, raison).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// La copie personnelle d'un élément d'organisation : sans organisation ni
/// collections, sans clé d'élément (le SDK en tire une nouvelle au
/// chiffrement), sans pièces jointes (elles sont renvoyées à part).
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
    // Une date ancienne serait prise pour une copie périmée par le serveur
    // (`lastKnownRevisionDate`).
    view.revision_date = chrono::Utc::now();
    view
}

/// Pourquoi un élément ne peut pas quitter son organisation (`None` : il le
/// peut).
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
    /// Ramène des éléments d'organisation dans le coffre personnel (voir le
    /// module). Un élément à la fois : chacun réussit ou échoue en entier.
    pub async fn unshare(
        &mut self,
        ids: &[String],
        progress: Progress<'_>,
    ) -> Result<UnshareOutcome, Error> {
        let access = self.require_online("Le retrait d'un partage").await?;
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
                failed.push((title, "une pièce jointe est illisible".to_owned()));
                continue;
            }
            // Les pièces jointes, déchiffrées en mémoire (effacée à la
            // libération).
            let mut files = Vec::new();
            let mut unreadable = None;
            for attachment in view.attachments.iter().flatten() {
                let name = attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| "pièce jointe".to_owned());
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
                        unreadable = Some(format!("pièce jointe « {name} » : {error}"));
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
                    // Pas de doublon : la copie personnelle repart.
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
