//! Création conditionnelle de passkey (iOS 18, `mediation: "conditional"`).
//!
//! Après un mot de passe rempli par Verrou, Safari peut demander en arrière-
//! plan une passkey pour le même compte, sans interface
//! (`performWithoutUserInteractionIfPossible(passkeyRegistration:)`). Le
//! coffre de l'extension est alors fermé : un nouveau processus, sans Face
//! ID possible. D'où trois temps :
//!
//! 1. **Remplissage** (coffre ouvert, Face ID passé) : `prepare_passkey_upgrade`
//!    prépare une clé pour l'identifiant rempli s'il n'a pas de passkey. Le
//!    « ticket » (`passkey-upgrade.json`, dossier du compte) garde la clé
//!    publique, l'identifiant de l'accréditation, les domaines enregistrables
//!    et le nom d'utilisateur de l'élément, et la clé privée **scellée** par
//!    la clé locale du compte (lisible seulement coffre ouvert). Valable
//!    5 minutes, une seule fois.
//! 2. **Demande d'arrière-plan** (coffre fermé) : `conditional_passkey_registration`
//!    consomme le ticket si le site et le nom d'utilisateur correspondent, et
//!    rend l'attestation (`none`, sans présence ni vérification). La passkey
//!    attend dans `passkeys-pending.json`, clé toujours scellée.
//! 3. **Prochaine ouverture du coffre** dans l'app : `finish_pending_passkeys`
//!    descelle chaque clé et enregistre la passkey dans l'identifiant, sur le
//!    serveur. Le mot de passe reste : jamais rien n'est supprimé.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use verrou_bridge::access::Write;
use verrou_core::matching::registrable_domain;
use verrou_core::passkey::{self, ConditionalPasskey};
use verrou_core::{FieldKind, ItemKind};

use crate::autofill::{PasskeyCreationRequest, PasskeyRegistrationResult};
use crate::{VaultSession, VerrouError};

const TICKET_FILE: &str = "passkey-upgrade.json";
const PENDING_FILE: &str = "passkeys-pending.json";
/// Durée de validité d'un ticket : Safari demande la passkey juste après
/// l'envoi du formulaire.
const TICKET_SECONDS: i64 = 5 * 60;
/// Garde-fou : passkeys en attente gardées au plus.
const MAX_PENDING: usize = 20;

/// Clé préparée pendant le remplissage d'un mot de passe.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ticket {
    item_id: String,
    /// Domaines enregistrables des sites de l'élément.
    domains: Vec<String>,
    /// Nom d'utilisateur de l'élément, en minuscules.
    user: String,
    created: i64,
    /// base64url.
    credential_id: String,
    /// Clé publique SEC1, base64url.
    public_key: String,
    /// Clé privée PKCS#8 (base64url), scellée par la clé locale du compte.
    sealed_key: String,
}

/// Passkey enregistrée chez le site, pas encore dans le coffre.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    item_id: String,
    rp_id: String,
    /// base64url.
    user_handle: String,
    user_name: Option<String>,
    /// base64url.
    credential_id: String,
    sealed_key: String,
    created: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn invalid(message: &str) -> VerrouError {
    VerrouError::Invalid {
        message: message.to_owned(),
    }
}

fn storage(error: impl std::fmt::Display) -> VerrouError {
    VerrouError::Storage {
        message: error.to_string(),
    }
}

fn read<T: for<'de> Deserialize<'de>>(dir: &Path, file: &str) -> Option<T> {
    serde_json::from_slice(&fs::read(dir.join(file)).ok()?).ok()
}

/// Écriture atomique (fichier temporaire puis renommage) : l'app et son
/// extension partagent le dossier.
fn write<T: Serialize>(dir: &Path, file: &str, value: &T) -> Result<(), VerrouError> {
    fs::create_dir_all(dir).map_err(storage)?;
    let temp = dir.join(format!(".{file}.{}.tmp", std::process::id()));
    let data = serde_json::to_vec(value).map_err(storage)?;
    let mut handle = fs::File::create(&temp).map_err(storage)?;
    handle.write_all(&data).map_err(storage)?;
    handle.sync_all().map_err(storage)?;
    fs::rename(&temp, dir.join(file)).map_err(storage)
}

fn remove(dir: &Path, file: &str) {
    let _ = fs::remove_file(dir.join(file));
}

/// Le ticket, retiré du disque (une seule utilisation, valide ou non).
fn take_ticket(dir: &Path) -> Option<Ticket> {
    let ticket = read(dir, TICKET_FILE);
    remove(dir, TICKET_FILE);
    ticket
}

fn pending(dir: &Path) -> Vec<Pending> {
    read(dir, PENDING_FILE).unwrap_or_default()
}

fn save_pending(dir: &Path, list: &[Pending]) -> Result<(), VerrouError> {
    if list.is_empty() {
        remove(dir, PENDING_FILE);
        Ok(())
    } else {
        write(dir, PENDING_FILE, &list)
    }
}

/// La demande du site convient-elle au ticket : récent, même site (domaine
/// enregistrable), même nom d'utilisateur ?
fn check_ticket(ticket: &Ticket, rp_id: &str, user_name: &str, at: i64) -> Result<(), VerrouError> {
    if at < ticket.created || at - ticket.created > TICKET_SECONDS {
        return Err(invalid("aucun mot de passe rempli récemment"));
    }
    let site = registrable_domain(rp_id).ok_or_else(|| invalid("site invalide"))?;
    if !ticket.domains.contains(&site) {
        return Err(invalid("ce site n'est pas celui du mot de passe rempli"));
    }
    if ticket.user.is_empty() || user_name.trim().to_lowercase() != ticket.user {
        return Err(invalid("ce compte n'est pas celui du mot de passe rempli"));
    }
    Ok(())
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Extension, juste après avoir rempli le mot de passe de `id` (coffre
    /// ouvert) : prépare la clé d'une éventuelle création conditionnelle.
    /// Rien si l'élément a déjà une passkey, n'a pas de site ou pas de nom
    /// d'utilisateur (le ticket précédent est alors effacé). Rend `true` si
    /// un ticket est prêt.
    pub async fn prepare_passkey_upgrade(&self, id: String) -> Result<bool, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        remove(&dir, TICKET_FILE);
        let target = self.with_vault(|v| {
            let item = Self::item(v, &id)?;
            if item.kind != ItemKind::Login
                || !item.is_active()
                || !item.is_writable()
                || !v.passkeys_of(&item.id).is_empty()
            {
                return Ok(None);
            }
            let mut domains: Vec<String> = item
                .urls
                .iter()
                .filter_map(|u| registrable_domain(u))
                .collect();
            domains.sort();
            domains.dedup();
            let user = item
                .field_of_kind(FieldKind::Username)
                .or_else(|| item.field_of_kind(FieldKind::Email))
                .map(|f| f.value.expose().trim().to_lowercase())
                .unwrap_or_default();
            Ok((!domains.is_empty() && !user.is_empty()).then_some((domains, user)))
        })?;
        let Some((domains, user)) = target else {
            return Ok(false);
        };
        let prepared = passkey::prepare_credential(&mut rand::rngs::OsRng).map_err(|e| {
            VerrouError::Invalid {
                message: e.to_string(),
            }
        })?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let sealed_key = connection
            .lock()
            .await
            .seal_local(prepared.private_key.expose().to_owned())?;
        write(
            &dir,
            TICKET_FILE,
            &Ticket {
                item_id: id,
                domains,
                user,
                created: now(),
                credential_id: passkey::b64url(&prepared.credential_id),
                public_key: passkey::b64url(&prepared.public_key),
                sealed_key,
            },
        )?;
        Ok(true)
    }

    /// Extension, demande d'arrière-plan de Safari (coffre fermé) : crée la
    /// passkey avec la clé préparée au remplissage, si la demande vient du
    /// même site et du même compte dans les 5 minutes. La passkey attend la
    /// prochaine ouverture du coffre (`finish_pending_passkeys`). Toute
    /// autre situation est refusée, sans interface.
    pub fn conditional_passkey_registration(
        &self,
        request: PasskeyCreationRequest,
    ) -> Result<PasskeyRegistrationResult, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let ticket =
            take_ticket(&dir).ok_or_else(|| invalid("aucun mot de passe rempli récemment"))?;
        let rp_id = passkey::system_rp_id(&request.rp_id).map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        check_ticket(&ticket, &rp_id, &request.user_name, now())?;
        if request.user_handle.is_empty() || request.user_handle.len() > 64 {
            return Err(invalid("identifiant d'utilisateur invalide"));
        }
        let credential_id = passkey::b64url_decode(&ticket.credential_id)
            .ok_or_else(|| invalid("ticket illisible"))?;
        let public_key = passkey::b64url_decode(&ticket.public_key)
            .ok_or_else(|| invalid("ticket illisible"))?;
        let registration = passkey::conditional_registration(
            &rp_id,
            &credential_id,
            &public_key,
            &request.client_data_hash,
        )
        .map_err(|e| VerrouError::Invalid {
            message: e.to_string(),
        })?;
        let mut list = pending(&dir);
        list.push(Pending {
            item_id: ticket.item_id.clone(),
            rp_id,
            user_handle: passkey::b64url(&request.user_handle),
            user_name: Some(request.user_name.trim().chars().take(256).collect())
                .filter(|n: &String| !n.is_empty()),
            credential_id: ticket.credential_id,
            sealed_key: ticket.sealed_key,
            created: now(),
        });
        let overflow = list.len().saturating_sub(MAX_PENDING);
        list.drain(..overflow);
        save_pending(&dir, &list)?;
        Ok(PasskeyRegistrationResult {
            item_id: ticket.item_id,
            credential_id: registration.credential_id,
            attestation_object: registration.attestation_object,
        })
    }

    /// Passkeys créées en arrière-plan qui attendent d'entrer dans le coffre.
    pub fn pending_passkeys(&self) -> u32 {
        self.store().map_or(0, |s| pending(s.dir()).len() as u32)
    }

    /// App, coffre ouvert et en ligne : enregistre dans leur identifiant les
    /// passkeys créées en arrière-plan (un nouvel identifiant si l'élément
    /// a disparu). Rend les titres des éléments qui en ont reçu une ; les
    /// autres restent en attente (hors ligne) ou sont abandonnées (clé
    /// illisible : coffre d'un autre compte).
    pub async fn finish_pending_passkeys(&self) -> Result<Vec<String>, VerrouError> {
        let dir = self.store()?.dir().to_path_buf();
        let list = pending(&dir);
        if list.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut done = Vec::new();
        let mut left = Vec::new();
        let mut failure = None;
        for entry in list {
            if failure.is_some() {
                left.push(entry);
                continue;
            }
            let Ok(key) = connection.lock().await.open_local(entry.sealed_key.clone()) else {
                continue; // scellée par un autre compte : abandonnée
            };
            let (Some(credential_id), Some(user_id)) = (
                passkey::b64url_decode(&entry.credential_id),
                passkey::b64url_decode(&entry.user_handle),
            ) else {
                continue;
            };
            let built = self.with_vault(|v| {
                let target = v
                    .get(&entry.item_id)
                    .filter(|i| i.kind == ItemKind::Login && i.is_active() && i.is_writable());
                // Déjà là (une première tentative a abouti) : rien à refaire.
                if v.passkeys()
                    .iter()
                    .any(|p| p.raw_id().as_deref() == Some(&credential_id))
                {
                    return Ok(None);
                }
                let item_id = target.map(|i| i.id.clone());
                let key = passkey::conditional_passkey(&ConditionalPasskey {
                    item: item_id.as_deref().unwrap_or_default(),
                    rp_id: &entry.rp_id,
                    user_id: &user_id,
                    user_name: entry.user_name.as_deref(),
                    credential_id: &credential_id,
                    private_key: key.expose(),
                    created: entry.created,
                })
                .map_err(|e| VerrouError::Invalid {
                    message: e.to_string(),
                })?;
                let title = target.map_or_else(|| entry.rp_id.clone(), |i| i.title.clone());
                Ok(Some((
                    title,
                    Write::Passkey {
                        item: item_id,
                        title: entry.rp_id.clone(),
                        uri: crate::autofill::site_uri(&entry.rp_id),
                        username: entry.user_name.clone(),
                        passkey: Box::new(key),
                    },
                )))
            });
            match built {
                // Déjà dans le coffre, ou clé invalide : abandonnée.
                Ok(None) | Err(VerrouError::Invalid { .. }) => {}
                Ok(Some((title, write))) => match self.perform_write(&connection, write).await {
                    Ok(_) => done.push(title),
                    Err(error) => {
                        left.push(entry);
                        failure = Some(error);
                    }
                },
                Err(error) => {
                    left.push(entry);
                    failure = Some(error);
                }
            }
        }
        save_pending(&dir, &left)?;
        match failure {
            Some(error) if done.is_empty() => Err(error),
            _ => Ok(done),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(created: i64) -> Ticket {
        Ticket {
            item_id: "github".to_owned(),
            domains: vec!["github.com".to_owned()],
            user: "camille".to_owned(),
            created,
            credential_id: String::new(),
            public_key: String::new(),
            sealed_key: String::new(),
        }
    }

    #[test]
    fn a_ticket_matches_the_same_site_and_account_for_five_minutes() {
        let t = ticket(1_000);
        assert!(check_ticket(&t, "github.com", "camille", 1_000).is_ok());
        assert!(check_ticket(&t, "login.github.com", " Camille ", 1_299).is_ok());
        assert!(
            check_ticket(&t, "github.com", "camille", 1_301).is_err(),
            "périmé"
        );
        assert!(
            check_ticket(&t, "github.com", "camille", 999).is_err(),
            "horloge"
        );
        assert!(
            check_ticket(&t, "github.io", "camille", 1_000).is_err(),
            "autre site"
        );
        assert!(check_ticket(&t, "evil.com", "camille", 1_000).is_err());
        assert!(
            check_ticket(&t, "github.com", "dominique", 1_000).is_err(),
            "autre compte"
        );
        let mut anonymous = ticket(1_000);
        anonymous.user = String::new();
        assert!(check_ticket(&anonymous, "github.com", "", 1_000).is_err());
    }

    #[test]
    fn the_background_request_consumes_the_ticket_once() {
        let dir = std::env::temp_dir().join(format!("verrou-conditional-{}", uuid::Uuid::new_v4()));
        let session = VaultSession::with_store(verrou_vaultwarden::Store::new(
            dir.to_string_lossy().into_owned(),
        ));
        let prepared = passkey::prepare_credential(&mut rand::rngs::OsRng).unwrap();
        let mut t = ticket(now());
        t.credential_id = passkey::b64url(&prepared.credential_id);
        t.public_key = passkey::b64url(&prepared.public_key);
        t.sealed_key = "scellée".to_owned();
        write(&dir, TICKET_FILE, &t).unwrap();
        let request = |user: &str| PasskeyCreationRequest {
            rp_id: "github.com".to_owned(),
            user_name: user.to_owned(),
            user_handle: b"u-42".to_vec(),
            client_data_hash: vec![3; 32],
            user_verified: false,
            item_id: None,
            excluded_credentials: Vec::new(),
        };
        let result = session
            .conditional_passkey_registration(request("camille"))
            .unwrap();
        assert_eq!(result.item_id, "github");
        assert_eq!(result.credential_id, prepared.credential_id);
        assert_eq!(session.pending_passkeys(), 1);
        let waiting = pending(&dir);
        assert_eq!(waiting[0].rp_id, "github.com");
        assert_eq!(waiting[0].user_name.as_deref(), Some("camille"));
        assert_eq!(waiting[0].sealed_key, "scellée");
        // Une seule fois.
        assert!(
            session
                .conditional_passkey_registration(request("camille"))
                .is_err()
        );
        // Un ticket pour un autre compte est consommé sans rien créer.
        write(&dir, TICKET_FILE, &t).unwrap();
        assert!(
            session
                .conditional_passkey_registration(request("dominique"))
                .is_err()
        );
        assert!(!dir.join(TICKET_FILE).exists());
        assert_eq!(session.pending_passkeys(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
