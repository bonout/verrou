//! Accès d'urgence : contacts de confiance, demandes, et coffre d'un
//! concédant ouvert en lecture seule.
//!
//! Le coffre d'un concédant vit dans un objet à part (`EmergencyVault`),
//! que Swift garde le temps de la fenêtre : mêmes règles que le coffre
//! principal (les secrets ne traversent la frontière que par `reveal`), et
//! il se vide de lui-même quand le coffre principal se verrouille.

use std::sync::{Arc, Mutex, PoisonError, Weak};

use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Vault};
use verrou_vaultwarden::Connection;
use verrou_vaultwarden::emergency::{EmergencyAccess, EmergencyKind, EmergencyStatus};

use crate::{ItemDetail, ItemSummary, TotpView, VaultSession, VerrouError, detail, summary};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EmergencyType {
    /// Lecture seule.
    View,
    /// Prise de contrôle (depuis le coffre web).
    Takeover,
}

impl From<EmergencyKind> for EmergencyType {
    fn from(kind: EmergencyKind) -> Self {
        match kind {
            EmergencyKind::View => Self::View,
            EmergencyKind::Takeover => Self::Takeover,
        }
    }
}

impl From<EmergencyType> for EmergencyKind {
    fn from(kind: EmergencyType) -> Self {
        match kind {
            EmergencyType::View => Self::View,
            EmergencyType::Takeover => Self::Takeover,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EmergencyState {
    Invited,
    Accepted,
    Confirmed,
    RecoveryInitiated,
    RecoveryApproved,
}

impl From<EmergencyStatus> for EmergencyState {
    fn from(status: EmergencyStatus) -> Self {
        match status {
            EmergencyStatus::Invited => Self::Invited,
            EmergencyStatus::Accepted => Self::Accepted,
            EmergencyStatus::Confirmed => Self::Confirmed,
            EmergencyStatus::RecoveryInitiated => Self::RecoveryInitiated,
            EmergencyStatus::RecoveryApproved => Self::RecoveryApproved,
        }
    }
}

/// Un accès d'urgence : l'autre personne, le type d'accès, l'état.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmergencyContact {
    pub id: String,
    /// L'autre personne (contact ou concédant), une fois l'invitation acceptée.
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub access_type: EmergencyType,
    pub state: EmergencyState,
    pub wait_time_days: u32,
}

impl From<EmergencyAccess> for EmergencyContact {
    fn from(access: EmergencyAccess) -> Self {
        Self {
            id: access.id,
            user_id: access.user_id,
            name: access.name,
            email: access.email,
            access_type: access.kind.into(),
            state: access.status.into(),
            wait_time_days: access.wait_time_days,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct EmergencyOverview {
    /// Mes contacts de confiance (je suis le concédant).
    pub trusted: Vec<EmergencyContact>,
    /// Ceux qui m'ont choisi comme contact.
    pub granted: Vec<EmergencyContact>,
}

/// Le coffre d'un concédant, en lecture seule. Vidé (secrets mis à zéro)
/// dès que le coffre principal se verrouille, ou que Swift le libère.
#[derive(uniffi::Object)]
pub struct EmergencyVault {
    vault: Mutex<Option<Vault>>,
    /// La connexion qui l'a ouvert : disparue, le coffre principal est verrouillé.
    connection: Weak<tokio::sync::Mutex<Connection>>,
    failures: u32,
}

impl EmergencyVault {
    fn with_vault<T>(
        &self,
        f: impl FnOnce(&Vault) -> Result<T, VerrouError>,
    ) -> Result<T, VerrouError> {
        let mut guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        if self.connection.strong_count() == 0 {
            guard.take();
        }
        guard.as_ref().map_or(Err(VerrouError::Locked), f)
    }
}

#[uniffi::export]
impl EmergencyVault {
    /// Éléments qui ne se sont pas déchiffrés.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Les résumés, triés par titre. Aucun secret.
    pub fn summaries(&self) -> Result<Vec<ItemSummary>, VerrouError> {
        self.with_vault(|v| Ok(v.items().iter().map(summary).collect()))
    }

    pub fn detail(&self, id: String) -> Result<ItemDetail, VerrouError> {
        self.with_vault(|v| v.get(&id).map(detail).ok_or(VerrouError::NotFound))
    }

    /// Valeur d'un champ secret (ou `notes`), à la demande de l'utilisateur.
    pub fn reveal(&self, id: String, field_id: String) -> Result<String, VerrouError> {
        self.with_vault(|v| {
            let item = v.get(&id).ok_or(VerrouError::NotFound)?;
            if field_id == "notes" {
                return item
                    .notes
                    .as_ref()
                    .map(|n| n.expose().to_owned())
                    .ok_or(VerrouError::NotFound);
            }
            item.field(&field_id)
                .map(|f| f.value.expose().to_owned())
                .ok_or(VerrouError::NotFound)
        })
    }

    pub fn totp(&self, id: String, unix_time: u64) -> Result<TotpView, VerrouError> {
        self.with_vault(|v| {
            let item = v.get(&id).ok_or(VerrouError::NotFound)?;
            let field = item
                .field_of_kind(FieldKind::Totp)
                .ok_or(VerrouError::NotFound)?;
            let totp = Totp::parse(field.value.expose()).map_err(|e| VerrouError::InvalidTotp {
                message: e.to_string(),
            })?;
            let code = totp.generate(unix_time);
            Ok(TotpView {
                code: code.code,
                period: code.period,
                remaining: code.remaining,
            })
        })
    }

    /// Ferme le coffre du concédant tout de suite (fenêtre fermée).
    pub fn close(&self) {
        self.vault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Mes contacts d'urgence et ceux qui m'ont choisi, depuis le serveur.
    pub async fn emergency_access(&self) -> Result<EmergencyOverview, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let overview = connection.lock().await.emergency_access().await?;
        Ok(EmergencyOverview {
            trusted: overview.trusted.into_iter().map(Into::into).collect(),
            granted: overview.granted.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn invite_emergency_contact(
        &self,
        email: String,
        access_type: EmergencyType,
        wait_time_days: u32,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open
            .invite_emergency_contact(&email, access_type.into(), wait_time_days)
            .await?)
    }

    pub async fn update_emergency_contact(
        &self,
        id: String,
        access_type: EmergencyType,
        wait_time_days: u32,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open
            .update_emergency_contact(&id, access_type.into(), wait_time_days)
            .await?)
    }

    /// Empreinte de la clé publique du contact, à vérifier avec lui avant
    /// de confirmer.
    pub async fn emergency_contact_fingerprint(
        &self,
        grantee_id: String,
    ) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.emergency_contact_fingerprint(&grantee_id).await?)
    }

    /// Confirme le contact : la clé du coffre est chiffrée pour lui, à
    /// condition que sa clé ait toujours l'empreinte vérifiée.
    pub async fn confirm_emergency_contact(
        &self,
        id: String,
        grantee_id: String,
        fingerprint: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open
            .confirm_emergency_contact(&id, &grantee_id, &fingerprint)
            .await?)
    }

    pub async fn delete_emergency_access(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.delete_emergency_access(&id).await?)
    }

    pub async fn request_emergency_access(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.request_emergency_access(&id).await?)
    }

    pub async fn approve_emergency_access(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.approve_emergency_access(&id).await?)
    }

    pub async fn reject_emergency_access(&self, id: String) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.reject_emergency_access(&id).await?)
    }

    /// Ouvre en lecture seule le coffre d'un concédant (accès accordé).
    pub async fn open_emergency_vault(
        &self,
        id: String,
    ) -> Result<Arc<EmergencyVault>, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let opened = connection.lock().await.open_grantor_vault(&id).await?;
        Ok(Arc::new(EmergencyVault {
            vault: Mutex::new(Some(Vault::new(opened.items))),
            connection: Arc::downgrade(&connection),
            failures: opened.failures as u32,
        }))
    }
}
