//! Nouveautés à notifier et mises à jour en direct, pour les apps.
//!
//! Swift ne reçoit que des noms d'organisation, une adresse et des
//! nombres : de quoi composer une notification locale, jamais un secret.
//! Le jeton d'accès du canal des mises à jour reste ici.

use verrou_vaultwarden::activity::{self, Notice, NoticeKind, Remote, Snapshot};
use verrou_vaultwarden::hub::{HubUpdate, UpdateKind};
use verrou_vaultwarden::members::MemberStatus;

use crate::sharing::{PendingConfirmations, PendingMembershipView};
use crate::{VaultSession, VerrouError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ActivityKind {
    /// Invitation acceptée, en attente de la confirmation d'un administrateur.
    MembershipPending,
    /// Le compte a été confirmé : l'organisation est lisible.
    MembershipConfirmed,
    /// Des membres attendent la confirmation de ce compte.
    MembersToConfirm,
    /// Nouveaux éléments dans une organisation.
    ItemsShared,
    /// Un contact d'urgence demande l'accès au coffre.
    EmergencyRequested,
    /// Un proche a accordé l'accès à son coffre.
    EmergencyApproved,
}

impl From<NoticeKind> for ActivityKind {
    fn from(kind: NoticeKind) -> Self {
        match kind {
            NoticeKind::MembershipPending => Self::MembershipPending,
            NoticeKind::MembershipConfirmed => Self::MembershipConfirmed,
            NoticeKind::MembersToConfirm => Self::MembersToConfirm,
            NoticeKind::ItemsShared => Self::ItemsShared,
            NoticeKind::EmergencyRequested => Self::EmergencyRequested,
            NoticeKind::EmergencyApproved => Self::EmergencyApproved,
        }
    }
}

/// Une notification à poster.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ActivityNotice {
    /// Identifiant stable : une nouvelle du même sujet remplace l'ancienne.
    pub key: String,
    pub kind: ActivityKind,
    pub organization_id: Option<String>,
    pub organization: Option<String>,
    pub count: u32,
    pub email: Option<String>,
}

impl From<Notice> for ActivityNotice {
    fn from(notice: Notice) -> Self {
        Self {
            key: notice.key,
            kind: notice.kind.into(),
            organization_id: notice.organization_id,
            organization: notice.organization,
            count: notice.count,
            email: notice.email,
        }
    }
}

/// Bilan d'un examen, coffre ouvert : les nouvelles, et l'état des
/// invitations pour les bandeaux de l'app.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ActivityReport {
    pub notices: Vec<ActivityNotice>,
    /// Organisations rejointes, en attente de confirmation.
    pub pending: Vec<PendingMembershipView>,
    /// Membres à confirmer, par organisation administrée (vide si le
    /// réseau n'a pas été consulté ou n'a pas répondu).
    pub to_confirm: Vec<PendingConfirmations>,
    /// Le serveur a répondu pour les membres à confirmer.
    pub to_confirm_checked: bool,
    /// Organisations confirmées.
    pub organizations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ServerChangeKind {
    /// Canal (r)ouvert : des changements ont pu passer entre-temps.
    Connected,
    Items,
    Folders,
    Vault,
    Organizations,
    Settings,
    /// Le serveur ferme les sessions (mot de passe principal changé…).
    LogOut,
    Sends,
    AuthRequest,
    Other,
}

/// Un changement annoncé par le serveur.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ServerChange {
    pub kind: ServerChangeKind,
    /// Fait par cet appareil : rien à relire.
    pub from_this_device: bool,
}

impl From<HubUpdate> for ServerChange {
    fn from(update: HubUpdate) -> Self {
        Self {
            kind: match update.kind {
                UpdateKind::Items => ServerChangeKind::Items,
                UpdateKind::Folders => ServerChangeKind::Folders,
                UpdateKind::Vault => ServerChangeKind::Vault,
                UpdateKind::Organizations => ServerChangeKind::Organizations,
                UpdateKind::Settings => ServerChangeKind::Settings,
                UpdateKind::LogOut => ServerChangeKind::LogOut,
                UpdateKind::Sends => ServerChangeKind::Sends,
                UpdateKind::AuthRequest => ServerChangeKind::AuthRequest,
                UpdateKind::Other => ServerChangeKind::Other,
            },
            from_this_device: update.from_this_device,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Coffre ouvert, après une synchronisation : ce qui est nouveau depuis
    /// la dernière fois (une seule fois chaque chose, même après une
    /// relance). `network` : consulter aussi le serveur (membres à
    /// confirmer ; accès d'urgence si `emergency`). `notify` faux : tout
    /// est marqué vu sans rien rendre (après une action locale qui
    /// produirait sinon une nouvelle de soi-même).
    pub async fn check_activity(
        &self,
        network: bool,
        emergency: bool,
        notify: bool,
    ) -> Result<ActivityReport, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let json = connection.lock().await.account().sync.clone();
        let Some(snapshot) = json.as_deref().and_then(Snapshot::from_sync) else {
            return Ok(ActivityReport {
                notices: Vec::new(),
                pending: Vec::new(),
                to_confirm: Vec::new(),
                to_confirm_checked: false,
                organizations: 0,
            });
        };
        let mut remote = Remote::default();
        let mut to_confirm = Vec::new();
        if network {
            let managed: Vec<(String, String)> = self
                .organizations
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter(|o| o.member_rights().manage)
                .map(|o| (o.id.clone(), o.name.clone()))
                .collect();
            let mut waiting = Vec::new();
            let mut reachable = true;
            for (id, name) in managed {
                // Le verrou de la connexion n'est tenu que le temps d'une requête.
                let Ok(members) = connection.lock().await.organization_members(&id).await else {
                    reachable = false;
                    continue;
                };
                let accepted: Vec<String> = members
                    .into_iter()
                    .filter(|m| m.status == MemberStatus::Accepted)
                    .map(|m| m.id)
                    .collect();
                if !accepted.is_empty() {
                    to_confirm.push(PendingConfirmations {
                        organization_id: id.clone(),
                        organization: name.clone(),
                        count: accepted.len() as u32,
                    });
                }
                waiting.extend(accepted.into_iter().map(|m| (id.clone(), name.clone(), m)));
            }
            if reachable {
                remote.to_confirm = Some(waiting);
            }
            if emergency {
                remote.emergency = connection.lock().await.emergency_access().await.ok();
            }
        }
        let notices = match &self.store {
            Some(store) => activity::observe(
                store,
                &snapshot,
                &remote,
                &std::collections::HashSet::<String>::new(),
                notify,
            )?,
            None => Vec::new(),
        };
        Ok(ActivityReport {
            notices: notices.into_iter().map(Into::into).collect(),
            pending: snapshot
                .pending
                .iter()
                .map(|o| PendingMembershipView {
                    organization_id: o.id.clone(),
                    name: o.name.clone(),
                })
                .collect(),
            to_confirm_checked: remote.to_confirm.is_some(),
            to_confirm,
            organizations: snapshot.confirmed.len() as u32,
        })
    }

    /// Coffre verrouillé (tâche d'arrière-plan) : ce que le cache seul
    /// permet de dire, sans clé ni réseau. Vide pour un coffre fictif.
    pub fn check_activity_locked(&self) -> Vec<ActivityNotice> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        activity::observe_cache(store)
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Attend le prochain changement annoncé par le serveur, coffre ouvert.
    /// Le premier appel ouvre le canal et rend aussitôt `Connected` (à
    /// suivre d'une synchronisation). Une erreur : le canal est perdu
    /// (rappeler après un délai) ; `NotFound` : le serveur ne l'a pas ;
    /// `Locked` : le coffre a été verrouillé (s'arrêter).
    pub async fn wait_for_server_change(&self) -> Result<ServerChange, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut epoch = self.hub_epoch.subscribe();
        let mut guard = self.hub.lock().await;
        // Verrouillé pendant l'attente du verrou du canal.
        if !self
            .current_connection()
            .is_some_and(|current| std::sync::Arc::ptr_eq(&current, &connection))
        {
            return Err(VerrouError::Locked);
        }
        epoch.mark_unchanged();
        let Some(hub) = guard.as_mut() else {
            let opened = tokio::select! {
                hub = async { connection.lock().await.open_hub().await } => hub?,
                _ = epoch.changed() => return Err(VerrouError::Locked),
            };
            *guard = Some(opened);
            return Ok(ServerChange {
                kind: ServerChangeKind::Connected,
                from_this_device: false,
            });
        };
        let next = tokio::select! {
            update = hub.next() => update,
            _ = epoch.changed() => {
                guard.take();
                return Err(VerrouError::Locked);
            }
        };
        match next {
            Ok(update) => Ok(update.into()),
            Err(error) => {
                guard.take();
                Err(error.into())
            }
        }
    }

    /// Ferme le canal des mises à jour (l'attente en cours rend `Locked`).
    pub fn stop_server_changes(&self) {
        self.hub_epoch.send_modify(|epoch| *epoch += 1);
        if let Ok(mut hub) = self.hub.try_lock() {
            hub.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_vault_has_no_activity() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert_eq!(session.check_activity_locked(), []);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Pas de connexion au serveur : ni bilan ni canal.
        assert!(matches!(
            runtime.block_on(session.check_activity(true, true, true)),
            Err(VerrouError::Locked)
        ));
        assert!(matches!(
            runtime.block_on(session.wait_for_server_change()),
            Err(VerrouError::Locked)
        ));
        session.stop_server_changes();
    }
}
