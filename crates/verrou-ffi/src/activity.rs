//! News to notify and live updates, for the apps.
//!
//! Swift only receives organization names, an address and some
//! numbers: enough to compose a local notification, never a secret.
//! The access token of the updates channel stays here.

use verrou_vaultwarden::activity::{self, Notice, NoticeKind, Remote, Snapshot};
use verrou_vaultwarden::hub::{HubUpdate, UpdateKind};
use verrou_vaultwarden::members::MemberStatus;

use crate::sharing::{PendingConfirmations, PendingMembershipView};
use crate::{VaultSession, VerrouError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ActivityKind {
    /// Invitation accepted, waiting for an administrator's confirmation.
    MembershipPending,
    /// The account was confirmed: the organization is readable.
    MembershipConfirmed,
    /// Members are waiting for this account's confirmation.
    MembersToConfirm,
    /// New items in an organization.
    ItemsShared,
    /// An emergency contact requests access to the vault.
    EmergencyRequested,
    /// A grantor has granted access to their vault.
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

/// A notification to post.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ActivityNotice {
    /// Stable identifier: news on the same subject replaces the previous one.
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

/// Result of a check, vault unlocked: the news, and the state of the
/// invitations for the app's banners.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ActivityReport {
    pub notices: Vec<ActivityNotice>,
    /// Joined organizations, waiting for confirmation.
    pub pending: Vec<PendingMembershipView>,
    /// Members to confirm, per managed organization (empty if the
    /// network was not queried or did not answer).
    pub to_confirm: Vec<PendingConfirmations>,
    /// The server answered for the members to confirm.
    pub to_confirm_checked: bool,
    /// Confirmed organizations.
    pub organizations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ServerChangeKind {
    /// Channel (re)opened: changes may have happened in the meantime.
    Connected,
    Items,
    Folders,
    Vault,
    Organizations,
    Settings,
    /// The server closes the sessions (master password changed...).
    LogOut,
    Sends,
    AuthRequest,
    Other,
}

/// A change announced by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ServerChange {
    pub kind: ServerChangeKind,
    /// Made by this device: nothing to reload.
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
    /// Vault unlocked, after a sync: what is new since last time (each
    /// thing only once, even after a relaunch). `network`: also query
    /// the server (members to confirm; emergency access if
    /// `emergency`). `notify` false: everything is marked seen without
    /// returning anything (after a local action that would otherwise
    /// produce news about oneself).
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
                // The connection lock is only held for the duration of one request.
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

    /// Vault locked (background task): what the cache alone can tell,
    /// without key or network. Empty for a mock vault.
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

    /// Waits for the next change announced by the server, vault unlocked.
    /// The first call opens the channel and returns `Connected` right
    /// away (to be followed by a sync). An error: the channel is lost
    /// (call again after a delay); `NotFound`: the server doesn't have
    /// it; `Locked`: the vault was locked (stop).
    pub async fn wait_for_server_change(&self) -> Result<ServerChange, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut epoch = self.hub_epoch.subscribe();
        let mut guard = self.hub.lock().await;
        // Locked while waiting for the channel lock.
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

    /// Closes the updates channel (the pending wait returns `Locked`).
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
        // No server connection: neither report nor channel.
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
