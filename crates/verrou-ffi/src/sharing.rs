//! Sharing with the server's other accounts: several items at once
//! into a shared vault, organizations (create, rename, leave),
//! collections and their access, groups, received invitations.
//!
//! No key crosses the boundary: an organization's key is born and
//! stays in the SDK's key store, on the Rust side; Swift only sees
//! names, ids and rights.

use verrou_vaultwarden::Skipped;
use verrou_vaultwarden::collections::{CollectionMembers, Group};
use verrou_vaultwarden::members::{CollectionAccess, MemberStatus};
use verrou_vaultwarden::register::{self, SignupLink};

use crate::bulk::BulkProgress;
use crate::members::MemberCollectionAccess;
use crate::{IdMapping, VaultSession, VerrouError};

/// Result of removing items from sharing.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnshareResult {
    /// Items brought back to the personal vault: organization
    /// id (`temporary`) -> new id (`server`).
    pub moved: Vec<IdMapping>,
    /// Skipped: not in an organization.
    pub not_shared: u32,
    /// Skipped: read-only (editing and deleting must be allowed).
    pub read_only: u32,
    /// Skipped: the organization hides their passwords from this account.
    pub passwords_hidden: u32,
    /// Skipped: in the trash.
    pub in_trash: u32,
    /// Skipped: no longer in the vault.
    pub not_found: u32,
    /// Refused: titles and reasons.
    pub failures: Vec<String>,
}

/// Result of sharing several items.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ShareResult {
    /// Items moved into the organization.
    pub shared: u32,
    /// Skipped: already in an organization.
    pub already_shared: u32,
    /// Skipped: shared read-only.
    pub read_only: u32,
    /// Skipped: in the trash.
    pub in_trash: u32,
    /// Skipped: no longer in the vault.
    pub not_found: u32,
    /// Refused: titles and reasons.
    pub failures: Vec<String>,
}

/// An organization joined, awaiting an administrator's confirmation
/// (the organization's key has not arrived yet).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingMembershipView {
    pub organization_id: String,
    pub name: String,
}

/// What a pasted invitation link says.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct InvitationInfo {
    pub server: String,
    pub email: String,
    pub organization_name: Option<String>,
    /// The invitation targets the open account (same address).
    pub for_this_account: bool,
}

/// An access (of a member or a group) to a collection.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AccessGrant {
    /// Membership id of the member, or the group id.
    pub id: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl From<AccessGrant> for CollectionAccess {
    fn from(grant: AccessGrant) -> Self {
        Self {
            id: grant.id,
            read_only: grant.read_only,
            hide_passwords: grant.hide_passwords,
            manage: grant.manage,
        }
    }
}

impl From<CollectionAccess> for AccessGrant {
    fn from(access: CollectionAccess) -> Self {
        Self {
            id: access.id,
            read_only: access.read_only,
            hide_passwords: access.hide_passwords,
            manage: access.manage,
        }
    }
}

/// Who accesses a collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct CollectionAccessList {
    pub members: Vec<AccessGrant>,
    pub groups: Vec<AccessGrant>,
}

impl From<CollectionAccessList> for CollectionMembers {
    fn from(list: CollectionAccessList) -> Self {
        Self {
            users: list.members.into_iter().map(Into::into).collect(),
            groups: list.groups.into_iter().map(Into::into).collect(),
        }
    }
}

/// A group of members.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizationGroup {
    pub id: String,
    pub name: String,
    /// Membership ids of the members.
    pub members: Vec<String>,
    pub collections: Vec<MemberCollectionAccess>,
}

impl From<Group> for OrganizationGroup {
    fn from(group: Group) -> Self {
        Self {
            id: group.id,
            name: group.name,
            members: group.members,
            collections: group
                .collections
                .into_iter()
                .map(|c| MemberCollectionAccess {
                    collection_id: c.id,
                    read_only: c.read_only,
                    hide_passwords: c.hide_passwords,
                    manage: c.manage,
                })
                .collect(),
        }
    }
}

/// Members to confirm in an organization the account administers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingConfirmations {
    pub organization_id: String,
    pub organization: String,
    pub count: u32,
}

fn mock_refusal() -> VerrouError {
    VerrouError::Invalid {
        message: "mock vault: read-only".to_owned(),
    }
}

impl VaultSession {
    /// The open connection, or the error that says why there is none.
    fn sharing_connection(
        &self,
    ) -> Result<std::sync::Arc<tokio::sync::Mutex<verrou_vaultwarden::Connection>>, VerrouError>
    {
        self.current_connection().ok_or_else(|| {
            if self.is_unlocked() {
                mock_refusal()
            } else {
                VerrouError::Locked
            }
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// "Share..." on several items: re-encrypted under the
    /// organization's key and sent together. Protected items must
    /// have been confirmed (`authorize_item`); the other skipped ones are
    /// counted.
    pub async fn share_items(
        &self,
        ids: Vec<String>,
        organization_id: String,
        collection_ids: Vec<String>,
        progress: Box<dyn BulkProgress>,
    ) -> Result<ShareResult, VerrouError> {
        let connection = self.sharing_connection()?;
        self.with_vault(|v| {
            for id in &ids {
                if let Ok(item) = Self::item(v, id) {
                    self.require_authorized(item)?;
                }
            }
            Ok(())
        })?;
        let report = |done: usize, total: usize| {
            progress.progress(done as u32, total as u32);
        };
        let outcome = connection
            .lock()
            .await
            .share_many(&ids, &organization_id, &collection_ids, &report)
            .await?;
        let count =
            |reason: Skipped| outcome.skipped.iter().filter(|(_, r)| *r == reason).count() as u32;
        let result = ShareResult {
            shared: outcome.shared as u32,
            already_shared: count(Skipped::AlreadyShared),
            read_only: count(Skipped::ReadOnly),
            in_trash: count(Skipped::InTrash),
            not_found: count(Skipped::NotFound),
            failures: outcome
                .failed
                .iter()
                .map(|(title, reason)| format!("{title}: {reason}"))
                .collect(),
        };
        self.install_if_current(&connection, outcome.vault)?;
        Ok(result)
    }

    /// "Remove from sharing": brings organization items back to the
    /// personal vault (copy encrypted under the user's key, with
    /// a new item key and its attachments, then permanent deletion
    /// of the organization's item). Needs the server; protected
    /// items must have been confirmed (`authorize_item`).
    pub async fn unshare_items(
        &self,
        ids: Vec<String>,
        progress: Box<dyn BulkProgress>,
    ) -> Result<UnshareResult, VerrouError> {
        let connection = self.sharing_connection()?;
        self.with_vault(|v| {
            for id in &ids {
                if let Ok(item) = Self::item(v, id) {
                    self.require_authorized(item)?;
                }
            }
            Ok(())
        })?;
        let report = |done: usize, total: usize| {
            progress.progress(done as u32, total as u32);
        };
        let outcome = connection.lock().await.unshare(&ids, &report).await?;
        let count =
            |reason: Skipped| outcome.skipped.iter().filter(|(_, r)| *r == reason).count() as u32;
        for (from, to) in &outcome.moved {
            self.rename_use(from, to);
        }
        let result = UnshareResult {
            moved: outcome
                .moved
                .iter()
                .map(|(from, to)| IdMapping {
                    temporary: from.clone(),
                    server: to.clone(),
                })
                .collect(),
            not_shared: count(Skipped::NotShared),
            read_only: count(Skipped::ReadOnly),
            passwords_hidden: count(Skipped::PasswordsHidden),
            in_trash: count(Skipped::InTrash),
            not_found: count(Skipped::NotFound),
            failures: outcome
                .failed
                .iter()
                .map(|(title, reason)| format!("{title}: {reason}"))
                .collect(),
        };
        self.install_if_current(&connection, outcome.vault)?;
        Ok(result)
    }

    /// Creates an organization (the account owns it) with a
    /// first collection; returns its id.
    pub async fn create_organization(
        &self,
        name: String,
        collection_name: String,
    ) -> Result<String, VerrouError> {
        let connection = self.sharing_connection()?;
        let (id, vault) = connection
            .lock()
            .await
            .create_organization(&name, &collection_name)
            .await?;
        self.install_if_current(&connection, vault)?;
        Ok(id)
    }

    /// Renames the organization (owner).
    pub async fn rename_organization(
        &self,
        organization_id: String,
        name: String,
    ) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        let vault = connection
            .lock()
            .await
            .rename_organization(&organization_id, &name)
            .await?;
        self.install_if_current(&connection, vault)
    }

    /// Leaves the organization: its items disappear from this vault.
    pub async fn leave_organization(&self, organization_id: String) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        let vault = connection
            .lock()
            .await
            .leave_organization(&organization_id)
            .await?;
        self.install_if_current(&connection, vault)
    }

    /// Organizations joined, awaiting confirmation (from the
    /// last sync, without network).
    pub async fn pending_memberships(&self) -> Vec<PendingMembershipView> {
        let Some(connection) = self.current_connection() else {
            return Vec::new();
        };
        connection
            .lock()
            .await
            .pending_memberships()
            .into_iter()
            .map(|p| PendingMembershipView {
                organization_id: p.organization_id,
                name: p.name,
            })
            .collect()
    }

    /// Reads a pasted invitation link (without network).
    pub fn invitation_info(&self, link: String) -> Result<InvitationInfo, VerrouError> {
        let SignupLink::Invite(invite) = register::parse_link(&link)? else {
            return Err(VerrouError::Invalid {
                message: "this link is not an invitation to an organization".to_owned(),
            });
        };
        let account = self.account();
        Ok(InvitationInfo {
            for_this_account: account
                .as_ref()
                .is_some_and(|a| a.email.eq_ignore_ascii_case(&invite.email)),
            server: invite.server,
            email: invite.email,
            organization_name: invite.organization_name,
        })
    }

    /// "Join an organization" with this account: accepts the link's
    /// invitation; returns the organization's name. An administrator must
    /// then confirm the member.
    pub async fn join_organization(&self, link: String) -> Result<String, VerrouError> {
        let connection = self.sharing_connection()?;
        let (name, vault) = connection.lock().await.join_organization(&link).await?;
        self.install_if_current(&connection, vault)?;
        Ok(name)
    }

    /// Who accesses the collection (members and groups).
    pub async fn collection_access(
        &self,
        organization_id: String,
        collection_id: String,
    ) -> Result<CollectionAccessList, VerrouError> {
        let connection = self.sharing_connection()?;
        let members = connection
            .lock()
            .await
            .collection_members(&organization_id, &collection_id)
            .await?;
        Ok(CollectionAccessList {
            members: members.users.into_iter().map(Into::into).collect(),
            groups: members.groups.into_iter().map(Into::into).collect(),
        })
    }

    /// Creates a collection; returns its id.
    pub async fn create_collection(
        &self,
        organization_id: String,
        name: String,
        access: CollectionAccessList,
    ) -> Result<String, VerrouError> {
        let connection = self.sharing_connection()?;
        let (id, vault) = connection
            .lock()
            .await
            .create_collection(&organization_id, &name, &access.into())
            .await?;
        self.install_if_current(&connection, vault)?;
        Ok(id)
    }

    /// Renames the collection and replaces its access.
    pub async fn update_collection(
        &self,
        organization_id: String,
        collection_id: String,
        name: String,
        access: CollectionAccessList,
    ) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        let vault = connection
            .lock()
            .await
            .update_collection(&organization_id, &collection_id, &name, &access.into())
            .await?;
        self.install_if_current(&connection, vault)
    }

    /// Deletes the collection (its items stay in the organization).
    pub async fn delete_collection(
        &self,
        organization_id: String,
        collection_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        let vault = connection
            .lock()
            .await
            .delete_collection(&organization_id, &collection_id)
            .await?;
        self.install_if_current(&connection, vault)
    }

    /// The organization's groups (empty if the server doesn't enable them).
    pub async fn organization_groups(
        &self,
        organization_id: String,
    ) -> Result<Vec<OrganizationGroup>, VerrouError> {
        let connection = self.sharing_connection()?;
        let groups = connection
            .lock()
            .await
            .organization_groups(&organization_id)
            .await?;
        Ok(groups.into_iter().map(Into::into).collect())
    }

    /// Creates (`id` absent) or edits a group; returns its id.
    pub async fn save_organization_group(
        &self,
        organization_id: String,
        id: Option<String>,
        name: String,
        members: Vec<String>,
        collections: Vec<MemberCollectionAccess>,
    ) -> Result<String, VerrouError> {
        let connection = self.sharing_connection()?;
        let collections: Vec<CollectionAccess> = collections.into_iter().map(Into::into).collect();
        Ok(connection
            .lock()
            .await
            .save_group(
                &organization_id,
                id.as_deref(),
                &name,
                &members,
                &collections,
            )
            .await?)
    }

    pub async fn delete_organization_group(
        &self,
        organization_id: String,
        id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        Ok(connection
            .lock()
            .await
            .delete_group(&organization_id, &id)
            .await?)
    }

    /// For each organization the account administers, the number of
    /// members who accepted the invitation and are waiting to be confirmed.
    /// An unreachable organization is skipped.
    pub async fn members_to_confirm(&self) -> Vec<PendingConfirmations> {
        let Some(connection) = self.current_connection() else {
            return Vec::new();
        };
        let organizations: Vec<_> = self
            .organizations
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|o| o.member_rights().manage)
            .map(|o| (o.id.clone(), o.name.clone()))
            .collect();
        let mut pending = Vec::new();
        for (id, name) in organizations {
            let Ok(members) = connection.lock().await.organization_members(&id).await else {
                continue;
            };
            let count = members
                .iter()
                .filter(|m| m.status == MemberStatus::Accepted)
                .count() as u32;
            if count > 0 {
                pending.push(PendingConfirmations {
                    organization_id: id,
                    organization: name,
                    count,
                });
            }
        }
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_links_are_read_offline() {
        let session = VaultSession::new();
        let info = session
            .invitation_info(
                "http://localhost:8120/#/accept-organization/?email=lea%40exemple.fr\
                 &organizationId=6f4a2a52-0000-0000-0000-000000000001\
                 &organizationUserId=6f4a2a52-0000-0000-0000-000000000002\
                 &organizationName=Famille%20Martin&token=abc"
                    .to_owned(),
            )
            .unwrap();
        assert_eq!(info.email, "lea@exemple.fr");
        assert_eq!(info.organization_name.as_deref(), Some("Famille Martin"));
        assert!(!info.for_this_account, "no open account");
        assert!(
            session
                .invitation_info("https://exemple.fr".to_owned())
                .is_err()
        );
    }

    #[test]
    fn the_mock_vault_refuses_sharing_writes() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let refused = runtime.block_on(session.create_organization("x".into(), "y".into()));
        assert!(matches!(refused, Err(VerrouError::Invalid { .. })));
        assert_eq!(runtime.block_on(session.pending_memberships()).len(), 0);
    }
}
