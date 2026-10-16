//! Partage avec les autres comptes du serveur : plusieurs éléments à la fois
//! dans un coffre partagé, organisations (créer, renommer, quitter),
//! collections et leurs accès, groupes, invitations reçues.
//!
//! Aucune clé ne traverse la frontière : la clé d'une organisation naît et
//! reste dans le magasin de clés du SDK, côté Rust ; Swift ne voit que des
//! noms, des identifiants et des droits.

use verrou_vaultwarden::Skipped;
use verrou_vaultwarden::collections::{CollectionMembers, Group};
use verrou_vaultwarden::members::{CollectionAccess, MemberStatus};
use verrou_vaultwarden::register::{self, SignupLink};

use crate::bulk::BulkProgress;
use crate::members::MemberCollectionAccess;
use crate::{IdMapping, VaultSession, VerrouError};

/// Bilan d'un retrait du partage.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnshareResult {
    /// Éléments ramenés dans le coffre personnel : identifiant
    /// d'organisation (`temporary`) → nouvel identifiant (`server`).
    pub moved: Vec<IdMapping>,
    /// Écartés : pas dans une organisation.
    pub not_shared: u32,
    /// Écartés : en lecture seule (il faut pouvoir modifier et supprimer).
    pub read_only: u32,
    /// Écartés : l'organisation masque leurs mots de passe à ce compte.
    pub passwords_hidden: u32,
    /// Écartés : dans la corbeille.
    pub in_trash: u32,
    /// Écartés : plus dans le coffre.
    pub not_found: u32,
    /// Refusés : titres et raisons.
    pub failures: Vec<String>,
}

/// Bilan d'un partage de plusieurs éléments.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ShareResult {
    /// Éléments passés dans l'organisation.
    pub shared: u32,
    /// Écartés : déjà dans une organisation.
    pub already_shared: u32,
    /// Écartés : partagés en lecture seule.
    pub read_only: u32,
    /// Écartés : dans la corbeille.
    pub in_trash: u32,
    /// Écartés : plus dans le coffre.
    pub not_found: u32,
    /// Refusés : titres et raisons.
    pub failures: Vec<String>,
}

/// Une organisation rejointe, en attente de la confirmation d'un
/// administrateur (la clé de l'organisation n'est pas encore arrivée).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingMembershipView {
    pub organization_id: String,
    pub name: String,
}

/// Ce que dit un lien d'invitation collé.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct InvitationInfo {
    pub server: String,
    pub email: String,
    pub organization_name: Option<String>,
    /// L'invitation vise le compte ouvert (même adresse).
    pub for_this_account: bool,
}

/// Un accès (d'un membre ou d'un groupe) à une collection.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AccessGrant {
    /// Identifiant d'adhésion du membre, ou du groupe.
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

/// Qui accède à une collection.
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

/// Un groupe de membres.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizationGroup {
    pub id: String,
    pub name: String,
    /// Identifiants d'adhésion des membres.
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

/// Membres à confirmer dans une organisation que le compte administre.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingConfirmations {
    pub organization_id: String,
    pub organization: String,
    pub count: u32,
}

fn mock_refusal() -> VerrouError {
    VerrouError::Invalid {
        message: "coffre fictif : lecture seule".to_owned(),
    }
}

impl VaultSession {
    /// La connexion ouverte, ou l'erreur qui dit pourquoi il n'y en a pas.
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
    /// « Partager… » sur plusieurs éléments : rechiffrés sous la clé de
    /// l'organisation et envoyés ensemble. Les éléments protégés doivent
    /// avoir été confirmés (`authorize_item`) ; les autres écartés sont
    /// comptés.
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
                .map(|(title, reason)| format!("{title} : {reason}"))
                .collect(),
        };
        self.install_if_current(&connection, outcome.vault)?;
        Ok(result)
    }

    /// « Retirer du partage » : ramène des éléments d'organisation dans le
    /// coffre personnel (copie chiffrée sous la clé de l'utilisateur, avec
    /// une nouvelle clé d'élément et ses pièces jointes, puis suppression
    /// définitive de l'élément de l'organisation). Demande le serveur ; les
    /// éléments protégés doivent avoir été confirmés (`authorize_item`).
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
                .map(|(title, reason)| format!("{title} : {reason}"))
                .collect(),
        };
        self.install_if_current(&connection, outcome.vault)?;
        Ok(result)
    }

    /// Crée une organisation (le compte en est propriétaire) avec une
    /// première collection ; rend son identifiant.
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

    /// Renomme l'organisation (propriétaire).
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

    /// Quitte l'organisation : ses éléments disparaissent de ce coffre.
    pub async fn leave_organization(&self, organization_id: String) -> Result<(), VerrouError> {
        let connection = self.sharing_connection()?;
        let vault = connection
            .lock()
            .await
            .leave_organization(&organization_id)
            .await?;
        self.install_if_current(&connection, vault)
    }

    /// Organisations rejointes, en attente de confirmation (d'après la
    /// dernière synchronisation, sans réseau).
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

    /// Lit un lien d'invitation collé (sans réseau).
    pub fn invitation_info(&self, link: String) -> Result<InvitationInfo, VerrouError> {
        let SignupLink::Invite(invite) = register::parse_link(&link)? else {
            return Err(VerrouError::Invalid {
                message: "ce lien n'est pas une invitation à une organisation".to_owned(),
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

    /// « Rejoindre une organisation » avec ce compte : accepte l'invitation
    /// du lien ; rend le nom de l'organisation. Un administrateur doit
    /// ensuite confirmer le membre.
    pub async fn join_organization(&self, link: String) -> Result<String, VerrouError> {
        let connection = self.sharing_connection()?;
        let (name, vault) = connection.lock().await.join_organization(&link).await?;
        self.install_if_current(&connection, vault)?;
        Ok(name)
    }

    /// Qui accède à la collection (membres et groupes).
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

    /// Crée une collection ; rend son identifiant.
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

    /// Renomme la collection et remplace ses accès.
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

    /// Supprime la collection (ses éléments restent dans l'organisation).
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

    /// Les groupes de l'organisation (vide si le serveur ne les active pas).
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

    /// Crée (`id` absent) ou modifie un groupe ; rend son identifiant.
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

    /// Pour chaque organisation que le compte administre, le nombre de
    /// membres qui ont accepté l'invitation et attendent d'être confirmés.
    /// Une organisation injoignable est passée.
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
        assert!(!info.for_this_account, "aucun compte ouvert");
        assert!(
            session
                .invitation_info("https://exemple.fr".to_owned())
                .is_err()
        );
    }

    #[test]
    fn the_mock_vault_refuses_sharing_writes() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let refused = runtime.block_on(session.create_organization("x".into(), "y".into()));
        assert!(matches!(refused, Err(VerrouError::Invalid { .. })));
        assert_eq!(runtime.block_on(session.pending_memberships()).len(), 0);
    }
}
