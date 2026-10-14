//! Membres des organisations (inviter, confirmer après vérification de
//! l'empreinte, rôles, collections) et création d'un compte sur invitation.
//!
//! Aucun secret du coffre ne traverse la frontière : des adresses, des
//! rôles, des états, et des empreintes de clés publiques. Le mot de passe
//! d'un nouveau compte part de Swift une fois, comme à la connexion ; Rust
//! le garde dans un `SecretString` le temps de dériver les clés.

use verrou_core::SecretString;
use verrou_vaultwarden::members::{CollectionAccess, Member, MemberRole, MemberStatus};
use verrou_vaultwarden::register::{self, NewAccount, NewAccountKdf, SignupLink};

use crate::{LoginResult, VaultSession, VerrouError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum OrganizationMemberRole {
    Owner,
    Admin,
    User,
    Manager,
}

impl From<MemberRole> for OrganizationMemberRole {
    fn from(role: MemberRole) -> Self {
        match role {
            MemberRole::Owner => Self::Owner,
            MemberRole::Admin => Self::Admin,
            MemberRole::User => Self::User,
            MemberRole::Manager => Self::Manager,
        }
    }
}

impl From<OrganizationMemberRole> for MemberRole {
    fn from(role: OrganizationMemberRole) -> Self {
        match role {
            OrganizationMemberRole::Owner => Self::Owner,
            OrganizationMemberRole::Admin => Self::Admin,
            OrganizationMemberRole::User => Self::User,
            OrganizationMemberRole::Manager => Self::Manager,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OrganizationMemberStatus {
    Revoked,
    Invited,
    Accepted,
    Confirmed,
}

impl From<MemberStatus> for OrganizationMemberStatus {
    fn from(status: MemberStatus) -> Self {
        match status {
            MemberStatus::Revoked => Self::Revoked,
            MemberStatus::Invited => Self::Invited,
            MemberStatus::Accepted => Self::Accepted,
            MemberStatus::Confirmed => Self::Confirmed,
        }
    }
}

/// Accès d'un membre à une collection.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MemberCollectionAccess {
    pub collection_id: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl From<MemberCollectionAccess> for CollectionAccess {
    fn from(access: MemberCollectionAccess) -> Self {
        Self {
            id: access.collection_id,
            read_only: access.read_only,
            hide_passwords: access.hide_passwords,
            manage: access.manage,
        }
    }
}

/// Un membre d'une organisation, vu par un administrateur.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizationMember {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub email: String,
    pub role: OrganizationMemberRole,
    pub status: OrganizationMemberStatus,
    /// Toutes les collections (rôle, ou gestionnaire avec accès complet).
    pub access_all: bool,
    pub collections: Vec<MemberCollectionAccess>,
    pub two_factor_enabled: bool,
    /// Le compte existe déjà sur le serveur.
    pub has_account: bool,
}

impl From<Member> for OrganizationMember {
    fn from(member: Member) -> Self {
        Self {
            id: member.id,
            user_id: member.user_id,
            name: member.name,
            email: member.email,
            role: member.role.into(),
            status: member.status.into(),
            access_all: member.access_all,
            collections: member
                .collections
                .into_iter()
                .map(|c| MemberCollectionAccess {
                    collection_id: c.id,
                    read_only: c.read_only,
                    hide_passwords: c.hide_passwords,
                    manage: c.manage,
                })
                .collect(),
            two_factor_enabled: member.two_factor_enabled,
            has_account: member.has_account,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NewAccountKdfChoice {
    /// PBKDF2-SHA256, 600 000 itérations (défaut des apps Bitwarden).
    Pbkdf2,
    /// Argon2id : 3 itérations, 64 Mio, 4 fils.
    Argon2id,
}

/// « Créer un compte » : ce que l'utilisateur a saisi.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NewAccountRequest {
    pub server: String,
    pub email: String,
    pub name: Option<String>,
    pub password: String,
    pub password_hint: Option<String>,
    pub kdf: NewAccountKdfChoice,
    /// Lien d'invitation (ou de vérification) reçu par courriel.
    pub link: Option<String>,
}

/// Ce qu'un lien collé permet de préremplir.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SignupLinkInfo {
    pub server: String,
    pub email: String,
    /// Organisation qui invite (lien d'invitation).
    pub organization_name: Option<String>,
    /// Invitation (sinon, lien de vérification de l'adresse).
    pub invitation: bool,
}

/// Lit un lien d'invitation ou de vérification collé dans « Créer un compte ».
#[uniffi::export]
pub fn parse_signup_link(text: String) -> Result<SignupLinkInfo, VerrouError> {
    let link = register::parse_link(&text)?;
    Ok(SignupLinkInfo {
        server: link.server().to_owned(),
        email: link.email().to_owned(),
        organization_name: match &link {
            SignupLink::Invite(invite) if !invite.is_server_invite() => {
                invite.organization_name.clone()
            }
            _ => None,
        },
        invitation: matches!(link, SignupLink::Invite(_)),
    })
}

/// Robustesse d'un mot de passe principal, de 0 (très faible) à 4 (fort).
#[uniffi::export]
pub fn master_password_strength(password: String, email: String, name: Option<String>) -> u8 {
    register::password_strength(&password, &email, name.as_deref())
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Crée le compte (clés générées par le SDK), puis s'y connecte. Une
    /// invitation d'organisation est acceptée après la connexion
    /// (`accept_pending_invitation`), second facteur compris.
    pub async fn register_account(
        &self,
        request: NewAccountRequest,
    ) -> Result<LoginResult, VerrouError> {
        let store = self.store()?.clone();
        let link = request
            .link
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(register::parse_link)
            .transpose()?;
        let account = NewAccount {
            server: request.server.clone(),
            email: request.email.clone(),
            name: request.name,
            password: SecretString::new(request.password),
            hint: request.password_hint,
            kdf: match request.kdf {
                NewAccountKdfChoice::Pbkdf2 => NewAccountKdf::Pbkdf2,
                NewAccountKdfChoice::Argon2id => NewAccountKdf::Argon2id,
            },
            link,
        };
        register::register(&account).await?;
        *self
            .pending_invite
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = match account.link {
            Some(SignupLink::Invite(invite)) if !invite.is_server_invite() => Some(invite),
            _ => None,
        };
        let step =
            verrou_vaultwarden::login(&store, &request.server, &request.email, account.password)
                .await?;
        Ok(self.login_result(step))
    }

    /// Accepte l'invitation gardée par `register_account`, coffre ouvert ;
    /// rend le nom de l'organisation (`None` : rien à accepter).
    pub async fn accept_pending_invitation(&self) -> Result<Option<String>, VerrouError> {
        let Some(connection) = self.current_connection() else {
            return Ok(None);
        };
        let invite = self
            .pending_invite
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(invite) = invite else {
            return Ok(None);
        };
        connection.lock().await.accept_invitation(&invite).await?;
        Ok(Some(
            invite
                .organization_name
                .unwrap_or_else(|| "l'organisation".to_owned()),
        ))
    }

    /// L'empreinte de ma clé publique (« Phrase d'empreinte »).
    pub async fn own_fingerprint(&self) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let open = connection.lock().await;
        Ok(open.own_fingerprint()?)
    }

    /// Les membres de l'organisation, triés par nom.
    pub async fn organization_members(
        &self,
        organization_id: String,
    ) -> Result<Vec<OrganizationMember>, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let members = connection
            .lock()
            .await
            .organization_members(&organization_id)
            .await?;
        Ok(members.into_iter().map(Into::into).collect())
    }

    /// Invite des adresses (séparées par des virgules ou des retours à la
    /// ligne) ; rend celles qui ont été invitées.
    pub async fn invite_organization_members(
        &self,
        organization_id: String,
        emails: String,
        role: OrganizationMemberRole,
        collections: Vec<MemberCollectionAccess>,
    ) -> Result<Vec<String>, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let collections: Vec<CollectionAccess> = collections.into_iter().map(Into::into).collect();
        let mut open = connection.lock().await;
        Ok(open
            .invite_members(&organization_id, &emails, role.into(), &collections)
            .await?)
    }

    pub async fn reinvite_organization_member(
        &self,
        organization_id: String,
        member_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.reinvite_member(&organization_id, &member_id).await?)
    }

    pub async fn edit_organization_member(
        &self,
        organization_id: String,
        member_id: String,
        role: OrganizationMemberRole,
        collections: Vec<MemberCollectionAccess>,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let collections: Vec<CollectionAccess> = collections.into_iter().map(Into::into).collect();
        let mut open = connection.lock().await;
        Ok(open
            .edit_member(&organization_id, &member_id, role.into(), &collections)
            .await?)
    }

    pub async fn revoke_organization_member(
        &self,
        organization_id: String,
        member_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.revoke_member(&organization_id, &member_id).await?)
    }

    pub async fn restore_organization_member(
        &self,
        organization_id: String,
        member_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.restore_member(&organization_id, &member_id).await?)
    }

    pub async fn remove_organization_member(
        &self,
        organization_id: String,
        member_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open.remove_member(&organization_id, &member_id).await?)
    }

    /// Empreinte de la clé publique d'un membre qui a accepté l'invitation,
    /// à vérifier avec lui avant de le confirmer.
    pub async fn organization_member_fingerprint(
        &self,
        organization_id: String,
        member_id: String,
    ) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open
            .member_fingerprint(&organization_id, &member_id)
            .await?)
    }

    /// Confirme le membre : la clé de l'organisation est chiffrée pour lui,
    /// à condition que sa clé ait toujours l'empreinte vérifiée.
    pub async fn confirm_organization_member(
        &self,
        organization_id: String,
        member_id: String,
        fingerprint: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let mut open = connection.lock().await;
        Ok(open
            .confirm_member(&organization_id, &member_id, &fingerprint)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_prefill_the_form() {
        let info = parse_signup_link(
            "https://vault.exemple.fr/#/accept-organization/?email=lea%40exemple.fr\
             &organizationName=Famille&organizationId=o&organizationUserId=m&token=t"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(
            info,
            SignupLinkInfo {
                server: "https://vault.exemple.fr".into(),
                email: "lea@exemple.fr".into(),
                organization_name: Some("Famille".into()),
                invitation: true,
            }
        );
        assert!(matches!(
            parse_signup_link("https://vault.exemple.fr".into()),
            Err(VerrouError::Invalid { .. })
        ));
    }

    #[test]
    fn the_mock_organization_is_managed_by_its_owner() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        let org = &session.organizations()[0];
        assert_eq!(org.role, Some(OrganizationMemberRole::Owner));
        assert!(org.can_view_members && org.can_manage_members && org.is_owner);
    }
}
