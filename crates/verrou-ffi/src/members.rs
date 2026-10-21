//! Organization members (invite, confirm after checking the
//! fingerprint, roles, collections) and account creation from an invitation.
//!
//! No vault secret crosses the boundary: addresses, roles, states, and
//! public key fingerprints. A new account's password leaves Swift once,
//! as at login; Rust keeps it in a `SecretString` while deriving the keys.

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

/// A member's access to a collection.
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

/// A member of an organization, as seen by an administrator.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizationMember {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub email: String,
    pub role: OrganizationMemberRole,
    pub status: OrganizationMemberStatus,
    /// All collections (role, or manager with full access).
    pub access_all: bool,
    pub collections: Vec<MemberCollectionAccess>,
    pub two_factor_enabled: bool,
    /// The account already exists on the server.
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
    /// PBKDF2-SHA256, 600,000 iterations (Bitwarden apps' default).
    Pbkdf2,
    /// Argon2id: 3 iterations, 64 MiB, 4 threads.
    Argon2id,
}

/// "Create an account": what the user entered.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NewAccountRequest {
    pub server: String,
    pub email: String,
    pub name: Option<String>,
    pub password: String,
    pub password_hint: Option<String>,
    pub kdf: NewAccountKdfChoice,
    /// Invitation (or verification) link received by email.
    pub link: Option<String>,
}

/// What a pasted link lets us prefill.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SignupLinkInfo {
    pub server: String,
    pub email: String,
    /// Inviting organization (invitation link).
    pub organization_name: Option<String>,
    /// Invitation (otherwise, address verification link).
    pub invitation: bool,
}

/// Reads an invitation or verification link pasted into "Create an account".
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

/// Strength of a master password, from 0 (very weak) to 4 (strong).
#[uniffi::export]
pub fn master_password_strength(password: String, email: String, name: Option<String>) -> u8 {
    register::password_strength(&password, &email, name.as_deref())
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Creates the account (keys generated by the SDK), then logs into it.
    /// An organization invitation is accepted after login
    /// (`accept_pending_invitation`), second factor included.
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

    /// Accepts the invitation kept by `register_account`, vault unlocked;
    /// returns the organization's name (`None`: nothing to accept).
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
                .unwrap_or_else(|| "the organization".to_owned()),
        ))
    }

    /// The fingerprint of my public key ("Fingerprint phrase").
    pub async fn own_fingerprint(&self) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let open = connection.lock().await;
        Ok(open.own_fingerprint()?)
    }

    /// The organization's members, sorted by name.
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

    /// Invites addresses (separated by commas or line breaks); returns
    /// those that were invited.
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

    /// Public key fingerprint of a member who accepted the invitation, to
    /// check with them before confirming them.
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

    /// Confirms the member: the organization key is encrypted for them,
    /// provided their key still has the checked fingerprint.
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
