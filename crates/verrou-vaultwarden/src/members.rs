//! Members of an organization: invite, confirm, manage roles and
//! collection access, without a server admin token.
//!
//! A new member's journey, on Vaultwarden 1.37:
//! 1. an owner or an admin **invites** them by address
//!    (`POST /api/organizations/{org}/users/invite`); if the server sends
//!    emails, the invitation link carries a token signed by the
//!    server, otherwise the server keeps an invitation in their name;
//! 2. the person creates their account (see `register`) or logs in, then
//!    **accepts** (`…/users/{member}/accept`, with the token);
//! 3. an owner or an admin **confirms** them: the organization's
//!    key is encrypted for their public key (RSA-OAEP-SHA1, by
//!    the SDK) and handed to the server, which cannot read it.
//!
//! As for emergency access, the public key comes from the server: before
//! confirming, the user compares its **fingerprint** (5-word phrase) with
//! the one the member reads in their account; when sending, the key is read again and
//! refused if its fingerprint changed.
//!
//! The rights are Vaultwarden's, checked here before any request for
//! a clear message (the server checks them anyway): view the list
//! (owner, admin, manager with access to all
//! collections); manage (owner, admin); invite, confirm,
//! remove a manager, an admin or an owner, or grant
//! these roles (owner only).

use bitwarden_core::OrganizationId;
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::{PublicKey, SpkiPublicKeyBytes, UnsignedSharedKey};
use reqwest::Method;
use serde_json::{Value, json};

use crate::emergency::key_fingerprint;
use crate::{Connection, Error, Organization};

/// Number of addresses per invitation (web vault limit).
pub const MAX_INVITES: usize = 20;

/// Role of a member in the organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberRole {
    Owner,
    Admin,
    User,
    /// Manager (the "custom" role of the Bitwarden apps, which
    /// Vaultwarden treats as a manager).
    Manager,
}

impl MemberRole {
    /// Role number in the API (`type`).
    pub fn code(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::User => 2,
            Self::Manager => 3,
        }
    }

    /// `4` (custom) is Vaultwarden's manager.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Owner),
            1 => Some(Self::Admin),
            2 => Some(Self::User),
            3 | 4 => Some(Self::Manager),
            _ => None,
        }
    }

    /// Owners and admins see all collections: the
    /// server then ignores the list sent.
    pub fn sees_all_collections(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Roles above "user": only an owner grants them,
    /// removes them, invites or confirms those who have them.
    fn is_privileged(self) -> bool {
        self != Self::User
    }
}

/// Status of a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Access revoked (restorable).
    Revoked,
    /// Invitation sent, not accepted yet.
    Invited,
    /// Invitation accepted: to be confirmed (fingerprint).
    Accepted,
    /// Confirmed: they have the organization's key.
    Confirmed,
}

impl MemberStatus {
    fn from_code(code: i64) -> Option<Self> {
        match code {
            // Vaultwarden shifts a revoked member's status; the API returns -1.
            i64::MIN..=-1 => Some(Self::Revoked),
            0 => Some(Self::Invited),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            _ => None,
        }
    }
}

/// A member's access to a collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionAccess {
    pub id: String,
    /// View without modifying.
    pub read_only: bool,
    /// Fill without seeing the passwords.
    pub hide_passwords: bool,
    /// Manage the collection (members, rights).
    pub manage: bool,
}

impl CollectionAccess {
    fn json(&self) -> Value {
        json!({
            "id": self.id,
            "readOnly": self.read_only,
            "hidePasswords": self.hide_passwords,
            "manage": self.manage,
        })
    }
}

/// A member of the organization, as the server describes them to an
/// admin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Id of the membership (not of the account).
    pub id: String,
    /// The member's account.
    pub user_id: String,
    /// Name chosen by the member (once the invitation is accepted).
    pub name: Option<String>,
    pub email: String,
    pub role: MemberRole,
    pub status: MemberStatus,
    /// All collections (owner, admin, or
    /// manager with full access).
    pub access_all: bool,
    /// Access granted collection by collection (empty if `access_all`).
    pub collections: Vec<CollectionAccess>,
    /// Groups (kept as is when the member is modified).
    pub groups: Vec<String>,
    /// Two-step login enabled on their account.
    pub two_factor_enabled: bool,
    /// The account already exists (master password chosen); otherwise
    /// the invitee must create their account first.
    pub has_account: bool,
}

impl Member {
    fn parse(value: &Value) -> Option<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let flag = |key: &str| value.get(key).and_then(Value::as_bool).unwrap_or(false);
        let role = MemberRole::from_code(value.get("type")?.as_i64()?)?;
        let access_all = role.sees_all_collections()
            || value
                .pointer("/permissions/editAnyCollection")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let collections = value
            .get("collections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| {
                let flag = |key: &str| c.get(key).and_then(Value::as_bool).unwrap_or(false);
                Some(CollectionAccess {
                    id: c.get("id")?.as_str()?.to_owned(),
                    read_only: flag("readOnly"),
                    hide_passwords: flag("hidePasswords"),
                    manage: flag("manage"),
                })
            })
            .collect();
        let groups = value
            .get("groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|g| g.as_str().map(str::to_owned))
            .collect();
        Some(Self {
            id: text("id")?,
            user_id: text("userId")?,
            name: text("name"),
            email: text("email")?,
            role,
            status: MemberStatus::from_code(value.get("status")?.as_i64()?)?,
            access_all,
            collections,
            groups,
            two_factor_enabled: flag("twoFactorEnabled"),
            // Missing from older versions: assume the account is created.
            has_account: value
                .get("hasMasterPassword")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }

    /// Name to display: their name, otherwise their address.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.email)
    }
}

fn parse_members(body: &Value) -> Vec<Member> {
    let mut members: Vec<Member> = body
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Member::parse)
        .collect();
    members.sort_by_key(|m| m.display_name().to_lowercase());
    members
}

/// What the account can do with the members of an organization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRights {
    /// View the member list.
    pub view: bool,
    /// Invite, confirm, modify, revoke, remove.
    pub manage: bool,
    /// Owner: the roles above "user" too.
    pub owner: bool,
}

impl Organization {
    /// The account's rights over the members of this organization.
    pub fn member_rights(&self) -> MemberRights {
        let manage = matches!(self.role, Some(MemberRole::Owner | MemberRole::Admin));
        MemberRights {
            // Manager: only with access to all collections
            // (otherwise the server answers 404).
            view: self.admin,
            manage,
            owner: self.role == Some(MemberRole::Owner),
        }
    }
}

/// What we want to do with a member, to check the rights before sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberAction {
    Invite(MemberRole),
    /// New role; the current role is the member's.
    Edit(MemberRole),
    Reinvite,
    Confirm,
    Revoke,
    Restore,
    Remove,
}

/// Vaultwarden's rules, with a message that says what to do.
pub fn check_rights(
    rights: MemberRights,
    action: MemberAction,
    member: Option<&Member>,
) -> Result<(), Error> {
    let refuse = |message: &str| Err(Error::Invalid(message.to_owned()));
    if !rights.manage {
        return refuse("only the organization's owners and admins manage its members");
    }
    if rights.owner {
        return Ok(());
    }
    let current = member.map(|m| m.role);
    match action {
        MemberAction::Invite(role) if role.is_privileged() => {
            refuse("only an owner can invite a manager, an admin or an owner")
        }
        MemberAction::Edit(_) if current == Some(MemberRole::Owner) => {
            refuse("only an owner can modify an owner")
        }
        MemberAction::Edit(role)
            if Some(role) != current
                && (role.sees_all_collections()
                    || current.is_some_and(MemberRole::sees_all_collections)) =>
        {
            refuse("only an owner can grant or remove the admin role")
        }
        MemberAction::Confirm if current.is_some_and(MemberRole::is_privileged) => {
            refuse("only an owner can confirm a manager, an admin or an owner")
        }
        MemberAction::Remove if current.is_some_and(MemberRole::is_privileged) => {
            refuse("only an owner can remove a manager, an admin or an owner")
        }
        MemberAction::Revoke | MemberAction::Restore if current == Some(MemberRole::Owner) => {
            refuse("only an owner can revoke or restore an owner")
        }
        _ => Ok(()),
    }
}

/// The typed addresses (separated by commas, semicolons,
/// spaces or line breaks), without duplicates, lower-cased.
pub fn parse_emails(text: &str) -> Result<Vec<String>, Error> {
    let mut emails: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let email = raw
            .trim()
            .trim_matches(|c| c == '<' || c == '>')
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let valid = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }) && email.matches('@').count() == 1;
        if !valid {
            return Err(Error::Invalid(format!("invalid email address: {email}")));
        }
        if !emails.contains(&email) {
            emails.push(email);
        }
    }
    if emails.is_empty() {
        return Err(Error::Invalid(
            "enter at least one email address".to_owned(),
        ));
    }
    if emails.len() > MAX_INVITES {
        return Err(Error::Invalid(format!(
            "at most {MAX_INVITES} addresses per invitation"
        )));
    }
    Ok(emails)
}

/// The body of `POST /api/organizations/{org}/users/invite`.
pub fn invite_body(emails: &[String], role: MemberRole, collections: &[CollectionAccess]) -> Value {
    json!({
        "emails": emails,
        "type": role.code(),
        "collections": access_list(role, collections),
        "groups": [],
        "accessAll": role.sees_all_collections(),
        "permissions": {},
    })
}

/// The body of `PUT /api/organizations/{org}/users/{member}`: the role and
/// the collections replace the previous ones; the groups are kept.
pub fn edit_body(role: MemberRole, collections: &[CollectionAccess], groups: &[String]) -> Value {
    json!({
        "type": role.code(),
        "collections": access_list(role, collections),
        "groups": groups,
        "accessAll": role.sees_all_collections(),
        "permissions": {},
    })
}

fn access_list(role: MemberRole, collections: &[CollectionAccess]) -> Vec<Value> {
    if role.sees_all_collections() {
        Vec::new()
    } else {
        collections.iter().map(CollectionAccess::json).collect()
    }
}

impl Connection {
    /// The organization, from the cache (the account must be a confirmed member).
    pub(crate) fn organization(&self, organization_id: &str) -> Result<Organization, Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?;
        self.decrypt_directory(&sync)
            .organizations
            .into_iter()
            .find(|o| o.id == organization_id)
            .ok_or_else(|| Error::Invalid("unknown organization".to_owned()))
    }

    /// Checks the account's rights for this action, from the cache.
    fn require_rights(
        &self,
        organization_id: &str,
        action: MemberAction,
        member: Option<&Member>,
    ) -> Result<(), Error> {
        let rights = self.organization(organization_id)?.member_rights();
        check_rights(rights, action, member)
    }

    /// The organization's members, sorted by name.
    pub async fn organization_members(
        &mut self,
        organization_id: &str,
    ) -> Result<Vec<Member>, Error> {
        if !self.organization(organization_id)?.member_rights().view {
            return Err(Error::Invalid(
                "your role does not allow viewing the members of this organization".to_owned(),
            ));
        }
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!(
                    "organizations/{organization_id}/users?includeCollections=true&includeGroups=true"
                ),
                None,
            )
            .await?;
        Ok(parse_members(&body))
    }

    /// A member, read again from the server (their status and account are authoritative, not
    /// what the interface shows).
    async fn member(&mut self, organization_id: &str, member_id: &str) -> Result<Member, Error> {
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!(
                    "organizations/{organization_id}/users/{member_id}?includeCollections=true&includeGroups=true"
                ),
                None,
            )
            .await?;
        Member::parse(&body).ok_or_else(|| Error::Server("unreadable member".to_owned()))
    }

    /// Invites one or more addresses. The server sends the invitation
    /// link by email (without email, it keeps an invitation in the
    /// address's name, and an existing account accepts it automatically).
    pub async fn invite_members(
        &mut self,
        organization_id: &str,
        emails: &str,
        role: MemberRole,
        collections: &[CollectionAccess],
    ) -> Result<Vec<String>, Error> {
        let emails = parse_emails(emails)?;
        if emails.contains(&self.account.email.to_lowercase()) {
            return Err(Error::Invalid(
                "you are already a member of this organization".to_owned(),
            ));
        }
        self.require_rights(organization_id, MemberAction::Invite(role), None)?;
        let body = invite_body(&emails, role, collections);
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/invite"),
            Some(&body),
        )
        .await?;
        Ok(emails)
    }

    /// Resends the invitation (email) of a member who has not accepted it.
    pub async fn reinvite_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Reinvite, Some(&member))?;
        if member.status != MemberStatus::Invited {
            return Err(Error::Invalid(
                "this member has already accepted the invitation".to_owned(),
            ));
        }
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/{member_id}/reinvite"),
            None,
        )
        .await
    }

    /// Changes a member's role and collection access.
    pub async fn edit_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
        role: MemberRole,
        collections: &[CollectionAccess],
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Edit(role), Some(&member))?;
        let body = edit_body(role, collections, &member.groups);
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}"),
            Some(&body),
        )
        .await
    }

    /// Revokes a member's access without deleting them (restorable).
    pub async fn revoke_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Revoke, Some(&member))?;
        if member.user_id == self.account.user_id {
            return Err(Error::Invalid(
                "you cannot revoke your own access".to_owned(),
            ));
        }
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}/revoke"),
            None,
        )
        .await
    }

    /// Gives a revoked member their access back (in the previous state).
    pub async fn restore_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Restore, Some(&member))?;
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}/restore"),
            None,
        )
        .await
    }

    /// Removes a member from the organization (their account stays on the server).
    pub async fn remove_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Remove, Some(&member))?;
        if member.user_id == self.account.user_id {
            return Err(Error::Invalid(
                "to leave the organization, use the web vault".to_owned(),
            ));
        }
        self.org_call(
            Method::DELETE,
            &format!("organizations/{organization_id}/users/{member_id}"),
            None,
        )
        .await
    }

    /// Fingerprint of the public key of a member who accepted the invitation,
    /// to compare with theirs before confirming them.
    pub async fn member_fingerprint(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<String, Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Confirm, Some(&member))?;
        if member.status != MemberStatus::Accepted {
            return Err(Error::Invalid(
                "only a member who accepted the invitation can be confirmed".to_owned(),
            ));
        }
        let der = self.public_key(&member.user_id).await?;
        key_fingerprint(&member.user_id, &der)
    }

    /// Confirms a member: the organization's key is encrypted for their
    /// public key (RSA-OAEP-SHA1, by the SDK). `fingerprint` is
    /// the fingerprint the user checked: if the server's key no longer
    /// matches it, nothing is sent.
    pub async fn confirm_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
        fingerprint: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Confirm, Some(&member))?;
        if member.status != MemberStatus::Accepted {
            return Err(Error::Invalid(
                "only a member who accepted the invitation can be confirmed".to_owned(),
            ));
        }
        let der = self.public_key(&member.user_id).await?;
        if key_fingerprint(&member.user_id, &der)? != fingerprint {
            return Err(Error::Crypto(
                "the member's key changed since it was checked: nothing was sent".to_owned(),
            ));
        }
        let public_key =
            PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).map_err(Error::crypto)?;
        let organization: OrganizationId = organization_id.parse().map_err(Error::crypto)?;
        let key_store = self.sdk.internal.get_key_store();
        let wrapped = UnsignedSharedKey::encapsulate(
            SymmetricKeySlotId::Organization(organization),
            &public_key,
            &key_store.context(),
        )
        .map_err(|_| Error::Crypto("organization key unavailable".to_owned()))?;
        let body = json!({ "key": wrapped.to_string() });
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/{member_id}/confirm"),
            Some(&body),
        )
        .await
    }

    /// The fingerprint of my own public key ("Fingerprint phrase" in the
    /// web vault), which I read to the person confirming me.
    pub fn own_fingerprint(&self) -> Result<String, Error> {
        self.sdk
            .platform()
            .user_fingerprint(self.account.user_id.clone())
            .map_err(Error::crypto)
    }

    async fn org_call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(), Error> {
        let access = self.access_token().await?;
        self.api.call(method, &access, path, body).await.map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(role: MemberRole) -> Member {
        Member {
            id: "m".into(),
            user_id: "u".into(),
            name: None,
            email: "a@exemple.fr".into(),
            role,
            status: MemberStatus::Accepted,
            access_all: false,
            collections: Vec::new(),
            groups: Vec::new(),
            two_factor_enabled: false,
            has_account: true,
        }
    }

    #[test]
    fn members_are_parsed_like_vaultwarden_sends_them() {
        let body = json!({ "data": [
            { "id": "m1", "userId": "u1", "name": "Zoé", "email": "zoe@exemple.fr", "status": 2,
              "type": 0, "twoFactorEnabled": true, "hasMasterPassword": true,
              "collections": [], "groups": [], "permissions": null },
            { "id": "m2", "userId": "u2", "name": null, "email": "invite@exemple.fr", "status": 0,
              "type": 2, "twoFactorEnabled": false, "hasMasterPassword": false,
              "collections": [{ "id": "c1", "readOnly": true, "hidePasswords": true, "manage": false }],
              "groups": ["g1"] },
            { "id": "m3", "userId": "u3", "name": "Bob", "email": "bob@exemple.fr", "status": -1,
              "type": 4, "permissions": { "editAnyCollection": true }, "collections": [] },
            { "id": "m4", "userId": "u4", "email": "x@exemple.fr", "status": 1, "type": 9 },
        ]});
        let members = parse_members(&body);
        assert_eq!(members.len(), 3, "unknown role ignored");
        // Sorted by display name.
        assert_eq!(members[0].display_name(), "Bob");
        assert_eq!(members[1].display_name(), "invite@exemple.fr");
        assert_eq!(members[2].display_name(), "Zoé");
        let bob = &members[0];
        assert_eq!(bob.role, MemberRole::Manager, "custom = manager");
        assert_eq!(bob.status, MemberStatus::Revoked);
        assert!(bob.access_all);
        let invited = &members[1];
        assert_eq!(invited.status, MemberStatus::Invited);
        assert!(!invited.has_account);
        assert_eq!(invited.groups, ["g1"]);
        assert_eq!(
            invited.collections,
            [CollectionAccess {
                id: "c1".into(),
                read_only: true,
                hide_passwords: true,
                manage: false
            }]
        );
        let owner = &members[2];
        assert!(owner.access_all && owner.two_factor_enabled);
        assert_eq!(owner.status, MemberStatus::Confirmed);
    }

    #[test]
    fn invite_body_matches_vaultwarden() {
        let collections = [CollectionAccess {
            id: "c1".into(),
            read_only: false,
            hide_passwords: true,
            manage: false,
        }];
        let emails = vec!["lea@exemple.fr".to_owned()];
        assert_eq!(
            invite_body(&emails, MemberRole::User, &collections),
            json!({
                "emails": ["lea@exemple.fr"], "type": 2,
                "collections": [{ "id": "c1", "readOnly": false, "hidePasswords": true, "manage": false }],
                "groups": [], "accessAll": false, "permissions": {},
            })
        );
        // An admin sees everything: no list.
        let admin = invite_body(&emails, MemberRole::Admin, &collections);
        assert_eq!(admin["type"], 1);
        assert_eq!(admin["accessAll"], true);
        assert_eq!(admin["collections"], json!([]));
        assert_eq!(
            invite_body(&emails, MemberRole::Manager, &collections)["type"],
            3
        );
    }

    #[test]
    fn edit_body_keeps_groups() {
        let body = edit_body(MemberRole::Manager, &[], &["g1".to_owned()]);
        assert_eq!(
            body,
            json!({ "type": 3, "collections": [], "groups": ["g1"], "accessAll": false, "permissions": {} })
        );
    }

    #[test]
    fn emails_are_split_checked_and_deduplicated() {
        assert_eq!(
            parse_emails(" Lea@Exemple.fr, <tom@exemple.fr>;\nlea@exemple.fr ").unwrap(),
            ["lea@exemple.fr", "tom@exemple.fr"]
        );
        assert!(parse_emails("").is_err());
        assert!(parse_emails("lea@exemple").is_err());
        assert!(parse_emails("a@@exemple.fr").is_err());
        let many: Vec<String> = (0..=MAX_INVITES)
            .map(|i| format!("p{i}@exemple.fr"))
            .collect();
        assert!(parse_emails(&many.join(",")).is_err());
    }

    #[test]
    fn rights_follow_vaultwarden() {
        let owner = MemberRights {
            view: true,
            manage: true,
            owner: true,
        };
        let admin = MemberRights {
            owner: false,
            ..owner
        };
        let manager = MemberRights {
            view: true,
            manage: false,
            owner: false,
        };
        let user = member(MemberRole::User);
        let other_admin = member(MemberRole::Admin);
        let other_owner = member(MemberRole::Owner);
        let other_manager = member(MemberRole::Manager);

        // Manager: read-only.
        assert!(check_rights(manager, MemberAction::Invite(MemberRole::User), None).is_err());
        // Owner: everything.
        for action in [
            MemberAction::Invite(MemberRole::Owner),
            MemberAction::Edit(MemberRole::Admin),
            MemberAction::Confirm,
            MemberAction::Remove,
            MemberAction::Revoke,
        ] {
            assert!(check_rights(owner, action, Some(&other_owner)).is_ok());
        }
        // Admin: users, and managers without promoting them.
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::User), None).is_ok());
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::Manager), None).is_err());
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::Admin), None).is_err());
        assert!(check_rights(admin, MemberAction::Confirm, Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Confirm, Some(&other_manager)).is_err());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::User), Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::Manager), Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::Admin), Some(&user)).is_err());
        assert!(
            check_rights(
                admin,
                MemberAction::Edit(MemberRole::User),
                Some(&other_admin)
            )
            .is_err()
        );
        assert!(
            check_rights(
                admin,
                MemberAction::Edit(MemberRole::Owner),
                Some(&other_owner)
            )
            .is_err()
        );
        assert!(check_rights(admin, MemberAction::Remove, Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Remove, Some(&other_admin)).is_err());
        assert!(check_rights(admin, MemberAction::Revoke, Some(&other_admin)).is_ok());
        assert!(check_rights(admin, MemberAction::Revoke, Some(&other_owner)).is_err());
        assert!(check_rights(admin, MemberAction::Reinvite, Some(&other_owner)).is_ok());
    }

    #[test]
    fn roles_round_trip() {
        for role in [
            MemberRole::Owner,
            MemberRole::Admin,
            MemberRole::User,
            MemberRole::Manager,
        ] {
            assert_eq!(MemberRole::from_code(i64::from(role.code())), Some(role));
        }
        assert_eq!(MemberRole::from_code(4), Some(MemberRole::Manager));
        assert_eq!(MemberStatus::from_code(-129), Some(MemberStatus::Revoked));
    }
}
