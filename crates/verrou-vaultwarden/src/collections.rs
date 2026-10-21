//! An organization's collections and member groups: create, rename, delete
//! a collection, and choose who accesses it, with which rights.
//!
//! A collection's name is encrypted with the organization key (in the SDK's
//! key store); the server doesn't read it. The access rights are
//! Bitwarden's, set member by member (or group by group): read-only, hidden
//! passwords, manage the collection.
//!
//! Vaultwarden 1.37's rules, checked here before anything is sent for a
//! clear message (the server checks them anyway):
//! - create: owner, admin, or manager with access to all collections;
//! - rename, delete, change access: owner, admin, or manager who manages
//!   this collection;
//! - groups: only if the server enables them (`ORG_GROUPS_ENABLED`);
//!   creating and editing them is up to the owner and the admin.
//!
//! Members who see everything (owners, admins) need no access: the server
//! ignores them in the lists sent.

use bitwarden_core::OrganizationId;
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::{EncString, PrimitiveEncryptable};
use reqwest::Method;
use serde_json::{Value, json};

use crate::members::{CollectionAccess, MemberRole};
use crate::{Connection, Decrypted, Error, Organization};

/// Who accesses a collection: members (membership ids) and groups, with
/// their rights.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectionMembers {
    pub users: Vec<CollectionAccess>,
    pub groups: Vec<CollectionAccess>,
}

/// A group of members (names in clear, as in Bitwarden).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    /// The group's members (membership ids).
    pub members: Vec<String>,
    /// The group's collections, with its rights.
    pub collections: Vec<CollectionAccess>,
}

fn access_list(value: Option<&Value>) -> Vec<CollectionAccess> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let flag = |key: &str| entry.get(key).and_then(Value::as_bool).unwrap_or(false);
            Some(CollectionAccess {
                id: entry.get("id")?.as_str()?.to_owned(),
                read_only: flag("readOnly"),
                hide_passwords: flag("hidePasswords"),
                manage: flag("manage"),
            })
        })
        .collect()
}

fn access_json(list: &[CollectionAccess]) -> Vec<Value> {
    list.iter()
        .map(|a| {
            json!({
                "id": a.id,
                "readOnly": a.read_only,
                "hidePasswords": a.hide_passwords,
                "manage": a.manage,
            })
        })
        .collect()
}

/// The body of `POST`/`PUT /api/organizations/{org}/collections[/{id}]`.
pub fn collection_body(encrypted_name: &str, members: &CollectionMembers) -> Value {
    json!({
        "name": encrypted_name,
        "users": access_json(&members.users),
        "groups": access_json(&members.groups),
        "externalId": null,
    })
}

/// The body of `POST`/`PUT /api/organizations/{org}/groups[/{id}]`.
pub fn group_body(name: &str, members: &[String], collections: &[CollectionAccess]) -> Value {
    json!({
        "name": name,
        "accessAll": false,
        "externalId": null,
        "collections": access_json(collections),
        "users": members,
    })
}

/// The name, trimmed, required.
fn required_name(name: &str, what: &str) -> Result<String, Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Invalid(format!("the {what} name is required")));
    }
    Ok(name.to_owned())
}

impl Organization {
    /// Creating, editing or deleting groups: owner or admin, groups
    /// enabled.
    pub fn can_manage_groups(&self) -> bool {
        self.use_groups && matches!(self.role, Some(MemberRole::Owner | MemberRole::Admin))
    }
}

impl Connection {
    /// The organization and the collection, if the account manages it.
    fn managed_collection(
        &self,
        organization_id: &str,
        collection_id: &str,
    ) -> Result<Organization, Error> {
        let organization = self.organization(organization_id)?;
        let collection = organization
            .collections
            .iter()
            .find(|c| c.id == collection_id)
            .ok_or_else(|| Error::Invalid("unknown collection".to_owned()))?;
        if !organization.can_manage_collection(collection) {
            return Err(Error::Invalid(
                "your role does not allow managing this collection".to_owned(),
            ));
        }
        Ok(organization)
    }

    /// Encrypts the name with the organization key (already in the SDK's key
    /// store, decrypted from the account's private key).
    fn encrypt_for_organization(
        &self,
        organization_id: &str,
        text: &str,
    ) -> Result<EncString, Error> {
        let organization: OrganizationId = organization_id.parse().map_err(Error::crypto)?;
        let key_store = self.sdk.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        text.encrypt(&mut ctx, SymmetricKeySlotId::Organization(organization))
            .map_err(|_| Error::Crypto("organization key unavailable".to_owned()))
    }

    /// Who accesses the collection (members and groups), to edit it.
    pub async fn collection_members(
        &mut self,
        organization_id: &str,
        collection_id: &str,
    ) -> Result<CollectionMembers, Error> {
        self.managed_collection(organization_id, collection_id)?;
        let access = self.require_online("Managing collections").await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!("organizations/{organization_id}/collections/{collection_id}/details"),
                None,
            )
            .await?;
        Ok(CollectionMembers {
            users: access_list(body.get("users")),
            groups: access_list(body.get("groups")),
        })
    }

    /// Creates a collection; returns its id and the resynced vault.
    pub async fn create_collection(
        &mut self,
        organization_id: &str,
        name: &str,
        members: &CollectionMembers,
    ) -> Result<(String, Decrypted), Error> {
        let name = required_name(name, "collection")?;
        let organization = self.organization(organization_id)?;
        if !organization.can_create_collections {
            return Err(Error::Invalid(
                "your role does not allow creating collections in this organization".to_owned(),
            ));
        }
        if !organization.use_groups && !members.groups.is_empty() {
            return Err(Error::Invalid(
                "groups are not enabled on this server".to_owned(),
            ));
        }
        let encrypted = self.encrypt_for_organization(organization_id, &name)?;
        let access = self.require_online("Creating a collection").await?;
        let created = self
            .api
            .call(
                Method::POST,
                &access,
                &format!("organizations/{organization_id}/collections"),
                Some(&collection_body(&encrypted.to_string(), members)),
            )
            .await?;
        let id = created
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("collection created without an id".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Renames the collection and replaces its access (members and groups).
    pub async fn update_collection(
        &mut self,
        organization_id: &str,
        collection_id: &str,
        name: &str,
        members: &CollectionMembers,
    ) -> Result<Decrypted, Error> {
        let name = required_name(name, "collection")?;
        let organization = self.managed_collection(organization_id, collection_id)?;
        if !organization.use_groups && !members.groups.is_empty() {
            return Err(Error::Invalid(
                "groups are not enabled on this server".to_owned(),
            ));
        }
        let encrypted = self.encrypt_for_organization(organization_id, &name)?;
        let access = self.require_online("Managing collections").await?;
        self.api
            .call(
                Method::PUT,
                &access,
                &format!("organizations/{organization_id}/collections/{collection_id}"),
                Some(&collection_body(&encrypted.to_string(), members)),
            )
            .await?;
        self.sync_with(&access).await
    }

    /// Deletes the collection. Its items stay in the organization (visible to
    /// admins) if they have no other collection left.
    pub async fn delete_collection(
        &mut self,
        organization_id: &str,
        collection_id: &str,
    ) -> Result<Decrypted, Error> {
        self.managed_collection(organization_id, collection_id)?;
        let access = self.require_online("Deleting a collection").await?;
        self.api
            .call(
                Method::DELETE,
                &access,
                &format!("organizations/{organization_id}/collections/{collection_id}"),
                None,
            )
            .await?;
        self.sync_with(&access).await
    }

    /// The organization's groups (empty if the server doesn't enable them),
    /// with their members and their collections, sorted by name.
    pub async fn organization_groups(
        &mut self,
        organization_id: &str,
    ) -> Result<Vec<Group>, Error> {
        let organization = self.organization(organization_id)?;
        if !organization.use_groups {
            return Ok(Vec::new());
        }
        let access = self.require_online("Managing groups").await?;
        let details = organization.admin;
        let path = if details {
            format!("organizations/{organization_id}/groups/details")
        } else {
            format!("organizations/{organization_id}/groups")
        };
        let body = self.api.call(Method::GET, &access, &path, None).await?;
        let list = body
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut groups = Vec::with_capacity(list.len());
        for entry in list {
            let Some(id) = entry.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            let members = if details {
                self.api
                    .call(
                        Method::GET,
                        &access,
                        &format!("organizations/{organization_id}/groups/{id}/users"),
                        None,
                    )
                    .await?
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|m| m.as_str().map(str::to_owned))
                    .collect()
            } else {
                Vec::new()
            };
            groups.push(Group {
                name: entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                collections: access_list(entry.get("collections")),
                members,
                id,
            });
        }
        groups.sort_by_key(|g| g.name.to_lowercase());
        Ok(groups)
    }

    /// Creates (no `id`) or edits a group: its name, its members and its
    /// collections replace the previous ones. Returns its id.
    pub async fn save_group(
        &mut self,
        organization_id: &str,
        id: Option<&str>,
        name: &str,
        members: &[String],
        collections: &[CollectionAccess],
    ) -> Result<String, Error> {
        let name = required_name(name, "group")?;
        if !self.organization(organization_id)?.can_manage_groups() {
            return Err(Error::Invalid(
                "only owners and admins manage groups, if they are enabled on the server"
                    .to_owned(),
            ));
        }
        let access = self.require_online("Managing groups").await?;
        let body = group_body(&name, members, collections);
        let (method, path) = match id {
            Some(id) => (
                Method::PUT,
                format!("organizations/{organization_id}/groups/{id}"),
            ),
            None => (
                Method::POST,
                format!("organizations/{organization_id}/groups"),
            ),
        };
        let saved = self.api.call(method, &access, &path, Some(&body)).await?;
        saved
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| id.map(str::to_owned))
            .ok_or_else(|| Error::Server("group saved without an id".to_owned()))
    }

    /// Deletes a group (its members keep their direct access).
    pub async fn delete_group(&mut self, organization_id: &str, id: &str) -> Result<(), Error> {
        if !self.organization(organization_id)?.can_manage_groups() {
            return Err(Error::Invalid(
                "only owners and admins manage groups".to_owned(),
            ));
        }
        let access = self.require_online("Managing groups").await?;
        self.api
            .call(
                Method::DELETE,
                &access,
                &format!("organizations/{organization_id}/groups/{id}"),
                None,
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Collection;

    fn access(id: &str, read_only: bool, hide_passwords: bool, manage: bool) -> CollectionAccess {
        CollectionAccess {
            id: id.to_owned(),
            read_only,
            hide_passwords,
            manage,
        }
    }

    #[test]
    fn collection_body_matches_vaultwarden() {
        let members = CollectionMembers {
            users: vec![access("m1", true, true, false)],
            groups: vec![access("g1", false, false, true)],
        };
        assert_eq!(
            collection_body("2.nom==", &members),
            json!({
                "name": "2.nom==",
                "users": [{ "id": "m1", "readOnly": true, "hidePasswords": true, "manage": false }],
                "groups": [{ "id": "g1", "readOnly": false, "hidePasswords": false, "manage": true }],
                "externalId": null,
            })
        );
    }

    #[test]
    fn details_are_parsed() {
        let body = json!({
            "users": [
                { "id": "m1", "readOnly": true, "hidePasswords": false, "manage": false },
                { "readOnly": true },
            ],
            "groups": [],
        });
        assert_eq!(
            access_list(body.get("users")),
            [access("m1", true, false, false)]
        );
        assert_eq!(access_list(body.get("groups")).len(), 0);
        assert_eq!(access_list(None).len(), 0);
    }

    #[test]
    fn group_body_lists_members_and_collections() {
        let body = group_body(
            "Parents",
            &["m1".to_owned()],
            &[access("c1", false, true, false)],
        );
        assert_eq!(body["name"], "Parents");
        assert_eq!(body["users"], json!(["m1"]));
        assert_eq!(body["collections"][0]["hidePasswords"], true);
        assert_eq!(body["accessAll"], false);
    }

    #[test]
    fn rights_follow_vaultwarden() {
        let collection = |manage| Collection {
            id: "c".into(),
            name: "C".into(),
            read_only: false,
            hide_passwords: false,
            manage,
        };
        let org = |role, admin| Organization {
            id: "o".into(),
            name: "O".into(),
            admin,
            role: Some(role),
            collections: vec![collection(false)],
            use_groups: true,
            can_create_collections: admin,
        };
        let owner = org(MemberRole::Owner, true);
        assert!(owner.can_manage_collection(&collection(false)));
        assert!(owner.can_manage_groups() && owner.can_rename());
        let admin = org(MemberRole::Admin, true);
        assert!(admin.can_manage_groups() && !admin.can_rename());
        let manager = org(MemberRole::Manager, false);
        assert!(!manager.can_manage_collection(&collection(false)));
        assert!(manager.can_manage_collection(&collection(true)));
        assert!(!manager.can_manage_groups());
        assert!(!manager.manages_collections());
        let full_manager = org(MemberRole::Manager, true);
        assert!(full_manager.can_manage_collection(&collection(false)));
        let user = org(MemberRole::User, false);
        assert!(
            !user.can_manage_collection(&collection(true)),
            "\"manage\" requires a manager"
        );
        let mut no_groups = owner.clone();
        no_groups.use_groups = false;
        assert!(!no_groups.can_manage_groups());
    }

    #[test]
    fn names_are_required() {
        assert!(required_name("  ", "collection").is_err());
        assert_eq!(required_name(" Banque ", "x").unwrap(), "Banque");
    }
}
