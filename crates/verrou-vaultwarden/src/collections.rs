//! Collections d'une organisation et groupes de membres : créer, renommer,
//! supprimer une collection, et choisir qui y accède, avec quels droits.
//!
//! Le nom d'une collection est chiffré avec la clé de l'organisation (dans
//! le magasin de clés du SDK) ; le serveur ne le lit pas. Les droits d'accès
//! sont ceux de Bitwarden, posés membre par membre (ou groupe par groupe) :
//! lecture seule, mots de passe masqués, gérer la collection.
//!
//! Les règles de Vaultwarden 1.37, vérifiées ici avant tout envoi pour un
//! message clair (le serveur les vérifie de toute façon) :
//! - créer : propriétaire, administrateur, ou gestionnaire avec accès à
//!   toutes les collections ;
//! - renommer, supprimer, changer les accès : propriétaire, administrateur,
//!   ou gestionnaire qui gère cette collection ;
//! - groupes : seulement si le serveur les active (`ORG_GROUPS_ENABLED`) ;
//!   les créer et les modifier revient au propriétaire et à l'administrateur.
//!
//! Les membres qui voient tout (propriétaires, administrateurs) n'ont pas
//! besoin d'accès : le serveur les ignore dans les listes envoyées.

use bitwarden_core::OrganizationId;
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::{EncString, PrimitiveEncryptable};
use reqwest::Method;
use serde_json::{Value, json};

use crate::members::{CollectionAccess, MemberRole};
use crate::{Connection, Decrypted, Error, Organization};

/// Qui accède à une collection : membres (identifiants d'adhésion) et
/// groupes, avec leurs droits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectionMembers {
    pub users: Vec<CollectionAccess>,
    pub groups: Vec<CollectionAccess>,
}

/// Un groupe de membres (noms en clair, comme dans Bitwarden).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    /// Membres du groupe (identifiants d'adhésion).
    pub members: Vec<String>,
    /// Collections du groupe, avec ses droits.
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

/// Le corps de `POST`/`PUT /api/organizations/{org}/collections[/{id}]`.
pub fn collection_body(encrypted_name: &str, members: &CollectionMembers) -> Value {
    json!({
        "name": encrypted_name,
        "users": access_json(&members.users),
        "groups": access_json(&members.groups),
        "externalId": null,
    })
}

/// Le corps de `POST`/`PUT /api/organizations/{org}/groups[/{id}]`.
pub fn group_body(name: &str, members: &[String], collections: &[CollectionAccess]) -> Value {
    json!({
        "name": name,
        "accessAll": false,
        "externalId": null,
        "collections": access_json(collections),
        "users": members,
    })
}

/// Le nom, débarrassé des espaces, obligatoire.
fn required_name(name: &str, what: &str) -> Result<String, Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Invalid(format!("le nom {what} est obligatoire")));
    }
    Ok(name.to_owned())
}

impl Organization {
    /// Créer, modifier ou supprimer des groupes : propriétaire ou
    /// administrateur, groupes activés.
    pub fn can_manage_groups(&self) -> bool {
        self.use_groups && matches!(self.role, Some(MemberRole::Owner | MemberRole::Admin))
    }
}

impl Connection {
    /// L'organisation et la collection, si le compte la gère.
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
            .ok_or_else(|| Error::Invalid("collection inconnue".to_owned()))?;
        if !organization.can_manage_collection(collection) {
            return Err(Error::Invalid(
                "votre rôle ne permet pas de gérer cette collection".to_owned(),
            ));
        }
        Ok(organization)
    }

    /// Chiffre le nom avec la clé de l'organisation (déjà dans le magasin
    /// de clés du SDK, déchiffrée de la clé privée du compte).
    fn encrypt_for_organization(
        &self,
        organization_id: &str,
        text: &str,
    ) -> Result<EncString, Error> {
        let organization: OrganizationId = organization_id.parse().map_err(Error::crypto)?;
        let key_store = self.sdk.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        text.encrypt(&mut ctx, SymmetricKeySlotId::Organization(organization))
            .map_err(|_| Error::Crypto("clé de l'organisation indisponible".to_owned()))
    }

    /// Qui accède à la collection (membres et groupes), pour la modifier.
    pub async fn collection_members(
        &mut self,
        organization_id: &str,
        collection_id: &str,
    ) -> Result<CollectionMembers, Error> {
        self.managed_collection(organization_id, collection_id)?;
        let access = self.require_online("La gestion des collections").await?;
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

    /// Crée une collection ; rend son identifiant et le coffre resynchronisé.
    pub async fn create_collection(
        &mut self,
        organization_id: &str,
        name: &str,
        members: &CollectionMembers,
    ) -> Result<(String, Decrypted), Error> {
        let name = required_name(name, "de la collection")?;
        let organization = self.organization(organization_id)?;
        if !organization.can_create_collections {
            return Err(Error::Invalid(
                "votre rôle ne permet pas de créer des collections dans cette organisation"
                    .to_owned(),
            ));
        }
        if !organization.use_groups && !members.groups.is_empty() {
            return Err(Error::Invalid(
                "les groupes ne sont pas activés sur ce serveur".to_owned(),
            ));
        }
        let encrypted = self.encrypt_for_organization(organization_id, &name)?;
        let access = self.require_online("La création d'une collection").await?;
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
            .ok_or_else(|| Error::Server("collection créée sans identifiant".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Renomme la collection et remplace ses accès (membres et groupes).
    pub async fn update_collection(
        &mut self,
        organization_id: &str,
        collection_id: &str,
        name: &str,
        members: &CollectionMembers,
    ) -> Result<Decrypted, Error> {
        let name = required_name(name, "de la collection")?;
        let organization = self.managed_collection(organization_id, collection_id)?;
        if !organization.use_groups && !members.groups.is_empty() {
            return Err(Error::Invalid(
                "les groupes ne sont pas activés sur ce serveur".to_owned(),
            ));
        }
        let encrypted = self.encrypt_for_organization(organization_id, &name)?;
        let access = self.require_online("La gestion des collections").await?;
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

    /// Supprime la collection. Ses éléments restent dans l'organisation
    /// (visibles des administrateurs) s'ils n'ont plus d'autre collection.
    pub async fn delete_collection(
        &mut self,
        organization_id: &str,
        collection_id: &str,
    ) -> Result<Decrypted, Error> {
        self.managed_collection(organization_id, collection_id)?;
        let access = self
            .require_online("La suppression d'une collection")
            .await?;
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

    /// Les groupes de l'organisation (vide si le serveur ne les active pas),
    /// avec leurs membres et leurs collections, triés par nom.
    pub async fn organization_groups(
        &mut self,
        organization_id: &str,
    ) -> Result<Vec<Group>, Error> {
        let organization = self.organization(organization_id)?;
        if !organization.use_groups {
            return Ok(Vec::new());
        }
        let access = self.require_online("La gestion des groupes").await?;
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

    /// Crée (`id` absent) ou modifie un groupe : son nom, ses membres et
    /// ses collections remplacent les précédents. Rend son identifiant.
    pub async fn save_group(
        &mut self,
        organization_id: &str,
        id: Option<&str>,
        name: &str,
        members: &[String],
        collections: &[CollectionAccess],
    ) -> Result<String, Error> {
        let name = required_name(name, "du groupe")?;
        if !self.organization(organization_id)?.can_manage_groups() {
            return Err(Error::Invalid(
                "seuls les propriétaires et les administrateurs gèrent les groupes, s'ils sont \
                 activés sur le serveur"
                    .to_owned(),
            ));
        }
        let access = self.require_online("La gestion des groupes").await?;
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
            .ok_or_else(|| Error::Server("groupe enregistré sans identifiant".to_owned()))
    }

    /// Supprime un groupe (ses membres gardent leurs accès directs).
    pub async fn delete_group(&mut self, organization_id: &str, id: &str) -> Result<(), Error> {
        if !self.organization(organization_id)?.can_manage_groups() {
            return Err(Error::Invalid(
                "seuls les propriétaires et les administrateurs gèrent les groupes".to_owned(),
            ));
        }
        let access = self.require_online("La gestion des groupes").await?;
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
            "« gérer » demande un gestionnaire"
        );
        let mut no_groups = owner.clone();
        no_groups.use_groups = false;
        assert!(!no_groups.can_manage_groups());
    }

    #[test]
    fn names_are_required() {
        assert!(required_name("  ", "de la collection").is_err());
        assert_eq!(required_name(" Banque ", "x").unwrap(), "Banque");
    }
}
