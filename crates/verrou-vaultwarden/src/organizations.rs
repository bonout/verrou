//! Organisations de Vaultwarden : les coffres partagés.
//!
//! Lecture : la clé de chaque organisation arrive dans le profil, chiffrée
//! (RSA-OAEP) avec la clé publique du compte ; le SDK la déchiffre avec la
//! clé privée (`initialize_org_crypto`), puis déchiffre avec elle les noms
//! des collections et les éléments de l'organisation.
//!
//! Écriture : un élément partagé se chiffre avec la clé de l'organisation
//! (le SDK la choisit d'après `organization_id`). Créer dans une collection
//! passe par `POST /api/ciphers/create`, partager un élément personnel par
//! `PUT /api/ciphers/{id}/share` (rechiffré sous la clé de l'organisation,
//! clés des pièces jointes comprises), changer ses collections par
//! `PUT /api/ciphers/{id}/collections_v2`. Les droits (lecture seule,
//! mots de passe masqués) sont ceux que le serveur annonce ; il les vérifie
//! de toute façon à chaque écriture.

use std::collections::HashMap;

use bitwarden_api_api::models::{
    CipherCollectionsRequestModel, CipherCreateRequestModel, CipherShareRequestModel,
    SyncResponseModel,
};
use bitwarden_collections::collection::{
    Collection as SdkCollection, CollectionId, CollectionType,
};
use bitwarden_core::OrganizationId;
use bitwarden_vault::{CipherError, CipherView, VaultClientExt};
use chrono::Utc;
use verrou_core::Sharing;

use crate::edit::new_view;
use crate::{Connection, Decrypted, Draft, Error};

/// Une organisation dont le compte est membre confirmé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    /// Propriétaire, administrateur ou gestionnaire : gère les collections
    /// dans le coffre web.
    pub admin: bool,
    /// Collections visibles par le compte, triées par nom.
    pub collections: Vec<Collection>,
}

impl Organization {
    /// Le compte peut-il y ranger un élément (au moins une collection où il
    /// a le droit d'écrire) ?
    pub fn is_writable(&self) -> bool {
        self.collections.iter().any(|c| !c.read_only)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub name: String,
    /// Le compte peut voir, pas modifier.
    pub read_only: bool,
    /// Le compte ne voit pas les mots de passe (il peut remplir).
    pub hide_passwords: bool,
    /// Le compte gère la collection (membres, droits).
    pub manage: bool,
}

/// Organisations et collections, pour rattacher chaque élément aux siennes.
#[derive(Default)]
pub(crate) struct Directory {
    pub organizations: Vec<Organization>,
    collection_names: HashMap<String, String>,
    organization_names: HashMap<String, String>,
}

impl Directory {
    /// Où se trouve l'élément, `None` pour un élément personnel.
    pub fn sharing(&self, view: &CipherView) -> Option<Sharing> {
        let organization_id = view.organization_id?.to_string();
        let mut collections: Vec<(String, String)> = view
            .collection_ids
            .iter()
            .map(ToString::to_string)
            .filter_map(|id| {
                let name = self.collection_names.get(&id)?.clone();
                Some((id, name))
            })
            .collect();
        collections.sort_by_key(|(_, name)| name.to_lowercase());
        Some(Sharing {
            organization: self
                .organization_names
                .get(&organization_id)
                .cloned()
                .unwrap_or_else(|| "Organisation".to_owned()),
            organization_id,
            collections,
            read_only: !view.edit,
            hide_passwords: !view.view_password,
        })
    }
}

impl Connection {
    /// Organisations du profil et collections de la synchronisation, noms
    /// déchiffrés. Les clés des organisations sont déjà chargées
    /// (`init_organizations`).
    pub(crate) fn decrypt_directory(&self, sync: &SyncResponseModel) -> Directory {
        let mut organizations: Vec<Organization> = sync
            .profile
            .as_ref()
            .and_then(|p| p.organizations.as_ref())
            .into_iter()
            .flatten()
            // Sans clé (invitation pas encore confirmée), rien à déchiffrer.
            .filter(|org| org.key.is_some() && org.enabled != Some(false))
            .filter_map(|org| {
                use bitwarden_api_api::models::OrganizationUserType as Role;
                Some(Organization {
                    id: org.id?.to_string(),
                    name: org.name.clone().unwrap_or_default(),
                    admin: matches!(org.r#type, Some(Role::Owner | Role::Admin))
                        || org
                            .permissions
                            .as_ref()
                            .is_some_and(|p| p.edit_any_collection == Some(true)),
                    collections: Vec::new(),
                })
            })
            .collect();

        let encrypted: Vec<SdkCollection> = sync
            .collections
            .iter()
            .flatten()
            .filter_map(|c| {
                Some(SdkCollection {
                    id: c.id.map(CollectionId::new),
                    organization_id: OrganizationId::new(c.organization_id?),
                    name: c.name.as_ref()?.parse().ok()?,
                    external_id: None,
                    hide_passwords: c.hide_passwords.unwrap_or(false),
                    read_only: c.read_only.unwrap_or(false),
                    manage: c.manage.unwrap_or(false),
                    default_user_collection_email: None,
                    // Vaultwarden n'a que des collections partagées.
                    r#type: CollectionType::SharedCollection,
                })
            })
            .collect();
        // Une collection illisible (clé d'organisation absente) est ignorée.
        let decrypted = self
            .sdk
            .vault()
            .collections()
            .decrypt_list_with_failures(encrypted)
            .successes;

        let mut collection_names = HashMap::new();
        for view in decrypted {
            let Some(id) = view.id.map(|id| id.to_string()) else {
                continue;
            };
            let organization_id = view.organization_id.to_string();
            collection_names.insert(id.clone(), view.name.clone());
            if let Some(org) = organizations.iter_mut().find(|o| o.id == organization_id) {
                org.collections.push(Collection {
                    id,
                    name: view.name,
                    read_only: view.read_only,
                    hide_passwords: view.hide_passwords,
                    manage: view.manage,
                });
            }
        }
        for org in &mut organizations {
            org.collections.sort_by_key(|c| c.name.to_lowercase());
        }
        organizations.sort_by_key(|o| o.name.to_lowercase());
        let organization_names = organizations
            .iter()
            .map(|o| (o.id.clone(), o.name.clone()))
            .collect();
        Directory {
            organizations,
            collection_names,
            organization_names,
        }
    }

    /// Crée l'élément directement dans des collections d'une organisation ;
    /// rend son identifiant et le coffre resynchronisé.
    pub async fn create_shared(
        &mut self,
        draft: Draft,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<(String, Decrypted), Error> {
        let access = self
            .require_online("La création dans un coffre partagé")
            .await?;
        let (organization, collections) = self.destination(organization_id, collection_ids)?;
        let mut view = new_view(draft, Utc::now())?;
        // Le dossier reste personnel : seul ce compte le voit.
        view.organization_id = Some(organization);
        view.collection_ids.clone_from(&collections);
        let cipher = self.encrypt(view).await?;
        let mut request = CipherCreateRequestModel::new(cipher);
        request.collection_ids = Some(collections.into_iter().map(Into::into).collect());
        let body = self
            .api
            .send_json(
                reqwest::Method::POST,
                "/api/ciphers/create",
                &access,
                &request,
            )
            .await?;
        let id = body
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("élément créé sans identifiant".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// « Partager… » : déplace un élément personnel dans des collections
    /// d'une organisation. Il est rechiffré sous la clé de l'organisation,
    /// ses pièces jointes gardent leur contenu (leurs clés sont rechiffrées).
    pub async fn share(
        &mut self,
        id: &str,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<Decrypted, Error> {
        let access = self.require_online("Le partage").await?;
        let id = &self.resolve(id);
        let (organization, collections) = self.destination(organization_id, collection_ids)?;
        let mut view = self.editable_view(id).await?;
        if view.organization_id.is_some() {
            return Err(Error::Invalid(
                "cet élément est déjà dans une organisation".to_owned(),
            ));
        }
        view.move_to_organization(organization)
            .map_err(|e| match e {
                CipherError::AttachmentsWithoutKeys => Error::Invalid(
                    "ses pièces jointes datent d'un ancien format : partagez-le depuis le \
                     coffre web, qui les rechiffre"
                        .to_owned(),
                ),
                other => Error::crypto(other),
            })?;
        view.collection_ids.clone_from(&collections);
        let cipher = self.encrypt(view).await?;
        let request = CipherShareRequestModel::new(
            collections.iter().map(ToString::to_string).collect(),
            cipher,
        );
        self.api
            .send_json(
                reqwest::Method::PUT,
                &format!("/api/ciphers/{id}/share"),
                &access,
                &request,
            )
            .await?;
        self.sync_with(&access).await
    }

    /// Range un élément d'organisation dans d'autres collections (de la même
    /// organisation). Il faut pouvoir écrire dans chacune.
    pub async fn set_collections(
        &mut self,
        id: &str,
        collection_ids: &[String],
    ) -> Result<Decrypted, Error> {
        let access = self.require_online("Le changement de collections").await?;
        let id = &self.resolve(id);
        let view = self.editable_view(id).await?;
        let organization = view
            .organization_id
            .ok_or_else(|| Error::Invalid("cet élément n'est pas partagé".to_owned()))?;
        let (_, collections) = self.destination(&organization.to_string(), collection_ids)?;
        let request = CipherCollectionsRequestModel::new(
            collections.iter().map(ToString::to_string).collect(),
        );
        self.api
            .send_json(
                reqwest::Method::PUT,
                &format!("/api/ciphers/{id}/collections_v2"),
                &access,
                &request,
            )
            .await?;
        self.sync_with(&access).await
    }

    /// Vérifie la destination d'après le cache : organisation connue, au
    /// moins une collection, toutes de cette organisation et ouvertes en
    /// écriture à ce compte.
    fn destination(
        &self,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<(OrganizationId, Vec<CollectionId>), Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        let directory = self.decrypt_directory(&sync);
        let organization = directory
            .organizations
            .iter()
            .find(|o| o.id == organization_id)
            .ok_or_else(|| Error::Invalid("organisation inconnue".to_owned()))?;
        if collection_ids.is_empty() {
            return Err(Error::Invalid(
                "choisissez au moins une collection".to_owned(),
            ));
        }
        let mut collections = Vec::with_capacity(collection_ids.len());
        for id in collection_ids {
            let collection = organization
                .collections
                .iter()
                .find(|c| &c.id == id)
                .ok_or_else(|| {
                    Error::Invalid(format!("collection inconnue dans {}", organization.name))
                })?;
            if collection.read_only {
                return Err(Error::ReadOnly);
            }
            collections.push(id.parse().map_err(Error::crypto)?);
        }
        Ok((organization_id.parse().map_err(Error::crypto)?, collections))
    }
}
