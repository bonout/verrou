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
    CipherBulkShareRequestModel, CipherCollectionsRequestModel, CipherCreateRequestModel,
    CipherShareRequestModel, CipherWithIdRequestModel, SyncResponseModel,
};
use bitwarden_collections::collection::{
    Collection as SdkCollection, CollectionId, CollectionType,
};
use bitwarden_core::OrganizationId;
use bitwarden_vault::{CipherError, CipherView, VaultClientExt};
use chrono::Utc;
use verrou_core::Sharing;

use crate::bulk::{Progress, Skipped};
use crate::edit::new_view;
use crate::members::MemberRole;
use crate::{Connection, Decrypted, Draft, Error};

/// Une organisation dont le compte est membre confirmé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    /// Propriétaire, administrateur ou gestionnaire : gère les collections
    /// dans le coffre web.
    pub admin: bool,
    /// Rôle du compte dans l'organisation (`None` : inconnu du serveur).
    pub role: Option<MemberRole>,
    /// Collections visibles par le compte, triées par nom.
    pub collections: Vec<Collection>,
    /// Groupes activés sur le serveur (`ORG_GROUPS_ENABLED`).
    pub use_groups: bool,
    /// Créer des collections : propriétaire, administrateur, gestionnaire
    /// avec accès à toutes les collections.
    pub can_create_collections: bool,
}

impl Organization {
    /// Le compte peut-il y ranger un élément (au moins une collection où il
    /// a le droit d'écrire) ?
    pub fn is_writable(&self) -> bool {
        self.collections.iter().any(|c| !c.read_only)
    }

    /// Le compte gère-t-il cette collection (renommer, supprimer, choisir
    /// qui y accède) ? Les règles de Vaultwarden : propriétaire et
    /// administrateur partout ; gestionnaire avec accès complet partout,
    /// sinon là où il a le droit « gérer » ; un simple utilisateur jamais.
    pub fn can_manage_collection(&self, collection: &Collection) -> bool {
        match self.role {
            Some(MemberRole::Owner | MemberRole::Admin) => true,
            Some(MemberRole::Manager) => self.admin || collection.manage,
            _ => false,
        }
    }

    /// Une collection au moins à gérer, ou le droit d'en créer : l'écran
    /// des collections a quelque chose à proposer.
    pub fn manages_collections(&self) -> bool {
        self.can_create_collections
            || self
                .collections
                .iter()
                .any(|c| self.can_manage_collection(c))
    }

    /// Propriétaire : renommer l'organisation.
    pub fn can_rename(&self) -> bool {
        self.role == Some(MemberRole::Owner)
    }
}

/// Une organisation que le compte a rejointe sans encore en avoir la clé :
/// invitation acceptée, en attente de la confirmation d'un administrateur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMembership {
    pub organization_id: String,
    pub name: String,
}

/// Bilan d'un partage de plusieurs éléments.
pub struct ShareOutcome {
    /// Éléments passés dans l'organisation.
    pub shared: usize,
    /// Écartés avant tout envoi : (identifiant, raison).
    pub skipped: Vec<(String, Skipped)>,
    /// Refusés (par le SDK ou le serveur) : (titre, raison).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// Nombre d'éléments par requête de partage groupé : le serveur les traite
/// un par un, un lot raisonnable garde la requête de taille modeste.
const SHARE_BATCH: usize = 100;

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
                    role: org
                        .r#type
                        .as_ref()
                        .and_then(|t| MemberRole::from_code(t.as_i64())),
                    collections: Vec::new(),
                    use_groups: org.use_groups == Some(true),
                    can_create_collections: matches!(org.r#type, Some(Role::Owner | Role::Admin))
                        || org
                            .permissions
                            .as_ref()
                            .is_some_and(|p| p.create_new_collections == Some(true)),
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
            .map_err(share_error)?;
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

    /// « Partager… » sur plusieurs éléments : chacun est rechiffré sous la
    /// clé de l'organisation (clés des pièces jointes comprises, par le SDK)
    /// et tous partent en une requête (`PUT /api/ciphers/share`), par lots.
    /// Sont écartés sans envoi : les éléments déjà partagés, en lecture
    /// seule, dans la corbeille ou disparus. Un lot refusé (Vaultwarden
    /// s'arrête au premier élément refusé, les précédents restent partagés)
    /// est repris élément par élément, pour savoir lequel.
    pub async fn share_many(
        &mut self,
        ids: &[String],
        organization_id: &str,
        collection_ids: &[String],
        progress: Progress<'_>,
    ) -> Result<ShareOutcome, Error> {
        let access = self.require_online("Le partage").await?;
        let (organization, collections) = self.destination(organization_id, collection_ids)?;
        let collection_list: Vec<String> = collections.iter().map(ToString::to_string).collect();

        let (ready, skipped, mut failed) = self.plan_share(ids, organization, &collections).await?;
        let total = ready.len();
        let mut shared = 0;
        let mut batches = Vec::new();
        let mut rest = ready;
        while !rest.is_empty() {
            let tail = rest.split_off(rest.len().min(SHARE_BATCH));
            batches.push(std::mem::replace(&mut rest, tail));
        }
        for batch in batches {
            let request = CipherBulkShareRequestModel::new(
                collection_list.clone(),
                batch.iter().map(|(_, _, r)| r.clone()).collect(),
            );
            let sent = self
                .api
                .send_json(
                    reqwest::Method::PUT,
                    "/api/ciphers/share",
                    &access,
                    &request,
                )
                .await;
            match sent {
                Ok(_) => shared += batch.len(),
                Err(Error::Network(message)) => {
                    self.mark_offline();
                    return Err(Error::Network(message));
                }
                Err(_) => {
                    // Lot refusé : élément par élément. Ceux que le lot a déjà
                    // partagés sont refusés à leur tour (déjà dans
                    // l'organisation) : on les reconnaît à la resynchronisation.
                    let already = self.shared_ids(&access).await?;
                    for (id, title, cipher) in batch {
                        if already.contains(&id) {
                            shared += 1;
                            continue;
                        }
                        let request = serde_json::json!({
                            "cipher": without_id(&cipher)?,
                            "collectionIds": collection_list,
                        });
                        match self
                            .api
                            .send_json(
                                reqwest::Method::PUT,
                                &format!("/api/ciphers/{id}/share"),
                                &access,
                                &request,
                            )
                            .await
                        {
                            Ok(_) => shared += 1,
                            Err(error) => failed.push((title, error.to_string())),
                        }
                    }
                }
            }
            progress(shared, total);
        }
        let vault = self.sync_with(&access).await?;
        Ok(ShareOutcome {
            shared,
            skipped,
            failed,
            vault,
        })
    }

    /// Les éléments à partager (rechiffrés pour l'organisation), les
    /// écartés et les refusés avant tout envoi.
    #[allow(clippy::type_complexity)]
    async fn plan_share(
        &self,
        ids: &[String],
        organization: OrganizationId,
        collections: &[CollectionId],
    ) -> Result<
        (
            Vec<(String, String, CipherWithIdRequestModel)>,
            Vec<(String, Skipped)>,
            Vec<(String, String)>,
        ),
        Error,
    > {
        let mut ciphers: HashMap<String, _> = self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| Some((c.id?.to_string(), c)))
            .collect();
        let mut seen = std::collections::HashSet::new();
        let (mut skipped, mut failed) = (Vec::new(), Vec::new());
        // (identifiant, titre, requête chiffrée)
        let mut ready: Vec<(String, String, CipherWithIdRequestModel)> = Vec::new();
        for id in ids {
            let id = self.resolve(id);
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(cipher) = ciphers.remove(&id) else {
                skipped.push((id, Skipped::NotFound));
                continue;
            };
            let mut view = self.decrypt_view(cipher).await?;
            let reason = if view.organization_id.is_some() {
                Some(Skipped::AlreadyShared)
            } else if !view.edit || view.partial {
                Some(Skipped::ReadOnly)
            } else if view.deleted_date.is_some() {
                Some(Skipped::InTrash)
            } else {
                None
            };
            if let Some(reason) = reason {
                skipped.push((id, reason));
                continue;
            }
            let title = view.name.clone();
            if let Err(error) = view.move_to_organization(organization) {
                failed.push((title, share_error(error).to_string()));
                continue;
            }
            view.collection_ids = collections.to_vec();
            let request = match self.encrypt_context(view).await {
                Ok(encrypted) => {
                    CipherWithIdRequestModel::try_from(encrypted).map_err(Error::crypto)
                }
                Err(error) => Err(error),
            };
            match request {
                Ok(request) => ready.push((id, title, request)),
                Err(error) => failed.push((title, error.to_string())),
            }
        }

        Ok((ready, skipped, failed))
    }

    /// Les éléments d'organisation que le serveur connaît (synchronisation
    /// fraîche, enregistrée comme cache).
    async fn shared_ids(
        &mut self,
        access: &str,
    ) -> Result<std::collections::HashSet<String>, Error> {
        let json = self.api.sync(access).await?;
        let sync: SyncResponseModel = serde_json::from_str(&json)
            .map_err(|e| Error::Server(format!("synchronisation illisible ({e})")))?;
        Ok(sync
            .ciphers
            .into_iter()
            .flatten()
            .filter(|c| c.organization_id.is_some())
            .filter_map(|c| c.id.map(|id| id.to_string()))
            .collect())
    }

    /// Crée une organisation dont ce compte est propriétaire, avec une
    /// première collection, comme le coffre web : la clé de l'organisation
    /// est tirée au hasard par le SDK, chiffrée pour la clé publique du
    /// compte (RSA-OAEP) ; la paire de clés de l'organisation (sa clé privée
    /// chiffrée par la clé de l'organisation) sert aux invitations de
    /// Bitwarden. Le serveur ne voit aucune clé en clair. Il peut refuser
    /// (`ORG_CREATION_USERS` de Vaultwarden). Rend l'identifiant et le
    /// coffre resynchronisé.
    pub async fn create_organization(
        &mut self,
        name: &str,
        collection_name: &str,
    ) -> Result<(String, Decrypted), Error> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid(
                "le nom de l'organisation est obligatoire".to_owned(),
            ));
        }
        let collection_name = match collection_name.trim() {
            "" => "Général",
            other => other,
        };
        let access = self
            .require_online("La création d'une organisation")
            .await?;
        let body = self.new_organization_body(name, collection_name)?;
        let created = self
            .api
            .call(reqwest::Method::POST, &access, "organizations", Some(&body))
            .await
            .map_err(|error| match error {
                Error::Server(message) if message.contains("not allowed to create") => {
                    Error::Invalid(
                        "ce serveur ne vous permet pas de créer une organisation (réglage \
                         ORG_CREATION_USERS de Vaultwarden)"
                            .to_owned(),
                    )
                }
                other => other,
            })?;
        let id = created
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("organisation créée sans identifiant".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Le corps de `POST /api/organizations` : clés tirées et chiffrées dans
    /// le magasin de clés du SDK, sans jamais en sortir en clair.
    fn new_organization_body(
        &self,
        name: &str,
        collection_name: &str,
    ) -> Result<serde_json::Value, Error> {
        use bitwarden_core::key_management::PrivateKeySlotId;
        use bitwarden_crypto::{
            EncString, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
            UnsignedSharedKey,
        };
        let key_store = self.sdk.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        let org_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_private = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let org_public = ctx
            .get_public_key(org_private)
            .and_then(|p| p.to_der())
            .map_err(Error::crypto)?;
        let wrapped_private = ctx
            .wrap_private_key(org_key, org_private)
            .map_err(Error::crypto)?;
        let own_public = ctx
            .get_public_key(PrivateKeySlotId::UserPrivateKey)
            .map_err(|_| Error::Crypto("clé privée du compte indisponible".to_owned()))?;
        let key =
            UnsignedSharedKey::encapsulate(org_key, &own_public, &ctx).map_err(Error::crypto)?;
        let collection: EncString = collection_name
            .encrypt(&mut ctx, org_key)
            .map_err(Error::crypto)?;
        Ok(serde_json::json!({
            "name": name,
            "billingEmail": self.account.email,
            "collectionName": collection.to_string(),
            "key": key.to_string(),
            "keys": {
                "publicKey": data_encoding::BASE64.encode(org_public.as_ref()),
                "encryptedPrivateKey": wrapped_private.to_string(),
            },
            "planType": 0,
        }))
    }

    /// Renomme l'organisation (propriétaire seulement). L'adresse de
    /// facturation, que Vaultwarden demande aussi, est relue et gardée.
    pub async fn rename_organization(
        &mut self,
        organization_id: &str,
        name: &str,
    ) -> Result<Decrypted, Error> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid(
                "le nom de l'organisation est obligatoire".to_owned(),
            ));
        }
        if !self.organization(organization_id)?.can_rename() {
            return Err(Error::Invalid(
                "seul un propriétaire peut renommer l'organisation".to_owned(),
            ));
        }
        let access = self.require_online("Renommer l'organisation").await?;
        let path = format!("organizations/{organization_id}");
        let current = self
            .api
            .call(reqwest::Method::GET, &access, &path, None)
            .await?;
        let billing = current
            .get("billingEmail")
            .and_then(serde_json::Value::as_str)
            .filter(|b| !b.is_empty())
            .unwrap_or(&self.account.email)
            .to_owned();
        let body = serde_json::json!({ "name": name, "billingEmail": billing });
        self.api
            .call(reqwest::Method::PUT, &access, &path, Some(&body))
            .await?;
        self.sync_with(&access).await
    }

    /// Quitte l'organisation : ses éléments disparaissent du coffre de ce
    /// compte (ils restent dans l'organisation). Le dernier propriétaire ne
    /// peut pas partir.
    pub async fn leave_organization(&mut self, organization_id: &str) -> Result<Decrypted, Error> {
        let organization = self.organization(organization_id)?;
        let access = self.require_online("Quitter l'organisation").await?;
        self.api
            .call(
                reqwest::Method::POST,
                &access,
                &format!("organizations/{organization_id}/leave"),
                None,
            )
            .await
            .map_err(|error| match error {
                Error::Server(message) if message.contains("last owner") => {
                    Error::Invalid(format!(
                        "vous êtes le dernier propriétaire de {} : nommez un autre propriétaire \
                     avant de la quitter",
                        organization.name
                    ))
                }
                other => other,
            })?;
        self.sync_with(&access).await
    }

    /// Les organisations rejointes en attente de confirmation (invitation
    /// acceptée, clé pas encore reçue), d'après la dernière synchronisation.
    /// Vaultwarden les liste dans `profile.organizationsNew`.
    pub fn pending_memberships(&self) -> Vec<PendingMembership> {
        self.account
            .sync
            .as_deref()
            .map(parse_pending_memberships)
            .unwrap_or_default()
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

/// Les adhésions acceptées mais pas encore confirmées d'une synchronisation
/// (`profile.organizationsNew`, état 1), triées par nom. Seul le profil est
/// lu : le reste du document (les éléments, des mégaoctets dans un grand
/// coffre) est sauté sans être construit.
fn parse_pending_memberships(json: &str) -> Vec<PendingMembership> {
    #[derive(serde::Deserialize)]
    struct Sync {
        profile: Option<Profile>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Profile {
        #[serde(default)]
        organizations_new: Vec<Membership>,
    }
    #[derive(serde::Deserialize)]
    struct Membership {
        id: Option<String>,
        name: Option<String>,
        status: Option<i64>,
    }
    let Ok(sync) = serde_json::from_str::<Sync>(json) else {
        return Vec::new();
    };
    let mut pending: Vec<PendingMembership> = sync
        .profile
        .map(|p| p.organizations_new)
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.status == Some(1))
        .filter_map(|m| {
            Some(PendingMembership {
                organization_id: m.id?,
                name: m.name.unwrap_or_else(|| "Organisation".to_owned()),
            })
        })
        .collect();
    pending.sort_by_key(|p| p.name.to_lowercase());
    pending
}

/// Le message d'un refus du SDK au moment de partager.
fn share_error(error: CipherError) -> Error {
    match error {
        CipherError::AttachmentsWithoutKeys => Error::Invalid(
            "ses pièces jointes datent d'un ancien format (sans clé propre) : partagez-le \
             depuis le coffre web, qui les rechiffre"
                .to_owned(),
        ),
        other => Error::crypto(other),
    }
}

/// Le même élément chiffré, sans son identifiant (corps d'un seul
/// partage, `PUT /api/ciphers/{id}/share`).
fn without_id(with_id: &CipherWithIdRequestModel) -> Result<serde_json::Value, Error> {
    let mut value = serde_json::to_value(with_id).map_err(Error::crypto)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("id");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_memberships_come_from_organizations_new() {
        let json = r#"{"ciphers":[{"id":"c","name":"2.x"}],"profile":{"organizations":[],
            "organizationsNew":[
              {"id":"o2","name":"Zèbres","status":1,"key":null},
              {"id":"o1","name":"Famille","status":2,"key":"4.k"},
              {"id":"o3","name":"Atelier","status":1}
            ]}}"#;
        let pending = parse_pending_memberships(json);
        let names: Vec<&str> = pending.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Atelier", "Zèbres"], "confirmées écartées, triées");
        assert_eq!(parse_pending_memberships(r#"{"profile":{}}"#).len(), 0);
        assert_eq!(parse_pending_memberships("pas du json").len(), 0);
    }
}
