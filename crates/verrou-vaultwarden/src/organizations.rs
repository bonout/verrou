//! Vaultwarden organizations: the shared vaults.
//!
//! Reading: each organization's key arrives in the profile, encrypted
//! (RSA-OAEP) with the account's public key; the SDK decrypts it with the
//! private key (`initialize_org_crypto`), then decrypts with it the names
//! of the collections and the organization's items.
//!
//! Writing: a shared item is encrypted with the organization's key
//! (the SDK picks it from `organization_id`). Creating in a collection
//! goes through `POST /api/ciphers/create`, sharing a personal item through
//! `PUT /api/ciphers/{id}/share` (re-encrypted under the organization's key,
//! attachment keys included), changing its collections through
//! `PUT /api/ciphers/{id}/collections_v2`. The rights (read-only,
//! hidden passwords) are those the server announces; it checks them
//! anyway on every write.

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

/// An organization the account is a confirmed member of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    /// Owner, admin or manager: manages the collections
    /// in the web vault.
    pub admin: bool,
    /// The account's role in the organization (`None`: unknown to the server).
    pub role: Option<MemberRole>,
    /// Collections visible to the account, sorted by name.
    pub collections: Vec<Collection>,
    /// Groups enabled on the server (`ORG_GROUPS_ENABLED`).
    pub use_groups: bool,
    /// Create collections: owner, admin, manager
    /// with access to all collections.
    pub can_create_collections: bool,
}

impl Organization {
    /// Can the account put an item in it (at least one collection where it
    /// may write)?
    pub fn is_writable(&self) -> bool {
        self.collections.iter().any(|c| !c.read_only)
    }

    /// Does the account manage this collection (rename, delete, choose
    /// who accesses it)? Vaultwarden's rules: owner and
    /// admin everywhere; manager with full access everywhere,
    /// otherwise where they have the "manage" right; a plain user never.
    pub fn can_manage_collection(&self, collection: &Collection) -> bool {
        match self.role {
            Some(MemberRole::Owner | MemberRole::Admin) => true,
            Some(MemberRole::Manager) => self.admin || collection.manage,
            _ => false,
        }
    }

    /// At least one collection to manage, or the right to create one: the
    /// collections screen has something to offer.
    pub fn manages_collections(&self) -> bool {
        self.can_create_collections
            || self
                .collections
                .iter()
                .any(|c| self.can_manage_collection(c))
    }

    /// Owner: rename the organization.
    pub fn can_rename(&self) -> bool {
        self.role == Some(MemberRole::Owner)
    }
}

/// An organization the account joined without having its key yet:
/// invitation accepted, waiting for an admin's confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMembership {
    pub organization_id: String,
    pub name: String,
}

/// Outcome of sharing several items.
pub struct ShareOutcome {
    /// Items moved into the organization.
    pub shared: usize,
    /// Skipped before any request: (id, reason).
    pub skipped: Vec<(String, Skipped)>,
    /// Refused (by the SDK or the server): (title, reason).
    pub failed: Vec<(String, String)>,
    pub vault: Decrypted,
}

/// Number of items per bulk share request: the server handles them
/// one by one, a reasonable batch keeps the request modest in size.
const SHARE_BATCH: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub name: String,
    /// The account can view, not modify.
    pub read_only: bool,
    /// The account does not see the passwords (it can fill).
    pub hide_passwords: bool,
    /// The account manages the collection (members, rights).
    pub manage: bool,
}

/// Organizations and collections, to attach each item to its own.
#[derive(Default)]
pub(crate) struct Directory {
    pub organizations: Vec<Organization>,
    collection_names: HashMap<String, String>,
    organization_names: HashMap<String, String>,
}

impl Directory {
    /// Where the item is, `None` for a personal item.
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
                .unwrap_or_else(|| "Organization".to_owned()),
            organization_id,
            collections,
            read_only: !view.edit,
            hide_passwords: !view.view_password,
        })
    }
}

impl Connection {
    /// The profile's organizations and the sync's collections, names
    /// decrypted. The organization keys are already loaded
    /// (`init_organizations`).
    pub(crate) fn decrypt_directory(&self, sync: &SyncResponseModel) -> Directory {
        let mut organizations: Vec<Organization> = sync
            .profile
            .as_ref()
            .and_then(|p| p.organizations.as_ref())
            .into_iter()
            .flatten()
            // Without a key (invitation not confirmed yet), nothing to decrypt.
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
                    // Vaultwarden only has shared collections.
                    r#type: CollectionType::SharedCollection,
                })
            })
            .collect();
        // An unreadable collection (missing organization key) is ignored.
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

    /// Creates the item directly in collections of an organization;
    /// returns its id and the resynced vault.
    pub async fn create_shared(
        &mut self,
        draft: Draft,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<(String, Decrypted), Error> {
        let access = self.require_online("Creating in a shared vault").await?;
        let (organization, collections) = self.destination(organization_id, collection_ids)?;
        let mut view = new_view(draft, Utc::now())?;
        // The folder stays personal: only this account sees it.
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
            .ok_or_else(|| Error::Server("item created without an id".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// "Share…": moves a personal item into collections
    /// of an organization. It is re-encrypted under the organization's key,
    /// its attachments keep their content (their keys are re-encrypted).
    pub async fn share(
        &mut self,
        id: &str,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<Decrypted, Error> {
        let access = self.require_online("Sharing").await?;
        let id = &self.resolve(id);
        let (organization, collections) = self.destination(organization_id, collection_ids)?;
        let mut view = self.editable_view(id).await?;
        if view.organization_id.is_some() {
            return Err(Error::Invalid(
                "this item is already in an organization".to_owned(),
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

    /// Puts an organization item in other collections (of the same
    /// organization). Writing must be allowed in each one.
    pub async fn set_collections(
        &mut self,
        id: &str,
        collection_ids: &[String],
    ) -> Result<Decrypted, Error> {
        let access = self.require_online("Changing collections").await?;
        let id = &self.resolve(id);
        let view = self.editable_view(id).await?;
        let organization = view
            .organization_id
            .ok_or_else(|| Error::Invalid("this item is not shared".to_owned()))?;
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

    /// "Share…" on several items: each is re-encrypted under the
    /// organization's key (attachment keys included, by the SDK)
    /// and all go in one request (`PUT /api/ciphers/share`), in batches.
    /// Skipped without a request: items already shared, read-only,
    /// in the trash or gone. A refused batch (Vaultwarden
    /// stops at the first refused item, the previous ones stay shared)
    /// is retried item by item, to find out which one.
    pub async fn share_many(
        &mut self,
        ids: &[String],
        organization_id: &str,
        collection_ids: &[String],
        progress: Progress<'_>,
    ) -> Result<ShareOutcome, Error> {
        let access = self.require_online("Sharing").await?;
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
                    // Batch refused: item by item. Those the batch already
                    // shared are refused in turn (already in
                    // the organization): they are recognized by the resync.
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

    /// The items to share (re-encrypted for the organization), the
    /// skipped and the refused ones before any request.
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
        // (id, title, encrypted request)
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

    /// The organization items the server knows (fresh
    /// sync, saved as the cache).
    async fn shared_ids(
        &mut self,
        access: &str,
    ) -> Result<std::collections::HashSet<String>, Error> {
        let json = self.api.sync(access).await?;
        let sync: SyncResponseModel = serde_json::from_str(&json)
            .map_err(|e| Error::Server(format!("unreadable sync ({e})")))?;
        Ok(sync
            .ciphers
            .into_iter()
            .flatten()
            .filter(|c| c.organization_id.is_some())
            .filter_map(|c| c.id.map(|id| id.to_string()))
            .collect())
    }

    /// Creates an organization owned by this account, with a
    /// first collection, like the web vault: the organization's key
    /// is drawn at random by the SDK, encrypted for the account's public
    /// key (RSA-OAEP); the organization's key pair (its private key
    /// encrypted by the organization's key) is used for Bitwarden
    /// invitations. The server sees no key in clear. It may refuse
    /// (Vaultwarden's `ORG_CREATION_USERS`). Returns the id and the
    /// resynced vault.
    pub async fn create_organization(
        &mut self,
        name: &str,
        collection_name: &str,
    ) -> Result<(String, Decrypted), Error> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid(
                "the organization name is required".to_owned(),
            ));
        }
        let collection_name = match collection_name.trim() {
            "" => "General",
            other => other,
        };
        let access = self.require_online("Creating an organization").await?;
        let body = self.new_organization_body(name, collection_name)?;
        let created = self
            .api
            .call(reqwest::Method::POST, &access, "organizations", Some(&body))
            .await
            .map_err(|error| match error {
                Error::Server(message) if message.contains("not allowed to create") => {
                    Error::Invalid(
                        "this server does not allow you to create an organization (Vaultwarden's \
                         ORG_CREATION_USERS setting)"
                            .to_owned(),
                    )
                }
                other => other,
            })?;
        let id = created
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("organization created without an id".to_owned()))?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// The body of `POST /api/organizations`: keys drawn and encrypted in
    /// the SDK's key store, never leaving it in clear.
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
            .map_err(|_| Error::Crypto("the account's private key is unavailable".to_owned()))?;
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

    /// Renames the organization (owner only). The billing
    /// address, which Vaultwarden also requires, is read back and kept.
    pub async fn rename_organization(
        &mut self,
        organization_id: &str,
        name: &str,
    ) -> Result<Decrypted, Error> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid(
                "the organization name is required".to_owned(),
            ));
        }
        if !self.organization(organization_id)?.can_rename() {
            return Err(Error::Invalid(
                "only an owner can rename the organization".to_owned(),
            ));
        }
        let access = self.require_online("Renaming the organization").await?;
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

    /// Leaves the organization: its items disappear from this account's
    /// vault (they stay in the organization). The last owner cannot
    /// leave.
    pub async fn leave_organization(&mut self, organization_id: &str) -> Result<Decrypted, Error> {
        let organization = self.organization(organization_id)?;
        let access = self.require_online("Leaving the organization").await?;
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
                        "you are the last owner of {}: appoint another owner \
                     before leaving it",
                        organization.name
                    ))
                }
                other => other,
            })?;
        self.sync_with(&access).await
    }

    /// The joined organizations waiting for confirmation (invitation
    /// accepted, key not received yet), from the last sync.
    /// Vaultwarden lists them in `profile.organizationsNew`.
    pub fn pending_memberships(&self) -> Vec<PendingMembership> {
        self.account
            .sync
            .as_deref()
            .map(parse_pending_memberships)
            .unwrap_or_default()
    }

    /// Checks the destination from the cache: known organization, at
    /// least one collection, all of this organization and open for
    /// writing to this account.
    fn destination(
        &self,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<(OrganizationId, Vec<CollectionId>), Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("unreadable cache ({e})")))?;
        let directory = self.decrypt_directory(&sync);
        let organization = directory
            .organizations
            .iter()
            .find(|o| o.id == organization_id)
            .ok_or_else(|| Error::Invalid("unknown organization".to_owned()))?;
        if collection_ids.is_empty() {
            return Err(Error::Invalid("choose at least one collection".to_owned()));
        }
        let mut collections = Vec::with_capacity(collection_ids.len());
        for id in collection_ids {
            let collection = organization
                .collections
                .iter()
                .find(|c| &c.id == id)
                .ok_or_else(|| {
                    Error::Invalid(format!("unknown collection in {}", organization.name))
                })?;
            if collection.read_only {
                return Err(Error::ReadOnly);
            }
            collections.push(id.parse().map_err(Error::crypto)?);
        }
        Ok((organization_id.parse().map_err(Error::crypto)?, collections))
    }
}

/// The memberships accepted but not yet confirmed in a sync
/// (`profile.organizationsNew`, status 1), sorted by name. Only the profile is
/// read: the rest of the document (the items, megabytes in a large
/// vault) is skipped without being built.
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
                name: m.name.unwrap_or_else(|| "Organization".to_owned()),
            })
        })
        .collect();
    pending.sort_by_key(|p| p.name.to_lowercase());
    pending
}

/// The message of an SDK refusal when sharing.
fn share_error(error: CipherError) -> Error {
    match error {
        CipherError::AttachmentsWithoutKeys => Error::Invalid(
            "its attachments use an old format (without their own key): share it \
             from the web vault, which re-encrypts them"
                .to_owned(),
        ),
        other => Error::crypto(other),
    }
}

/// The same encrypted item, without its id (body of a single
/// share, `PUT /api/ciphers/{id}/share`).
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
        assert_eq!(
            names,
            ["Atelier", "Zèbres"],
            "confirmed ones skipped, sorted"
        );
        assert_eq!(parse_pending_memberships(r#"{"profile":{}}"#).len(), 0);
        assert_eq!(parse_pending_memberships("not json").len(), 0);
    }
}
