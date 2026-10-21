//! Bulk writes: import of an export (Apple, 1Password, Proton Pass) and
//! trashing of several items.
//!
//! Creating hundreds of items one by one would sync the vault each time.
//! The import therefore goes through `POST /api/ciphers/import`, the web
//! vault's: each item is encrypted by the SDK like a creation, then
//! everything goes in one request (in batches of 500), followed by a single
//! sync. Existing items being completed (new password, one-time code) go
//! through the usual edit, without a sync in between. Items carrying files
//! (1Password, Proton Pass) are created one by one, each followed by its
//! attachments (`attachments`). Bulk trashing uses
//! `PUT /api/ciphers/delete`, restorable like a single item's trash.

use std::collections::{BTreeSet, HashMap};

use bitwarden_api_api::models::{
    CipherRequestModel, FolderWithIdRequestModel, ImportCiphersRequestModel, Int32Int32KeyValuePair,
};
use bitwarden_vault::{CardView, CipherType, FolderView, IdentityView, VaultClientExt};
use chrono::{DateTime, Utc};
use verrou_core::SecretString;
use verrou_core::import::{ImportKind, ImportedItem};
use verrou_core::matching::host_of;
use verrou_core::template;

use crate::edit::{apply, draft_of, new_view};
use crate::{Connection, CustomFieldDraft, CustomFieldKind, Decrypted, Draft, Error, LoginDraft};

/// Items per request: well below Vaultwarden's request size limit
/// (20 MB).
pub(crate) const BATCH: usize = 500;

/// Maximum length of encrypted notes, enforced by Vaultwarden.
const MAX_ENCRYPTED_NOTES: usize = 10_000;

/// Where to put the items created by an import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// No folder.
    None,
    /// This folder, created if it doesn't exist.
    Folder(String),
    /// Each item's folder (or vault) in the original application, created if
    /// it doesn't exist.
    Original,
}

/// What an import writes.
#[derive(Clone, Debug)]
pub struct ImportPlan {
    /// Items to create.
    pub create: Vec<ImportedItem>,
    /// Vault items to complete (item id, imported item): new password (the
    /// old one joins the history), one-time code and notes if missing, sites
    /// on other hosts.
    pub update: Vec<(String, ImportedItem)>,
    pub destination: Destination,
}

/// Outcome of an import.
pub struct ImportReport {
    pub created: usize,
    pub updated: usize,
    /// Title of each item not written, and why.
    pub failures: Vec<(String, String)>,
    /// The resynced vault.
    pub vault: Decrypted,
}

impl Connection {
    /// Imports the plan's items, then syncs once.
    ///
    /// Returns an error only if nothing was written; after that, each
    /// failure is recorded in the report and the import goes on.
    pub async fn import(&mut self, plan: ImportPlan) -> Result<ImportReport, Error> {
        // The items to complete start from their server version.
        self.require_online("Importing").await?;
        let now = Utc::now();
        let mut failures = Vec::new();

        // Encrypt everything before writing anything.
        let mut ciphers: Vec<(Option<String>, CipherRequestModel)> = Vec::new();
        let mut with_files: Vec<(Option<String>, &ImportedItem)> = Vec::new();
        for item in &plan.create {
            let folder = match &plan.destination {
                Destination::None => None,
                Destination::Folder(name) => Some(name.trim().to_owned()),
                Destination::Original => item.folder.as_ref().map(|f| f.trim().to_owned()),
            }
            .filter(|f| !f.is_empty());
            if !item.attachments.is_empty() {
                // With files: created separately, to know its id.
                with_files.push((folder, item));
                continue;
            }
            let request = self.encrypt(import_view(item, now)?).await?;
            if request
                .notes
                .as_ref()
                .is_some_and(|n| n.len() > MAX_ENCRYPTED_NOTES)
            {
                failures.push((
                    item.title.clone(),
                    "notes too long for Vaultwarden".to_owned(),
                ));
                continue;
            }
            ciphers.push((folder, request));
        }
        let updates = self.merged(&plan.update, now, &mut failures).await?;

        let access = self.access_token().await?;
        let wanted: BTreeSet<String> = ciphers
            .iter()
            .map(|(f, _)| f)
            .chain(with_files.iter().map(|(f, _)| f))
            .filter_map(Clone::clone)
            .collect();
        let folders = self.ensure_folders(&access, wanted).await?;

        let mut created = 0;
        for batch in ciphers.chunks(BATCH) {
            let request = import_request(batch, &folders);
            match self.api.import_ciphers(&access, &request).await {
                Ok(()) => created += batch.len(),
                Err(error) if created == 0 && updates.is_empty() && failures.is_empty() => {
                    return Err(error);
                }
                Err(error) => {
                    failures.push((format!("{} item(s)", batch.len()), error.to_string()));
                }
            }
        }

        // Items with attachments: one by one, the item then its files; if a
        // file doesn't go through, the item is removed.
        for (folder, item) in with_files {
            let mut view = import_view(item, now)?;
            view.folder_id = folder
                .and_then(|f| folders.get(&f))
                .and_then(|(id, _)| id.parse().ok());
            match self.create_with_files(view, &item.attachments).await {
                Ok(_) => created += 1,
                Err(error) => failures.push((item.title.clone(), error.to_string())),
            }
        }

        let mut amended = 0;
        for (id, title, request) in updates {
            match self.api.update_cipher(&access, &id, &request).await {
                Ok(()) => amended += 1,
                Err(error) => failures.push((title, error.to_string())),
            }
        }

        let vault = self.sync_with(&access).await?;
        Ok(ImportReport {
            created,
            updated: amended,
            failures,
            vault,
        })
    }

    /// Moves several items to the server's trash (restorable from the web
    /// vault), then syncs once. Items the account can't edit are refused
    /// before anything is sent. Offline, each one waits for the server in
    /// the queue.
    pub async fn trash_many(&mut self, ids: &[String]) -> Result<Decrypted, Error> {
        let access = self.online().await?;
        let mut ids: Vec<String> = ids.iter().map(|id| self.resolve(id)).collect();
        ids.sort();
        ids.dedup();
        let views = self.editable_views(&ids).await?;
        if let Some(access) = access {
            let mut sent = Ok(());
            for batch in ids.chunks(BATCH) {
                sent = self.api.trash_ciphers(&access, batch).await;
                if sent.is_err() {
                    break;
                }
            }
            match sent {
                Ok(()) => return self.sync_with(&access).await,
                // Nothing went out (first batch): everything waits in the queue.
                Err(Error::Network(_)) if ids.len() <= BATCH => self.mark_offline(),
                Err(error) => return Err(error),
            }
        }
        let now = Utc::now();
        for (id, view) in ids.into_iter().zip(views) {
            self.outbox
                .push_action(id, view.name, crate::outbox::Action::Trash, now);
        }
        self.persist_outbox()?;
        self.decrypt_cache().await
    }

    /// The items to complete, re-encrypted. An item that can no longer be
    /// found or became read-only is recorded among the failures.
    async fn merged(
        &self,
        updates: &[(String, ImportedItem)],
        now: DateTime<Utc>,
        failures: &mut Vec<(String, String)>,
    ) -> Result<Vec<(String, String, CipherRequestModel)>, Error> {
        let mut merged = Vec::with_capacity(updates.len());
        for (id, item) in updates {
            let mut view = match self.editable_view(id).await {
                Ok(view) => view,
                Err(error @ (Error::NotFound | Error::ReadOnly)) => {
                    failures.push((item.title.clone(), error.to_string()));
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut draft = draft_of(view.clone());
            if !complete(&mut draft, item) {
                failures.push((
                    item.title.clone(),
                    "the vault item is not a login".to_owned(),
                ));
                continue;
            }
            apply(&mut view, draft, now)?;
            merged.push((id.clone(), item.title.clone(), self.encrypt(view).await?));
        }
        Ok(merged)
    }

    /// Id and encrypted name of each wanted folder (by name): the existing
    /// one, otherwise a created folder.
    pub(crate) async fn ensure_folders(
        &self,
        access: &str,
        wanted: BTreeSet<String>,
    ) -> Result<HashMap<String, (String, String)>, Error> {
        if wanted.is_empty() {
            return Ok(HashMap::new());
        }
        let existing: HashMap<String, String> = self
            .cached_folders()?
            .into_iter()
            .map(|(id, name)| (name, id))
            .collect();
        let mut ids = HashMap::new();
        for name in wanted {
            // The name only goes out encrypted, even for an existing folder.
            // As for reading, the SDK's "high-level" method: Verrou doesn't
            // use its state storage.
            #[allow(deprecated)]
            let encrypted = self
                .sdk
                .vault()
                .folders()
                .encrypt(FolderView {
                    id: None,
                    name: name.clone(),
                    revision_date: Utc::now(),
                })
                .map_err(Error::crypto)?
                .name
                .to_string();
            let id = match existing.get(&name) {
                Some(id) => id.clone(),
                None => self.api.create_folder(access, &encrypted).await?,
            };
            ids.insert(name, (id, encrypted));
        }
        Ok(ids)
    }
}

/// Carries an imported item over to the draft of a vault login: password
/// (the old one will join the history), username, one-time code and notes
/// if missing, sites on missing hosts. `false` if the vault item is not a
/// login.
fn complete(draft: &mut Draft, item: &ImportedItem) -> bool {
    let Some(login) = draft.login.as_mut() else {
        return false;
    };
    if item.password.is_some() {
        login.password.clone_from(&item.password);
    }
    // A likely duplicate without a username in the vault: the import gives it.
    if login
        .username
        .as_deref()
        .is_none_or(|u| u.trim().is_empty())
    {
        login.username.clone_from(&item.username);
    }
    if login.totp.as_ref().is_none_or(SecretString::is_empty) {
        login.totp.clone_from(&item.totp);
    }
    let hosts: Vec<String> = login.uris.iter().filter_map(|u| host_of(u)).collect();
    for url in &item.urls {
        if host_of(url).is_some_and(|h| !hosts.contains(&h)) && !login.uris.contains(url) {
            login.uris.push(url.clone());
        }
    }
    if draft.notes.is_none() {
        draft.notes.clone_from(&item.notes);
    }
    true
}

/// The item to create, decrypted: login, secure note, card or identity,
/// with its template's field if it has one.
fn import_view(
    item: &ImportedItem,
    now: DateTime<Utc>,
) -> Result<bitwarden_vault::CipherView, Error> {
    let login = (item.kind == ImportKind::Login).then(|| LoginDraft {
        uri_matches: None,
        username: item.username.clone(),
        password: item.password.clone(),
        totp: item.totp.clone(),
        uris: item.urls.clone(),
    });
    let fields = item
        .fields
        .iter()
        .map(|f| CustomFieldDraft {
            // A name reserved for Verrou coming from elsewhere must not pass
            // for a template.
            name: if template::is_reserved(&f.name) {
                format!("({})", f.name)
            } else {
                f.name.clone()
            },
            value: Some(f.value.clone()),
            kind: if f.hidden {
                CustomFieldKind::Hidden
            } else {
                CustomFieldKind::Text
            },
            linked_id: None,
        })
        .collect();
    let mut view = new_view(
        Draft {
            name: item.title.clone(),
            folder_id: None,
            favorite: item.favorite,
            notes: item.notes.clone(),
            login,
            fields: Some(fields),
            template: item.template,
            card: None,
            identity: None,
        },
        now,
    )?;
    if item.kind == ImportKind::Identity {
        let id = item.identity.clone().unwrap_or_default();
        let secret = |s: Option<SecretString>| s.map(|s| s.expose().to_owned());
        view.r#type = CipherType::Identity;
        view.secure_note = None;
        view.identity = Some(IdentityView {
            title: id.title,
            first_name: id.first_name,
            middle_name: id.middle_name,
            last_name: id.last_name,
            address1: id.address1,
            address2: id.address2,
            address3: None,
            city: id.city,
            state: id.state,
            postal_code: id.postal_code,
            country: id.country,
            company: id.company,
            email: id.email,
            phone: id.phone,
            ssn: secret(id.ssn),
            username: id.username,
            passport_number: secret(id.passport_number),
            license_number: secret(id.license_number),
        });
    }
    if item.kind == ImportKind::Card {
        let card = item.card.clone().unwrap_or_default();
        view.r#type = CipherType::Card;
        view.secure_note = None;
        view.card = Some(CardView {
            cardholder_name: card.cardholder,
            exp_month: card.exp_month,
            exp_year: card.exp_year,
            code: card.code.map(|c| c.expose().to_owned()),
            brand: card.brand,
            number: card.number.map(|n| n.expose().to_owned()),
        });
    }
    Ok(view)
}

/// An import request: the items, and the folders (existing, designated by
/// their id) to put them in.
fn import_request(
    batch: &[(Option<String>, CipherRequestModel)],
    folders: &HashMap<String, (String, String)>,
) -> ImportCiphersRequestModel {
    let mut used: Vec<&(String, String)> = Vec::new();
    let mut relationships = Vec::new();
    for (index, (folder, _)) in batch.iter().enumerate() {
        let Some(target) = folder.as_ref().and_then(|f| folders.get(f)) else {
            continue;
        };
        let position = used
            .iter()
            .position(|u| u.0 == target.0)
            .unwrap_or_else(|| {
                used.push(target);
                used.len() - 1
            });
        relationships.push(Int32Int32KeyValuePair {
            key: i32::try_from(index).ok(),
            value: i32::try_from(position).ok(),
        });
    }
    ImportCiphersRequestModel {
        // Vaultwarden files into an existing folder when its id is given
        // (the encrypted name is then not used).
        folders: Some(
            used.iter()
                .map(|(id, name)| FolderWithIdRequestModel {
                    name: name.clone(),
                    id: id.parse().ok(),
                })
                .collect(),
        ),
        ciphers: Some(batch.iter().map(|(_, c)| c.clone()).collect()),
        folder_relationships: Some(relationships),
    }
}

#[cfg(test)]
mod tests {

    use bitwarden_vault::FieldType;
    use verrou_core::Template;
    use verrou_core::import::{CardData, ExtraField, IdentityData};

    use super::*;

    fn imported(kind: ImportKind) -> ImportedItem {
        ImportedItem {
            kind,
            title: "Exemple".to_owned(),
            username: Some("camille".to_owned()),
            password: Some(SecretString::new("nouveau")),
            urls: vec![
                "https://exemple.fr".to_owned(),
                "https://autre.fr".to_owned(),
            ],
            totp: Some(SecretString::new("JBSWY3DPEHPK3PXP")),
            notes: None,
            folder: Some("Perso".to_owned()),
            favorite: true,
            card: None,
            identity: None,
            template: None,
            fields: vec![ExtraField {
                name: "PIN".to_owned(),
                value: SecretString::new("1234"),
                hidden: true,
            }],
            modified: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn identities_and_templates_become_bitwarden_views() {
        let mut person = imported(ImportKind::Identity);
        person.identity = Some(IdentityData {
            first_name: Some("Camille".to_owned()),
            city: Some("Annecy".to_owned()),
            passport_number: Some(SecretString::new("12AB34567")),
            ..IdentityData::default()
        });
        let view = import_view(&person, Utc::now()).unwrap();
        assert_eq!(view.r#type, CipherType::Identity);
        assert!(view.secure_note.is_none() && view.login.is_none());
        let identity = view.identity.unwrap();
        assert_eq!(identity.first_name.as_deref(), Some("Camille"));
        assert_eq!(identity.passport_number.as_deref(), Some("12AB34567"));

        let mut wifi = imported(ImportKind::SecureNote);
        wifi.template = Some(Template::Wifi);
        wifi.fields.push(ExtraField {
            name: "verrou:type".to_owned(),
            value: SecretString::new("passport"),
            hidden: false,
        });
        let view = import_view(&wifi, Utc::now()).unwrap();
        assert_eq!(view.r#type, CipherType::SecureNote);
        let fields = view.fields.unwrap();
        let names: Vec<_> = fields.iter().filter_map(|f| f.name.as_deref()).collect();
        assert_eq!(names, ["PIN", "(verrou:type)", "verrou:type"]);
        assert_eq!(fields[2].value.as_deref(), Some("wifi"));

        let mut server = imported(ImportKind::Login);
        server.template = Some(Template::Server);
        let view = import_view(&server, Utc::now()).unwrap();
        assert_eq!(view.r#type, CipherType::Login);
        assert_eq!(view.login.unwrap().username.as_deref(), Some("camille"));
        assert_eq!(
            view.fields.unwrap().last().unwrap().value.as_deref(),
            Some("server")
        );
    }

    #[test]
    fn cards_and_fields_become_bitwarden_views() {
        let mut item = imported(ImportKind::Card);
        item.card = Some(CardData {
            number: Some(SecretString::new("4242424242424242")),
            exp_month: Some("09".to_owned()),
            exp_year: Some("2029".to_owned()),
            ..CardData::default()
        });
        let view = import_view(&item, Utc::now()).unwrap();
        assert_eq!(view.r#type, CipherType::Card);
        assert!(view.login.is_none() && view.secure_note.is_none());
        assert_eq!(
            view.card.unwrap().number.as_deref(),
            Some("4242424242424242")
        );
        let fields = view.fields.unwrap();
        assert_eq!(fields[0].r#type, FieldType::Hidden);
        assert!(view.favorite);
    }

    #[test]
    fn completing_keeps_the_existing_seed_and_adds_new_hosts() {
        let mut draft = Draft {
            name: "Exemple".to_owned(),
            login: Some(LoginDraft {
                uri_matches: None,
                username: Some("camille".to_owned()),
                password: Some(SecretString::new("ancien")),
                totp: Some(SecretString::new("AUTRE")),
                uris: vec!["https://www.exemple.fr/connexion".to_owned()],
            }),
            ..Draft::default()
        };
        assert!(complete(&mut draft, &imported(ImportKind::Login)));
        let login = draft.login.unwrap();
        assert_eq!(login.password.unwrap().expose(), "nouveau");
        assert_eq!(login.totp.unwrap().expose(), "AUTRE");
        assert_eq!(
            login.uris,
            vec!["https://www.exemple.fr/connexion", "https://autre.fr"]
        );
        let mut note = Draft::default();
        assert!(!complete(&mut note, &imported(ImportKind::Login)));
    }

    #[test]
    fn folders_are_referenced_by_id() {
        let folders = HashMap::from([(
            "Perso".to_owned(),
            (
                "0b1e3a62-4d64-4f3f-9a3c-1d2c3b4a5f6e".to_owned(),
                "2.chiffré".to_owned(),
            ),
        )]);
        let batch = vec![
            (None, CipherRequestModel::default()),
            (Some("Perso".to_owned()), CipherRequestModel::default()),
        ];
        let request = import_request(&batch, &folders);
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["folders"][0]["id"],
            "0b1e3a62-4d64-4f3f-9a3c-1d2c3b4a5f6e"
        );
        assert_eq!(json["folders"][0]["name"], "2.chiffré");
        assert_eq!(json["folderRelationships"][0]["key"], 1);
        assert_eq!(json["folderRelationships"][0]["value"], 0);
        assert_eq!(json["ciphers"].as_array().unwrap().len(), 2);
    }
}
