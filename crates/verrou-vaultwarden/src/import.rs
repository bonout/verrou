//! Écritures en masse : import d'un export (Apple, 1Password, Proton Pass)
//! et corbeille de plusieurs éléments.
//!
//! Créer des centaines d'éléments un par un synchroniserait le coffre à
//! chaque fois. L'import passe donc par `POST /api/ciphers/import`, celui du
//! coffre web : chaque élément est chiffré par le SDK comme une création,
//! puis tout part en une requête (par lot de 500), suivie d'une seule
//! synchronisation. Les éléments déjà présents qu'on complète (nouveau mot de
//! passe, code à usage unique) passent par la modification habituelle, sans
//! synchronisation entre deux. La corbeille en masse utilise
//! `PUT /api/ciphers/delete`, restaurable comme la corbeille d'un élément.

use std::collections::{BTreeSet, HashMap};

use bitwarden_api_api::models::{
    CipherRequestModel, FolderWithIdRequestModel, ImportCiphersRequestModel, Int32Int32KeyValuePair,
};
use bitwarden_vault::{CardView, CipherType, FieldType, FieldView, FolderView, VaultClientExt};
use chrono::{DateTime, Utc};
use verrou_core::SecretString;
use verrou_core::import::{ImportKind, ImportedItem};
use verrou_core::matching::host_of;

use crate::edit::{apply, draft_of, new_view};
use crate::{Connection, Decrypted, Draft, Error, LoginDraft};

/// Éléments par requête : bien en deçà de la limite de taille des requêtes
/// de Vaultwarden (20 Mo).
const BATCH: usize = 500;

/// Longueur maximale des notes chiffrées, imposée par Vaultwarden.
const MAX_ENCRYPTED_NOTES: usize = 10_000;

/// Où ranger les éléments créés par un import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// Aucun dossier.
    None,
    /// Ce dossier, créé s'il n'existe pas.
    Folder(String),
    /// Le dossier (ou coffre) de chaque élément dans l'application d'origine,
    /// créé s'il n'existe pas.
    Original,
}

/// Ce qu'un import écrit.
#[derive(Clone, Debug)]
pub struct ImportPlan {
    /// Éléments à créer.
    pub create: Vec<ImportedItem>,
    /// Éléments du coffre à compléter (identifiant de l'élément, élément
    /// importé) : nouveau mot de passe (l'ancien rejoint l'historique), code
    /// à usage unique et notes s'ils manquent, sites d'autres hôtes.
    pub update: Vec<(String, ImportedItem)>,
    pub destination: Destination,
}

/// Bilan d'un import.
pub struct ImportReport {
    pub created: usize,
    pub updated: usize,
    /// Titre de chaque élément non écrit, et pourquoi.
    pub failures: Vec<(String, String)>,
    /// Le coffre resynchronisé.
    pub vault: Decrypted,
}

impl Connection {
    /// Importe les éléments du plan, puis synchronise une fois.
    ///
    /// Rend une erreur seulement si rien n'a été écrit ; ensuite, chaque
    /// échec est noté dans le bilan et l'import continue.
    pub async fn import(&mut self, plan: ImportPlan) -> Result<ImportReport, Error> {
        let now = Utc::now();
        let mut failures = Vec::new();

        // Tout chiffrer avant d'écrire quoi que ce soit.
        let mut ciphers: Vec<(Option<String>, CipherRequestModel)> = Vec::new();
        for item in &plan.create {
            let folder = match &plan.destination {
                Destination::None => None,
                Destination::Folder(name) => Some(name.trim().to_owned()),
                Destination::Original => item.folder.as_ref().map(|f| f.trim().to_owned()),
            }
            .filter(|f| !f.is_empty());
            let request = self.encrypt(import_view(item, now)?).await?;
            if request
                .notes
                .as_ref()
                .is_some_and(|n| n.len() > MAX_ENCRYPTED_NOTES)
            {
                failures.push((
                    item.title.clone(),
                    "notes trop longues pour Vaultwarden".to_owned(),
                ));
                continue;
            }
            ciphers.push((folder, request));
        }
        let updates = self.merged(&plan.update, now, &mut failures).await?;

        let access = self.access_token().await?;
        let wanted: BTreeSet<String> = ciphers.iter().filter_map(|(f, _)| f.clone()).collect();
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
                    failures.push((format!("{} élément(s)", batch.len()), error.to_string()));
                }
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

    /// Met plusieurs éléments à la corbeille du serveur (restaurables depuis
    /// le coffre web), puis synchronise une fois. Les éléments que le compte
    /// ne peut pas modifier sont refusés avant tout envoi.
    pub async fn trash_many(&mut self, ids: &[String]) -> Result<Decrypted, Error> {
        let mut ids = ids.to_vec();
        ids.sort();
        ids.dedup();
        self.editable_views(&ids).await?;
        let access = self.access_token().await?;
        for batch in ids.chunks(BATCH) {
            self.api.trash_ciphers(&access, batch).await?;
        }
        self.sync_with(&access).await
    }

    /// Les éléments à compléter, rechiffrés. Un élément devenu introuvable
    /// ou en lecture seule est noté parmi les échecs.
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
                    "l'élément du coffre n'est pas un identifiant".to_owned(),
                ));
                continue;
            }
            apply(&mut view, draft, now)?;
            merged.push((id.clone(), item.title.clone(), self.encrypt(view).await?));
        }
        Ok(merged)
    }

    /// Identifiant et nom chiffré de chaque dossier voulu (par nom) : celui
    /// qui existe déjà, sinon un dossier créé.
    async fn ensure_folders(
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
            // Le nom ne part que chiffré, même pour un dossier existant.
            // Comme pour la lecture, la méthode « de haut niveau » du SDK :
            // Verrou n'utilise pas son stockage d'état.
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

/// Reporte un élément importé sur le brouillon d'un identifiant du coffre :
/// mot de passe (l'ancien rejoindra l'historique), code à usage unique et
/// notes s'ils manquent, sites d'hôtes absents. `false` si l'élément du
/// coffre n'est pas un identifiant.
fn complete(draft: &mut Draft, item: &ImportedItem) -> bool {
    let Some(login) = draft.login.as_mut() else {
        return false;
    };
    if item.password.is_some() {
        login.password.clone_from(&item.password);
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

/// L'élément à créer, déchiffré : identifiant, note sécurisée ou carte.
fn import_view(
    item: &ImportedItem,
    now: DateTime<Utc>,
) -> Result<bitwarden_vault::CipherView, Error> {
    let login = (item.kind == ImportKind::Login).then(|| LoginDraft {
        username: item.username.clone(),
        password: item.password.clone(),
        totp: item.totp.clone(),
        uris: item.urls.clone(),
    });
    let mut view = new_view(
        Draft {
            name: item.title.clone(),
            folder_id: None,
            favorite: item.favorite,
            notes: item.notes.clone(),
            login,
        },
        now,
    )?;
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
    if !item.fields.is_empty() {
        view.fields = Some(
            item.fields
                .iter()
                .map(|f| FieldView {
                    name: Some(f.name.clone()),
                    value: Some(f.value.expose().to_owned()),
                    r#type: if f.hidden {
                        FieldType::Hidden
                    } else {
                        FieldType::Text
                    },
                    linked_id: None,
                })
                .collect(),
        );
    }
    Ok(view)
}

/// Une requête d'import : les éléments, et les dossiers (existants,
/// désignés par leur identifiant) où les ranger.
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
        // Vaultwarden range dans un dossier existant quand son identifiant
        // est donné (le nom, chiffré, ne sert alors pas).
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

    use verrou_core::import::{CardData, ExtraField};

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
            fields: vec![ExtraField {
                name: "PIN".to_owned(),
                value: SecretString::new("1234"),
                hidden: true,
            }],
            modified: None,
        }
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
