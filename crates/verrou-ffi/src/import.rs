//! Import depuis un autre gestionnaire (Apple, 1Password, Proton Pass) et
//! nettoyage des doublons du coffre.
//!
//! Même principe que le reste de l'interface : le fichier est lu ici, ses
//! secrets restent dans Rust jusqu'à l'import (ou l'abandon, ou le
//! verrouillage). Swift ne reçoit que titres, identifiants et sites, et le
//! verdict de la comparaison des mots de passe.

use std::io::Read;
use std::sync::PoisonError;

use verrou_core::duplicates::{self, Classification, Decision, Existing, Status};
use verrou_core::import::{self, Format, ImportKind, Parsed};
use verrou_vaultwarden::{Destination, ImportPlan};
use zeroize::Zeroizing;

use crate::{ItemCategory, ItemSummary, VaultSession, VerrouError, summary};

/// Un export lu, en attente de confirmation.
pub(crate) struct PendingImport {
    parsed: Parsed,
    classes: Vec<Classification>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportFormat {
    ApplePasswords,
    OnePassword1pux,
    OnePasswordCsv,
    ProtonPassZip,
    ProtonPassCsv,
}

impl From<ImportFormat> for Format {
    fn from(format: ImportFormat) -> Self {
        match format {
            ImportFormat::ApplePasswords => Self::ApplePasswordsCsv,
            ImportFormat::OnePassword1pux => Self::OnePassword1pux,
            ImportFormat::OnePasswordCsv => Self::OnePasswordCsv,
            ImportFormat::ProtonPassZip => Self::ProtonPassZip,
            ImportFormat::ProtonPassCsv => Self::ProtonPassCsv,
        }
    }
}

impl From<Format> for ImportFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::ApplePasswordsCsv => Self::ApplePasswords,
            Format::OnePassword1pux => Self::OnePassword1pux,
            Format::OnePasswordCsv => Self::OnePasswordCsv,
            Format::ProtonPassZip => Self::ProtonPassZip,
            Format::ProtonPassCsv => Self::ProtonPassCsv,
        }
    }
}

/// Libellé d'un format, pour le choisir à la main.
#[uniffi::export]
pub fn import_format_label(format: ImportFormat) -> String {
    Format::from(format).label().to_owned()
}

/// Un élément importé par rapport au coffre.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportStatus {
    New,
    /// Même site, identifiant et mot de passe qu'un élément du coffre.
    AlreadyPresent,
    /// Le même élément figure plus haut dans le fichier.
    RepeatedInFile,
    /// Déjà dans le coffre, mais l'import apporte un code à usage unique.
    AddsCode,
    /// Même site et identifiant qu'un élément du coffre, autre mot de passe.
    NewPassword,
    /// Même site et identifiant qu'un élément plus haut dans le fichier,
    /// autre mot de passe.
    ConflictInFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportChoice {
    /// Ne pas importer (garder l'existant).
    Skip,
    /// Créer l'élément (à côté de l'existant s'il y en a un).
    Create,
    /// Compléter l'élément du coffre : nouveau mot de passe (l'ancien
    /// rejoint son historique), code à usage unique.
    Update,
}

impl From<Decision> for ImportChoice {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Skip => Self::Skip,
            Decision::Create => Self::Create,
            Decision::Update => Self::Update,
        }
    }
}

/// Une ligne de la revue d'import. Aucun secret.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportEntry {
    pub category: ItemCategory,
    pub title: String,
    pub username: String,
    pub host: Option<String>,
    /// Dossier (ou coffre) dans l'application d'origine.
    pub folder: Option<String>,
    pub has_totp: bool,
    pub status: ImportStatus,
    /// Titre de l'élément déjà connu (dans le coffre, ou plus haut dans le
    /// fichier).
    pub existing_title: Option<String>,
    /// Choix proposé.
    pub choice: ImportChoice,
}

/// Un élément laissé de côté (ou non écrit), et pourquoi.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportSkipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportReview {
    pub format: ImportFormat,
    pub format_label: String,
    /// Application d'origine (« 1Password »…).
    pub source: String,
    pub entries: Vec<ImportEntry>,
    pub skipped: Vec<ImportSkipped>,
    /// L'export range ses éléments dans des dossiers (ou coffres).
    pub has_folders: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportDestination {
    NoFolder,
    /// Ce dossier, créé s'il n'existe pas.
    Folder {
        name: String,
    },
    /// Les dossiers (ou coffres) de l'application d'origine.
    OriginalFolders,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportOutcome {
    pub created: u32,
    pub updated: u32,
    pub failures: Vec<ImportSkipped>,
}

/// Des éléments du coffre qui désignent le même compte. Le premier est celui
/// qu'il est suggéré de garder.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DuplicateGroupView {
    pub label: String,
    pub username: String,
    /// Tous ont le même mot de passe : supprimer les autres ne perd rien.
    pub same_password: bool,
    pub items: Vec<ItemSummary>,
}

fn category(kind: ImportKind) -> ItemCategory {
    match kind {
        ImportKind::Login => ItemCategory::Login,
        ImportKind::SecureNote => ItemCategory::SecureNote,
        ImportKind::Card => ItemCategory::Card,
        ImportKind::Identity => ItemCategory::Identity,
    }
}

fn invalid(message: impl Into<String>) -> VerrouError {
    VerrouError::Invalid {
        message: message.into(),
    }
}

/// Le fichier d'export, lu une fois, effacé de la mémoire après usage.
fn read_export(path: &str) -> Result<Zeroizing<Vec<u8>>, VerrouError> {
    let file =
        std::fs::File::open(path).map_err(|e| invalid(format!("fichier illisible ({e})")))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(import::MAX_ARCHIVE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| invalid(format!("fichier illisible ({e})")))?;
    if bytes.len() as u64 > import::MAX_ARCHIVE_SIZE {
        return Err(invalid(import::ImportError::TooLarge.to_string()));
    }
    Ok(bytes)
}

impl VaultSession {
    fn review(&self, pending: &PendingImport) -> Result<ImportReview, VerrouError> {
        let items = &pending.parsed.items;
        self.with_vault(|vault| {
            let title_of = |existing: &Existing| match existing {
                Existing::Vault(id) => vault.get(id).map(|i| i.title.clone()),
                Existing::Import(index) => items.get(*index).map(|i| i.title.clone()),
            };
            let entries = items
                .iter()
                .zip(&pending.classes)
                .map(|(item, class)| {
                    let (status, existing_title) = match &class.status {
                        Status::New => (ImportStatus::New, None),
                        Status::Exact(e @ Existing::Vault(_)) => {
                            (ImportStatus::AlreadyPresent, title_of(e))
                        }
                        Status::Exact(e @ Existing::Import(_)) => {
                            (ImportStatus::RepeatedInFile, title_of(e))
                        }
                        Status::AddsTotp(id) => (
                            ImportStatus::AddsCode,
                            vault.get(id).map(|i| i.title.clone()),
                        ),
                        Status::NewPassword(e @ Existing::Vault(_)) => {
                            (ImportStatus::NewPassword, title_of(e))
                        }
                        Status::NewPassword(e @ Existing::Import(_)) => {
                            (ImportStatus::ConflictInFile, title_of(e))
                        }
                    };
                    ImportEntry {
                        category: category(item.kind),
                        title: item.title.clone(),
                        username: item.username.clone().unwrap_or_default(),
                        host: item.primary_host(),
                        folder: item.folder.clone(),
                        has_totp: item.totp.is_some(),
                        status,
                        existing_title,
                        choice: class.decision.into(),
                    }
                })
                .collect();
            let format = pending.parsed.format;
            Ok(ImportReview {
                format: format.into(),
                format_label: format.label().to_owned(),
                source: format.source().to_owned(),
                entries,
                skipped: pending
                    .parsed
                    .skipped
                    .iter()
                    .map(|s| ImportSkipped {
                        title: s.title.clone(),
                        reason: s.reason.clone(),
                    })
                    .collect(),
                has_folders: items.iter().any(|i| i.folder.is_some()),
            })
        })
    }

    /// Le plan d'import : les choix de l'utilisateur, ligne par ligne.
    fn plan(
        &self,
        choices: &[ImportChoice],
        destination: ImportDestination,
    ) -> Result<ImportPlan, VerrouError> {
        let guard = self
            .pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let pending = guard
            .as_ref()
            .ok_or_else(|| invalid("aucun import en attente"))?;
        if choices.len() != pending.parsed.items.len() {
            return Err(invalid("les choix ne correspondent plus au fichier"));
        }
        let mut plan = ImportPlan {
            create: Vec::new(),
            update: Vec::new(),
            destination: match destination {
                ImportDestination::NoFolder => Destination::None,
                ImportDestination::Folder { name } => Destination::Folder(name),
                ImportDestination::OriginalFolders => Destination::Original,
            },
        };
        for ((item, class), choice) in pending
            .parsed
            .items
            .iter()
            .zip(&pending.classes)
            .zip(choices)
        {
            match (choice, &class.status) {
                (ImportChoice::Create, _) => plan.create.push(item.clone()),
                (
                    ImportChoice::Update,
                    Status::AddsTotp(id) | Status::NewPassword(Existing::Vault(id)),
                ) => plan.update.push((id.clone(), item.clone())),
                // Rien à compléter dans le coffre : ignoré.
                (ImportChoice::Update | ImportChoice::Skip, _) => {}
            }
        }
        Ok(plan)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Lit un export choisi par l'utilisateur (`format` absent : reconnu
    /// d'après le contenu) et le compare au coffre. Rien n'est écrit : la
    /// revue attend `commit_import` ou `cancel_import`.
    pub async fn prepare_import(
        &self,
        path: String,
        format: Option<ImportFormat>,
    ) -> Result<ImportReview, VerrouError> {
        // Lecture et décompression : hors des fils de l'exécuteur.
        let parsed = tokio::task::spawn_blocking(move || {
            let bytes = read_export(&path)?;
            import::parse(&bytes, format.map(Into::into)).map_err(|e| invalid(e.to_string()))
        })
        .await
        .map_err(|e| invalid(e.to_string()))??;
        let classes = self.with_vault(|v| Ok(duplicates::classify(&parsed.items, v.items())))?;
        let pending = PendingImport { parsed, classes };
        let review = self.review(&pending)?;
        *self
            .pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(pending);
        Ok(review)
    }

    /// Importe selon les choix (un par ligne de la revue), en une requête,
    /// puis resynchronise. Les positions de `summaries()` changent.
    pub async fn commit_import(
        &self,
        choices: Vec<ImportChoice>,
        destination: ImportDestination,
    ) -> Result<ImportOutcome, VerrouError> {
        let plan = self.plan(&choices, destination)?;
        let Some(connection) = self.current_connection() else {
            return Err(invalid("coffre fictif : lecture seule"));
        };
        let report = connection.lock().await.import(plan).await?;
        self.cancel_import();
        let outcome = ImportOutcome {
            created: report.created as u32,
            updated: report.updated as u32,
            failures: report
                .failures
                .into_iter()
                .map(|(title, reason)| ImportSkipped { title, reason })
                .collect(),
        };
        self.install_written(&connection, report.vault)?;
        Ok(outcome)
    }

    /// Met ces éléments à la corbeille du serveur en une requête
    /// (restaurables depuis le coffre web), puis resynchronise.
    pub async fn trash_items(&self, ids: Vec<String>) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.trash_many(&ids).await?;
        self.install_if_current(&connection, decrypted)
    }
}

#[uniffi::export]
impl VaultSession {
    /// Oublie l'export en attente (et ses secrets).
    pub fn cancel_import(&self) {
        self.pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Les groupes de doublons du coffre, triés par site.
    pub fn duplicates(&self) -> Result<Vec<DuplicateGroupView>, VerrouError> {
        self.with_vault(|vault| {
            Ok(duplicates::find_duplicates(vault.items())
                .into_iter()
                .map(|group| DuplicateGroupView {
                    label: group.label,
                    username: group.username,
                    same_password: group.same_password,
                    items: group
                        .items
                        .iter()
                        .filter_map(|id| vault.get(id))
                        .map(summary)
                        .collect(),
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn session() -> Arc<VaultSession> {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        session
    }

    #[test]
    fn review_never_carries_secrets_and_lock_forgets_the_file() {
        let session = session();
        let github = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == "GitHub")
            .unwrap();
        let password = session.reveal(github.id, "password".into()).unwrap();
        let csv = format!(
            "Title,URL,Username,Password,Notes,OTPAuth\n\
             GitHub,https://github.com,camille.martin,{password},,\n\
             Nouveau,https://nouveau.fr,camille,secret-tres-long-1234,,\n"
        );
        let path = std::env::temp_dir().join(format!("verrou-import-{}.csv", std::process::id()));
        std::fs::write(&path, csv).unwrap();
        let review = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(session.prepare_import(path.display().to_string(), None))
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(review.format, ImportFormat::ApplePasswords);
        assert_eq!(review.entries[1].status, ImportStatus::New);
        assert_eq!(review.entries[1].choice, ImportChoice::Create);
        let debug = format!("{review:?}");
        assert!(!debug.contains("secret-tres-long-1234"));
        assert!(!debug.contains(&password));

        // Coffre fictif : rien ne s'écrit, et l'import reste en attente.
        let choices = review.entries.iter().map(|e| e.choice).collect();
        assert!(matches!(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(session.commit_import(choices, ImportDestination::NoFolder)),
            Err(VerrouError::Invalid { .. })
        ));
        assert!(session.pending_import.lock().unwrap().is_some());
        session.lock();
        assert!(session.pending_import.lock().unwrap().is_none());
    }

    #[test]
    fn self_hosted_services_are_not_duplicates() {
        // Nextcloud, Vaultwarden et Jellyfin du coffre fictif : même domaine,
        // même identifiant, mais trois services.
        assert_eq!(session().duplicates().unwrap().len(), 0);
    }
}
