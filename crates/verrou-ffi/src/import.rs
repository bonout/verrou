//! Import from another password manager (Apple, 1Password, Proton Pass) and
//! cleanup of the vault's duplicates.
//!
//! Same principle as the rest of the interface: the file is read here, its
//! secrets stay in Rust until the import (or it is abandoned, or the vault
//! is locked). Swift only receives titles, usernames and sites, and the
//! verdict of the password comparison.

use std::io::Read;
use std::sync::PoisonError;

use std::collections::HashMap;

use verrou_core::duplicates::{
    self, Classification, Confidence, Decision, DuplicateGroup, Existing, ItemExtras, Status,
};
use verrou_core::import::{self, Format, ImportKind, Parsed};
use verrou_vaultwarden::{Destination, ImportPlan};
use zeroize::Zeroizing;

use crate::{ItemCategory, ItemSummary, VaultSession, VerrouError, summary};
use verrou_core::Item;

/// An export that was read, awaiting confirmation.
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

/// Label of a format, to pick it by hand.
#[uniffi::export]
pub fn import_format_label(format: ImportFormat) -> String {
    Format::from(format).label().to_owned()
}

/// An imported item compared to the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportStatus {
    New,
    /// Same site, username and password as a vault item.
    AlreadyPresent,
    /// The same item appears earlier in the file.
    RepeatedInFile,
    /// Already in the vault, but the import brings a one-time code.
    AddsCode,
    /// Same site and username as a vault item, different password.
    NewPassword,
    /// Same site and username as an item earlier in the file,
    /// different password.
    ConflictInFile,
    /// Looks like a vault item, same password (a missing username,
    /// a title without a site): to complete rather than create.
    Similar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportChoice {
    /// Don't import (keep the existing one).
    Skip,
    /// Create the item (next to the existing one if there is one).
    Create,
    /// Complete the vault item: new password (the old one
    /// joins its history), one-time code.
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

/// One row of the import review. No secret.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportEntry {
    pub category: ItemCategory,
    pub title: String,
    pub username: String,
    pub host: Option<String>,
    /// Folder (or vault) in the source application.
    pub folder: Option<String>,
    pub has_totp: bool,
    pub status: ImportStatus,
    /// Title of the already known item (in the vault, or earlier in the
    /// file).
    pub existing_title: Option<String>,
    /// Why it looks like it ("same site (maif.fr), same username,
    /// different password"); empty for a new item.
    pub reason: String,
    /// Suggested choice.
    pub choice: ImportChoice,
}

/// An item left aside (or not written), and why.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportSkipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportReview {
    pub format: ImportFormat,
    pub format_label: String,
    /// Source application ("1Password"...).
    pub source: String,
    pub entries: Vec<ImportEntry>,
    pub skipped: Vec<ImportSkipped>,
    /// The export stores its items in folders (or vaults).
    pub has_folders: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportDestination {
    NoFolder,
    /// This folder, created if it doesn't exist.
    Folder {
        name: String,
    },
    /// The folders (or vaults) of the source application.
    OriginalFolders,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportOutcome {
    pub created: u32,
    pub updated: u32,
    pub failures: Vec<ImportSkipped>,
}

/// Degree of certainty of a duplicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum DuplicateConfidence {
    /// Same site, same username, same password: checked by default.
    Certain,
    /// Suggested, not checked.
    Probable,
    /// To check: never checked.
    Review,
}

impl From<Confidence> for DuplicateConfidence {
    fn from(confidence: Confidence) -> Self {
        match confidence {
            Confidence::Certain => Self::Certain,
            Confidence::Probable => Self::Probable,
            Confidence::Review => Self::Review,
        }
    }
}

/// An item of a duplicate group. No secret.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DuplicateMemberView {
    pub item: ItemSummary,
    /// Resemblance to the kept item; `None` for the kept item.
    pub confidence: Option<DuplicateConfidence>,
    /// Why, in plain words; empty for the kept item.
    pub reason: String,
    /// Checked by default for the trash (certain duplicate).
    pub preselected: bool,
}

/// Vault items that designate the same account. The first one is the one
/// it is suggested to keep.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DuplicateGroupView {
    /// Fingerprint of the set of items: to ignore the group.
    pub key: String,
    pub label: String,
    pub username: String,
    pub confidence: DuplicateConfidence,
    /// The reason for this degree ("same site (maif.fr), same username, same
    /// password").
    pub reason: String,
    /// All have the same password: deleting the others loses nothing.
    pub same_password: bool,
    /// Logins: "Merge" is possible.
    pub mergeable: bool,
    pub members: Vec<DuplicateMemberView>,
}

/// Result of a merge.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MergeReport {
    /// Sites added to the kept item.
    pub sites: u32,
    pub username: bool,
    pub totp: bool,
    pub notes: u32,
    pub fields: u32,
    /// Passwords added to its history.
    pub history: u32,
    /// The current password comes from another, more recent item.
    pub newer_password: bool,
    /// Items moved to the trash.
    pub trashed: u32,
}

/// The view of a group, with the summary of each item.
fn group_view(
    group: DuplicateGroup,
    describe: impl Fn(&str) -> Option<ItemSummary>,
) -> Option<DuplicateGroupView> {
    let members = group
        .members
        .into_iter()
        .map(|m| {
            Some(DuplicateMemberView {
                item: describe(&m.id)?,
                confidence: m.confidence.map(Into::into),
                reason: m.reason,
                preselected: m.preselected,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(DuplicateGroupView {
        key: group.key,
        label: group.label,
        username: group.username,
        confidence: group.confidence.into(),
        reason: group.reason,
        same_password: group.same_password,
        mergeable: group.mergeable,
        members,
    })
}

/// Mock duplicates (imports from Apple, 1Password and Proton Pass), for
/// the visual review of the duplicates sheet. Outside any vault.
#[uniffi::export]
pub fn demo_duplicates(language: crate::MockLanguage) -> Vec<DuplicateGroupView> {
    let items = verrou_core::mock::duplicate_items(language.into());
    let by_id: HashMap<&str, &Item> = items.iter().map(|i| (i.id.as_str(), i)).collect();
    duplicates::find_duplicates(&items)
        .into_iter()
        .filter_map(|g| group_view(g, |id| by_id.get(id).map(|i| summary(i))))
        .collect()
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

/// The export file, read once, wiped from memory after use.
fn read_export(path: &str) -> Result<Zeroizing<Vec<u8>>, VerrouError> {
    let file = std::fs::File::open(path).map_err(|e| invalid(format!("unreadable file ({e})")))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(import::MAX_ARCHIVE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| invalid(format!("unreadable file ({e})")))?;
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
                        Status::NewPassword(e @ Existing::Import(_))
                        | Status::Similar(e @ Existing::Import(_)) => {
                            (ImportStatus::ConflictInFile, title_of(e))
                        }
                        Status::Similar(e @ Existing::Vault(_)) => {
                            (ImportStatus::Similar, title_of(e))
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
                        reason: class.reason.clone().unwrap_or_default(),
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

    /// The import plan: the user's choices, row by row.
    fn plan(
        &self,
        choices: &[ImportChoice],
        destination: ImportDestination,
    ) -> Result<ImportPlan, VerrouError> {
        let guard = self
            .pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let pending = guard.as_ref().ok_or_else(|| invalid("no pending import"))?;
        if choices.len() != pending.parsed.items.len() {
            return Err(invalid("the choices no longer match the file"));
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
                    Status::AddsTotp(id)
                    | Status::NewPassword(Existing::Vault(id))
                    | Status::Similar(Existing::Vault(id)),
                ) => plan.update.push((id.clone(), item.clone())),
                // Nothing to complete in the vault: ignored.
                (ImportChoice::Update | ImportChoice::Skip, _) => {}
            }
        }
        Ok(plan)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Reads an export chosen by the user (`format` absent: detected
    /// from the content) and compares it to the vault. Nothing is written: the
    /// review waits for `commit_import` or `cancel_import`.
    pub async fn prepare_import(
        &self,
        path: String,
        format: Option<ImportFormat>,
    ) -> Result<ImportReview, VerrouError> {
        // Reading and decompression: off the executor threads.
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

    /// Imports according to the choices (one per review row), in one request,
    /// then resyncs. The positions in `summaries()` change.
    pub async fn commit_import(
        &self,
        choices: Vec<ImportChoice>,
        destination: ImportDestination,
    ) -> Result<ImportOutcome, VerrouError> {
        let plan = self.plan(&choices, destination)?;
        let Some(connection) = self.current_connection() else {
            return Err(invalid("mock vault: read-only"));
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

    /// The vault's duplicate groups, most certain first. Passkeys and
    /// attachments (counted in the cache, without network)
    /// decide which item to keep.
    pub async fn duplicates(&self) -> Result<Vec<DuplicateGroupView>, VerrouError> {
        let attachments = match self.current_connection() {
            Some(connection) => connection.lock().await.attachment_counts()?,
            None => HashMap::new(),
        };
        self.with_vault(|vault| {
            let mut extras: HashMap<String, ItemExtras> = HashMap::new();
            for passkey in vault.passkeys() {
                extras
                    .entry(passkey.item.clone())
                    .or_default()
                    .passkey_sites
                    .push(passkey.rp_id.clone());
            }
            for (id, count) in attachments {
                extras.entry(id).or_default().attachments = count;
            }
            Ok(duplicates::find_duplicates_with(vault.items(), &extras)
                .into_iter()
                .filter_map(|group| {
                    group_view(group, |id| vault.get(id).map(|i| self.summary_of(i)))
                })
                .collect())
        })
    }

    /// Merges `others` into `keep` (sites, code, notes, fields, old
    /// passwords), then moves them to the trash; resyncs. Offline,
    /// everything waits in the queue.
    pub async fn merge_duplicates(
        &self,
        keep: String,
        others: Vec<String>,
    ) -> Result<MergeReport, VerrouError> {
        let Some(connection) = self.current_connection() else {
            return Err(invalid("mock vault: read-only"));
        };
        let outcome = connection
            .lock()
            .await
            .merge_duplicates(&keep, &others)
            .await?;
        let summary = outcome.summary;
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let report = MergeReport {
            sites: count(summary.uris),
            username: summary.username,
            totp: summary.totp,
            notes: count(summary.notes),
            fields: count(summary.fields),
            history: count(summary.history),
            newer_password: summary.newer_password,
            trashed: count(outcome.trashed),
        };
        self.install_written(&connection, outcome.vault)?;
        Ok(report)
    }

    /// Moves these items to the server's trash in one request
    /// (restorable from the web vault), then resyncs.
    pub async fn trash_items(&self, ids: Vec<String>) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection.lock().await.trash_many(&ids).await?;
        self.install_if_current(&connection, decrypted)
    }
}

#[uniffi::export]
impl VaultSession {
    /// Forgets the pending export (and its secrets).
    pub fn cancel_import(&self) {
        self.pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn session() -> Arc<VaultSession> {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, crate::MockLanguage::English);
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

        // Mock vault: nothing is written, and the import stays pending.
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
        // Nextcloud, Vaultwarden and Jellyfin in the mock vault: same domain,
        // same username, but three services.
        let groups = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(session().duplicates())
            .unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn demo_duplicates_carry_no_secret() {
        for (language, site, password) in [
            (crate::MockLanguage::English, "geico.com", "geico-Lilac-42"),
            (crate::MockLanguage::French, "maif.fr", "maif-Lilas-42"),
        ] {
            let groups = demo_duplicates(language);
            assert_eq!(groups.len(), 8);
            assert_eq!(groups[0].confidence, DuplicateConfidence::Certain);
            assert_eq!(
                groups.last().unwrap().confidence,
                DuplicateConfidence::Review
            );
            let insurer = groups.iter().find(|g| g.label == site).unwrap();
            assert_eq!(insurer.members.len(), 4);
            assert!(insurer.members[1].preselected && !insurer.members[3].preselected);
            let debug = format!("{groups:?}");
            for secret in [password, "JBSWY3DPEHPK3PXP", "4242 4242"] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn merging_needs_a_server() {
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(session().merge_duplicates("a".into(), vec!["b".into()]));
        assert!(matches!(result, Err(VerrouError::Invalid { .. })));
    }
}
