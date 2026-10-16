//! Réglages propres à l'appareil : règles de correspondance des sites
//! (défaut et dossiers) et registre de dernière utilisation des éléments.
//!
//! Ni l'un ni l'autre ne part au serveur : Bitwarden n'a ni règle par
//! dossier, ni règle par défaut partagée, ni date de dernière utilisation.
//! Les fichiers vivent dans le dossier du compte, partagé avec l'extension de
//! remplissage automatique de l'iPhone :
//!
//! - `match-rules.json` : la règle par défaut et celles des dossiers (par
//!   identifiant de dossier) ;
//! - `usage.json` : identifiants d'éléments et horodatages, rien d'autre.

use std::collections::HashMap;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

use verrou_core::UriMatch;
use verrou_core::matching::{DeviceMatchSettings, MatchRules};
use verrou_core::search::fold;
use verrou_core::usage::UsageLog;

use crate::{VaultSession, VerrouError};

pub(crate) const MATCH_RULES_FILE: &str = "match-rules.json";
pub(crate) const USAGE_FILE: &str = "usage.json";

/// Règle de correspondance d'un site (`UriMatchType` de Bitwarden).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UriMatchRule {
    Domain,
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
}

impl From<UriMatch> for UriMatchRule {
    fn from(rule: UriMatch) -> Self {
        match rule {
            UriMatch::Domain => Self::Domain,
            UriMatch::Host => Self::Host,
            UriMatch::StartsWith => Self::StartsWith,
            UriMatch::Exact => Self::Exact,
            UriMatch::RegularExpression => Self::RegularExpression,
            UriMatch::Never => Self::Never,
        }
    }
}

impl From<UriMatchRule> for UriMatch {
    fn from(rule: UriMatchRule) -> Self {
        match rule {
            UriMatchRule::Domain => Self::Domain,
            UriMatchRule::Host => Self::Host,
            UriMatchRule::StartsWith => Self::StartsWith,
            UriMatchRule::Exact => Self::Exact,
            UriMatchRule::RegularExpression => Self::RegularExpression,
            UriMatchRule::Never => Self::Never,
        }
    }
}

/// Nom affiché d'une règle (« Domaine de base », « Hôte »…).
#[uniffi::export]
pub fn uri_match_label(rule: UriMatchRule) -> String {
    UriMatch::from(rule).label().to_owned()
}

/// Toutes les règles, dans l'ordre de Bitwarden.
#[uniffi::export]
pub fn uri_match_rules() -> Vec<UriMatchRule> {
    UriMatch::ALL.into_iter().map(Into::into).collect()
}

/// La règle d'un dossier, réglée sur cet appareil.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderMatchRule {
    pub folder_id: String,
    /// Nom du dossier (vide s'il n'existe plus).
    pub folder_name: String,
    pub rule: UriMatchRule,
}

/// Les réglages de correspondance de l'appareil.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MatchSettingsView {
    pub default_rule: UriMatchRule,
    /// Dossiers qui ont leur propre règle, par nom.
    pub folder_rules: Vec<FolderMatchRule>,
    /// Groupes de domaines équivalents du compte (réglages Bitwarden, lus
    /// sur le serveur).
    pub equivalent_domains: Vec<Vec<String>>,
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl VaultSession {
    /// Réglages de correspondance enregistrés (défaut : domaine de base).
    pub(crate) fn load_match_settings(&self) -> DeviceMatchSettings {
        self.store
            .as_ref()
            .and_then(|s| s.read_file(MATCH_RULES_FILE))
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    /// Les règles du coffre : celles de l'appareil (dossiers par nom) et les
    /// domaines équivalents du compte.
    pub(crate) fn match_rules(
        settings: &DeviceMatchSettings,
        folders: &[(String, String)],
        equivalent_domains: Vec<Vec<String>>,
    ) -> MatchRules {
        let names: HashMap<&str, &str> = folders
            .iter()
            .map(|(id, name)| (id.as_str(), name.as_str()))
            .collect();
        MatchRules {
            default: settings.default,
            folders: settings
                .folders
                .iter()
                .filter_map(|(id, rule)| Some((fold(names.get(id.as_str())?), *rule)))
                .collect(),
            equivalent_domains,
        }
    }

    /// Réapplique les réglages au coffre ouvert.
    fn apply_match_settings(&self, settings: &DeviceMatchSettings) {
        let folders: Vec<(String, String)> = self
            .folders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|f| (f.id.clone(), f.name.clone()))
            .collect();
        let equivalent = self
            .equivalent_domains
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let rules = Self::match_rules(settings, &folders, equivalent);
        if let Some(vault) = self
            .vault
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            vault.set_match_rules(rules);
        }
    }

    fn save_match_settings(&self, settings: &DeviceMatchSettings) -> Result<(), VerrouError> {
        if let Some(store) = &self.store {
            let data = serde_json::to_vec_pretty(settings).map_err(|e| VerrouError::Storage {
                message: e.to_string(),
            })?;
            store.write_file(MATCH_RULES_FILE, &data)?;
        }
        *self
            .match_settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = settings.clone();
        self.apply_match_settings(settings);
        Ok(())
    }

    // MARK: Dernière utilisation

    /// Relit le registre du disque (l'extension de remplissage y écrit
    /// aussi) et le fusionne avec celui en mémoire.
    pub(crate) fn reload_usage(&self) {
        let Some(on_disk) = self
            .store
            .as_ref()
            .and_then(|s| s.read_file(USAGE_FILE))
            .map(|data| UsageLog::from_json(&data))
        else {
            return;
        };
        self.usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .merge(&on_disk);
    }

    /// Note une utilisation de l'élément (remplissage, copie, secret
    /// affiché) et l'écrit aussitôt. Une erreur d'écriture est ignorée : le
    /// registre n'est qu'une commodité.
    pub(crate) fn record_use(&self, id: &str) {
        let on_disk = self
            .store
            .as_ref()
            .and_then(|s| s.read_file(USAGE_FILE))
            .map(|data| UsageLog::from_json(&data));
        let data = {
            let mut usage = self.usage.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(on_disk) = on_disk {
                usage.merge(&on_disk);
            }
            usage.record(id, now());
            usage.to_json()
        };
        if let Some(store) = &self.store {
            let _ = store.write_file(USAGE_FILE, &data);
        }
    }

    /// Reporte la date d'un élément sur son nouvel identifiant.
    pub(crate) fn rename_use(&self, from: &str, to: &str) {
        let data = {
            let mut usage = self.usage.lock().unwrap_or_else(PoisonError::into_inner);
            if usage.last_used(from).is_none() {
                return;
            }
            usage.rename(from, to);
            usage.to_json()
        };
        if let Some(store) = &self.store {
            let _ = store.write_file(USAGE_FILE, &data);
        }
    }

    pub(crate) fn last_used_map(&self) -> HashMap<String, i64> {
        self.usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .clone()
    }

    pub(crate) fn last_used(&self, id: &str) -> Option<i64> {
        self.usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_used(id)
    }
}

#[uniffi::export]
impl VaultSession {
    /// Règles de correspondance de l'appareil, et domaines équivalents du
    /// compte.
    pub fn match_settings(&self) -> MatchSettingsView {
        let settings = self
            .match_settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let folders = self.folders.read().unwrap_or_else(PoisonError::into_inner);
        let mut folder_rules: Vec<FolderMatchRule> = settings
            .folders
            .iter()
            .map(|(id, rule)| FolderMatchRule {
                folder_id: id.clone(),
                folder_name: folders
                    .iter()
                    .find(|f| &f.id == id)
                    .map(|f| f.name.clone())
                    .unwrap_or_default(),
                rule: (*rule).into(),
            })
            .collect();
        folder_rules.sort_by_key(|r| fold(&r.folder_name));
        MatchSettingsView {
            default_rule: settings.default.into(),
            folder_rules,
            equivalent_domains: self
                .equivalent_domains
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// Règle des sites qui n'en ont pas, sur cet appareil.
    pub fn set_default_match_rule(&self, rule: UriMatchRule) -> Result<(), VerrouError> {
        let mut settings = self
            .match_settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        settings.default = rule.into();
        self.save_match_settings(&settings)
    }

    /// Règle d'un dossier sur cet appareil ; `None` : celle par défaut.
    pub fn set_folder_match_rule(
        &self,
        folder_id: String,
        rule: Option<UriMatchRule>,
    ) -> Result<(), VerrouError> {
        let mut settings = self
            .match_settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match rule {
            Some(rule) => {
                settings.folders.insert(folder_id, rule.into());
            }
            None => {
                settings.folders.remove(&folder_id);
            }
        }
        self.save_match_settings(&settings)
    }

    /// Note une utilisation que Rust ne voit pas passer (copie d'un champ
    /// non secret, d'un code à usage unique, ouverture du site).
    pub fn record_item_use(&self, id: String) {
        if self
            .with_vault(|v| Ok(v.get(&id).is_some()))
            .unwrap_or(false)
        {
            self.record_use(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ResultOrder, SidebarFilter, VaultSession};

    use super::*;

    fn titles(
        session: &VaultSession,
        query: &str,
        filter: SidebarFilter,
        order: ResultOrder,
    ) -> Vec<String> {
        let summaries = session.summaries().unwrap();
        session
            .search(query.to_owned(), filter, order)
            .unwrap()
            .into_iter()
            .map(|hit| summaries[hit.position as usize].title.clone())
            .collect()
    }

    #[test]
    fn passkeys_are_listed_with_their_site_and_user() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        assert_eq!(session.counts().unwrap().passkeys, 3);
        let found = titles(&session, "", SidebarFilter::Passkeys, ResultOrder::Title);
        assert_eq!(found, ["Apple ID", "GitHub", "Google"]);
        let github = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == "GitHub")
            .unwrap();
        assert_eq!(github.passkey_rp_id.as_deref(), Some("github.com"));
        assert_eq!(github.passkey_user_name.as_deref(), Some("camille-dev"));
        assert_eq!(
            titles(
                &session,
                "passkey:goo",
                SidebarFilter::All,
                ResultOrder::Relevance
            ),
            ["Google"]
        );
    }

    #[test]
    fn last_use_is_recorded_on_disk_with_ids_only() {
        let dir = std::env::temp_dir().join(format!("verrou-usage-{}", std::process::id()));
        let session = VaultSession::with_storage(dir.to_string_lossy().into_owned());
        session.unlock_mock(0, 42);
        let summaries = session.summaries().unwrap();
        let id_of = |title: &str| {
            summaries
                .iter()
                .find(|s| s.title == title)
                .unwrap()
                .id
                .clone()
        };
        let (netflix, github) = (id_of("Netflix"), id_of("GitHub"));
        session.record_item_use(github.clone());
        session
            .reveal(netflix.clone(), "password".to_owned())
            .unwrap();
        session.record_item_use("inconnu".to_owned());
        let order = titles(&session, "", SidebarFilter::All, ResultOrder::LastUsed);
        // Même seconde possible : les deux en tête, dans un ordre ou l'autre.
        let mut head = order[..2].to_vec();
        head.sort();
        assert_eq!(head, ["GitHub", "Netflix"]);
        let summary = session
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.id == netflix)
            .unwrap();
        assert!(summary.last_used.is_some());
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(USAGE_FILE)).unwrap()).unwrap();
        let items = file["items"].as_object().unwrap();
        assert_eq!(items.len(), 2, "élément inconnu ignoré");
        assert!(items.contains_key(&netflix) && items.contains_key(&github));
        assert!(items.values().all(serde_json::Value::is_i64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_rules_change_suggestions_and_persist() {
        let dir = std::env::temp_dir().join(format!("verrou-rules-{}", std::process::id()));
        let session = VaultSession::with_storage(dir.to_string_lossy().into_owned());
        session.unlock_mock(0, 42);
        let suggested = |page: &str| -> Vec<String> {
            session
                .suggestions(page.to_owned())
                .unwrap()
                .into_iter()
                .map(|s| s.title)
                .collect()
        };
        assert!(suggested("https://gist.github.com").contains(&"GitHub".to_owned()));
        session.set_default_match_rule(UriMatchRule::Host).unwrap();
        assert!(!suggested("https://gist.github.com").contains(&"GitHub".to_owned()));
        assert!(suggested("https://github.com/login").contains(&"GitHub".to_owned()));
        session
            .set_folder_match_rule("dossier-1".to_owned(), Some(UriMatchRule::Never))
            .unwrap();
        let view = session.match_settings();
        assert_eq!(view.default_rule, UriMatchRule::Host);
        assert_eq!(view.folder_rules[0].folder_id, "dossier-1");
        let saved: DeviceMatchSettings =
            serde_json::from_slice(&std::fs::read(dir.join(MATCH_RULES_FILE)).unwrap()).unwrap();
        assert_eq!(saved.default, UriMatch::Host);
        session
            .set_folder_match_rule("dossier-1".to_owned(), None)
            .unwrap();
        assert_eq!(session.match_settings().folder_rules.len(), 0);
        assert_eq!(uri_match_rules().len(), 6);
        assert_eq!(uri_match_label(UriMatchRule::StartsWith), "Commence par");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
