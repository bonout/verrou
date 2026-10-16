//! Dernière utilisation des éléments, sur cet appareil.
//!
//! Bitwarden ne connaît que la date de dernière utilisation d'un mot de passe
//! remplacé (historique) et, pour les passkeys, un compteur : aucun champ du
//! format ne dit quand un élément a servi. Verrou tient donc son propre
//! registre, local à l'appareil et jamais envoyé au serveur : des
//! identifiants d'éléments et des horodatages, rien d'autre (ni titre, ni
//! site, ni secret). Il sert au tri « Dernière utilisation ».
//!
//! Une utilisation, c'est un remplissage (extension, ⌘\, remplissage
//! automatique de l'iPhone), une copie ou l'affichage d'un secret.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Éléments gardés au plus : au-delà, les plus anciens sont oubliés.
pub const MAX_ENTRIES: usize = 5_000;

/// Le registre : identifiant d'élément → horodatage Unix (secondes) de sa
/// dernière utilisation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLog {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub items: HashMap<String, i64>,
}

impl UsageLog {
    pub const VERSION: u32 = 1;

    /// Lit le fichier ; illisible ou absent : registre vide (il n'est
    /// qu'une commodité).
    pub fn from_json(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap_or_default()
    }

    pub fn to_json(&self) -> Vec<u8> {
        let file = Self {
            version: Self::VERSION,
            items: self.items.clone(),
        };
        serde_json::to_vec(&file).unwrap_or_default()
    }

    /// Note une utilisation. Une date plus ancienne que celle connue ne la
    /// remplace pas (deux processus, horloge reculée).
    pub fn record(&mut self, id: &str, at: i64) {
        let entry = self.items.entry(id.to_owned()).or_insert(at);
        *entry = (*entry).max(at);
        self.trim();
    }

    /// Fusionne un autre registre (celui de l'extension de remplissage,
    /// écrit par un autre processus) : la date la plus récente l'emporte.
    pub fn merge(&mut self, other: &Self) {
        for (id, at) in &other.items {
            let entry = self.items.entry(id.clone()).or_insert(*at);
            *entry = (*entry).max(*at);
        }
        self.trim();
    }

    /// Oublie un élément (supprimé, ou devenu un autre élément).
    pub fn forget(&mut self, id: &str) {
        self.items.remove(id);
    }

    /// Reporte la date d'un élément sur son nouvel identifiant (élément
    /// créé hors ligne puis envoyé, élément retiré d'un partage).
    pub fn rename(&mut self, from: &str, to: &str) {
        if let Some(at) = self.items.remove(from) {
            self.record(to, at);
        }
    }

    pub fn last_used(&self, id: &str) -> Option<i64> {
        self.items.get(id).copied()
    }

    fn trim(&mut self) {
        if self.items.len() <= MAX_ENTRIES {
            return;
        }
        let mut dates: Vec<i64> = self.items.values().copied().collect();
        dates.sort_unstable_by(|a, b| b.cmp(a));
        let floor = dates[MAX_ENTRIES - 1];
        self.items.retain(|_, at| *at >= floor);
        // Ex aequo à la limite : on retire les derniers arbitrairement.
        while self.items.len() > MAX_ENTRIES {
            let Some(id) = self
                .items
                .iter()
                .find(|(_, at)| **at == floor)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.items.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_latest_date_and_only_ids() {
        let mut log = UsageLog::default();
        log.record("a", 10);
        log.record("a", 5);
        log.record("b", 7);
        assert_eq!(log.last_used("a"), Some(10));
        let json = String::from_utf8(log.to_json()).unwrap();
        // Rien d'autre que des identifiants et des dates.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["items"]["a"], 10);
        assert_eq!(parsed.as_object().unwrap().len(), 2);

        let mut other = UsageLog::default();
        other.record("a", 20);
        other.record("c", 1);
        log.merge(&other);
        assert_eq!(log.last_used("a"), Some(20));
        assert_eq!(log.last_used("c"), Some(1));
        log.rename("c", "d");
        assert_eq!((log.last_used("c"), log.last_used("d")), (None, Some(1)));
        log.forget("d");
        assert_eq!(log.last_used("d"), None);
        assert_eq!(UsageLog::from_json(b"pas du json"), UsageLog::default());
        assert_eq!(UsageLog::from_json(&log.to_json()).items, log.items);
    }

    #[test]
    fn oldest_entries_are_dropped() {
        let mut log = UsageLog::default();
        let max = i64::try_from(MAX_ENTRIES).unwrap();
        for i in 0..=max {
            log.record(&format!("id-{i}"), i);
        }
        assert_eq!(log.items.len(), MAX_ENTRIES);
        assert_eq!(log.last_used("id-0"), None);
        assert_eq!(log.last_used(&format!("id-{MAX_ENTRIES}")), Some(max));
    }
}
