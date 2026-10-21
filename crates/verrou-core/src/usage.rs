//! Items' last use, on this device.
//!
//! Bitwarden only knows the last-used date of a replaced password
//! (history) and, for passkeys, a counter: no field of the
//! format says when an item was used. So Verrou keeps its own
//! log, local to the device and never sent to the server: item
//! ids and timestamps, nothing else (no title, no
//! site, no secret). It backs the "Last used" sort.
//!
//! A use is a fill (extension, ⌘\, iPhone
//! autofill), a copy or the display of a secret.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Maximum number of items kept: beyond that, the oldest are forgotten.
pub const MAX_ENTRIES: usize = 5_000;

/// The log: item id → Unix timestamp (seconds) of its
/// last use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLog {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub items: HashMap<String, i64>,
}

impl UsageLog {
    pub const VERSION: u32 = 1;

    /// Reads the file; unreadable or missing: empty log (it is
    /// only a convenience).
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

    /// Records a use. A date older than the known one does not
    /// replace it (two processes, clock set back).
    pub fn record(&mut self, id: &str, at: i64) {
        let entry = self.items.entry(id.to_owned()).or_insert(at);
        *entry = (*entry).max(at);
        self.trim();
    }

    /// Merges another log (the autofill extension's,
    /// written by another process): the most recent date wins.
    pub fn merge(&mut self, other: &Self) {
        for (id, at) in &other.items {
            let entry = self.items.entry(id.clone()).or_insert(*at);
            *entry = (*entry).max(*at);
        }
        self.trim();
    }

    /// Forgets an item (deleted, or turned into another item).
    pub fn forget(&mut self, id: &str) {
        self.items.remove(id);
    }

    /// Carries an item's date over to its new id (item
    /// created offline then uploaded, item removed from sharing).
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
        // Ties at the limit: the last ones are removed arbitrarily.
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
        // Nothing but ids and dates.
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
