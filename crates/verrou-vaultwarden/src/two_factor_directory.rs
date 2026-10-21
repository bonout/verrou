//! List of the sites that offer two-factor authentication, from
//! 2fa.directory, cached on disk.
//!
//! Privacy: the list is downloaded **in full** (about 400 KB), without
//! sending anything from the vault; the comparison with the logins' sites
//! happens on the Mac (`verrou_core::watchtower`). Offline, the last copy
//! is used, even if stale.

use std::path::Path;
use std::time::Duration;

use verrou_core::watchtower::TwoFactorDirectory;

use crate::Error;
use crate::directory_cache;

/// All the sites that offer at least one method (TOTP, SMS, key…).
pub const URL: &str = "https://api.2fa.directory/v3/tfa.json";
/// A younger copy is not downloaded again.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FILE: &str = "2fa-directory.json";

/// The loaded list, and where it comes from.
pub struct Loaded {
    pub directory: TwoFactorDirectory,
    /// Unix timestamp of this copy's download.
    pub fetched_at: i64,
    /// `true`: copy older than `MAX_AGE`, for lack of network.
    pub stale: bool,
}

fn parse(data: &[u8]) -> Option<TwoFactorDirectory> {
    TwoFactorDirectory::parse(data)
        .ok()
        .filter(|d| !d.is_empty())
}

/// The list, from the cache in `dir` if it is younger than `MAX_AGE`,
/// otherwise downloaded (and cached). Network unavailable: the stale copy,
/// or the error if there is none.
pub async fn load(dir: &Path) -> Result<Loaded, Error> {
    let loaded = directory_cache::load(dir, FILE, MAX_AGE, parse, || {
        directory_cache::download(URL, "2fa.directory")
    })
    .await?;
    Ok(Loaded {
        directory: loaded.value,
        fetched_at: loaded.fetched_at,
        stale: loaded.stale,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("verrou-2fa-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn a_fresh_cache_is_used_without_network() {
        let dir = temp_dir();
        directory_cache::save(
            &dir,
            FILE,
            br#"[["GitHub", {"domain": "github.com", "tfa": ["totp"]}]]"#,
        )
        .unwrap();
        let loaded = load(&dir).await.unwrap();
        assert!(!loaded.stale);
        assert_eq!(loaded.directory.len(), 1);
        assert!(loaded.directory.lookup("https://github.com").is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unreadable_cache_is_ignored() {
        let dir = temp_dir();
        directory_cache::save(&dir, FILE, b"pas du json").unwrap();
        assert!(directory_cache::cached(&dir, FILE, &parse).is_none());
        directory_cache::save(&dir, FILE, b"[]").unwrap();
        assert!(directory_cache::cached(&dir, FILE, &parse).is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Against the real service (network):
    /// `cargo test -p verrou-vaultwarden -- --ignored two_factor_directory`.
    #[tokio::test]
    #[ignore = "network: api.2fa.directory"]
    async fn real_service_lists_github() {
        let dir = temp_dir();
        let loaded = load(&dir).await.unwrap();
        assert!(loaded.directory.len() > 1000);
        let github = loaded.directory.lookup("https://github.com").unwrap();
        assert!(github.supports_totp());
        assert!(directory_cache::cached(&dir, FILE, &parse).is_some());
        fs::remove_dir_all(dir).unwrap();
    }
}
