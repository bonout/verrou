//! Directory of the sites that accept passkeys (passkeys.2fa.directory,
//! from the same project as 2fa.directory), cached on disk.
//!
//! Privacy: as for 2fa.directory, the directory is downloaded **in full**
//! (about 75 KB), at most once a week, without sending anything from the
//! vault; the comparison with the logins' sites happens on the device
//! (`verrou_core::passkey_upgrade`). No per-site request. Offline, the last
//! copy is used, even if stale.

use std::path::Path;
use std::time::Duration;

use verrou_core::passkey_upgrade::PasskeyDirectory;

use crate::Error;
use crate::directory_cache;

/// The sites that accept a passkey, passwordless or as a second factor
/// (`all.json` also lists those that don't yet).
pub const URL: &str = "https://passkeys-api.2fa.directory/v1/supported.json";
/// A younger copy is not downloaded again.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FILE: &str = "passkeys-directory.json";

/// The loaded directory, and where it comes from.
pub struct Loaded {
    pub directory: PasskeyDirectory,
    /// Unix timestamp of this copy's download.
    pub fetched_at: i64,
    /// `true`: copy older than `MAX_AGE`, for lack of network.
    pub stale: bool,
}

fn parse(data: &[u8]) -> Option<PasskeyDirectory> {
    PasskeyDirectory::parse(data).ok().filter(|d| !d.is_empty())
}

/// The cached copy, whatever its age, without network.
pub fn cached(dir: &Path) -> Option<PasskeyDirectory> {
    directory_cache::cached(dir, FILE, &parse).map(|(directory, _)| directory)
}

/// The directory, from the cache in `dir` if it is younger than `MAX_AGE`,
/// otherwise downloaded (and cached). Network unavailable: the stale copy,
/// or the error if there is none.
pub async fn load(dir: &Path) -> Result<Loaded, Error> {
    let loaded = directory_cache::load(dir, FILE, MAX_AGE, parse, || {
        directory_cache::download(URL, "passkeys.2fa.directory")
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
        std::env::temp_dir().join(format!("verrou-passkeys-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn a_fresh_cache_is_used_without_network() {
        let dir = temp_dir();
        directory_cache::save(
            &dir,
            FILE,
            br#"{"github.com": {"passwordless": "allowed", "mfa": "allowed"}}"#,
        )
        .unwrap();
        let loaded = load(&dir).await.unwrap();
        assert!(!loaded.stale);
        assert_eq!(loaded.directory.len(), 1);
        assert!(loaded.directory.lookup("https://github.com").is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_empty_or_unreadable_cache_is_ignored() {
        let dir = temp_dir();
        for data in [
            &b"pas du json"[..],
            b"{}",
            br#"{"2k.com": {"contact": {}}}"#,
        ] {
            directory_cache::save(&dir, FILE, data).unwrap();
            assert!(directory_cache::cached(&dir, FILE, &parse).is_none());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    /// Against the real service (network):
    /// `cargo test -p verrou-vaultwarden -- --ignored passkey_directory`.
    #[tokio::test]
    #[ignore = "network: passkeys-api.2fa.directory"]
    async fn real_service_lists_github() {
        let dir = temp_dir();
        let loaded = load(&dir).await.unwrap();
        assert!(loaded.directory.len() > 100);
        let github = loaded.directory.lookup("https://github.com").unwrap();
        assert!(github.passwordless());
        assert!(directory_cache::cached(&dir, FILE, &parse).is_some());
        fs::remove_dir_all(dir).unwrap();
    }
}
