//! Liste des sites qui proposent la double authentification, d'après
//! 2fa.directory, gardée en cache sur le disque.
//!
//! Confidentialité : la liste est téléchargée **en entier** (environ 400 Ko),
//! sans rien envoyer du coffre ; la comparaison avec les sites des
//! identifiants se fait sur le Mac (`verrou_core::watchtower`). Hors ligne,
//! la dernière copie sert, même périmée.

use std::path::Path;
use std::time::Duration;

use verrou_core::watchtower::TwoFactorDirectory;

use crate::Error;
use crate::directory_cache;

/// Tous les sites qui proposent au moins une méthode (TOTP, SMS, clé…).
pub const URL: &str = "https://api.2fa.directory/v3/tfa.json";
/// Une copie plus jeune n'est pas retéléchargée.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FILE: &str = "2fa-directory.json";

/// La liste chargée, et d'où elle vient.
pub struct Loaded {
    pub directory: TwoFactorDirectory,
    /// Horodatage Unix du téléchargement de cette copie.
    pub fetched_at: i64,
    /// `true` : copie de plus de `MAX_AGE`, faute de réseau.
    pub stale: bool,
}

fn parse(data: &[u8]) -> Option<TwoFactorDirectory> {
    TwoFactorDirectory::parse(data)
        .ok()
        .filter(|d| !d.is_empty())
}

/// La liste, depuis le cache de `dir` s'il a moins de `MAX_AGE`, sinon
/// téléchargée (et mise en cache). Réseau indisponible : la copie périmée,
/// ou l'erreur s'il n'y en a pas.
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

    /// Contre le vrai service (réseau) :
    /// `cargo test -p verrou-vaultwarden -- --ignored two_factor_directory`.
    #[tokio::test]
    #[ignore = "réseau : api.2fa.directory"]
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
