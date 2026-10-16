//! Annuaire des sites qui acceptent les passkeys (passkeys.2fa.directory,
//! du même projet que 2fa.directory), gardé en cache sur le disque.
//!
//! Confidentialité : comme pour 2fa.directory, l'annuaire est téléchargé
//! **en entier** (environ 75 Ko), au plus une fois par semaine, sans rien
//! envoyer du coffre ; la comparaison avec les sites des identifiants se
//! fait sur l'appareil (`verrou_core::passkey_upgrade`). Aucune requête par
//! site. Hors ligne, la dernière copie sert, même périmée.

use std::path::Path;
use std::time::Duration;

use verrou_core::passkey_upgrade::PasskeyDirectory;

use crate::Error;
use crate::directory_cache;

/// Les sites qui acceptent une passkey, sans mot de passe ou en second
/// facteur (`all.json` liste aussi ceux qui ne le font pas encore).
pub const URL: &str = "https://passkeys-api.2fa.directory/v1/supported.json";
/// Une copie plus jeune n'est pas retéléchargée.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FILE: &str = "passkeys-directory.json";

/// L'annuaire chargé, et d'où il vient.
pub struct Loaded {
    pub directory: PasskeyDirectory,
    /// Horodatage Unix du téléchargement de cette copie.
    pub fetched_at: i64,
    /// `true` : copie de plus de `MAX_AGE`, faute de réseau.
    pub stale: bool,
}

fn parse(data: &[u8]) -> Option<PasskeyDirectory> {
    PasskeyDirectory::parse(data).ok().filter(|d| !d.is_empty())
}

/// La copie en cache, quel que soit son âge, sans réseau.
pub fn cached(dir: &Path) -> Option<PasskeyDirectory> {
    directory_cache::cached(dir, FILE, &parse).map(|(directory, _)| directory)
}

/// L'annuaire, depuis le cache de `dir` s'il a moins de `MAX_AGE`, sinon
/// téléchargé (et mis en cache). Réseau indisponible : la copie périmée,
/// ou l'erreur s'il n'y en a pas.
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

    /// Contre le vrai service (réseau) :
    /// `cargo test -p verrou-vaultwarden -- --ignored passkey_directory`.
    #[tokio::test]
    #[ignore = "réseau : passkeys-api.2fa.directory"]
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
