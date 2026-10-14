//! Liste des sites qui proposent la double authentification, d'après
//! 2fa.directory, gardée en cache sur le disque.
//!
//! Confidentialité : la liste est téléchargée **en entier** (environ 400 Ko),
//! sans rien envoyer du coffre ; la comparaison avec les sites des
//! identifiants se fait sur le Mac (`verrou_core::watchtower`). Hors ligne,
//! la dernière copie sert, même périmée.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use verrou_core::watchtower::TwoFactorDirectory;

use crate::Error;

/// Tous les sites qui proposent au moins une méthode (TOTP, SMS, clé…).
pub const URL: &str = "https://api.2fa.directory/v3/tfa.json";
/// Une copie plus jeune n'est pas retéléchargée.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FILE: &str = "2fa-directory.json";
/// Garde-fou : la liste fait quelques centaines de Ko.
const MAX_BYTES: usize = 16 * 1024 * 1024;

/// La liste chargée, et d'où elle vient.
pub struct Loaded {
    pub directory: TwoFactorDirectory,
    /// Horodatage Unix du téléchargement de cette copie.
    pub fetched_at: i64,
    /// `true` : copie de plus de `MAX_AGE`, faute de réseau.
    pub stale: bool,
}

fn unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// La copie en cache, si elle est lisible, avec sa date.
fn cached(dir: &Path) -> Option<(TwoFactorDirectory, SystemTime)> {
    let path = dir.join(FILE);
    let modified = fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let data = fs::read(&path).ok()?;
    let directory = TwoFactorDirectory::parse(&data).ok()?;
    (!directory.is_empty()).then_some((directory, modified))
}

fn save(dir: &Path, data: &[u8]) -> Result<(), Error> {
    fs::create_dir_all(dir).map_err(Error::storage)?;
    let temp = dir.join(format!(".{FILE}.tmp"));
    let mut file = fs::File::create(&temp).map_err(Error::storage)?;
    file.write_all(data).map_err(Error::storage)?;
    file.sync_all().map_err(Error::storage)?;
    fs::rename(&temp, dir.join(FILE)).map_err(Error::storage)
}

async fn download() -> Result<Vec<u8>, Error> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;
    let bytes = client
        .get(URL)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Error::Network(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| Error::Network(e.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::Server(
            "liste 2fa.directory trop volumineuse".to_owned(),
        ));
    }
    Ok(bytes.to_vec())
}

/// La liste, depuis le cache de `dir` s'il a moins de `MAX_AGE`, sinon
/// téléchargée (et mise en cache). Réseau indisponible : la copie périmée,
/// ou l'erreur s'il n'y en a pas.
pub async fn load(dir: &Path) -> Result<Loaded, Error> {
    let cache = cached(dir);
    if let Some((_, modified)) = &cache
        && modified.elapsed().is_ok_and(|age| age < MAX_AGE)
    {
        let (directory, modified) = cache.expect("vérifié");
        return Ok(Loaded {
            directory,
            fetched_at: unix(modified),
            stale: false,
        });
    }
    let downloaded = download().await.and_then(|data| {
        let directory =
            TwoFactorDirectory::parse(&data).map_err(|e| Error::Server(e.to_string()))?;
        if directory.is_empty() {
            return Err(Error::Server("liste 2fa.directory vide".to_owned()));
        }
        Ok((data, directory))
    });
    match (downloaded, cache) {
        (Ok((data, directory)), _) => {
            // Un cache impossible à écrire n'empêche pas l'audit.
            let _ = save(dir, &data);
            Ok(Loaded {
                directory,
                fetched_at: unix(SystemTime::now()),
                stale: false,
            })
        }
        (Err(_), Some((directory, modified))) => Ok(Loaded {
            directory,
            fetched_at: unix(modified),
            stale: true,
        }),
        (Err(error), None) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("verrou-2fa-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn a_fresh_cache_is_used_without_network() {
        let dir = temp_dir();
        save(
            &dir,
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
        save(&dir, b"pas du json").unwrap();
        assert!(cached(&dir).is_none());
        save(&dir, b"[]").unwrap();
        assert!(cached(&dir).is_none());
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
        assert!(cached(&dir).is_some());
        fs::remove_dir_all(dir).unwrap();
    }
}
