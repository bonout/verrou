//! Listes publiques téléchargées en entier et gardées sur le disque :
//! 2fa.directory (`two_factor_directory`) et l'annuaire des passkeys
//! (`passkey_directory`).
//!
//! Une copie plus jeune que `max_age` sert telle quelle, sans réseau ; sinon
//! la liste est retéléchargée **en entier** (rien du coffre ne part), puis
//! mise en cache. Hors ligne, la dernière copie sert, même périmée.

use std::fs;
use std::future::Future;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Error;

/// Garde-fou : ces listes font quelques centaines de Ko.
const MAX_BYTES: usize = 16 * 1024 * 1024;

/// Une liste chargée, et d'où elle vient.
pub(crate) struct Loaded<T> {
    pub value: T,
    /// Horodatage Unix du téléchargement de cette copie.
    pub fetched_at: i64,
    /// `true` : copie de plus de `max_age`, faute de réseau.
    pub stale: bool,
}

fn unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// La copie en cache, si elle est lisible, avec sa date.
pub(crate) fn cached<T>(
    dir: &Path,
    file: &str,
    parse: &impl Fn(&[u8]) -> Option<T>,
) -> Option<(T, SystemTime)> {
    let path = dir.join(file);
    let modified = fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let data = fs::read(&path).ok()?;
    parse(&data).map(|value| (value, modified))
}

pub(crate) fn save(dir: &Path, file: &str, data: &[u8]) -> Result<(), Error> {
    fs::create_dir_all(dir).map_err(Error::storage)?;
    let temp = dir.join(format!(".{file}.tmp"));
    let mut handle = fs::File::create(&temp).map_err(Error::storage)?;
    handle.write_all(data).map_err(Error::storage)?;
    handle.sync_all().map_err(Error::storage)?;
    fs::rename(&temp, dir.join(file)).map_err(Error::storage)
}

/// Télécharge `url` en entier (HTTPS, délai de 30 s, taille bornée).
pub(crate) async fn download(url: &str, name: &str) -> Result<Vec<u8>, Error> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .referer(false)
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;
    let bytes = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Error::Network(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| Error::Network(e.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::Server(format!("liste {name} trop volumineuse")));
    }
    Ok(bytes.to_vec())
}

/// La liste, depuis le cache `dir/file` s'il a moins de `max_age`, sinon
/// par `fetch` (puis mise en cache). `parse` rend `None` pour une liste
/// illisible ou vide : elle n'est ni gardée ni utilisée. Réseau
/// indisponible : la copie périmée, ou l'erreur s'il n'y en a pas.
pub(crate) async fn load<T, F, Fut>(
    dir: &Path,
    file: &str,
    max_age: Duration,
    parse: impl Fn(&[u8]) -> Option<T>,
    fetch: F,
) -> Result<Loaded<T>, Error>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<u8>, Error>>,
{
    let cache = cached(dir, file, &parse);
    let fresh = cache
        .as_ref()
        .is_some_and(|(_, modified)| modified.elapsed().is_ok_and(|age| age < max_age));
    if fresh {
        let (value, modified) = cache.expect("vérifié");
        return Ok(Loaded {
            value,
            fetched_at: unix(modified),
            stale: false,
        });
    }
    let downloaded = fetch().await.and_then(|data| {
        let value =
            parse(&data).ok_or_else(|| Error::Server(format!("liste {file} illisible ou vide")))?;
        Ok((data, value))
    });
    match (downloaded, cache) {
        (Ok((data, value)), _) => {
            // Un cache impossible à écrire n'empêche pas l'audit.
            let _ = save(dir, file, &data);
            Ok(Loaded {
                value,
                fetched_at: unix(SystemTime::now()),
                stale: false,
            })
        }
        (Err(_), Some((value, modified))) => Ok(Loaded {
            value,
            fetched_at: unix(modified),
            stale: true,
        }),
        (Err(error), None) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);
    const FILE: &str = "liste.json";

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("verrou-cache-{}", uuid::Uuid::new_v4()))
    }

    /// Liste « valide » : du texte non vide.
    fn parse(data: &[u8]) -> Option<String> {
        let text = String::from_utf8(data.to_vec()).ok()?;
        (!text.is_empty() && text != "illisible").then_some(text)
    }

    /// Fait vieillir la copie en cache de `age`.
    fn age_cache(dir: &Path, age: Duration) {
        let file = fs::File::options()
            .write(true)
            .open(dir.join(FILE))
            .unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    /// Téléchargement factice qui compte ses appels.
    async fn load_with(
        dir: &Path,
        calls: &AtomicUsize,
        answer: Result<&str, ()>,
    ) -> Result<Loaded<String>, Error> {
        load(dir, FILE, 7 * DAY, parse, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            answer
                .map(|text| text.as_bytes().to_vec())
                .map_err(|()| Error::Network("hors ligne".to_owned()))
        })
        .await
    }

    #[tokio::test]
    async fn downloads_at_most_once_a_week() {
        let dir = temp_dir();
        let calls = AtomicUsize::new(0);
        // Pas de cache : téléchargée, puis gardée.
        let first = load_with(&dir, &calls, Ok("v1")).await.unwrap();
        assert_eq!((first.value.as_str(), first.stale), ("v1", false));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Copie fraîche (6 jours) : aucun téléchargement.
        age_cache(&dir, 6 * DAY);
        let cached = load_with(&dir, &calls, Ok("v2")).await.unwrap();
        assert_eq!((cached.value.as_str(), cached.stale), ("v1", false));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Plus de 7 jours : retéléchargée et remplacée.
        age_cache(&dir, 7 * DAY + Duration::from_secs(60));
        let renewed = load_with(&dir, &calls, Ok("v2")).await.unwrap();
        assert_eq!((renewed.value.as_str(), renewed.stale), ("v2", false));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read_to_string(dir.join(FILE)).unwrap(), "v2");
        // Juste remplacée : de nouveau fraîche.
        load_with(&dir, &calls, Ok("v3")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn offline_falls_back_to_the_stale_copy() {
        let dir = temp_dir();
        let calls = AtomicUsize::new(0);
        assert!(matches!(
            load_with(&dir, &calls, Err(())).await,
            Err(Error::Network(_))
        ));
        save(&dir, FILE, b"ancienne").unwrap();
        age_cache(&dir, 30 * DAY);
        let stale = load_with(&dir, &calls, Err(())).await.unwrap();
        assert_eq!((stale.value.as_str(), stale.stale), ("ancienne", true));
        assert!(stale.fetched_at > 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_unreadable_download_is_never_cached() {
        let dir = temp_dir();
        let calls = AtomicUsize::new(0);
        assert!(matches!(
            load_with(&dir, &calls, Ok("illisible")).await,
            Err(Error::Server(_))
        ));
        assert!(!dir.join(FILE).exists());
        // Avec une copie périmée : elle sert, et reste en place.
        save(&dir, FILE, b"bonne").unwrap();
        age_cache(&dir, 8 * DAY);
        let loaded = load_with(&dir, &calls, Ok("illisible")).await.unwrap();
        assert_eq!((loaded.value.as_str(), loaded.stale), ("bonne", true));
        assert_eq!(fs::read_to_string(dir.join(FILE)).unwrap(), "bonne");
        // Un cache illisible est ignoré : la liste est retéléchargée.
        save(&dir, FILE, b"illisible").unwrap();
        let loaded = load_with(&dir, &calls, Ok("neuve")).await.unwrap();
        assert_eq!(loaded.value, "neuve");
        fs::remove_dir_all(dir).unwrap();
    }
}
