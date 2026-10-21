//! Public lists downloaded in full and kept on disk: 2fa.directory
//! (`two_factor_directory`) and the passkey directory
//! (`passkey_directory`).
//!
//! A copy younger than `max_age` is used as is, without network; otherwise
//! the list is downloaded again **in full** (nothing from the vault is
//! sent), then cached. Offline, the last copy is used, even if stale.

use std::fs;
use std::future::Future;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Error;

/// Safeguard: these lists are a few hundred KB.
const MAX_BYTES: usize = 16 * 1024 * 1024;

/// A loaded list, and where it comes from.
pub(crate) struct Loaded<T> {
    pub value: T,
    /// Unix timestamp of this copy's download.
    pub fetched_at: i64,
    /// `true`: copy older than `max_age`, for lack of network.
    pub stale: bool,
}

fn unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The cached copy, if it is readable, with its date.
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

/// Downloads `url` in full (HTTPS, 30 s timeout, bounded size).
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
        return Err(Error::Server(format!("{name} list is too large")));
    }
    Ok(bytes.to_vec())
}

/// The list, from the cache `dir/file` if it is younger than `max_age`,
/// otherwise through `fetch` (then cached). `parse` returns `None` for an
/// unreadable or empty list: it is neither kept nor used. Network
/// unavailable: the stale copy, or the error if there is none.
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
        let (value, modified) = cache.expect("checked");
        return Ok(Loaded {
            value,
            fetched_at: unix(modified),
            stale: false,
        });
    }
    let downloaded = fetch().await.and_then(|data| {
        let value = parse(&data)
            .ok_or_else(|| Error::Server(format!("{file} list is unreadable or empty")))?;
        Ok((data, value))
    });
    match (downloaded, cache) {
        (Ok((data, value)), _) => {
            // A cache that can't be written doesn't prevent the audit.
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

    /// "Valid" list: non-empty text.
    fn parse(data: &[u8]) -> Option<String> {
        let text = String::from_utf8(data.to_vec()).ok()?;
        (!text.is_empty() && text != "illisible").then_some(text)
    }

    /// Ages the cached copy by `age`.
    fn age_cache(dir: &Path, age: Duration) {
        let file = fs::File::options()
            .write(true)
            .open(dir.join(FILE))
            .unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    /// Fake download that counts its calls.
    async fn load_with(
        dir: &Path,
        calls: &AtomicUsize,
        answer: Result<&str, ()>,
    ) -> Result<Loaded<String>, Error> {
        load(dir, FILE, 7 * DAY, parse, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            answer
                .map(|text| text.as_bytes().to_vec())
                .map_err(|()| Error::Network("offline".to_owned()))
        })
        .await
    }

    #[tokio::test]
    async fn downloads_at_most_once_a_week() {
        let dir = temp_dir();
        let calls = AtomicUsize::new(0);
        // No cache: downloaded, then kept.
        let first = load_with(&dir, &calls, Ok("v1")).await.unwrap();
        assert_eq!((first.value.as_str(), first.stale), ("v1", false));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Fresh copy (6 days): no download.
        age_cache(&dir, 6 * DAY);
        let cached = load_with(&dir, &calls, Ok("v2")).await.unwrap();
        assert_eq!((cached.value.as_str(), cached.stale), ("v1", false));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Over 7 days: downloaded again and replaced.
        age_cache(&dir, 7 * DAY + Duration::from_secs(60));
        let renewed = load_with(&dir, &calls, Ok("v2")).await.unwrap();
        assert_eq!((renewed.value.as_str(), renewed.stale), ("v2", false));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read_to_string(dir.join(FILE)).unwrap(), "v2");
        // Just replaced: fresh again.
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
        // With a stale copy: it is used, and stays in place.
        save(&dir, FILE, b"bonne").unwrap();
        age_cache(&dir, 8 * DAY);
        let loaded = load_with(&dir, &calls, Ok("illisible")).await.unwrap();
        assert_eq!((loaded.value.as_str(), loaded.stale), ("bonne", true));
        assert_eq!(fs::read_to_string(dir.join(FILE)).unwrap(), "bonne");
        // An unreadable cache is ignored: the list is downloaded again.
        save(&dir, FILE, b"illisible").unwrap();
        let loaded = load_with(&dir, &calls, Ok("neuve")).await.unwrap();
        assert_eq!(loaded.value, "neuve");
        fs::remove_dir_all(dir).unwrap();
    }
}
