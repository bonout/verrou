//! Ce que Verrou garde sur le disque entre deux lancements.
//!
//! Rien n'y est lisible sans le mot de passe principal : la clé de
//! l'utilisateur y est chiffrée par sa clé principale (comme sur le serveur),
//! le cache du coffre est la réponse de synchronisation telle que le serveur
//! l'envoie (chiffrée), et le jeton de renouvellement est chiffré par Verrou
//! avec la clé de l'utilisateur. Les clés de sécurité enrôlées
//! (`security-keys.json`) n'y gardent la clé de l'utilisateur que scellée par
//! un secret qui ne quitte pas la clé physique. Les modifications faites
//! hors ligne (`outbox.json`, voir `outbox`) y attendent le serveur,
//! chiffrées en bloc par la clé de l'utilisateur.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::unlock_keys::EnrolledKey;

const ACCOUNT_FILE: &str = "account.json";
const DEVICE_FILE: &str = "device-id";
/// Clés de sécurité enrôlées pour déverrouiller (voir `unlock_keys`).
pub(crate) const SECURITY_KEYS_FILE: &str = "security-keys.json";
/// File des modifications faites hors ligne (voir `outbox`).
const OUTBOX_FILE: &str = "outbox.json";
const OUTBOX_VERSION: u32 = 1;
const FORMAT_VERSION: u32 = 1;
const SECURITY_KEYS_VERSION: u32 = 1;

/// Contenu de `security-keys.json`.
#[derive(Serialize, Deserialize)]
struct SecurityKeysFile {
    version: u32,
    keys: Vec<EnrolledKey>,
}

/// Contenu de `outbox.json` : la file entière, chiffrée par la clé de
/// l'utilisateur (`data`). En clair : le compte auquel elle appartient et le
/// nombre de modifications en attente, pour prévenir avant une déconnexion
/// sans déverrouiller.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OutboxFile {
    pub version: u32,
    pub user_id: String,
    pub pending: u32,
    pub data: String,
}

/// Paramètres de dérivation du mot de passe principal, dans un format propre
/// à Verrou : le fichier ne dépend pas de la sérialisation du SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum KdfSettings {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory: u32,
        parallelism: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub version: u32,
    pub server: String,
    pub email: String,
    pub user_id: String,
    pub kdf: KdfSettings,
    pub salt: String,
    /// Clé de l'utilisateur, chiffrée par la clé dérivée du mot de passe.
    pub wrapped_user_key: String,
    /// Clé privée RSA de l'utilisateur, chiffrée par sa clé.
    pub private_key: String,
    /// Jeton de renouvellement, chiffré par la clé de l'utilisateur.
    pub refresh_token: String,
    /// Horodatage Unix de la dernière synchronisation réussie.
    pub synced_at: Option<i64>,
    /// Réponse brute de `/api/sync`, chiffrée par Bitwarden.
    pub sync: Option<String>,
}

impl Account {
    pub(crate) fn new_version() -> u32 {
        FORMAT_VERSION
    }
}

/// Verrou entre processus (`flock`) des écritures du dossier : l'app
/// iPhone et son extension de remplissage partagent le dossier du compte.
const LOCK_FILE: &str = ".verrou.lock";

/// Le dossier de Verrou (dans le conteneur de l'app sandboxée).
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
    /// Ouvert par un autre processus que l'app (extension de remplissage
    /// automatique iOS) : la file des modifications appartient à l'app, il
    /// n'y touche jamais (ni envoi, ni écriture). Voir `Store::guest`.
    guest: bool,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            guest: false,
        }
    }

    /// Le même dossier, ouvert en invité : par l'extension de remplissage
    /// automatique, pendant que l'app peut tourner. L'invité lit le cache et
    /// la file de l'app (pour afficher ses modifications pas encore
    /// envoyées), écrit directement sur le serveur (passkeys) puis enregistre
    /// le cache resynchronisé ; il n'envoie ni n'écrit jamais la file (l'app
    /// la garde en mémoire : la réécrire ou l'envoyer depuis un autre
    /// processus perdrait ou doublerait des modifications).
    #[must_use]
    pub fn guest(mut self) -> Self {
        self.guest = true;
        self
    }

    pub fn is_guest(&self) -> bool {
        self.guest
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load_account(&self) -> Result<Option<Account>, Error> {
        let path = self.dir.join(ACCOUNT_FILE);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::storage(e)),
        };
        let account: Account = serde_json::from_slice(&data).map_err(Error::storage)?;
        if account.version != FORMAT_VERSION {
            return Err(Error::Storage(format!(
                "format de compte {} inconnu",
                account.version
            )));
        }
        Ok(Some(account))
    }

    pub fn save_account(&self, account: &Account) -> Result<(), Error> {
        let data = serde_json::to_vec(account).map_err(Error::storage)?;
        self.write_private(ACCOUNT_FILE, &data)
    }

    pub fn delete_account(&self) -> Result<(), Error> {
        match fs::remove_file(self.dir.join(ACCOUNT_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::storage(e)),
        }
    }

    /// La file des modifications hors ligne, telle qu'écrite (chiffrée).
    /// Un fichier d'un autre format compte pour absent.
    pub(crate) fn load_outbox(&self) -> Result<Option<OutboxFile>, Error> {
        let data = match fs::read(self.dir.join(OUTBOX_FILE)) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::storage(e)),
        };
        Ok(serde_json::from_slice::<OutboxFile>(&data)
            .ok()
            .filter(|f| f.version == OUTBOX_VERSION))
    }

    /// Remplace la file ; vide (`None`), le fichier est supprimé.
    pub(crate) fn save_outbox(&self, file: Option<OutboxFile>) -> Result<(), Error> {
        if self.guest {
            return Ok(());
        }
        let Some(mut file) = file else {
            return self.delete_outbox();
        };
        file.version = OUTBOX_VERSION;
        let data = serde_json::to_vec(&file).map_err(Error::storage)?;
        self.write_private(OUTBOX_FILE, &data)
    }

    pub(crate) fn delete_outbox(&self) -> Result<(), Error> {
        if self.guest {
            return Ok(());
        }
        match fs::remove_file(self.dir.join(OUTBOX_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::storage(e)),
        }
    }

    /// Modifications faites hors ligne qui attendent encore le serveur
    /// (lisible coffre verrouillé : pour prévenir avant une déconnexion).
    pub fn pending_changes(&self) -> u32 {
        self.load_outbox().ok().flatten().map_or(0, |f| f.pending)
    }

    /// Les clés de sécurité enrôlées pour déverrouiller (aucune si le
    /// fichier n'existe pas).
    pub fn load_security_keys(&self) -> Result<Vec<EnrolledKey>, Error> {
        let data = match fs::read(self.dir.join(SECURITY_KEYS_FILE)) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::storage(e)),
        };
        let file: SecurityKeysFile = serde_json::from_slice(&data).map_err(Error::storage)?;
        if file.version != SECURITY_KEYS_VERSION {
            return Err(Error::Storage(format!(
                "format de clés de sécurité {} inconnu",
                file.version
            )));
        }
        Ok(file.keys)
    }

    /// Remplace la liste ; une liste vide supprime le fichier.
    pub fn save_security_keys(&self, keys: &[EnrolledKey]) -> Result<(), Error> {
        if keys.is_empty() {
            return self.delete_security_keys();
        }
        let file = SecurityKeysFile {
            version: SECURITY_KEYS_VERSION,
            keys: keys.to_vec(),
        };
        let data = serde_json::to_vec(&file).map_err(Error::storage)?;
        self.write_private(SECURITY_KEYS_FILE, &data)
    }

    pub fn delete_security_keys(&self) -> Result<(), Error> {
        match fs::remove_file(self.dir.join(SECURITY_KEYS_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::storage(e)),
        }
    }

    /// Identifiant de cet appareil auprès du serveur, créé au premier besoin et
    /// conservé ensuite : une reconnexion n'ajoute pas un nouvel appareil.
    pub fn device_id(&self) -> Result<String, Error> {
        let path = self.dir.join(DEVICE_FILE);
        if let Ok(id) = fs::read_to_string(&path) {
            let id = id.trim();
            if uuid::Uuid::parse_str(id).is_ok() {
                return Ok(id.to_owned());
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.write_private(DEVICE_FILE, id.as_bytes())?;
        Ok(id)
    }

    /// Écriture atomique (fichier temporaire puis renommage), lisible par le
    /// seul utilisateur. Le fichier temporaire est propre au processus et à
    /// l'écriture, et le renommage se fait sous le verrou du dossier
    /// (`flock`, tenu quelques millisecondes, jamais pendant le réseau :
    /// iOS met fin à une app suspendue qui tient un verrou de fichier dans
    /// un conteneur partagé). Un lecteur voit l'ancien fichier ou le
    /// nouveau, jamais un mélange.
    fn write_private(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static WRITES: AtomicU64 = AtomicU64::new(0);
        fs::create_dir_all(&self.dir).map_err(Error::storage)?;
        let target = self.dir.join(name);
        let temp = self.dir.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            WRITES.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(Error::storage)?;
        let written = file
            .write_all(data)
            .and_then(|()| file.sync_all())
            .map_err(Error::storage)
            .and_then(|()| {
                let _lock = self.lock()?;
                fs::rename(&temp, &target).map_err(Error::storage)
            });
        if written.is_err() {
            let _ = fs::remove_file(&temp);
        }
        written
    }

    /// Verrou exclusif du dossier, entre processus, relâché à la fin de la
    /// portée (fermeture du descripteur).
    fn lock(&self) -> Result<DirLock, Error> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(LOCK_FILE))
            .map_err(Error::storage)?;
        #[cfg(unix)]
        loop {
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(Error::storage(std::io::Error::from(error))),
            }
        }
        Ok(DirLock(file))
    }
}

/// Verrou tenu (`Store::lock`) : fermer le fichier le relâche.
struct DirLock(#[allow(dead_code)] fs::File);

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!("verrou-store-{}", uuid::Uuid::new_v4()));
        Store::new(dir)
    }

    #[test]
    fn device_id_is_stable() {
        let store = temp_store();
        let first = store.device_id().unwrap();
        assert_eq!(store.device_id().unwrap(), first);
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn account_round_trips_and_is_private() {
        let store = temp_store();
        assert!(store.load_account().unwrap().is_none());
        let account = Account {
            version: FORMAT_VERSION,
            server: "https://vault.exemple.fr".into(),
            email: "camille@exemple.fr".into(),
            user_id: "00000000-0000-0000-0000-000000000000".into(),
            kdf: KdfSettings::Argon2id {
                iterations: 3,
                memory: 64,
                parallelism: 4,
            },
            salt: "camille@exemple.fr".into(),
            wrapped_user_key: "2.a|b|c".into(),
            private_key: "2.d|e|f".into(),
            refresh_token: "2.g|h|i".into(),
            synced_at: Some(1),
            sync: None,
        };
        store.save_account(&account).unwrap();
        let loaded = store.load_account().unwrap().unwrap();
        assert_eq!(loaded.kdf, account.kdf);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(store.dir().join(ACCOUNT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.delete_account().unwrap();
        assert!(store.load_account().unwrap().is_none());
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn concurrent_writers_never_tear_a_file() {
        let store = temp_store();
        let guest = store.clone().guest();
        let writers: Vec<_> = (0..8u8)
            .map(|n| {
                let store = if n % 2 == 0 {
                    store.clone()
                } else {
                    guest.clone()
                };
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        store.write_private("shared.json", &[n; 4096]).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let data = fs::read(store.dir().join("shared.json")).unwrap();
        assert_eq!(data.len(), 4096);
        assert!(data.iter().all(|b| *b == data[0]));
        // Aucun fichier temporaire oublié.
        let leftovers = fs::read_dir(store.dir())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        fs::remove_dir_all(store.dir()).unwrap();
    }

    #[test]
    fn a_guest_never_writes_the_outbox() {
        let store = temp_store();
        let file = OutboxFile {
            version: 0,
            user_id: "u".into(),
            pending: 2,
            data: "2.a|b|c".into(),
        };
        store.save_outbox(Some(file.clone())).unwrap();
        let guest = store.clone().guest();
        guest.save_outbox(None).unwrap();
        guest.delete_outbox().unwrap();
        guest
            .save_outbox(Some(OutboxFile { pending: 9, ..file }))
            .unwrap();
        assert_eq!(store.pending_changes(), 2);
        assert_eq!(guest.pending_changes(), 2);
        fs::remove_dir_all(store.dir()).unwrap();
    }
}
