//! Extensions appairées, dans le dossier de Verrou (conteneur de l'app,
//! fichier lisible par le seul utilisateur).
//!
//! La clé d'un client ne permet que ce que permet l'extension : demander les
//! identifiants d'une page, coffre déverrouillé. Révoquer un client
//! l'oblige à s'appairer de nouveau.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto::ChannelKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredClient {
    id: String,
    name: String,
    key: String,
    /// Horodatage Unix de l'appairage.
    created: i64,
}

/// Ce que les réglages affichent d'un client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub created: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    clients: Vec<StoredClient>,
}

pub(crate) struct ClientStore {
    path: PathBuf,
    clients: Vec<StoredClient>,
}

impl ClientStore {
    pub fn open(path: PathBuf) -> Self {
        let clients = fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice::<File>(&data).ok())
            .map(|f| f.clients)
            .unwrap_or_default();
        Self { path, clients }
    }

    pub fn key(&self, id: &str) -> Option<ChannelKey> {
        self.clients
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| ChannelKey::from_base64(&c.key).ok())
    }

    pub fn list(&self) -> Vec<ClientInfo> {
        self.clients
            .iter()
            .map(|c| ClientInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                created: c.created,
            })
            .collect()
    }

    pub fn add(&mut self, id: String, name: String, key: &ChannelKey, created: i64) {
        self.clients.push(StoredClient {
            id,
            name,
            key: key.to_base64(),
            created,
        });
        self.save();
    }

    pub fn remove(&mut self, id: &str) {
        self.clients.retain(|c| c.id != id);
        self.save();
    }

    /// Écriture atomique, mode 600. Un échec laisse l'ancien fichier : au
    /// pire, un appairage est à refaire.
    fn save(&self) {
        let Some(dir) = self.path.parent() else {
            return;
        };
        let _ = fs::create_dir_all(dir);
        let temp = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let data = serde_json::to_vec(&File {
            clients: self.clients.clone(),
        })
        .unwrap_or_default();
        let written = options
            .open(&temp)
            .and_then(|mut f| f.write_all(&data).and_then(|()| f.sync_all()));
        if written.is_ok() {
            let _ = fs::rename(&temp, &self.path);
        }
    }
}
