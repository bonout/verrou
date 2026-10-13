//! Clients appairés (extensions, terminal), dans le dossier de Verrou
//! (conteneur de l'app, fichier lisible par le seul utilisateur).
//!
//! La clé d'un client ne permet que ce que permet sa nature
//! ([`crate::access::allowed`]) : pour l'extension, demander les
//! identifiants d'une page ; pour le terminal, chercher et demander un
//! secret, que l'utilisateur confirme dans Verrou. Révoquer un client
//! l'oblige à s'appairer de nouveau.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto::ChannelKey;
use crate::protocol::ClientKind;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredClient {
    id: String,
    name: String,
    key: String,
    /// Horodatage Unix de l'appairage.
    created: i64,
    /// Absent des fichiers d'avant le terminal : une extension.
    #[serde(default)]
    kind: ClientKind,
}

/// Ce que les réglages affichent d'un client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub created: i64,
    pub kind: ClientKind,
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

    /// La clé du client et ce qu'on sait de lui.
    pub fn get(&self, id: &str) -> Option<(ChannelKey, ClientInfo)> {
        let client = self.clients.iter().find(|c| c.id == id)?;
        let key = ChannelKey::from_base64(&client.key).ok()?;
        Some((key, info(client)))
    }

    pub fn list(&self) -> Vec<ClientInfo> {
        self.clients.iter().map(info).collect()
    }

    pub fn add(
        &mut self,
        id: String,
        name: String,
        kind: ClientKind,
        key: &ChannelKey,
        created: i64,
    ) {
        self.clients.push(StoredClient {
            id,
            name,
            key: key.to_base64(),
            created,
            kind,
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

fn info(client: &StoredClient) -> ClientInfo {
    ClientInfo {
        id: client.id.clone(),
        name: client.name.clone(),
        created: client.created,
        kind: client.kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_saved_before_the_terminal_are_browsers() {
        let path =
            std::env::temp_dir().join(format!("verrou-clients-{}.json", uuid::Uuid::new_v4()));
        let key = ChannelKey::from_bytes([3; 32]);
        fs::write(
            &path,
            format!(
                r#"{{"clients":[{{"id":"ancien","name":"Brave","key":"{}","created":1}}]}}"#,
                key.to_base64()
            ),
        )
        .unwrap();
        let mut store = ClientStore::open(path.clone());
        assert_eq!(store.get("ancien").unwrap().1.kind, ClientKind::Browser);
        store.add(
            "cli".to_owned(),
            "verrou".to_owned(),
            ClientKind::Cli,
            &key,
            2,
        );
        let reopened = ClientStore::open(path.clone());
        assert_eq!(reopened.get("cli").unwrap().1.kind, ClientKind::Cli);
        assert_eq!(reopened.list().len(), 2);
        let _ = fs::remove_file(path);
    }
}
