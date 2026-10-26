//! New SSH keys: generated here, stored in the vault the way the Bitwarden
//! apps create them. The private key never goes through Swift; the app only
//! receives the id of the created item.

use verrou_vaultwarden::ssh_key::{self, SshKeyAlgorithm};

use crate::{VaultSession, VerrouError};

/// Algorithm of a new SSH key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SshKeyType {
    /// Default.
    Ed25519,
    /// For servers that only accept RSA.
    Rsa4096,
}

impl From<SshKeyType> for SshKeyAlgorithm {
    fn from(kind: SshKeyType) -> Self {
        match kind {
            SshKeyType::Ed25519 => Self::Ed25519,
            SshKeyType::Rsa4096 => Self::Rsa4096,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Generates an SSH key and stores it in the personal vault (folder
    /// `folder_id`, if any), then resyncs; returns the id
    /// of the item.
    pub async fn create_ssh_key(
        &self,
        name: String,
        folder_id: Option<String>,
        key_type: SshKeyType,
    ) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        // RSA 4096 takes up to a few seconds: off the async threads.
        let key = tokio::task::spawn_blocking(move || ssh_key::generate(key_type.into()))
            .await
            .map_err(|e| VerrouError::Invalid {
                message: format!("could not generate the key ({e})"),
            })??;
        let (id, decrypted) = connection
            .lock()
            .await
            .create_ssh_key(name, folder_id, key)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(self.qualify(&id))
    }
}
