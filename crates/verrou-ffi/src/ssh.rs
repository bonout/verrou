//! Nouvelles clés SSH : générées ici, rangées dans le coffre comme les apps
//! Bitwarden les créent. La clé privée ne passe jamais par Swift ; l'app ne
//! reçoit que l'identifiant de l'élément créé.

use verrou_vaultwarden::ssh_key::{self, SshKeyAlgorithm};

use crate::{VaultSession, VerrouError};

/// Algorithme d'une nouvelle clé SSH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SshKeyType {
    /// Par défaut.
    Ed25519,
    /// Pour les serveurs qui n'acceptent que RSA.
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
    /// Génère une clé SSH et la range dans le coffre personnel (dossier
    /// `folder_id`, s'il y en a un), puis resynchronise ; rend l'identifiant
    /// de l'élément.
    pub async fn create_ssh_key(
        &self,
        name: String,
        folder_id: Option<String>,
        key_type: SshKeyType,
    ) -> Result<String, VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        // RSA 4096 prend jusqu'à quelques secondes : hors des fils asynchrones.
        let key = tokio::task::spawn_blocking(move || ssh_key::generate(key_type.into()))
            .await
            .map_err(|e| VerrouError::Invalid {
                message: format!("génération de la clé impossible ({e})"),
            })??;
        let (id, decrypted) = connection
            .lock()
            .await
            .create_ssh_key(name, folder_id, key)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(id)
    }
}
