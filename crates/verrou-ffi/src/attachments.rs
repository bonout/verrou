//! Pièces jointes et documents.
//!
//! La liste (noms et tailles) vient du cache, sans réseau. Le contenu d'un
//! fichier se télécharge à chaque ouverture, déchiffré dans Rust, puis
//! traverse la frontière vers Swift (qui l'ouvre dans Quick Look depuis un
//! fichier temporaire, effacé ensuite, ou l'écrit où l'utilisateur l'a
//! demandé). Comme les autres secrets, un élément protégé (« redemander le
//! mot de passe principal ») ne livre ses fichiers qu'après confirmation.
//! Limite connue : la copie passée à Swift (`Data`) n'est pas mise à zéro.

use verrou_vaultwarden::AttachmentInfo;

use crate::{VaultSession, VerrouError};

/// Une pièce jointe, telle que la montre la fiche de l'élément. Aucun secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentEntry {
    pub id: String,
    /// Nom du fichier ; vide si le SDK n'a pas pu le déchiffrer.
    pub file_name: String,
    pub readable: bool,
    /// Taille du fichier chiffré, en octets.
    pub size: u64,
}

impl From<AttachmentInfo> for AttachmentEntry {
    fn from(info: AttachmentInfo) -> Self {
        Self {
            id: info.id,
            readable: info.file_name.is_some(),
            file_name: info.file_name.unwrap_or_default(),
            size: info.size,
        }
    }
}

/// Un fichier déchiffré.
#[derive(Clone, uniffi::Record)]
pub struct AttachmentContent {
    pub file_name: String,
    pub data: Vec<u8>,
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Pièces jointes d'un élément (vide pour le coffre fictif).
    pub async fn attachments(&self, item_id: String) -> Result<Vec<AttachmentEntry>, VerrouError> {
        self.with_vault(|v| Self::item(v, &item_id).map(drop))?;
        let Some(connection) = self.current_connection() else {
            return Ok(Vec::new());
        };
        let list = connection.lock().await.attachments(&item_id).await?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// ⚠️ Télécharge et déchiffre une pièce jointe, à la demande de
    /// l'utilisateur (ouvrir, enregistrer sous).
    pub async fn download_attachment(
        &self,
        item_id: String,
        attachment_id: String,
    ) -> Result<AttachmentContent, VerrouError> {
        self.with_vault(|v| self.require_authorized(Self::item(v, &item_id)?))?;
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (file_name, data) = connection
            .lock()
            .await
            .download_attachment(&item_id, &attachment_id)
            .await?;
        Ok(AttachmentContent {
            file_name,
            data: data.to_vec(),
        })
    }

    /// Ajoute un fichier à l'élément, puis resynchronise.
    pub async fn add_attachment(
        &self,
        item_id: String,
        file_name: String,
        data: Vec<u8>,
    ) -> Result<(), VerrouError> {
        let data = zeroize::Zeroizing::new(data);
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .add_attachment(&item_id, &file_name, &data)
            .await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Supprime définitivement une pièce jointe, puis resynchronise.
    pub async fn delete_attachment(
        &self,
        item_id: String,
        attachment_id: String,
    ) -> Result<(), VerrouError> {
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let decrypted = connection
            .lock()
            .await
            .delete_attachment(&item_id, &attachment_id)
            .await?;
        self.install_if_current(&connection, decrypted)
    }

    /// Nouveau « document » : une note sécurisée au nom du fichier, le
    /// fichier en pièce jointe. Rend l'identifiant de la note.
    pub async fn create_document(
        &self,
        file_name: String,
        data: Vec<u8>,
        folder_id: Option<String>,
    ) -> Result<String, VerrouError> {
        let data = zeroize::Zeroizing::new(data);
        let connection = self.current_connection().ok_or(VerrouError::Locked)?;
        let (id, decrypted) = connection
            .lock()
            .await
            .create_document(&file_name, &data, folder_id)
            .await?;
        self.install_if_current(&connection, decrypted)?;
        Ok(id)
    }
}
