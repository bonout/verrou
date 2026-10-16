//! Pièces jointes, au format de Bitwarden.
//!
//! Chaque fichier a sa propre clé (AES-256-CBC + HMAC-SHA256, 64 octets),
//! elle-même chiffrée par la clé de l'élément (ou, à défaut, celle de
//! l'utilisateur ou de l'organisation). Le nom du fichier est chiffré comme
//! un champ de l'élément ; le contenu forme un « `EncArrayBuffer` » : un
//! octet de type (2), le vecteur d'initialisation (16), le MAC (32), puis
//! le texte chiffré. Le SDK fait toute cette cryptographie, MAC vérifié
//! avant tout déchiffrement ; ce module ne fait que le transport.
//!
//! Échanges avec Vaultwarden (1.37) :
//! - ajout, en deux temps (« v2 ») : `POST /api/ciphers/{id}/attachment/v2`
//!   (nom et clé chiffrés, taille du contenu chiffré) réserve la pièce
//!   jointe et rend l'adresse d'envoi, où partent les octets chiffrés
//!   (`multipart/form-data`). Si le second temps échoue, la réservation est
//!   supprimée. Repli sur l'ancien envoi en une fois
//!   (`POST /api/ciphers/{id}/attachment`) pour un serveur qui ne connaît
//!   pas la v2 ;
//! - lecture : `GET /api/ciphers/{id}/attachment/{pièce}` rend une adresse
//!   de téléchargement (signée, valable quelques minutes) ;
//! - suppression : `DELETE /api/ciphers/{id}/attachment/{pièce}`.
//!
//! Rien n'est gardé hors ligne : une pièce jointe se télécharge à chaque
//! ouverture, et son contenu déchiffré n'est rendu qu'en mémoire (effacée à
//! la libération). Le cache du coffre ne contient que les métadonnées
//! chiffrées, comme le reste de la synchronisation.

use std::collections::HashMap;
use std::time::Duration;

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_vault::{
    AttachmentEncryptResult, AttachmentView, Cipher, CipherView, DecryptError, VaultClientExt,
};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use serde_json::{Value, json};
use verrou_core::import::{ImportedFile, MAX_ATTACHMENT_SIZE};
use zeroize::Zeroizing;

use crate::api::{Api, write_response};
use crate::edit::new_view;
use crate::{Connection, Decrypted, Draft, Error};

/// Envoi ou téléchargement d'un gros fichier : bien plus long qu'une écriture.
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Surcoût du chiffrement : type, IV, MAC et bourrage (au plus un bloc).
pub(crate) const ENCRYPTION_OVERHEAD: u64 = 1 + 16 + 32 + 16;

/// Une pièce jointe d'un élément, telle que l'interface la montre. Aucun
/// secret : le nom, déchiffré, et la taille annoncée par le serveur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub id: String,
    /// Nom du fichier ; `None` si le SDK n'a pas pu le déchiffrer.
    pub file_name: Option<String>,
    /// Taille du fichier chiffré, en octets.
    pub size: u64,
    /// Taille lisible (« 1,4 MB »), calculée par le serveur.
    pub size_name: String,
}

impl Connection {
    /// Pièces jointes d'un élément, d'après le cache (sans réseau).
    pub async fn attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>, Error> {
        let view = self.cached_view(item_id).await?;
        let readable = view
            .attachments
            .iter()
            .flatten()
            .map(|a| info(a, a.file_name.clone()));
        let unreadable = view
            .attachment_decryption_failures
            .iter()
            .flatten()
            .map(|a| info(a, None));
        Ok(readable
            .chain(unreadable)
            .filter(|a| !a.id.is_empty())
            .collect())
    }

    /// Nombre de pièces jointes de chaque élément qui en a, d'après le cache
    /// et sans rien déchiffrer : pour choisir quel doublon garder.
    pub fn attachment_counts(&self) -> Result<HashMap<String, usize>, Error> {
        Ok(self
            .cached_ciphers()?
            .into_iter()
            .filter_map(|c| {
                let count = c.attachments.as_ref().map_or(0, Vec::len);
                let id = c.id?;
                (count > 0).then(|| (id.to_string(), count))
            })
            .collect())
    }

    /// Télécharge une pièce jointe et la déchiffre. Le contenu n'existe
    /// qu'en mémoire, effacée à la libération.
    pub async fn download_attachment(
        &mut self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
        let cipher = self.cached_cipher(item_id)?;
        let view = self.decrypt_view(cipher.clone()).await?;
        let attachment = view
            .attachments
            .into_iter()
            .flatten()
            .find(|a| a.id.as_deref() == Some(attachment_id))
            .ok_or(Error::NotFound)?;
        let name = attachment
            .file_name
            .clone()
            .unwrap_or_else(|| "pièce jointe".to_owned());
        let access = self.access_token().await?;
        let plain = Box::pin(self.fetch_attachment(&access, item_id, cipher, attachment)).await?;
        Ok((name, plain))
    }

    /// Télécharge et déchiffre une pièce jointe d'un élément chiffré
    /// (`cipher`) : vérifie sa taille, puis la déchiffre par le SDK.
    pub(crate) async fn fetch_attachment(
        &self,
        access: &str,
        item_id: &str,
        cipher: Cipher,
        attachment: AttachmentView,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let attachment_id = attachment.id.clone().ok_or(Error::NotFound)?;
        let expected = attachment
            .size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok());
        let url = self
            .api
            .attachment_url(access, item_id, &attachment_id)
            .await?;
        let encrypted = self
            .api
            .download(&url, MAX_ATTACHMENT_SIZE + ENCRYPTION_OVERHEAD)
            .await?;
        if expected.is_some_and(|size| size != encrypted.len() as u64) {
            return Err(Error::Crypto(
                "pièce jointe incomplète (taille inattendue)".to_owned(),
            ));
        }
        let plain = self
            .sdk
            .vault()
            .attachments()
            .decrypt_buffer(cipher, attachment, &encrypted)
            .map_err(|e| attachment_error(&e))?;
        Ok(Zeroizing::new(plain))
    }

    /// Ajoute un fichier à un élément modifiable, puis synchronise.
    pub async fn add_attachment(
        &mut self,
        item_id: &str,
        file_name: &str,
        contents: &[u8],
    ) -> Result<Decrypted, Error> {
        let file_name = checked_name(file_name, contents)?;
        let access = self.require_online("L'ajout d'une pièce jointe").await?;
        let item_id = &self.resolve(item_id);
        // Refuse un élément en lecture seule ou à la corbeille.
        self.editable_view(item_id).await?;
        let cipher = self.cached_cipher(item_id)?;
        let encrypted = self.encrypt_file(cipher, file_name, contents)?;
        self.api
            .upload_attachment(&access, item_id, encrypted)
            .await?;
        self.sync_with(&access).await
    }

    /// Retire une pièce jointe (définitivement), puis synchronise.
    pub async fn delete_attachment(
        &mut self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Decrypted, Error> {
        let access = self
            .require_online("La suppression d'une pièce jointe")
            .await?;
        let item_id = &self.resolve(item_id);
        let view = self.editable_view(item_id).await?;
        if !view
            .attachments
            .iter()
            .flatten()
            .chain(view.attachment_decryption_failures.iter().flatten())
            .any(|a| a.id.as_deref() == Some(attachment_id))
        {
            return Err(Error::NotFound);
        }
        self.api
            .delete_attachment(&access, item_id, attachment_id)
            .await?;
        self.sync_with(&access).await
    }

    /// « Document » : une note sécurisée au nom du fichier (sans son
    /// extension), avec le fichier en pièce jointe. Si l'envoi du fichier
    /// échoue, la note est supprimée.
    pub async fn create_document(
        &mut self,
        file_name: &str,
        contents: &[u8],
        folder_id: Option<String>,
    ) -> Result<(String, Decrypted), Error> {
        let file_name = checked_name(file_name, contents)?;
        self.require_online("L'ajout d'un document").await?;
        let draft = Draft {
            name: document_title(file_name),
            folder_id,
            ..Draft::default()
        };
        let file = ImportedFile::new(file_name, contents.to_vec());
        let id = self
            .create_with_files(draft_view(draft)?, std::slice::from_ref(&file))
            .await?;
        let access = self.access_token().await?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Crée un élément (chiffré par le SDK) puis lui joint `files`. Si un
    /// fichier ne part pas, l'élément est supprimé et l'erreur rendue : pas
    /// d'élément à moitié importé. Ne synchronise pas.
    pub(crate) async fn create_with_files(
        &mut self,
        view: CipherView,
        files: &[ImportedFile],
    ) -> Result<String, Error> {
        for file in files {
            checked_name(&file.name, &file.data)?;
        }
        let encrypted = self
            .sdk
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .map_err(Error::crypto)?;
        let cipher = encrypted.cipher.clone();
        let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
        request.encrypted_for = Some(encrypted.encrypted_for.into());
        request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
        let access = self.access_token().await?;
        let id = self.api.create_cipher(&access, &request).await?;
        let mut sent = Ok(());
        for file in files {
            let attachment = self.encrypt_file(cipher.clone(), file.name.trim(), &file.data);
            sent = match attachment {
                Ok(attachment) => self.api.upload_attachment(&access, &id, attachment).await,
                Err(error) => Err(error),
            };
            if sent.is_err() {
                break;
            }
        }
        if let Err(error) = sent {
            let _ = self.api.delete_cipher(&access, &id).await;
            return Err(error);
        }
        Ok(id)
    }

    fn encrypt_file(
        &self,
        cipher: Cipher,
        file_name: &str,
        contents: &[u8],
    ) -> Result<AttachmentEncryptResult, Error> {
        self.sdk
            .vault()
            .attachments()
            .encrypt_buffer(cipher, new_attachment(file_name), contents)
            .map_err(Error::crypto)
    }

    async fn cached_view(&self, id: &str) -> Result<CipherView, Error> {
        let cipher = self.cached_cipher(id)?;
        self.decrypt_view(cipher).await
    }

    pub(crate) async fn decrypt_view(&self, cipher: Cipher) -> Result<CipherView, Error> {
        // Sur le tas : la tâche du SDK est volumineuse (plus de 20 Ko).
        Box::pin(self.sdk.vault().ciphers().decrypt(cipher))
            .await
            .map_err(Error::crypto)
    }
}

fn info(attachment: &AttachmentView, file_name: Option<String>) -> AttachmentInfo {
    let size = attachment
        .size
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    AttachmentInfo {
        id: attachment.id.clone().unwrap_or_default(),
        file_name,
        size,
        size_name: attachment.size_name.clone().unwrap_or_default(),
    }
}

/// Pièce jointe à créer : le SDK lui tire sa clé au chiffrement.
fn new_attachment(file_name: &str) -> AttachmentView {
    AttachmentView {
        id: None,
        url: None,
        size: None,
        size_name: None,
        file_name: Some(file_name.to_owned()),
        key: None,
    }
}

/// Nom sans espaces autour, non vide ; fichier sous la limite.
fn checked_name<'a>(file_name: &'a str, contents: &[u8]) -> Result<&'a str, Error> {
    let name = file_name.trim();
    if name.is_empty() {
        return Err(Error::Invalid("le fichier n'a pas de nom".to_owned()));
    }
    if contents.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err(Error::Invalid(format!(
            "« {name} » dépasse 100 Mo, la taille maximale d'une pièce jointe"
        )));
    }
    Ok(name)
}

/// `Passeport.pdf` → `Passeport` ; `.env` reste `.env`.
fn document_title(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, _)) if !stem.trim().is_empty() => stem.trim().to_owned(),
        _ => file_name.to_owned(),
    }
}

fn draft_view(draft: Draft) -> Result<CipherView, Error> {
    new_view(draft, Utc::now())
}

/// Un MAC faux ou un contenu tronqué : le fichier a été altéré (ou la clé
/// n'est pas la bonne). Rien n'est rendu.
fn attachment_error(error: &DecryptError) -> Error {
    Error::Crypto(format!("pièce jointe altérée ou illisible ({error})"))
}

/// Adresse donnée par le serveur : absolue, ou relative à `base`.
pub(crate) fn resolve(url: &str, base: &str) -> Result<String, Error> {
    let absolute = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_owned()
    } else if url.starts_with('/') {
        format!("{base}{url}")
    } else {
        return Err(Error::Server(format!(
            "adresse de fichier inattendue ({url})"
        )));
    };
    let parsed = reqwest::Url::parse(&absolute)
        .map_err(|e| Error::Server(format!("adresse de fichier invalide ({e})")))?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !local {
        return Err(Error::Server(
            "adresse de fichier en clair (HTTP) refusée".to_owned(),
        ));
    }
    Ok(absolute)
}

impl Api {
    /// Adresse de téléchargement d'une pièce jointe (signée, de courte durée).
    pub(crate) async fn attachment_url(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<String, Error> {
        let response = self
            .http
            .get(format!(
                "{}/api/ciphers/{cipher_id}/attachment/{attachment_id}",
                self.base
            ))
            .bearer_auth(access_token)
            .send()
            .await?;
        let body = write_response(response).await?;
        let url = body
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("pièce jointe sans adresse".to_owned()))?;
        resolve(url, &self.base)
    }

    /// Le fichier chiffré, sans en-tête d'authentification : l'adresse porte
    /// sa propre signature (et peut viser un stockage externe).
    pub(crate) async fn download(&self, url: &str, limit: u64) -> Result<Vec<u8>, Error> {
        let mut response = self.http.get(url).timeout(TRANSFER_TIMEOUT).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(if status == reqwest::StatusCode::NOT_FOUND {
                Error::NotFound
            } else {
                Error::Server(status.to_string())
            });
        }
        if response.content_length().is_some_and(|l| l > limit) {
            return Err(Error::Server("pièce jointe trop volumineuse".to_owned()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if (bytes.len() + chunk.len()) as u64 > limit {
                return Err(Error::Server("pièce jointe trop volumineuse".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Envoie une pièce jointe chiffrée : réservation (v2) puis contenu ;
    /// l'ancien envoi en une fois si le serveur ne connaît pas la v2.
    pub(crate) async fn upload_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment: AttachmentEncryptResult,
    ) -> Result<(), Error> {
        let file_name = attachment
            .attachment
            .file_name
            .as_ref()
            .ok_or_else(|| Error::Crypto("nom de fichier non chiffré".to_owned()))?
            .to_string();
        let key = attachment
            .attachment
            .key
            .as_ref()
            .ok_or_else(|| Error::Crypto("clé de pièce jointe absente".to_owned()))?
            .to_string();
        let contents = attachment.contents;
        let response = self
            .http
            .post(format!(
                "{}/api/ciphers/{cipher_id}/attachment/v2",
                self.base
            ))
            .bearer_auth(access_token)
            .json(&json!({
                "key": key,
                "fileName": file_name,
                "fileSize": contents.len(),
                "adminRequest": false,
            }))
            .send()
            .await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
        ) {
            return self
                .upload_legacy(access_token, cipher_id, &file_name, &key, contents)
                .await;
        }
        let body = write_response(response).await?;
        let attachment_id = body
            .get("attachmentId")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("réservation sans identifiant".to_owned()))?
            .to_owned();
        let sent = self
            .upload_reserved(access_token, &body, &file_name, contents)
            .await;
        if sent.is_err() {
            // Pas de pièce jointe vide laissée sur le serveur.
            let _ = self
                .delete_attachment(access_token, cipher_id, &attachment_id)
                .await;
        }
        sent
    }

    pub(crate) async fn upload_reserved(
        &self,
        access_token: &str,
        reservation: &Value,
        file_name: &str,
        contents: Vec<u8>,
    ) -> Result<(), Error> {
        // 0 : envoi direct au serveur ; 1 : Azure (serveur officiel seulement).
        if reservation.get("fileUploadType").and_then(Value::as_i64) != Some(0) {
            return Err(Error::Server(
                "envoi vers un stockage externe non pris en charge".to_owned(),
            ));
        }
        let url = reservation
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Server("réservation sans adresse".to_owned()))?;
        // Vaultwarden rend une adresse relative à l'API.
        let url = resolve(url, &format!("{}/api", self.base))?;
        if !url.starts_with(&self.base) {
            return Err(Error::Server(
                "adresse d'envoi hors du serveur du compte".to_owned(),
            ));
        }
        let form = Form::new().part("data", file_part(file_name, contents)?);
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .timeout(TRANSFER_TIMEOUT)
            .multipart(form)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Ancien envoi, en une requête : clé et contenu ensemble.
    async fn upload_legacy(
        &self,
        access_token: &str,
        cipher_id: &str,
        file_name: &str,
        key: &str,
        contents: Vec<u8>,
    ) -> Result<(), Error> {
        let form = Form::new()
            .text("key", key.to_owned())
            .part("data", file_part(file_name, contents)?);
        let response = self
            .http
            .post(format!("{}/api/ciphers/{cipher_id}/attachment", self.base))
            .bearer_auth(access_token)
            .timeout(TRANSFER_TIMEOUT)
            .multipart(form)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    pub(crate) async fn delete_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<(), Error> {
        let response = self
            .http
            .delete(format!(
                "{}/api/ciphers/{cipher_id}/attachment/{attachment_id}",
                self.base
            ))
            .bearer_auth(access_token)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Supprime définitivement un élément (sans passer par la corbeille).
    pub(crate) async fn delete_cipher(&self, access_token: &str, id: &str) -> Result<(), Error> {
        let response = self
            .http
            .delete(format!("{}/api/ciphers/{id}", self.base))
            .bearer_auth(access_token)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }
}

/// Le contenu chiffré, nommé par le nom de fichier chiffré (comme les apps
/// Bitwarden) : le serveur ne voit jamais le vrai nom.
pub(crate) fn file_part(encrypted_name: &str, contents: Vec<u8>) -> Result<Part, Error> {
    Part::bytes(contents)
        .file_name(encrypted_name.to_owned())
        .mime_str("application/octet-stream")
        .map_err(|e| Error::Server(e.to_string()))
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{EncString, SymmetricCryptoKey};
    use bitwarden_vault::{AttachmentFile, AttachmentFileView};

    use super::*;

    /// Clé d'utilisateur et vecteurs tirés des tests du SDK de Bitwarden :
    /// un fichier chiffré par une app officielle, à relire tel quel.
    const USER_KEY: &str =
        "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";
    const CIPHER_KEY: &str = "2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=";
    const ATTACHMENT_KEY: &str = "2.r288/AOSPiaLFkW07EBGBw==|SAmnnCbOLFjX5lnURvoualOetQwuyPc54PAmHDTRrhT0gwO9ailna9U09q9bmBfI5XrjNNEsuXssgzNygRkezoVQvZQggZddOwHB6KQW5EQ=|erIMUJp8j+aTcmhdE50zEX+ipv/eR1sZ7EwULJm/6DY=";
    const ENCRYPTED_FILE: &str = "Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=";
    const ORIGINAL: &str = "rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==";

    fn base64(text: &str) -> Vec<u8> {
        data_encoding::BASE64.decode(text.as_bytes()).unwrap()
    }

    fn cipher(key: Option<&str>) -> Cipher {
        serde_json::from_value(json!({
            "id": null, "organizationId": null, "folderId": null, "collectionIds": [],
            "key": key,
            "name": "2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM=",
            "notes": null, "type": 1, "login": null, "identity": null, "card": null,
            "secureNote": null, "sshKey": null, "favorite": false, "reprompt": 0,
            "organizationUseTotp": false, "edit": true, "permissions": null,
            "viewPassword": true, "localData": null, "attachments": null, "fields": null,
            "passwordHistory": null, "creationDate": "2023-07-24T12:05:09.466Z",
            "deletedDate": null, "revisionDate": "2023-07-27T19:28:05.240Z",
            "archivedDate": null, "data": null,
        }))
        .unwrap()
    }

    fn store() -> bitwarden_crypto::KeyStore<bitwarden_core::key_management::KeySlotIds> {
        let key: SymmetricCryptoKey = USER_KEY.to_owned().try_into().unwrap();
        create_test_crypto_with_user_key(key)
    }

    /// Un fichier chiffré par Bitwarden (clé de pièce jointe chiffrée par la
    /// clé de l'élément) se relit à l'identique.
    #[test]
    fn known_bitwarden_file_decrypts() {
        let store = store();
        // La clé de la pièce jointe, telle que la synchronisation la donne.
        let attachment = bitwarden_vault::Attachment {
            id: Some("a1".to_owned()),
            url: None,
            size: Some("161".to_owned()),
            size_name: Some("161 Bytes".to_owned()),
            file_name: Some(
                "2.d24xECyEdMZ3MG9s6SrGNw==|XvJlTeu5KJ22M3jKosy6iw==|8xGiQty4X61cDMx6PVqkJfSQ0ZTdA/5L9TpG7QfovoM="
                    .parse()
                    .unwrap(),
            ),
            key: Some(ATTACHMENT_KEY.parse().unwrap()),
        };
        let encrypted = base64(ENCRYPTED_FILE);
        assert_eq!(encrypted[0], 2, "type 2 : AES-CBC-256 + HMAC-SHA256");
        assert_eq!(
            encrypted.len(),
            1 + 16 + 32 + 112,
            "type | IV | MAC | texte chiffré"
        );
        let cipher = cipher(Some(CIPHER_KEY));
        let view = attachment_view(&store, &cipher, &attachment);
        let plain = store
            .decrypt(&AttachmentFile {
                cipher,
                attachment: view,
                contents: EncString::from_buffer(&encrypted).unwrap(),
            })
            .unwrap();
        assert_eq!(plain, base64(ORIGINAL));
    }

    /// La clé de pièce jointe se déchiffre avec celle de l'élément, comme
    /// le fait `CipherView` à la synchronisation.
    fn attachment_view(
        store: &bitwarden_crypto::KeyStore<bitwarden_core::key_management::KeySlotIds>,
        cipher: &Cipher,
        attachment: &bitwarden_vault::Attachment,
    ) -> AttachmentView {
        let mut with_attachment = cipher.clone();
        with_attachment.attachments = Some(vec![attachment.clone()]);
        let view: CipherView = store.decrypt(&with_attachment).unwrap();
        // Nom illisible (vecteur sans nom chiffré connu) : la clé, elle,
        // est quand même rendue.
        view.attachments
            .into_iter()
            .chain(view.attachment_decryption_failures)
            .flatten()
            .next()
            .unwrap()
    }

    /// Aller-retour : chiffré avec une clé neuve, enveloppée par la clé de
    /// l'élément ; un octet changé (contenu ou MAC) fait tout refuser.
    #[test]
    fn round_trip_and_tampering() {
        let store = store();
        let contents = "Bail signé — page 1/3\n".repeat(500).into_bytes();
        for key in [Some(CIPHER_KEY), None] {
            let cipher = cipher(key);
            let result: AttachmentEncryptResult = store
                .encrypt(AttachmentFileView {
                    cipher: cipher.clone(),
                    attachment: new_attachment("bail.txt"),
                    contents: &contents,
                })
                .unwrap();
            assert_eq!(result.contents[0], 2);
            assert_eq!(
                result.attachment.size.as_deref(),
                Some(result.contents.len().to_string().as_str())
            );
            assert!(result.contents.len() as u64 <= contents.len() as u64 + ENCRYPTION_OVERHEAD);
            assert!(
                !result.contents.windows(4).any(|w| w == b"Bail"),
                "rien en clair"
            );
            let view = attachment_view(&store, &cipher, &result.attachment);
            assert_eq!(view.file_name.as_deref(), Some("bail.txt"));
            let decrypt = |bytes: &[u8]| {
                store.decrypt(&AttachmentFile {
                    cipher: cipher.clone(),
                    attachment: view.clone(),
                    contents: EncString::from_buffer(bytes)?,
                })
            };
            assert_eq!(decrypt(&result.contents).unwrap(), contents);
            for position in [20, 60, result.contents.len() - 1] {
                let mut altered = result.contents.clone();
                altered[position] ^= 1;
                assert!(decrypt(&altered).is_err(), "octet {position} modifié");
            }
            assert!(decrypt(&result.contents[..result.contents.len() - 16]).is_err());
        }
    }

    #[test]
    fn server_addresses_are_resolved() {
        assert_eq!(
            resolve("/ciphers/c/attachment/a", "https://vault.exemple.fr/api").unwrap(),
            "https://vault.exemple.fr/api/ciphers/c/attachment/a"
        );
        assert_eq!(
            resolve(
                "https://vault.exemple.fr/attachments/c/a?token=x",
                "https://vault.exemple.fr"
            )
            .unwrap(),
            "https://vault.exemple.fr/attachments/c/a?token=x"
        );
        assert!(resolve("http://vault.exemple.fr/attachments/c/a", "https://x").is_err());
        assert!(
            resolve(
                "http://localhost:8104/attachments/c/a",
                "http://localhost:8104"
            )
            .is_ok()
        );
        assert!(resolve("ftp://x", "https://x").is_err());
    }

    #[test]
    fn names_titles_and_limits() {
        assert_eq!(document_title("Passeport.pdf"), "Passeport");
        assert_eq!(document_title("archive.tar.gz"), "archive.tar");
        assert_eq!(document_title(".env"), ".env");
        assert_eq!(document_title("LISEZMOI"), "LISEZMOI");
        assert!(checked_name("  ", b"x").is_err());
        assert_eq!(checked_name(" a.txt ", b"x").unwrap(), "a.txt");
        let too_big = vec![0; MAX_ATTACHMENT_SIZE as usize + 1];
        assert!(matches!(
            checked_name("gros.bin", &too_big),
            Err(Error::Invalid(_))
        ));
    }
}
