//! Passkeys dans le coffre : ajout, compteur, suppression.
//!
//! Elles vivent dans `login.fido2Credentials` d'un identifiant, chiffrées
//! champ par champ par le SDK comme le reste de l'élément : les apps
//! Bitwarden et le coffre web les relisent. Comme Bitwarden, un identifiant
//! porte une passkey : en enregistrer une nouvelle remplace l'ancienne.

use bitwarden_vault::Fido2CredentialView;
use chrono::{DateTime, Utc};
use verrou_core::Passkey;

use crate::edit::{Draft, LoginDraft, new_view};
use crate::{Connection, Decrypted, Error};

/// Au format de Bitwarden : tout en texte, la clé en PKCS#8 base64url.
fn credential(passkey: &Passkey) -> Fido2CredentialView {
    Fido2CredentialView {
        credential_id: passkey.credential_id.clone(),
        key_type: "public-key".to_owned(),
        key_algorithm: "ECDSA".to_owned(),
        key_curve: "P-256".to_owned(),
        key_value: passkey.key.expose().to_owned(),
        rp_id: passkey.rp_id.clone(),
        user_handle: passkey.user_handle.clone(),
        user_name: passkey.user_name.clone(),
        counter: passkey.counter.to_string(),
        rp_name: passkey.rp_name.clone(),
        user_display_name: passkey.user_display_name.clone(),
        discoverable: passkey.discoverable.to_string(),
        creation_date: DateTime::<Utc>::from_timestamp(passkey.created, 0).unwrap_or_else(Utc::now),
    }
}

impl Connection {
    /// Enregistre `passkey` dans l'identifiant `item` (sa passkey précédente
    /// est remplacée), ou dans un nouvel identifiant (`title`, `uri`,
    /// `username`). Rend l'identifiant de l'élément et le coffre resynchronisé.
    pub async fn save_passkey(
        &mut self,
        item: Option<&str>,
        title: String,
        uri: String,
        username: Option<String>,
        passkey: &Passkey,
    ) -> Result<(String, Decrypted), Error> {
        let mut view = if let Some(id) = item {
            let mut view = self.editable_view(id).await?;
            let Some(login) = view.login.as_mut() else {
                return Err(Error::Invalid(
                    "cet élément n'est pas un identifiant".to_owned(),
                ));
            };
            if login.username.as_deref().is_none_or(str::is_empty) {
                login.username = username.filter(|u| !u.trim().is_empty());
            }
            view
        } else {
            new_view(
                Draft {
                    name: title,
                    login: Some(LoginDraft {
                        username,
                        password: None,
                        totp: None,
                        uris: vec![uri],
                    }),
                    ..Draft::default()
                },
                Utc::now(),
            )?
        };
        if let Some(login) = view.login.as_mut() {
            login.fido2_credentials = Some(vec![credential(passkey)]);
        }
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        let id = if let Some(id) = item {
            self.api.update_cipher(&access, id, &request).await?;
            id.to_owned()
        } else {
            self.api.create_cipher(&access, &request).await?
        };
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    /// Nouveau compteur d'une passkey, après une authentification.
    pub async fn set_passkey_counter(
        &mut self,
        item: &str,
        credential_id: &str,
        counter: u32,
    ) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(item).await?;
        let credential = view
            .login
            .as_mut()
            .and_then(|l| l.fido2_credentials.as_mut())
            .and_then(|list| list.iter_mut().find(|c| c.credential_id == credential_id))
            .ok_or(Error::NotFound)?;
        credential.counter = counter.to_string();
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, item, &request).await?;
        self.sync_with(&access).await
    }

    /// Retire une passkey de l'identifiant ; le reste de l'élément est gardé.
    pub async fn delete_passkey(
        &mut self,
        item: &str,
        credential_id: &str,
    ) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(item).await?;
        let list = view
            .login
            .as_mut()
            .and_then(|l| l.fido2_credentials.as_mut())
            .ok_or(Error::NotFound)?;
        let before = list.len();
        list.retain(|c| c.credential_id != credential_id);
        if list.len() == before {
            return Err(Error::NotFound);
        }
        if list.is_empty() {
            view.login.as_mut().map(|l| l.fido2_credentials.take());
        }
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, item, &request).await?;
        self.sync_with(&access).await
    }
}
