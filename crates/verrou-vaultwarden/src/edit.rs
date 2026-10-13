//! Écriture dans le coffre : créer, modifier, mettre à la corbeille.
//!
//! Même répartition que pour la lecture : le SDK chiffre (`CipherView` →
//! `Cipher` → requête d'API), Verrou envoie la requête. Une modification part
//! de l'élément tel que le cache le connaît, déchiffré, et ne touche qu'aux
//! champs que Verrou sait éditer : le reste (champs personnalisés, passkeys,
//! pièces jointes, historique) repart intact. La date de révision envoyée
//! permet au serveur de refuser une modification faite sur une copie périmée.

use bitwarden_api_api::models::{CipherRequestModel, SyncResponseModel};
use bitwarden_vault::{
    Cipher, CipherRepromptType, CipherType, CipherView, FolderId, LoginUriView, LoginView,
    PasswordHistoryView, SecureNoteType, SecureNoteView, VaultClientExt,
};
use chrono::{DateTime, Utc};
use verrou_core::SecretString;

use crate::{Connection, Decrypted, Error};

/// Anciens mots de passe gardés par élément, comme les apps Bitwarden.
const MAX_PASSWORD_HISTORY: usize = 5;

/// Ce que l'écran d'édition modifie. Un brouillon sans `login` crée une note
/// sécurisée.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<SecretString>,
    pub login: Option<LoginDraft>,
}

#[derive(Clone, Debug, Default)]
pub struct LoginDraft {
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub totp: Option<SecretString>,
    pub uris: Vec<String>,
}

impl Connection {
    /// Brouillon prérempli pour modifier un élément.
    pub async fn draft(&self, id: &str) -> Result<Draft, Error> {
        let view = self.editable_view(id).await?;
        Ok(Draft {
            name: view.name,
            folder_id: view.folder_id.map(|f| f.to_string()),
            favorite: view.favorite,
            notes: view.notes.filter(|n| !n.is_empty()).map(SecretString::new),
            login: view.login.map(|login| LoginDraft {
                username: login.username,
                password: login.password.map(SecretString::new),
                totp: login.totp.map(SecretString::new),
                uris: login
                    .uris
                    .into_iter()
                    .flatten()
                    .filter_map(|u| u.uri)
                    .collect(),
            }),
        })
    }

    /// Crée l'élément dans le coffre personnel ; rend son identifiant et le
    /// coffre resynchronisé.
    pub async fn create(&mut self, draft: Draft) -> Result<(String, Decrypted), Error> {
        let view = new_view(draft, Utc::now())?;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        let id = self.api.create_cipher(&access, &request).await?;
        let vault = self.sync_with(&access).await?;
        Ok((id, vault))
    }

    pub async fn update(&mut self, id: &str, draft: Draft) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(id).await?;
        apply(&mut view, draft, Utc::now())?;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, id, &request).await?;
        self.sync_with(&access).await
    }

    /// Remplace, dans un identifiant existant, ce qui est fourni : le mot de
    /// passe (l'ancien rejoint l'historique), la graine TOTP, et l'identifiant
    /// seulement s'il n'y en a pas. Le reste de l'élément repart intact.
    /// C'est l'écriture de l'extension de navigateur.
    pub async fn amend_login(
        &mut self,
        id: &str,
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
    ) -> Result<Decrypted, Error> {
        let mut draft = self.draft(id).await?;
        let Some(login) = draft.login.as_mut() else {
            return Err(Error::Invalid(
                "cet élément n'est pas un identifiant".to_owned(),
            ));
        };
        if login.username.as_deref().is_none_or(str::is_empty) && username.is_some() {
            login.username = username;
        }
        if password.is_some() {
            login.password = password;
        }
        if totp.is_some() {
            login.totp = totp;
        }
        self.update(id, draft).await
    }

    /// Corbeille du serveur : l'élément se restaure depuis le coffre web
    /// pendant 30 jours (réglage de Vaultwarden).
    pub async fn trash(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.editable_view(id).await?;
        let access = self.access_token().await?;
        self.api.trash_cipher(&access, id).await?;
        self.sync_with(&access).await
    }

    /// Archive l'élément (ou le sort des archives) : il quitte la liste
    /// principale et le remplissage, sans être supprimé.
    pub async fn set_archived(&mut self, id: &str, archived: bool) -> Result<Decrypted, Error> {
        self.editable_view(id).await?;
        let access = self.access_token().await?;
        let action = if archived { "archive" } else { "unarchive" };
        self.api.cipher_action(&access, id, action).await?;
        self.sync_with(&access).await
    }

    /// Sort l'élément de la corbeille.
    pub async fn restore(&mut self, id: &str) -> Result<Decrypted, Error> {
        let access = self.access_token().await?;
        self.api.cipher_action(&access, id, "restore").await?;
        self.sync_with(&access).await
    }

    pub async fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<Decrypted, Error> {
        let mut view = self.editable_view(id).await?;
        view.favorite = favorite;
        let request = self.encrypt(view).await?;
        let access = self.access_token().await?;
        self.api.update_cipher(&access, id, &request).await?;
        self.sync_with(&access).await
    }

    /// L'élément tel que le cache le connaît, déchiffré, s'il peut être modifié.
    async fn editable_view(&self, id: &str) -> Result<CipherView, Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        let model = sync
            .ciphers
            .unwrap_or_default()
            .into_iter()
            .find(|c| c.id.is_some_and(|c| c.to_string() == id))
            .ok_or(Error::NotFound)?;
        let cipher = Cipher::try_from(model).map_err(Error::crypto)?;
        let view = self
            .sdk
            .vault()
            .ciphers()
            .decrypt(cipher)
            .await
            .map_err(Error::crypto)?;
        if !view.edit || view.partial || view.deleted_date.is_some() {
            return Err(Error::ReadOnly);
        }
        Ok(view)
    }

    async fn encrypt(&self, view: CipherView) -> Result<CipherRequestModel, Error> {
        let encrypted = self
            .sdk
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .map_err(Error::crypto)?;
        let mut request = CipherRequestModel::try_from(encrypted.cipher).map_err(Error::crypto)?;
        request.encrypted_for = Some(encrypted.encrypted_for.into());
        request.encrypted_by_key_id = encrypted.encrypted_by_key_id;
        Ok(request)
    }
}

fn folder_id(id: Option<String>) -> Result<Option<FolderId>, Error> {
    id.filter(|f| !f.is_empty())
        .map(|f| {
            f.parse()
                .map_err(|_| Error::Storage(format!("dossier inconnu ({f})")))
        })
        .transpose()
}

fn text(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn secret(value: Option<SecretString>) -> Option<String> {
    text(value.map(|v| v.expose().to_owned()))
}

fn uris(list: Vec<String>, previous: &[LoginUriView]) -> Option<Vec<LoginUriView>> {
    let uris: Vec<LoginUriView> = list
        .into_iter()
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .map(|uri| {
            // Un site gardé garde sa règle de correspondance.
            let rule = previous
                .iter()
                .find(|p| p.uri.as_deref() == Some(uri.as_str()))
                .and_then(|p| p.r#match);
            LoginUriView {
                uri: Some(uri),
                r#match: rule,
                uri_checksum: None,
            }
        })
        .collect();
    (!uris.is_empty()).then_some(uris)
}

fn new_view(draft: Draft, now: DateTime<Utc>) -> Result<CipherView, Error> {
    let name = draft.name.trim().to_owned();
    if name.is_empty() {
        return Err(Error::Invalid("le titre est obligatoire".to_owned()));
    }
    let (r#type, login, secure_note) = match draft.login {
        Some(d) => {
            let mut login = LoginView {
                username: text(d.username),
                password: secret(d.password),
                password_revision_date: None,
                uris: uris(d.uris, &[]),
                totp: secret(d.totp),
                autofill_on_page_load: None,
                fido2_credentials: None,
            };
            login.generate_checksums();
            (CipherType::Login, Some(login), None)
        }
        None => (
            CipherType::SecureNote,
            None,
            Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            }),
        ),
    };
    Ok(CipherView {
        id: None,
        organization_id: None,
        folder_id: folder_id(draft.folder_id)?,
        collection_ids: Vec::new(),
        key: None,
        name,
        notes: secret(draft.notes),
        r#type,
        login,
        identity: None,
        card: None,
        secure_note,
        ssh_key: None,
        bank_account: None,
        drivers_license: None,
        passport: None,
        favorite: draft.favorite,
        reprompt: CipherRepromptType::None,
        organization_use_totp: false,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields: None,
        password_history: None,
        creation_date: now,
        deleted_date: None,
        revision_date: now,
        archived_date: None,
        partial: false,
    })
}

/// Reporte le brouillon sur l'élément. Un mot de passe remplacé rejoint
/// l'historique de l'élément.
fn apply(view: &mut CipherView, draft: Draft, now: DateTime<Utc>) -> Result<(), Error> {
    let name = draft.name.trim().to_owned();
    if name.is_empty() {
        return Err(Error::Invalid("le titre est obligatoire".to_owned()));
    }
    view.name = name;
    view.folder_id = folder_id(draft.folder_id)?;
    view.favorite = draft.favorite;
    view.notes = secret(draft.notes);
    let (Some(d), Some(login)) = (draft.login, view.login.as_mut()) else {
        return Ok(());
    };
    let password = secret(d.password);
    if let Some(old) = login
        .password
        .take()
        .filter(|old| Some(old) != password.as_ref())
    {
        let mut history = vec![PasswordHistoryView {
            password: old,
            last_used_date: now,
        }];
        history.extend(view.password_history.take().into_iter().flatten());
        history.truncate(MAX_PASSWORD_HISTORY);
        view.password_history = Some(history);
        login.password_revision_date = Some(now);
    }
    login.password = password;
    login.username = text(d.username);
    login.totp = secret(d.totp);
    login.uris = uris(d.uris, login.uris.as_deref().unwrap_or_default());
    login.generate_checksums();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_draft(password: &str) -> Draft {
        Draft {
            name: " Exemple ".to_owned(),
            login: Some(LoginDraft {
                username: Some("camille".to_owned()),
                password: Some(SecretString::new(password)),
                totp: None,
                uris: vec!["https://exemple.fr".to_owned(), "  ".to_owned()],
            }),
            ..Draft::default()
        }
    }

    #[test]
    fn new_login_is_trimmed_and_personal() {
        let view = new_view(login_draft("un"), Utc::now()).unwrap();
        assert_eq!(view.name, "Exemple");
        assert_eq!(view.r#type, CipherType::Login);
        assert!(view.organization_id.is_none());
        let login = view.login.unwrap();
        assert_eq!(login.uris.unwrap().len(), 1);
        assert!(login.totp.is_none());
    }

    #[test]
    fn draft_without_login_is_a_note_and_title_is_required() {
        let note = new_view(
            Draft {
                name: "Wi-Fi".to_owned(),
                ..Draft::default()
            },
            Utc::now(),
        )
        .unwrap();
        assert_eq!(note.r#type, CipherType::SecureNote);
        assert!(matches!(
            new_view(Draft::default(), Utc::now()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn replaced_password_goes_to_history() {
        let now = Utc::now();
        let mut view = new_view(login_draft("ancien"), now).unwrap();
        apply(&mut view, login_draft("ancien"), now).unwrap();
        assert!(
            view.password_history.is_none(),
            "inchangé : pas d'historique"
        );
        for n in 0..7 {
            apply(&mut view, login_draft(&format!("nouveau-{n}")), now).unwrap();
        }
        let history = view.password_history.unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(history[0].password, "nouveau-5");
        assert_eq!(view.login.unwrap().password.as_deref(), Some("nouveau-6"));
    }
}
