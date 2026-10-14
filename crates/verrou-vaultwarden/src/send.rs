//! Bitwarden Send : partager un texte par un lien, chiffré de bout en bout.
//!
//! Toute la cryptographie vient du SDK (`bitwarden-send`), comme pour les
//! éléments du coffre :
//! - chaque envoi a sa clé, 16 octets tirés au hasard ; HKDF-SHA256 (sel
//!   `bitwarden-send`, info `send`) en dérive la clé de 64 octets qui
//!   chiffre le nom, les notes et le texte ;
//! - la clé de l'envoi est gardée sur le serveur chiffrée par la clé de
//!   l'utilisateur (`key`), et part dans le lien, après le `#` : le
//!   navigateur du destinataire ne l'envoie jamais au serveur ;
//! - un mot de passe éventuel n'est envoyé qu'haché (PBKDF2-SHA256, 100 000
//!   itérations, salé par la clé de l'envoi).
//!
//! Verrou fait le transport (`/api/sends`) et la mise en forme.

use bitwarden_api_api::models::{
    SendAccessResponseModel, SendResponseModel, SendWithIdRequestModel, SyncResponseModel,
};
use bitwarden_crypto::KeyStore;
use bitwarden_send::{
    Send, SendAccessKey, SendAccessResponse, SendAddRequest, SendAuthType, SendClientExt,
    SendTextView, SendType, SendView, SendViewType,
};
use chrono::{DateTime, Duration, Utc};
use reqwest::Method;
use serde_json::Value;
use verrou_core::SecretString;

use crate::api::Api;
use crate::{Connection, Decrypted, Error};

/// Durée de vie d'un nouvel envoi, comme les apps Bitwarden.
pub const DEFAULT_DELETION_DAYS: i64 = 7;
/// Vaultwarden refuse une date de suppression à plus de 31 jours.
pub const MAX_DELETION_DAYS: i64 = 31;

/// Ce que l'écran d'un envoi crée ou modifie.
#[derive(Clone, Debug)]
pub struct SendDraft {
    pub name: String,
    /// Le texte partagé. Ignoré pour un envoi de fichier (créé ailleurs).
    pub text: SecretString,
    /// Texte masqué par défaut chez le destinataire.
    pub hidden: bool,
    /// Notes privées, visibles du seul expéditeur.
    pub notes: Option<String>,
    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub max_access_count: Option<u32>,
    /// Nouveau mot de passe. `None` : aucun (création) ou inchangé
    /// (modification ; pour le retirer, `remove_send_password`).
    pub password: Option<SecretString>,
    pub hide_email: bool,
    pub disabled: bool,
}

impl SendDraft {
    /// Un envoi de texte avec les réglages par défaut (suppression dans 7 jours).
    pub fn text(name: impl Into<String>, text: SecretString, now: DateTime<Utc>) -> Self {
        Self {
            name: name.into(),
            text,
            hidden: false,
            notes: None,
            deletion_date: now + Duration::days(DEFAULT_DELETION_DAYS),
            expiration_date: None,
            max_access_count: None,
            password: None,
            hide_email: false,
            disabled: false,
        }
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), Error> {
        if self.name.trim().is_empty() {
            return Err(Error::Invalid(
                "le nom de l'envoi est obligatoire".to_owned(),
            ));
        }
        if self.deletion_date <= now {
            return Err(Error::Invalid(
                "la date de suppression doit être dans le futur".to_owned(),
            ));
        }
        if self.deletion_date > now + Duration::days(MAX_DELETION_DAYS) {
            return Err(Error::Invalid(format!(
                "la date de suppression ne peut pas dépasser {MAX_DELETION_DAYS} jours"
            )));
        }
        if self
            .expiration_date
            .is_some_and(|expiry| expiry > self.deletion_date)
        {
            return Err(Error::Invalid(
                "l'expiration doit précéder la suppression".to_owned(),
            ));
        }
        if self.max_access_count == Some(0) {
            return Err(Error::Invalid(
                "le nombre d'accès maximal doit être d'au moins 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendKind {
    Text,
    File,
}

/// Ce que la liste des envois affiche. Ni le texte ni le lien (qui porte la
/// clé) : ils se demandent à part.
#[derive(Clone, Debug)]
pub struct SendInfo {
    pub id: String,
    pub access_id: String,
    pub name: String,
    pub kind: SendKind,
    pub file_name: Option<String>,
    pub has_password: bool,
    pub access_count: u32,
    pub max_access_count: Option<u32>,
    pub disabled: bool,
    pub hide_email: bool,
    /// Horodatages Unix.
    pub deletion_date: i64,
    pub expiration_date: Option<i64>,
    pub revision_date: i64,
}

impl SendInfo {
    fn of(view: &SendView) -> Option<Self> {
        Some(Self {
            id: view.id?.to_string(),
            access_id: view.access_id.clone()?,
            name: view.name.clone(),
            kind: if view.r#type == SendType::File {
                SendKind::File
            } else {
                SendKind::Text
            },
            file_name: view.file.as_ref().map(|f| f.file_name.clone()),
            has_password: view.has_password,
            access_count: view.access_count,
            max_access_count: view.max_access_count,
            disabled: view.disabled,
            hide_email: view.hide_email,
            deletion_date: view.deletion_date.timestamp(),
            expiration_date: view.expiration_date.map(|d| d.timestamp()),
            revision_date: view.revision_date.timestamp(),
        })
    }

    /// Plus accessible (désactivé, expiré, accès épuisés) : le lien ne
    /// mène plus à rien, mais l'envoi existe jusqu'à sa suppression.
    pub fn is_available(&self, now: i64) -> bool {
        !self.disabled
            && self.expiration_date.is_none_or(|e| e > now)
            && self.deletion_date > now
            && self.max_access_count.is_none_or(|m| self.access_count < m)
    }
}

/// Lien de partage, comme le coffre web : `<serveur>/#/send/<accès>/<clé>`.
/// La clé suit le `#` : elle ne quitte jamais le navigateur du destinataire.
pub fn share_link(server: &str, access_id: &str, key_b64url: &str) -> String {
    format!(
        "{}/#/send/{access_id}/{key_b64url}",
        server.trim_end_matches('/')
    )
}

/// Un lien d'envoi décomposé : serveur, identifiant d'accès, clé.
pub(crate) fn parse_link(link: &str) -> Result<(String, String, String), Error> {
    let invalid = || Error::Invalid("lien d'envoi invalide".to_owned());
    let link = link.trim();
    let (server, rest) = link
        .split_once("/#/send/")
        .or_else(|| link.split_once("#/send/"))
        .ok_or_else(invalid)?;
    let mut parts = rest.trim_end_matches('/').split('/');
    let (Some(access_id), Some(key), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    if access_id.is_empty() || key.is_empty() {
        return Err(invalid());
    }
    Ok((
        server.trim_end_matches('/').to_owned(),
        access_id.to_owned(),
        key.to_owned(),
    ))
}

/// Un envoi reçu par son lien, déchiffré.
#[derive(Clone, Debug)]
pub struct ReceivedSend {
    pub name: Option<String>,
    pub text: Option<SecretString>,
    pub hidden: bool,
    pub file_name: Option<String>,
    pub expiration_date: Option<i64>,
    /// Adresse de l'expéditeur, s'il ne l'a pas masquée.
    pub creator: Option<String>,
}

/// Ouvre un envoi par son lien, comme le ferait le destinataire, sans
/// compte : jeton anonyme (avec l'empreinte du mot de passe s'il y en a un),
/// contenu chiffré, déchiffré avec la clé du lien. Compte un accès.
pub async fn receive(link: &str, password: Option<&SecretString>) -> Result<ReceivedSend, Error> {
    let (server, access_id, key) = parse_link(link)?;
    let key = SendAccessKey::from_url_b64(&key)
        .map_err(|_| Error::Invalid("lien d'envoi invalide (clé)".to_owned()))?;
    let api = Api::new(&server)?;
    let hash = password.map(|p| key.hash_password_b64(p.expose()));
    let token = api.send_access_token(&access_id, hash.as_deref()).await?;
    let body = api.send_access(&token).await?;
    let model: SendAccessResponseModel = serde_json::from_value(body)
        .map_err(|e| Error::Server(format!("envoi illisible ({e})")))?;
    let response = SendAccessResponse::try_from(model).map_err(Error::crypto)?;
    let view = key.decrypt_response(response).map_err(Error::crypto)?;
    Ok(ReceivedSend {
        name: view.name,
        hidden: view.text.as_ref().is_some_and(|t| t.hidden),
        text: view.text.and_then(|t| t.text).map(SecretString::new),
        file_name: view.file.and_then(|f| f.file_name),
        expiration_date: view.expiration_date.map(|d| d.timestamp()),
        creator: view.creator_identifier,
    })
}

impl Connection {
    fn key_store(&self) -> &KeyStore<bitwarden_core::key_management::KeySlotIds> {
        self.sdk.internal.get_key_store()
    }

    /// Les envois du cache (dernière synchronisation), du plus récent au
    /// plus ancien. Ceux qui ne se déchiffrent pas sont ignorés.
    pub fn sends(&self) -> Result<Vec<SendInfo>, Error> {
        let mut sends: Vec<SendInfo> = self
            .cached_sends()?
            .into_iter()
            .filter_map(|send| self.sdk.sends().decrypt(send).ok())
            .filter_map(|view| SendInfo::of(&view))
            .collect();
        sends.sort_by_key(|s| std::cmp::Reverse(s.revision_date));
        Ok(sends)
    }

    /// ⚠️ Lien de partage d'un envoi : il porte la clé, donc le contenu.
    pub fn send_link(&self, id: &str) -> Result<SecretString, Error> {
        let view = self.send_view(id)?;
        let key = view.key.as_deref().ok_or(Error::NotFound)?;
        let access_id = view.access_id.as_deref().ok_or(Error::NotFound)?;
        Ok(SecretString::new(share_link(
            self.api.server(),
            access_id,
            key,
        )))
    }

    /// ⚠️ Brouillon prérempli pour modifier un envoi, texte compris.
    pub fn send_draft(&self, id: &str) -> Result<SendDraft, Error> {
        let view = self.send_view(id)?;
        let text = view.text.unwrap_or(SendTextView {
            text: None,
            hidden: false,
        });
        Ok(SendDraft {
            name: view.name,
            text: SecretString::new(text.text.unwrap_or_default()),
            hidden: text.hidden,
            notes: view.notes.filter(|n| !n.is_empty()),
            deletion_date: view.deletion_date,
            expiration_date: view.expiration_date,
            max_access_count: view.max_access_count,
            password: None,
            hide_email: view.hide_email,
            disabled: view.disabled,
        })
    }

    /// Crée un envoi de texte ; rend son identifiant, son lien et le coffre
    /// resynchronisé.
    pub async fn create_send(
        &mut self,
        draft: SendDraft,
    ) -> Result<(String, SecretString, Decrypted), Error> {
        draft.validate(Utc::now())?;
        let request = SendAddRequest {
            name: draft.name.trim().to_owned(),
            notes: text(draft.notes),
            view_type: SendViewType::Text(SendTextView {
                text: Some(draft.text.expose().to_owned()),
                hidden: draft.hidden,
            }),
            max_access_count: draft.max_access_count,
            disabled: draft.disabled,
            hide_email: draft.hide_email,
            deletion_date: draft.deletion_date,
            expiration_date: draft.expiration_date,
            auth: match draft.password.filter(|p| !p.is_empty()) {
                Some(password) => SendAuthType::Password {
                    password: password.expose().to_owned(),
                },
                None => SendAuthType::None,
            },
        };
        let body: bitwarden_api_api::models::SendRequestModel =
            self.key_store().encrypt(request).map_err(Error::crypto)?;
        let body = serde_json::to_value(body).map_err(Error::crypto)?;
        let access = self.access_token().await?;
        let created = self
            .api
            .call(Method::POST, &access, "sends", Some(&body))
            .await?;
        let view = self.decrypt_response(created)?;
        let id = view.id.ok_or(Error::NotFound)?.to_string();
        let link = share_link(
            self.api.server(),
            view.access_id.as_deref().ok_or(Error::NotFound)?,
            view.key.as_deref().ok_or(Error::NotFound)?,
        );
        let vault = self.sync_with(&access).await?;
        Ok((id, SecretString::new(link), vault))
    }

    /// Modifie un envoi : nom, texte (envoi de texte), notes, dates,
    /// limites, et le mot de passe s'il est fourni. La clé ne change pas : le
    /// lien déjà partagé reste valable.
    pub async fn update_send(&mut self, id: &str, draft: SendDraft) -> Result<Decrypted, Error> {
        draft.validate(Utc::now())?;
        let mut view = self.send_view(id)?;
        view.name = draft.name.trim().to_owned();
        view.notes = text(draft.notes);
        if view.r#type == SendType::Text {
            view.text = Some(SendTextView {
                text: Some(draft.text.expose().to_owned()),
                hidden: draft.hidden,
            });
        }
        view.deletion_date = draft.deletion_date;
        view.expiration_date = draft.expiration_date;
        view.max_access_count = draft.max_access_count;
        view.hide_email = draft.hide_email;
        view.disabled = draft.disabled;
        view.new_password = draft
            .password
            .filter(|p| !p.is_empty())
            .map(|p| p.expose().to_owned());
        let send = self.sdk.sends().encrypt(view).map_err(Error::crypto)?;
        let body =
            serde_json::to_value(SendWithIdRequestModel::from(send)).map_err(Error::crypto)?;
        let access = self.access_token().await?;
        self.api
            .call(Method::PUT, &access, &format!("sends/{id}"), Some(&body))
            .await?;
        self.sync_with(&access).await
    }

    /// Supprime l'envoi du serveur : le lien ne mène plus à rien.
    pub async fn delete_send(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.send_view(id)?;
        let access = self.access_token().await?;
        self.api
            .call(Method::DELETE, &access, &format!("sends/{id}"), None)
            .await?;
        self.sync_with(&access).await
    }

    /// Retire le mot de passe d'un envoi.
    pub async fn remove_send_password(&mut self, id: &str) -> Result<Decrypted, Error> {
        self.send_view(id)?;
        let access = self.access_token().await?;
        self.api
            .call(
                Method::PUT,
                &access,
                &format!("sends/{id}/remove-password"),
                None,
            )
            .await?;
        self.sync_with(&access).await
    }

    fn cached_sends(&self) -> Result<Vec<Send>, Error> {
        let Some(json) = &self.account.sync else {
            return Ok(Vec::new());
        };
        let sync: SyncResponseModel = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        Ok(sync
            .sends
            .unwrap_or_default()
            .into_iter()
            .filter_map(|model| Send::try_from(model).ok())
            .collect())
    }

    fn send_view(&self, id: &str) -> Result<SendView, Error> {
        let send = self
            .cached_sends()?
            .into_iter()
            .find(|s| s.id.is_some_and(|sid| sid.to_string() == id))
            .ok_or(Error::NotFound)?;
        self.sdk.sends().decrypt(send).map_err(Error::crypto)
    }

    fn decrypt_response(&self, body: Value) -> Result<SendView, Error> {
        let model: SendResponseModel = serde_json::from_value(body)
            .map_err(|e| Error::Server(format!("envoi illisible ({e})")))?;
        let send = Send::try_from(model).map_err(Error::crypto)?;
        self.sdk.sends().decrypt(send).map_err(Error::crypto)
    }
}

fn text(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::SymmetricKeySlotId;
    use bitwarden_crypto::{
        Decryptable, EncString, KeyStore, PrimitiveEncryptable, SymmetricCryptoKey,
        derive_shareable_key,
    };
    use data_encoding::BASE64URL_NOPAD;
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn links_round_trip() {
        let link = share_link("https://vault.exemple.fr/", "AbC-d_e", "a2V5");
        assert_eq!(link, "https://vault.exemple.fr/#/send/AbC-d_e/a2V5");
        let (server, access, key) = parse_link(&link).unwrap();
        assert_eq!(server, "https://vault.exemple.fr");
        assert_eq!(access, "AbC-d_e");
        assert_eq!(key, "a2V5");
        assert!(parse_link("https://vault.exemple.fr/#/send/seul").is_err());
        assert!(parse_link("https://vault.exemple.fr/").is_err());
    }

    #[test]
    fn drafts_are_checked() {
        let now = Utc::now();
        let draft = SendDraft::text("Wi-Fi", SecretString::new("secret"), now);
        assert_eq!(
            draft.deletion_date - now,
            Duration::days(DEFAULT_DELETION_DAYS)
        );
        assert!(draft.validate(now).is_ok());
        let too_far = SendDraft {
            deletion_date: now + Duration::days(40),
            ..draft.clone()
        };
        assert!(too_far.validate(now).is_err());
        let expires_after_deletion = SendDraft {
            expiration_date: Some(draft.deletion_date + Duration::hours(1)),
            ..draft.clone()
        };
        assert!(expires_after_deletion.validate(now).is_err());
        let unnamed = SendDraft {
            name: "  ".to_owned(),
            ..draft
        };
        assert!(unnamed.validate(now).is_err());
    }

    /// Vecteur de Bitwarden : une clé d'envoi connue et le texte qu'elle
    /// chiffre (`Send::derive_shareable_key`, HKDF-SHA256, sel
    /// `bitwarden-send`, info `send`). Vérifie, indépendamment du SDK, la
    /// dérivation que le lien impose au destinataire.
    #[test]
    fn send_key_derivation_matches_the_bitwarden_recipe() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let raw = [7u8; 16];
        // HKDF-SHA256 : extraction salée par « bitwarden-send », expansion
        // avec l'info « send », 64 octets (clé AES-256 puis clé HMAC).
        let hkdf = Hkdf::<Sha256>::new(Some(b"bitwarden-send"), &raw);
        let mut expected = [0u8; 64];
        hkdf.expand(b"send", &mut expected).unwrap();

        let derived = SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            Zeroizing::new(raw),
            "send",
            Some("send"),
        ));
        assert_eq!(derived.to_encoded().as_ref(), &expected[..]);

        // Et la clé du lien (base64url) déchiffre ce que la clé dérivée chiffre.
        let store: KeyStore<bitwarden_core::key_management::KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let slot: SymmetricKeySlotId = ctx.add_local_symmetric_key(derived);
        let encrypted: EncString = "mot de passe du Wi-Fi".encrypt(&mut ctx, slot).unwrap();
        let plain: String = encrypted.decrypt(&mut ctx, slot).unwrap();
        assert_eq!(plain, "mot de passe du Wi-Fi");
        let access = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&raw)).unwrap();
        let response = SendAccessResponse {
            id: None,
            type_: Some(SendType::Text),
            name: Some(encrypted.to_string()),
            text: None,
            file: None,
            data: None,
            expiration_date: None,
            creator_identifier: None,
        };
        let view = access.decrypt_response(response).unwrap();
        assert_eq!(view.name.as_deref(), Some("mot de passe du Wi-Fi"));
    }

    /// Mot de passe d'un envoi : PBKDF2-SHA256, 100 000 itérations, salé par
    /// la clé brute de l'envoi, en base64 (ce que le serveur compare).
    #[test]
    fn send_password_hash_is_pbkdf2_of_the_send_key() {
        use data_encoding::BASE64;

        use hmac::{Hmac, Mac};

        // PBKDF2 sur un seul bloc (32 octets) : U1 = HMAC(mdp, sel ‖ 1),
        // Ui = HMAC(mdp, Ui-1), résultat = U1 ⊕ … ⊕ U100000.
        let raw = [42u8; 16];
        let hmac = |message: &[u8]| {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"ouvre-toi").unwrap();
            mac.update(message);
            mac.finalize().into_bytes()
        };
        let mut block = hmac(&[&raw[..], &1u32.to_be_bytes()].concat());
        let mut expected: [u8; 32] = block.into();
        for _ in 1..100_000 {
            block = hmac(&block);
            for (out, byte) in expected.iter_mut().zip(block.iter()) {
                *out ^= byte;
            }
        }
        let access = SendAccessKey::from_url_b64(&BASE64URL_NOPAD.encode(&raw)).unwrap();
        assert_eq!(
            access.hash_password_b64("ouvre-toi"),
            BASE64.encode(&expected)
        );
    }
}
