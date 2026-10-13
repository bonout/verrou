//! Échanges HTTP avec Vaultwarden : prélogin, jetons, synchronisation,
//! écritures.
//!
//! Aucune cryptographie ici. Le mot de passe principal n'y arrive que déjà
//! dérivé par le SDK (`MasterPasswordAuthenticationData`), et les données du
//! coffre en repartent telles que le serveur les stocke : chiffrées.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_crypto::Kdf;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;

/// Verrou se présente comme l'app de bureau macOS : c'est ce qu'il est, et
/// c'est ainsi que l'appareil apparaît dans la liste des sessions du coffre web.
const CLIENT_ID: &str = "desktop";
const DEVICE_TYPE: &str = "7"; // DeviceType::MacOsDesktop
const DEVICE_NAME: &str = "Verrou (macOS)";
/// Version de client annoncée : Vaultwarden adapte certaines réponses aux
/// clients trop anciens.
const CLIENT_VERSION: &str = "2026.6.0";

#[derive(Clone)]
pub(crate) struct Api {
    http: reqwest::Client,
    base: String,
}

/// Paramètres de dérivation du mot de passe, renvoyés par le prélogin.
#[derive(Clone)]
pub(crate) struct Prelogin {
    pub kdf: Kdf,
    pub salt: String,
}

/// Une méthode de second facteur proposée par le serveur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TwoFactorMethod {
    /// Application TOTP (code à 6 chiffres).
    Authenticator,
    /// Code reçu par e-mail.
    Email,
    /// `YubiKey` en mode OTP (on touche la clé, elle « tape » un code).
    YubiKeyOtp,
    /// Clé de sécurité `FIDO2`/`WebAuthn`. `challenge` est le JSON des options
    /// d'assertion, à passer tel quel à la page de connexion du serveur.
    WebAuthn { challenge: String },
}

impl TwoFactorMethod {
    /// Numéro du fournisseur dans le protocole Bitwarden.
    pub fn provider(&self) -> u8 {
        match self {
            Self::Authenticator => 0,
            Self::Email => 1,
            Self::YubiKeyOtp => 3,
            Self::WebAuthn { .. } => 7,
        }
    }
}

/// Réponse au second facteur : la méthode choisie et ce qu'elle a produit
/// (code saisi, ou JSON de l'assertion `WebAuthn`).
#[derive(Clone, Debug)]
pub struct TwoFactorAnswer {
    pub provider: u8,
    pub token: String,
}

/// Jetons et clés renvoyés par une connexion réussie.
pub(crate) struct Tokens {
    pub access: String,
    pub refresh: String,
    /// Clé de l'utilisateur, chiffrée par sa clé principale.
    pub wrapped_user_key: Option<String>,
    pub private_key: Option<String>,
    /// Paramètres de déverrouillage par mot de passe, quand le serveur les donne.
    pub unlock: Option<Prelogin>,
}

pub(crate) enum TokenOutcome {
    Granted(Tokens),
    TwoFactorRequired(Vec<TwoFactorMethod>),
}

/// Ce qu'envoie une demande de jeton par mot de passe.
pub(crate) struct PasswordGrant<'a> {
    pub email: &'a str,
    /// Empreinte d'authentification, dérivée par le SDK.
    pub auth_hash: &'a str,
    pub device_id: &'a str,
    pub two_factor: Option<&'a TwoFactorAnswer>,
}

impl Api {
    pub fn new(server: &str) -> Result<Self, Error> {
        let base = normalize_server(server)?;
        let mut headers = HeaderMap::new();
        headers.insert("bitwarden-client-name", HeaderValue::from_static("desktop"));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert("device-type", HeaderValue::from_static(DEVICE_TYPE));
        let http = reqwest::Client::builder()
            .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION"), " (macOS)"))
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .default_headers(headers)
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self { http, base })
    }

    pub fn server(&self) -> &str {
        &self.base
    }

    pub async fn prelogin(&self, email: &str) -> Result<Prelogin, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            kdf: u8,
            kdf_iterations: u32,
            kdf_memory: Option<u32>,
            kdf_parallelism: Option<u32>,
            salt: Option<String>,
        }
        let response: Response = self
            .http
            .post(format!("{}/identity/accounts/prelogin", self.base))
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Prelogin {
            kdf: kdf(
                response.kdf,
                response.kdf_iterations,
                response.kdf_memory,
                response.kdf_parallelism,
            )?,
            salt: response.salt.unwrap_or_else(|| default_salt(email)),
        })
    }

    pub async fn password_token(&self, grant: &PasswordGrant<'_>) -> Result<TokenOutcome, Error> {
        let mut form = vec![
            ("grant_type", "password".to_owned()),
            ("username", grant.email.to_owned()),
            ("password", grant.auth_hash.to_owned()),
            ("scope", "api offline_access".to_owned()),
            ("client_id", CLIENT_ID.to_owned()),
            ("deviceType", DEVICE_TYPE.to_owned()),
            ("deviceIdentifier", grant.device_id.to_owned()),
            ("deviceName", DEVICE_NAME.to_owned()),
        ];
        if let Some(answer) = grant.two_factor {
            form.push(("twoFactorProvider", answer.provider.to_string()));
            form.push(("twoFactorToken", answer.token.clone()));
            form.push(("twoFactorRemember", "0".to_owned()));
        }
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.base))
            // Le serveur officiel l'exige ; Vaultwarden l'ignore.
            .header(
                "Auth-Email",
                data_encoding::BASE64URL_NOPAD.encode(grant.email.as_bytes()),
            )
            .form(&form)
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await?;
        if status.is_success() {
            return Ok(TokenOutcome::Granted(tokens(&body)?));
        }
        if let Some(providers) = body.get("TwoFactorProviders2").filter(|v| v.is_object()) {
            if grant.two_factor.is_some() {
                return Err(Error::TwoFactorRejected(error_message(&body)));
            }
            return Ok(TokenOutcome::TwoFactorRequired(two_factor_methods(
                providers,
            )));
        }
        Err(grant_error(&body, grant.two_factor.is_some()))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, Error> {
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.base))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return tokens(&body);
        }
        if body.get("error").and_then(Value::as_str) == Some("invalid_grant")
            || status == reqwest::StatusCode::UNAUTHORIZED
        {
            return Err(Error::SessionExpired);
        }
        Err(Error::Server(error_message(&body)))
    }

    /// Réponse brute de `/api/sync` : profil, dossiers et éléments, tous
    /// chiffrés. Elle sert telle quelle de cache hors ligne.
    pub async fn sync(&self, access_token: &str) -> Result<String, Error> {
        let response = self
            .http
            .get(format!("{}/api/sync?excludeDomains=true", self.base))
            .bearer_auth(access_token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::SessionExpired);
        }
        Ok(response.error_for_status()?.text().await?)
    }

    /// Crée un élément (déjà chiffré) ; rend son identifiant.
    pub async fn create_cipher(
        &self,
        access_token: &str,
        cipher: &CipherRequestModel,
    ) -> Result<String, Error> {
        let response = self
            .http
            .post(format!("{}/api/ciphers", self.base))
            .bearer_auth(access_token)
            .json(cipher)
            .send()
            .await?;
        let body = write_response(response).await?;
        body.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("élément créé sans identifiant".to_owned()))
    }

    /// Remplace un élément. Le serveur refuse si `lastKnownRevisionDate` ne
    /// correspond plus (modifié ailleurs entre-temps).
    pub async fn update_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequestModel,
    ) -> Result<(), Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{id}", self.base))
            .bearer_auth(access_token)
            .json(cipher)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Met l'élément à la corbeille (suppression douce, restaurable).
    pub async fn trash_cipher(&self, access_token: &str, id: &str) -> Result<(), Error> {
        self.cipher_action(access_token, id, "delete").await
    }

    /// `PUT /api/ciphers/{id}/{action}` : `delete` (corbeille), `restore`,
    /// `archive`, `unarchive`.
    pub async fn cipher_action(
        &self,
        access_token: &str,
        id: &str,
        action: &str,
    ) -> Result<(), Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{id}/{action}", self.base))
            .bearer_auth(access_token)
            .send()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Demande l'envoi du code de second facteur par e-mail.
    pub async fn send_email_code(
        &self,
        email: &str,
        auth_hash: &str,
        device_id: &str,
    ) -> Result<(), Error> {
        let response = self
            .http
            .post(format!("{}/api/two-factor/send-email-login", self.base))
            .json(&serde_json::json!({
                "email": email,
                "masterPasswordHash": auth_hash,
                "deviceIdentifier": device_id,
            }))
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let body: Value = response.json().await.unwrap_or(Value::Null);
        Err(Error::Server(error_message(&body)))
    }
}

/// Réponse d'une écriture : le JSON renvoyé, ou l'erreur traduite.
async fn write_response(response: reqwest::Response) -> Result<Value, Error> {
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        return Ok(body);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Error::SessionExpired);
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(Error::NotFound);
    }
    let message = error_message(&body);
    if message.contains("out of date") {
        return Err(Error::Conflict);
    }
    Err(Error::Server(message))
}

/// `https://vault.exemple.fr/` → `https://vault.exemple.fr`. HTTP en clair
/// n'est accepté que pour un serveur local (tests).
fn normalize_server(server: &str) -> Result<String, Error> {
    let trimmed = server.trim().trim_end_matches('/');
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let url = reqwest::Url::parse(&with_scheme)
        .map_err(|e| Error::InvalidServer(format!("{trimmed} ({e})")))?;
    let host = url.host_str().unwrap_or_default();
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        _ => {
            return Err(Error::InvalidServer(format!(
                "{trimmed} : seul HTTPS est accepté"
            )));
        }
    }
    if host.is_empty() {
        return Err(Error::InvalidServer(trimmed.to_owned()));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Les clients Bitwarden salent la dérivation avec l'adresse, sans espaces et
/// en minuscules, quand le serveur ne donne pas de sel.
pub(crate) fn default_salt(email: &str) -> String {
    email.trim().to_lowercase()
}

pub(crate) fn kdf(
    kind: u8,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<Kdf, Error> {
    let nonzero = |value: Option<u32>, what: &str| {
        value
            .and_then(NonZeroU32::new)
            .ok_or_else(|| Error::Server(format!("paramètre de dérivation manquant : {what}")))
    };
    match kind {
        0 => Ok(Kdf::PBKDF2 {
            iterations: nonzero(Some(iterations), "itérations")?,
        }),
        1 => Ok(Kdf::Argon2id {
            iterations: nonzero(Some(iterations), "itérations")?,
            memory: nonzero(memory, "mémoire")?,
            parallelism: nonzero(parallelism, "parallélisme")?,
        }),
        other => Err(Error::Server(format!(
            "dérivation de clé inconnue ({other})"
        ))),
    }
}

fn tokens(body: &Value) -> Result<Tokens, Error> {
    let text = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let unlock = body
        .pointer("/UserDecryptionOptions/MasterPasswordUnlock")
        .and_then(|unlock| {
            let kdf_value = unlock.get("Kdf")?;
            let number = |key: &str| kdf_value.get(key).and_then(Value::as_u64).map(|n| n as u32);
            Some(Prelogin {
                kdf: kdf(
                    number("KdfType")? as u8,
                    number("Iterations")?,
                    number("Memory"),
                    number("Parallelism"),
                )
                .ok()?,
                salt: unlock.get("Salt")?.as_str()?.to_owned(),
            })
        });
    let wrapped_user_key = body
        .pointer("/UserDecryptionOptions/MasterPasswordUnlock/MasterKeyWrappedUserKey")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| text("Key"));
    Ok(Tokens {
        access: text("access_token")
            .ok_or_else(|| Error::Server("jeton d'accès absent".to_owned()))?,
        refresh: text("refresh_token")
            .ok_or_else(|| Error::Server("jeton de renouvellement absent".to_owned()))?,
        wrapped_user_key,
        private_key: text("PrivateKey"),
        unlock,
    })
}

fn two_factor_methods(providers: &Value) -> Vec<TwoFactorMethod> {
    let Some(map) = providers.as_object() else {
        return Vec::new();
    };
    // Ordre de préférence : la clé de sécurité d'abord.
    let mut methods: BTreeMap<u8, TwoFactorMethod> = BTreeMap::new();
    for (id, data) in map {
        let method = match id.as_str() {
            "7" => TwoFactorMethod::WebAuthn {
                challenge: data.to_string(),
            },
            "0" => TwoFactorMethod::Authenticator,
            "3" => TwoFactorMethod::YubiKeyOtp,
            "1" => TwoFactorMethod::Email,
            _ => continue,
        };
        let rank = match method {
            TwoFactorMethod::WebAuthn { .. } => 0,
            TwoFactorMethod::Authenticator => 1,
            TwoFactorMethod::YubiKeyOtp => 2,
            TwoFactorMethod::Email => 3,
        };
        methods.insert(rank, method);
    }
    methods.into_values().collect()
}

fn grant_error(body: &Value, with_two_factor: bool) -> Error {
    let message = error_message(body);
    let lowered = message.to_lowercase();
    if lowered.contains("password is incorrect") || lowered.contains("username or password") {
        Error::WrongPassword
    } else if with_two_factor {
        Error::TwoFactorRejected(message)
    } else {
        Error::Server(message)
    }
}

/// Le message lisible d'une erreur du serveur, quel que soit son format.
fn error_message(body: &Value) -> String {
    [
        "/ErrorModel/Message",
        "/errorModel/message",
        "/error_description",
        "/message",
        "/error",
    ]
    .iter()
    .find_map(|path| {
        body.pointer(path)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    })
    .unwrap_or("erreur inconnue")
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_are_normalized() {
        assert_eq!(
            normalize_server("vault.example.net/").unwrap(),
            "https://vault.example.net"
        );
        assert_eq!(
            normalize_server(" https://vault.exemple.fr/sub/ ").unwrap(),
            "https://vault.exemple.fr/sub"
        );
        assert_eq!(
            normalize_server("http://localhost:8099").unwrap(),
            "http://localhost:8099"
        );
        assert!(matches!(
            normalize_server("http://vault.exemple.fr"),
            Err(Error::InvalidServer(_))
        ));
    }

    #[test]
    fn two_factor_methods_put_the_security_key_first() {
        let providers = serde_json::json!({
            "0": null,
            "7": { "challenge": "abc", "allowCredentials": [] },
        });
        let methods = two_factor_methods(&providers);
        assert!(
            matches!(&methods[0], TwoFactorMethod::WebAuthn { challenge } if challenge.contains("abc"))
        );
        assert_eq!(methods[1], TwoFactorMethod::Authenticator);
    }

    #[test]
    fn wrong_password_is_recognized() {
        let body = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Username or password is incorrect. Try again",
        });
        assert!(matches!(grant_error(&body, false), Error::WrongPassword));
    }
}
