//! HTTP exchanges with Vaultwarden: prelogin, tokens, sync,
//! writes.
//!
//! No cryptography here. The master password only arrives already
//! derived by the SDK (`MasterPasswordAuthenticationData`), and the vault
//! data leaves as the server stores it: encrypted.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::Duration;

use bitwarden_api_api::models::{
    CipherBulkDeleteRequestModel, CipherRequestModel, ImportCiphersRequestModel,
};
use bitwarden_crypto::Kdf;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;

/// Verrou presents itself as the macOS desktop app: that is what it is, and
/// that is how the device shows up in the web vault's session list.
const CLIENT_ID: &str = "desktop";
const DEVICE_TYPE: &str = "7"; // DeviceType::MacOsDesktop
const DEVICE_NAME: &str = "Verrou (macOS)";
/// Announced client version: Vaultwarden adapts some responses for
/// clients that are too old.
const CLIENT_VERSION: &str = "2026.6.0";

/// Connection setup timeout. Short: an unreachable address
/// (local network seen from outside, VPN coming up, IPv6 without a route) does
/// not hold the sync for 10 s; hyper splits it across the name's addresses
/// (and tries IPv4 and IPv6 in parallel, "happy eyeballs"). The
/// total request timeout stays long, for large transfers.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Pause before retrying a connection that could not be established.
const CONNECT_RETRY_PAUSE: Duration = Duration::from_millis(250);

/// Send that retries once a failed connection (timeout,
/// refusal): nothing reached the server, the request can be replayed
/// safely. The phone's network (radio, on-demand VPN) has often
/// finished coming up in the meantime.
pub(crate) trait SendRetrying {
    fn send_retrying(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send;
}

impl SendRetrying for reqwest::RequestBuilder {
    async fn send_retrying(self) -> reqwest::Result<reqwest::Response> {
        // Streamed body (attachment): cannot be copied, a single attempt.
        let Some(retry) = self.try_clone() else {
            return self.send().await;
        };
        match self.send().await {
            Err(error) if error.is_connect() => {
                tokio::time::sleep(CONNECT_RETRY_PAUSE).await;
                retry.send().await
            }
            result => result,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Api {
    pub(crate) http: reqwest::Client,
    pub(crate) base: String,
}

/// Password derivation parameters, returned by the prelogin.
#[derive(Clone)]
pub(crate) struct Prelogin {
    pub kdf: Kdf,
    pub salt: String,
}

/// A second-factor method offered by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TwoFactorMethod {
    /// TOTP app (6-digit code).
    Authenticator,
    /// Code received by email.
    Email,
    /// `YubiKey` in OTP mode (you touch the key, it "types" a code).
    YubiKeyOtp,
    /// `FIDO2`/`WebAuthn` security key. `challenge` is the JSON of the assertion
    /// options, to pass as is to the server's login page.
    WebAuthn { challenge: String },
}

impl TwoFactorMethod {
    /// Provider number in the Bitwarden protocol.
    pub fn provider(&self) -> u8 {
        match self {
            Self::Authenticator => 0,
            Self::Email => 1,
            Self::YubiKeyOtp => 3,
            Self::WebAuthn { .. } => 7,
        }
    }
}

/// Second-factor answer: the chosen method and what it produced
/// (typed code, or JSON of the `WebAuthn` assertion).
#[derive(Clone, Debug)]
pub struct TwoFactorAnswer {
    pub provider: u8,
    pub token: String,
}

/// Tokens and keys returned by a successful login.
pub(crate) struct Tokens {
    pub access: String,
    pub refresh: String,
    /// The user's key, encrypted with their master key.
    pub wrapped_user_key: Option<String>,
    pub private_key: Option<String>,
    /// Password unlock parameters, when the server provides them.
    pub unlock: Option<Prelogin>,
}

pub(crate) enum TokenOutcome {
    Granted(Tokens),
    TwoFactorRequired(Vec<TwoFactorMethod>),
}

/// What a password token request sends.
pub(crate) struct PasswordGrant<'a> {
    pub email: &'a str,
    /// Authentication hash, derived by the SDK.
    pub auth_hash: &'a str,
    /// Login approved by another device: `auth_hash` is then the
    /// request's access code.
    pub auth_request: Option<&'a str>,
    pub device_id: &'a str,
    pub two_factor: Option<&'a TwoFactorAnswer>,
}

impl Api {
    pub fn new(server: &str) -> Result<Self, Error> {
        Self::with_client(server, |builder| builder)
    }

    /// `configure` completes the client (tests: forced name resolution).
    fn with_client(
        server: &str,
        configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        let base = normalize_server(server)?;
        let mut headers = HeaderMap::new();
        headers.insert("bitwarden-client-name", HeaderValue::from_static("desktop"));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert("device-type", HeaderValue::from_static(DEVICE_TYPE));
        let builder = reqwest::Client::builder()
            .user_agent(concat!("Verrou/", env!("CARGO_PKG_VERSION"), " (macOS)"))
            .timeout(Duration::from_secs(30))
            .connect_timeout(CONNECT_TIMEOUT)
            .default_headers(headers);
        let http = configure(builder)
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
            .send_retrying()
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
        if let Some(request) = grant.auth_request {
            form.push(("authRequest", request.to_owned()));
        }
        if let Some(answer) = grant.two_factor {
            form.push(("twoFactorProvider", answer.provider.to_string()));
            form.push(("twoFactorToken", answer.token.clone()));
            form.push(("twoFactorRemember", "0".to_owned()));
        }
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.base))
            // The official server requires it; Vaultwarden ignores it.
            .header(
                "Auth-Email",
                data_encoding::BASE64URL_NOPAD.encode(grant.email.as_bytes()),
            )
            .form(&form)
            .send_retrying()
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
            .send_retrying()
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

    /// Raw response of `/api/sync`: profile, folders and items, all
    /// encrypted. It serves as is as the offline cache.
    pub async fn sync(&self, access_token: &str) -> Result<String, Error> {
        let response = self
            .http
            .get(format!("{}/api/sync?excludeDomains=true", self.base))
            .bearer_auth(access_token)
            .send_retrying()
            .await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::SessionExpired);
        }
        Ok(response.error_for_status()?.text().await?)
    }

    /// Creates an item (already encrypted); returns its id.
    pub async fn create_cipher(
        &self,
        access_token: &str,
        cipher: &CipherRequestModel,
    ) -> Result<String, Error> {
        let body = self.post_cipher(access_token, cipher).await?;
        body.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("item created without an id".to_owned()))
    }

    /// Creates an item (already encrypted); returns the item as the server
    /// keeps it (id, revision date).
    pub async fn post_cipher(
        &self,
        access_token: &str,
        cipher: &CipherRequestModel,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .post(format!("{}/api/ciphers", self.base))
            .bearer_auth(access_token)
            .json(cipher)
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// Replaces an item. The server refuses if `lastKnownRevisionDate` no
    /// longer matches (modified elsewhere in the meantime).
    pub async fn update_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequestModel,
    ) -> Result<(), Error> {
        self.put_cipher(access_token, id, cipher).await.map(drop)
    }

    /// Like `update_cipher`, returning the item as the server
    /// keeps it (new revision date).
    pub async fn put_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequestModel,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{id}", self.base))
            .bearer_auth(access_token)
            .json(cipher)
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// `PUT /api/ciphers/{id}/{action}`: `delete` (trash), `restore`,
    /// `archive`, `unarchive`.
    pub async fn cipher_action(
        &self,
        access_token: &str,
        id: &str,
        action: &str,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{id}/{action}", self.base))
            .bearer_auth(access_token)
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// Imports already encrypted items in a single request, like
    /// the web vault import. Folders are referenced by their
    /// id (`folders` + `folderRelationships`).
    pub async fn import_ciphers(
        &self,
        access_token: &str,
        request: &ImportCiphersRequestModel,
    ) -> Result<(), Error> {
        let response = self
            .http
            .post(format!("{}/api/ciphers/import", self.base))
            .bearer_auth(access_token)
            // Hundreds of encrypted items: longer than a write.
            .timeout(Duration::from_secs(120))
            .json(request)
            .send_retrying()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Creates a folder (name already encrypted); returns its id.
    pub async fn create_folder(&self, access_token: &str, name: &str) -> Result<String, Error> {
        let response = self
            .http
            .post(format!("{}/api/folders", self.base))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "name": name }))
            .send_retrying()
            .await?;
        let body = write_response(response).await?;
        body.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Server("folder created without an id".to_owned()))
    }

    /// Renames a folder (name already encrypted), `PUT /api/folders/{id}`.
    pub async fn rename_folder(
        &self,
        access_token: &str,
        id: &str,
        name: &str,
    ) -> Result<(), Error> {
        let response = self
            .http
            .put(format!("{}/api/folders/{id}", self.base))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "name": name }))
            .send_retrying()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Deletes a folder, `DELETE /api/folders/{id}`. The server only
    /// removes the folder: its items stay in the vault, outside any folder.
    pub async fn delete_folder(&self, access_token: &str, id: &str) -> Result<(), Error> {
        let response = self
            .http
            .delete(format!("{}/api/folders/{id}", self.base))
            .bearer_auth(access_token)
            .send_retrying()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Moves several items to the trash in one request (restorable).
    pub async fn trash_ciphers(&self, access_token: &str, ids: &[String]) -> Result<(), Error> {
        self.bulk_cipher_action(access_token, ids, "delete")
            .await
            .map(drop)
    }

    /// `PUT /api/ciphers/{action}` on several items in one request:
    /// `delete` (trash), `restore`, `archive`, `unarchive`. Vaultwarden
    /// stops at the first refused item (the ones before stay done).
    pub async fn bulk_cipher_action(
        &self,
        access_token: &str,
        ids: &[String],
        action: &str,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/{action}", self.base))
            .bearer_auth(access_token)
            .json(&CipherBulkDeleteRequestModel::new(ids.to_vec()))
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// Files several items into a folder (`None`: none) in one
    /// request, `PUT /api/ciphers/move`. The folder belongs to the account:
    /// the item itself is not rewritten.
    pub async fn move_ciphers(
        &self,
        access_token: &str,
        ids: &[String],
        folder_id: Option<&str>,
    ) -> Result<(), Error> {
        let response = self
            .http
            .put(format!("{}/api/ciphers/move", self.base))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "folderId": folder_id, "ids": ids }))
            .send_retrying()
            .await?;
        write_response(response).await.map(drop)
    }

    /// Authenticated JSON request to `/api/{path}` (sends, emergency access):
    /// the returned JSON (`Null` if empty), or the translated error.
    pub async fn call(
        &self,
        method: reqwest::Method,
        access_token: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        let mut request = self
            .http
            .request(method, format!("{}/api/{path}", self.base))
            .bearer_auth(access_token);
        if let Some(body) = body {
            request = request.json(body);
        }
        write_response(request.send_retrying().await?).await
    }

    /// Anonymous access token for a send (`grant_type=send_access`), with
    /// the password hash if it has one.
    pub async fn send_access_token(
        &self,
        access_id: &str,
        password_hash: Option<&str>,
    ) -> Result<String, Error> {
        let mut form = vec![
            ("grant_type", "send_access"),
            ("client_id", "send"),
            ("scope", "api.send.access"),
            ("send_id", access_id),
        ];
        if let Some(hash) = password_hash {
            form.push(("password_hash_b64", hash));
        }
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.base))
            .form(&form)
            .send_retrying()
            .await?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return body
                .get("access_token")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::Server("missing access token".to_owned()));
        }
        Err(
            match body.get("send_access_error_type").and_then(Value::as_str) {
                Some("password_hash_b64_required") => {
                    Error::Invalid("this send is protected by a password".to_owned())
                }
                Some("password_hash_b64_invalid") => {
                    Error::Invalid("incorrect send password".to_owned())
                }
                Some(_) => Error::NotFound,
                None => Error::Server(error_message(&body)),
            },
        )
    }

    /// Content of a send (encrypted), with the token from `send_access_token`.
    /// The server counts an access.
    pub async fn send_access(&self, token: &str) -> Result<Value, Error> {
        let response = self
            .http
            .post(format!("{}/api/sends/access", self.base))
            .bearer_auth(token)
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// Authenticated JSON write (`path` starts with `/api/`); returns the
    /// response JSON.
    pub async fn send_json(
        &self,
        method: reqwest::Method,
        path: &str,
        access_token: &str,
        body: &impl serde::Serialize,
    ) -> Result<Value, Error> {
        let response = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(access_token)
            .json(body)
            .send_retrying()
            .await?;
        write_response(response).await
    }

    /// Asks for the second-factor code to be sent by email.
    pub async fn send_email_code(
        &self,
        email: &str,
        auth_hash: &str,
        auth_request: Option<&str>,
        device_id: &str,
    ) -> Result<(), Error> {
        // Login through another device: the request and its access code
        // instead of the password hash.
        let body = match auth_request {
            Some(request) => serde_json::json!({
                "email": email,
                "authRequestId": request,
                "authRequestAccessCode": auth_hash,
                "deviceIdentifier": device_id,
            }),
            None => serde_json::json!({
                "email": email,
                "masterPasswordHash": auth_hash,
                "deviceIdentifier": device_id,
            }),
        };
        let response = self
            .http
            .post(format!("{}/api/two-factor/send-email-login", self.base))
            .json(&body)
            .send_retrying()
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let body: Value = response.json().await.unwrap_or(Value::Null);
        Err(Error::Server(error_message(&body)))
    }
}

/// Response of a write: the returned JSON, or the translated error.
pub(crate) async fn write_response(response: reqwest::Response) -> Result<Value, Error> {
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

/// `https://vault.exemple.fr/` → `https://vault.exemple.fr`. Plain HTTP
/// is only accepted for a local server (tests).
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
                "{trimmed}: only HTTPS is accepted"
            )));
        }
    }
    if host.is_empty() {
        return Err(Error::InvalidServer(trimmed.to_owned()));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Bitwarden clients salt the derivation with the address, trimmed and
/// lower-cased, when the server gives no salt.
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
            .ok_or_else(|| Error::Server(format!("missing key derivation parameter: {what}")))
    };
    match kind {
        0 => Ok(Kdf::PBKDF2 {
            iterations: nonzero(Some(iterations), "iterations")?,
        }),
        1 => Ok(Kdf::Argon2id {
            iterations: nonzero(Some(iterations), "iterations")?,
            memory: nonzero(memory, "memory")?,
            parallelism: nonzero(parallelism, "parallelism")?,
        }),
        other => Err(Error::Server(format!("unknown key derivation ({other})"))),
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
            .ok_or_else(|| Error::Server("missing access token".to_owned()))?,
        refresh: text("refresh_token")
            .ok_or_else(|| Error::Server("missing refresh token".to_owned()))?,
        wrapped_user_key,
        private_key: text("PrivateKey"),
        unlock,
    })
}

fn two_factor_methods(providers: &Value) -> Vec<TwoFactorMethod> {
    let Some(map) = providers.as_object() else {
        return Vec::new();
    };
    // Order of preference: the security key first.
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

/// The readable message of a server error, whatever its format.
pub(crate) fn error_message(body: &Value) -> String {
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
    .unwrap_or("unknown error")
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Answers `{}` to one request, on `listener`.
    async fn answer_once(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_refused_connection_is_retried() {
        // The server is not listening yet on the first attempt (network coming up).
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            answer_once(TcpListener::bind(("127.0.0.1", port)).await.unwrap()).await;
        });
        let api = Api::new(&format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(api.sync("jeton").await.unwrap(), "{}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn an_unreachable_first_address_does_not_hold_the_sync() {
        // The name first gives an address that never answers (documentation
        // network, no route), then the server: before, the
        // connection waited 10 s (5 s per address).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(answer_once(listener));
        let addresses = [
            std::net::SocketAddr::from(([192, 0, 2, 1], port)),
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        ];
        let api = Api::with_client(&format!("https://vault.exemple.fr:{port}"), |builder| {
            builder.resolve_to_addrs("vault.exemple.fr", &addresses)
        })
        .unwrap();
        // HTTPS to a plain-text server: the TCP connection succeeds, then the
        // TLS handshake fails right away. Only the delay matters.
        let start = Instant::now();
        let _ = api.sync("jeton").await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(4),
            "connection held {elapsed:?} by the unreachable address"
        );
        server.abort();
    }

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
