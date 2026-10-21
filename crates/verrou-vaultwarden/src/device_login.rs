//! Login with a device (Bitwarden's "auth requests"), both ways:
//!
//! - **approving** (`Connection::auth_requests`, `answer_auth_request`):
//!   another client of the same account (web vault, another Verrou) asks to
//!   log in without the master password. The vault unlocked here shows the
//!   request (device type, IP address, time, fingerprint phrase); approving
//!   it encrypts the **user key** for the request's RSA public key
//!   (`approve_auth_request` from Bitwarden's SDK, like the official apps)
//!   and sends it with `PUT /api/auth-requests/{id}`;
//! - **requesting** (`begin`, then `DeviceLogin::answer_now` or
//!   `wait_for_answer`, then `DeviceLogin::login`): this device creates an
//!   RSA key pair and an access code (`new_auth_request` from the SDK),
//!   publishes the public key (`POST /api/auth-requests`), shows the
//!   fingerprint phrase, waits for the answer (anonymous channel
//!   `/notifications/anonymous-hub`, otherwise polling), then logs in with
//!   the access code in place of the password and decrypts the received
//!   key with its private key.
//!
//! The fingerprint phrase is computed on both sides from the public key
//! and the account's address (`fingerprint` from the SDK): if they differ,
//! the request is not the one it seems (phishing).
//!
//! What Vaultwarden 1.37.4 enforces (`src/api/core/accounts.rs`,
//! `src/api/identity.rs`, `src/db/models/auth_request.rs`):
//! - the request is only accepted from a device **already known** to the
//!   account (`deviceIdentifier` and type identical to a past login): a new
//!   device must first log in once with the password;
//! - the login with the access code must come from the **same IP address**
//!   as the request, within **5 minutes** of its creation, only once; the
//!   account's second factor is still required;
//! - a denied request is erased; all are after 15 minutes.

use std::time::Duration;

use bitwarden_crypto::{SpkiPublicKeyBytes, UnsignedSharedKey};
use bitwarden_encoding::B64;
use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use verrou_core::SecretString;

use crate::api::{Api, SendRetrying as _, error_message};
use crate::{Connection, Error, LoginStep, PendingLogin, Store};

/// Lifetime of a request, as in Bitwarden (and Vaultwarden's purge):
/// beyond it, it is no longer shown.
pub const REQUEST_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Vaultwarden refuses the login with the access code more than 5 minutes
/// after the request was created.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);

/// A login request from another device, to approve or deny.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub id: String,
    /// The device type, readable ("Chrome browser", "iPhone"…).
    pub device: String,
    /// IP address seen by the server (empty if it doesn't give it).
    pub ip: String,
    /// Creation, in seconds since 1970.
    pub created_at: i64,
    /// Fingerprint phrase (five words) of the public key and the account's
    /// address: the one the requesting device shows.
    pub fingerprint: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestModel {
    id: String,
    public_key: String,
    request_device_type: Option<String>,
    request_ip_address: Option<String>,
    key: Option<String>,
    master_password_hash: Option<String>,
    creation_date: String,
    request_approved: Option<bool>,
}

/// The device type the server announces, in plain words.
pub fn device_label(device_type: &str) -> String {
    let label = match device_type {
        "Android" | "Android (Amazon)" => "Android",
        "iOS" => "iPhone or iPad",
        "Chrome Extension" => "Chrome extension",
        "Firefox Extension" => "Firefox extension",
        "Opera Extension" => "Opera extension",
        "Edge Extension" => "Edge extension",
        "Vivaldi Extension" => "Vivaldi extension",
        "Safari Extension" => "Safari extension",
        "Windows" | "Windows Desktop" => "Windows (desktop app)",
        "macOS" | "MacOS Desktop" | "macOS Desktop" => "Mac (desktop app)",
        "Linux" | "Linux Desktop" => "Linux (desktop app)",
        "Chrome" | "Chrome Browser" => "Chrome browser",
        "Firefox" | "Firefox Browser" => "Firefox browser",
        "Opera" | "Opera Browser" => "Opera browser",
        "Edge" | "Edge Browser" => "Edge browser",
        "Internet Explorer" | "IE Browser" => "Internet Explorer",
        "Safari" | "Safari Browser" => "Safari browser",
        "Vivaldi" | "Vivaldi Browser" => "Vivaldi browser",
        "DuckDuckGo" | "DuckDuckGo Browser" => "DuckDuckGo browser",
        "Unknown Browser" => "Unknown browser",
        "Windows CLI" | "MacOs CLI" | "macOS CLI" | "Linux CLI" => "Command line",
        "" => "Unknown device",
        other => other,
    };
    label.to_owned()
}

/// The server's RFC 3339 date → seconds since 1970.
fn timestamp(date: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|d| d.timestamp())
}

/// The fingerprint phrase of `public_key` (DER SPKI in base64) for the
/// address `email` (lower-case, as the server keeps it).
pub fn fingerprint_phrase(email: &str, public_key: &str) -> Result<String, Error> {
    let key: B64 = public_key
        .parse()
        .map_err(|_| Error::Invalid("unreadable public key in the request".to_owned()))?;
    bitwarden_crypto::fingerprint(
        &normalize_email(email),
        &SpkiPublicKeyBytes::from(key.as_bytes().to_vec()),
    )
    .map_err(Error::crypto)
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn expired(created_at: i64, lifetime: Duration) -> bool {
    now() - created_at >= i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX)
}

impl Connection {
    /// The pending login requests for this account, newest first, without
    /// those older than 15 minutes.
    pub async fn auth_requests(&mut self) -> Result<Vec<AuthRequest>, Error> {
        let access = self.access_token().await?;
        let response = self
            .api
            .http
            .get(format!("{}/api/auth-requests/pending", self.api.base))
            .bearer_auth(&access)
            .send_retrying()
            .await?;
        // Older server: the route without `/pending`.
        let response = if response.status() == StatusCode::NOT_FOUND {
            self.api
                .http
                .get(format!("{}/api/auth-requests", self.api.base))
                .bearer_auth(&access)
                .send_retrying()
                .await?
        } else {
            response
        };
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(Error::SessionExpired);
        }
        let body: Value = response.error_for_status()?.json().await?;
        let models: Vec<RequestModel> = body
            .get("data")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| Error::Server(format!("unreadable login requests ({e})")))?
            .unwrap_or_default();
        let email = self.account.email.clone();
        let mut requests: Vec<AuthRequest> = models
            .into_iter()
            .filter(|m| m.request_approved.is_none())
            .filter_map(|m| {
                let created_at = timestamp(&m.creation_date)?;
                if expired(created_at, REQUEST_LIFETIME) {
                    return None;
                }
                Some(AuthRequest {
                    fingerprint: fingerprint_phrase(&email, &m.public_key).ok()?,
                    device: device_label(m.request_device_type.as_deref().unwrap_or_default()),
                    ip: m.request_ip_address.unwrap_or_default(),
                    created_at,
                    id: m.id,
                    public_key: m.public_key,
                })
            })
            .collect();
        requests.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(requests)
    }

    /// Approves (`approve`) or denies the request `id`.
    ///
    /// The request is read again from the server just before (never a
    /// public key from elsewhere); approving encrypts the user key for its
    /// public key (RSA-OAEP, like Bitwarden's SDK): only the device holding
    /// the private key can read it. An expired request, or one whose
    /// fingerprint phrase is no longer the one shown (`fingerprint`), is
    /// refused without sending anything.
    pub async fn answer_auth_request(
        &mut self,
        id: &str,
        fingerprint: &str,
        approve: bool,
    ) -> Result<(), Error> {
        let access = self.access_token().await?;
        let response = self
            .api
            .http
            .get(format!("{}/api/auth-requests/{id}", self.api.base))
            .bearer_auth(&access)
            .send_retrying()
            .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(Error::SessionExpired);
        }
        if !response.status().is_success() {
            return Err(Error::Invalid(
                "this login request no longer exists".to_owned(),
            ));
        }
        let model: RequestModel = response.json().await?;
        if model.request_approved.is_some() {
            return Err(Error::Invalid(
                "this login request has already been answered".to_owned(),
            ));
        }
        let created_at = timestamp(&model.creation_date).unwrap_or(0);
        if approve && expired(created_at, REQUEST_LIFETIME) {
            return Err(Error::Invalid("this login request has expired".to_owned()));
        }
        if approve && fingerprint_phrase(&self.account.email, &model.public_key)? != fingerprint {
            return Err(Error::Invalid(
                "the request's fingerprint phrase has changed: refused".to_owned(),
            ));
        }
        let key = if approve {
            let public_key: B64 = model
                .public_key
                .parse()
                .map_err(|_| Error::Invalid("unreadable public key in the request".to_owned()))?;
            self.sdk
                .auth()
                .approve_auth_request(public_key)
                .map_err(Error::crypto)?
                .to_string()
        } else {
            // Vaultwarden requires the field, even for a denial.
            String::new()
        };
        let device_id = self.store.device_id()?;
        let response = self
            .api
            .http
            .put(format!("{}/api/auth-requests/{id}", self.api.base))
            .bearer_auth(&access)
            .json(&json!({
                "key": key,
                "masterPasswordHash": null,
                "deviceIdentifier": device_id,
                "requestApproved": approve,
            }))
            .send_retrying()
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::SessionExpired);
        }
        Err(Error::Server(error_message(&body)))
    }
}

/// A login request made by this device, waiting for an answer. Keeps the
/// RSA private key and the access code (in memory only): if lost, start
/// over.
pub struct DeviceLogin {
    api: Api,
    store: Store,
    email: String,
    device_id: String,
    id: String,
    fingerprint: String,
    access_code: SecretString,
    private_key: SecretString,
    created_at: i64,
}

/// What the other device sent back: the key encrypted for our public key.
#[derive(Clone)]
pub(crate) struct Approval {
    pub private_key: SecretString,
    pub key: String,
    /// The received key is the master key (old clients), not the user key.
    pub master_key: bool,
}

/// Answer to a request, seen from the requesting device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Pending,
    Approved,
    /// Denied (the server erased it) or expired.
    Denied,
}

/// Creates this device's login request for `email`.
pub async fn begin(store: &Store, server: &str, email: &str) -> Result<DeviceLogin, Error> {
    let api = Api::new(server)?;
    let email = normalize_email(email);
    if email.is_empty() {
        return Err(Error::Invalid("email address missing".to_owned()));
    }
    let device_id = store.device_id()?;
    let keys = crate::sdk_client(api.server())
        .auth()
        .new_auth_request(&email)
        .map_err(Error::crypto)?;
    let response = api
        .http
        .post(format!("{}/api/auth-requests", api.base))
        .json(&json!({
            "email": email,
            "publicKey": keys.public_key.to_string(),
            "deviceIdentifier": device_id,
            "accessCode": keys.access_code,
            // AuthenticateAndUnlock
            "type": 0,
        }))
        .send_retrying()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let message = error_message(&body);
        // Vaultwarden answers the same for an unknown account and for a
        // device never logged in to this account (it doesn't say which).
        if message.contains("doesn't exist") {
            return Err(Error::Invalid(
                "request refused by the server: this account does not exist, or this device \
                 has never logged in to it (Vaultwarden requires a first login with the \
                 master password)"
                    .to_owned(),
            ));
        }
        return Err(Error::Server(message));
    }
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Server("request created without an id".to_owned()))?
        .to_owned();
    let created_at = body
        .get("creationDate")
        .and_then(Value::as_str)
        .and_then(timestamp)
        .unwrap_or_else(now);
    Ok(DeviceLogin {
        api,
        store: store.clone(),
        email,
        device_id,
        id,
        fingerprint: keys.fingerprint,
        access_code: SecretString::new(keys.access_code),
        private_key: SecretString::new(keys.private_key.to_string()),
        created_at,
    })
}

impl DeviceLogin {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The phrase to compare with the one the approving device shows.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn server(&self) -> &str {
        self.api.server()
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Login no longer possible: Vaultwarden refuses the access code 5
    /// minutes after creation.
    pub fn is_expired(&self) -> bool {
        expired(self.created_at, LOGIN_WINDOW)
    }

    /// Reads the answer (without waiting).
    pub async fn answer_now(&self) -> Result<Answer, Error> {
        Ok(match self.fetch().await? {
            None => Answer::Denied,
            Some(model) if model.request_approved == Some(true) && model.key.is_some() => {
                Answer::Approved
            }
            Some(_) if self.is_expired() => Answer::Denied,
            Some(_) => Answer::Pending,
        })
    }

    /// `None`: the request no longer exists (denied, or purged).
    async fn fetch(&self) -> Result<Option<RequestModel>, Error> {
        let response = self
            .api
            .http
            .get(format!(
                "{}/api/auth-requests/{}/response",
                self.api.base, self.id
            ))
            .query(&[("code", self.access_code.expose())])
            .send_retrying()
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(Some(response.json().await?));
        }
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status == StatusCode::NOT_FOUND
            || (status.is_client_error() && error_message(&body).contains("doesn't exist"))
        {
            return Ok(None);
        }
        Err(Error::Server(error_message(&body)))
    }

    /// Waits for an answer on Vaultwarden's anonymous channel
    /// (`/notifications/anonymous-hub?Token=<id>`), at most `timeout`, then
    /// reads it. A server without the channel (`ENABLE_WEBSOCKET=false`):
    /// polls every 3 seconds.
    pub async fn wait_for_answer(&self, timeout: Duration) -> Result<Answer, Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        match crate::hub::wait_for_auth_response(self.api.server(), &self.id, deadline).await {
            Ok(()) | Err(Error::NotFound | Error::Network(_)) => {}
            Err(error) => return Err(error),
        }
        loop {
            let answer = self.answer_now().await?;
            if answer != Answer::Pending || tokio::time::Instant::now() >= deadline {
                return Ok(answer);
            }
            tokio::time::sleep(
                Duration::from_secs(3)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
            )
            .await;
        }
    }

    /// Request approved: log in with the access code. The server may still
    /// ask for the second factor (`LoginStep::TwoFactor`, like a password
    /// login).
    pub async fn login(&self) -> Result<LoginStep, Error> {
        let model = self.fetch().await?.ok_or_else(|| {
            Error::Invalid("the login request was denied or has expired".to_owned())
        })?;
        if model.request_approved != Some(true) {
            return Err(Error::Invalid(
                "the login request is not approved yet".to_owned(),
            ));
        }
        let key = model
            .key
            .ok_or_else(|| Error::Server("request approved without a key".to_owned()))?;
        // Checks right away that the key opens with our private key.
        key.parse::<UnsignedSharedKey>().map_err(Error::crypto)?;
        let prelogin = self.api.prelogin(&self.email).await?;
        let pending = PendingLogin {
            api: self.api.clone(),
            store: self.store.clone(),
            email: self.email.clone(),
            secret: crate::LoginSecret::Device(Approval {
                private_key: self.private_key.clone(),
                key,
                master_key: model.master_password_hash.is_some(),
            }),
            prelogin,
            auth_hash: self.access_code.expose().to_owned(),
            auth_request: Some(self.id.clone()),
            device_id: self.device_id.clone(),
            methods: Vec::new(),
        };
        pending.request(None).await
    }
}

/// Waits for the answer to the request `id` on the anonymous channel, until
/// `deadline`. `Ok`: an answer arrived (or the deadline passed).
pub(crate) async fn read_anonymous_hub(
    socket: &mut crate::hub::Socket,
    id: &str,
    deadline: tokio::time::Instant,
) -> Result<bool, Error> {
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let Ok(message) =
            tokio::time::timeout(remaining.min(crate::hub::SILENCE), socket.next()).await
        else {
            if remaining > crate::hub::SILENCE {
                return Err(Error::Network("anonymous channel: silence".to_owned()));
            }
            return Ok(false);
        };
        match message {
            Some(Ok(Message::Binary(data))) => {
                if crate::hub::frames(&data)
                    .into_iter()
                    .any(|frame| crate::hub::is_auth_response(frame, id))
                {
                    return Ok(true);
                }
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(Error::Network("anonymous channel closed".to_owned()));
            }
            Some(Ok(Message::Ping(data))) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(Error::Network(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_types_are_translated() {
        assert_eq!(device_label("Chrome Browser"), "Chrome browser");
        assert_eq!(device_label("iOS"), "iPhone or iPad");
        assert_eq!(device_label(""), "Unknown device");
        assert_eq!(device_label("Toaster"), "Toaster");
    }

    #[test]
    fn the_fingerprint_matches_bitwarden() {
        // Vector from Bitwarden's SDK (auth_request.rs, test_approve).
        let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyLRDUwXB4BfQ507D4meFPmwn5zwy3IqTPJO4plrrhnclWahXa240BzyFW9gHgYu+Jrgms5xBfRTBMcEsqqNm7+JpB6C1B6yvnik0DpJgWQw1rwvy4SUYidpR/AWbQi47n/hvnmzI/sQxGddVfvWu1iTKOlf5blbKYAXnUE5DZBGnrWfacNXwRRdtP06tFB0LwDgw+91CeLSJ9py6dm1qX5JIxoO8StJOQl65goLCdrTWlox+0Jh4xFUfCkb+s3px+OhSCzJbvG/hlrSRcUz5GnwlCEyF3v5lfUtV96MJD+78d8pmH6CfFAp2wxKRAbGdk+JccJYO6y6oIXd3Fm7twIDAQAB";
        assert_eq!(
            fingerprint_phrase("test@bitwarden.com", key).unwrap(),
            "childless-unfair-prowler-dropbox-designate"
        );
        // Address typed with capitals: same phrase.
        assert_eq!(
            fingerprint_phrase(" Test@Bitwarden.com ", key).unwrap(),
            "childless-unfair-prowler-dropbox-designate"
        );
        assert!(fingerprint_phrase("a@b.c", "pas de la base64 !").is_err());
    }

    #[test]
    fn dates_and_expiry() {
        assert_eq!(timestamp("1970-01-01T00:01:00.000000Z"), Some(60));
        assert_eq!(timestamp("hier"), None);
        assert!(expired(now() - 16 * 60, REQUEST_LIFETIME));
        assert!(!expired(now() - 60, REQUEST_LIFETIME));
        assert!(expired(now() - 5 * 60, LOGIN_WINDOW));
    }
}
