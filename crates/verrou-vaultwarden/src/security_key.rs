//! Second factor with a security key (`YubiKey` over `FIDO2`), without a
//! browser.
//!
//! Verrou plays here the role a browser plays for `WebAuthn`:
//! 1. it builds `clientDataJSON` (type, server challenge, server origin)
//!    and gives its hash to the key;
//! 2. the key signs, after a touch, the hash of the domain (`rpId`) and
//!    that of `clientDataJSON`: the signature is only valid for this server;
//! 3. Verrou returns the answer to the server in the format Vaultwarden
//!    expects (that of its `webauthn-mobile-connector.html` page).
//!
//! The "dialogue with the key" part (USB, CTAP2 protocol) is handed to
//! `authenticator-rs`, Firefox's library. No cryptography here: only the
//! key signs, and only the server verifies.

use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// What to ask the key.
#[derive(Clone, Debug)]
pub struct AssertionRequest {
    pub rp_id: String,
    pub origin: String,
    pub client_data_json: Vec<u8>,
    pub client_data_hash: [u8; 32],
    /// Ids of the keys registered on the account.
    pub allow_credentials: Vec<Vec<u8>>,
    /// `appid` extension (keys registered long ago with U2F).
    pub app_id: Option<String>,
    pub timeout_ms: u64,
}

/// What the key answered.
#[derive(Clone, Debug)]
pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// The key signed for the `appid` (U2F) rather than for the `rpId`.
    pub used_app_id: bool,
}

/// Prepares the request from the `WebAuthn` challenge sent by the server.
pub fn assertion_request(server: &str, challenge_json: &str) -> Result<AssertionRequest, Error> {
    let options: Value = serde_json::from_str(challenge_json)
        .map_err(|e| Error::SecurityKey(format!("unreadable challenge ({e})")))?;
    let options = options.get("publicKey").unwrap_or(&options);
    let challenge = options
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::SecurityKey("challenge missing".to_owned()))?;
    let origin = origin_of(server)?;
    let rp_id = options
        .get("rpId")
        .and_then(Value::as_str)
        .map_or_else(|| host_of(server), |id| Ok(id.to_owned()))?;
    let allow_credentials = options
        .get("allowCredentials")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .map(decode_base64)
        .collect::<Result<Vec<_>, _>>()?;
    if allow_credentials.is_empty() {
        return Err(Error::SecurityKey(
            "no security key is registered on this account".to_owned(),
        ));
    }
    // Order and shape of what a browser writes; the server checks the type,
    // the challenge and the origin.
    let client_data_json = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))
    .map_err(|e| Error::SecurityKey(e.to_string()))?;
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();
    let timeout_ms = options
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(60_000)
        .clamp(10_000, 120_000);
    Ok(AssertionRequest {
        rp_id,
        origin,
        client_data_json,
        client_data_hash,
        allow_credentials,
        app_id: options
            .pointer("/extensions/appid")
            .and_then(Value::as_str)
            .map(str::to_owned),
        timeout_ms,
    })
}

/// The token to send to the server as the second factor answer.
pub fn token(request: &AssertionRequest, response: &AssertionResponse) -> String {
    let id = BASE64URL_NOPAD.encode(&response.credential_id);
    let extensions = if response.used_app_id {
        json!({ "appid": true })
    } else {
        json!({})
    };
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": extensions,
        "response": {
            "authenticatorData": BASE64URL_NOPAD.encode(&response.authenticator_data),
            "clientDataJson": BASE64URL_NOPAD.encode(&request.client_data_json),
            "signature": BASE64URL_NOPAD.encode(&response.signature),
        },
    })
    .to_string()
}

/// `https://vault.exemple.fr/path` → `https://vault.exemple.fr`.
fn origin_of(server: &str) -> Result<String, Error> {
    let url =
        reqwest::Url::parse(server).map_err(|e| Error::InvalidServer(format!("{server} ({e})")))?;
    Ok(url.origin().ascii_serialization())
}

fn host_of(server: &str) -> Result<String, Error> {
    reqwest::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .ok_or_else(|| Error::InvalidServer(server.to_owned()))
}

/// Ids arrive in base64url; some old servers send them in standard base64,
/// with or without padding.
fn decode_base64(text: &str) -> Result<Vec<u8>, Error> {
    let trimmed = text.trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(trimmed.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(trimmed.as_bytes()))
        .map_err(|_| Error::SecurityKey("unreadable key id".to_owned()))
}

pub use device::{SecurityKeyStatus, SigningSession};

/// Outside macOS, no USB: the same interface, which refuses everything. The
/// Swift interface and the Linux CI tests compile without conditions.
#[cfg(not(target_os = "macos"))]
mod device {
    use super::{AssertionRequest, AssertionResponse};
    use crate::error::Error;
    use crate::unlock_keys::{HmacSecret, UnlockCredential};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SecurityKeyStatus {
        TouchRequired,
        PinRequired { retry: bool, attempts: Option<u8> },
    }

    #[derive(Clone, Default)]
    pub struct SigningSession;

    fn unsupported() -> Error {
        Error::SecurityKey("USB security keys: macOS only".to_owned())
    }

    #[allow(clippy::unused_self)]
    impl SigningSession {
        pub fn new() -> Self {
            Self
        }

        pub fn cancel(&self) {}

        pub fn submit_pin(&self, _pin: &str) -> bool {
            false
        }

        pub fn sign(
            &self,
            _request: &AssertionRequest,
            _on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<AssertionResponse, Error> {
            Err(unsupported())
        }

        pub fn enroll_for_unlock(
            &self,
            _salt: &[u8; 32],
            _exclude: &[Vec<u8>],
            _on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<(Vec<u8>, HmacSecret), Error> {
            Err(unsupported())
        }

        pub fn unlock_secret(
            &self,
            _credentials: &[UnlockCredential],
            _on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<(Option<Vec<u8>>, HmacSecret), Error> {
            Err(unsupported())
        }
    }
}

/// Dialogue with the key, over USB (macOS only: the sandboxed app has the
/// `com.apple.security.device.usb` entitlement).
#[cfg(target_os = "macos")]
mod device {
    use std::collections::HashMap;
    use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
    use authenticator::crypto::COSEAlgorithm;
    use authenticator::ctap2::commands::StatusCode;
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientInputs, AuthenticationExtensionsPRFInputs,
        AuthenticationExtensionsPRFValues, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, Transport, UserVerificationRequirement,
    };
    use authenticator::errors::{AuthenticatorError, CommandError, HIDError};
    use authenticator::statecallback::StateCallback;
    use authenticator::{Pin, PinError, StatusPinUv, StatusUpdate};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use zeroize::{Zeroize, Zeroizing};

    use super::{AssertionRequest, AssertionResponse};
    use crate::error::Error;
    use crate::unlock_keys::{HmacSecret, RP_ID, UnlockCredential};

    /// Unlocking and enrolment: time to plug in the key, type its PIN and
    /// touch it.
    const UNLOCK_TIMEOUT_MS: u64 = 120_000;

    /// Where the exchange stands, to display it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SecurityKeyStatus {
        /// Key detected: it must be touched.
        TouchRequired,
        /// The key waits for its PIN, to be given through
        /// [`SigningSession::submit_pin`]. `retry`: the previous one was
        /// wrong; `attempts`: attempts left, if the key says so.
        PinRequired { retry: bool, attempts: Option<u8> },
    }

    /// An ongoing exchange with the key, cancellable from another thread.
    #[derive(Clone, Default)]
    pub struct SigningSession {
        service: Arc<Mutex<Option<AuthenticatorService>>>,
        /// Where to answer when the key waits for its PIN.
        pin_reply: Arc<Mutex<Option<Sender<Pin>>>>,
        /// The typed PIN, kept for the length of an enrolment (two exchanges
        /// with the key, a single PIN to type), then wiped.
        pin: Arc<Mutex<Option<Zeroizing<String>>>>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl SigningSession {
        pub fn new() -> Self {
            Self::default()
        }

        /// Interrupts the wait (the user cancelled or changed method).
        pub fn cancel(&self) {
            // Without a receiver, the library stops waiting for the PIN.
            lock(&self.pin_reply).take();
            lock(&self.pin).take();
            let mut guard = lock(&self.service);
            if let Some(service) = guard.as_mut() {
                let _ = service.cancel();
            }
            guard.take();
        }

        /// The PIN the key waits for (after
        /// [`SecurityKeyStatus::PinRequired`]). `false`: nothing waits any more.
        pub fn submit_pin(&self, pin: &str) -> bool {
            let Some(reply) = lock(&self.pin_reply).take() else {
                return false;
            };
            *lock(&self.pin) = Some(Zeroizing::new(pin.to_owned()));
            reply.send(Pin::new(pin)).is_ok()
        }

        /// Creates on the key a credential to unlock Verrou (`hmac-secret`
        /// extension, PIN required), then asks it for its secret for `salt`.
        /// Two touches, a single PIN. `exclude`: the credentials already
        /// enrolled, so as not to enrol the same key twice. Returns the
        /// credential id and the secret.
        pub fn enroll_for_unlock(
            &self,
            salt: &[u8; 32],
            exclude: &[Vec<u8>],
            on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<(Vec<u8>, HmacSecret), Error> {
            let result = self.enroll(salt, exclude, &on_status);
            lock(&self.pin).take();
            result
        }

        fn enroll(
            &self,
            salt: &[u8; 32],
            exclude: &[Vec<u8>],
            on_status: &dyn Fn(SecurityKeyStatus),
        ) -> Result<(Vec<u8>, HmacSecret), Error> {
            // The credential is not "resident": the key keeps nothing, the
            // user is a meaningless random id.
            let mut user_id = [0u8; 16];
            OsRng.fill_bytes(&mut user_id);
            let args = RegisterArgs {
                client_data_hash: random_hash(),
                relying_party: RelyingParty {
                    id: RP_ID.to_owned(),
                    name: Some("Verrou".to_owned()),
                },
                origin: RP_ID.to_owned(),
                user: PublicKeyCredentialUserEntity {
                    id: user_id.to_vec(),
                    name: Some("Verrou".to_owned()),
                    display_name: Some("Verrou unlock".to_owned()),
                },
                pub_cred_params: vec![
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithm::ES256,
                    },
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithm::EDDSA,
                    },
                ],
                exclude_list: descriptors(exclude.iter()),
                user_verification_req: UserVerificationRequirement::Required,
                resident_key_req: ResidentKeyRequirement::Discouraged,
                extensions: AuthenticationExtensionsClientInputs {
                    hmac_create_secret: Some(true),
                    ..Default::default()
                },
                pin: None,
                use_ctap1_fallback: false,
            };
            let registered = self
                .exchange(
                    UNLOCK_TIMEOUT_MS,
                    true,
                    on_status,
                    |service, status, callback| {
                        service.register(UNLOCK_TIMEOUT_MS, args, status, callback)
                    },
                )?
                .map_err(unlock_error)?;
            if registered.extensions.hmac_create_secret != Some(true) {
                return Err(Error::SecurityKey(
                    "this key does not support hmac-secret".to_owned(),
                ));
            }
            let credential_id = registered
                .att_obj
                .auth_data
                .credential_data
                .map(|data| data.credential_id)
                .ok_or_else(|| Error::SecurityKey("the key did not return an id".to_owned()))?;
            let credential = UnlockCredential {
                credential_id: credential_id.clone(),
                salt: *salt,
            };
            let (_, secret) = self.read_secret(&[credential], on_status)?;
            Ok((credential_id, secret))
        }

        /// Asks the plugged-in key for the secret of one of the enrolled
        /// credentials (PIN required, then a touch). Returns the credential
        /// that answered, if the key says so, and the secret.
        pub fn unlock_secret(
            &self,
            credentials: &[UnlockCredential],
            on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<(Option<Vec<u8>>, HmacSecret), Error> {
            self.read_secret(credentials, &on_status)
        }

        fn read_secret(
            &self,
            credentials: &[UnlockCredential],
            on_status: &dyn Fn(SecurityKeyStatus),
        ) -> Result<(Option<Vec<u8>>, HmacSecret), Error> {
            // One salt per credential (PRF extension, `evalByCredential`): the
            // library keeps from the list only the plugged-in key's
            // credentials, then picks the matching salt.
            let by_credential: HashMap<Vec<u8>, AuthenticationExtensionsPRFValues> = credentials
                .iter()
                .map(|c| {
                    let values = AuthenticationExtensionsPRFValues {
                        first: c.salt.to_vec(),
                        second: None,
                    };
                    (c.credential_id.clone(), values)
                })
                .collect();
            let args = SignArgs {
                client_data_hash: random_hash(),
                origin: RP_ID.to_owned(),
                relying_party_id: RP_ID.to_owned(),
                allow_list: descriptors(credentials.iter().map(|c| &c.credential_id)),
                user_verification_req: UserVerificationRequirement::Required,
                user_presence_req: true,
                extensions: AuthenticationExtensionsClientInputs {
                    prf: Some(AuthenticationExtensionsPRFInputs {
                        eval: None,
                        eval_by_credential: Some(by_credential),
                    }),
                    ..Default::default()
                },
                // Enrolment: the PIN was just typed to create the credential.
                pin: lock(&self.pin).as_ref().map(|pin| Pin::new(pin)),
                use_ctap1_fallback: false,
            };
            let signed = self
                .exchange(
                    UNLOCK_TIMEOUT_MS,
                    true,
                    on_status,
                    |service, status, callback| {
                        service.sign(UNLOCK_TIMEOUT_MS, args, status, callback)
                    },
                )?
                .map_err(unlock_error)?;
            let mut output = signed
                .extensions
                .prf
                .and_then(|prf| prf.results)
                .map(|values| values.first)
                .ok_or_else(|| {
                    Error::SecurityKey(
                        "the key did not return its secret (hmac-secret not supported)".to_owned(),
                    )
                })?;
            let secret = HmacSecret::from_slice(&output);
            output.zeroize();
            Ok((signed.assertion.credentials.map(|c| c.id), secret?))
        }

        /// An exchange with the key: relays the touch and PIN requests
        /// (`allow_pin`), until the answer, the timeout, or `cancel`.
        fn exchange<T: Send + 'static>(
            &self,
            timeout_ms: u64,
            allow_pin: bool,
            on_status: &dyn Fn(SecurityKeyStatus),
            start: impl FnOnce(
                &mut AuthenticatorService,
                Sender<StatusUpdate>,
                StateCallback<authenticator::Result<T>>,
            ) -> authenticator::Result<()>,
        ) -> Result<authenticator::Result<T>, Error> {
            let mut service = AuthenticatorService::new()
                .map_err(|e| Error::SecurityKey(format!("USB unavailable ({e:?})")))?;
            service.add_u2f_usb_hid_platform_transports();
            let (status_tx, status_rx) = channel::<StatusUpdate>();
            let (result_tx, result_rx) = channel();
            let callback = StateCallback::new(Box::new(move |result| {
                let _ = result_tx.send(result);
            }));
            start(&mut service, status_tx, callback)
                .map_err(|e| Error::SecurityKey(format!("{e:?}")))?;
            *lock(&self.service) = Some(service);

            let deadline = Instant::now() + Duration::from_millis(timeout_ms + 2_000);
            let outcome = loop {
                while let Ok(status) = status_rx.try_recv() {
                    match status {
                        StatusUpdate::PresenceRequired => {
                            on_status(SecurityKeyStatus::TouchRequired);
                        }
                        StatusUpdate::PinUvError(StatusPinUv::PinRequired(reply)) if allow_pin => {
                            *lock(&self.pin_reply) = Some(reply);
                            on_status(SecurityKeyStatus::PinRequired {
                                retry: false,
                                attempts: None,
                            });
                        }
                        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(reply, attempts))
                            if allow_pin =>
                        {
                            lock(&self.pin).take();
                            *lock(&self.pin_reply) = Some(reply);
                            on_status(SecurityKeyStatus::PinRequired {
                                retry: true,
                                attempts,
                            });
                        }
                        StatusUpdate::PinUvError(
                            StatusPinUv::PinRequired(_) | StatusPinUv::InvalidPin(..),
                        ) => {
                            self.cancel();
                            return Err(Error::SecurityKey(
                                "the key asks for its PIN: use the browser login".to_owned(),
                            ));
                        }
                        _ => {}
                    }
                }
                match result_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(result) => break result,
                    Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                    Err(_) => {
                        self.cancel();
                        return Err(Error::SecurityKey("no key answered in time".to_owned()));
                    }
                }
            };
            lock(&self.service).take();
            lock(&self.pin_reply).take();
            Ok(outcome)
        }

        /// Blocking: waits for a key, then its touch, until the timeout.
        pub fn sign(
            &self,
            request: &AssertionRequest,
            on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<AssertionResponse, Error> {
            let args = SignArgs {
                client_data_hash: request.client_data_hash,
                origin: request.origin.clone(),
                relying_party_id: request.rp_id.clone(),
                allow_list: descriptors(request.allow_credentials.iter()),
                // Vaultwarden asks for "discouraged": a touch is enough, no
                // PIN.
                user_verification_req: UserVerificationRequirement::Discouraged,
                user_presence_req: true,
                extensions: AuthenticationExtensionsClientInputs {
                    app_id: request.app_id.clone(),
                    ..Default::default()
                },
                pin: None,
                use_ctap1_fallback: false,
            };
            // No PIN here: the second factor makes do with a touch.
            let outcome = self.exchange(
                request.timeout_ms,
                false,
                &on_status,
                |service, status, callback| {
                    service.sign(request.timeout_ms, args, status, callback)
                },
            )?;

            match outcome {
                Ok(result) => {
                    let assertion = result.assertion;
                    let credential_id = assertion
                        .credentials
                        .map(|c| c.id)
                        .or_else(|| {
                            (request.allow_credentials.len() == 1)
                                .then(|| request.allow_credentials[0].clone())
                        })
                        .ok_or_else(|| {
                            Error::SecurityKey("the key did not say which id it used".to_owned())
                        })?;
                    Ok(AssertionResponse {
                        credential_id,
                        authenticator_data: assertion.auth_data.to_vec(),
                        signature: assertion.signature,
                        used_app_id: result.extensions.app_id == Some(true),
                    })
                }
                Err(AuthenticatorError::CancelledByUser) => {
                    Err(Error::SecurityKey("request cancelled".to_owned()))
                }
                Err(
                    AuthenticatorError::CredentialExcluded
                    | AuthenticatorError::UnsupportedOption(_),
                ) => Err(Error::SecurityKey("this key is not suitable".to_owned())),
                Err(e) => Err(Error::SecurityKey(format!(
                    "this key is not registered on this account, or it refused ({e:?})"
                ))),
            }
        }
    }

    fn descriptors<'a>(
        ids: impl Iterator<Item = &'a Vec<u8>>,
    ) -> Vec<PublicKeyCredentialDescriptor> {
        ids.map(|id| PublicKeyCredentialDescriptor {
            id: id.clone(),
            transports: vec![Transport::USB],
        })
        .collect()
    }

    /// No server checks the unlock signature: only the `hmac-secret` secret
    /// counts. The signed hash is therefore random.
    fn random_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);
        hash
    }

    /// The key's refusals, told to the user.
    fn unlock_error(error: AuthenticatorError) -> Error {
        let message = match error {
            AuthenticatorError::CancelledByUser => "request cancelled",
            AuthenticatorError::CredentialExcluded => {
                "this key is already registered to unlock this vault"
            }
            AuthenticatorError::PinError(PinError::PinNotSet) => {
                "the key has no PIN: set one (Yubico Authenticator, Passkeys section), then try again"
            }
            AuthenticatorError::PinError(PinError::PinBlocked) => {
                "PIN blocked: the key must be reset (its credentials will be lost)"
            }
            AuthenticatorError::PinError(PinError::PinAuthBlocked | PinError::UvBlocked) => {
                "too many wrong PINs: unplug the key, plug it back in, then try again"
            }
            AuthenticatorError::PinError(PinError::PinIsTooShort | PinError::PinIsTooLong(_)) => {
                "invalid PIN length"
            }
            AuthenticatorError::HIDError(HIDError::Command(CommandError::StatusCode(
                StatusCode::NoCredentials,
                _,
            ))) => "this key is not registered to unlock this vault",
            AuthenticatorError::HIDError(HIDError::IO(..)) | AuthenticatorError::Io(_) => {
                "the key was unplugged"
            }
            AuthenticatorError::UnsupportedOption(_) => {
                "this key is not suitable: a FIDO2 key with a PIN and hmac-secret is needed"
            }
            e => return Error::SecurityKey(format!("the key refused ({e:?})")),
        };
        Error::SecurityKey(message.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Challenge as Vaultwarden 1.37 sends it (`PublicKeyCredentialRequestOptions`).
    const CHALLENGE: &str = r#"{"challenge":"q83vEjRWeJA","timeout":60000,"rpId":"vault.exemple.fr","allowCredentials":[{"type":"public-key","id":"AQIDBA"}],"userVerification":"discouraged","extensions":{"appid":"https://vault.exemple.fr/app-id.json"}}"#;

    #[test]
    fn request_follows_the_server_challenge() {
        let request = assertion_request("https://vault.exemple.fr", CHALLENGE).unwrap();
        assert_eq!(request.rp_id, "vault.exemple.fr");
        assert_eq!(request.origin, "https://vault.exemple.fr");
        assert_eq!(request.allow_credentials, [vec![1, 2, 3, 4]]);
        assert_eq!(
            request.app_id.as_deref(),
            Some("https://vault.exemple.fr/app-id.json")
        );
        let client: Value = serde_json::from_slice(&request.client_data_json).unwrap();
        assert_eq!(client["type"], "webauthn.get");
        assert_eq!(client["challenge"], "q83vEjRWeJA");
        assert_eq!(client["origin"], "https://vault.exemple.fr");
        let hash: [u8; 32] = Sha256::digest(&request.client_data_json).into();
        assert_eq!(request.client_data_hash, hash);
    }

    #[test]
    fn origin_keeps_a_non_default_port() {
        let request = assertion_request("http://localhost:8099", CHALLENGE).unwrap();
        assert_eq!(request.origin, "http://localhost:8099");
    }

    #[test]
    fn token_has_the_connector_shape() {
        let request = assertion_request("https://vault.exemple.fr", CHALLENGE).unwrap();
        let response = AssertionResponse {
            credential_id: vec![1, 2, 3, 4],
            authenticator_data: vec![9; 37],
            signature: vec![7; 70],
            used_app_id: false,
        };
        let token: Value = serde_json::from_str(&token(&request, &response)).unwrap();
        assert_eq!(token["id"], "AQIDBA");
        assert_eq!(token["rawId"], "AQIDBA");
        assert_eq!(token["type"], "public-key");
        assert_eq!(token["extensions"], json!({}));
        let client = BASE64URL_NOPAD
            .decode(
                token["response"]["clientDataJson"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        assert_eq!(client, request.client_data_json);
    }

    #[test]
    fn missing_credentials_are_explained() {
        let challenge = r#"{"challenge":"abc","allowCredentials":[]}"#;
        assert!(matches!(
            assertion_request("https://vault.exemple.fr", challenge),
            Err(Error::SecurityKey(_))
        ));
    }

    #[test]
    fn standard_base64_ids_are_accepted() {
        assert_eq!(decode_base64("AQIDBA==").unwrap(), [1, 2, 3, 4]);
        assert_eq!(decode_base64("+/8").unwrap(), [0xfb, 0xff]);
    }
}
