//! Second facteur par clé de sécurité (`YubiKey` en `FIDO2`), sans navigateur.
//!
//! Verrou joue ici le rôle que tient un navigateur pour `WebAuthn` :
//! 1. il construit `clientDataJSON` (type, défi du serveur, origine du
//!    serveur) et en donne l'empreinte à la clé ;
//! 2. la clé signe, après un contact, l'empreinte du domaine (`rpId`) et
//!    celle de `clientDataJSON` : la signature ne vaut que pour ce serveur ;
//! 3. Verrou rend au serveur la réponse au format qu'attend Vaultwarden (celui
//!    de sa page `webauthn-mobile-connector.html`).
//!
//! La partie « dialogue avec la clé » (USB, protocole CTAP2) est confiée à
//! `authenticator-rs`, la bibliothèque de Firefox. Aucune cryptographie ici :
//! seule la clé signe, et seul le serveur vérifie.

use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Ce qu'il faut demander à la clé.
#[derive(Clone, Debug)]
pub struct AssertionRequest {
    pub rp_id: String,
    pub origin: String,
    pub client_data_json: Vec<u8>,
    pub client_data_hash: [u8; 32],
    /// Identifiants des clés enregistrées sur le compte.
    pub allow_credentials: Vec<Vec<u8>>,
    /// Extension `appid` (clés enregistrées autrefois en U2F).
    pub app_id: Option<String>,
    pub timeout_ms: u64,
}

/// Ce que la clé a répondu.
#[derive(Clone, Debug)]
pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// La clé a signé pour l'`appid` (U2F) plutôt que pour le `rpId`.
    pub used_app_id: bool,
}

/// Prépare la demande à partir du défi `WebAuthn` envoyé par le serveur.
pub fn assertion_request(server: &str, challenge_json: &str) -> Result<AssertionRequest, Error> {
    let options: Value = serde_json::from_str(challenge_json)
        .map_err(|e| Error::SecurityKey(format!("défi illisible ({e})")))?;
    let options = options.get("publicKey").unwrap_or(&options);
    let challenge = options
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::SecurityKey("défi absent".to_owned()))?;
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
            "aucune clé de sécurité n'est enregistrée sur ce compte".to_owned(),
        ));
    }
    // Ordre et forme de ce qu'écrit un navigateur ; le serveur vérifie le
    // type, le défi et l'origine.
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

/// Le jeton à envoyer au serveur comme réponse au second facteur.
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

/// `https://vault.exemple.fr/chemin` → `https://vault.exemple.fr`.
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

/// Les identifiants arrivent en base64url ; certains serveurs anciens les
/// envoient en base64 classique, avec ou sans remplissage.
fn decode_base64(text: &str) -> Result<Vec<u8>, Error> {
    let trimmed = text.trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(trimmed.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(trimmed.as_bytes()))
        .map_err(|_| Error::SecurityKey("identifiant de clé illisible".to_owned()))
}

pub use device::{SecurityKeyStatus, SigningSession};

/// Hors macOS, pas d'USB : la même interface, qui refuse tout. L'interface
/// Swift et les tests de la CI Linux compilent sans conditions.
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
        Error::SecurityKey("clé de sécurité en USB : macOS seulement".to_owned())
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

/// Dialogue avec la clé, par USB (macOS seulement : l'app sandboxée a le droit
/// `com.apple.security.device.usb`).
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

    /// Déverrouillage et enrôlement : le temps de brancher la clé, de saisir
    /// son code PIN et de la toucher.
    const UNLOCK_TIMEOUT_MS: u64 = 120_000;

    /// Où en est l'échange, pour l'afficher.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SecurityKeyStatus {
        /// Clé détectée : il faut la toucher.
        TouchRequired,
        /// La clé attend son code PIN, à donner par
        /// [`SigningSession::submit_pin`]. `retry` : le précédent était faux ;
        /// `attempts` : essais restants, si la clé le dit.
        PinRequired { retry: bool, attempts: Option<u8> },
    }

    /// Un échange en cours avec la clé, annulable depuis un autre fil.
    #[derive(Clone, Default)]
    pub struct SigningSession {
        service: Arc<Mutex<Option<AuthenticatorService>>>,
        /// Où répondre quand la clé attend son code PIN.
        pin_reply: Arc<Mutex<Option<Sender<Pin>>>>,
        /// Le code PIN saisi, gardé le temps d'un enrôlement (deux échanges
        /// avec la clé, un seul code à taper), puis effacé.
        pin: Arc<Mutex<Option<Zeroizing<String>>>>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl SigningSession {
        pub fn new() -> Self {
            Self::default()
        }

        /// Interrompt l'attente (l'utilisateur a annulé ou changé de méthode).
        pub fn cancel(&self) {
            // Sans destinataire, la bibliothèque cesse d'attendre le code PIN.
            lock(&self.pin_reply).take();
            lock(&self.pin).take();
            let mut guard = lock(&self.service);
            if let Some(service) = guard.as_mut() {
                let _ = service.cancel();
            }
            guard.take();
        }

        /// Le code PIN que la clé attend (après
        /// [`SecurityKeyStatus::PinRequired`]). `false` : plus rien n'attend.
        pub fn submit_pin(&self, pin: &str) -> bool {
            let Some(reply) = lock(&self.pin_reply).take() else {
                return false;
            };
            *lock(&self.pin) = Some(Zeroizing::new(pin.to_owned()));
            reply.send(Pin::new(pin)).is_ok()
        }

        /// Crée sur la clé une accréditation pour déverrouiller Verrou
        /// (extension `hmac-secret`, code PIN exigé), puis lui demande son
        /// secret pour `salt`. Deux contacts, un seul code PIN. `exclude` : les
        /// accréditations déjà enrôlées, pour ne pas enrôler deux fois la même
        /// clé. Rend l'identifiant de l'accréditation et le secret.
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
            // L'accréditation n'est pas « résidente » : la clé ne garde rien,
            // l'utilisateur est un identifiant aléatoire sans signification.
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
                    display_name: Some("Déverrouillage de Verrou".to_owned()),
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
                    "cette clé ne prend pas en charge hmac-secret".to_owned(),
                ));
            }
            let credential_id = registered
                .att_obj
                .auth_data
                .credential_data
                .map(|data| data.credential_id)
                .ok_or_else(|| {
                    Error::SecurityKey("la clé n'a pas rendu d'identifiant".to_owned())
                })?;
            let credential = UnlockCredential {
                credential_id: credential_id.clone(),
                salt: *salt,
            };
            let (_, secret) = self.read_secret(&[credential], on_status)?;
            Ok((credential_id, secret))
        }

        /// Demande à la clé branchée le secret de l'une des accréditations
        /// enrôlées (code PIN exigé, puis un contact). Rend l'accréditation
        /// qui a répondu, si la clé le dit, et le secret.
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
            // Un sel par accréditation (extension PRF, `evalByCredential`) : la
            // bibliothèque ne garde de la liste que les accréditations de la
            // clé branchée, puis choisit le sel qui va avec.
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
                // Enrôlement : le code PIN vient d'être saisi pour créer
                // l'accréditation.
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
                        "la clé n'a pas rendu son secret (hmac-secret non pris en charge)"
                            .to_owned(),
                    )
                })?;
            let secret = HmacSecret::from_slice(&output);
            output.zeroize();
            Ok((signed.assertion.credentials.map(|c| c.id), secret?))
        }

        /// Un échange avec la clé : relaie les demandes de contact et de code
        /// PIN (`allow_pin`), jusqu'à la réponse, au délai, ou à `cancel`.
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
                .map_err(|e| Error::SecurityKey(format!("USB indisponible ({e:?})")))?;
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
                                "la clé demande son code PIN : utilisez la connexion par le navigateur"
                                    .to_owned(),
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
                        return Err(Error::SecurityKey(
                            "aucune clé n'a répondu à temps".to_owned(),
                        ));
                    }
                }
            };
            lock(&self.service).take();
            lock(&self.pin_reply).take();
            Ok(outcome)
        }

        /// Bloquant : attend une clé, puis son contact, jusqu'au délai.
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
                // Vaultwarden demande « discouraged » : un contact suffit,
                // pas de code PIN.
                user_verification_req: UserVerificationRequirement::Discouraged,
                user_presence_req: true,
                extensions: AuthenticationExtensionsClientInputs {
                    app_id: request.app_id.clone(),
                    ..Default::default()
                },
                pin: None,
                use_ctap1_fallback: false,
            };
            // Pas de code PIN ici : le second facteur se contente d'un contact.
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
                            Error::SecurityKey(
                                "la clé n'a pas dit quel identifiant elle a utilisé".to_owned(),
                            )
                        })?;
                    Ok(AssertionResponse {
                        credential_id,
                        authenticator_data: assertion.auth_data.to_vec(),
                        signature: assertion.signature,
                        used_app_id: result.extensions.app_id == Some(true),
                    })
                }
                Err(AuthenticatorError::CancelledByUser) => {
                    Err(Error::SecurityKey("demande annulée".to_owned()))
                }
                Err(
                    AuthenticatorError::CredentialExcluded
                    | AuthenticatorError::UnsupportedOption(_),
                ) => Err(Error::SecurityKey("cette clé ne convient pas".to_owned())),
                Err(e) => Err(Error::SecurityKey(format!(
                    "cette clé n'est pas enregistrée sur ce compte, ou elle a refusé ({e:?})"
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

    /// Aucun serveur ne vérifie la signature du déverrouillage : seul compte
    /// le secret `hmac-secret`. L'empreinte signée est donc aléatoire.
    fn random_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);
        hash
    }

    /// Les refus de la clé, dits à l'utilisateur.
    fn unlock_error(error: AuthenticatorError) -> Error {
        let message = match error {
            AuthenticatorError::CancelledByUser => "demande annulée",
            AuthenticatorError::CredentialExcluded => {
                "cette clé est déjà enregistrée pour déverrouiller ce coffre"
            }
            AuthenticatorError::PinError(PinError::PinNotSet) => {
                "la clé n'a pas de code PIN : définissez-en un (Yubico Authenticator, rubrique Passkeys), puis recommencez"
            }
            AuthenticatorError::PinError(PinError::PinBlocked) => {
                "code PIN bloqué : la clé doit être réinitialisée (ses accréditations seront perdues)"
            }
            AuthenticatorError::PinError(PinError::PinAuthBlocked | PinError::UvBlocked) => {
                "trop de codes PIN erronés : débranchez la clé, rebranchez-la, puis recommencez"
            }
            AuthenticatorError::PinError(PinError::PinIsTooShort | PinError::PinIsTooLong(_)) => {
                "longueur de code PIN invalide"
            }
            AuthenticatorError::HIDError(HIDError::Command(CommandError::StatusCode(
                StatusCode::NoCredentials,
                _,
            ))) => "cette clé n'est pas enregistrée pour déverrouiller ce coffre",
            AuthenticatorError::HIDError(HIDError::IO(..)) | AuthenticatorError::Io(_) => {
                "la clé a été débranchée"
            }
            AuthenticatorError::UnsupportedOption(_) => {
                "cette clé ne convient pas : il faut une clé FIDO2 avec code PIN et hmac-secret"
            }
            e => return Error::SecurityKey(format!("la clé a refusé ({e:?})")),
        };
        Error::SecurityKey(message.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Défi tel que l'envoie Vaultwarden 1.37 (`PublicKeyCredentialRequestOptions`).
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
