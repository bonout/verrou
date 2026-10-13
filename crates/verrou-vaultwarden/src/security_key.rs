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

#[cfg(target_os = "macos")]
pub use device::{SecurityKeyStatus, SigningSession};

/// Dialogue avec la clé, par USB (macOS seulement : l'app sandboxée a le droit
/// `com.apple.security.device.usb`).
#[cfg(target_os = "macos")]
mod device {
    use std::sync::mpsc::{RecvTimeoutError, channel};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
        UserVerificationRequirement,
    };
    use authenticator::errors::AuthenticatorError;
    use authenticator::statecallback::StateCallback;
    use authenticator::{StatusPinUv, StatusUpdate};

    use super::{AssertionRequest, AssertionResponse};
    use crate::error::Error;

    /// Où en est l'échange, pour l'afficher.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SecurityKeyStatus {
        /// Clé détectée : il faut la toucher.
        TouchRequired,
    }

    /// Une demande de signature en cours, annulable depuis un autre fil.
    #[derive(Clone, Default)]
    pub struct SigningSession {
        service: Arc<Mutex<Option<AuthenticatorService>>>,
    }

    impl SigningSession {
        pub fn new() -> Self {
            Self::default()
        }

        /// Interrompt l'attente (l'utilisateur a annulé ou changé de méthode).
        pub fn cancel(&self) {
            let mut guard = self.service.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(service) = guard.as_mut() {
                let _ = service.cancel();
            }
            guard.take();
        }

        /// Bloquant : attend une clé, puis son contact, jusqu'au délai.
        pub fn sign(
            &self,
            request: &AssertionRequest,
            on_status: impl Fn(SecurityKeyStatus),
        ) -> Result<AssertionResponse, Error> {
            let mut service = AuthenticatorService::new()
                .map_err(|e| Error::SecurityKey(format!("USB indisponible ({e:?})")))?;
            service.add_u2f_usb_hid_platform_transports();

            let args = SignArgs {
                client_data_hash: request.client_data_hash,
                origin: request.origin.clone(),
                relying_party_id: request.rp_id.clone(),
                allow_list: request
                    .allow_credentials
                    .iter()
                    .map(|id| PublicKeyCredentialDescriptor {
                        id: id.clone(),
                        transports: vec![Transport::USB],
                    })
                    .collect(),
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
            let (status_tx, status_rx) = channel::<StatusUpdate>();
            let (result_tx, result_rx) = channel();
            let callback = StateCallback::new(Box::new(move |result| {
                let _ = result_tx.send(result);
            }));
            service
                .sign(request.timeout_ms, args, status_tx, callback)
                .map_err(|e| Error::SecurityKey(format!("{e:?}")))?;
            *self.service.lock().unwrap_or_else(PoisonError::into_inner) = Some(service);

            let deadline = Instant::now() + Duration::from_millis(request.timeout_ms + 2_000);
            let outcome = loop {
                while let Ok(status) = status_rx.try_recv() {
                    match status {
                        StatusUpdate::PresenceRequired => {
                            on_status(SecurityKeyStatus::TouchRequired);
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
            self.service
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();

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
