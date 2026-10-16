//! Connexion avec un appareil (les « auth requests » de Bitwarden), dans les
//! deux sens :
//!
//! - **approuver** (`Connection::auth_requests`, `answer_auth_request`) : un
//!   autre client du même compte (coffre web, autre Verrou) demande à se
//!   connecter sans mot de passe principal. Le coffre ouvert ici montre la
//!   demande (type d'appareil, adresse IP, heure, phrase d'empreinte) ;
//!   l'approuver chiffre la **clé de l'utilisateur** pour la clé publique
//!   RSA de la demande (`approve_auth_request` du SDK de Bitwarden, comme les
//!   apps officielles) et l'envoie par `PUT /api/auth-requests/{id}` ;
//! - **demander** (`begin`, puis `DeviceLogin::answer_now` ou
//!   `wait_for_answer`, puis `DeviceLogin::login`) : cet appareil crée une
//!   paire de clés RSA et un code d'accès (`new_auth_request` du SDK),
//!   publie la clé publique (`POST /api/auth-requests`), montre la phrase
//!   d'empreinte, attend la réponse (canal anonyme
//!   `/notifications/anonymous-hub`, sinon interrogation), puis se connecte
//!   avec le code d'accès à la place du mot de passe et déchiffre la clé
//!   reçue avec sa clé privée.
//!
//! La phrase d'empreinte se calcule des deux côtés à partir de la clé
//! publique et de l'adresse du compte (`fingerprint` du SDK) : si elles
//! diffèrent, la demande n'est pas celle qu'on croit (hameçonnage).
//!
//! Ce que Vaultwarden 1.37.4 impose (`src/api/core/accounts.rs`,
//! `src/api/identity.rs`, `src/db/models/auth_request.rs`) :
//! - la demande n'est acceptée que d'un appareil **déjà connu** du compte
//!   (`deviceIdentifier` et type identiques à une connexion passée) : un
//!   appareil neuf doit d'abord se connecter une fois avec le mot de passe ;
//! - la connexion par le code d'accès doit venir de la **même adresse IP**
//!   que la demande, dans les **5 minutes** qui suivent sa création, une
//!   seule fois ; le second facteur du compte reste exigé ;
//! - une demande refusée est effacée ; toutes le sont après 15 minutes.

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

/// Durée de vie d'une demande, comme Bitwarden (et la purge de
/// Vaultwarden) : au-delà, elle n'est plus montrée.
pub const REQUEST_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Vaultwarden refuse la connexion par le code d'accès plus de 5 minutes
/// après la création de la demande.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Une demande de connexion d'un autre appareil, à approuver ou refuser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub id: String,
    /// Le type d'appareil, en clair (« Navigateur Chrome », « iPhone »…).
    pub device: String,
    /// Adresse IP vue par le serveur (vide s'il ne la donne pas).
    pub ip: String,
    /// Création, en secondes depuis 1970.
    pub created_at: i64,
    /// Phrase d'empreinte (cinq mots) de la clé publique et de l'adresse du
    /// compte : celle qu'affiche l'appareil qui demande.
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

/// Le type d'appareil que le serveur annonce, en français.
pub fn device_label(device_type: &str) -> String {
    let label = match device_type {
        "Android" | "Android (Amazon)" => "Android",
        "iOS" => "iPhone ou iPad",
        "Chrome Extension" => "Extension Chrome",
        "Firefox Extension" => "Extension Firefox",
        "Opera Extension" => "Extension Opera",
        "Edge Extension" => "Extension Edge",
        "Vivaldi Extension" => "Extension Vivaldi",
        "Safari Extension" => "Extension Safari",
        "Windows" | "Windows Desktop" => "Windows (app de bureau)",
        "macOS" | "MacOS Desktop" | "macOS Desktop" => "Mac (app de bureau)",
        "Linux" | "Linux Desktop" => "Linux (app de bureau)",
        "Chrome" | "Chrome Browser" => "Navigateur Chrome",
        "Firefox" | "Firefox Browser" => "Navigateur Firefox",
        "Opera" | "Opera Browser" => "Navigateur Opera",
        "Edge" | "Edge Browser" => "Navigateur Edge",
        "Internet Explorer" | "IE Browser" => "Internet Explorer",
        "Safari" | "Safari Browser" => "Navigateur Safari",
        "Vivaldi" | "Vivaldi Browser" => "Navigateur Vivaldi",
        "DuckDuckGo" | "DuckDuckGo Browser" => "Navigateur DuckDuckGo",
        "Unknown Browser" => "Navigateur inconnu",
        "Windows CLI" | "MacOs CLI" | "macOS CLI" | "Linux CLI" => "Ligne de commande",
        "" => "Appareil inconnu",
        other => other,
    };
    label.to_owned()
}

/// Date RFC 3339 du serveur → secondes depuis 1970.
fn timestamp(date: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|d| d.timestamp())
}

/// La phrase d'empreinte de `public_key` (DER SPKI en base64) pour
/// l'adresse `email` (en minuscules, comme le serveur la garde).
pub fn fingerprint_phrase(email: &str, public_key: &str) -> Result<String, Error> {
    let key: B64 = public_key
        .parse()
        .map_err(|_| Error::Invalid("clé publique de la demande illisible".to_owned()))?;
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
    /// Les demandes de connexion en attente pour ce compte, de la plus
    /// récente à la plus ancienne, sans celles de plus de 15 minutes.
    pub async fn auth_requests(&mut self) -> Result<Vec<AuthRequest>, Error> {
        let access = self.access_token().await?;
        let response = self
            .api
            .http
            .get(format!("{}/api/auth-requests/pending", self.api.base))
            .bearer_auth(&access)
            .send_retrying()
            .await?;
        // Serveur plus ancien : la route sans `/pending`.
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
            .map_err(|e| Error::Server(format!("demandes de connexion illisibles ({e})")))?
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

    /// Approuve (`approve`) ou refuse la demande `id`.
    ///
    /// La demande est relue sur le serveur juste avant (jamais une clé
    /// publique venue d'ailleurs) ; approuver chiffre la clé de
    /// l'utilisateur pour sa clé publique (RSA-OAEP, comme le SDK de
    /// Bitwarden) : seul l'appareil qui a la clé privée peut la lire. Une
    /// demande expirée, ou dont la phrase d'empreinte n'est plus celle qui a
    /// été montrée (`fingerprint`), est refusée sans rien envoyer.
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
                "cette demande de connexion n'existe plus".to_owned(),
            ));
        }
        let model: RequestModel = response.json().await?;
        if model.request_approved.is_some() {
            return Err(Error::Invalid(
                "cette demande de connexion a déjà reçu une réponse".to_owned(),
            ));
        }
        let created_at = timestamp(&model.creation_date).unwrap_or(0);
        if approve && expired(created_at, REQUEST_LIFETIME) {
            return Err(Error::Invalid(
                "cette demande de connexion a expiré".to_owned(),
            ));
        }
        if approve && fingerprint_phrase(&self.account.email, &model.public_key)? != fingerprint {
            return Err(Error::Invalid(
                "la phrase d'empreinte de la demande a changé : refusée".to_owned(),
            ));
        }
        let key = if approve {
            let public_key: B64 = model
                .public_key
                .parse()
                .map_err(|_| Error::Invalid("clé publique de la demande illisible".to_owned()))?;
            self.sdk
                .auth()
                .approve_auth_request(public_key)
                .map_err(Error::crypto)?
                .to_string()
        } else {
            // Vaultwarden exige le champ, même pour un refus.
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

/// Une demande de connexion faite par cet appareil, en attente d'une
/// réponse. Garde la clé privée RSA et le code d'accès (en mémoire
/// seulement) : perdue, il faut recommencer.
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

/// Ce que l'autre appareil a renvoyé : la clé chiffrée pour notre clé
/// publique.
#[derive(Clone)]
pub(crate) struct Approval {
    pub private_key: SecretString,
    pub key: String,
    /// La clé reçue est la clé principale (anciens clients), pas la clé de
    /// l'utilisateur.
    pub master_key: bool,
}

/// Réponse à une demande, vue de l'appareil qui demande.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Pending,
    Approved,
    /// Refusée (le serveur l'a effacée) ou expirée.
    Denied,
}

/// Crée la demande de connexion de cet appareil pour `email`.
pub async fn begin(store: &Store, server: &str, email: &str) -> Result<DeviceLogin, Error> {
    let api = Api::new(server)?;
    let email = normalize_email(email);
    if email.is_empty() {
        return Err(Error::Invalid("adresse e-mail manquante".to_owned()));
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
        // Vaultwarden répond pareil pour un compte inconnu et pour un
        // appareil jamais connecté à ce compte (il ne dit pas lequel).
        if message.contains("doesn't exist") {
            return Err(Error::Invalid(
                "demande refusée par le serveur : ce compte n'existe pas, ou cet appareil ne \
                 s'y est encore jamais connecté (Vaultwarden exige une première connexion \
                 avec le mot de passe principal)"
                    .to_owned(),
            ));
        }
        return Err(Error::Server(message));
    }
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Server("demande créée sans identifiant".to_owned()))?
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

    /// La phrase à comparer avec celle que montre l'appareil qui approuve.
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

    /// Plus de connexion possible : Vaultwarden refuse le code d'accès
    /// 5 minutes après la création.
    pub fn is_expired(&self) -> bool {
        expired(self.created_at, LOGIN_WINDOW)
    }

    /// Lit la réponse (sans attendre).
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

    /// `None` : la demande n'existe plus (refusée, ou purgée).
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

    /// Attend une réponse sur le canal anonyme de Vaultwarden
    /// (`/notifications/anonymous-hub?Token=<id>`), au plus `timeout`, puis
    /// la lit. Un serveur sans canal (`ENABLE_WEBSOCKET=false`) : on
    /// interroge toutes les 3 secondes.
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

    /// Demande approuvée : se connecter avec le code d'accès. Le serveur
    /// peut encore demander le second facteur (`LoginStep::TwoFactor`,
    /// comme une connexion par mot de passe).
    pub async fn login(&self) -> Result<LoginStep, Error> {
        let model = self.fetch().await?.ok_or_else(|| {
            Error::Invalid("la demande de connexion a été refusée ou a expiré".to_owned())
        })?;
        if model.request_approved != Some(true) {
            return Err(Error::Invalid(
                "la demande de connexion n'est pas encore approuvée".to_owned(),
            ));
        }
        let key = model
            .key
            .ok_or_else(|| Error::Server("demande approuvée sans clé".to_owned()))?;
        // Vérifie tout de suite que la clé s'ouvre avec notre clé privée.
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

/// Attend la réponse à la demande `id` sur le canal anonyme, jusqu'à
/// `deadline`. `Ok` : une réponse est arrivée (ou le délai est passé).
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
                return Err(Error::Network("canal anonyme : silence".to_owned()));
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
                return Err(Error::Network("canal anonyme fermé".to_owned()));
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
        assert_eq!(device_label("Chrome Browser"), "Navigateur Chrome");
        assert_eq!(device_label("iOS"), "iPhone ou iPad");
        assert_eq!(device_label(""), "Appareil inconnu");
        assert_eq!(device_label("Toaster"), "Toaster");
    }

    #[test]
    fn the_fingerprint_matches_bitwarden() {
        // Vecteur du SDK de Bitwarden (auth_request.rs, test_approve).
        let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyLRDUwXB4BfQ507D4meFPmwn5zwy3IqTPJO4plrrhnclWahXa240BzyFW9gHgYu+Jrgms5xBfRTBMcEsqqNm7+JpB6C1B6yvnik0DpJgWQw1rwvy4SUYidpR/AWbQi47n/hvnmzI/sQxGddVfvWu1iTKOlf5blbKYAXnUE5DZBGnrWfacNXwRRdtP06tFB0LwDgw+91CeLSJ9py6dm1qX5JIxoO8StJOQl65goLCdrTWlox+0Jh4xFUfCkb+s3px+OhSCzJbvG/hlrSRcUz5GnwlCEyF3v5lfUtV96MJD+78d8pmH6CfFAp2wxKRAbGdk+JccJYO6y6oIXd3Fm7twIDAQAB";
        assert_eq!(
            fingerprint_phrase("test@bitwarden.com", key).unwrap(),
            "childless-unfair-prowler-dropbox-designate"
        );
        // Adresse saisie avec des majuscules : même phrase.
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
