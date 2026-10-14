//! Passkeys (`WebAuthn`) : la clé privée reste dans Rust.
//!
//! Format de Bitwarden et Vaultwarden (`login.fido2Credentials`), pour que
//! les apps officielles et le coffre web les relisent : clé ECDSA P-256 en
//! PKCS#8 (base64url), identifiant d'accréditation en UUID (16 octets) ou
//! `b64.<base64url>`, identifiant d'utilisateur en base64url, compteur et
//! « découvrable » en texte.
//!
//! Ce module fabrique ce que le navigateur rendrait à la page : création
//! (attestation `none`, ou `packed` auto-signée si le site la demande) et
//! assertion signée ES256. L'origine vient de l'adresse de la page (fournie
//! par le navigateur, jamais par la page) ; l'identifiant du site (`rpId`)
//! doit être cet hôte ou l'un de ses domaines parents, jamais un suffixe
//! public. L'extension ne voit jamais la clé privée.

use std::fmt::Write as _;

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroize as _;

use crate::secret::SecretString;

/// Algorithme COSE d'ES256 (ECDSA P-256, SHA-256), le seul que Verrou crée.
pub const ES256: i64 = -7;

/// Indicateurs des données d'authentification (`WebAuthn` §6.1).
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
/// Sauvegardable et sauvegardée : la passkey est synchronisée par le coffre.
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED_DATA: u8 = 0x40;

/// AAGUID nul : Verrou ne prétend être aucun modèle d'authentificateur
/// (attestation `none`).
const AAGUID: [u8; 16] = [0; 16];

/// Longueurs maximales acceptées depuis une page.
const MAX_CHALLENGE: usize = 1024;
const MAX_USER_ID: usize = 64;

/// Une passkey du coffre, déchiffrée. `key` : la clé privée PKCS#8 en
/// base64url, telle que Bitwarden la garde ; elle ne sort jamais de Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passkey {
    /// L'élément (identifiant) qui la porte.
    pub item: String,
    /// Identifiant au format de Bitwarden (UUID, ou `b64.…`).
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// Identifiant de l'utilisateur chez le site, base64url.
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub counter: u32,
    pub discoverable: bool,
    /// Horodatage Unix de création, en secondes.
    pub created: i64,
    pub key: SecretString,
}

impl Passkey {
    /// L'identifiant tel que la page le voit (octets bruts).
    pub fn raw_id(&self) -> Option<Vec<u8>> {
        credential_id_bytes(&self.credential_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    #[error("page non sécurisée (HTTPS exigé)")]
    InsecurePage,
    #[error("identifiant de site (rpId) invalide pour cette page")]
    BadRpId,
    #[error("cette passkey n'appartient pas à ce site")]
    WrongSite,
    #[error("passkey illisible (clé ou identifiant)")]
    BadKey,
    #[error("requête de passkey invalide : {0}")]
    BadRequest(&'static str),
}

// MARK: Encodages

/// base64url, avec ou sans remplissage (Bitwarden n'en met pas).
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(input.trim().trim_end_matches('=').as_bytes())
        .ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// `0f4e…` (UUID, 16 octets) ou `b64.<base64url>` → octets bruts.
pub fn credential_id_bytes(id: &str) -> Option<Vec<u8>> {
    if let Some(encoded) = id.strip_prefix("b64.") {
        return b64url_decode(encoded);
    }
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || id.len() != 36 {
        return None;
    }
    (0..16)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Octets bruts → format de Bitwarden : UUID pour 16 octets, `b64.…` sinon.
pub fn credential_id_string(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return format!("b64.{}", b64url(bytes));
    }
    let hex = bytes.iter().fold(String::with_capacity(32), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// MARK: Origine et identifiant du site

/// L'origine de la page (`https://hôte[:port]`) et l'identifiant du site
/// retenu : `requested` s'il est cet hôte ou un domaine parent enregistrable,
/// sinon l'hôte lui-même quand rien n'est demandé.
pub fn origin_and_rp_id(
    page_url: &str,
    requested: Option<&str>,
) -> Result<(String, String), PasskeyError> {
    let url = Url::parse(page_url).map_err(|_| PasskeyError::InsecurePage)?;
    let host = url
        .host_str()
        .ok_or(PasskeyError::InsecurePage)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    match url.scheme() {
        "https" => {}
        "http" if host == "localhost" => {}
        _ => return Err(PasskeyError::InsecurePage),
    }
    // Pas d'adresse IP : WebAuthn veut un nom de domaine.
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return Err(PasskeyError::BadRpId);
    }
    let origin = url.origin().ascii_serialization();
    let rp_id = match requested.map(|r| r.trim().trim_end_matches('.').to_ascii_lowercase()) {
        None => host,
        Some(rp) if rp.is_empty() => host,
        Some(rp) if rp == host => rp,
        // Domaine parent : il doit être enregistrable (`github.com`, pas `com`
        // ni `co.uk`).
        Some(rp) if host.ends_with(&format!(".{rp}")) && psl::domain_str(&rp).is_some() => rp,
        Some(_) => return Err(PasskeyError::BadRpId),
    };
    Ok((origin, rp_id))
}

#[derive(Serialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: String,
    origin: &'a str,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

/// `clientDataJSON`, comme Chrome l'écrit (même ordre des clés).
fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    serde_json::to_vec(&ClientData {
        kind,
        challenge: b64url(challenge),
        origin,
        cross_origin: false,
    })
    .unwrap_or_default()
}

fn check_challenge(challenge: &[u8]) -> Result<(), PasskeyError> {
    if challenge.len() < 16 || challenge.len() > MAX_CHALLENGE {
        return Err(PasskeyError::BadRequest("défi absent ou trop long"));
    }
    Ok(())
}

// MARK: CBOR (le strict nécessaire, forme canonique de CTAP2)

fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend([major | 0x18, value as u8]),
        0x100..=0xffff => {
            out.push(major | 0x19);
            out.extend((value as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 0x1a);
            out.extend((value as u32).to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_head(out, 0, value as u64);
    } else {
        cbor_head(out, 1, (-1 - value) as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// Clé publique COSE EC2 (P-256, ES256), clés dans l'ordre canonique.
fn cose_public_key(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let mut out = Vec::with_capacity(77);
    cbor_head(&mut out, 5, 5);
    cbor_int(&mut out, 1); // kty
    cbor_int(&mut out, 2); // EC2
    cbor_int(&mut out, 3); // alg
    cbor_int(&mut out, ES256);
    cbor_int(&mut out, -1); // crv
    cbor_int(&mut out, 1); // P-256
    cbor_int(&mut out, -2); // x
    cbor_bytes(&mut out, point.x().map(AsRef::as_ref).unwrap_or_default());
    cbor_int(&mut out, -3); // y
    cbor_bytes(&mut out, point.y().map(AsRef::as_ref).unwrap_or_default());
    out
}

fn authenticator_data(rp_id: &str, flags: u8, counter: u32, attested: Option<&[u8]>) -> Vec<u8> {
    let mut data = Vec::with_capacity(37 + attested.map_or(0, <[u8]>::len));
    data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    data.push(flags | if attested.is_some() { ATTESTED_DATA } else { 0 });
    data.extend_from_slice(&counter.to_be_bytes());
    if let Some(attested) = attested {
        data.extend_from_slice(attested);
    }
    data
}

/// Signature ES256 (DER) de `authenticatorData ‖ SHA-256(clientDataJSON)`.
fn sign(key: &SigningKey, authenticator_data: &[u8], client_data: &[u8]) -> Vec<u8> {
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data));
    let signature: Signature = key.sign(&message);
    signature.to_der().as_bytes().to_vec()
}

fn signing_key(passkey: &Passkey) -> Result<SigningKey, PasskeyError> {
    let mut der = b64url_decode(passkey.key.expose()).ok_or(PasskeyError::BadKey)?;
    let key = SigningKey::from_pkcs8_der(&der).map_err(|_| PasskeyError::BadKey);
    der.zeroize();
    key
}

fn flags(user_verified: bool) -> u8 {
    USER_PRESENT | BACKUP_ELIGIBLE | BACKED_UP | if user_verified { USER_VERIFIED } else { 0 }
}

// MARK: Création

/// Ce que la page demande à `navigator.credentials.create`.
#[derive(Clone, Debug)]
pub struct RegistrationRequest<'a> {
    pub page_url: &'a str,
    pub rp_id: Option<&'a str>,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    pub challenge: &'a [u8],
    /// L'utilisateur a été vérifié (Touch ID) : indicateur UV.
    pub user_verified: bool,
    /// Attestation demandée (`direct`, `enterprise`) : `packed` auto-signée,
    /// sinon `none`.
    pub self_attestation: bool,
}

/// Réponse de création, pour la page. Aucun secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// Clé publique `SubjectPublicKeyInfo` (DER), pour `getPublicKey()`.
    pub public_key: Vec<u8>,
}

/// Crée une passkey pour la page : la passkey à enregistrer dans l'élément
/// `item`, et la réponse pour la page.
pub fn register(
    request: &RegistrationRequest<'_>,
    item: &str,
    created: i64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Passkey, Registration), PasskeyError> {
    let (origin, rp_id) = origin_and_rp_id(request.page_url, request.rp_id)?;
    check_challenge(request.challenge)?;
    if request.user_id.is_empty() || request.user_id.len() > MAX_USER_ID {
        return Err(PasskeyError::BadRequest(
            "identifiant d'utilisateur invalide",
        ));
    }
    let key = SigningKey::random(rng);
    let mut credential_id = [0u8; 16];
    rng.fill_bytes(&mut credential_id);

    let cose = cose_public_key(&key);
    let mut attested = Vec::with_capacity(18 + credential_id.len() + cose.len());
    attested.extend_from_slice(&AAGUID);
    attested.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    attested.extend_from_slice(&credential_id);
    attested.extend_from_slice(&cose);
    let authenticator_data =
        authenticator_data(&rp_id, flags(request.user_verified), 0, Some(&attested));
    let client_data_json = client_data("webauthn.create", request.challenge, &origin);

    // { "fmt", "attStmt", "authData" }, dans l'ordre canonique.
    let mut attestation_object = Vec::with_capacity(authenticator_data.len() + 128);
    cbor_head(&mut attestation_object, 5, 3);
    cbor_text(&mut attestation_object, "fmt");
    if request.self_attestation {
        cbor_text(&mut attestation_object, "packed");
        cbor_text(&mut attestation_object, "attStmt");
        cbor_head(&mut attestation_object, 5, 2);
        cbor_text(&mut attestation_object, "alg");
        cbor_int(&mut attestation_object, ES256);
        cbor_text(&mut attestation_object, "sig");
        cbor_bytes(
            &mut attestation_object,
            &sign(&key, &authenticator_data, &client_data_json),
        );
    } else {
        cbor_text(&mut attestation_object, "none");
        cbor_text(&mut attestation_object, "attStmt");
        cbor_head(&mut attestation_object, 5, 0);
    }
    cbor_text(&mut attestation_object, "authData");
    cbor_bytes(&mut attestation_object, &authenticator_data);

    let public_key = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| PasskeyError::BadKey)?
        .into_vec();
    let pkcs8 = key.to_pkcs8_der().map_err(|_| PasskeyError::BadKey)?;
    let passkey = Passkey {
        item: item.to_owned(),
        credential_id: credential_id_string(&credential_id),
        rp_id,
        rp_name: request.rp_name.map(str::to_owned),
        user_handle: Some(b64url(request.user_id)),
        user_name: request.user_name.map(str::to_owned),
        user_display_name: request.user_display_name.map(str::to_owned),
        counter: 0,
        discoverable: true,
        created,
        key: SecretString::new(b64url(pkcs8.as_bytes())),
    };
    Ok((
        passkey,
        Registration {
            credential_id: credential_id.to_vec(),
            client_data_json,
            authenticator_data,
            attestation_object,
            public_key,
        },
    ))
}

// MARK: Assertion

#[derive(Clone, Debug)]
pub struct AssertionRequest<'a> {
    pub page_url: &'a str,
    pub rp_id: Option<&'a str>,
    pub challenge: &'a [u8],
    pub user_verified: bool,
}

/// Réponse d'authentification, pour la page. `counter` : la nouvelle valeur
/// du compteur, à enregistrer dans le coffre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub counter: u32,
}

/// Signe le défi de la page avec la passkey, si elle appartient au site.
pub fn assert(
    passkey: &Passkey,
    request: &AssertionRequest<'_>,
) -> Result<Assertion, PasskeyError> {
    let (origin, rp_id) = origin_and_rp_id(request.page_url, request.rp_id)?;
    if !passkey.rp_id.eq_ignore_ascii_case(&rp_id) {
        return Err(PasskeyError::WrongSite);
    }
    check_challenge(request.challenge)?;
    let key = signing_key(passkey)?;
    let credential_id = passkey.raw_id().ok_or(PasskeyError::BadKey)?;
    let counter = passkey.counter.saturating_add(1);
    let authenticator_data =
        authenticator_data(&rp_id, flags(request.user_verified), counter, None);
    let client_data_json = client_data("webauthn.get", request.challenge, &origin);
    let signature = sign(&key, &authenticator_data, &client_data_json);
    Ok(Assertion {
        credential_id,
        client_data_json,
        authenticator_data,
        signature,
        user_handle: passkey.user_handle.as_deref().and_then(b64url_decode),
        counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey as _;
    use rand::SeedableRng as _;

    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(7)
    }

    fn request<'a>(page: &'a str, rp_id: Option<&'a str>) -> RegistrationRequest<'a> {
        RegistrationRequest {
            page_url: page,
            rp_id,
            rp_name: Some("GitHub"),
            user_id: b"utilisateur-42",
            user_name: Some("camille"),
            user_display_name: Some("Camille Martin"),
            challenge: &[9; 32],
            user_verified: true,
            self_attestation: false,
        }
    }

    fn verify(public_key: &[u8], authenticator_data: &[u8], client_data: &[u8], sig: &[u8]) {
        let key = VerifyingKey::from_public_key_der(public_key).unwrap();
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data));
        let signature = DerSignature::try_from(sig).unwrap();
        key.verify(&message, &signature)
            .expect("signature ES256 valide");
    }

    #[test]
    fn rp_id_is_the_host_or_a_registrable_parent() {
        let ok = |page, rp| origin_and_rp_id(page, rp).map(|(_, rp)| rp);
        assert_eq!(ok("https://github.com/login", None).unwrap(), "github.com");
        assert_eq!(
            ok("https://login.github.com/", Some("github.com")).unwrap(),
            "github.com"
        );
        assert_eq!(
            origin_and_rp_id("https://login.github.com:8443/x", None)
                .unwrap()
                .0,
            "https://login.github.com:8443"
        );
        assert_eq!(ok("http://localhost:8000/", None).unwrap(), "localhost");
        assert_eq!(
            ok("https://github.com/", Some("evil.com")),
            Err(PasskeyError::BadRpId)
        );
        assert_eq!(
            ok("https://exemple.co.uk/", Some("co.uk")),
            Err(PasskeyError::BadRpId)
        );
        assert_eq!(
            ok("https://evilgithub.com/", Some("github.com")),
            Err(PasskeyError::BadRpId)
        );
        assert_eq!(
            ok("http://github.com/", None),
            Err(PasskeyError::InsecurePage)
        );
        assert_eq!(ok("https://192.168.1.1/", None), Err(PasskeyError::BadRpId));
    }

    #[test]
    fn credential_ids_use_the_bitwarden_format() {
        let bytes: Vec<u8> = (0..16).collect();
        let id = credential_id_string(&bytes);
        assert_eq!(id, "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(credential_id_bytes(&id).unwrap(), bytes);
        let long = [7u8; 20];
        let id = credential_id_string(&long);
        assert!(id.starts_with("b64."));
        assert_eq!(credential_id_bytes(&id).unwrap(), long);
        assert_eq!(credential_id_bytes("pas-un-uuid"), None);
    }

    #[test]
    fn registration_then_assertions_verify_and_count() {
        let (mut passkey, registration) = register(
            &request("https://github.com/signup", None),
            "item-1",
            1_700_000_000,
            &mut rng(),
        )
        .unwrap();
        assert_eq!(passkey.rp_id, "github.com");
        assert_eq!(passkey.counter, 0);
        assert!(passkey.discoverable);
        assert_eq!(passkey.user_handle.as_deref(), Some("dXRpbGlzYXRldXItNDI"));
        assert_eq!(passkey.raw_id().unwrap(), registration.credential_id);
        // La clé est une clé PKCS#8 P-256 que Bitwarden relit.
        let der = b64url_decode(passkey.key.expose()).unwrap();
        assert!(SigningKey::from_pkcs8_der(&der).is_ok());

        // Données d'authentification de la création : rpIdHash, UP|UV|BE|BS|AT,
        // compteur 0, AAGUID, identifiant, clé COSE.
        let data = &registration.authenticator_data;
        assert_eq!(&data[..32], Sha256::digest(b"github.com").as_slice());
        assert_eq!(data[32], 0x01 | 0x04 | 0x08 | 0x10 | 0x40);
        assert_eq!(&data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&data[53..55], &[0, 16]);
        assert_eq!(&data[55..71], registration.credential_id.as_slice());
        assert_eq!(&data[71..73], &[0xa5, 0x01]);
        let client: serde_json::Value =
            serde_json::from_slice(&registration.client_data_json).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://github.com");
        assert_eq!(client["challenge"], b64url(&[9; 32]));
        // Attestation « none » : { fmt: "none", attStmt: {}, authData }.
        assert!(
            registration
                .attestation_object
                .starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData")
        );

        for expected in 1..=3 {
            let assertion = assert(
                &passkey,
                &AssertionRequest {
                    page_url: "https://github.com/login",
                    rp_id: Some("github.com"),
                    challenge: &[expected as u8; 32],
                    user_verified: false,
                },
            )
            .unwrap();
            assert_eq!(assertion.counter, expected);
            assert_eq!(
                &assertion.authenticator_data[33..37],
                expected.to_be_bytes().as_slice()
            );
            assert_eq!(assertion.authenticator_data[32], 0x01 | 0x08 | 0x10);
            assert_eq!(
                assertion.user_handle.as_deref(),
                Some(&b"utilisateur-42"[..])
            );
            verify(
                &registration.public_key,
                &assertion.authenticator_data,
                &assertion.client_data_json,
                &assertion.signature,
            );
            // L'app enregistre le nouveau compteur.
            passkey.counter = assertion.counter;
        }
    }

    #[test]
    fn packed_self_attestation_is_signed_by_the_new_key() {
        let mut req = request("https://github.com/", None);
        req.self_attestation = true;
        let (_, registration) = register(&req, "x", 0, &mut rng()).unwrap();
        let object = &registration.attestation_object;
        assert!(object.starts_with(b"\xa3\x63fmt\x66packed\x67attStmt\xa2\x63alg\x26\x63sig"));
        let start = b"\xa3\x63fmt\x66packed\x67attStmt\xa2\x63alg\x26\x63sig".len();
        let len = object[start + 1] as usize;
        let sig = &object[start + 2..start + 2 + len];
        verify(
            &registration.public_key,
            &registration.authenticator_data,
            &registration.client_data_json,
            sig,
        );
    }

    #[test]
    fn a_passkey_only_signs_for_its_site() {
        let (passkey, _) =
            register(&request("https://github.com/", None), "x", 0, &mut rng()).unwrap();
        let ask = |page| {
            assert(
                &passkey,
                &AssertionRequest {
                    page_url: page,
                    rp_id: None,
                    challenge: &[1; 32],
                    user_verified: false,
                },
            )
        };
        assert!(ask("https://github.com/login").is_ok());
        assert_eq!(
            ask("https://gitlab.com/").unwrap_err(),
            PasskeyError::WrongSite
        );
        assert_eq!(
            ask("http://github.com/").unwrap_err(),
            PasskeyError::InsecurePage
        );
        // Un défi trop court est refusé.
        assert!(
            assert(
                &passkey,
                &AssertionRequest {
                    page_url: "https://github.com/",
                    rp_id: None,
                    challenge: &[1; 4],
                    user_verified: false,
                },
            )
            .is_err()
        );
    }

    /// Une passkey créée par Bitwarden (clé PKCS#8 de `p256`, identifiant
    /// UUID, compteur à 0) signe chez Verrou.
    #[test]
    fn signs_with_a_bitwarden_passkey() {
        let key = SigningKey::random(&mut rng());
        let passkey = Passkey {
            item: "x".to_owned(),
            credential_id: "1d5d8a2f-0f4e-4c3b-9a55-8d7a1b3c2e10".to_owned(),
            rp_id: "webauthn.io".to_owned(),
            rp_name: None,
            user_handle: Some("YWJj".to_owned()),
            user_name: Some("camille".to_owned()),
            user_display_name: None,
            counter: 0,
            discoverable: true,
            created: 0,
            key: SecretString::new(b64url(key.to_pkcs8_der().unwrap().as_bytes())),
        };
        let assertion = assert(
            &passkey,
            &AssertionRequest {
                page_url: "https://webauthn.io/",
                rp_id: Some("webauthn.io"),
                challenge: &[3; 32],
                user_verified: true,
            },
        )
        .unwrap();
        let public = key.verifying_key().to_public_key_der().unwrap();
        verify(
            public.as_bytes(),
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature,
        );
        assert_eq!(assertion.credential_id.len(), 16);
        assert_eq!(assertion.user_handle.as_deref(), Some(&b"abc"[..]));
    }
}
