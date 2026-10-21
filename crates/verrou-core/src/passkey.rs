//! Passkeys (`WebAuthn`): the private key stays in Rust.
//!
//! Bitwarden and Vaultwarden format (`login.fido2Credentials`), so that the
//! official apps and the web vault read them back: ECDSA P-256 key in
//! PKCS#8 (base64url), credential identifier as a UUID (16 bytes) or
//! `b64.<base64url>`, user identifier in base64url, counter and
//! "discoverable" as text.
//!
//! This module builds what the browser would return to the page: creation
//! (`none` attestation, or self-signed `packed` if the site asks for it) and
//! ES256-signed assertion. The origin comes from the page address (supplied
//! by the browser, never by the page); the site identifier (`rpId`) must be
//! this host or one of its parent domains, never a public suffix. The
//! extension never sees the private key.

use std::fmt::Write as _;

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroize as _;

use crate::secret::SecretString;

/// COSE algorithm of ES256 (ECDSA P-256, SHA-256), the only one Verrou creates.
pub const ES256: i64 = -7;

/// Authenticator data flags (`WebAuthn` §6.1).
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
/// Backup eligible and backed up: the passkey is synced by the vault.
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED_DATA: u8 = 0x40;

/// Zero AAGUID: Verrou claims to be no authenticator model
/// (`none` attestation).
const AAGUID: [u8; 16] = [0; 16];

/// Maximum lengths accepted from a page.
const MAX_CHALLENGE: usize = 1024;
const MAX_USER_ID: usize = 64;

/// A vault passkey, decrypted. `key`: the PKCS#8 private key in
/// base64url, as Bitwarden stores it; it never leaves Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passkey {
    /// The item (login) that holds it.
    pub item: String,
    /// Identifier in the Bitwarden format (UUID, or `b64.…`).
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// The user's identifier at the site, base64url.
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub counter: u32,
    pub discoverable: bool,
    /// Unix creation timestamp, in seconds.
    pub created: i64,
    pub key: SecretString,
}

impl Passkey {
    /// The identifier as the page sees it (raw bytes).
    pub fn raw_id(&self) -> Option<Vec<u8>> {
        credential_id_bytes(&self.credential_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    #[error("insecure page (HTTPS required)")]
    InsecurePage,
    #[error("invalid site identifier (rpId) for this page")]
    BadRpId,
    #[error("this passkey does not belong to this site")]
    WrongSite,
    #[error("unreadable passkey (key or identifier)")]
    BadKey,
    #[error("invalid passkey request: {0}")]
    BadRequest(&'static str),
}

// MARK: Encodings

/// base64url, with or without padding (Bitwarden uses none).
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(input.trim().trim_end_matches('=').as_bytes())
        .ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// `0f4e…` (UUID, 16 bytes) or `b64.<base64url>` → raw bytes.
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

/// Raw bytes → Bitwarden format: UUID for 16 bytes, `b64.…` otherwise.
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

// MARK: Origin and site identifier

/// The page origin (`https://host[:port]`) and the chosen site identifier:
/// `requested` if it is this host or a registrable parent domain,
/// otherwise the host itself when nothing is requested.
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
    // No IP address: WebAuthn wants a domain name.
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return Err(PasskeyError::BadRpId);
    }
    let origin = url.origin().ascii_serialization();
    let rp_id = match requested.map(|r| r.trim().trim_end_matches('.').to_ascii_lowercase()) {
        None => host,
        Some(rp) if rp.is_empty() => host,
        Some(rp) if rp == host => rp,
        // Parent domain: it must be registrable (`github.com`, not `com`
        // nor `co.uk`).
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

/// `clientDataJSON`, as Chrome writes it (same key order).
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
        return Err(PasskeyError::BadRequest("challenge missing or too long"));
    }
    Ok(())
}

// MARK: CBOR (the bare minimum, CTAP2 canonical form)

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

/// COSE EC2 public key (P-256, ES256), keys in canonical order.
fn cose_public_key(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
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

/// ES256 signature (DER) of `authenticatorData ‖ SHA-256(clientDataJSON)`.
fn sign(key: &SigningKey, authenticator_data: &[u8], client_data: &[u8]) -> Vec<u8> {
    sign_hash(key, authenticator_data, &Sha256::digest(client_data))
}

/// ES256 signature (DER) of `authenticatorData ‖ clientDataHash`, when the
/// system (iOS) has already computed the hash of `clientDataJSON`.
fn sign_hash(key: &SigningKey, authenticator_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(client_data_hash);
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

/// New key, random identifier (16 bytes, a UUID for Bitwarden)
/// and authenticator data of the creation (counter 0, COSE key).
fn new_credential(
    rp_id: &str,
    user_verified: bool,
    rng: &mut (impl RngCore + CryptoRng),
) -> (SigningKey, [u8; 16], Vec<u8>) {
    let key = SigningKey::random(rng);
    let mut credential_id = [0u8; 16];
    rng.fill_bytes(&mut credential_id);
    let cose = cose_public_key(key.verifying_key());
    let mut attested = Vec::with_capacity(18 + credential_id.len() + cose.len());
    attested.extend_from_slice(&AAGUID);
    attested.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    attested.extend_from_slice(&credential_id);
    attested.extend_from_slice(&cose);
    let authenticator_data = authenticator_data(rp_id, flags(user_verified), 0, Some(&attested));
    (key, credential_id, authenticator_data)
}

fn public_key_der(key: &SigningKey) -> Result<Vec<u8>, PasskeyError> {
    Ok(key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| PasskeyError::BadKey)?
        .into_vec())
}

/// What the stored passkey says about itself: site, user, item.
struct PasskeyOwner<'a> {
    item: &'a str,
    rp_id: String,
    rp_name: Option<&'a str>,
    user_id: &'a [u8],
    user_name: Option<&'a str>,
    user_display_name: Option<&'a str>,
    created: i64,
}

/// The passkey as the vault stores it (Bitwarden format).
fn stored_passkey(
    key: &SigningKey,
    credential_id: &[u8],
    owner: &PasskeyOwner<'_>,
) -> Result<Passkey, PasskeyError> {
    let pkcs8 = key.to_pkcs8_der().map_err(|_| PasskeyError::BadKey)?;
    Ok(Passkey {
        item: owner.item.to_owned(),
        credential_id: credential_id_string(credential_id),
        rp_id: owner.rp_id.clone(),
        rp_name: owner.rp_name.map(str::to_owned),
        user_handle: Some(b64url(owner.user_id)),
        user_name: owner.user_name.map(str::to_owned),
        user_display_name: owner.user_display_name.map(str::to_owned),
        counter: 0,
        discoverable: true,
        created: owner.created,
        key: SecretString::new(b64url(pkcs8.as_bytes())),
    })
}

/// `{ "fmt": "none", "attStmt": {}, "authData": … }`, in canonical order.
fn none_attestation(authenticator_data: &[u8]) -> Vec<u8> {
    let mut object = Vec::with_capacity(authenticator_data.len() + 32);
    cbor_head(&mut object, 5, 3);
    cbor_text(&mut object, "fmt");
    cbor_text(&mut object, "none");
    cbor_text(&mut object, "attStmt");
    cbor_head(&mut object, 5, 0);
    cbor_text(&mut object, "authData");
    cbor_bytes(&mut object, authenticator_data);
    object
}

// MARK: Creation

/// What the page asks of `navigator.credentials.create`.
#[derive(Clone, Debug)]
pub struct RegistrationRequest<'a> {
    pub page_url: &'a str,
    pub rp_id: Option<&'a str>,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    pub challenge: &'a [u8],
    /// The user was verified (Touch ID): UV flag.
    pub user_verified: bool,
    /// Attestation requested (`direct`, `enterprise`): self-signed `packed`,
    /// otherwise `none`.
    pub self_attestation: bool,
}

/// Creation response, for the page. No secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// `SubjectPublicKeyInfo` public key (DER), for `getPublicKey()`.
    pub public_key: Vec<u8>,
}

/// Creates a passkey for the page: the passkey to store in item `item`,
/// and the response for the page.
pub fn register(
    request: &RegistrationRequest<'_>,
    item: &str,
    created: i64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Passkey, Registration), PasskeyError> {
    let (origin, rp_id) = origin_and_rp_id(request.page_url, request.rp_id)?;
    check_challenge(request.challenge)?;
    if request.user_id.is_empty() || request.user_id.len() > MAX_USER_ID {
        return Err(PasskeyError::BadRequest("invalid user identifier"));
    }
    let (key, credential_id, authenticator_data) =
        new_credential(&rp_id, request.user_verified, rng);
    let client_data_json = client_data("webauthn.create", request.challenge, &origin);

    // { "fmt", "attStmt", "authData" }, in canonical order.
    let attestation_object = if request.self_attestation {
        // { "fmt": "packed", "attStmt": { alg, sig }, "authData" }.
        let mut object = Vec::with_capacity(authenticator_data.len() + 128);
        cbor_head(&mut object, 5, 3);
        cbor_text(&mut object, "fmt");
        cbor_text(&mut object, "packed");
        cbor_text(&mut object, "attStmt");
        cbor_head(&mut object, 5, 2);
        cbor_text(&mut object, "alg");
        cbor_int(&mut object, ES256);
        cbor_text(&mut object, "sig");
        cbor_bytes(
            &mut object,
            &sign(&key, &authenticator_data, &client_data_json),
        );
        cbor_text(&mut object, "authData");
        cbor_bytes(&mut object, &authenticator_data);
        object
    } else {
        none_attestation(&authenticator_data)
    };

    let public_key = public_key_der(&key)?;
    let passkey = stored_passkey(
        &key,
        &credential_id,
        &PasskeyOwner {
            item,
            rp_id,
            rp_name: request.rp_name,
            user_id: request.user_id,
            user_name: request.user_name,
            user_display_name: request.user_display_name,
            created,
        },
    )?;
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

/// Authentication response, for the page. `counter`: the new counter
/// value, to store in the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub counter: u32,
}

/// Signs the page's challenge with the passkey, if it belongs to the site.
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

// MARK: System provider (iOS)
//
// On iPhone, the system builds `clientDataJSON` (it knows the page or the
// app, and has checked that the site may ask for this `rpId`: the page's
// domain in Safari, associated domains for an app); the AutoFill extension
// only receives the `rpId` and the SHA-256 hash of `clientDataJSON`. Verrou
// builds the authenticator data and signs
// `authenticatorData ‖ clientDataHash`.

/// Checks the shape of an `rpId` given by the system: a domain name
/// (not an IP address, not a bare public suffix), or `localhost`.
pub fn system_rp_id(rp_id: &str) -> Result<String, PasskeyError> {
    let rp = rp_id.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid_chars = rp
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if rp.is_empty() || !valid_chars || rp.starts_with('.') || rp.contains("..") {
        return Err(PasskeyError::BadRpId);
    }
    if rp.parse::<std::net::IpAddr>().is_ok() {
        return Err(PasskeyError::BadRpId);
    }
    if rp != "localhost" && psl::domain_str(&rp).is_none() {
        return Err(PasskeyError::BadRpId);
    }
    Ok(rp)
}

fn check_client_data_hash(hash: &[u8]) -> Result<(), PasskeyError> {
    if hash.len() == 32 {
        Ok(())
    } else {
        Err(PasskeyError::BadRequest("invalid clientDataJSON hash"))
    }
}

/// Creation requested by the system (`ASPasskeyCredentialRequest`).
#[derive(Clone, Debug)]
pub struct SystemRegistrationRequest<'a> {
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    /// SHA-256 of `clientDataJSON`, computed by the system.
    pub client_data_hash: &'a [u8],
    /// Face ID or master password asked for this creation.
    pub user_verified: bool,
}

/// Creation response for the system: `none` attestation. No secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemRegistration {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// `SubjectPublicKeyInfo` public key (DER), for tests.
    pub public_key: Vec<u8>,
}

/// Creates a passkey for the system: the one to store in item `item`
/// (Bitwarden format), and the `none` attestation to return to it.
pub fn register_for_system(
    request: &SystemRegistrationRequest<'_>,
    item: &str,
    created: i64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Passkey, SystemRegistration), PasskeyError> {
    let rp_id = system_rp_id(request.rp_id)?;
    check_client_data_hash(request.client_data_hash)?;
    if request.user_id.is_empty() || request.user_id.len() > MAX_USER_ID {
        return Err(PasskeyError::BadRequest("invalid user identifier"));
    }
    let (key, credential_id, authenticator_data) =
        new_credential(&rp_id, request.user_verified, rng);
    let attestation_object = none_attestation(&authenticator_data);
    let public_key = public_key_der(&key)?;
    let passkey = stored_passkey(
        &key,
        &credential_id,
        &PasskeyOwner {
            item,
            rp_id,
            rp_name: request.rp_name,
            user_id: request.user_id,
            user_name: request.user_name,
            user_display_name: request.user_display_name,
            created,
        },
    )?;
    Ok((
        passkey,
        SystemRegistration {
            credential_id: credential_id.to_vec(),
            authenticator_data,
            attestation_object,
            public_key,
        },
    ))
}

/// Assertion for the system: signed, counter incremented (`counter`, to
/// store in the vault).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub counter: u32,
}

/// Signs for the system (`ASPasskeyCredentialRequest`): `rp_id` must be
/// the passkey's.
pub fn assert_for_system(
    passkey: &Passkey,
    rp_id: &str,
    client_data_hash: &[u8],
    user_verified: bool,
) -> Result<SystemAssertion, PasskeyError> {
    let rp_id = system_rp_id(rp_id)?;
    if !passkey.rp_id.eq_ignore_ascii_case(&rp_id) {
        return Err(PasskeyError::WrongSite);
    }
    check_client_data_hash(client_data_hash)?;
    let key = signing_key(passkey)?;
    let credential_id = passkey.raw_id().ok_or(PasskeyError::BadKey)?;
    let counter = passkey.counter.saturating_add(1);
    let authenticator_data = authenticator_data(&rp_id, flags(user_verified), counter, None);
    let signature = sign_hash(&key, &authenticator_data, client_data_hash);
    Ok(SystemAssertion {
        credential_id,
        authenticator_data,
        signature,
        user_handle: passkey.user_handle.as_deref().and_then(b64url_decode),
        counter,
    })
}

// MARK: Conditional creation (iOS 18)
//
// After a password filled by Verrou, Safari can ask in the background for a
// passkey for the same account (`mediation: "conditional"`), with no UI.
// The vault is then locked (new process, no Face ID): the key is prepared
// **during** the fill, with the vault unlocked, and its private part sealed
// with the account's local key; the background request only needs the
// public key. The passkey joins the item the next time the vault is
// unlocked.

/// Key prepared for a conditional creation.
pub struct PreparedCredential {
    pub credential_id: [u8; 16],
    /// Uncompressed SEC1 public key (65 bytes).
    pub public_key: Vec<u8>,
    /// PKCS#8 private key in base64url, as Bitwarden stores it.
    pub private_key: SecretString,
}

/// New key and random identifier, with no site or user.
pub fn prepare_credential(
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PreparedCredential, PasskeyError> {
    let key = SigningKey::random(rng);
    let mut credential_id = [0u8; 16];
    rng.fill_bytes(&mut credential_id);
    let pkcs8 = key.to_pkcs8_der().map_err(|_| PasskeyError::BadKey)?;
    Ok(PreparedCredential {
        credential_id,
        public_key: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        private_key: SecretString::new(b64url(pkcs8.as_bytes())),
    })
}

/// Response to a conditional creation, with the prepared key: `none`
/// attestation, without user presence or verification (no UI was shown),
/// counter 0. No secret.
pub fn conditional_registration(
    rp_id: &str,
    credential_id: &[u8],
    public_key: &[u8],
    client_data_hash: &[u8],
) -> Result<SystemRegistration, PasskeyError> {
    let rp_id = system_rp_id(rp_id)?;
    check_client_data_hash(client_data_hash)?;
    if credential_id.is_empty() || credential_id.len() > 64 {
        return Err(PasskeyError::BadKey);
    }
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| PasskeyError::BadKey)?;
    let cose = cose_public_key(&key);
    let mut attested = Vec::with_capacity(18 + credential_id.len() + cose.len());
    attested.extend_from_slice(&AAGUID);
    attested.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    attested.extend_from_slice(credential_id);
    attested.extend_from_slice(&cose);
    let authenticator_data =
        authenticator_data(&rp_id, BACKUP_ELIGIBLE | BACKED_UP, 0, Some(&attested));
    Ok(SystemRegistration {
        credential_id: credential_id.to_vec(),
        attestation_object: none_attestation(&authenticator_data),
        public_key: key
            .to_public_key_der()
            .map_err(|_| PasskeyError::BadKey)?
            .into_vec(),
        authenticator_data,
    })
}

/// What a conditional creation registered at the site, to turn it into
/// the vault passkey.
pub struct ConditionalPasskey<'a> {
    pub item: &'a str,
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub credential_id: &'a [u8],
    /// PKCS#8 private key in base64url (unsealed, vault unlocked).
    pub private_key: &'a str,
    pub created: i64,
}

/// The vault passkey (Bitwarden format) of a conditional creation.
/// The private key must be a valid P-256 key.
pub fn conditional_passkey(created: &ConditionalPasskey<'_>) -> Result<Passkey, PasskeyError> {
    let rp_id = system_rp_id(created.rp_id)?;
    let mut der = b64url_decode(created.private_key).ok_or(PasskeyError::BadKey)?;
    let key = SigningKey::from_pkcs8_der(&der).map_err(|_| PasskeyError::BadKey);
    der.zeroize();
    stored_passkey(
        &key?,
        created.credential_id,
        &PasskeyOwner {
            item: created.item,
            rp_id,
            rp_name: None,
            user_id: created.user_id,
            user_name: created.user_name,
            user_display_name: None,
            created: created.created,
        },
    )
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
            .expect("valid ES256 signature");
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
        // The key is a PKCS#8 P-256 key that Bitwarden reads back.
        let der = b64url_decode(passkey.key.expose()).unwrap();
        assert!(SigningKey::from_pkcs8_der(&der).is_ok());

        // Authenticator data of the creation: rpIdHash, UP|UV|BE|BS|AT,
        // counter 0, AAGUID, identifier, COSE key.
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
        // "none" attestation: { fmt: "none", attStmt: {}, authData }.
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
            // The app stores the new counter.
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
        // A challenge that is too short is refused.
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

    /// A passkey created by Bitwarden (`p256` PKCS#8 key, UUID identifier,
    /// counter at 0) signs in Verrou.
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

    // MARK: System provider (iOS)

    fn system_request(hash: &[u8; 32]) -> SystemRegistrationRequest<'_> {
        SystemRegistrationRequest {
            rp_id: "localhost",
            rp_name: Some("Banc d'essai"),
            user_id: b"utilisateur-42",
            user_name: Some("camille"),
            user_display_name: Some("Camille Martin"),
            client_data_hash: hash,
            user_verified: true,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn system_rp_ids_are_domains() {
        assert_eq!(system_rp_id("GitHub.com.").unwrap(), "github.com");
        assert_eq!(system_rp_id("localhost").unwrap(), "localhost");
        assert_eq!(
            system_rp_id("login.example.co.uk").unwrap(),
            "login.example.co.uk"
        );
        for bad in [
            "",
            "co.uk",
            "com",
            "192.168.1.1",
            "::1",
            "a b.com",
            "evil.com/x",
            ".github.com",
            "a..b.com",
        ] {
            assert_eq!(system_rp_id(bad), Err(PasskeyError::BadRpId), "{bad}");
        }
    }

    /// Test vector: expected authenticator data byte by byte for
    /// `localhost`, UV set, counter 1.
    #[test]
    fn system_assertion_matches_the_test_vector_and_verifies() {
        let hash = [0x42; 32];
        let (passkey, registration) =
            register_for_system(&system_request(&hash), "item-1", 1_700_000_000, &mut rng())
                .unwrap();
        // Creation: rpIdHash(localhost), UP|UV|BE|BS|AT, counter 0, zero AAGUID.
        assert_eq!(
            hex(&registration.authenticator_data[..37]),
            "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97635d00000000"
        );
        assert_eq!(&registration.authenticator_data[37..53], &[0; 16]);
        assert_eq!(
            &registration.authenticator_data[55..71],
            registration.credential_id.as_slice()
        );
        assert!(
            registration
                .attestation_object
                .starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData")
        );
        assert_eq!(passkey.rp_id, "localhost");
        assert_eq!(passkey.raw_id().unwrap(), registration.credential_id);
        assert_eq!(passkey.user_handle.as_deref(), Some("dXRpbGlzYXRldXItNDI"));

        let client_data_hash = Sha256::digest(b"{\"type\":\"webauthn.get\"}");
        let assertion = assert_for_system(&passkey, "localhost", &client_data_hash, true).unwrap();
        assert_eq!(
            hex(&assertion.authenticator_data),
            "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000001"
        );
        assert_eq!(assertion.counter, 1);
        assert_eq!(assertion.credential_id, registration.credential_id);
        assert_eq!(
            assertion.user_handle.as_deref(),
            Some(&b"utilisateur-42"[..])
        );
        // Verification by a P-256 verifier independent of the signer:
        // the message is authenticatorData ‖ clientDataHash.
        let key = VerifyingKey::from_public_key_der(&registration.public_key).unwrap();
        let mut message = assertion.authenticator_data.clone();
        message.extend_from_slice(&client_data_hash);
        key.verify(
            &message,
            &DerSignature::try_from(assertion.signature.as_slice()).unwrap(),
        )
        .expect("valid ES256 signature");
    }

    /// Same passkey, same page: the browser path (clientDataJSON) and the
    /// system path (its hash) sign exactly the same thing
    /// (deterministic ECDSA, RFC 6979).
    #[test]
    fn system_and_browser_paths_sign_identically() {
        let (passkey, _) =
            register(&request("https://github.com/", None), "x", 0, &mut rng()).unwrap();
        let browser = assert(
            &passkey,
            &AssertionRequest {
                page_url: "https://github.com/login",
                rp_id: Some("github.com"),
                challenge: &[5; 32],
                user_verified: true,
            },
        )
        .unwrap();
        let system = assert_for_system(
            &passkey,
            "github.com",
            &Sha256::digest(&browser.client_data_json),
            true,
        )
        .unwrap();
        assert_eq!(system.authenticator_data, browser.authenticator_data);
        assert_eq!(system.signature, browser.signature);
    }

    #[test]
    fn system_requests_are_checked() {
        let hash = [1; 32];
        let (passkey, _) = register_for_system(&system_request(&hash), "x", 0, &mut rng()).unwrap();
        assert_eq!(
            assert_for_system(&passkey, "github.com", &hash, false).unwrap_err(),
            PasskeyError::WrongSite
        );
        assert!(matches!(
            assert_for_system(&passkey, "localhost", &[1; 20], false),
            Err(PasskeyError::BadRequest(_))
        ));
        let short = [1; 31];
        let mut bad = system_request(&hash);
        bad.client_data_hash = &short;
        assert!(register_for_system(&bad, "x", 0, &mut rng()).is_err());
        let mut no_user = system_request(&hash);
        no_user.user_id = b"";
        assert!(register_for_system(&no_user, "x", 0, &mut rng()).is_err());
        let mut public_suffix = system_request(&hash);
        public_suffix.rp_id = "github.io";
        assert_eq!(
            register_for_system(&public_suffix, "x", 0, &mut rng()).unwrap_err(),
            PasskeyError::BadRpId
        );
        // Without user verification: UP|BE|BS only.
        let assertion = assert_for_system(&passkey, "localhost", &hash, false).unwrap();
        assert_eq!(assertion.authenticator_data[32], 0x01 | 0x08 | 0x10);
    }

    #[test]
    fn conditional_creation_uses_the_prepared_key() {
        let prepared = prepare_credential(&mut rng()).unwrap();
        let hash = [5u8; 32];
        let registration = conditional_registration(
            "github.com",
            &prepared.credential_id,
            &prepared.public_key,
            &hash,
        )
        .unwrap();
        let data = &registration.authenticator_data;
        assert_eq!(&data[..32], Sha256::digest(b"github.com").as_slice());
        // Neither presence nor verification: no UI shown.
        assert_eq!(data[32] & (USER_PRESENT | USER_VERIFIED), 0);
        assert_eq!(data[32] & ATTESTED_DATA, ATTESTED_DATA);
        assert_eq!(&data[33..37], &[0, 0, 0, 0]);
        assert_eq!(
            &data[37 + 16 + 2..37 + 16 + 2 + 16],
            &prepared.credential_id
        );
        assert!(
            registration
                .attestation_object
                .windows(4)
                .any(|w| w == b"none")
        );
        // The vault passkey signs with the key whose public part the page
        // received.
        let passkey = conditional_passkey(&ConditionalPasskey {
            item: "github",
            rp_id: "GitHub.com",
            user_id: b"u-42",
            user_name: Some("camille"),
            credential_id: &prepared.credential_id,
            private_key: prepared.private_key.expose(),
            created: 1_700_000_000,
        })
        .unwrap();
        assert_eq!(passkey.rp_id, "github.com");
        assert_eq!(passkey.raw_id().unwrap(), prepared.credential_id);
        assert_eq!(passkey.counter, 0);
        let assertion = assert_for_system(&passkey, "github.com", &hash, true).unwrap();
        let mut message = assertion.authenticator_data.clone();
        message.extend_from_slice(&hash);
        let key = VerifyingKey::from_public_key_der(&registration.public_key).unwrap();
        key.verify(
            &message,
            &DerSignature::try_from(assertion.signature.as_slice()).unwrap(),
        )
        .expect("signature of the prepared key");
        // Refused inputs.
        assert!(
            conditional_registration(
                "co.uk",
                &prepared.credential_id,
                &prepared.public_key,
                &hash
            )
            .is_err()
        );
        assert!(
            conditional_registration("github.com", &prepared.credential_id, &[4; 65], &hash)
                .is_err()
        );
        assert!(
            conditional_registration(
                "github.com",
                &prepared.credential_id,
                &prepared.public_key,
                &[1; 8]
            )
            .is_err()
        );
        assert!(
            conditional_passkey(&ConditionalPasskey {
                private_key: "pas une clé",
                ..ConditionalPasskey {
                    item: "x",
                    rp_id: "github.com",
                    user_id: b"u",
                    user_name: None,
                    credential_id: &prepared.credential_id,
                    private_key: "",
                    created: 0,
                }
            })
            .is_err()
        );
    }
}
