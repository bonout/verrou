//! Messages exchanged with the bridge's clients (extension, terminal).
//!
//! In clear, the envelope: a pairing request, or an encrypted request from a
//! paired client. Encrypted, the command and its response.

use serde::{Deserialize, Serialize};
use verrou_core::{FieldKind, ItemKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum size of a message (Native Messaging limits what the host sends
/// back to the browser to 1 MiB).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Tolerated gap between a request's timestamp and Verrou's clock.
pub const MAX_CLOCK_SKEW_MS: i64 = 120_000;

/// A client's kind: it sets the commands it can send
/// ([`crate::access::allowed`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// The browser extension: the logins for the current page.
    #[default]
    Browser,
    /// The terminal (`verrou`): search, secrets after confirmation, SSH agent.
    Cli,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Incoming {
    /// `key`: the client's P-256 public key (SEC1, base64). `kind` missing:
    /// the extension, which does not send it.
    Pair {
        name: String,
        key: String,
        #[serde(default)]
        kind: ClientKind,
    },
    Request {
        client: String,
        iv: String,
        data: String,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outgoing {
    /// Verrou's public key and the assigned identifier: the extension can
    /// compute the channel key and show the code while awaiting approval.
    Pairing {
        client: String,
        key: String,
    },
    Paired,
    Refused,
    Response {
        iv: String,
        data: String,
    },
    Error {
        code: ErrorCode,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Unknown or revoked client: it must pair again.
    UnknownClient,
    /// Malformed, unreadable or stale message.
    BadRequest,
    /// A pairing is already in progress, or too close to the previous one.
    Busy,
}

/// Decrypted request.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    /// Unix timestamp in milliseconds.
    pub ts: i64,
    /// Why the terminal asks (`verrou --reason`, `VERROU_REASON`): shown in
    /// the approval, as declared by the client, never checked
    /// ([`clean_reason`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub command: Command,
}

/// Longest reason shown, in characters.
pub const MAX_REASON: usize = 120;

/// The reason as shown: one line, no control characters, at most
/// [`MAX_REASON`] characters.
pub fn clean_reason(reason: Option<&str>) -> String {
    let flat: String = reason
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() <= MAX_REASON {
        trimmed
    } else {
        format!(
            "{}…",
            trimmed.chars().take(MAX_REASON - 1).collect::<String>()
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Status,
    /// Logins suggested for the page `url`.
    Suggest {
        url: String,
    },
    /// Username, password and code of the item `item`, if it matches
    /// the page `url`.
    Fill {
        url: String,
        item: String,
    },
    /// Brings Verrou to the foreground to unlock it.
    Unlock,
    /// Login typed on the page `url`: already in the vault, new,
    /// or a new password for an item? `current`: the old password
    /// of a change form.
    Check {
        url: String,
        username: String,
        password: String,
        #[serde(default)]
        current: Option<String>,
    },
    /// Saves the page's login: `item` missing, a new
    /// item; otherwise the new password of that item.
    Save {
        url: String,
        username: String,
        password: String,
        #[serde(default)]
        item: Option<String>,
    },
    /// Adds the TOTP seed (or the `otpauth://` URI of a QR code) to
    /// the page's item `item`, or to a new item.
    SetTotp {
        url: String,
        totp: String,
        #[serde(default)]
        item: Option<String>,
    },
    /// Terminal: items matching `query`, without secrets.
    VaultSearch {
        query: String,
        #[serde(default)]
        kind: Option<ItemKind>,
        #[serde(default)]
        favorites: bool,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Terminal: one item (identifier, otherwise the best search
    /// result), without the value of its secret fields.
    VaultItem {
        query: String,
    },
    /// Terminal: the value of a field (`notes` included) of the item `item`.
    /// A secret field requires the user's approval in Verrou.
    Reveal {
        item: String,
        field: String,
    },
    /// Terminal: the one-time code of the item `item`, with approval.
    Totp {
        item: String,
    },
    /// Terminal: forget this client (`verrou unlink`).
    Unlink,
    /// SSH agent: the public keys of the vault's SSH keys.
    SshKeys,
    /// SSH agent: sign `data` (base64) with the key whose SSH binary form is
    /// `public_key` (base64). `flags`: those of the OpenSSH agent
    /// (`rsa-sha2-256` = 2, `rsa-sha2-512` = 4). The private key does not leave
    /// Verrou: only the signature comes back.
    SshSign {
        public_key: String,
        data: String,
        #[serde(default)]
        flags: u32,
    },
    /// Cards and identities suggested for a payment or address form
    /// on the page `url` (titles and masked subtitles only).
    Forms {
        url: String,
    },
    /// The fields of the card or identity `item`, for the page `url`.
    FillForm {
        url: String,
        item: String,
    },
    /// Search among logins (title and displayed username, no
    /// secret), to link one to a site that has none.
    SearchLogins {
        query: String,
    },
    /// Adds the site of the page `url` to the login `item` (chosen by
    /// the user in the extension's popup): it then matches it,
    /// and fills like the others.
    LinkSite {
        url: String,
        item: String,
    },
    /// Passkeys: see [`crate::passkeys`].
    PasskeyList(PasskeyQuery),
    PasskeyGet(PasskeyUse),
    PasskeyTargets(PasskeyTargetsQuery),
    PasskeyCreate(Box<PasskeyCreation>),
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    #[serde(flatten)]
    pub result: ReplyResult,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReplyResult {
    Status {
        unlocked: bool,
        /// Version of the extension shipped with Verrou (the `manifest.json` of
        /// the app bundle): the extension reloads if it differs from its
        /// own. Missing: unknown (tests, another client).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extension_version: Option<String>,
    },
    Suggestions {
        items: Vec<Suggestion>,
    },
    Credentials(Credentials),
    Locked,
    Denied {
        reason: String,
    },
    Done,
    Check {
        action: SaveAction,
        /// The item concerned, for `known` and `update`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item: Option<Suggestion>,
    },
    /// Written to the vault: the identifier of the created or modified item.
    Saved {
        item: String,
    },
    /// Protected item ("master password re-prompt"): Verrou
    /// asks for confirmation; the extension then retries.
    Confirm,
    /// Results of a terminal search: the first ones, and their total.
    Items {
        items: Vec<ItemSummary>,
        total: u32,
    },
    Item {
        item: ItemView,
    },
    /// Value of a field, revealed with the user's approval.
    Secret(SecretValue),
    Code {
        code: String,
        period: u64,
        remaining: u64,
    },
    SshKeys {
        keys: Vec<SshIdentity>,
    },
    Forms {
        cards: Vec<FormSuggestion>,
        identities: Vec<FormSuggestion>,
    },
    Form(Box<FormData>),
    /// Signature in the SSH agent's format (algorithm and signature), base64.
    Signature {
        signature: String,
    },
    Passkeys {
        items: Vec<PasskeySuggestion>,
    },
    PasskeyTargets {
        /// A passkey from `exclude` is already in the vault.
        excluded: bool,
        logins: Vec<PasskeyTarget>,
    },
    Assertion(PasskeyAssertion),
    Registration(PasskeyRegistration),
}

/// An item in a terminal list. No secrets.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
    /// Shared vault: "Organization › Collection, …". Missing for a
    /// personal item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<String>,
}

/// An item for `verrou get`: the value of secret fields is missing.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ItemView {
    #[serde(flatten)]
    pub summary: ItemSummary,
    pub fields: Vec<FieldView>,
    pub has_notes: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub secret: bool,
    /// Missing for a secret field: `reveal` is needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    pub value: String,
}

/// An SSH key of the vault, as the agent sees it: its public key only.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SshIdentity {
    pub item: String,
    pub title: String,
    /// SSH binary form of the public key, base64.
    pub public_key: String,
}

/// Special refusal from [`crate::Backend::credentials`]: the item awaits a
/// confirmation in Verrou (sent back to the extension as [`ReplyResult::Confirm`]).
pub const CONFIRM_IN_APP: &str = "confirmation required in Verrou";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SaveAction {
    /// Already in the vault, identical: nothing to offer.
    Known,
    New,
    Update,
}

/// What the extension's menu shows. No secrets.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Suggestion {
    pub id: String,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

/// A card or identity suggested in the menu: no secrets
/// ("Visa •••• 4242", the identity's email).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FormSuggestion {
    pub id: String,
    pub title: String,
    pub subtitle: String,
}

/// The fields of a card (`kind` = `card`) or an identity (`identity`),
/// at fill time. Missing: empty in the vault.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FormData {
    pub kind: String,
    // Card
    pub cardholder: Option<String>,
    /// Digits only.
    pub number: Option<String>,
    /// `MM`.
    pub exp_month: Option<String>,
    /// `YYYY`.
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    // Identity
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub full_name: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Current one-time code, if there is a seed.
    pub totp: Option<String>,
}

// MARK: Passkeys
//
// Bytes in base64url, like `PublicKeyCredential.toJSON()`. The address
// (`url`) is the one the browser assigns to the page; the rest comes from
// the page (options of `navigator.credentials`).

/// The vault's passkeys for the site: all discoverable ones, or those in
/// `allow` (credential identifiers).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyQuery {
    pub url: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Sign `challenge` with the passkey `credential` of the item `item`.
/// `uv`: the site asks for user verification (Touch ID).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyUse {
    pub url: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    pub item: String,
    pub credential: String,
    pub challenge: String,
    #[serde(default)]
    pub uv: bool,
    /// PRF extension requested by the page (`extensions.prf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfRequest>,
}

/// Where to save a new passkey: the site's logins, and whether
/// one of the `exclude` passkeys is already there.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyTargetsQuery {
    pub url: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Create a passkey (`navigator.credentials.create`) and save it in
/// the login `item`, or in a new login.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyCreation {
    pub url: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_name: Option<String>,
    pub user_id: String,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
    pub challenge: String,
    /// COSE algorithms accepted by the site (`pubKeyCredParams`).
    #[serde(default)]
    pub algorithms: Vec<i64>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub uv: bool,
    /// `none`, `indirect`, `direct` or `enterprise`.
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub item: Option<String>,
    /// PRF extension requested at creation (`eval` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfRequest>,
}

/// Inputs of the PRF extension (`AuthenticationExtensionsPRFValues`), raw,
/// in base64url: Verrou hashes them (`"WebAuthn PRF" ‖ 0 ‖ input`) like a
/// browser before the key (see `verrou_core::passkey_prf`).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrfValues {
    pub first: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// The page's `extensions.prf`: `eval`, and for a sign-in,
/// `evalByCredential` (identifier in base64url → inputs).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrfRequest {
    #[serde(default)]
    pub eval: Option<PrfValues>,
    #[serde(default)]
    pub eval_by_credential: std::collections::BTreeMap<String, PrfValues>,
}

/// Creation result: the passkey can evaluate the PRF (`enabled`), and
/// the outputs if the page gave `eval`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrfCreated {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfValues>,
}

/// A passkey suggested in the page. No secrets.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeySuggestion {
    pub item: String,
    pub title: String,
    pub credential: String,
    pub user_name: String,
}

/// A login of the site that can receive the passkey.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyTarget {
    pub id: String,
    pub title: String,
    pub username: String,
    /// It already has one: it would be replaced.
    pub has_passkey: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyAssertion {
    pub credential: String,
    pub client_data: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
    /// PRF outputs (base64url), if the page requested it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfValues>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasskeyRegistration {
    pub item: String,
    pub credential: String,
    pub client_data: String,
    pub authenticator_data: String,
    pub attestation_object: String,
    /// `SubjectPublicKeyInfo` (DER) of the public key.
    pub public_key: String,
    pub algorithm: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfCreated>,
}

#[cfg(test)]
mod reason_tests {
    use super::*;

    #[test]
    fn reason_is_one_short_line() {
        assert_eq!(clean_reason(None), "");
        assert_eq!(
            clean_reason(Some("  deploy\n\tto  prod\u{7} ")),
            "deploy to prod"
        );
        let long = "x".repeat(300);
        let cleaned = clean_reason(Some(&long));
        assert_eq!(cleaned.chars().count(), MAX_REASON);
        assert!(cleaned.ends_with('…'));
    }

    #[test]
    fn requests_without_a_reason_still_parse() {
        let request: Request = serde_json::from_str(r#"{"id":1,"ts":0,"cmd":"status"}"#).unwrap();
        assert_eq!(request.reason, None);
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("reason"));
    }
}
