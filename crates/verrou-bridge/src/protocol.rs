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

/// The bridge applies [`Request::approval_scope`] (advertised in the status).
pub const CAPABILITY_APPROVAL_SCOPE: &str = "approval_scope";

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
    /// An agent's request (`verrou mcp`): this approval is asked for this
    /// request alone. The server neither reuses an approval given earlier
    /// to the same client (a `verrou run` approved a minute ago must not
    /// cover whatever else the agent asks) nor remembers this one.
    /// Additive: absent means the usual five minutes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ephemeral_approval: bool,
    /// What the secrets are for: the command line and the fields it gets,
    /// shown in the approval apart from the reason, because the command is
    /// what actually decides what happens to the values ([`RunDetail`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<RunDetail>,
    /// Added to the key of the five-minute approval: a request that carries
    /// one is approved, and remembered, apart from the ordinary approval of
    /// the same item (`verrou get`, `verrou run`), and never covered by it.
    /// It is only ever a key, never shown. Additive: absent means the
    /// item's ordinary approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_scope: Option<String>,
    #[serde(flatten)]
    pub command: Command,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // the signature serde wants
fn is_false(value: &bool) -> bool {
    !*value
}

/// The command an agent wants to run with secrets, and the secret fields it
/// will receive ("GitHub › Password"), for the approval. Cleaned by the
/// bridge, whatever the client sent ([`RunDetail::cleaned`]).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunDetail {
    pub command: String,
    pub fields: Vec<String>,
}

/// Longest command line shown, in characters (as rendered, [`visible`]).
pub const MAX_COMMAND: usize = 200;
/// Most fields listed, and the longest one.
const MAX_FIELDS: usize = 10;
const MAX_FIELD: usize = 100;

impl RunDetail {
    /// As shown: the command with its control and invisible characters made
    /// visible ([`visible`]), at most [`MAX_COMMAND`] characters; the fields
    /// on one line each, without control or format characters.
    #[must_use]
    pub fn cleaned(&self) -> Self {
        let mut fields: Vec<String> = self
            .fields
            .iter()
            .take(MAX_FIELDS)
            .map(|f| truncate(&flatten(f), MAX_FIELD))
            .collect();
        if self.fields.len() > MAX_FIELDS {
            fields.push("…".to_owned());
        }
        Self {
            command: truncate(&visible(&self.command), MAX_COMMAND),
            fields,
        }
    }

    /// Can the approval show all of it? One that shows half a command line,
    /// or the first ten of twelve fields, approves the rest blind.
    pub fn check(&self) -> Result<(), &'static str> {
        if visible(&self.command).chars().count() > MAX_COMMAND {
            return Err(COMMAND_TOO_LONG);
        }
        if self.fields.len() > MAX_FIELDS
            || self
                .fields
                .iter()
                .any(|f| flatten(f).chars().count() > MAX_FIELD)
        {
            return Err(FIELDS_TOO_LONG);
        }
        Ok(())
    }

    /// [`Self::check`] as a yes or no.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.check().is_ok()
    }

    /// The fields as one line.
    #[must_use]
    pub fn fields_line(&self) -> String {
        self.fields.join(", ")
    }
}

/// Why an agent's command line is refused: it does not fit in the
/// approval. The agent is told what to do about it.
pub const COMMAND_TOO_LONG: &str = "the command line is too long to be shown whole in the approval (at most 200 characters): write it to a script file the user can read, and run that file";

/// Likewise for the list of secrets the command gets.
pub const FIELDS_TOO_LONG: &str = "too many secrets, or names too long, to be shown whole in the approval (at most 10, of at most 100 characters each): ask for fewer, or use shorter item and field names";

/// The program and arguments as one line a person can read: an argument
/// with a space or a quote is single-quoted, as a shell would need it.
#[must_use]
pub fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_alphanumeric() || "_-./:=@%+,".contains(c));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Characters that can reorder, hide or imitate what an approval says:
/// control characters (`Cc`), invisible formatting (`Cf`: bidirectional
/// overrides and isolates, zero-width characters, the byte order mark…) and
/// the default-ignorable code points (variation selectors, the Hangul
/// fillers…), straight from the Unicode data.
fn is_invisible(c: char) -> bool {
    use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory};
    use icu_properties::{CodePointMapData, CodePointSetData};
    CodePointMapData::<GeneralCategory>::new().get(c) == GeneralCategory::Format
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
}

/// One line: control characters become spaces, invisible ones vanish,
/// runs of white space shrink to one space. For text that is read, not run:
/// titles, reasons, field names.
fn flatten(text: &str) -> String {
    let spaced: String = text
        .chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A command line as it is shown, character for character: nothing is
/// dropped or merged, and what could pass unseen is spelled out. A line
/// break reads `⏎`, a tab `⇥`, any other control, invisible or unusual
/// white space character `\u{…}`.
#[must_use]
pub fn visible(text: &str) -> String {
    use std::fmt::Write as _;
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => shown.push('⏎'),
            '\r' => shown.push('␍'),
            '\t' => shown.push('⇥'),
            ' ' => shown.push(' '),
            c if c.is_control() || c.is_whitespace() || is_invisible(c) => {
                let _ = write!(shown, "\\u{{{:x}}}", u32::from(c));
            }
            c => shown.push(c),
        }
    }
    shown
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

/// What the terminal reads after an unlock: the item as it asked for it
/// (a title or an identifier: the locked vault can't name it), and the
/// field (`password`, `totp`…).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnlockIntent {
    pub item: String,
    pub field: String,
}

impl UnlockIntent {
    /// As shown: one short line each.
    #[must_use]
    pub fn cleaned(&self) -> Self {
        Self {
            item: clean_reason(Some(&self.item)),
            field: clean_reason(Some(&self.field)),
        }
    }
}

/// Longest reason shown, in characters.
pub const MAX_REASON: usize = 120;

/// The reason as shown: one line, no control or invisible formatting
/// characters, at most [`MAX_REASON`] characters.
pub fn clean_reason(reason: Option<&str>) -> String {
    truncate(&flatten(reason.unwrap_or_default()), MAX_REASON)
}

/// An item title, folder, client name or list of changed fields as an
/// approval shows it: one line, without control or invisible formatting
/// characters ([`clean_reason`]'s rules), at most `max` characters. These
/// come from the vault, or from what a client declared: a title made of a
/// bidirectional override is a title that reads as another.
#[must_use]
pub fn clean_text(text: &str, max: usize) -> String {
    truncate(&flatten(text), max)
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
    /// Brings Verrou to the foreground to unlock it (the terminal: asks
    /// the paired iPhone when the user is away).
    Unlock {
        /// Terminal: what it will read once unlocked. Shown in the iPhone's
        /// request, whose approval then also covers that item, once
        /// ([`UnlockIntent`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        then: Option<UnlockIntent>,
    },
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
    /// Terminal: a new item in the personal vault (`verrou item create`),
    /// with the user's approval.
    ItemCreate {
        changes: ItemChanges,
    },
    /// Terminal: changes to the item `item` (an identifier), with the
    /// user's approval.
    ItemEdit {
        item: String,
        changes: ItemChanges,
    },
    /// Terminal: move the item `item` (identifier or title) to the trash,
    /// to the archive, or back, with the user's approval.
    ItemMove {
        item: String,
        to: ItemMove,
    },
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

/// What the terminal writes to an item. A missing value leaves it as is.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ItemChanges {
    /// Creation only: login (by default), secure note, card or identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ItemKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The login's sites: they replace the item's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    /// A folder's name; empty: out of any folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// Fields set or removed, in order ([`crate::access::field_target`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldChange>,
}

/// `name=value`: one of the item's own fields (`password`, `number`…,
/// `notes`), otherwise a custom field, by its name.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FieldChange {
    pub name: String,
    /// `None`: the field is removed.
    pub value: Option<String>,
    /// A new custom field: hidden (`name[password]=…`) or not.
    #[serde(default)]
    pub hidden: bool,
}

/// The value stays out of logs and error messages.
impl std::fmt::Debug for FieldChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldChange")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "••••"))
            .field("hidden", &self.hidden)
            .finish()
    }
}

/// Where `ItemMove` takes an item.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemMove {
    /// The trash (restorable 30 days).
    Trash,
    Archive,
    /// Out of the trash or of the archive.
    Restore,
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
        /// What this bridge does beyond the base protocol, by name: a client
        /// that needs one checks for it before relying on it (an older
        /// bridge ignores what it does not know and says nothing).
        /// [`CAPABILITY_APPROVAL_SCOPE`]: it keeps an approval apart by
        /// [`Request::approval_scope`]. Additive: absent means none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
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

impl ReplyResult {
    /// The kind of reply, for a message: never its content (a secret, a
    /// one-time code, a card), which has no business in an error.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Suggestions { .. } => "suggestions",
            Self::Credentials(_) => "credentials",
            Self::Locked => "locked",
            Self::Denied { .. } => "denied",
            Self::Done => "done",
            Self::Check { .. } => "check",
            Self::Saved { .. } => "saved",
            Self::Confirm => "confirm",
            Self::Items { .. } => "items",
            Self::Item { .. } => "item",
            Self::Secret(_) => "secret",
            Self::Code { .. } => "code",
            Self::SshKeys { .. } => "ssh_keys",
            Self::Forms { .. } => "forms",
            Self::Form(_) => "form",
            Self::Signature { .. } => "signature",
            Self::Passkeys { .. } => "passkeys",
            Self::PasskeyTargets { .. } => "passkey_targets",
            Self::Assertion(_) => "assertion",
            Self::Registration(_) => "registration",
        }
    }
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

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    pub value: String,
}

/// The value stays out of logs, panics and error messages.
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("value", &"••••")
            .finish()
    }
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
#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Current one-time code, if there is a seed.
    pub totp: Option<String>,
}

/// Nothing of the values: they stay out of logs, panics and error messages.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username.as_ref().map(|_| "••••"))
            .field("password", &self.password.as_ref().map(|_| "••••"))
            .field("totp", &self.totp.as_ref().map(|_| "••••"))
            .finish()
    }
}

/// Nothing of the values (names, numbers, addresses).
impl std::fmt::Debug for FormData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormData")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
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
    fn invisible_formatting_characters_are_dropped() {
        // Bidirectional overrides and isolates, zero-width characters, the
        // byte order mark: they can reorder or hide what an approval says.
        let tricky = "deploy \u{202E}evil\u{202C} to\u{200B} prod\u{2066}\u{FEFF}";
        assert_eq!(clean_reason(Some(tricky)), "deploy evil to prod");
        let detail = RunDetail {
            command: "cat \u{202E}\u{2069}x\n\ty".to_owned(),
            fields: vec!["A\u{200D} › B".to_owned()],
        }
        .cleaned();
        // A command shows what it holds: nothing dropped, nothing merged.
        assert_eq!(detail.command, "cat \\u{202e}\\u{2069}x⏎⇥y");
        assert_eq!(detail.fields, ["A › B"]);
    }

    #[test]
    fn a_run_detail_is_shown_cleaned_and_short() {
        let detail = RunDetail {
            command: "x".repeat(500),
            fields: (0..30)
                .map(|i| format!("Item {i} › {}", "y".repeat(100)))
                .collect(),
        }
        .cleaned();
        assert_eq!(detail.command.chars().count(), MAX_COMMAND);
        assert!(detail.command.ends_with('…'));
        assert_eq!(detail.fields.len(), MAX_FIELDS + 1);
        assert_eq!(detail.fields[MAX_FIELDS], "…");
        assert!(detail.fields[0].chars().count() <= MAX_FIELD);
    }

    #[test]
    fn a_command_line_is_quoted_as_a_shell_would_need_it() {
        let line =
            |args: &[&str]| command_line(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>());
        assert_eq!(line(&["cargo", "test", "-p", "x"]), "cargo test -p x");
        assert_eq!(
            line(&["sh", "-c", "echo $T; cat .env"]),
            "sh -c 'echo $T; cat .env'"
        );
        assert_eq!(line(&["echo", "it's"]), "echo 'it'\\''s'");
        assert_eq!(line(&["a", ""]), "a ''");
    }

    #[test]
    fn requests_from_an_agent_travel_additively() {
        let request: Request = serde_json::from_str(
            r#"{"id":1,"ts":0,"cmd":"status","ephemeral_approval":true,"detail":{"command":"ls","fields":["A › B"]}}"#,
        )
        .unwrap();
        assert!(request.ephemeral_approval);
        assert_eq!(request.detail.as_ref().unwrap().command, "ls");
        // Older terminals send neither, and the flag is not written when off.
        let plain: Request = serde_json::from_str(r#"{"id":1,"ts":0,"cmd":"status"}"#).unwrap();
        assert!(!plain.ephemeral_approval && plain.detail.is_none());
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("ephemeral") && !json.contains("detail"));
        assert!(plain.approval_scope.is_none() && !json.contains("approval_scope"));
        let scoped: Request = serde_json::from_str(
            r#"{"id":1,"ts":0,"cmd":"status","approval_scope":"env:/a/.env:/bin/cat:none"}"#,
        )
        .unwrap();
        assert_eq!(
            scoped.approval_scope.as_deref(),
            Some("env:/a/.env:/bin/cat:none")
        );
    }

    #[test]
    fn the_status_says_what_the_bridge_can_do_and_an_older_one_says_nothing() {
        let status = ReplyResult::Status {
            unlocked: true,
            extension_version: None,
            capabilities: vec![CAPABILITY_APPROVAL_SCOPE.to_owned()],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(
            json.contains(r#""capabilities":["approval_scope"]"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<ReplyResult>(&json).unwrap(), status);
        // A bridge that has none writes nothing; one that predates the field
        // is read as having none.
        let none = ReplyResult::Status {
            unlocked: true,
            extension_version: None,
            capabilities: Vec::new(),
        };
        assert!(
            !serde_json::to_string(&none)
                .unwrap()
                .contains("capabilities")
        );
        let old: ReplyResult =
            serde_json::from_str(r#"{"result":"status","unlocked":false}"#).unwrap();
        assert_eq!(
            old,
            ReplyResult::Status {
                unlocked: false,
                extension_version: None,
                capabilities: Vec::new()
            }
        );
    }

    #[test]
    fn requests_without_a_reason_still_parse() {
        let request: Request = serde_json::from_str(r#"{"id":1,"ts":0,"cmd":"status"}"#).unwrap();
        assert_eq!(request.reason, None);
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("reason"));
    }

    #[test]
    fn invisible_characters_come_from_the_unicode_data() {
        // Cf and default-ignorable code points the old table did not name:
        // the Arabic number sign U+0890, the interlinear annotation anchors,
        // variation selectors, the Hangul fillers, Mongolian free variation
        // selectors, the tag block, the shorthand format controls.
        for c in [
            '\u{200B}',
            '\u{202E}',
            '\u{2066}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{0890}',
            '\u{FFF9}',
            '\u{FE0F}',
            '\u{E0100}',
            '\u{3164}',
            '\u{115F}',
            '\u{FFA0}',
            '\u{180B}',
            '\u{E0041}',
            '\u{1BCA0}',
            '\u{1D173}',
            '\u{034F}',
            '\u{2062}',
        ] {
            assert!(
                is_invisible(c),
                "U+{:04X} should be invisible",
                u32::from(c)
            );
            assert_eq!(clean_reason(Some(&format!("a{c}b"))), "ab");
        }
        for c in [
            'a', ' ', 'é', '漢', '🔒', '-', '›', '…', '\u{00A0}', '\u{0301}',
        ] {
            assert!(!is_invisible(c), "U+{:04X} is visible", u32::from(c));
        }
        // Titles are cleaned the same way.
        let tricky = "Git\u{202E}Hub\u{200B}\n";
        assert_eq!(clean_reason(Some(tricky)), "GitHub");
    }

    #[test]
    fn a_command_shows_everything_it_holds() {
        assert_eq!(visible("ls -la"), "ls -la");
        assert_eq!(visible("a\nb\r\nc\td"), "a⏎b␍⏎c⇥d");
        assert_eq!(visible("x\u{7}y\u{0}"), "x\\u{7}y\\u{0}");
        // Unusual white space does not pass for a space.
        assert_eq!(
            visible("a\u{00A0}b\u{3000}c\u{2028}d"),
            "a\\u{a0}b\\u{3000}c\\u{2028}d"
        );
        // Nothing merged: two spaces stay two.
        assert_eq!(visible("a  b"), "a  b");
        assert_eq!(visible("évite 漢"), "évite 漢");
        // Lines of a script are not one: `echo hi⏎rm -rf x`.
        let detail = RunDetail {
            command: "sh -c 'echo hi\nrm x'".to_owned(),
            fields: vec![],
        };
        assert_eq!(detail.cleaned().command, "sh -c 'echo hi⏎rm x'");
    }

    #[test]
    fn what_the_approval_cannot_show_whole_is_refused() {
        let detail = |command: String, fields: Vec<String>| RunDetail { command, fields };
        assert!(detail("x".repeat(MAX_COMMAND), vec![]).fits());
        assert_eq!(
            detail("x".repeat(MAX_COMMAND + 1), vec![]).check(),
            Err(COMMAND_TOO_LONG)
        );
        // Measured as shown: each line break is one character, but an
        // invisible one spells out as six.
        assert!(detail("\n".repeat(MAX_COMMAND), vec![]).fits());
        assert!(!detail("\u{200B}".repeat(MAX_COMMAND / 2), vec![]).fits());
        let ten: Vec<String> = (0..MAX_FIELDS).map(|i| format!("F{i}")).collect();
        assert!(detail("ls".to_owned(), ten.clone()).fits());
        let mut eleven = ten;
        eleven.push("F10".to_owned());
        assert_eq!(
            detail("ls".to_owned(), eleven).check(),
            Err(FIELDS_TOO_LONG)
        );
        let long = vec!["y".repeat(MAX_FIELD + 1)];
        assert_eq!(detail("ls".to_owned(), long).check(), Err(FIELDS_TOO_LONG));
        assert!(COMMAND_TOO_LONG.contains("script file"));
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let secret = SecretValue {
            value: "hunter2-very-secret".to_owned(),
        };
        let reply = Reply {
            id: 1,
            result: ReplyResult::Secret(secret.clone()),
        };
        for shown in [
            format!("{secret:?}"),
            format!("{reply:?}"),
            format!("{secret:#?}"),
        ] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("••••"), "{shown}");
        }
        let credentials = Credentials {
            username: Some("camille-user".to_owned()),
            password: Some("pw-in-clear".to_owned()),
            totp: Some("123456".to_owned()),
        };
        let shown = format!("{:?}", ReplyResult::Credentials(credentials));
        assert!(
            !shown.contains("pw-in-clear") && !shown.contains("123456"),
            "{shown}"
        );
        assert!(!shown.contains("camille-user"), "{shown}");
        let mut form = FormData::default();
        "card".clone_into(&mut form.kind);
        form.number = Some("4242424242424242".to_owned());
        assert!(!format!("{form:?}").contains("4242"));
        // The kind of a reply, for messages, never its content.
        assert_eq!(reply.result.kind(), "secret");
        assert_eq!(
            ReplyResult::Code {
                code: "654321".to_owned(),
                period: 30,
                remaining: 3
            }
            .kind(),
            "code"
        );
    }
}
