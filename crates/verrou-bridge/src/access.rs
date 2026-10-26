//! What each client is allowed to get from the vault.
//!
//! **Commands**: each kind of client has its own ([`allowed`]);
//! the extension cannot search the vault, the terminal cannot
//! fill a page.
//!
//! **Extension**: a password only leaves for a login that
//! matches the requested page (same registrable domain, like
//! Bitwarden), and only towards an HTTPS page. The page's address
//! is asserted by the extension: against a stolen pairing key, the
//! bridge server asks for the user's approval beyond a few
//! items in a short time, for each card and for each site added to
//! a login (`server.rs`). Writing follows the same rule: the extension
//! only saves a login, or modifies one, for the page's
//! site, after a click by the user in Verrou's banner.
//!
//! **Terminal**: it searches the whole vault, but results and
//! items carry no secret ([`item_view`]). A secret (concealed
//! field, notes, one-time code) and each SSH signature require
//! the user's approval in Verrou ([`field_needs_confirmation`]), kept
//! a few minutes for this item and this client only.

use url::Url;
use verrou_core::matching::host_of;
use verrou_core::totp::Totp;
use verrou_core::{FieldKind, Filter, Item, ItemKind, SecretString, Sort, Vault};

use crate::protocol::{
    ClientKind, Command, Credentials, FieldView, FormData, FormSuggestion, ItemSummary, ItemView,
    SaveAction, Suggestion,
};

/// Maximum number of results returned by a terminal search.
const MAX_RESULTS: usize = 200;

/// Is the command allowed for this client? The common commands: the status
/// and the unlock request.
pub fn allowed(kind: ClientKind, command: &Command) -> bool {
    match command {
        Command::Status | Command::Unlock { .. } => true,
        Command::Suggest { .. }
        | Command::Fill { .. }
        | Command::Check { .. }
        | Command::Save { .. }
        | Command::SetTotp { .. }
        | Command::Forms { .. }
        | Command::FillForm { .. }
        | Command::LinkSite { .. }
        | Command::SearchLogins { .. }
        | Command::PasskeyList(_)
        | Command::PasskeyGet(_)
        | Command::PasskeyTargets(_)
        | Command::PasskeyCreate(_) => kind == ClientKind::Browser,
        Command::VaultSearch { .. }
        | Command::VaultItem { .. }
        | Command::Reveal { .. }
        | Command::Totp { .. }
        | Command::Unlink
        | Command::ItemCreate { .. }
        | Command::ItemEdit { .. }
        | Command::ItemMove { .. }
        | Command::VaultOverview
        | Command::VaultList { .. }
        | Command::VaultDuplicates
        | Command::PlanPropose { .. }
        | Command::PlanStatus { .. }
        | Command::PlanCancel { .. }
        | Command::SshKeys
        | Command::SshSign { .. } => kind == ClientKind::Cli,
    }
}

// MARK: Terminal

fn item_summary(item: &Item) -> ItemSummary {
    ItemSummary {
        id: item.id.clone(),
        kind: item.kind,
        title: item.title.clone(),
        subtitle: item.subtitle.clone(),
        urls: item.urls.clone(),
        folder: item.folder.clone(),
        tags: item.tags.clone(),
        favorite: item.favorite,
        has_totp: item.has_totp(),
        shared: item.shared.as_ref().map(shared_label),
    }
}

/// "Organization › Collection, Collection" (or the organization alone).
pub fn shared_label(sharing: &verrou_core::Sharing) -> String {
    if sharing.collections.is_empty() {
        return sharing.organization.clone();
    }
    let collections: Vec<&str> = sharing
        .collections
        .iter()
        .map(|(_, name)| name.as_str())
        .collect();
    format!("{} › {}", sharing.organization, collections.join(", "))
}

/// Terminal search: the first `limit` results and their total.
pub fn search(
    vault: &Vault,
    query: &str,
    kind: Option<ItemKind>,
    favorites: bool,
    limit: Option<u32>,
) -> (Vec<ItemSummary>, usize) {
    let filter = match (kind, favorites) {
        (Some(kind), _) => Filter::Kind(kind),
        (None, true) => Filter::Favorites,
        (None, false) => Filter::All,
    };
    let hits = vault.search(query, &filter, Sort::Relevance);
    let limit = limit.map_or(MAX_RESULTS, |l| (l as usize).min(MAX_RESULTS));
    let items = hits
        .iter()
        .take(limit)
        .map(|hit| item_summary(&vault.items()[hit.index]))
        .collect();
    (items, hits.len())
}

/// The item with identifier `query`, otherwise the best search result.
pub fn find<'v>(vault: &'v Vault, query: &str) -> Result<&'v Item, String> {
    if let Some(item) = vault.get(query) {
        return Ok(item);
    }
    vault
        .search(query, &Filter::All, Sort::Relevance)
        .first()
        .map(|hit| &vault.items()[hit.index])
        .ok_or_else(|| format!("no item for \"{query}\""))
}

/// The item without the value of its secret fields or its notes.
pub fn item_view(item: &Item) -> ItemView {
    ItemView {
        summary: item_summary(item),
        fields: item
            .fields
            .iter()
            .map(|f| {
                let secret = f.kind.is_secret();
                FieldView {
                    id: f.id.clone(),
                    label: f.label.clone(),
                    kind: f.kind,
                    secret,
                    value: (!secret).then(|| f.value.expose().to_owned()),
                }
            })
            .collect(),
        has_notes: item.notes.is_some(),
    }
}

/// Does the item's field `field` (or `notes`) require the user's
/// approval? `Err`: item or field not found.
pub fn field_needs_confirmation(vault: &Vault, item_id: &str, field: &str) -> Result<bool, String> {
    let item = vault
        .get(item_id)
        .ok_or_else(|| "item not found".to_owned())?;
    if field == "notes" {
        return item
            .notes
            .as_ref()
            .map(|_| true)
            .ok_or_else(|| format!("\"{}\" has no notes", item.title));
    }
    match item.field(field) {
        Some(f) if item.hides(f) => Err(format!(
            "the organization of \"{}\" hides this field",
            item.title
        )),
        Some(f) => Ok(f.kind.is_secret()),
        None => Err(format!("\"{}\" has no field \"{field}\"", item.title)),
    }
}

/// The value of the item's field `field` (or of the notes).
pub fn field_value(vault: &Vault, item_id: &str, field: &str) -> Result<String, String> {
    let item = vault
        .get(item_id)
        .ok_or_else(|| "item not found".to_owned())?;
    if item.field(field).is_some_and(|f| item.hides(f)) {
        return Err(format!(
            "the organization of \"{}\" hides this field",
            item.title
        ));
    }
    let value = if field == "notes" {
        item.notes.as_ref().map(|n| n.expose().to_owned())
    } else {
        item.field(field).map(|f| f.value.expose().to_owned())
    };
    value.ok_or_else(|| format!("\"{}\" has no field \"{field}\"", item.title))
}

/// The current one-time code: code, period, seconds remaining.
pub fn totp_code(
    vault: &Vault,
    item_id: &str,
    unix_time: u64,
) -> Result<(String, u64, u64), String> {
    let item = vault
        .get(item_id)
        .ok_or_else(|| "item not found".to_owned())?;
    let field = item
        .field_of_kind(FieldKind::Totp)
        .ok_or_else(|| format!("\"{}\" has no one-time code", item.title))?;
    let code = Totp::parse(field.value.expose())
        .map_err(|e| e.to_string())?
        .generate(unix_time);
    Ok((code.code, code.period, code.remaining))
}

/// The item's title, for the approval request.
pub fn title_of(vault: &Vault, item_id: &str) -> Option<String> {
    vault.get(item_id).map(|i| i.title.clone())
}

// MARK: Extension

/// Maximum lengths accepted from a page.
const MAX_USERNAME: usize = 512;
const MAX_PASSWORD: usize = 1024;
const MAX_TOTP: usize = 2048;

/// HTTPS, or HTTP to the machine itself (development).
pub fn page_allowed(page_url: &str) -> bool {
    let Ok(url) = Url::parse(page_url) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

pub fn suggestions(vault: &Vault, page_url: &str) -> Vec<Suggestion> {
    if !page_allowed(page_url) {
        return Vec::new();
    }
    vault
        .suggestions_for(page_url)
        .into_iter()
        .map(suggestion)
        .collect()
}

fn suggestion(item: &Item) -> Suggestion {
    Suggestion {
        id: item.id.clone(),
        title: item.title.clone(),
        username: username_of(item).unwrap_or_default().to_owned(),
        has_totp: item.has_totp(),
    }
}

fn username_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose())
        .filter(|u| !u.is_empty())
}

fn password_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Password)
        .map(|f| f.value.expose())
}

/// The page's logins, only the login items.
pub(crate) fn logins_for<'v>(vault: &'v Vault, page_url: &str) -> Vec<&'v Item> {
    vault
        .suggestions_for(page_url)
        .into_iter()
        .filter(|item| item.kind == ItemKind::Login)
        .collect()
}

/// What the extension should offer after a form is submitted.
///
/// - Same username and same password: nothing (`Known`).
/// - Same username, other password: update.
/// - No username (two-step sign-in, password
///   change): the item whose password is the old one (`current`), or the
///   site's only login.
/// - Otherwise: a new item.
pub fn check_save(
    vault: &Vault,
    page_url: &str,
    username: &str,
    password: &str,
    current: Option<&str>,
) -> Result<(SaveAction, Option<Suggestion>), String> {
    check_input(page_url, username, password)?;
    let logins = logins_for(vault, page_url);
    let username = username.trim();
    let same_password = |item: &Item| password_of(item) == Some(password);
    let by_current = || {
        current.filter(|c| !c.is_empty()).and_then(|c| {
            logins
                .iter()
                .copied()
                .find(|item| password_of(item) == Some(c))
        })
    };
    let found = if username.is_empty() {
        logins
            .iter()
            .copied()
            .find(|item| same_password(item))
            .or_else(by_current)
            .or(if logins.len() == 1 {
                logins.first().copied()
            } else {
                None
            })
    } else {
        logins
            .iter()
            .copied()
            .find(|item| username_of(item).is_some_and(|u| u.eq_ignore_ascii_case(username)))
            .or_else(by_current)
    };
    Ok(match found {
        Some(item) if same_password(item) => (SaveAction::Known, Some(suggestion(item))),
        // Shared read-only: offer a new item instead.
        Some(item) if item.is_writable() => (SaveAction::Update, Some(suggestion(item))),
        _ => (SaveAction::New, None),
    })
}

fn check_input(page_url: &str, username: &str, password: &str) -> Result<(), String> {
    if !page_allowed(page_url) {
        return Err("insecure page (HTTPS required)".to_owned());
    }
    if password.is_empty() {
        return Err("empty password".to_owned());
    }
    if username.len() > MAX_USERNAME || password.len() > MAX_PASSWORD {
        return Err("username or password too long".to_owned());
    }
    Ok(())
}

/// A write requested by the extension, checked: the app only has to
/// carry it out.
#[derive(Debug)]
pub enum Write {
    Create {
        title: String,
        uri: String,
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
    },
    Update {
        item: String,
        /// Only if the item has none.
        username: Option<String>,
        password: Option<SecretString>,
        totp: Option<SecretString>,
        /// Site added to the item (`LinkSite`).
        uri: Option<String>,
    },
    /// Passkey created for the page ([`crate::passkeys::plan_creation`]):
    /// in the login `item`, or a new login (`title`, `uri`).
    Passkey {
        item: Option<String>,
        title: String,
        uri: String,
        username: Option<String>,
        passkey: Box<verrou_core::Passkey>,
    },
    /// New counter of a passkey, after an authentication.
    PasskeyCounter {
        item: String,
        credential_id: String,
        counter: u32,
    },
    /// The terminal: a new item ([`crate::items::plan_create`]).
    NewItem {
        changes: Box<crate::protocol::ItemChanges>,
    },
    /// The terminal: changes to the item ([`crate::items::plan_edit`]).
    EditItem {
        item: String,
        changes: Box<crate::protocol::ItemChanges>,
    },
    /// The terminal: the item to the trash, the archive, or back
    /// ([`crate::items::plan_move`]).
    MoveItem {
        item: String,
        to: crate::items::StateChange,
    },
}

/// The item `item` if it matches the page.
fn matching_login<'v>(vault: &'v Vault, page_url: &str, item: &str) -> Result<&'v Item, String> {
    logins_for(vault, page_url)
        .into_iter()
        .find(|i| i.id == item)
        .ok_or_else(|| "this login does not match this site".to_owned())
        .and_then(writable)
}

/// An item shared read-only is not written.
pub(crate) fn writable(item: &Item) -> Result<&Item, String> {
    if item.is_writable() {
        Ok(item)
    } else {
        Err(format!(
            "\"{}\" is shared read-only with this account",
            item.title
        ))
    }
}

/// Title and address of a new item for the page: the site, without a path.
pub(crate) fn new_site(page_url: &str) -> Result<(String, String), String> {
    let url = Url::parse(page_url).map_err(|_| "invalid page address".to_owned())?;
    let title = host_of(page_url).ok_or_else(|| "invalid page address".to_owned())?;
    Ok((title, url.origin().ascii_serialization()))
}

pub fn plan_save(
    vault: &Vault,
    page_url: &str,
    username: &str,
    password: &str,
    item: Option<&str>,
) -> Result<Write, String> {
    check_input(page_url, username, password)?;
    let username = username.trim();
    let username = (!username.is_empty()).then(|| username.to_owned());
    let password = Some(SecretString::new(password));
    if let Some(id) = item {
        let item = matching_login(vault, page_url, id)?;
        return Ok(Write::Update {
            item: item.id.clone(),
            username: username.filter(|_| username_of(item).is_none()),
            password,
            totp: None,
            uri: None,
        });
    }
    let (title, uri) = new_site(page_url)?;
    Ok(Write::Create {
        title,
        uri,
        username,
        password,
        totp: None,
    })
}

/// TOTP seed read on the page (QR code or pasted key).
pub fn plan_totp(
    vault: &Vault,
    page_url: &str,
    totp: &str,
    item: Option<&str>,
) -> Result<Write, String> {
    if !page_allowed(page_url) {
        return Err("insecure page (HTTPS required)".to_owned());
    }
    let totp = totp.trim();
    if totp.len() > MAX_TOTP {
        return Err("code too long".to_owned());
    }
    Totp::parse(totp).map_err(|e| e.to_string())?;
    let seed = Some(SecretString::new(totp));
    if let Some(id) = item {
        return Ok(Write::Update {
            item: matching_login(vault, page_url, id)?.id.clone(),
            username: None,
            password: None,
            totp: seed,
            uri: None,
        });
    }
    let (title, uri) = new_site(page_url)?;
    Ok(Write::Create {
        title,
        uri,
        username: otpauth_account(totp),
        password: None,
        totp: seed,
    })
}

/// The account announced by an `otpauth://totp/Issuer:account` URI.
fn otpauth_account(totp: &str) -> Option<String> {
    let url = Url::parse(totp).ok().filter(|u| u.scheme() == "otpauth")?;
    let label = url.path().trim_start_matches('/');
    let label = url::form_urlencoded::parse(format!("l={label}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())?;
    let account = label.rsplit(':').next()?.trim();
    (!account.is_empty()).then(|| account.to_owned())
}

/// Username, password and current code, if the item matches
/// the page. `Err`: the reason for the refusal, to display.
/// Does the item `item` require a confirmation before releasing its secrets?
pub fn needs_confirmation(vault: &Vault, item: &str) -> bool {
    vault.get(item).is_some_and(|i| i.reprompt)
}

pub fn credentials(
    vault: &Vault,
    item_id: &str,
    page_url: &str,
    unix_time: u64,
) -> Result<Credentials, String> {
    if !page_allowed(page_url) {
        return Err("insecure page (HTTPS required)".to_owned());
    }
    let item = vault
        .suggestions_for(page_url)
        .into_iter()
        .find(|item| item.id == item_id)
        .filter(|item| item.kind == ItemKind::Login)
        .ok_or_else(|| "this login does not match this site".to_owned())?;
    let value = |kind| {
        item.field_of_kind(kind)
            .map(|f| f.value.expose().to_owned())
    };
    let totp = value(FieldKind::Totp)
        .and_then(|seed| Totp::parse(&seed).ok())
        .map(|totp| totp.generate(unix_time).code);
    Ok(Credentials {
        username: value(FieldKind::Username).or_else(|| value(FieldKind::Email)),
        password: value(FieldKind::Password),
        totp,
    })
}

// MARK: Cards and identities

/// Active cards and identities, offered on a secure page; no secrets.
pub fn form_suggestions(
    vault: &Vault,
    page_url: &str,
) -> (Vec<FormSuggestion>, Vec<FormSuggestion>) {
    if !page_allowed(page_url) {
        return (Vec::new(), Vec::new());
    }
    let of_kind = |kind| {
        let mut list: Vec<FormSuggestion> = vault
            .items()
            .iter()
            .filter(|i| i.kind == kind && i.is_active())
            .map(|i| FormSuggestion {
                id: i.id.clone(),
                title: i.title.clone(),
                subtitle: i.subtitle.clone(),
            })
            .collect();
        list.sort_by_key(|s| s.title.to_lowercase());
        list
    };
    (of_kind(ItemKind::Card), of_kind(ItemKind::Identity))
}

/// The card or identity `item`, field by field, for the page `url`.
pub fn form_data(vault: &Vault, item_id: &str, page_url: &str) -> Result<FormData, String> {
    if !page_allowed(page_url) {
        return Err("insecure page (HTTPS required)".to_owned());
    }
    let item = vault
        .get(item_id)
        .filter(|i| i.is_active())
        .ok_or_else(|| "item not found".to_owned())?;
    let value = |id: &str| {
        item.field(id)
            .map(|f| f.value.expose().trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    match item.kind {
        ItemKind::Card => {
            let (exp_month, exp_year) = value("expiry")
                .and_then(|e| {
                    let (m, y) = e.split_once('/')?;
                    let y = y.trim();
                    let year = if y.len() == 2 {
                        format!("20{y}")
                    } else {
                        y.to_owned()
                    };
                    Some((format!("{:0>2}", m.trim()), year))
                })
                .unzip();
            // No `..Default::default()`: `FormData` is wiped when dropped.
            let mut data = FormData::default();
            "card".clone_into(&mut data.kind);
            data.cardholder = value("cardholder");
            data.number = value("number").map(|n| n.chars().filter(char::is_ascii_digit).collect());
            data.exp_month = exp_month;
            data.exp_year = exp_year;
            data.code = value("code");
            data.brand = value("brand");
            Ok(data)
        }
        ItemKind::Identity => {
            let first_name = value("first_name");
            let last_name = value("last_name");
            let full_name = [&first_name, &value("middle_name"), &last_name]
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let mut data = FormData::default();
            "identity".clone_into(&mut data.kind);
            data.first_name = first_name;
            data.last_name = last_name;
            data.full_name = (!full_name.is_empty()).then_some(full_name);
            data.company = value("company");
            data.email = value("email");
            data.phone = value("phone");
            data.address1 = value("part:address1");
            data.address2 = value("part:address2");
            data.postal_code = value("part:postal_code");
            data.city = value("part:city");
            data.state = value("part:state");
            data.country = value("part:country");
            Ok(data)
        }
        _ => Err("neither a card nor an identity".to_owned()),
    }
}

/// Logins matching `query` (20 at most), without secrets.
pub fn search_logins(vault: &Vault, query: &str) -> Vec<Suggestion> {
    vault
        .search(query, &Filter::Kind(ItemKind::Login), Sort::Relevance)
        .into_iter()
        .take(20)
        .map(|hit| suggestion(&vault.items()[hit.index]))
        .collect()
}

/// Add the page's site to the login `item`, chosen by
/// the user in the extension's popup.
pub fn plan_link_site(vault: &Vault, page_url: &str, item_id: &str) -> Result<Write, String> {
    if !page_allowed(page_url) {
        return Err("insecure page (HTTPS required)".to_owned());
    }
    let item = vault
        .get(item_id)
        .filter(|i| i.kind == ItemKind::Login && i.is_active())
        .ok_or_else(|| "login not found".to_owned())
        .and_then(writable)?;
    if logins_for(vault, page_url).iter().any(|i| i.id == item.id) {
        return Err("this login already matches this site".to_owned());
    }
    let (_, origin) = new_site(page_url)?;
    Ok(Write::Update {
        item: item.id.clone(),
        username: None,
        password: None,
        totp: None,
        uri: Some(origin),
    })
}

/// Carries out the write on an in-memory vault: for fake vaults (tests
/// and the extension's test server). The app itself writes to the server.
pub fn apply_in_memory(vault: &Vault, write: Write, new_id: &str) -> (Vault, String) {
    use verrou_core::Field;
    let mut items = vault.items().to_vec();
    let passkeys = vault.passkeys().to_vec();
    let set = |item: &mut Item, kind: FieldKind, id: &str, label: &str, value: Option<String>| {
        let Some(value) = value else { return };
        match item.fields.iter_mut().find(|f| f.kind == kind) {
            Some(field) => *field = Field::new(id, label, kind, value),
            None => item.fields.push(Field::new(id, label, kind, value)),
        }
    };
    let expose = |s: Option<SecretString>| s.map(|s| s.expose().to_owned());
    match write {
        Write::Create {
            title,
            uri,
            username,
            password,
            totp,
        } => {
            let mut item = Item {
                id: new_id.to_owned(),
                kind: ItemKind::Login,
                subtitle: username.clone().unwrap_or_default(),
                title,
                urls: vec![uri],
                url_matches: Vec::new(),
                folder: None,
                tags: Vec::new(),
                favorite: false,
                created: 0,
                modified: 0,
                fields: Vec::new(),
                notes: None,
                reprompt: false,
                state: verrou_core::ItemState::Active,
                shared: None,
            };
            set(
                &mut item,
                FieldKind::Username,
                "username",
                "Username",
                username,
            );
            set(
                &mut item,
                FieldKind::Password,
                "password",
                "Password",
                expose(password),
            );
            set(&mut item, FieldKind::Totp, "totp", "Code", expose(totp));
            items.push(item);
            (
                Vault::new(items)
                    .with_passkeys(passkeys)
                    .with_match_rules(vault.match_rules().clone()),
                new_id.to_owned(),
            )
        }
        Write::Update {
            item: id,
            username,
            password,
            totp,
            uri,
        } => {
            if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                item.urls.extend(uri);
                set(item, FieldKind::Username, "username", "Username", username);
                set(
                    item,
                    FieldKind::Password,
                    "password",
                    "Password",
                    expose(password),
                );
                set(item, FieldKind::Totp, "totp", "Code", expose(totp));
            }
            (
                Vault::new(items)
                    .with_passkeys(passkeys)
                    .with_match_rules(vault.match_rules().clone()),
                id,
            )
        }
        write @ (Write::Passkey { .. } | Write::PasskeyCounter { .. }) => {
            crate::passkeys::apply_in_memory(vault, write, new_id)
        }
        write @ (Write::NewItem { .. } | Write::EditItem { .. } | Write::MoveItem { .. }) => {
            crate::items::apply_in_memory(vault, write, new_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_core::{Field, Item};

    fn item(id: &str, url: &str) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: "camille".to_owned(),
            urls: vec![url.to_owned()],
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![
                Field::new("username", "Identifiant", FieldKind::Username, "camille"),
                Field::new("password", "Mot de passe", FieldKind::Password, "secret"),
                Field::new("totp", "Code", FieldKind::Totp, "JBSWY3DPEHPK3PXP"),
            ],
            notes: None,
            reprompt: false,
            state: verrou_core::ItemState::Active,
            shared: None,
        }
    }

    fn vault() -> Vault {
        Vault::new(vec![
            item("github", "https://github.com"),
            item("banque", "https://banque.fr"),
        ])
    }

    #[test]
    fn only_secure_pages() {
        assert!(page_allowed("https://github.com/login"));
        assert!(page_allowed("http://localhost:8000/"));
        assert!(!page_allowed("http://github.com/login"));
        assert!(!page_allowed("file:///etc/passwd"));
        assert!(!page_allowed("chrome://settings"));
        assert_eq!(suggestions(&vault(), "http://github.com/login"), []);
    }

    #[test]
    fn suggestions_match_the_page() {
        let found = suggestions(&vault(), "https://gist.github.com/");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "github");
        assert_eq!(found[0].username, "camille");
        assert!(found[0].has_totp);
    }

    /// The extension's path (suggestions then credentials) follows the
    /// rule of each site, the device's rule and equivalent
    /// domains.
    #[test]
    fn extension_fill_honours_match_rules() {
        use verrou_core::{MatchRules, UriMatch};
        let mut exact = item("exact", "https://banque.fr/connexion");
        exact.url_matches = vec![Some(UriMatch::Exact)];
        let mut never = item("jamais", "https://banque.fr");
        never.url_matches = vec![Some(UriMatch::Never)];
        let rules = MatchRules {
            default: UriMatch::Host,
            ..MatchRules::default()
        };
        let v = Vault::new(vec![item("github", "https://github.com"), exact, never])
            .with_match_rules(rules);
        let ids = |page: &str| -> Vec<String> {
            suggestions(&v, page).into_iter().map(|s| s.id).collect()
        };
        assert_eq!(ids("https://banque.fr/connexion"), ["exact"]);
        assert_eq!(ids("https://banque.fr/connexion?x=1"), Vec::<String>::new());
        // Device rule "host": no subdomain.
        assert_eq!(ids("https://gist.github.com"), Vec::<String>::new());
        assert_eq!(ids("https://github.com/login"), ["github"]);
        assert!(credentials(&v, "jamais", "https://banque.fr", 0).is_err());
        assert!(credentials(&v, "exact", "https://banque.fr/connexion", 0).is_ok());
        // Equivalent domains: only for the "domain" rule.
        let mut domain = item("domaine", "https://compte.exemple.fr");
        domain.url_matches = vec![Some(UriMatch::Domain)];
        let mut host = item("hote", "https://compte.exemple.fr");
        host.url_matches = vec![Some(UriMatch::Host)];
        let v = Vault::new(vec![domain, host]).with_match_rules(MatchRules {
            equivalent_domains: vec![vec!["exemple.fr".into(), "exemple-banque.com".into()]],
            ..MatchRules::default()
        });
        let found: Vec<String> = suggestions(&v, "https://www.exemple-banque.com/login")
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(found, ["domaine"]);
    }

    #[test]
    fn check_save_tells_known_update_and_new() {
        let v = vault();
        let page = "https://github.com/login";
        let check = |u: &str, p: &str, c: Option<&str>| check_save(&v, page, u, p, c).unwrap();
        assert_eq!(check("camille", "secret", None).0, SaveAction::Known);
        assert_eq!(check("Camille ", "secret", None).0, SaveAction::Known);
        let (action, item) = check("camille", "nouveau", None);
        assert_eq!(action, SaveAction::Update);
        assert_eq!(item.unwrap().id, "github");
        assert_eq!(check("dominique", "x", None).0, SaveAction::New);
        // Password change without a username: the old one designates the item.
        assert_eq!(check("", "nouveau", Some("secret")).0, SaveAction::Update);
        // The site's only login, second step of a sign-in.
        assert_eq!(check("", "nouveau", None).0, SaveAction::Update);
        assert!(check_save(&v, "http://github.com/", "camille", "x", None).is_err());
        assert!(check_save(&v, page, "camille", "", None).is_err());
    }

    #[test]
    fn writes_only_for_the_page_site() {
        let v = vault();
        let Write::Update {
            item,
            username,
            password,
            ..
        } = plan_save(
            &v,
            "https://github.com/",
            "autre",
            "nouveau",
            Some("github"),
        )
        .unwrap()
        else {
            panic!("expected an update");
        };
        assert_eq!(item, "github");
        assert_eq!(username, None, "the existing username is kept");
        assert_eq!(password.unwrap().expose(), "nouveau");
        assert!(plan_save(&v, "https://github.com/", "c", "x", Some("banque")).is_err());
        let Write::Create { title, uri, .. } =
            plan_save(&v, "https://www.exemple.fr/inscription?x=1", "c", "x", None).unwrap()
        else {
            panic!("expected a creation");
        };
        assert_eq!(
            (title.as_str(), uri.as_str()),
            ("exemple.fr", "https://www.exemple.fr")
        );
    }

    #[test]
    fn totp_from_a_qr_code() {
        let v = vault();
        let uri =
            "otpauth://totp/Exemple:camille%40exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Exemple";
        let Write::Create { username, totp, .. } =
            plan_totp(&v, "https://exemple.fr/2fa", uri, None).unwrap()
        else {
            panic!("expected a creation");
        };
        assert_eq!(username.as_deref(), Some("camille@exemple.fr"));
        assert_eq!(totp.unwrap().expose(), uri);
        assert!(matches!(
            plan_totp(
                &v,
                "https://github.com/settings",
                "JBSWY3DPEHPK3PXP",
                Some("github")
            ),
            Ok(Write::Update { .. })
        ));
        assert!(
            plan_totp(
                &v,
                "https://github.com/",
                "pas une graine !",
                Some("github")
            )
            .is_err()
        );
        assert!(plan_totp(&v, "https://github.com/", uri, Some("banque")).is_err());
    }

    #[test]
    fn each_kind_of_client_has_its_own_commands() {
        let browser_only = [
            Command::Suggest { url: String::new() },
            Command::Fill {
                url: String::new(),
                item: String::new(),
            },
            Command::Check {
                url: String::new(),
                username: String::new(),
                password: String::new(),
                current: None,
            },
            Command::Save {
                url: String::new(),
                username: String::new(),
                password: String::new(),
                item: None,
            },
            Command::SetTotp {
                url: String::new(),
                totp: String::new(),
                item: None,
            },
        ];
        let cli_only = [
            Command::VaultSearch {
                query: String::new(),
                kind: None,
                favorites: false,
                limit: None,
            },
            Command::ItemCreate {
                changes: crate::protocol::ItemChanges::default(),
            },
            Command::ItemMove {
                item: String::new(),
                to: crate::protocol::ItemMove::Trash,
            },
            Command::VaultOverview,
            Command::VaultList {
                offset: 0,
                limit: None,
                archived: false,
            },
            Command::VaultDuplicates,
            Command::PlanPropose {
                plan: crate::protocol::Plan::default(),
            },
            Command::PlanStatus {
                plan: String::new(),
                wait: 0,
            },
            Command::PlanCancel {
                plan: String::new(),
            },
            Command::VaultItem {
                query: String::new(),
            },
            Command::Reveal {
                item: String::new(),
                field: String::new(),
            },
            Command::Totp {
                item: String::new(),
            },
            Command::Unlink,
            Command::SshKeys,
            Command::SshSign {
                public_key: String::new(),
                data: String::new(),
                flags: 0,
            },
        ];
        for command in &browser_only {
            assert!(allowed(ClientKind::Browser, command), "{command:?}");
            assert!(!allowed(ClientKind::Cli, command), "{command:?}");
        }
        for command in &cli_only {
            assert!(allowed(ClientKind::Cli, command), "{command:?}");
            assert!(!allowed(ClientKind::Browser, command), "{command:?}");
        }
        for command in [Command::Status, Command::Unlock { then: None }] {
            assert!(allowed(ClientKind::Browser, &command));
            assert!(allowed(ClientKind::Cli, &command));
        }
    }

    #[test]
    fn terminal_views_carry_no_secret() {
        let mut v = vec![item("github", "https://github.com")];
        v[0].notes = Some(SecretString::new("note secrète"));
        let v = Vault::new(v);
        let (found, total) = search(&v, "git", None, false, Some(10));
        assert_eq!((found.len(), total), (1, 1));
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains("secret"), "{json}");
        let view = item_view(find(&v, "github").unwrap());
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains(r#":"secret""#), "{json}");
        assert!(!json.contains("JBSWY3DPEHPK3PXP"), "{json}");
        assert!(!json.contains("note secrète"), "{json}");
        assert_eq!(view.fields[0].value.as_deref(), Some("camille"));
        assert!(view.has_notes);
        // The non-secret field leaves without approval; password and notes do not.
        assert_eq!(
            field_needs_confirmation(&v, "github", "username"),
            Ok(false)
        );
        assert_eq!(field_needs_confirmation(&v, "github", "password"), Ok(true));
        assert_eq!(field_needs_confirmation(&v, "github", "notes"), Ok(true));
        assert!(field_needs_confirmation(&v, "github", "inconnu").is_err());
        assert_eq!(field_value(&v, "github", "password").unwrap(), "secret");
        assert_eq!(totp_code(&v, "github", 59).unwrap().0.len(), 6);
        assert!(find(&v, "zzzz").is_err());
    }

    #[test]
    fn credentials_only_for_the_matching_site() {
        let creds = credentials(&vault(), "github", "https://github.com/login", 59).unwrap();
        assert_eq!(creds.password.as_deref(), Some("secret"));
        assert_eq!(creds.totp.as_deref().map(str::len), Some(6));
        assert!(credentials(&vault(), "banque", "https://github.com/login", 59).is_err());
        assert!(credentials(&vault(), "github", "https://github.com.evil.fr/", 59).is_err());
        assert!(credentials(&vault(), "github", "http://github.com/", 59).is_err());
        assert!(credentials(&vault(), "inconnu", "https://github.com/", 59).is_err());
    }

    #[test]
    fn shared_items_respect_the_organization_rights() {
        let mut item = item("famille", "https://netflix.com");
        item.shared = Some(verrou_core::Sharing {
            organization_id: "org".to_owned(),
            organization: "Famille".to_owned(),
            collections: vec![("c".to_owned(), "Streaming".to_owned())],
            read_only: true,
            hide_passwords: true,
        });
        let vault = Vault::new(vec![item]);
        let page = "https://www.netflix.com/login";
        // Filling stays allowed (like Bitwarden), displaying does not.
        assert!(credentials(&vault, "famille", page, 0).is_ok());
        assert!(field_value(&vault, "famille", "password").is_err());
        assert_eq!(
            field_value(&vault, "famille", "username").unwrap(),
            "camille"
        );
        assert_eq!(
            search(&vault, "", None, false, None).0[0].shared.as_deref(),
            Some("Famille › Streaming")
        );
        // Read-only: no update, the extension offers a new item.
        assert!(plan_save(&vault, page, "camille", "autre", Some("famille")).is_err());
        assert_eq!(
            check_save(&vault, page, "camille", "autre", None)
                .unwrap()
                .0,
            SaveAction::New
        );
        assert!(plan_link_site(&vault, "https://disneyplus.com", "famille").is_err());
    }
}
