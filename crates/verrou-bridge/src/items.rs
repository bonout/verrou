//! The terminal writes items: `verrou item create`, `edit`, `delete`,
//! `archive` and `restore`.
//!
//! Each write is checked here against the vault before the user is asked
//! for approval (a refused write asks nothing), then once more when the app
//! carries it out ([`crate::Backend::write`]). The terminal never reads a
//! secret this way: it only sends values.

use verrou_core::totp::Totp;
use verrou_core::{Field, FieldKind, Filter, Item, ItemKind, ItemState, SecretString, Sort, Vault};

use crate::access::{Write, writable};
use crate::protocol::{FieldChange, ItemChanges, ItemMove};

const MAX_TITLE: usize = 512;
const MAX_VALUE: usize = 10_000;
const MAX_FIELDS: usize = 100;
const MAX_URLS: usize = 50;

/// Where an item goes, as the app carries it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateChange {
    Trash,
    Restore,
    Archive,
    Unarchive,
}

/// The item's own field that `name` designates, for an item of `kind`:
/// the name the app writes. `None`: a custom field.
pub fn field_target(kind: ItemKind, name: &str) -> Option<&'static str> {
    let name = name.trim().to_lowercase().replace([' ', '-'], "_");
    if name == "notes" {
        return Some("notes");
    }
    let target = match kind {
        ItemKind::Login => match name.as_str() {
            "username" => "username",
            "password" => "password",
            "totp" | "otp" | "one_time_code" => "totp",
            _ => return None,
        },
        ItemKind::Card => match name.as_str() {
            "cardholder" | "cardholder_name" => "cardholder",
            "brand" => "brand",
            "number" => "number",
            "expiry" | "expiration" => "expiry",
            "code" | "cvv" | "security_code" => "code",
            _ => return None,
        },
        ItemKind::Identity => [
            "first_name",
            "middle_name",
            "last_name",
            "company",
            "email",
            "phone",
            "username",
            "ssn",
            "passport",
            "license",
            "address1",
            "address2",
            "address3",
            "postal_code",
            "city",
            "state",
            "country",
        ]
        .into_iter()
        .find(|field| *field == name)?,
        _ => return None,
    };
    Some(target)
}

/// `MM/YY` or `MM/YYYY`: the month (`1` to `12`) and the year (four
/// digits), as Bitwarden stores them.
pub fn parse_expiry(value: &str) -> Option<(String, String)> {
    let (month, year) = value.trim().split_once('/')?;
    let month: u8 = month.trim().parse().ok().filter(|m| (1..=12).contains(m))?;
    let year = year.trim();
    let year: u16 = match year.len() {
        2 => 2000 + year.parse::<u16>().ok()?,
        4 => year.parse().ok()?,
        _ => return None,
    };
    Some((month.to_string(), year.to_string()))
}

/// A new item, checked.
pub fn plan_create(changes: ItemChanges) -> Result<Write, String> {
    let kind = changes.kind.unwrap_or(ItemKind::Login);
    if !matches!(
        kind,
        ItemKind::Login | ItemKind::SecureNote | ItemKind::Card | ItemKind::Identity
    ) {
        return Err(format!(
            "\"{}\" items cannot be created from the terminal: login, note, card or identity",
            kind.keyword()
        ));
    }
    if changes.title.as_deref().is_none_or(|t| t.trim().is_empty()) {
        return Err("the title is required".to_owned());
    }
    if changes.fields.iter().any(|f| f.value.is_none()) {
        return Err("a new item has no field to remove".to_owned());
    }
    check(kind, &changes)?;
    Ok(Write::NewItem {
        changes: Box::new(changes),
    })
}

/// Changes to the item `id`, checked.
pub fn plan_edit(vault: &Vault, id: &str, changes: ItemChanges) -> Result<Write, String> {
    let item = vault
        .get(id)
        .ok_or_else(|| "item not found".to_owned())
        .and_then(writable)?;
    if item.state == ItemState::Trashed {
        return Err(format!(
            "\"{}\" is in the trash: restore it first",
            item.title
        ));
    }
    if changes.kind.is_some_and(|k| k != item.kind) {
        return Err("an item's kind cannot change".to_owned());
    }
    if changes
        .title
        .as_deref()
        .is_some_and(|t| t.trim().is_empty())
    {
        return Err("the title is required".to_owned());
    }
    let ItemChanges {
        title,
        urls,
        folder,
        favorite,
        fields,
        ..
    } = &changes;
    if title.is_none()
        && urls.is_none()
        && folder.is_none()
        && favorite.is_none()
        && fields.is_empty()
    {
        return Err("nothing to change".to_owned());
    }
    check(item.kind, &changes)?;
    for field in &changes.fields {
        let custom = field_target(item.kind, &field.name).is_none();
        let name = field.name.trim();
        if custom
            && field.value.is_none()
            && !item
                .fields
                .iter()
                .any(|f| f.label.eq_ignore_ascii_case(name))
        {
            return Err(format!("\"{}\" has no field \"{name}\"", item.title));
        }
    }
    Ok(Write::EditItem {
        item: item.id.clone(),
        changes: Box::new(changes),
    })
}

/// The item `query` (identifier or title) moved, checked: what the app
/// does, and the item.
pub fn plan_move(vault: &Vault, query: &str, to: ItemMove) -> Result<(Write, String), String> {
    let found = vault.get(query).or_else(|| {
        let filters: &[Filter] = match to {
            ItemMove::Trash | ItemMove::Archive => &[Filter::All],
            ItemMove::Restore => &[Filter::Trash, Filter::Archived],
        };
        filters.iter().find_map(|filter| {
            vault
                .search(query, filter, Sort::Relevance)
                .first()
                .map(|hit| &vault.items()[hit.index])
        })
    });
    let item = found
        .ok_or_else(|| format!("no item for \"{query}\""))
        .and_then(writable)?;
    let change = match (to, item.state) {
        (ItemMove::Trash, ItemState::Trashed) => {
            return Err(format!("\"{}\" is already in the trash", item.title));
        }
        (ItemMove::Trash, _) => StateChange::Trash,
        (ItemMove::Archive, ItemState::Active) => StateChange::Archive,
        (ItemMove::Archive, ItemState::Archived) => {
            return Err(format!("\"{}\" is already archived", item.title));
        }
        (ItemMove::Archive, ItemState::Trashed) => {
            return Err(format!(
                "\"{}\" is in the trash: restore it first",
                item.title
            ));
        }
        (ItemMove::Restore, ItemState::Trashed) => StateChange::Restore,
        (ItemMove::Restore, ItemState::Archived) => StateChange::Unarchive,
        (ItemMove::Restore, ItemState::Active) => {
            return Err(format!(
                "\"{}\" is neither in the trash nor archived",
                item.title
            ));
        }
    };
    Ok((
        Write::MoveItem {
            item: item.id.clone(),
            to: change,
        },
        item.title.clone(),
    ))
}

/// What a write changes, for its approval: the names of the fields set
/// and, after `−`, of those removed; never a value. `new`: an item being
/// created (its title is not a change). One line, cut like a reason.
pub fn summary(changes: &ItemChanges, new: bool) -> String {
    let mut names: Vec<String> = Vec::new();
    if !new && changes.title.is_some() {
        names.push("title".to_owned());
    }
    if changes.urls.is_some() {
        names.push("url".to_owned());
    }
    if changes.favorite.is_some() {
        names.push("favorite".to_owned());
    }
    for field in &changes.fields {
        let name = field.name.trim();
        match field.value {
            Some(_) => names.push(name.to_owned()),
            None => names.push(format!("−{name}")),
        }
    }
    crate::protocol::clean_reason(Some(&names.join(", ")))
}

/// The values make sense for an item of `kind`.
fn check(kind: ItemKind, changes: &ItemChanges) -> Result<(), String> {
    if changes
        .title
        .as_deref()
        .is_some_and(|t| t.len() > MAX_TITLE)
    {
        return Err("title too long".to_owned());
    }
    if let Some(urls) = &changes.urls {
        if kind != ItemKind::Login && !urls.is_empty() {
            return Err("only a login has websites".to_owned());
        }
        if urls.len() > MAX_URLS || urls.iter().any(|u| u.len() > MAX_VALUE) {
            return Err("too many or too long websites".to_owned());
        }
    }
    if changes.fields.len() > MAX_FIELDS {
        return Err("too many fields".to_owned());
    }
    for FieldChange { name, value, .. } in &changes.fields {
        if name.trim().is_empty() || name.len() > MAX_TITLE {
            return Err(format!("invalid field name \"{name}\""));
        }
        let lower = name.trim().to_lowercase();
        // Reserved fields (`verrou:` template, `part:` address pieces), and
        // fields shown but written another way.
        if lower.starts_with("verrou:") || lower.starts_with("part:") {
            return Err(format!("\"{name}\": reserved field"));
        }
        if kind == ItemKind::Identity && lower == "address" {
            return Err(
                "the address is written in parts: address1, address2, postal_code, city, state, country"
                    .to_owned(),
            );
        }
        if kind == ItemKind::SshKey
            && ["public_key", "private_key", "fingerprint"]
                .contains(&lower.replace(' ', "_").as_str())
        {
            return Err(format!(
                "\"{name}\": an SSH key is not changed from the terminal"
            ));
        }
        let Some(value) = value else { continue };
        if value.len() > MAX_VALUE {
            return Err(format!("\"{name}\": value too long"));
        }
        match field_target(kind, name) {
            Some("totp") if !value.is_empty() => {
                Totp::parse(value).map_err(|e| format!("\"{name}\": {e}"))?;
            }
            Some("expiry") if !value.is_empty() && parse_expiry(value).is_none() => {
                return Err(format!("\"{name}\": expected MM/YY"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Carries out a terminal write on an in-memory vault (tests and the test
/// server); the app writes to the server.
pub(crate) fn apply_in_memory(vault: &Vault, write: Write, new_id: &str) -> (Vault, String) {
    let mut items = vault.items().to_vec();
    let id = match write {
        Write::NewItem { changes } => {
            let mut item = Item {
                id: new_id.to_owned(),
                kind: changes.kind.unwrap_or(ItemKind::Login),
                title: String::new(),
                subtitle: String::new(),
                urls: Vec::new(),
                url_matches: Vec::new(),
                folder: None,
                tags: Vec::new(),
                favorite: false,
                created: 0,
                modified: 0,
                fields: Vec::new(),
                notes: None,
                reprompt: false,
                state: ItemState::Active,
                shared: None,
            };
            change(&mut item, &changes);
            items.push(item);
            new_id.to_owned()
        }
        Write::EditItem { item: id, changes } => {
            if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                change(item, &changes);
            }
            id
        }
        Write::MoveItem { item: id, to } => {
            if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                item.state = match to {
                    StateChange::Trash => ItemState::Trashed,
                    StateChange::Archive => ItemState::Archived,
                    StateChange::Restore | StateChange::Unarchive => ItemState::Active,
                };
            }
            id
        }
        // The other writes: `crate::access::apply_in_memory`.
        _ => new_id.to_owned(),
    };
    (
        Vault::new(items)
            .with_passkeys(vault.passkeys().to_vec())
            .with_match_rules(vault.match_rules().clone()),
        id,
    )
}

fn change(item: &mut Item, changes: &ItemChanges) {
    if let Some(title) = &changes.title {
        title.trim().clone_into(&mut item.title);
    }
    if let Some(urls) = &changes.urls {
        item.urls.clone_from(urls);
    }
    if let Some(folder) = &changes.folder {
        item.folder = (!folder.is_empty()).then(|| folder.clone());
    }
    if let Some(favorite) = changes.favorite {
        item.favorite = favorite;
    }
    for field in &changes.fields {
        let target = field_target(item.kind, &field.name);
        if target == Some("notes") {
            item.notes = field.value.as_deref().map(SecretString::new);
            continue;
        }
        let id = target.map_or_else(
            || {
                item.fields
                    .iter()
                    .find(|f| f.label.eq_ignore_ascii_case(field.name.trim()))
                    .map_or_else(|| format!("custom-{}", item.fields.len()), |f| f.id.clone())
            },
            str::to_owned,
        );
        item.fields.retain(|f| f.id != id);
        if let Some(value) = &field.value {
            let kind = match target {
                Some("password") => FieldKind::Password,
                Some("totp") => FieldKind::Totp,
                Some("username") => FieldKind::Username,
                _ if field.hidden => FieldKind::Concealed,
                _ => FieldKind::Text,
            };
            let label = match target {
                Some("username") => "Username",
                Some("password") => "Password",
                Some("totp") => "One-time code",
                _ => field.name.trim(),
            };
            item.fields
                .push(Field::new(&id, label, kind, value.as_str()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, value: &str) -> FieldChange {
        FieldChange {
            name: name.to_owned(),
            value: Some(value.to_owned()),
            hidden: false,
        }
    }

    fn login(id: &str, state: ItemState) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: id.to_owned(),
            subtitle: String::new(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: Vec::new(),
            notes: None,
            reprompt: false,
            state,
            shared: None,
        }
    }

    #[test]
    fn field_names_designate_the_items_own_fields() {
        assert_eq!(field_target(ItemKind::Login, "Password"), Some("password"));
        assert_eq!(field_target(ItemKind::Login, "otp"), Some("totp"));
        assert_eq!(field_target(ItemKind::Card, "CVV"), Some("code"));
        assert_eq!(
            field_target(ItemKind::Identity, "postal code"),
            Some("postal_code")
        );
        assert_eq!(field_target(ItemKind::SecureNote, "notes"), Some("notes"));
        assert_eq!(field_target(ItemKind::Login, "API key"), None);
        assert_eq!(field_target(ItemKind::SecureNote, "password"), None);
    }

    #[test]
    fn a_summary_names_fields_never_values() {
        let changes = ItemChanges {
            title: Some("GitHub".into()),
            urls: Some(vec!["https://github.com".into()]),
            fields: vec![
                set("password", "hunter2"),
                FieldChange {
                    name: "Old token".into(),
                    value: None,
                    hidden: false,
                },
            ],
            ..ItemChanges::default()
        };
        assert_eq!(summary(&changes, false), "title, url, password, −Old token");
        assert_eq!(summary(&changes, true), "url, password, −Old token");
        assert!(!summary(&changes, false).contains("hunter2"));
    }

    #[test]
    fn expiry_is_month_and_year() {
        assert_eq!(parse_expiry("04/27"), Some(("4".into(), "2027".into())));
        assert_eq!(parse_expiry("12/2030"), Some(("12".into(), "2030".into())));
        assert_eq!(parse_expiry("13/27"), None);
        assert_eq!(parse_expiry("0427"), None);
    }

    #[test]
    fn a_new_item_is_checked() {
        let ok = ItemChanges {
            title: Some("GitHub".into()),
            fields: vec![set("password", "hunter2"), set("totp", "JBSWY3DPEHPK3PXP")],
            ..ItemChanges::default()
        };
        assert!(plan_create(ok.clone()).is_ok());
        let untitled = ItemChanges {
            title: Some("  ".into()),
            ..ok.clone()
        };
        assert!(plan_create(untitled).is_err());
        let bad_code = ItemChanges {
            fields: vec![set("otp", "not a seed!")],
            ..ok.clone()
        };
        assert!(plan_create(bad_code).is_err());
        let ssh = ItemChanges {
            kind: Some(ItemKind::SshKey),
            ..ok.clone()
        };
        assert!(plan_create(ssh).is_err());
        let note_with_site = ItemChanges {
            kind: Some(ItemKind::SecureNote),
            urls: Some(vec!["https://x.fr".into()]),
            ..ok
        };
        assert!(plan_create(note_with_site).is_err());
        let reserved = ItemChanges {
            title: Some("x".into()),
            fields: vec![set("verrou:template", "wifi")],
            ..ItemChanges::default()
        };
        assert!(plan_create(reserved).is_err());
        let address = ItemChanges {
            kind: Some(ItemKind::Identity),
            title: Some("Me".into()),
            fields: vec![set("Address", "1 rue de la Paix")],
            ..ItemChanges::default()
        };
        assert!(plan_create(address).is_err());
    }

    #[test]
    fn edits_and_moves_follow_the_items_state() {
        let vault = Vault::new(vec![
            login("active", ItemState::Active),
            login("archived", ItemState::Archived),
            login("trashed", ItemState::Trashed),
        ]);
        let rename = ItemChanges {
            title: Some("New".into()),
            ..ItemChanges::default()
        };
        assert!(plan_edit(&vault, "active", rename.clone()).is_ok());
        assert!(plan_edit(&vault, "trashed", rename).is_err());
        assert!(plan_edit(&vault, "active", ItemChanges::default()).is_err());
        let remove_missing = ItemChanges {
            fields: vec![FieldChange {
                name: "Nope".into(),
                value: None,
                hidden: false,
            }],
            ..ItemChanges::default()
        };
        assert!(plan_edit(&vault, "active", remove_missing).is_err());

        let to = |query, to| plan_move(&vault, query, to).map(|(w, _)| w);
        assert!(matches!(
            to("active", ItemMove::Trash),
            Ok(Write::MoveItem {
                to: StateChange::Trash,
                ..
            })
        ));
        assert!(matches!(
            to("archived", ItemMove::Restore),
            Ok(Write::MoveItem {
                to: StateChange::Unarchive,
                ..
            })
        ));
        assert!(matches!(
            to("trashed", ItemMove::Restore),
            Ok(Write::MoveItem {
                to: StateChange::Restore,
                ..
            })
        ));
        assert!(to("active", ItemMove::Restore).is_err());
        assert!(to("trashed", ItemMove::Archive).is_err());
    }

    #[test]
    fn a_shared_read_only_item_is_not_written() {
        let mut item = login("shared", ItemState::Active);
        item.shared = Some(verrou_core::Sharing {
            read_only: true,
            ..verrou_core::Sharing::default()
        });
        let vault = Vault::new(vec![item]);
        assert!(plan_move(&vault, "shared", ItemMove::Trash).is_err());
    }

    #[test]
    fn writes_apply_in_memory() {
        let vault = Vault::new(vec![]);
        let changes = ItemChanges {
            title: Some("Stripe".into()),
            fields: vec![FieldChange {
                name: "API key".into(),
                value: Some("sk_live".into()),
                hidden: true,
            }],
            ..ItemChanges::default()
        };
        let (vault, id) = apply_in_memory(&vault, plan_create(changes).unwrap(), "new");
        let item = vault.get(&id).unwrap();
        assert_eq!(item.title, "Stripe");
        assert_eq!(item.fields[0].kind, FieldKind::Concealed);
        let (vault, _) = apply_in_memory(
            &vault,
            plan_move(&vault, "new", ItemMove::Archive).unwrap().0,
            "",
        );
        assert_eq!(vault.get("new").unwrap().state, ItemState::Archived);
    }
}
