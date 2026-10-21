//! Items decrypted by the SDK (`CipherView`) → Verrou's model.
//!
//! The field ids (`username`, `password`, `totp`, `number`…) are those of
//! the mock vault: the interface doesn't need to know where the item comes
//! from.

use std::collections::HashMap;

use bitwarden_vault::{CipherRepromptType, CipherType, CipherView, FieldType, UriMatchType};
use verrou_core::{
    Field, FieldKind, Item, ItemKind, ItemState, Passkey, SecretString, UriMatch, template,
};

/// Bitwarden match rule → Verrou.
pub(crate) fn uri_match(rule: UriMatchType) -> UriMatch {
    match rule {
        UriMatchType::Domain => UriMatch::Domain,
        UriMatchType::Host => UriMatch::Host,
        UriMatchType::StartsWith => UriMatch::StartsWith,
        UriMatchType::Exact => UriMatch::Exact,
        UriMatchType::RegularExpression => UriMatch::RegularExpression,
        UriMatchType::Never => UriMatch::Never,
    }
}

/// Verrou match rule → Bitwarden.
pub(crate) fn uri_match_type(rule: UriMatch) -> UriMatchType {
    match rule {
        UriMatch::Domain => UriMatchType::Domain,
        UriMatch::Host => UriMatchType::Host,
        UriMatch::StartsWith => UriMatchType::StartsWith,
        UriMatch::Exact => UriMatchType::Exact,
        UriMatch::RegularExpression => UriMatchType::RegularExpression,
        UriMatch::Never => UriMatchType::Never,
    }
}

/// Archived and trashed items are kept, with their state: the interface
/// shows them separately.
pub(crate) fn item(view: &CipherView, folders: &HashMap<String, String>) -> Option<Item> {
    let state = if view.deleted_date.is_some() {
        ItemState::Trashed
    } else if view.archived_date.is_some() {
        ItemState::Archived
    } else {
        ItemState::Active
    };
    let id = view.id.map(|id| id.to_string())?;
    let folder = view
        .folder_id
        .map(|id| id.to_string())
        .and_then(|id| folders.get(&id).cloned());
    let mut item = Item {
        id,
        kind: ItemKind::SecureNote,
        title: if view.name.trim().is_empty() {
            "(untitled)".to_owned()
        } else {
            view.name.clone()
        },
        subtitle: String::new(),
        urls: Vec::new(),
        url_matches: Vec::new(),
        folder,
        tags: Vec::new(),
        favorite: view.favorite,
        created: view.creation_date.timestamp(),
        modified: view.revision_date.timestamp(),
        fields: Vec::new(),
        notes: view
            .notes
            .clone()
            .filter(|n| !n.is_empty())
            .map(SecretString::new),
        reprompt: view.reprompt == CipherRepromptType::Password,
        state,
        shared: None,
    };
    match view.r#type {
        CipherType::Login => login(view, &mut item),
        CipherType::Card => card(view, &mut item),
        CipherType::Identity => identity(view, &mut item),
        CipherType::SshKey => ssh_key(view, &mut item),
        CipherType::SecureNote => "Secure note".clone_into(&mut item.subtitle),
        // Recent types (bank account, licence, passport): shown as notes,
        // with their custom fields and their notes.
        CipherType::BankAccount => "Bank account".clone_into(&mut item.subtitle),
        CipherType::DriversLicense => "Driver's license".clone_into(&mut item.subtitle),
        CipherType::Passport => "Passport".clone_into(&mut item.subtitle),
    }
    custom_fields(view, &mut item);
    password_history(view, &mut item);
    Some(item)
}

fn push(item: &mut Item, id: &str, label: &str, kind: FieldKind, value: Option<&String>) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        item.fields.push(Field::new(id, label, kind, value.clone()));
    }
}

fn login(view: &CipherView, item: &mut Item) {
    item.kind = ItemKind::Login;
    let Some(login) = &view.login else { return };
    let username = login.username.as_ref().filter(|u| !u.is_empty());
    let kind = match username {
        Some(u) if u.contains('@') => FieldKind::Email,
        _ => FieldKind::Username,
    };
    push(item, "username", "Username", kind, username);
    push(
        item,
        "password",
        "Password",
        FieldKind::Password,
        login.password.as_ref(),
    );
    push(
        item,
        "totp",
        "One-time code",
        FieldKind::Totp,
        login.totp.as_ref(),
    );
    item.subtitle = username.cloned().unwrap_or_default();
    // Sites and rules, in the same order.
    (item.urls, item.url_matches) = login
        .uris
        .iter()
        .flatten()
        .filter_map(|u| Some((u.uri.clone()?, u.r#match.map(uri_match))))
        .filter(|(u, _)| !u.trim().is_empty())
        .unzip();
}

fn card(view: &CipherView, item: &mut Item) {
    item.kind = ItemKind::Card;
    let Some(card) = &view.card else { return };
    let digits: String = card
        .number
        .iter()
        .flat_map(|n| n.chars())
        .filter(char::is_ascii_digit)
        .collect();
    let last4 = &digits[digits.len().saturating_sub(4)..];
    let brand = card.brand.clone().unwrap_or_default();
    item.subtitle = match (brand.is_empty(), last4.is_empty()) {
        (false, false) => format!("{brand} •••• {last4}"),
        (true, false) => format!("•••• {last4}"),
        _ => brand.clone(),
    };
    push(
        item,
        "cardholder",
        "Cardholder",
        FieldKind::Text,
        card.cardholder_name.as_ref(),
    );
    push(item, "brand", "Brand", FieldKind::Text, card.brand.as_ref());
    let number = (!digits.is_empty()).then(|| group_card_number(&digits));
    push(
        item,
        "number",
        "Number",
        FieldKind::CardNumber,
        number.as_ref(),
    );
    let expiry = match (&card.exp_month, &card.exp_year) {
        (Some(m), Some(y)) if !m.is_empty() && !y.is_empty() => {
            let year = y.trim();
            let short = &year[year.len().saturating_sub(2)..];
            Some(format!("{:0>2}/{short}", m.trim()))
        }
        _ => None,
    };
    push(
        item,
        "expiry",
        "Expiration",
        FieldKind::Expiry,
        expiry.as_ref(),
    );
    push(
        item,
        "code",
        "Security code",
        FieldKind::Pin,
        card.code.as_ref(),
    );
}

/// `4242424242424242` → `4242 4242 4242 4242` (the interface copies it without spaces).
fn group_card_number(digits: &str) -> String {
    digits
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn identity(view: &CipherView, item: &mut Item) {
    item.kind = ItemKind::Identity;
    let Some(id) = &view.identity else { return };
    let full_name = join(
        [&id.title, &id.first_name, &id.middle_name, &id.last_name],
        " ",
    );
    item.subtitle = id
        .email
        .clone()
        .filter(|e| !e.is_empty())
        .unwrap_or(full_name);
    let address = Some(join(
        [
            &id.address1,
            &id.address2,
            &id.address3,
            &Some(join([&id.postal_code, &id.city], " ")),
            &id.state,
            &id.country,
        ],
        "\n",
    ));
    let fields = [
        ("first_name", "First name", FieldKind::Text, &id.first_name),
        (
            "middle_name",
            "Middle name",
            FieldKind::Text,
            &id.middle_name,
        ),
        ("last_name", "Last name", FieldKind::Text, &id.last_name),
        ("company", "Company", FieldKind::Text, &id.company),
        ("email", "Email", FieldKind::Email, &id.email),
        ("phone", "Phone", FieldKind::Phone, &id.phone),
        ("username", "Username", FieldKind::Username, &id.username),
        ("address", "Address", FieldKind::Address, &address),
        (
            "ssn",
            "Social security number",
            FieldKind::Concealed,
            &id.ssn,
        ),
        (
            "passport",
            "Passport",
            FieldKind::Concealed,
            &id.passport_number,
        ),
        (
            "license",
            "Driver's license",
            FieldKind::Concealed,
            &id.license_number,
        ),
    ];
    for (key, label, kind, value) in fields {
        push(item, key, label, kind, value.as_ref());
    }
    // The address in pieces, to fill forms field by field (`part:…`: never
    // shown, the full address already is).
    let parts = [
        ("part:address1", &id.address1),
        ("part:address2", &id.address2),
        ("part:postal_code", &id.postal_code),
        ("part:city", &id.city),
        ("part:state", &id.state),
        ("part:country", &id.country),
    ];
    for (key, value) in parts {
        push(item, key, key, FieldKind::Text, value.as_ref());
    }
}

/// The non-empty parts, separated by `separator`.
fn join<const N: usize>(parts: [&Option<String>; N], separator: &str) -> String {
    parts
        .into_iter()
        .flatten()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(separator)
}

fn ssh_key(view: &CipherView, item: &mut Item) {
    item.kind = ItemKind::SshKey;
    let Some(key) = &view.ssh_key else { return };
    item.subtitle.clone_from(&key.fingerprint);
    push(
        item,
        "public_key",
        "Public key",
        FieldKind::Multiline,
        Some(&key.public_key),
    );
    push(
        item,
        "fingerprint",
        "Fingerprint",
        FieldKind::Text,
        Some(&key.fingerprint),
    );
    push(
        item,
        "private_key",
        "Private key",
        FieldKind::Concealed,
        Some(&key.private_key),
    );
}

/// Custom fields. A "linked" field (pointing to the username, the
/// password…) has no value of its own: it shows the designated field. The
/// reserved `verrou:…` fields keep their name as id (never shown); the
/// template they designate replaces the generic subtitle.
fn custom_fields(view: &CipherView, item: &mut Item) {
    for (index, field) in view.fields.iter().flatten().enumerate() {
        let label = field
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Field".to_owned());
        if template::is_reserved(&label) {
            push(item, &label, &label, FieldKind::Text, field.value.as_ref());
            continue;
        }
        let id = format!("custom-{index}");
        match field.r#type {
            FieldType::Text => push(item, &id, &label, FieldKind::Text, field.value.as_ref()),
            FieldType::Hidden => push(
                item,
                &id,
                &label,
                FieldKind::Concealed,
                field.value.as_ref(),
            ),
            FieldType::Boolean => {
                let value = if field.value.as_deref() == Some("true") {
                    "Yes"
                } else {
                    "No"
                };
                item.fields
                    .push(Field::new(&id, &label, FieldKind::Text, value));
            }
            FieldType::Linked => {
                let target = field.linked_id.map_or(0, u32::from);
                let value = format!("Linked to the \"{}\" field", linked_label(target));
                item.fields
                    .push(Field::new(&id, &label, FieldKind::Text, value));
            }
        }
    }
    let Some(template) = item.template() else {
        return;
    };
    if item.kind == ItemKind::SecureNote {
        // The template's first visible field (network, bank…), otherwise its name.
        item.subtitle = template
            .fields()
            .iter()
            .filter(|f| !f.hidden)
            .find_map(|f| item.field_labelled(f.label))
            .map_or_else(
                || template.singular().to_owned(),
                |f| f.value.expose().to_owned(),
            );
    }
}

/// Name of the field designated by a linked field (Bitwarden's numbering).
fn linked_label(id: u32) -> &'static str {
    match id {
        100 | 413 => "Username",
        101 => "Password",
        300 => "Cardholder",
        301 => "Expiration month",
        302 => "Expiration year",
        303 => "Security code",
        304 => "Brand",
        305 => "Number",
        400 => "Title",
        401 => "Middle name",
        402..=404 => "Address",
        405 => "City",
        406 => "State",
        407 => "Postal code",
        408 => "Country",
        409 => "Company",
        410 => "Email",
        411 => "Phone",
        412 => "Social security number",
        414 => "Passport",
        415 => "Driver's license",
        416 => "First name",
        417 => "Last name",
        418 => "Full name",
        _ => "unknown",
    }
}

/// Old passwords, from newest to oldest: secret `history-N` fields (never
/// `Password`, so that the current password stays the only one the audit
/// and autofill see).
fn password_history(view: &CipherView, item: &mut Item) {
    for (index, entry) in view.password_history.iter().flatten().enumerate() {
        if entry.password.is_empty() {
            continue;
        }
        let label = format!(
            "Replaced on {}",
            entry.last_used_date.format("%Y-%m-%d at %H:%M")
        );
        item.fields.push(Field::new(
            &format!("history-{index}"),
            &label,
            FieldKind::Concealed,
            entry.password.clone(),
        ));
    }
}

/// A login's passkeys, in Bitwarden's format. Those whose item has no id
/// are ignored.
pub(crate) fn passkeys(view: &CipherView) -> Vec<Passkey> {
    let Some(item) = view.id.map(|id| id.to_string()) else {
        return Vec::new();
    };
    view.login
        .as_ref()
        .and_then(|l| l.fido2_credentials.as_ref())
        .into_iter()
        .flatten()
        .map(|c| Passkey {
            item: item.clone(),
            credential_id: c.credential_id.clone(),
            rp_id: c.rp_id.clone(),
            rp_name: c.rp_name.clone().filter(|n| !n.is_empty()),
            user_handle: c.user_handle.clone().filter(|h| !h.is_empty()),
            user_name: c.user_name.clone().filter(|n| !n.is_empty()),
            user_display_name: c.user_display_name.clone().filter(|n| !n.is_empty()),
            counter: c.counter.trim().parse().unwrap_or(0),
            discoverable: c.discoverable.trim().eq_ignore_ascii_case("true"),
            created: c.creation_date.timestamp(),
            key: SecretString::new(c.key_value.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_numbers_are_grouped() {
        assert_eq!(group_card_number("4242424242424242"), "4242 4242 4242 4242");
        assert_eq!(group_card_number("378282246310005"), "3782 8224 6310 005");
    }
}
