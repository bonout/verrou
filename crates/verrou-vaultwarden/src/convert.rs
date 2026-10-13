//! Éléments déchiffrés par le SDK (`CipherView`) → modèle de Verrou.
//!
//! Les identifiants de champs (`username`, `password`, `totp`, `number`…) sont
//! ceux du coffre fictif : l'interface n'a pas à savoir d'où vient l'élément.

use std::collections::HashMap;

use bitwarden_vault::{CipherRepromptType, CipherType, CipherView, FieldType};
use verrou_core::{Field, FieldKind, Item, ItemKind, ItemState, SecretString};

/// Les éléments archivés et ceux de la corbeille sont gardés, avec leur état :
/// l'interface les montre à part.
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
            "(sans nom)".to_owned()
        } else {
            view.name.clone()
        },
        subtitle: String::new(),
        urls: Vec::new(),
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
    };
    match view.r#type {
        CipherType::Login => login(view, &mut item),
        CipherType::Card => card(view, &mut item),
        CipherType::Identity => identity(view, &mut item),
        CipherType::SshKey => ssh_key(view, &mut item),
        CipherType::SecureNote => "Note sécurisée".clone_into(&mut item.subtitle),
        // Types récents (compte bancaire, permis, passeport) : affichés comme
        // des notes, avec leurs champs personnalisés et leurs notes.
        CipherType::BankAccount => "Compte bancaire".clone_into(&mut item.subtitle),
        CipherType::DriversLicense => "Permis de conduire".clone_into(&mut item.subtitle),
        CipherType::Passport => "Passeport".clone_into(&mut item.subtitle),
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
    push(item, "username", "Identifiant", kind, username);
    push(
        item,
        "password",
        "Mot de passe",
        FieldKind::Password,
        login.password.as_ref(),
    );
    push(
        item,
        "totp",
        "Code à usage unique",
        FieldKind::Totp,
        login.totp.as_ref(),
    );
    item.subtitle = username.cloned().unwrap_or_default();
    item.urls = login
        .uris
        .iter()
        .flatten()
        .filter_map(|u| u.uri.clone())
        .filter(|u| !u.trim().is_empty())
        .collect();
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
        "Titulaire",
        FieldKind::Text,
        card.cardholder_name.as_ref(),
    );
    push(
        item,
        "brand",
        "Réseau",
        FieldKind::Text,
        card.brand.as_ref(),
    );
    let number = (!digits.is_empty()).then(|| group_card_number(&digits));
    push(
        item,
        "number",
        "Numéro",
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
        "Cryptogramme",
        FieldKind::Pin,
        card.code.as_ref(),
    );
}

/// `4242424242424242` → `4242 4242 4242 4242` (l'interface le copie sans espaces).
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
        ("first_name", "Prénom", FieldKind::Text, &id.first_name),
        (
            "middle_name",
            "Deuxième prénom",
            FieldKind::Text,
            &id.middle_name,
        ),
        ("last_name", "Nom", FieldKind::Text, &id.last_name),
        ("company", "Société", FieldKind::Text, &id.company),
        ("email", "E-mail", FieldKind::Email, &id.email),
        ("phone", "Téléphone", FieldKind::Phone, &id.phone),
        ("username", "Identifiant", FieldKind::Username, &id.username),
        ("address", "Adresse", FieldKind::Address, &address),
        (
            "ssn",
            "Numéro de sécurité sociale",
            FieldKind::Concealed,
            &id.ssn,
        ),
        (
            "passport",
            "Passeport",
            FieldKind::Concealed,
            &id.passport_number,
        ),
        (
            "license",
            "Permis de conduire",
            FieldKind::Concealed,
            &id.license_number,
        ),
    ];
    for (key, label, kind, value) in fields {
        push(item, key, label, kind, value.as_ref());
    }
}

/// Les parties non vides, séparées par `separator`.
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
        "Clé publique",
        FieldKind::Multiline,
        Some(&key.public_key),
    );
    push(
        item,
        "fingerprint",
        "Empreinte",
        FieldKind::Text,
        Some(&key.fingerprint),
    );
    push(
        item,
        "private_key",
        "Clé privée",
        FieldKind::Concealed,
        Some(&key.private_key),
    );
}

/// Champs personnalisés. Les champs « liés » (qui renvoient à l'identifiant ou
/// au mot de passe) n'ont pas de valeur propre : ils sont ignorés.
fn custom_fields(view: &CipherView, item: &mut Item) {
    for (index, field) in view.fields.iter().flatten().enumerate() {
        let label = field
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Champ".to_owned());
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
                    "Oui"
                } else {
                    "Non"
                };
                item.fields
                    .push(Field::new(&id, &label, FieldKind::Text, value));
            }
            FieldType::Linked => {}
        }
    }
}

/// Anciens mots de passe, du plus récent au plus ancien : champs secrets
/// `history-N` (jamais `Password`, pour que le mot de passe actuel reste le
/// seul que l'audit et le remplissage voient).
fn password_history(view: &CipherView, item: &mut Item) {
    for (index, entry) in view.password_history.iter().flatten().enumerate() {
        if entry.password.is_empty() {
            continue;
        }
        let label = format!(
            "Remplacé le {}",
            entry.last_used_date.format("%d/%m/%Y à %H:%M")
        );
        item.fields.push(Field::new(
            &format!("history-{index}"),
            &label,
            FieldKind::Concealed,
            entry.password.clone(),
        ));
    }
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
