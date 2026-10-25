//! Items written from the terminal (`verrou item create`, `verrou item
//! edit`): the changes the bridge checked ([`verrou_bridge::items`]),
//! applied to the edit screen's draft, so the item is written as the app
//! writes it.

use verrou_bridge::items::{field_target, parse_expiry};
use verrou_bridge::protocol::{FieldChange, ItemChanges};
use verrou_core::{ItemKind, SecretString};
use verrou_vaultwarden::{
    CardDraft, CustomFieldDraft, CustomFieldKind, Draft, IdentityDraft, LoginDraft,
};

use crate::{FolderOption, VerrouError};

fn invalid(message: impl Into<String>) -> VerrouError {
    VerrouError::Invalid {
        message: message.into(),
    }
}

/// The draft of a new item.
pub(crate) fn new_draft(
    changes: &ItemChanges,
    folders: &[FolderOption],
) -> Result<Draft, VerrouError> {
    let kind = changes.kind.unwrap_or(ItemKind::Login);
    let mut draft = Draft {
        fields: Some(Vec::new()),
        login: (kind == ItemKind::Login).then(LoginDraft::default),
        card: (kind == ItemKind::Card).then(CardDraft::default),
        identity: (kind == ItemKind::Identity).then(IdentityDraft::default),
        ..Draft::default()
    };
    apply(&mut draft, changes, folders)?;
    Ok(draft)
}

/// The item's kind, as its draft shows it.
fn kind_of(draft: &Draft) -> ItemKind {
    if draft.login.is_some() {
        ItemKind::Login
    } else if draft.card.is_some() {
        ItemKind::Card
    } else if draft.identity.is_some() {
        ItemKind::Identity
    } else {
        ItemKind::SecureNote
    }
}

/// Applies the changes to an item's draft.
pub(crate) fn apply(
    draft: &mut Draft,
    changes: &ItemChanges,
    folders: &[FolderOption],
) -> Result<(), VerrouError> {
    if let Some(title) = &changes.title {
        title.trim().clone_into(&mut draft.name);
    }
    if let Some(urls) = &changes.urls {
        let login = draft
            .login
            .as_mut()
            .ok_or_else(|| invalid("this item has no website"))?;
        login.uris.clone_from(urls);
        // The kept sites keep their rule.
        login.uri_matches = None;
    }
    if let Some(folder) = &changes.folder {
        draft.folder_id = if folder.trim().is_empty() {
            None
        } else {
            let found = folders
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(folder.trim()))
                .ok_or_else(|| invalid(format!("unknown folder \"{folder}\"")))?;
            Some(found.id.clone())
        };
    }
    if let Some(favorite) = changes.favorite {
        draft.favorite = favorite;
    }
    let kind = kind_of(draft);
    for change in &changes.fields {
        match field_target(kind, &change.name) {
            Some(target) => set_own(draft, target, change)?,
            None => set_custom(draft, change)?,
        }
    }
    Ok(())
}

/// One of the item's own fields; an empty value clears it.
fn set_own(draft: &mut Draft, target: &str, change: &FieldChange) -> Result<(), VerrouError> {
    let text = change.value.clone().filter(|v| !v.trim().is_empty());
    let secret = text.as_deref().map(SecretString::new);
    if target == "notes" {
        draft.notes = secret;
        return Ok(());
    }
    if let Some(login) = draft.login.as_mut() {
        match target {
            "username" => login.username = text,
            "password" => login.password = secret,
            "totp" => login.totp = secret,
            _ => {}
        }
    } else if let Some(card) = draft.card.as_mut() {
        match target {
            "cardholder" => card.cardholder_name = text,
            "brand" => card.brand = text,
            "number" => card.number = secret,
            "code" => card.code = secret,
            "expiry" => {
                let (month, year) = match text.as_deref() {
                    Some(value) => {
                        let (m, y) = parse_expiry(value)
                            .ok_or_else(|| invalid(format!("\"{value}\": expected MM/YY")))?;
                        (Some(m), Some(y))
                    }
                    None => (None, None),
                };
                card.exp_month = month;
                card.exp_year = year;
            }
            _ => {}
        }
    } else if let Some(identity) = draft.identity.as_mut() {
        let slot = match target {
            "first_name" => &mut identity.first_name,
            "middle_name" => &mut identity.middle_name,
            "last_name" => &mut identity.last_name,
            "company" => &mut identity.company,
            "email" => &mut identity.email,
            "phone" => &mut identity.phone,
            "username" => &mut identity.username,
            "address1" => &mut identity.address1,
            "address2" => &mut identity.address2,
            "address3" => &mut identity.address3,
            "postal_code" => &mut identity.postal_code,
            "city" => &mut identity.city,
            "state" => &mut identity.state,
            "country" => &mut identity.country,
            "ssn" => {
                identity.ssn = secret;
                return Ok(());
            }
            "passport" => {
                identity.passport_number = secret;
                return Ok(());
            }
            "license" => {
                identity.license_number = secret;
                return Ok(());
            }
            _ => return Ok(()),
        };
        *slot = text;
    }
    Ok(())
}

/// A custom field, by its name: set, created, or removed.
fn set_custom(draft: &mut Draft, change: &FieldChange) -> Result<(), VerrouError> {
    let name = change.name.trim();
    let fields = draft.fields.get_or_insert_with(Vec::new);
    let found = fields
        .iter()
        .position(|f| f.name.eq_ignore_ascii_case(name));
    match (found, &change.value) {
        (Some(index), None) => {
            fields.remove(index);
        }
        (None, None) => return Err(invalid(format!("no field \"{name}\" to remove"))),
        (Some(index), Some(value)) => {
            let field = &mut fields[index];
            if field.kind == CustomFieldKind::Linked {
                return Err(invalid(format!(
                    "\"{name}\" is linked to another field: it has no value of its own"
                )));
            }
            if change.hidden {
                field.kind = CustomFieldKind::Hidden;
            }
            field.value = Some(SecretString::new(value.as_str()));
        }
        (None, Some(value)) => fields.push(CustomFieldDraft {
            name: name.to_owned(),
            value: Some(SecretString::new(value.as_str())),
            kind: if change.hidden {
                CustomFieldKind::Hidden
            } else {
                CustomFieldKind::Text
            },
            linked_id: None,
        }),
    }
    Ok(())
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

    fn folders() -> Vec<FolderOption> {
        vec![FolderOption {
            id: "f1".into(),
            name: "Work".into(),
        }]
    }

    #[test]
    fn a_new_login() {
        let draft = new_draft(
            &ItemChanges {
                title: Some(" GitHub ".into()),
                urls: Some(vec!["https://github.com".into()]),
                folder: Some("work".into()),
                fields: vec![
                    set("username", "camille"),
                    set("password", "hunter2"),
                    FieldChange {
                        name: "API key".into(),
                        value: Some("ghp_x".into()),
                        hidden: true,
                    },
                ],
                ..ItemChanges::default()
            },
            &folders(),
        )
        .unwrap();
        assert_eq!(draft.name, "GitHub");
        assert_eq!(draft.folder_id.as_deref(), Some("f1"));
        let login = draft.login.unwrap();
        assert_eq!(login.username.as_deref(), Some("camille"));
        assert_eq!(login.password.unwrap().expose(), "hunter2");
        assert_eq!(login.uris, ["https://github.com"]);
        let fields = draft.fields.unwrap();
        assert_eq!(fields[0].name, "API key");
        assert_eq!(fields[0].kind, CustomFieldKind::Hidden);
    }

    #[test]
    fn a_card_and_an_unknown_folder() {
        let draft = new_draft(
            &ItemChanges {
                kind: Some(ItemKind::Card),
                title: Some("Visa".into()),
                fields: vec![set("number", "4242424242424242"), set("expiry", "04/27")],
                ..ItemChanges::default()
            },
            &[],
        )
        .unwrap();
        let card = draft.card.unwrap();
        assert_eq!(card.exp_month.as_deref(), Some("4"));
        assert_eq!(card.exp_year.as_deref(), Some("2027"));
        assert!(
            new_draft(
                &ItemChanges {
                    title: Some("x".into()),
                    folder: Some("Nope".into()),
                    ..ItemChanges::default()
                },
                &folders()
            )
            .is_err()
        );
    }

    #[test]
    fn an_edit_sets_clears_and_removes() {
        let mut draft = Draft {
            name: "GitHub".into(),
            login: Some(LoginDraft {
                username: Some("camille".into()),
                ..LoginDraft::default()
            }),
            fields: Some(vec![CustomFieldDraft {
                name: "Old".into(),
                value: Some(SecretString::new("1")),
                ..CustomFieldDraft::default()
            }]),
            ..Draft::default()
        };
        apply(
            &mut draft,
            &ItemChanges {
                favorite: Some(true),
                fields: vec![
                    set("username", ""),
                    FieldChange {
                        name: "old".into(),
                        value: None,
                        hidden: false,
                    },
                    set("notes", "hello"),
                ],
                ..ItemChanges::default()
            },
            &[],
        )
        .unwrap();
        assert!(draft.favorite);
        assert_eq!(draft.login.unwrap().username, None);
        assert_eq!(draft.fields.unwrap(), []);
        assert_eq!(draft.notes.unwrap().expose(), "hello");
    }
}
