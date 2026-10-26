//! Item identifiers on the wire.
//!
//! The app hands out qualified ids (`"<tag>:<id>"`, see
//! `VaultSession::local_id` in `verrou-ffi`) and the backend's vault knows
//! only its own. The server therefore translates at its two edges, once, for
//! every command and every reply:
//!
//! - **in**: the item ids of a command become the vault's own
//!   ([`Backend::local_id`](crate::Backend::local_id)); an id of another
//!   account is refused as "item not found", and an unqualified id (an older
//!   extension or terminal) is taken as the account's own;
//! - **out**: every id of a reply is qualified
//!   ([`Backend::qualify`](crate::Backend::qualify)).
//!
//! The extension and the terminal treat ids as opaque strings, so they need
//! no change.

use crate::protocol::{
    Command, FormSuggestion, ItemSummary, PasskeyCreation, PasskeySuggestion, PasskeyTarget,
    PasskeyUse, ReplyResult, Suggestion,
};

/// What the server says when an id belongs to another account.
pub const NOT_FOUND: &str = "item not found";

/// The command with the vault's own ids; `Err`: an id of another account.
///
/// # Errors
/// [`NOT_FOUND`] when an id names another account.
pub fn localize(
    command: Command,
    local: &dyn Fn(&str) -> Option<String>,
) -> Result<Command, &'static str> {
    let one = |id: String| local(&id).ok_or(NOT_FOUND);
    // An id or a title (`vault_item`, `item_move`): our own tag comes off.
    // `local` says `None` for a prefix that is another account's tag: with a
    // uuid after it that is another account's item, refused; otherwise a
    // title that happens to look like `tag:text` (`github:work`).
    let id_or_title = |query: String| match local(&query) {
        Some(own) => Ok(own),
        None if query
            .split_once(':')
            .is_some_and(|(_, rest)| uuid_shaped(rest)) =>
        {
            Err(NOT_FOUND)
        }
        None => Ok(query),
    };
    let opt = |id: Option<String>| id.map(|id| local(&id).ok_or(NOT_FOUND)).transpose();
    Ok(match command {
        Command::Fill { url, item } => Command::Fill {
            url,
            item: one(item)?,
        },
        Command::Save {
            url,
            username,
            password,
            item,
        } => Command::Save {
            url,
            username,
            password,
            item: opt(item)?,
        },
        Command::SetTotp { url, totp, item } => Command::SetTotp {
            url,
            totp,
            item: opt(item)?,
        },
        Command::VaultItem { query } => Command::VaultItem {
            query: id_or_title(query)?,
        },
        Command::Reveal { item, field } => Command::Reveal {
            item: one(item)?,
            field,
        },
        Command::Totp { item } => Command::Totp { item: one(item)? },
        Command::ItemEdit { item, changes } => Command::ItemEdit {
            item: one(item)?,
            changes,
        },
        Command::ItemMove { item, to } => Command::ItemMove {
            item: id_or_title(item)?,
            to,
        },
        Command::FillForm { url, item } => Command::FillForm {
            url,
            item: one(item)?,
        },
        Command::LinkSite { url, item } => Command::LinkSite {
            url,
            item: one(item)?,
        },
        Command::PasskeyGet(request) => Command::PasskeyGet(PasskeyUse {
            item: one(request.item.clone())?,
            ..request
        }),
        Command::PasskeyCreate(request) => Command::PasskeyCreate(Box::new(PasskeyCreation {
            item: opt(request.item.clone())?,
            ..*request
        })),
        other => other,
    })
}

/// The shape of a vault item id: 36 characters, hexadecimal digits and
/// hyphens.
fn uuid_shaped(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Qualifies every item id of a reply.
pub fn qualify(result: &mut ReplyResult, q: &dyn Fn(&str) -> String) {
    let suggestion = |s: &mut Suggestion| s.id = q(&s.id);
    let summary = |s: &mut ItemSummary| s.id = q(&s.id);
    let form = |s: &mut FormSuggestion| s.id = q(&s.id);
    let passkey = |s: &mut PasskeySuggestion| s.item = q(&s.item);
    let target = |s: &mut PasskeyTarget| s.id = q(&s.id);
    match result {
        ReplyResult::Suggestions { items } => items.iter_mut().for_each(suggestion),
        ReplyResult::Check {
            item: Some(item), ..
        } => suggestion(item),
        ReplyResult::Saved { item } => *item = q(item),
        ReplyResult::Items { items, .. } => items.iter_mut().for_each(summary),
        ReplyResult::Item { item } => summary(&mut item.summary),
        ReplyResult::SshKeys { keys } => keys.iter_mut().for_each(|k| k.item = q(&k.item)),
        ReplyResult::Forms { cards, identities } => {
            cards.iter_mut().for_each(form);
            identities.iter_mut().for_each(form);
        }
        ReplyResult::Passkeys { items } => items.iter_mut().for_each(passkey),
        ReplyResult::PasskeyTargets { logins, .. } => logins.iter_mut().for_each(target),
        ReplyResult::Registration(registration) => {
            registration.item = q(&registration.item);
        }
        // No item id: the rest.
        ReplyResult::Status { .. }
        | ReplyResult::Credentials(_)
        | ReplyResult::Locked
        | ReplyResult::Denied { .. }
        | ReplyResult::Done
        | ReplyResult::Check { item: None, .. }
        | ReplyResult::Confirm
        | ReplyResult::Secret(_)
        | ReplyResult::Code { .. }
        | ReplyResult::Form(_)
        | ReplyResult::Signature { .. }
        | ReplyResult::Assertion(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PasskeyAssertion;

    fn local(id: &str) -> Option<String> {
        match id.split_once(':') {
            Some(("acct01", rest)) => Some(rest.to_owned()),
            Some(("other2", _)) => None,
            _ => Some(id.to_owned()),
        }
    }

    fn qualified(id: &str) -> String {
        format!("acct01:{id}")
    }

    #[test]
    fn commands_get_the_vaults_own_ids_or_are_refused() {
        let fill = |item: &str| Command::Fill {
            url: "https://x.fr".into(),
            item: item.into(),
        };
        assert_eq!(localize(fill("acct01:a"), &local), Ok(fill("a")));
        assert_eq!(localize(fill("a"), &local), Ok(fill("a")));
        assert_eq!(localize(fill("other2:a"), &local), Err(NOT_FOUND));
        // Optional ids: absent stays absent, a foreign one is refused.
        let save = |item: Option<&str>| Command::Save {
            url: "https://x.fr".into(),
            username: "u".into(),
            password: "p".into(),
            item: item.map(Into::into),
        };
        assert_eq!(localize(save(None), &local), Ok(save(None)));
        assert_eq!(
            localize(save(Some("acct01:a")), &local),
            Ok(save(Some("a")))
        );
        assert_eq!(localize(save(Some("other2:a")), &local), Err(NOT_FOUND));
        // A query is an id or a title: our id loses its tag, another
        // account's item is not found, a title that looks like a tag stays.
        let query = |q: &str| Command::VaultItem { query: q.into() };
        assert_eq!(localize(query("acct01:a"), &local), Ok(query("a")));
        assert_eq!(localize(query("other2:a"), &local), Ok(query("other2:a")));
        let uuid = "0b6f1c2e-5d4a-4e8b-9c3d-7a1f2e3d4c5b";
        assert_eq!(
            localize(query(&format!("other2:{uuid}")), &local),
            Err(NOT_FOUND)
        );
        assert_eq!(
            localize(query(&format!("acct01:{uuid}")), &local),
            Ok(query(uuid))
        );
        let moved = |item: &str| Command::ItemMove {
            item: item.into(),
            to: crate::protocol::ItemMove::Trash,
        };
        assert_eq!(
            localize(moved(&format!("other2:{uuid}")), &local),
            Err(NOT_FOUND)
        );
        assert_eq!(
            localize(moved("other2:work"), &local),
            Ok(moved("other2:work"))
        );
        assert_eq!(
            localize(moved(&format!("acct01:{uuid}")), &local),
            Ok(moved(uuid))
        );
        // Not uuid-shaped: 36 characters but not hex, or a hyphen misplaced.
        assert!(!uuid_shaped(&"g".repeat(36)));
        assert!(!uuid_shaped("0b6f1c2e5-d4a-4e8b-9c3d-7a1f2e3d4c5b"));
        assert!(uuid_shaped(uuid));
        assert_eq!(localize(Command::Status, &local), Ok(Command::Status));
        // Passkeys carry the item inside their request.
        let get = |item: &str| {
            Command::PasskeyGet(PasskeyUse {
                url: "https://x.fr".into(),
                rp_id: None,
                item: item.into(),
                credential: "c".into(),
                challenge: "ch".into(),
                uv: false,
                prf: None,
            })
        };
        assert_eq!(localize(get("acct01:a"), &local), Ok(get("a")));
        assert_eq!(localize(get("other2:a"), &local), Err(NOT_FOUND));
    }

    #[test]
    fn every_id_of_a_reply_is_qualified() {
        let mut passkeys = ReplyResult::Passkeys {
            items: vec![PasskeySuggestion {
                item: "a".into(),
                title: "t".into(),
                credential: "c".into(),
                user_name: "u".into(),
            }],
        };
        qualify(&mut passkeys, &qualified);
        assert!(
            matches!(&passkeys, ReplyResult::Passkeys { items } if items[0].item == "acct01:a")
        );
        let mut targets = ReplyResult::PasskeyTargets {
            excluded: false,
            logins: vec![PasskeyTarget {
                id: "a".into(),
                title: "t".into(),
                username: "u".into(),
                has_passkey: false,
            }],
        };
        qualify(&mut targets, &qualified);
        assert!(
            matches!(&targets, ReplyResult::PasskeyTargets { logins, .. } if logins[0].id == "acct01:a")
        );
        let mut saved = ReplyResult::Saved { item: "a".into() };
        qualify(&mut saved, &qualified);
        assert_eq!(
            saved,
            ReplyResult::Saved {
                item: "acct01:a".into()
            }
        );
        // No id in these: untouched.
        let mut assertion = ReplyResult::Assertion(PasskeyAssertion {
            credential: "c".into(),
            client_data: "d".into(),
            authenticator_data: "a".into(),
            signature: "s".into(),
            user_handle: None,
            prf: None,
        });
        qualify(&mut assertion, &qualified);
        assert!(matches!(assertion, ReplyResult::Assertion(a) if a.credential == "c"));
    }
}
