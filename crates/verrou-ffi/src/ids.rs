//! Qualified item ids: `"<tag>:<id>"`.
//!
//! A session opened through `Accounts::session(tag)` hands out every item id
//! qualified with its account's tag, and takes every id back through
//! `VaultSession::local_id` (this module's `split_item_id`): the ONE place
//! that strips and checks the tag. What the vault, the account folder's
//! files (usage, SSH approvals, passkey tickets) and the server know stays
//! the plain id.
//!
//! Rules, for every entry point that takes an item id:
//!
//! - `<this tag>:<id>`: the item `<id>`;
//! - `<another tag>:<id>`: `NotFound` (or, for the entry points that cannot
//!   fail, nothing: `false`, empty, the default, no-op). Never looked up;
//! - an unqualified `<id>`: accepted as this session's own. Identities the
//!   system still holds from before the update, an older browser extension
//!   or terminal, and bridge clients that kept an id keep working.
//!
//! Not qualified: folders, organizations, collections, Sends, attachments,
//! emergency contacts and credential ids (they are never mixed between
//! accounts by a caller, which always acts inside one account's scope), and
//! the items of a grantor's vault opened through emergency access
//! (`EmergencyVault`, a separate object).

use crate::VerrouError;
use verrou_vaultwarden::accounts::valid_tag;

/// Strips the tag of an item id (see `VaultSession::local_id`). A session
/// without a tag takes every id as it is.
pub(crate) fn split_item_id<'a>(tag: Option<&str>, id: &'a str) -> Result<&'a str, VerrouError> {
    let Some(tag) = tag else {
        return Ok(id);
    };
    match id.split_once(':') {
        Some((prefix, rest)) if prefix == tag => Ok(rest),
        Some((prefix, _)) if valid_tag(prefix) => Err(VerrouError::NotFound),
        _ => Ok(id),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use verrou_core::SecretString;

    use super::*;
    use crate::preferences::SshApprovalScope;
    use crate::{
        Accounts, BreachedPassword, BulkItemAction, BulkProgress, ItemDraft, ItemSummary,
        MockLanguage, PasskeyCreationRequest, SendFields, VaultSession,
    };

    #[test]
    fn the_tag_is_stripped_checked_or_left_alone() {
        let own = Some("k3f7qa");
        assert_eq!(split_item_id(own, "k3f7qa:abc").unwrap(), "abc");
        assert!(
            matches!(split_item_id(own, "zzzzzz:abc"), Err(VerrouError::NotFound)),
            "another account"
        );
        // Unqualified, or a colon that is not a tag's: the account's own.
        assert_eq!(split_item_id(own, "abc").unwrap(), "abc");
        assert_eq!(split_item_id(own, ":abc").unwrap(), ":abc");
        assert_eq!(split_item_id(own, "K3F9QA:abc").unwrap(), "K3F9QA:abc");
        assert_eq!(split_item_id(own, "k3f9q:abc").unwrap(), "k3f9q:abc");
        assert_eq!(split_item_id(own, "ssh:key:1").unwrap(), "ssh:key:1");
        // The rest after the tag is kept whole.
        assert_eq!(split_item_id(own, "k3f7qa:a:b").unwrap(), "a:b");
        // A session outside the registry takes everything.
        assert_eq!(split_item_id(None, "zzzzzz:abc").unwrap(), "zzzzzz:abc");
    }

    /// A tagged session on the mock vault, in a throwaway root.
    struct Fixture {
        root: PathBuf,
        session: Arc<VaultSession>,
        tag: String,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("verrou-ids-{}", uuid::Uuid::new_v4()));
            let accounts = Accounts::open(root.display().to_string()).unwrap();
            let tag = accounts.primary_tag().unwrap().unwrap();
            let session = accounts.session(tag.clone()).unwrap();
            session.unlock_mock(0, 42, MockLanguage::English);
            Self { root, session, tag }
        }

        fn summaries(&self) -> Vec<ItemSummary> {
            self.session.summaries().unwrap()
        }

        fn find(&self, wanted: impl Fn(&ItemSummary) -> bool) -> String {
            self.summaries().into_iter().find(wanted).unwrap().id
        }

        /// An id of another account.
        fn foreign(&self, id: &str) -> String {
            let other = if self.tag == "aaaaaa" {
                "bbbbbb"
            } else {
                "aaaaaa"
            };
            format!("{other}:{}", self.local(id))
        }

        fn local(&self, id: &str) -> String {
            id.strip_prefix(&format!("{}:", self.tag))
                .unwrap_or(id)
                .to_owned()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The mock items the table works on, with their qualified ids.
    struct Items {
        login: String,
        other: String,
        protected: String,
        passkey: String,
        note: String,
        ssh: String,
        wifi: String,
        /// An item linked to a Mac app, and the app.
        linked: (String, String),
    }

    impl Items {
        fn of(f: &Fixture) -> Self {
            let summaries = f.summaries();
            let login = summaries
                .iter()
                .find(|s| s.title == "GitHub")
                .unwrap()
                .id
                .clone();
            let linked = summaries
                .iter()
                .find_map(|s| {
                    let detail = f.session.detail(s.id.clone()).unwrap();
                    let url = detail.urls.iter().find(|u| u.starts_with("macapp://"))?;
                    Some((s.id.clone(), url["macapp://".len()..].to_owned()))
                })
                .unwrap();
            Self {
                other: summaries
                    .iter()
                    .find(|s| s.title == "Netflix")
                    .unwrap()
                    .id
                    .clone(),
                protected: f.find(|s| s.reprompt),
                passkey: summaries
                    .iter()
                    .find(|s| s.passkey_rp_id.is_some())
                    .unwrap()
                    .id
                    .clone(),
                note: f.find(|s| matches!(s.category, crate::ItemCategory::SecureNote)),
                ssh: f.find(|s| matches!(s.category, crate::ItemCategory::SshKey)),
                wifi: f.find(|s| matches!(s.template, Some(crate::ItemTemplate::Wifi))),
                login,
                linked,
            }
        }
    }

    struct Quiet;
    impl BulkProgress for Quiet {
        fn progress(&self, _: u32, _: u32) {}
    }

    /// The outcome of a call as a word: `ok` or the error's name.
    fn class<T>(result: Result<T, VerrouError>) -> String {
        match result {
            Ok(_) => "ok".to_owned(),
            Err(error) => format!("{error:?}")
                .split([' ', '{', '('])
                .next()
                .unwrap_or_default()
                .to_owned(),
        }
    }

    fn word(accepted: bool) -> String {
        if accepted { "recognised" } else { "ignored" }.to_owned()
    }

    type Pick = fn(&Items) -> String;
    type Probe = fn(&Fixture, &Items, &tokio::runtime::Runtime, &str) -> String;

    /// One entry point: the item it works on, what it does with this
    /// account's id (qualified or not), and with another account's.
    struct Row {
        name: &'static str,
        pick: Pick,
        /// `None`: whatever it is, the same for both forms of the own id.
        own: Option<&'static str>,
        foreign: &'static str,
        probe: Probe,
    }

    const NOT_FOUND: &str = "NotFound";

    fn row(
        name: &'static str,
        pick: Pick,
        own: Option<&'static str>,
        foreign: &'static str,
        probe: Probe,
    ) -> Row {
        Row {
            name,
            pick,
            own,
            foreign,
            probe,
        }
    }

    #[allow(clippy::too_many_lines)] // one row per entry point, a table
    fn table() -> Vec<Row> {
        let login: Pick = |i| i.login.clone();
        let protected: Pick = |i| i.protected.clone();
        let passkey: Pick = |i| i.passkey.clone();
        let note: Pick = |i| i.note.clone();
        let ssh: Pick = |i| i.ssh.clone();
        let wifi: Pick = |i| i.wifi.clone();
        let linked: Pick = |i| i.linked.0.clone();
        vec![
            // lib.rs: the vault.
            row(
                "edit_draft",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.edit_draft(id.into()))),
            ),
            row(
                "update_item",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.update_item(id.into(), ItemDraft::default())))
                },
            ),
            row(
                "trash_item",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.trash_item(id.into()))),
            ),
            row(
                "restore_item",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.restore_item(id.into()))),
            ),
            row(
                "set_archived",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.set_archived(id.into(), true))),
            ),
            row(
                "set_favorite",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.set_favorite(id.into(), true))),
            ),
            row(
                "link_to_app",
                linked,
                Some("ok"),
                NOT_FOUND,
                |f, i, rt, id| {
                    class(rt.block_on(f.session.link_to_app(id.into(), i.linked.1.clone())))
                },
            ),
            row("detail", login, Some("ok"), NOT_FOUND, |f, _, _, id| {
                class(f.session.detail(id.into()))
            }),
            row("reveal", login, Some("ok"), NOT_FOUND, |f, _, _, id| {
                class(f.session.reveal(id.into(), "password".into()))
            }),
            row("totp", login, Some("ok"), NOT_FOUND, |f, _, _, id| {
                class(f.session.totp(id.into(), 59))
            }),
            row(
                "autofill_keystrokes",
                login,
                Some("ok"),
                NOT_FOUND,
                |f, _, _, id| class(f.session.autofill_keystrokes(id.into(), false, false)),
            ),
            row(
                "autofill_password",
                login,
                Some("ok"),
                NOT_FOUND,
                |f, _, _, id| class(f.session.autofill_password(id.into())),
            ),
            row(
                "wifi_qr_code",
                wifi,
                Some("ok"),
                NOT_FOUND,
                |f, _, _, id| class(f.session.wifi_qr_code(id.into())),
            ),
            row(
                "passkey_registration",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(
                        rt.block_on(f.session.passkey_registration(PasskeyCreationRequest {
                            rp_id: "exemple.fr".into(),
                            user_name: "camille".into(),
                            user_handle: vec![1; 16],
                            client_data_hash: vec![0; 32],
                            user_verified: true,
                            item_id: Some(id.into()),
                            excluded_credentials: Vec::new(),
                        })),
                    )
                },
            ),
            row(
                "prepare_passkey_upgrade",
                login,
                None,
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.prepare_passkey_upgrade(id.into()))),
            ),
            row(
                "share_item",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.share_item(id.into(), "org".into(), Vec::new())))
                },
            ),
            row(
                "set_item_collections",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.set_item_collections(id.into(), Vec::new())))
                },
            ),
            row(
                "delete_passkey",
                passkey,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.delete_passkey(id.into(), "x".into()))),
            ),
            row(
                "passkey_setup_page",
                note,
                Some("Invalid"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.passkey_setup_page(id.into()))),
            ),
            row(
                "change_password_page",
                note,
                Some("Invalid"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.change_password_page(id.into()))),
            ),
            // attachments.rs
            row(
                "attachments",
                login,
                Some("ok"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.attachments(id.into()))),
            ),
            row(
                "download_attachment",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.download_attachment(id.into(), "a".into())))
                },
            ),
            row(
                "add_attachment",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.add_attachment(id.into(), "f".into(), vec![1])))
                },
            ),
            row(
                "delete_attachment",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.delete_attachment(id.into(), "a".into())))
                },
            ),
            // bulk.rs, sharing.rs, import.rs: lists, one foreign id refuses all.
            row(
                "bulk_action",
                login,
                Some("Invalid"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.bulk_action(
                        vec![id.into()],
                        BulkItemAction::Archive,
                        Box::new(Quiet),
                    )))
                },
            ),
            row(
                "bulk_action (foreign last)",
                login,
                Some("Invalid"),
                NOT_FOUND,
                |f, i, rt, id| {
                    class(rt.block_on(f.session.bulk_action(
                        vec![i.other.clone(), id.into()],
                        BulkItemAction::Archive,
                        Box::new(Quiet),
                    )))
                },
            ),
            row(
                "trash_items",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| class(rt.block_on(f.session.trash_items(vec![id.into()]))),
            ),
            row(
                "merge_duplicates (keep)",
                login,
                Some("Invalid"),
                NOT_FOUND,
                |f, i, rt, id| {
                    class(rt.block_on(f.session.merge_duplicates(id.into(), vec![i.other.clone()])))
                },
            ),
            row(
                "merge_duplicates (others)",
                login,
                Some("Invalid"),
                NOT_FOUND,
                |f, i, rt, id| {
                    class(rt.block_on(f.session.merge_duplicates(i.other.clone(), vec![id.into()])))
                },
            ),
            row("share_items", login, None, NOT_FOUND, |f, _, rt, id| {
                class(rt.block_on(f.session.share_items(
                    vec![id.into()],
                    "org".into(),
                    Vec::new(),
                    Box::new(Quiet),
                )))
            }),
            row("unshare_items", login, None, NOT_FOUND, |f, _, rt, id| {
                class(rt.block_on(f.session.unshare_items(vec![id.into()], Box::new(Quiet))))
            }),
            // send.rs
            row(
                "send_fields_for_attachment",
                login,
                Some("Locked"),
                NOT_FOUND,
                |f, _, rt, id| {
                    class(rt.block_on(f.session.send_fields_for_attachment(id.into(), "a".into())))
                },
            ),
            row(
                "create_send_from_attachment",
                login,
                None,
                NOT_FOUND,
                |f, _, rt, id| {
                    let fields = SendFields {
                        name: "n".into(),
                        text: String::new(),
                        hidden: false,
                        notes: None,
                        deletion_date: 4_000_000_000,
                        expiration_date: None,
                        max_access_count: None,
                        password: None,
                        hide_email: false,
                        disabled: false,
                    };
                    class(rt.block_on(f.session.create_send_from_attachment(
                        fields,
                        id.into(),
                        "a".into(),
                    )))
                },
            ),
            row(
                "send_fields_for_field",
                login,
                Some("ok"),
                NOT_FOUND,
                |f, _, _, id| {
                    class(
                        f.session
                            .send_fields_for_field(id.into(), "password".into()),
                    )
                },
            ),
            // preferences.rs
            row(
                "set_ssh_approval_scope",
                ssh,
                Some("ok"),
                NOT_FOUND,
                |f, _, _, id| {
                    class(
                        f.session
                            .set_ssh_approval_scope(id.into(), SshApprovalScope::UntilLocked),
                    )
                },
            ),
            // Entry points that cannot fail: foreign is ignored, never answered.
            row(
                "ssh_approval_scope",
                ssh,
                Some("UntilLocked"),
                "FiveMinutes",
                |f, i, _, id| {
                    f.session
                        .set_ssh_approval_scope(i.ssh.clone(), SshApprovalScope::UntilLocked)
                        .unwrap();
                    format!("{:?}", f.session.ssh_approval_scope(id.into()))
                },
            ),
            row(
                "record_item_use",
                login,
                Some("true"),
                "false",
                |f, i, _, id| {
                    f.session.record_item_use(id.into());
                    let used = f.summaries().into_iter().find(|s| s.id == i.login);
                    format!("{}", used.unwrap().last_used.is_some())
                },
            ),
            row(
                "needs_confirmation",
                protected,
                Some("true"),
                // Fails closed: another account's item needs a confirmation.
                "true",
                |f, _, _, id| format!("{}", f.session.needs_confirmation(id.into())),
            ),
            row(
                "authorize_item",
                protected,
                Some("false"),
                "true",
                |f, i, _, id| {
                    f.session.authorize_item(id.into());
                    format!("{}", f.session.needs_confirmation(i.protected.clone()))
                },
            ),
            row(
                "is_linked_to_app",
                linked,
                Some("true"),
                "false",
                |f, i, _, id| {
                    format!(
                        "{}",
                        f.session.is_linked_to_app(id.into(), i.linked.1.clone())
                    )
                },
            ),
            row("passkeys", passkey, Some("true"), "false", |f, _, _, id| {
                format!("{}", !f.session.passkeys(id.into()).is_empty())
            }),
            row(
                "resolve_item_id",
                login,
                Some("qualified"),
                "unchanged",
                |f, i, _, id| {
                    let resolved = f.session.resolve_item_id(id.into());
                    if resolved == i.login {
                        "qualified".to_owned()
                    } else if resolved == id {
                        "unchanged".to_owned()
                    } else {
                        format!("other: {resolved}")
                    }
                },
            ),
            row(
                "still_breached",
                login,
                Some("recognised"),
                "ignored",
                |f, i, _, id| {
                    let local = f.local(&i.login);
                    let password = f
                        .session
                        .reveal(i.login.clone(), "password".into())
                        .unwrap();
                    let mut summary = f.summaries().into_iter().find(|s| s.id == i.login).unwrap();
                    let found = vec![BreachedPassword {
                        item: summary.clone(),
                        count: 3,
                    }];
                    f.session
                        .remember_breached(&[(local, SecretString::new(password))], &found);
                    summary.id = id.to_owned();
                    word(
                        !f.session
                            .still_breached(vec![BreachedPassword {
                                item: summary,
                                count: 3,
                            }])
                            .is_empty(),
                    )
                },
            ),
        ]
    }

    #[test]
    fn every_entry_point_checks_the_tag_of_the_id_it_takes() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let rows = table();
        for row in &rows {
            let outcome = |form: &dyn Fn(&Fixture, &str) -> String| {
                let fixture = Fixture::new();
                let items = Items::of(&fixture);
                let id = form(&fixture, &(row.pick)(&items));
                (row.probe)(&fixture, &items, &runtime, &id)
            };
            let qualified = outcome(&|_, id| id.to_owned());
            let unqualified = outcome(&|f, id| f.local(id));
            let foreign = outcome(&|f, id| f.foreign(id));
            assert_eq!(
                foreign, row.foreign,
                "{}: an id of another account must fail closed",
                row.name
            );
            assert_ne!(qualified, NOT_FOUND, "{}: its own qualified id", row.name);
            assert_eq!(
                unqualified, qualified,
                "{}: an unqualified id is the session's own",
                row.name
            );
            if let Some(expected) = row.own {
                assert_eq!(qualified, expected, "{}: its own id", row.name);
            }
        }
        // Each id-taking entry point of the FFI is in the table (a new one
        // must be added here: see the list in `ids.rs`'s header).
        assert!(rows.len() >= 40, "{} rows", rows.len());
    }

    /// Entry points that take a parameter called `id` (and the like) that is
    /// not an item id, with what it is.
    const NOT_ITEM_IDS: &[(&str, &str)] = &[
        ("remove_security_key", "credential id"),
        ("answer_bridge_pairing", "pairing request"),
        ("answer_bridge_confirmation", "approval request"),
        ("revoke_bridge_client", "bridge client"),
        ("send_link", "Send"),
        ("send_fields", "Send"),
        ("update_send", "Send"),
        ("delete_send", "Send"),
        ("remove_send_password", "Send"),
        ("delete_organization_group", "organization group"),
        ("save_organization_group", "organization group"),
        (
            "conditional_passkey_registration",
            "the request's item id is not read: the one-use ticket names the item",
        ),
    ];

    /// Parameter names that carry an item id.
    const ID_PARAMS: &[&str] = &[
        "id", "ids", "item", "items", "item_id", "item_ids", "keep", "others", "target", "uuid",
    ];

    /// Records that carry an item id: an exported function taking one is an
    /// entry point that takes an item id.
    const ID_RECORDS: &[&str] = &[
        "PasskeyCreationRequest",
        "BreachedPassword",
        "ItemSummary",
        "SearchHit",
        "OtpTarget",
        "AutofillIdentity",
        "AutofillPasskey",
        "PasskeyAssertionResult",
        "PasskeyRegistrationResult",
        "WeakPassword",
        "DuplicateMemberView",
        "SignalFinding",
        "ExpiringCard",
        "OldPassword",
        "MissingTwoFactor",
        "PasskeyCandidate",
    ];

    /// `source` without its `#[cfg(test)]` items (module, function, use):
    /// the attribute, then the item up to its `;` or its matching `}`.
    fn without_test_items(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut out = String::new();
        let mut at = 0;
        while let Some(found) = source[at..].find("#[cfg(test)]") {
            let start = at + found;
            out.push_str(&source[at..start]);
            at = skip_item(bytes, start + "#[cfg(test)]".len());
        }
        out.push_str(&source[at..]);
        out
    }

    /// The index just after the item that starts at `from`.
    fn skip_item(b: &[u8], from: usize) -> usize {
        let mut i = from;
        let mut depth = 0i32; // () and [] before the body
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'"' => i = skip_string(b, i),
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => return i + 1,
                b'{' if depth == 0 => return skip_braces(b, i),
                _ => {}
            }
            i += 1;
        }
        b.len()
    }

    /// The index just after the `}` matching the `{` at `open`.
    fn skip_braces(b: &[u8], open: usize) -> usize {
        let mut depth = 0i32;
        let mut i = open;
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'"' => i = skip_string(b, i),
                // A character literal (`'{'`, `'\n'`), not a lifetime.
                b'\'' => {
                    if b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'') {
                        i += 3;
                    } else if b.get(i + 2) == Some(&b'\'') {
                        i += 2;
                    }
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        b.len()
    }

    /// The index of the closing quote of the string opened at `open` (raw
    /// strings included).
    fn skip_string(b: &[u8], open: usize) -> usize {
        let mut hashes = 0;
        let mut k = open;
        while k > 0 && b[k - 1] == b'#' {
            hashes += 1;
            k -= 1;
        }
        let raw = k > 0 && b[k - 1] == b'r';
        let mut i = open + 1;
        while i < b.len() {
            if raw {
                if b[i] == b'"' && b[i + 1..].iter().take(hashes).all(|c| *c == b'#') {
                    return i + hashes;
                }
            } else if b[i] == b'\\' {
                i += 1;
            } else if b[i] == b'"' {
                return i;
            }
            i += 1;
        }
        b.len()
    }

    /// The exported functions of a source (outside the test items) that
    /// take an item id, by name.
    fn id_taking_fns(source: &str) -> Vec<String> {
        let code = without_test_items(source);
        let mut found = Vec::new();
        for (at, _) in code
            .match_indices("pub fn ")
            .chain(code.match_indices("pub async fn "))
        {
            let after = &code[at..];
            let Some(open) = after.find('(') else {
                continue;
            };
            let name = after[..open].rsplit(' ').next().unwrap_or_default();
            // Parameters up to the matching parenthesis, split at the
            // commas outside `<>`, `()` and `[]`.
            let (mut depth, mut params, mut current) = (0i32, Vec::new(), String::new());
            for c in after[open + 1..].chars() {
                match c {
                    '(' | '<' | '[' => depth += 1,
                    ')' | '>' | ']' if depth > 0 => depth -= 1,
                    ')' => break,
                    ',' if depth == 0 => {
                        params.push(std::mem::take(&mut current));
                        continue;
                    }
                    _ => {}
                }
                current.push(c);
            }
            params.push(current);
            let takes_id = params.iter().any(|p| {
                let Some((pname, ty)) = p.split_once(':') else {
                    return false;
                };
                let (pname, ty) = (pname.trim(), ty.trim());
                let bare = ty
                    .trim_start_matches('&')
                    .trim_start_matches("Vec<")
                    .trim_start_matches("Option<")
                    .trim_end_matches('>');
                (ID_PARAMS.contains(&pname)
                    && ["String", "Option<String>", "Vec<String>", "&str"].contains(&ty))
                    || ID_RECORDS.contains(&bare)
            });
            if takes_id {
                found.push(name.to_owned());
            }
        }
        found
    }

    #[test]
    fn the_scan_finds_a_function_after_a_test_module_and_skips_test_items() {
        let source = r#"
            pub fn before(&self, id: String) {}
            #[cfg(test)]
            mod tests {
                fn helper() { let c = '{'; let s = "}"; }
                pub fn in_tests(&self, id: String) {}
            }
            #[cfg(test)]
            fn only_in_tests(id: String, pairs: [u8; 4]) { if true { } }
            pub async fn after_the_module(&self, target: Option<String>) {}
            pub fn by_record(&self, request: PasskeyCreationRequest) {}
            pub fn by_list(&self, found: Vec<BreachedPassword>) {}
            pub fn by_str(&self, uuid: &str) {}
            pub fn unrelated(&self, name: String, count: u32) {}
        "#;
        let mut found = id_taking_fns(source);
        found.sort();
        let mut expected = [
            "before",
            "after_the_module",
            "by_record",
            "by_list",
            "by_str",
        ]
        .map(String::from)
        .to_vec();
        expected.sort();
        assert_eq!(found, expected);
    }

    /// A new exported function that takes an item id must be added to the
    /// table, or named in `NOT_ITEM_IDS` with a reason.
    #[test]
    fn the_table_lists_every_exported_function_that_takes_an_item_id() {
        let table: Vec<&str> = table().iter().map(|r| r.name).collect();
        let covered = |name: &str| table.iter().any(|t| t.split(' ').next() == Some(name));
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut missing = Vec::new();
        let mut scanned = 0;
        for entry in std::fs::read_dir(src).unwrap() {
            let path = entry.unwrap().path();
            // The grantor's vault (`EmergencyVault`) and the emergency
            // contacts have ids of their own, outside the scheme.
            if path.extension().is_none_or(|e| e != "rs")
                || path
                    .file_name()
                    .is_some_and(|n| n == "emergency.rs" || n == "ids.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for name in id_taking_fns(&text) {
                scanned += 1;
                if !covered(&name) && !NOT_ITEM_IDS.iter().any(|(n, _)| *n == name) {
                    missing.push(format!(
                        "{} ({})",
                        name,
                        path.file_name().unwrap().to_string_lossy()
                    ));
                }
            }
        }
        assert!(scanned > 40, "the scan found only {scanned} functions");
        assert!(missing.is_empty(), "not in the ids table: {missing:?}");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one block per emitting call
    fn every_id_a_session_emits_is_qualified() {
        let f = Fixture::new();
        let items = Items::of(&f);
        let prefix = format!("{}:", f.tag);
        let mut emitted: Vec<(&str, String)> = Vec::new();
        let mut collect = |from: &'static str, ids: Vec<String>| {
            assert!(!ids.is_empty(), "{from}: nothing to check");
            emitted.extend(ids.into_iter().map(|id| (from, id)));
        };
        let summaries = f.summaries();
        collect(
            "summaries",
            summaries.iter().map(|s| s.id.clone()).collect(),
        );
        collect(
            "search",
            f.session
                .search(
                    "git".into(),
                    crate::SidebarFilter::All,
                    crate::ResultOrder::Title,
                )
                .unwrap()
                .into_iter()
                .map(|h| h.id)
                .collect(),
        );
        collect(
            "detail",
            vec![f.session.detail(items.login.clone()).unwrap().summary.id],
        );
        collect(
            "suggestions",
            f.session
                .suggestions("https://github.com/login".into())
                .unwrap()
                .into_iter()
                .map(|s| s.id)
                .collect(),
        );
        collect(
            "app_suggestions",
            f.session
                .app_suggestions(items.linked.1.clone())
                .unwrap()
                .into_iter()
                .map(|s| s.id)
                .collect(),
        );
        collect(
            "autofill_identities",
            f.session
                .autofill_identities()
                .unwrap()
                .into_iter()
                .map(|i| i.item_id)
                .collect(),
        );
        collect(
            "autofill_matches",
            f.session
                .autofill_matches(vec!["github.com".into()])
                .unwrap()
                .into_iter()
                .map(|s| s.id)
                .collect(),
        );
        collect(
            "autofill_passkeys",
            f.session
                .autofill_passkeys(
                    summaries
                        .iter()
                        .find_map(|s| s.passkey_rp_id.clone())
                        .unwrap(),
                    Vec::new(),
                )
                .unwrap()
                .into_iter()
                .map(|p| p.item_id)
                .collect(),
        );
        collect(
            "autofill_passkey_targets",
            f.session
                .autofill_passkey_targets("github.com".into())
                .unwrap()
                .into_iter()
                .map(|s| s.id)
                .collect(),
        );
        let audit = f.session.audit().unwrap();
        collect(
            "audit",
            audit
                .reused
                .into_iter()
                .flatten()
                .chain(audit.weak.into_iter().map(|w| w.item))
                .chain(audit.insecure)
                .map(|s| s.id)
                .collect(),
        );
        let watchtower = f.session.watchtower().unwrap();
        collect(
            "watchtower",
            watchtower
                .cards
                .into_iter()
                .map(|c| c.item.id)
                .chain(watchtower.old.into_iter().map(|o| o.item.id))
                .collect(),
        );
        collect(
            "scan_otp",
            f.session
                .scan_otp(
                    "otpauth://totp/Netflix:camille?secret=JBSWY3DPEHPK3PXP&issuer=Netflix".into(),
                    59,
                )
                .unwrap()
                .accounts
                .into_iter()
                .flat_map(|a| a.matches)
                .map(|m| m.id)
                .collect(),
        );
        // The emitters that need no network. `duplicates()` itself reads the
        // attachment counts from the connection: its grouping is exercised
        // here on the mock's duplicate items.
        collect(
            "duplicates",
            f.session
                .duplicate_groups(
                    &verrou_core::mock::duplicate_items(MockLanguage::English.into()),
                    &std::collections::HashMap::new(),
                )
                .into_iter()
                .flat_map(|g| g.members)
                .map(|m| m.item.id)
                .collect(),
        );
        let github = f
            .session
            .autofill_identities()
            .unwrap()
            .into_iter()
            .find(|i| i.item_id == items.login && i.kind == crate::AutofillIdentityKind::Password)
            .unwrap();
        f.session
            .record_credential_signal(crate::signals::CredentialSignal::UnusedPassword {
                domain: github.service.clone(),
                user_name: github.user.clone(),
            })
            .unwrap();
        collect(
            "credential_signal_findings",
            f.session
                .credential_signal_findings()
                .unwrap()
                .into_iter()
                .map(|s| s.item.id)
                .collect(),
        );
        let password = f
            .session
            .reveal(items.login.clone(), "password".into())
            .unwrap();
        let candidates = vec![(f.local(&items.login), SecretString::new(password))];
        let breached = f
            .session
            .with_vault(|v| Ok(f.session.breached_passwords(v, &candidates, [7])))
            .unwrap();
        collect(
            "breached_passwords",
            breached.iter().map(|b| b.item.id.clone()).collect(),
        );
        f.session.remember_breached(&candidates, &breached);
        collect(
            "still_breached",
            f.session
                .still_breached(breached)
                .into_iter()
                .map(|b| b.item.id)
                .collect(),
        );
        // Expiring cards: far enough ahead that the mock's cards have all
        // expired.
        let report = f.session.watchtower_at(4_000_000_000).unwrap();
        collect(
            "expiring_cards",
            report.cards.into_iter().map(|c| c.item.id).collect(),
        );
        // A directory listing every site the mock's items have a URL on.
        let sites: Vec<String> = summaries
            .iter()
            .flat_map(|s| f.session.detail(s.id.clone()).unwrap().urls)
            .filter_map(|u| {
                let rest = u.strip_prefix("https://")?;
                Some(rest.split('/').next()?.to_owned())
            })
            .map(|host| format!(r#"["{host}", {{"domain": "{host}", "tfa": ["totp"]}}]"#))
            .collect();
        let two_factor = verrou_core::watchtower::TwoFactorDirectory::parse(
            format!("[{}]", sites.join(",")).as_bytes(),
        )
        .unwrap();
        collect(
            "missing_two_factor",
            f.session
                .with_vault(|v| {
                    Ok(crate::watchtower::missing_two_factor(
                        &f.session,
                        v,
                        &two_factor,
                    ))
                })
                .unwrap()
                .into_iter()
                .map(|m| m.item.id)
                .collect(),
        );
        let passkeys = verrou_core::passkey_upgrade::PasskeyDirectory::parse(
            verrou_core::mock::PASSKEY_DIRECTORY.as_bytes(),
        )
        .unwrap();
        collect(
            "passkey_candidates",
            f.session
                .with_vault(|v| {
                    Ok(crate::watchtower::passkey_candidates(
                        &f.session, v, &passkeys,
                    ))
                })
                .unwrap()
                .into_iter()
                .map(|c| c.item.id)
                .collect(),
        );
        collect(
            "resolve_item_id",
            vec![f.session.resolve_item_id(items.login.clone())],
        );
        collect(
            "resolve_item_id (unqualified)",
            vec![f.session.resolve_item_id(f.local(&items.login))],
        );
        for (from, id) in &emitted {
            assert!(
                id.starts_with(&prefix) && !id[prefix.len()..].contains(&prefix),
                "{from}: {id}"
            );
        }
        // What was emitted comes back in as it is.
        let sample = &emitted[0].1;
        assert!(f.session.detail(sample.clone()).is_ok());
    }

    #[test]
    fn id_changes_are_reported_qualified() {
        let f = Fixture::new();
        // The sync report's `remapped` and the unshare result's `moved`.
        let mappings = f
            .session
            .id_mappings([("tmp-1".to_owned(), "srv-1".to_owned())]);
        assert_eq!(
            mappings,
            [crate::IdMapping {
                temporary: format!("{}:tmp-1", f.tag),
                server: format!("{}:srv-1", f.tag),
            }]
        );
        assert_eq!(f.session.id_mappings(Vec::new()).len(), 0);
        // A session outside the registry: plain ids.
        let plain = VaultSession::new();
        assert_eq!(
            plain.id_mappings([("a".to_owned(), "b".to_owned())])[0].server,
            "b"
        );
    }

    #[test]
    fn confirmations_qualify_only_real_item_ids() {
        use verrou_bridge::Purpose;
        let q = |id: &str| format!("k3f7qa:{id}");
        let shown = |purpose, item: &str| crate::shown_item(purpose, item, &q);
        assert_eq!(shown(Purpose::Reveal, "abc"), "k3f7qa:abc");
        assert_eq!(shown(Purpose::Ssh, "abc"), "k3f7qa:abc");
        assert_eq!(shown(Purpose::Create, "My title"), "My title");
        // A passkey for a site without a login stays `passkey:<site>`.
        assert_eq!(
            shown(Purpose::Passkey, "passkey:github.com"),
            "passkey:github.com"
        );
        assert_eq!(shown(Purpose::Passkey, "abc"), "k3f7qa:abc");
        // A site link names the item and the host: only the id is qualified.
        assert_eq!(
            shown(Purpose::LinkSite, "abc github.com"),
            "k3f7qa:abc github.com"
        );
    }

    #[test]
    fn a_foreign_item_needs_a_confirmation() {
        let f = Fixture::new();
        let items = Items::of(&f);
        assert!(f.session.needs_confirmation(f.foreign(&items.login)));
        // Its own unprotected item, and an unknown one, do not.
        assert!(!f.session.needs_confirmation(items.login.clone()));
        assert!(!f.session.needs_confirmation(format!("{}:nope", f.tag)));
    }

    #[test]
    fn ids_taken_back_after_a_lock_and_unlock_stay_valid() {
        let f = Fixture::new();
        let id = Items::of(&f).login;
        f.session.lock();
        f.session.unlock_mock(0, 42, MockLanguage::English);
        assert!(f.session.detail(id).is_ok(), "same vault, same ids");
    }

    #[test]
    fn a_session_outside_the_registry_keeps_plain_ids() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42, MockLanguage::English);
        let id = session.summaries().unwrap()[0].id.clone();
        assert!(!id.contains(':'));
        assert!(session.detail(id.clone()).is_ok());
        assert_eq!(session.resolve_item_id(id.clone()), id);
    }
}
