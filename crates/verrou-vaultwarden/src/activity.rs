//! What is new for the account since last time: enough to post a local
//! notification (never a remote notification service), without secrets.
//!
//! Sources, and what they need:
//! - **the sync response** (vault cache), without a key: the confirmed
//!   organizations and their name (the server sends them in clear), the
//!   accepted memberships waiting for confirmation
//!   (`profile.organizationsNew`), the item ids and their organization.
//!   Nothing in it is decrypted;
//! - **the server**, vault unlocked (access token): the members waiting for
//!   an administrator's confirmation, the emergency access requests and
//!   grants.
//!
//! What Vaultwarden 1.37 doesn't show: an invitation not accepted yet
//! ("Invited" state). The invitee's sync lists it nowhere
//! (`organizations`: confirmed; `organizationsNew`: accepted and
//! confirmed), and no route returns it to the invitee. Only the email
//! carries it.
//!
//! So as not to repeat anything, a per-account set of "already seen"
//! (`activity.json`, ids only, never a name or a secret) survives
//! relaunches; it is erased at logout. The first observation of an account
//! reports nothing: it serves as a starting point (the app's banners
//! already show the current state).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::emergency::{EmergencyOverview, EmergencyStatus};
use crate::{Error, Store};

const ACTIVITY_FILE: &str = "activity.json";
const ACTIVITY_VERSION: u32 = 1;

/// Read-modify-write of the file: one at a time in the process
/// (foreground sync and background task).
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// What deserves a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoticeKind {
    /// Invitation accepted: an administrator still has to confirm the
    /// account (on a server without email, it is the invitation itself).
    MembershipPending,
    /// The account was confirmed: the organization's items are readable.
    MembershipConfirmed,
    /// Members wait for this account's confirmation (administrator).
    MembersToConfirm,
    /// New items in an organization (not created by this device).
    ItemsShared,
    /// An emergency contact requests access to this account's vault.
    EmergencyRequested,
    /// Someone granted access to their vault (request approved, or wait
    /// time elapsed).
    EmergencyApproved,
}

/// A notification to post: organization names, an address, numbers. Never
/// a secret, a username or an item title (they are encrypted anyway).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Stable key (the notification's id: a new one on the same subject
    /// replaces the old one).
    pub key: String,
    pub kind: NoticeKind,
    pub organization_id: Option<String>,
    pub organization: Option<String>,
    /// New items, or members to confirm (in total).
    pub count: u32,
    /// The other person, for emergency access.
    pub email: Option<String>,
}

/// An organization seen in the sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationRef {
    pub id: String,
    pub name: String,
    /// Owner: they most likely created it themselves.
    pub owner: bool,
}

/// What a sync response says, without a key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub user_id: String,
    /// Confirmed organizations (key received).
    pub confirmed: Vec<OrganizationRef>,
    /// Accepted invitations, waiting for confirmation.
    pub pending: Vec<OrganizationRef>,
    /// Items: id, organization, in the trash.
    pub items: Vec<(String, Option<String>, bool)>,
}

impl Snapshot {
    /// Reads the raw `/api/sync` response. Encrypted fields are not read; an
    /// unreadable document gives `None`.
    pub fn from_sync(json: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct Sync {
            profile: Option<Profile>,
            #[serde(default)]
            ciphers: Vec<CipherRef>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            id: Option<String>,
            #[serde(default)]
            organizations: Vec<Membership>,
            #[serde(default)]
            organizations_new: Vec<Membership>,
        }
        #[derive(Deserialize)]
        struct Membership {
            id: Option<String>,
            name: Option<String>,
            status: Option<i64>,
            #[serde(rename = "type")]
            role: Option<i64>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CipherRef {
            id: Option<String>,
            organization_id: Option<String>,
            deleted_date: Option<String>,
        }
        let sync: Sync = serde_json::from_str(json).ok()?;
        let profile = sync.profile?;
        let organization = |m: Membership| {
            Some(OrganizationRef {
                id: m.id?,
                name: m.name.unwrap_or_else(|| "Organization".to_owned()),
                owner: m.role == Some(0),
            })
        };
        let confirmed: Vec<OrganizationRef> = profile
            .organizations
            .into_iter()
            .filter(|m| m.status.is_none_or(|s| s == 2))
            .filter_map(organization)
            .collect();
        let pending = profile
            .organizations_new
            .into_iter()
            .filter(|m| m.status == Some(1))
            .filter_map(organization)
            .collect();
        Some(Self {
            user_id: profile.id?,
            confirmed,
            pending,
            items: sync
                .ciphers
                .into_iter()
                .filter_map(|c| Some((c.id?, c.organization_id, c.deleted_date.is_some())))
                .collect(),
        })
    }
}

/// What only the server knows (vault unlocked). `None`: not asked, or not
/// reachable; what had already been seen of this category is kept.
#[derive(Clone, Debug, Default)]
pub struct Remote {
    /// Members to confirm: (organization, name, membership id).
    pub to_confirm: Option<Vec<(String, String, String)>>,
    /// Emergency access (both sides).
    pub emergency: Option<EmergencyOverview>,
}

/// The already-seen file.
#[derive(Serialize, Deserialize)]
struct SeenFile {
    version: u32,
    user_id: String,
    seen: BTreeSet<String>,
}

const ORG: &str = "org:";
const PENDING: &str = "pending:";
const ITEM: &str = "item:";
const CONFIRM: &str = "confirm:";
const EMERGENCY_REQUEST: &str = "ea-request:";
const EMERGENCY_APPROVED: &str = "ea-approved:";

/// Compares the observed state with the account's already-seen set, saves
/// the new state, and returns what is new. `own`: items created by this
/// device (not news to it). `notify` false: everything is marked seen
/// without reporting anything (right after a local write, for example).
///
/// Does nothing for a guest session (autofill extension): only the app
/// keeps this file.
pub fn observe<S: BuildHasher>(
    store: &Store,
    snapshot: &Snapshot,
    remote: &Remote,
    own: &HashSet<String, S>,
    notify: bool,
) -> Result<Vec<Notice>, Error> {
    if store.is_guest() {
        return Ok(Vec::new());
    }
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = load(store)?.filter(|f| f.user_id == snapshot.user_id);
    let first = previous.is_none();
    let seen = previous.map(|f| f.seen).unwrap_or_default();
    let (notices, current) = diff(&seen, snapshot, remote, own);
    save(
        store,
        &SeenFile {
            version: ACTIVITY_VERSION,
            user_id: snapshot.user_id.clone(),
            seen: current,
        },
    )?;
    Ok(if notify && !first {
        notices
    } else {
        Vec::new()
    })
}

/// The core of `observe`, without the file: the news, and the new
/// already-seen set.
fn diff<S: BuildHasher>(
    seen: &BTreeSet<String>,
    snapshot: &Snapshot,
    remote: &Remote,
    own: &HashSet<String, S>,
) -> (Vec<Notice>, BTreeSet<String>) {
    let mut diff = Diff {
        seen,
        current: BTreeSet::new(),
        notices: Vec::new(),
    };
    let just_confirmed = diff.memberships(snapshot);
    diff.items(snapshot, own, &just_confirmed);
    match &remote.to_confirm {
        Some(members) => diff.confirmations(members),
        None => diff.carry(CONFIRM),
    }
    if let Some(overview) = &remote.emergency {
        diff.emergency(overview);
    } else {
        diff.carry(EMERGENCY_REQUEST);
        diff.carry(EMERGENCY_APPROVED);
    }
    (diff.notices, diff.current)
}

struct Diff<'a> {
    seen: &'a BTreeSet<String>,
    current: BTreeSet<String>,
    notices: Vec<Notice>,
}

impl Diff<'_> {
    /// Records the key; returns true if it had never been seen.
    fn note(&mut self, key: String) -> bool {
        let new = !self.seen.contains(&key);
        self.current.insert(key);
        new
    }

    fn push(&mut self, key: String, kind: NoticeKind, organization: Option<&OrganizationRef>) {
        self.notices.push(Notice {
            key,
            kind,
            organization_id: organization.map(|o| o.id.clone()),
            organization: organization.map(|o| o.name.clone()),
            count: 0,
            email: None,
        });
    }

    /// Keeps the already-seen of a category that was not observed this time.
    fn carry(&mut self, prefix: &str) {
        self.current
            .extend(self.seen.iter().filter(|k| k.starts_with(prefix)).cloned());
    }

    /// Confirmed and pending memberships; returns the organizations just
    /// confirmed (their items don't make a second piece of news).
    fn memberships(&mut self, snapshot: &Snapshot) -> HashSet<String> {
        let mut just_confirmed = HashSet::new();
        for org in &snapshot.confirmed {
            // An organization the account owns: it created it.
            if self.note(format!("{ORG}{}", org.id)) && !org.owner {
                just_confirmed.insert(org.id.clone());
                let key = format!("confirmed-{}", org.id);
                self.push(key, NoticeKind::MembershipConfirmed, Some(org));
            }
        }
        for org in &snapshot.pending {
            if self.note(format!("{PENDING}{}", org.id)) {
                let key = format!("pending-{}", org.id);
                self.push(key, NoticeKind::MembershipPending, Some(org));
            }
        }
        just_confirmed
    }

    /// New organization items, counted per organization.
    fn items<S: BuildHasher>(
        &mut self,
        snapshot: &Snapshot,
        own: &HashSet<String, S>,
        just_confirmed: &HashSet<String>,
    ) {
        let organizations: BTreeMap<&str, &OrganizationRef> = snapshot
            .confirmed
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let mut shared: BTreeMap<&str, u32> = BTreeMap::new();
        for (id, organization, trashed) in &snapshot.items {
            if self.note(format!("{ITEM}{id}"))
                && !own.contains(id)
                && !trashed
                && let Some(org) = organization.as_deref()
                && organizations.contains_key(org)
                && !just_confirmed.contains(org)
            {
                *shared.entry(org).or_default() += 1;
            }
        }
        for (org, count) in shared {
            self.push(
                format!("items-{org}"),
                NoticeKind::ItemsShared,
                organizations.get(org).copied(),
            );
            if let Some(notice) = self.notices.last_mut() {
                notice.count = count;
            }
        }
    }

    /// Members to confirm: one piece of news per organization where some
    /// arrive, with the total waiting.
    fn confirmations(&mut self, members: &[(String, String, String)]) {
        let mut fresh: BTreeMap<&str, &str> = BTreeMap::new();
        let mut totals: BTreeMap<&str, u32> = BTreeMap::new();
        for (org, name, member) in members {
            *totals.entry(org).or_default() += 1;
            if self.note(format!("{CONFIRM}{org}:{member}")) {
                fresh.entry(org).or_insert(name);
            }
        }
        for (org, name) in fresh {
            let organization = OrganizationRef {
                id: org.to_owned(),
                name: name.to_owned(),
                owner: false,
            };
            self.push(
                format!("confirm-{org}"),
                NoticeKind::MembersToConfirm,
                Some(&organization),
            );
            if let Some(notice) = self.notices.last_mut() {
                notice.count = totals.get(org).copied().unwrap_or(1);
            }
        }
    }

    /// Emergency access requests (I am the grantor) and granted accesses (I
    /// am the contact).
    fn emergency(&mut self, overview: &EmergencyOverview) {
        let wanted = [
            (
                &overview.trusted,
                EmergencyStatus::RecoveryInitiated,
                EMERGENCY_REQUEST,
                NoticeKind::EmergencyRequested,
                "emergency-request-",
            ),
            (
                &overview.granted,
                EmergencyStatus::RecoveryApproved,
                EMERGENCY_APPROVED,
                NoticeKind::EmergencyApproved,
                "emergency-approved-",
            ),
        ];
        for (list, status, prefix, kind, key) in wanted {
            for access in list.iter().filter(|a| a.status == status) {
                if self.note(format!("{prefix}{}", access.id)) {
                    self.push(format!("{key}{}", access.id), kind, None);
                    if let Some(notice) = self.notices.last_mut() {
                        notice.email.clone_from(&access.email);
                    }
                }
            }
        }
    }
}

fn load(store: &Store) -> Result<Option<SeenFile>, Error> {
    let path = store.dir().join(ACTIVITY_FILE);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::storage(e)),
    };
    // An unreadable file or one of another format starts from scratch.
    Ok(serde_json::from_slice::<SeenFile>(&data)
        .ok()
        .filter(|f| f.version == ACTIVITY_VERSION))
}

fn save(store: &Store, file: &SeenFile) -> Result<(), Error> {
    let data = serde_json::to_vec(file).map_err(Error::storage)?;
    store.write_private(ACTIVITY_FILE, &data)
}

/// Marks as seen items this device just created in an organization: they
/// won't be announced as shared by someone else.
pub fn acknowledge_items(store: &Store, user_id: &str, ids: &[String]) -> Result<(), Error> {
    if store.is_guest() || ids.is_empty() {
        return Ok(());
    }
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // No starting point yet: the first observation will absorb them.
    let Some(mut file) = load(store)?.filter(|f| f.user_id == user_id) else {
        return Ok(());
    };
    file.seen.extend(ids.iter().map(|id| format!("{ITEM}{id}")));
    save(store, &file)
}

/// Erases the already-seen set (logout).
pub fn forget(store: &Store) -> Result<(), Error> {
    if store.is_guest() {
        return Ok(());
    }
    match std::fs::remove_file(store.dir().join(ACTIVITY_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::storage(e)),
    }
}

/// Vault locked: what the cache alone can tell, without key or network
/// (the refresh token is encrypted by the user key). Useful when the cache
/// was refreshed without the app examining it (autofill extension, app
/// interrupted).
pub fn observe_cache(store: &Store) -> Result<Vec<Notice>, Error> {
    let Some(account) = store.load_account()? else {
        return Ok(Vec::new());
    };
    let Some(snapshot) = account.sync.as_deref().and_then(Snapshot::from_sync) else {
        return Ok(Vec::new());
    };
    observe(store, &snapshot, &Remote::default(), &HashSet::new(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emergency::{EmergencyAccess, EmergencyKind};

    fn sync(orgs: &str, new: &str, ciphers: &str) -> Snapshot {
        Snapshot::from_sync(&format!(
            r#"{{"profile":{{"id":"moi","organizations":[{orgs}],"organizationsNew":[{new}]}},
                "ciphers":[{ciphers}]}}"#
        ))
        .unwrap()
    }

    fn kinds(notices: &[Notice]) -> Vec<NoticeKind> {
        notices.iter().map(|n| n.kind).collect()
    }

    #[test]
    fn the_sync_is_read_without_any_key() {
        let snapshot = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2,"key":"4.chiffré"}"#,
            r#"{"id":"o2","name":"Club","status":1,"type":2}"#,
            r#"{"id":"c1","organizationId":"o1","name":"2.chiffré"},{"id":"c2","organizationId":null,"deletedDate":"2026-01-01"}"#,
        );
        assert_eq!(snapshot.user_id, "moi");
        assert_eq!(snapshot.confirmed[0].name, "Famille");
        assert!(!snapshot.confirmed[0].owner);
        assert_eq!(snapshot.pending[0].id, "o2");
        assert_eq!(
            snapshot.items,
            [
                ("c1".to_owned(), Some("o1".to_owned()), false),
                ("c2".to_owned(), None, true)
            ]
        );
        assert!(Snapshot::from_sync("pas du json").is_none());
    }

    #[test]
    fn invitation_then_confirmation_then_new_items() {
        let empty = BTreeSet::new();
        let own = HashSet::new();
        let remote = Remote::default();
        // Invitation accepted.
        let pending = sync(
            "",
            r#"{"id":"o1","name":"Famille","status":1,"type":2}"#,
            "",
        );
        let (notices, seen) = diff(&empty, &pending, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::MembershipPending]);
        assert_eq!(notices[0].organization.as_deref(), Some("Famille"));
        // Nothing new: nothing to say.
        let (again, seen) = diff(&seen, &pending, &remote, &own);
        assert_eq!(again, [] as [Notice; 0]);
        // Confirmed, with two items: a single piece of news.
        let confirmed = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            r#"{"id":"c1","organizationId":"o1"},{"id":"c2","organizationId":"o1"}"#,
        );
        let (notices, seen) = diff(&seen, &confirmed, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::MembershipConfirmed]);
        // Two new items, plus one created here, and one in the trash.
        let more = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            "",
            r#"{"id":"c1","organizationId":"o1"},{"id":"c2","organizationId":"o1"},
               {"id":"c3","organizationId":"o1"},{"id":"c4","organizationId":"o1"},
               {"id":"c5","organizationId":"o1"},{"id":"c6","organizationId":"o1","deletedDate":"x"},
               {"id":"c7","organizationId":null}"#,
        );
        let own: HashSet<String> = ["c5".to_owned()].into();
        let (notices, _) = diff(&seen, &more, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::ItemsShared]);
        assert_eq!(notices[0].count, 2, "c3 and c4");
    }

    #[test]
    fn an_organization_created_here_is_not_news() {
        let owned = sync(r#"{"id":"o1","name":"À moi","status":2,"type":0}"#, "", "");
        let (notices, _) = diff(
            &BTreeSet::new(),
            &owned,
            &Remote::default(),
            &HashSet::new(),
        );
        assert_eq!(notices, [] as [Notice; 0]);
    }

    #[test]
    fn members_to_confirm_count_and_carry_over() {
        let snapshot = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":0}"#,
            "",
            "",
        );
        let one = Remote {
            to_confirm: Some(vec![("o1".into(), "Famille".into(), "m1".into())]),
            emergency: None,
        };
        let (notices, seen) = diff(&BTreeSet::new(), &snapshot, &one, &HashSet::new());
        assert_eq!(kinds(&notices), [NoticeKind::MembersToConfirm]);
        assert_eq!(notices[0].count, 1);
        // Offline: the already-seen stays, nothing is repeated on return.
        let (_, seen) = diff(&seen, &snapshot, &Remote::default(), &HashSet::new());
        let (notices, seen) = diff(&seen, &snapshot, &one, &HashSet::new());
        assert_eq!(notices, [] as [Notice; 0]);
        // A second member: the news gives the total.
        let two = Remote {
            to_confirm: Some(vec![
                ("o1".into(), "Famille".into(), "m1".into()),
                ("o1".into(), "Famille".into(), "m2".into()),
            ]),
            emergency: None,
        };
        let (notices, _) = diff(&seen, &snapshot, &two, &HashSet::new());
        assert_eq!(notices[0].count, 2);
    }

    #[test]
    fn emergency_requests_and_approvals() {
        let access = |id: &str, status| EmergencyAccess {
            id: id.to_owned(),
            user_id: None,
            name: None,
            email: Some("lea@exemple.fr".to_owned()),
            kind: EmergencyKind::View,
            status,
            wait_time_days: 7,
        };
        let remote = Remote {
            to_confirm: None,
            emergency: Some(EmergencyOverview {
                trusted: vec![
                    access("e1", EmergencyStatus::RecoveryInitiated),
                    access("e2", EmergencyStatus::Confirmed),
                ],
                granted: vec![access("e3", EmergencyStatus::RecoveryApproved)],
            }),
        };
        let (notices, seen) = diff(
            &BTreeSet::new(),
            &Snapshot::default(),
            &remote,
            &HashSet::new(),
        );
        assert_eq!(
            kinds(&notices),
            [
                NoticeKind::EmergencyRequested,
                NoticeKind::EmergencyApproved
            ]
        );
        assert_eq!(notices[0].email.as_deref(), Some("lea@exemple.fr"));
        let (notices, _) = diff(&seen, &Snapshot::default(), &remote, &HashSet::new());
        assert_eq!(notices, [] as [Notice; 0]);
    }

    #[test]
    fn the_first_observation_is_silent_and_survives_relaunches() {
        let dir = std::env::temp_dir().join(format!("verrou-activity-{}", uuid::Uuid::new_v4()));
        let store = Store::new(&dir);
        let pending = sync(
            "",
            r#"{"id":"o1","name":"Famille","status":1,"type":2}"#,
            "",
        );
        let none = HashSet::new();
        assert_eq!(
            observe(
                &store,
                &Snapshot {
                    pending: vec![],
                    ..pending.clone()
                },
                &Remote::default(),
                &none,
                true
            )
            .unwrap(),
            [] as [Notice; 0]
        );
        let notices =
            observe(&Store::new(&dir), &pending, &Remote::default(), &none, true).unwrap();
        assert_eq!(kinds(&notices), [NoticeKind::MembershipPending]);
        assert_eq!(
            observe(&Store::new(&dir), &pending, &Remote::default(), &none, true).unwrap(),
            [] as [Notice; 0]
        );
        // The file only contains ids.
        let text = std::fs::read_to_string(dir.join(ACTIVITY_FILE)).unwrap();
        assert!(!text.contains("Famille"));
        // The (guest) extension doesn't touch it.
        assert_eq!(
            observe(
                &Store::new(&dir).guest(),
                &sync("", "", ""),
                &Remote::default(),
                &none,
                true
            )
            .unwrap(),
            [] as [Notice; 0]
        );
        assert!(
            std::fs::read_to_string(dir.join(ACTIVITY_FILE))
                .unwrap()
                .contains("pending:o1")
        );
        forget(&store).unwrap();
        assert!(!dir.join(ACTIVITY_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
