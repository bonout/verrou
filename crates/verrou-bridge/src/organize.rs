//! An agent reorganizes the vault: the catalog it reads, and the plan it
//! proposes for the user to review.
//!
//! **The catalog** ([`overview`], [`catalog`], [`duplicate_infos`]) is the
//! vault's index: titles, usernames, hosts, folders, flags and counts. It
//! never carries a password, a one-time code, a note, the name or value of a
//! custom field, or the path of a site: an agent that can read it learns what
//! the user has, not how to get into any of it.
//!
//! **A plan** is checked here ([`validate`]), without the network, against
//! the unlocked vault: when it is proposed, so that the user never reviews
//! an operation Verrou already knows is wrong, and again when the user
//! applies it, because the vault may have changed during the review. One
//! operation that fails a rule is refused on its own, with its reason; the
//! others go on to the review. A plan that is shaped wrong (no reason, too
//! many operations, an operation without its rationale) or has nothing valid
//! is refused whole. The rules exist so that a reorganization can never
//! silently lose anything: a merge only takes items whose password, sites,
//! one-time code, username, attachments and passkeys all survive (see
//! `verrou_vaultwarden::merge`), and an item that goes away (merged,
//! archived, trashed) is not also renamed or moved.
//!
//! What the review shows ([`CheckedOp`]) is built here too, from the vault
//! and not from the agent's words: the agent's own text (its reason, its
//! rationales, the new titles and folder names) is cleaned and shown as
//! its claim, apart from what the operation does.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use verrou_core::duplicates::{self, DuplicateGroup, ItemExtras};
use verrou_core::matching::host_of;
use verrou_core::{FieldKind, Item, ItemKind, ItemState, Vault};

use crate::protocol::{
    CatalogItem, DuplicateInfo, DuplicateMemberInfo, FolderCount, KindCount, Plan, PlanOp,
    VaultOverview, clean_text, has_hidden_characters,
};

/// Most operations in a plan.
pub const MAX_OPS: usize = 1000;
/// Longest rationale, and longest reason for a whole plan, in characters.
pub const MAX_RATIONALE: usize = 120;
/// Longest folder name and item title a plan may write.
pub const MAX_FOLDER_NAME: usize = 100;
pub const MAX_TITLE: usize = 200;
/// Most items in a page of the catalog, and the default.
pub const MAX_PAGE: u32 = 500;
pub const DEFAULT_PAGE: u32 = 200;
/// Longest text of the catalog, in characters, and the sites kept per item.
const MAX_TEXT: usize = 200;
const MAX_SITE: usize = 100;
const MAX_SITES: usize = 10;
/// What a reply of the catalog may weigh (as JSON, before it is encrypted):
/// the bridge's frames are 1 MiB at most, and encryption makes them a third
/// bigger.
const MAX_REPLY: usize = 600 * 1024;
/// Duplicate groups listed at most: more is more than anyone reviews.
const MAX_GROUPS: usize = 300;

// MARK: Catalog

/// The folder names the account has (the empty ones too, which the vault's
/// items cannot tell), the duplicate groups and the attachments of each item,
/// all of which only the app knows.
pub struct Context<'a> {
    /// The duplicate groups an agent may name in a merge: those of
    /// [`scan_duplicates`], which never compares two secrets.
    pub groups: &'a [DuplicateGroup],
    pub attachments: &'a HashMap<String, usize>,
    /// The account's folder names, one per folder (two folders may share a
    /// name: a plan then cannot tell them apart and moves nothing into them).
    pub folders: &'a [String],
    /// When each login's password last changed (Unix seconds), by item; an
    /// item missing here is dated by its creation, never by its last edit.
    pub password_dates: &'a HashMap<String, i64>,
}

/// Most distinct former passwords an item's history holds
/// (`verrou_vaultwarden::MAX_PASSWORD_HISTORY`, which a test of the app
/// crate keeps equal): a merge with more puts the rest in hidden fields.
pub const PASSWORD_HISTORY_LIMIT: usize = 5;

/// The vault's duplicate groups as an agent may see them, with what makes the
/// best item to keep: its passkeys and attachments. Two passwords, or two
/// one-time code seeds, are never compared: whether the secrets of two
/// logins are equal is not for an agent to learn by asking for the groups
/// (see [`verrou_core::duplicates::find_duplicates_blind_with`]). The review
/// and the checks of a merge read the items themselves.
#[must_use]
#[allow(clippy::implicit_hasher)] // a map built by the caller, from a cache
pub fn scan_duplicates(vault: &Vault, attachments: &HashMap<String, usize>) -> Vec<DuplicateGroup> {
    let mut extras: HashMap<String, ItemExtras> = HashMap::new();
    for passkey in vault.passkeys() {
        extras
            .entry(passkey.item.clone())
            .or_default()
            .passkey_sites
            .push(passkey.rp_id.clone());
    }
    for (id, count) in attachments {
        extras.entry(id.clone()).or_default().attachments = *count;
    }
    duplicates::find_duplicates_blind_with(vault.items(), &extras)
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Items an operation may concern: not in the trash.
fn listed(item: &Item) -> bool {
    item.state != ItemState::Trashed
}

/// The login's username (or email), the only field of an item the catalog
/// reads, and only for logins.
fn username_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Username)
        .or_else(|| item.field_of_kind(FieldKind::Email))
        .map(|f| f.value.expose())
        .filter(|u| !u.is_empty())
}

/// What the vault holds, counted.
#[must_use]
pub fn overview(vault: &Vault, folders: &[String]) -> VaultOverview {
    let passkeys: HashSet<&str> = vault.passkeys().iter().map(|p| p.item.as_str()).collect();
    let mut summary = VaultOverview::default();
    let mut kinds: BTreeMap<ItemKind, usize> = BTreeMap::new();
    let mut per_folder: BTreeMap<String, usize> = folders
        .iter()
        .map(|f| (clean_text(f, MAX_TEXT), 0))
        .collect();
    let (mut items, mut archived, mut loose) = (0, 0, 0);
    for item in vault.items().iter().filter(|i| listed(i)) {
        if item.state == ItemState::Archived {
            archived += 1;
        } else {
            items += 1;
            *kinds.entry(item.kind).or_default() += 1;
        }
        match item.folder.as_deref().filter(|f| !f.is_empty()) {
            Some(folder) => *per_folder.entry(clean_text(folder, MAX_TEXT)).or_default() += 1,
            None => loose += 1,
        }
        summary.shared += u32::from(item.shared.is_some());
        summary.protected += u32::from(item.reprompt);
        summary.with_totp += u32::from(item.has_totp());
        summary.with_passkey += u32::from(passkeys.contains(item.id.as_str()));
    }
    summary.items = count(items);
    summary.archived = count(archived);
    summary.without_folder = count(loose);
    summary.kinds = kinds
        .into_iter()
        .map(|(kind, n)| KindCount {
            kind,
            count: count(n),
        })
        .collect();
    summary.folders = per_folder
        .into_iter()
        .map(|(name, n)| FolderCount {
            name,
            count: count(n),
        })
        .collect();
    summary
}

/// The sites of an item as the catalog tells them: the host of a website,
/// the identifier of an application, nothing else (no scheme, port, path,
/// query or fragment: those can carry tokens). A value that is not an address
/// (no scheme, no dot: something typed in the wrong field, maybe a secret) is
/// left out.
fn sites_of(item: &Item) -> Vec<String> {
    let mut sites: Vec<String> = Vec::new();
    for url in &item.urls {
        let site = if verrou_core::apps::is_app_uri(url) {
            // The application's identifier: what follows its first slash is
            // a path.
            let url = url.trim();
            let start = url.find("://").map_or(0, |i| i + 3);
            let end = url[start..]
                .find(['/', '?', '#'])
                .map_or(url.len(), |i| start + i);
            Some(url[..end].to_owned())
        } else if url.contains("://") || url.contains('.') {
            host_of(url)
        } else {
            None
        };
        if let Some(site) = site.map(|s| clean_text(&s, MAX_SITE))
            && !site.is_empty()
            && !sites.contains(&site)
        {
            sites.push(site);
        }
        if sites.len() == MAX_SITES {
            break;
        }
    }
    sites
}

fn catalog_item(
    item: &Item,
    passkeys: &HashSet<&str>,
    attachments: &HashMap<String, usize>,
) -> CatalogItem {
    CatalogItem {
        id: item.id.clone(),
        kind: item.kind,
        title: clean_text(&item.title, MAX_TEXT),
        username: (item.kind == ItemKind::Login)
            .then(|| username_of(item).map(|u| clean_text(u, MAX_TEXT)))
            .flatten(),
        sites: sites_of(item),
        folder: item
            .folder
            .as_deref()
            .filter(|f| !f.is_empty())
            .map(|f| clean_text(f, MAX_TEXT)),
        favorite: item.favorite,
        state: if item.state == ItemState::Archived {
            "archived"
        } else {
            "active"
        }
        .to_owned(),
        shared: item
            .shared
            .as_ref()
            .map(|s| clean_text(&s.organization, MAX_TEXT)),
        read_only: !item.is_writable(),
        protected: item.reprompt,
        has_totp: item.has_totp(),
        has_passkey: passkeys.contains(item.id.as_str()),
        attachments: count(attachments.get(&item.id).copied().unwrap_or(0)),
        has_notes: item.notes.as_ref().is_some_and(|n| !n.is_empty()),
        created: item.created,
        modified: item.modified,
    }
}

/// A page of the catalog: the items after `offset` (title order, then
/// identifier, so that pages follow one another), at most `limit` and as
/// many as a reply may weigh; and how many items there are in all.
/// `archived`: the archive too. The trash never.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn catalog(
    vault: &Vault,
    attachments: &HashMap<String, usize>,
    offset: u32,
    limit: Option<u32>,
    archived: bool,
) -> (Vec<CatalogItem>, usize) {
    let passkeys: HashSet<&str> = vault.passkeys().iter().map(|p| p.item.as_str()).collect();
    let mut shown: Vec<&Item> = vault
        .items()
        .iter()
        .filter(|i| match i.state {
            ItemState::Active => true,
            ItemState::Archived => archived,
            ItemState::Trashed => false,
        })
        .collect();
    shown.sort_by_cached_key(|i| (i.title.to_lowercase(), i.id.clone()));
    let total = shown.len();
    let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize;
    let mut page: Vec<CatalogItem> = shown
        .into_iter()
        .skip(offset as usize)
        .take(limit)
        .map(|item| catalog_item(item, &passkeys, attachments))
        .collect();
    fit(&mut page);
    (page, total)
}

/// Drops items from the end until the page fits a reply.
fn fit<T: serde::Serialize>(page: &mut Vec<T>) {
    while page.len() > 1 && serde_json::to_vec(page).map_or(0, |v| v.len()) > MAX_REPLY {
        let keep = page.len() - page.len().div_ceil(8);
        page.truncate(keep);
    }
}

/// The logins' duplicate groups for the agent, the most certain first, and
/// how many there are. Groups of cards or notes are left out: a plan can
/// only merge logins.
#[must_use]
pub fn duplicate_infos(groups: &[DuplicateGroup], vault: &Vault) -> (Vec<DuplicateInfo>, usize) {
    let mut infos: Vec<DuplicateInfo> = groups
        .iter()
        .filter(|g| g.mergeable)
        .filter_map(|g| {
            let members = g
                .members
                .iter()
                .map(|m| {
                    Some(DuplicateMemberInfo {
                        item: m.id.clone(),
                        title: clean_text(&vault.get(&m.id)?.title, MAX_TEXT),
                        confidence: m.confidence.map(|c| confidence_name(c).to_owned()),
                        reason: clean_text(&m.reason, MAX_TEXT),
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some(DuplicateInfo {
                group: g.key.clone(),
                label: clean_text(&g.label, MAX_TEXT),
                username: clean_text(&g.username, MAX_TEXT),
                confidence: confidence_name(g.confidence).to_owned(),
                reason: clean_text(&g.reason, MAX_TEXT),
                mergeable: g.mergeable,
                suggested_keep: g.kept().to_owned(),
                members,
            })
        })
        .collect();
    let total = infos.len();
    infos.truncate(MAX_GROUPS);
    fit(&mut infos);
    (infos, total)
}

fn confidence_name(confidence: duplicates::Confidence) -> &'static str {
    match confidence {
        duplicates::Confidence::Certain => "certain",
        duplicates::Confidence::Probable => "probable",
        duplicates::Confidence::Review => "review",
    }
}

// MARK: Plans

/// What the user should know about an operation before they check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flag {
    /// The item asks for confirmation before it releases a secret: its
    /// operation is not checked by default.
    Protected,
    /// The item belongs to an organization.
    Shared,
    /// A merge of items whose passwords differ (the others' go to history).
    DifferentPasswords,
    /// A merge into another item than the one Verrou would keep.
    KeepDiffersFromSuggestion,
    /// A merge of items with different usernames: maybe two accounts. Not
    /// checked by default.
    DifferentUsernames,
    /// A merge of items with different one-time code seeds: the kept item
    /// keeps its own, the others become fields.
    OtherTotp,
    /// A merge with more different passwords than a history holds: the ones
    /// that do not fit become hidden fields of the kept item.
    PasswordsAsFields,
}

/// What the review shows of an operation, from the vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Display {
    /// The item concerned (the kept item of a merge), or the new folder.
    pub title: String,
    /// The new title, the destination folder (empty: no folder).
    pub detail: String,
    /// The old title, the current folder (empty: none).
    pub from: String,
    /// A merge: the titles of the items that go to the trash.
    pub members: Vec<String>,
    /// A merge: the title of the item whose password becomes the current one,
    /// when it is not the kept item's (empty: the kept item's stays).
    pub password_from: String,
}

/// An operation that passed the rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedOp {
    /// Position in the plan, from 0.
    pub index: usize,
    /// As it will be carried out: names trimmed, rationale cleaned.
    pub op: PlanOp,
    /// What the agent said about it, cleaned.
    pub rationale: String,
    pub flags: Vec<Flag>,
    /// A move into a folder the plan creates: that operation.
    pub depends_on: Option<usize>,
    pub display: Display,
    /// A merge: the items that go to the trash, once their data is carried
    /// over to the kept one.
    pub others: Vec<String>,
}

impl CheckedOp {
    /// Checked when the review opens. The trash is never checked for the
    /// user: moving to the trash is the one thing an agent proposes that
    /// hides data. Neither is what changes an organization's items (merge,
    /// archive, trash: it concerns the other members), a protected item's
    /// operation, nor a merge of items that may be two accounts.
    #[must_use]
    pub fn default_on(&self) -> bool {
        if matches!(self.op, PlanOp::Trash { .. }) {
            return false;
        }
        if self.flags.contains(&Flag::Shared)
            && matches!(self.op, PlanOp::Merge { .. } | PlanOp::Archive { .. })
        {
            return false;
        }
        !self
            .flags
            .iter()
            .any(|f| matches!(f, Flag::Protected | Flag::DifferentUsernames))
    }
}

/// An operation Verrou refused, with the words to say so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub index: usize,
    /// What it was ("rename “Old”"), for the review.
    pub what: String,
    pub reason: String,
}

/// The outcome of the rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    pub ops: Vec<CheckedOp>,
    pub refused: Vec<Refused>,
    /// Operations that would change nothing, left out.
    pub unchanged: usize,
}

/// What a backend is asked to show the user: a plan to review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanReview {
    pub id: String,
    /// The client's identifier and the name it announced, cleaned.
    pub client: String,
    pub client_name: String,
    /// The agent's reason for the whole plan, cleaned.
    pub reason: String,
    pub ops: Vec<CheckedOp>,
    pub refused: Vec<Refused>,
    /// Seconds the user has to review it.
    pub expires_in: u64,
}

/// The plan's shape: refused whole if it has no reason, none or too many
/// operations, or an operation without its rationale. An agent that cannot
/// say why it wants something does not get the user's attention for it.
pub fn check_shape(plan: &Plan) -> Result<(), String> {
    let reason = clean_text(&plan.reason, usize::MAX);
    if reason.is_empty() {
        return Err("the plan's reason is required: say in one sentence what it is for".to_owned());
    }
    if reason.chars().count() > MAX_RATIONALE {
        return Err(format!(
            "the plan's reason is too long (at most {MAX_RATIONALE} characters)"
        ));
    }
    if plan.operations.is_empty() {
        return Err("the plan has no operation".to_owned());
    }
    if plan.operations.len() > MAX_OPS {
        return Err(format!(
            "a plan has at most {MAX_OPS} operations: propose the rest in another plan once the user has reviewed this one"
        ));
    }
    for (index, op) in plan.operations.iter().enumerate() {
        if *op == PlanOp::Unsupported {
            continue;
        }
        let rationale = clean_text(op.rationale(), usize::MAX);
        if rationale.is_empty() {
            return Err(format!(
                "operation {index}: a rationale is required: say in a few words why this one"
            ));
        }
        if rationale.chars().count() > MAX_RATIONALE {
            return Err(format!(
                "operation {index}: the rationale is too long (at most {MAX_RATIONALE} characters)"
            ));
        }
    }
    Ok(())
}

/// Checks a plan against the vault: [`check_shape`], then each operation.
/// `Err`: the plan is refused whole.
pub fn validate(plan: &Plan, vault: &Vault, context: &Context<'_>) -> Result<Checked, String> {
    check_shape(plan)?;
    let entries: Vec<(usize, PlanOp)> = plan.operations.iter().cloned().enumerate().collect();
    let checked = check_ops(&entries, vault, context);
    if !checked.ops.is_empty() {
        return Ok(checked);
    }
    if checked.refused.is_empty() {
        return Err("nothing to do: the vault already is as this plan describes it".to_owned());
    }
    let reasons: Vec<String> = checked
        .refused
        .iter()
        .take(3)
        .map(|r| format!("operation {}: {}", r.index, r.reason))
        .collect();
    Err(format!(
        "none of the operations can be applied ({}{})",
        reasons.join("; "),
        if checked.refused.len() > 3 {
            "; …"
        } else {
            ""
        }
    ))
}

/// A folder name a plan may create or file into: trimmed, one to
/// [`MAX_FOLDER_NAME`] characters, no control or invisible character, and
/// no empty level (`A//B`, `/A`). `A/B` nests, as in Bitwarden.
pub fn checked_folder_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("the folder name is empty".to_owned());
    }
    if name.chars().count() > MAX_FOLDER_NAME {
        return Err(format!(
            "the folder name is too long (at most {MAX_FOLDER_NAME} characters)"
        ));
    }
    if has_hidden_characters(name) {
        return Err("the folder name has control or invisible characters".to_owned());
    }
    if name.split('/').any(|level| level.trim().is_empty()) {
        return Err("a folder name cannot have an empty level (/ separates levels)".to_owned());
    }
    Ok(name.to_owned())
}

/// A title a plan may write: trimmed, one to [`MAX_TITLE`] characters, no
/// control or invisible character.
pub fn checked_title(title: &str) -> Result<String, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("the title is empty".to_owned());
    }
    if title.chars().count() > MAX_TITLE {
        return Err(format!(
            "the title is too long (at most {MAX_TITLE} characters)"
        ));
    }
    if has_hidden_characters(title) {
        return Err("the title has control or invisible characters".to_owned());
    }
    Ok(title.to_owned())
}

/// Why an operation is not carried out, or that it needs nothing.
enum Verdict {
    Refuse(String),
    Unchanged,
}

fn refuse<T>(reason: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict::Refuse(reason.into()))
}

/// How the rules see a folder name.
enum FolderLookup {
    Exists,
    /// The plan creates it: that operation.
    Created(usize),
    /// Only a name that differs by case exists.
    Lookalike(String),
    Missing,
}

struct Checker<'a> {
    vault: &'a Vault,
    context: &'a Context<'a>,
    folders: HashSet<String>,
    /// Folder names more than one folder has.
    ambiguous: HashSet<String>,
    lowercase: HashMap<String, String>,
    created: HashMap<String, usize>,
    /// Items an operation takes away (archive, trash, merged away): the
    /// operation, and what it does.
    leaving: HashMap<String, (usize, &'static str)>,
    /// The kept item of each merge.
    keeping: HashMap<String, usize>,
    renamed: HashMap<String, usize>,
    moved: HashMap<String, usize>,
    out: Checked,
}

/// What the item is called in a refusal: its title. An identifier the vault
/// does not know is never repeated back: it is the agent's, and it says
/// nothing.
fn shown(vault: &Vault, id: &str) -> String {
    vault.get(id).map_or_else(
        || "an unknown item".to_owned(),
        |item| clean_text(&item.title, 60),
    )
}

impl<'a> Checker<'a> {
    fn new(vault: &'a Vault, context: &'a Context<'a>) -> Self {
        let mut folders: HashSet<String> = context.folders.iter().cloned().collect();
        for item in vault.items().iter().filter(|i| listed(i)) {
            if let Some(folder) = item.folder.as_deref().filter(|f| !f.is_empty()) {
                folders.insert(folder.to_owned());
            }
        }
        let lowercase = folders
            .iter()
            .map(|f| (f.to_lowercase(), f.clone()))
            .collect();
        let mut seen: HashSet<&str> = HashSet::new();
        let ambiguous = context
            .folders
            .iter()
            .filter(|f| !seen.insert(f.as_str()))
            .cloned()
            .collect();
        Self {
            vault,
            context,
            folders,
            ambiguous,
            lowercase,
            created: HashMap::new(),
            leaving: HashMap::new(),
            keeping: HashMap::new(),
            renamed: HashMap::new(),
            moved: HashMap::new(),
            out: Checked::default(),
        }
    }

    /// The item an operation names, if the account can still change it.
    fn usable(&self, id: &str) -> Result<&'a Item, Verdict> {
        let Some(item) = self.vault.get(id) else {
            return refuse("no such item in the vault: use an id from verrou_list_items");
        };
        if item.state == ItemState::Trashed {
            return refuse(format!("\"{}\" is in the trash", shown(self.vault, id)));
        }
        if !item.is_writable() {
            return refuse(format!(
                "\"{}\" is shared read-only with this account",
                shown(self.vault, id)
            ));
        }
        Ok(item)
    }

    fn lookup(&self, name: &str) -> FolderLookup {
        if self.folders.contains(name) {
            FolderLookup::Exists
        } else if let Some(&index) = self.created.get(name) {
            FolderLookup::Created(index)
        } else if let Some(existing) = self.lowercase.get(&name.to_lowercase()) {
            FolderLookup::Lookalike(existing.clone())
        } else {
            FolderLookup::Missing
        }
    }

    fn flags_of(item: &Item) -> Vec<Flag> {
        let mut flags = Vec::new();
        if item.reprompt {
            flags.push(Flag::Protected);
        }
        if item.shared.is_some() {
            flags.push(Flag::Shared);
        }
        flags
    }

    fn push(&mut self, op: CheckedOp) {
        self.out.ops.push(op);
    }

    fn settle(&mut self, index: usize, what: String, verdict: Result<CheckedOp, Verdict>) {
        match verdict {
            Ok(op) => self.push(op),
            Err(Verdict::Unchanged) => self.out.unchanged += 1,
            Err(Verdict::Refuse(reason)) => self.out.refused.push(Refused {
                index,
                what,
                reason,
            }),
        }
    }

    fn create_folder(&mut self, index: usize, op: &PlanOp) -> Result<CheckedOp, Verdict> {
        let PlanOp::CreateFolder { name, rationale } = op else {
            return refuse("unexpected operation");
        };
        let name = checked_folder_name(name).map_err(Verdict::Refuse)?;
        match self.lookup(&name) {
            FolderLookup::Exists | FolderLookup::Created(_) => return Err(Verdict::Unchanged),
            FolderLookup::Lookalike(existing) => {
                return refuse(format!(
                    "a folder named \"{}\" exists (case matters): use that name",
                    clean_text(&existing, 60)
                ));
            }
            FolderLookup::Missing => {}
        }
        self.created.insert(name.clone(), index);
        self.lowercase.insert(name.to_lowercase(), name.clone());
        Ok(CheckedOp {
            index,
            op: PlanOp::CreateFolder {
                name: name.clone(),
                rationale: clean_text(rationale, MAX_RATIONALE),
            },
            rationale: clean_text(rationale, MAX_RATIONALE),
            flags: Vec::new(),
            depends_on: None,
            display: Display {
                title: clean_text(&name, MAX_TEXT),
                ..Display::default()
            },
            others: Vec::new(),
        })
    }

    /// Archive and trash: the item leaves the active list.
    fn leave(&mut self, index: usize, op: &PlanOp) -> Result<CheckedOp, Verdict> {
        let (id, rationale, what, trash) = match op {
            PlanOp::Archive { item, rationale } => (item, rationale, "archives", false),
            PlanOp::Trash { item, rationale } => (item, rationale, "trashes", true),
            _ => return refuse("unexpected operation"),
        };
        let item = self.usable(id)?;
        if trash && item.reprompt {
            return refuse(format!(
                "\"{}\" asks for confirmation before it releases a secret: trash it yourself",
                shown(self.vault, id)
            ));
        }
        if !trash && item.state == ItemState::Archived {
            return Err(Verdict::Unchanged);
        }
        self.claim(index, &item.id, what)?;
        Ok(CheckedOp {
            index,
            op: match op {
                PlanOp::Archive { .. } => PlanOp::Archive {
                    item: item.id.clone(),
                    rationale: clean_text(rationale, MAX_RATIONALE),
                },
                _ => PlanOp::Trash {
                    item: item.id.clone(),
                    rationale: clean_text(rationale, MAX_RATIONALE),
                },
            },
            rationale: clean_text(rationale, MAX_RATIONALE),
            flags: Self::flags_of(item),
            depends_on: None,
            display: Display {
                title: clean_text(&item.title, MAX_TEXT),
                from: clean_text(item.folder.as_deref().unwrap_or_default(), MAX_TEXT),
                ..Display::default()
            },
            others: Vec::new(),
        })
    }

    /// The operation takes the item away: no other does, and it is not the
    /// item a merge keeps.
    fn claim(&mut self, index: usize, id: &str, what: &'static str) -> Result<(), Verdict> {
        self.claimable(id)?;
        self.leaving.insert(id.to_owned(), (index, what));
        Ok(())
    }

    /// Can an operation take the item away? Nothing is recorded.
    fn claimable(&self, id: &str) -> Result<(), Verdict> {
        if let Some((other, how)) = self.leaving.get(id) {
            return refuse(format!(
                "operation {other} already {how} \"{}\"",
                shown(self.vault, id)
            ));
        }
        if let Some(other) = self.keeping.get(id) {
            return refuse(format!(
                "\"{}\" is the item operation {other} merges into: it cannot also go away",
                shown(self.vault, id)
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // every rule a merge must pass, in order
    fn merge(&mut self, index: usize, op: &PlanOp) -> Result<CheckedOp, Verdict> {
        let PlanOp::Merge {
            group,
            keep,
            rationale,
        } = op
        else {
            return refuse("unexpected operation");
        };
        let Some(found) = self.context.groups.iter().find(|g| g.key == *group) else {
            return refuse(
                "no duplicate group with this key (the vault may have changed): call verrou_find_duplicates again",
            );
        };
        if !found.mergeable {
            return refuse("this group cannot be merged: only logins can");
        }
        let ids: Vec<&str> = found.members.iter().map(|m| m.id.as_str()).collect();
        if !ids.contains(&keep.as_str()) {
            return refuse("\"keep\" is not a member of the group");
        }
        let mut items: Vec<&Item> = Vec::new();
        for id in &ids {
            let item = self.usable(id)?;
            if item.state != ItemState::Active {
                return refuse(format!(
                    "\"{}\" is archived: only active items are merged",
                    shown(self.vault, id)
                ));
            }
            if item.kind != ItemKind::Login {
                return refuse(format!("\"{}\" is not a login", shown(self.vault, id)));
            }
            if item.reprompt {
                return refuse(format!(
                    "\"{}\" asks for confirmation before it releases a secret: merge it yourself",
                    shown(self.vault, id)
                ));
            }
            items.push(item);
        }
        let kept = self
            .vault
            .get(keep)
            .ok_or(Verdict::Refuse("\"keep\" is gone".to_owned()))?;
        let organization = |item: &Item| item.shared.as_ref().map(|s| s.organization_id.clone());
        if items.iter().any(|i| organization(i) != organization(kept)) {
            return refuse(
                "the items are not all in the same vault (personal or one organization)",
            );
        }
        let collections = |item: &Item| {
            item.shared.as_ref().map(|s| {
                s.collections
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect::<BTreeSet<_>>()
            })
        };
        if items.iter().any(|i| collections(i) != collections(kept)) {
            return refuse(
                "these organization items are not all in the same collections: merge them in the app",
            );
        }
        let others: Vec<&Item> = items.iter().copied().filter(|i| i.id != *keep).collect();
        for other in &others {
            if self
                .context
                .attachments
                .get(&other.id)
                .copied()
                .unwrap_or(0)
                > 0
            {
                return refuse(format!(
                    "\"{}\" has attachments, which a merge does not move: keep it instead",
                    shown(self.vault, &other.id)
                ));
            }
            if self.vault.passkeys().iter().any(|p| p.item == other.id) {
                return refuse(format!(
                    "\"{}\" has a passkey, which a merge does not move: keep it instead",
                    shown(self.vault, &other.id)
                ));
            }
        }
        // Everything checked: now the claims (nothing is claimed by a merge
        // that is refused).
        if let Some((other, how)) = self.leaving.get(&kept.id) {
            return refuse(format!(
                "operation {other} already {how} \"{}\", the item to keep",
                shown(self.vault, &kept.id)
            ));
        }
        // All of them can go before any is recorded: a merge refused halfway
        // must not leave members claimed.
        for other in &others {
            self.claimable(&other.id)?;
        }
        for other in &others {
            self.claim(index, &other.id, "merges away")?;
        }
        self.keeping.insert(kept.id.clone(), index);

        let usernames: HashSet<String> = items
            .iter()
            .filter_map(|i| username_of(i))
            .map(str::to_lowercase)
            .collect();
        let seeds: HashSet<&str> = items
            .iter()
            .filter_map(|i| i.field_of_kind(FieldKind::Totp))
            .map(|f| f.value.expose())
            .filter(|s| !s.is_empty())
            .collect();
        let mut flags = Self::flags_of(kept);
        if !found.same_password {
            flags.push(Flag::DifferentPasswords);
        }
        if *keep != found.kept() {
            flags.push(Flag::KeepDiffersFromSuggestion);
        }
        if usernames.len() > 1 {
            flags.push(Flag::DifferentUsernames);
        }
        if seeds.len() > 1 {
            flags.push(Flag::OtherTotp);
        }
        if password_overflow(&items) {
            flags.push(Flag::PasswordsAsFields);
        }
        let from = self.newest_password(&items, kept);
        Ok(CheckedOp {
            index,
            op: PlanOp::Merge {
                group: group.clone(),
                keep: keep.clone(),
                rationale: clean_text(rationale, MAX_RATIONALE),
            },
            rationale: clean_text(rationale, MAX_RATIONALE),
            flags,
            depends_on: None,
            display: Display {
                title: clean_text(&kept.title, MAX_TEXT),
                members: others
                    .iter()
                    .map(|i| clean_text(&i.title, MAX_TEXT))
                    .collect(),
                password_from: from,
                ..Display::default()
            },
            others: others.iter().map(|i| i.id.clone()).collect(),
        })
    }

    /// The title of the item whose password a merge makes current, when it is
    /// not the kept item: the most recently changed. Same rule as the merge
    /// (`verrou_vaultwarden::merge`): the kept item wins a tie, and an item
    /// without a dated password change counts from its creation.
    fn newest_password(&self, items: &[&Item], kept: &Item) -> String {
        let date = |item: &Item| {
            self.context
                .password_dates
                .get(&item.id)
                .copied()
                .unwrap_or(item.created)
        };
        let mut best = kept;
        for item in items {
            if password_of(item).is_some()
                && (password_of(best).is_none() || date(item) > date(best))
            {
                best = item;
            }
        }
        if best.id == kept.id {
            String::new()
        } else {
            clean_text(&best.title, MAX_TEXT)
        }
    }

    /// An item that goes away (merged, archived, trashed) is neither renamed
    /// nor moved.
    fn staying(&self, id: &str, what: &str) -> Result<(), Verdict> {
        match self.leaving.get(id) {
            Some((other, how)) => refuse(format!(
                "operation {other} {how} \"{}\", so it cannot also be {what}",
                shown(self.vault, id)
            )),
            None => Ok(()),
        }
    }

    fn rename(&mut self, index: usize, op: &PlanOp) -> Result<CheckedOp, Verdict> {
        let PlanOp::Rename {
            item: id,
            title,
            rationale,
        } = op
        else {
            return refuse("unexpected operation");
        };
        let item = self.usable(id)?;
        self.staying(&item.id, "renamed")?;
        if let Some(other) = self.renamed.get(&item.id) {
            return refuse(format!(
                "operation {other} already renames \"{}\"",
                shown(self.vault, id)
            ));
        }
        let title = checked_title(title).map_err(Verdict::Refuse)?;
        if title == item.title {
            return Err(Verdict::Unchanged);
        }
        self.renamed.insert(item.id.clone(), index);
        Ok(CheckedOp {
            index,
            op: PlanOp::Rename {
                item: item.id.clone(),
                title: title.clone(),
                rationale: clean_text(rationale, MAX_RATIONALE),
            },
            rationale: clean_text(rationale, MAX_RATIONALE),
            flags: Self::flags_of(item),
            depends_on: None,
            display: Display {
                title: clean_text(&item.title, MAX_TEXT),
                detail: clean_text(&title, MAX_TEXT),
                from: clean_text(&item.title, MAX_TEXT),
                ..Display::default()
            },
            others: Vec::new(),
        })
    }

    fn relocate(&mut self, index: usize, op: &PlanOp) -> Result<CheckedOp, Verdict> {
        let PlanOp::Move {
            item: id,
            folder,
            rationale,
        } = op
        else {
            return refuse("unexpected operation");
        };
        let item = self.usable(id)?;
        self.staying(&item.id, "moved")?;
        if let Some(other) = self.moved.get(&item.id) {
            return refuse(format!(
                "operation {other} already moves \"{}\"",
                shown(self.vault, id)
            ));
        }
        let target = if folder.trim().is_empty() {
            String::new()
        } else {
            checked_folder_name(folder).map_err(Verdict::Refuse)?
        };
        let mut depends_on = None;
        if !target.is_empty() {
            match self.lookup(&target) {
                FolderLookup::Exists => {}
                FolderLookup::Created(creator) => depends_on = Some(creator),
                FolderLookup::Lookalike(existing) => {
                    return refuse(format!(
                        "no folder has exactly this name, but \"{}\" exists (case matters)",
                        clean_text(&existing, 60)
                    ));
                }
                FolderLookup::Missing => {
                    return refuse("no folder has this name: add a create_folder operation first");
                }
            }
            if self.ambiguous.contains(&target) {
                return refuse(
                    "several folders have this name, and a plan cannot tell which: move the item in the app",
                );
            }
        }
        let current = item.folder.clone().unwrap_or_default();
        if current == target {
            return Err(Verdict::Unchanged);
        }
        self.moved.insert(item.id.clone(), index);
        Ok(CheckedOp {
            index,
            op: PlanOp::Move {
                item: item.id.clone(),
                folder: target.clone(),
                rationale: clean_text(rationale, MAX_RATIONALE),
            },
            rationale: clean_text(rationale, MAX_RATIONALE),
            flags: Self::flags_of(item),
            depends_on,
            display: Display {
                title: clean_text(&item.title, MAX_TEXT),
                detail: clean_text(&target, MAX_TEXT),
                from: clean_text(&current, MAX_TEXT),
                ..Display::default()
            },
            others: Vec::new(),
        })
    }
}

/// An item's current password, if it has one.
fn password_of(item: &Item) -> Option<&str> {
    item.field_of_kind(FieldKind::Password)
        .map(|f| f.value.expose())
        .filter(|p| !p.is_empty())
}

/// Would a merge of these items have more different old passwords than a
/// history holds? Their current ones, and the history of each, count once
/// each; the newest becomes the current password.
fn password_overflow(items: &[&Item]) -> bool {
    let mut all: HashSet<&str> = HashSet::new();
    let mut has_current = false;
    for item in items {
        if let Some(password) = password_of(item) {
            all.insert(password);
            has_current = true;
        }
        for field in item.fields.iter().filter(|f| f.id.starts_with("history-")) {
            let password = field.value.expose();
            if !password.is_empty() {
                all.insert(password);
            }
        }
    }
    all.len().saturating_sub(usize::from(has_current)) > PASSWORD_HISTORY_LIMIT
}

/// The name of the operation and what it concerns, for a refusal.
fn describe(vault: &Vault, op: &PlanOp) -> String {
    let quoted = |id: &str| {
        vault.get(id).map_or_else(
            || "an unknown item".to_owned(),
            |item| format!("“{}”", clean_text(&item.title, 60)),
        )
    };
    match op {
        PlanOp::CreateFolder { name, .. } => match checked_folder_name(name) {
            Ok(name) => format!("create the folder “{}”", clean_text(&name, 60)),
            // A name that fails the rules is not repeated.
            Err(_) => "create a folder (this folder name)".to_owned(),
        },
        PlanOp::Move { item, .. } => format!("move {}", quoted(item)),
        PlanOp::Rename { item, .. } => format!("rename {}", quoted(item)),
        PlanOp::Merge { keep, .. } => format!("merge into {}", quoted(keep)),
        PlanOp::Archive { item, .. } => format!("archive {}", quoted(item)),
        PlanOp::Trash { item, .. } => format!("trash {}", quoted(item)),
        PlanOp::Unsupported => "an unsupported operation".to_owned(),
    }
}

/// The operations (with their position in the plan) against the vault: the
/// rules of the module header. Folders first, then what takes items away
/// (merges, archives, trash), then what changes the items that stay.
#[must_use]
pub fn check_ops(entries: &[(usize, PlanOp)], vault: &Vault, context: &Context<'_>) -> Checked {
    let mut checker = Checker::new(vault, context);
    let phases: [fn(&PlanOp) -> bool; 3] = [
        |op| matches!(op, PlanOp::CreateFolder { .. }),
        |op| {
            matches!(
                op,
                PlanOp::Merge { .. } | PlanOp::Archive { .. } | PlanOp::Trash { .. }
            )
        },
        |op| matches!(op, PlanOp::Rename { .. } | PlanOp::Move { .. }),
    ];
    for phase in phases {
        for (index, op) in entries.iter().filter(|(_, op)| phase(op)) {
            let verdict = match op {
                PlanOp::CreateFolder { .. } => checker.create_folder(*index, op),
                PlanOp::Merge { .. } => checker.merge(*index, op),
                PlanOp::Archive { .. } | PlanOp::Trash { .. } => checker.leave(*index, op),
                PlanOp::Rename { .. } => checker.rename(*index, op),
                PlanOp::Move { .. } => checker.relocate(*index, op),
                PlanOp::Unsupported => continue,
            };
            checker.settle(*index, describe(vault, op), verdict);
        }
    }
    for (index, op) in entries.iter().filter(|(_, op)| *op == PlanOp::Unsupported) {
        checker.out.refused.push(Refused {
            index: *index,
            what: describe(vault, op),
            reason: "this operation is not supported: use create_folder, move, rename, merge, archive or trash (Vaultwarden has no tags: use folders)".to_owned(),
        });
    }
    let mut out = checker.out;
    out.ops.sort_by_key(|op| op.index);
    out.refused.sort_by_key(|r| r.index);
    out
}

// MARK: Without the app

/// Carries checked operations out on an in-memory vault: for fake vaults
/// (tests and the extension's test server). The app writes to the server
/// (`verrou-ffi`). A merge only brings over the sites the kept item lacks.
#[must_use]
pub fn apply_in_memory(vault: &Vault, ops: &[CheckedOp]) -> Vault {
    let mut items = vault.items().to_vec();
    for checked in ops {
        match &checked.op {
            PlanOp::Move { item, folder, .. } => {
                if let Some(found) = items.iter_mut().find(|i| i.id == *item) {
                    found.folder = (!folder.is_empty()).then(|| folder.clone());
                }
            }
            PlanOp::Rename { item, title, .. } => {
                if let Some(found) = items.iter_mut().find(|i| i.id == *item) {
                    title.clone_into(&mut found.title);
                }
            }
            PlanOp::Archive { item, .. } => set_state(&mut items, item, ItemState::Archived),
            PlanOp::Trash { item, .. } => set_state(&mut items, item, ItemState::Trashed),
            PlanOp::Merge { keep, .. } => {
                let brought: Vec<String> = items
                    .iter()
                    .filter(|i| checked.others.contains(&i.id))
                    .flat_map(|i| i.urls.clone())
                    .collect();
                if let Some(found) = items.iter_mut().find(|i| i.id == *keep) {
                    for url in brought {
                        if !found.urls.contains(&url) {
                            found.urls.push(url);
                        }
                    }
                }
                for other in &checked.others {
                    set_state(&mut items, other, ItemState::Trashed);
                }
            }
            PlanOp::CreateFolder { .. } | PlanOp::Unsupported => {}
        }
    }
    Vault::new(items)
        .with_passkeys(vault.passkeys().to_vec())
        .with_match_rules(vault.match_rules().clone())
}

fn set_state(items: &mut [Item], id: &str, state: ItemState) {
    if let Some(found) = items.iter_mut().find(|i| i.id == id) {
        found.state = state;
    }
}

#[cfg(test)]
mod tests {
    use verrou_core::{Field, SecretString, Sharing};

    use super::*;

    const PASSWORD: &str = "pw-never-leaves-0xDEADBEEF";
    const SEED: &str = "JBSWY3DPEHPK3PXP-planted";
    const NOTE: &str = "the safe code is 4521";

    fn login(id: &str, title: &str, urls: &[&str]) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: String::new(),
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: 1_700_000_000,
            modified: 1_700_000_100,
            fields: vec![
                Field::new("username", "Username", FieldKind::Username, "camille"),
                Field::new("password", "Password", FieldKind::Password, PASSWORD),
            ],
            notes: None,
            reprompt: false,
            state: ItemState::Active,
            shared: None,
        }
    }

    fn plan(operations: Vec<PlanOp>) -> Plan {
        Plan {
            reason: "tidy up".to_owned(),
            operations,
        }
    }

    fn check(
        vault: &Vault,
        groups: &[DuplicateGroup],
        operations: Vec<PlanOp>,
    ) -> Result<Checked, String> {
        let attachments = HashMap::new();
        validate(
            &plan(operations),
            vault,
            &Context {
                groups,
                attachments: &attachments,
                folders: &["Work".to_owned(), "Empty".to_owned()],
                password_dates: &HashMap::new(),
            },
        )
    }

    fn rename(item: &str, title: &str) -> PlanOp {
        PlanOp::Rename {
            item: item.to_owned(),
            title: title.to_owned(),
            rationale: "clearer".to_owned(),
        }
    }

    fn relocate(item: &str, folder: &str) -> PlanOp {
        PlanOp::Move {
            item: item.to_owned(),
            folder: folder.to_owned(),
            rationale: "belongs there".to_owned(),
        }
    }

    fn create(name: &str) -> PlanOp {
        PlanOp::CreateFolder {
            name: name.to_owned(),
            rationale: "new area".to_owned(),
        }
    }

    fn archive(item: &str) -> PlanOp {
        PlanOp::Archive {
            item: item.to_owned(),
            rationale: "unused".to_owned(),
        }
    }

    fn trash(item: &str) -> PlanOp {
        PlanOp::Trash {
            item: item.to_owned(),
            rationale: "junk".to_owned(),
        }
    }

    fn vault() -> Vault {
        let mut shared_read_only = login("ro", "Team wiki", &["https://wiki.example.com"]);
        shared_read_only.shared = Some(Sharing {
            organization_id: "org".to_owned(),
            organization: "Acme".to_owned(),
            read_only: true,
            ..Sharing::default()
        });
        let mut protected = login("bank", "Bank", &["https://bank.example.com"]);
        protected.reprompt = true;
        let mut trashed = login("old", "Old", &[]);
        trashed.state = ItemState::Trashed;
        Vault::new(vec![
            login("a", "GitHub", &["https://github.com/login?token=abc#frag"]),
            login("b", "github.com", &["https://www.github.com/camille"]),
            login("c", "Gitlab", &["https://gitlab.com"]),
            shared_read_only,
            protected,
            trashed,
        ])
    }

    fn reasons(checked: &Checked) -> Vec<&str> {
        checked.refused.iter().map(|r| r.reason.as_str()).collect()
    }

    #[test]
    fn a_plan_is_refused_whole_when_it_is_shaped_wrong() {
        let v = vault();
        let err = |plan: Plan| {
            let attachments = HashMap::new();
            validate(
                &plan,
                &v,
                &Context {
                    groups: &[],
                    attachments: &attachments,
                    folders: &[],
                    password_dates: &HashMap::new(),
                },
            )
            .unwrap_err()
        };
        assert!(err(Plan::default()).contains("reason is required"));
        let mut long = plan(vec![rename("a", "x")]);
        long.reason = "r".repeat(MAX_RATIONALE + 1);
        assert!(err(long).contains("too long"));
        assert!(err(plan(vec![])).contains("no operation"));
        let many = plan(
            (0..=MAX_OPS)
                .map(|i| rename("a", &format!("t{i}")))
                .collect(),
        );
        assert!(err(many).contains("at most 1000"));
        let mut op = rename("a", "x");
        if let PlanOp::Rename { rationale, .. } = &mut op {
            rationale.clear();
        }
        assert!(err(plan(vec![op])).contains("operation 0: a rationale is required"));
        let mut op = rename("a", "x");
        if let PlanOp::Rename { rationale, .. } = &mut op {
            *rationale = "y".repeat(MAX_RATIONALE + 1);
        }
        assert!(err(plan(vec![op])).contains("rationale is too long"));
        // Exactly at the limits is fine.
        assert!(
            check(
                &v,
                &[],
                (0..MAX_OPS)
                    .map(|i| rename("a", &format!("t{i}")))
                    .collect()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_plan_with_nothing_valid_is_refused_whole() {
        let v = vault();
        let err = check(&v, &[], vec![rename("nope", "x"), trash("old")]).unwrap_err();
        assert!(
            err.contains("none of the operations can be applied"),
            "{err}"
        );
        assert!(
            err.contains("operation 0") && err.contains("operation 1"),
            "{err}"
        );
        // All no-ops: nothing to do.
        let err = check(&v, &[], vec![rename("a", "GitHub"), relocate("a", "")]).unwrap_err();
        assert!(err.contains("nothing to do"), "{err}");
    }

    #[test]
    fn each_operation_is_refused_on_its_own() {
        let v = vault();
        let checked = check(
            &v,
            &[],
            vec![
                rename("a", "GitHub (work)"),
                rename("nope", "x"),
                rename("old", "x"),
                rename("ro", "x"),
                trash("bank"),
                rename("c", "  "),
                rename("c", &"t".repeat(MAX_TITLE + 1)),
                rename("c", "bad\u{202E}title"),
                relocate("c", "Nowhere"),
                relocate("c", "work"),
                relocate("c", "A//B"),
                create("bad\nname"),
                PlanOp::Unsupported,
            ],
        )
        .unwrap();
        assert_eq!(checked.ops.len(), 1);
        assert_eq!(checked.ops[0].index, 0);
        assert_eq!(checked.refused.len(), 12);
        let all = reasons(&checked).join("\n");
        for needle in [
            "no such item",
            "is in the trash",
            "read-only",
            "trash it yourself",
            "title is empty",
            "title is too long",
            "invisible",
            "no folder has this name",
            "\"Work\" exists (case matters)",
            "empty level",
            "control or invisible",
            "not supported",
            "use folders",
        ] {
            assert!(all.contains(needle), "{needle}\n{all}");
        }
        // What the agent invented is not repeated back, in a reason or in
        // what the refusal says it was.
        let whats: Vec<&str> = checked.refused.iter().map(|r| r.what.as_str()).collect();
        for text in [all.as_str(), whats.join("\n").as_str()] {
            assert!(
                !text.contains("nope") && !text.contains("Nowhere"),
                "{text}"
            );
        }
        assert!(whats.contains(&"rename an unknown item"), "{whats:?}");
        assert!(whats.contains(&"create a folder (this folder name)"));
    }

    #[test]
    fn a_move_into_a_new_folder_depends_on_its_creation() {
        let v = vault();
        let checked = check(
            &v,
            &[],
            vec![
                relocate("a", "Dev"),
                create(" Dev "),
                relocate("b", "Work"),
                relocate("c", "Dev"),
            ],
        )
        .unwrap();
        assert_eq!(checked.ops.len(), 4);
        assert_eq!(
            checked.ops[0].depends_on,
            Some(1),
            "to the creation, wherever it is"
        );
        assert_eq!(
            checked.ops[2].depends_on, None,
            "an existing folder needs none"
        );
        assert_eq!(checked.ops[3].depends_on, Some(1));
        // The name is trimmed in what will be carried out.
        assert!(matches!(&checked.ops[1].op, PlanOp::CreateFolder { name, .. } if name == "Dev"));
        // A creation that is refused leaves the moves without a folder.
        let checked = check(
            &v,
            &[],
            vec![create("A\u{200B}"), relocate("a", "A"), rename("c", "x")],
        )
        .unwrap();
        assert_eq!(checked.ops.len(), 1);
        assert_eq!(checked.refused.len(), 2);
    }

    #[test]
    fn no_op_operations_are_dropped_and_counted() {
        let mut v = vault();
        let mut items = v.items().to_vec();
        items[0].folder = Some("Work".to_owned());
        v = Vault::new(items);
        let checked = check(
            &v,
            &[],
            vec![
                create("Work"),
                create("Empty"),
                create("Fresh"),
                create("Fresh"),
                relocate("a", "Work"),
                rename("a", " GitHub "),
                rename("c", "Gitlab (self-hosted)"),
            ],
        )
        .unwrap();
        // Existing folders (even empty ones), the same creation twice, a
        // move to where the item is, a rename to the same title.
        assert_eq!(checked.unchanged, 5);
        assert_eq!(checked.ops.len(), 2);
        assert_eq!(checked.refused.len(), 0);
    }

    #[test]
    fn what_goes_away_is_not_also_renamed_or_moved() {
        let v = vault();
        let checked = check(
            &v,
            &[],
            vec![
                archive("a"),
                rename("a", "x"),
                relocate("a", "Work"),
                trash("a"),
                trash("c"),
                rename("c", "y"),
                rename("b", "z"),
                rename("b", "z2"),
                relocate("b", "Work"),
                relocate("b", "Empty"),
            ],
        )
        .unwrap();
        let kept: Vec<usize> = checked.ops.iter().map(|o| o.index).collect();
        assert_eq!(kept, [0, 4, 6, 8], "{:?}", reasons(&checked));
        let all = reasons(&checked).join("\n");
        assert!(all.contains("operation 0 archives \"GitHub\", so it cannot also be renamed"));
        assert!(all.contains("operation 4 trashes \"Gitlab\", so it cannot also be renamed"));
        assert!(all.contains("operation 0 already archives"));
        assert!(all.contains("operation 6 already renames"));
        assert!(all.contains("operation 8 already moves"));
    }

    #[test]
    fn protected_and_shared_items_are_flagged_and_not_checked_by_default() {
        let mut shared = login("s", "Shared one", &[]);
        shared.shared = Some(Sharing {
            organization_id: "org".to_owned(),
            organization: "Acme".to_owned(),
            ..Sharing::default()
        });
        let mut protected = login("p", "Protected", &[]);
        protected.reprompt = true;
        let v = Vault::new(vec![shared, protected, login("c", "Gitlab", &[])]);
        let checked = check(
            &v,
            &[],
            vec![rename("s", "S"), rename("p", "P"), rename("c", "C")],
        )
        .unwrap();
        assert_eq!(checked.ops[0].flags, [Flag::Shared]);
        assert!(checked.ops[0].default_on());
        assert_eq!(checked.ops[1].flags, [Flag::Protected]);
        assert!(!checked.ops[1].default_on());
        assert!(checked.ops[2].flags.is_empty() && checked.ops[2].default_on());
    }

    fn two_accounts() -> (Vault, Vec<DuplicateGroup>) {
        let mut a = login("a", "GitHub", &["https://github.com"]);
        let mut b = login("b", "GitHub (old)", &["https://github.com"]);
        let c = login("c", "Gitlab", &["https://gitlab.com"]);
        a.fields
            .push(Field::new("totp", "Code", FieldKind::Totp, SEED));
        b.fields = vec![
            Field::new("username", "Username", FieldKind::Username, "camille"),
            Field::new("password", "Password", FieldKind::Password, "other-pw"),
        ];
        let vault = Vault::new(vec![a, b, c]);
        let groups = scan_duplicates(&vault, &HashMap::new());
        assert_eq!(groups.len(), 1, "{groups:?}");
        (vault, groups)
    }

    fn merge(group: &DuplicateGroup, keep: &str) -> PlanOp {
        PlanOp::Merge {
            group: group.key.clone(),
            keep: keep.to_owned(),
            rationale: "same account".to_owned(),
        }
    }

    #[test]
    fn a_merge_is_checked_against_the_current_scan() {
        let (v, groups) = two_accounts();
        let group = &groups[0];
        let suggested = group.kept().to_owned();
        let other = if suggested == "a" { "b" } else { "a" };
        let checked = check(&v, &groups, vec![merge(group, &suggested)]).unwrap();
        let op = &checked.ops[0];
        assert_eq!(op.others, [other]);
        assert_eq!(op.display.members.len(), 1);
        assert!(op.flags.contains(&Flag::DifferentPasswords));
        assert!(!op.flags.contains(&Flag::KeepDiffersFromSuggestion));
        assert!(op.default_on());
        // Keeping the other one is flagged.
        let checked = check(&v, &groups, vec![merge(group, other)]).unwrap();
        assert!(
            checked.ops[0]
                .flags
                .contains(&Flag::KeepDiffersFromSuggestion)
        );
        // A group that changed (or never was) is refused.
        let mut stale = merge(group, &suggested);
        if let PlanOp::Merge { group, .. } = &mut stale {
            "group-that-never-was".clone_into(group);
        }
        let err = check(&v, &groups, vec![stale, rename("c", "x")]).unwrap();
        assert!(reasons(&err)[0].contains("no duplicate group"));
        // `keep` outside the group.
        let err = check(&v, &groups, vec![merge(group, "c"), rename("c", "x")]).unwrap();
        assert!(reasons(&err)[0].contains("not a member"));
    }

    #[test]
    fn a_merge_never_takes_what_it_cannot_carry() {
        let (v, groups) = two_accounts();
        let group = &groups[0];
        let suggested = group.kept().to_owned();
        let other = if suggested == "a" { "b" } else { "a" }.to_owned();
        let ask = |vault: &Vault, attachments: &HashMap<String, usize>| {
            validate(
                &plan(vec![merge(group, &suggested), rename("c", "x")]),
                vault,
                &Context {
                    groups: &groups,
                    attachments,
                    folders: &[],
                    password_dates: &HashMap::new(),
                },
            )
            .unwrap()
        };
        // Attachments on the one that would go to the trash.
        let with_attachment = HashMap::from([(other.clone(), 1)]);
        let checked = ask(&v, &with_attachment);
        assert!(reasons(&checked)[0].contains("attachments"));
        // Attachments on the kept one are fine.
        assert_eq!(
            ask(&v, &HashMap::from([(suggested.clone(), 2)]))
                .refused
                .len(),
            0
        );
        // A passkey on the one that would go to the trash.
        let passkey = verrou_core::Passkey {
            item: other.clone(),
            credential_id: "cred".to_owned(),
            rp_id: "github.com".to_owned(),
            rp_name: None,
            user_handle: None,
            user_name: None,
            user_display_name: None,
            counter: 0,
            discoverable: true,
            created: 0,
            key: SecretString::new("key"),
        };
        let with_passkey = Vault::new(v.items().to_vec()).with_passkeys(vec![passkey]);
        assert!(reasons(&ask(&with_passkey, &HashMap::new()))[0].contains("passkey"));
        // A protected member, either side.
        let mut items = v.items().to_vec();
        items
            .iter_mut()
            .find(|i| i.id == suggested)
            .unwrap()
            .reprompt = true;
        let checked = ask(&Vault::new(items), &HashMap::new());
        assert!(reasons(&checked)[0].contains("asks for confirmation"));
        // Read-only, or another vault.
        let mut items = v.items().to_vec();
        items.iter_mut().find(|i| i.id == other).unwrap().shared = Some(Sharing {
            organization_id: "org".to_owned(),
            organization: "Acme".to_owned(),
            ..Sharing::default()
        });
        let checked = ask(&Vault::new(items), &HashMap::new());
        assert!(reasons(&checked)[0].contains("same vault"));
    }

    #[test]
    fn a_merge_claims_its_items_and_keeps_the_kept_one() {
        let (v, groups) = two_accounts();
        let group = &groups[0];
        let suggested = group.kept().to_owned();
        let other = if suggested == "a" { "b" } else { "a" }.to_owned();
        let checked = check(
            &v,
            &groups,
            vec![
                merge(group, &suggested),
                trash(&other),
                archive(&suggested),
                rename(&other, "x"),
                rename(&suggested, "Renamed"),
            ],
        )
        .unwrap();
        let kept: Vec<usize> = checked.ops.iter().map(|o| o.index).collect();
        assert_eq!(kept, [0, 4], "{:?}", reasons(&checked));
        // Trashing the item to keep first leaves the merge refused instead.
        let checked = check(
            &v,
            &groups,
            vec![trash(&suggested), merge(group, &suggested)],
        )
        .unwrap();
        assert_eq!(checked.ops.len(), 1);
        assert!(reasons(&checked)[0].contains("the item to keep"));
    }

    #[test]
    fn the_catalog_never_carries_a_secret() {
        let mut item = login(
            "a",
            "GitHub",
            &[
                "https://user:hunter2@github.com:8443/a/b?token=SECRET-QUERY#frag",
                "iosapp://com.github.app/deep/path?x=1",
                "https://github.com",
            ],
        );
        item.fields
            .push(Field::new("totp", "Code", FieldKind::Totp, SEED));
        item.fields.push(Field::new(
            "custom-0",
            "API key name",
            FieldKind::Concealed,
            "custom-value-secret",
        ));
        item.notes = Some(SecretString::new(NOTE));
        let mut card = login("card", "Visa", &[]);
        card.kind = ItemKind::Card;
        card.fields = vec![Field::new(
            "number",
            "Number",
            FieldKind::CardNumber,
            "4242424242424242",
        )];
        card.subtitle = "Visa •••• 4242".to_owned();
        let v = Vault::new(vec![item, card]);
        let groups = scan_duplicates(&v, &HashMap::new());
        let (items, total) = catalog(&v, &HashMap::new(), 0, None, true);
        let (infos, _) = duplicate_infos(&groups, &v);
        let mut everything = serde_json::to_string(&items).unwrap();
        everything += &serde_json::to_string(&overview(&v, &["Work".to_owned()])).unwrap();
        everything += &serde_json::to_string(&infos).unwrap();
        for secret in [
            PASSWORD,
            SEED,
            NOTE,
            "hunter2",
            "SECRET-QUERY",
            "frag",
            "/a/b",
            "deep/path",
            "custom-value-secret",
            "API key name",
            "4242424242424242",
            "8443",
        ] {
            assert!(
                !everything.contains(secret),
                "{secret} leaked: {everything}"
            );
        }
        assert_eq!(total, 2);
        let a = items.iter().find(|i| i.id == "a").unwrap();
        assert_eq!(a.username.as_deref(), Some("camille"));
        assert_eq!(a.sites, ["github.com", "iosapp://com.github.app"]);
        assert!(a.has_totp && a.has_notes);
        // Only logins have a username in the catalog.
        assert!(
            items
                .iter()
                .find(|i| i.id == "card")
                .unwrap()
                .username
                .is_none()
        );
    }

    #[test]
    fn the_catalog_lists_pages_without_the_trash() {
        let mut items: Vec<Item> = (0..7)
            .map(|n| login(&format!("i{n}"), &format!("Item {n}"), &[]))
            .collect();
        items[1].state = ItemState::Archived;
        items[2].state = ItemState::Trashed;
        let v = Vault::new(items);
        let (page, total) = catalog(&v, &HashMap::new(), 0, Some(3), false);
        assert_eq!(
            (page.len(), total),
            (3, 5),
            "five active items, the trash never"
        );
        let (rest, _) = catalog(&v, &HashMap::new(), 3, Some(3), false);
        assert_eq!(rest.len(), 2);
        let (with_archive, total) = catalog(&v, &HashMap::new(), 0, None, true);
        assert_eq!((with_archive.len(), total), (6, 6));
        assert!(with_archive.iter().all(|i| i.id != "i2"));
        // The limit is clamped.
        let (all, _) = catalog(&v, &HashMap::new(), 0, Some(0), false);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn a_page_is_cut_to_fit_a_reply() {
        let items: Vec<Item> = (0..500)
            .map(|n| {
                let mut item = login(&format!("i{n}"), &"é".repeat(MAX_TEXT), &[]);
                item.urls = (0..20)
                    .map(|k| format!("https://{}{k}.example.com", "h".repeat(90)))
                    .collect();
                item
            })
            .collect();
        let (page, total) = catalog(&Vault::new(items), &HashMap::new(), 0, Some(500), false);
        assert_eq!(total, 500);
        assert!(!page.is_empty() && page.len() < 500);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_REPLY);
    }

    #[test]
    fn the_overview_counts_and_lists_empty_folders() {
        let mut items = vec![
            login("a", "A", &[]),
            login("b", "B", &[]),
            login("c", "C", &[]),
        ];
        items[0].folder = Some("Work".to_owned());
        items[1].state = ItemState::Archived;
        items[1].folder = Some("Work".to_owned());
        items[2].reprompt = true;
        let summary = overview(&Vault::new(items), &["Work".to_owned(), "Empty".to_owned()]);
        assert_eq!(
            (
                summary.items,
                summary.archived,
                summary.without_folder,
                summary.protected
            ),
            (2, 1, 1, 1)
        );
        let folders: Vec<(&str, u32)> = summary
            .folders
            .iter()
            .map(|f| (f.name.as_str(), f.count))
            .collect();
        assert_eq!(folders, [("Empty", 0), ("Work", 2)]);
    }

    #[test]
    fn the_in_memory_apply_carries_the_plan_out() {
        let (v, groups) = two_accounts();
        let group = &groups[0];
        let suggested = group.kept().to_owned();
        let checked = check(
            &v,
            &groups,
            vec![
                merge(group, &suggested),
                rename("c", "GitLab"),
                relocate("c", "Dev"),
                create("Dev"),
            ],
        )
        .unwrap();
        let after = apply_in_memory(&v, &checked.ops);
        let c = after.get("c").unwrap();
        assert_eq!(
            (c.title.as_str(), c.folder.as_deref()),
            ("GitLab", Some("Dev"))
        );
        let other = if suggested == "a" { "b" } else { "a" };
        assert_eq!(after.get(other).unwrap().state, ItemState::Trashed);
        assert_eq!(after.get(&suggested).unwrap().state, ItemState::Active);
    }

    fn shared_in(item: &mut Item, collections: &[&str]) {
        item.shared = Some(Sharing {
            organization_id: "org".to_owned(),
            organization: "Acme".to_owned(),
            collections: collections
                .iter()
                .map(|c| ((*c).to_owned(), (*c).to_owned()))
                .collect(),
            ..Sharing::default()
        });
    }

    fn with_password(mut item: Item, password: &str) -> Item {
        item.fields.retain(|f| f.kind != FieldKind::Password);
        item.fields.push(Field::new(
            "password",
            "Password",
            FieldKind::Password,
            password,
        ));
        item
    }

    fn account_with(password_b: &str, seed_b: Option<&str>) -> Vault {
        let mut a = login("a", "GitHub", &["https://github.com"]);
        a.fields
            .push(Field::new("totp", "Code", FieldKind::Totp, SEED));
        let mut b = with_password(
            login("b", "GitHub (old)", &["https://github.com"]),
            password_b,
        );
        if let Some(seed) = seed_b {
            b.fields
                .push(Field::new("totp", "Code", FieldKind::Totp, seed));
        }
        Vault::new(vec![a, b])
    }

    #[test]
    fn the_groups_an_agent_reads_never_say_whether_secrets_are_equal() {
        // The same two logins, with the same password or with different
        // ones, the same one-time code or another: the agent reads the same.
        let seen = |vault: &Vault| {
            let groups = scan_duplicates(vault, &HashMap::new());
            let (infos, _) = duplicate_infos(&groups, vault);
            serde_json::to_string(&infos).unwrap()
        };
        let same = account_with(PASSWORD, Some(SEED));
        let different = account_with("another-password", Some("OTHERSEED234567"));
        let json = seen(&same);
        assert_eq!(json, seen(&different));
        assert_eq!(json, seen(&account_with(PASSWORD, None)));
        assert!(!json.contains("same_password"), "{json}");
        let lower = json.to_lowercase();
        assert!(
            !lower.contains("password") && !lower.contains("one-time"),
            "no clause about secrets: {json}"
        );
        assert!(json.contains("same site"), "{json}");
        // The review still tells the user the passwords differ.
        let groups = scan_duplicates(&different, &HashMap::new());
        let checked = check(
            &different,
            &groups,
            vec![merge(&groups[0], groups[0].kept())],
        )
        .unwrap();
        assert!(checked.ops[0].flags.contains(&Flag::DifferentPasswords));
        let groups = scan_duplicates(&same, &HashMap::new());
        let checked = check(&same, &groups, vec![merge(&groups[0], groups[0].kept())]).unwrap();
        assert!(!checked.ops[0].flags.contains(&Flag::DifferentPasswords));
    }

    #[test]
    fn a_merge_names_the_group_key_the_agent_was_given() {
        let vault = account_with("another-password", None);
        let groups = scan_duplicates(&vault, &HashMap::new());
        let (infos, _) = duplicate_infos(&groups, &vault);
        assert_eq!(infos.len(), 1);
        // The key and the suggested item the agent reads are what the checks
        // look up.
        let op = PlanOp::Merge {
            group: infos[0].group.clone(),
            keep: infos[0].suggested_keep.clone(),
            rationale: "same account".to_owned(),
        };
        let checked = check(&vault, &groups, vec![op]).unwrap();
        assert_eq!(checked.ops.len(), 1, "{:?}", reasons(&checked));
        // A scan that compares passwords would not be the agent's: its keys
        // are not accepted for a plan unless they are the same set.
        let full = verrou_core::duplicates::find_duplicates(vault.items());
        assert_eq!(full.len(), 1);
        assert_eq!(full[0].key, groups[0].key, "same members, same key");
    }

    #[test]
    fn a_merge_with_more_passwords_than_a_history_holds_is_flagged_and_stays_checked() {
        let mut items: Vec<Item> = (0..8)
            .map(|n| {
                with_password(
                    login(
                        &format!("i{n}"),
                        &format!("Copy {n}"),
                        &["https://site.example"],
                    ),
                    &format!("password-{n}"),
                )
            })
            .collect();
        let vault = Vault::new(items.clone());
        let groups = scan_duplicates(&vault, &HashMap::new());
        assert_eq!(groups.len(), 1, "{groups:?}");
        let checked = check(&vault, &groups, vec![merge(&groups[0], groups[0].kept())]).unwrap();
        let op = &checked.ops[0];
        assert!(
            op.flags.contains(&Flag::PasswordsAsFields),
            "{:?}",
            op.flags
        );
        assert!(op.default_on(), "a badge, not a reason to uncheck");
        // Five of them fit: no badge.
        items.truncate(6);
        let vault = Vault::new(items);
        let groups = scan_duplicates(&vault, &HashMap::new());
        let checked = check(&vault, &groups, vec![merge(&groups[0], groups[0].kept())]).unwrap();
        assert!(!checked.ops[0].flags.contains(&Flag::PasswordsAsFields));
        // The history of the members counts too.
        let mut items: Vec<Item> = (0..2)
            .map(|n| {
                with_password(
                    login(
                        &format!("h{n}"),
                        &format!("Copy {n}"),
                        &["https://site.example"],
                    ),
                    &format!("current-{n}"),
                )
            })
            .collect();
        for n in 0..5 {
            items[0].fields.push(Field::new(
                &format!("history-{n}"),
                "Replaced",
                FieldKind::Concealed,
                format!("old-{n}"),
            ));
        }
        let vault = Vault::new(items);
        let groups = scan_duplicates(&vault, &HashMap::new());
        let checked = check(&vault, &groups, vec![merge(&groups[0], groups[0].kept())]).unwrap();
        assert!(checked.ops[0].flags.contains(&Flag::PasswordsAsFields));
    }

    #[test]
    fn the_trash_and_what_changes_an_organization_are_not_checked_by_default() {
        let mut shared_a = login("sa", "Shared A", &["https://site.example"]);
        let mut shared_b = login("sb", "Shared B", &["https://site.example"]);
        shared_in(&mut shared_a, &["col"]);
        shared_in(&mut shared_b, &["col"]);
        let own = login("own", "Own", &["https://own.example"]);
        let vault = Vault::new(vec![shared_a, shared_b, own]);
        let groups = scan_duplicates(&vault, &HashMap::new());
        assert_eq!(groups.len(), 1, "{groups:?}");
        let checked = check(
            &vault,
            &groups,
            vec![
                merge(&groups[0], "sa"),
                archive("own"),
                trash("own-never"),
                rename("sa", "Shared A2"),
            ],
        )
        .unwrap();
        let on = |index: usize| {
            checked
                .ops
                .iter()
                .find(|o| o.index == index)
                .map(CheckedOp::default_on)
        };
        assert_eq!(on(0), Some(false), "a merge of organization items");
        assert_eq!(on(1), Some(true), "an archive of a personal item");
        assert_eq!(on(3), Some(true), "a rename is not destructive");
        let checked = check(&vault, &groups, vec![archive("sb"), trash("own")]).unwrap();
        assert!(!checked.ops[0].default_on(), "archiving an organization's");
        assert!(!checked.ops[1].default_on(), "the trash is never checked");
        let trash_of_shared = check(&vault, &groups, vec![trash("sb")]).unwrap();
        assert!(!trash_of_shared.ops[0].default_on());
    }

    #[test]
    fn organization_items_in_other_collections_are_not_merged() {
        let mut a = login("a", "One", &["https://site.example"]);
        let mut b = login("b", "Two", &["https://site.example"]);
        shared_in(&mut a, &["col-1"]);
        shared_in(&mut b, &["col-1", "col-2"]);
        let vault = Vault::new(vec![a, b]);
        let groups = scan_duplicates(&vault, &HashMap::new());
        assert_eq!(groups.len(), 1);
        let checked = check(&vault, &groups, vec![merge(&groups[0], "a")]).unwrap_err();
        assert!(checked.contains("merge them in the app"), "{checked}");
    }

    #[test]
    fn a_merge_refused_halfway_leaves_nothing_claimed() {
        let items: Vec<Item> = ["a", "b", "c"]
            .iter()
            .map(|id| login(id, &format!("Copy {id}"), &["https://site.example"]))
            .collect();
        let vault = Vault::new(items);
        let groups = scan_duplicates(&vault, &HashMap::new());
        assert_eq!(groups[0].members.len(), 3);
        let keep = groups[0].kept().to_owned();
        let others: Vec<&str> = ["a", "b", "c"]
            .into_iter()
            .filter(|id| *id != keep)
            .collect();
        // The second member is archived first: the merge cannot take it, and
        // must not keep the first one claimed for it.
        let checked = check(
            &vault,
            &groups,
            vec![
                archive(others[1]),
                merge(&groups[0], &keep),
                trash(others[0]),
            ],
        )
        .unwrap();
        let kept: Vec<usize> = checked.ops.iter().map(|o| o.index).collect();
        assert_eq!(kept, [0, 2], "{:?}", reasons(&checked));
        assert!(reasons(&checked)[0].contains("already archives"));
    }

    #[test]
    fn what_the_review_shows_of_a_folder_is_cleaned() {
        let mut item = login("a", "GitHub", &[]);
        item.folder = Some("Wo\u{202E}rk\nfolder".to_owned());
        let vault = Vault::new(vec![item]);
        let checked = check(&vault, &[], vec![archive("a")]).unwrap();
        let from = &checked.ops[0].display.from;
        assert!(
            !from.contains('\u{202E}') && !from.contains('\n'),
            "{from:?}"
        );
    }

    #[test]
    fn a_name_two_folders_share_takes_no_move() {
        let vault = Vault::new(vec![login("a", "GitHub", &[])]);
        let folders = ["Work".to_owned(), "Work".to_owned(), "Home".to_owned()];
        let ask = |ops| {
            validate(
                &plan(ops),
                &vault,
                &Context {
                    groups: &[],
                    attachments: &HashMap::new(),
                    folders: &folders,
                    password_dates: &HashMap::new(),
                },
            )
        };
        let err = ask(vec![relocate("a", "Work")]).unwrap_err();
        assert!(err.contains("several folders have this name"), "{err}");
        assert_eq!(ask(vec![relocate("a", "Home")]).unwrap().ops.len(), 1);
    }

    #[test]
    fn a_site_is_only_what_looks_like_an_address() {
        let item = login(
            "a",
            "GitHub",
            &[
                "hunter2-typed-in-the-wrong-field",
                "password123",
                "https://ok.example/path?token=x",
                "example.org",
                "localhost:8080",
                "http://intranet/home",
            ],
        );
        let sites = sites_of(&item);
        assert!(sites.contains(&"ok.example".to_owned()), "{sites:?}");
        assert!(sites.contains(&"example.org".to_owned()), "{sites:?}");
        assert!(sites.contains(&"intranet".to_owned()), "{sites:?}");
        let joined = sites.join(" ");
        assert!(
            !joined.contains("hunter2") && !joined.contains("password123"),
            "{sites:?}"
        );
    }

    #[test]
    fn the_review_says_which_item_gives_the_merged_password() {
        let (vault, groups) = two_accounts();
        let group = &groups[0];
        let kept = group.kept().to_owned();
        let other = if kept == "a" { "b" } else { "a" };
        let title_of = |id: &str| vault.get(id).unwrap().title.clone();
        // Without dates, items count from their creation (equal here): the
        // kept item's password stays.
        let checked = check(&vault, &groups, vec![merge(group, &kept)]).unwrap();
        assert_eq!(checked.ops[0].display.password_from, "");
        // The other item's password changed more recently.
        let dates = HashMap::from([(kept.clone(), 1_000), (other.to_owned(), 2_000)]);
        let checked = validate(
            &plan(vec![merge(group, &kept)]),
            &vault,
            &Context {
                groups: &groups,
                attachments: &HashMap::new(),
                folders: &[],
                password_dates: &dates,
            },
        )
        .unwrap();
        assert_eq!(checked.ops[0].display.password_from, title_of(other));
    }
}
