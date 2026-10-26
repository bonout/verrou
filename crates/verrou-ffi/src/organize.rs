//! An agent's reorganization plan, reviewed and applied from the app.
//!
//! The bridge checks the plan when the agent proposes it
//! (`verrou_bridge::organize`) and hands it to the app as an
//! [`OrganizeReview`]: operations to check, each with what Verrou knows
//! about it and, apart, what the agent says. The user's one Touch ID applies
//! the checked ones: [`VaultSession::apply_organize_plan`] checks them
//! against the vault once more (it may have changed during the review) and
//! carries them out through the same write path as the app's own actions:
//! offline queue, conflicts, one sync at the end of each step.
//!
//! The order is the one that cannot lose anything: folders, then merges (a
//! merge writes the kept item before it trashes the others), renames, moves,
//! archives, the trash. An operation that fails does not stop the others and
//! is never retried by itself; the report says which failed and why.
//!
//! The undo record ([`OrganizeUndo`]) names what was done: restores what
//! went to the trash, unarchives, moves back, restores titles. It touches an
//! item only if it still is as the plan left it. New folders stay; a kept
//! item keeps what a merge gave it. It holds titles and identifiers, never a
//! secret, and the app drops it when the vault locks.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use verrou_bridge::organize::{self, CheckedOp, Context, Flag, PlanReview, Refused};
use verrou_bridge::protocol::{PlanFailure, PlanOp, PlanReport};
use verrou_core::{ItemState, Vault};
use verrou_vaultwarden::{BulkAction, BulkFailure, BulkOutcome, MergeSnapshot, Skipped};

use crate::bulk::BulkProgress;
use crate::{VaultSession, VerrouError};

/// How long the user can undo an applied plan, in seconds.
const UNDO_WINDOW: i64 = 10 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OrganizeKind {
    CreateFolder,
    Move,
    Rename,
    Merge,
    Archive,
    Trash,
}

/// What the user should know about an operation before checking it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OrganizeFlag {
    /// Asks for confirmation before it releases a secret.
    Protected,
    /// Belongs to an organization.
    Shared,
    /// A merge of items with different passwords.
    DifferentPasswords,
    /// A merge into another item than the suggested one.
    KeepDiffers,
    /// A merge of items with different usernames: maybe two accounts.
    DifferentUsernames,
    /// A merge of items with different one-time code seeds.
    OtherTotp,
    /// A merge with more passwords than a history holds: the rest becomes
    /// hidden fields of the kept item.
    PasswordsAsFields,
}

impl From<Flag> for OrganizeFlag {
    fn from(flag: Flag) -> Self {
        match flag {
            Flag::Protected => Self::Protected,
            Flag::Shared => Self::Shared,
            Flag::DifferentPasswords => Self::DifferentPasswords,
            Flag::KeepDiffersFromSuggestion => Self::KeepDiffers,
            Flag::DifferentUsernames => Self::DifferentUsernames,
            Flag::OtherTotp => Self::OtherTotp,
            Flag::PasswordsAsFields => Self::PasswordsAsFields,
        }
    }
}

/// An operation of the plan, to check. No secret: titles and folder names
/// only, and the agent's words, cleaned.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeOpView {
    /// Position in the plan: what `apply_organize_plan` takes.
    pub index: u32,
    pub kind: OrganizeKind,
    /// The item (the kept item of a merge, the new folder).
    pub title: String,
    /// The new title, the destination folder (empty: out of any folder).
    pub detail: String,
    /// The old title, the current folder (empty: none).
    pub from: String,
    /// A merge: the titles of the items that go to the trash.
    pub members: Vec<String>,
    /// A merge: the item whose password becomes the current one, when it is
    /// not the kept item's (empty: the kept item's stays).
    pub password_from: String,
    /// What the agent says about this one.
    pub rationale: String,
    pub flags: Vec<OrganizeFlag>,
    /// A move into a new folder: the operation that creates it.
    pub depends_on: Option<u32>,
    /// Checked when the review opens.
    pub default_on: bool,
}

/// An operation Verrou refused when it was proposed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeRefusedView {
    pub index: u32,
    pub what: String,
    pub reason: String,
}

/// A plan to review.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeReview {
    pub id: String,
    /// The terminal client, as it announced itself (an agent's name is
    /// declared by itself: only as trustworthy as that).
    pub client_name: String,
    /// The agent's reason for the whole plan.
    pub reason: String,
    /// Seconds left to review it.
    pub expires_in: u32,
    pub ops: Vec<OrganizeOpView>,
    pub refused: Vec<OrganizeRefusedView>,
}

fn index(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn op_view(op: &CheckedOp) -> OrganizeOpView {
    OrganizeOpView {
        index: index(op.index),
        kind: match op.op {
            // An unsupported operation never passes the rules.
            PlanOp::CreateFolder { .. } | PlanOp::Unsupported => OrganizeKind::CreateFolder,
            PlanOp::Move { .. } => OrganizeKind::Move,
            PlanOp::Rename { .. } => OrganizeKind::Rename,
            PlanOp::Merge { .. } => OrganizeKind::Merge,
            PlanOp::Archive { .. } => OrganizeKind::Archive,
            PlanOp::Trash { .. } => OrganizeKind::Trash,
        },
        title: op.display.title.clone(),
        detail: op.display.detail.clone(),
        from: op.display.from.clone(),
        members: op.display.members.clone(),
        password_from: op.display.password_from.clone(),
        rationale: op.rationale.clone(),
        flags: op.flags.iter().copied().map(Into::into).collect(),
        depends_on: op.depends_on.map(index),
        default_on: op.default_on(),
    }
}

impl From<PlanReview> for OrganizeReview {
    fn from(review: PlanReview) -> Self {
        Self {
            id: review.id,
            client_name: review.client_name,
            reason: review.reason,
            expires_in: u32::try_from(review.expires_in).unwrap_or(u32::MAX),
            ops: review.ops.iter().map(op_view).collect(),
            refused: review
                .refused
                .into_iter()
                .map(
                    |Refused {
                         index: i,
                         what,
                         reason,
                     }| OrganizeRefusedView {
                        index: index(i),
                        what,
                        reason,
                    },
                )
                .collect(),
        }
    }
}

/// An operation that failed when applied.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeFailure {
    pub index: u32,
    /// The operation's name (`move`, `merge`…).
    pub op: String,
    pub reason: String,
}

/// What came of applying a plan.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeReport {
    /// Operations carried out (the queued ones included).
    pub applied: u32,
    /// Of which waiting for the server (offline).
    pub queued: u32,
    /// Left as they were: already as wanted, or not checked.
    pub unchanged: u32,
    pub failed: Vec<OrganizeFailure>,
}

/// An item moved to a folder: where it was, to put it back.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UndoMove {
    pub item: String,
    /// The folder the plan put it in (empty: none): it is moved back only
    /// if it still is there.
    pub to: String,
    /// The folder it came from, `None`: no folder.
    pub previous: Option<String>,
}

/// An item renamed: the title the plan gave it, and the one it had.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UndoRename {
    pub item: String,
    pub from: String,
    pub to: String,
}

/// What it takes to undo an applied plan.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeUndo {
    pub plan: String,
    /// Unix time after which it is no longer offered.
    pub expires: i64,
    /// Items the plan put in the trash (merged away, trashed).
    pub trashed: Vec<String>,
    pub archived: Vec<String>,
    pub moves: Vec<UndoMove>,
    pub renames: Vec<UndoRename>,
    /// The kept items of the merges: put back as they were if nobody
    /// changed them since. What it takes (the item as it was, with its
    /// secrets) stays in the app's memory, not in this record.
    pub merged: Vec<String>,
}

impl OrganizeUndo {
    /// Nothing to undo (everything failed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.trashed.is_empty()
            && self.archived.is_empty()
            && self.moves.is_empty()
            && self.renames.is_empty()
            && self.merged.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OrganizeOutcome {
    pub report: OrganizeReport,
    pub undo: OrganizeUndo,
}

/// What came of undoing.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct UndoReport {
    /// Changes put back.
    pub restored: u32,
    /// Left alone: the item is no longer as the plan left it.
    pub skipped: u32,
    pub failures: Vec<String>,
}

fn invalid(message: impl Into<String>) -> VerrouError {
    VerrouError::Invalid {
        message: message.into(),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The item an operation changes (the kept item of a merge); none for a
/// folder.
fn item_of(op: &CheckedOp) -> Option<&str> {
    match &op.op {
        PlanOp::Move { item, .. }
        | PlanOp::Rename { item, .. }
        | PlanOp::Archive { item, .. }
        | PlanOp::Trash { item, .. } => Some(item),
        PlanOp::Merge { keep, .. } => Some(keep),
        PlanOp::CreateFolder { .. } | PlanOp::Unsupported => None,
    }
}

fn skipped_reason(skipped: Skipped) -> &'static str {
    match skipped {
        Skipped::ReadOnly => "shared read-only with this account",
        Skipped::InTrash => "it is in the trash",
        Skipped::NotFound => "it is no longer in the vault",
        Skipped::AlreadyShared | Skipped::NotShared | Skipped::PasswordsHidden => {
            "the server does not allow it for this item"
        }
    }
}

/// An item as the vault had it before the plan.
struct Before {
    title: String,
    folder: Option<String>,
}

/// The state of an apply: what was done, failed and can be undone.
struct Run<'a> {
    session: &'a VaultSession,
    connection: std::sync::Arc<tokio::sync::Mutex<verrou_vaultwarden::Connection>>,
    progress: &'a dyn BulkProgress,
    before: HashMap<String, Before>,
    /// Folder name → identifier: the account's, then those just created.
    /// A name that several folders have is not here: nothing is moved
    /// into, or back to, a folder that cannot be told from another.
    folders: HashMap<String, String>,
    ambiguous: HashSet<String>,
    /// The kept items of the merges, as they were.
    snapshots: Vec<MergeSnapshot>,
    report: OrganizeReport,
    undo: OrganizeUndo,
    handled: HashSet<usize>,
    done: usize,
    total: usize,
}

impl Run<'_> {
    fn fail(&mut self, op: &CheckedOp, reason: impl Into<String>) {
        self.handled.insert(op.index);
        self.report.failed.push(OrganizeFailure {
            index: index(op.index),
            op: op.op.name().to_owned(),
            reason: reason.into(),
        });
    }

    fn succeed(&mut self, op: &CheckedOp) {
        self.handled.insert(op.index);
        self.report.applied += 1;
    }

    fn step(&mut self, n: usize) {
        self.done += n;
        self.progress.progress(index(self.done), index(self.total));
    }

    fn title_of(&self, id: &str) -> String {
        self.before
            .get(id)
            .map(|b| b.title.clone())
            .unwrap_or_default()
    }

    /// Folders first: a move into a new folder waits for it.
    async fn create_folders(
        &mut self,
        ops: &[&CheckedOp],
        blocked: &mut HashSet<String>,
    ) -> Result<(), VerrouError> {
        for op in ops {
            let PlanOp::CreateFolder { name, .. } = &op.op else {
                continue;
            };
            let created = self.connection.lock().await.create_folder(name).await;
            match created {
                Ok((id, vault)) => {
                    self.session.install_if_current(&self.connection, vault)?;
                    self.folders.insert(name.clone(), id);
                    self.succeed(op);
                }
                Err(error) => {
                    blocked.insert(name.clone());
                    self.fail(op, error.to_string());
                }
            }
            self.step(1);
        }
        Ok(())
    }

    /// Merges, one at a time: the kept item is written first, so a failure
    /// loses nothing.
    async fn merges(&mut self, ops: &[&CheckedOp]) -> Result<(), VerrouError> {
        for op in ops {
            let PlanOp::Merge { keep, .. } = &op.op else {
                continue;
            };
            let merged = self
                .connection
                .lock()
                .await
                .merge_duplicates(keep, &op.others)
                .await;
            match merged {
                Ok(outcome) => {
                    self.session
                        .install_written(&self.connection, outcome.vault)?;
                    self.undo.trashed.extend(op.others.iter().cloned());
                    self.undo.merged.push(keep.clone());
                    self.snapshots.push(outcome.snapshot);
                    self.succeed(op);
                }
                Err(error) => self.fail(op, error.to_string()),
            }
            self.step(1);
        }
        Ok(())
    }

    /// What a bulk step did, operation by operation: the items it set aside
    /// or refused fail, the others are done. Returns the ones that were.
    fn settle<'o>(&mut self, ops: &[&'o CheckedOp], outcome: &BulkOutcome) -> Vec<&'o CheckedOp> {
        let (done, failures) = sort_outcome(ops, &outcome.skipped, &outcome.failed);
        for (op, reason) in failures {
            self.fail(op, reason);
        }
        for op in &done {
            self.succeed(op);
        }
        // Items already as wanted need no write and are not changes.
        let already = outcome.done.saturating_sub(outcome.queued);
        self.report.applied = self
            .report
            .applied
            .saturating_sub(index(already.min(done.len())));
        self.report.unchanged += index(already.min(done.len()));
        done
    }

    /// One bulk action on these operations' items.
    async fn bulk(
        &mut self,
        ops: &[&CheckedOp],
        action: BulkAction,
    ) -> Result<Vec<CheckedOp>, VerrouError> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = ops
            .iter()
            .filter_map(|op| item_of(op))
            .map(str::to_owned)
            .collect();
        let (base, total, progress) = (self.done, self.total, self.progress);
        let report = move |done: usize, _: usize| {
            progress.progress(index(base + done), index(total));
        };
        let outcome = self
            .connection
            .lock()
            .await
            .bulk(&ids, &action, &report)
            .await;
        let done = match outcome {
            Ok(outcome) => {
                let done = self.settle(ops, &outcome);
                self.session
                    .install_if_current(&self.connection, outcome.vault)?;
                done.into_iter().cloned().collect()
            }
            Err(error) => {
                for op in ops {
                    self.fail(op, error.to_string());
                }
                Vec::new()
            }
        };
        self.step(ops.len());
        Ok(done)
    }

    async fn renames(&mut self, ops: &[&CheckedOp]) -> Result<(), VerrouError> {
        if ops.is_empty() {
            return Ok(());
        }
        let renames: Vec<(String, String)> = ops
            .iter()
            .filter_map(|op| match &op.op {
                PlanOp::Rename { item, title, .. } => Some((item.clone(), title.clone())),
                _ => None,
            })
            .collect();
        let (base, total, progress) = (self.done, self.total, self.progress);
        let report = move |done: usize, _: usize| {
            progress.progress(index(base + done), index(total));
        };
        let outcome = self
            .connection
            .lock()
            .await
            .bulk_rename(&renames, &report)
            .await;
        match outcome {
            Ok(outcome) => {
                let done = self.settle(ops, &outcome);
                for op in done {
                    if let PlanOp::Rename { item, title, .. } = &op.op {
                        self.undo.renames.push(UndoRename {
                            item: item.clone(),
                            from: self.title_of(item),
                            to: title.clone(),
                        });
                    }
                }
                self.session
                    .install_if_current(&self.connection, outcome.vault)?;
            }
            Err(error) => {
                for op in ops {
                    self.fail(op, error.to_string());
                }
            }
        }
        self.step(ops.len());
        Ok(())
    }

    /// Moves, one bulk action per destination folder.
    async fn moves(
        &mut self,
        ops: &[&CheckedOp],
        blocked: &HashSet<String>,
    ) -> Result<(), VerrouError> {
        let mut by_folder: Vec<(String, Vec<&CheckedOp>)> = Vec::new();
        for op in ops {
            let PlanOp::Move { folder, .. } = &op.op else {
                continue;
            };
            if blocked.contains(folder) {
                self.fail(op, format!("the folder “{folder}” could not be created"));
                self.step(1);
                continue;
            }
            if self.ambiguous.contains(folder) {
                self.fail(
                    op,
                    "several folders have this name: move it in the app".to_owned(),
                );
                self.step(1);
                continue;
            }
            match by_folder.iter_mut().find(|(name, _)| name == folder) {
                Some((_, group)) => group.push(op),
                None => by_folder.push((folder.clone(), vec![*op])),
            }
        }
        for (folder, group) in by_folder {
            let target = if folder.is_empty() {
                None
            } else if let Some(id) = self.folders.get(&folder) {
                Some(id.clone())
            } else {
                for op in &group {
                    self.fail(op, format!("the folder “{folder}” is not in the account"));
                }
                self.step(group.len());
                continue;
            };
            let done = self.bulk(&group, BulkAction::MoveToFolder(target)).await?;
            for op in done {
                let PlanOp::Move { item, folder, .. } = &op.op else {
                    continue;
                };
                // Where it was: only worth putting back if that folder can
                // be named.
                let before = self.before.get(item).and_then(|b| b.folder.clone());
                let previous = match before {
                    None => Some(None),
                    Some(name) => self.folders.get(&name).map(|id| Some(id.clone())),
                };
                if let Some(previous) = previous {
                    self.undo.moves.push(UndoMove {
                        item: item.clone(),
                        to: folder.clone(),
                        previous,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Which operations a bulk step did and which it did not, by the identifier
/// of their item (two items may share a title, a title may change). A
/// refused rename is never reported as done.
fn sort_outcome<'o>(
    ops: &[&'o CheckedOp],
    skipped: &[(String, Skipped)],
    failed: &[BulkFailure],
) -> (Vec<&'o CheckedOp>, Vec<(&'o CheckedOp, String)>) {
    let skipped: HashMap<&str, Skipped> = skipped
        .iter()
        .map(|(id, reason)| (id.as_str(), *reason))
        .collect();
    let refused: HashMap<&str, &str> = failed
        .iter()
        .map(|f| (f.id.as_str(), f.reason.as_str()))
        .collect();
    let (mut done, mut failures) = (Vec::new(), Vec::new());
    for op in ops {
        let id = item_of(op).unwrap_or_default();
        if let Some(reason) = skipped.get(id) {
            failures.push((*op, skipped_reason(*reason).to_owned()));
        } else if let Some(reason) = refused.get(id) {
            failures.push((*op, (*reason).to_owned()));
        } else {
            done.push(*op);
        }
    }
    (done, failures)
}

/// What undoing a plan would do now, from the vault as it is: a change is
/// only put back on an item that still is as the plan left it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UndoSteps {
    pub restore: Vec<String>,
    pub unarchive: Vec<String>,
    /// Folder to put them back in (`None`: no folder), and the items.
    pub moves: Vec<(Option<String>, Vec<String>)>,
    pub renames: Vec<(String, String)>,
    /// Kept items of merges to put back, if their snapshot says they still
    /// are as the merge left them.
    pub merges: Vec<String>,
    /// Records left alone: the item changed since, or is gone.
    pub skipped: usize,
}

pub(crate) fn undo_steps(undo: &OrganizeUndo, vault: &Vault) -> UndoSteps {
    let mut steps = UndoSteps::default();
    let mut count = |ok: bool| {
        if !ok {
            steps.skipped += 1;
        }
        ok
    };
    let (mut restore, mut unarchive) = (Vec::new(), Vec::new());
    for id in &undo.trashed {
        if count(vault.get(id).is_some_and(|i| i.state == ItemState::Trashed)) {
            restore.push(id.clone());
        }
    }
    for id in &undo.archived {
        if count(
            vault
                .get(id)
                .is_some_and(|i| i.state == ItemState::Archived),
        ) {
            unarchive.push(id.clone());
        }
    }
    let mut moves: Vec<(Option<String>, Vec<String>)> = Vec::new();
    for back in &undo.moves {
        let still_there = vault.get(&back.item).is_some_and(|i| {
            i.state != ItemState::Trashed && i.folder.clone().unwrap_or_default() == back.to
        });
        if !count(still_there) {
            continue;
        }
        match moves
            .iter_mut()
            .find(|(folder, _)| *folder == back.previous)
        {
            Some((_, items)) => items.push(back.item.clone()),
            None => moves.push((back.previous.clone(), vec![back.item.clone()])),
        }
    }
    let mut renames = Vec::new();
    for back in &undo.renames {
        let unchanged = vault.get(&back.item).is_some_and(|i| i.title == back.to);
        if count(unchanged) {
            renames.push((back.item.clone(), back.from.clone()));
        }
    }
    for id in &undo.merged {
        if count(vault.get(id).is_some_and(|i| i.state != ItemState::Trashed)) {
            steps.merges.push(id.clone());
        }
    }
    steps.restore = restore;
    steps.unarchive = unarchive;
    steps.moves = moves;
    steps.renames = renames;
    steps
}

fn op_name(entries: &[(usize, PlanOp)], position: usize) -> String {
    entries
        .iter()
        .find(|(i, _)| *i == position)
        .map_or("unknown", |(_, op)| op.name())
        .to_owned()
}

/// How an operation checked again differs from the one the user approved, in
/// a way they did not see: a warning it did not have, other members of a
/// merge, another item whose password becomes current. `None`: the same.
fn changed_since(approved: &CheckedOp, now: &CheckedOp) -> Option<String> {
    if let Some(flag) = now.flags.iter().find(|f| !approved.flags.contains(f)) {
        return Some(flag_name(*flag).to_owned());
    }
    let (mut before, mut after) = (approved.others.clone(), now.others.clone());
    before.sort();
    after.sort();
    if before != after {
        return Some("the items to merge".to_owned());
    }
    if approved.display.password_from != now.display.password_from {
        return Some("the password that becomes current".to_owned());
    }
    None
}

/// What changed, in words: they go to the agent in the report, so nothing
/// that says whether passwords or one-time codes are equal.
fn flag_name(flag: Flag) -> &'static str {
    match flag {
        Flag::Protected => "the item now asks for confirmation",
        Flag::Shared => "the item is shared",
        Flag::KeepDiffersFromSuggestion => "another item would now be kept",
        Flag::DifferentUsernames => "the usernames differ",
        Flag::DifferentPasswords | Flag::OtherTotp | Flag::PasswordsAsFields => {
            "the contents of the items changed"
        }
    }
}

/// The report the agent reads.
fn plan_report(report: &OrganizeReport) -> PlanReport {
    PlanReport {
        applied: report.applied,
        queued: report.queued,
        unchanged: report.unchanged,
        failed: report
            .failed
            .iter()
            .map(|f| PlanFailure {
                index: f.index,
                op: f.op.clone(),
                reason: f.reason.clone(),
            })
            .collect(),
    }
}

impl VaultSession {
    /// Runs `f` on the bridge, if it runs.
    fn with_bridge<T>(&self, f: impl FnOnce(&verrou_bridge::Bridge) -> T) -> Option<T> {
        let bridge = self
            .bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        bridge.as_ref().map(f)
    }

    /// The checked operations of a plan, checked again against the vault as
    /// it is now. What no longer passes is reported as failed, what is
    /// already done as unchanged.
    async fn recheck(
        &self,
        connection: &std::sync::Arc<tokio::sync::Mutex<verrou_vaultwarden::Connection>>,
        approved: &[CheckedOp],
    ) -> Result<(Vec<CheckedOp>, Vec<OrganizeFailure>, usize), VerrouError> {
        let attachments = connection
            .lock()
            .await
            .attachment_counts()
            .unwrap_or_default();
        let folders: Vec<String> = self
            .folders
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|f| f.name.clone())
            .collect();
        let password_dates = connection.lock().await.password_dates().unwrap_or_default();
        let entries: Vec<(usize, PlanOp)> =
            approved.iter().map(|c| (c.index, c.op.clone())).collect();
        let checked = self.with_vault(|vault| {
            let groups = organize::scan_duplicates(vault, &attachments);
            Ok(organize::check_ops(
                &entries,
                vault,
                &Context {
                    groups: &groups,
                    attachments: &attachments,
                    folders: &folders,
                    password_dates: &password_dates,
                },
            ))
        })?;
        let mut failed: Vec<OrganizeFailure> = checked
            .refused
            .iter()
            .map(|r| OrganizeFailure {
                index: index(r.index),
                op: op_name(&entries, r.index),
                reason: format!("the vault changed since the review: {}", r.reason),
            })
            .collect();
        // What passes the rules again is not necessarily what the user
        // approved: a new warning, or other items in a merge, is a change
        // they did not see.
        let mut ops = Vec::new();
        for now in checked.ops {
            let Some(before) = approved.iter().find(|op| op.index == now.index) else {
                continue;
            };
            match changed_since(before, &now) {
                None => ops.push(now),
                Some(what) => failed.push(OrganizeFailure {
                    index: index(now.index),
                    op: op_name(&entries, now.index),
                    reason: format!("changed since the review: {what}"),
                }),
            }
        }
        Ok((ops, failed, checked.unchanged))
    }

    /// The account's folders by name, with the names that more than one folder
    /// has apart: nothing is moved into, or back to, a folder that cannot be
    /// told from another.
    fn folder_ids(&self) -> (HashMap<String, String>, HashSet<String>) {
        let mut folders: HashMap<String, String> = HashMap::new();
        let mut ambiguous: HashSet<String> = HashSet::new();
        for folder in self
            .folders
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            if folders
                .insert(folder.name.clone(), folder.id.clone())
                .is_some()
            {
                ambiguous.insert(folder.name.clone());
            }
        }
        for name in &ambiguous {
            folders.remove(name);
        }
        (folders, ambiguous)
    }

    /// Puts the kept items of merges back as they were, each only if nobody
    /// changed it since; what could not be is left as it is and counted.
    async fn undo_merges(
        &self,
        connection: &std::sync::Arc<tokio::sync::Mutex<verrou_vaultwarden::Connection>>,
        id: &str,
        kept: &[String],
        report: &mut UndoReport,
    ) -> Result<(), VerrouError> {
        if kept.is_empty() {
            return Ok(());
        }
        let snapshots = self
            .merge_undos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id)
            .unwrap_or_default();
        for item in kept {
            let Some(snapshot) = snapshots.iter().find(|s| s.id() == item) else {
                report.skipped += 1;
                continue;
            };
            let undone =
                Box::pin(async { connection.lock().await.undo_merge(snapshot).await }).await;
            match undone {
                Ok(Some(vault)) => {
                    report.restored += 1;
                    self.install_if_current(connection, vault)?;
                }
                // Edited since: left as it is, with what the merge gave it.
                Ok(None) => report.skipped += 1,
                Err(error) => report.failures.push(error.to_string()),
            }
        }
        Ok(())
    }

    /// Carries out the operations that passed the second check.
    async fn carry_out(
        &self,
        connection: std::sync::Arc<tokio::sync::Mutex<verrou_vaultwarden::Connection>>,
        id: &str,
        ops: &[CheckedOp],
        progress: &dyn BulkProgress,
        report: &mut OrganizeReport,
    ) -> Result<(OrganizeUndo, Vec<MergeSnapshot>), VerrouError> {
        let before: HashMap<String, Before> = self.with_vault(|vault| {
            Ok(ops
                .iter()
                .flat_map(|op| {
                    item_of(op)
                        .into_iter()
                        .chain(op.others.iter().map(String::as_str))
                })
                .filter_map(|item| {
                    let found = vault.get(item)?;
                    Some((
                        item.to_owned(),
                        Before {
                            title: found.title.clone(),
                            folder: found.folder.clone().filter(|f| !f.is_empty()),
                        },
                    ))
                })
                .collect())
        })?;
        let (folders, ambiguous) = self.folder_ids();
        let of = |pick: fn(&PlanOp) -> bool| -> Vec<&CheckedOp> {
            ops.iter().filter(|op| pick(&op.op)).collect()
        };
        let mut run = Run {
            session: self,
            connection,
            progress,
            before,
            folders,
            ambiguous,
            snapshots: Vec::new(),
            report: std::mem::take(report),
            undo: OrganizeUndo {
                plan: id.to_owned(),
                expires: now() + UNDO_WINDOW,
                ..OrganizeUndo::default()
            },
            handled: HashSet::new(),
            done: 0,
            total: ops.len(),
        };
        let mut blocked = HashSet::new();
        let phases = async {
            run.create_folders(
                &of(|op| matches!(op, PlanOp::CreateFolder { .. })),
                &mut blocked,
            )
            .await?;
            run.merges(&of(|op| matches!(op, PlanOp::Merge { .. })))
                .await?;
            run.renames(&of(|op| matches!(op, PlanOp::Rename { .. })))
                .await?;
            run.moves(&of(|op| matches!(op, PlanOp::Move { .. })), &blocked)
                .await?;
            let archived = run
                .bulk(
                    &of(|op| matches!(op, PlanOp::Archive { .. })),
                    BulkAction::Archive,
                )
                .await?;
            run.undo.archived.extend(
                archived
                    .iter()
                    .filter_map(|op| item_of(op).map(str::to_owned)),
            );
            let trashed = run
                .bulk(
                    &of(|op| matches!(op, PlanOp::Trash { .. })),
                    BulkAction::Trash,
                )
                .await?;
            run.undo.trashed.extend(
                trashed
                    .iter()
                    .filter_map(|op| item_of(op).map(str::to_owned)),
            );
            Ok::<(), VerrouError>(())
        }
        .await;
        // The vault locked meanwhile: what was not reached did not happen.
        if let Err(error) = &phases {
            let missed: Vec<&CheckedOp> = ops
                .iter()
                .filter(|op| !run.handled.contains(&op.index))
                .collect();
            for op in missed {
                run.fail(op, error.to_string());
            }
        }
        *report = run.report;
        phases?;
        // What is queued now is what the server did not take: offline. Not
        // what merely goes out a moment later.
        let _ = self.sync_shared(true).await;
        let waiting = run.connection.lock().await.pending_changes();
        report.queued = index(waiting.min(report.applied as usize));
        Ok((run.undo, run.snapshots))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VaultSession {
    /// Applies the operations the user checked (`accepted`: their positions
    /// in the plan), once Touch ID has been given. They are checked against
    /// the vault again, then carried out in an order that cannot lose
    /// anything (see the module header). Whatever happens, the agent is
    /// told how it ended.
    pub async fn apply_organize_plan(
        &self,
        id: String,
        accepted: Vec<u32>,
        progress: Box<dyn BulkProgress>,
    ) -> Result<OrganizeOutcome, VerrouError> {
        let Some(connection) = self.current_connection() else {
            return Err(if self.is_unlocked() {
                invalid("mock vault: read-only")
            } else {
                VerrouError::Locked
            });
        };
        let accepted: Vec<usize> = accepted.iter().map(|i| *i as usize).collect();
        let approved = self
            .with_bridge(|bridge| bridge.take_plan(&id, &accepted))
            .ok_or_else(|| invalid("the bridge is not running"))?
            .map_err(invalid)?;
        let mut report = OrganizeReport::default();
        let outcome = async {
            let (ops, failed, unchanged) = self.recheck(&connection, &approved.ops).await?;
            report.failed = failed;
            report.unchanged = index(unchanged);
            Box::pin(self.carry_out(connection, &id, &ops, &*progress, &mut report)).await
        }
        .await;
        let (undo, snapshots) = match outcome {
            Ok(done) => done,
            Err(error) => {
                // The agent must not wait for an application that stopped:
                // it is told that it stopped, and what was done before.
                self.with_bridge(|bridge| {
                    bridge.interrupt_plan(
                        &id,
                        plan_report(&report),
                        "applying the plan stopped before the end (Verrou was locked, or the vault no longer fit the plan): the report says what was done before; nothing more will be",
                    );
                });
                return Err(error);
            }
        };
        if !snapshots.is_empty() {
            self.merge_undos
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id.clone(), snapshots);
        }
        self.with_bridge(|bridge| bridge.finish_plan(&id, plan_report(&report)));
        Ok(OrganizeOutcome { report, undo })
    }

    /// The user declines the plan. `away`: they are not at the Mac, where
    /// a plan is reviewed (the agent is told so).
    pub fn decline_organize_plan(&self, id: String, away: bool) {
        let message = if away {
            // Whether the user is at the Mac is not for the agent to learn.
            "plans are reviewed in Verrou on the Mac; try again later: nothing was applied"
        } else {
            "the user declined the plan: nothing was applied"
        };
        self.with_bridge(|bridge| bridge.decline_plan(&id, message));
    }

    /// The user is still reviewing another plan (or its result): this one
    /// is declined at once, and the agent is told to wait.
    pub fn decline_organize_plan_busy(&self, id: String) {
        self.with_bridge(|bridge| {
            bridge.decline_plan(
                &id,
                "the user is still reviewing the previous plan: nothing was applied; wait for them before proposing another",
            );
        });
    }

    /// The user closed the sheet of this plan: the agent may propose another
    /// one, and what undoes its merges is dropped from memory.
    pub fn organize_plan_closed(&self, id: String) {
        self.merge_undos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        self.with_bridge(|bridge| bridge.plan_closed(&id));
    }

    /// Puts back what an applied plan changed, within ten minutes and as
    /// long as the vault stayed unlocked (no Touch ID: it only undoes what
    /// the user just approved). Only an item that still is as the plan left
    /// it is touched; folders created stay.
    pub async fn undo_organize_plan(
        &self,
        id: String,
        undo: OrganizeUndo,
        progress: Box<dyn BulkProgress>,
    ) -> Result<UndoReport, VerrouError> {
        let Some(connection) = self.current_connection() else {
            return Err(if self.is_unlocked() {
                invalid("mock vault: read-only")
            } else {
                VerrouError::Locked
            });
        };
        if undo.plan != id || now() > undo.expires {
            return Err(invalid("it is too late to undo this plan"));
        }
        let steps = self.with_vault(|vault| Ok(undo_steps(&undo, vault)))?;
        let total = steps.restore.len()
            + steps.merges.len()
            + steps.unarchive.len()
            + steps
                .moves
                .iter()
                .map(|(_, items)| items.len())
                .sum::<usize>()
            + steps.renames.len();
        let mut report = UndoReport {
            skipped: index(steps.skipped),
            ..UndoReport::default()
        };
        let mut done = 0;
        let mut settle = |count: usize, result: Result<BulkOutcome, verrou_vaultwarden::Error>| {
            done += count;
            progress.progress(index(done), index(total));
            match result {
                Ok(outcome) => {
                    report.restored += index(count.saturating_sub(outcome.skipped.len()));
                    report.skipped += index(outcome.skipped.len());
                    report.failures.extend(
                        outcome
                            .failed
                            .iter()
                            .map(|f| format!("{}: {}", f.title, f.reason)),
                    );
                    Some(outcome.vault)
                }
                Err(error) => {
                    report.failures.push(error.to_string());
                    None
                }
            }
        };
        let nothing = |_: usize, _: usize| {};
        if !steps.restore.is_empty() {
            let result = connection
                .lock()
                .await
                .bulk(&steps.restore, &BulkAction::Restore, &nothing)
                .await;
            let count = steps.restore.len();
            if let Some(vault) = settle(count, result) {
                self.install_if_current(&connection, vault)?;
            }
        }
        if !steps.unarchive.is_empty() {
            let result = connection
                .lock()
                .await
                .bulk(&steps.unarchive, &BulkAction::Unarchive, &nothing)
                .await;
            let count = steps.unarchive.len();
            if let Some(vault) = settle(count, result) {
                self.install_if_current(&connection, vault)?;
            }
        }
        for (folder, items) in &steps.moves {
            let action = BulkAction::MoveToFolder(folder.clone());
            let result = connection.lock().await.bulk(items, &action, &nothing).await;
            if let Some(vault) = settle(items.len(), result) {
                self.install_if_current(&connection, vault)?;
            }
        }
        if !steps.renames.is_empty() {
            let result = connection
                .lock()
                .await
                .bulk_rename(&steps.renames, &nothing)
                .await;
            let count = steps.renames.len();
            if let Some(vault) = settle(count, result) {
                self.install_if_current(&connection, vault)?;
            }
        }
        // The kept items of the merges, now that what they took from the
        // copies is back with the copies.
        self.undo_merges(&connection, &id, &steps.merges, &mut report)
            .await?;
        progress.progress(index(total), index(total));
        self.with_bridge(|bridge| bridge.mark_undone(&id));
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use verrou_bridge::organize::Display;
    use verrou_core::{Field, FieldKind, Item, ItemKind};

    use super::*;

    fn item(id: &str, title: &str, state: ItemState, folder: Option<&str>) -> Item {
        Item {
            id: id.to_owned(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: String::new(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: folder.map(str::to_owned),
            tags: Vec::new(),
            favorite: false,
            created: 0,
            modified: 0,
            fields: vec![Field::new(
                "password",
                "Password",
                FieldKind::Password,
                "pw",
            )],
            notes: None,
            reprompt: false,
            state,
            shared: None,
        }
    }

    struct Ignore;
    impl BulkProgress for Ignore {
        fn progress(&self, _: u32, _: u32) {}
    }

    fn checked(index: usize, op: PlanOp) -> CheckedOp {
        CheckedOp {
            index,
            op,
            rationale: "because".to_owned(),
            flags: vec![Flag::Protected],
            depends_on: Some(0),
            display: Display {
                title: "T".to_owned(),
                detail: "D".to_owned(),
                from: "F".to_owned(),
                members: vec!["M".to_owned()],
                password_from: "P".to_owned(),
            },
            others: Vec::new(),
        }
    }

    #[test]
    fn a_review_reaches_swift_with_what_the_user_decides_on() {
        let review = PlanReview {
            id: "abc".to_owned(),
            client: "client".to_owned(),
            client_name: "Coding Agent".to_owned(),
            reason: "tidy".to_owned(),
            ops: vec![checked(
                3,
                PlanOp::Archive {
                    item: "a".to_owned(),
                    rationale: "r".to_owned(),
                },
            )],
            refused: vec![Refused {
                index: 4,
                what: "rename “X”".to_owned(),
                reason: "no".to_owned(),
            }],
            expires_in: 600,
        };
        let view = OrganizeReview::from(review);
        assert_eq!(
            (view.client_name.as_str(), view.expires_in),
            ("Coding Agent", 600)
        );
        let op = &view.ops[0];
        assert_eq!(
            (op.index, op.kind, op.depends_on),
            (3, OrganizeKind::Archive, Some(0))
        );
        assert_eq!(op.flags, [OrganizeFlag::Protected]);
        assert!(!op.default_on, "protected: not checked by default");
        assert_eq!(view.refused[0].index, 4);
    }

    #[test]
    fn a_mock_or_locked_vault_applies_nothing_and_leaves_the_plan_alone() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = VaultSession::new();
        let locked =
            runtime.block_on(session.apply_organize_plan("abc".into(), vec![0], Box::new(Ignore)));
        assert!(matches!(locked, Err(VerrouError::Locked)));
        session.unlock_mock(0, 42, crate::MockLanguage::English);
        let mock =
            runtime.block_on(session.apply_organize_plan("abc".into(), vec![0], Box::new(Ignore)));
        assert!(matches!(mock, Err(VerrouError::Invalid { .. })));
        let undo = runtime.block_on(session.undo_organize_plan(
            "abc".into(),
            OrganizeUndo::default(),
            Box::new(Ignore),
        ));
        assert!(matches!(undo, Err(VerrouError::Invalid { .. })));
    }

    #[test]
    fn what_to_undo_is_what_still_is_as_the_plan_left_it() {
        let vault = Vault::new(vec![
            item("trashed", "Gone", ItemState::Trashed, None),
            item("edited", "Back from the trash", ItemState::Active, None),
            item("archived", "Shelf", ItemState::Archived, None),
            item("moved", "Moved", ItemState::Active, Some("Work")),
            item(
                "moved-again",
                "Moved again",
                ItemState::Active,
                Some("Elsewhere"),
            ),
            item("renamed", "New title", ItemState::Active, None),
            item("renamed-again", "Another title", ItemState::Active, None),
        ]);
        let undo = OrganizeUndo {
            plan: "abc".to_owned(),
            expires: i64::MAX,
            trashed: vec![
                "trashed".to_owned(),
                "edited".to_owned(),
                "missing".to_owned(),
            ],
            archived: vec!["archived".to_owned(), "edited".to_owned()],
            moves: vec![
                UndoMove {
                    item: "moved".to_owned(),
                    to: "Work".to_owned(),
                    previous: Some("folder-id".to_owned()),
                },
                UndoMove {
                    item: "moved-again".to_owned(),
                    to: "Work".to_owned(),
                    previous: None,
                },
            ],
            renames: vec![
                UndoRename {
                    item: "renamed".to_owned(),
                    from: "Old title".to_owned(),
                    to: "New title".to_owned(),
                },
                UndoRename {
                    item: "renamed-again".to_owned(),
                    from: "Old".to_owned(),
                    to: "New title".to_owned(),
                },
            ],
            // A kept item still there, one gone, one in the trash.
            merged: vec![
                "renamed".to_owned(),
                "missing".to_owned(),
                "trashed".to_owned(),
            ],
        };
        let steps = undo_steps(&undo, &vault);
        assert_eq!(steps.merges, ["renamed"]);
        assert_eq!(steps.restore, ["trashed"]);
        assert_eq!(steps.unarchive, ["archived"]);
        assert_eq!(
            steps.moves,
            [(Some("folder-id".to_owned()), vec!["moved".to_owned()])]
        );
        assert_eq!(
            steps.renames,
            [("renamed".to_owned(), "Old title".to_owned())]
        );
        // The item gone, the one restored by hand, the one moved or renamed
        // by someone since: left alone, and counted.
        assert_eq!(steps.skipped, 7);
        // An empty record undoes nothing.
        assert_eq!(
            undo_steps(&OrganizeUndo::default(), &vault),
            UndoSteps::default()
        );
    }

    #[test]
    fn the_undo_record_holds_no_secret() {
        let undo = OrganizeUndo {
            plan: "abc".to_owned(),
            expires: 1,
            trashed: vec!["id".to_owned()],
            renames: vec![UndoRename {
                item: "id".to_owned(),
                from: "Old".to_owned(),
                to: "New".to_owned(),
            }],
            ..OrganizeUndo::default()
        };
        assert!(!format!("{undo:?}").contains("pw"));
        assert!(!undo.is_empty() && OrganizeUndo::default().is_empty());
    }

    #[test]
    fn the_agent_reads_how_it_ended() {
        let report = OrganizeReport {
            applied: 3,
            queued: 1,
            unchanged: 2,
            failed: vec![OrganizeFailure {
                index: 4,
                op: "move".to_owned(),
                reason: "gone".to_owned(),
            }],
        };
        let told = plan_report(&report);
        assert_eq!((told.applied, told.queued, told.unchanged), (3, 1, 2));
        assert_eq!(told.failed[0].op, "move");
    }

    fn rename_op(index: usize, item: &str) -> CheckedOp {
        checked(
            index,
            PlanOp::Rename {
                item: item.to_owned(),
                title: "New".to_owned(),
                rationale: "r".to_owned(),
            },
        )
    }

    #[test]
    fn a_bulk_step_is_read_by_item_not_by_title() {
        // Two items with the same title: only one of them was refused, and
        // the refusal is not reported on the other.
        let (first, second, third) = (
            rename_op(0, "id-1"),
            rename_op(1, "id-2"),
            rename_op(2, "id-3"),
        );
        let ops = [&first, &second, &third];
        let failed = [BulkFailure {
            id: "id-2".to_owned(),
            title: "Same title".to_owned(),
            reason: "the title is required".to_owned(),
        }];
        let skipped = [("id-3".to_owned(), Skipped::InTrash)];
        let (done, failures) = sort_outcome(&ops, &skipped, &failed);
        assert_eq!(done.iter().map(|o| o.index).collect::<Vec<_>>(), [0]);
        let failures: Vec<(usize, &str)> = failures
            .iter()
            .map(|(op, reason)| (op.index, reason.as_str()))
            .collect();
        assert_eq!(
            failures,
            [(1, "the title is required"), (2, "it is in the trash")],
            "a refused rename is a failure, never an applied one"
        );
    }

    #[test]
    fn a_new_warning_or_other_members_is_a_change_the_user_did_not_see() {
        let merge = |others: &[&str], flags: Vec<Flag>, from: &str| {
            let mut op = checked(
                0,
                PlanOp::Merge {
                    group: "g".to_owned(),
                    keep: "a".to_owned(),
                    rationale: "r".to_owned(),
                },
            );
            op.flags = flags;
            op.others = others.iter().map(|s| (*s).to_owned()).collect();
            op.display.password_from = from.to_owned();
            op
        };
        let approved = merge(&["b", "c"], vec![Flag::DifferentPasswords], "");
        // The same, in another order: nothing changed.
        assert_eq!(
            changed_since(
                &approved,
                &merge(&["c", "b"], vec![Flag::DifferentPasswords], "")
            ),
            None
        );
        // A warning it gained.
        let gained = changed_since(
            &approved,
            &merge(
                &["b", "c"],
                vec![Flag::DifferentPasswords, Flag::Protected],
                "",
            ),
        );
        assert!(gained.unwrap().contains("confirmation"));
        let gained = changed_since(
            &approved,
            &merge(
                &["b", "c"],
                vec![Flag::DifferentPasswords, Flag::PasswordsAsFields],
                "",
            ),
        );
        let gained = gained.unwrap();
        assert!(gained.contains("contents"), "{gained}");
        assert!(
            !gained.to_lowercase().contains("password") && !gained.contains("code"),
            "what goes to the agent says nothing of secrets: {gained}"
        );
        // A warning it lost is not a reason to stop.
        assert_eq!(
            changed_since(&approved, &merge(&["b", "c"], Vec::new(), "")),
            None
        );
        // Other members, or another item giving its password.
        assert!(
            changed_since(
                &approved,
                &merge(&["b", "d"], vec![Flag::DifferentPasswords], "")
            )
            .unwrap()
            .contains("items to merge")
        );
        assert!(
            changed_since(
                &approved,
                &merge(&["b"], vec![Flag::DifferentPasswords], "")
            )
            .is_some()
        );
        assert!(
            changed_since(
                &approved,
                &merge(&["b", "c"], vec![Flag::DifferentPasswords], "Other")
            )
            .unwrap()
            .contains("password")
        );
    }

    #[test]
    fn the_snapshot_of_a_merge_never_prints_the_item() {
        // The merge snapshot is memory only: even a log of it shows nothing.
        let text = format!(
            "{:?}",
            OrganizeUndo {
                merged: vec!["a".to_owned()],
                ..OrganizeUndo::default()
            }
        );
        assert!(text.contains("merged") && !text.contains("pw"));
    }

    #[test]
    fn the_history_the_bridge_assumes_is_the_one_the_vault_keeps() {
        assert_eq!(
            organize::PASSWORD_HISTORY_LIMIT,
            verrou_vaultwarden::MAX_PASSWORD_HISTORY
        );
    }
}
