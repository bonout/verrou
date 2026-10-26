//! The plans an agent proposed, from the proposal to the answer.
//!
//! Where a plan stands is [`PlanState`]: awaiting the user's review, being
//! applied, then applied, declined, expired, cancelled or undone. The
//! agent reads it with `plan_status`, which can wait for it to change (a
//! review takes minutes: the agent's request is not held that long).
//!
//! A plan is the user's to answer, so what an agent may do is bounded here:
//! one plan awaiting review per client, one in review at all (the user is
//! not shown two), a pause after a plan was declined, and a few proposals an
//! hour (and a larger number of attempts, refused or not). A plan nobody
//! answers expires (the sheet closes); a finished plan is kept a few minutes
//! for the agent to read its outcome. While the user can still undo an
//! applied plan, the same client proposes no other: its result sheet is
//! still open. A plan belongs to the agent session that proposed it.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::organize::{CheckedOp, Refused};
use crate::protocol::{PlanPhase, PlanReport, PlanState, Rejection};

/// How long the user has to review a plan.
pub const REVIEW_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a finished plan stays readable by the agent.
pub const KEEP_FINISHED: Duration = Duration::from_secs(10 * 60);
/// After the user declined a plan, this client's next proposal is refused
/// for this long.
pub const DECLINE_PAUSE: Duration = Duration::from_secs(60);
/// Plans one client may propose within [`PROPOSAL_WINDOW`].
pub const MAX_PROPOSALS: usize = 6;
pub const PROPOSAL_WINDOW: Duration = Duration::from_secs(60 * 60);
/// Proposals one client may make within [`PROPOSAL_WINDOW`], counting those
/// Verrou refused: a client that proposes plans in a loop to probe the rules
/// is stopped.
pub const MAX_ATTEMPTS: usize = 30;
/// How long the user can undo an applied plan: the app's window, which this
/// side only uses to stop proposals meanwhile.
pub const UNDO_WINDOW: Duration = Duration::from_secs(10 * 60);

struct Entry {
    client: String,
    /// The agent session that proposed it ([`crate::protocol::clean_session`]).
    session: String,
    reason: String,
    ops: Vec<CheckedOp>,
    /// Operations that were already as wanted when proposed.
    unchanged: usize,
    /// Operations the user took to apply (checked).
    taken: usize,
    state: watch::Sender<PlanState>,
    expires: Instant,
    finished: Option<Instant>,
    /// Applied: until when the user can undo it (the result sheet is open).
    undo_until: Option<Instant>,
}

impl Entry {
    fn phase(&self) -> PlanPhase {
        self.state.borrow().state
    }

    /// Changes the phase, wakes whoever waits for it, and marks the end.
    fn set(&mut self, phase: PlanPhase, message: &str, now: Instant) {
        self.state.send_modify(|state| {
            state.state = phase;
            message.clone_into(&mut state.message);
            state.expires_in = None;
        });
        if !phase.is_open() {
            self.finished = Some(now);
        }
    }
}

/// What the app takes to carry out: the operations the user checked.
#[derive(Clone, Debug)]
pub struct ApprovedPlan {
    pub client: String,
    pub reason: String,
    pub ops: Vec<CheckedOp>,
}

#[derive(Default)]
pub struct Plans {
    entries: HashMap<String, Entry>,
    /// When each client's last plan was declined.
    declined: HashMap<String, Instant>,
    /// When each client proposed its recent plans (those that reached the
    /// user).
    proposals: HashMap<String, Vec<Instant>>,
    /// When each client made its recent proposals, refused or not.
    attempts: HashMap<String, Vec<Instant>>,
}

fn fresh_id() -> String {
    let bytes: [u8; 8] = rand::random();
    data_encoding::HEXLOWER.encode(&bytes)
}

impl Plans {
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            e.finished
                .is_none_or(|at| now.saturating_duration_since(at) < KEEP_FINISHED)
        });
        self.declined
            .retain(|_, at| now.saturating_duration_since(*at) < DECLINE_PAUSE);
        for times in self.proposals.values_mut() {
            times.retain(|at| now.saturating_duration_since(*at) < PROPOSAL_WINDOW);
        }
        self.proposals.retain(|_, times| !times.is_empty());
        for times in self.attempts.values_mut() {
            times.retain(|at| now.saturating_duration_since(*at) < PROPOSAL_WINDOW);
        }
        self.attempts.retain(|_, times| !times.is_empty());
        for entry in self.entries.values_mut() {
            if entry.undo_until.is_some_and(|until| now >= until) {
                entry.undo_until = None;
            }
        }
    }

    /// A proposal arrives, whatever becomes of it: counted. `Err`: too many.
    pub fn attempt(&mut self, client: &str, now: Instant) -> Result<(), String> {
        self.prune(now);
        let times = self.attempts.entry(client.to_owned()).or_default();
        if times.len() >= MAX_ATTEMPTS {
            return Err(format!(
                "at most {MAX_ATTEMPTS} proposals an hour, refused ones included: ask the user before proposing more"
            ));
        }
        times.push(now);
        Ok(())
    }

    /// May this client propose a plan now? `Err`: why not, for the agent.
    pub fn admit(&mut self, client: &str, now: Instant) -> Result<(), String> {
        self.prune(now);
        if let Some(at) = self.declined.get(client) {
            let left = DECLINE_PAUSE.saturating_sub(now.saturating_duration_since(*at));
            return Err(format!(
                "the user declined a plan a moment ago: do not propose another for {} seconds, and ask the user what they want first",
                left.as_secs() + 1
            ));
        }
        if let Some((id, _)) = self
            .entries
            .iter()
            .find(|(_, e)| e.client == client && e.phase().is_open())
        {
            return Err(format!(
                "plan {id} is still awaiting the user's review: call verrou_plan_status to wait for it, or verrou_plan_cancel to withdraw it"
            ));
        }
        if self.entries.values().any(|e| {
            e.client == client && e.phase() == PlanPhase::Applied && e.undo_until.is_some()
        }) {
            return Err(
                "the user is still reviewing the previous plan (they can undo it for ten minutes): do not propose another until they have closed it"
                    .to_owned(),
            );
        }
        if self.entries.values().any(|e| e.phase().is_open()) {
            return Err(
                "another plan is awaiting the user's review in Verrou: try again once they have answered it"
                    .to_owned(),
            );
        }
        if self.proposals.get(client).map_or(0, Vec::len) >= MAX_PROPOSALS {
            return Err(format!(
                "at most {MAX_PROPOSALS} plans an hour: ask the user before proposing more"
            ));
        }
        Ok(())
    }

    /// A checked plan, awaiting review: its identifier and state. The client
    /// is admitted again here, under the same lock that registers the plan:
    /// two proposals that were both admitted while their plans were being
    /// checked cannot both reach the user. `Err`: why not, for the agent.
    pub fn register(
        &mut self,
        client: &str,
        session: &str,
        reason: &str,
        checked: (Vec<CheckedOp>, Vec<Refused>, usize),
        now: Instant,
    ) -> Result<(String, PlanState), String> {
        self.admit(client, now)?;
        let (ops, refused, unchanged) = checked;
        let id = fresh_id();
        let state = PlanState {
            plan: id.clone(),
            state: PlanPhase::AwaitingReview,
            message: String::new(),
            expires_in: None,
            rejected: refused
                .iter()
                .map(|r| Rejection {
                    index: u32::try_from(r.index).unwrap_or(u32::MAX),
                    reason: r.reason.clone(),
                })
                .collect(),
            report: None,
        };
        let (sender, _) = watch::channel(state.clone());
        self.entries.insert(
            id.clone(),
            Entry {
                client: client.to_owned(),
                session: session.to_owned(),
                reason: reason.to_owned(),
                ops,
                unchanged,
                taken: 0,
                state: sender,
                expires: now + REVIEW_TTL,
                finished: None,
                undo_until: None,
            },
        );
        self.proposals
            .entry(client.to_owned())
            .or_default()
            .push(now);
        let shown = PlanState {
            expires_in: Some(REVIEW_TTL.as_secs()),
            ..state
        };
        Ok((id, shown))
    }

    /// A plan the app could not show: forgotten, and not counted.
    pub fn discard(&mut self, id: &str, client: &str) {
        self.entries.remove(id);
        if let Some(times) = self.proposals.get_mut(client) {
            times.pop();
        }
    }

    /// The state of the client's plan, with the time left to review it.
    pub fn state(
        &mut self,
        client: &str,
        session: &str,
        id: &str,
        now: Instant,
    ) -> Option<PlanState> {
        self.prune(now);
        let entry = self
            .entries
            .get(id)
            .filter(|e| e.client == client && e.session == session)?;
        let mut state = entry.state.borrow().clone();
        if state.state == PlanPhase::AwaitingReview {
            state.expires_in = Some(entry.expires.saturating_duration_since(now).as_secs());
        }
        Some(state)
    }

    /// Something to wait on for the client's plan to change.
    pub fn subscribe(
        &self,
        client: &str,
        session: &str,
        id: &str,
    ) -> Option<watch::Receiver<PlanState>> {
        self.entries
            .get(id)
            .filter(|e| e.client == client && e.session == session)
            .map(|e| e.state.subscribe())
    }

    /// Nobody reviewed the plan in time. `true`: it was awaiting review, and
    /// the app is to close it.
    pub fn expire(&mut self, id: &str, now: Instant) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if entry.phase() != PlanPhase::AwaitingReview {
            return false;
        }
        entry.set(
            PlanPhase::Expired,
            "nobody reviewed the plan in time: the user did not apply anything",
            now,
        );
        true
    }

    /// The agent withdraws its plan. `Ok(true)`: it was awaiting review, and
    /// the app is to close it.
    pub fn cancel(
        &mut self,
        client: &str,
        session: &str,
        id: &str,
        now: Instant,
    ) -> Result<bool, String> {
        let Some(entry) = self
            .entries
            .get_mut(id)
            .filter(|e| e.client == client && e.session == session)
        else {
            return Err("no such plan (a finished plan is kept ten minutes)".to_owned());
        };
        match entry.phase() {
            PlanPhase::AwaitingReview => {
                entry.set(PlanPhase::Cancelled, "the agent withdrew the plan", now);
                Ok(true)
            }
            PlanPhase::Applying => {
                Err("the user is applying this plan: it can no longer be withdrawn".to_owned())
            }
            _ => Ok(false),
        }
    }

    /// The user applies the operations at `accepted` (positions in the
    /// plan): the plan is now being applied, and these are to be carried out.
    pub fn take(
        &mut self,
        id: &str,
        accepted: &[usize],
        now: Instant,
    ) -> Result<ApprovedPlan, String> {
        let Some(entry) = self.entries.get_mut(id) else {
            return Err("this plan is no longer there".to_owned());
        };
        match entry.phase() {
            PlanPhase::AwaitingReview => {}
            PlanPhase::Expired => {
                return Err("this plan expired: ask the agent to propose it again".to_owned());
            }
            PlanPhase::Cancelled => return Err("the agent withdrew this plan".to_owned()),
            _ => return Err("this plan was already answered".to_owned()),
        }
        if now >= entry.expires {
            entry.set(
                PlanPhase::Expired,
                "nobody reviewed the plan in time: the user did not apply anything",
                now,
            );
            return Err("this plan expired: ask the agent to propose it again".to_owned());
        }
        let ops: Vec<CheckedOp> = entry
            .ops
            .iter()
            .filter(|op| accepted.contains(&op.index))
            .cloned()
            .collect();
        if ops.is_empty() {
            return Err("no operation was checked".to_owned());
        }
        entry.taken = ops.len();
        entry.set(PlanPhase::Applying, "", now);
        Ok(ApprovedPlan {
            client: entry.client.clone(),
            reason: entry.reason.clone(),
            ops,
        })
    }

    /// The plan was applied: what came of it.
    pub fn finish(&mut self, id: &str, mut report: PlanReport, now: Instant) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        let left = entry.unchanged + entry.ops.len().saturating_sub(entry.taken);
        report.unchanged = report
            .unchanged
            .saturating_add(u32::try_from(left).unwrap_or(u32::MAX));
        entry.state.send_modify(|state| state.report = Some(report));
        entry.set(PlanPhase::Applied, "", now);
        entry.undo_until = Some(now + UNDO_WINDOW);
    }

    /// Applying stopped halfway: what was done before, and why it stopped.
    /// There is nothing to undo.
    pub fn interrupt(&mut self, id: &str, mut report: PlanReport, message: &str, now: Instant) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        let left = entry.unchanged + entry.ops.len().saturating_sub(entry.taken);
        report.unchanged = report
            .unchanged
            .saturating_add(u32::try_from(left).unwrap_or(u32::MAX));
        entry.state.send_modify(|state| state.report = Some(report));
        entry.set(PlanPhase::Interrupted, message, now);
    }

    /// The user closed the result sheet: the client may propose again.
    pub fn closed(&mut self, id: &str) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.undo_until = None;
        }
    }

    /// The user declined the plan. The client's next proposal waits.
    pub fn decline(&mut self, id: &str, message: &str, now: Instant) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        if entry.phase() != PlanPhase::AwaitingReview {
            return;
        }
        let client = entry.client.clone();
        entry.set(PlanPhase::Declined, message, now);
        self.declined.insert(client, now);
    }

    /// The user undid the plan.
    pub fn undone(&mut self, id: &str, now: Instant) {
        if let Some(entry) = self.entries.get_mut(id)
            && entry.phase() == PlanPhase::Applied
        {
            entry.set(PlanPhase::Undone, "the user undid the plan", now);
            entry.undo_until = None;
        }
    }

    /// The vault locked: plans awaiting review are dropped (a plan being
    /// applied finishes: the app holds its connection).
    pub fn drop_all(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            // The undo record goes with the lock.
            entry.undo_until = None;
            if entry.phase() == PlanPhase::AwaitingReview {
                entry.set(
                    PlanPhase::Cancelled,
                    "Verrou was locked: the plan was dropped",
                    now,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organize::Display;
    use crate::protocol::PlanOp;

    fn op(index: usize) -> CheckedOp {
        CheckedOp {
            index,
            op: PlanOp::Archive {
                item: format!("item-{index}"),
                rationale: "r".to_owned(),
            },
            rationale: "r".to_owned(),
            flags: Vec::new(),
            depends_on: None,
            display: Display::default(),
            others: Vec::new(),
        }
    }

    fn propose(plans: &mut Plans, client: &str, now: Instant) -> String {
        plans.admit(client, now).unwrap();
        plans
            .register(
                client,
                "s",
                "tidy",
                (vec![op(0), op(1), op(2)], Vec::new(), 1),
                now,
            )
            .unwrap()
            .0
    }

    #[test]
    fn one_plan_per_client_and_one_in_review_at_all() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let first = propose(&mut plans, "a", now);
        let own = plans.admit("a", now).unwrap_err();
        assert!(
            own.contains(&first) && own.contains("verrou_plan_cancel"),
            "{own}"
        );
        let other = plans.admit("b", now).unwrap_err();
        assert!(other.contains("another plan is awaiting"), "{other}");
        // Answered: the next one may come.
        plans.decline(&first, "no", now);
        assert!(plans.admit("b", now).is_ok());
    }

    #[test]
    fn a_declined_plan_pauses_that_client_for_a_minute() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        plans.decline(&id, "the user declined", now);
        let state = plans.state("a", "s", &id, now).unwrap();
        assert_eq!(state.state, PlanPhase::Declined);
        assert_eq!(state.message, "the user declined");
        let soon = now + Duration::from_secs(30);
        assert!(plans.admit("a", soon).unwrap_err().contains("declined"));
        assert!(
            plans.admit("b", soon).is_ok(),
            "another client is not paused"
        );
        assert!(plans.admit("a", now + DECLINE_PAUSE).is_ok());
    }

    #[test]
    fn at_most_six_proposals_an_hour() {
        let mut plans = Plans::default();
        let mut now = Instant::now();
        for _ in 0..MAX_PROPOSALS {
            let id = propose(&mut plans, "a", now);
            assert!(plans.cancel("a", "s", &id, now).unwrap());
            now += Duration::from_secs(60);
        }
        assert!(plans.admit("a", now).unwrap_err().contains("at most 6"));
        assert!(plans.admit("b", now).is_ok());
        assert!(plans.admit("a", now + PROPOSAL_WINDOW).is_ok());
    }

    #[test]
    fn a_plan_nobody_answers_expires_and_a_late_apply_is_refused() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        let state = plans
            .state("a", "s", &id, now + Duration::from_secs(100))
            .unwrap();
        assert_eq!(state.expires_in, Some(500));
        // Applying after the time is up fails, and the plan reads as expired.
        let late = now + REVIEW_TTL;
        assert!(plans.take(&id, &[0], late).unwrap_err().contains("expired"));
        assert_eq!(
            plans.state("a", "s", &id, late).unwrap().state,
            PlanPhase::Expired
        );
        assert!(!plans.expire(&id, late), "once");
        assert!(
            plans.admit("a", late).is_ok(),
            "an expired plan frees the slot"
        );
    }

    #[test]
    fn taking_a_plan_moves_it_to_applying_with_the_checked_operations() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        assert!(
            plans
                .take(&id, &[], now)
                .unwrap_err()
                .contains("no operation")
        );
        assert!(
            plans
                .take(&id, &[7], now)
                .unwrap_err()
                .contains("no operation")
        );
        let taken = plans.take(&id, &[0, 2, 9], now).unwrap();
        assert_eq!(
            taken.ops.iter().map(|o| o.index).collect::<Vec<_>>(),
            [0, 2]
        );
        assert_eq!(
            plans.state("a", "s", &id, now).unwrap().state,
            PlanPhase::Applying
        );
        assert!(
            plans
                .take(&id, &[0], now)
                .unwrap_err()
                .contains("already answered")
        );
        assert!(
            plans
                .cancel("a", "s", &id, now)
                .unwrap_err()
                .contains("applying")
        );
        // The report counts what was left out: one already as wanted at
        // proposal, one not checked.
        plans.finish(
            &id,
            PlanReport {
                applied: 2,
                ..PlanReport::default()
            },
            now,
        );
        let state = plans.state("a", "s", &id, now).unwrap();
        assert_eq!(state.state, PlanPhase::Applied);
        assert_eq!(state.report.unwrap().unchanged, 2);
        plans.undone(&id, now);
        assert_eq!(
            plans.state("a", "s", &id, now).unwrap().state,
            PlanPhase::Undone
        );
    }

    #[test]
    fn only_the_proposing_client_sees_a_plan() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        assert!(plans.state("b", "s", &id, now).is_none());
        assert!(plans.subscribe("b", "s", &id).is_none());
        assert!(plans.cancel("b", "s", &id, now).is_err());
        assert!(plans.state("a", "s", "nope", now).is_none());
    }

    #[test]
    fn cancelling_withdraws_a_plan_awaiting_review_once() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        assert_eq!(plans.cancel("a", "s", &id, now), Ok(true));
        assert_eq!(plans.cancel("a", "s", &id, now), Ok(false), "already over");
        let state = plans.state("a", "s", &id, now).unwrap();
        assert_eq!(state.state, PlanPhase::Cancelled);
        assert!(plans.take(&id, &[0], now).unwrap_err().contains("withdrew"));
    }

    #[test]
    fn locking_drops_plans_awaiting_review_not_those_being_applied() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let waiting = propose(&mut plans, "a", now);
        plans.drop_all(now);
        let state = plans.state("a", "s", &waiting, now).unwrap();
        assert_eq!(state.state, PlanPhase::Cancelled);
        assert!(state.message.contains("locked"));
        let applying = propose(&mut plans, "a", now);
        plans.take(&applying, &[0], now).unwrap();
        plans.drop_all(now);
        assert_eq!(
            plans.state("a", "s", &applying, now).unwrap().state,
            PlanPhase::Applying
        );
    }

    #[test]
    fn finished_plans_are_forgotten_after_ten_minutes() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        plans.decline(&id, "no", now);
        assert!(
            plans
                .state("a", "s", &id, now + Duration::from_secs(599))
                .is_some()
        );
        assert!(plans.state("a", "s", &id, now + KEEP_FINISHED).is_none());
    }

    #[test]
    fn rejections_travel_with_the_state() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let refused = vec![Refused {
            index: 4,
            what: "rename".to_owned(),
            reason: "no such item".to_owned(),
        }];
        let (_, state) = plans
            .register("a", "s", "r", (vec![op(0)], refused, 0), now)
            .unwrap();
        assert_eq!(
            state.rejected,
            [Rejection {
                index: 4,
                reason: "no such item".to_owned()
            }]
        );
        assert_eq!(state.expires_in, Some(600));
    }

    #[test]
    fn discarding_a_plan_the_app_could_not_show_does_not_count() {
        let mut plans = Plans::default();
        let now = Instant::now();
        for _ in 0..10 {
            let id = propose(&mut plans, "a", now);
            plans.discard(&id, "a");
        }
        assert!(plans.admit("a", now).is_ok());
    }

    fn applied(plans: &mut Plans, client: &str, now: Instant) -> String {
        let id = propose(plans, client, now);
        plans.take(&id, &[0], now).unwrap();
        plans.finish(&id, PlanReport::default(), now);
        id
    }

    #[test]
    fn no_new_plan_while_the_result_of_the_last_can_be_undone() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = applied(&mut plans, "a", now);
        let refused = plans.admit("a", now).unwrap_err();
        assert!(refused.contains("still reviewing"), "{refused}");
        assert!(plans.admit("b", now).is_ok(), "another client is not held");
        // The undo window ends: the client may propose again.
        assert!(plans.admit("a", now + UNDO_WINDOW).is_ok());
        // Or the app closes the sheet.
        let id2 = applied(&mut plans, "a", now + UNDO_WINDOW);
        assert!(plans.admit("a", now + UNDO_WINDOW).is_err());
        plans.closed(&id2);
        assert!(plans.admit("a", now + UNDO_WINDOW).is_ok());
        // An undone plan frees it too, and so does a lock.
        let id3 = applied(&mut plans, "a", now);
        plans.undone(&id3, now);
        assert!(plans.admit("a", now).is_ok());
        let _ = id;
        let _ = applied(&mut plans, "c", now);
        plans.drop_all(now);
        assert!(plans.admit("c", now).is_ok());
    }

    #[test]
    fn two_proposals_admitted_together_cannot_both_register() {
        let mut plans = Plans::default();
        let now = Instant::now();
        // Both pass `admit` while their plans are being checked.
        plans.admit("a", now).unwrap();
        plans.admit("a", now).unwrap();
        let checked = || (vec![op(0)], Vec::new(), 0);
        assert!(plans.register("a", "s", "one", checked(), now).is_ok());
        let second = plans.register("a", "s", "two", checked(), now).unwrap_err();
        assert!(second.contains("awaiting"), "{second}");
        // Nor do two clients: one plan in review at all.
        plans.admit("b", now).unwrap_err();
    }

    #[test]
    fn every_attempt_counts_toward_a_larger_cap() {
        let mut plans = Plans::default();
        let now = Instant::now();
        for _ in 0..MAX_ATTEMPTS {
            plans.attempt("a", now).unwrap();
        }
        let refused = plans.attempt("a", now).unwrap_err();
        assert!(refused.contains("at most 30"), "{refused}");
        assert!(plans.attempt("b", now).is_ok());
        assert!(plans.attempt("a", now + PROPOSAL_WINDOW).is_ok());
        // Refused attempts did not use the six plans an hour.
        assert!(plans.admit("a", now).is_ok());
    }

    #[test]
    fn a_plan_belongs_to_its_session() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        assert!(plans.state("a", "other", &id, now).is_none());
        assert!(plans.subscribe("a", "other", &id).is_none());
        assert!(plans.cancel("a", "other", &id, now).is_err());
        assert!(plans.state("a", "s", &id, now).is_some());
    }

    #[test]
    fn an_interrupted_plan_ends_with_what_was_done_and_nothing_to_undo() {
        let mut plans = Plans::default();
        let now = Instant::now();
        let id = propose(&mut plans, "a", now);
        plans.take(&id, &[0], now).unwrap();
        plans.interrupt(
            &id,
            PlanReport {
                applied: 1,
                ..PlanReport::default()
            },
            "stopped",
            now,
        );
        let state = plans.state("a", "s", &id, now).unwrap();
        assert_eq!(state.state, PlanPhase::Interrupted);
        assert_eq!(state.message, "stopped");
        assert_eq!(state.report.unwrap().applied, 1);
        assert!(plans.admit("a", now).is_ok(), "no result sheet to wait for");
    }
}
