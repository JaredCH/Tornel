//! The consent gate and group security state (`plan.md` §5.1, §5.2).
//!
//! # The state machine
//!
//! ```text
//!                    draft()
//!                       |
//!                       v
//!   [Pending] --approve--> [Approved] --> rotation executes
//!        |
//!        +----deny------> [Denied] --> group marked stale-epoch
//!        |
//!        +----expiry----> [Expired] --> group marked stale-epoch
//! ```
//!
//! # Fail-closed behaviour (§5.2)
//!
//! The plan requires that ignoring or denying a prompt must **not** leave the
//! system silently running on a stale epoch. Two mechanisms enforce that:
//!
//! * `Denied` and `Expired` are recorded as *decisions*, not as "nothing
//!   happened".
//! * [`GroupSecurityState::is_forward_secret`] becomes false, and the caller is
//!   expected to block sending or visibly flag messages. The gate exposes
//!   [`ConsentGate::assert_forward_secret`] so a caller can turn that into a hard
//!   error rather than relying on a UI convention.

use crate::audit::{AuditEntry, AuditLog};
use crate::error::{ConsentError, Result};
use crate::proposal::{ProposalId, RotationProposal, RotationReason};
use anon_core::{IdentityKeys, PublicIdentity};
use std::collections::HashMap;
use std::sync::Mutex;

/// The outcome of a consent decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsentOutcome {
    /// The user agreed. The rotation may be executed.
    Approved,
    /// The user declined. The group stays on the old epoch and is marked stale.
    Denied,
    /// No decision was made before the deadline. **Never auto-approved** (§5.2).
    Expired,
}

impl ConsentOutcome {
    /// Machine-readable label for the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Whether this outcome permits executing the rotation.
    pub fn permits_execution(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// Whether a group is currently operating with forward secrecy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupSecurityState {
    /// The group identifier.
    pub group_id: String,
    /// The epoch the group is actually on.
    pub current_epoch: u64,
    /// Whether a rotation is outstanding but undecided.
    pub rotation_pending: bool,
    /// Whether a rotation was declined or lapsed, leaving the group stale.
    pub rotation_stale: bool,
    /// The reason for the pending or stale rotation, for display.
    pub reason: Option<RotationReason>,
}

impl GroupSecurityState {
    /// A fresh, healthy group.
    pub fn healthy(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            group_id: group_id.into(),
            current_epoch: epoch,
            rotation_pending: false,
            rotation_stale: false,
            reason: None,
        }
    }

    /// Whether the group's keys are currently giving forward secrecy.
    ///
    /// False when a rotation is stale **or** when one is pending in a way that
    /// already invalidates the current epoch. The caller decides how to present
    /// that (`plan.md` §5.2 requires the UI to say so rather than stay silent).
    pub fn is_forward_secret(&self) -> bool {
        !self.rotation_stale
    }

    /// Whether the current epoch is stale and sending should be blocked/flagged.
    pub fn requires_user_action(&self) -> bool {
        self.rotation_stale || self.rotation_pending
    }
}

/// A decision submitted by the frontend.
///
/// The frontend supplies only the id, the outcome, and the nonce it was shown.
/// It cannot supply epochs, names, or keys — §5.2's "single source of truth"
/// requirement, enforced by the fields simply not existing.
#[derive(Clone, Debug)]
pub struct DecisionRequest {
    /// The proposal being decided.
    pub proposal_id: ProposalId,
    /// The decision.
    pub outcome: ConsentOutcome,
    /// The nonce from the proposal the user was actually shown.
    pub nonce: [u8; 32],
}

/// The consent gate.
///
/// Owns all proposals and group states. Every mutation goes through the methods
/// here, so there is exactly one place where consent state can change.
pub struct ConsentGate {
    identity_public: PublicIdentity,
    proposals: Mutex<HashMap<String, RotationProposal>>,
    decided: Mutex<HashMap<String, ConsentOutcome>>,
    groups: Mutex<HashMap<String, GroupSecurityState>>,
    audit: Mutex<AuditLog>,
}

impl ConsentGate {
    /// Create a gate that signs proposals with `identity`.
    pub fn new(identity: &IdentityKeys, audit_capacity: usize) -> Self {
        Self {
            identity_public: identity.public(),
            proposals: Mutex::new(HashMap::new()),
            decided: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            audit: Mutex::new(AuditLog::with_capacity(audit_capacity)),
        }
    }

    /// Register a group's initial security state.
    pub fn register_group(&self, group_id: &str, epoch: u64) {
        self.groups.lock().unwrap().insert(
            group_id.to_string(),
            GroupSecurityState::healthy(group_id, epoch),
        );
    }

    /// Current security state for a group.
    pub fn group_state(&self, group_id: &str) -> Option<GroupSecurityState> {
        self.groups.lock().unwrap().get(group_id).cloned()
    }

    /// Sync the gate's view of a group's epoch to what MLS actually did.
    ///
    /// # Why this exists
    ///
    /// Some epoch transitions happen without a consent decision: adding a member
    /// advances the epoch immediately, because the new member must be able to read
    /// from the new epoch onward. The gate's `current_epoch` is what
    /// [`ConsentGate::draft_rotation`] uses as `epoch_before`, so if it drifts the
    /// next proposal would name the wrong starting epoch and the modal would show a
    /// misleading "before" value.
    ///
    /// # Monotonic only
    ///
    /// A lower epoch is ignored rather than applied. MLS epochs only increase, so a
    /// decreasing value means a bug or a rollback attempt; accepting it would make
    /// the gate's state a lie. Returns whether the state moved.
    ///
    /// # What this does not do
    ///
    /// It does not clear `rotation_stale`. A group whose rotation was denied stays
    /// stale even as its epoch advances, because "the user refused the rotation" is a
    /// decision that must keep blocking sends until it is resolved — not something a
    /// later epoch bump should quietly erase.
    pub fn sync_group_epoch(&self, group_id: &str, epoch: u64) -> bool {
        let mut groups = self.groups.lock().unwrap();
        match groups.get_mut(group_id) {
            Some(state) if epoch > state.current_epoch => {
                state.current_epoch = epoch;
                true
            }
            _ => false,
        }
    }

    /// Draft a rotation and register it as pending.
    ///
    /// This is §5.1's "Drafting State". The returned proposal is what the UI must
    /// render; the gate keeps its own copy and will only accept a decision that
    /// matches it.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_rotation(
        &self,
        identity: &IdentityKeys,
        group_id: &str,
        group_name: &str,
        reason: RotationReason,
        epoch_after: u64,
        member_count: u32,
        now: i64,
        ttl_seconds: i64,
    ) -> Result<RotationProposal> {
        let current_epoch = self
            .group_state(group_id)
            .map(|s| s.current_epoch)
            .ok_or_else(|| ConsentError::UnknownGroup(group_id.to_string()))?;

        let proposal = RotationProposal::draft(
            identity,
            group_id,
            group_name,
            reason,
            current_epoch,
            epoch_after,
            member_count,
            now,
            ttl_seconds,
        )?;

        // Mark the group as having an outstanding decision.
        {
            let mut groups = self.groups.lock().unwrap();
            if let Some(state) = groups.get_mut(group_id) {
                state.rotation_pending = true;
                state.reason = Some(reason);
            }
        }

        self.proposals.lock().unwrap().insert(
            proposal.id().as_str().to_string(),
            proposal.clone_for_gate(),
        );

        self.record_audit(AuditEntry::proposed(&proposal, now));

        Ok(proposal)
    }

    /// Submit a decision for a proposal.
    ///
    /// Enforcement, in order:
    ///
    /// 1. The proposal must exist and belong to this gate.
    /// 2. It must not already be decided (replay protection, §5.2).
    /// 3. The submitted nonce must match, so an approval of proposal A cannot be
    ///    replayed against proposal B.
    /// 4. Expiry is checked *before* honouring an approval, and an expired
    ///    proposal is recorded as `Expired` — never as approved.
    pub fn decide(&self, request: &DecisionRequest, now: i64) -> Result<ConsentOutcome> {
        let proposal = {
            let proposals = self.proposals.lock().unwrap();
            proposals
                .get(request.proposal_id.as_str())
                .map(|p| p.clone_for_gate())
                .ok_or_else(|| ConsentError::UnknownProposal(request.proposal_id.to_string()))?
        };

        // Replay: a second decision for the same proposal is refused outright.
        {
            let decided = self.decided.lock().unwrap();
            if decided.contains_key(request.proposal_id.as_str()) {
                return Err(ConsentError::AlreadyDecided(
                    request.proposal_id.to_string(),
                ));
            }
        }

        // Binding: the nonce proves the UI is deciding the proposal it was shown.
        if proposal.nonce() != &request.nonce {
            return Err(ConsentError::ProposalMismatch);
        }

        // Re-verify the backend's own signature as defence in depth against a
        // mutated in-memory proposal.
        proposal.verify(&self.identity_public)?;

        // Expiry wins over approval. §5.2: "on expiry, do not auto-approve."
        let effective = if proposal.is_expired(now) {
            ConsentOutcome::Expired
        } else {
            request.outcome
        };

        self.finalize(&proposal, effective, now)?;
        Ok(effective)
    }

    /// Finalise a decision: record it, update group state, and log it.
    fn finalize(
        &self,
        proposal: &RotationProposal,
        outcome: ConsentOutcome,
        now: i64,
    ) -> Result<()> {
        {
            let mut decided = self.decided.lock().unwrap();
            decided.insert(proposal.id().as_str().to_string(), outcome);
        }

        {
            let mut groups = self.groups.lock().unwrap();
            if let Some(state) = groups.get_mut(proposal.group_id()) {
                state.rotation_pending = false;
                match outcome {
                    ConsentOutcome::Approved => {
                        state.current_epoch = proposal.epoch_after();
                        state.rotation_stale = false;
                        state.reason = None;
                    }
                    // Fail closed: a denied or lapsed rotation leaves the group on
                    // the old epoch and explicitly marked not forward-secret.
                    ConsentOutcome::Denied | ConsentOutcome::Expired => {
                        state.rotation_stale = true;
                        state.reason = Some(proposal.reason());
                    }
                }
            }
        }

        self.record_audit(AuditEntry::decided(proposal, outcome, now));
        Ok(())
    }

    /// Expire proposals whose deadline has passed, recording each as a decision.
    ///
    /// Returns the ids that expired. Called on a timer; see `plan.md` §6.5(2) on
    /// why a timer alone is insufficient, so callers should also invoke this at
    /// startup and on resume.
    pub fn sweep_expired(&self, now: i64) -> Vec<ProposalId> {
        let pending: Vec<RotationProposal> = {
            let decided = self.decided.lock().unwrap();
            let proposals = self.proposals.lock().unwrap();
            proposals
                .iter()
                .filter(|(id, p)| !decided.contains_key(*id) && p.is_expired(now))
                .map(|(_, p)| p.clone_for_gate())
                .collect()
        };

        let mut expired = Vec::new();
        for proposal in pending {
            if self
                .finalize(&proposal, ConsentOutcome::Expired, now)
                .is_ok()
            {
                expired.push(proposal.id().clone());
            }
        }
        expired
    }

    /// The recorded outcome for a proposal, if decided.
    pub fn outcome_of(&self, id: &ProposalId) -> Option<ConsentOutcome> {
        self.decided.lock().unwrap().get(id.as_str()).copied()
    }

    /// Whether a proposal has been decided.
    pub fn is_decided(&self, id: &ProposalId) -> bool {
        self.decided.lock().unwrap().contains_key(id.as_str())
    }

    /// Turn "not forward secret" into a hard error.
    ///
    /// `plan.md` §5.2 requires that the system not silently continue on a stale
    /// epoch. Callers that must not send under stale keys should call this first.
    pub fn assert_forward_secret(&self, group_id: &str) -> Result<()> {
        match self.group_state(group_id) {
            Some(state) if !state.is_forward_secret() => Err(ConsentError::NotForwardSecret),
            Some(_) => Ok(()),
            None => Err(ConsentError::UnknownGroup(group_id.to_string())),
        }
    }

    /// Pending proposals that the UI should surface.
    pub fn pending_proposals(&self) -> Vec<RotationProposal> {
        let decided = self.decided.lock().unwrap();
        self.proposals
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| !decided.contains_key(*id))
            .map(|(_, p)| p.clone_for_gate())
            .collect()
    }

    /// The audit log, cloned for inspection or persistence.
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit.lock().unwrap().entries()
    }

    fn record_audit(&self, entry: AuditEntry) {
        self.audit.lock().unwrap().append(entry);
    }
}

impl std::fmt::Debug for ConsentGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentGate")
            .field("pending", &self.pending_proposals().len())
            .field("groups", &self.groups.lock().unwrap().len())
            .finish_non_exhaustive()
    }
}
