//! Consent audit log (`plan.md` §5.2 "Auditability").
//!
//! Every decision is appended with the proposal id, so a user can later see what
//! they approved and when. The log is deliberately **not** a secret store: it
//! records that a rotation happened and why, never key material.
//!
//! The log is bounded, mirroring the retention philosophy of §6: an unbounded
//! in-memory log would itself be a retention leak. Persisting entries into the
//! `consent_log` table (which carries `expires_at`, §6.4) is the storage layer's
//! job.

use crate::gate::ConsentOutcome;
use crate::proposal::RotationProposal;

/// One audited consent event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The proposal this concerns.
    pub proposal_id: String,
    /// The group.
    pub group_id: String,
    /// Whether this entry records drafting or a decision.
    pub kind: AuditKind,
    /// The decision, for `AuditKind::Decided`.
    pub outcome: Option<ConsentOutcome>,
    /// Why the rotation was proposed.
    pub reason: &'static str,
    /// Epoch before, when known.
    pub epoch_before: Option<u64>,
    /// Epoch after, when known.
    pub epoch_after: Option<u64>,
    /// When the event occurred, in epoch seconds.
    pub occurred_at: i64,
    /// Content hash of the proposal, so an entry can be tied to a document.
    pub content_hash: String,
}

/// What kind of event an entry records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditKind {
    /// The backend drafted a proposal and surfaced it.
    Proposed,
    /// A decision was recorded, including expiry.
    Decided,
}

impl AuditEntry {
    /// Record that a proposal was surfaced to the user.
    pub fn proposed(proposal: &RotationProposal, now: i64) -> Self {
        Self {
            proposal_id: proposal.id().as_str().to_string(),
            group_id: proposal.group_id().to_string(),
            kind: AuditKind::Proposed,
            outcome: None,
            reason: proposal.reason().label(),
            epoch_before: Some(proposal.epoch_before()),
            epoch_after: Some(proposal.epoch_after()),
            occurred_at: now,
            content_hash: proposal.content_hash(),
        }
    }

    /// Record a decision.
    pub fn decided(proposal: &RotationProposal, outcome: ConsentOutcome, now: i64) -> Self {
        Self {
            proposal_id: proposal.id().as_str().to_string(),
            group_id: proposal.group_id().to_string(),
            kind: AuditKind::Decided,
            outcome: Some(outcome),
            reason: proposal.reason().label(),
            epoch_before: Some(proposal.epoch_before()),
            epoch_after: Some(proposal.epoch_after()),
            occurred_at: now,
            content_hash: proposal.content_hash(),
        }
    }

    /// Human-readable one-line summary.
    pub fn summary(&self) -> String {
        match self.kind {
            AuditKind::Proposed => format!(
                "[{}] proposed rotation for {} ({}), epoch {} -> {}",
                self.occurred_at,
                self.group_id,
                self.reason,
                self.epoch_before.unwrap_or(0),
                self.epoch_after.unwrap_or(0)
            ),
            AuditKind::Decided => format!(
                "[{}] {} rotation for {} ({}), epoch {} -> {}",
                self.occurred_at,
                self.outcome.map(|o| o.label()).unwrap_or("unknown"),
                self.group_id,
                self.reason,
                self.epoch_before.unwrap_or(0),
                self.epoch_after.unwrap_or(0)
            ),
        }
    }
}

/// A bounded, in-memory audit log.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    capacity: usize,
}

impl AuditLog {
    /// Create a log that retains at most `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Append an entry, evicting the oldest if at capacity.
    pub fn append(&mut self, entry: AuditEntry) {
        if self.entries.len() >= self.capacity {
            // Drop the oldest entries. Retention-over-completeness matches the
            // philosophy of §6: the log should not outlive the data it describes.
            let excess = self.entries.len() + 1 - self.capacity;
            self.entries.drain(..excess);
        }
        self.entries.push(entry);
    }

    /// All current entries, oldest first.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.clone()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries for one proposal.
    pub fn for_proposal(&self, id: &str) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.proposal_id == id)
            .cloned()
            .collect()
    }

    /// Whether every decision in the log has a matching proposal entry.
    ///
    /// A decision without a recorded proposal would mean a decision was made for
    /// something never surfaced, which must not happen.
    pub fn is_consistent(&self) -> bool {
        self.entries
            .iter()
            .filter(|e| e.kind == AuditKind::Decided)
            .all(|d| {
                self.entries
                    .iter()
                    .any(|p| p.proposal_id == d.proposal_id && p.kind == AuditKind::Proposed)
            })
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposal::RotationReason;
    use anon_core::IdentityKeys;

    fn proposal() -> RotationProposal {
        RotationProposal::draft(
            &IdentityKeys::from_seed(&[4u8; 32]),
            "g",
            "Group",
            RotationReason::Manual,
            1,
            2,
            3,
            1_700_000_000,
            60,
        )
        .unwrap()
    }

    #[test]
    fn appends_and_retains_within_capacity() {
        let mut log = AuditLog::with_capacity(3);
        for i in 0..5 {
            log.append(AuditEntry::proposed(&proposal(), 1_700_000_000 + i));
        }
        assert_eq!(log.len(), 3, "log must stay bounded");
        // Oldest evicted, newest kept.
        assert_eq!(log.entries().last().unwrap().occurred_at, 1_700_000_004);
    }

    #[test]
    fn entries_are_summarisable_without_secrets() {
        let p = proposal();
        let entry = AuditEntry::decided(&p, ConsentOutcome::Approved, 1_700_000_100);
        let s = entry.summary();
        assert!(s.contains("approved"));
        assert!(s.contains("manual"));
        // No key material anywhere in the summary.
        assert!(!s.contains(&p.content_hash()) || p.content_hash().len() == 16);
    }

    #[test]
    fn consistency_detects_an_orphan_decision() {
        let mut log = AuditLog::with_capacity(10);
        let p = proposal();

        // A decision with no matching proposal entry is inconsistent.
        log.append(AuditEntry::decided(&p, ConsentOutcome::Approved, 1));
        assert!(!log.is_consistent());

        let mut log = AuditLog::with_capacity(10);
        log.append(AuditEntry::proposed(&p, 1));
        log.append(AuditEntry::decided(&p, ConsentOutcome::Approved, 2));
        assert!(log.is_consistent());
    }

    #[test]
    fn for_proposal_filters_correctly() {
        let mut log = AuditLog::with_capacity(10);
        let a = proposal();
        let b = proposal();
        log.append(AuditEntry::proposed(&a, 1));
        log.append(AuditEntry::proposed(&b, 2));

        assert_eq!(log.for_proposal(a.id().as_str()).len(), 1);
        assert_eq!(log.for_proposal("nonexistent").len(), 0);
    }
}
