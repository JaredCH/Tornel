//! Consent gate integration tests — the Phase 5 exit criteria (`plan.md` §7.1).
//!
//! Every §5.2 constraint has a test here, because those constraints are what make
//! the consent prompt a security control rather than a notification.

use anon_consent::{ConsentGate, ConsentOutcome, DecisionRequest, ProposalId, RotationReason};
use anon_core::IdentityKeys;

const NOW: i64 = 1_700_000_000;
const TTL: i64 = 3600;

fn keys() -> IdentityKeys {
    IdentityKeys::from_seed(&[31u8; 32])
}

fn gate_with_group() -> ConsentGate {
    let gate = ConsentGate::new(&keys(), 256);
    gate.register_group("group-1", 7);
    gate
}

fn draft(gate: &ConsentGate, reason: RotationReason) -> anon_consent::RotationProposal {
    gate.draft_rotation(&keys(), "group-1", "Project Sigma", reason, 8, 5, NOW, TTL)
        .expect("draft")
}

fn approve(id: &ProposalId, nonce: &[u8; 32]) -> DecisionRequest {
    DecisionRequest {
        proposal_id: id.clone(),
        outcome: ConsentOutcome::Approved,
        nonce: *nonce,
    }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn approval_advances_the_epoch_and_keeps_the_group_forward_secret() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::ScheduledEpochBoundary);

    let outcome = gate.decide(&approve(p.id(), p.nonce()), NOW + 10).unwrap();
    assert_eq!(outcome, ConsentOutcome::Approved);

    let state = gate.group_state("group-1").unwrap();
    assert_eq!(state.current_epoch, 8, "epoch must advance on approval");
    assert!(!state.rotation_pending);
    assert!(!state.rotation_stale);
    assert!(state.is_forward_secret());
    assert!(gate.assert_forward_secret("group-1").is_ok());
}

#[test]
fn drafting_marks_the_group_as_pending() {
    let gate = gate_with_group();
    let _ = draft(&gate, RotationReason::MemberRemoved);

    let state = gate.group_state("group-1").unwrap();
    assert!(state.rotation_pending);
    assert!(state.requires_user_action());
    assert_eq!(state.reason, Some(RotationReason::MemberRemoved));
    assert!(state.is_forward_secret());
}

// ---------------------------------------------------------------------------
// §5.2: fail closed
// ---------------------------------------------------------------------------

#[test]
fn denial_leaves_the_group_explicitly_stale_and_not_forward_secret() {
    // The critical fail-closed property: refusing must not be silent.
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::MemberRemoved);

    let deny = DecisionRequest {
        proposal_id: p.id().clone(),
        outcome: ConsentOutcome::Denied,
        nonce: *p.nonce(),
    };
    assert_eq!(
        gate.decide(&deny, NOW + 10).unwrap(),
        ConsentOutcome::Denied
    );

    let state = gate.group_state("group-1").unwrap();
    assert_eq!(state.current_epoch, 7, "epoch must NOT advance");
    assert!(
        state.rotation_stale,
        "a denial must leave an explicit stale marker"
    );
    assert!(!state.is_forward_secret());
    assert!(state.requires_user_action());

    assert!(gate.assert_forward_secret("group-1").is_err());
}

#[test]
fn expiry_is_a_decision_and_never_an_approval() {
    // §5.2: "on expiry, do not auto-approve".
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::MemberRemoved);

    let after = NOW + TTL + 1;
    let outcome = gate.decide(&approve(p.id(), p.nonce()), after).unwrap();

    assert_eq!(
        outcome,
        ConsentOutcome::Expired,
        "a late approval must be recorded as expiry, not approval"
    );

    let state = gate.group_state("group-1").unwrap();
    assert_eq!(state.current_epoch, 7, "epoch must not advance on expiry");
    assert!(state.rotation_stale);
    assert!(!state.is_forward_secret());
}

#[test]
fn sweep_records_expired_proposals_as_decisions() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::ScheduledEpochBoundary);

    assert!(gate.sweep_expired(NOW + 1).is_empty());
    assert!(!gate.is_decided(p.id()));

    let expired = gate.sweep_expired(NOW + TTL + 1);
    assert_eq!(expired.len(), 1);
    assert!(gate.is_decided(p.id()));
    assert_eq!(gate.outcome_of(p.id()), Some(ConsentOutcome::Expired));
    assert!(gate.group_state("group-1").unwrap().rotation_stale);
}

#[test]
fn a_decided_proposal_is_not_swept_again() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::Manual);
    gate.decide(&approve(p.id(), p.nonce()), NOW + 1).unwrap();

    assert!(gate.sweep_expired(NOW + TTL + 100).is_empty());
    assert_eq!(gate.outcome_of(p.id()), Some(ConsentOutcome::Approved));
    assert_eq!(gate.group_state("group-1").unwrap().current_epoch, 8);
}

// ---------------------------------------------------------------------------
// §5.2: replay safety and binding
// ---------------------------------------------------------------------------

#[test]
fn a_second_decision_for_the_same_proposal_is_rejected() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::Manual);

    gate.decide(&approve(p.id(), p.nonce()), NOW + 1).unwrap();

    let err = gate
        .decide(&approve(p.id(), p.nonce()), NOW + 2)
        .unwrap_err();
    assert!(
        matches!(err, anon_consent::ConsentError::AlreadyDecided(_)),
        "got {err:?}"
    );
}

#[test]
fn an_approval_cannot_be_replayed_against_a_different_proposal() {
    // §5.2: approval binds to *that* proposal. The nonce is what enforces it.
    let gate = gate_with_group();
    let a = draft(&gate, RotationReason::Manual);
    let b = draft(&gate, RotationReason::Manual);

    let cross = approve(b.id(), a.nonce());
    let err = gate.decide(&cross, NOW + 1).unwrap_err();
    assert!(matches!(err, anon_consent::ConsentError::ProposalMismatch));
    assert!(!gate.is_decided(b.id()));
}

#[test]
fn an_unknown_proposal_cannot_be_decided() {
    // §5.2: the UI cannot approve a rotation the backend never issued.
    let gate = gate_with_group();
    let fabricated = DecisionRequest {
        proposal_id: ProposalId::parse("deadbeefdeadbeefdeadbeefdeadbeef"),
        outcome: ConsentOutcome::Approved,
        nonce: [0u8; 32],
    };
    let err = gate.decide(&fabricated, NOW).unwrap_err();
    assert!(matches!(
        err,
        anon_consent::ConsentError::UnknownProposal(_)
    ));
}

#[test]
fn a_proposal_signed_by_a_foreign_key_cannot_verify() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::Manual);

    let foreign = IdentityKeys::from_seed(&[77u8; 32]);
    assert!(p.verify(&foreign.public()).is_err());
    assert!(p.verify(&keys().public()).is_ok());
}

// ---------------------------------------------------------------------------
// Decision D4: batching / consent fatigue
// ---------------------------------------------------------------------------

#[test]
fn blocking_prompts_are_limited_to_high_impact_rotations() {
    // Decision D4: don't prompt on everything, or users click through.
    let gate = gate_with_group();

    let removal = draft(&gate, RotationReason::MemberRemoved);
    assert!(removal.is_blocking());
    assert_eq!(
        removal.reason().urgency(),
        anon_consent::ConsentUrgency::Blocking
    );

    let scheduled = draft(&gate, RotationReason::ScheduledEpochBoundary);
    assert!(!scheduled.is_blocking());
    assert_eq!(
        scheduled.reason().urgency(),
        anon_consent::ConsentUrgency::Batchable
    );

    assert!(draft(&gate, RotationReason::Manual).is_blocking());
    assert!(!draft(&gate, RotationReason::MemberAdded).is_blocking());
}

#[test]
fn batchable_rotations_can_accumulate_as_pending_together() {
    let gate = gate_with_group();
    let a = draft(&gate, RotationReason::ScheduledEpochBoundary);
    let b = draft(&gate, RotationReason::MemberAdded);

    let pending = gate.pending_proposals();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(|p| p.id() == a.id()));
    assert!(pending.iter().any(|p| p.id() == b.id()));
}

// ---------------------------------------------------------------------------
// §5.2: auditability
// ---------------------------------------------------------------------------

#[test]
fn every_decision_is_audited_with_its_proposal_id() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::MemberRemoved);
    gate.decide(&approve(p.id(), p.nonce()), NOW + 5).unwrap();

    let entries = gate.audit_entries();
    let for_proposal: Vec<_> = entries
        .iter()
        .filter(|e| e.proposal_id == p.id().as_str())
        .collect();

    assert_eq!(for_proposal.len(), 2, "one proposed + one decided entry");
    assert!(for_proposal
        .iter()
        .any(|e| e.kind == anon_consent::AuditKind::Proposed));
    assert!(for_proposal
        .iter()
        .any(|e| e.kind == anon_consent::AuditKind::Decided));
}

#[test]
fn audit_entries_summarise_without_leaking_key_material() {
    let gate = gate_with_group();
    let p = draft(&gate, RotationReason::Manual);
    gate.decide(&approve(p.id(), p.nonce()), NOW + 1).unwrap();

    for entry in gate.audit_entries() {
        let summary = entry.summary();
        assert!(summary.contains("group-1"));
        assert!(
            !summary
                .split_whitespace()
                .any(|tok| tok.len() >= 64 && tok.chars().all(|c| c.is_ascii_hexdigit())),
            "audit summary may contain key-like data: {summary}"
        );
    }
}

// ---------------------------------------------------------------------------
// Multiple groups and defensive edge cases
// ---------------------------------------------------------------------------

#[test]
fn groups_are_isolated_from_each_other() {
    let gate = ConsentGate::new(&keys(), 64);
    gate.register_group("a", 1);
    gate.register_group("b", 1);

    let pa = gate
        .draft_rotation(
            &keys(),
            "a",
            "A",
            RotationReason::MemberRemoved,
            2,
            3,
            NOW,
            TTL,
        )
        .unwrap();

    gate.decide(
        &DecisionRequest {
            proposal_id: pa.id().clone(),
            outcome: ConsentOutcome::Denied,
            nonce: *pa.nonce(),
        },
        NOW + 1,
    )
    .unwrap();

    assert!(gate.group_state("a").unwrap().rotation_stale);
    assert!(!gate.group_state("b").unwrap().rotation_stale);
    assert!(gate.assert_forward_secret("b").is_ok());
}

#[test]
fn an_unknown_group_cannot_draft_a_rotation() {
    let gate = gate_with_group();
    let err = gate
        .draft_rotation(&keys(), "nope", "N", RotationReason::Manual, 2, 1, NOW, TTL)
        .unwrap_err();
    assert!(matches!(err, anon_consent::ConsentError::UnknownGroup(_)));
}

#[test]
fn assert_forward_secret_rejects_an_unknown_group() {
    let gate = gate_with_group();
    assert!(gate.assert_forward_secret("missing").is_err());
}

#[test]
fn audit_capacity_is_respected() {
    let gate = ConsentGate::new(&keys(), 4);
    gate.register_group("g", 1);
    for i in 0..6i64 {
        let p = gate
            .draft_rotation(
                &keys(),
                "g",
                "G",
                RotationReason::Manual,
                2 + i as u64,
                1,
                NOW + i,
                TTL,
            )
            .unwrap();
        gate.decide(&approve(p.id(), p.nonce()), NOW + i).unwrap();
    }
    assert!(gate.audit_entries().len() <= 4);
}

#[test]
fn an_approved_rotation_updates_the_epoch_used_for_the_next_draft() {
    // End-to-end: approve, then draft again and confirm the new proposal builds
    // on the post-rotation epoch rather than the stale one.
    let gate = gate_with_group();
    let p1 = draft(&gate, RotationReason::ScheduledEpochBoundary);
    gate.decide(&approve(p1.id(), p1.nonce()), NOW + 1).unwrap();

    let p2 = gate
        .draft_rotation(
            &keys(),
            "group-1",
            "Project Sigma",
            RotationReason::Manual,
            9,
            5,
            NOW + 2,
            TTL,
        )
        .unwrap();
    assert_eq!(
        p2.epoch_before(),
        8,
        "second proposal must start from epoch 8"
    );
    assert_eq!(p2.epoch_after(), 9);
}
