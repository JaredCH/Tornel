//! Consent-gated key rotation (`plan.md` §5, decision D4).
//!
//! # What this crate is
//!
//! The consent gate is a **security control**, not a notification. `plan.md`
//! §5.2 lists six constraints, and this module enforces them structurally rather
//! than by convention:
//!
//! | §5.2 constraint | How it is enforced here |
//! | --- | --- |
//! | Fail closed | A denied or ignored rotation leaves an explicit *stale epoch*; [`GroupSecurityState::is_forward_secret`] goes false and sending must stop. |
//! | Single source of truth in Rust | [`ConsentGate`] owns every proposal. The UI can only submit a decision for an id the gate already issued — it cannot invent a rotation. |
//! | Rendered from a signed payload | [`RotationProposal`] carries the displayable fields *and* a signature over them, so the modal has something verifiable. |
//! | Idempotent + replay-safe | Each proposal has a nonce and a one-shot decision; a second decision is rejected, and an expired proposal is never auto-approved. |
//! | Bounded wait | Proposals carry `expires_at`. Expiry is a **decision**, recorded as such, never a silent approval. |
//! | Auditability | Every decision is appended to an audit log with the proposal id. |
//!
//! # Decision D4: batching
//!
//! Prompting on every rotation trains users to click through security dialogs.
//! [`RotationReason::urgency`] therefore distinguishes a **blocking** prompt
//! (member removed, manual) from a **batchable** one (routine time-based). The UI
//! uses that to decide what it may postpone.

pub mod audit;
pub mod error;
pub mod gate;
pub mod proposal;

pub use audit::{AuditEntry, AuditKind, AuditLog};
pub use error::{ConsentError, Result};
pub use gate::{ConsentGate, ConsentOutcome, DecisionRequest, GroupSecurityState};
pub use proposal::{ConsentUrgency, ProposalId, RotationProposal, RotationReason};
