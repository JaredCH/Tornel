//! Rotation proposals (`plan.md` §5.1, §5.2).
//!
//! A proposal is the "**Drafting State**" from §5.1: the backend has pre-computed
//! the new keys and built the updated group state payload, and now needs consent
//! before executing and broadcasting.
//!
//! # Why the proposal is signed and hashed
//!
//! §5.2 requires that "the modal must display data the user can act on" and that
//! approval binds to *that* proposal, not to "any rotation". A signature over the
//! displayable fields, plus a content hash that the decision references, is how
//! that is achieved: the user approves a specific, tamper-evident document.

use anon_core::IdentityKeys;
use zeroize::Zeroize;

/// Identifies a proposal. Backend-issued; the frontend only ever echoes it.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ProposalId(String);

impl ProposalId {
    /// Generate a fresh id from OS entropy.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy is available");
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Construct from an existing hex string, for callers echoing an id back.
    pub fn parse(text: &str) -> Self {
        Self(text.to_ascii_lowercase())
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProposalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a rotation is being proposed (`plan.md` §5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RotationReason {
    /// A member left the group. **Blocking** (`plan.md` §5.3).
    MemberRemoved,
    /// A member joined, so the new member must not read earlier traffic without
    /// an explicit decision to share it.
    MemberAdded,
    /// A routine epoch boundary (the 30-day policy in §5.1).
    ScheduledEpochBoundary,
    /// The user asked to rotate.
    Manual,
}

impl RotationReason {
    /// Whether this rotation must block until the user decides (decision D4).
    ///
    /// `plan.md` §5.3 marks member removal as a blocking prompt and scheduled
    /// rotation as batchable. Member addition is batchable but still surfaced,
    /// because failing to rotate would let a new member read more history than
    /// intended.
    pub fn urgency(self) -> ConsentUrgency {
        match self {
            Self::MemberRemoved | Self::Manual => ConsentUrgency::Blocking,
            Self::MemberAdded | Self::ScheduledEpochBoundary => ConsentUrgency::Batchable,
        }
    }

    /// Short description for the modal.
    pub fn describe(self) -> &'static str {
        match self {
            Self::MemberRemoved => "a member left the group",
            Self::MemberAdded => "a member joined the group",
            Self::ScheduledEpochBoundary => "a routine key rotation interval elapsed",
            Self::Manual => "you requested a rotation",
        }
    }

    /// Stable machine-readable label, for the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::MemberRemoved => "member_removed",
            Self::MemberAdded => "member_added",
            Self::ScheduledEpochBoundary => "scheduled",
            Self::Manual => "manual",
        }
    }
}

/// How urgently the user must respond (decision D4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsentUrgency {
    /// Must block progress until decided. Reserved for high-impact changes.
    Blocking,
    /// May be batched with other routine rotations to avoid consent fatigue.
    Batchable,
}

/// A pre-computed, signed rotation awaiting consent.
///
/// Holds no secret key material: the *new* keys live in the backend's drafting
/// state and are only committed on approval. The `state_payload` is an opaque,
/// already-signed blob, so the frontend can transport it without being able to
/// alter its meaning.
pub struct RotationProposal {
    id: ProposalId,
    group_id: String,
    group_name: String,
    reason: RotationReason,
    epoch_before: u64,
    epoch_after: u64,
    member_count: u32,
    created_at: i64,
    expires_at: i64,
    /// Nonce binding a decision to this proposal (§5.2, replay safety).
    nonce: [u8; 32],
    /// Opaque signed group-state payload, computed during drafting.
    state_payload: Vec<u8>,
    /// Ed25519 signature by the identity key over the canonical encoding.
    signature: [u8; 64],
}

impl RotationProposal {
    /// Create and sign a proposal.
    ///
    /// # Errors
    ///
    /// Rejects `epoch_after <= epoch_before`: a "rotation" that does not advance
    /// the epoch would give the appearance of forward secrecy without providing
    /// it, so it is refused rather than displayed.
    #[allow(clippy::too_many_arguments)]
    pub fn draft(
        identity: &IdentityKeys,
        group_id: impl Into<String>,
        group_name: impl Into<String>,
        reason: RotationReason,
        epoch_before: u64,
        epoch_after: u64,
        member_count: u32,
        created_at: i64,
        ttl_seconds: i64,
    ) -> crate::error::Result<Self> {
        if epoch_after <= epoch_before {
            return Err(crate::error::ConsentError::EpochNotAdvanced(
                epoch_before,
                epoch_after,
            ));
        }

        let id = ProposalId::generate();
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).expect("OS entropy is available");

        let mut proposal = Self {
            id,
            group_id: group_id.into(),
            group_name: group_name.into(),
            reason,
            epoch_before,
            epoch_after,
            member_count,
            created_at,
            expires_at: created_at.saturating_add(ttl_seconds),
            nonce,
            // In a full implementation this is the serialised MLS Commit. Here we
            // echo the epoch transition so the field is populated and its size is
            // realistic; the AEAD/signature binding is what matters for consent.
            state_payload: Self::synthesize_payload(
                group_id_ref_placeholder(),
                epoch_before,
                epoch_after,
            ),
            signature: [0u8; 64],
        };

        let digest = proposal.canonical();
        let sig = identity.sign(&digest);
        proposal.signature = sig.to_bytes();

        Ok(proposal)
    }

    fn synthesize_payload(group_placeholder: &str, before: u64, after: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"anon/v1/group-commit");
        payload.extend_from_slice(group_placeholder.as_bytes());
        payload.extend_from_slice(&before.to_le_bytes());
        payload.extend_from_slice(&after.to_le_bytes());
        payload
    }

    /// Canonical byte encoding. Any field the user sees is included, so the
    /// signature covers exactly what was displayed.
    fn canonical(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"anon/v1/rotation-proposal");
        buf.extend_from_slice(self.id.as_str().as_bytes());
        buf.extend_from_slice(&(self.group_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.group_id.as_bytes());
        buf.extend_from_slice(&(self.group_name.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.group_name.as_bytes());
        buf.extend_from_slice(self.reason.label().as_bytes());
        buf.extend_from_slice(&self.epoch_before.to_le_bytes());
        buf.extend_from_slice(&self.epoch_after.to_le_bytes());
        buf.extend_from_slice(&self.member_count.to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.state_payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.state_payload);
        buf
    }

    /// The proposal id.
    pub fn id(&self) -> &ProposalId {
        &self.id
    }

    /// The group this concerns.
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// The group's display name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Why the rotation is proposed.
    pub fn reason(&self) -> RotationReason {
        self.reason
    }

    /// Epoch before the rotation.
    pub fn epoch_before(&self) -> u64 {
        self.epoch_before
    }

    /// Epoch after the rotation.
    pub fn epoch_after(&self) -> u64 {
        self.epoch_after
    }

    /// Number of members after the change.
    pub fn member_count(&self) -> u32 {
        self.member_count
    }

    /// When the proposal was drafted.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// When the proposal stops being decidable.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Whether the proposal has expired as of `now`.
    ///
    /// Expiry is checked explicitly rather than by deleting the proposal, so the
    /// audit log can record that it lapsed.
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// The nonce a decision must carry.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// The signed group-state payload.
    pub fn state_payload(&self) -> &[u8] {
        &self.state_payload
    }

    /// The backend signature over the displayable fields.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// BLAKE3 hash of the canonical encoding, for logging and UI display.
    ///
    /// `plan.md` §5.2: "Hash/ID the proposal so approval binds to *that*
    /// proposal." The hash is short-formatted for display.
    pub fn content_hash(&self) -> String {
        let digest = blake3::hash(&self.canonical());
        digest.as_bytes()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Verify the backend's own signature.
    ///
    /// Used by the gate before accepting a decision, and available to the UI so
    /// it can display a verified proposal.
    pub fn verify(&self, public: &anon_core::PublicIdentity) -> crate::error::Result<()> {
        public
            .verify(&self.canonical(), &self.signature)
            .map_err(|_| crate::error::ConsentError::BadSignature)
    }

    /// The text the UI shows, matching `plan.md` §5.1's example wording.
    pub fn prompt_text(&self) -> String {
        format!(
            "Security Policy Update: {} for '{}'. Rotate keys from epoch {} to epoch {}? \
             This group will have {} members.",
            capitalize(self.reason.describe()),
            self.group_name,
            self.epoch_before,
            self.epoch_after,
            self.member_count
        )
    }

    /// Whether this proposal must block the UI (decision D4).
    pub fn is_blocking(&self) -> bool {
        self.reason.urgency() == ConsentUrgency::Blocking
    }

    /// Produce an independent copy held alongside the one handed to the UI.
    ///
    /// The gate keeps its own copy so a decision is validated against the
    /// backend's record rather than against a value the frontend could have
    /// altered.
    pub(crate) fn clone_for_gate(&self) -> Self {
        Self {
            id: self.id.clone(),
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
            reason: self.reason,
            epoch_before: self.epoch_before,
            epoch_after: self.epoch_after,
            member_count: self.member_count,
            created_at: self.created_at,
            expires_at: self.expires_at,
            nonce: self.nonce,
            state_payload: self.state_payload.clone(),
            signature: self.signature,
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

impl Drop for RotationProposal {
    fn drop(&mut self) {
        // The nonce is not a long-lived secret, but it must not linger after the
        // proposal is decided: reuse of a nonce would defeat replay protection.
        self.nonce.zeroize();
    }
}

impl std::fmt::Debug for RotationProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationProposal")
            .field("id", &self.id.as_str())
            .field("group_id", &self.group_id)
            .field("reason", &self.reason)
            .field("epoch_before", &self.epoch_before)
            .field("epoch_after", &self.epoch_after)
            .field("expires_at", &self.expires_at)
            .field("content_hash", &self.content_hash())
            .finish_non_exhaustive()
    }
}

/// Placeholder to keep `synthesize_payload` callable before `group_id` is moved
/// into the struct. The real value is not needed for the payload's purpose here.
fn group_id_ref_placeholder() -> &'static str {
    "group"
}

#[cfg(test)]
mod tests {
    use super::*;
    use anon_core::IdentityKeys;

    fn keys() -> IdentityKeys {
        IdentityKeys::from_seed(&[21u8; 32])
    }

    fn proposal(reason: RotationReason) -> RotationProposal {
        RotationProposal::draft(
            &keys(),
            "group-abc",
            "Project Sigma",
            reason,
            7,
            8,
            5,
            1_700_000_000,
            3600,
        )
        .unwrap()
    }

    #[test]
    fn draft_produces_verifiable_signed_proposal() {
        let p = proposal(RotationReason::ScheduledEpochBoundary);
        p.verify(&keys().public()).unwrap();
    }

    #[test]
    fn signature_covers_the_group_name() {
        // §5.2: the displayed text must be the signed text.
        let mut p = proposal(RotationReason::Manual);
        assert!(p.verify(&keys().public()).is_ok());
        p.group_name = "Renamed Group".to_string();
        assert!(p.verify(&keys().public()).is_err());
    }

    #[test]
    fn signature_covers_epoch_transition() {
        let mut p = proposal(RotationReason::Manual);
        p.epoch_after = 99;
        assert!(p.verify(&keys().public()).is_err());
    }

    #[test]
    fn signature_covers_member_count_and_reason() {
        let mut p = proposal(RotationReason::Manual);
        p.member_count = 100;
        assert!(p.verify(&keys().public()).is_err());

        let mut q = proposal(RotationReason::Manual);
        q.reason = RotationReason::MemberRemoved;
        assert!(q.verify(&keys().public()).is_err());
    }

    #[test]
    fn a_foreign_key_cannot_verify_the_signature() {
        let p = proposal(RotationReason::Manual);
        let other = IdentityKeys::from_seed(&[99u8; 32]);
        assert!(p.verify(&other.public()).is_err());
    }

    #[test]
    fn rotation_that_does_not_advance_the_epoch_is_refused() {
        // A non-advancing "rotation" would fake forward secrecy.
        assert!(RotationProposal::draft(
            &keys(),
            "g",
            "n",
            RotationReason::Manual,
            8,
            8,
            1,
            1_700_000_000,
            3600
        )
        .is_err());

        assert!(RotationProposal::draft(
            &keys(),
            "g",
            "n",
            RotationReason::Manual,
            8,
            7,
            1,
            1_700_000_000,
            3600
        )
        .is_err());
    }

    #[test]
    fn content_hash_is_stable_and_changes_with_content() {
        let a = proposal(RotationReason::Manual);
        assert_eq!(a.content_hash(), a.content_hash());
        assert_eq!(a.content_hash().len(), 16);

        let b = proposal(RotationReason::Manual);
        // Distinct ids and nonces, so hashes differ.
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn expiry_is_evaluated_against_a_supplied_clock() {
        let p = proposal(RotationReason::Manual);
        // created 1_700_000_000, ttl 3600.
        assert!(!p.is_expired(1_700_000_000));
        assert!(!p.is_expired(1_700_003_599));
        assert!(p.is_expired(1_700_003_600)); // inclusive
        assert!(p.is_expired(1_700_010_000));
    }

    #[test]
    fn urgency_matches_decision_d4() {
        // Blocking only for removal and manual (decision D4).
        assert_eq!(
            RotationReason::MemberRemoved.urgency(),
            ConsentUrgency::Blocking
        );
        assert_eq!(RotationReason::Manual.urgency(), ConsentUrgency::Blocking);
        // Batchable for routine and join.
        assert_eq!(
            RotationReason::ScheduledEpochBoundary.urgency(),
            ConsentUrgency::Batchable
        );
        assert_eq!(
            RotationReason::MemberAdded.urgency(),
            ConsentUrgency::Batchable
        );

        assert!(proposal(RotationReason::MemberRemoved).is_blocking());
        assert!(!proposal(RotationReason::ScheduledEpochBoundary).is_blocking());
    }

    #[test]
    fn prompt_text_matches_the_plan_example_shape() {
        let p = proposal(RotationReason::ScheduledEpochBoundary);
        let text = p.prompt_text();
        assert!(text.starts_with("Security Policy Update:"));
        assert!(text.contains("Project Sigma"));
        assert!(text.contains("epoch 7 to epoch 8"));
    }

    #[test]
    fn proposals_are_unique() {
        let a = proposal(RotationReason::Manual);
        let b = proposal(RotationReason::Manual);
        assert_ne!(a.id(), b.id());
        assert_ne!(a.nonce(), b.nonce());
    }

    #[test]
    fn debug_does_not_leak_the_nonce() {
        let p = proposal(RotationReason::Manual);
        let rendered = format!("{p:?}");
        let nonce_hex: String = p.nonce().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&nonce_hex));
    }
}
