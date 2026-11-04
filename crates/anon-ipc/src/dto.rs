//! Data-transfer objects that cross the Rust↔webview boundary (`plan.md` §7.3).
//!
//! # The invariant
//!
//! **Every field here is a public value.** There is no field capable of carrying a
//! private key, a seed, a passphrase, or a database handle. That is the whole
//! point of the module: the boundary's safety is a property of its types, not of
//! reviewer diligence.
//!
//! The one thing resembling a secret is [`crate::SecretHandle`], which *names* a
//! value held in Rust without revealing it.

use crate::SecretHandle;

/// Identity information the UI may display (`plan.md` §2).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityView {
    /// The shareable contact code. Public by design.
    pub contact_code: String,
    /// Grouped fingerprint for out-of-band comparison.
    pub fingerprint: String,
    /// The user's chosen local display name, if any.
    pub display_name: Option<String>,
    /// Whether an escrow artifact has been exported (`plan.md` §2.5).
    ///
    /// Note this is a *boolean*, not the artifact: the app never stores the
    /// artifact, so it can only recall whether the flow completed.
    pub escrow_exported: bool,
}

/// A known peer (`plan.md` §4.3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerView {
    /// The peer's contact code.
    pub contact_code: String,
    /// Short onion label for display. Routing detail, not identity.
    pub onion_short: Option<String>,
    /// When the peer was added, in epoch seconds.
    pub added_at: i64,
    /// Whether the user has verified the peer out of band.
    pub verified: bool,
}

/// A conversation, with its retention deadline (`plan.md` §6).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationView {
    /// Opaque conversation id, hex-encoded.
    pub id: String,
    /// `direct` or `group`.
    pub kind: String,
    /// Display label (peer name or group name).
    pub label: String,
    /// When this conversation's content expires.
    pub expires_at: i64,
    /// Number of messages currently retained.
    pub message_count: usize,
}

/// How far a message actually got (`plan.md` §8).
///
/// Mirrors `anon_messaging::DeliveryOutcome` but as a plain data type, so the
/// webview cannot depend on the messaging crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeliveryState {
    /// Encrypted and stored locally only.
    QueuedLocal,
    /// Handed to a mailbox host.
    AtMailbox,
    /// The recipient's client acknowledged receipt.
    Delivered,
    /// The recipient's client reported it read.
    Read,
}

impl DeliveryState {
    /// A truthful label for the UI (`plan.md` §8).
    pub fn label(self) -> &'static str {
        match self {
            Self::QueuedLocal => "Queued on this device",
            Self::AtMailbox => "Waiting at a peer's mailbox",
            Self::Delivered => "Delivered",
            Self::Read => "Read",
        }
    }

    /// Whether the state is backed by peer evidence.
    pub fn is_peer_confirmed(self) -> bool {
        matches!(self, Self::Delivered | Self::Read)
    }

    /// Hex-free stable code for the frontend.
    pub fn code(self) -> &'static str {
        match self {
            Self::QueuedLocal => "queued_local",
            Self::AtMailbox => "at_mailbox",
            Self::Delivered => "delivered",
            Self::Read => "read",
        }
    }
}

/// A decrypted message prepared for display.
///
/// This is the only type carrying message plaintext across the boundary, and it
/// is populated from a store read that already refused to return data for a
/// crypto-shredded bucket (`plan.md` §6.2).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageView {
    /// Hex message id.
    pub message_id: String,
    /// Sender's fingerprint, for attribution.
    pub sender_fingerprint: String,
    /// Send time, epoch seconds.
    pub sent_at: i64,
    /// This message's retention deadline.
    pub expires_at: i64,
    /// How far it got.
    pub delivery: DeliveryState,
    /// The message text.
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrivacyView {
    pub restricted_discovery: bool,
    pub legacy_contacts: usize,
    pub traffic_shaping: bool,
}

/// Transport status for the header (`plan.md` §3.4, §8).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransportView {
    /// `tor_onion`, `loopback`, or `none`.
    pub anonymity: String,
    /// `idle`, `bootstrapping`, `ready`, or `failed`.
    pub status: String,
    /// Whether sending is possible right now.
    pub can_send: bool,
    /// Why sending is unavailable, when it is. Must be shown, not hidden.
    pub blocked_reason: Option<String>,
    /// Short label of our own onion address, when published.
    pub local_onion_short: Option<String>,
    /// Full `.onion` address of our hosted service, so the user can copy and share it.
    pub local_onion: Option<String>,
    /// Frames waiting in the outbound queue because the peer was unreachable.
    ///
    /// Shown so "queued" is a visible state rather than a silent one (`plan.md` §8).
    pub queued_count: usize,
}

/// One frame waiting in the outbound send queue.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueuedMessageView {
    /// Queue row id, hex. Not a message id — the frame's own id is inside it.
    pub id: String,
    /// When it was queued (epoch seconds).
    pub created_at: i64,
    /// Delivery attempts so far.
    pub attempts: u32,
    /// Why the last attempt failed, when it did.
    pub last_error: Option<String>,
}

/// A rotation proposal rendered for the consent modal (`plan.md` §5.1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProposalView {
    /// The proposal id the decision must reference.
    pub proposal_id: String,
    /// The group it concerns.
    pub group_id: String,
    /// The group's display name.
    pub group_name: String,
    /// Machine-readable reason.
    pub reason: String,
    /// Epoch before.
    pub epoch_before: u64,
    /// Epoch after.
    pub epoch_after: u64,
    /// Member count after the change.
    pub member_count: u32,
    /// When the decision deadline passes.
    pub expires_at: i64,
    /// Content hash, so the user can tie approval to a document.
    pub content_hash: String,
    /// Whether this must block the UI (decision D4).
    pub is_blocking: bool,
    /// The sentence to display.
    pub prompt_text: String,
}

/// Everything the modal needs: the proposal plus a handle to its nonce.
///
/// The nonce itself stays in Rust. The webview receives a [`SecretHandle`] it can
/// echo back, which proves the decision refers to the proposal it was shown
/// (`plan.md` §5.2) without the nonce being exposed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentPrompt {
    /// The proposal to display.
    pub proposal: ProposalView,
    /// Opaque handle for the proposal's nonce.
    pub nonce_handle: String,
}

/// A decision submitted from the UI.
///
/// Note what is *absent*: no epochs, no group name, no keys. The frontend cannot
/// influence what it is approving — only whether to approve (`plan.md` §5.2).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentSubmission {
    /// The proposal being decided.
    pub proposal_id: String,
    /// The nonce handle the UI was given.
    pub nonce_handle: String,
    /// `true` to approve, `false` to deny.
    pub approved: bool,
}

/// A request to send a message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SendRequest {
    /// Target conversation, hex id.
    pub conversation_id: String,
    /// Recipient onion address.
    pub recipient_onion: String,
    /// Epoch to encrypt under.
    pub epoch: u64,
    /// The message text.
    pub body: String,
}

impl SendRequest {
    /// Validate the request before any crypto runs.
    ///
    /// Rejects empty/oversized fields and malformed addresses up front, so a bad
    /// input cannot reach the transport (`plan.md` §7.3: "validate all inputs in
    /// Rust; never trust webview-supplied IDs").
    pub fn validate(&self) -> crate::Result<()> {
        const MAX_BODY: usize = 520_000;

        if self.conversation_id.trim().is_empty() {
            return Err(crate::IpcError::EmptyField("conversation_id"));
        }
        if self.conversation_id.len() > 64 {
            return Err(crate::IpcError::FieldTooLong("conversation_id"));
        }
        if self.recipient_onion.trim().is_empty() {
            return Err(crate::IpcError::EmptyField("recipient_onion"));
        }
        if self.body.len() > MAX_BODY {
            return Err(crate::IpcError::FieldTooLong("body"));
        }
        if self.body.is_empty() {
            return Err(crate::IpcError::EmptyField("body"));
        }

        // Parse the address here so the messaging layer only ever sees a
        // validated value.
        anon_transport::OnionId::parse(&self.recipient_onion)
            .map_err(|_| crate::IpcError::BadOnion(self.recipient_onion.clone()))?;

        Ok(())
    }
}

impl ConsentSubmission {
    /// Validate the submission shape before it reaches the gate.
    pub fn validate(&self) -> crate::Result<()> {
        if self.proposal_id.trim().is_empty() {
            return Err(crate::IpcError::EmptyField("proposal_id"));
        }
        if self.nonce_handle.trim().is_empty() {
            return Err(crate::IpcError::EmptyField("nonce_handle"));
        }
        Ok(())
    }
}

/// A handle plus a non-secret label, for values the UI must reference.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HandleView {
    /// The handle to echo back.
    pub handle: String,
    /// A short label safe to display.
    pub label: String,
}

/// A group this device belongs to, as the UI renders it (`plan.md` §4.2).
///
/// Metadata only: the group id, a local display name, the current epoch, and how
/// many members the last observed epoch had. No key material and no message
/// content — the MLS state stays in Rust.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupView {
    /// MLS group id, hex-encoded.
    pub group_id: String,
    /// Local display name. Not identity (`plan.md` §2).
    pub name: Option<String>,
    /// The last epoch this device observed.
    pub epoch: u64,
    /// How many members the group had at that epoch.
    pub member_count: u32,
    /// When this device first recorded the group, epoch seconds.
    pub created_at: i64,
}

/// One member of a group, as the UI renders it.
///
/// The identity is shown as a short fingerprint rather than the full contact code:
/// the UI needs enough to distinguish speakers and to let the user compare out of
/// band, not a full identity dump in a list.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupMemberView {
    /// Leaf index in the ratchet tree. Stable only within an epoch.
    pub leaf_index: u32,
    /// Short fingerprint of the member's contact code.
    pub contact_code_short: String,
    /// Whether this row is the local user.
    pub is_self: bool,
    /// Member role in the group (`owner`, `admin`, `moderator`, `member`).
    pub role: String,
    /// Friendly display name if known in local contacts or local identity.
    pub display_name: Option<String>,
}

/// The result of adding a member to a group.
///
/// # Why the Welcome crosses the boundary
///
/// `welcome_hex` looks like an exception to the "no key material" rule, and it is
/// worth being explicit about why it is not one. An MLS Welcome is **public key
/// material addressed to the invitee**: it is the artifact the inviter must deliver
/// so the invitee can join. It grants no ability to read past traffic (key packages
/// are single-use, `plan.md` §4.3) and it is useless to anyone but the holder of the
/// matching key package private key.
///
/// It is returned rather than persisted because persisting it would leave a second
/// copy of group-joining material on disk for no benefit — the inviter's job is to
/// hand it over, once.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AddMemberOutcome {
    /// The group the member was added to, hex-encoded.
    pub group_id: String,
    /// The epoch after the add.
    pub epoch: u64,
    /// The Welcome message, hex-encoded, for the inviter to deliver out of band.
    pub welcome_hex: String,
}

/// The result of removing a member from a group.
///
/// A removal implies a rotation, so the outcome carries the drafted proposal when
/// one was created. The UI renders it in the existing consent modal — removal is
/// exactly the `RotationReason::MemberRemoved` case the gate already models.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoveMemberOutcome {
    /// The group the member was removed from, hex-encoded.
    pub group_id: String,
    /// The epoch after the removal.
    pub epoch: u64,
    /// The drafted rotation proposal, when one was created.
    pub proposal: Option<ProposalView>,
}

/// What the launch screen must ask the user for (gap-closure plan Gap 2).
///
/// # Why this is a DTO and not a boolean
///
/// The webview has to render three genuinely different screens — "choose a
/// passphrase", "enter your passphrase", and "finish an interrupted migration" — and
/// the difference matters to the user. A single `locked: bool` would collapse them and
/// the UI would have to guess, which is how a returning user ends up being asked to
/// choose a new passphrase and concluding their database was lost.
///
/// # What this deliberately does not carry
///
/// No passphrase, no derived key, no salt. It is a routing decision plus the facts the
/// screen needs to explain itself. The passphrase travels the other way, as a command
/// argument, and is never returned.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultView {
    /// Which screen to show: `fresh_install`, `needs_migration`, `locked`, or
    /// `interrupted_migration`.
    pub state: String,
    /// Whether the user is choosing a passphrase (`true`) or entering an existing one
    /// (`false`).
    pub is_setup: bool,
    /// The minimum passphrase length, so the hint and the policy cannot disagree.
    pub min_chars: usize,
    /// The interrupted migration's stage, when `state` is `interrupted_migration`.
    ///
    /// A display string, not a number: the UI shows it verbatim so a stuck migration
    /// reports where it stopped rather than "please wait".
    pub migration_stage: Option<String>,
}

/// A passphrase strength report for the setup screen (gap-closure plan Gap 2).
///
/// The setup screen calls this as the user types so the hint is live. It reports facts
/// and lets the UI decide how to present them — the same shape the escrow flow uses, so
/// there is one policy rather than two.
///
/// # The field names are chosen to clear the boundary guard
///
/// `FORBIDDEN_FIELD_MARKERS` includes `passphrase`, so no field here may be named with
/// it. That is not a nuisance: it is the guard doing its job. A field named
/// `passphrase_warnings` would be a strong signal that a passphrase was being carried,
/// and the guard cannot tell the difference between "warnings about" and "the value
/// itself". Naming these `warnings` and `entropy_bits` keeps the guard strict.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StrengthView {
    /// Whether the candidate meets the minimum length.
    pub meets_minimum_length: bool,
    /// Estimated entropy in bits. Order-of-magnitude, not a guarantee.
    pub entropy_bits: u32,
    /// Whether the candidate is on the well-known-weak deny-list.
    ///
    /// Reported separately from `warnings` so the UI can colour its bar from the
    /// same facts the vault rejects on, instead of inferring from prose.
    pub is_well_known_weak: bool,
    /// Whether the candidate looks like a repeated or sequential pattern.
    pub is_repeated_pattern: bool,
    /// Human-readable warnings. Empty when nothing is wrong.
    pub warnings: Vec<String>,
    /// Whether the vault would accept this candidate.
    ///
    /// Stricter than `meets_minimum_length`: the database passphrase is the only thing
    /// protecting the message history, so the deny-list and pattern checks are enforced
    /// rather than merely warned about.
    pub acceptable: bool,
}

impl HandleView {
    /// Build a display-safe handle view.
    pub fn from_handle(h: &SecretHandle) -> Self {
        Self {
            handle: h.to_string(),
            label: h.label().to_string(),
        }
    }
}
