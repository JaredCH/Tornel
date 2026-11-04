//! The backend-facing command surface (`plan.md` §7.3).
//!
//! # Purpose
//!
//! `plan.md` §7.3 draws a hard boundary: the webview gets *presentation and
//! consent only*; keys, the database, Tor, and rotation state stay in Rust. This
//! crate defines the exact set of values that may cross that boundary, and the
//! validation each input must pass.
//!
//! It deliberately has **no Tauri dependency**, so every rule below is unit
//! testable without a webview. The Tauri binary is a thin adapter that calls
//! these functions.
//!
//! # The rule this crate exists to enforce
//!
//! > No private key, seed, or database handle ever crosses this boundary.
//!
//! Three mechanisms make that more than a comment:
//!
//! 1. **The DTOs cannot hold secrets.** Every field is a plain, public value:
//!    ids, labels, epochs, counts, fingerprints. There is no field that could
//!    carry a key or a seed.
//! 2. **Secrets are passed as opaque handles.** When the backend needs the UI to
//!    confirm a secret with the user, it uses [`SecretHandle`], which names a
//!    value held in Rust without revealing it.
//! 3. **A compile-time test enumerates the fields.** [`dto_inventory`] lists every
//!    field name in the boundary types, and a test asserts none of them looks
//!    like secret material. Adding a `seed` field would fail the build.

pub mod commands;
pub mod dto;
pub mod error;

pub use commands::Backend;
pub use dto::PrivacyView;
pub use dto::{
    AddMemberOutcome, ConsentPrompt, ConsentSubmission, ConversationView, DeliveryState,
    GroupMemberView, GroupView, IdentityView, MessageView, PeerView, ProposalView,
    QueuedMessageView, RemoveMemberOutcome, SendRequest, StrengthView, TransportView, VaultView,
};
pub use error::{CommandError, IpcError, Result};

/// An opaque name for a value that stays inside Rust.
///
/// The webview may hold and echo a handle, but cannot derive the secret from it.
/// Handles are per-session and never persisted.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct SecretHandle(String);

impl SecretHandle {
    /// Mint a handle for a value the backend is holding.
    pub fn mint() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy is available");
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// A short, non-secret label safe to display.
    pub fn label(&self) -> &str {
        &self.0[..8]
    }

    /// The raw handle, for the backend's own map lookup.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returns every field name declared in the IPC boundary data-transfer objects.
///
/// Used by the boundary test to assert no secret-bearing field can be added
/// without the test noticing. This is intentionally a hand-maintained list paired
/// with a test that reads the DTO sources, so drift is detected.
pub fn dto_inventory() -> Vec<&'static str> {
    vec![
        "restricted_discovery",
        "legacy_contacts",
        "traffic_shaping",
        // IdentityView
        "contact_code",
        "fingerprint",
        "display_name",
        "escrow_exported",
        // PeerView
        "contact_code",
        "onion_short",
        "added_at",
        "verified",
        // ConversationView
        "id",
        "kind",
        "label",
        "expires_at",
        "message_count",
        // MessageView
        "message_id",
        "sender_fingerprint",
        "sent_at",
        "expires_at",
        "delivery",
        "body",
        // TransportView
        "anonymity",
        "status",
        "can_send",
        "blocked_reason",
        "local_onion_short",
        "local_onion",
        "queued_count",
        // QueuedMessageView
        "created_at",
        "attempts",
        "last_error",
        // ProposalView
        "proposal_id",
        "group_id",
        "group_name",
        "reason",
        "epoch_before",
        "epoch_after",
        "member_count",
        "expires_at",
        "content_hash",
        "is_blocking",
        "prompt_text",
        // ConsentPrompt
        "proposal",
        "nonce_handle",
        // ConsentSubmission
        "proposal_id",
        "nonce_handle",
        "approved",
        // SendRequest
        "conversation_id",
        "recipient_onion",
        "epoch",
        "body",
        // HandleView
        "handle",
        "label",
        // GroupView
        "group_id",
        "name",
        "epoch",
        "member_count",
        "created_at",
        // GroupMemberView
        "leaf_index",
        "contact_code_short",
        "is_self",
        "role",
        "display_name",
        // AddMemberOutcome
        "group_id",
        "epoch",
        "welcome_hex",
        // RemoveMemberOutcome
        "group_id",
        "epoch",
        "proposal",
        // VaultView
        "state",
        "is_setup",
        "min_chars",
        "migration_stage",
        "blocked_reason",
        // StrengthView
        "meets_minimum_length",
        "entropy_bits",
        "is_well_known_weak",
        "is_repeated_pattern",
        "is_obviously_weak_pattern",
        "warnings",
        "acceptable",
    ]
}

/// Substrings that must never appear in a boundary field name.
///
/// If a DTO field is ever named one of these, it is almost certainly carrying
/// secret material across the boundary.
pub const FORBIDDEN_FIELD_MARKERS: &[&str] = &[
    "secret",
    "private",
    "seed",
    "passphrase",
    "password",
    "master_key",
    "private_key",
    "data_key",
    "raw_key",
    "key_bytes",
];
