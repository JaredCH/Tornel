//! MLS (RFC 9420) group ratcheting over the app's encrypted store
//! (`plan.md` §4.2, §4.3, §7.1 Phase 4).
//!
//! # Why this crate exists
//!
//! `plan.md` §4.2 rejects the original plan's "one shared symmetric group key"
//! for a concrete reason: with a single key, removing a member requires
//! re-keying everyone, and *any* member — including a compromised one — can
//! decrypt all past traffic. Both are exactly what forward secrecy and
//! post-compromise security exist to prevent.
//!
//! So group key management is delegated to a vetted implementation of MLS rather
//! than hand-rolled. This crate is the thin, auditable seam between that
//! implementation and the rest of the app:
//!
//! ```text
//! anon-messaging  -- padded frames, replay protection, delivery
//!       |
//! anon-mls        -- THIS CRATE: group lifecycle, epoch transitions
//!       |
//! openmls         -- RFC 9420 protocol
//!       |
//! anon-storage    -- SQLCipher: one encrypted file, one key, one retention rule
//! ```
//!
//! # The exit criterion this satisfies
//!
//! §7.1 Phase 4 requires: *"member removal advances the epoch and the removed
//! member cannot decrypt subsequent messages (test this explicitly)"*. That is
//! [`Group::remove_member`] plus the `removed_member_cannot_decrypt` test in
//! `tests/group.rs`, which asserts the failure rather than assuming it.
//!
//! # What is deliberately not here
//!
//! * **No networking.** Delivery is `anon-messaging`'s job, and it goes through
//!   the no-clearnet transport gate. This crate only produces and consumes bytes.
//! * **No key storage of its own.** MLS state lives in the same SQLCipher
//!   database as everything else, via [`anon_storage::Store::open_secondary_connection`].
//! * **No consent logic.** Whether an epoch transition is *allowed* is
//!   `anon-consent`'s decision (`plan.md` §5). This crate performs the
//!   transition once told to.

pub mod error;
pub mod group;
pub mod provider;

pub use error::{MlsError, Result};
pub use group::{AddOutcome, Group, GroupInfo, GroupMember, RemoveOutcome, CIPHERSUITE};
pub use provider::{JsonCodec, MlsProvider, MlsStorage};
