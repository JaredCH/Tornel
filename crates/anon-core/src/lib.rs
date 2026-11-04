//! Core cryptography, identity, and retention policy for the anonymous P2P app.
//!
//! Implements plan.md §2 (identity), §2.2 (contact code), §2.5 (escrow),
//! §6 (retention policy math).
//!
//! # Security posture
//!
//! * All secret material is held in exactly one owning buffer and dropped via
//!   `zeroize`-enabled destructors (`plan.md` §2.3).
//! * No function in this crate logs, formats, or serialises a secret.
//! * Nothing here performs I/O, so it is safe to call from any thread.

pub mod code;
pub mod error;
pub mod escrow;
pub mod identity;
pub mod retention;

pub use code::{ContactCode, CONTACT_CODE_HRP};
pub use error::{CoreError, Result};
pub use identity::{IdentityKeys, PublicIdentity};
pub use retention::{
    expiry_from_sent_at, is_expired, retention_bucket, RETENTION_DAYS, RETENTION_SECONDS,
    SECONDS_PER_DAY,
};

/// Domain separation tag for deriving the encryption keypair seed from the
/// identity seed. Keeps the two keypairs cryptographically independent.
pub const KDF_DOMAIN_X25519: &[u8] = b"anon/v1/x25519-from-ed25519";

/// Domain separation tag for escrow key derivation.
pub const KDF_DOMAIN_ESCROW: &[u8] = b"anon/v1/escrow";
