//! Encrypted local storage with a mandatory 90-day retention ceiling
//! (`plan.md` §6).
//!
//! # The two corrections this crate implements
//!
//! `plan.md` §6.1 and §6.2 identify two ways the original design would have
//! shipped a **false** retention guarantee. Both are addressed structurally:
//!
//! ## 1. Integer timestamps, precomputed expiry (§6.1)
//!
//! The original purge used `strftime('%s','now','-90 days')`, which returns a
//! *string of digits*. Compared against a text timestamp column, that is a
//! string comparison and silently purges nothing. Here:
//!
//! * all times are `INTEGER` epoch **seconds**;
//! * every row carries a precomputed absolute `expires_at`;
//! * tables are `STRICT`, so SQLite itself rejects type confusion rather than
//!   silently coercing;
//! * purge filters on the indexed `expires_at`.
//!
//! ## 2. Crypto-shredding rather than trusting `VACUUM` (§6.2)
//!
//! `VACUUM` is a logical compaction, not a guaranteed physical erase: flash
//! wear-levelling and the translation layer may retain old blocks. So the
//! primary control is a **per-month data key** that is destroyed when the bucket
//! ages past the ceiling. Surviving ciphertext is then undecryptable regardless
//! of filesystem behaviour. `secure_delete` and `VACUUM` remain as secondary
//! layers.
//!
//! # Layering
//!
//! ```text
//! passphrase --Argon2id--> master key --HKDF--> per-bucket data key
//! data key + AEAD --> row ciphertext
//! ```

pub mod bucket;
pub mod error;
pub mod mailbox;
pub mod rekey;
pub mod schema;
pub mod send_queue;
pub mod store;

pub use bucket::{BucketId, DataKey, KeyRing};
pub use error::{Result, StorageError};
pub use mailbox::{BufferedBlob, Mailbox, MailboxPolicy, MailboxReceipt, MailboxRejection};
pub use rekey::{rekey, resume, RekeyMarker, RekeyPaths, RekeyReport, RekeyStage};
pub use schema::{RETENTION_DAYS, SCHEMA_VERSION};
pub use send_queue::{QueuedSend, SendQueue};
pub use store::{
    Argon2Params, ContactRow, ConversationKind, ConversationRow, GroupRow, MessageRow, PurgeReport,
    Store, StoreConfig,
};
