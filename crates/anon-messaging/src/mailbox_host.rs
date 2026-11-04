//! Hosting a peer mailbox (`plan.md` §4.4).
//!
//! # What this layer does and does not do
//!
//! The storage layer ([`anon_storage::mailbox`]) owns the table, the quotas, and
//! the TTL. This module is the *policy* layer above it: it decides what a host
//! accepts, what it tells the sender, and how a recipient drains its mail.
//!
//! It deliberately never decrypts. A host has no group key, so the blobs it holds
//! are opaque. That is the property that makes peer hosting tolerable: a
//! compromised host leaks *who is talking to whom and when*, but not *what was
//! said*.
//!
//! # The honest-delivery rule
//!
//! `plan.md` §8 forbids a false "delivered" state. A mailbox host can only ever
//! say "I am holding this". So:
//!
//! * [`MailboxHost::accept`] returns a [`MailboxReceipt`], whose
//!   `is_delivery()` is hard-coded `false`;
//! * the sender's UI must render that as "at mailbox", never "delivered";
//! * only the recipient's own acknowledgement moves the state forward, and that
//!   acknowledgement travels back over the network — this layer cannot fabricate
//!   it.
//!
//! # Hostile-peer posture
//!
//! The host is the party at risk here, not the sender. A peer that offers to host
//! for you can:
//!
//! * refuse to accept anything (availability — unavoidable, and why the sender
//!   must treat a mailbox drop as possible loss);
//! * keep a copy past the ceiling (mitigated: the same purge covers mailbox rows,
//!   and the read path enforces expiry itself);
//! * fill your disk (mitigated: quotas are enforced before any write);
//! * read the content (impossible without the group key);
//! * learn the social graph (unavoidable, and documented in §4.4's privacy row).
//!
//! The first and last are accepted risks. The middle three are enforced here.

use crate::error::{MessageError, Result};
use anon_storage::mailbox::{
    BufferedBlob, Mailbox, MailboxPolicy, MailboxReceipt, MailboxRejection,
};
use anon_storage::Store;

/// A host's view of one mailbox it is holding for a recipient.
///
/// Wraps the storage-level [`Mailbox`] with the policy decisions this layer owns:
/// what to do with a refusal, and how to hand blobs to the recipient.
pub struct MailboxHost<'a> {
    mailbox: Mailbox<'a>,
}

impl<'a> MailboxHost<'a> {
    /// Build a host over a store with an explicit quota policy.
    pub fn new(store: &'a Store, policy: MailboxPolicy) -> Self {
        Self {
            mailbox: Mailbox::new(store, policy),
        }
    }

    /// Build a host with the default mobile policy.
    pub fn with_defaults(store: &'a Store) -> Self {
        Self {
            mailbox: Mailbox::with_defaults(store),
        }
    }

    /// The quota policy in force.
    pub fn policy(&self) -> MailboxPolicy {
        self.mailbox.policy()
    }

    /// Accept an opaque blob for `recipient`.
    ///
    /// Returns a receipt on success. A refusal is a *policy* outcome, not an
    /// error: the caller is expected to tell the sender "not accepted" rather
    /// than retry blindly. That is why the rejection type is separate from
    /// [`MessageError`].
    pub fn accept(
        &self,
        recipient: &[u8],
        sender: &[u8],
        ciphertext: &[u8],
        expires_at: i64,
    ) -> std::result::Result<MailboxReceipt, MailboxRejection> {
        self.mailbox
            .enqueue(recipient, sender, ciphertext, expires_at)
    }

    /// Accept a batch, reporting what landed.
    ///
    /// A partial batch is reported honestly rather than rolled back: a sender
    /// needs to know which messages did not land so it can retry exactly those.
    pub fn accept_batch(
        &self,
        recipient: &[u8],
        sender: &[u8],
        blobs: &[(&[u8], i64)],
    ) -> (Vec<MailboxReceipt>, Option<MailboxRejection>) {
        self.mailbox.enqueue_batch(recipient, sender, blobs)
    }

    /// Drain every live blob for `recipient`, removing each one as it is taken.
    ///
    /// This is the recipient's side: it takes custody of the blobs and deletes
    /// them from the host in one step, so a host cannot keep serving the same mail
    /// after the recipient has it. If the caller fails to process a blob after
    /// this returns, that blob is lost — which is the correct trade for not
    /// leaving a copy on a third party's disk.
    ///
    /// Returns the blobs in arrival order, which matters for MLS: group messages
    /// must be processed in the order the sender produced them.
    pub fn drain(&self, recipient: &[u8]) -> Result<Vec<BufferedBlob>> {
        let blobs = self.mailbox.read(recipient)?;
        for blob in &blobs {
            // Best effort: a failed delete leaves the row to expire on its own,
            // which is still bounded by the ceiling. Reporting it as an error
            // would lose the blobs we already read.
            let _ = self.mailbox.acknowledge(recipient, &blob.id);
        }
        Ok(blobs)
    }

    /// Read without removing, for a caller that wants to inspect first.
    pub fn peek(&self, recipient: &[u8]) -> Result<Vec<BufferedBlob>> {
        Ok(self.mailbox.read(recipient)?)
    }

    /// Remove one blob after the recipient has taken custody of it.
    pub fn acknowledge(&self, recipient: &[u8], id: &[u8; 16]) -> Result<bool> {
        Ok(self.mailbox.acknowledge(recipient, id)?)
    }

    /// Bytes and messages currently held, optionally for one sender.
    ///
    /// Exposed so a host can show its own storage pressure honestly, and so tests
    /// can assert that a refusal consumed nothing.
    pub fn usage(&self, recipient: &[u8], sender: Option<&[u8]>) -> Result<(usize, usize)> {
        Ok(self.mailbox.usage(recipient, sender)?)
    }
}

/// Convert a mailbox refusal into a message-layer error.
///
/// Kept as a free function rather than an `impl From` so the conversion is
/// explicit at call sites: a refusal is a *policy* answer the UI must surface,
/// and silently turning it into a generic error would lose that distinction.
pub fn refusal_to_error(rejection: MailboxRejection) -> MessageError {
    MessageError::MailboxRefused(rejection.to_string())
}

impl std::fmt::Debug for MailboxHost<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxHost")
            .field("policy", &self.policy())
            .finish_non_exhaustive()
    }
}
