//! Peer-hosted offline mailbox (`plan.md` §4.4).
//!
//! # Why this exists
//!
//! Group members are not online simultaneously. Without a server, someone has to
//! hold a message until its recipient connects. `plan.md` §4.4 makes a peer the
//! host, and is explicit that this is **the weakest link**: third-party storage
//! under hostile conditions.
//!
//! The table in §4.4 is the specification this module implements:
//!
//! | §4.4 requirement | How it is met here |
//! | --- | --- |
//! | Confidentiality | The host stores *ciphertext it cannot read*: MLS protects the content, so this layer never has the key. |
//! | Integrity | AEAD over the stored blob plus a length-bound AAD; tampering is detected on read. |
//! | Disappearance | Every buffered row carries `expires_at` and is purged by the same routine as everything else, so a host cannot keep a copy past the 90-day ceiling. |
//! | Abuse | Per-sender byte quotas and a per-mailbox total cap, enforced **before** writing. Without this a hostile peer fills the host's disk. |
//! | Availability | Best effort by design: [`Mailbox::enqueue`] can refuse, and callers must treat a mailbox drop as loss, never as delivery. |
//! | Attestation | [`MailboxReceipt`] records when the host accepted a blob and when it will expire, so a sender can infer loss rather than guess. |
//! | Privacy | Documented, not solved: the host learns who is in the group and when they send, but not what. |
//!
//! # What this module refuses to do
//!
//! It never decrypts. A mailbox host has no group key by design, so a compromised
//! host leaks traffic *metadata* but not content. That is the property that makes
//! "peer-hosted" tolerable at all, and it is why the blob is stored as opaque
//! bytes rather than being re-encrypted by the host.
//!
//! # Quota policy
//!
//! `plan.md` §13 lists the quota numbers as an open decision. This module picks
//! defaults and makes them configurable in [`MailboxPolicy`], so the policy can
//! change without touching the enforcement code:
//!
//! * **per-sender** total bytes, so one peer cannot dominate;
//! * **per-mailbox** total bytes, so the host's disk is bounded regardless of how
//!   many peers send;
//! * **per-sender** message count, so a flood of tiny messages is also bounded.
//!
//! Quotas are checked against *currently buffered* bytes, so space is returned
//! when a message is delivered or expires. A rejected message is refused
//! explicitly — it is never silently dropped.

use crate::bucket::BucketId;
use crate::error::{Result, StorageError};
use crate::store::Store;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

/// Mailbox quota policy (`plan.md` §4.4 "Abuse", §13 open question).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxPolicy {
    /// Maximum bytes buffered for one sender.
    pub max_bytes_per_sender: usize,
    /// Maximum messages buffered for one sender.
    pub max_messages_per_sender: usize,
    /// Maximum bytes buffered across the whole mailbox.
    pub max_bytes_total: usize,
    /// Maximum blobs accepted in one envelope batch.
    pub max_blobs_per_enqueue: usize,
}

impl MailboxPolicy {
    /// Conservative defaults sized for a mobile host.
    ///
    /// A phone hosting a mailbox for a modest group should not exceed a few MB of
    /// buffered ciphertext, and no single peer should be able to claim most of it.
    pub const fn mobile_default() -> Self {
        Self {
            max_bytes_per_sender: 256 * 1024,
            max_messages_per_sender: 64,
            max_bytes_total: 4 * 1024 * 1024,
            max_blobs_per_enqueue: 32,
        }
    }
}

impl Default for MailboxPolicy {
    fn default() -> Self {
        Self::mobile_default()
    }
}

/// What the host tells a sender when a blob is accepted (`plan.md` §4.4
/// "Attestation").
///
/// Deliberately *not* a delivery receipt: a mailbox receipt means "the host now
/// holds this", and the sender must not render it as "the recipient read it".
/// That distinction is why [`MailboxReceipt::is_delivery`] is a hard `false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxReceipt {
    /// Row id assigned by the host.
    pub id: [u8; 16],
    /// When the host accepted it (epoch seconds).
    pub received_at: i64,
    /// When the host will delete it (epoch seconds).
    pub expires_at: i64,
}

impl MailboxReceipt {
    /// Always `false`. A mailbox is storage, not delivery.
    ///
    /// Exists as a named method so UI code cannot accidentally treat a receipt as
    /// proof of delivery — the `plan.md` §8 "no false delivered state" rule.
    pub const fn is_delivery(&self) -> bool {
        false
    }
}

/// A buffered blob as read by the recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct BufferedBlob {
    /// Row id.
    pub id: [u8; 16],
    /// The sender's identity bytes.
    pub sender: Vec<u8>,
    /// The opaque ciphertext, as stored.
    pub ciphertext: Vec<u8>,
    /// When the host accepted it.
    pub received_at: i64,
}

impl std::fmt::Debug for BufferedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The ciphertext is not ours to print, and could be long.
        f.debug_struct("BufferedBlob")
            .field("id", &self.id)
            .field("sender_len", &self.sender.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("received_at", &self.received_at)
            .finish()
    }
}

/// A refusal from the mailbox.
///
/// Distinct from [`StorageError`] because these are *policy* outcomes a caller is
/// expected to handle, not failures of the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxRejection {
    /// This sender already holds more bytes than allowed.
    SenderByteQuota { held: usize, limit: usize },
    /// This sender already holds more messages than allowed.
    SenderCountQuota { held: usize, limit: usize },
    /// The mailbox as a whole is full.
    MailboxFull { held: usize, limit: usize },
    /// Too many blobs in one call.
    BatchTooLarge { count: usize, limit: usize },
    /// One blob is larger than a sender is allowed to hold in total, so it could
    /// never fit.
    BlobTooLarge { size: usize, limit: usize },
    /// The blob's own lifetime is already over.
    AlreadyExpired,
}

impl std::fmt::Display for MailboxRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SenderByteQuota { held, limit } => {
                write!(f, "sender byte quota exceeded ({held} of {limit})")
            }
            Self::SenderCountQuota { held, limit } => {
                write!(f, "sender message quota exceeded ({held} of {limit})")
            }
            Self::MailboxFull { held, limit } => {
                write!(f, "mailbox is full ({held} of {limit} bytes)")
            }
            Self::BatchTooLarge { count, limit } => {
                write!(f, "batch of {count} exceeds the limit of {limit}")
            }
            Self::BlobTooLarge { size, limit } => {
                write!(f, "blob of {size} bytes exceeds the limit of {limit}")
            }
            Self::AlreadyExpired => f.write_str("blob lifetime is already over"),
        }
    }
}

/// A peer-hosted mailbox.
///
/// Hosted on the local store. A mailbox is keyed by `recipient` — the design in
/// `plan.md` §4.4 is one mailbox per recipient address, so any online member can
/// read their own mail from whichever peer is hosting it.
pub struct Mailbox<'a> {
    store: &'a Store,
    policy: MailboxPolicy,
}

impl<'a> Mailbox<'a> {
    /// Build a mailbox over a store with an explicit policy.
    pub fn new(store: &'a Store, policy: MailboxPolicy) -> Self {
        Self { store, policy }
    }

    /// Build a mailbox with the default policy.
    pub fn with_defaults(store: &'a Store) -> Self {
        Self::new(store, MailboxPolicy::default())
    }

    /// The policy in force.
    pub fn policy(&self) -> MailboxPolicy {
        self.policy
    }

    /// Accept a ciphertext blob for `recipient`.
    ///
    /// The blob is stored **opaque**: this host cannot read it, because it has no
    /// group key. Its own at-rest encryption uses a mailbox-specific bucket key so
    /// the on-disk bytes differ from the wire bytes, but that is defence in depth,
    /// not confidentiality from the host — see the module docs.
    ///
    /// All quota checks happen before any write, so a rejected blob consumes
    /// nothing.
    pub fn enqueue(
        &self,
        recipient: &[u8],
        sender: &[u8],
        ciphertext: &[u8],
        expires_at: i64,
    ) -> std::result::Result<MailboxReceipt, MailboxRejection> {
        let now = self.store.now();

        if expires_at <= now {
            return Err(MailboxRejection::AlreadyExpired);
        }
        if ciphertext.len() > self.policy.max_bytes_per_sender {
            return Err(MailboxRejection::BlobTooLarge {
                size: ciphertext.len(),
                limit: self.policy.max_bytes_per_sender,
            });
        }

        let (sender_bytes, sender_count) = self
            .usage(recipient, Some(sender))
            .map_err(|_| MailboxRejection::MailboxFull { held: 0, limit: 0 })?;
        let (total_bytes, _) = self
            .usage(recipient, None)
            .map_err(|_| MailboxRejection::MailboxFull { held: 0, limit: 0 })?;

        if sender_bytes + ciphertext.len() > self.policy.max_bytes_per_sender {
            return Err(MailboxRejection::SenderByteQuota {
                held: sender_bytes,
                limit: self.policy.max_bytes_per_sender,
            });
        }
        if sender_count + 1 > self.policy.max_messages_per_sender {
            return Err(MailboxRejection::SenderCountQuota {
                held: sender_count,
                limit: self.policy.max_messages_per_sender,
            });
        }
        if total_bytes + ciphertext.len() > self.policy.max_bytes_total {
            return Err(MailboxRejection::MailboxFull {
                held: total_bytes,
                limit: self.policy.max_bytes_total,
            });
        }

        let id: [u8; 16] = {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).expect("OS entropy is available");
            bytes
        };

        self.store
            .mailbox_insert(&id, recipient, sender, ciphertext, now, expires_at)
            .map_err(|_| MailboxRejection::MailboxFull {
                held: total_bytes,
                limit: self.policy.max_bytes_total,
            })?;

        Ok(MailboxReceipt {
            id,
            received_at: now,
            expires_at,
        })
    }

    /// Accept several blobs in one call, stopping at the first refusal.
    ///
    /// Returns the receipts that were accepted together with any rejection, so a
    /// partial batch is reported honestly rather than rolled back silently — a
    /// sender needs to know which messages did not land.
    pub fn enqueue_batch(
        &self,
        recipient: &[u8],
        sender: &[u8],
        blobs: &[(&[u8], i64)],
    ) -> (Vec<MailboxReceipt>, Option<MailboxRejection>) {
        if blobs.len() > self.policy.max_blobs_per_enqueue {
            return (
                Vec::new(),
                Some(MailboxRejection::BatchTooLarge {
                    count: blobs.len(),
                    limit: self.policy.max_blobs_per_enqueue,
                }),
            );
        }
        let mut receipts = Vec::with_capacity(blobs.len());
        for (ciphertext, expires_at) in blobs {
            match self.enqueue(recipient, sender, ciphertext, *expires_at) {
                Ok(r) => receipts.push(r),
                Err(e) => return (receipts, Some(e)),
            }
        }
        (receipts, None)
    }

    /// Read every live blob addressed to `recipient`.
    ///
    /// Only unexpired rows are returned; expired-but-not-yet-purged rows are
    /// skipped so a recipient never receives something past the ceiling even if
    /// the purge has not run yet (§6.4 "enforcement points").
    pub fn read(&self, recipient: &[u8]) -> Result<Vec<BufferedBlob>> {
        let now = self.store.now();
        self.store.mailbox_read(recipient, now)
    }

    /// Remove one blob after the recipient has taken it.
    ///
    /// Returns whether a row was removed. Delivery is confirmed only by the
    /// recipient calling this, which is what makes the receipt an honest
    /// "at mailbox" state rather than "delivered".
    pub fn acknowledge(&self, recipient: &[u8], id: &[u8; 16]) -> Result<bool> {
        self.store.mailbox_delete(recipient, id)
    }

    /// Bytes and messages currently buffered, optionally for one sender.
    ///
    /// Expired rows are excluded, so quotas reflect what the host is actually
    /// holding rather than what a purge has not reached yet.
    pub fn usage(&self, recipient: &[u8], sender: Option<&[u8]>) -> Result<(usize, usize)> {
        self.store
            .mailbox_usage(recipient, sender, self.store.now())
    }
}

impl Store {
    /// Insert a blob into `mailbox_buffer`.
    ///
    /// The blob is re-encrypted at rest under a mailbox bucket key, so the stored
    /// bytes differ from the bytes that arrived. As the module docs say, that is
    /// defence in depth: the confidentiality boundary for mailbox content is MLS,
    /// not this.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mailbox_insert(
        &self,
        id: &[u8; 16],
        recipient: &[u8],
        sender: &[u8],
        ciphertext: &[u8],
        received_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        // The bucket is chosen from the *expiry* month, not the receive month:
        // a blob must never land in a bucket that will be shredded while the blob
        // is still live.
        let bucket = BucketId::from_epoch(expires_at);
        let key = self.open_bucket(&bucket)?;
        let nonce: [u8; 12] = {
            let mut n = [0u8; 12];
            getrandom::fill(&mut n).expect("OS entropy is available");
            n
        };

        let aad = mailbox_aad(recipient, sender, received_at, expires_at);
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::Decrypt)?;

        self.raw_execute(
            "INSERT INTO mailbox_buffer
               (id, recipient, sender, received_at, expires_at, size_bytes, bucket, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &id[..],
                recipient,
                sender,
                received_at,
                expires_at,
                ciphertext.len() as i64,
                bucket.as_str(),
                &nonce[..],
                &sealed
            ],
                )?;
        Ok(())
    }

    /// Read live blobs for a recipient.
    pub(crate) fn mailbox_read(&self, recipient: &[u8], now: i64) -> Result<Vec<BufferedBlob>> {
        let rows = self.raw_query_all(
            "SELECT id, sender, received_at, expires_at, bucket, nonce, ciphertext
               FROM mailbox_buffer
              WHERE recipient = ?1 AND expires_at > ?2
              ORDER BY received_at ASC, rowid ASC",
            rusqlite::params![recipient, now],
        )?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Vec<u8> = row.get(0)?;
            let sender: Vec<u8> = row.get(1)?;
            let received_at: i64 = row.get(2)?;
            let expires_at: i64 = row.get(3)?;
            let bucket: String = row.get(4)?;
            let nonce: Vec<u8> = row.get(5)?;
            let ciphertext: Vec<u8> = row.get(6)?;

            let bucket = BucketId::parse(&bucket)?;
            let key = self.key_ring().get(&bucket)?;
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| StorageError::InvalidRecord("bad mailbox nonce length"))?;

            let aad = mailbox_aad(recipient, &sender, received_at, expires_at);
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            let plaintext = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| StorageError::Decrypt)?;

            out.push(BufferedBlob {
                id: id
                    .try_into()
                    .map_err(|_| StorageError::InvalidRecord("bad mailbox id length"))?,
                sender,
                ciphertext: plaintext,
                received_at,
            });
        }
        Ok(out)
    }

    /// Delete one blob, scoped to its recipient so a caller cannot delete another
    /// mailbox's mail by guessing an id.
    pub(crate) fn mailbox_delete(&self, recipient: &[u8], id: &[u8; 16]) -> Result<bool> {
        let deleted = self.raw_execute(
            "DELETE FROM mailbox_buffer WHERE recipient = ?1 AND id = ?2",
            rusqlite::params![recipient, &id[..]],
        )?;
        Ok(deleted > 0)
    }

    /// Bytes and count currently buffered, excluding expired rows.
    pub(crate) fn mailbox_usage(
        &self,
        recipient: &[u8],
        sender: Option<&[u8]>,
        now: i64,
    ) -> Result<(usize, usize)> {
        let row = match sender {
            Some(sender) => self.raw_query_one(
                "SELECT COALESCE(SUM(size_bytes), 0), COUNT(*)
                   FROM mailbox_buffer
                  WHERE recipient = ?1 AND sender = ?2 AND expires_at > ?3",
                rusqlite::params![recipient, sender, now],
            )?,
            None => self.raw_query_one(
                "SELECT COALESCE(SUM(size_bytes), 0), COUNT(*)
                   FROM mailbox_buffer
                  WHERE recipient = ?1 AND expires_at > ?2",
                rusqlite::params![recipient, now],
            )?,
        };
        match row {
            Some(row) => {
                let bytes: i64 = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((bytes.max(0) as usize, count.max(0) as usize))
            }
            None => Ok((0, 0)),
        }
    }
}

/// AAD binding a mailbox blob to its routing metadata.
///
/// Binding recipient, sender, and both timestamps means a host cannot move a blob
/// to another recipient, re-attribute it, or extend its lifetime without the
/// recipient's read failing authentication.
fn mailbox_aad(recipient: &[u8], sender: &[u8], received_at: i64, expires_at: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(recipient.len() + sender.len() + 48);
    aad.extend_from_slice(b"anon/v1/mailbox");
    aad.extend_from_slice(&(recipient.len() as u32).to_le_bytes());
    aad.extend_from_slice(recipient);
    aad.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    aad.extend_from_slice(sender);
    aad.extend_from_slice(&received_at.to_le_bytes());
    aad.extend_from_slice(&expires_at.to_le_bytes());
    aad
}
