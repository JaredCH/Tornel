//! Durable outbound send queue.
//!
//! # Why this exists
//!
//! A peer-to-peer messenger has no server to hold a message when the recipient is
//! offline. Without a queue, a send to an unreachable peer is simply lost, and the
//! user has no way to tell "not sent yet" from "gone".
//!
//! This table is the sender-side counterpart to [`crate::mailbox`]: the mailbox
//! holds *inbound* ciphertext for a peer that is not online, and this holds
//! *outbound* ciphertext for a peer that is not online yet. Both are bounded by
//! the same retention ceiling, so a message that never lands cannot outlive the
//! 90-day promise (`plan.md` §6.4).
//!
//! # What is stored
//!
//! The already-sealed frame — never plaintext. The queue is therefore not a second
//! copy of the message history; it is a copy of the *wire bytes* that still need
//! to go out. Re-encrypting at rest under a bucket key means a queue row that
//! survives a crypto-shred is undecryptable, exactly like every other table.
//!
//! # Ordering
//!
//! Rows are drained oldest-first. Tor gives no ordering guarantee on the wire, but
//! the sender should still *attempt* in the order the user wrote, because that is
//! the order the recipient's UI will show once the frames arrive.

use crate::bucket::BucketId;
use crate::error::{Result, StorageError};
use crate::store::Store;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

/// One queued outbound frame.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedSend {
    /// Row id, used to remove the row once it is delivered.
    pub id: [u8; 16],
    /// Conversation the frame belongs to.
    pub conversation: Vec<u8>,
    /// Destination route, as text (an `.onion` address).
    pub route: String,
    /// Epoch the frame was sealed under.
    pub epoch: u64,
    /// When the frame was queued (epoch seconds).
    pub created_at: i64,
    /// When the row will be purged (epoch seconds).
    pub expires_at: i64,
    /// How many delivery attempts have been made.
    pub attempts: u32,
    /// When the last attempt happened, if any.
    pub last_attempt_at: Option<i64>,
    /// Why the last attempt failed, if it did.
    pub last_error: Option<String>,
    /// The sealed frame bytes.
    pub frame: Vec<u8>,
}

impl std::fmt::Debug for QueuedSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The frame is ciphertext, but it is still not ours to print in full.
        f.debug_struct("QueuedSend")
            .field("id", &self.id)
            .field("route", &self.route)
            .field("epoch", &self.epoch)
            .field("attempts", &self.attempts)
            .field("frame_len", &self.frame.len())
            .finish()
    }
}

/// A queue over the local store.
pub struct SendQueue<'a> {
    store: &'a Store,
}

impl<'a> SendQueue<'a> {
    /// Build a queue over a store.
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// Queue a sealed frame for later delivery.
    ///
    /// `expires_at` is the retention deadline for the *message*, not a separate
    /// queue lifetime: a queued frame must not outlive the message it carries.
    pub fn enqueue(
        &self,
        conversation: &[u8],
        route: &str,
        epoch: u64,
        frame: &[u8],
        expires_at: i64,
    ) -> Result<[u8; 16]> {
        let now = self.store.now();
        if expires_at <= now {
            return Err(StorageError::AlreadyExpired { expires_at, now });
        }
        self.store
            .send_queue_insert(conversation, route, epoch, frame, now, expires_at)
    }

    /// Every live queued frame, oldest first.
    pub fn pending(&self) -> Result<Vec<QueuedSend>> {
        self.store.send_queue_pending(self.store.now())
    }

    /// Queued frames for one conversation, oldest first.
    pub fn pending_for(&self, conversation: &[u8]) -> Result<Vec<QueuedSend>> {
        Ok(self
            .pending()?
            .into_iter()
            .filter(|q| q.conversation == conversation)
            .collect())
    }

    /// Number of live queued frames.
    pub fn len(&self) -> Result<usize> {
        Ok(self.pending()?.len())
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Record a failed attempt without removing the row.
    ///
    /// The error text is stored so the UI can explain *why* a message is still
    /// queued rather than showing an unexplained spinner (`plan.md` §8).
    pub fn record_failure(&self, id: &[u8; 16], error: &str) -> Result<bool> {
        let now = self.store.now();
        self.store.send_queue_record_failure(id, now, error)
    }

    /// Remove a row after it was delivered.
    pub fn remove(&self, id: &[u8; 16]) -> Result<bool> {
        self.store.send_queue_delete(id)
    }
}

impl Store {
    /// Insert a queued frame, re-encrypting it at rest.
    pub(crate) fn send_queue_insert(
        &self,
        conversation: &[u8],
        route: &str,
        epoch: u64,
        frame: &[u8],
        created_at: i64,
        expires_at: i64,
    ) -> Result<[u8; 16]> {
        // Bucket from the expiry month, so a queued frame never lands in a bucket
        // that will be shredded while the frame is still live.
        let bucket = BucketId::from_epoch(expires_at);
        let key = self.open_bucket(&bucket)?;

        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("OS entropy is available");
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS entropy is available");

        let aad = send_queue_aad(&id, conversation, route, epoch, created_at, expires_at);
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: frame,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::Decrypt)?;

        self.raw_execute(
            "INSERT INTO send_queue
               (id, conversation, route, epoch, created_at, expires_at, attempts,
                last_attempt_at, last_error, bucket, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, NULL, ?7, ?8, ?9)",
            rusqlite::params![
                &id[..],
                conversation,
                route,
                epoch as i64,
                created_at,
                expires_at,
                bucket.as_str(),
                &nonce[..],
                &sealed
            ],
        )?;
        Ok(id)
    }

    /// Read every live queued frame, oldest first.
    pub(crate) fn send_queue_pending(&self, now: i64) -> Result<Vec<QueuedSend>> {
        let rows = self.raw_query_all(
            "SELECT id, conversation, route, epoch, created_at, expires_at, attempts,
                    last_attempt_at, last_error, bucket, nonce, ciphertext
               FROM send_queue
              WHERE expires_at > ?1
              ORDER BY created_at ASC, rowid ASC",
            rusqlite::params![now],
        )?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Vec<u8> = row.get(0)?;
            let conversation: Vec<u8> = row.get(1)?;
            let route: String = row.get(2)?;
            let epoch: i64 = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let expires_at: i64 = row.get(5)?;
            let attempts: i64 = row.get(6)?;
            let last_attempt_at: Option<i64> = row.get(7)?;
            let last_error: Option<String> = row.get(8)?;
            let bucket: String = row.get(9)?;
            let nonce: Vec<u8> = row.get(10)?;
            let ciphertext: Vec<u8> = row.get(11)?;

            let id: [u8; 16] = id
                .try_into()
                .map_err(|_| StorageError::InvalidRecord("bad send queue id length"))?;
            let bucket = BucketId::parse(&bucket)?;
            let key = self.key_ring().get(&bucket)?;
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| StorageError::InvalidRecord("bad send queue nonce length"))?;

            let aad = send_queue_aad(
                &id,
                &conversation,
                &route,
                epoch as u64,
                created_at,
                expires_at,
            );
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            let frame = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| StorageError::Decrypt)?;

            out.push(QueuedSend {
                id,
                conversation,
                route,
                epoch: epoch.max(0) as u64,
                created_at,
                expires_at,
                attempts: attempts.max(0) as u32,
                last_attempt_at,
                last_error,
                frame,
            });
        }
        Ok(out)
    }

    /// Bump the attempt counter and record why the attempt failed.
    pub(crate) fn send_queue_record_failure(
        &self,
        id: &[u8; 16],
        now: i64,
        error: &str,
    ) -> Result<bool> {
        let updated = self.raw_execute(
            "UPDATE send_queue
                SET attempts = attempts + 1, last_attempt_at = ?1, last_error = ?2
              WHERE id = ?3",
            rusqlite::params![now, error, &id[..]],
        )?;
        Ok(updated > 0)
    }

    /// Delete a queued frame after successful delivery.
    pub(crate) fn send_queue_delete(&self, id: &[u8; 16]) -> Result<bool> {
        let deleted = self.raw_execute(
            "DELETE FROM send_queue WHERE id = ?1",
            rusqlite::params![&id[..]],
        )?;
        Ok(deleted > 0)
    }
}

/// AAD binding a queued frame to its routing metadata.
///
/// Binding the id, conversation, route, epoch, and both timestamps means a
/// tampered row cannot be re-pointed at another peer or have its lifetime
/// extended without the read failing authentication.
fn send_queue_aad(
    id: &[u8; 16],
    conversation: &[u8],
    route: &str,
    epoch: u64,
    created_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(conversation.len() + route.len() + 64);
    aad.extend_from_slice(b"anon/v1/send_queue");
    aad.extend_from_slice(id);
    aad.extend_from_slice(&(conversation.len() as u32).to_le_bytes());
    aad.extend_from_slice(conversation);
    aad.extend_from_slice(&(route.len() as u32).to_le_bytes());
    aad.extend_from_slice(route.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&created_at.to_le_bytes());
    aad.extend_from_slice(&expires_at.to_le_bytes());
    aad
}
