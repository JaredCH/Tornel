//! The outbound send queue (`plan.md` §9.2, §4.4).
//!
//! # The problem this solves
//!
//! A send to an offline peer fails: there is no server to hold the frame, and the
//! transport refuses rather than degrading (`plan.md` §1.2). Without a queue that
//! failure is *loss* — the user typed a message, it never arrived, and nothing
//! says so.
//!
//! This module keeps the sealed frame on the sender's own disk and retries it when
//! the transport becomes usable again. It is deliberately the sender-side mirror of
//! [`crate::mailbox_host`]: the mailbox holds inbound ciphertext for a peer that is
//! offline, and this holds outbound ciphertext for a peer that is offline.
//!
//! # What it will not do
//!
//! * It never stores plaintext. The frame is sealed before it is queued, so the
//!   queue is a copy of wire bytes, not a second copy of the message history.
//! * It never claims delivery. A queued frame is [`DeliveryOutcome::QueuedLocal`]
//!   until the transport actually accepts it, and even then it is only
//!   "handed to the transport" — never "delivered to the peer" (`plan.md` §8).
//! * It never retries a *policy* refusal. A local-only route or an oversized
//!   payload will fail identically forever, so those are reported to the caller
//!   instead of being queued.
//!
//! # Retry policy
//!
//! Retries are bounded by the message's own retention deadline, not by an attempt
//! count: a message that is still within the 90-day window is still worth sending.
//! A per-attempt backoff is applied so a permanently unreachable peer does not
//! cause a tight retry loop.

use crate::deliver::{DeliveryOutcome, DeliveryReport};
use crate::error::{MessageError, Result};
use crate::frame::Frame;
use anon_storage::{QueuedSend, SendQueue, Store};
use anon_transport::{AnonymityTransport, PeerRoute, TransportError};
use std::sync::Mutex;

/// How long to wait before retrying a frame that failed for a transient reason.
///
/// Deliberately short: the common case is "the peer's onion service was not
/// published yet", which resolves in seconds to minutes, not hours. The retention
/// deadline is the real bound on how long a frame stays queued.
pub const RETRY_BACKOFF_SECONDS: i64 = 30;

/// The result of one drain pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Frames the transport accepted and that were removed from the queue.
    pub sent: usize,
    /// Frames that failed and remain queued.
    pub failed: usize,
    /// Frames skipped because their backoff has not elapsed.
    pub deferred: usize,
    /// Frames dropped because they were already past their retention deadline.
    pub expired: usize,
}

impl DrainReport {
    /// Whether the pass changed anything.
    pub fn is_noop(&self) -> bool {
        self.sent == 0 && self.expired == 0
    }
}

/// The sender-side queue.
///
/// Holds no key material: the frames it stores are already sealed, and the
/// at-rest encryption is the store's job.
pub struct SendQueueService {
    /// Serializes drain passes so two callers cannot send the same frame twice.
    draining: Mutex<()>,
}

impl SendQueueService {
    /// Create a queue service.
    pub fn new() -> Self {
        Self {
            draining: Mutex::new(()),
        }
    }

    /// Queue a sealed frame for later delivery.
    ///
    /// Returns the queue row id. The caller keeps the frame's [`MessageId`] for
    /// display; the row id is only for removal.
    ///
    /// [`MessageId`]: crate::frame::MessageId
    pub fn enqueue(
        &self,
        store: &Store,
        route: &PeerRoute,
        conversation: [u8; 16],
        epoch: u64,
        frame: &Frame,
        expires_at: i64,
    ) -> Result<[u8; 16]> {
        // A local route can never be delivered, so queueing it would only defer an
        // inevitable failure. Refuse now, with the same error a direct send gives.
        let target = route
            .onion_target()
            .ok_or(MessageError::LocalRouteNotDeliverable)?;
        let queue = SendQueue::new(store);
        queue
            .enqueue(&conversation, target, epoch, &frame.encode(), expires_at)
            .map_err(MessageError::from)
    }

    /// Attempt to deliver every queued frame that is due.
    ///
    /// Frames are attempted oldest-first. A frame that fails for a transient reason
    /// stays queued with its attempt counter bumped; a frame whose backoff has not
    /// elapsed is skipped so a caller can poll this cheaply.
    ///
    /// Returns what happened, so the UI can say "3 waiting, 1 sent" rather than
    /// guessing.
    pub fn drain(
        &self,
        store: &Store,
        transport: &dyn AnonymityTransport,
        now: i64,
    ) -> Result<DrainReport> {
        let _guard = self.draining.lock().unwrap();
        let queue = SendQueue::new(store);
        let mut report = DrainReport::default();

        for queued in queue.pending()? {
            if queued.expires_at <= now {
                // The purge will remove it; counting it here keeps the report
                // honest in the window before the purge runs.
                report.expired += 1;
                continue;
            }

            if let Some(last) = queued.last_attempt_at {
                if now.saturating_sub(last) < RETRY_BACKOFF_SECONDS {
                    report.deferred += 1;
                    continue;
                }
            }

            match self.attempt(transport, &queued) {
                Ok(()) => {
                    queue.remove(&queued.id)?;
                    report.sent += 1;
                }
                Err(e) => {
                    queue.record_failure(&queued.id, &e.to_string())?;
                    report.failed += 1;
                }
            }
        }

        Ok(report)
    }

    /// Try one queued frame.
    fn attempt(&self, transport: &dyn AnonymityTransport, queued: &QueuedSend) -> Result<()> {
        let onion =
            anon_transport::OnionId::parse(&queued.route).map_err(MessageError::Transport)?;
        let route = PeerRoute::onion(onion);
        transport
            .send(&route, &queued.frame)
            .map_err(MessageError::Transport)
    }

    /// Number of frames waiting.
    pub fn pending_count(&self, store: &Store) -> Result<usize> {
        Ok(SendQueue::new(store).len()?)
    }

    /// Frames waiting for one conversation.
    pub fn pending_for(&self, store: &Store, conversation: &[u8]) -> Result<Vec<QueuedSend>> {
        Ok(SendQueue::new(store).pending_for(conversation)?)
    }
}

impl Default for SendQueueService {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a send failure is worth retrying later.
///
/// The distinction matters: a transient failure (peer offline, our circuit still
/// bootstrapping) should be queued, while a permanent one (a local route, an
/// oversized payload, a replay) should be reported to the user immediately.
pub fn is_retryable(error: &MessageError) -> bool {
    match error {
        // The peer is not reachable yet, or our own transport is not ready. Both
        // resolve on their own.
        MessageError::Transport(TransportError::NotReady) => true,
        MessageError::Transport(TransportError::Failed(_)) => true,
        MessageError::Transport(TransportError::PeerRejected(_)) => true,
        // A mailbox host refusing is a policy answer, not a transient failure: the
        // sender must surface it rather than retry blindly (`plan.md` §4.4).
        MessageError::MailboxRefused(_) => false,
        // Everything else is a caller bug or a permanent condition.
        _ => false,
    }
}

/// Build the report for a frame that was queued instead of sent.
pub fn queued_report(frame: &Frame) -> DeliveryReport {
    DeliveryReport {
        id: frame.id(),
        outcome: DeliveryOutcome::QueuedLocal,
        duplicate: false,
        bytes_sent: None,
    }
}
