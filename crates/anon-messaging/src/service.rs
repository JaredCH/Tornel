//! The messaging service facade (`plan.md` §7.3).
//!
//! Wires a transport and a store together and exposes the operations the UI
//! needs. Deliberately the only place messaging, storage, and transport meet, so
//! the boundaries stay visible.

use crate::deliver::{accept_frame, send_frame, DeliveryReport, Outbox};
use crate::error::Result;
use crate::frame::Frame;
use crate::queue::{is_retryable, queued_report, DrainReport, SendQueueService};
use anon_storage::Store;
use anon_transport::{AnonymityTransport, PeerRoute};
use std::sync::Arc;

/// A ready-to-use messaging service.
pub struct MessagingService {
    transport: Arc<dyn AnonymityTransport>,
    store: Arc<Store>,
    outbox: Outbox,
    queue: SendQueueService,
}

impl MessagingService {
    /// Build a service over a transport and store.
    pub fn new(transport: Arc<dyn AnonymityTransport>, store: Arc<Store>) -> Self {
        Self {
            transport,
            store,
            outbox: Outbox::new(),
            queue: SendQueueService::new(),
        }
    }

    /// Whether sending is currently possible.
    ///
    /// Exposed so the UI can render an honest offline state rather than a
    /// disabled-looking button with no explanation (`plan.md` §3.4, §8).
    pub fn can_send(&self) -> bool {
        use anon_transport::{AnonymityClass, TransportStatus};
        self.transport.status() == TransportStatus::Ready
            && self.transport.anonymity() == AnonymityClass::TorOnion
    }

    /// Whether a frame that cannot be sent right now is worth queueing.
    ///
    /// True when the transport is Tor-class but not currently ready: the frame
    /// will go out once the circuit is up or the peer's onion service publishes.
    /// False when there is no Tor transport at all — queueing then would promise a
    /// delivery that can never happen, which is exactly the false certainty
    /// `plan.md` §8 forbids.
    pub fn can_queue(&self) -> bool {
        use anon_transport::AnonymityClass;
        self.transport.anonymity() == AnonymityClass::TorOnion
    }

    /// A human-readable reason sending is unavailable, when it is.
    pub fn send_unavailable_reason(&self) -> Option<String> {
        use anon_transport::{AnonymityClass, TransportStatus};
        match self.transport.status() {
            TransportStatus::Ready => {}
            TransportStatus::Idle => return Some("Transport not started.".to_string()),
            TransportStatus::Bootstrapping => return Some("Connecting to Tor…".to_string()),
            TransportStatus::Failed => {
                return Some(
                    self.transport
                        .failure_reason()
                        .unwrap_or_else(|| "Transport failed.".to_string()),
                )
            }
        }
        if self.transport.anonymity() != AnonymityClass::TorOnion {
            return Some(
                "Anonymity unavailable — this build has no Tor transport, so sending is \
                 disabled rather than sent unprotected."
                    .to_string(),
            );
        }
        None
    }

    /// Encrypt and send a message over an onion route.
    ///
    /// Refuses (never silently degrades) when transport anonymity is unavailable.
    pub fn send(
        &self,
        route: &PeerRoute,
        conversation: [u8; 16],
        epoch: u64,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<DeliveryReport> {
        let plaintext = crate::attachment::sanitize_body(plaintext)?;
        let frame = Frame::seal(key, conversation, epoch, &plaintext)?;
        send_frame(self.transport.as_ref(), route, &self.outbox, &frame)
    }

    /// Encrypt and send, falling back to the durable queue when the peer is
    /// unreachable.
    ///
    /// This is the operation the UI should call. A transient failure (peer
    /// offline, our circuit still bootstrapping) is not an error the user can act
    /// on — it is a message that has not gone out yet. Those are queued and
    /// reported as [`DeliveryOutcome::QueuedLocal`], which the UI renders as
    /// "queued" rather than "delivered" (`plan.md` §8).
    ///
    /// A permanent failure (local route, oversized payload, replay) is returned as
    /// an error, because queueing it would only defer an identical failure.
    ///
    /// `expires_at` is the message's retention deadline; a queued frame is never
    /// kept past it.
    pub fn send_or_queue(
        &self,
        route: &PeerRoute,
        conversation: [u8; 16],
        epoch: u64,
        key: &[u8; 32],
        plaintext: &[u8],
        expires_at: i64,
    ) -> Result<DeliveryReport> {
        let plaintext = crate::attachment::sanitize_body(plaintext)?;
        let frame = Frame::seal(key, conversation, epoch, &plaintext)?;

        match send_frame(self.transport.as_ref(), route, &self.outbox, &frame) {
            Ok(report) => Ok(report),
            Err(e) if is_retryable(&e) => {
                self.queue
                    .enqueue(&self.store, route, conversation, epoch, &frame, expires_at)?;
                Ok(queued_report(&frame))
            }
            Err(e) => Err(e),
        }
    }

    /// Retry every queued frame that is due.
    ///
    /// Safe to call on a timer: frames whose backoff has not elapsed are skipped,
    /// and a pass is serialized so the same frame cannot be sent twice.
    pub fn drain_queue(&self, now: i64) -> Result<DrainReport> {
        self.queue.drain(&self.store, self.transport.as_ref(), now)
    }

    /// How many frames are waiting to go out.
    pub fn queued_count(&self) -> Result<usize> {
        self.queue.pending_count(&self.store)
    }

    /// Queued frames for one conversation, oldest first.
    pub fn queued_for(&self, conversation: &[u8]) -> Result<Vec<anon_storage::QueuedSend>> {
        self.queue.pending_for(&self.store, conversation)
    }

    /// Receive a frame, decrypt it, and persist it under the retention policy.
    pub fn receive(
        &self,
        frame: &Frame,
        key: &[u8; 32],
        sender: &[u8],
        received_at: i64,
    ) -> Result<DeliveryReport> {
        accept_frame(&self.store, &self.outbox, frame, key, sender, received_at)
    }

    /// The underlying transport, for status display.
    pub fn transport(&self) -> &Arc<dyn AnonymityTransport> {
        &self.transport
    }

    /// The underlying store.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The outbox / replay tracker.
    pub fn outbox(&self) -> &Outbox {
        &self.outbox
    }
}

impl std::fmt::Debug for MessagingService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagingService")
            .field("can_send", &self.can_send())
            .finish_non_exhaustive()
    }
}
