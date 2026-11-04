//! The messaging service facade (`plan.md` §7.3).
//!
//! Wires a transport and a store together and exposes the operations the UI
//! needs. Deliberately the only place messaging, storage, and transport meet, so
//! the boundaries stay visible.

use crate::deliver::{accept_frame, send_frame, DeliveryReport, Outbox};
use crate::error::Result;
use crate::frame::Frame;
use anon_storage::Store;
use anon_transport::{AnonymityTransport, PeerRoute};
use std::sync::Arc;

/// A ready-to-use messaging service.
pub struct MessagingService {
    transport: Arc<dyn AnonymityTransport>,
    store: Arc<Store>,
    outbox: Outbox,
}

impl MessagingService {
    /// Build a service over a transport and store.
    pub fn new(transport: Arc<dyn AnonymityTransport>, store: Arc<Store>) -> Self {
        Self {
            transport,
            store,
            outbox: Outbox::new(),
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
