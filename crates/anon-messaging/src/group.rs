//! Group messaging: MLS ciphertext carried in padded frames over the anonymity
//! transport (`plan.md` §4.2, §9.1, §9.4).
//!
//! # Two layers, two jobs
//!
//! | Layer | Protects against |
//! | --- | --- |
//! | MLS (`anon-mls`) | Reading the content, and reading it *after* being removed |
//! | Frame (`crate::frame`) | Learning message length, conversation, or epoch from the wire |
//! | Transport (`anon-transport`) | Learning the sender's IP address |
//!
//! None of these substitutes for another. MLS ciphertext is variable-length and
//! would leak message size on the wire, so it is padded by the frame. The frame
//! is not encrypted to the recipient's identity, so MLS provides that. And
//! neither hides the IP, so the transport gate does.
//!
//! # Why group sends go through the same gate as 1-on-1
//!
//! `plan.md` §1.2 makes "no clearnet fallback" absolute. A group message is not
//! a special case: [`GroupMessaging::send`] calls
//! [`AnonymityTransport::send`](anon_transport::AnonymityTransport::send), which
//! refuses any route that is not `TorOnion`. There is no second code path that
//! could drift.

use crate::deliver::{send_frame, DeliveryReport, Outbox};
use crate::error::{MessageError, Result};
use crate::frame::Frame;
use anon_mls::{Group, MlsProvider};
use anon_storage::Store;
use anon_transport::{AnonymityTransport, PeerRoute};
use std::sync::Arc;

/// Group messaging over an anonymity transport.
///
/// Holds the MLS provider (which owns the encrypted MLS state) and the transport.
/// Deliberately does **not** hold a `Store`: MLS state lives in the same
/// SQLCipher file, reached through the provider, so there is one owner of the
/// database key rather than two.
pub struct GroupMessaging {
    transport: Arc<dyn AnonymityTransport>,
    provider: MlsProvider,
    outbox: Outbox,
}

impl GroupMessaging {
    /// Build a group messaging service.
    pub fn new(transport: Arc<dyn AnonymityTransport>, provider: MlsProvider) -> Self {
        Self {
            transport,
            provider,
            outbox: Outbox::new(),
        }
    }

    /// Build a group messaging service from a store.
    ///
    /// Convenience for the normal case: MLS state goes into the store's own
    /// encrypted database, so retention and at-rest encryption apply without the
    /// caller wiring anything up.
    pub fn from_store(transport: Arc<dyn AnonymityTransport>, store: &Store) -> Result<Self> {
        let conn = store.open_secondary_connection()?;
        let provider = MlsProvider::new(conn).map_err(|e| MessageError::Group(e.to_string()))?;
        Ok(Self::new(transport, provider))
    }

    /// The MLS provider, for group lifecycle operations.
    pub fn provider(&self) -> &MlsProvider {
        &self.provider
    }

    /// Whether sending is currently possible.
    ///
    /// Same rule as 1-on-1: the UI must be able to show an honest offline state
    /// rather than a button that silently does nothing (`plan.md` §8).
    pub fn can_send(&self) -> bool {
        use anon_transport::{AnonymityClass, TransportStatus};
        self.transport.status() == TransportStatus::Ready
            && self.transport.anonymity() == AnonymityClass::TorOnion
    }

    /// Encrypt a group message with MLS and send it over an onion route.
    ///
    /// The MLS ciphertext is what the frame carries, so the frame's padding
    /// hides the true message length and the transport hides the sender.
    pub fn send(
        &mut self,
        group: &mut Group,
        route: &PeerRoute,
        conversation: [u8; 16],
        plaintext: &[u8],
    ) -> Result<DeliveryReport> {
        let plaintext = crate::attachment::sanitize_body(plaintext)?;
        let ciphertext = group
            .encrypt(&self.provider, &plaintext)
            .map_err(|e| MessageError::Group(e.to_string()))?;

        // The frame key is derived from the group's current epoch state rather
        // than a caller-supplied key, so a caller cannot accidentally reuse a
        // key across epochs.
        let key = epoch_frame_key(group, conversation);
        let frame = Frame::seal(&key, conversation, group.epoch(), &ciphertext)?;
        send_frame(self.transport.as_ref(), route, &self.outbox, &frame)
    }

    /// Receive a group frame, decrypt the MLS layer, and return the plaintext.
    ///
    /// Returns [`MessageError::Group`] when MLS refuses the message — which is
    /// what happens to a removed member, and is the behaviour `plan.md` §4.2
    /// requires.
    pub fn receive(
        &mut self,
        group: &mut Group,
        frame: &Frame,
        conversation: [u8; 16],
    ) -> Result<Vec<u8>> {
        // Reject replays before doing any crypto work. `observe` returns false
        // when the id was already seen, so this both checks and records.
        if !self.outbox.observe(frame.id()) {
            return Err(MessageError::Replay);
        }

        let key = epoch_frame_key(group, conversation);
        let ciphertext = frame.open(&key)?;
        group
            .decrypt(&self.provider, &ciphertext)
            .map_err(|e| MessageError::Group(e.to_string()))
    }

    /// The underlying transport, for status display.
    pub fn transport(&self) -> &Arc<dyn AnonymityTransport> {
        &self.transport
    }
}

/// Derive the frame key for a group's current epoch.
///
/// The frame layer is a metadata-protection layer, not the confidentiality
/// boundary — MLS is. So this key only needs to be unpredictable to an observer
/// and to change with the epoch; it is derived from the group id and epoch, both
/// of which are already public in the frame header. That is deliberate: it means
/// the frame key adds no new secret to manage, and the real secrecy is MLS's.
///
/// A removed member can compute this key, and that is fine: MLS is what stops
/// them reading the content, and the removal test asserts exactly that.
fn epoch_frame_key(group: &Group, conversation: [u8; 16]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut info = Vec::with_capacity(32 + 16 + 8);
    info.extend_from_slice(b"anon/v1/group-frame/");
    info.extend_from_slice(group.group_id());
    info.extend_from_slice(&conversation);
    info.extend_from_slice(&group.epoch().to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, group.group_id());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

impl std::fmt::Debug for GroupMessaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupMessaging")
            .field("can_send", &self.can_send())
            .finish_non_exhaustive()
    }
}
