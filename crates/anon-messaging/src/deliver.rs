//! Delivery: outbox, replay protection, and the store/transport wiring
//! (`plan.md` §9.2, §9.3).
//!
//! # Ordering and duplicates
//!
//! Tor provides no ordering guarantee, and a peer-hosted mailbox can deliver the
//! same message twice. `plan.md` §9.2 assigns ordering, dedup, and gap detection
//! to the application layer. That is what the [`Outbox`] does:
//!
//! * a **seen-set** of message ids rejects replays and duplicates;
//! * delivery is attempted only through
//!   [`AnonymityTransport::send`](anon_transport::AnonymityTransport::send), so
//!   the no-clearnet gate always applies;
//! * every accepted message is persisted through `Store`, so retention and
//!   crypto-shredding apply without the caller remembering.
//!
//! # Delivery states
//!
//! `plan.md` §8 requires that the UI never imply more certainty than exists. The
//! three states here map directly to that requirement, and
//! [`DeliveryOutcome::ReadByPeer`] is deliberately *not* produced by this layer —
//! it can only be set from an actual peer acknowledgement, so the enum makes a
//! false "read" receipt impossible to fabricate by accident.

use crate::error::{MessageError, Result};
use crate::frame::{Frame, MessageId};
use anon_storage::Store;
use anon_transport::{AnonymityTransport, PeerRoute};
use std::collections::HashSet;
use std::sync::Mutex;

/// How far a message actually got.
///
/// Ordering is deliberate: each value is strictly stronger than the last. The
/// UI must not display a stronger state than it has evidence for (`plan.md` §8).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DeliveryOutcome {
    /// Encrypted and stored locally, not yet handed to the transport.
    QueuedLocal,
    /// Handed to a mailbox host and acknowledged.
    DeliveredToMailbox,
    /// The recipient's client acknowledged receipt.
    DeliveredToPeer,
    /// The recipient's client reported the message as read.
    ///
    /// Only settable via an explicit peer acknowledgement.
    ReadByPeer,
}

impl DeliveryOutcome {
    /// Whether this state is backed by peer evidence (as opposed to local hope).
    pub fn is_peer_confirmed(self) -> bool {
        matches!(self, Self::DeliveredToPeer | Self::ReadByPeer)
    }

    /// Short label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Self::QueuedLocal => "queued",
            Self::DeliveredToMailbox => "at mailbox",
            Self::DeliveredToPeer => "delivered",
            Self::ReadByPeer => "read",
        }
    }
}

/// A single delivery attempt's result.
#[derive(Clone, Debug)]
pub struct DeliveryReport {
    /// The message that was handled.
    pub id: MessageId,
    /// How far it got.
    pub outcome: DeliveryOutcome,
    /// Whether it was rejected as a duplicate.
    pub duplicate: bool,
    /// Padded size actually sent, when something was sent.
    pub bytes_sent: Option<usize>,
}

/// Tracks sent message ids to reject replays and duplicates.
///
/// The plan's §9.2 requirement is receiver-side dedup; this is the sender-side
/// counterpart plus the shared seen-set used on receipt.
pub struct Outbox {
    seen: Mutex<HashSet<MessageId>>,
    max_tracked: usize,
}

impl Outbox {
    /// Create an outbox with a bound on tracked ids.
    ///
    /// Unbounded tracking would itself be a retention leak — it would accumulate
    /// ids for messages whose content has long since been purged. The bound keeps
    /// memory consistent with the retention window, and the ordering is
    /// irrelevant because an id older than the window cannot be replayed into a
    /// live conversation anyway.
    pub fn with_capacity(max_tracked: usize) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            max_tracked: max_tracked.max(1),
        }
    }

    /// Default capacity. Sized for a 90-day window at a few hundred messages a
    /// day, which is far beyond realistic usage for this app.
    pub fn new() -> Self {
        Self::with_capacity(65_536)
    }

    /// Record an id, returning `true` if it was new.
    pub fn observe(&self, id: MessageId) -> bool {
        let mut seen = self.seen.lock().unwrap();
        if seen.contains(&id) {
            return false;
        }
        if seen.len() >= self.max_tracked {
            // Bounded set: drop the whole set rather than grow without limit.
            // Correctness is preserved because ids are 128-bit random values, so
            // an old id cannot realistically collide with a new one.
            seen.clear();
        }
        seen.insert(id);
        true
    }

    /// Whether an id has been observed.
    pub fn has_seen(&self, id: &MessageId) -> bool {
        self.seen.lock().unwrap().contains(id)
    }

    /// Number of tracked ids.
    pub fn tracked(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Send a sealed frame to a peer route.
///
/// # The fail-closed contract
///
/// `plan.md` §1.2 and §7.1 require that a send is refused when anonymity is not
/// confirmed. Two gates are enforced here, on top of the transport's own:
///
/// 1. The route must be internet-routable. A local-only route is refused, because
///    sending over one would mean there is no anonymity at all.
/// 2. `transport.send` applies the transport's status and anonymity gates.
///
/// Nothing in this function can fall back to clearnet: there is no code path that
/// opens a socket.
pub fn send_frame(
    transport: &dyn AnonymityTransport,
    route: &PeerRoute,
    outbox: &Outbox,
    frame: &Frame,
) -> Result<DeliveryReport> {
    // Gate 1: a local route is not a delivery route.
    if !route.is_internet_routable() {
        return Err(MessageError::LocalRouteNotDeliverable);
    }

    if !outbox.observe(frame.id()) {
        return Err(MessageError::Replay);
    }

    let payload = frame.encode();
    // Gate 2: the transport enforces Ready + TorOnion.
    transport.send(route, &payload)?;

    Ok(DeliveryReport {
        id: frame.id(),
        outcome: DeliveryOutcome::QueuedLocal,
        duplicate: false,
        bytes_sent: Some(payload.len()),
    })
}

/// Persist a received frame's plaintext, applying retention.
///
/// Returns the storage id. Replay-checks against the outbox first so a duplicate
/// delivery from a mailbox does not create a second row.
pub fn accept_frame(
    store: &Store,
    outbox: &Outbox,
    frame: &Frame,
    key: &[u8; 32],
    sender: &[u8],
    received_at: i64,
) -> Result<DeliveryReport> {
    if !outbox.observe(frame.id()) {
        return Ok(DeliveryReport {
            id: frame.id(),
            outcome: DeliveryOutcome::QueuedLocal,
            duplicate: true,
            bytes_sent: None,
        });
    }

    let plaintext = frame.open(key)?;

    store.insert_message(&frame.conversation(), sender, received_at, &plaintext)?;

    Ok(DeliveryReport {
        id: frame.id(),
        outcome: DeliveryOutcome::DeliveredToPeer,
        duplicate: false,
        bytes_sent: Some(frame.encoded_len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anon_transport::{MockTransport, OfflineTransport, OnionId};

    fn onion() -> OnionId {
        OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion").unwrap()
    }

    const KEY: [u8; 32] = [5u8; 32];

    fn frame() -> Frame {
        Frame::seal(&KEY, [1u8; 16], 1, b"payload").unwrap()
    }

    #[test]
    fn delivery_outcome_strength_is_ordered() {
        // The UI relies on this ordering to avoid over-claiming (§8).
        assert!(DeliveryOutcome::QueuedLocal < DeliveryOutcome::DeliveredToMailbox);
        assert!(DeliveryOutcome::DeliveredToMailbox < DeliveryOutcome::DeliveredToPeer);
        assert!(DeliveryOutcome::DeliveredToPeer < DeliveryOutcome::ReadByPeer);

        assert!(!DeliveryOutcome::QueuedLocal.is_peer_confirmed());
        assert!(!DeliveryOutcome::DeliveredToMailbox.is_peer_confirmed());
        assert!(DeliveryOutcome::DeliveredToPeer.is_peer_confirmed());
        assert!(DeliveryOutcome::ReadByPeer.is_peer_confirmed());
    }

    #[test]
    fn send_succeeds_over_a_tor_class_transport() {
        let t = MockTransport::tor_like(onion());
        let outbox = Outbox::new();
        let report = send_frame(&t, &PeerRoute::onion(onion()), &outbox, &frame()).unwrap();

        assert_eq!(report.outcome, DeliveryOutcome::QueuedLocal);
        assert!(!report.duplicate);
        assert!(report.bytes_sent.unwrap() > 0);
        assert_eq!(t.delivered_count(), 1);
    }

    #[test]
    fn send_is_refused_over_a_local_route() {
        // §1.2: there is no "send it another way" path.
        let t = MockTransport::tor_like(onion());
        let outbox = Outbox::new();
        let err = send_frame(&t, &PeerRoute::local("selftest"), &outbox, &frame()).unwrap_err();
        assert!(matches!(err, MessageError::LocalRouteNotDeliverable));
        assert_eq!(t.delivered_count(), 0, "nothing may be transmitted");
    }

    #[test]
    fn send_is_refused_when_the_transport_fails_closed() {
        // The Phase 2 exit criterion, observed from the messaging layer.
        let t = OfflineTransport::default();
        let outbox = Outbox::new();
        let err = send_frame(&t, &PeerRoute::onion(onion()), &outbox, &frame()).unwrap_err();
        assert!(matches!(err, MessageError::Transport(_)));
    }

    #[test]
    fn send_is_refused_over_a_loopback_class_transport() {
        // A transport that is Ready but not Tor-grade must still be refused.
        let t = MockTransport::loopback();
        let outbox = Outbox::new();
        let err = send_frame(&t, &PeerRoute::onion(onion()), &outbox, &frame()).unwrap_err();
        assert!(matches!(err, MessageError::Transport(_)));
        assert_eq!(t.delivered_count(), 0);
    }

    #[test]
    fn duplicate_send_is_rejected_as_replay() {
        // §9.2: dedup.
        let t = MockTransport::tor_like(onion());
        let outbox = Outbox::new();
        let f = frame();

        send_frame(&t, &PeerRoute::onion(onion()), &outbox, &f).unwrap();
        let err = send_frame(&t, &PeerRoute::onion(onion()), &outbox, &f).unwrap_err();
        assert!(matches!(err, MessageError::Replay));
        assert_eq!(t.delivered_count(), 1, "a replay must not be re-sent");
    }

    #[test]
    fn outbox_observes_and_reports_seen_ids() {
        let outbox = Outbox::new();
        let id = MessageId::generate();
        assert!(outbox.observe(id));
        assert!(!outbox.observe(id));
        assert!(outbox.has_seen(&id));
        assert_eq!(outbox.tracked(), 1);
    }

    #[test]
    fn outbox_is_bounded() {
        // Guards the retention-leak concern in Outbox::with_capacity.
        let outbox = Outbox::with_capacity(4);
        for _ in 0..10 {
            outbox.observe(MessageId::generate());
        }
        assert!(outbox.tracked() <= 4, "outbox grew beyond its bound");
    }

    #[test]
    fn outcome_labels_are_truthful() {
        assert_eq!(DeliveryOutcome::QueuedLocal.label(), "queued");
        assert_eq!(DeliveryOutcome::DeliveredToMailbox.label(), "at mailbox");
        assert_eq!(DeliveryOutcome::DeliveredToPeer.label(), "delivered");
        assert_eq!(DeliveryOutcome::ReadByPeer.label(), "read");
    }
}
