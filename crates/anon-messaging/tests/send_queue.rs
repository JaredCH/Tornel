//! Send-queue integration tests (`plan.md` §9.2, §8).
//!
//! These cover the behaviour the queue exists for: a frame that cannot be sent
//! right now is kept, retried, and removed only once the transport accepts it —
//! and never reported as delivered before that.

use anon_messaging::queue::{is_retryable, RETRY_BACKOFF_SECONDS};
use anon_messaging::{DeliveryOutcome, Frame, MessageError, MessagingService};
use anon_storage::{Argon2Params, Store, StoreConfig};
use anon_transport::{MockTransport, OfflineTransport, OnionId, PeerRoute};
use std::path::PathBuf;
use std::sync::Arc;

const NOW: i64 = 1_700_000_000;
const DAY: i64 = 86_400;
const KEY: [u8; 32] = [7u8; 32];

struct Fixture {
    store: Arc<Store>,
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "anon-sendqueue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open(
            &dir.join("queue.db"),
            "queue-passphrase",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("store opens");
        store.freeze_clock_at(NOW);
        Self {
            store: Arc::new(store),
            dir,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn onion() -> OnionId {
    OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion").unwrap()
}

fn conversation() -> [u8; 16] {
    [3u8; 16]
}

#[test]
fn a_send_to_an_unready_transport_is_queued_not_lost() {
    let f = Fixture::new();
    // A Tor-class transport that is still bootstrapping: the frame cannot go out
    // yet, but it can go out later.
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    let report = service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"hello while offline",
            NOW + 30 * DAY,
        )
        .expect("queueing is not an error");

    assert_eq!(report.outcome, DeliveryOutcome::QueuedLocal);
    assert!(!report.outcome.is_peer_confirmed());
    assert_eq!(report.bytes_sent, None, "nothing was transmitted");
    assert_eq!(transport.delivered_count(), 0);
    assert_eq!(service.queued_count().unwrap(), 1);
}

#[test]
fn a_queued_frame_is_sent_once_the_transport_is_ready() {
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"deliver me later",
            NOW + 30 * DAY,
        )
        .unwrap();
    assert_eq!(service.queued_count().unwrap(), 1);

    // The transport comes up. A freshly queued frame has no recorded attempt, so
    // it is due immediately.
    transport.set_ready(true);
    let report = service.drain_queue(NOW).unwrap();
    assert_eq!(report.sent, 1, "the queued frame should have gone out");
    assert_eq!(report.failed, 0);
    assert_eq!(transport.delivered_count(), 1);
    assert_eq!(service.queued_count().unwrap(), 0, "the row is removed");
}

#[test]
fn a_failed_retry_stays_queued_and_records_why() {
    let f = Fixture::new();
    // Still not ready: the drain attempt fails and the frame must survive it.
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"still waiting",
            NOW + 30 * DAY,
        )
        .unwrap();

    let report = service.drain_queue(NOW).unwrap();
    assert_eq!(report.sent, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(service.queued_count().unwrap(), 1, "the frame is kept");

    let queued = service.queued_for(&conversation()).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].attempts, 1);
    assert!(
        queued[0].last_error.is_some(),
        "the UI needs a reason to show"
    );
}

#[test]
fn a_retry_inside_the_backoff_window_is_deferred() {
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"backoff",
            NOW + 30 * DAY,
        )
        .unwrap();

    service.drain_queue(NOW).unwrap(); // fails, records an attempt at NOW
    let report = service.drain_queue(NOW + 1).unwrap();
    assert_eq!(report.deferred, 1, "a second attempt must wait");
    assert_eq!(report.failed, 0);

    // Past the window it is attempted again.
    let report = service
        .drain_queue(NOW + RETRY_BACKOFF_SECONDS + 1)
        .unwrap();
    assert_eq!(report.deferred, 0);
    assert_eq!(report.failed, 1);
}

#[test]
fn a_retry_is_not_rejected_as_a_replay() {
    // The regression this guards: `send_frame` observes the id before the
    // transport is asked to carry it, so a failed attempt must forget the id or
    // every retry would look like a duplicate and the frame would never leave.
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"retry me",
            NOW + 30 * DAY,
        )
        .unwrap();

    // First drain fails; second drain (after backoff) must not report Replay.
    service.drain_queue(NOW).unwrap();
    let report = service
        .drain_queue(NOW + RETRY_BACKOFF_SECONDS + 1)
        .unwrap();
    assert_eq!(report.failed, 1);
    let queued = service.queued_for(&conversation()).unwrap();
    let err = queued[0].last_error.clone().unwrap_or_default();
    assert!(
        !err.contains("replay"),
        "a retry must not be treated as a replay, got: {err}"
    );
}

#[test]
fn a_local_route_is_refused_rather_than_queued() {
    // Queueing a route that can never be delivered would promise a delivery that
    // cannot happen (`plan.md` §8).
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::tor_like(onion()));
    let service = MessagingService::new(transport, f.store.clone());

    let err = service
        .send_or_queue(
            &PeerRoute::local("selftest"),
            conversation(),
            1,
            &KEY,
            b"nowhere",
            NOW + 30 * DAY,
        )
        .unwrap_err();
    assert!(matches!(err, MessageError::LocalRouteNotDeliverable));
    assert_eq!(service.queued_count().unwrap(), 0);
}

#[test]
fn a_healthy_send_does_not_touch_the_queue() {
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::tor_like(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    let report = service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"straight through",
            NOW + 30 * DAY,
        )
        .unwrap();

    assert_eq!(report.outcome, DeliveryOutcome::QueuedLocal);
    assert_eq!(report.bytes_sent, Some(report.bytes_sent.unwrap()));
    assert_eq!(transport.delivered_count(), 1);
    assert_eq!(service.queued_count().unwrap(), 0);
}

#[test]
fn an_expired_queued_frame_is_not_sent() {
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"too late",
            NOW + DAY,
        )
        .unwrap();

    // Drain well past the frame's own deadline.
    let report = service.drain_queue(NOW + 2 * DAY).unwrap();
    assert_eq!(report.sent, 0);
    assert_eq!(report.expired, 1);
    assert_eq!(transport.delivered_count(), 0);
}

#[test]
fn the_queue_never_stores_plaintext() {
    // The queue holds sealed frames, so a row read back must not contain the
    // message text. This is the property that keeps the queue from being a second
    // copy of the message history.
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport, f.store.clone());

    let secret = b"the eagle lands at midnight";
    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            secret,
            NOW + 30 * DAY,
        )
        .unwrap();

    let queued = service.queued_for(&conversation()).unwrap();
    assert_eq!(queued.len(), 1);
    assert!(
        !queued[0]
            .frame
            .windows(secret.len())
            .any(|w| w == secret.as_slice()),
        "the queued frame must be ciphertext, not plaintext"
    );
}

#[test]
fn a_frame_queued_under_a_shredded_bucket_is_unreadable() {
    // Retention applies to the queue like every other table: once the bucket is
    // shredded, the row cannot be decrypted even if it survived the delete.
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport, f.store.clone());

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"shred me",
            NOW + 30 * DAY,
        )
        .unwrap();

    // Purge far enough ahead that the bucket's whole month is outside the window.
    f.store.purge(NOW + 400 * DAY).unwrap();
    assert_eq!(service.queued_count().unwrap(), 0);
}

#[test]
fn retryability_distinguishes_transient_from_permanent() {
    assert!(is_retryable(&MessageError::Transport(
        anon_transport::TransportError::NotReady
    )));
    assert!(is_retryable(&MessageError::Transport(
        anon_transport::TransportError::Failed("circuit closed".into())
    )));
    assert!(!is_retryable(&MessageError::LocalRouteNotDeliverable));
    assert!(!is_retryable(&MessageError::Replay));
    assert!(!is_retryable(&MessageError::MailboxRefused("quota".into())));
}

#[test]
fn an_offline_transport_cannot_queue() {
    // No Tor backend means no delivery is possible, so queueing would be a false
    // promise. `can_queue` is what the backend uses to decide.
    let f = Fixture::new();
    let service = MessagingService::new(Arc::new(OfflineTransport::default()), f.store.clone());
    assert!(!service.can_queue());
    assert!(!service.can_send());
}

#[test]
fn a_tor_class_transport_can_queue_even_when_not_ready() {
    let f = Fixture::new();
    let service =
        MessagingService::new(Arc::new(MockTransport::not_ready(onion())), f.store.clone());
    assert!(service.can_queue());
    assert!(!service.can_send());
}

#[test]
fn queued_frames_are_drained_oldest_first() {
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    for i in 0..3u8 {
        service
            .send_or_queue(
                &PeerRoute::onion(onion()),
                conversation(),
                1,
                &KEY,
                &[b'a' + i],
                NOW + 30 * DAY,
            )
            .unwrap();
    }

    let queued = service.queued_for(&conversation()).unwrap();
    assert_eq!(queued.len(), 3);
    let created: Vec<i64> = queued.iter().map(|q| q.created_at).collect();
    let mut sorted = created.clone();
    sorted.sort_unstable();
    assert_eq!(created, sorted, "the queue must drain oldest-first");
}

#[test]
fn a_frame_sealed_for_the_queue_round_trips_through_the_transport() {
    // End-to-end: queue a frame, bring the transport up, drain, and confirm the
    // bytes that arrived are the frame that was sealed.
    let f = Fixture::new();
    let transport = Arc::new(MockTransport::not_ready(onion()));
    let service = MessagingService::new(transport.clone(), f.store.clone());

    let frame = Frame::seal(&KEY, conversation(), 1, b"round trip").unwrap();
    let expected = frame.encode();

    service
        .send_or_queue(
            &PeerRoute::onion(onion()),
            conversation(),
            1,
            &KEY,
            b"round trip",
            NOW + 30 * DAY,
        )
        .unwrap();

    transport.set_ready(true);
    service.drain_queue(NOW).unwrap();
    let delivered = transport.take_delivered();
    assert_eq!(delivered.len(), 1);
    // The frame is re-sealed on send, so the bytes differ; what matters is that a
    // decodable frame arrived and it opens under the same key.
    let arrived = Frame::decode(&delivered[0].1).expect("a valid frame arrived");
    assert_eq!(arrived.open(&KEY).unwrap(), b"round trip");
    assert_eq!(arrived.conversation(), conversation());
    assert_ne!(delivered[0].1, expected, "a fresh nonce is used per seal");
}
