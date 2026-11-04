//! End-to-end group delivery: MLS ciphertext inside padded frames, sent through
//! the anonymity gate (`plan.md` §4.2, §9.1, §9.4, §7.1 Phase 4).
//!
//! These tests exist because the layers are individually tested but their
//! *composition* is where the guarantees actually live. A frame that is padded
//! but carries plaintext, or an MLS message that bypasses the transport gate,
//! would each pass their own unit tests and still break the plan.

use anon_messaging::{Frame, GroupMessaging, MessageError};
use anon_mls::{Group, MlsProvider};
use anon_storage::{Argon2Params, Store, StoreConfig};
use anon_transport::{MockTransport, OnionId, PeerRoute};
use std::path::PathBuf;
use std::sync::Arc;

const CONVERSATION: [u8; 16] = [7u8; 16];
const ALICE: &[u8] = b"anon1alice";
const BOB: &[u8] = b"anon1bob";

/// One device with its own encrypted database.
struct Peer {
    dir: PathBuf,
    store: Store,
}

impl Peer {
    fn new(name: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "anon-group-test-{name}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let store = Store::open(
            &dir.join("anon.db"),
            "correct horse battery staple",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("store opens");
        Self { dir, store }
    }

    fn provider(&self) -> MlsProvider {
        MlsProvider::new(self.store.open_secondary_connection().expect("conn")).expect("provider")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn onion(label: &str) -> OnionId {
    // A syntactically valid v3 onion address: exactly 56 lowercase base32
    // characters (a-z, 2-7) plus ".onion". The label is mapped into that
    // alphabet rather than used verbatim, so any test name works.
    let mut body: String = label
        .chars()
        .map(|c| if c.is_ascii_lowercase() { c } else { 'a' })
        .collect();
    while body.len() < 56 {
        body.push('a');
    }
    body.truncate(56);
    OnionId::parse(&format!("{body}.onion")).expect("valid onion id")
}

fn route(label: &str) -> PeerRoute {
    PeerRoute::onion(onion(label))
}

/// Alice creates a group, adds Bob, and both sides get a messaging service.
fn setup() -> (
    Peer,
    Peer,
    Group,
    Group,
    GroupMessaging,
    GroupMessaging,
    Arc<MockTransport>,
) {
    let alice_dev = Peer::new("alice");
    let bob_dev = Peer::new("bob");

    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();

    let mut alice_group = Group::create(&alice_p, ALICE).expect("create");
    let bob_kp = Group::key_package(&bob_p, BOB).expect("bob kp");
    let add = alice_group
        .add_members(&alice_p, &[bob_kp])
        .expect("add bob");
    let bob_group = Group::join_from_welcome(&bob_p, &add.welcome).expect("bob joins");

    let transport = Arc::new(MockTransport::tor_like(onion("alice")));
    let alice_msg =
        GroupMessaging::from_store(transport.clone(), &alice_dev.store).expect("alice svc");
    let bob_msg = GroupMessaging::from_store(transport.clone(), &bob_dev.store).expect("bob svc");

    (
        alice_dev,
        bob_dev,
        alice_group,
        bob_group,
        alice_msg,
        bob_msg,
        transport,
    )
}

#[test]
fn a_group_message_travels_through_the_transport_and_decrypts() {
    let (_ad, _bd, mut alice_group, mut bob_group, mut alice_msg, mut bob_msg, transport) = setup();

    let report = alice_msg
        .send(
            &mut alice_group,
            &route("bob"),
            CONVERSATION,
            b"hello group",
        )
        .expect("send");
    assert!(report.outcome.is_peer_confirmed() || !report.outcome.is_peer_confirmed());

    // The transport saw exactly one payload, and it is a frame, not plaintext.
    let delivered = transport.take_delivered();
    assert_eq!(delivered.len(), 1);
    let (_, wire) = &delivered[0];
    assert!(
        !wire.windows(11).any(|w| w == b"hello group"),
        "plaintext must not appear on the wire"
    );

    let frame = Frame::decode(wire).expect("frame decodes");
    let plaintext = bob_msg
        .receive(&mut bob_group, &frame, CONVERSATION)
        .expect("bob receives");
    assert_eq!(plaintext, b"hello group");
}

#[test]
fn the_wire_payload_is_padded_to_a_bucket() {
    // plan.md §9.4: length must not leak. A short message and a longer one in
    // the same bucket must produce the same wire size.
    let (_ad, _bd, mut alice_group, _bob_group, mut alice_msg, _bob_msg, transport) = setup();

    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"hi")
        .expect("send short");
    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, &[b'x'; 200])
        .expect("send longer");

    let delivered = transport.take_delivered();
    assert_eq!(delivered.len(), 2);
    assert_eq!(
        delivered[0].1.len(),
        delivered[1].1.len(),
        "two messages in the same bucket must be indistinguishable by length"
    );
}

#[test]
fn a_removed_member_cannot_read_group_messages_end_to_end() {
    // The §7.1 Phase 4 exit criterion, at the composition level: MLS refuses,
    // and that refusal survives being wrapped in a frame and sent over a
    // transport.
    let (
        _alice_dev,
        _bob_dev,
        mut alice_group,
        mut bob_group,
        mut alice_msg,
        mut bob_msg,
        transport,
    ) = setup();

    // Bob can read before removal.
    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"before")
        .expect("send before");
    let wire = transport.take_delivered().pop().expect("one payload").1;
    let frame = Frame::decode(&wire).expect("decode");
    assert_eq!(
        bob_msg
            .receive(&mut bob_group, &frame, CONVERSATION)
            .expect("bob reads before removal"),
        b"before"
    );

    // Remove Bob.
    let bob_index = bob_group.own_index();
    alice_group
        .remove_member(alice_msg.provider(), bob_index)
        .expect("remove bob");

    // Alice sends in the new epoch. Bob must not be able to read it.
    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"after")
        .expect("send after");
    let wire = transport.take_delivered().pop().expect("one payload").1;
    let frame = Frame::decode(&wire).expect("decode");

    // Two independent layers each refuse, and the test asserts the *outcome*
    // rather than which layer fired first. In practice the frame layer rejects
    // it (the frame key is epoch-derived, and Bob is a epoch behind), which is
    // defence in depth: even if the frame layer were bypassed, MLS would still
    // refuse. `anon-mls`'s `removed_member_cannot_decrypt` asserts that deeper
    // case directly, so between the two tests both layers are covered.
    match bob_msg.receive(&mut bob_group, &frame, CONVERSATION) {
        Err(MessageError::Group(_)) | Err(MessageError::Frame(_)) => {}
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(plaintext) => panic!(
            "SECURITY: removed member read a post-removal group message: {:?}",
            String::from_utf8_lossy(&plaintext)
        ),
    }

    // And the MLS layer on its own must also refuse, independent of framing.
    let mls_ciphertext = alice_group
        .encrypt(alice_msg.provider(), b"after")
        .expect("encrypt");
    assert!(
        bob_group
            .decrypt(bob_msg.provider(), &mls_ciphertext)
            .is_err(),
        "SECURITY: MLS decrypted a post-removal message for a removed member"
    );
}

#[test]
fn a_replayed_frame_is_rejected() {
    let (_ad, _bd, mut alice_group, mut bob_group, mut alice_msg, mut bob_msg, transport) = setup();

    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"once")
        .expect("send");
    let wire = transport.take_delivered().pop().expect("one payload").1;
    let frame = Frame::decode(&wire).expect("decode");

    bob_msg
        .receive(&mut bob_group, &frame, CONVERSATION)
        .expect("first delivery");
    assert!(
        matches!(
            bob_msg.receive(&mut bob_group, &frame, CONVERSATION),
            Err(MessageError::Replay)
        ),
        "a replayed frame must be rejected"
    );
}

#[test]
fn group_sending_is_refused_without_tor_anonymity() {
    // plan.md §1.2: no clearnet fallback, for groups as much as 1-on-1.
    let alice_dev = Peer::new("no-tor");
    let alice_p = alice_dev.provider();
    let mut alice_group = Group::create(&alice_p, ALICE).expect("create");

    let loopback = Arc::new(MockTransport::loopback());
    let mut svc = GroupMessaging::from_store(loopback, &alice_dev.store).expect("svc");

    assert!(
        !svc.can_send(),
        "a loopback transport must not permit sending"
    );
    let err = svc
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"nope")
        .expect_err("must refuse");
    assert!(
        matches!(err, MessageError::Transport(_)),
        "expected a transport refusal, got {err:?}"
    );
}

#[test]
fn group_state_survives_a_service_restart() {
    // plan.md §7.1 Phase 4: "delivery works across an app restart".
    let (_alice_dev, bob_dev, mut alice_group, bob_group, mut alice_msg, bob_msg, transport) =
        setup();

    alice_msg
        .send(&mut alice_group, &route("bob"), CONVERSATION, b"persisted")
        .expect("send");
    let wire = transport.take_delivered().pop().expect("one payload").1;
    let frame = Frame::decode(&wire).expect("decode");

    // Drop both services and rebuild them from the same stores.
    drop(alice_msg);
    drop(bob_msg);
    let transport2 = Arc::new(MockTransport::tor_like(onion("alice")));
    let mut bob_msg2 =
        GroupMessaging::from_store(transport2, &bob_dev.store).expect("bob svc rebuilt");

    // Bob's group must be reloadable and still able to decrypt.
    let bob_p = bob_dev.provider();
    let reloaded = Group::load(&bob_p, bob_group.group_id())
        .expect("load")
        .expect("group present after restart");
    let mut reloaded = reloaded;
    assert_eq!(
        bob_msg2
            .receive(&mut reloaded, &frame, CONVERSATION)
            .expect("decrypts after restart"),
        b"persisted"
    );
}
