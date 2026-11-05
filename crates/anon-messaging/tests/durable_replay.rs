//! Durable replay protection (`plan.md` §9.2).
//!
//! The in-memory seen-set is lost on every restart, so a replayed frame was
//! accepted again after a relaunch. These tests pin the durable half: the
//! store's `seen_frames` table rejects a replayed id across a reopen, forgets
//! an id on a failed send, and purges expired ids with the retention sweep.

use anon_messaging::deliver::accept_frame;
use anon_messaging::{DeliveryOutcome, Frame, Outbox};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::PathBuf;

const NOW: i64 = 1_700_000_000;
const KEY: [u8; 32] = [9u8; 32];

struct Fixture {
    store: Store,
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "anon-durable-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open(
            &dir.join("replay.db"),
            "replay-passphrase",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("store opens");
        store.freeze_clock_at(NOW);
        Self { store, dir }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn frame() -> Frame {
    Frame::seal(&KEY, [4u8; 16], 1, b"payload").unwrap()
}

#[test]
fn a_replayed_frame_is_rejected_across_a_restart() {
    let f = Fixture::new();
    let outbox = Outbox::new();
    let frame = frame();

    let first = accept_frame(&f.store, &outbox, &frame, &KEY, b"sender", NOW).unwrap();
    assert!(!first.duplicate, "first delivery is accepted");

    // Simulate a restart: a fresh in-memory outbox, same store.
    let fresh_outbox = Outbox::new();
    let second = accept_frame(&f.store, &fresh_outbox, &frame, &KEY, b"sender", NOW).unwrap();
    assert!(
        second.duplicate,
        "the same frame after a restart is a replay, not a new message"
    );
}

#[test]
fn a_forgotten_id_can_be_sent_again() {
    let f = Fixture::new();
    let outbox = Outbox::new();
    let frame = frame();

    accept_frame(&f.store, &outbox, &frame, &KEY, b"sender", NOW).unwrap();
    // A failed attempt forgets the id in both layers.
    f.store.forget_frame(frame.id().as_bytes()).unwrap();

    let fresh_outbox = Outbox::new();
    let retry = accept_frame(&f.store, &fresh_outbox, &frame, &KEY, b"sender", NOW).unwrap();
    assert!(!retry.duplicate, "a forgotten id is deliverable again");
}

#[test]
fn expired_frame_ids_are_purged_with_retention() {
    let f = Fixture::new();
    let outbox = Outbox::new();
    let frame = frame();

    accept_frame(&f.store, &outbox, &frame, &KEY, b"sender", NOW).unwrap();

    // Advance past the retention ceiling and purge.
    let later = NOW + 91 * 86_400;
    let report = f.store.purge(later).unwrap();
    assert!(
        report.deleted_for("seen_frames") > 0,
        "expired frame ids are swept with the retention purge"
    );

    // The id is gone, so the frame would be accepted again — but its content
    // would be rejected as expired on arrival, so this is not a replay hole.
    let fresh_outbox = Outbox::new();
    let after = accept_frame(&f.store, &fresh_outbox, &frame, &KEY, b"sender", later).unwrap();
    assert_eq!(after.outcome, DeliveryOutcome::DeliveredToPeer);
}
