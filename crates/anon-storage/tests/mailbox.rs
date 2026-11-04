//! Peer-hosted mailbox tests (`plan.md` §4.4).
//!
//! The properties under test are the ones §4.4 calls out as the reason a
//! peer-hosted mailbox is tolerable at all:
//!
//! * a hostile peer cannot fill the host's disk (quota enforcement);
//! * buffered content cannot outlive the retention ceiling (host-side TTL);
//! * the host cannot read what it stores (opaque blobs);
//! * a receipt is never mistaken for delivery.

use anon_storage::mailbox::{Mailbox, MailboxPolicy, MailboxRejection};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::PathBuf;

const DAY: i64 = 86_400;

/// A store in a unique temp directory, with a frozen clock.
struct Fixture {
    store: Store,
    dir: PathBuf,
}

impl Fixture {
    fn new(now: i64) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "anon-mailbox-{}-{}",
            std::process::id(),
            // Distinguish concurrent tests within one process.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mailbox.db");

        let mut store = Store::open(
            &path,
            "correct horse battery staple",
            StoreConfig {
                params: Argon2Params::test_fast(),
                // Purge explicitly in these tests so the clock is unambiguous.
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("store opens");
        store.freeze_clock_at(now);

        Self { store, dir }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn recipient() -> Vec<u8> {
    b"recipient-onion-address-bytes".to_vec()
}

fn sender(n: u8) -> Vec<u8> {
    vec![n; 32]
}

#[test]
fn a_blob_round_trips_and_is_readable_by_its_recipient() {
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let payload = b"mls ciphertext, opaque to the host";
    let receipt = mailbox
        .enqueue(&recipient(), &sender(1), payload, now + 30 * DAY)
        .expect("accepted");

    assert_eq!(receipt.received_at, now);
    assert_eq!(receipt.expires_at, now + 30 * DAY);

    let blobs = mailbox.read(&recipient()).expect("read");
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].ciphertext, payload);
    assert_eq!(blobs[0].sender, sender(1));
    assert_eq!(blobs[0].id, receipt.id);
}

#[test]
fn a_receipt_is_never_a_delivery_confirmation() {
    // plan.md §8: no false "delivered" state. A mailbox receipt means the host
    // holds the blob, nothing more.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let receipt = mailbox
        .enqueue(&recipient(), &sender(1), b"x", now + DAY)
        .unwrap();
    assert!(!receipt.is_delivery());
}

#[test]
fn the_host_stores_ciphertext_it_cannot_read() {
    // The bytes on disk must not equal the bytes that arrived: the host
    // re-encrypts under its own bucket key. This is defence in depth — the real
    // confidentiality boundary is MLS — but it must hold.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let payload = b"PLAINTEXT-MARKER-do-not-store-verbatim";
    mailbox
        .enqueue(&recipient(), &sender(1), payload, now + DAY)
        .unwrap();

    // Read the raw file and confirm the marker is absent.
    let raw = std::fs::read(fx.store.path()).expect("db file readable");
    let needle = b"PLAINTEXT-MARKER-do-not-store-verbatim";
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "plaintext marker found in the database file"
    );
}

#[test]
fn a_sender_cannot_exceed_its_byte_quota() {
    // plan.md §4.4 "Abuse": a hostile peer must not be able to fill the disk.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1024,
        max_messages_per_sender: 100,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    // Fill the quota exactly.
    mailbox
        .enqueue(&recipient(), &sender(1), &[0u8; 1024], now + DAY)
        .expect("first blob fits exactly");

    // One more byte must be refused, and must consume nothing.
    let err = mailbox
        .enqueue(&recipient(), &sender(1), b"x", now + DAY)
        .unwrap_err();
    assert!(matches!(
        err,
        MailboxRejection::SenderByteQuota {
            held: 1024,
            limit: 1024
        }
    ));

    // The refusal must not have written anything.
    let (bytes, count) = mailbox.usage(&recipient(), Some(&sender(1))).unwrap();
    assert_eq!((bytes, count), (1024, 1));
}

#[test]
fn a_sender_cannot_exceed_its_message_count_quota() {
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1_000_000,
        max_messages_per_sender: 3,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    for _ in 0..3 {
        mailbox
            .enqueue(&recipient(), &sender(1), b"tiny", now + DAY)
            .expect("within count quota");
    }
    let err = mailbox
        .enqueue(&recipient(), &sender(1), b"tiny", now + DAY)
        .unwrap_err();
    assert!(matches!(
        err,
        MailboxRejection::SenderCountQuota { held: 3, limit: 3 }
    ));
}

#[test]
fn the_whole_mailbox_is_bounded_regardless_of_sender_count() {
    // Many distinct senders must not add up past the total cap.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 10_000,
        max_messages_per_sender: 100,
        max_bytes_total: 2500,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    for i in 0..2u8 {
        mailbox
            .enqueue(&recipient(), &sender(i), &[0u8; 1000], now + DAY)
            .expect("fits in total");
    }
    // 2000 held; a third 1000-byte blob would exceed 2500.
    let err = mailbox
        .enqueue(&recipient(), &sender(9), &[0u8; 1000], now + DAY)
        .unwrap_err();
    assert!(matches!(
        err,
        MailboxRejection::MailboxFull {
            held: 2000,
            limit: 2500
        }
    ));
}

#[test]
fn a_single_oversized_blob_is_refused_outright() {
    // A blob bigger than the per-sender cap could never fit, so it is rejected
    // with a specific reason rather than a confusing "quota exceeded".
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 100,
        max_messages_per_sender: 10,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    let err = mailbox
        .enqueue(&recipient(), &sender(1), &[0u8; 101], now + DAY)
        .unwrap_err();
    assert!(matches!(
        err,
        MailboxRejection::BlobTooLarge {
            size: 101,
            limit: 100
        }
    ));
}

#[test]
fn an_already_expired_blob_is_refused() {
    // plan.md §6.5(3): never insert an immortal or already-dead row.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let err = mailbox
        .enqueue(&recipient(), &sender(1), b"x", now)
        .unwrap_err();
    assert_eq!(err, MailboxRejection::AlreadyExpired);
}

#[test]
fn an_expired_blob_is_not_returned_even_before_the_purge_runs() {
    // §6.4 "enforcement points": the read path must enforce the ceiling itself,
    // so a host that has not purged yet still cannot hand over stale mail.
    let now = 1_700_000_000;
    let mut fx = Fixture::new(now);

    {
        let mailbox = Mailbox::with_defaults(&fx.store);
        mailbox
            .enqueue(&recipient(), &sender(1), b"x", now + DAY)
            .unwrap();
        assert_eq!(mailbox.read(&recipient()).unwrap().len(), 1);
    }

    // Advance past expiry without purging.
    fx.store.freeze_clock_at(now + 2 * DAY);

    let mailbox = Mailbox::with_defaults(&fx.store);
    assert!(
        mailbox.read(&recipient()).unwrap().is_empty(),
        "expired blob was returned"
    );
}

#[test]
fn the_retention_purge_removes_buffered_mail() {
    // The host-side TTL from §4.4: the same purge that covers messages covers
    // mailbox rows, so a host cannot keep a copy past the ceiling.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    mailbox
        .enqueue(&recipient(), &sender(1), b"x", now + DAY)
        .unwrap();

    let report = fx.store.purge(now + 2 * DAY).expect("purge runs");
    assert_eq!(report.deleted_for("mailbox_buffer"), 1);
    assert!(mailbox.read(&recipient()).unwrap().is_empty());
}

#[test]
fn acknowledging_removes_only_that_recipients_blob() {
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let r = mailbox
        .enqueue(&recipient(), &sender(1), b"x", now + DAY)
        .unwrap();

    // A different recipient cannot delete it by guessing the id.
    assert!(!mailbox.acknowledge(b"someone-else", &r.id).unwrap());
    assert_eq!(mailbox.read(&recipient()).unwrap().len(), 1);

    // The real recipient can.
    assert!(mailbox.acknowledge(&recipient(), &r.id).unwrap());
    assert!(mailbox.read(&recipient()).unwrap().is_empty());
}

#[test]
fn space_is_returned_after_acknowledgement() {
    // Quotas count *currently buffered* bytes, so a delivered message frees room.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1000,
        max_messages_per_sender: 2,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    let r = mailbox
        .enqueue(&recipient(), &sender(1), &[0u8; 900], now + DAY)
        .unwrap();
    assert!(mailbox
        .enqueue(&recipient(), &sender(1), &[0u8; 900], now + DAY)
        .is_err());

    mailbox.acknowledge(&recipient(), &r.id).unwrap();
    mailbox
        .enqueue(&recipient(), &sender(1), &[0u8; 900], now + DAY)
        .expect("space was returned");
}

#[test]
fn a_batch_is_refused_whole_when_it_is_too_large() {
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1_000_000,
        max_messages_per_sender: 1000,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 2,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    let blobs: Vec<(&[u8], i64)> = vec![
        (b"a".as_slice(), now + DAY),
        (b"b".as_slice(), now + DAY),
        (b"c".as_slice(), now + DAY),
    ];
    let (receipts, rejection) = mailbox.enqueue_batch(&recipient(), &sender(1), &blobs);
    assert!(receipts.is_empty());
    assert!(matches!(
        rejection,
        Some(MailboxRejection::BatchTooLarge { count: 3, limit: 2 })
    ));
}

#[test]
fn a_partial_batch_reports_what_landed() {
    // A sender needs to know which messages did not land, so a partial batch is
    // reported rather than rolled back silently.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1000,
        max_messages_per_sender: 2,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let mailbox = Mailbox::new(&fx.store, policy);

    let blobs: Vec<(&[u8], i64)> = vec![
        (b"first".as_slice(), now + DAY),
        (b"second".as_slice(), now + DAY),
        (b"third".as_slice(), now + DAY),
    ];
    let (receipts, rejection) = mailbox.enqueue_batch(&recipient(), &sender(1), &blobs);
    assert_eq!(receipts.len(), 2, "two blobs fit within the count quota");
    assert!(matches!(
        rejection,
        Some(MailboxRejection::SenderCountQuota { .. })
    ));
    assert_eq!(mailbox.read(&recipient()).unwrap().len(), 2);
}

#[test]
fn a_tampered_blob_fails_authentication() {
    // The AAD binds recipient, sender, and both timestamps, so a host that edits
    // the row cannot make the recipient accept altered metadata.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    let r = mailbox
        .enqueue(&recipient(), &sender(1), b"payload", now + DAY)
        .unwrap();

    // Extend the stored lifetime directly, as a malicious host would.
    fx.store
        .raw_execute_for_test(
            "UPDATE mailbox_buffer SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params![now + 365 * DAY, &r.id[..]],
        )
        .expect("host edits the row");

    // The recipient's read must fail rather than silently accept the new expiry.
    let err = mailbox.read(&recipient()).unwrap_err();
    assert!(
        matches!(err, anon_storage::StorageError::Decrypt),
        "tampered metadata was accepted: {err:?}"
    );
}

#[test]
fn buffered_mail_survives_a_reopen() {
    // A host restart must not lose mail it accepted.
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);
    let payload = b"survives restart";
    mailbox
        .enqueue(&recipient(), &sender(1), payload, now + 30 * DAY)
        .unwrap();

    let path = fx.store.path().to_path_buf();

    // Reopen the same file with the same passphrase and clock.
    let mut reopened = Store::open(
        &path,
        "correct horse battery staple",
        StoreConfig {
            params: Argon2Params::test_fast(),
            purge_on_open: false,
            vacuum_after_purge: false,
        },
    )
    .expect("reopen");
    reopened.freeze_clock_at(now);

    let mailbox = Mailbox::with_defaults(&reopened);
    let blobs = mailbox.read(&recipient()).expect("read after reopen");
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].ciphertext, payload);
}

#[test]
fn mailboxes_are_isolated_by_recipient() {
    let now = 1_700_000_000;
    let fx = Fixture::new(now);
    let mailbox = Mailbox::with_defaults(&fx.store);

    mailbox
        .enqueue(b"alice", &sender(1), b"for alice", now + DAY)
        .unwrap();
    mailbox
        .enqueue(b"bob", &sender(2), b"for bob", now + DAY)
        .unwrap();

    let alice = mailbox.read(b"alice").unwrap();
    let bob = mailbox.read(b"bob").unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(bob.len(), 1);
    assert_eq!(alice[0].ciphertext, b"for alice");
    assert_eq!(bob[0].ciphertext, b"for bob");
}

#[test]
fn blobs_are_returned_in_arrival_order() {
    // Ordering matters for a group ratchet: MLS messages must be processed in the
    // order the sender produced them.
    let now = 1_700_000_000;
    let mut fx = Fixture::new(now);

    for i in 0..5u8 {
        {
            let mailbox = Mailbox::with_defaults(&fx.store);
            mailbox
                .enqueue(&recipient(), &sender(1), &[i], now + DAY)
                .unwrap();
        }
        // Distinct receive times so ordering is unambiguous.
        fx.store.freeze_clock_at(now + i64::from(i) + 1);
    }

    let mailbox = Mailbox::with_defaults(&fx.store);
    let blobs = mailbox.read(&recipient()).unwrap();
    let order: Vec<u8> = blobs.iter().map(|b| b.ciphertext[0]).collect();
    assert_eq!(order, vec![0, 1, 2, 3, 4]);
}

#[test]
fn the_default_policy_is_bounded() {
    // A sanity check that the shipped defaults actually bound the host's disk.
    let p = MailboxPolicy::mobile_default();
    assert!(p.max_bytes_total >= p.max_bytes_per_sender);
    assert!(p.max_bytes_total <= 16 * 1024 * 1024);
    assert!(p.max_messages_per_sender > 0);
    assert!(p.max_blobs_per_enqueue > 0);
}
