//! Mailbox host integration tests (`plan.md` §4.4).
//!
//! These cover the *policy* layer above storage: what a host accepts, what it
//! tells the sender, and how a recipient drains its mail. The storage-level
//! guarantees (quotas, TTL, tamper detection) are tested in
//! `anon-storage/tests/mailbox.rs`; these tests confirm the messaging layer wires
//! them up without weakening them.

use anon_messaging::mailbox_host::{refusal_to_error, MailboxHost};
use anon_messaging::MessageError;
use anon_storage::mailbox::{MailboxPolicy, MailboxRejection};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::PathBuf;

const DAY: i64 = 86_400;
const NOW: i64 = 1_700_000_000;

struct Fixture {
    store: Store,
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "anon-mboxhost-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open(
            &dir.join("host.db"),
            "host-passphrase",
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

fn recipient() -> Vec<u8> {
    b"recipient-onion".to_vec()
}

fn sender(n: u8) -> Vec<u8> {
    vec![n; 32]
}

#[test]
fn a_host_accepts_and_the_recipient_drains() {
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    let receipt = host
        .accept(&recipient(), &sender(1), b"opaque mls bytes", NOW + 7 * DAY)
        .expect("accepted");
    assert!(
        !receipt.is_delivery(),
        "a receipt must never claim delivery"
    );

    let drained = host.drain(&recipient()).expect("drain");
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].ciphertext, b"opaque mls bytes");

    // Draining takes custody: the host no longer holds it.
    assert!(host.peek(&recipient()).unwrap().is_empty());
}

#[test]
fn draining_returns_arrival_order() {
    // MLS group messages must be processed in the order the sender produced them.
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    for i in 0..4u8 {
        host.accept(&recipient(), &sender(1), &[i], NOW + 7 * DAY)
            .unwrap();
    }

    let drained = host.drain(&recipient()).unwrap();
    let order: Vec<u8> = drained.iter().map(|b| b.ciphertext[0]).collect();
    assert_eq!(order, vec![0, 1, 2, 3]);
}

#[test]
fn a_refusal_is_a_policy_answer_not_an_error() {
    // The distinction matters: a refusal means "tell the sender no", while an
    // error means "something broke". Conflating them would make the UI retry
    // forever against a full mailbox.
    let fx = Fixture::new();
    let policy = MailboxPolicy {
        max_bytes_per_sender: 100,
        max_messages_per_sender: 10,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let host = MailboxHost::new(&fx.store, policy);

    host.accept(&recipient(), &sender(1), &[0u8; 100], NOW + DAY)
        .expect("fits exactly");

    let rejection = host
        .accept(&recipient(), &sender(1), b"x", NOW + DAY)
        .unwrap_err();
    assert!(matches!(
        rejection,
        MailboxRejection::SenderByteQuota { .. }
    ));

    // And it converts to a message error only when the caller chooses to.
    let err = refusal_to_error(rejection);
    assert!(matches!(err, MessageError::MailboxRefused(_)));
}

#[test]
fn a_partial_batch_reports_what_landed() {
    let fx = Fixture::new();
    let policy = MailboxPolicy {
        max_bytes_per_sender: 1_000_000,
        max_messages_per_sender: 2,
        max_bytes_total: 1_000_000,
        max_blobs_per_enqueue: 32,
    };
    let host = MailboxHost::new(&fx.store, policy);

    let blobs: Vec<(&[u8], i64)> = vec![
        (b"one".as_slice(), NOW + DAY),
        (b"two".as_slice(), NOW + DAY),
        (b"three".as_slice(), NOW + DAY),
    ];
    let (receipts, rejection) = host.accept_batch(&recipient(), &sender(1), &blobs);
    assert_eq!(receipts.len(), 2);
    assert!(matches!(
        rejection,
        Some(MailboxRejection::SenderCountQuota { .. })
    ));
    assert_eq!(host.peek(&recipient()).unwrap().len(), 2);
}

#[test]
fn a_hostile_peer_cannot_fill_the_hosts_disk() {
    // plan.md §4.4 "Abuse": the host must be protected from the peer, not the
    // other way round. Repeated sends from one peer stop at the quota.
    let fx = Fixture::new();
    let policy = MailboxPolicy {
        max_bytes_per_sender: 4096,
        max_messages_per_sender: 8,
        max_bytes_total: 8192,
        max_blobs_per_enqueue: 32,
    };
    let host = MailboxHost::new(&fx.store, policy);

    let mut accepted = 0;
    for _ in 0..1000 {
        match host.accept(&recipient(), &sender(1), &[0u8; 512], NOW + DAY) {
            Ok(_) => accepted += 1,
            Err(_) => break,
        }
    }
    assert_eq!(accepted, 8, "the count quota must stop the flood");

    let (bytes, count) = host.usage(&recipient(), Some(&sender(1))).unwrap();
    assert_eq!(count, 8);
    assert_eq!(bytes, 8 * 512);
    assert!(bytes <= policy.max_bytes_per_sender);
}

#[test]
fn a_host_cannot_hold_mail_past_the_ceiling() {
    // The host-side TTL from §4.4: the same purge covers mailbox rows.
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    host.accept(&recipient(), &sender(1), b"x", NOW + DAY)
        .unwrap();
    assert_eq!(host.peek(&recipient()).unwrap().len(), 1);

    let report = fx.store.purge(NOW + 2 * DAY).expect("purge");
    assert_eq!(report.deleted_for("mailbox_buffer"), 1);
    assert!(host.peek(&recipient()).unwrap().is_empty());
}

#[test]
fn a_host_cannot_serve_expired_mail_before_purging() {
    // §6.4 "enforcement points": the read path enforces the ceiling itself, so a
    // host that has not purged yet still cannot hand over stale mail.
    let mut fx = Fixture::new();
    {
        let host = MailboxHost::with_defaults(&fx.store);
        host.accept(&recipient(), &sender(1), b"x", NOW + DAY)
            .unwrap();
        assert_eq!(host.peek(&recipient()).unwrap().len(), 1);
    }

    fx.store.freeze_clock_at(NOW + 2 * DAY);

    let host = MailboxHost::with_defaults(&fx.store);
    assert!(host.peek(&recipient()).unwrap().is_empty());
}

#[test]
fn the_host_never_sees_plaintext() {
    // The confidentiality boundary is MLS: the host stores opaque bytes. This test
    // confirms the messaging layer does not accidentally decrypt or re-encode.
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    let marker = b"MARKER-must-not-appear-in-the-database";
    host.accept(&recipient(), &sender(1), marker, NOW + DAY)
        .unwrap();

    let raw = std::fs::read(fx.store.path()).expect("db readable");
    assert!(
        !raw.windows(marker.len()).any(|w| w == marker),
        "the host stored the blob verbatim"
    );

    // And what the recipient drains is byte-identical to what was sent.
    let drained = host.drain(&recipient()).unwrap();
    assert_eq!(drained[0].ciphertext, marker);
}

#[test]
fn mailboxes_are_isolated_by_recipient() {
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    host.accept(b"alice", &sender(1), b"for alice", NOW + DAY)
        .unwrap();
    host.accept(b"bob", &sender(2), b"for bob", NOW + DAY)
        .unwrap();

    let alice = host.drain(b"alice").unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].ciphertext, b"for alice");

    // Bob's mail is untouched by Alice draining hers.
    let bob = host.peek(b"bob").unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].ciphertext, b"for bob");
}

#[test]
fn a_recipient_cannot_acknowledge_another_mailboxs_blob() {
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);

    let receipt = host
        .accept(&recipient(), &sender(1), b"x", NOW + DAY)
        .unwrap();

    assert!(!host.acknowledge(b"someone-else", &receipt.id).unwrap());
    assert_eq!(host.peek(&recipient()).unwrap().len(), 1);
    assert!(host.acknowledge(&recipient(), &receipt.id).unwrap());
    assert!(host.peek(&recipient()).unwrap().is_empty());
}

#[test]
fn buffered_mail_survives_a_host_restart() {
    // A host restart must not lose mail it accepted — that would be a silent
    // message loss the sender never learns about.
    let fx = Fixture::new();
    let path = fx.store.path().to_path_buf();
    {
        let host = MailboxHost::with_defaults(&fx.store);
        host.accept(&recipient(), &sender(1), b"survives", NOW + 30 * DAY)
            .unwrap();
    }

    let mut reopened = Store::open(
        &path,
        "host-passphrase",
        StoreConfig {
            params: Argon2Params::test_fast(),
            purge_on_open: false,
            vacuum_after_purge: false,
        },
    )
    .expect("reopen");
    reopened.freeze_clock_at(NOW);

    let host = MailboxHost::with_defaults(&reopened);
    let drained = host.drain(&recipient()).expect("drain after restart");
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].ciphertext, b"survives");
}

#[test]
fn the_default_policy_bounds_a_mobile_host() {
    let fx = Fixture::new();
    let host = MailboxHost::with_defaults(&fx.store);
    let p = host.policy();
    assert!(p.max_bytes_total <= 16 * 1024 * 1024);
    assert!(p.max_bytes_per_sender <= p.max_bytes_total);
}
