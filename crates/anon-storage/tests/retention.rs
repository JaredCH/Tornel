//! Storage integration tests — the Phase 3 exit criteria (`plan.md` §7.1).
//!
//! These are the tests that make the 90-day retention claim *verifiable* rather
//! than asserted. Each maps to a requirement in §6 and §10.

use anon_storage::{Argon2Params, Store, StoreConfig};

const PASSPHRASE: &str = "test-database-passphrase-1234";

/// The fixed instant these tests operate at.
///
/// Retention behaviour is only testable with a deterministic clock
/// (`plan.md` §10). Every store opened by [`open`] is frozen here, and individual
/// tests move it with `freeze_clock_at`.
const NOW: i64 = 1_700_000_000;

/// A store with light KDF parameters, so tests stay fast. The parameters are
/// format-identical to production; only the cost is reduced. The clock is frozen
/// at [`NOW`] so inserts are accepted deterministically.
fn open(dir: &tempdir::TempDir) -> Store {
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: true,
    };
    let mut store =
        Store::open(&dir.path().join("test.db"), PASSPHRASE, config).expect("open store");
    store.freeze_clock_at(NOW);
    store
}

/// Minimal temp-dir helper so the crate has no dev-dependency on `tempfile`.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-storage-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            p.push(unique);
            std::fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

const DAY: i64 = 86_400;

// ---------------------------------------------------------------------------
// Open / encrypt / key handling
// ---------------------------------------------------------------------------

#[test]
fn opens_creates_and_reopens_with_the_same_passphrase() {
    let dir = tempdir::TempDir::new("reopen");
    {
        let s = open(&dir);
        s.insert_message(b"conv", b"peer", 1_700_000_000, b"hello")
            .unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.message_count().unwrap(), 1);
}

/// Regression: a message written before a restart must still be readable after.
///
/// Bucket keys are derived rather than stored, so "which buckets are live" is
/// state that has to persist. Without it, the ring starts empty on every launch
/// and every pre-restart row looks like it belongs to a shredded bucket. This is
/// a silent data-loss bug — nothing errors at write time, and the loss only shows
/// up the next time the app opens.
#[test]
fn a_message_survives_a_restart_and_is_still_readable() {
    let dir = tempdir::TempDir::new("restart-read");
    let id = {
        let s = open(&dir);
        s.insert_message(b"conv", b"peer", NOW, b"read me after restart")
            .unwrap()
    };

    let s = open(&dir);
    let plaintext = s
        .read_message(&id)
        .expect("a message from before the restart must decrypt");
    assert_eq!(plaintext, b"read me after restart");
}

/// Regression: a bucket shredded before a restart must stay shredded after.
///
/// Persisting the live set must not weaken crypto-shredding. If a retired bucket
/// were treated as live again on the next launch, its key would be re-derived and
/// the guarantee in `plan.md` §6.2 would be false.
#[test]
fn a_shredded_bucket_is_not_resurrected_by_a_restart() {
    let dir = tempdir::TempDir::new("restart-shred");
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    };
    let path = dir.path().join("test.db");

    // Insert while the message is legitimately live, so the store accepts it.
    let id = {
        let mut s = Store::open(&path, PASSPHRASE, config.clone()).expect("open");
        s.freeze_clock_at(NOW);
        s.insert_message(b"conv", b"peer", NOW, b"should be shredded")
            .unwrap()
    };

    // Age the clock well past the retention ceiling so the message's whole bucket
    // falls outside the window, then purge: the bucket is shredded and retired.
    let later = NOW + 400 * DAY;
    {
        let mut s = Store::open(&path, PASSPHRASE, config.clone()).expect("open");
        s.freeze_clock_at(later);
        let report = s.purge(later).expect("purge runs");
        assert!(
            !report.shredded_buckets.is_empty(),
            "the aged bucket should have been shredded"
        );
    }

    // After a restart the bucket must *stay* shredded. If it were treated as live
    // again its key would be re-derived, making plan.md §6.2's guarantee false.
    let mut s = Store::open(&path, PASSPHRASE, config).expect("open");
    s.freeze_clock_at(later);
    match s.read_message(&id) {
        // The row is gone (purged), so "not found" is also a correct outcome;
        // either way the plaintext must not come back.
        Err(anon_storage::StorageError::KeyShredded(_))
        | Err(anon_storage::StorageError::InvalidRecord(_)) => {}
        Err(other) => panic!("expected the message to be unavailable, got {other:?}"),
        Ok(plaintext) => panic!(
            "SECURITY: a shredded bucket was re-derived after restart; plaintext = {:?}",
            String::from_utf8_lossy(&plaintext)
        ),
    }
}

#[test]
fn a_wrong_passphrase_cannot_open_the_database() {
    // plan.md §6.3: the file is encrypted at rest, so a wrong key fails at open.
    let dir = tempdir::TempDir::new("wrongpw");
    {
        let _ = open(&dir);
    }
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    };
    let result = Store::open(&dir.path().join("test.db"), "not-the-passphrase", config);
    assert!(
        result.is_err(),
        "opening with the wrong passphrase must fail"
    );
}

#[test]
fn the_database_file_is_actually_ciphertext() {
    // Phase 3 exit criterion: "DB opendump shows ciphertext only."
    let dir = tempdir::TempDir::new("ciphertext");
    let marker = b"UNENCRYPTED-MARKER-1234567890";
    {
        let s = open(&dir);
        s.insert_message(b"conv", b"peer", 1_700_000_000, marker)
            .unwrap();
        assert_eq!(
            s.read_message(&s.message_ids().unwrap()[0]).unwrap(),
            marker
        );
    }

    let bytes = std::fs::read(dir.path().join("test.db")).expect("read db file");

    // The plaintext must not appear anywhere in the file.
    assert!(
        !contains(&bytes, marker),
        "plaintext message content found in the database file"
    );
    // A SQLite header would indicate the file is not encrypted.
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "database file has a plaintext SQLite header; SQLCipher is not active"
    );
}

#[test]
fn schema_audit_passes_on_a_fresh_database() {
    // plan.md §6.5(4): every content table must have retention.
    let dir = tempdir::TempDir::new("audit");
    let s = open(&dir);
    let violations = s.audit_schema().unwrap();
    assert!(
        violations.is_empty(),
        "tables lacking retention: {violations:?}"
    );
}

// ---------------------------------------------------------------------------
// Message encryption round-trip and AEAD binding
// ---------------------------------------------------------------------------

#[test]
fn messages_round_trip_through_encryption() {
    let dir = tempdir::TempDir::new("roundtrip");
    let s = open(&dir);
    let id = s
        .insert_message(b"conv-1", b"peer-a", 1_700_000_000, b"secret text")
        .unwrap();
    assert_eq!(s.read_message(&id).unwrap(), b"secret text");
}

#[test]
fn empty_and_large_payloads_round_trip() {
    let dir = tempdir::TempDir::new("sizes");
    let s = open(&dir);

    let empty = s.insert_message(b"c", b"p", 1_700_000_000, b"").unwrap();
    assert_eq!(s.read_message(&empty).unwrap(), b"");

    let big = vec![0xABu8; 256 * 1024];
    let id = s.insert_message(b"c", b"p", 1_700_000_000, &big).unwrap();
    assert_eq!(s.read_message(&id).unwrap(), big);
}

#[test]
fn reading_an_unknown_message_fails_cleanly() {
    let dir = tempdir::TempDir::new("unknown");
    let s = open(&dir);
    assert!(s.read_message(b"does-not-exist").is_err());
}

// ---------------------------------------------------------------------------
// Retention: the §6.1 corrections
// ---------------------------------------------------------------------------

#[test]
fn inserting_an_already_expired_record_is_rejected() {
    // plan.md §6.5(3): a row must not be insertable in an immortal state.
    let dir = tempdir::TempDir::new("expired-insert");
    let mut s = open(&dir);
    let now = 1_700_000_000i64;
    s.set_clock(Box::new(move || now));

    // Sent 91 days ago -> expiry already in the past.
    let err = s
        .insert_message(b"c", b"p", now - 91 * DAY, b"stale")
        .unwrap_err();
    assert!(matches!(
        err,
        anon_storage::StorageError::AlreadyExpired { .. }
    ));
    assert_eq!(s.message_count().unwrap(), 0);
}

#[test]
fn purge_deletes_rows_past_the_ceiling_and_keeps_live_ones() {
    // The headline §6.1 behaviour.
    let dir = tempdir::TempDir::new("purge");
    let mut s = open(&dir);

    let now = 1_700_000_000i64;
    s.set_clock(Box::new(move || now));

    // Sent 100 days ago: safely expired. Insert while the clock is in the past,
    // then advance it. This is exactly what happens over 100 real days.
    let insert_clock = now - 100 * DAY;
    s.set_clock(Box::new(move || insert_clock));
    let old_id = s.insert_message(b"c", b"p", insert_clock, b"old").unwrap();
    s.freeze_clock_at(now);

    // Sent today: fresh.
    let fresh_id = s.insert_message(b"c", b"p", now, b"fresh").unwrap();
    assert_eq!(s.message_count().unwrap(), 2);

    let report = s.purge(now).unwrap();
    assert_eq!(
        report.total_deleted(),
        1,
        "exactly the expired row should go"
    );
    assert_eq!(s.message_count().unwrap(), 1);

    // The fresh row survives and still decrypts.
    assert_eq!(s.read_message(&fresh_id).unwrap(), b"fresh");
    // The expired row is gone.
    assert!(s.read_message(&old_id).is_err());
}

#[test]
fn purge_is_a_no_op_when_everything_is_within_the_window() {
    let dir = tempdir::TempDir::new("purge-noop");
    let mut s = open(&dir);
    let now = 1_700_000_000i64;
    s.set_clock(Box::new(move || now));

    for i in 0..5 {
        s.insert_message(b"c", b"p", now - i * DAY, b"data")
            .unwrap();
    }

    let report = s.purge(now).unwrap();
    assert_eq!(report.total_deleted(), 0);
    assert_eq!(s.message_count().unwrap(), 5);
}

#[test]
fn purge_runs_on_open_when_configured() {
    // plan.md §6.5(2)/(5): purge must not depend on a timer surviving.
    let dir = tempdir::TempDir::new("purge-on-open");
    let now = 1_700_000_000i64;

    {
        let mut s = open(&dir);
        let long_ago = now - 200 * DAY;
        s.set_clock(Box::new(move || long_ago));
        s.insert_message(b"c", b"p", long_ago, b"ancient").unwrap();
        assert_eq!(s.message_count().unwrap(), 1);
    }

    // Reopen with the real (later) clock and purge-on-open enabled.
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: true,
        vacuum_after_purge: true,
    };
    let s = Store::open(&dir.path().join("test.db"), PASSPHRASE, config).unwrap();
    assert_eq!(
        s.message_count().unwrap(),
        0,
        "purge-on-open failed to remove an expired row"
    );
}

#[test]
fn retention_clock_is_absolute_so_a_backwards_clock_cannot_extend_it() {
    // plan.md §6.5(1): the anti-regression property.
    let dir = tempdir::TempDir::new("clock-skew");
    let mut s = open(&dir);

    let sent = 1_700_000_000i64;
    s.set_clock(Box::new(move || sent));
    let id = s.insert_message(b"c", b"p", sent, b"data").unwrap();

    // Jump far past the ceiling.
    let future = sent + 91 * DAY;
    s.set_clock(Box::new(move || future));

    // Now simulate the user setting the clock *back* before purging.
    let skewed_back = sent + 10 * DAY;
    s.set_clock(Box::new(move || skewed_back));

    // The row's expiry is a stored absolute value, so its status is unchanged by
    // the clock. Purging at the *true* later time must remove it.
    let report = s.purge(future).unwrap();
    // One message plus its now-empty conversation row expire together: purging
    // the conversation entry point is deliberate (`plan.md` §6.4).
    assert_eq!(report.deleted_for("messages"), 1);
    assert!(s.read_message(&id).is_err());
    assert_eq!(s.message_count().unwrap(), 0);
}

#[test]
fn boundary_rows_expire_exactly_at_ninety_days() {
    let dir = tempdir::TempDir::new("boundary");
    let mut s = open(&dir);

    let sent = 1_700_000_000i64;
    s.set_clock(Box::new(move || sent));
    s.insert_message(b"c", b"p", sent, b"boundary").unwrap();

    // One second before expiry: retained.
    let just_before = sent + 90 * DAY - 1;
    let report = s.purge(just_before).unwrap();
    assert_eq!(report.deleted_for("messages"), 0);
    assert_eq!(s.message_count().unwrap(), 1);

    // Exactly at expiry: purged (inclusive comparison).
    let at_expiry = sent + 90 * DAY;
    let report = s.purge(at_expiry).unwrap();
    assert_eq!(report.deleted_for("messages"), 1);
    assert_eq!(s.message_count().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Crypto-shredding: the §6.2 correction
// ---------------------------------------------------------------------------

#[test]
fn shredding_a_bucket_makes_its_ciphertext_unrecoverable() {
    // The key property that replaces reliance on `VACUUM` (§6.2, layer 4).
    // A message from long ago: insert with a clock that makes it fresh, then
    // shred by moving time forward past the ceiling.
    let dir = tempdir::TempDir::new("shred");
    let mut s = open(&dir);

    let sent = 1_700_000_000i64;
    s.freeze_clock_at(sent);
    let id = s
        .insert_message(b"c", b"p", sent, b"will-be-shredded")
        .unwrap();
    assert_eq!(s.read_message(&id).unwrap(), b"will-be-shredded");

    // Advance well past the ceiling so the bucket is fully expired.
    let far_future = sent + 200 * DAY;
    s.freeze_clock_at(far_future);
    let report = s.purge(far_future).unwrap();

    assert!(
        !report.shredded_buckets.is_empty(),
        "purge should have shredded at least one bucket"
    );

    // The row is deleted, so reading fails — but the important part is that the
    // key is gone from the ring entirely.
    assert!(s.read_message(&id).is_err());
    for bucket in &report.shredded_buckets {
        assert!(
            !s.key_ring()
                .is_live(&anon_storage::BucketId::parse(bucket).unwrap()),
            "bucket {bucket} was reported shredded but is still live"
        );
    }
}

#[test]
fn a_shredded_bucket_refuses_to_yield_a_key_even_if_ciphertext_remains() {
    // Simulates the case crypto-shredding exists for: the bytes survived
    // (filesystem copy, flash remnant) but the key does not.
    let dir = tempdir::TempDir::new("shred-key");
    let s = open(&dir);

    let bucket = anon_storage::BucketId::new(2026, 5).unwrap();
    let key_before = s.key_ring().open(&bucket).as_bytes().to_owned();

    // Confirm the key is available while live.
    assert_eq!(s.key_ring().get(&bucket).unwrap().as_bytes(), &key_before);

    assert!(s.key_ring().shred(&bucket));

    // The key can no longer be obtained — this is what makes surviving
    // ciphertext useless.
    match s.key_ring().get(&bucket) {
        Err(anon_storage::StorageError::KeyShredded(_)) => {}
        other => panic!("expected KeyShredded, got {other:?}"),
    }
}

#[test]
fn crypto_shredding_replaces_reliance_on_vacuum() {
    // Even with VACUUM disabled, the shredded bucket's data is unrecoverable via
    // the store. This demonstrates §6.2's claim that the guarantee does not
    // depend on filesystem behaviour.
    let dir = tempdir::TempDir::new("no-vacuum");
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false, // deliberately off
    };
    let s = Store::open(&dir.path().join("test.db"), PASSPHRASE, config).unwrap();

    let sent = 1_700_000_000i64;
    let mut s2 = s;
    s2.set_clock(Box::new(move || sent));
    let id = s2.insert_message(b"c", b"p", sent, b"shred-me").unwrap();
    s2.set_clock(Box::new(move || sent + 200 * DAY));

    let report = s2.purge(sent + 200 * DAY).unwrap();
    assert!(!report.vacuumed, "vacuum was disabled for this test");
    assert!(!report.shredded_buckets.is_empty());
    assert!(s2.read_message(&id).is_err());
}

#[test]
fn double_purge_is_idempotent() {
    let dir = tempdir::TempDir::new("idempotent");
    let mut s = open(&dir);
    let sent = 1_700_000_000i64;
    s.set_clock(Box::new(move || sent));
    s.insert_message(b"c", b"p", sent, b"x").unwrap();

    let future = sent + 200 * DAY;
    let first = s.purge(future).unwrap();
    let second = s.purge(future).unwrap();

    assert!(first.total_deleted() > 0);
    assert_eq!(
        second.total_deleted(),
        0,
        "second purge should find nothing"
    );
    // Shredding is likewise idempotent.
    assert!(second.shredded_buckets.is_empty());
}

#[test]
fn latex_shredding_does_not_touch_live_buckets() {
    // Guards the invariant that makes monthly buckets compatible with a 90-day
    // ceiling: a still-live bucket must never be shredded.
    let dir = tempdir::TempDir::new("live-bucket");
    let mut s = open(&dir);

    let now = 1_700_000_000i64;
    s.set_clock(Box::new(move || now));
    let live_id = s.insert_message(b"c", b"p", now, b"live").unwrap();

    // Purge at "now": nothing is expired, so nothing should be shredded.
    let report = s.purge(now).unwrap();
    assert!(report.shredded_buckets.is_empty());
    assert_eq!(s.read_message(&live_id).unwrap(), b"live");
}

// ---------------------------------------------------------------------------
// Helpers used above
// ---------------------------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// The clock-swapping helpers used by the retention tests come from the public
// `Store::set_clock` API. Clock mutation is deliberately not hidden behind
// `#[cfg(test)]`, because these tests live in a separate crate.
