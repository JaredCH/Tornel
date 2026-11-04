//! Database rekey tests (gap-closure plan Gap 2).
//!
//! # What these tests are actually proving
//!
//! A rekey is the one storage operation that can destroy a user's entire message history,
//! and there is no server-side copy to fall back on. So the tests here are not "does the
//! happy path work" — they are "does every failure leave the data recoverable".
//!
//! The properties asserted:
//!
//! * **The data survives.** After a rekey, every row is still readable under the new
//!   passphrase, with the same contents.
//! * **The old passphrase stops working.** A rekey that leaves the old key valid has not
//!   retired anything.
//! * **The original is untouched until verification passes.** A failed verification must
//!   leave the original openable with the old passphrase.
//! * **Every stage resumes.** A crash at each of the five stages must complete on the next
//!   call without losing data — including the `swapped` stage, where re-running the swap
//!   would destroy the database.
//! * **The marker holds no secrets.** It is written to disk and left there between
//!   crashes, so it must contain only salts.
//! * **The retired file is gone.** A leftover `.rekey-old` is encrypted with the
//!   passphrase the user just retired, which is exactly the artifact a rekey is meant to
//!   eliminate.

use anon_storage::rekey::{rekey, resume, RekeyMarker, RekeyPaths, RekeyStage};
use anon_storage::{Argon2Params, GroupRow, Store, StoreConfig};

const OLD: &str = "the-old-database-passphrase";
const NEW: &str = "the-new-database-passphrase";
const NOW: i64 = 1_700_000_000;

mod tempdir {
    use std::path::PathBuf;

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-storage-rekey-{tag}-{}-{:?}",
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

        pub fn db(&self) -> PathBuf {
            self.0.join("anon.db")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn config() -> StoreConfig {
    StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    }
}

/// Open a store and seed it with a known set of rows.
fn seed(dir: &tempdir::TempDir, passphrase: &str) -> Store {
    let mut store = Store::open(&dir.db(), passphrase, config()).expect("open store");
    store.freeze_clock_at(NOW);

    for i in 0..3u8 {
        store
            .insert_group(&GroupRow {
                group_id: vec![b'g', i],
                name: Some(format!("group {i}")),
                created_at: NOW + i as i64,
                epoch: i as u64,
            })
            .expect("insert group");
    }

    for i in 0..5u8 {
        store
            .insert_message(&[b'c', i % 2], &[b's', i], NOW, b"hello")
            .expect("insert message");
    }

    store
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_rekey_preserves_every_row_and_retires_the_old_passphrase() {
    let dir = tempdir::TempDir::new("happy");
    let before = {
        let s = seed(&dir, OLD);
        let groups = s.groups().expect("list groups");
        let messages = s.message_ids().expect("list messages");
        (groups, messages)
    };
    assert_eq!(before.0.len(), 3);
    assert_eq!(before.1.len(), 5);

    let report = rekey(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("rekey");
    assert!(!report.resumed, "a fresh rekey must not report as resumed");

    // The new passphrase opens the database and every row is still there.
    let after = Store::open(&dir.db(), NEW, config()).expect("open with new passphrase");
    let groups = after.groups().expect("list groups");
    let messages = after.message_ids().expect("list messages");
    assert_eq!(groups, before.0, "group rows must survive byte-identically");
    assert_eq!(messages, before.1, "message ids must survive");

    // The row counts in the report match what is actually there.
    let groups_count = report
        .row_counts
        .iter()
        .find(|(t, _)| t == "groups")
        .map(|(_, n)| *n)
        .expect("groups counted");
    assert_eq!(groups_count, 3);
}

#[test]
fn the_old_passphrase_no_longer_opens_the_database() {
    // This is the whole point of a rekey. If the old key still works, nothing was
    // retired and the user's reason for rekeying (a compromised passphrase) is unmet.
    let dir = tempdir::TempDir::new("retired");
    seed(&dir, OLD);
    rekey(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("rekey");

    let attempt = Store::open(&dir.db(), OLD, config());
    assert!(
        attempt.is_err(),
        "the old passphrase must be rejected after a rekey"
    );
}

#[test]
fn the_retired_original_is_removed() {
    // A leftover `.rekey-old` is encrypted with the passphrase the user just retired.
    // Leaving it on disk would mean the rekey accomplished nothing against an attacker
    // who has the old passphrase and the disk.
    let dir = tempdir::TempDir::new("cleanup");
    seed(&dir, OLD);
    rekey(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("rekey");

    let paths = RekeyPaths::new(&dir.db());
    assert!(!paths.old.exists(), "the retired original must be deleted");
    assert!(
        !paths.old_salt.exists(),
        "the retired original's salt must be deleted"
    );
    assert!(!paths.marker.exists(), "the marker must be deleted");
    assert!(
        !paths.tmp.exists(),
        "the copy must have been moved into place"
    );
}

#[test]
fn the_rekeyed_file_is_not_plaintext() {
    // A rekey that produced an unencrypted file would "work" by every functional test
    // while destroying the at-rest guarantee. The SQLCipher header is the cheap check.
    let dir = tempdir::TempDir::new("ciphertext");
    seed(&dir, OLD);
    rekey(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("rekey");

    let bytes = std::fs::read(dir.db()).expect("read db");
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "the rekeyed database must not have a plaintext SQLite header"
    );
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn an_empty_passphrase_is_refused() {
    let dir = tempdir::TempDir::new("empty");
    seed(&dir, OLD);

    assert!(rekey(&dir.db(), OLD, "", Argon2Params::test_fast()).is_err());
    assert!(rekey(&dir.db(), "", NEW, Argon2Params::test_fast()).is_err());

    // The database is still openable with the original passphrase: a refused rekey must
    // not have touched anything.
    Store::open(&dir.db(), OLD, config()).expect("original still opens");
}

#[test]
fn rekeying_to_the_same_passphrase_is_refused() {
    // A no-op rekey would copy the whole database for no benefit, and would leave the
    // user believing a compromised passphrase had been retired when it had not.
    let dir = tempdir::TempDir::new("same");
    seed(&dir, OLD);

    let err = rekey(&dir.db(), OLD, OLD, Argon2Params::test_fast());
    assert!(err.is_err(), "same-passphrase rekey must be refused");
    assert!(
        !RekeyPaths::new(&dir.db()).marker.exists(),
        "no marker written"
    );
}

#[test]
fn a_wrong_old_passphrase_fails_without_touching_the_database() {
    let dir = tempdir::TempDir::new("wrongold");
    seed(&dir, OLD);

    let err = rekey(
        &dir.db(),
        "not-the-old-passphrase",
        NEW,
        Argon2Params::test_fast(),
    );
    assert!(err.is_err(), "a wrong old passphrase must fail");

    // The original must still open. This is the property that makes the copy-then-swap
    // design worth its cost: a failed attempt is a no-op.
    Store::open(&dir.db(), OLD, config()).expect("original still opens after a failed rekey");
}

// ---------------------------------------------------------------------------
// Resuming from each stage
// ---------------------------------------------------------------------------

/// Build a database and drive it to a given stage, leaving the marker in place.
///
/// Simulates a crash by stopping the migration at the requested stage. The real `rekey`
/// cannot be interrupted mid-call, so this reproduces the on-disk state a crash would
/// leave: the marker at stage N, plus exactly the files that stage produces.
///
/// The file operations are written out here rather than calling the module's own
/// `swap`/`cleanup`, so this harness independently checks the layout the module assumes.
/// If the module's naming ever drifts, these tests fail rather than agreeing with it.
fn drive_to_stage(dir: &tempdir::TempDir, stage: RekeyStage) {
    let paths = RekeyPaths::new(&dir.db());

    // The original, encrypted with the old passphrase.
    seed(dir, OLD);
    let old_salt = read_salt_hex(&paths.salt);

    // The copy, encrypted with the new passphrase. Opening it creates its schema and its
    // own salt; the backup then replaces the schema with the original's.
    let new_salt = {
        let source = Store::open(&paths.db, OLD, config()).expect("open original");
        let dest = Store::open(&paths.tmp, NEW, config()).expect("open copy");
        source.backup_into(&dest).expect("backup");
        read_salt_hex(&paths.tmp_salt)
    };

    // A `prepared` crash leaves no copy at all — the marker was written and nothing else.
    if stage == RekeyStage::Prepared {
        let _ = std::fs::remove_file(&paths.tmp);
        let _ = std::fs::remove_file(&paths.tmp_salt);
    }

    // Write the marker at the requested stage.
    let marker = RekeyMarker {
        stage,
        old_salt,
        new_salt,
    };
    std::fs::write(&paths.marker, marker.to_text()).expect("write marker");

    // A `swapped` or `done` crash means the rename already happened: the live database is
    // the new file and the original is at `.rekey-old`.
    if stage >= RekeyStage::Swapped {
        std::fs::rename(&paths.db, &paths.old).expect("move original aside");
        std::fs::rename(&paths.salt, &paths.old_salt).expect("move original salt aside");
        std::fs::rename(&paths.tmp, &paths.db).expect("move copy into place");
        std::fs::rename(&paths.tmp_salt, &paths.salt).expect("move new salt into place");
    }

    // A `done` crash means cleanup already ran.
    if stage >= RekeyStage::Done {
        let _ = std::fs::remove_file(&paths.old);
        let _ = std::fs::remove_file(&paths.old_salt);
        let _ = std::fs::remove_file(&paths.marker);
    }
}

fn read_salt_hex(path: &std::path::Path) -> String {
    std::fs::read(path)
        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
        .unwrap_or_default()
}

#[test]
fn a_rekey_resumes_from_the_prepared_stage() {
    // A crash right after the marker was written: nothing else happened. The next call
    // must do the whole migration.
    let dir = tempdir::TempDir::new("resume-prepared");
    drive_to_stage(&dir, RekeyStage::Prepared);

    let report = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast())
        .expect("resume")
        .expect("a marker was present");
    assert!(report.resumed, "this run must report as resumed");

    let s = Store::open(&dir.db(), NEW, config()).expect("new passphrase opens");
    assert_eq!(s.groups().expect("groups").len(), 3);
    assert!(
        Store::open(&dir.db(), OLD, config()).is_err(),
        "old key retired"
    );
}

#[test]
fn a_rekey_resumes_from_the_copied_stage() {
    // A crash after the copy was made but before it was verified. The copy exists and is
    // encrypted with the new key; the original is still in place. The next call must
    // verify and swap without re-copying.
    let dir = tempdir::TempDir::new("resume-copied");
    drive_to_stage(&dir, RekeyStage::Copied);

    let report = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast())
        .expect("resume")
        .expect("a marker was present");
    assert!(report.resumed);

    let s = Store::open(&dir.db(), NEW, config()).expect("new passphrase opens");
    assert_eq!(s.groups().expect("groups").len(), 3);
    assert!(
        Store::open(&dir.db(), OLD, config()).is_err(),
        "old key retired"
    );
}

#[test]
fn a_rekey_resumes_from_the_verified_stage() {
    // A crash after verification but before the swap. The copy is proven good; the next
    // call must swap it in without re-verifying or re-copying.
    let dir = tempdir::TempDir::new("resume-verified");
    drive_to_stage(&dir, RekeyStage::Verified);

    let report = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast())
        .expect("resume")
        .expect("a marker was present");
    assert!(report.resumed);

    let s = Store::open(&dir.db(), NEW, config()).expect("new passphrase opens");
    assert_eq!(s.groups().expect("groups").len(), 3);
    assert!(
        Store::open(&dir.db(), OLD, config()).is_err(),
        "old key retired"
    );
}

#[test]
fn a_rekey_resumes_from_the_swapped_stage_without_swapping_again() {
    // The dangerous one. At `swapped` the live database is already the new file and the
    // original is at `.rekey-old`. Re-running the swap would move the new database aside
    // and then fail to find a copy to replace it — destroying the user's data. The next
    // call must only clean up.
    let dir = tempdir::TempDir::new("resume-swapped");
    drive_to_stage(&dir, RekeyStage::Swapped);

    let report = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast())
        .expect("resume")
        .expect("a marker was present");
    assert!(report.resumed);

    // The data must still be there. If the swap ran twice, this is where it would fail.
    let s = Store::open(&dir.db(), NEW, config()).expect("new passphrase opens");
    assert_eq!(
        s.groups().expect("groups").len(),
        3,
        "a resumed swap must not lose the database"
    );
    assert!(
        Store::open(&dir.db(), OLD, config()).is_err(),
        "old key retired"
    );
    assert!(
        !RekeyPaths::new(&dir.db()).marker.exists(),
        "marker cleaned up"
    );
}

#[test]
fn resume_reports_nothing_when_no_marker_exists() {
    // Startup calls `resume` unconditionally. "Nothing to do" must be an ordinary answer,
    // not an error, or every launch would log a failure.
    let dir = tempdir::TempDir::new("no-marker");
    seed(&dir, OLD);

    let result = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("resume");
    assert!(result.is_none(), "no marker means nothing to resume");
}

// ---------------------------------------------------------------------------
// The marker
// ---------------------------------------------------------------------------

#[test]
fn the_marker_round_trips_through_text() {
    let marker = RekeyMarker {
        stage: RekeyStage::Verified,
        old_salt: "00112233445566778899aabbccddeeff".into(),
        new_salt: "ffeeddccbbaa99887766554433221100".into(),
    };
    let parsed = RekeyMarker::parse(&marker.to_text()).expect("parse");
    assert_eq!(parsed, marker);
}

#[test]
fn the_marker_holds_no_key_material() {
    // The marker is written to disk and left there between crashes. It must contain only
    // salts — which are not secret — and never a passphrase or a derived key. This test
    // asserts the *shape*: the only fields are stage and two salts.
    let dir = tempdir::TempDir::new("marker-secrets");
    seed(&dir, OLD);
    rekey(&dir.db(), OLD, NEW, Argon2Params::test_fast()).expect("rekey");

    // The marker is deleted on success, so drive a partial run to inspect one.
    let dir2 = tempdir::TempDir::new("marker-secrets-2");
    drive_to_stage(&dir2, RekeyStage::Copied);
    let text = std::fs::read_to_string(RekeyPaths::new(&dir2.db()).marker).expect("read marker");

    assert!(
        !text.contains(OLD),
        "the marker must not contain the old passphrase"
    );
    assert!(
        !text.contains(NEW),
        "the marker must not contain the new passphrase"
    );
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let key = line.split_once('=').map(|(k, _)| k.trim()).unwrap_or("");
        assert!(
            matches!(key, "stage" | "old_salt" | "new_salt"),
            "unexpected marker field {key:?} — the marker must hold only salts"
        );
    }
}

#[test]
fn a_corrupt_marker_is_an_error_not_a_restart() {
    // Treating an unreadable marker as "start over" would let a half-swapped database be
    // treated as healthy. It must stop the migration instead.
    let dir = tempdir::TempDir::new("corrupt-marker");
    seed(&dir, OLD);
    std::fs::write(RekeyPaths::new(&dir.db()).marker, "stage=nonsense\n").expect("write");

    let err = resume(&dir.db(), OLD, NEW, Argon2Params::test_fast());
    assert!(err.is_err(), "an unknown stage must be refused");
}

#[test]
fn a_marker_missing_a_salt_is_an_error() {
    let dir = tempdir::TempDir::new("partial-marker");
    seed(&dir, OLD);
    std::fs::write(RekeyPaths::new(&dir.db()).marker, "stage=prepared\n").expect("write");

    assert!(resume(&dir.db(), OLD, NEW, Argon2Params::test_fast()).is_err());
}

// ---------------------------------------------------------------------------
// Path derivation
// ---------------------------------------------------------------------------

#[test]
fn every_rekey_path_is_derived_from_the_database_path() {
    // The suffixes are appended, not substituted for the extension: `anon.db` must yield
    // `anon.db.rekey-tmp`, not `anon.rekey-tmp`. Getting this wrong would put the copy
    // somewhere the swap does not look.
    let paths = RekeyPaths::new(std::path::Path::new("/tmp/anon.db"));
    assert!(paths.tmp.ends_with("anon.db.rekey-tmp"));
    assert!(paths.tmp_salt.ends_with("anon.db.rekey-tmp.salt"));
    assert!(paths.old.ends_with("anon.db.rekey-old"));
    assert!(paths.old_salt.ends_with("anon.db.rekey-old.salt"));
    assert!(paths.marker.ends_with("anon.db.rekey-state"));
    assert!(paths.salt.ends_with("anon.db.salt"));
}

#[test]
fn the_salt_path_matches_the_stores_own_sidecar() {
    // `Store::open` writes its salt to `<db>.salt`. If the rekey used a different name,
    // the swapped-in database would be paired with the wrong salt and fail to open.
    let dir = tempdir::TempDir::new("salt-agreement");
    seed(&dir, OLD);

    let paths = RekeyPaths::new(&dir.db());
    assert!(
        paths.salt.exists(),
        "the store's salt sidecar must be at the path the rekey expects"
    );
}
