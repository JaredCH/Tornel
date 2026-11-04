//! Migration against a **real** existing install's database.
//!
//! # Why this test exists separately from the vault unit tests
//!
//! The unit tests build their own database with `Store::open`, so they prove the logic
//! works on a database this code created. They do not prove it works on a database the
//! *previous build* created — which is the only kind that exists in the field. A real
//! install has a 256 KiB SQLCipher file with the schema already populated and a
//! `db.passphrase` written by the old `database_passphrase` function.
//!
//! This test runs against a copy of exactly that, so the migration path is exercised
//! against the artifact it will actually meet.
//!
//! # Opt-in
//!
//! Gated on `ANON_REAL_MIGRATION_DIR` pointing at a directory containing `anon.db`,
//! `anon.db.salt`, and `db.passphrase`. It is not run by default because it needs a real
//! install to copy from, and because it takes a few seconds (Argon2id at production
//! parameters, twice).
//!
//! Run it with:
//!
//! ```text
//! set ANON_REAL_MIGRATION_DIR=%APPDATA%\invalid.example.anon
//! cargo test -p anon-app --test real_migration -- --ignored --nocapture
//! ```

use anon_app::vault::{Vault, VaultState};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::{Path, PathBuf};

/// The new passphrase the test migrates to. Fixed so a failed run leaves a database the
/// next run can open.
///
/// Deliberately does **not** contain the word "passphrase": the vault's deny-list rejects
/// any candidate containing it, and a test that tripped its own guard would be testing the
/// guard rather than the migration.
const NEW_PASSPHRASE: &str = "Quixotic-Feldspar-9f3a-Vellum";

fn real_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("ANON_REAL_MIGRATION_DIR")?;
    let path = PathBuf::from(dir);
    if path.join("anon.db").exists() {
        Some(path)
    } else {
        None
    }
}

/// Copy the real install into a scratch directory so the test never touches the original.
fn scratch_copy(source: &Path, tag: &str) -> PathBuf {
    let mut dst = std::env::temp_dir();
    dst.push(format!(
        "anon-real-migration-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dst).expect("create scratch dir");

    for name in ["anon.db", "anon.db.salt", "db.passphrase"] {
        let from = source.join(name);
        if from.exists() {
            std::fs::copy(&from, dst.join(name)).expect("copy file");
        }
    }
    dst
}

fn config() -> StoreConfig {
    StoreConfig {
        params: Argon2Params::mobile_default(),
        purge_on_open: false,
        vacuum_after_purge: false,
    }
}

#[test]
#[ignore = "needs ANON_REAL_MIGRATION_DIR pointing at a real install"]
fn a_real_install_migrates_to_a_user_passphrase() {
    let Some(source) = real_dir() else {
        eprintln!("ANON_REAL_MIGRATION_DIR is not set; skipping");
        return;
    };

    let dir = scratch_copy(&source, "migrate");
    let vault = Vault::new(&dir, Argon2Params::mobile_default());

    // The copy must be classified as needing migration — that is the whole premise. If it
    // came back as `Locked`, the legacy file name drifted and every existing install would
    // be misclassified.
    assert_eq!(
        vault.state(),
        VaultState::NeedsMigration,
        "a real install with db.passphrase must be classified as needing migration"
    );

    // Read the machine-held passphrase so we can prove it stops working afterwards.
    let old_passphrase = std::fs::read_to_string(dir.join("db.passphrase"))
        .expect("read legacy")
        .trim()
        .to_string();

    // Count what is in the real database before migrating, so we can prove nothing was
    // lost. This is the assertion that matters: a migration that "succeeds" while dropping
    // rows is worse than one that fails.
    let before = {
        let store = Store::open(&dir.join("anon.db"), &old_passphrase, config())
            .expect("open the real database with its machine-held key");
        store.table_row_counts().expect("count rows")
    };
    eprintln!("row counts before migration: {before:?}");

    // Migrate.
    let (store, report) = vault
        .migrate(NEW_PASSPHRASE, NEW_PASSPHRASE)
        .expect("migrate a real install");
    eprintln!("row counts after migration: {:?}", report.row_counts);

    // Every table's row count must be identical. A migration that loses rows would show up
    // here as a smaller count in some table.
    assert_eq!(
        before, report.row_counts,
        "the migration must not change any table's row count"
    );

    // The data is readable through the store the migration returned.
    let groups = store.groups().expect("list groups");
    eprintln!("groups after migration: {}", groups.len());

    // The machine-held secret is gone.
    assert!(
        !dir.join("db.passphrase").exists(),
        "the machine-held passphrase file must be deleted"
    );

    // The old key no longer opens the database; the new one does.
    assert!(
        Store::open(&dir.join("anon.db"), &old_passphrase, config()).is_err(),
        "the machine-held passphrase must be rejected after migration"
    );
    Store::open(&dir.join("anon.db"), NEW_PASSPHRASE, config())
        .expect("the user passphrase opens the migrated database");

    // The vault now reports Locked, not NeedsMigration: the next launch asks for the
    // passphrase rather than offering to migrate again.
    assert_eq!(vault.state(), VaultState::Locked);

    // No rekey artifacts left behind.
    for suffix in [".rekey-tmp", ".rekey-old", ".rekey-state"] {
        let mut p = dir.join("anon.db").as_os_str().to_owned();
        p.push(suffix);
        assert!(
            !PathBuf::from(p).exists(),
            "the rekey artifact {suffix} must be cleaned up"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "needs ANON_REAL_MIGRATION_DIR pointing at a real install"]
fn a_real_install_migration_resumes_after_a_crash_before_the_copy() {
    // The property that matters most for a real install: a crash mid-migration must not
    // lose the user's history.
    //
    // `prepared` is the one stage reachable without artifacts: the marker is written
    // *before* the copy begins, so a crash there leaves a marker and nothing else. That is
    // a genuine crash point, and it is the one this test reproduces against the real
    // database.
    //
    // The later stages (`copied`, `verified`, `swapped`) each require a real `.rekey-tmp`
    // or `.rekey-old` artifact to be meaningful. Fabricating a marker without the artifact
    // it describes is not a crash simulation — it is a corrupt state, and the state machine
    // correctly refuses it. Those stages are covered by `anon-storage/tests/rekey.rs`,
    // which can construct the artifacts directly because it owns the rekey internals.
    let Some(source) = real_dir() else {
        eprintln!("ANON_REAL_MIGRATION_DIR is not set; skipping");
        return;
    };

    let dir = scratch_copy(&source, "prepared");
    let vault = Vault::new(&dir, Argon2Params::mobile_default());
    let old_passphrase = std::fs::read_to_string(dir.join("db.passphrase"))
        .expect("read legacy")
        .trim()
        .to_string();

    let before = {
        let store = Store::open(&dir.join("anon.db"), &old_passphrase, config()).expect("open");
        store.table_row_counts().expect("count")
    };

    // Reproduce the on-disk state a crash at `prepared` leaves: a marker naming the old and
    // new salts, and no copy.
    let paths = anon_storage::RekeyPaths::new(&dir.join("anon.db"));
    let marker = anon_storage::RekeyMarker {
        stage: anon_storage::RekeyStage::Prepared,
        old_salt: hex_of(&paths.salt),
        new_salt: "00112233445566778899aabbccddeeff".to_string(),
    };
    std::fs::write(&paths.marker, marker.to_text()).expect("write marker");
    assert!(
        !paths.tmp.exists(),
        "the premise is that no copy exists at the prepared stage"
    );

    // Resume: this must complete the whole migration from the marker.
    let report = vault
        .resume_migration(&old_passphrase, NEW_PASSPHRASE)
        .expect("resume")
        .expect("a marker was present");
    assert!(report.resumed, "a marker was present, so this is a resume");

    let after = {
        let store = Store::open(&dir.join("anon.db"), NEW_PASSPHRASE, config())
            .expect("the new passphrase opens after resuming");
        store.table_row_counts().expect("count")
    };
    assert_eq!(
        before, after,
        "resuming from the prepared stage must not change any row count"
    );

    // The marker is gone, so the next launch asks for the passphrase instead of resuming.
    assert!(!paths.marker.exists(), "the marker must be cleaned up");
    assert!(!paths.tmp.exists(), "the copy must be cleaned up");
    assert!(
        !paths.old.exists(),
        "the retired original must be cleaned up"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn hex_of(path: &Path) -> String {
    std::fs::read(path)
        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
        .unwrap_or_default()
}
