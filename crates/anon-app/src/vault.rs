//! The user-held database passphrase (gap-closure plan Gap 2).
//!
//! # What this replaces
//!
//! Before this module the database key came from `db.passphrase`: 32 random bytes
//! generated on first launch and stored in the clear beside the database. That made the
//! at-rest encryption decorative — anyone who copied the data directory got the
//! passphrase and the database together. The README said so, but a documented gap is
//! still a gap.
//!
//! Now the passphrase is the user's. It is never written to disk in any form. The only
//! thing persisted is the Argon2id-derived key's *salt*, which is not secret.
//!
//! # The three states a launch can be in
//!
//! ```text
//! Fresh install      no database, no marker        -> setup screen
//! Existing install   database + db.passphrase      -> migrate, then unlock
//! Normal launch      database, no db.passphrase    -> unlock screen
//! ```
//!
//! [`VaultState`] is that decision, computed once at startup before any window opens.
//! Getting it wrong in either direction is bad: treating a fresh install as "locked"
//! would ask a new user for a passphrase to a database that does not exist, and treating
//! an existing install as "fresh" would create a second database and lose the first.
//!
//! # Why the migration is a separate step from the unlock
//!
//! An existing install's database is encrypted with the machine-held passphrase. The user
//! does not know that passphrase — it was never shown to them. So the migration cannot be
//! "unlock, then rekey": there is nothing to unlock *with*. Instead the app reads the
//! machine-held passphrase itself, uses it as the old key, and rekeys to the passphrase
//! the user just chose. That is the one moment the machine-held secret is used, and it is
//! deleted immediately afterwards.
//!
//! # The honest cost
//!
//! This removes "starts without a login". Every launch now needs the passphrase. That is
//! a real usability regression and the README says so in the same breath as the security
//! improvement — a user who is not told will be surprised at the worst moment, which is
//! the one time they cannot look it up.
//!
//! # What this does not protect against
//!
//! A user-held passphrase protects the database **at rest**: a copied disk, a stolen
//! backup, a forensic image. It does not protect against malware running as the user while
//! the app is unlocked, because at that point the key is in memory by necessity. That
//! caveat stays in the README; only the "the passphrase sits next to the database" caveat
//! goes away.

use anon_core::escrow::{assess_passphrase, PassphraseAssessment, MIN_PASSPHRASE_CHARS};
use anon_storage::rekey::{rekey, resume, RekeyPaths, RekeyReport};
use anon_storage::{Argon2Params, StorageError, Store};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The name of the machine-held passphrase file this module retires.
///
/// Kept as a constant so the migration and the "is this an existing install?" check
/// cannot disagree about the filename.
pub const LEGACY_PASSPHRASE_FILE: &str = "db.passphrase";

/// The name of the database file.
pub const DATABASE_FILE: &str = "anon.db";

/// What a launch needs to do about the database passphrase.
///
/// Computed at startup from the files on disk. See the module docs for the three states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultState {
    /// No database exists. The user must choose a passphrase before one is created.
    FreshInstall,
    /// A database exists and is still encrypted with the machine-held passphrase.
    ///
    /// The user must choose a passphrase; the app then rekeys from the machine-held one.
    NeedsMigration,
    /// A database exists and is encrypted with a user passphrase. The user must unlock.
    Locked,
    /// A rekey was interrupted. The next launch must finish it before anything else.
    ///
    /// Carries the stage so the UI can say something honest rather than "please wait".
    InterruptedMigration {
        /// The stage the interrupted run reached, as a display string.
        stage: String,
    },
}

impl VaultState {
    /// Whether the app can start without asking the user for anything.
    ///
    /// Always `false` in this build: every state needs either a passphrase or a
    /// migration. Kept as a method so the call sites read as intent rather than as a
    /// literal `false`.
    pub fn can_start_unattended(&self) -> bool {
        false
    }

    /// Whether the user is being asked to *choose* a passphrase (rather than enter an
    /// existing one).
    pub fn is_setup(&self) -> bool {
        matches!(self, Self::FreshInstall | Self::NeedsMigration)
    }
}

/// Why a vault operation failed.
#[derive(Debug)]
pub enum VaultError {
    /// The passphrase did not open the database.
    ///
    /// Deliberately distinct from a generic storage error: the unlock screen must be able
    /// to say "wrong passphrase" rather than "storage error", because those two mean very
    /// different things to a user. A wrong passphrase is recoverable by trying again; a
    /// storage error may mean the file is damaged.
    WrongPassphrase,
    /// The chosen passphrase is too weak to accept.
    WeakPassphrase(PassphraseAssessment),
    /// The two passphrase fields did not match.
    Mismatch,
    /// The database could not be opened for a reason other than a wrong passphrase.
    Storage(StorageError),
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// The migration could not complete.
    Migration(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassphrase => write!(
                f,
                "That passphrase did not open the database. Check it and try again."
            ),
            Self::WeakPassphrase(a) => {
                write!(f, "That passphrase is too weak. {}", a.warnings.join(" "))
            }
            Self::Mismatch => write!(f, "The two passphrases did not match."),
            Self::Storage(e) => write!(f, "The database could not be opened: {e}"),
            Self::Io(e) => write!(f, "A file operation failed: {e}"),
            Self::Migration(m) => write!(f, "The passphrase migration failed: {m}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StorageError> for VaultError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The vault: the database path plus the passphrase policy.
///
/// Holds no passphrase. The passphrase arrives per call and is dropped when the call
/// returns — the vault is a set of rules about a file, not a secret store.
pub struct Vault {
    data_dir: PathBuf,
    params: Argon2Params,
}

impl Vault {
    /// Build a vault over a data directory.
    pub fn new(data_dir: impl Into<PathBuf>, params: Argon2Params) -> Self {
        Self {
            data_dir: data_dir.into(),
            params,
        }
    }

    /// The database path.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DATABASE_FILE)
    }

    /// The retired machine-held passphrase file's path.
    pub fn legacy_passphrase_path(&self) -> PathBuf {
        self.data_dir.join(LEGACY_PASSPHRASE_FILE)
    }

    /// Decide what this launch needs to do.
    ///
    /// Reads only filenames and the marker's stage — never a passphrase. Called before
    /// any window opens, so the UI can be routed to setup or unlock without first
    /// attempting to open a database it cannot open.
    pub fn state(&self) -> VaultState {
        let paths = RekeyPaths::new(&self.db_path());

        // An interrupted migration takes precedence over everything: the database may be
        // mid-swap, so neither "fresh" nor "locked" describes it accurately.
        if let Ok(Some(marker)) = paths.read_marker() {
            return VaultState::InterruptedMigration {
                stage: marker.stage.as_str().to_string(),
            };
        }

        if !self.db_path().exists() {
            return VaultState::FreshInstall;
        }

        if self.legacy_passphrase_path().exists() {
            return VaultState::NeedsMigration;
        }

        VaultState::Locked
    }

    /// Assess a candidate passphrase without storing anything.
    ///
    /// The setup screen calls this as the user types so the strength hint is live. It is
    /// the same assessment the escrow export uses, so there is one policy, not two.
    pub fn assess(&self, passphrase: &str) -> PassphraseAssessment {
        assess_passphrase(passphrase)
    }

    /// Whether a candidate passphrase is acceptable for the database.
    ///
    /// Stricter than [`PassphraseAssessment::is_acceptable`] in one way: the database
    /// passphrase is the *only* thing protecting the message history, whereas the escrow
    /// passphrase protects an artifact the user can re-export. So this requires the
    /// minimum length *and* refuses a passphrase the assessment flags as a well-known
    /// weak one. A long-but-obvious passphrase is not accepted here even though the
    /// escrow flow would warn and proceed.
    pub fn is_acceptable(&self, passphrase: &str) -> bool {
        // Delegated to the assessment so the UI's live hint and this check cannot
        // drift apart. They previously did: the hint coloured its bar from entropy
        // alone while this rejected on warning *text*, so a passphrase could show a
        // green bar and still be refused.
        assess_passphrase(passphrase).is_acceptable_for_vault()
    }

    /// Create a new database with a user-chosen passphrase.
    ///
    /// Only valid in [`VaultState::FreshInstall`]. Refuses if a database already exists:
    /// creating a second one would silently orphan the first, and the user would see an
    /// empty app with no explanation.
    pub fn create(&self, passphrase: &str, confirm: &str) -> Result<Store, VaultError> {
        if passphrase != confirm {
            return Err(VaultError::Mismatch);
        }
        if !self.is_acceptable(passphrase) {
            return Err(VaultError::WeakPassphrase(assess_passphrase(passphrase)));
        }
        if self.db_path().exists() {
            return Err(VaultError::Migration(
                "a database already exists; refusing to create a second one".to_string(),
            ));
        }

        std::fs::create_dir_all(&self.data_dir)?;
        let store = Store::open(&self.db_path(), passphrase, self.config())?;
        Ok(store)
    }

    /// Open an existing database with the user's passphrase.
    ///
    /// Maps a failed open to [`VaultError::WrongPassphrase`] so the unlock screen can say
    /// the right thing. `Store::open` deliberately collapses "wrong key" and "corrupt
    /// file" into one opaque error to avoid helping an attacker; this layer re-labels it
    /// for the *user's* benefit without exposing which of the two it was. The message
    /// says "check it and try again", which is the correct action either way.
    pub fn unlock(&self, passphrase: &str) -> Result<Store, VaultError> {
        if !self.db_path().exists() {
            return Err(VaultError::Migration(
                "there is no database to unlock".to_string(),
            ));
        }
        match Store::open(&self.db_path(), passphrase, self.config()) {
            Ok(store) => Ok(store),
            Err(StorageError::OpenFailed) => Err(VaultError::WrongPassphrase),
            Err(e) => Err(VaultError::Storage(e)),
        }
    }

    /// Migrate an existing install from the machine-held passphrase to a user passphrase.
    ///
    /// # What this does with the machine-held secret
    ///
    /// Reads it, uses it as the old key for the rekey, and deletes the file. It is never
    /// logged, never returned, and never crosses the IPC boundary. The read is wrapped in
    /// `Zeroizing` so the buffer is wiped when the function returns.
    ///
    /// # Ordering
    ///
    /// The rekey runs *first* and the legacy file is deleted *after* it succeeds. If the
    /// deletion ran first and the rekey then failed, the database would be unopenable —
    /// the old key would be gone and the new key would not be in place. This ordering is
    /// the difference between a failed migration and a destroyed install.
    pub fn migrate(
        &self,
        new_passphrase: &str,
        confirm: &str,
    ) -> Result<(Store, RekeyReport), VaultError> {
        if new_passphrase != confirm {
            return Err(VaultError::Mismatch);
        }
        if !self.is_acceptable(new_passphrase) {
            return Err(VaultError::WeakPassphrase(assess_passphrase(
                new_passphrase,
            )));
        }

        let legacy_path = self.legacy_passphrase_path();
        if !legacy_path.exists() {
            return Err(VaultError::Migration(
                "there is no machine-held passphrase to migrate from".to_string(),
            ));
        }

        // Read the machine-held passphrase. Zeroizing so the buffer is wiped on return.
        let old_passphrase: Zeroizing<String> = Zeroizing::new(
            std::fs::read_to_string(&legacy_path)
                .map_err(|e| VaultError::Migration(format!("could not read the old key: {e}")))?
                .trim()
                .to_string(),
        );
        if old_passphrase.is_empty() {
            return Err(VaultError::Migration(
                "the machine-held passphrase file is empty".to_string(),
            ));
        }

        // Rekey. This is the resumable copy-then-swap path, so a crash here leaves the
        // original intact and the next launch finishes the job.
        let report = rekey(
            &self.db_path(),
            old_passphrase.as_str(),
            new_passphrase,
            self.params,
        )
        .map_err(|e| VaultError::Migration(e.to_string()))?;

        // Only now is the old key safe to delete: the database is encrypted with the new
        // one and has been verified to open with it.
        delete_legacy_passphrase(&legacy_path)?;

        let store = self.unlock(new_passphrase)?;
        Ok((store, report))
    }

    /// Finish an interrupted migration.
    ///
    /// Called at startup when [`Vault::state`] reports
    /// [`VaultState::InterruptedMigration`]. Needs both passphrases because the marker
    /// does not record which key the live file currently has — at the `swapped` stage it
    /// is the new one, before that it is the old one. The rekey module resolves that by
    /// stage, so this only has to supply both.
    pub fn resume_migration(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<Option<RekeyReport>, VaultError> {
        let report = resume(&self.db_path(), old_passphrase, new_passphrase, self.params)
            .map_err(|e| VaultError::Migration(e.to_string()))?;

        if report.is_some() {
            // The migration completed, so the machine-held secret is no longer needed.
            let legacy = self.legacy_passphrase_path();
            if legacy.exists() {
                delete_legacy_passphrase(&legacy)?;
            }
        }
        Ok(report)
    }

    /// Whether a migration is in progress.
    pub fn migration_in_progress(&self) -> bool {
        RekeyPaths::new(&self.db_path()).in_progress()
    }

    fn config(&self) -> anon_storage::StoreConfig {
        anon_storage::StoreConfig {
            params: self.params,
            purge_on_open: true,
            vacuum_after_purge: true,
        }
    }
}

/// Delete the machine-held passphrase file.
///
/// Overwritten with zeroes first, best-effort. That is *not* a secure erase on flash
/// storage — wear levelling means the original blocks may survive — so the code says so
/// rather than implying more. What makes this safe is that the database is now encrypted
/// with a key the file never contained; the overwrite is a courtesy, not the control.
fn delete_legacy_passphrase(path: &Path) -> Result<(), VaultError> {
    if let Ok(metadata) = std::fs::metadata(path) {
        let len = metadata.len() as usize;
        let _ = std::fs::write(path, vec![b'0'; len]);
    }
    std::fs::remove_file(path)?;
    Ok(())
}

/// The minimum passphrase length, re-exported so the UI and the policy cannot disagree.
pub const MIN_CHARS: usize = MIN_PASSPHRASE_CHARS;

#[cfg(test)]
mod tests {
    use super::*;

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new(tag: &str) -> Self {
                let mut p = std::env::temp_dir();
                let unique = format!(
                    "anon-app-vault-{tag}-{}-{:?}",
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

    const GOOD: &str = "Tr0ub4dor&3-feldspar-quixotic";

    fn vault(dir: &tempdir::TempDir) -> Vault {
        Vault::new(dir.path(), Argon2Params::test_fast())
    }

    #[test]
    fn a_fresh_install_is_reported_as_fresh() {
        let dir = tempdir::TempDir::new("fresh");
        assert_eq!(vault(&dir).state(), VaultState::FreshInstall);
    }

    #[test]
    fn a_created_database_is_then_locked() {
        // The whole point: after setup, the next launch must ask for the passphrase
        // rather than starting unattended.
        let dir = tempdir::TempDir::new("locked");
        let v = vault(&dir);
        v.create(GOOD, GOOD).expect("create");
        assert_eq!(v.state(), VaultState::Locked);
    }

    #[test]
    fn a_legacy_install_is_reported_as_needing_migration() {
        let dir = tempdir::TempDir::new("legacy");
        let v = vault(&dir);

        // Simulate an existing install: a database plus the machine-held passphrase.
        let legacy = "00112233445566778899aabbccddeeff";
        Store::open(&v.db_path(), legacy, v.config()).expect("open");
        std::fs::write(v.legacy_passphrase_path(), legacy).expect("write legacy");

        assert_eq!(v.state(), VaultState::NeedsMigration);
    }

    #[test]
    fn a_weak_passphrase_is_refused_at_creation() {
        let dir = tempdir::TempDir::new("weak");
        let v = vault(&dir);

        let err = v.create("12345678", "12345678").expect_err("too short");
        assert!(matches!(err, VaultError::WeakPassphrase(_)));
        assert!(!v.db_path().exists(), "no database must be created");
    }

    #[test]
    fn a_long_but_obvious_passphrase_is_refused() {
        // "passwordpassword" is 16 characters — long enough by length alone — but it is
        // on the deny-list. The database passphrase is the only thing protecting the
        // message history, so the deny-list is enforced here rather than merely warned
        // about as it is in the escrow flow.
        let dir = tempdir::TempDir::new("obvious");
        let v = vault(&dir);
        assert!(!v.is_acceptable("passwordpassword"));
        assert!(v.create("passwordpassword", "passwordpassword").is_err());
    }

    #[test]
    fn a_repeated_pattern_is_refused() {
        let dir = tempdir::TempDir::new("pattern");
        let v = vault(&dir);
        assert!(!v.is_acceptable("abababababababab"));
    }

    #[test]
    fn a_strong_passphrase_is_accepted() {
        let dir = tempdir::TempDir::new("strong");
        let v = vault(&dir);
        assert!(v.is_acceptable(GOOD));
    }

    #[test]
    fn the_live_hint_and_the_vault_agree_on_every_candidate() {
        // The regression this guards: the setup screen coloured its strength bar from
        // entropy alone while `is_acceptable` rejected on warning text, so a passphrase
        // could show a green bar and still be refused. Both now derive from the same
        // assessment, and this asserts they cannot drift apart again.
        let dir = tempdir::TempDir::new("agree");
        let v = vault(&dir);

        let candidates = [
            "",
            "short",
            "123456789012",
            "passwordpassword",
            "abababababababab",
            "abcdefghijklmnop",
            "correcthorsebatterystaple",
            GOOD,
            "Tr0ub4dor&3-horse-battery",
        ];

        for candidate in candidates {
            let assessment = v.assess(candidate);
            assert_eq!(
                v.is_acceptable(candidate),
                assessment.is_acceptable_for_vault(),
                "the vault and the assessment disagree about {candidate:?}"
            );
        }
    }

    #[test]
    fn a_high_entropy_but_obvious_passphrase_is_not_acceptable() {
        // The exact shape of the reported bug: long enough to score well on entropy,
        // but on the deny-list. It must be reported as unacceptable so the bar cannot
        // be green.
        let dir = tempdir::TempDir::new("entropy-trap");
        let v = vault(&dir);
        let assessment = v.assess("passwordpassword");

        assert!(
            assessment.estimated_entropy_bits >= 60,
            "this candidate is meant to score well on entropy, got {}",
            assessment.estimated_entropy_bits
        );
        assert!(assessment.is_well_known_weak);
        assert!(!assessment.is_acceptable_for_vault());
        assert!(!v.is_acceptable("passwordpassword"));
    }

    #[test]
    fn mismatched_confirmation_is_refused() {
        let dir = tempdir::TempDir::new("mismatch");
        let v = vault(&dir);
        let err = v
            .create(GOOD, "something else entirely")
            .expect_err("mismatch");
        assert!(matches!(err, VaultError::Mismatch));
        assert!(!v.db_path().exists());
    }

    #[test]
    fn creating_over_an_existing_database_is_refused() {
        // Creating a second database would silently orphan the first and the user would
        // see an empty app with no explanation.
        let dir = tempdir::TempDir::new("overwrite");
        let v = vault(&dir);
        v.create(GOOD, GOOD).expect("first create");
        let err = v.create(GOOD, GOOD).expect_err("second create");
        assert!(matches!(err, VaultError::Migration(_)));
    }

    #[test]
    fn the_right_passphrase_unlocks_and_the_wrong_one_is_distinguishable() {
        let dir = tempdir::TempDir::new("unlock");
        let v = vault(&dir);
        v.create(GOOD, GOOD).expect("create");

        v.unlock(GOOD).expect("the right passphrase opens it");

        let err = v
            .unlock("not the passphrase")
            .expect_err("wrong passphrase");
        assert!(
            matches!(err, VaultError::WrongPassphrase),
            "a wrong passphrase must be distinguishable from a storage error, \
             so the unlock screen can say the right thing; got {err:?}"
        );
    }

    #[test]
    fn unlocking_a_nonexistent_database_is_an_error_not_a_creation() {
        // A typo in the data directory must not silently create a new empty database.
        let dir = tempdir::TempDir::new("no-db");
        let v = vault(&dir);
        assert!(v.unlock(GOOD).is_err());
        assert!(!v.db_path().exists(), "unlock must never create a database");
    }

    #[test]
    fn migration_rekeys_and_deletes_the_machine_held_secret() {
        let dir = tempdir::TempDir::new("migrate");
        let v = vault(&dir);

        // An existing install: database encrypted with the machine-held passphrase.
        let legacy = "00112233445566778899aabbccddeeff";
        {
            let s = Store::open(&v.db_path(), legacy, v.config()).expect("open");
            s.insert_group(&anon_storage::GroupRow {
                group_id: b"existing-group".to_vec(),
                name: Some("survivors".into()),
                created_at: 1_700_000_000,
                epoch: 7,
            })
            .expect("insert");
        }
        std::fs::write(v.legacy_passphrase_path(), legacy).expect("write legacy");

        let (store, report) = v.migrate(GOOD, GOOD).expect("migrate");
        assert!(!report.resumed, "a first migration is not a resume");

        // The data survived.
        let groups = store.groups().expect("list groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name.as_deref(), Some("survivors"));
        assert_eq!(groups[0].epoch, 7);

        // The machine-held secret is gone. This is the exit criterion.
        assert!(
            !v.legacy_passphrase_path().exists(),
            "the machine-held passphrase file must be deleted after migration"
        );

        // The old key no longer opens the database; the new one does.
        assert!(Store::open(&v.db_path(), legacy, v.config()).is_err());
        Store::open(&v.db_path(), GOOD, v.config()).expect("new passphrase opens");
    }

    #[test]
    fn a_failed_migration_leaves_the_legacy_secret_in_place() {
        // If the rekey fails, the old key must still be there — otherwise the database
        // would be unopenable: the old key gone and the new key not in place.
        let dir = tempdir::TempDir::new("failed-migrate");
        let v = vault(&dir);

        let legacy = "00112233445566778899aabbccddeeff";
        Store::open(&v.db_path(), legacy, v.config()).expect("open");
        std::fs::write(v.legacy_passphrase_path(), legacy).expect("write legacy");

        // A weak new passphrase fails before the rekey starts.
        let err = v.migrate("12345678", "12345678").expect_err("weak");
        assert!(matches!(err, VaultError::WeakPassphrase(_)));

        assert!(
            v.legacy_passphrase_path().exists(),
            "the old key must survive a refused migration"
        );
        Store::open(&v.db_path(), legacy, v.config())
            .expect("database still opens with the old key");
    }

    #[test]
    fn a_migration_with_a_wrong_legacy_passphrase_does_not_destroy_the_database() {
        // The legacy file could be corrupt or truncated. The rekey must fail cleanly and
        // leave the database openable — with whatever key actually works.
        let dir = tempdir::TempDir::new("bad-legacy");
        let v = vault(&dir);

        let real = "00112233445566778899aabbccddeeff";
        Store::open(&v.db_path(), real, v.config()).expect("open");
        // The file says something else entirely.
        std::fs::write(
            v.legacy_passphrase_path(),
            "ffeeddccbbaa99887766554433221100",
        )
        .expect("write wrong legacy");

        let err = v.migrate(GOOD, GOOD).expect_err("wrong old key");
        assert!(matches!(err, VaultError::Migration(_)));

        // The database is untouched and still opens with its real key.
        Store::open(&v.db_path(), real, v.config()).expect("database still opens");
    }

    #[test]
    fn an_interrupted_migration_is_reported_before_anything_else() {
        // A marker on disk means the database may be mid-swap. Neither "fresh" nor
        // "locked" describes that, so the state must say so.
        let dir = tempdir::TempDir::new("interrupted");
        let v = vault(&dir);
        v.create(GOOD, GOOD).expect("create");

        let paths = RekeyPaths::new(&v.db_path());
        std::fs::write(
            &paths.marker,
            "stage=copied\nold_salt=00112233445566778899aabbccddeeff\nnew_salt=ffeeddccbbaa99887766554433221100\n",
        )
        .expect("write marker");

        match v.state() {
            VaultState::InterruptedMigration { stage } => assert_eq!(stage, "copied"),
            other => panic!("expected an interrupted migration, got {other:?}"),
        }
    }

    #[test]
    fn no_state_allows_an_unattended_start() {
        // The security property this whole module exists for. If any state returned
        // true, the app would start without the user's passphrase and the at-rest
        // guarantee would be decorative again.
        for state in [
            VaultState::FreshInstall,
            VaultState::NeedsMigration,
            VaultState::Locked,
            VaultState::InterruptedMigration {
                stage: "copied".into(),
            },
        ] {
            assert!(
                !state.can_start_unattended(),
                "{state:?} must not allow an unattended start"
            );
        }
    }

    #[test]
    fn setup_states_are_distinguished_from_unlock_states() {
        // The UI routes to "choose a passphrase" or "enter your passphrase" based on
        // this. Getting it backwards would ask a returning user to choose a new
        // passphrase, which reads as "your database is gone".
        assert!(VaultState::FreshInstall.is_setup());
        assert!(VaultState::NeedsMigration.is_setup());
        assert!(!VaultState::Locked.is_setup());
        assert!(!VaultState::InterruptedMigration {
            stage: "copied".into()
        }
        .is_setup());
    }

    #[test]
    fn the_legacy_file_name_is_the_one_the_old_code_used() {
        // The migration reads this file. If the name drifted, every existing install
        // would be misclassified as "locked" and the user would be asked for a
        // passphrase they were never given.
        assert_eq!(LEGACY_PASSPHRASE_FILE, "db.passphrase");
        assert_eq!(DATABASE_FILE, "anon.db");
    }
}
