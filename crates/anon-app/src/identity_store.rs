//! Persisting the identity seed and the database passphrase.
//!
//! # The seed now lives in the OS keychain (`plan.md` §2.3)
//!
//! [`crate::keychain`] holds the seed in Windows Credential Manager / macOS Keychain /
//! Linux Secret Service. This module owns the *policy* around it: create on first
//! launch, migrate a legacy plaintext file, and refuse to start when the keychain is
//! unavailable.
//!
//! # Migration from `identity.seed`
//!
//! Builds before this one wrote the seed to `identity.seed` beside the database. That
//! file is migrated on first launch: the seed is written to the keychain, **read back
//! and compared byte-for-byte**, and only then is the file deleted. A mismatch or a
//! keychain error leaves the file in place and fails loudly — two identities or a
//! silently discarded identity are both worse than a noisy error.
//!
//! # Seed conflicts are fatal
//!
//! If the keychain already holds a seed *and* a legacy file exists with a different
//! value, that is two identities for one install. The app refuses to choose: picking
//! either would discard a contact code the user may have shared. The message tells the
//! user which files are involved.
//!
//! # What is still true
//!
//! * The seed is **never** written to the database, a log, or the webview.
//! * The seed is held in a `Zeroizing` buffer so it is wiped when dropped.
//! * The escrow artifact (`plan.md` §2.5) remains the *supported* way to move an
//!   identity between devices; the keychain is only the local cache.
//!
//! # Why the database passphrase is still machine-local
//!
//! Closing this one is Gap 2 of the gap-closure plan, not this module's job. Until then
//! a random per-install secret is stored beside the database so the app can start
//! without a login screen. The *cryptography* is unchanged — Argon2id still derives the
//! key, SQLCipher still encrypts the file — only the input is machine-held. That means
//! the at-rest encryption protects against a stolen database file but **not** against
//! an attacker who has the whole data directory. The README says so.

use crate::keychain::{KeychainBackend, KeychainError, OsKeychain, SEED_LEN};
use anon_core::IdentityKeys;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Load the identity from the OS keychain, creating one on first launch.
///
/// Uses [`OsKeychain`]. Call [`load_or_create_with`] to supply a different backend —
/// that is how the tests exercise the migration and failure paths without touching the
/// real credential store.
///
/// Returns the keys, which are not `Clone` and not `Debug`-printable in terms of
/// secrets (`anon_core::IdentityKeys` enforces that).
pub fn load_or_create(data_dir: &Path) -> Result<IdentityKeys, Box<dyn std::error::Error>> {
    load_or_create_with(data_dir, &OsKeychain::for_data_dir(data_dir))
}

/// Load the identity using a caller-supplied keychain backend.
///
/// # Sequence
///
/// 1. Read whatever the keychain holds.
/// 2. If a legacy `identity.seed` file also exists, compare. Equal → delete the file.
///    Different → refuse, naming both. This is the only case where the app stops with
///    the seed still on disk, and it stops deliberately.
/// 3. Keychain empty + file present → migrate (store, verify, then delete).
/// 4. Both empty → generate, store, verify.
///
/// Every path that writes the keychain reads it back before trusting it. `set_secret`
/// returning `Ok` is not evidence that the value is retrievable — a locked or read-only
/// store can accept a write and hand back nothing.
pub fn load_or_create_with(
    data_dir: &Path,
    keychain: &dyn KeychainBackend,
) -> Result<IdentityKeys, Box<dyn std::error::Error>> {
    let file = seed_path(data_dir);

    // Fail before doing anything if the store is not usable. Falling back to a file
    // would convert a documented gap into an undocumented one.
    if !keychain.available() {
        return Err(Box::new(KeychainError::Unavailable(
            "the platform credential store could not be initialised".to_string(),
        )));
    }

    let from_keychain = keychain.load()?;
    let from_file = read_legacy_seed(&file)?;

    match (from_keychain, from_file) {
        // Both present: they must agree.
        (Some(stored), Some(legacy)) => {
            if stored.as_ref() != legacy.as_ref() {
                return Err(format!(
                    "two different identities were found for this install. The OS keychain \
                     holds one seed and the legacy file {} holds another. Refusing to choose: \
                     picking either would discard a contact code you may have shared. \
                     Restore the one you want into the OS keychain, then delete the file.",
                    file.display()
                )
                .into());
            }
            delete_legacy_seed(&file)?;
            Ok(IdentityKeys::from_seed(&stored))
        }

        // Keychain only: the normal case after migration.
        (Some(stored), None) => Ok(IdentityKeys::from_seed(&stored)),

        // Legacy file only: migrate. Store, read back, compare, then delete.
        (None, Some(legacy)) => {
            keychain.store(&legacy)?;

            // Verify the write landed before destroying the only other copy.
            let readback = keychain.load()?.ok_or_else(|| {
                KeychainError::Operation(
                    "the keychain accepted the seed but returned nothing on read-back; \
                     keeping the legacy file"
                        .to_string(),
                )
            })?;

            if readback.as_ref() != legacy.as_ref() {
                return Err(KeychainError::Operation(
                    "the keychain returned a different seed than it was given; keeping the \
                     legacy file"
                        .to_string(),
                )
                .into());
            }

            delete_legacy_seed(&file)?;
            Ok(IdentityKeys::from_seed(&legacy))
        }

        // First launch: generate, store, verify.
        (None, None) => {
            let keys = IdentityKeys::generate()?;
            let seed = keys.to_escrow_seed();

            keychain.store(&seed)?;

            let readback = keychain.load()?.ok_or_else(|| {
                KeychainError::Operation(
                    "the keychain accepted a new seed but returned nothing on read-back"
                        .to_string(),
                )
            })?;
            if readback.as_ref() != seed.as_ref() {
                return Err(KeychainError::Operation(
                    "the keychain returned a different seed than it was given".to_string(),
                )
                .into());
            }

            Ok(keys)
        }
    }
}

/// Read and decode the legacy `identity.seed` file, if it exists.
///
/// Returns `Ok(None)` when there is no file. A malformed file is an error rather than
/// `None`: treating it as absent would cause a fresh identity to be minted, silently
/// destroying the user's contact code.
fn read_legacy_seed(
    path: &Path,
) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }

    let hex = std::fs::read_to_string(path)?;
    let bytes = decode_hex(hex.trim()).ok_or_else(|| {
        format!(
            "the legacy seed file {} is not valid hexadecimal; refusing to replace it",
            path.display()
        )
    })?;
    if bytes.len() != SEED_LEN {
        return Err(format!(
            "the legacy seed file {} holds {} bytes, expected {SEED_LEN}",
            path.display(),
            bytes.len()
        )
        .into());
    }

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

/// Delete the legacy seed file after a verified migration.
///
/// The file is overwritten with zeroes first, best-effort. That is *not* a secure erase
/// on flash storage — wear levelling means the original blocks may survive — so the code
/// says so rather than implying more. What makes this safe is that the seed is now in the
/// keychain; the overwrite is a courtesy, not the control.
fn delete_legacy_seed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(metadata) = std::fs::metadata(path) {
        let len = metadata.len() as usize;
        // Best-effort overwrite. Failure is not fatal: the seed is safely in the
        // keychain either way, and failing here would leave the app unable to start.
        let _ = std::fs::write(path, vec![b'0'; len]);
    }
    std::fs::remove_file(path)?;
    Ok(())
}

// NOTE: `database_passphrase` used to live here. It generated a random per-install
// secret and wrote it to `db.passphrase` beside the database, which made the at-rest
// encryption decorative: anyone who copied the data directory got the passphrase and the
// database together. Gap 2 replaced it with a user-held passphrase in
// [`crate::vault`], and the migration there deletes any `db.passphrase` file it finds.
//
// The function is deliberately *removed* rather than deprecated: leaving a callable
// "generate a machine-held passphrase" helper in the tree is an invitation to reintroduce
// the gap. The vault is the only way to obtain a database key now.

fn seed_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.seed")
}

/// Hex-encode bytes. Test-only: the production paths that needed it moved to
/// [`crate::vault`], and the tests below still build legacy seed files by hand.
#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::KeychainBackend;
    use std::sync::Mutex;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anon-app-idstore-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An in-memory keychain so these tests never touch the real credential store.
    ///
    /// Touching the real one would clobber a developer's actual identity, and would make
    /// the suite depend on a platform service being present.
    struct MemoryKeychain {
        seed: Mutex<Option<[u8; SEED_LEN]>>,
        available: bool,
    }

    impl MemoryKeychain {
        fn new() -> Self {
            Self {
                seed: Mutex::new(None),
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                seed: Mutex::new(None),
                available: false,
            }
        }

        fn with_seed(seed: [u8; SEED_LEN]) -> Self {
            Self {
                seed: Mutex::new(Some(seed)),
                available: true,
            }
        }

        fn peek(&self) -> Option<[u8; SEED_LEN]> {
            *self.seed.lock().unwrap()
        }
    }

    impl KeychainBackend for MemoryKeychain {
        fn available(&self) -> bool {
            self.available
        }
        fn store(&self, seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
            if !self.available {
                return Err(KeychainError::Unavailable("test backend".into()));
            }
            *self.seed.lock().unwrap() = Some(*seed);
            Ok(())
        }
        fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
            if !self.available {
                return Err(KeychainError::Unavailable("test backend".into()));
            }
            Ok(self.seed.lock().unwrap().map(Zeroizing::new))
        }
        fn delete(&self) -> Result<(), KeychainError> {
            *self.seed.lock().unwrap() = None;
            Ok(())
        }
    }

    fn write_legacy(dir: &Path, seed: &[u8; SEED_LEN]) {
        std::fs::write(dir.join("identity.seed"), hex_encode(seed)).unwrap();
    }

    // -- First launch ---------------------------------------------------------

    #[test]
    fn a_first_launch_generates_and_stores_a_seed() {
        let dir = temp_dir("first");
        let kc = MemoryKeychain::new();

        let keys = load_or_create_with(&dir, &kc).expect("create");
        let code = anon_core::ContactCode::encode(&keys.public()).unwrap();

        assert!(kc.peek().is_some(), "the seed must be in the keychain");
        assert!(
            !dir.join("identity.seed").exists(),
            "no plaintext seed file may be written"
        );
        assert!(!code.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_identity_is_created_once_and_reloaded_identically() {
        let dir = temp_dir("reload");
        let kc = MemoryKeychain::new();

        let first = load_or_create_with(&dir, &kc).expect("create");
        let code_first = anon_core::ContactCode::encode(&first.public()).unwrap();

        let second = load_or_create_with(&dir, &kc).expect("reload");
        let code_second = anon_core::ContactCode::encode(&second.public()).unwrap();

        assert_eq!(
            code_first, code_second,
            "reloading must yield the same identity, not a new one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Migration ------------------------------------------------------------

    #[test]
    fn a_legacy_seed_file_is_migrated_and_deleted() {
        let dir = temp_dir("migrate");
        let kc = MemoryKeychain::new();

        // A pre-existing install: seed on disk, nothing in the keychain.
        let original = [0x11u8; SEED_LEN];
        write_legacy(&dir, &original);
        let expected_code =
            anon_core::ContactCode::encode(&IdentityKeys::from_seed(&original).public()).unwrap();

        let keys = load_or_create_with(&dir, &kc).expect("migrate");
        let code = anon_core::ContactCode::encode(&keys.public()).unwrap();

        assert_eq!(code, expected_code, "the identity must not change");
        assert_eq!(
            kc.peek(),
            Some(original),
            "the seed must now be in the keychain"
        );
        assert!(
            !dir.join("identity.seed").exists(),
            "the legacy file must be deleted after a verified migration"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_migration_that_cannot_verify_keeps_the_legacy_file() {
        // A keychain that accepts a write but returns nothing on read-back. Deleting the
        // file here would destroy the only copy of the identity.
        struct LyingKeychain;
        impl KeychainBackend for LyingKeychain {
            fn available(&self) -> bool {
                true
            }
            fn store(&self, _seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
                Ok(())
            }
            fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
                Ok(None)
            }
            fn delete(&self) -> Result<(), KeychainError> {
                Ok(())
            }
        }

        let dir = temp_dir("lying");
        write_legacy(&dir, &[0x22u8; SEED_LEN]);

        let result = load_or_create_with(&dir, &LyingKeychain);
        assert!(result.is_err(), "an unverifiable migration must fail");
        assert!(
            dir.join("identity.seed").exists(),
            "the legacy file must survive a failed migration"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_migration_that_reads_back_a_different_seed_keeps_the_file() {
        struct SwappingKeychain;
        impl KeychainBackend for SwappingKeychain {
            fn available(&self) -> bool {
                true
            }
            fn store(&self, _seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
                Ok(())
            }
            fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
                // A different seed than was stored.
                Ok(Some(Zeroizing::new([0x99u8; SEED_LEN])))
            }
            fn delete(&self) -> Result<(), KeychainError> {
                Ok(())
            }
        }

        let dir = temp_dir("swapping");
        write_legacy(&dir, &[0x33u8; SEED_LEN]);

        assert!(load_or_create_with(&dir, &SwappingKeychain).is_err());
        assert!(
            dir.join("identity.seed").exists(),
            "a mismatched read-back must not delete the only good copy"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_conflicting_seed_is_fatal_and_names_the_file() {
        // Two identities for one install. Picking either would discard a contact code
        // the user may have shared, so the app refuses.
        let dir = temp_dir("conflict");
        let kc = MemoryKeychain::with_seed([0x44u8; SEED_LEN]);
        write_legacy(&dir, &[0x55u8; SEED_LEN]);

        let err = load_or_create_with(&dir, &kc).expect_err("conflict must be fatal");
        let text = err.to_string();
        assert!(
            text.contains("two different identities"),
            "the message must say what happened: {text}"
        );
        assert!(
            text.contains("identity.seed"),
            "the message must name the file involved: {text}"
        );
        assert!(
            dir.join("identity.seed").exists(),
            "a conflict must not delete anything"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_matching_seed_in_both_places_cleans_up_the_file() {
        // The benign version of the conflict: same seed, so the file is redundant.
        let dir = temp_dir("matching");
        let seed = [0x66u8; SEED_LEN];
        let kc = MemoryKeychain::with_seed(seed);
        write_legacy(&dir, &seed);

        let keys = load_or_create_with(&dir, &kc).expect("load");
        let expected =
            anon_core::ContactCode::encode(&IdentityKeys::from_seed(&seed).public()).unwrap();
        assert_eq!(
            anon_core::ContactCode::encode(&keys.public()).unwrap(),
            expected
        );
        assert!(
            !dir.join("identity.seed").exists(),
            "a redundant file must be cleaned up"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Failure paths --------------------------------------------------------

    #[test]
    fn an_unavailable_keychain_is_fatal_and_writes_no_file() {
        // The whole point of decision #3: no silent plaintext fallback.
        let dir = temp_dir("unavailable");
        let kc = MemoryKeychain::unavailable();

        let err = load_or_create_with(&dir, &kc).expect_err("must refuse to start");
        let text = err.to_string();
        assert!(
            text.contains("unavailable"),
            "the message must name the cause: {text}"
        );
        assert!(
            !dir.join("identity.seed").exists(),
            "an unavailable keychain must not produce a plaintext seed file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_legacy_file_is_rejected_rather_than_silently_replaced() {
        // Silently generating a new identity would destroy the user's contact code
        // without telling them. Failing loudly is the only safe behaviour.
        let dir = temp_dir("corrupt");
        let kc = MemoryKeychain::new();
        std::fs::write(dir.join("identity.seed"), "not-hex-at-all").unwrap();

        assert!(load_or_create_with(&dir, &kc).is_err());
        assert!(
            dir.join("identity.seed").exists(),
            "a corrupt file must not be deleted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_short_legacy_file_is_rejected() {
        let dir = temp_dir("short");
        let kc = MemoryKeychain::new();
        std::fs::write(dir.join("identity.seed"), "0011").unwrap();

        assert!(load_or_create_with(&dir, &kc).is_err());
        assert!(dir.join("identity.seed").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- The seed must not leak into the database -----------------------------

    #[test]
    fn the_seed_never_appears_in_the_database() {
        // §2.3's hard rule. Scanned rather than assumed: the seed's bytes and its hex
        // form must not appear anywhere in the encrypted file.
        use anon_storage::{Argon2Params, Store, StoreConfig};

        let dir = temp_dir("noleak");
        let kc = MemoryKeychain::new();
        let keys = load_or_create_with(&dir, &kc).expect("create");
        let seed = keys.to_escrow_seed();
        let seed_hex = hex_encode(seed.as_ref());

        // Write some data so the file is not empty.
        let store = Store::open(
            &dir.join("anon.db"),
            "test-passphrase",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("open store");
        // Use the store's own clock: a hardcoded past timestamp would be rejected as
        // already-expired, which is the retention guard doing its job.
        let now = store.now();
        store
            .insert_message(b"conv", b"peer", now, b"hello")
            .expect("insert");
        drop(store);

        let raw = std::fs::read(dir.join("anon.db")).expect("read db");

        // The raw seed bytes.
        assert!(
            !raw.windows(SEED_LEN).any(|w| w == seed.as_ref()),
            "the raw seed must not appear in the database file"
        );

        // The hex form, which is how a careless implementation would store it.
        let hex_bytes = seed_hex.as_bytes();
        assert!(
            !raw.windows(hex_bytes.len()).any(|w| w == hex_bytes),
            "the hex form of the seed must not appear in the database file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_seed_never_appears_in_debug_output() {
        // A `Debug` impl that printed the seed would leak it into any log line that
        // formatted the keys.
        let dir = temp_dir("debug");
        let kc = MemoryKeychain::new();
        let keys = load_or_create_with(&dir, &kc).expect("create");
        let seed = keys.to_escrow_seed();
        let seed_hex = hex_encode(seed.as_ref());

        let debug = format!("{keys:?}");
        assert!(
            !debug.contains(&seed_hex),
            "IdentityKeys' Debug must not print the seed"
        );
        assert!(
            !debug.contains(&format!("{:?}", seed.as_ref())),
            "IdentityKeys' Debug must not print the seed bytes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // The database-passphrase tests that used to live here moved to
    // `crate::vault::tests`, where the passphrase is user-held. Keeping them here would
    // have meant keeping `database_passphrase` alive to test it.
}
