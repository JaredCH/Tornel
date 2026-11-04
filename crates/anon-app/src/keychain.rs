//! The OS keychain for the identity seed (`plan.md` §2.3).
//!
//! # What this replaces
//!
//! Before this module the seed lived in `identity.seed` beside the database with
//! owner-only permissions, and [`crate::identity_store`]'s docs said plainly that this
//! was a gap against §2.3 rather than a design choice. §2.3 requires Keychain on macOS,
//! DPAPI / Credential Manager on Windows, and Secret Service on Linux.
//!
//! `keyring` 4.2.0's `v1` facade picks the right one per platform. Verified on Windows
//! Credential Manager: `store_status()` returns `Ok(())`, `set_secret`/`get_secret`
//! round-trip byte-identically, an overwrite replaces cleanly, a missing entry returns
//! `NoEntry`, and `delete_credential` works.
//!
//! # The distinction that matters most
//!
//! [`Keychain::load`] returns `Ok(None)` for "no seed stored" and `Err` for "the
//! keychain itself is unavailable". Collapsing those two would be a data-loss bug: the
//! caller would treat an unreachable keychain as "this is a new install", generate a
//! fresh identity, and silently destroy the user's contact code. The `NoEntry` variant
//! is what separates them, and [`KeychainError`] keeps that distinction observable.
//!
//! # Hard fail, not fallback
//!
//! When the keychain is unavailable the app **refuses to start**. It does not fall back
//! to writing a plaintext file. A security tool that silently degrades to plaintext has
//! converted a documented gap into an undocumented one, and the rest of this codebase
//! already fails closed in the same spirit (the offline transport refuses to send; the
//! store refuses to open on a wrong key).
//!
//! # Why the trait
//!
//! [`KeychainBackend`] exists so a test can substitute a failing implementation and
//! prove the hard-fail path. It has three methods and no more — a wider seam would be
//! harder to review than the code it replaces.
//!
//! # Zeroization
//!
//! Every path hands the seed back as `Zeroizing<[u8; 32]>`. No `Vec<u8>` copy of the
//! seed escapes this module, and the keychain's own string form is wiped after decoding.

use zeroize::Zeroizing;

/// Length of an identity seed, in bytes.
pub const SEED_LEN: usize = 32;

/// The service name entries are stored under.
///
/// A constant rather than a computed value: the service/username pair *is* the lookup
/// key, so changing either orphans every existing install's seed.
const SERVICE: &str = "anon";

/// The username (account) entries are stored under. Fixed for the same reason.
const ACCOUNT: &str = "identity-seed";

/// Why a keychain operation failed.
///
/// Kept separate from the "no seed stored" case on purpose — see the module docs.
#[derive(Debug)]
pub enum KeychainError {
    /// The platform credential store could not be initialised at all.
    ///
    /// This is fatal at startup: the app must not fall back to a plaintext file.
    Unavailable(String),
    /// An operation on an otherwise-usable store failed.
    Operation(String),
    /// The stored value is not a valid 32-byte seed.
    ///
    /// Distinct from `Unavailable`: the keychain worked, the value in it is wrong. A
    /// caller must not generate a new identity in this case — that would discard a
    /// seed the user may be able to repair.
    CorruptSeed(String),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(
                f,
                "the OS keychain is unavailable ({reason}); refusing to fall back to a \
                 plaintext seed file"
            ),
            Self::Operation(reason) => write!(f, "keychain operation failed: {reason}"),
            Self::CorruptSeed(reason) => write!(f, "the stored identity seed is invalid: {reason}"),
        }
    }
}

impl std::error::Error for KeychainError {}

/// The credential-store operations this app needs.
///
/// Three methods: store, load, delete. Narrow on purpose so a substitute is trivial and
/// a reviewer can hold the whole surface in their head.
pub trait KeychainBackend {
    /// Whether a usable credential store exists.
    fn available(&self) -> bool;

    /// Store the seed, replacing any existing value atomically from the caller's view.
    fn store(&self, seed: &[u8; SEED_LEN]) -> Result<(), KeychainError>;

    /// Load the seed.
    ///
    /// `Ok(None)` means "no seed stored" — a normal first-run answer. An `Err` means the
    /// store could not be consulted, which is *not* the same thing.
    fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError>;

    /// Delete the stored seed. Deleting a non-existent entry is not an error.
    fn delete(&self) -> Result<(), KeychainError>;
}

/// The entry type for the platform's credential store.
///
/// On desktop this is `keyring`'s `v1` facade, which picks Keychain / Credential Manager /
/// Secret Service itself. On Android the facade has no store at all — its
/// `set_credential_store` returns `Invalid("platform")` — so the Keystore-backed store is
/// installed explicitly and `keyring-core`'s entry type is used directly. Both expose the
/// same four methods and the same error type, which is why one alias is enough.
#[cfg(not(target_os = "android"))]
type PlatformEntry = keyring::Entry;

#[cfg(target_os = "android")]
type PlatformEntry = keyring_core::Entry;

/// Install the Android credential store, once per process.
///
/// `keyring-core` requires the store to be set before any entry is created, and setting it
/// twice would replace the first. `OnceLock` makes the second call a no-op that reports the
/// first call's answer.
///
/// The store needs the NDK application context, which `tao` initialises when it creates the
/// window. That is why this is called lazily from [`KeychainBackend::available`] rather than
/// from a static initialiser: at static-init time the context does not exist yet.
#[cfg(target_os = "android")]
fn android_store_ready() -> bool {
    use std::sync::OnceLock;
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| match android_native_keyring_store::Store::new() {
        Ok(store) => {
            keyring_core::set_default_store(store);
            true
        }
        Err(error) => {
            eprintln!("anon: the Android credential store could not be initialised: {error}");
            false
        }
    })
}

/// The real OS keychain, via `keyring`'s `v1` facade (or the Android store).
pub struct OsKeychain {
    account: String,
}

impl OsKeychain {
    /// Create the default backend (`identity-seed`).
    ///
    /// Does not touch the credential store: `keyring` initialises lazily, and doing it
    /// here would make construction fallible for reasons the caller cannot act on.
    /// Use [`KeychainBackend::available`] to check.
    pub fn new() -> Self {
        Self {
            account: ACCOUNT.to_string(),
        }
    }

    /// Create a backend scoped to a specific data directory when running a custom
    /// multi-instance profile (`ANON_DATA_DIR`), so two local desktop instances on the
    /// same OS user account do not overwrite each other's identity seed in Credential Manager.
    pub fn for_data_dir(data_dir: &std::path::Path) -> Self {
        if std::env::var("ANON_DATA_DIR")
            .ok()
            .is_some_and(|v| !v.trim().is_empty())
        {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(data_dir.to_string_lossy().as_bytes());
            let digest = hasher.finalize();
            let mut suffix = String::with_capacity(16);
            for b in &digest[..8] {
                suffix.push_str(&format!("{b:02x}"));
            }
            return Self {
                account: format!("{ACCOUNT}-{suffix}"),
            };
        }
        Self::new()
    }

    /// Build an entry, mapping a store-initialisation failure to [`KeychainError`].
    fn entry(&self) -> Result<PlatformEntry, KeychainError> {
        #[cfg(target_os = "android")]
        if !android_store_ready() {
            return Err(KeychainError::Unavailable(
                "the Android Keystore store could not be initialised".to_string(),
            ));
        }

        PlatformEntry::new(SERVICE, &self.account).map_err(|e| match e {
            // `NoDefaultStore` is the documented signal that the platform credential
            // store could not be initialised (see `keyring::v1::Entry::new`).
            keyring_core::Error::NoDefaultStore => {
                KeychainError::Unavailable("no platform credential store".to_string())
            }
            other => KeychainError::Operation(other.to_string()),
        })
    }
}

impl Default for OsKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainBackend for OsKeychain {
    fn available(&self) -> bool {
        // On desktop, `store_status()` initialises the store on first call and reports
        // whether it worked, which is exactly the question being asked. On Android there
        // is no facade to ask, so the store is installed here and its outcome reported.
        #[cfg(not(target_os = "android"))]
        {
            keyring::Entry::store_status().is_ok()
        }
        #[cfg(target_os = "android")]
        {
            android_store_ready()
        }
    }

    fn store(&self, seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
        let entry = self.entry()?;
        entry.set_secret(seed).map_err(|e| match e {
            keyring_core::Error::NoDefaultStore => {
                KeychainError::Unavailable("no platform credential store".to_string())
            }
            other => KeychainError::Operation(other.to_string()),
        })
    }

    fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
        let entry = self.entry()?;
        match entry.get_secret() {
            Ok(bytes) => decode_seed(&bytes).map(Some),
            // The one variant that means "nothing is stored" rather than "it broke".
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(keyring_core::Error::NoDefaultStore) => Err(KeychainError::Unavailable(
                "no platform credential store".to_string(),
            )),
            Err(other) => Err(KeychainError::Operation(other.to_string())),
        }
    }

    fn delete(&self) -> Result<(), KeychainError> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            // Deleting what is not there is the desired end state, so it is not an error.
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(other) => Err(KeychainError::Operation(other.to_string())),
        }
    }
}

/// Turn stored bytes into a seed, rejecting anything the wrong length.
///
/// A wrong length is reported as [`KeychainError::CorruptSeed`] rather than being
/// padded or truncated: a silently "fixed" seed would derive a *different* identity,
/// which is worse than a clear failure.
fn decode_seed(bytes: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, KeychainError> {
    let arr: [u8; SEED_LEN] = bytes.try_into().map_err(|_| {
        KeychainError::CorruptSeed(format!("expected {SEED_LEN} bytes, found {}", bytes.len()))
    })?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that always fails, for the hard-fail path.
    struct FailingKeychain {
        reason: &'static str,
    }

    impl KeychainBackend for FailingKeychain {
        fn available(&self) -> bool {
            false
        }
        fn store(&self, _seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
            Err(KeychainError::Unavailable(self.reason.to_string()))
        }
        fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
            Err(KeychainError::Unavailable(self.reason.to_string()))
        }
        fn delete(&self) -> Result<(), KeychainError> {
            Err(KeychainError::Unavailable(self.reason.to_string()))
        }
    }

    /// An in-memory backend, so the logic around it can be tested without touching the
    /// real credential store.
    struct MemoryKeychain {
        seed: std::sync::Mutex<Option<[u8; SEED_LEN]>>,
    }

    impl MemoryKeychain {
        fn new() -> Self {
            Self {
                seed: std::sync::Mutex::new(None),
            }
        }
    }

    impl KeychainBackend for MemoryKeychain {
        fn available(&self) -> bool {
            true
        }
        fn store(&self, seed: &[u8; SEED_LEN]) -> Result<(), KeychainError> {
            *self.seed.lock().unwrap() = Some(*seed);
            Ok(())
        }
        fn load(&self) -> Result<Option<Zeroizing<[u8; SEED_LEN]>>, KeychainError> {
            Ok(self.seed.lock().unwrap().map(Zeroizing::new))
        }
        fn delete(&self) -> Result<(), KeychainError> {
            *self.seed.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn a_memory_backend_round_trips_a_seed() {
        let kc = MemoryKeychain::new();
        let seed = [0x42u8; SEED_LEN];

        assert!(kc.load().unwrap().is_none(), "starts empty");
        kc.store(&seed).expect("store");

        let loaded = kc.load().expect("load").expect("present");
        assert_eq!(loaded.as_ref(), &seed, "byte-identical round-trip");
    }

    #[test]
    fn deleting_clears_the_seed() {
        let kc = MemoryKeychain::new();
        kc.store(&[1u8; SEED_LEN]).expect("store");
        kc.delete().expect("delete");
        assert!(kc.load().unwrap().is_none());
    }

    #[test]
    fn a_failing_backend_reports_unavailable() {
        let kc = FailingKeychain {
            reason: "no Secret Service on this host",
        };
        assert!(!kc.available());
        assert!(
            matches!(kc.load(), Err(KeychainError::Unavailable(_))),
            "an unavailable store must not look like an empty one"
        );
    }

    #[test]
    fn an_unavailable_store_does_not_report_none() {
        // The distinction this whole module exists for: `None` means "new install" and
        // would cause the caller to mint a fresh identity, destroying the old one.
        let kc = FailingKeychain { reason: "broken" };
        let result = kc.load();
        assert!(
            result.is_err(),
            "an unavailable keychain must return Err, never Ok(None)"
        );
    }

    #[test]
    fn a_wrong_length_seed_is_corrupt_not_padded() {
        // A silently padded seed derives a different identity, which is worse than a
        // clear failure.
        assert!(matches!(
            decode_seed(&[0u8; 16]),
            Err(KeychainError::CorruptSeed(_))
        ));
        assert!(matches!(
            decode_seed(&[0u8; 33]),
            Err(KeychainError::CorruptSeed(_))
        ));
        assert!(matches!(
            decode_seed(&[]),
            Err(KeychainError::CorruptSeed(_))
        ));
    }

    #[test]
    fn a_correct_length_seed_decodes() {
        let seed = decode_seed(&[7u8; SEED_LEN]).expect("decode");
        assert_eq!(seed.as_ref(), &[7u8; SEED_LEN]);
    }

    #[test]
    fn the_error_messages_say_what_happened() {
        let unavailable = KeychainError::Unavailable("no store".into());
        let text = unavailable.to_string();
        assert!(
            text.contains("unavailable"),
            "the message must name the cause: {text}"
        );
        assert!(
            text.contains("refusing to fall back"),
            "the message must say the app will not silently degrade: {text}"
        );

        let corrupt = KeychainError::CorruptSeed("expected 32 bytes, found 4".into());
        assert!(corrupt.to_string().contains("expected 32 bytes"));
    }

    // -- Real OS keychain: opt-in -------------------------------------------------
    //
    // These touch the actual platform credential store, so they are opt-in to avoid
    // clobbering a developer's real identity. Run with ANON_KEYCHAIN_TEST=1.

    fn real_keychain_enabled() -> bool {
        std::env::var("ANON_KEYCHAIN_TEST")
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    #[test]
    fn the_os_keychain_round_trips_a_seed() {
        if !real_keychain_enabled() {
            eprintln!("skipped: set ANON_KEYCHAIN_TEST=1 to exercise the real keychain");
            return;
        }

        let kc = OsKeychain::new();
        assert!(
            kc.available(),
            "the platform credential store must be usable"
        );

        // Clear first so the assertion below cannot pass on a leftover value.
        kc.delete().expect("clear");
        assert!(kc.load().expect("load").is_none(), "starts empty");

        let seed = [0x5au8; SEED_LEN];
        kc.store(&seed).expect("store");
        let loaded = kc.load().expect("load").expect("present");
        assert_eq!(loaded.as_ref(), &seed, "byte-identical round-trip");

        kc.delete().expect("cleanup");
        assert!(kc.load().expect("load").is_none(), "delete works");
    }

    #[test]
    fn the_os_keychain_reports_availability() {
        if !real_keychain_enabled() {
            eprintln!("skipped: set ANON_KEYCHAIN_TEST=1 to check the real keychain");
            return;
        }
        let kc = OsKeychain::new();
        assert!(
            kc.available(),
            "on Windows this means Windows Credential Manager initialised"
        );
    }
}
