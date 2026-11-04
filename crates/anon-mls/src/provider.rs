//! The MLS provider: RustCrypto primitives over a SQLCipher-backed store
//! (`plan.md` §4.2, §6.3).
//!
//! # Why a custom provider
//!
//! `openmls_rust_crypto::OpenMlsRustCrypto` hardcodes
//! `StorageProvider = MemoryStorage`. That is fine for tests but wrong here for
//! two reasons:
//!
//! 1. **Persistence.** `plan.md` §7.1 Phase 4 requires delivery to survive an
//!    app restart. Group state (epoch secrets, ratchet tree, proposal store)
//!    must be on disk.
//! 2. **Encryption at rest.** `plan.md` §6.3 requires *all* local state to be
//!    encrypted. A second plaintext database would quietly break that promise.
//!
//! So this module pairs `RustCrypto` (the same primitives OpenMLS's own provider
//! uses) with `SqliteStorageProvider` over a connection to the app's existing
//! SQLCipher database. One file, one key, one retention policy.
//!
//! # The codec
//!
//! `SqliteStorageProvider` is generic over a [`Codec`]. JSON is used because it
//! is what `openmls_sqlite_storage`'s own tests use and it round-trips every
//! type OpenMLS stores. The codec's output is *inside* the SQLCipher-encrypted
//! page, so its readability is irrelevant to confidentiality.

use crate::error::{MlsError, Result};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;

/// JSON codec for the MLS storage provider.
#[derive(Default, Debug)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(
        slice: &[u8],
    ) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The storage provider type this crate uses throughout.
pub type MlsStorage = SqliteStorageProvider<JsonCodec, Connection>;

/// An MLS provider: RustCrypto for primitives, SQLCipher for state.
///
/// Not `Clone`: the underlying `Connection` is owned, and duplicating it would
/// mean two writers to the same file without coordination.
pub struct MlsProvider {
    crypto: RustCrypto,
    storage: MlsStorage,
}

impl MlsProvider {
    /// Build a provider over an already-keyed SQLCipher connection.
    ///
    /// The caller is responsible for applying `PRAGMA key` first — normally by
    /// calling [`anon_storage::Store::open_secondary_connection`], which applies
    /// the store's own key so no key material is handled here.
    ///
    /// Runs the MLS schema migrations, which are namespaced in their own
    /// migration table (`openmls_sqlite_storage_migrations`) so they cannot
    /// collide with the app's own `schema_meta`.
    pub fn new(conn: Connection) -> Result<Self> {
        let mut storage = SqliteStorageProvider::<JsonCodec, _>::new(conn);
        storage
            .run_migrations()
            .map_err(|e| MlsError::Backend(format!("MLS schema migration failed: {e}")))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }

    /// The raw storage provider, for `MlsGroup::load` and friends.
    pub fn storage(&self) -> &MlsStorage {
        &self.storage
    }
}

impl OpenMlsProvider for MlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl std::fmt::Debug for MlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material or the connection.
        f.debug_struct("MlsProvider").finish_non_exhaustive()
    }
}
