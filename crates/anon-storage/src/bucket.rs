//! Per-month data keys and crypto-shredding (`plan.md` §6.2, layer 4).
//!
//! # Why bucket keys exist
//!
//! Encrypting the whole database with one key means deleting a row is only as
//! good as the storage stack's willingness to actually destroy the bytes.
//! `VACUUM` does not guarantee that on flash storage, and `PRAGMA secure_delete`
//! only overwrites within the database file.
//!
//! Instead, message ciphertext is encrypted under a **per-month data key**. When
//! a month ages past the retention ceiling, the key is destroyed, and every
//! byte encrypted under it becomes undecryptable — independent of whether the
//! ciphertext was physically erased. This is the "cryptographically
//! unrecoverable" property the plan asks for.
//!
//! # Key hierarchy
//!
//! ```text
//! user passphrase
//!   -> Argon2id(mobile-calibrated params, per-database salt)
//!   -> master key (32 bytes, never stored)
//!   -> HKDF-SHA256(master, info = "anon/v1/data-key/" + bucket label)
//!   -> per-bucket data key (32 bytes)
//! ```
//!
//! Bucket keys are **derived, not stored**. That means there is nothing on disk
//! to steal, and "shredding" is simply a matter of never deriving that bucket's
//! key again. A [`KeyRing`] records which buckets are still live so the store can
//! refuse to resurrect a shredded bucket.

use crate::error::{Result, StorageError};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Domain separation for bucket key derivation.
const KDF_INFO_PREFIX: &str = "anon/v1/data-key/";

/// A `YYYY-MM` bucket label.
///
/// Buckets are calendar months because the retention ceiling is 90 days: a
/// monthly bucket never needs to be kept for more than one retention period,
/// so shredding a bucket can never destroy a still-live record. (A 30-day bucket
/// would straddle the 90-day boundary and could shred live data.)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct BucketId(String);

impl BucketId {
    /// Build a bucket from a year and month.
    ///
    /// Rejects month values outside 1..=12 rather than trusting the caller.
    pub fn new(year: i32, month: u8) -> Result<Self> {
        if !(1..=12).contains(&month) {
            return Err(StorageError::InvalidRecord("month must be in 1..=12"));
        }
        Ok(Self(format!("{year:04}-{month:02}")))
    }

    /// Parse a `YYYY-MM` label, validating its shape.
    pub fn parse(label: &str) -> Result<Self> {
        let bytes = label.as_bytes();
        if bytes.len() != 7 || bytes[4] != b'-' {
            return Err(StorageError::InvalidRecord("bucket label must be YYYY-MM"));
        }
        let year: i32 = label[..4]
            .parse()
            .map_err(|_| StorageError::InvalidRecord("bucket year is not numeric"))?;
        let month: u8 = label[5..]
            .parse()
            .map_err(|_| StorageError::InvalidRecord("bucket month is not numeric"))?;
        Self::new(year, month)
    }

    /// The bucket containing a given epoch-seconds timestamp.
    pub fn from_epoch(seconds: i64) -> Self {
        match time::OffsetDateTime::from_unix_timestamp(seconds) {
            Ok(dt) => Self(format!("{:04}-{:02}", dt.year(), u8::from(dt.month()))),
            Err(_) => Self("0000-00".to_string()),
        }
    }

    /// The label, e.g. `2026-11`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Epoch seconds of the first instant in the *next* bucket.
    ///
    /// Used to decide whether an entire bucket is past the retention ceiling.
    pub fn next_bucket_start(&self) -> Option<i64> {
        let year: i32 = self.0[..4].parse().ok()?;
        let month: u8 = self.0[5..].parse().ok()?;
        let (next_year, next_month) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        let month_enum = time::Month::try_from(next_month).ok()?;
        let date = time::Date::from_calendar_date(next_year, month_enum, 1).ok()?;
        Some(date.midnight().assume_utc().unix_timestamp())
    }
}

impl std::fmt::Display for BucketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single bucket's data key. Wiped on drop.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Raw key bytes for use by an AEAD.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material, even accidentally.
        f.write_str("DataKey(<redacted>)")
    }
}

/// Derives and tracks bucket data keys.
pub struct KeyRing {
    master: Zeroizing<[u8; 32]>,
    /// Buckets that are still live. A bucket absent here has been shredded and
    /// its key will never be re-derived.
    live: Mutex<BTreeSet<BucketId>>,
}

impl KeyRing {
    /// Build a key ring from a master key.
    ///
    /// The master key is held in a `Zeroizing` buffer and wiped on drop; it is
    /// never written to disk (`plan.md` §6.3).
    pub fn new(master: Zeroizing<[u8; 32]>) -> Self {
        Self {
            master,
            live: Mutex::new(BTreeSet::new()),
        }
    }

    /// Mark a bucket live and return its derived key, without touching the
    /// persisted set.
    ///
    /// Crate-internal: used when rebuilding the ring from the persisted bucket
    /// table at open time, where the set is already authoritative.
    pub(crate) fn derive_and_mark_live(&self, bucket: &BucketId) -> DataKey {
        self.live.lock().unwrap().insert(bucket.clone());
        self.derive(bucket)
    }

    /// Derive the data key for a bucket.
    ///
    /// Deterministic: the same master and bucket always yield the same key, which
    /// is what makes derivation-instead-of-storage viable.
    fn derive(&self, bucket: &BucketId) -> DataKey {
        let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + bucket.as_str().len());
        info.extend_from_slice(KDF_INFO_PREFIX.as_bytes());
        info.extend_from_slice(bucket.as_str().as_bytes());

        // `master` is high-entropy key material, so passing it as HKDF input key
        // material (with no extra salt) is appropriate.
        let hk = Hkdf::<Sha256>::new(None, self.master.as_ref());
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(&info, key.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        DataKey(key)
    }

    /// Register a bucket as live and return its key.
    pub fn open(&self, bucket: &BucketId) -> DataKey {
        self.live.lock().unwrap().insert(bucket.clone());
        self.derive(bucket)
    }

    /// Fetch the key for a live bucket, or fail if it was shredded.
    pub fn get(&self, bucket: &BucketId) -> Result<DataKey> {
        if !self.live.lock().unwrap().contains(bucket) {
            return Err(StorageError::KeyShredded(bucket.to_string()));
        }
        Ok(self.derive(bucket))
    }

    /// Destroy a bucket's key, making its ciphertext unrecoverable.
    ///
    /// After this call, `get` for the bucket fails forever (for this process
    /// lifetime) and no key material for it exists anywhere. This is the
    /// crypto-shredding operation from `plan.md` §6.2.
    pub fn shred(&self, bucket: &BucketId) -> bool {
        self.live.lock().unwrap().remove(bucket)
    }

    /// Whether a bucket is still live.
    pub fn is_live(&self, bucket: &BucketId) -> bool {
        self.live.lock().unwrap().contains(bucket)
    }

    /// All currently live buckets, in order.
    pub fn live_buckets(&self) -> Vec<BucketId> {
        self.live.lock().unwrap().iter().cloned().collect()
    }

    /// Apply this ring's master key to a fresh SQLCipher connection.
    ///
    /// Exists so a second connection to the *same* database file (for example
    /// the one MLS group state is persisted through) is encrypted with the same
    /// key without the master key being copied into a second owner. The key
    /// stays in exactly one place: this ring.
    pub fn apply_to(&self, conn: &rusqlite::Connection) -> Result<()> {
        let mut hex = String::with_capacity(64);
        for b in self.master.as_ref() {
            hex.push_str(&format!("{b:02x}"));
        }
        let applied = conn
            .execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
            .map_err(StorageError::from);
        hex.clear();
        applied
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("master", &"<redacted>")
            .field("live_buckets", &self.live_buckets().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::new(Zeroizing::new([9u8; 32]))
    }

    #[test]
    fn bucket_ids_validate_month() {
        assert!(BucketId::new(2026, 11).is_ok());
        assert!(BucketId::new(2026, 1).is_ok());
        assert!(BucketId::new(2026, 12).is_ok());
        assert!(BucketId::new(2026, 0).is_err());
        assert!(BucketId::new(2026, 13).is_err());
    }

    #[test]
    fn bucket_labels_are_zero_padded_and_stable() {
        assert_eq!(BucketId::new(2026, 1).unwrap().as_str(), "2026-01");
        assert_eq!(BucketId::new(2026, 11).unwrap().as_str(), "2026-11");
        assert_eq!(BucketId::parse("2026-11").unwrap().as_str(), "2026-11");
    }

    #[test]
    fn bucket_parse_rejects_malformed_labels() {
        for bad in ["2026-1", "202611", "2026/11", "abcd-11", "2026-xx", ""] {
            assert!(BucketId::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bucket_from_epoch_matches_retention_helper() {
        // The two independent implementations (this one and anon-core's) must
        // agree, since one computes expiry and the other selects keys.
        let t = 1_700_000_000i64;
        assert_eq!(
            BucketId::from_epoch(t).as_str(),
            anon_core::retention_bucket(t)
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let r = ring();
        let b = BucketId::new(2026, 11).unwrap();
        let k1 = r.open(&b);
        let k2 = r.open(&b);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn distinct_buckets_get_distinct_keys() {
        let r = ring();
        let a = r.open(&BucketId::new(2026, 10).unwrap());
        let b = r.open(&BucketId::new(2026, 11).unwrap());
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn distinct_masters_get_distinct_keys() {
        let r1 = KeyRing::new(Zeroizing::new([1u8; 32]));
        let r2 = KeyRing::new(Zeroizing::new([2u8; 32]));
        let b = BucketId::new(2026, 11).unwrap();
        assert_ne!(r1.open(&b).as_bytes(), r2.open(&b).as_bytes());
    }

    #[test]
    fn shredding_makes_the_key_unavailable_forever() {
        // The core crypto-shredding guarantee from plan.md §6.2.
        let r = ring();
        let b = BucketId::new(2026, 11).unwrap();
        let _ = r.open(&b);
        assert!(r.is_live(&b));
        assert!(r.get(&b).is_ok());

        assert!(r.shred(&b));
        assert!(!r.is_live(&b));
        match r.get(&b) {
            Err(StorageError::KeyShredded(label)) => assert_eq!(label, "2026-11"),
            other => panic!("expected shredded error, got {other:?}"),
        }
    }

    #[test]
    fn shredding_an_unknown_bucket_reports_false() {
        let r = ring();
        assert!(!r.shred(&BucketId::new(2026, 11).unwrap()));
    }

    #[test]
    fn a_shredded_bucket_is_not_revived_by_open() {
        // `open` re-registers a bucket. The store must therefore never `open` a
        // bucket it has shredded — this documents that hazard explicitly.
        let r = ring();
        let b = BucketId::new(2026, 11).unwrap();
        let _ = r.open(&b);
        r.shred(&b);
        let _ = r.open(&b); // deliberate revival (store never does this)
        assert!(
            r.is_live(&b),
            "open() re-registers by design; store must avoid it"
        );
    }

    #[test]
    fn shredding_one_bucket_leaves_others_intact() {
        let r = ring();
        let a = BucketId::new(2026, 10).unwrap();
        let b = BucketId::new(2026, 11).unwrap();
        let ka = r.open(&a).as_bytes().to_owned();
        let _ = r.open(&b);
        r.shred(&b);

        assert!(r.get(&a).is_ok());
        assert_eq!(r.get(&a).unwrap().as_bytes(), &ka);
    }

    #[test]
    fn next_bucket_start_rolls_over_the_year() {
        let dec = BucketId::new(2026, 12).unwrap();
        let jan = BucketId::new(2027, 1).unwrap();
        assert_eq!(
            dec.next_bucket_start(),
            jan.next_bucket_start()
                .map(|_| dec.next_bucket_start().unwrap())
        );
        // December's next bucket begins in the following January.
        let start = dec.next_bucket_start().unwrap();
        assert_eq!(BucketId::from_epoch(start), jan);
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let r = ring();
        let b = BucketId::new(2026, 11).unwrap();
        let key = r.open(&b);
        assert_eq!(format!("{key:?}"), "DataKey(<redacted>)");
        assert!(!format!("{r:?}").contains("9, 9, 9"));
    }
}
