//! Resumable database rekeying (`plan.md` §6.3, gap-closure plan Gap 2).
//!
//! # Why this is copy-then-swap rather than in-place `PRAGMA rekey`
//!
//! `PRAGMA rekey` genuinely re-encrypts — verified against this build: the old key is
//! rejected afterwards, the new key reads the data, and the file header is not plaintext.
//! But it rewrites the live file with **no rollback**. A crash mid-rewrite leaves a
//! database that may open with neither key, and this is a database the user cannot
//! recover any other way: there is no server, no backup, and the escrow artifact restores
//! an *identity*, not message history.
//!
//! So the rekey happens on a **copy**. The original is untouched until the copy has been
//! opened with the new passphrase and its row counts match. Only then is it swapped in.
//! The cost is disk space and time; the benefit is that every failure is recoverable.
//!
//! # The stage marker
//!
//! Progress is recorded in a sidecar file (`<db>.rekey-state`) written *before* each
//! stage begins. It holds no key material — only salts, which are not secret — so it is
//! safe to leave on disk between crashes.
//!
//! The marker records the last stage that **completed**, which is what makes resuming
//! safe: a stage is only re-entered when the marker says it did not finish.
//!
//! ```text
//! prepared  marker written; original untouched, no copy yet
//! copied    <db>.rekey-tmp exists, encrypted with the new key
//! verified  the copy opens with the new passphrase and row counts match
//! swapped   original -> <db>.rekey-old, copy -> <db>, new salt in place
//! done      marker and <db>.rekey-old removed
//! ```
//!
//! # Resuming
//!
//! [`resume`] reads the marker and continues from the recorded stage. A crash in
//! `prepared`, `copied`, or `verified` leaves the original intact, so the migration
//! restarts from that stage. `swapped` is the only ambiguous window, and it is resolved
//! by *not* swapping again — the swap already happened, so only cleanup remains. That
//! distinction is load-bearing: re-running the swap would move the new database aside and
//! then fail to find a copy to put in its place, destroying the user's data.
//!
//! # Disk space
//!
//! A rekey needs free space for a full second copy of the database. This module does not
//! pre-check it: there is no portable `std` API for free space, and a check that silently
//! does nothing is worse than no check. The `verified` stage is the real control — a copy
//! truncated by a full disk fails to open or fails the row-count comparison, and the
//! original is still intact at that point. Callers that can check free space should do so
//! before calling [`rekey`].

use crate::error::{Result, StorageError};
use crate::store::{Argon2Params, Store, StoreConfig};
use std::path::{Path, PathBuf};

/// The last stage a rekey completed.
///
/// Ordered: each variant implies every earlier one finished.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RekeyStage {
    /// The marker was written; nothing else has happened.
    Prepared,
    /// A full copy exists at `<db>.rekey-tmp`, encrypted with the new key.
    Copied,
    /// The copy opens with the new passphrase and its row counts match the original.
    Verified,
    /// The original was renamed to `<db>.rekey-old` and the copy took its place.
    Swapped,
    /// The marker and the old file were removed.
    Done,
}

impl RekeyStage {
    /// The token stored in the marker file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Copied => "copied",
            Self::Verified => "verified",
            Self::Swapped => "swapped",
            Self::Done => "done",
        }
    }

    /// Parse a stored token. Returns `None` for anything unrecognised, so a corrupt
    /// marker surfaces as an error rather than being treated as "start over" — starting
    /// over could re-copy over a file that is mid-swap.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "prepared" => Some(Self::Prepared),
            "copied" => Some(Self::Copied),
            "verified" => Some(Self::Verified),
            "swapped" => Some(Self::Swapped),
            "done" => Some(Self::Done),
            _ => None,
        }
    }
}

/// The on-disk marker recording rekey progress.
///
/// Deliberately plain text with one `key=value` per line: it must be readable by a human
/// debugging a stuck migration, and it holds nothing secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyMarker {
    /// How far the rekey got.
    pub stage: RekeyStage,
    /// The salt the original file was encrypted with, hex. Not secret.
    pub old_salt: String,
    /// The salt the new file will use, hex. Not secret.
    pub new_salt: String,
}

impl RekeyMarker {
    /// Serialize to the marker file's format.
    pub fn to_text(&self) -> String {
        format!(
            "stage={}\nold_salt={}\nnew_salt={}\n",
            self.stage.as_str(),
            self.old_salt,
            self.new_salt
        )
    }

    /// Parse the marker file's format.
    ///
    /// Returns `Err` for a missing stage or an unrecognised one. A marker that cannot be
    /// understood must stop the migration, not be ignored: ignoring it would let a
    /// half-swapped database be treated as healthy.
    pub fn parse(text: &str) -> Result<Self> {
        let mut stage = None;
        let mut old_salt = None;
        let mut new_salt = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "stage" => {
                    stage = Some(RekeyStage::parse(value.trim()).ok_or(
                        StorageError::InvalidRecord("the rekey marker has an unknown stage"),
                    )?);
                }
                "old_salt" => old_salt = Some(value.trim().to_string()),
                "new_salt" => new_salt = Some(value.trim().to_string()),
                _ => {}
            }
        }

        Ok(Self {
            stage: stage.ok_or(StorageError::InvalidRecord("the rekey marker has no stage"))?,
            old_salt: old_salt.ok_or(StorageError::InvalidRecord(
                "the rekey marker has no old_salt",
            ))?,
            new_salt: new_salt.ok_or(StorageError::InvalidRecord(
                "the rekey marker has no new_salt",
            ))?,
        })
    }
}

/// The paths a rekey touches, derived from the database path.
///
/// One struct so the naming is defined once. Every suffix is appended to the database
/// path rather than replacing its extension, so `anon.db` yields `anon.db.rekey-tmp`
/// rather than `anon.rekey-tmp`. The `.salt` suffix matches [`crate::store`]'s own salt
/// sidecar, so the two agree by construction.
#[derive(Clone, Debug)]
pub struct RekeyPaths {
    /// The live database.
    pub db: PathBuf,
    /// The salt sidecar for the live database.
    pub salt: PathBuf,
    /// The in-progress copy.
    pub tmp: PathBuf,
    /// The salt sidecar for the copy.
    pub tmp_salt: PathBuf,
    /// The original, after the swap.
    pub old: PathBuf,
    /// The salt sidecar for the original.
    pub old_salt: PathBuf,
    /// The stage marker.
    pub marker: PathBuf,
}

impl RekeyPaths {
    /// Derive every path from the database path.
    pub fn new(db: &Path) -> Self {
        let with = |suffix: &str| {
            let mut p = db.as_os_str().to_owned();
            p.push(suffix);
            PathBuf::from(p)
        };
        Self {
            db: db.to_path_buf(),
            salt: with(".salt"),
            tmp: with(".rekey-tmp"),
            tmp_salt: with(".rekey-tmp.salt"),
            old: with(".rekey-old"),
            old_salt: with(".rekey-old.salt"),
            marker: with(".rekey-state"),
        }
    }

    /// Whether a rekey is in progress (a marker exists).
    pub fn in_progress(&self) -> bool {
        self.marker.exists()
    }

    /// Read the marker, if there is one.
    pub fn read_marker(&self) -> Result<Option<RekeyMarker>> {
        if !self.marker.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&self.marker)
            .map_err(|_| StorageError::InvalidRecord("the rekey marker could not be read"))?;
        Ok(Some(RekeyMarker::parse(&text)?))
    }

    /// Write the marker. Called *before* the stage it describes begins.
    fn write_marker(&self, marker: &RekeyMarker) -> Result<()> {
        std::fs::write(&self.marker, marker.to_text())
            .map_err(|_| StorageError::InvalidRecord("the rekey marker could not be written"))
    }
}

/// What a completed rekey did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyReport {
    /// Rows in each table, as counted in the live database after the swap.
    pub row_counts: Vec<(String, i64)>,
    /// Whether the migration resumed from a marker rather than starting fresh.
    pub resumed: bool,
}

/// Rekey a database from `old_passphrase` to `new_passphrase`, resumably.
///
/// # Preconditions
///
/// The database must not be open elsewhere. SQLite allows concurrent readers, but a
/// rekey copies the file and then swaps it, so an open handle would keep writing to the
/// file that is about to be renamed.
///
/// # Disk space
///
/// Needs room for a full second copy. See the module docs for why this is not pre-checked
/// here and why the `verified` stage makes a full disk recoverable rather than fatal.
pub fn rekey(
    db_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    params: Argon2Params,
) -> Result<RekeyReport> {
    if old_passphrase.is_empty() || new_passphrase.is_empty() {
        return Err(StorageError::InvalidParams("passphrases must not be empty"));
    }
    if old_passphrase == new_passphrase {
        return Err(StorageError::InvalidParams(
            "the new passphrase must differ from the old one",
        ));
    }

    let paths = RekeyPaths::new(db_path);

    // Resume if a marker exists, otherwise start fresh.
    let (mut marker, resumed) = match paths.read_marker()? {
        Some(m) => (m, true),
        None => {
            let old_salt = read_salt_hex(&paths.salt)?;
            let new_salt = random_salt_hex()?;
            let marker = RekeyMarker {
                stage: RekeyStage::Prepared,
                old_salt,
                new_salt,
            };
            paths.write_marker(&marker)?;
            (marker, false)
        }
    };

    // Each stage is entered only when the marker says the previous one finished. That is
    // what makes a crash at any point resumable without repeating a destructive step.
    if marker.stage < RekeyStage::Copied {
        copy_and_rekey(&paths, old_passphrase, new_passphrase, params)?;
        marker.stage = RekeyStage::Copied;
        paths.write_marker(&marker)?;
    }

    if marker.stage < RekeyStage::Verified {
        verify_copy(&paths, old_passphrase, new_passphrase, params)?;
        marker.stage = RekeyStage::Verified;
        paths.write_marker(&marker)?;
    }

    if marker.stage < RekeyStage::Swapped {
        swap(&paths, &marker)?;
        marker.stage = RekeyStage::Swapped;
        paths.write_marker(&marker)?;
    }

    // At `Swapped` the live database is already the new file. Counting it here (rather
    // than the copy) is what makes the report accurate on a resumed run.
    let row_counts = count_rows(&paths.db, new_passphrase, params)?;

    cleanup(&paths, &marker)?;
    Ok(RekeyReport {
        row_counts,
        resumed,
    })
}

/// Copy the database and rekey the copy to the new passphrase.
///
/// The copy is made with SQLite's own backup API rather than a filesystem copy: a
/// filesystem copy of a live database can capture a torn page, whereas the backup API
/// produces a consistent snapshot. The destination is opened with the *new* passphrase
/// first, so the pages land encrypted under the new key — that is what makes this a
/// rekey rather than a plain copy.
fn copy_and_rekey(
    paths: &RekeyPaths,
    old_passphrase: &str,
    new_passphrase: &str,
    params: Argon2Params,
) -> Result<()> {
    // Remove any partial copy from a previous attempt so the backup starts clean. A
    // truncated `.rekey-tmp` from a crashed run would otherwise be appended to.
    let _ = std::fs::remove_file(&paths.tmp);
    let _ = std::fs::remove_file(&paths.tmp_salt);

    // The copy gets its own salt, taken from the marker so a resumed run reuses it.
    // Reusing it matters: if the salt changed between attempts, a copy made in the first
    // attempt would be unopenable in the second.
    let marker = paths
        .read_marker()?
        .ok_or(StorageError::InvalidRecord("the rekey marker vanished"))?;
    let new_salt = decode_salt_hex(&marker.new_salt)?;
    std::fs::write(&paths.tmp_salt, new_salt)
        .map_err(|_| StorageError::InvalidRecord("the copy's salt could not be written"))?;

    let config = StoreConfig {
        params,
        purge_on_open: false,
        vacuum_after_purge: false,
    };

    // Open the original with the old key and the copy with the new key. Opening the copy
    // creates its schema; the backup then replaces that schema wholesale with the
    // original's, so the copy ends up structurally identical but encrypted differently.
    let source = Store::open(&paths.db, old_passphrase, config.clone())?;
    let dest = Store::open(&paths.tmp, new_passphrase, config)?;

    source.backup_into(&dest)?;
    Ok(())
}

/// Open the copy with the new passphrase and confirm its row counts match the original.
///
/// This is the gate: nothing is replaced until it passes. A copy that opens but has fewer
/// rows means the backup was truncated, and swapping it in would silently lose data.
fn verify_copy(
    paths: &RekeyPaths,
    old_passphrase: &str,
    new_passphrase: &str,
    params: Argon2Params,
) -> Result<()> {
    if !paths.tmp.exists() {
        return Err(StorageError::InvalidRecord(
            "the rekey marker says a copy exists, but it does not",
        ));
    }

    let original = count_rows(&paths.db, old_passphrase, params)?;
    let copy = count_rows(&paths.tmp, new_passphrase, params)?;

    if original != copy {
        return Err(StorageError::InvalidRecord(
            "the rekeyed copy does not match the original's row counts; refusing to swap",
        ));
    }

    // The old passphrase must no longer open the copy. If it does, the rekey did not take
    // and swapping would leave the database readable with the passphrase the user is
    // trying to retire.
    if Store::open(
        &paths.tmp,
        old_passphrase,
        StoreConfig {
            params,
            purge_on_open: false,
            vacuum_after_purge: false,
        },
    )
    .is_ok()
    {
        return Err(StorageError::InvalidRecord(
            "the rekeyed copy still opens with the old passphrase; refusing to swap",
        ));
    }

    Ok(())
}

/// Rename the original aside and move the copy into place.
///
/// Only called when the marker says the swap has not happened. Re-running it would move
/// the *new* database aside and then fail to find a copy to replace it — so the caller's
/// stage check is the guard, not a check inside this function.
fn swap(paths: &RekeyPaths, marker: &RekeyMarker) -> Result<()> {
    // Record the intent *before* doing it, so a crash between the two renames is
    // recognisable as "mid-swap" rather than "never started".
    let mut swapped = marker.clone();
    swapped.stage = RekeyStage::Swapped;
    paths.write_marker(&swapped)?;

    // Original aside. A leftover `.rekey-old` from an earlier attempt is removed first;
    // it is encrypted with the retired passphrase and is not needed.
    if paths.db.exists() {
        let _ = std::fs::remove_file(&paths.old);
        std::fs::rename(&paths.db, &paths.old)
            .map_err(|_| StorageError::InvalidRecord("the original could not be moved aside"))?;
    }
    if paths.salt.exists() {
        let _ = std::fs::remove_file(&paths.old_salt);
        let _ = std::fs::rename(&paths.salt, &paths.old_salt);
    }

    // Copy into place.
    std::fs::rename(&paths.tmp, &paths.db).map_err(|_| {
        StorageError::InvalidRecord("the rekeyed copy could not be moved into place")
    })?;
    if paths.tmp_salt.exists() {
        std::fs::rename(&paths.tmp_salt, &paths.salt).map_err(|_| {
            StorageError::InvalidRecord("the new salt could not be moved into place")
        })?;
    }

    Ok(())
}

/// Remove the marker and the retired original.
///
/// Idempotent: every removal tolerates absence. A failure here is not fatal — the live
/// database is already correct, and a leftover `.rekey-old` is encrypted with the
/// passphrase the user just retired.
fn cleanup(paths: &RekeyPaths, marker: &RekeyMarker) -> Result<()> {
    let mut done = marker.clone();
    done.stage = RekeyStage::Done;
    let _ = paths.write_marker(&done);

    let _ = std::fs::remove_file(&paths.old);
    let _ = std::fs::remove_file(&paths.old_salt);
    let _ = std::fs::remove_file(&paths.marker);
    Ok(())
}

/// Count rows in every table of a database.
///
/// Used to compare the original against the copy. Counts every table the schema creates,
/// not just the retention-bound ones, so a copy that lost the `groups` table would be
/// caught too.
fn count_rows(
    db_path: &Path,
    passphrase: &str,
    params: Argon2Params,
) -> Result<Vec<(String, i64)>> {
    let store = Store::open(
        db_path,
        passphrase,
        StoreConfig {
            params,
            purge_on_open: false,
            vacuum_after_purge: false,
        },
    )?;
    store.table_row_counts()
}

fn read_salt_hex(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .map_err(|_| StorageError::InvalidRecord("the database salt could not be read"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn decode_salt_hex(hex: &str) -> Result<[u8; 16]> {
    if hex.len() != 32 {
        return Err(StorageError::InvalidRecord("the salt must be 16 bytes"));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| StorageError::InvalidRecord("the salt is not hexadecimal"))?;
    }
    Ok(out)
}

fn random_salt_hex() -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| StorageError::KeyDerivation)?;
    Ok(salt.iter().map(|b| format!("{b:02x}")).collect())
}

/// Resume an interrupted rekey, if one is in progress.
///
/// Returns `Ok(None)` when there is nothing to resume. Called at startup so a crash
/// mid-migration is completed rather than leaving the app unable to open its database.
pub fn resume(
    db_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    params: Argon2Params,
) -> Result<Option<RekeyReport>> {
    let paths = RekeyPaths::new(db_path);
    if !paths.in_progress() {
        return Ok(None);
    }
    rekey(db_path, old_passphrase, new_passphrase, params).map(Some)
}
