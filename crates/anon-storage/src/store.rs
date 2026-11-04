//! The encrypted store (`plan.md` §6).
//!
//! Owns the SQLCipher connection, the crypto-shredding key ring, the retention
//! purge, and the schema audit.
//!
//! # Clock injection
//!
//! Every time-sensitive operation goes through [`Store::now`], which is a field
//! rather than a direct call to the system clock. Tests substitute a closed clock
//! to prove the retention behaviour (see `plan.md` §10 and §6.5). The default is
//! the real system clock.

use crate::bucket::{BucketId, KeyRing};
use crate::error::{Result, StorageError};
use crate::schema;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Argon2id parameters for the database passphrase.
///
/// Defaults are the **mobile-calibrated** values from `plan.md` §6.3: 64 MiB,
/// 3 passes. They are recorded in `schema_meta` so a future build can verify it
/// is using parameters at least as strong as those the file was created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Mobile-calibrated defaults (`plan.md` §6.3).
    pub const fn mobile_default() -> Self {
        Self {
            m_cost: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Deliberately light parameters, for tests only.
    ///
    /// Public rather than `#[cfg(test)]` because the retention tests live in a
    /// separate crate. The *format* is identical to production; only the cost is
    /// reduced, so these tests exercise the real code path.
    pub const fn test_fast() -> Self {
        Self {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::mobile_default()
    }
}

/// Configuration for opening a store.
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Argon2id cost parameters used to derive the database key.
    pub params: Argon2Params,
    /// Run the retention purge immediately after opening.
    pub purge_on_open: bool,
    /// Run `VACUUM` after purging (`plan.md` §6.2, layer 2).
    pub vacuum_after_purge: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            params: Argon2Params::mobile_default(),
            purge_on_open: true,
            vacuum_after_purge: true,
        }
    }
}

/// What a purge removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Rows deleted per table.
    pub deleted: Vec<(String, usize)>,
    /// Buckets whose keys were destroyed this pass.
    pub shredded_buckets: Vec<String>,
    /// Whether `VACUUM` was run and succeeded.
    pub vacuumed: bool,
}

impl PurgeReport {
    /// Total rows deleted across all tables.
    pub fn total_deleted(&self) -> usize {
        self.deleted.iter().map(|(_, n)| *n).sum()
    }

    /// Rows deleted from one named table.
    ///
    /// Tests assert per-table counts, because a purge touches both messages and
    /// their conversation entry point (`plan.md` §6.4), so a total is a poor
    /// signal for "did the right rows go?".
    pub fn deleted_for(&self, table: &str) -> usize {
        self.deleted
            .iter()
            .filter(|(name, _)| name == table)
            .map(|(_, n)| *n)
            .sum()
    }

    /// Whether anything was changed (deleted rows or shredded keys).
    pub fn is_empty(&self) -> bool {
        self.total_deleted() == 0 && self.shredded_buckets.is_empty()
    }
}

/// One row of query results, decoupled from the borrowed statement that produced
/// it.
///
/// `rusqlite::Row` borrows its statement, so a `Vec<Row>` cannot outlive the loop
/// that built it. Callers that need to collect rows (the mailbox reader) use this
/// owned form instead.
pub struct OwnedRow(Vec<rusqlite::types::Value>);

impl OwnedRow {
    /// Read column `idx` by position.
    ///
    /// Generic over `FromSql`, so it works for the same types `Row::get` does.
    pub fn get<T: rusqlite::types::FromSql>(&self, idx: usize) -> Result<T> {
        self.0
            .get(idx)
            .cloned()
            .ok_or(StorageError::InvalidRecord("column index out of range"))
            .and_then(|v| {
                T::column_result((&v).into())
                    .map_err(|_| StorageError::InvalidRecord("column has an unexpected type"))
            })
    }
}

impl std::fmt::Debug for OwnedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Row contents may be ciphertext; report the shape only.
        f.debug_struct("OwnedRow")
            .field("columns", &self.0.len())
            .finish()
    }
}

/// What a conversation is: a one-to-one chat or a group.
///
/// A closed enum rather than a `&str` so the two legal values are the only two
/// values. The schema's `kind` column is `TEXT` with no `CHECK`, so the type system
/// is where this constraint lives; [`ConversationKind::as_str`] is the only way to
/// produce the stored form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationKind {
    /// A one-to-one conversation with a single peer.
    Direct,
    /// A group conversation, keyed by MLS.
    Group,
}

impl ConversationKind {
    /// The value stored in the `kind` column.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Group => "group",
        }
    }

    /// Parse a stored value. Returns `None` for anything unrecognised, so a corrupt
    /// row surfaces as a missing kind rather than being silently treated as direct.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "direct" => Some(Self::Direct),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

/// A conversation row for the UI's sidebar.
///
/// Metadata only. Deliberately carries no message content: a listing should not
/// be able to leak plaintext (`plan.md` §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationRow {
    /// Conversation id.
    pub id: Vec<u8>,
    /// `direct` or `group`.
    pub kind: String,
    /// The peer's contact code or the group id.
    pub peer_or_group: Vec<u8>,
    /// When the conversation was created, epoch seconds.
    pub created_at: i64,
    /// When its content expires, epoch seconds.
    pub expires_at: i64,
    /// How many messages are currently retained.
    pub message_count: usize,
}

/// A message row's metadata, without ciphertext or plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRow {
    /// Message id.
    pub id: Vec<u8>,
    /// Sender's contact code or fingerprint bytes.
    pub sender: Vec<u8>,
    /// When the sender says it was sent, epoch seconds.
    pub sent_at: i64,
    /// When this device received it, epoch seconds.
    pub received_at: i64,
    /// Retention deadline, epoch seconds.
    pub expires_at: i64,
    /// MLS epoch it was encrypted under, when known.
    pub epoch: Option<i64>,
}

/// A contact row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRow {
    /// The peer's contact code.
    pub contact_code: String,
    /// Local display name, if the user set one.
    pub display_name: Option<String>,
    /// When the contact was added, epoch seconds.
    pub added_at: i64,
    /// Grouped fingerprint for out-of-band comparison.
    pub fingerprint: String,
}

/// A group row: the local record of an MLS group this device belongs to.
///
/// # What this row is and is not
///
/// It is **metadata only**: the group id, a local display name, when the row was
/// created, and the last epoch this device observed. The MLS state itself — epoch
/// secrets, the ratchet tree, the proposal store — lives in the MLS storage tables
/// in the same encrypted database (`anon-mls`'s provider), not here.
///
/// The `groups` table is listed in [`crate::schema::RETENTION_EXEMPT_TABLES`], so it
/// carries no `expires_at`. That exemption is deliberate and narrow: a group row
/// holds no message history and no key material, so there is nothing for the
/// retention ceiling to bound. Deleting the row without deleting the MLS state would
/// leave epoch secrets behind, so [`Store::delete_group`] documents that the caller
/// must remove both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRow {
    /// MLS group id.
    pub group_id: Vec<u8>,
    /// Local display name, if the user set one. Not identity (`plan.md` §2).
    pub name: Option<String>,
    /// When this device first recorded the group, epoch seconds.
    pub created_at: i64,
    /// The last epoch this device observed for the group.
    pub epoch: u64,
}

/// The encrypted store.
pub struct Store {
    conn: Mutex<Connection>,
    keys: Arc<KeyRing>,
    config: StoreConfig,
    /// The file this store was opened from. Kept so secondary connections (MLS
    /// group state) can be opened against the same encrypted database.
    path: std::path::PathBuf,
    /// Clock injection point. Seconds since the Unix epoch.
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Store {
    /// Open (or create) an encrypted store.
    ///
    /// The database key is derived from `passphrase` with Argon2id; SQLCipher then
    /// encrypts the whole file at rest, so even the schema and indexes are
    /// ciphertext (`plan.md` §6.3).
    pub fn open(path: &Path, passphrase: &str, config: StoreConfig) -> Result<Self> {
        // Derive the master key. A per-database salt is stored in a sidecar so
        // it survives restarts; the salt is not secret.
        let salt = load_or_create_salt(path)?;
        let master = derive_master_key(passphrase, &salt, config.params)?;

        let conn = Connection::open(path).map_err(|_| StorageError::OpenFailed)?;

        // Hand the key to SQLCipher as a raw key. Using `PRAGMA key` with a hex
        // key avoids a second KDF pass inside SQLCipher (we already did Argon2id)
        // and avoids the passphrase ever being formatted into SQL text.
        apply_sqlcipher_key(&conn, &master)?;

        // Verify the key is correct before doing anything else. Without this,
        // a wrong passphrase only surfaces as a confusing error on the first
        // real query.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::OpenFailed)?;

        for pragma in schema::SETUP_PRAGMAS {
            conn.execute_batch(pragma)?;
        }

        let store = Self {
            conn: Mutex::new(conn),
            keys: Arc::new(KeyRing::new(master)),
            config,
            path: path.to_path_buf(),
            clock: Box::new(anon_core::retention::now_epoch_seconds),
        };

        store.bootstrap_schema()?;

        // Rebuild the key ring's live-bucket set from disk.
        //
        // This must happen before anything is read. Bucket keys are derived rather
        // than stored, so "which buckets are live" is state that has to survive a
        // restart: without it, every row written before the restart would look
        // like it belonged to a shredded bucket and be unreadable. Persisting the
        // *labels* (not the keys) keeps the crypto-shredding guarantee — a bucket
        // absent from this set can never be re-derived.
        store.load_live_buckets()?;

        if store.config.purge_on_open {
            let now = (store.clock)();
            let _ = store.purge(now);
        }

        Ok(store)
    }

    /// Substitute the clock.
    ///
    /// This is public rather than `#[cfg(test)]` because the retention tests live
    /// in `tests/` (a separate crate) and must be able to freeze time. It is the
    /// only supported way to make retention behaviour deterministic, and
    /// `plan.md` §10 requires exactly that.
    pub fn set_clock(&mut self, clock: Box<dyn Fn() -> i64 + Send + Sync>) {
        self.clock = clock;
    }

    /// Freeze the clock at a fixed instant. Convenience wrapper for tests.
    pub fn freeze_clock_at(&mut self, now: i64) {
        self.set_clock(Box::new(move || now));
    }

    /// All message ids, in insertion order. Used by tests and by the UI's
    /// conversation listing.
    pub fn message_ids(&self) -> Result<Vec<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id FROM messages ORDER BY sent_at, rowid")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    /// Current time in epoch seconds, from the injected clock.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// List conversations for the UI, newest first.
    ///
    /// Returns only metadata: id, kind, label, expiry, and a message count. No
    /// message content is read here, so listing a conversation cannot leak
    /// plaintext into a caller that only wanted a sidebar (`plan.md` §7.3).
    ///
    /// Expired conversations are excluded even if the purge has not run yet, so
    /// the UI never shows a row the retention ceiling has already passed.
    pub fn conversations(&self) -> Result<Vec<ConversationRow>> {
        let now = self.now();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.kind, c.peer_or_group, c.created_at, c.expires_at,
                    (SELECT count(*) FROM messages m WHERE m.conversation = c.id)
             FROM conversations c
             WHERE c.expires_at > ?1
             ORDER BY c.created_at DESC",
        )?;
        let rows = stmt
            .query_map([now], |r| {
                Ok(ConversationRow {
                    id: r.get::<_, Vec<u8>>(0)?,
                    kind: r.get::<_, String>(1)?,
                    peer_or_group: r.get::<_, Vec<u8>>(2)?,
                    created_at: r.get::<_, i64>(3)?,
                    expires_at: r.get::<_, i64>(4)?,
                    message_count: r.get::<_, i64>(5)? as usize,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List message metadata for one conversation, oldest first.
    ///
    /// Metadata only — no ciphertext and no plaintext. The caller decrypts the
    /// specific messages it intends to display via [`Store::read_message`], which
    /// is where the crypto-shredding check lives. Splitting the two means a
    /// listing cannot accidentally decrypt a whole history.
    pub fn messages_in(&self, conversation: &[u8]) -> Result<Vec<MessageRow>> {
        let now = self.now();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sender, sent_at, received_at, expires_at, epoch
             FROM messages
             WHERE conversation = ?1 AND expires_at > ?2
             ORDER BY sent_at, rowid",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![conversation, now], |r| {
                Ok(MessageRow {
                    id: r.get::<_, Vec<u8>>(0)?,
                    sender: r.get::<_, Vec<u8>>(1)?,
                    sent_at: r.get::<_, i64>(2)?,
                    received_at: r.get::<_, i64>(3)?,
                    expires_at: r.get::<_, i64>(4)?,
                    epoch: r.get::<_, Option<i64>>(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn privacy_config(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'privacy_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_privacy_config(&self, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO schema_meta (key, value) VALUES ('privacy_v1', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [value],
        )?;
        Ok(())
    }

    /// List known contacts, most recently added first.
    pub fn contacts(&self) -> Result<Vec<ContactRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT contact_code, display_name, added_at, fingerprint
             FROM contacts
             ORDER BY added_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ContactRow {
                    contact_code: r.get::<_, String>(0)?,
                    display_name: r.get::<_, Option<String>>(1)?,
                    added_at: r.get::<_, i64>(2)?,
                    fingerprint: r.get::<_, String>(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Record or update a contact (`plan.md` §4.3).
    ///
    /// Idempotent on `contact_code`: re-inserting updates `display_name` if provided.
    pub fn insert_contact(&self, contact: &ContactRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO contacts (contact_code, display_name, added_at, fingerprint)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(contact_code) DO UPDATE SET
               display_name = COALESCE(excluded.display_name, contacts.display_name)",
            rusqlite::params![
                &contact.contact_code,
                &contact.display_name,
                contact.added_at,
                &contact.fingerprint,
            ],
        )?;
        Ok(())
    }

    /// Look up one contact by canonical contact code.
    pub fn contact(&self, contact_code: &str) -> Result<Option<ContactRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT contact_code, display_name, added_at, fingerprint
                 FROM contacts
                 WHERE contact_code = ?1",
                [contact_code],
                |r| {
                    Ok(ContactRow {
                        contact_code: r.get::<_, String>(0)?,
                        display_name: r.get::<_, Option<String>>(1)?,
                        added_at: r.get::<_, i64>(2)?,
                        fingerprint: r.get::<_, String>(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // -- Groups ------------------------------------------------------------

    /// Record a group this device belongs to.
    ///
    /// Idempotent on `group_id`: re-inserting an existing group updates its name and
    /// epoch rather than failing. That matters because the same group can be reached
    /// two ways — created locally, or joined from a Welcome — and neither path should
    /// have to check first.
    ///
    /// The name is validated by the caller (`anon-ipc`), not here: this layer stores
    /// what it is given and refuses only what the schema refuses. Keeping validation
    /// in one place is what stops two different length limits existing.
    pub fn insert_group(&self, group: &GroupRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO groups (group_id, name, created_at, epoch)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET
               name = excluded.name,
               epoch = excluded.epoch",
            rusqlite::params![
                &group.group_id,
                &group.name,
                group.created_at,
                group.epoch as i64
            ],
        )?;
        Ok(())
    }

    /// Fetch one group by id.
    ///
    /// Returns `Ok(None)` for an unknown id rather than an error: "no such group" is
    /// an ordinary answer to a lookup, and the caller decides whether it is a problem.
    pub fn group(&self, group_id: &[u8]) -> Result<Option<GroupRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT group_id, name, created_at, epoch FROM groups WHERE group_id = ?1",
                [group_id],
                |r| {
                    Ok(GroupRow {
                        group_id: r.get::<_, Vec<u8>>(0)?,
                        name: r.get::<_, Option<String>>(1)?,
                        created_at: r.get::<_, i64>(2)?,
                        epoch: r.get::<_, i64>(3)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// List every group this device belongs to, newest first.
    pub fn groups(&self) -> Result<Vec<GroupRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT group_id, name, created_at, epoch FROM groups ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(GroupRow {
                    group_id: r.get::<_, Vec<u8>>(0)?,
                    name: r.get::<_, Option<String>>(1)?,
                    created_at: r.get::<_, i64>(2)?,
                    epoch: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Update a group's recorded epoch.
    ///
    /// Returns the number of rows changed, so a caller can tell "updated" from "no
    /// such group" without a second query. An epoch that goes *backwards* is refused:
    /// MLS epochs only increase, so a decreasing value means a bug or a rollback
    /// attempt, and silently accepting it would make the stored epoch a lie.
    pub fn update_group_epoch(&self, group_id: &[u8], epoch: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE groups SET epoch = ?1 WHERE group_id = ?2 AND epoch <= ?1",
            rusqlite::params![epoch as i64, group_id],
        )?;
        Ok(changed)
    }

    /// Delete a group row.
    ///
    /// # This does not delete the MLS state
    ///
    /// The MLS group state (epoch secrets, ratchet tree) lives in the MLS storage
    /// tables, which this crate does not own — `anon-mls` does. A caller deleting a
    /// group must also call `anon_mls::Group::delete`, or the epoch secrets survive a
    /// row deletion and a re-created group id would resurrect them. That is why this
    /// method's doc says so rather than leaving the trap implicit.
    ///
    /// Returns the number of rows deleted.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute("DELETE FROM group_roles WHERE group_id = ?1", [group_id]);
        let deleted = conn.execute("DELETE FROM groups WHERE group_id = ?1", [group_id])?;
        Ok(deleted)
    }

    /// Set or update a member's role in a group (`owner`, `admin`, `moderator`, `member`).
    pub fn set_group_role(&self, group_id: &[u8], contact_code: &str, role: &str) -> Result<()> {
        let now = self.now();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO group_roles (group_id, contact_code, role, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id, contact_code) DO UPDATE SET
               role = excluded.role,
               updated_at = excluded.updated_at",
            rusqlite::params![group_id, contact_code, role, now],
        )?;
        Ok(())
    }

    /// Look up one member's role in a group, if explicitly recorded.
    pub fn group_role(&self, group_id: &[u8], contact_code: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let role = conn
            .query_row(
                "SELECT role FROM group_roles WHERE group_id = ?1 AND contact_code = ?2",
                rusqlite::params![group_id, contact_code],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(role)
    }

    /// List all explicitly recorded `(contact_code, role)` pairs for a group.
    pub fn group_roles(&self, group_id: &[u8]) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT contact_code, role FROM group_roles WHERE group_id = ?1")?;
        let rows = stmt
            .query_map([group_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Rebuild the key ring's live set from the persisted `live_buckets` table.
    ///
    /// See the comment in [`Store::open`] for why this is load-bearing rather than
    /// an optimization: bucket keys are derived, not stored, so the *set* of live
    /// buckets is the only record that a key may still be derived.
    fn load_live_buckets(&self) -> Result<()> {
        let buckets = {
            let conn = self.conn.lock().unwrap();
            let mut stmt =
                conn.prepare("SELECT bucket FROM live_buckets WHERE retired_at IS NULL")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };

        for label in buckets {
            let bucket = BucketId::parse(&label)?;
            // `derive_and_mark_live` marks the bucket live; the key itself is
            // derived on demand, so nothing secret is materialized here.
            let _ = self.keys.derive_and_mark_live(&bucket);
        }
        Ok(())
    }

    /// Record a bucket as live in the persisted set, then return its key.
    ///
    /// The write happens before the key is handed back, so a crash between the two
    /// cannot leave encrypted rows referring to a bucket the database does not
    /// know is live. (The reverse — a live bucket with no rows — is harmless.)
    pub(crate) fn open_bucket(&self, bucket: &BucketId) -> Result<crate::bucket::DataKey> {
        {
            let conn = self.conn.lock().unwrap();
            let now = self.now();
            // `first_seen_at` records when the bucket was first used; the
            // `DO NOTHING` keeps the original timestamp on repeat opens.
            conn.execute(
                "INSERT INTO live_buckets (bucket, first_seen_at, retired_at)
                 VALUES (?1, ?2, NULL)
                 ON CONFLICT(bucket) DO UPDATE SET retired_at = NULL",
                rusqlite::params![bucket.as_str(), now],
            )?;
        }
        Ok(self.keys.open(bucket))
    }

    /// Persist that a bucket's key was destroyed.
    fn retire_bucket(&self, bucket: &BucketId) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = self.now();
        conn.execute(
            "UPDATE live_buckets SET retired_at = ?1 WHERE bucket = ?2 AND retired_at IS NULL",
            rusqlite::params![now, bucket.as_str()],
        )?;
        Ok(())
    }

    /// Apply the DDL and record the schema version and KDF parameters.
    fn bootstrap_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(schema::DDL)?;

        let version: Option<String> = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;

        match version {
            None => {
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
                    [schema::SCHEMA_VERSION.to_string()],
                )?;
                let p = self.config.params;
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('argon2_m_cost', ?1)",
                    [p.m_cost.to_string()],
                )?;
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('argon2_t_cost', ?1)",
                    [p.t_cost.to_string()],
                )?;
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('argon2_p_cost', ?1)",
                    [p.p_cost.to_string()],
                )?;
            }
            Some(found) => {
                let found: i32 = found.parse().unwrap_or(-1);
                if found > schema::SCHEMA_VERSION {
                    return Err(StorageError::SchemaTooNew {
                        found,
                        supported: schema::SCHEMA_VERSION,
                    });
                }
                if found < schema::SCHEMA_VERSION {
                    // A real migration would live here. Refusing loudly is correct
                    // for now: silently continuing could drop retention metadata.
                    return Err(StorageError::SchemaMigrationRequired {
                        required: schema::SCHEMA_VERSION,
                        found,
                    });
                }
            }
        }

        Ok(())
    }

    /// Verify that the live schema still matches the retention rules
    /// (`plan.md` §6.4, §6.5(4)).
    ///
    /// Called by tests and available at runtime. Returns the names of any
    /// retention-bound table that is missing an `expires_at` column, so a new
    /// content table added without retention is caught rather than shipped.
    pub fn audit_schema(&self) -> Result<Vec<String>> {
        for table in schema::RETENTION_BOUND_TABLES {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<_>>()?;

            if columns.is_empty() {
                // The table is missing entirely: that is a schema bug too.
                return Err(StorageError::InvalidRecord(
                    "a retention-bound table is missing from the schema",
                ));
            }
            if !columns.iter().any(|c| c == "expires_at") {
                return Ok(vec![(*table).to_string()]);
            }
        }
        Ok(Vec::new())
    }

    /// Ensure a conversation row exists (or refresh its expiry and peer_or_group metadata).
    pub fn ensure_conversation(
        &self,
        conversation: &[u8],
        kind: ConversationKind,
        peer_or_group: &[u8],
    ) -> Result<()> {
        let now = self.now();
        let expires_at = self.expiry_for(now);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conversations (id, kind, peer_or_group, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               peer_or_group = excluded.peer_or_group,
               expires_at = MAX(conversations.expires_at, excluded.expires_at)",
            rusqlite::params![conversation, kind.as_str(), peer_or_group, now, expires_at],
        )?;
        Ok(())
    }

    /// Compute the expiry for a record created at `created_at`.
    ///
    /// Uses the absolute form from `anon-core` so there is exactly one
    /// implementation of the retention arithmetic.
    pub fn expiry_for(&self, created_at: i64) -> i64 {
        anon_core::expiry_from_sent_at(created_at)
    }

    /// Insert an encrypted message into a direct conversation.
    ///
    /// Convenience wrapper over [`Store::insert_message_in`] for the common case.
    /// Kept as its own method so the twenty-odd existing call sites do not have to
    /// name a kind they do not care about.
    pub fn insert_message(
        &self,
        conversation: &[u8],
        sender: &[u8],
        sent_at: i64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.insert_message_in(
            conversation,
            ConversationKind::Direct,
            sender,
            sent_at,
            plaintext,
        )
    }

    /// Insert an encrypted message into a conversation of a given kind.
    ///
    /// * Plaintext is encrypted here and never stored.
    /// * `expires_at` is **precomputed** and rejected if already in the past,
    ///   which stops a caller from accidentally inserting an immortal row
    ///   (`plan.md` §6.5(3)).
    ///
    /// # Why the kind is a parameter
    ///
    /// The conversation row is auto-created when a message arrives for one that does
    /// not exist yet. That auto-created row used to hardcode `kind = 'direct'`, which
    /// meant a group message would create a conversation the UI then labelled as a
    /// direct chat. The kind is now bound as a parameter so the caller states what it
    /// is writing into, and the SQL carries no literal.
    ///
    /// On conflict the kind is **not** overwritten: a conversation's kind is set when
    /// it is created. Flipping an existing conversation from `direct` to `group`
    /// would silently reinterpret its history.
    pub fn insert_message_in(
        &self,
        conversation: &[u8],
        kind: ConversationKind,
        sender: &[u8],
        sent_at: i64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let now = self.now();
        let expires_at = self.expiry_for(sent_at);

        if expires_at <= now {
            return Err(StorageError::AlreadyExpired { expires_at, now });
        }

        // The bucket is chosen from the *send* time so a message never lands in
        // a bucket that would be shredded while the message is still live.
        let bucket = BucketId::from_epoch(sent_at);
        let key = self.open_bucket(&bucket)?;

        let id = random_id();
        let nonce = random_nonce();
        let nonce_arr: [u8; 12] = nonce
            .as_slice()
            .try_into()
            .expect("random_nonce always returns 12 bytes");

        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let aad = message_aad(conversation, sender, sent_at, expires_at);
        let ciphertext = cipher
            .encrypt(
                (&nonce_arr).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::Decrypt)?;

        let conn = self.conn.lock().unwrap();

        // A message implies its conversation, so create the parent row if it does
        // not exist. `messages.conversation` is a real foreign key, and requiring
        // every caller to create conversations first would be an easy way to lose
        // messages to a constraint error at the worst moment.
        //
        // The conversation's own expiry is the *latest* expiry among its messages,
        // so it never outlives its content (`plan.md` §6.4).
        conn.execute(
            "INSERT INTO conversations (id, kind, peer_or_group, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               expires_at = MAX(conversations.expires_at, excluded.expires_at)",
            rusqlite::params![conversation, kind.as_str(), sender, now, expires_at],
        )?;

        conn.execute(
            "INSERT INTO messages
               (id, conversation, sender, sent_at, received_at, expires_at, bucket, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &id,
                conversation,
                sender,
                sent_at,
                now,
                expires_at,
                bucket.as_str(),
                &nonce,
                &ciphertext
            ],
        )?;

        Ok(id)
    }

    /// Decrypt a stored message by id.
    ///
    /// Expired messages are unavailable even before the scheduled purge runs.
    /// Retired buckets are rejected by the key ring as an additional policy check.
    pub fn read_message(&self, id: &[u8]) -> Result<Vec<u8>> {
        let now = self.now();
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT conversation, sender, sent_at, expires_at, bucket, nonce, ciphertext
                 FROM messages WHERE id = ?1 AND expires_at > ?2",
                rusqlite::params![id, now],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::InvalidRecord("message not found"))?;

        let (conversation, sender, sent_at, expires_at, bucket, nonce, ciphertext) = row;
        let bucket = BucketId::parse(&bucket)?;
        let key = self.keys.get(&bucket)?;

        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| StorageError::InvalidRecord("bad nonce length"))?;

        let aad = message_aad(&conversation, &sender, sent_at, expires_at);
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::Decrypt)?;

        Ok(plaintext)
    }

    /// Count stored messages, optionally only those not yet expired.
    pub fn message_count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Execute the retention purge (`plan.md` §6.1, §6.2).
    ///
    /// Three things happen, in order:
    ///
    /// 1. Rows past `expires_at` are deleted, per table.
    /// 2. Buckets whose **entire** month has aged past the ceiling are
    ///    crypto-shredded — their keys are destroyed, so any ciphertext that
    ///    survived the delete (or a filesystem-level copy) is unrecoverable.
    /// 3. Optionally `VACUUM`, and always `PRAGMA incremental_vacuum` to reclaim
    ///    freed pages.
    ///
    /// Step 2 is why this is safe even though `VACUUM` cannot be trusted to
    /// physically erase flash blocks (§6.2).
    pub fn purge(&self, now: i64) -> Result<PurgeReport> {
        let mut report = PurgeReport::default();

        {
            let conn = self.conn.lock().unwrap();
            for (table, sql) in schema::PURGE_STATEMENTS {
                // `now` is bound as an integer, so the comparison is
                // integer-to-integer and uses the same clock as every insert.
                let deleted = conn.execute(sql, [now])?;
                if deleted > 0 {
                    report.deleted.push(((*table).to_string(), deleted));
                }
            }
        }

        // Crypto-shredding: shred any bucket whose entire month already lies outside
        // the retention window. Two conditions must both hold for a bucket to be
        // safe to shred:
        //
        //   1. The bucket's month is *strictly older* than the month containing
        //      the retention cutoff. A bucket equal to the cutoff month may still
        //      hold a live record, so it is never shredded.
        //   2. The bucket's month has, in fact, ended (its next month has begun)
        //      on or before the cutoff. This guards against a clock jump that has
        //      not actually aged the data.
        //
        // Together these keep a 90-day ceiling compatible with monthly buckets:
        // shredding can never destroy a live record.
        let cutoff = now.saturating_sub(anon_core::RETENTION_SECONDS);
        let cutoff_bucket = BucketId::from_epoch(cutoff);

        for bucket in self.keys.live_buckets() {
            if bucket.as_str() >= cutoff_bucket.as_str() {
                continue;
            }
            let Some(bucket_end) = bucket.next_bucket_start() else {
                continue;
            };
            if bucket_end <= cutoff && self.keys.shred(&bucket) {
                // Persist the retirement so a restart cannot re-derive a key for a
                // bucket that was already shredded.
                self.retire_bucket(&bucket)?;
                report.shredded_buckets.push(bucket.to_string());
            }
        }

        {
            let conn = self.conn.lock().unwrap();
            // `incremental_vacuum` requires `auto_vacuum` (set in SETUP_PRAGMAS).
            let _ = conn.execute_batch("PRAGMA incremental_vacuum");

            if self.config.vacuum_after_purge {
                report.vacuumed = conn.execute_batch("VACUUM").is_ok();
            }
        }

        Ok(report)
    }

    /// Access the key ring, for tests that need to inspect shredding state.
    pub fn key_ring(&self) -> &Arc<KeyRing> {
        &self.keys
    }

    /// The database file this store was opened from.
    ///
    /// Exposed so a second connection (MLS group state) can be opened against
    /// the same encrypted file rather than a separate database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Execute a statement and return the number of affected rows.
    ///
    /// Crate-internal: the mailbox module needs to write rows whose encryption is
    /// its own concern, and duplicating the connection plumbing there would mean
    /// two places to get the locking wrong.
    pub(crate) fn raw_execute(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(sql, params)?)
    }

    /// Run a query and collect every row as an owned [`OwnedRow`].
    pub(crate) fn raw_query_all(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<OwnedRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query(params)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(columns);
            for i in 0..columns {
                values.push(row.get::<_, rusqlite::types::Value>(i)?);
            }
            out.push(OwnedRow(values));
        }
        Ok(out)
    }

    /// Execute arbitrary SQL against the store's connection.
    ///
    /// Exists so integration tests can simulate a *malicious host* editing rows
    /// behind the API's back — the tampering tests need to corrupt storage in ways
    /// the public API deliberately prevents. Not part of the supported surface.
    #[doc(hidden)]
    pub fn raw_execute_for_test(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize> {
        self.raw_execute(sql, params)
    }

    /// Run a query expected to return at most one row.
    pub(crate) fn raw_query_one(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<OwnedRow>> {
        Ok(self.raw_query_all(sql, params)?.into_iter().next())
    }

    /// Copy this store's contents into another store.
    ///
    /// Uses SQLite's backup API rather than a filesystem copy: a filesystem copy of a
    /// live database can capture a torn page, whereas the backup API produces a
    /// consistent snapshot. The destination must already be open with its own key, so
    /// the copy lands encrypted under that key — which is what makes a rekey a copy
    /// rather than an in-place rewrite.
    ///
    /// The destination's existing contents are replaced.
    pub fn backup_into(&self, dest: &Store) -> Result<()> {
        let src_conn = self.conn.lock().unwrap();
        let mut dest_conn = dest.conn.lock().unwrap();
        // `Backup::new` takes the destination as `&mut` because SQLite forbids any
        // other API call on the destination while a backup is running. Both
        // connections are already keyed, so the copy lands encrypted under the
        // destination's key — which is the whole point of copying rather than
        // rewriting in place.
        let backup = rusqlite::backup::Backup::new(&src_conn, &mut dest_conn)
            .map_err(|_| StorageError::InvalidRecord("the database copy could not start"))?;
        backup
            .run_to_completion(100, std::time::Duration::from_millis(0), None)
            .map_err(|_| StorageError::InvalidRecord("the database copy failed"))?;
        Ok(())
    }

    /// Row counts for every table in the schema.
    ///
    /// Used by the rekey verification to prove a copy is complete before it replaces the
    /// original. Counts every table the DDL creates, not only the retention-bound ones, so
    /// a copy that lost a metadata table is caught too.
    ///
    /// A table that does not exist is reported as `-1` rather than failing the whole
    /// call: during a migration the copy may legitimately be mid-schema.
    pub fn table_row_counts(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            // Table names come from `sqlite_master`, not from user input, so quoting them
            // into the statement is safe. They are still quoted to handle names that need
            // it.
            let count: rusqlite::Result<i64> = conn.query_row(
                &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
                [],
                |r| r.get(0),
            );
            out.push((name, count.unwrap_or(-1)));
        }
        Ok(out)
    }

    /// Open a second connection to the same encrypted database.
    ///
    /// The key is applied from the existing [`KeyRing`], so the caller never
    /// handles key material and there is still exactly one owner of the master
    /// key. The returned connection carries the same pragmas as the primary one.
    ///
    /// This exists because `openmls_sqlite_storage` takes its `Connection` by
    /// value, so it cannot share the `Mutex`-guarded connection the store uses.
    /// SQLite supports multiple connections to one file, and both are encrypted
    /// with the same key — so MLS state is covered by the same at-rest
    /// encryption as everything else (`plan.md` §6.3).
    pub fn open_secondary_connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path).map_err(|_| StorageError::OpenFailed)?;
        self.keys.apply_to(&conn)?;
        // Verify the key before handing the connection out, for the same reason
        // `open` does: a wrong key otherwise surfaces as a confusing error later.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::OpenFailed)?;
        for pragma in schema::SETUP_PRAGMAS {
            conn.execute_batch(pragma)?;
        }
        Ok(conn)
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("config", &self.config)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// Associated data bound into a message's AEAD.
///
/// Binding conversation, sender, and both timestamps prevents an attacker (or a
/// bug) from moving a ciphertext to a different conversation, attributing it to a
/// different sender, or altering its retention window.
fn message_aad(conversation: &[u8], sender: &[u8], sent_at: i64, expires_at: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(conversation.len() + sender.len() + 16 + 16);
    aad.extend_from_slice(b"anon/v1/message");
    aad.extend_from_slice(&(conversation.len() as u32).to_le_bytes());
    aad.extend_from_slice(conversation);
    aad.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    aad.extend_from_slice(sender);
    aad.extend_from_slice(&sent_at.to_le_bytes());
    aad.extend_from_slice(&expires_at.to_le_bytes());
    aad
}

/// Derive the database master key with Argon2id.
fn derive_master_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    if params.m_cost == 0 || params.t_cost == 0 || params.p_cost == 0 {
        return Err(StorageError::InvalidParams(
            "cost parameters must be non-zero",
        ));
    }

    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| StorageError::InvalidParams("rejected by argon2"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| StorageError::KeyDerivation)?;
    Ok(key)
}

/// Load the per-database salt, creating it on first use.
///
/// The salt is not secret; it only prevents cross-database rainbow tables. It
/// lives beside the database so the two stay together.
fn load_or_create_salt(db_path: &Path) -> Result<[u8; 16]> {
    let mut salt_path = db_path.as_os_str().to_owned();
    salt_path.push(".salt");
    let salt_path = std::path::PathBuf::from(salt_path);

    if let Ok(existing) = std::fs::read(&salt_path) {
        if let Ok(arr) = <[u8; 16]>::try_from(existing.as_slice()) {
            return Ok(arr);
        }
    }

    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| StorageError::KeyDerivation)?;
    std::fs::write(&salt_path, salt).map_err(|_| StorageError::KeyDerivation)?;
    Ok(salt)
}

/// Give SQLCipher a raw key.
///
/// `PRAGMA key = "x'<hex>'"` passes key material to SQLCipher without it
/// performing its own KDF (we already did Argon2id). The hex string is built as
/// SQL text, so the key is never interpolated into a statement that could be
/// logged — the connection stays local.
fn apply_sqlcipher_key(conn: &Connection, master: &Zeroizing<[u8; 32]>) -> Result<()> {
    let mut hex = String::with_capacity(64);
    for b in master.as_ref() {
        hex.push_str(&format!("{b:02x}"));
    }
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))?;
    hex.clear();
    Ok(())
}

fn random_id() -> Vec<u8> {
    let mut id = vec![0u8; 16];
    getrandom::fill(&mut id).expect("OS entropy is available");
    id
}

fn random_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 12];
    getrandom::fill(&mut nonce).expect("OS entropy is available");
    nonce
}
