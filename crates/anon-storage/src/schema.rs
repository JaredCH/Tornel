//! Database schema (`plan.md` §6.1, §6.4).
//!
//! # Design rules encoded here
//!
//! 1. **Every table that holds user content has an `expires_at` column.** A table
//!    without one would silently hold data past the retention ceiling, which
//!    would make the 90-day promise false. `Store::audit_schema` enforces this.
//! 2. **Tables are `STRICT`.** SQLite's default type affinity would happily store
//!    the text `"1700000000"` in an INTEGER column; `STRICT` rejects it. This is
//!    what makes the §6.1 bug structurally impossible rather than merely absent.
//! 3. **Times are `INTEGER` epoch seconds.** Never text, never a date string.
//! 4. **`expires_at` is indexed** so purge is an index scan, not a table scan —
//!    meaningful on constrained mobile storage.
//!
//! # Retention scope (`plan.md` §6.4)
//!
//! Retention applies to *every* store, not just messages. This schema therefore
//! covers conversations, messages, attachments, mailbox buffers, and the consent
//! audit log — each with its own `expires_at`.

/// Schema version. Bump on an incompatible change and add a migration.
pub const SCHEMA_VERSION: i32 = 1;

/// The mandatory retention ceiling in days (`plan.md` §6).
pub const RETENTION_DAYS: i64 = anon_core::RETENTION_DAYS;

/// Tables that must carry an `expires_at` column because they hold user content.
///
/// `Store::audit_schema` asserts the live database matches this list, so adding a
/// content table without retention fails a test rather than shipping.
pub const RETENTION_BOUND_TABLES: &[&str] = &[
    "conversations",
    "messages",
    "attachments",
    "mailbox_buffer",
    "send_queue",
    "consent_log",
];

/// Tables that are metadata and deliberately have no retention bound.
///
/// These hold no user content and no message history. If you add a table here,
/// justify why it cannot leak history.
pub const RETENTION_EXEMPT_TABLES: &[&str] = &[
    "schema_meta",
    "identity_meta",
    "live_buckets",
    "contacts",
    "groups",
    "group_roles",
];

/// The complete DDL.
///
/// Note `PRAGMA`s are issued separately: `journal_mode` and `foreign_keys` are
/// per-connection settings, and `auto_vacuum` must be set before the first table
/// is created to take effect.
pub const DDL: &str = r#"
-- Schema bookkeeping. Not retention-bound: it holds no user content.
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Identity metadata. The private seed lives in the OS keychain or the escrow
-- artifact, never here (plan.md §2.3). This table holds only the public
-- identity and the local display name.
CREATE TABLE IF NOT EXISTS identity_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

-- Live crypto-shredding buckets. Metadata only: these are labels, not keys.
-- Keys are derived, never stored (plan.md §6.2).
CREATE TABLE IF NOT EXISTS live_buckets (
    bucket       TEXT PRIMARY KEY,
    first_seen_at INTEGER NOT NULL,
    retired_at   INTEGER
) STRICT;

-- Contacts. Public keys only; no message content.
CREATE TABLE IF NOT EXISTS contacts (
    contact_code TEXT PRIMARY KEY,
    display_name TEXT,
    added_at     INTEGER NOT NULL,
    fingerprint  TEXT NOT NULL
) STRICT;

-- Groups. Holds MLS group identifiers; group keys live in the MLS store.
CREATE TABLE IF NOT EXISTS groups (
    group_id     BLOB PRIMARY KEY,
    name         TEXT,
    created_at   INTEGER NOT NULL,
    epoch        INTEGER NOT NULL
) STRICT;

-- Group member roles (owner, admin, moderator, member). Holds no message history.
CREATE TABLE IF NOT EXISTS group_roles (
    group_id     BLOB NOT NULL,
    contact_code TEXT NOT NULL,
    role         TEXT NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (group_id, contact_code)
) STRICT;

-- Conversations. Retention-bound: a conversation row is the entry point to
-- message history, so it must expire with it.
CREATE TABLE IF NOT EXISTS conversations (
    id           BLOB PRIMARY KEY,
    kind         TEXT NOT NULL,
    peer_or_group BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_conversations_expires_at
    ON conversations (expires_at);

-- Messages. The core retention-bound table.
CREATE TABLE IF NOT EXISTS messages (
    id          BLOB PRIMARY KEY,
    conversation BLOB NOT NULL,
    sender      BLOB NOT NULL,
    sent_at     INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    bucket      TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    epoch       INTEGER,
    CHECK (expires_at > sent_at),
    CHECK (expires_at > received_at),
    FOREIGN KEY (conversation) REFERENCES conversations (id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages (expires_at);
CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON messages (conversation, sent_at);

-- Attachments. Separate table so a large blob gets its own retention row
-- (plan.md §6.4 explicitly calls out attachments as an easy leak).
CREATE TABLE IF NOT EXISTS attachments (
    id          BLOB PRIMARY KEY,
    message_id  BLOB NOT NULL,
    media_type  TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    bucket      TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    expires_at  INTEGER NOT NULL,
    CHECK (size_bytes >= 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_attachments_expires_at
    ON attachments (expires_at);
CREATE INDEX IF NOT EXISTS idx_attachments_message
    ON attachments (message_id);

-- Peer-hosted mailbox buffer. Retention-bound on the host too, or an offline
-- peer could keep a copy longer than the ceiling (plan.md §6.4).
CREATE TABLE IF NOT EXISTS mailbox_buffer (
    id           BLOB PRIMARY KEY,
    recipient    BLOB NOT NULL,
    sender       BLOB NOT NULL,
    received_at  INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    size_bytes   INTEGER NOT NULL,
    bucket       TEXT NOT NULL,
    nonce        BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,
    CHECK (expires_at > received_at),
    CHECK (size_bytes >= 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_mailbox_expires_at ON mailbox_buffer (expires_at);
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient
    ON mailbox_buffer (recipient, received_at);

-- Outbound send queue. Holds frames that could not be handed to the transport
-- because the peer (or our own Tor circuit) was not reachable yet, so they can be
-- retried instead of being lost. Retention-bound for the same reason as the
-- mailbox: a message that never lands must not outlive the ceiling either.
--
-- The stored `ciphertext` is the already-sealed frame, re-encrypted at rest under
-- a bucket key. The queue therefore never holds plaintext, and a queue row that
-- survives a shred is undecryptable.
CREATE TABLE IF NOT EXISTS send_queue (
    id              BLOB PRIMARY KEY,
    conversation    BLOB NOT NULL,
    route           TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    attempts        INTEGER NOT NULL,
    last_attempt_at INTEGER,
    last_error      TEXT,
    bucket          TEXT NOT NULL,
    nonce           BLOB NOT NULL,
    ciphertext      BLOB NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (attempts >= 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_send_queue_expires_at ON send_queue (expires_at);
CREATE INDEX IF NOT EXISTS idx_send_queue_created
    ON send_queue (created_at);

-- Consent audit log (plan.md §5.2 "Auditability"). Retention-bound: the log
-- itself must not outlive the retention ceiling.
CREATE TABLE IF NOT EXISTS consent_log (
    id          BLOB PRIMARY KEY,
    proposal_id BLOB NOT NULL,
    occurred_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    epoch_before INTEGER,
    epoch_after  INTEGER,
    CHECK (expires_at > occurred_at)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_consent_expires_at ON consent_log (expires_at);
"#;

/// The purge statements, one per retention-bound table (`plan.md` §6.1).
///
/// Every statement filters on the **precomputed absolute** `expires_at`, never
/// on a re-derived `now - 90 days`. That is what stops a backwards clock change
/// or a long offline period from silently extending retention.
///
/// # Why `?1` and not `strftime('now')`
///
/// The cutoff is passed in as a bound integer parameter rather than read from
/// SQLite's own clock. Two reasons:
///
/// 1. **One clock.** The store already owns the notion of "now" (it is injected
///    so retention is testable, `plan.md` §10). Reading a *second*, independent
///    clock inside SQL would mean inserts and purges could disagree about the
///    time — and a test that freezes the clock would silently exercise the real
///    one.
/// 2. **No type ambiguity.** `?1` is bound as an `i64`, so the comparison is
///    integer-to-integer by construction. `strftime('%s', ...)` returns *text*,
///    which is the exact failure mode §6.1 warns about.
pub const PURGE_STATEMENTS: &[(&str, &str)] = &[
    ("messages", "DELETE FROM messages WHERE expires_at <= ?1"),
    (
        "attachments",
        "DELETE FROM attachments WHERE expires_at <= ?1",
    ),
    (
        "mailbox_buffer",
        "DELETE FROM mailbox_buffer WHERE expires_at <= ?1",
    ),
    (
        "send_queue",
        "DELETE FROM send_queue WHERE expires_at <= ?1",
    ),
    (
        "conversations",
        "DELETE FROM conversations WHERE expires_at <= ?1",
    ),
    (
        "consent_log",
        "DELETE FROM consent_log WHERE expires_at <= ?1",
    ),
];

/// Pragma applied to every connection.
pub const SETUP_PRAGMAS: &[&str] = &[
    // Required for `expires_at` to be a true absolute instant independent of
    // per-connection or historical local time.
    "PRAGMA foreign_keys = ON",
    // Layer 1 of the §6.2 wipe strategy: overwrite deleted content in-file.
    "PRAGMA secure_delete = ON",
    // Keep the freelist small so purge reclaims space without a full rewrite.
    // `incremental_vacuum` then only has to touch freed pages.
    "PRAGMA auto_vacuum = INCREMENTAL",
];

/// Legacy purge query, retained for documentation and regression detection.
///
/// This is the form from the original plan. It is **not** used by the store.
/// It appears here so the test suite can assert that the store does not rely on
/// it, and so the reason it is wrong stays visible next to the schema.
///
/// The bug: `strftime('%s', ...)` yields a *string*. If `timestamp` were a text
/// column the comparison is lexicographic and purges the wrong rows (or none).
pub const LEGACY_BROKEN_PURGE: &str =
    "DELETE FROM messages WHERE timestamp < strftime('%s', 'now', '-90 days')";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_retention_bound_table_has_an_expires_at_column() {
        // Guards the §6.4 requirement: a content table without retention would
        // make the 90-day promise false.
        for table in RETENTION_BOUND_TABLES {
            let create_marker = format!("CREATE TABLE IF NOT EXISTS {table} (");
            let start = DDL
                .find(&create_marker)
                .unwrap_or_else(|| panic!("no DDL for retention-bound table {table}"));
            let rest = &DDL[start..];
            let end = rest.find(") STRICT;").expect("table should be STRICT");
            let body = &rest[..end];

            assert!(
                body.contains("expires_at"),
                "table `{table}` is retention-bound but has no expires_at column"
            );
        }
    }

    #[test]
    fn every_retention_bound_table_is_in_the_purge_list() {
        for table in RETENTION_BOUND_TABLES {
            assert!(
                PURGE_STATEMENTS.iter().any(|(name, _)| name == table),
                "table `{table}` has no purge statement"
            );
        }
        assert_eq!(
            PURGE_STATEMENTS.len(),
            RETENTION_BOUND_TABLES.len(),
            "purge list and retention-bound table list disagree"
        );
    }

    #[test]
    fn all_content_tables_are_strict() {
        // `STRICT` is what makes the §6.1 type-confusion bug impossible.
        let strict_count = DDL.matches(") STRICT;").count();
        let table_count = DDL.matches("CREATE TABLE IF NOT EXISTS").count();
        assert_eq!(
            strict_count, table_count,
            "every table must be declared STRICT"
        );
    }

    #[test]
    fn no_table_uses_a_text_timestamp() {
        // Times must be INTEGER epoch seconds (plan.md §6.1).
        for bad in ["TEXT NOT NULL,\n    received_at", "sent_at       TEXT"] {
            assert!(!DDL.contains(bad), "found a text timestamp: {bad}");
        }
        assert!(DDL.contains("sent_at     INTEGER NOT NULL"));
        assert!(DDL.contains("expires_at  INTEGER NOT NULL"));
    }

    #[test]
    fn purge_statements_are_integer_compared_and_use_absolute_expiry() {
        for (table, sql) in PURGE_STATEMENTS {
            assert!(
                sql.contains("expires_at <="),
                "purge for `{table}` must compare the absolute expiry"
            );
            // The cutoff must be a bound integer parameter, not a value read from
            // SQLite's own clock: one clock, no text comparison (§6.1).
            assert!(
                sql.contains("?1"),
                "purge for `{table}` must bind the cutoff as a parameter"
            );
            assert!(
                !sql.contains("strftime"),
                "purge for `{table}` must not read a second clock via strftime"
            );
            // Re-deriving the window is the bug §6.1 warns about.
            assert!(
                !sql.contains("-90 days") && !sql.contains("-90 day"),
                "purge for `{table}` must not re-derive the retention window"
            );
        }
    }

    #[test]
    fn the_legacy_query_is_documented_as_broken() {
        // Keep the wrong form visible so nobody reintroduces it.
        assert!(LEGACY_BROKEN_PURGE.contains("-90 days"));
        assert!(
            !PURGE_STATEMENTS
                .iter()
                .any(|(_, sql)| *sql == LEGACY_BROKEN_PURGE),
            "the store must never use the legacy purge query"
        );
    }

    #[test]
    fn expires_at_is_indexed_on_every_bound_table() {
        for table in RETENTION_BOUND_TABLES {
            let index_marker = "(expires_at)";
            let has_index = DDL
                .lines()
                .any(|l| l.contains("ON") && l.contains(table) && l.contains(index_marker));
            assert!(has_index, "table `{table}` has no index on expires_at");
        }
    }

    #[test]
    fn retention_days_matches_the_core_policy() {
        // One source of truth for the ceiling.
        assert_eq!(RETENTION_DAYS, 90);
        assert_eq!(RETENTION_DAYS, anon_core::RETENTION_DAYS);
    }
}
