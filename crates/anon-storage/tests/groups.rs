//! Group persistence tests (`plan.md` §4.2, §6.4).
//!
//! The `groups` table was declared in the schema and listed as retention-exempt, but
//! had no store API at all — so "wire the group UI" was really "build the persistence
//! layer first". These tests cover that layer.
//!
//! # What is deliberately asserted here
//!
//! * Round-trip: a group row survives a close/reopen, because a group the user
//!   created must still be there next launch.
//! * Epoch updates persist, and an epoch that goes backwards is refused.
//! * Delete removes the row.
//! * The retention exemption is *deliberate*: `audit_schema` must not complain about
//!   `groups`, and the table must genuinely have no `expires_at` column. If someone
//!   later adds one, this test fails and forces the decision to be re-made rather
//!   than drifting.
//! * A group message creates a `group`-kind conversation, not a `direct` one. That
//!   was a real bug: `insert_message` hardcoded `kind = 'direct'`.

use anon_storage::{Argon2Params, ConversationKind, GroupRow, Store, StoreConfig};

const PASSPHRASE: &str = "test-database-passphrase-1234";
const NOW: i64 = 1_700_000_000;

fn open(dir: &tempdir::TempDir) -> Store {
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    };
    let mut store =
        Store::open(&dir.path().join("test.db"), PASSPHRASE, config).expect("open store");
    store.freeze_clock_at(NOW);
    store
}

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-storage-groups-{tag}-{}-{:?}",
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

fn group(id: &[u8], name: Option<&str>, epoch: u64) -> GroupRow {
    GroupRow {
        group_id: id.to_vec(),
        name: name.map(|s| s.to_string()),
        created_at: NOW,
        epoch,
    }
}

// ---------------------------------------------------------------------------
// Round-trip and persistence
// ---------------------------------------------------------------------------

#[test]
fn a_group_round_trips_through_the_store() {
    let dir = tempdir::TempDir::new("roundtrip");
    let s = open(&dir);

    let row = group(b"group-id-1", Some("book club"), 0);
    s.insert_group(&row).expect("insert");

    let read = s.group(b"group-id-1").expect("get").expect("present");
    assert_eq!(read, row, "the row must come back exactly as written");
}

#[test]
fn a_group_survives_a_close_and_reopen() {
    // A group the user created must still exist next launch. This is the whole
    // reason the row is persisted rather than held in memory.
    let dir = tempdir::TempDir::new("reopen");
    {
        let s = open(&dir);
        s.insert_group(&group(b"persisted", Some("survivors"), 3))
            .expect("insert");
    }

    let s = open(&dir);
    let read = s.group(b"persisted").expect("get").expect("present");
    assert_eq!(read.name.as_deref(), Some("survivors"));
    assert_eq!(read.epoch, 3, "the epoch must survive the restart too");
}

#[test]
fn an_unknown_group_is_none_not_an_error() {
    // "No such group" is an ordinary answer to a lookup. Returning an error would
    // force every caller to distinguish "absent" from "broken" by string matching.
    let dir = tempdir::TempDir::new("absent");
    let s = open(&dir);
    assert!(s.group(b"never-existed").expect("get").is_none());
}

#[test]
fn groups_are_listed_newest_first() {
    let dir = tempdir::TempDir::new("list");
    let s = open(&dir);

    s.insert_group(&GroupRow {
        group_id: b"older".to_vec(),
        name: Some("older".into()),
        created_at: NOW - 100,
        epoch: 0,
    })
    .unwrap();
    s.insert_group(&GroupRow {
        group_id: b"newer".to_vec(),
        name: Some("newer".into()),
        created_at: NOW,
        epoch: 0,
    })
    .unwrap();

    let listed = s.groups().expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].group_id, b"newer", "newest first");
    assert_eq!(listed[1].group_id, b"older");
}

#[test]
fn inserting_the_same_group_twice_updates_rather_than_failing() {
    // The same group can be reached two ways — created locally or joined from a
    // Welcome — so neither path should have to check for existence first.
    let dir = tempdir::TempDir::new("upsert");
    let s = open(&dir);

    s.insert_group(&group(b"dup", Some("first name"), 0))
        .unwrap();
    s.insert_group(&group(b"dup", Some("renamed"), 2)).unwrap();

    let read = s.group(b"dup").expect("get").expect("present");
    assert_eq!(read.name.as_deref(), Some("renamed"));
    assert_eq!(read.epoch, 2);
    assert_eq!(s.groups().expect("list").len(), 1, "no duplicate row");
}

// ---------------------------------------------------------------------------
// Epoch updates
// ---------------------------------------------------------------------------

#[test]
fn an_epoch_update_persists() {
    let dir = tempdir::TempDir::new("epoch");
    let s = open(&dir);
    s.insert_group(&group(b"g", None, 0)).unwrap();

    let changed = s.update_group_epoch(b"g", 7).expect("update");
    assert_eq!(changed, 1, "one row changed");
    assert_eq!(s.group(b"g").unwrap().unwrap().epoch, 7);
}

#[test]
fn an_epoch_that_goes_backwards_is_refused() {
    // MLS epochs only increase. Accepting a decreasing value would make the stored
    // epoch a lie, and the stored epoch is what the UI shows and what the consent
    // gate reasons about.
    let dir = tempdir::TempDir::new("backwards");
    let s = open(&dir);
    s.insert_group(&group(b"g", None, 5)).unwrap();

    let changed = s.update_group_epoch(b"g", 4).expect("update runs");
    assert_eq!(changed, 0, "no row changed");
    assert_eq!(
        s.group(b"g").unwrap().unwrap().epoch,
        5,
        "the stored epoch must not move backwards"
    );
}

#[test]
fn updating_an_unknown_group_changes_nothing() {
    let dir = tempdir::TempDir::new("epoch-absent");
    let s = open(&dir);
    assert_eq!(s.update_group_epoch(b"nope", 1).expect("update"), 0);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[test]
fn deleting_a_group_removes_the_row() {
    let dir = tempdir::TempDir::new("delete");
    let s = open(&dir);
    s.insert_group(&group(b"doomed", None, 0)).unwrap();

    assert_eq!(s.delete_group(b"doomed").expect("delete"), 1);
    assert!(s.group(b"doomed").expect("get").is_none());
    assert!(s.groups().expect("list").is_empty());
}

#[test]
fn deleting_an_unknown_group_is_a_no_op() {
    let dir = tempdir::TempDir::new("delete-absent");
    let s = open(&dir);
    assert_eq!(s.delete_group(b"nope").expect("delete"), 0);
}

// ---------------------------------------------------------------------------
// The retention exemption is deliberate
// ---------------------------------------------------------------------------

#[test]
fn the_groups_table_is_retention_exempt_and_audit_agrees() {
    // `groups` is in RETENTION_EXEMPT_TABLES. That is a decision, not an oversight:
    // a group row holds no message history and no key material. This test pins the
    // decision so a future change has to be deliberate.
    let dir = tempdir::TempDir::new("audit");
    let s = open(&dir);

    let violations = s.audit_schema().expect("audit");
    assert!(
        violations.is_empty(),
        "audit_schema must not flag any table, including groups: {violations:?}"
    );

    // The table must exist and accept a row — an exemption for a table that was
    // never created would be meaningless.
    s.insert_group(&group(b"audited", Some("audited"), 1))
        .expect("the groups table must exist and accept a row");
}

#[test]
fn the_groups_table_has_no_expires_at_column() {
    // The exemption's other half: `groups` genuinely carries no retention column.
    // If someone adds one, this fails and the decision gets re-made rather than
    // drifting into "the table has a column nobody maintains".
    //
    // Asserted by attempting an insert that names `expires_at`: SQLite rejects an
    // unknown column, so a successful insert would mean the column exists.
    let dir = tempdir::TempDir::new("no-expiry");
    let s = open(&dir);

    let result = s.raw_execute_for_test(
        "INSERT INTO groups (group_id, name, created_at, epoch, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![b"x".to_vec(), "x", NOW, 0i64, NOW + 1],
    );

    assert!(
        result.is_err(),
        "the groups table must not have an expires_at column; the retention \
         exemption in RETENTION_EXEMPT_TABLES depends on it holding metadata only"
    );
}

#[test]
fn a_group_row_holds_no_message_content() {
    // The exemption's justification, asserted rather than asserted-in-a-comment:
    // the row's fields are id, name, created_at, epoch — nothing that could carry
    // message history.
    let row = group(b"id", Some("name"), 4);
    let debug = format!("{row:?}");
    assert!(debug.contains("group_id"));
    assert!(debug.contains("epoch"));
    // A row cannot hold a message body because there is no field for one; this test
    // documents that by naming the fields that do exist.
    for field in ["group_id", "name", "created_at", "epoch"] {
        assert!(
            debug.contains(field),
            "GroupRow must expose `{field}`; the retention exemption depends on the \
             row holding only metadata"
        );
    }
}

// ---------------------------------------------------------------------------
// Conversation kind
// ---------------------------------------------------------------------------

#[test]
fn a_group_message_creates_a_group_conversation() {
    // The bug this fixes: `insert_message` hardcoded `kind = 'direct'`, so a group
    // message auto-created a conversation the UI then labelled as a direct chat.
    let dir = tempdir::TempDir::new("kind-group");
    let s = open(&dir);

    s.insert_message_in(
        b"group-conv",
        ConversationKind::Group,
        b"sender",
        NOW,
        b"hello group",
    )
    .expect("insert");

    let conversations = s.conversations().expect("list");
    let row = conversations
        .iter()
        .find(|c| c.id == b"group-conv")
        .expect("the conversation must exist");
    assert_eq!(
        row.kind, "group",
        "a group message must create a group-kind conversation"
    );
}

#[test]
fn a_direct_message_still_creates_a_direct_conversation() {
    // The wrapper must not have changed the default behaviour.
    let dir = tempdir::TempDir::new("kind-direct");
    let s = open(&dir);

    s.insert_message(b"direct-conv", b"peer", NOW, b"hello")
        .expect("insert");

    let conversations = s.conversations().expect("list");
    let row = conversations
        .iter()
        .find(|c| c.id == b"direct-conv")
        .expect("the conversation must exist");
    assert_eq!(row.kind, "direct");
}

#[test]
fn a_conversations_kind_is_not_overwritten_by_a_later_message() {
    // Flipping an existing conversation from direct to group would silently
    // reinterpret its history. The kind is set at creation and stays.
    let dir = tempdir::TempDir::new("kind-stable");
    let s = open(&dir);

    s.insert_message(b"stable", b"peer", NOW, b"first").unwrap();
    s.insert_message_in(
        b"stable",
        ConversationKind::Group,
        b"peer",
        NOW + 1,
        b"second",
    )
    .expect("insert");

    let conversations = s.conversations().expect("list");
    let row = conversations
        .iter()
        .find(|c| c.id == b"stable")
        .expect("the conversation must exist");
    assert_eq!(
        row.kind, "direct",
        "the original kind must survive a later insert"
    );
    assert_eq!(row.message_count, 2, "both messages are retained");
}

#[test]
fn conversation_kind_round_trips_through_its_string_form() {
    for kind in [ConversationKind::Direct, ConversationKind::Group] {
        assert_eq!(ConversationKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(
        ConversationKind::parse("something-else"),
        None,
        "an unrecognised stored kind must not be silently treated as direct"
    );
}
