//! The user's own display name survives a restart.
//!
//! Before this, the name lived only in an in-memory mutex inside `anon-ipc`'s
//! `Backend` and vanished on every launch — which also meant the signed invite
//! could not carry it. These tests pin the storage contract: set, reopen, still
//! there; clear, reopen, gone.

use anon_storage::{Argon2Params, Store, StoreConfig};

const PASSPHRASE: &str = "test-database-passphrase-1234";

fn open(dir: &tempdir::TempDir) -> Store {
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    };
    let mut store =
        Store::open(&dir.path().join("test.db"), PASSPHRASE, config).expect("open store");
    store.freeze_clock_at(1_700_000_000);
    store
}

/// Minimal temp-dir helper so the crate has no dev-dependency on `tempfile`.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-storage-{tag}-{}-{:?}",
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

#[test]
fn a_set_name_survives_a_reopen() {
    let dir = tempdir::TempDir::new("name-set");
    {
        let s = open(&dir);
        assert_eq!(s.display_name().unwrap(), None, "fresh install has no name");
        s.set_display_name(Some("Jared")).unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.display_name().unwrap(), Some("Jared".to_string()));
}

#[test]
fn clearing_the_name_survives_a_reopen() {
    let dir = tempdir::TempDir::new("name-clear");
    {
        let s = open(&dir);
        s.set_display_name(Some("Jared")).unwrap();
        s.set_display_name(None).unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.display_name().unwrap(), None);
}

#[test]
fn an_overwrite_replaces_the_previous_name() {
    let dir = tempdir::TempDir::new("name-overwrite");
    {
        let s = open(&dir);
        s.set_display_name(Some("First")).unwrap();
        s.set_display_name(Some("Second")).unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.display_name().unwrap(), Some("Second".to_string()));
}

#[test]
fn the_name_is_not_in_any_message_or_contact_row() {
    // The name is a schema_meta scalar, not a message field: it must not leak
    // into rows that get purged or exported as conversations.
    let dir = tempdir::TempDir::new("name-isolation");
    let s = open(&dir);
    s.set_display_name(Some("Jared")).unwrap();
    s.insert_message(b"conv", b"peer", 1_700_000_000, b"hello")
        .unwrap();
    let conversations = s.conversations().unwrap();
    assert_eq!(conversations.len(), 1);
    assert_ne!(
        conversations[0].peer_or_group,
        b"Jared".as_slice(),
        "the display name is not a conversation peer"
    );
}
