//! Group lifecycle tests, including the §7.1 Phase 4 exit criterion.
//!
//! The headline test is [`removed_member_cannot_decrypt`]: `plan.md` §4.2 claims
//! MLS gives forward secrecy on removal, and §7.1 requires that claim be *tested
//! explicitly* rather than assumed. A test that only checked "the epoch number
//! went up" would pass even if the removed member could still read everything.
//!
//! # Why each peer gets its own store
//!
//! Every peer is a separate device with its own encrypted database — that is the
//! whole point of a serverless design. Sharing one store between peers would
//! also be wrong mechanically: MLS refuses to create a group whose id already
//! exists in the same storage, so a shared store cannot represent two members of
//! one group. [`Peer`] models one device.

use anon_mls::{Group, MlsError, MlsProvider};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::PathBuf;

/// One device: its own encrypted database and its own MLS provider.
struct Peer {
    dir: PathBuf,
    store: Store,
}

impl Peer {
    fn new(name: &str) -> Self {
        // A monotonic counter, not a timestamp: tests run concurrently in one
        // process, and two `SystemTime::now()` calls can land in the same
        // nanosecond, which would make two peers share a directory.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("anon-mls-test-{name}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let store = Store::open(
            &dir.join("anon.db"),
            "correct horse battery staple",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .expect("store opens");
        Self { dir, store }
    }

    /// A provider over this device's encrypted database.
    ///
    /// A fresh connection each call is fine: all MLS state lives in the file, so
    /// this also exercises the "reopen and keep working" path.
    fn provider(&self) -> MlsProvider {
        MlsProvider::new(
            self.store
                .open_secondary_connection()
                .expect("secondary conn"),
        )
        .expect("provider")
    }

    fn db_path(&self) -> PathBuf {
        self.dir.join("anon.db")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const ALICE: &[u8] = b"anon1alice";
const BOB: &[u8] = b"anon1bob";
const CAROL: &[u8] = b"anon1carol";

/// Alice creates a group and adds Bob. Returns both devices, Alice's group, and
/// the Welcome Bob needs to join.
fn alice_and_bob() -> (Peer, Peer, Group, Vec<u8>) {
    let alice_dev = Peer::new("alice");
    let bob_dev = Peer::new("bob");

    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();

    let mut alice = Group::create(&alice_p, ALICE).expect("create");
    let bob_kp = Group::key_package(&bob_p, BOB).expect("bob kp");
    let add = alice.add_members(&alice_p, &[bob_kp]).expect("add bob");

    (alice_dev, bob_dev, alice, add.welcome)
}

#[test]
fn create_group_starts_at_epoch_zero_with_one_member() {
    let dev = Peer::new("create");
    let p = dev.provider();
    let group = Group::create(&p, ALICE).expect("create");

    assert_eq!(group.epoch(), 0);
    let info = group.info();
    assert_eq!(info.members.len(), 1);
    assert!(info.members[0].is_self);
    assert_eq!(info.members[0].identity, ALICE);
}

#[test]
fn adding_a_member_advances_the_epoch_and_grows_the_member_list() {
    let alice_dev = Peer::new("add-alice");
    let bob_dev = Peer::new("add-bob");
    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();

    let mut alice = Group::create(&alice_p, ALICE).expect("create");
    let bob_kp = Group::key_package(&bob_p, BOB).expect("bob kp");

    let outcome = alice.add_members(&alice_p, &[bob_kp]).expect("add bob");
    assert_eq!(outcome.epoch, 1);
    assert_eq!(alice.epoch(), 1);
    assert_eq!(alice.info().members.len(), 2);
    assert!(!outcome.welcome.is_empty(), "a Welcome is required to join");
    assert!(
        !outcome.commit.is_empty(),
        "a Commit is required to advance"
    );
}

#[test]
fn a_joined_member_can_decrypt_messages_from_the_group() {
    let (alice_dev, bob_dev, mut alice, welcome) = alice_and_bob();
    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();

    let mut bob = Group::join_from_welcome(&bob_p, &welcome).expect("bob joins");
    assert_eq!(bob.epoch(), alice.epoch());
    assert_eq!(bob.info().members.len(), 2);

    let ciphertext = alice.encrypt(&alice_p, b"hello bob").expect("encrypt");
    let plaintext = bob.decrypt(&bob_p, &ciphertext).expect("bob decrypts");
    assert_eq!(plaintext, b"hello bob");
}

/// The §7.1 Phase 4 exit criterion, asserted rather than assumed.
#[test]
fn removed_member_cannot_decrypt() {
    let (alice_dev, bob_dev, mut alice, welcome) = alice_and_bob();
    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();

    let mut bob = Group::join_from_welcome(&bob_p, &welcome).expect("bob joins");

    // Sanity: before removal, Bob really can read Alice's messages. Without this
    // the test could pass for the wrong reason (e.g. Bob never worked at all).
    let before = alice.encrypt(&alice_p, b"before removal").expect("encrypt");
    assert_eq!(
        bob.decrypt(&bob_p, &before).expect("bob reads"),
        b"before removal"
    );

    let bob_index = bob.own_index();
    let epoch_before = alice.epoch();
    let removal = alice
        .remove_member(&alice_p, bob_index)
        .expect("remove bob");

    // The epoch must advance: that is what re-keys the group.
    assert!(
        removal.epoch > epoch_before,
        "removal must advance the epoch ({epoch_before} -> {})",
        removal.epoch
    );
    assert_eq!(alice.info().members.len(), 1);

    // The removed member must not be able to read anything from the new epoch.
    let after = alice.encrypt(&alice_p, b"after removal").expect("encrypt");
    match bob.decrypt(&bob_p, &after) {
        Err(MlsError::Decrypt) => {}
        Err(other) => panic!("expected Decrypt, got {other:?}"),
        Ok(plaintext) => panic!(
            "SECURITY: removed member decrypted post-removal message: {:?}",
            String::from_utf8_lossy(&plaintext)
        ),
    }
}

#[test]
fn remaining_members_can_still_talk_after_a_removal() {
    let alice_dev = Peer::new("rm-alice");
    let bob_dev = Peer::new("rm-bob");
    let carol_dev = Peer::new("rm-carol");

    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();
    let carol_p = carol_dev.provider();

    let mut alice = Group::create(&alice_p, ALICE).expect("create");
    let bob_kp = Group::key_package(&bob_p, BOB).expect("bob kp");
    let carol_kp = Group::key_package(&carol_p, CAROL).expect("carol kp");
    let add = alice
        .add_members(&alice_p, &[bob_kp, carol_kp])
        .expect("add both");

    let bob = Group::join_from_welcome(&bob_p, &add.welcome).expect("bob joins");
    let mut carol = Group::join_from_welcome(&carol_p, &add.welcome).expect("carol joins");

    let bob_index = bob.own_index();
    let removal = alice
        .remove_member(&alice_p, bob_index)
        .expect("remove bob");

    // Carol must apply the Commit to reach the new epoch.
    let _ = carol.decrypt(&carol_p, &removal.commit);

    let ciphertext = alice.encrypt(&alice_p, b"carol only").expect("encrypt");
    assert_eq!(
        carol.decrypt(&carol_p, &ciphertext).expect("carol reads"),
        b"carol only"
    );
}

#[test]
fn group_state_survives_a_reopen() {
    let (alice_dev, _bob_dev, alice, _welcome) = alice_and_bob();
    let group_id = alice.group_id().to_vec();
    let epoch = alice.epoch();
    drop(alice);

    // A fresh provider over a fresh connection to the same encrypted file.
    let p = alice_dev.provider();
    let loaded = Group::load(&p, &group_id)
        .expect("load")
        .expect("group should be present after reopen");
    assert_eq!(loaded.epoch(), epoch);
    assert_eq!(loaded.info().members.len(), 2);
}

#[test]
fn a_loaded_group_can_still_encrypt() {
    // Persistence is only useful if the reloaded group is functional, not just
    // readable. This catches a missing signature key, which OpenMLS stores
    // separately from group state.
    let (alice_dev, _bob_dev, alice, _welcome) = alice_and_bob();
    let group_id = alice.group_id().to_vec();
    drop(alice);

    let p = alice_dev.provider();
    let mut loaded = Group::load(&p, &group_id).expect("load").expect("present");
    let ciphertext = loaded.encrypt(&p, b"still works").expect("encrypt");
    assert!(!ciphertext.is_empty());
}

#[test]
fn loading_an_unknown_group_returns_none() {
    let dev = Peer::new("unknown");
    let p = dev.provider();
    assert!(Group::load(&p, b"no-such-group").expect("load").is_none());
}

#[test]
fn removing_the_last_member_is_refused() {
    let dev = Peer::new("last-member");
    let p = dev.provider();
    let mut alice = Group::create(&p, ALICE).expect("create");
    let own = alice.own_index();
    assert!(matches!(
        alice.remove_member(&p, own),
        Err(MlsError::WouldEmptyGroup)
    ));
}

#[test]
fn removing_an_unknown_member_is_refused() {
    let (alice_dev, _bob_dev, mut alice, _welcome) = alice_and_bob();
    let p = alice_dev.provider();
    assert!(matches!(
        alice.remove_member(&p, 99),
        Err(MlsError::UnknownMember(99))
    ));
}

#[test]
fn a_tampered_ciphertext_is_rejected() {
    let (alice_dev, bob_dev, mut alice, welcome) = alice_and_bob();
    let alice_p = alice_dev.provider();
    let bob_p = bob_dev.provider();
    let mut bob = Group::join_from_welcome(&bob_p, &welcome).expect("bob joins");

    let mut ciphertext = alice.encrypt(&alice_p, b"integrity").expect("encrypt");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xff;

    assert!(
        bob.decrypt(&bob_p, &ciphertext).is_err(),
        "a flipped bit must not decrypt"
    );
}

#[test]
fn garbage_input_is_rejected_without_panicking() {
    let dev = Peer::new("garbage");
    let p = dev.provider();
    let mut alice = Group::create(&p, ALICE).expect("create");
    for bad in [&b""[..], &b"\x00"[..], &b"not mls at all"[..]] {
        assert!(alice.decrypt(&p, bad).is_err());
    }
}

#[test]
fn an_empty_identity_is_refused() {
    let dev = Peer::new("empty-id");
    let p = dev.provider();
    assert!(matches!(
        Group::create(&p, b""),
        Err(MlsError::InvalidIdentity(_))
    ));
}

#[test]
fn an_invalid_key_package_is_refused() {
    let dev = Peer::new("bad-kp");
    let p = dev.provider();
    let mut alice = Group::create(&p, ALICE).expect("create");
    assert!(matches!(
        alice.add_members(&p, &[vec![0xff; 32]]),
        Err(MlsError::InvalidKeyPackage(_))
    ));
}

#[test]
fn mls_state_is_encrypted_at_rest() {
    // plan.md §6.3: all local state is encrypted. MLS state lives in the same
    // SQLCipher file, so a plaintext identity must not appear in the bytes.
    let (alice_dev, _bob_dev, alice, _welcome) = alice_and_bob();
    drop(alice);

    let bytes = std::fs::read(alice_dev.db_path()).expect("read db");
    assert!(!bytes.is_empty());
    for needle in [ALICE, BOB] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "identity {:?} found in plaintext in the database file",
            String::from_utf8_lossy(needle)
        );
    }
}
