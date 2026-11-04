//! Group lifecycle through the backend facade (`plan.md` §4.2, §5.1, §7.1 Phase 4).
//!
//! These test the layer the UI actually calls. `anon-mls`'s own tests prove MLS works;
//! these prove the *backend* wires it correctly: a group is persisted, an add advances
//! the stored epoch, a removal drafts the rotation the consent modal then renders, and
//! no webview-supplied id is trusted.
//!
//! # What is not tested here
//!
//! Delivery. The transport in these tests is the fail-closed `OfflineTransport`, so
//! adding a member succeeds locally and returns a Welcome the inviter would have to
//! deliver — but nothing is sent. That is the honest state of this build without Tor
//! (see the README status section).

use anon_ipc::Backend;
use anon_storage::{Argon2Params, Store, StoreConfig};
use anon_transport::OfflineTransport;
use std::sync::Arc;

const PASSPHRASE: &str = "test-group-passphrase-1234";

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-ipc-groups-{tag}-{}-{:?}",
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

/// A store with light KDF parameters so tests stay fast.
///
/// The KDF *format* is identical to production; only the cost is reduced, so this
/// exercises the real code path.
fn open_store(dir: &tempdir::TempDir) -> Arc<Store> {
    let config = StoreConfig {
        params: Argon2Params::test_fast(),
        purge_on_open: false,
        vacuum_after_purge: false,
    };
    let mut store =
        Store::open(&dir.path().join("test.db"), PASSPHRASE, config).expect("open store");
    store.freeze_clock_at(1_700_000_000);
    Arc::new(store)
}

fn backend(dir: &tempdir::TempDir) -> Backend {
    let identity = anon_core::IdentityKeys::generate().expect("keygen");
    let store = open_store(dir);
    let transport: Arc<dyn anon_transport::AnonymityTransport> =
        Arc::new(OfflineTransport::new("no Tor in tests"));
    Backend::new(identity, transport, store)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[test]
fn creating_a_group_persists_it_and_returns_a_view() {
    let dir = tempdir::TempDir::new("create");
    let b = backend(&dir);

    let view = b.create_group("book club").expect("create");

    assert_eq!(view.name.as_deref(), Some("book club"));
    assert_eq!(view.epoch, 0, "a fresh MLS group starts at epoch 0");
    assert_eq!(view.member_count, 1, "the creator is the only member");
    assert!(!view.group_id.is_empty(), "the view must name the group");
    assert!(
        view.group_id.chars().all(|c| c.is_ascii_hexdigit()),
        "the group id crosses the boundary as hex"
    );

    // And it is listed.
    let listed = b.groups().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].group_id, view.group_id);
}

#[test]
fn a_created_group_is_listed_with_its_real_member_count() {
    // member_count is read from MLS state, not from the row. This asserts the wiring
    // actually reaches MLS rather than reporting a default.
    let dir = tempdir::TempDir::new("count");
    let b = backend(&dir);
    b.create_group("solo").expect("create");

    let listed = b.groups().expect("list");
    assert_eq!(listed[0].member_count, 1);
}

#[test]
fn the_group_name_is_trimmed_and_validated() {
    let dir = tempdir::TempDir::new("name");
    let b = backend(&dir);

    let view = b.create_group("  padded  ").expect("create");
    assert_eq!(
        view.name.as_deref(),
        Some("padded"),
        "a name is stored trimmed, matching set_display_name"
    );
}

#[test]
fn an_empty_group_name_is_rejected() {
    let dir = tempdir::TempDir::new("empty-name");
    let b = backend(&dir);
    let err = b.create_group("").expect_err("empty name must be refused");
    assert_eq!(err.code, "invalid_input");
}

#[test]
fn a_whitespace_only_group_name_is_rejected() {
    // Trimming happens first, so `"   "` must fail the same way `""` does.
    let dir = tempdir::TempDir::new("ws-name");
    let b = backend(&dir);
    let err = b
        .create_group("   ")
        .expect_err("whitespace only must be refused");
    assert_eq!(err.code, "invalid_input");
}

#[test]
fn an_overlong_group_name_is_rejected() {
    let dir = tempdir::TempDir::new("long-name");
    let b = backend(&dir);
    let err = b
        .create_group(&"x".repeat(65))
        .expect_err("a 65-character name must be refused");
    assert_eq!(err.code, "invalid_input");

    // Exactly 64 is allowed, so the boundary is inclusive.
    b.create_group(&"y".repeat(64))
        .expect("64 characters must be allowed");
}

#[test]
fn two_groups_are_independent() {
    let dir = tempdir::TempDir::new("two");
    let b = backend(&dir);

    let a = b.create_group("alpha").expect("create a");
    let c = b.create_group("beta").expect("create c");
    assert_ne!(a.group_id, c.group_id, "each group gets its own id");

    let listed = b.groups().expect("list");
    assert_eq!(listed.len(), 2);
}

#[test]
fn creating_a_group_registers_it_with_the_consent_gate() {
    // Without registration, a later rotation has no `epoch_before` to name and
    // draft_rotation fails with UnknownGroup.
    let dir = tempdir::TempDir::new("registered");
    let b = backend(&dir);

    let view = b.create_group("gated").expect("create");
    assert!(
        b.consent().group_state(&view.group_id).is_some(),
        "create_group must register the group so a rotation can be drafted"
    );
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_group_lists_its_creator_as_the_only_member() {
    let dir = tempdir::TempDir::new("members");
    let b = backend(&dir);
    let view = b.create_group("members").expect("create");

    let members = b.group_members(&view.group_id).expect("members");
    assert_eq!(members.len(), 1);
    assert!(members[0].is_self, "the creator must be flagged as self");
    assert_eq!(members[0].leaf_index, 0);
}

#[test]
fn the_members_contact_code_is_shortened_for_display() {
    // The member list shows a short fingerprint rather than a full contact code: the
    // UI needs enough to distinguish speakers, not a full identity dump.
    let dir = tempdir::TempDir::new("short");
    let b = backend(&dir);
    let view = b.create_group("short").expect("create");
    let code = b.contact_code().expect("contact code");

    let members = b.group_members(&view.group_id).expect("members");
    let shown = &members[0].contact_code_short;
    assert!(
        code.starts_with(shown.trim_end_matches('…')),
        "the short form must be a prefix of the real contact code"
    );
}

#[test]
fn adding_a_member_advances_the_epoch_and_returns_a_welcome() {
    let dir = tempdir::TempDir::new("add");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("grow").expect("create");

    // A peer's key package, produced from *their* identity and *their* MLS provider.
    // That is what makes the add real: the private material stays on their side.
    let key_package = peer_key_package(&store);

    let outcome = b
        .add_member(&view.group_id, &key_package)
        .expect("add member");

    assert_eq!(outcome.group_id, view.group_id);
    assert_eq!(outcome.epoch, 1, "an add advances the epoch");
    assert!(!outcome.welcome_hex.is_empty(), "a Welcome is produced");
    assert!(
        outcome.welcome_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "the Welcome crosses the boundary as hex"
    );
}

#[test]
fn adding_a_member_persists_the_new_epoch() {
    // If the stored epoch did not advance, the next rotation would name a stale
    // "before" value and the modal would show "0 -> 1" for a group already at 1.
    let dir = tempdir::TempDir::new("add-epoch");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("grow").expect("create");
    let key_package = peer_key_package(&store);

    b.add_member(&view.group_id, &key_package).expect("add");

    let listed = b.groups().expect("list");
    assert_eq!(listed[0].epoch, 1, "the stored epoch must follow MLS");
    assert_eq!(listed[0].member_count, 2, "two members after the add");
}

#[test]
fn adding_a_member_syncs_the_consent_gates_epoch_view() {
    // The gate's `current_epoch` is what a later proposal uses as `epoch_before`. An
    // add advances the epoch without a consent decision, so the gate must catch up.
    let dir = tempdir::TempDir::new("add-sync");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("sync").expect("create");
    let key_package = peer_key_package(&store);

    b.add_member(&view.group_id, &key_package).expect("add");

    let state = b.consent().group_state(&view.group_id).expect("registered");
    assert_eq!(
        state.current_epoch, 1,
        "the gate must track the epoch MLS actually reached"
    );
}

#[test]
fn the_welcome_is_not_persisted() {
    // The Welcome is a delivery artifact. Storing it would leave a second copy of
    // group-joining material on disk for no benefit.
    let dir = tempdir::TempDir::new("welcome");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("w").expect("create");
    let key_package = peer_key_package(&store);

    let outcome = b.add_member(&view.group_id, &key_package).expect("add");

    // The stored group rows must not contain the Welcome. A cheap but real check:
    // the row's Debug form is metadata only, so a Welcome appearing there would mean
    // someone added a field for it.
    let rows = b.store().groups().expect("groups");
    for row in rows {
        let debug = format!("{row:?}");
        assert!(
            !debug.contains(&outcome.welcome_hex),
            "the Welcome must not appear in any stored row"
        );
    }

    // And no welcome file is written beside the database.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read data dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !entries.iter().any(|n| n.contains("welcome")),
        "no welcome file must be written; found: {entries:?}"
    );
}

#[test]
fn adding_to_an_unknown_group_is_refused() {
    // A webview-supplied id is never trusted to name a group the backend has not
    // recorded (`plan.md` §7.3).
    let dir = tempdir::TempDir::new("add-unknown");
    let b = backend(&dir);
    let err = b
        .add_member("deadbeef", "0011")
        .expect_err("unknown group must be refused");
    assert_eq!(err.code, "unknown_group");
}

#[test]
fn a_malformed_group_id_is_refused() {
    let dir = tempdir::TempDir::new("bad-id");
    let b = backend(&dir);

    for bad in ["", "zz", "abc", "   "] {
        let err = b
            .add_member(bad, "0011")
            .expect_err("malformed id must be refused");
        assert!(
            err.code == "invalid_group_id" || err.code == "invalid_input",
            "unexpected code `{err}` for id `{bad}`"
        );
    }
}

#[test]
fn an_overlong_group_id_is_refused() {
    // A 65+ byte id is not something this app creates; accepting one would mean
    // trusting an arbitrary blob as a storage key.
    let dir = tempdir::TempDir::new("long-id");
    let b = backend(&dir);
    let err = b
        .add_member(&"ab".repeat(65), "0011")
        .expect_err("overlong id must be refused");
    assert_eq!(err.code, "invalid_group_id");
}

#[test]
fn a_non_hex_key_package_is_refused() {
    let dir = tempdir::TempDir::new("bad-kp");
    let b = backend(&dir);
    let view = b.create_group("kp").expect("create");

    let err = b
        .add_member(&view.group_id, "not-hex-at-all")
        .expect_err("non-hex key package must be refused");
    assert_eq!(err.code, "invalid_group_id");
}

#[test]
fn an_empty_key_package_is_refused() {
    let dir = tempdir::TempDir::new("empty-kp");
    let b = backend(&dir);
    let view = b.create_group("kp").expect("create");

    let err = b
        .add_member(&view.group_id, "")
        .expect_err("empty key package must be refused");
    assert_eq!(err.code, "invalid_input");
}

#[test]
fn a_garbage_key_package_is_rejected_by_mls_not_accepted() {
    // MLS validation is the real gate: an unverified key package is attacker-supplied
    // bytes that would otherwise join the ratchet tree.
    let dir = tempdir::TempDir::new("garbage-kp");
    let b = backend(&dir);
    let view = b.create_group("kp").expect("create");

    let err = b
        .add_member(&view.group_id, "deadbeefdeadbeef")
        .expect_err("garbage must not be accepted as a key package");
    // The exact code is an MLS mapping; what matters is that it failed.
    assert!(
        !err.code.is_empty(),
        "a rejection must carry a code the UI can branch on"
    );
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

#[test]
fn removing_a_member_advances_the_epoch_and_drafts_a_proposal() {
    let dir = tempdir::TempDir::new("remove");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("shrink").expect("create");
    let key_package = peer_key_package(&store);
    b.add_member(&view.group_id, &key_package).expect("add");

    // The added member is the highest leaf index; the local member is 0.
    let members = b.group_members(&view.group_id).expect("members");
    let target = members
        .iter()
        .find(|m| !m.is_self)
        .expect("the added member must be present");

    let outcome = b
        .remove_member(&view.group_id, target.leaf_index)
        .expect("remove");

    assert_eq!(outcome.epoch, 2, "a removal advances the epoch");
    let proposal = outcome
        .proposal
        .expect("a removal must draft a rotation proposal");

    // The proposal must name the pre-removal epoch as "before", so the modal reads
    // "1 -> 2" rather than "2 -> 2".
    assert_eq!(
        proposal.epoch_before, 1,
        "epoch_before is the pre-removal epoch"
    );
    assert_eq!(proposal.epoch_after, 2);
    assert_eq!(proposal.reason, "member_removed");
    assert!(
        proposal.is_blocking,
        "a removal is a blocking prompt (decision D4)"
    );
    assert_eq!(
        proposal.member_count, 1,
        "the count shown is the count after the removal"
    );
}

#[test]
fn a_removal_makes_the_proposal_pending_so_the_modal_renders_it() {
    // Reusing the existing modal is the whole point: `pending_consent` must return the
    // proposal the removal drafted, with a nonce handle the UI can echo back.
    let dir = tempdir::TempDir::new("pending");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("pending").expect("create");
    let key_package = peer_key_package(&store);
    b.add_member(&view.group_id, &key_package).expect("add");

    let members = b.group_members(&view.group_id).expect("members");
    let target = members.iter().find(|m| !m.is_self).expect("member");

    assert!(
        b.pending_consent().is_none(),
        "nothing should be pending before a removal"
    );

    b.remove_member(&view.group_id, target.leaf_index)
        .expect("remove");

    let prompt = b
        .pending_consent()
        .expect("the removal must leave a prompt for the modal");
    assert_eq!(prompt.proposal.reason, "member_removed");
    assert!(
        !prompt.nonce_handle.is_empty(),
        "the modal needs a handle to submit a decision"
    );
}

#[test]
fn an_approved_removal_rotation_moves_the_gate_to_the_new_epoch() {
    // The end-to-end consent path for a removal: draft, approve, epoch advances and the
    // group is forward-secret again.
    let dir = tempdir::TempDir::new("approve");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("approve").expect("create");
    let key_package = peer_key_package(&store);
    b.add_member(&view.group_id, &key_package).expect("add");

    let members = b.group_members(&view.group_id).expect("members");
    let target = members.iter().find(|m| !m.is_self).expect("member");
    b.remove_member(&view.group_id, target.leaf_index)
        .expect("remove");

    let prompt = b.pending_consent().expect("prompt");
    let submission = anon_ipc::ConsentSubmission {
        proposal_id: prompt.proposal.proposal_id.clone(),
        nonce_handle: prompt.nonce_handle.clone(),
        approved: true,
    };
    let now = b.store().now();
    let outcome = b.submit_consent(&submission, now).expect("approve");
    assert_eq!(outcome, anon_consent::ConsentOutcome::Approved);

    let state = b.consent().group_state(&view.group_id).expect("state");
    assert_eq!(state.current_epoch, 2);
    assert!(state.is_forward_secret(), "approval clears the stale flag");
    assert!(b.pending_consent().is_none(), "the prompt is resolved");
}

#[test]
fn a_denied_removal_rotation_leaves_the_group_explicitly_stale() {
    // §5.2 fail-closed: denying must not look like "nothing happened".
    let dir = tempdir::TempDir::new("deny");
    let b = backend(&dir);
    let store = b.store().clone();
    let view = b.create_group("deny").expect("create");
    let key_package = peer_key_package(&store);
    b.add_member(&view.group_id, &key_package).expect("add");

    let members = b.group_members(&view.group_id).expect("members");
    let target = members.iter().find(|m| !m.is_self).expect("member");
    b.remove_member(&view.group_id, target.leaf_index)
        .expect("remove");

    let prompt = b.pending_consent().expect("prompt");
    let submission = anon_ipc::ConsentSubmission {
        proposal_id: prompt.proposal.proposal_id.clone(),
        nonce_handle: prompt.nonce_handle.clone(),
        approved: false,
    };
    let now = b.store().now();
    b.submit_consent(&submission, now).expect("deny");

    assert!(
        !b.is_forward_secret(&view.group_id),
        "a denied rotation must leave the group not forward-secret"
    );
}

#[test]
fn removing_from_an_unknown_group_is_refused() {
    let dir = tempdir::TempDir::new("remove-unknown");
    let b = backend(&dir);
    let err = b
        .remove_member("deadbeef", 0)
        .expect_err("unknown group must be refused");
    assert_eq!(err.code, "unknown_group");
}

#[test]
fn removing_the_last_member_is_refused() {
    // MLS refuses to leave a group empty; the backend must surface that rather than
    // leaving an unreadable group behind.
    let dir = tempdir::TempDir::new("remove-last");
    let b = backend(&dir);
    let view = b.create_group("solo").expect("create");

    let err = b
        .remove_member(&view.group_id, 0)
        .expect_err("removing the only member must be refused");
    assert!(!err.code.is_empty());

    // And the group is still intact.
    let members = b.group_members(&view.group_id).expect("members");
    assert_eq!(members.len(), 1);
}

#[test]
fn removing_an_unknown_leaf_is_refused() {
    let dir = tempdir::TempDir::new("remove-leaf");
    let b = backend(&dir);
    let view = b.create_group("g").expect("create");

    let err = b
        .remove_member(&view.group_id, 99)
        .expect_err("a leaf index that is not a member must be refused");
    assert!(!err.code.is_empty());
}

// ---------------------------------------------------------------------------
// Error shapes the UI branches on
// ---------------------------------------------------------------------------

#[test]
fn group_errors_carry_stable_codes() {
    // The frontend switches on these strings, so they are part of the contract.
    let dir = tempdir::TempDir::new("codes");
    let b = backend(&dir);

    assert_eq!(b.create_group("").expect_err("empty").code, "invalid_input");
    assert_eq!(
        b.remove_member("deadbeef", 0).expect_err("unknown").code,
        "unknown_group"
    );
    assert_eq!(
        b.add_member("not-hex", "0011").expect_err("bad id").code,
        "invalid_group_id"
    );
}

// ---------------------------------------------------------------------------
// Helper: produce a peer key package from a separate MLS provider
// ---------------------------------------------------------------------------

/// Build a key package for a *different* identity over the same store.
///
/// In production the peer generates this on their own device and the inviter receives
/// it out of band. Here both sides share one database, which is enough to exercise the
/// add path: what matters is that the key package is valid MLS bytes produced from a
/// credential that is not the local member's.
fn peer_key_package(store: &Arc<Store>) -> String {
    let conn = store.open_secondary_connection().expect("secondary conn");
    let provider = anon_mls::MlsProvider::new(conn).expect("provider");
    let key_package =
        anon_mls::Group::key_package(&provider, b"anon1peercontactcode").expect("key package");
    key_package.iter().map(|b| format!("{b:02x}")).collect()
}
