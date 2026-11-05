//! Signed-invite round trip through the backend facade.
//!
//! The UI's "Share My Invite" produces a `tornel1:` bundle and "Add Friend" consumes
//! it. These tests prove the two halves agree: a bundle one backend exports is
//! accepted by another, and the peer it creates carries the inviter's onion address.

use anon_ipc::Backend;
use anon_storage::{Argon2Params, Store, StoreConfig};
use anon_transport::{AnonymityTransport, OfflineTransport, OnionId};
use std::sync::Arc;

const PASSPHRASE: &str = "test-invite-passphrase-1234";

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = format!(
                "anon-ipc-invite-{tag}-{}-{:?}",
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

/// A transport that reports a fixed onion address, so `export_invite` can succeed.
///
/// `OfflineTransport` has no onion, and `export_invite` refuses without one — which is
/// correct behaviour but makes it useless for exercising the invite path.
struct OnionTransport {
    onion: OnionId,
}

impl AnonymityTransport for OnionTransport {
    fn anonymity(&self) -> anon_transport::AnonymityClass {
        anon_transport::AnonymityClass::TorOnion
    }

    fn status(&self) -> anon_transport::TransportStatus {
        anon_transport::TransportStatus::Ready
    }

    fn local_onion(&self) -> Option<OnionId> {
        Some(self.onion.clone())
    }

    fn is_onion_service_reachable(&self) -> bool {
        true
    }

    fn configure_discovery(
        &self,
        _key: &anon_transport::DiscoveryKey,
        _authorized: Option<&[String]>,
    ) -> anon_transport::Result<()> {
        Ok(())
    }

    fn failure_reason(&self) -> Option<String> {
        None
    }

    fn send_ready(
        &self,
        _route: &anon_transport::PeerRoute,
        _payload: &[u8],
    ) -> anon_transport::Result<()> {
        Ok(())
    }

    fn shutdown(&self) {}
}

const ONION_A: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
const ONION_B: &str = "zyxwvutsrqponmlkjihgfedcba234567zyxwvutsrqponmlkjihgfedc.onion";

fn backend_with_onion(dir: &tempdir::TempDir, onion: &str) -> Backend {
    let identity = anon_core::IdentityKeys::generate().expect("keygen");
    let store = open_store(dir);
    let transport: Arc<dyn AnonymityTransport> = Arc::new(OnionTransport {
        onion: OnionId::parse(onion).expect("valid onion"),
    });
    Backend::new(identity, transport, store)
}

#[test]
fn an_exported_invite_is_accepted_by_another_backend() {
    let alice_dir = tempdir::TempDir::new("alice");
    let bob_dir = tempdir::TempDir::new("bob");
    let alice = backend_with_onion(&alice_dir, ONION_A);
    let bob = backend_with_onion(&bob_dir, ONION_B);

    let invite = alice.export_invite().expect("alice exports an invite");
    assert!(
        invite.starts_with("tornel1:"),
        "invite must carry the tornel1: prefix, got {invite:.40}"
    );

    let (peer, conversation_id) = bob
        .add_peer(&invite, Some("Alice".to_string()))
        .expect("bob accepts alice's invite");

    assert_eq!(peer.contact_code, alice.contact_code().expect("alice code"));
    assert!(
        peer.onion_short
            .as_deref()
            .is_some_and(|s| s.contains(ONION_A)),
        "the saved peer must carry alice's onion, got {:?}",
        peer.onion_short
    );
    assert!(!conversation_id.is_empty());
}

#[test]
fn a_plain_contact_code_is_still_accepted() {
    let alice_dir = tempdir::TempDir::new("alice-plain");
    let bob_dir = tempdir::TempDir::new("bob-plain");
    let alice = backend_with_onion(&alice_dir, ONION_A);
    let bob = backend_with_onion(&bob_dir, ONION_B);

    let code = alice.contact_code().expect("alice code");
    let (peer, _) = bob
        .add_peer(&code, Some("Alice".to_string()))
        .expect("a bare contact code is accepted");

    assert_eq!(peer.contact_code, code);
}

#[test]
fn a_tampered_invite_is_rejected() {
    let alice_dir = tempdir::TempDir::new("alice-tamper");
    let bob_dir = tempdir::TempDir::new("bob-tamper");
    let alice = backend_with_onion(&alice_dir, ONION_A);
    let bob = backend_with_onion(&bob_dir, ONION_B);

    let invite = alice.export_invite().expect("export");
    // Swap the onion for a different valid one; the signature covers it.
    let tampered = invite.replace(ONION_A, ONION_B);
    assert_ne!(
        tampered, invite,
        "the test must actually change the payload"
    );

    let error = bob
        .add_peer(&tampered, None)
        .expect_err("a tampered invite must be refused");
    assert!(
        format!("{error}").contains("signature"),
        "expected a signature failure, got {error}"
    );
}

#[test]
fn export_invite_refuses_without_an_onion() {
    let dir = tempdir::TempDir::new("no-onion");
    let identity = anon_core::IdentityKeys::generate().expect("keygen");
    let store = open_store(&dir);
    let transport: Arc<dyn AnonymityTransport> = Arc::new(OfflineTransport::new("no Tor in tests"));
    let backend = Backend::new(identity, transport, store);

    let error = backend
        .export_invite()
        .expect_err("no onion means no invite");
    assert!(
        format!("{error}").contains("still starting"),
        "expected the 'still starting' reason, got {error}"
    );
}
