//! Tor end-to-end verification (`plan.md` §7.1 Phase 2, §10).
//!
//! # What this test can and cannot prove
//!
//! It can prove the bootstrap path *runs* and reports honestly. It cannot prove Tor
//! publication works unless the network completes a consensus download, which is not
//! something a test can arrange.
//!
//! The test is gated on `ANON_TOR_E2E=1`. Once enabled, bootstrap failure is a test
//! failure; this distinguishes an unsuccessful live probe from a successful one.
//!
//! # The rule this test exists to enforce
//!
//! Launching a service does not prove publication or frame delivery. This test does not
//! yet exercise independent peers or restart persistence.
//!
//! # Running it
//!
//! ```text
//! set ANON_TOR_E2E=1
//! cargo test -p anon-transport --features arti --test tor_e2e -- --nocapture
//! ```
//!
//! Set `ANON_TOR_BOOTSTRAP_TIMEOUT_SECS` to bound the wait.

#![cfg(feature = "arti")]

use anon_transport::arti::{bootstrap_timeout, ArtiTransport, BOOTSTRAP_TIMEOUT_ENV};
use anon_transport::{AnonymityTransport, TransportStatus};

/// Whether the gated test should run.
fn e2e_enabled() -> bool {
    std::env::var("ANON_TOR_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Serialises the tests in this binary that read or write the deadline variable.
///
/// Cargo runs the tests in one binary on parallel threads, and the deadline is
/// process-wide state. Without this lock the second test's one-second override could be
/// observed by the first test's read, which would make a healthy network look like a
/// blocked one. Poisoning is ignored: a panic in one test should not cascade into a
/// misleading failure in the other.
static DEADLINE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquires [`DEADLINE_ENV_LOCK`], ignoring poisoning.
fn lock_deadline_env() -> std::sync::MutexGuard<'static, ()> {
    DEADLINE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn tor_bootstraps_and_hosts_an_onion_service() {
    if !e2e_enabled() {
        eprintln!(
            "skipped: set ANON_TOR_E2E=1 to run the live Tor test. \
             This test needs a network that completes a consensus download."
        );
        return;
    }

    // Held for the whole test so the other test's one-second override cannot be read
    // here as if it were the caller's deadline.
    let _deadline_guard = lock_deadline_env();

    // Install the tracing subscriber so a CI run leaves Arti's bootstrap stages in the
    // log. Without this the test prints only its own summary, and a failure to reach a
    // consensus looks like a bare timeout rather than "connected, then could not fetch a
    // consensus" — the distinction that took a tracing subscriber to establish. Silent
    // unless `RUST_LOG` is set, so a normal run is unaffected.
    anon_transport::init_tracing();

    let timeout = bootstrap_timeout();
    eprintln!(
        "bootstrapping with a {}s deadline (override with {BOOTSTRAP_TIMEOUT_ENV})",
        timeout.as_secs()
    );

    let dir_a = std::env::temp_dir().join(format!("anon-tor-e2e-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("anon-tor-e2e-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let trans_a = std::sync::Arc::new(ArtiTransport::with_config(
        anon_transport::TorConfig::none().with_data_dir(&dir_a),
    ));
    let trans_b = std::sync::Arc::new(ArtiTransport::with_config(
        anon_transport::TorConfig::none().with_data_dir(&dir_b),
    ));

    let (rx_tx, rx_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    trans_b.set_inbound_handler(move |payload| {
        let _ = rx_tx.send(payload);
    });

    let started = std::time::Instant::now();
    let h_a = {
        let t = trans_a.clone();
        std::thread::spawn(move || t.bootstrap())
    };
    let h_b = {
        let t = trans_b.clone();
        std::thread::spawn(move || t.bootstrap())
    };
    h_a.join().unwrap().expect("client A bootstrap");
    h_b.join().unwrap().expect("client B bootstrap");

    let elapsed = started.elapsed();
    eprintln!("BOTH CLIENTS BOOTSTRAPPED in {elapsed:?}");
    assert_eq!(trans_a.status(), TransportStatus::Ready);
    assert_eq!(trans_b.status(), TransportStatus::Ready);

    let onion = trans_b
        .host_onion_service()
        .expect("bootstrap succeeded so hosting must succeed");
    let address = onion.as_str().to_string();
    eprintln!("HOSTED onion service at {address}");
    assert!(
        address.ends_with(".onion"),
        "a hosted address must be a .onion name, got {address}"
    );
    assert!(
        trans_b.hosts_onion_service(),
        "the transport must report hosting once it has an address"
    );

    // D7: the address is derived from a persisted identity key, so a
    // second call in the same process must return the same address.
    let again = trans_b.host_onion_service().expect("hosting is idempotent");
    assert_eq!(
        again.as_str(),
        address,
        "the onion address must be stable within a process (D7)"
    );

    // Wait for descriptor publication (`Running` or `DegradedReachable`).
    let pub_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while std::time::Instant::now() < pub_deadline && !trans_b.is_onion_service_reachable() {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert!(
        trans_b.is_onion_service_reachable(),
        "onion service descriptor must reach a reachable state"
    );

    // Deliver a real payload from client A to client B's onion service over Tor.
    let route = anon_transport::PeerRoute::onion(onion);
    let expected = b"live-tor-e2e-payload".to_vec();
    let mut delivered = false;
    for _ in 0..4 {
        if trans_a.send(&route, &expected).is_ok() {
            delivered = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    assert!(
        delivered,
        "client A must deliver payload to client B over Tor"
    );

    let received = rx_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("client B must receive the inbound payload");
    assert_eq!(received, expected);

    trans_a.shutdown();
    trans_b.shutdown();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn restricted_discovery_blocks_unauthorized_and_shapes_authorized_traffic() {
    if std::env::var("ANON_TOR_PRIVACY_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: set ANON_TOR_PRIVACY_E2E=1 for live privacy verification");
        return;
    }
    let _deadline_guard = lock_deadline_env();
    let root = std::env::temp_dir().join(format!(
        "anon-privacy-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut transports = Vec::new();
    let mut keys = Vec::new();
    for index in 0..3 {
        let dir = root.join(index.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        transports.push(std::sync::Arc::new(ArtiTransport::with_config(
            anon_transport::TorConfig::none().with_data_dir(&dir),
        )));
        keys.push(anon_transport::DiscoveryKey::for_identity(
            &anon_core::IdentityKeys::generate().unwrap(),
        ));
    }
    let allowed = vec![keys[0].public_key(), keys[1].public_key()];
    for index in 0..3 {
        transports[index]
            .configure_discovery(&keys[index], Some(&allowed))
            .unwrap();
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    transports[1].set_inbound_handler(move |payload| {
        let _ = sender.send(payload);
    });
    let workers: Vec<_> = transports
        .iter()
        .map(|transport| {
            let transport = transport.clone();
            std::thread::spawn(move || transport.start())
        })
        .collect();
    for worker in workers {
        worker
            .join()
            .unwrap()
            .expect("privacy peer bootstrap and hosting");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while transports
        .iter()
        .any(|transport| !transport.is_onion_service_reachable())
        && std::time::Instant::now() < deadline
    {
        std::thread::park_timeout(std::time::Duration::from_secs(1));
    }
    assert!(transports
        .iter()
        .all(|transport| transport.is_onion_service_reachable()));
    let onion = transports[1].local_onion().unwrap();
    let route = anon_transport::PeerRoute::onion(onion.clone());
    assert!(
        transports[2].send(&route, b"unauthorized").is_err(),
        "unknown discovery key must not connect"
    );
    assert!(receiver.try_recv().is_err());
    transports[0]
        .send(&route, b"authorized")
        .expect("authorized discovery delivery");
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap(),
        b"authorized"
    );
    transports[1].configure_shaping(&[], true).unwrap();
    transports[0].configure_shaping(&[onion], true).unwrap();
    let expected = vec![42u8; 16_384];
    transports[0]
        .send(&route, &expected)
        .expect("shaped delivery");
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap(),
        expected
    );
    for transport in &transports {
        transport.shutdown();
    }
    drop(transports);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_failed_bootstrap_reports_a_reason_rather_than_hanging() {
    // This one runs unconditionally: it does not need Tor, only the guarantee that a
    // bootstrap which cannot finish reports *something*. That guarantee is the fix for the
    // defect where the transport stayed `Bootstrapping` forever at ~96% CPU.
    if !e2e_enabled() {
        eprintln!("skipped: set ANON_TOR_E2E=1 to run the live Tor test");
        return;
    }

    // A one-second deadline makes this fast regardless of the network. Save and restore
    // the previous value rather than removing it: cargo runs the tests in this binary on
    // separate threads, and an unconditional `remove_var` here would wipe a caller's
    // `ANON_TOR_BOOTSTRAP_TIMEOUT_SECS` override for the other test, which then waits the
    // full 120s default. That is exactly the kind of cross-test interference that makes a
    // bounded deadline look unbounded.
    let _deadline_guard = lock_deadline_env();
    let previous = std::env::var(BOOTSTRAP_TIMEOUT_ENV).ok();
    std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, "1");

    let rt = tokio::runtime::Runtime::new().expect("create runtime");
    let _guard = rt.enter();

    let transport = ArtiTransport::new();
    let started = std::time::Instant::now();
    let result = transport.bootstrap();
    let elapsed = started.elapsed();

    match previous {
        Some(v) => std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, v),
        None => std::env::remove_var(BOOTSTRAP_TIMEOUT_ENV),
    }

    // Either it bootstrapped in under a second (a very fast network) or it failed. What
    // must not happen is an unbounded wait.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "bootstrap must not run unbounded; it took {elapsed:?}"
    );

    if result.is_err() {
        assert_eq!(
            transport.status(),
            TransportStatus::Failed,
            "a failed bootstrap must leave the transport Failed"
        );
        let reason = transport
            .failure_reason()
            .expect("a failure must record a reason the UI can show");
        eprintln!("bootstrap failed as expected within {elapsed:?}: {reason}");
    } else {
        eprintln!("bootstrap succeeded within {elapsed:?} (fast network)");
    }
}
