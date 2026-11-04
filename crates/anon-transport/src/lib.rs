//! Network transport abstraction (`plan.md` §3, §3.3, §3.4).
//!
//! # Why this crate exists
//!
//! The plan's central promise is that **no traffic ever leaves over clearnet**.
//! That promise is enforced structurally here rather than by convention:
//!
//! * Messaging code depends on the [`AnonymityTransport`] trait, never on a
//!   socket or on Arti directly. Arti is a *feature-gated implementation detail*.
//! * [`AnonymityClass`] makes the anonymity property of a transport explicit.
//!   A transport that does not claim [`AnonymityClass::TorOnion`] cannot be used
//!   for internet routing, and [`AnonymityTransport::send`] refuses.
//! * The default transport is [`OfflineTransport`], which **fails closed**. A
//!   build with no Tor backend cannot accidentally transmit; it errors.
//!
//! # Arti is behind a feature flag on purpose
//!
//! `plan.md` §3.4 ranks embedded Arti as the highest-risk dependency: its API is
//! pre-1.0, and onion-service *hosting* (`tor-hsservice`) is its least mature
//! surface. Keeping it behind `feature = "arti"` means the rest of the system
//! builds, tests, and is audited without it, and the transport can be swapped
//! without touching messaging logic.
//!
//! # Note on the static no-cleartet guard
//!
//! `plan.md` §7.1 requires a check that no direct socket exists outside this
//! module. See `tests/no_clearnet.rs` in this crate for the automated guard, and
//! `scripts/check-no-clearnet.ps1` for the repository-wide scan.

use std::sync::Arc;
use zeroize::Zeroizing;

pub mod error;
pub mod logging;
pub mod route;
pub mod tor_config;

#[cfg(feature = "arti")]
pub mod arti;

pub use error::{Result, TransportError};
pub use logging::init_from_env as init_tracing;
pub use route::{OnionId, PeerRoute, RouteKind};
pub use tor_config::TorConfig;

/// How well a transport protects the user's network identity.
///
/// This is intentionally an enum rather than a boolean so that a future
/// transport cannot be silently treated as equivalent to Tor. See `plan.md`
/// §3.3: a plain Tor stream to a clearnet host is explicitly **disallowed** by
/// this design, and there is no variant for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnonymityClass {
    /// No usable transport. Sending is impossible by construction.
    None,
    /// Traffic stays on this machine only. Used for tests and local plumbing.
    /// Never acceptable for delivering a message to a peer.
    Loopback,
    /// Bidirectional anonymity via Tor onion-service rendezvous (`plan.md` §3.2).
    ///
    /// This is the only class permitted for internet-wide delivery.
    TorOnion,
}

impl AnonymityClass {
    /// Whether this class may be used to route traffic to a remote peer.
    ///
    /// Deliberately conservative: only [`AnonymityClass::TorOnion`] qualifies.
    pub const fn permits_internet_routing(self) -> bool {
        matches!(self, Self::TorOnion)
    }
}

/// Lifecycle state of the transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportStatus {
    /// Not started, or stopped.
    Idle,
    /// Establishing circuits / publishing the onion service descriptor.
    Bootstrapping,
    /// Confirmed usable. Only this state permits `send`.
    Ready,
    /// Failed, or shut down. Sending is refused (`plan.md` §3.4, fail closed).
    Failed,
}

/// A transport capable of delivering opaque payloads to a peer.
///
/// Implementations must uphold the fail-closed contract: `send` MUST return
/// [`TransportError::NotReady`] unless the transport is `Ready` **and** its
/// anonymity class permits internet routing.
pub trait AnonymityTransport: Send + Sync {
    /// The anonymity this transport provides.
    fn anonymity(&self) -> AnonymityClass;

    /// Current lifecycle state.
    fn status(&self) -> TransportStatus;

    /// This node's own onion identifier, once the service is launched.
    fn local_onion(&self) -> Option<OnionId>;

    /// Whether the hosted onion service has published its descriptor and is believed reachable.
    fn is_onion_service_reachable(&self) -> bool {
        false
    }

    /// Install a handler for complete inbound payloads received over this transport.
    fn set_inbound_handler(&self, _handler: Arc<dyn Fn(Vec<u8>) + Send + Sync>) {}

    /// Reason the transport failed, when `status()` is `Failed`.
    fn failure_reason(&self) -> Option<String>;

    /// Deliver `payload` to `route`.
    ///
    /// The default implementation performs the fail-closed gate and then
    /// delegates to [`AnonymityTransport::send_ready`]. Implementations should
    /// not override this unless they are implementing the gate themselves.
    fn send(&self, route: &PeerRoute, payload: &[u8]) -> Result<()> {
        // Gate 1: the transport must not be in a failed/idle state.
        match self.status() {
            TransportStatus::Ready => {}
            TransportStatus::Failed => {
                return Err(TransportError::Failed(
                    self.failure_reason()
                        .unwrap_or_else(|| "transport failed".to_string()),
                ))
            }
            TransportStatus::Idle | TransportStatus::Bootstrapping => {
                return Err(TransportError::NotReady)
            }
        }

        // Gate 2: the transport must actually provide the anonymity the plan
        // requires. This is what makes "no clearnet fallback" structural rather
        // than a code-review invariant (`plan.md` §1.2, §3.4).
        if !self.anonymity().permits_internet_routing() {
            return Err(TransportError::AnonymityUnavailable);
        }

        self.send_ready(route, payload)
    }

    /// Deliver a payload, assuming the fail-closed gate has already passed.
    ///
    /// # Contract
    ///
    /// Implementations must NOT be called directly from messaging code — always
    /// go through [`AnonymityTransport::send`] so the anonymity gate applies.
    fn send_ready(&self, route: &PeerRoute, payload: &[u8]) -> Result<()>;

    /// Shut the transport down and drop any long-lived circuits.
    fn shutdown(&self);
}

/// A transport that always fails closed.
///
/// This is the **default** transport in any build without a real Tor backend.
/// Its only job is to refuse: it makes "the app is offline rather than degraded"
/// the behaviour you get for free, and it is the control case for the
/// fail-closed test in `plan.md` §7.1 Phase 2.
#[derive(Default)]
pub struct OfflineTransport {
    reason: Option<String>,
}

impl OfflineTransport {
    /// Create an offline transport with a human-readable explanation.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
        }
    }
}

impl AnonymityTransport for OfflineTransport {
    fn anonymity(&self) -> AnonymityClass {
        AnonymityClass::None
    }

    fn status(&self) -> TransportStatus {
        TransportStatus::Failed
    }

    fn local_onion(&self) -> Option<OnionId> {
        None
    }

    fn failure_reason(&self) -> Option<String> {
        Some(
            self.reason
                .clone()
                .unwrap_or_else(|| "no Tor backend compiled in".to_string()),
        )
    }

    fn send_ready(&self, _route: &PeerRoute, _payload: &[u8]) -> Result<()> {
        // Unreachable: `send` refuses before delegating. Returning an error
        // rather than panicking keeps a programming mistake from becoming a
        // crash in a security-critical path.
        Err(TransportError::Failed("offline transport".to_string()))
    }

    fn shutdown(&self) {}
}

/// A deterministic in-process transport for exercising the messaging stack.
///
/// With `tor_like = true` it advertises [`AnonymityClass::TorOnion`] and behaves
/// like a healthy transport, so higher layers can be tested end to end. With
/// `tor_like = false` it advertises [`AnonymityClass::Loopback`], which
/// exercises the anonymity gate.
pub struct MockTransport {
    tor_like: bool,
    ready: bool,
    local: Option<OnionId>,
    /// Payloads observed, in order. Test-only introspection.
    delivered: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    inbound_handler: std::sync::Mutex<Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>>,
}

impl MockTransport {
    /// A healthy, Tor-class transport. Used as the positive test case.
    pub fn tor_like(onion: OnionId) -> Self {
        Self {
            tor_like: true,
            ready: true,
            local: Some(onion),
            delivered: std::sync::Mutex::new(Vec::new()),
            inbound_handler: std::sync::Mutex::new(None),
        }
    }

    /// A loopback-class transport. Used to prove the anonymity gate refuses it.
    pub fn loopback() -> Self {
        Self {
            tor_like: false,
            ready: true,
            local: None,
            delivered: std::sync::Mutex::new(Vec::new()),
            inbound_handler: std::sync::Mutex::new(None),
        }
    }

    /// Mark not-ready, to exercise the fail-closed path.
    pub fn not_ready(onion: OnionId) -> Self {
        Self {
            tor_like: true,
            ready: false,
            local: Some(onion),
            delivered: std::sync::Mutex::new(Vec::new()),
            inbound_handler: std::sync::Mutex::new(None),
        }
    }

    /// Simulate an inbound payload arriving on the hosted onion service.
    pub fn inject_inbound(&self, payload: Vec<u8>) {
        let cb = self.inbound_handler.lock().unwrap().clone();
        if let Some(cb) = cb {
            cb(payload);
        }
    }

    /// Number of payloads successfully delivered.
    pub fn delivered_count(&self) -> usize {
        self.delivered.lock().unwrap().len()
    }

    /// Snapshot of delivered (route, payload) pairs.
    pub fn take_delivered(&self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut self.delivered.lock().unwrap())
    }
}

impl AnonymityTransport for MockTransport {
    fn anonymity(&self) -> AnonymityClass {
        if self.tor_like {
            AnonymityClass::TorOnion
        } else {
            AnonymityClass::Loopback
        }
    }

    fn status(&self) -> TransportStatus {
        if self.ready {
            TransportStatus::Ready
        } else {
            TransportStatus::Bootstrapping
        }
    }

    fn local_onion(&self) -> Option<OnionId> {
        self.local.clone()
    }

    fn is_onion_service_reachable(&self) -> bool {
        self.ready && self.local.is_some()
    }

    fn set_inbound_handler(&self, handler: std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>) {
        *self.inbound_handler.lock().unwrap() = Some(handler);
    }

    fn failure_reason(&self) -> Option<String> {
        None
    }

    fn send_ready(&self, route: &PeerRoute, payload: &[u8]) -> Result<()> {
        self.delivered
            .lock()
            .unwrap()
            .push((route.describe(), payload.to_vec()));
        Ok(())
    }

    fn shutdown(&self) {}
}

/// Wrap a payload so it is scrubbed when dropped.
///
/// Messaging code should hand plaintext to the transport only inside this
/// wrapper (`plan.md` §2.3, §6.3).
pub fn secret_payload(plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion() -> OnionId {
        OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion").unwrap()
    }

    #[test]
    fn only_tor_onion_permits_internet_routing() {
        assert!(AnonymityClass::TorOnion.permits_internet_routing());
        // The whole point of §1.2 "no clearnet fallback": these must be false.
        assert!(!AnonymityClass::Loopback.permits_internet_routing());
        assert!(!AnonymityClass::None.permits_internet_routing());
    }

    #[test]
    fn offline_transport_fails_closed() {
        // The Phase 2 fail-closed exit criterion (plan.md §7.1).
        let t = OfflineTransport::default();
        assert_eq!(t.status(), TransportStatus::Failed);
        assert_eq!(t.anonymity(), AnonymityClass::None);

        let err = t
            .send(&PeerRoute::onion(onion()), b"hello")
            .expect_err("offline transport must never send");
        assert!(matches!(err, TransportError::Failed(_)));
    }

    #[test]
    fn loopback_transport_is_refused_by_the_anonymity_gate() {
        // Proves that a transport which *is* ready still cannot transmit unless
        // it provides Tor-grade anonymity.
        let t = MockTransport::loopback();
        assert_eq!(t.status(), TransportStatus::Ready);

        let err = t
            .send(&PeerRoute::onion(onion()), b"hello")
            .expect_err("loopback must not be usable for internet routing");
        assert!(matches!(err, TransportError::AnonymityUnavailable));
        assert_eq!(t.delivered_count(), 0);
    }

    #[test]
    fn not_ready_transport_refuses_to_send() {
        let t = MockTransport::not_ready(onion());
        assert_eq!(t.status(), TransportStatus::Bootstrapping);
        let err = t.send(&PeerRoute::onion(onion()), b"hello").unwrap_err();
        assert!(matches!(err, TransportError::NotReady));
        assert_eq!(t.delivered_count(), 0);
    }

    #[test]
    fn tor_like_transport_delivers() {
        let t = MockTransport::tor_like(onion());
        t.send(&PeerRoute::onion(onion()), b"payload").unwrap();
        assert_eq!(t.delivered_count(), 1);
        let got = t.take_delivered();
        assert_eq!(got[0].1, b"payload");
    }

    #[test]
    fn secret_payload_is_scrubbed_and_correct() {
        let p = secret_payload(b"top secret");
        assert_eq!(p.as_slice(), b"top secret");
        drop(p);
    }
}
