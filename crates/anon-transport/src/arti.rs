//! Embedded Arti transport (`plan.md` §3.1, §3.4).
//!
//! Enabled with `--features arti`. This module is the **only** place in the
//! workspace permitted to touch Arti, and the only file on the no-clearnet
//! allowlist (`crates/anon-transport/tests/no_clearnet.rs`), because Arti owns
//! its own sockets internally.
//!
//! # Why this is deliberately conservative
//!
//! `plan.md` §3.4 ranks embedded Arti as the highest-risk dependency in the plan:
//!
//! * `arti-client` is pre-1.0 and its API moves;
//! * onion-service **hosting** (`tor-hsservice`) is the least mature surface, with
//!   meaningful capabilities behind `experimental` flags.
//!
//! So this implementation does the minimum that is honest:
//!
//! * it bootstraps a Tor client and reports `Ready` only once bootstrap actually
//!   succeeds;
//! * it **fails closed** — any error leaves the transport `Failed`, and `send`
//!   then refuses;
//! * it launches a v3 onion service via `tor-hsservice`; its address is not proof
//!   that a descriptor was published or a peer can receive messages.
//!
//! # Why the address is not known immediately
//!
//! An onion service's address is derived from its identity key, which is
//! generated on first launch and then stored in Arti's key manager. That is what
//! makes the address **stable across restarts** (decision D7): the same key
//! yields the same `.onion` name and the same contact code, so a peer's saved
//! route keeps working. [`ArtiTransport::local_onion`] returns `None` until a
//! service has launched and produced an address. This does not establish
//! publication or reachability.

use crate::error::{Result, TransportError};
use crate::route::{OnionId, PeerRoute};
use crate::tor_config::TorConfig;
use crate::{AnonymityClass, AnonymityTransport, TransportStatus};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath};
use arti_client::{TorClient, TorClientConfig};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use tor_hsservice::OnionServiceConfig;
use tor_persist::hsnickname::HsNickname;
use tor_rtcompat::PreferredRuntime;

/// The nickname this app's onion service is stored under in Arti's key manager.
///
/// Fixed rather than derived from the identity: one install hosts one service,
/// and a stable nickname is what lets Arti find the *same* identity key on the
/// next launch — which is what makes the address stable (D7).
pub const ONION_SERVICE_NICKNAME: &str = "anon";

/// The default bootstrap deadline, in seconds.
///
/// Two minutes is generous for a healthy network — a normal bootstrap takes seconds to
/// tens of seconds — and short enough that a user is not left staring at "bootstrapping"
/// for an unreasonable time. It is long enough that a genuinely slow but working network
/// is not cut off.
pub const DEFAULT_BOOTSTRAP_TIMEOUT_SECS: u64 = 120;

/// The environment variable that overrides the bootstrap deadline.
///
/// Exists so a test or a user on a very slow link can extend it without a rebuild. It is
/// read once per bootstrap, not cached, so a test can set it per case.
pub const BOOTSTRAP_TIMEOUT_ENV: &str = "ANON_TOR_BOOTSTRAP_TIMEOUT_SECS";

/// The bootstrap deadline, honouring [`BOOTSTRAP_TIMEOUT_ENV`].
///
/// A malformed or zero value falls back to the default rather than being treated as
/// "no timeout": a typo in an environment variable must not silently restore the
/// unbounded hang this deadline exists to prevent.
pub fn bootstrap_timeout() -> std::time::Duration {
    let secs = std::env::var(BOOTSTRAP_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_BOOTSTRAP_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

/// Maximum size of a single inbound payload accepted from a rendezvous stream.
///
/// Matches the largest padded frame size (header + 512 KiB bucket) plus a small
/// envelope margin so a peer cannot force an unbounded allocation.
pub const MAX_INBOUND_PAYLOAD_BYTES: usize = 524_352;

/// Callback invoked for each complete inbound payload received on the onion service.
type InboundHandler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// A launched onion service and the handle keeping it alive.
///
/// Dropping `RunningOnionService` stops publishing and stops accepting new
/// introduction requests (`tor-hsservice` documents exactly this), so the handle
/// must be retained for as long as the node is reachable.
struct HostedService {
    address: OnionId,
    /// Kept alive for its `Drop` side effect and for reading service reachability status.
    running: Arc<tor_hsservice::RunningOnionService>,
}

struct ActiveClient {
    client: Arc<TorClient<PreferredRuntime>>,
    runtime: Arc<TorRuntime>,
}

struct TorRuntime(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for TorRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("runtime remains available until drop")
    }
}

impl Drop for TorRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// Lifecycle state, stored as an atomic so `status()` is lock-free.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum State {
    Idle = 0,
    Bootstrapping = 1,
    Ready = 2,
    Failed = 3,
}

impl State {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Bootstrapping,
            2 => Self::Ready,
            3 => Self::Failed,
            _ => Self::Idle,
        }
    }

    fn to_status(self) -> TransportStatus {
        match self {
            Self::Idle => TransportStatus::Idle,
            Self::Bootstrapping => TransportStatus::Bootstrapping,
            Self::Ready => TransportStatus::Ready,
            Self::Failed => TransportStatus::Failed,
        }
    }
}

/// An Arti-backed transport.
///
/// Construction is cheap and does not block; call [`ArtiTransport::bootstrap`]
/// (typically on a background task) to bring it up.
pub struct ArtiTransport {
    /// The lifecycle state.
    state: Arc<AtomicU8>,
    /// The failure reason.
    failure: Arc<Mutex<Option<String>>>,
    /// The bootstrapped client, once available.
    ///
    /// Held behind a `Mutex<Option<..>>` rather than being created eagerly so a
    /// failed bootstrap leaves nothing half-initialised.
    client: Mutex<Option<ActiveClient>>,
    /// Our hosted onion service, once one is actually running.
    ///
    /// `None` until [`ArtiTransport::host_onion_service`] succeeds. See the
    /// module docs for why the address is not available earlier.
    local_onion: Mutex<Option<HostedService>>,
    /// Handler called for each bounded payload read from an accepted inbound stream.
    inbound_handler: Arc<Mutex<Option<InboundHandler>>>,
    /// Bridge and pluggable-transport settings.
    ///
    /// Defaults to "no bridges" (direct connections). Set with
    /// [`ArtiTransport::with_config`] or [`ArtiTransport::set_config`] before
    /// bootstrapping. See [`crate::tor_config`] for why a bridge failure is fatal
    /// rather than a fallback.
    config: Mutex<TorConfig>,
}

impl ArtiTransport {
    /// Create a transport in the `Idle` state, with no bridges configured.
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(State::Idle as u8)),
            failure: Arc::new(Mutex::new(None)),
            client: Mutex::new(None),
            local_onion: Mutex::new(None),
            inbound_handler: Arc::new(Mutex::new(None)),
            config: Mutex::new(TorConfig::none()),
        }
    }

    /// Install a handler for complete inbound payloads received over the hosted onion service.
    pub fn set_inbound_handler<F>(&self, handler: F)
    where
        F: Fn(Vec<u8>) + Send + Sync + 'static,
    {
        *self.inbound_handler.lock().unwrap() = Some(Arc::new(handler));
    }

    /// Create a transport with bridge settings already applied.
    ///
    /// The configuration is **not** validated here; [`ArtiTransport::bootstrap`]
    /// validates it and fails closed. Validating at construction would make `new`
    /// fallible for a case the caller may never reach (a transport that is never
    /// bootstrapped), and would hide the failure from the place that reports it.
    pub fn with_config(config: TorConfig) -> Self {
        let transport = Self::new();
        *transport.config.lock().unwrap() = config;
        transport
    }

    /// Replace the bridge settings.
    ///
    /// Only meaningful before [`ArtiTransport::bootstrap`]: once a client exists the
    /// configuration has already been used. Returns an error in that case rather than
    /// silently accepting a change that would never take effect — a user who edits
    /// bridges and sees no change would reasonably conclude the bridges are broken.
    pub fn set_config(&self, config: TorConfig) -> Result<()> {
        let mut current = self.config.lock().unwrap();
        if self.state.load(Ordering::SeqCst) != State::Idle as u8 {
            return Err(TransportError::Failed(
                "cannot change Tor configuration after bootstrap; the client is already \
                 running with the previous settings. Restart the transport to apply it."
                    .to_string(),
            ));
        }
        *current = config;
        Ok(())
    }

    /// The current bridge settings.
    pub fn config(&self) -> TorConfig {
        self.config.lock().unwrap().clone()
    }

    /// Bootstrap the Tor client, giving up after [`bootstrap_timeout`].
    ///
    /// Blocks until bootstrap completes, fails, or times out. Callers should run this on
    /// a background task and surface [`TransportStatus::Bootstrapping`] meanwhile.
    ///
    /// # Why there is a deadline
    ///
    /// Without one, a bootstrap that cannot finish **never returns**. Measured on a
    /// network that reaches Tor but cannot download a consensus: one thread at ~96% of a
    /// core for 800+ seconds, zero established connections, no error, no log line. The
    /// transport stayed `Bootstrapping` forever, so the UI showed "bootstrapping" and the
    /// user had no way to tell a slow start from a permanent failure.
    ///
    /// A deadline converts that into an honest `Failed` with a reason. `plan.md` §8
    /// forbids hiding why sending is unavailable, and "it is still bootstrapping" after
    /// ten minutes is a hidden failure.
    ///
    /// # Why the timeout is not a retry
    ///
    /// On any failure the transport becomes `Failed` and stays there: there is no retry
    /// loop here, because a silent retry that eventually "succeeds" through a different
    /// path is precisely the kind of ambiguity this design avoids. The caller decides
    /// whether to retry explicitly.
    pub fn bootstrap(&self) -> Result<()> {
        let config_guard = self.config.lock().unwrap();
        self.state
            .compare_exchange(
                State::Idle as u8,
                State::Bootstrapping as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| TransportError::Failed(
                "Tor bootstrap is already running or has already completed; restart the transport to retry".to_string()
            ))?;
        let tor_config = config_guard.clone();
        drop(config_guard);

        let deadline = bootstrap_timeout();
        tracing::info!(
            deadline_secs = deadline.as_secs(),
            "starting Tor bootstrap; set RUST_LOG=arti=debug to see Arti's stages"
        );

        // The async timeout cancels a cooperative bootstrap. The outer deadline also
        // bounds the caller if a future does not yield; in that case its worker cannot
        // be forcibly cancelled and may outlive this call.
        //
        // A malformed bridge line or a bridge whose transport is missing must fail
        // loudly. Falling back to a direct connection when bridges were requested would
        // be a privacy failure (`crate::tor_config`), so validation happens before any
        // client is built and its error goes straight to `Failed`.
        let bridges = match tor_config.validate() {
            Ok(bridges) => bridges,
            Err(e) => return self.fail(e.to_string()),
        };

        let client_config = match build_client_config(&tor_config, &bridges) {
            Ok(config) => config,
            Err(e) => return self.fail(e),
        };

        let (tx, rx) = std::sync::mpsc::channel();

        {
            std::thread::spawn(move || {
                // The runtime must be created on the thread that uses it:
                // `PreferredRuntime::current()` looks at the current thread's context.
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => Arc::new(TorRuntime(Some(rt))),
                    Err(e) => {
                        let _ = tx.send(Err(format!("no async runtime available: {e}")));
                        return;
                    }
                };
                let outcome = {
                    let _guard = runtime.enter();
                    runtime
                        .block_on(tokio::time::timeout(
                            deadline,
                            TorClient::create_bootstrapped(client_config),
                        ))
                        .map_err(|_| {
                            format!("Tor bootstrap timed out after {}s", deadline.as_secs())
                        })
                        .and_then(|result| result.map_err(|e| format!("Tor bootstrap failed: {e}")))
                        .map(|client| ActiveClient {
                            client,
                            runtime: Arc::clone(&runtime),
                        })
                };
                let _ = tx.send(outcome);
            });
        }

        // Wait for the worker, but not past the deadline.
        match rx.recv_timeout(deadline) {
            Ok(Ok(client)) => {
                let mut slot = self.client.lock().unwrap();
                if self.state.load(Ordering::SeqCst) != State::Bootstrapping as u8 {
                    return Err(TransportError::Failed(
                        "Tor bootstrap was cancelled".to_string(),
                    ));
                }
                *slot = Some(client);
                self.state.store(State::Ready as u8, Ordering::SeqCst);
                Ok(())
            }
            Ok(Err(reason)) => self.fail(reason),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.fail(format!(
                "Tor bootstrap timed out after {}s. Check network access, the system \
                 clock, or configure a bridge. Sending stays disabled.",
                deadline.as_secs()
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.fail("the Tor bootstrap worker exited without reporting a result".to_string())
            }
        }
    }

    /// Record a failure and return it.
    fn fail(&self, reason: String) -> Result<()> {
        tracing::error!(reason = %reason, "Tor transport failed");
        *self.failure.lock().unwrap() = Some(reason.clone());
        self.state.store(State::Failed as u8, Ordering::SeqCst);
        Err(TransportError::Failed(reason))
    }

    /// Launch the node's v3 onion service and record its address (`plan.md` §3.2).
    ///
    /// Must be called after [`ArtiTransport::bootstrap`] succeeds: hosting needs a
    /// bootstrapped client (it publishes a descriptor through the Tor network).
    ///
    /// Returns the node's onion address. The address is derived from the identity
    /// key, which Arti persists in its key manager under
    /// [`ONION_SERVICE_NICKNAME`], so calling this again after a restart yields
    /// the **same** address (D7).
    ///
    /// On failure the transport goes `Failed` and stops accepting sends. That is
    /// deliberate: without an inbound service the node can send but never
    /// receive, which is not a state worth calling "ready".
    pub fn host_onion_service(&self) -> Result<OnionId> {
        {
            // Idempotent: a second call returns the existing address rather than
            // launching a duplicate service.
            let guard = self.local_onion.lock().unwrap();
            if let Some(hosted) = guard.as_ref() {
                return Ok(hosted.address.clone());
            }
        }

        if self.status() != TransportStatus::Ready {
            return Err(TransportError::NotReady);
        }

        let (client, runtime) = {
            let guard = self.client.lock().unwrap();
            guard
                .as_ref()
                .map(|active| (Arc::clone(&active.client), Arc::clone(&active.runtime)))
                .ok_or(TransportError::NotReady)?
        };

        let _runtime_guard = runtime.enter();
        let nickname = HsNickname::new(ONION_SERVICE_NICKNAME.to_string())
            .map_err(|e| TransportError::Failed(format!("invalid onion nickname: {e}")))?;
        let config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| TransportError::Failed(format!("onion service config rejected: {e}")))?;

        let launched = match client.launch_onion_service(config) {
            Ok(v) => v,
            Err(e) => {
                return self
                    .fail(format!("failed to launch onion service: {e}"))
                    .map(|()| unreachable!("fail always returns Err"))
            }
        };

        // `None` means the service is `enabled = false` in configuration. Treat it
        // as a failure rather than pretending we are reachable.
        let Some((running, requests)) = launched else {
            return self
                .fail("onion service is disabled in configuration".to_string())
                .map(|()| unreachable!("fail always returns Err"));
        };

        let address = running
            .onion_address()
            .ok_or_else(|| TransportError::Failed("onion service has no address".to_string()))?;
        // `HsId` deliberately has no `Display` impl (it is an identity, and
        // safelog wants accidental logging to be redacted). The full
        // `${base32}.onion` form is available opt-in via `display_unredacted`.
        let rendered = safelog::DisplayRedacted::display_unredacted(&address).to_string();
        let address = OnionId::parse(&rendered)
            .map_err(|e| TransportError::Failed(format!("Tor produced an invalid address: {e}")))?;

        // Accept rendezvous requests and read bounded payloads on a background task.
        //
        // The task is detached but bounded by the service handle: when
        // `RunningOnionService` is dropped the request stream ends and this loop
        // finishes.
        let streams = tor_hsservice::handle_rend_requests(requests);
        let inbound_handler = Arc::clone(&self.inbound_handler);
        let worker_runtime = Arc::clone(&runtime);
        runtime.spawn(async move {
            use futures::StreamExt;
            let mut streams = Box::pin(streams);
            while let Some(stream_req) = streams.next().await {
                let handler = inbound_handler.lock().unwrap().clone();
                worker_runtime.spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let Ok(mut stream) = stream_req
                        .accept(tor_cell::relaycell::msg::Connected::new_empty())
                        .await
                    else {
                        return;
                    };
                    let read_res =
                        tokio::time::timeout(std::time::Duration::from_secs(30), async {
                            let mut len_bytes = [0u8; 4];
                            stream.read_exact(&mut len_bytes).await?;
                            let len = u32::from_le_bytes(len_bytes) as usize;
                            if len == 0 || len > MAX_INBOUND_PAYLOAD_BYTES {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "inbound payload length out of bounds",
                                ));
                            }
                            let mut buf = vec![0u8; len];
                            stream.read_exact(&mut buf).await?;
                            // Send a 1-byte application-layer receipt so the sender knows the full
                            // frame arrived at the recipient onion service before closing the stream.
                            let _ = stream.write_all(&[1u8]).await;
                            let _ = stream.flush().await;
                            Ok::<Vec<u8>, std::io::Error>(buf)
                        })
                        .await;
                    if let Ok(Ok(buf)) = read_res {
                        if let Some(cb) = handler {
                            cb(buf);
                        }
                    }
                });
            }
        });

        *self.local_onion.lock().unwrap() = Some(HostedService {
            address: address.clone(),
            running,
        });
        Ok(address)
    }

    /// Whether an onion service is actually being hosted.
    pub fn hosts_onion_service(&self) -> bool {
        self.local_onion.lock().unwrap().is_some()
    }

    /// Whether the hosted onion service has published its descriptor and is believed reachable.
    pub fn is_onion_service_reachable(&self) -> bool {
        self.local_onion
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|h| h.running.status().state().is_fully_reachable())
    }

    /// High-level state of the hosted onion service, when launched.
    pub fn onion_service_state(&self) -> Option<tor_hsservice::status::State> {
        self.local_onion
            .lock()
            .unwrap()
            .as_ref()
            .map(|h| h.running.status().state())
    }
}

/// Build the `TorClientConfig` Arti needs, applying bridge settings.
///
/// Returns an error string rather than a `TransportError` so the caller can hand it
/// straight to [`ArtiTransport::fail`], which records it and flips the state.
///
/// # Why the bridge lines are parsed here and not in `TorConfig`
///
/// [`TorConfig::validate`] does the cheap shape check so a typo fails with a message that
/// quotes the user's own text. The authoritative parse is `BridgeConfigBuilder`'s, which
/// knows the full bridge-line grammar. Doing it here means the error names the line and
/// the reason Arti gave, which is what a user needs to fix it.
fn build_client_config(
    tor_config: &TorConfig,
    bridges: &[String],
) -> std::result::Result<TorClientConfig, String> {
    let mut builder = match tor_config.data_dir() {
        Some(dir) => arti_client::config::TorClientConfigBuilder::from_directories(
            dir.join("arti").join("state"),
            dir.join("arti").join("cache"),
        ),
        None => TorClientConfig::builder(),
    };

    for line in bridges {
        let parsed: BridgeConfigBuilder = line.parse().map_err(|e| {
            format!(
                "malformed bridge line {line:?}: {e}. Refusing to fall back to a direct \
                 connection when bridges were requested."
            )
        })?;
        builder.bridges().bridges().push(parsed);
    }

    // Pluggable transports. A bridge line whose first word is a transport name needs a
    // matching binary here; `TorConfig::validate` already rejected the case where one is
    // missing, so anything reaching this point has a transport for every named protocol.
    for transport in tor_config.transports() {
        let Some((protocol, path)) = transport.split_once('=') else {
            // Unreachable: `validate` rejects this shape. Kept as an error rather than an
            // `unwrap` so a future change to `validate` cannot turn it into a panic.
            return Err(format!("malformed transport {transport:?}"));
        };
        let protocol = protocol.trim();
        let path = path.trim();

        let mut transport_builder = TransportConfigBuilder::default();
        transport_builder
            .protocols(vec![protocol.parse().map_err(|e| {
                format!("invalid transport protocol {protocol:?}: {e}")
            })?])
            .path(CfgPath::new_literal(std::path::Path::new(path)))
            .run_on_startup(true);
        builder.bridges().transports().push(transport_builder);
    }

    builder
        .build()
        .map_err(|e| format!("invalid Tor configuration: {e}"))
}

impl Default for ArtiTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymityTransport for ArtiTransport {
    fn anonymity(&self) -> AnonymityClass {
        // Arti is a Tor client, so this is Tor-grade by construction. Note that
        // `send` still refuses unless the state is `Ready`.
        AnonymityClass::TorOnion
    }

    fn status(&self) -> TransportStatus {
        State::from_u8(self.state.load(Ordering::SeqCst)).to_status()
    }

    fn local_onion(&self) -> Option<OnionId> {
        self.local_onion
            .lock()
            .unwrap()
            .as_ref()
            .map(|h| h.address.clone())
    }

    fn is_onion_service_reachable(&self) -> bool {
        ArtiTransport::is_onion_service_reachable(self)
    }

    fn set_inbound_handler(&self, handler: Arc<dyn Fn(Vec<u8>) + Send + Sync>) {
        *self.inbound_handler.lock().unwrap() = Some(handler);
    }

    fn failure_reason(&self) -> Option<String> {
        self.failure.lock().unwrap().clone()
    }

    fn send_ready(&self, route: &PeerRoute, payload: &[u8]) -> Result<()> {
        // The gate in `AnonymityTransport::send` has already checked state and
        // anonymity class. What remains is route validity and the actual write.
        if !route.is_internet_routable() {
            return Err(TransportError::InvalidRoute(
                "only onion rendezvous routes are deliverable".to_string(),
            ));
        }

        let (client, runtime) = {
            let guard = self.client.lock().unwrap();
            guard
                .as_ref()
                .map(|active| (Arc::clone(&active.client), Arc::clone(&active.runtime)))
                .ok_or(TransportError::NotReady)?
        };

        // Extract the onion host from the route description. The route was
        // validated when constructed, so this cannot fail for a well-formed
        // onion route.
        let host = route
            .describe()
            .strip_prefix("onion:")
            .ok_or_else(|| TransportError::InvalidRoute("not an onion route".to_string()))?
            .to_string();

        // Connect, write the length-prefixed payload, and await the 1-byte receipt
        // before dropping the stream (dropping a Tor DataStream before the peer reads
        // sends an END cell that can truncate in-flight data).
        if payload.is_empty() || payload.len() > MAX_INBOUND_PAYLOAD_BYTES {
            return Err(TransportError::Failed(
                "outbound payload length out of bounds".to_string(),
            ));
        }
        let len_prefix = (payload.len() as u32).to_le_bytes();

        let result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    runtime.block_on(async {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut stream = client.connect((host.as_str(), 80)).await?;
                        stream.write_all(&len_prefix).await?;
                        stream.write_all(payload).await?;
                        stream.flush().await?;
                        let mut ack = [0u8; 1];
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            stream.read_exact(&mut ack),
                        )
                        .await;
                        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                    })
                })
                .join()
        })
        .map_err(|_| TransportError::Failed("onion delivery worker panicked".to_string()))?;

        result.map_err(|e| TransportError::Failed(format!("onion delivery failed: {e}")))
    }

    fn shutdown(&self) {
        *self.local_onion.lock().unwrap() = None;
        let mut client = self.client.lock().unwrap();
        match State::from_u8(self.state.load(Ordering::SeqCst)) {
            State::Bootstrapping => {
                *self.failure.lock().unwrap() =
                    Some("Tor bootstrap was cancelled; restart the transport to retry".to_string());
                self.state.store(State::Failed as u8, Ordering::SeqCst);
            }
            State::Failed => {}
            _ => self.state.store(State::Idle as u8, Ordering::SeqCst),
        }
        *client = None;
    }
}

impl std::fmt::Debug for ArtiTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiTransport")
            .field("status", &self.status())
            .field("hosts_onion_service", &self.hosts_onion_service())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_transport_is_idle_and_refuses_to_send() {
        let t = ArtiTransport::new();
        assert_eq!(t.status(), TransportStatus::Idle);
        assert_eq!(t.anonymity(), AnonymityClass::TorOnion);

        let onion =
            OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
                .unwrap();
        let err = t.send(&PeerRoute::onion(onion), b"x").unwrap_err();
        assert!(matches!(err, TransportError::NotReady));
    }

    #[test]
    fn it_does_not_advertise_an_onion_address_it_does_not_host() {
        // The honesty requirement from plan.md §8: never claim a capability that
        // is not implemented or not yet running.
        let t = ArtiTransport::new();
        assert!(t.local_onion().is_none());
        assert!(!t.hosts_onion_service());
    }

    #[test]
    fn hosting_before_bootstrap_is_refused() {
        // Hosting needs a bootstrapped client, so asking earlier must fail
        // explicitly rather than blocking or half-initialising.
        let t = ArtiTransport::new();
        let err = t.host_onion_service().unwrap_err();
        assert!(matches!(err, TransportError::NotReady));
        // And it must not have changed the honesty flag.
        assert!(!t.hosts_onion_service());
    }

    #[test]
    fn shutdown_returns_to_idle() {
        let t = ArtiTransport::new();
        t.shutdown();
        assert_eq!(t.status(), TransportStatus::Idle);
    }

    // -- The bootstrap deadline -------------------------------------------------
    //
    // These test the deadline *policy*, not a live bootstrap. A live bootstrap needs a
    // network that completes a consensus download, which is exactly what this build
    // environment cannot do — so the policy is what can be verified here, and the live
    // path is covered by the gated `tor_e2e` test.

    #[test]
    fn the_default_deadline_is_two_minutes() {
        // Pinned so a change to the default is deliberate. Two minutes is long enough for
        // a slow-but-working network and short enough that a user is not left staring at
        // "bootstrapping" indefinitely.
        assert_eq!(DEFAULT_BOOTSTRAP_TIMEOUT_SECS, 120);
    }

    #[test]
    fn the_deadline_honours_a_valid_override_and_rejects_a_malformed_one() {
        // One test rather than two, because both mutate the same process-wide environment
        // variable and cargo runs tests in parallel: two tests setting and restoring it
        // would race, and the failure would look like a bug in the deadline rather than in
        // the test.
        let previous = std::env::var(BOOTSTRAP_TIMEOUT_ENV).ok();

        // A valid override is honoured.
        std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, "7");
        assert_eq!(bootstrap_timeout().as_secs(), 7);

        // A malformed override falls back to the default. A typo in an environment
        // variable must not silently restore the unbounded hang this deadline exists to
        // prevent. Zero is treated the same way: "no timeout" is not a value a user can
        // ask for by accident.
        for bad in ["", "abc", "0", "-5", "1.5", "  "] {
            std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, bad);
            assert_eq!(
                bootstrap_timeout().as_secs(),
                DEFAULT_BOOTSTRAP_TIMEOUT_SECS,
                "the malformed value {bad:?} must fall back to the default"
            );
        }

        // Surrounding whitespace on a valid number is tolerated, because a trailing
        // newline from a shell `export` is a common and harmless way to get one.
        std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, " 30 ");
        assert_eq!(bootstrap_timeout().as_secs(), 30);

        match previous {
            Some(v) => std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, v),
            None => std::env::remove_var(BOOTSTRAP_TIMEOUT_ENV),
        }
    }

    #[test]
    fn a_bootstrap_returns_at_the_deadline_instead_of_hanging() {
        // The defect this fixes, tested end to end: `bootstrap()` must *return* at the
        // deadline, not merely flip a flag while the caller stays blocked.
        //
        // This is the assertion the earlier watchdog-only design failed. A watchdog that
        // flips the state is useless to a synchronous caller if `block_on` never returns —
        // and Arti's bootstrap busy-loops without yielding when it cannot download a
        // consensus, so `tokio::time::timeout` cannot interrupt it either.
        //
        // A one-second deadline keeps the test fast. On a network where Tor bootstraps in
        // under a second this would succeed instead, which is also a pass.
        let previous = std::env::var(BOOTSTRAP_TIMEOUT_ENV).ok();
        std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, "1");

        let t = ArtiTransport::new();
        let started = std::time::Instant::now();
        let result = t.bootstrap();
        let elapsed = started.elapsed();

        match previous {
            Some(v) => std::env::set_var(BOOTSTRAP_TIMEOUT_ENV, v),
            None => std::env::remove_var(BOOTSTRAP_TIMEOUT_ENV),
        }

        // The bound is generous — the point is that it is bounded at all. Before the fix
        // this call never returned.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "bootstrap must return within the deadline, took {elapsed:?}"
        );

        if result.is_err() {
            assert_eq!(
                t.status(),
                TransportStatus::Failed,
                "a timed-out bootstrap must leave the transport Failed, not Bootstrapping"
            );
            assert!(
                t.failure_reason().is_some_and(|r| r.contains("timed out")),
                "the reason must say it timed out, so the UI can explain it"
            );
        } else {
            assert_eq!(t.status(), TransportStatus::Ready);
        }
    }

    #[test]
    fn a_timed_out_bootstrap_leaves_the_transport_failed_not_bootstrapping() {
        // The defect this deadline fixes: without it the transport stayed `Bootstrapping`
        // forever, so the UI could not tell a slow start from a permanent failure. A
        // timeout must land on `Failed`, which is honest and lets the UI say why.
        //
        // Driven through `fail` rather than a live bootstrap: the point under test is that
        // the failure path sets the state and records a reason, which is what the timeout
        // branch calls.
        let t = ArtiTransport::new();
        let err = t
            .fail("Tor bootstrap timed out after 120s".to_string())
            .unwrap_err();

        assert_eq!(t.status(), TransportStatus::Failed);
        assert!(
            matches!(err, TransportError::Failed(_)),
            "a timeout must surface as a failure, not as a silent no-op"
        );
        assert!(
            t.failure_reason().is_some_and(|r| r.contains("timed out")),
            "the reason must say it timed out, so the UI can explain it"
        );
    }

    // -- Bridge configuration plumbing ------------------------------------------
    //
    // These prove the configuration reaches Arti's builder. They do not bootstrap: a
    // bridge only matters once a client is created, and creating one needs a network.

    #[test]
    fn a_fresh_transport_has_no_bridges_configured() {
        let t = ArtiTransport::new();
        assert!(!t.config().bridges_requested());
    }

    #[test]
    fn with_config_carries_the_bridge_settings() {
        let line = "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956";
        let t = ArtiTransport::with_config(TorConfig::with_bridges([line]));

        assert!(t.config().bridges_requested());
        assert_eq!(t.config().bridges(), &[line.to_string()]);
    }

    #[test]
    fn set_config_is_allowed_before_bootstrap() {
        // The allowed half of the `set_config` contract. The refusal half — "a client
        // already exists" — cannot be tested here without creating a real `TorClient`,
        // which needs a network. It is covered by inspection of the guard in
        // `set_config`, and the gated e2e test exercises the real path when a network
        // permits. Stated plainly rather than implied by a test name that overclaims.
        let t = ArtiTransport::new();
        assert!(t
            .set_config(TorConfig::with_bridges(["192.0.2.83:80 $0bac3941"]))
            .is_ok());
        assert!(t.config().bridges_requested());
    }

    #[test]
    fn a_direct_bridge_line_reaches_artis_builder() {
        // The pass-through requirement: a valid line must end up in the built
        // `TorClientConfig`, not merely be accepted by our own validator.
        let line = "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956";
        let config = TorConfig::with_bridges([line]);
        let bridges = config.validate().expect("the line is well formed");

        let built = build_client_config(&config, &bridges)
            .expect("a valid direct bridge must build a client config");

        // `TorClientConfig` exposes its bridges through `AsRef<[BridgeConfig]>`. The
        // element type is not publicly nameable (Arti keeps `BridgeConfig` private), so
        // the slice type is inferred from the single `AsRef<[T]>` impl.
        let configured: &[_] = built.as_ref();
        assert_eq!(
            configured.len(),
            1,
            "the bridge line must be present in the built configuration"
        );
    }

    #[test]
    fn no_bridges_builds_the_default_configuration() {
        let config = TorConfig::none();
        let bridges = config.validate().expect("nothing to validate");
        let built = build_client_config(&config, &bridges).expect("the default must build");
        let configured: &[_] = built.as_ref();
        assert!(
            configured.is_empty(),
            "no bridges requested must mean no bridges configured"
        );
    }

    #[test]
    fn profiles_have_distinct_arti_storage_configuration() {
        let first = TorConfig::none().with_data_dir(std::path::Path::new("profile-one"));
        let second = TorConfig::none().with_data_dir(std::path::Path::new("profile-two"));
        let first = build_client_config(&first, &[]).unwrap();
        let second = build_client_config(&second, &[]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn concurrent_bootstrap_and_configuration_changes_are_rejected() {
        let transport = ArtiTransport::new();
        transport
            .state
            .store(State::Bootstrapping as u8, Ordering::SeqCst);
        assert!(transport.bootstrap().is_err());
        assert!(transport.set_config(TorConfig::none()).is_err());
        transport.shutdown();
        assert_eq!(transport.status(), TransportStatus::Failed);
        assert!(transport.failure_reason().unwrap().contains("cancelled"));
    }

    #[test]
    fn runtime_outlives_creator_and_can_be_dropped_in_async_context() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = Arc::new(TorRuntime(Some(tokio::runtime::Runtime::new().unwrap())));
            assert!(sender.send(runtime).is_ok());
        })
        .join()
        .unwrap();
        let runtime = receiver.recv().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        runtime.spawn(async move {
            sender.send(()).unwrap();
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let other_runtime = tokio::runtime::Runtime::new().unwrap();
        other_runtime.block_on(async move { drop(runtime) });
    }

    #[test]
    fn a_malformed_bridge_line_fails_before_a_client_is_built() {
        // The privacy rule: a bad line must not be skipped so the remaining lines are used.
        let config = TorConfig::with_bridges(["obfs4"]);
        let err = config
            .validate()
            .expect_err("a one-word bridge line must be rejected");
        assert!(err.to_string().contains("malformed bridge line"));
    }

    #[test]
    fn bootstrap_fails_closed_when_bridges_are_unusable() {
        // End to end through the public API: a bridge needing a missing transport must
        // leave the transport `Failed` with a reason, and must not attempt a direct
        // connection. No network is touched because validation fails first.
        let line = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc";
        let t = ArtiTransport::with_config(TorConfig::with_bridges([line]));

        let err = t
            .bootstrap()
            .expect_err("unusable bridges must fail closed");
        assert_eq!(t.status(), TransportStatus::Failed);
        let message = err.to_string();
        assert!(
            message.contains("no transport binary is configured"),
            "the reason must name the missing transport, got: {message}"
        );
        assert!(
            t.failure_reason()
                .is_some_and(|r| r.contains("Refusing to fall back")),
            "the recorded reason must state the privacy consequence"
        );
    }
}
