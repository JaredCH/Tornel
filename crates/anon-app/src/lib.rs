//! The Tauri v2 shell (`plan.md` §7.3).
//!
//! # What this crate is
//!
//! The desktop application: a webview for presentation and consent, and a thin
//! Rust adapter over [`anon_ipc::Backend`]. Everything that matters — identity,
//! encryption, the anonymity gate, retention, consent binding — lives in the
//! crates below and is tested without a webview.
//!
//! ```text
//! webview (HTML/CSS/JS)   presentation + consent only
//!        |  Tauri IPC
//! anon-app                THIS CRATE: command adapter, no crypto
//!        |
//! anon-ipc                Backend facade, DTOs, validation
//!        |
//! core / storage / transport / mls / messaging / consent
//! ```
//!
//! # Why the adapter is deliberately boring
//!
//! `plan.md` §7.3 calls every command an attack surface. The defence is not
//! cleverness here — it is that this layer is too small to hide a bypass in. Each
//! command deserializes, calls one backend method, and serializes. If a rule needs
//! enforcing, it is enforced below.
//!
//! # Startup
//!
//! [`run`] presents the locked vault. Creating or unlocking it builds the backend
//! and applies saved privacy policy before starting the retention purge timer
//! and (with the `tor` feature) the Tor bootstrap and onion service.
//!
//! # The identity seed lives in the OS keychain
//!
//! `plan.md` §2.3 requires the private seed to live in the OS keychain (Windows
//! Credential Manager, macOS Keychain, Linux Secret Service). [`keychain`] provides it
//! and [`identity_store`] owns the policy: create on first launch, migrate a legacy
//! plaintext file, and **refuse to start** when the keychain is unavailable rather than
//! falling back to a file.
//!
//! # The database passphrase is user-held
//!
//! The store remains closed until the user supplies their vault passphrase.
//! Legacy machine-held passphrases use the explicit resumable migration flow.

pub mod commands;
pub mod identity_store;
pub mod keychain;
pub mod personas;
pub mod startup;
pub mod vault;

use anon_storage::{Argon2Params, Store};
use anon_transport::AnonymityTransport;
// Only the non-`tor` build constructs the offline transport; importing it
// unconditionally would warn on the `tor` build.
#[cfg(not(feature = "tor"))]
use anon_transport::OfflineTransport;
use commands::AppState;
use keychain::KeychainBackend;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;

/// How often the retention purge runs (`plan.md` §6.4: on launch and every 24h).
const PURGE_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// The Android entry point.
///
/// Tauri's mobile targets do not have a `main`: the Android activity loads the library and
/// calls this. It must exist for the Android build to link, and it is the same [`run`] the
/// desktop binary uses, so there is one startup path rather than two.
///
/// `tauri::mobile_entry_point` generates the JNI symbol the Java side looks up. It is
/// gated to mobile targets because on desktop the symbol would be dead code.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run_mobile() {
    if let Err(error) = run() {
        eprintln!("anon: failed to start: {error}");
    }
}

/// Build and run the application.
///
/// Returns the Tauri error type so `main.rs` can report a startup failure rather
/// than panicking — a panic in a security-sensitive app is a bad failure mode.
pub fn run() -> tauri::Result<()> {
    // Install the tracing subscriber first, so Arti's bootstrap stages are visible when
    // `RUST_LOG` asks for them. Silent by default. See `anon_transport::logging`: without
    // this, a stuck Tor bootstrap produces an empty log and looks like a silent hang.
    anon_transport::init_tracing();

    // A Linux launch that opens no window is the hardest failure to diagnose, because the
    // process exits without a message. These fallbacks are the documented WebKitGTK
    // switches for the two common causes; see the function's own docs.
    apply_linux_webview_fallbacks();

    // When `ANON_DATA_DIR` is set for running multiple instances side by side, also point
    // WebView2 (`WEBVIEW2_USER_DATA_FOLDER`) into a subdirectory of that profile if not
    // already overridden, so two instances do not contend on the same Chromium user-data folder.
    if let Ok(custom_dir) = std::env::var("ANON_DATA_DIR") {
        let trimmed = custom_dir.trim();
        if !trimmed.is_empty() && std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_none() {
            let wv_dir = PathBuf::from(trimmed).join("webview2");
            let _ = std::fs::create_dir_all(&wv_dir);
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", wv_dir);
        }
    }

    let result = tauri::Builder::default()
        .setup(|app| {
            let state = build_state(app.handle())?;
            if let Ok(title) = std::env::var("ANON_WINDOW_TITLE") {
                if !title.trim().is_empty() {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.set_title(title.trim());
                    }
                }
            }
            app.manage(state);
            Ok(())
        })
        .pipe(commands::register)
        .run(tauri::generate_context!());

    // A GUI launch has no terminal, so a failure before the window opens would otherwise
    // leave no trace at all. Record it where the user can find it.
    if let Err(error) = &result {
        if let Some(path) = startup::record_failure(error) {
            eprintln!("anon: startup details written to {}", path.display());
        }
    }
    result
}

/// Disable WebKitGTK's DMA-BUF renderer, which leaves a blank window on some systems.
///
/// On drivers and virtual machines without working GBM support, WebKitGTK's DMA-BUF
/// renderer fails with "Failed to get GBM device" and the window never paints. The
/// documented workaround is `WEBKIT_DISABLE_DMABUF_RENDERER=1`, which falls back to the
/// shared-memory path.
///
/// # Why this is set by default
///
/// The failure mode is a window that opens and stays blank, which a user cannot diagnose
/// and cannot work around without knowing the variable exists. The cost of the fallback is
/// a slower paint path on hardware that would have worked; the cost of not setting it is an
/// unusable app on hardware that would not. A user who wants the faster path back sets the
/// variable to `0`, and an explicit value is never overridden.
///
/// Deliberately *not* included: `WEBKIT_DISABLE_COMPOSITING_MODE`. It also fixes blank
/// windows, but it disables accelerated compositing for every user rather than only the
/// broken path, so it stays a documented manual fallback instead of a default.
#[cfg(target_os = "linux")]
fn apply_linux_webview_fallbacks() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_webview_fallbacks() {}

/// Build the application state.
///
/// # The app starts locked
///
/// Startup no longer opens the database. It cannot: the passphrase is user-held, so there
/// is nothing to open it with until the user supplies one. What startup does instead is
/// decide *which screen to show* — setup, migration, or unlock — and hand the webview a
/// vault it can act on.
///
/// This is the structural change Gap 2 required. The previous build opened the store here
/// using a machine-held secret, which meant the app started without a login and the
/// at-rest encryption was decorative. See [`vault`] for the full reasoning.
///
/// # The keychain check blocks, it does not abort
///
/// An unavailable keychain means the identity seed cannot be read or stored safely, and
/// the app must not start in a mode that would write a plaintext seed. That rule is
/// unchanged. What changed is the *reporting*: the state is marked blocked and the launch
/// screen explains why, instead of the process exiting before a window exists. A GUI
/// launch has no terminal, so an early exit is indistinguishable from a crash — which is
/// how an unavailable Linux Secret Service was reported.
fn build_state(handle: &tauri::AppHandle) -> Result<AppState, Box<dyn std::error::Error>> {
    let data_dir = app_data_dir(handle)?;
    std::fs::create_dir_all(&data_dir)?;

    // The vault owns the passphrase policy and the database path. It holds no secret.
    let vault = vault::Vault::new(&data_dir, Argon2Params::mobile_default());

    // The keychain must be usable before anything else. Checking here rather than at
    // unlock time means a broken keychain is reported at launch, not after the user has
    // typed a passphrase and expected to get in.
    //
    // The failure is *reported*, not fatal to the process. Returning an error here would
    // abort before the window opens, and a GUI launch has no terminal — so the user sees
    // the app start and vanish with no explanation. That is precisely how an unavailable
    // Linux Secret Service was reported. The app still refuses to write a plaintext seed;
    // it just says so on screen.
    let keychain = keychain::OsKeychain::new();
    if !keychain.available() {
        let reason = "The OS credential store is unavailable, so the identity seed cannot \
                      be read or stored safely. The app will not fall back to a plaintext \
                      seed file. On Linux this usually means no Secret Service provider is \
                      running: install and start gnome-keyring or KWallet, then relaunch."
            .to_string();
        eprintln!("anon: {reason}");
        return Ok(AppState::blocked(vault, data_dir, reason));
    }

    // A rekey interrupted by a crash must be finished before the app can open the
    // database. The vault reports that state so the launch screen can say where it
    // stopped rather than "please wait".
    if vault.migration_in_progress() {
        eprintln!(
            "anon: a passphrase migration was interrupted; the launch screen will \
             offer to finish it"
        );
    }

    Ok(AppState::locked(vault, data_dir))
}

/// Build the transport for this build.
///
/// With `--features tor` this is the embedded Arti client; without it, the
/// fail-closed offline transport. The offline transport is not a stub — it is the
/// control that makes "the app is offline rather than degraded" the default.
///
/// Public because the unlock commands build a backend after the user supplies their
/// passphrase, and the transport is part of that backend. Building it once at startup and
/// reusing it would mean a Tor bootstrap started before the user was even authenticated.
pub fn build_transport(data_dir: &std::path::Path) -> Arc<dyn AnonymityTransport> {
    #[cfg(feature = "tor")]
    {
        let config = match anon_transport::TorConfig::load(data_dir) {
            Ok(config) => config.with_data_dir(data_dir),
            Err(error) => {
                eprintln!("anon: Tor configuration failed: {error}");
                return Arc::new(anon_transport::OfflineTransport::new(error.to_string()));
            }
        };
        Arc::new(anon_transport::arti::ArtiTransport::with_config(config))
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = data_dir;
        Arc::new(OfflineTransport::new(
            "this build has no Tor backend; rebuild with --features tor",
        ))
    }
}

/// Run the retention purge every 24 hours.
///
/// Deliberately a plain thread rather than an async task: the purge is blocking
/// SQLite work, and putting it on the async runtime would stall the reactor.
///
/// Called from [`commands::AppState::install`] rather than at startup, because the store
/// does not exist until the user unlocks. The store's own `purge_on_open` handles the
/// launch-time purge; this timer covers the 24h cadence after that.
pub(crate) fn spawn_purge_timer(store: Arc<Store>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(PURGE_INTERVAL_SECS));
        let now = store.now();
        match store.purge(now) {
            Ok(report) if !report.is_empty() => {
                eprintln!(
                    "anon: retention purge removed {} row(s), shredded {} bucket(s)",
                    report.total_deleted(),
                    report.shredded_buckets.len()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("anon: retention purge failed: {e}"),
        }
    });
}

/// The per-user data directory, or `ANON_DATA_DIR` when running isolated multi-instance previews.
fn app_data_dir(handle: &tauri::AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(override_dir) = std::env::var("ANON_DATA_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}").into())
}

/// Small extension so the builder chain reads top-to-bottom.
trait Pipe: Sized {
    fn pipe<F: FnOnce(Self) -> Self>(self, f: F) -> Self {
        f(self)
    }
}

impl<T> Pipe for T {}
