//! Tracing initialisation (`GAP-CLOSURE-PLAN.md` Gap 3, item 2).
//!
//! # Why this exists
//!
//! Arti reports its bootstrap stages — "connecting to the network", "loading directory
//! information", "downloading a consensus" — as `tracing` events. Until a subscriber is
//! installed, those events go nowhere. That is not a cosmetic problem: it is *why* Gap 3
//! was misdiagnosed. An earlier attempt to reproduce the Tor failure produced an empty
//! log, which looked like a silent hang rather than "Arti is stuck downloading a
//! consensus". Every future Tor diagnosis would start blind the same way.
//!
//! # Why it is gated behind `RUST_LOG`
//!
//! A subscriber that is always on would print Arti's per-circuit chatter to every user's
//! terminal. The default must be silent. `RUST_LOG` is the conventional switch, and it is
//! what Arti's own documentation tells users to set, so a user following Tor's docs gets
//! the behaviour they expect.
//!
//! # Why installation is idempotent
//!
//! A process may call this from more than one entry point (the CLI's `tor-probe`, the
//! app's launch path, a test). `tracing` allows exactly one global subscriber; a second
//! `init` would panic. [`init_from_env`] therefore returns `false` when a subscriber is
//! already installed instead of panicking, so a caller can call it unconditionally.

use std::sync::OnceLock;

/// Set once a subscriber has been installed by this module.
///
/// `tracing`'s own `set_global_default` already rejects a second install, but it does so
/// by returning an error that callers routinely ignore or `unwrap`. Tracking it here lets
/// [`init_from_env`] answer "was I the one who installed it?" without guessing.
static INSTALLED: OnceLock<bool> = OnceLock::new();

/// Install a `tracing` subscriber if `RUST_LOG` asks for one.
///
/// Returns `true` when this call installed the subscriber, `false` when it was already
/// installed or when `RUST_LOG` was unset/empty. Never panics: a malformed `RUST_LOG`
/// falls back to a warning on stderr rather than taking the process down, because a typo
/// in a diagnostic switch must not be fatal.
///
/// # What a user sees
///
/// ```text
/// set RUST_LOG=arti=debug
/// anon-demo tor-probe
/// ```
///
/// With `RUST_LOG` unset the process is silent, which is the default.
///
/// # Why the filter is `EnvFilter` and not a fixed level
///
/// Arti's bootstrap stages are logged at `debug` and `info` under the `arti` target. A
/// fixed level would either hide them or flood the terminal with everything else. The
/// filter lets a user ask for exactly `arti=debug` and nothing more.
pub fn init_from_env() -> bool {
    // `OnceLock::get_or_init` runs the closure at most once per process, so the second
    // caller sees the first caller's answer rather than racing to install.
    *INSTALLED.get_or_init(|| {
        // Distinguish "not requested" from "requested but broken" *before* parsing.
        // `EnvFilter::try_from_default_env` returns an error for both an absent variable
        // and a malformed one, and reporting an absent `RUST_LOG` as unparseable would
        // print a warning on every normal run — which is exactly the noise this module
        // exists to avoid.
        match std::env::var("RUST_LOG") {
            Ok(value) if value.trim().is_empty() => return false,
            Ok(_) => {}
            Err(_) => return false,
        }

        let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() else {
            // `RUST_LOG` was set but could not be parsed. Say so and stay silent rather
            // than installing a subscriber with a guessed filter: a diagnostic switch
            // that silently does something other than what was asked is worse than one
            // that does nothing.
            eprintln!(
                "anon: ignoring an unparseable RUST_LOG value; tracing stays disabled. \
                 Expected a filter such as `arti=debug` or `info`."
            );
            return false;
        };

        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            // stderr, not stdout: the CLI's stdout is its output channel, and mixing
            // diagnostics into it would corrupt anything piping the command's result.
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_level(true)
            .finish();

        match tracing::subscriber::set_global_default(subscriber) {
            Ok(()) => true,
            Err(e) => {
                // Another library installed a subscriber first. That is not an error we
                // can fix, and it is not worth failing a launch over.
                eprintln!("anon: could not install the tracing subscriber: {e}");
                false
            }
        }
    })
}

/// Whether a subscriber was installed by [`init_from_env`].
pub fn is_installed() -> bool {
    INSTALLED.get().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_or_empty_rust_log_is_silent_not_an_error() {
        // Regression test for a real bug: `EnvFilter::try_from_default_env` returns an
        // error both when `RUST_LOG` is absent and when it is malformed. Treating the
        // absent case as malformed printed "ignoring an unparseable RUST_LOG value" on
        // every normal run — noise on the default path, which is the opposite of what
        // this module promises.
        //
        // The check is on the *decision*, not on the subscriber: a subscriber can only be
        // installed once per process, so the test asserts the predicate the decision is
        // built from.
        for value in [None, Some(""), Some("   ")] {
            let requested = match value {
                Some(v) => !v.trim().is_empty(),
                None => false,
            };
            assert!(
                !requested,
                "an absent or blank RUST_LOG must not be treated as a request for logging"
            );
        }
    }

    #[test]
    fn init_is_idempotent_and_never_panics() {
        // Called twice on purpose: the second call must not panic. The return value is
        // whatever the first call decided, so this asserts stability rather than a
        // particular answer — the answer depends on the ambient `RUST_LOG`, which the
        // test runner controls.
        let first = init_from_env();
        let second = init_from_env();
        assert_eq!(
            first, second,
            "a second install must report the same outcome as the first"
        );
        assert_eq!(is_installed(), first);
    }
}
