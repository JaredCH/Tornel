//! The desktop entry point.
//!
//! Deliberately tiny: `anon_app::run()` does the work. Keeping `main` trivial means
//! the startup path is testable as a library function rather than only by launching
//! a window.
//!
//! On Windows, release builds do not open a console window; the `windows_subsystem`
//! attribute is what suppresses it. Debug builds keep the console so startup errors
//! are visible.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(e) = anon_app::run() {
        // A startup failure is fatal and must be reported. An app that cannot open
        // its encrypted database must not start in a degraded mode that might write
        // plaintext (`plan.md` §6.3).
        eprintln!("anon: failed to start: {e}");
        std::process::exit(1);
    }
}
