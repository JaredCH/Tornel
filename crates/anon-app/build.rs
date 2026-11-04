//! Tauri build script.
//!
//! `tauri_build::build()` generates the context the `tauri::generate_context!`
//! macro needs (the asset map for the bundled frontend, the capability set, and
//! the window configuration from `tauri.conf.json`).
//!
//! If this fails, the usual cause is a malformed `tauri.conf.json` or a missing
//! `icons/` directory — Tauri validates both at build time rather than at
//! runtime, which is the behaviour we want: a broken bundle should not compile.

fn main() {
    tauri_build::build()
}
