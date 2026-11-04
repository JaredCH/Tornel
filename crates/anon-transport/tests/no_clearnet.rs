//! Automated guard for the "no clearnet fallback" invariant (`plan.md` §7.1, §10).
//!
//! The plan requires that the process holds **no direct socket outside the
//! transport module**. This test enforces that by scanning the workspace source
//! for socket APIs and failing if it finds any outside an explicit allowlist.
//!
//! Why a source scan rather than a runtime check only: a runtime check proves the
//! *current* code path is clean, but a newly added direct socket somewhere
//! unrelated would only be caught if a test happened to exercise it. Scanning
//! catches the addition at review time, which is when it is cheap to fix.
//!
//! There are two complementary guards:
//!
//! 1. This test (runs under `cargo test`, fails the build).
//! 2. `scripts/check-no-clearnet.ps1` (runs in CI, also scans non-Rust files).

use std::path::{Path, PathBuf};

/// Socket-bearing APIs that must not appear outside the transport crate.
///
/// Chosen to cover the ways Rust code actually opens a raw connection. Note that
/// `tokio::net::*` and `async_std::net::*` are included: a direct socket is a
/// direct socket regardless of the async runtime.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "std::net::TcpStream",
    "std::net::TcpListener",
    "std::net::UdpSocket",
    "std::net::ToSocketAddrs",
    "tokio::net::TcpStream",
    "tokio::net::TcpListener",
    "tokio::net::UdpSocket",
    "async_std::net::TcpStream",
    "async_std::net::TcpListener",
    "async_std::net::UdpSocket",
    "TcpStream::connect",
    "TcpListener::bind",
    "UdpSocket::bind",
    "UdpSocket::connect",
];

/// Files permitted to mention socket APIs.
///
/// Only the transport crate may, and even there the intent is that the socket is
/// owned by Arti rather than by us. Each entry must state why it is allowed.
const ALLOWED_FILES: &[&str] = &[
    // Arti owns its own sockets internally. We call its API, and its API
    // surface is the thing under the feature flag.
    "crates/anon-transport/src/arti.rs",
    // This test file necessarily names the patterns it searches for.
    "crates/anon-transport/tests/no_clearnet.rs",
];

fn workspace_root() -> PathBuf {
    // crates/anon-transport -> repo root is two levels up from the manifest dir.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("manifest dir should have a grandparent")
        .to_path_buf()
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() {
            // Skip build output and any vendored or tool directories.
            if matches!(name.as_str(), "target" | ".git" | "node_modules" | ".cargo") {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Return (relative_path, line_number, pattern) for every violation found.
fn find_violations(root: &Path) -> Vec<(String, usize, String)> {
    let mut files = Vec::new();
    // Only scan our crates, not the entire repo (docs and plan.md are prose).
    collect_rust_files(&root.join("crates"), &mut files);

    let mut violations = Vec::new();

    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");

        if ALLOWED_FILES.contains(&rel.as_str()) {
            continue;
        }

        let Ok(contents) = std::fs::read_to_string(&file) else {
            continue;
        };

        for (idx, line) in contents.lines().enumerate() {
            // Ignore comment lines so documentation about the invariant does not
            // trip the guard. A pattern in a comment cannot open a socket.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
                continue;
            }

            for pattern in FORBIDDEN_PATTERNS {
                if line.contains(pattern) {
                    violations.push((rel.clone(), idx + 1, (*pattern).to_string()));
                }
            }
        }
    }

    violations
}

#[test]
fn no_direct_sockets_outside_the_transport_module() {
    let root = workspace_root();
    let violations = find_violations(&root);

    assert!(
        violations.is_empty(),
        "direct socket usage found outside the transport module; this breaks the \
         no-clearnet-fallback guarantee (plan.md §1.2, §3.4):\n{}",
        violations
            .iter()
            .map(|(f, l, p)| format!("  {f}:{l} uses `{p}`"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_guard_actually_detects_a_violation() {
    // A guard that cannot fail is worthless. This proves the scanner works by
    // feeding it a synthetic file that contains a forbidden pattern.
    let temp = std::env::temp_dir().join("anon-no-clearnet-guard-test");
    let dir = temp.join("crates/fake/src");
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let offending = dir.join("offending.rs");
    std::fs::write(
        &offending,
        "fn evil() { let _ = std::net::TcpStream::connect(\"1.2.3.4:80\"); }\n",
    )
    .expect("write offending file");

    let violations = find_violations(&temp);
    assert!(
        !violations.is_empty(),
        "the guard failed to detect a planted direct socket"
    );
    assert!(violations
        .iter()
        .any(|(_, _, p)| p == "std::net::TcpStream"));

    // A comment mentioning a socket must NOT be flagged.
    let benign = temp.join("crates/fake/src/benign.rs");
    std::fs::write(
        &benign,
        "// We must never call std::net::TcpStream::connect here.\nfn fine() {}\n",
    )
    .expect("write benign file");
    let violations = find_violations(&temp);
    assert!(
        !violations.iter().any(|(f, _, _)| f.ends_with("benign.rs")),
        "comments must not trip the guard"
    );

    let _ = std::fs::remove_dir_all(&temp);
}
