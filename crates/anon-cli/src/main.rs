//! `anon-demo` — a runnable, two-process demonstration of the stack.
//!
//! # What this is for
//!
//! Every guarantee in `plan.md` is covered by tests, but tests are not the same as
//! watching two independent processes talk. This binary exists so the whole stack
//! can be exercised by hand: two real processes, two real encrypted databases, real
//! MLS ratcheting, real files on disk.
//!
//! # The honest limitation
//!
//! **The messaging demo does not use Tor.** It writes frames to a directory and
//! labels that everywhere it appears. The separate `tor-probe` command checks
//! embedded Arti bootstrap and onion-service launch without sending messages.
//!
//! What that means concretely:
//!
//! | Property | Demonstrated here? |
//! | --- | --- |
//! | MLS ratcheting, epoch advance, removal lockout | **Yes** — real `openmls` |
//! | SQLCipher encryption at rest, 90-day TTL, crypto-shredding | **Yes** — real files |
//! | Identity, contact codes, signatures, X25519 agreement | **Yes** — real keys |
//! | Padded framing, replay rejection | **Yes** — real frames |
//! | IP anonymity via Tor | **No** — needs a network where Tor bootstraps |
//!
//! The anonymity guarantee is enforced by the *transport gate*, which is tested
//! separately (`anon-transport`). This demo deliberately does not weaken that gate
//! to make itself work; it substitutes a different transport and says so.

use anon_core::{ContactCode, IdentityKeys};
use anon_messaging::Frame;
use anon_mls::{Group, MlsProvider};
use anon_storage::{Argon2Params, Store, StoreConfig};
use std::path::{Path, PathBuf};

/// The passphrase for the demo databases.
///
/// Hard-coded because this is a demo, and stated plainly so nobody mistakes it for
/// a design decision. A real build derives this from a user passphrase via Argon2id
/// (which it also does here — only the *input* is fixed).
const DEMO_PASSPHRASE: &str = "anon-demo-passphrase";

/// Conversation id used by the demo. A real app derives this per conversation.
const CONVERSATION: [u8; 16] = [0x42; 16];

fn main() {
    // Install the tracing subscriber before anything else so Arti's bootstrap stages are
    // visible when `RUST_LOG` asks for them. Silent by default: a diagnostic switch must
    // not add noise to a normal run. See `anon_transport::logging` for why this exists —
    // without it, a stuck Tor bootstrap produces an empty log and looks like a silent hang.
    anon_transport::init_tracing();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }

    let result = match args[0].as_str() {
        "init" => cmd_init(&args),
        "group-create" => cmd_group_create(&args),
        "group-add" => cmd_group_add(&args),
        "group-join" => cmd_group_join(&args),
        "send" => cmd_send(&args),
        "deliver" => cmd_deliver(&args),
        "recv" => cmd_recv(&args),
        "show" => cmd_show(&args),
        "remove" => cmd_remove(&args),
        "purge" => cmd_purge(&args),
        "tor-probe" => cmd_tor_probe(&args),
        "tor-e2e-chat" => cmd_tor_e2e_chat(&args),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown command `{other}`")),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn print_usage() {
    println!(
        "anon-demo — two-process demonstration of the anon stack\n\
         \n\
         NOTE: this demo uses a file-drop transport, NOT Tor. See the module docs.\n\
         \n\
         Commands:\n\
         \x20 init <dir>                        create an identity + encrypted database\n\
         \x20 group-create <dir>                create a group\n\
         \x20 group-add <dir> <peer-dir>        add a peer (writes a welcome file)\n\
         \x20 group-join <dir> <welcome-file>   join a group from a welcome file\n\
         \x20 send <dir> <text>                 encrypt and drop a frame\n\
         \x20 deliver <from-dir> <to-dir>       move dropped frames to a peer's drop dir\n\
         \x20 recv <dir>                        collect and decrypt dropped frames\n\
         \x20 show <dir>                        list stored messages\n\
         \x20 remove <dir> <leaf-index>         remove a member (advances the epoch)\n\
         \x20 purge <dir>                       run the retention purge\n\
         \x20 tor-probe [dir]                   check whether Tor bootstraps here\n\
         \x20 tor-e2e-chat <dir-a> <dir-b> [msg] live two-peer onion rendezvous messaging\n\
         \n\
         tor-probe reads bridges from <dir>/tor.conf when a directory is given, or from\n\
         ANON_TOR_BRIDGES. Set RUST_LOG=arti=debug to see Arti's bootstrap stages."
    );
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn db_path(dir: &Path) -> PathBuf {
    dir.join("anon.db")
}

fn drop_dir(dir: &Path) -> PathBuf {
    dir.join("drop")
}

fn group_file(dir: &Path) -> PathBuf {
    dir.join("group.id")
}

fn identity_file(dir: &Path) -> PathBuf {
    dir.join("identity.txt")
}

fn welcome_file(dir: &Path) -> PathBuf {
    dir.join("welcome.bin")
}

// ---------------------------------------------------------------------------
// Store / provider helpers
// ---------------------------------------------------------------------------

fn open_store(dir: &Path) -> Result<Store, String> {
    Store::open(
        &db_path(dir),
        DEMO_PASSPHRASE,
        StoreConfig {
            // Mobile-calibrated Argon2id, as production would use. Slower than the
            // test parameters on purpose: this is the real code path.
            params: Argon2Params::mobile_default(),
            purge_on_open: true,
            vacuum_after_purge: true,
        },
    )
    .map_err(|e| format!("could not open the encrypted database: {e}"))
}

fn provider(store: &Store) -> Result<MlsProvider, String> {
    let conn = store
        .open_secondary_connection()
        .map_err(|e| format!("secondary connection failed: {e}"))?;
    MlsProvider::new(conn).map_err(|e| format!("MLS provider failed: {e}"))
}

/// The MLS credential identity for a directory: its contact code.
///
/// Binding the MLS credential to the contact code (rather than a display name) is
/// what makes the member list a list of cryptographic identities (`plan.md` §4.3).
fn identity_bytes(dir: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(identity_file(dir))
        .map_err(|_| format!("no identity in {} — run `init` first", dir.display()))?;
    Ok(text.trim().as_bytes().to_vec())
}

fn load_group(dir: &Path, p: &MlsProvider) -> Result<Group, String> {
    let group_id = std::fs::read(group_file(dir))
        .map_err(|_| format!("no group in {} — run `group-create` first", dir.display()))?;
    Group::load(p, &group_id)
        .map_err(|e| format!("load group: {e}"))?
        .ok_or_else(|| "group not found in storage".to_string())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: init <dir>")?);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(drop_dir(&dir)).map_err(|e| format!("mkdir: {e}"))?;

    if identity_file(&dir).exists() {
        return Err(format!(
            "{} already has an identity; refusing to overwrite it",
            dir.display()
        ));
    }

    let keys = IdentityKeys::generate().map_err(|e| format!("keygen failed: {e}"))?;
    let public = keys.public();
    let code = ContactCode::encode(&public).map_err(|e| format!("contact code failed: {e}"))?;

    // The demo persists the *contact code* (public) and the escrow seed (secret).
    // A real build keeps the seed in the OS keychain (`plan.md` §2.3); writing it
    // to a file here is a demo convenience and is called out as such.
    std::fs::write(identity_file(&dir), &code).map_err(|e| format!("write identity: {e}"))?;
    let seed = keys.to_escrow_seed();
    std::fs::write(dir.join("escrow.seed"), hex::encode(seed.as_ref()))
        .map_err(|e| format!("write seed: {e}"))?;

    // Create the encrypted database so the first real command is fast.
    drop(open_store(&dir)?);

    println!("identity created in {}", dir.display());
    println!("  contact code : {code}");
    println!("  fingerprint  : {}", public.fingerprint());
    println!("  database     : {}", db_path(&dir).display());
    println!();
    println!("The escrow seed in `escrow.seed` is SECRET — it is your identity.");
    println!("This demo writes it to disk only so you can inspect it.");
    Ok(())
}

fn cmd_group_create(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: group-create <dir>")?);
    let store = open_store(&dir)?;
    let p = provider(&store)?;
    let id = identity_bytes(&dir)?;

    let group = Group::create(&p, &id).map_err(|e| format!("group create failed: {e}"))?;
    std::fs::write(group_file(&dir), group.group_id())
        .map_err(|e| format!("write group id: {e}"))?;

    println!("group created");
    println!("  group id : {}", hex::encode(group.group_id()));
    println!("  epoch    : {}", group.epoch());
    println!("  members  : {}", group.info().members.len());
    println!();
    println!(
        "Next: `group-add {0} <peer-dir>` to invite someone.",
        dir.display()
    );
    Ok(())
}

fn cmd_group_add(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: group-add <dir> <peer-dir>")?);
    let peer_dir = PathBuf::from(args.get(2).ok_or("usage: group-add <dir> <peer-dir>")?);

    let store = open_store(&dir)?;
    let p = provider(&store)?;
    let mut group = load_group(&dir, &p)?;

    // The peer's key package is generated from *their* identity, in *their* store.
    // That is what makes the add real: the private material stays on their side.
    let peer_store = open_store(&peer_dir)?;
    let peer_p = provider(&peer_store)?;
    let peer_id = identity_bytes(&peer_dir)?;
    let kp = Group::key_package(&peer_p, &peer_id)
        .map_err(|e| format!("peer key package failed: {e}"))?;

    let before = group.epoch();
    let outcome = group
        .add_members(&p, &[kp])
        .map_err(|e| format!("add failed: {e}"))?;

    // The Welcome is what the peer needs to join. Written to their directory so the
    // demo is a two-command flow rather than a copy-paste.
    let welcome_path = welcome_file(&peer_dir);
    std::fs::write(&welcome_path, &outcome.welcome).map_err(|e| format!("write welcome: {e}"))?;

    println!("added {}", peer_dir.display());
    println!("  epoch   : {before} -> {}", outcome.epoch);
    println!("  members : {}", group.info().members.len());
    println!("  welcome : {}", welcome_path.display());
    println!();
    println!(
        "Next: `group-join {} {}`",
        peer_dir.display(),
        welcome_path.display()
    );
    Ok(())
}

fn cmd_group_join(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(
        args.get(1)
            .ok_or("usage: group-join <dir> <welcome-file>")?,
    );
    let welcome_path = PathBuf::from(
        args.get(2)
            .ok_or("usage: group-join <dir> <welcome-file>")?,
    );

    let welcome = std::fs::read(&welcome_path).map_err(|e| format!("read welcome: {e}"))?;
    let store = open_store(&dir)?;
    let p = provider(&store)?;

    let group = Group::join_from_welcome(&p, &welcome).map_err(|e| format!("join failed: {e}"))?;
    std::fs::write(group_file(&dir), group.group_id())
        .map_err(|e| format!("write group id: {e}"))?;

    println!("joined group");
    println!("  group id : {}", hex::encode(group.group_id()));
    println!("  epoch    : {}", group.epoch());
    println!("  members  : {}", group.info().members.len());
    for m in group.info().members {
        let who = String::from_utf8_lossy(&m.identity);
        println!(
            "    leaf {:<3} {}{}",
            m.index,
            if m.is_self { "(you) " } else { "" },
            truncate(&who, 44)
        );
    }
    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: send <dir> <text>")?);
    let text = args.get(2).ok_or("usage: send <dir> <text>")?;

    let store = open_store(&dir)?;
    let p = provider(&store)?;
    let mut group = load_group(&dir, &p)?;

    // MLS encrypts the content. This is the real ratchet, not a stand-in.
    let ciphertext = group
        .encrypt(&p, text.as_bytes())
        .map_err(|e| format!("encrypt failed: {e}"))?;

    // The frame adds padding so length does not leak, and binds the header as AAD.
    let key = frame_key(&group, CONVERSATION);
    let frame = Frame::seal(&key, CONVERSATION, group.epoch(), &ciphertext)
        .map_err(|e| format!("frame seal failed: {e}"))?;
    let wire = frame.encode();

    // "Deliver" by writing to the drop directory. A real build hands this to
    // `AnonymityTransport::send`, which refuses unless a Tor circuit exists.
    let out = drop_dir(&dir).join(format!("{}.frame", frame.id()));
    std::fs::write(&out, &wire).map_err(|e| format!("write frame: {e}"))?;

    println!("sent");
    println!("  epoch      : {}", group.epoch());
    println!("  plaintext  : {} bytes", text.len());
    println!("  mls ct     : {} bytes", ciphertext.len());
    println!("  on the wire: {} bytes (padded to a bucket)", wire.len());
    println!("  dropped at : {}", out.display());
    println!();
    println!("The wire size is a bucket, not the message length — that is §9.4.");
    Ok(())
}

/// Move dropped frames from one peer's outbox to another peer's inbox.
///
/// This stands in for `AnonymityTransport::send`. In a real build the frame goes
/// over a Tor circuit to the recipient's onion service or mailbox; here it is a
/// file move, which is why the demo is honest about not being anonymous.
///
/// The frame is *moved*, not copied: a sender cannot decrypt its own application
/// message (MLS forbids it), so leaving a copy behind would only produce a
/// confusing "MLS refused" line on the sender's next `recv`.
fn cmd_deliver(args: &[String]) -> Result<(), String> {
    let from = PathBuf::from(args.get(1).ok_or("usage: deliver <from-dir> <to-dir>")?);
    let to = PathBuf::from(args.get(2).ok_or("usage: deliver <from-dir> <to-dir>")?);

    let to_drop = drop_dir(&to);
    std::fs::create_dir_all(&to_drop).map_err(|e| format!("mkdir: {e}"))?;

    let mut moved = 0usize;
    for entry in std::fs::read_dir(drop_dir(&from)).map_err(|e| format!("read drop dir: {e}"))? {
        let path = entry.map_err(|e| format!("read dir entry: {e}"))?.path();
        if path.extension().is_none_or(|x| x != "frame") {
            continue;
        }
        let name = path
            .file_name()
            .ok_or_else(|| "frame path has no file name".to_string())?;
        std::fs::rename(&path, to_drop.join(name))
            .map_err(|e| format!("move {}: {e}", path.display()))?;
        moved += 1;
    }

    if moved == 0 {
        println!("nothing to deliver from {}", drop_dir(&from).display());
    } else {
        println!("delivered {moved} frame(s) to {}", to_drop.display());
    }
    Ok(())
}

fn cmd_recv(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: recv <dir>")?);
    let store = open_store(&dir)?;
    let p = provider(&store)?;
    let mut group = load_group(&dir, &p)?;

    let drop_dir = drop_dir(&dir);
    let mut frames: Vec<PathBuf> = std::fs::read_dir(&drop_dir)
        .map_err(|e| format!("read drop dir: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "frame"))
        .collect();
    frames.sort();

    if frames.is_empty() {
        println!("no frames waiting in {}", drop_dir.display());
        return Ok(());
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for path in frames {
        let wire = std::fs::read(&path).map_err(|e| format!("read frame: {e}"))?;
        let frame = match Frame::decode(&wire) {
            Ok(f) => f,
            Err(e) => {
                println!("  {} : not a valid frame ({e})", file_label(&path));
                rejected += 1;
                continue;
            }
        };

        let key = frame_key(&group, CONVERSATION);
        let ciphertext = match frame.open(&key) {
            Ok(c) => c,
            Err(e) => {
                println!("  {} : frame rejected ({e})", file_label(&path));
                rejected += 1;
                continue;
            }
        };

        match group.decrypt(&p, &ciphertext) {
            Ok(plaintext) => {
                // Persist through the store so retention and crypto-shredding apply.
                let sender = b"peer".to_vec();
                let now = store.now();
                match store.insert_message(&CONVERSATION, &sender, now, &plaintext) {
                    Ok(_) => {
                        println!(
                            "  {} : \"{}\"  (epoch {})",
                            file_label(&path),
                            String::from_utf8_lossy(&plaintext),
                            group.epoch()
                        );
                        accepted += 1;
                    }
                    Err(e) => {
                        println!("  {} : decrypted but not stored ({e})", file_label(&path));
                        rejected += 1;
                    }
                }
            }
            Err(e) => {
                // This is the removal case: a removed member cannot decrypt.
                println!("  {} : MLS refused ({e})", file_label(&path));
                rejected += 1;
            }
        }

        // Consume the frame so a second `recv` does not replay it.
        let _ = std::fs::remove_file(&path);
    }

    println!();
    println!("accepted {accepted}, rejected {rejected}");
    Ok(())
}

fn cmd_show(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: show <dir>")?);
    let store = open_store(&dir)?;

    let ids = store.message_ids().map_err(|e| format!("list: {e}"))?;
    println!("{} message(s) in {}", ids.len(), db_path(&dir).display());
    for id in ids {
        match store.read_message(&id) {
            Ok(plaintext) => println!(
                "  {} : \"{}\"",
                hex::encode(&id[..4]),
                String::from_utf8_lossy(&plaintext)
            ),
            Err(e) => println!("  {} : unreadable ({e})", hex::encode(&id[..4])),
        }
    }

    let db = std::fs::read(db_path(&dir)).map_err(|e| format!("read db: {e}"))?;
    println!();
    println!("database file: {} bytes", db.len());
    println!("(SQLCipher ciphertext — the plaintext above is decrypted in memory only)");
    Ok(())
}

fn cmd_remove(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: remove <dir> <leaf-index>")?);
    let index: u32 = args
        .get(2)
        .ok_or("usage: remove <dir> <leaf-index>")?
        .parse()
        .map_err(|_| "leaf index must be a number".to_string())?;

    let store = open_store(&dir)?;
    let p = provider(&store)?;
    let mut group = load_group(&dir, &p)?;

    let before = group.epoch();
    let outcome = group
        .remove_member(&p, index)
        .map_err(|e| format!("remove failed: {e}"))?;

    println!("member at leaf {index} removed");
    println!("  epoch : {before} -> {}", outcome.epoch);
    println!("  members now: {}", group.info().members.len());
    println!();
    println!("The removed member cannot decrypt anything sent from this epoch on.");
    println!("That is the §7.1 Phase 4 exit criterion, and `recv` will show it.");
    Ok(())
}

fn cmd_purge(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(args.get(1).ok_or("usage: purge <dir>")?);
    let store = open_store(&dir)?;
    let now = store.now();
    let report = store.purge(now).map_err(|e| format!("purge: {e}"))?;

    println!("retention purge at epoch {now}");
    if report.is_empty() {
        println!("  nothing to remove (all data is within the 90-day ceiling)");
    } else {
        for (table, n) in &report.deleted {
            println!("  deleted {n} row(s) from {table}");
        }
        for bucket in &report.shredded_buckets {
            println!("  crypto-shredded bucket {bucket}");
        }
        println!("  vacuumed: {}", report.vacuumed);
    }
    Ok(())
}

#[cfg(feature = "tor")]
fn cmd_tor_probe(args: &[String]) -> Result<(), String> {
    use anon_transport::AnonymityTransport;

    let timeout = anon_transport::arti::bootstrap_timeout();
    println!(
        "probing Tor bootstrap (deadline {}s; override with {})",
        timeout.as_secs(),
        anon_transport::arti::BOOTSTRAP_TIMEOUT_ENV
    );

    // Load bridge settings so this probe exercises the same configuration path the app
    // uses. Without this the probe would silently ignore a user's bridges and report a
    // direct-connection failure — which is exactly the "bridges requested but not used"
    // privacy failure `tor_config` exists to prevent. An optional directory argument
    // supplies the data directory; without one only `ANON_TOR_BRIDGES` applies.
    let tor_config = match args.get(1) {
        Some(dir) => anon_transport::TorConfig::load(std::path::Path::new(dir))
            .map_err(|e| format!("Tor configuration: {e}"))?
            .with_data_dir(dir),
        None => {
            match std::env::var(anon_transport::tor_config::BRIDGES_ENV) {
                Ok(value) if !value.trim().is_empty() => {
                    let config = anon_transport::TorConfig::from_env_value(&value);
                    if !config.bridges_requested() {
                        return Err("ANON_TOR_BRIDGES contains no bridge lines; refusing a direct connection".to_string());
                    }
                    config
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(
                        "ANON_TOR_BRIDGES is not valid Unicode; refusing a direct connection"
                            .to_string(),
                    )
                }
                _ => anon_transport::TorConfig::none(),
            }
        }
    };

    if tor_config.bridges_requested() {
        println!(
            "using {} configured bridge line(s); a failure to use them is fatal, not a \
             fallback to a direct connection",
            tor_config.bridges().len()
        );
    }

    let transport =
        std::sync::Arc::new(anon_transport::arti::ArtiTransport::with_config(tor_config));

    // Run bootstrap off the main thread while displaying its status.
    {
        let t = std::sync::Arc::clone(&transport);
        std::thread::spawn(move || {
            let _ = t.bootstrap();
        });
    }

    let deadline = std::time::Instant::now() + timeout + std::time::Duration::from_secs(5);
    loop {
        match transport.status() {
            anon_transport::TransportStatus::Ready => {
                println!("BOOTSTRAPPED — status {:?}", transport.status());
                let onion = transport
                    .host_onion_service()
                    .map_err(|e| format!("onion service launch failed: {e}"))?;
                println!(
                    "launched onion service at {} (publication and delivery unverified)",
                    onion.as_str()
                );
                return Ok(());
            }
            anon_transport::TransportStatus::Failed => {
                let reason = transport
                    .failure_reason()
                    .unwrap_or_else(|| "unknown failure".to_string());
                return Err(format!("Tor bootstrap failed: {reason}"));
            }
            _ => {}
        }

        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Tor bootstrap did not finish within {}s and the transport did not report a \
                 failure. This is a bug: the watchdog should have flipped the state.",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(not(feature = "tor"))]
fn cmd_tor_probe(_args: &[String]) -> Result<(), String> {
    Err(
        "this build has no Tor backend. Rebuild with `--features tor`:\n  \
         cargo run -p anon-cli --features tor -- tor-probe"
            .to_string(),
    )
}

#[cfg(feature = "tor")]
fn cmd_tor_e2e_chat(args: &[String]) -> Result<(), String> {
    use anon_transport::AnonymityTransport;
    let dir_a = PathBuf::from(
        args.get(1)
            .ok_or("usage: tor-e2e-chat <dir-a> <dir-b> [message]")?,
    );
    let dir_b = PathBuf::from(
        args.get(2)
            .ok_or("usage: tor-e2e-chat <dir-a> <dir-b> [message]")?,
    );
    let message = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("Hello Bob over live Tor v3 onion rendezvous!");

    std::fs::create_dir_all(&dir_a).map_err(|e| format!("mkdir a: {e}"))?;
    std::fs::create_dir_all(&dir_b).map_err(|e| format!("mkdir b: {e}"))?;

    let store_a = std::sync::Arc::new(open_store(&dir_a)?);
    let store_b = std::sync::Arc::new(open_store(&dir_b)?);

    let cfg_a = anon_transport::TorConfig::load(&dir_a)
        .map_err(|e| format!("Tor config A: {e}"))?
        .with_data_dir(&dir_a);
    let cfg_b = anon_transport::TorConfig::load(&dir_b)
        .map_err(|e| format!("Tor config B: {e}"))?
        .with_data_dir(&dir_b);

    let trans_a = std::sync::Arc::new(anon_transport::arti::ArtiTransport::with_config(cfg_a));
    let trans_b = std::sync::Arc::new(anon_transport::arti::ArtiTransport::with_config(cfg_b));

    let id_a = IdentityKeys::generate().map_err(|e| format!("keygen A: {e}"))?;
    let id_b = IdentityKeys::generate().map_err(|e| format!("keygen B: {e}"))?;

    let backend_a = anon_ipc::Backend::new(id_a, trans_a.clone(), store_a);
    let backend_b = anon_ipc::Backend::new(id_b, trans_b.clone(), store_b);

    let code_a = backend_a
        .contact_code()
        .map_err(|e| format!("contact code A: {e}"))?;
    let code_b = backend_b
        .contact_code()
        .map_err(|e| format!("contact code B: {e}"))?;

    let (_, conv_hex) = backend_b
        .add_peer(&code_a, Some("Alice".into()))
        .map_err(|e| format!("Bob add_peer Alice: {e}"))?;
    backend_a
        .add_peer(&code_b, Some("Bob".into()))
        .map_err(|e| format!("Alice add_peer Bob: {e}"))?;

    println!("1. Bootstrapping two isolated Arti clients in parallel...");
    let h_a = {
        let t = trans_a.clone();
        std::thread::spawn(move || t.bootstrap())
    };
    let h_b = {
        let t = trans_b.clone();
        std::thread::spawn(move || t.bootstrap())
    };
    h_a.join()
        .map_err(|_| "bootstrap thread A panicked".to_string())?
        .map_err(|e| format!("Alice bootstrap failed: {e}"))?;
    h_b.join()
        .map_err(|_| "bootstrap thread B panicked".to_string())?
        .map_err(|e| format!("Bob bootstrap failed: {e}"))?;
    println!("   Both clients BOOTSTRAPPED.");

    println!("2. Launching Bob's v3 onion service...");
    let onion_b = trans_b
        .host_onion_service()
        .map_err(|e| format!("Bob onion launch failed: {e}"))?;
    println!("   Bob's onion address: {}", onion_b.as_str());

    println!(
        "3. Waiting for Bob's onion service to establish intro points & publish descriptor..."
    );
    let pub_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut last_state = None;
    while std::time::Instant::now() < pub_deadline {
        let st = trans_b.onion_service_state();
        if st != last_state {
            println!("   Bob onion service state: {st:?}");
            last_state = st;
        }
        if trans_b.is_onion_service_reachable() {
            println!("   Bob's onion service descriptor is PUBLISHED and REACHABLE.");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    if !trans_b.is_onion_service_reachable() {
        return Err(format!(
            "Bob's onion service did not reach Running/DegradedReachable within 180s (last state: {:?})",
            trans_b.onion_service_state()
        ));
    }

    println!(
        "4. Alice sending authenticated X25519-encrypted frame to Bob over Tor onion rendezvous..."
    );
    let send_req = anon_ipc::SendRequest {
        conversation_id: conv_hex.clone(),
        recipient_onion: onion_b.as_str().to_string(),
        epoch: 0,
        body: message.to_string(),
    };

    let mut sent = false;
    let mut last_err = String::new();
    for attempt in 1..=4 {
        match backend_a.send_direct(&send_req) {
            Ok(state) => {
                println!(
                    "   Alice send succeeded on attempt {attempt} (state: {})",
                    state.code()
                );
                sent = true;
                break;
            }
            Err(e) => {
                last_err = e.to_string();
                println!("   attempt {attempt} failed ({last_err}); retrying after descriptor propagation...");
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
    if !sent {
        return Err(format!(
            "Alice failed to send over Tor after 4 attempts: {last_err}"
        ));
    }

    println!(
        "5. Waiting for Bob's encrypted SQLCipher database to receive & verify the message..."
    );
    let recv_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < recv_deadline {
        let msgs = backend_b
            .messages(&conv_hex)
            .map_err(|e| format!("Bob read messages: {e}"))?;
        if let Some(first) = msgs.first() {
            println!(
                "   DELIVERED & VERIFIED OVER TOR: Bob decrypted \"{}\" from sender {}",
                first.body, first.sender_fingerprint
            );
            trans_a.shutdown();
            trans_b.shutdown();
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    Err(
        "Message was sent over the onion stream, but did not appear in Bob's store within 30s"
            .to_string(),
    )
}

#[cfg(not(feature = "tor"))]
fn cmd_tor_e2e_chat(_args: &[String]) -> Result<(), String> {
    Err("rebuild with `--features tor` to run `tor-e2e-chat`".to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the frame key for a group's current epoch.
///
/// Mirrors `anon_messaging::group::epoch_frame_key`. The frame layer is metadata
/// protection, not the confidentiality boundary — MLS is — so this key is derived
/// from public values and adds no new secret to manage.
fn frame_key(group: &Group, conversation: [u8; 16]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut info = Vec::with_capacity(32 + 16 + 8);
    info.extend_from_slice(b"anon/v1/group-frame/");
    info.extend_from_slice(group.group_id());
    info.extend_from_slice(&conversation);
    info.extend_from_slice(&group.epoch().to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, group.group_id());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn file_label(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}
