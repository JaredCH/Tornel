# Tornel (`anon`) — Serverless, 100% Tor v3 Onion P2P Messenger

A Rust + Tauri v2 desktop and mobile communication application built around **zero application-operated servers**, **Tor v3 onion-service rendezvous routing** (via embedded Arti), **authenticated end-to-end encryption** (X25519 + Ed25519 for 1-on-1, RFC 9420 MLS for groups), **encrypted image sharing with mandatory attachment sanitization**, and **local-only SQLCipher storage with an automatic 90-day retention policy**. Group role authorization and forensic key erasure remain incomplete; see the risks below.

> **Security Status & Audit Notice:** Embedded Arti bootstrap, v3 onion-service descriptor publication, and authenticated two-peer 1-on-1 and MLS group message/attachment delivery over Tor rendezvous have been verified end-to-end (both standalone and alongside an active Tor Browser daemon on ports `9150`/`9151`). However, this software has not yet undergone a formal third-party cryptographic or network-anonymity audit. Review the **Mitigated vs. Remaining Risks** section below before relying on it in high-adversary environments.

The full engineering blueprint is in [plan.md](./plan.md).

---

## Threat Model: Risks We Mitigate vs. Remaining Risks (100% Tor & Non-Identifiability)

Overstating protection in an anonymity tool is itself a hazard (`plan.md` §2.4, §11). Below is the explicit breakdown of what this architecture **mitigates** and what **remains a risk** when operating as a Tor-only, zero-identifier messenger.

### Risks Mitigated by Design

| Risk / Attack Vector | How Tornel Mitigates It |
| --- | --- |
| **Central server compromise, subpoena, or metadata logging** | **Zero central servers.** There is no user registry, no account server, no push-notification relay, and no central message broker. Peers address each other directly via Bech32m cryptographic contact codes (`anon1…`) and Tor v3 `.onion` hidden services. |
| **Clearnet IP leakage / accidental fallback** | **Structural Fail-Closed Transport Gate.** `AnonymityTransport::send` refuses to transmit unless `AnonymityClass == TorOnion` and `TransportStatus == Ready` with a published v3 onion service. Builds without `--features tor` use `OfflineTransport`, which fails closed. Enforced by compile-time/CI source scans (`no_clearnet.rs` and `scripts/check-no-clearnet.ps1`) that forbid `std::net`/`tokio::net` sockets outside the Arti wrapper. |
| **Exposing your IP address to a chat peer or group member** | **Bidirectional Tor v3 Onion Rendezvous.** Every running instance hosts its own Tor v3 hidden service via embedded Arti. Outbound and inbound connections meet at a Tor Rendezvous Point over a 6-hop onion circuit—neither peer ever learns the other's IP address or physical network location. |
| **Phone number, email, or username correlation** | **Self-Sovereign Cryptographic Identity.** No phone numbers, emails, or global usernames exist. Your identity is an Ed25519 signing keypair + X25519 agreement keypair generated locally from OS entropy and encoded into a self-checksummed Bech32m contact code (`anon1…`). Display names are strictly local labels. |
| **Coexistence conflicts with Tor Browser or system Tor** | **Isolated Embedded Arti Runtime.** The app embeds Arti directly with `SocksPort 0` / `ControlPort 0` and per-profile state (`<data_dir>/arti/state` and `arti/cache`). It works whether or not Tor is installed on the host and never collides with an active Tor Browser session on ports `9150`/`9151` or `9050`/`9051`. |
| **Ciphertext length analysis (partial mitigation)** | **Fixed-Bucket AEAD Frame Padding.** Frames use fixed size buckets (`512 B`, `2 KiB`, `8 KiB`, `32 KiB`, `128 KiB`, `512 KiB`). This reduces size granularity, not timing or volume correlation. The authenticated application header still contains the true payload length; padding does not hide it from anyone able to inspect that header. |
| **Disk forensics &stolen data directory backups** | **User-Held Passphrase + OS Keychain.** The SQLCipher database key is derived via Argon2id (`64 MiB`, 3 passes) from a passphrase you enter at launch—never stored on disk. The identity seed is stored in the OS Keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service). |
| **Historical data retention during normal application use** | **Automatic TTL enforcement.** Content tables carry integer `expires_at` deadlines. The app purges on unlock and every 24 hours; message reads reject expired rows even between purges. Monthly bucket retirement blocks normal key lookup. This is logical retention, **not guaranteed forensic erasure**: bucket keys can be re-derived from the master key. |
| **Public-onion stream exhaustion (partial mitigation)** | **Automatic bounded ingress.** At most 16 application stream handlers run concurrently, with a 30-second deadline covering stream acceptance, reading, and receipt writing. Payloads are capped at 524,352 bytes; synchronous processing runs off the Tor runtime workers while retaining its slot. Excess streams are dropped without prompting the user. Tor rendezvous work, sustained floods, and abuse by authenticated contacts remain risks. |
| **Stalled sends and false transport success** | **Bounded outbound exchange.** Connect/write/receipt work has a 120-second overall deadline, with a 30-second receipt wait. Missing or invalid receipts fail the send. The receipt confirms frame arrival only, not authentication, persistence, or reading by the recipient. |
| **Compromised or removed group member reading future messages** | **RFC 9420 MLS Ratcheting + Human-in-the-Loop Consent.** Group membership changes advance the MLS epoch and derive fresh tree secrets (`openmls`), locking removed leaves out of future messages. Sensitive rotations trigger a nonce-bound, Ed25519-signed consent modal before taking effect. |
| **Embedded attachment metadata and original filenames** | **Mandatory fail-closed sanitization before sending.** JPEG/PNG images are decoded and rebuilt as new JPEGs without source EXIF/GPS, XMP, ICC, comments, thumbnails, trailing data, or original filenames. Unsupported files are rejected, never passed through unchanged. |

### Remaining Risks & Operational Limitations

| Remaining Risk | Why It Exists & What You Must Consider |
| --- | --- |
| **Previously published identity seed (urgent operational action)** | An earlier version of this README included a complete seed from a real keychain migration transcript. It has been redacted here, but existing repository history and copies may retain it. Treat that identity as compromised: stop using it, replace it through an explicit identity-change workflow, and verify the replacement contact code with contacts over a trusted channel. Redaction alone does not revoke a key. |
| **Forensic recovery after expiry (high priority)** | Monthly keys are `HKDF(master, bucket label)`. Retiring a label does not destroy the derivation secret. Someone with a recovered database snapshot and its passphrase/master key can regenerate old keys. Real cryptographic erasure needs a reviewed, versioned key-management migration with non-regenerable keys and an explicit policy for backups, WAL files, and storage remnants. |
| **No forward secrecy for direct messages (high priority)** | Direct-message keys derive from persistent X25519 identity keys plus public conversation/epoch values. Changing the epoch alone does not erase the ability to derive past keys. Compromise of an identity agreement key can expose captured past direct-message frames. A maintained, audited ratcheting protocol with durable state is needed; MLS group ratcheting does not protect direct chats. |
| **Inbound group roles and sender attribution (high priority)** | MLS authenticates a group member, but the application receiver uses a sender code inside the plaintext and applies role-control messages without checking that sender's authority. Group role UI restrictions are not a security boundary against a modified client. Bind application attribution to the authenticated MLS sender and enforce role/membership permissions on receipt before relying on group roles. |
| **Replay across restarts and timestamp renewal (high priority)** | The application replay cache is memory-only and clears when full. Captured valid direct frames may be accepted again after restart/eviction. The receiver also clamps old signed timestamps to a recent time, potentially renewing their local retention. Persist deduplication atomically with message storage and enforce authenticated timestamp expiry; the lower-level receiver also needs authentication before cache mutation. |
| **Global Passive Adversary / End-to-End Timing & Volume Correlation** | **Tor is a low-latency anonymity network.** Optional experimental shaping emits fixed-size data/cover records on persistent streams, but does not guarantee constant Tor packet timing or defeat a global observer. Connection starts/stops, congestion, outages, and processing still leak information. Shaping is off by default and expensive; see Network Privacy below. |
| **ISP / Local Network Detection of Tor Usage** | While your ISP cannot see *who* you are talking to or *what* onion service you connect to, they can see that you are connecting to public Tor relays unless you configure **Tor Bridges** (`Bridge obfs4 …` + `UseTransport` in `tor.conf` or `ANON_TOR_BRIDGES`). If bridges are configured, Tornel fails closed if they are unreachable rather than falling back to direct Tor relays. |
| **Long-Lived Identity & `.onion` Linkability Across Contacts** | Each persona retains a stable contact code, onion address, and discovery public key. Sharing its signed invite with multiple people links that persona across them. The desktop persona controls create separate processes, identities, databases, Arti state, and WebView profiles; they do not undo past disclosures or prevent correlation through shared content, groups, or timing. |
| **Onion Reachability and Authorized-Peer Abuse** | New desktop profiles enable Arti restricted discovery before hosting. Legacy profiles remain public until explicitly migrated using mutual signed invitations. Knowing a restricted onion address alone is insufficient to fetch its descriptor. Authorized peers can still abuse bounded ingress, and cached introduction points can outlive authorization changes. Discovery protection is not application authorization or immediate revocation. |
| **Endpoint Compromise / Malware on an Unlocked Device** | SQLCipher and the OS Keychain protect data **at rest**. While the application is unlocked and running, decrypted keys and message plaintexts necessarily exist in process memory (mitigated on drop via `zeroize`, but exposed to root/user-level malware, screen capture, or memory dumps while live). |
| **Visual Identification and Camera Fingerprints** | Mandatory metadata removal, cropping, resampling, mild blur and tonal changes do **not** guarantee anonymity or defeat sensor-pattern noise (PRNU), steganography, perceptual matching, or forensic device attribution. Faces, landmarks, watermarks, visible text, and captions can still identify you. This processing has not been validated against camera-attribution datasets. |
| **Non-Repudiation (No Plausible Deniability)** | Direct messages are signed with your Ed25519 identity key (`ANM1` envelope) and group messages are signed with your MLS leaf signature key to prevent forgery and impersonation. A recipient who decrypts a message can cryptographically prove to a third party that your public key signed it (`plan.md` §9.5, §13). |
| **Asynchronous Offline Delivery Requires Online Rendezvous** | Because there are no central servers, sending a direct or group message requires both the sender's and recipient's Tor v3 onion services to be online simultaneously (until peer-hosted mailbox sync is wired to automatic background polling). |

---

### Hardening Review (2026-11-04)

Baseline hardening implemented without new prompts or wire-format changes:

- Bounded inbound concurrency, stream deadlines, and off-runtime message processing.
- Validated transport receipts and an overall outbound deadline.
- Expiry checks on direct storage reads, independent of the purge schedule.

Next priorities are authenticated group authorization, durable replay/timestamp
enforcement, direct-message ratcheting, and a migration for genuine key erasure.
These should run automatically inside the backend; users should not have to
manage keys, clear caches, or approve routine security maintenance. Preserve
explicit consent for membership removal and other identity-sensitive actions.
File metadata/EXIF hardening is separate work and was not changed by this review.

Do not silently rotate shared contact identities or enable expensive cover
traffic: either can disrupt reachability or battery/network use. Restricted discovery,
separate desktop personas, and optional shaping are now implemented as described below.
They complement, not replace, application authorization, quotas, and replay protection.

This is a source-level hardening review with local regression tests, not a formal
cryptographic audit, live-network anonymity assessment, or complete DoS defense.

## Network Privacy

### Restricted Discovery

New desktop vaults configure restricted discovery before starting Tor. Copy a
**Signed Invite** from Identity & Keys and exchange invites in both directions
over a trusted channel. Each `tornel1:` invite binds the contact identity, onion
address, and discovery public key with an Ed25519 signature. It contains no private
authorization key. The signature prevents alteration, not substitution of an entire
stranger's identity; verify the contact fingerprint out of band.

Existing profiles keep their public discovery mode. Re-add every saved contact
using their signed invite, ensure they have imported yours, then enable
**Restricted discovery**. There is no UI downgrade to public discovery. Old clients
cannot use restricted profiles. A persona supports up to 159 imported discovery
contacts; one additional slot is reserved for its own key before contacts exist.

The discovery key is domain-separated from the identity seed and is **one key per
persona, not per contact**. Arti stores its private client authorization key in the
profile-local keystore. Protect that directory as sensitive local data. This release
does not add a contact-revocation workflow; removing a key in Arti would not instantly
invalidate previously cached introduction points anyway. Application authentication
and resource limits remain necessary even for authorized clients.

### Desktop Personas

Use **Personas** on the locked launch screen or in Identity & Keys to create/open a
named persona in a separate window. Each has its own vault passphrase setup,
path-scoped OS-keychain identity, SQLCipher database, Arti directories, and WebView2
data folder under `<profile>/personas/<random-id>`. Existing identities are neither
rotated nor copied. Persona names are local, unencrypted filesystem metadata.

This is desktop process/profile isolation, not protection against a compromised OS
or a promise of unlinkability. Do not reuse invites or identifying content between
personas that should remain separate.

### Experimental Traffic Shaping

Shaping is **off by default**. Both peers must explicitly enable it, with restricted
discovery and at most four signed-invite contacts. Each peer maintains an outgoing
stream to the other; each stream emits 4096-byte data or cover records every second
in **each direction**, including while idle. With both streams connected, total
sent-plus-received traffic is about **1.3 GiB/day per peer per device**, before Tor
overhead. A maximum-size frame takes about 129 seconds just to schedule.

Queues, partial frames, incoming streams, and receipt waits are bounded. Enabling
shaping rejects ordinary inbound messages and never falls back to unshaped outbound
delivery. An offline, busy, or non-shaping peer can therefore make sends fail.
Disabling shaping can interrupt pending sends. The Tor status indicator does not
indicate that every shaped peer stream is connected. Cover records are not a new
cryptographic protocol; message authentication remains in the existing message layer.

Verification includes invitation tampering, legacy migration, settings across database
reopening, persona launch environments, record reassembly/idle cover, and browser UI
flows with mocked IPC. A live three-client Tor test verified unauthorized rejection,
authorized delivery, and a 16 KiB shaped transfer on 2026-11-04. This proves that path
works, not resistance to traffic analysis. Rerun it with:

```powershell
$env:ANON_TOR_PRIVACY_E2E = "1"
cargo test -p anon-transport --features arti --test tor_e2e restricted_discovery_blocks_unauthorized_and_shapes_authorized_traffic -- --nocapture
Remove-Item Env:ANON_TOR_PRIVACY_E2E
```

## Mandatory Attachment Sanitization

All application attachment sends, including direct and MLS group messages, pass
through the Rust sanitizer before signing/encryption and before saving sent
history. There is no opt-out or trusted-client flag. The lower-level messaging
send APIs also sanitize attachment envelopes. Opaque encrypted transport/mailbox
frames are not decoded or modified by relays.

- Only JPEG and PNG inputs are currently supported. PDF/Office documents,
  archives, SVG, GIF, WebP, HEIC, audio, video, and other files are **blocked**.
  Their metadata cannot safely be removed by a generic byte scrub. Filename,
  supplied MIME type, and supplied size are not trusted for format validation.
- Images are decoded with bounded allocations (64 MiB decoder budget), at most
  8 megapixels and 4096 pixels per side, and at least 16 pixels per side.
  Raw attachments remain limited to 360 KiB; invalid or oversized input is rejected.
- Orientation is applied to pixels before discarding source metadata. Transparent
  pixels are composited onto white; PNG animation/layers are flattened to the
  decoded default image. Embedded color profiles are discarded, so colors may shift.
- Each edge loses approximately 1-2% (at least one pixel). Images are downscaled
  to at most 1280 pixels per side without upscaling, mildly blurred, and given
  small randomized contrast/brightness changes using OS randomness. These are
  risk-reduction measures, not a proven fingerprint-removal algorithm.
- A fresh RGB JPEG is encoded at quality 82, with additional downscaling when
  necessary to fit the transfer limit. Every outgoing filename is `image.jpg`;
  MIME type and size are derived from the new bytes. Unknown envelope properties
  are discarded. Captions are retained as user-authored content, not anonymized.
- Processing failures reject the send with `unsafe_attachment`, without storing
  the original attachment in message history or transmitting it. Original files
  on disk and previously sent/received messages are not modified. The pre-send
  preview is local and shows the original; sent history shows the processed image.

Regression coverage includes metadata/trailing-data removal, transparent pixels,
crop and pixel changes, malformed/disguised/unsupported files, dimension and size
limits, and direct/group encryption and persistence boundaries:

```powershell
cargo test -p anon-messaging -p anon-ipc
```

## Offline Delivery: the Send Queue

A send to an offline peer used to fail outright: there is no server to hold the
frame, and the transport refuses rather than degrading. That made an offline
recipient a *lost message*.

The sender now keeps the sealed frame on its own disk and retries it:

- **What is stored.** The already-sealed frame, re-encrypted at rest under a
  bucket key. The queue never holds plaintext, so it is not a second copy of the
  message history, and a row that survives a crypto-shred is undecryptable.
- **When it is used.** Only for *transient* failures — the peer's onion service
  is not published yet, or our own circuit is still bootstrapping. A permanent
  failure (a local-only route, an oversized payload, a replay) is reported to the
  user immediately, because queueing it would only defer an identical failure.
- **When it is not used.** A build with no Tor transport cannot ever deliver, so
  it refuses rather than queueing. Queueing there would promise a delivery that
  cannot happen.
- **How long it lives.** Bounded by the message's own 90-day retention deadline,
  not by an attempt count. A frame still inside the window is still worth sending.
- **What the UI says.** A queued frame is `queued_local` — "queued", never
  "delivered". The transport header shows the queue depth, and the send result
  says the message will go out when the peer is reachable.

Retries are driven by a timer in the shell (`drain_send_queue`), with a per-frame
backoff so a permanently unreachable peer does not cause a tight loop. A failed
attempt forgets the frame's id in the replay guard, so a retry is not mistaken for
a duplicate.

```powershell
cargo test -p anon-messaging --test send_queue
```

## Architecture

```mermaid
flowchart TB
  UI["Webview — presentation + consent only"] --> APP["anon-app — Tauri shell"]
  APP --> IPC["anon-ipc — command boundary"]
    IPC --> MSG["anon-messaging — framing, delivery, replay, mailbox host"]
  IPC --> CON["anon-consent — rotation gate"]
    MSG --> MLS["anon-mls — MLS group ratcheting"]
    MSG --> TR["anon-transport — AnonymityTransport"]
    MSG --> ST["anon-storage — SQLCipher + TTL + mailbox"]
    CON --> ST
    MLS --> ST
    TR --> ART["Arti (feature-gated): client + onion service"]
    TR --> OFF["OfflineTransport (fails closed)"]
    ST --> KR["KeyRing — per-month derived keys, logical retirement"]
    CORE["anon-core — keys, codes, escrow, retention"] -.-> ST
    CORE -.-> CON
    CORE -.-> IPC
  ```

  ### Crates

  | Crate | Responsibility | Plan sections |
  | --- | --- | --- |
  | `anon-core` | Ed25519/X25519 identity, Bech32m contact codes, escrow, retention math | §2, §6 |
  | `anon-storage` | SQLCipher store, `STRICT` schema, 90-day purge, logical bucket retirement, peer mailbox | §6, §4.4 |
  | `anon-transport` | `AnonymityTransport` trait, onion routes, fail-closed gate, Arti client + onion service | §3 |
  | `anon-mls` | RFC 9420 group ratcheting over `openmls`, persisted into the same SQLCipher file | §4.2, §4.3 |
  | `anon-messaging` | Wire format, padding, replay protection, delivery, group messaging, mailbox policy | §9, §4.4 |
  | `anon-consent` | Signed rotation proposals, consent gate, audit log | §5 |
  | `anon-ipc` | The Rust↔webview boundary and its validation | §7.3 |
  | `anon-app` | The Tauri v2 desktop shell: command adapter + webview. No crypto. | §7.3 |
  | `anon-cli` | `anon-demo`, a two-process walkthrough of the stack | §7.1 |

  ### Why `anon-mls` is separate from `anon-messaging`

  `plan.md` §3.4 names Arti as the highest-risk dependency and §4.2 names MLS as the
  highest-complexity one. Keeping each behind its own crate and its own trait
  boundary means either can be replaced without touching the wire format: the frame
  layer does not know what produced its payload, and the ratchet does not know how
  its ciphertext travels. That is also why `anon-messaging` takes MLS state through
  a provider rather than owning a database handle.

---

## The three guarantees, and how they are enforced

### 1. No clearnet fallback — enforced, not documented

`plan.md` §1.2 says there is no mode that degrades to direct TCP/IP. That is
enforced in three places:

- `AnonymityClass::permits_internet_routing()` returns `true` **only** for
  `TorOnion`. `AnonymityTransport::send` refuses otherwise.
- Sending over a local route is a hard error, not a fallback
  (`MessageError::LocalRouteNotDeliverable`).
- A build with no Tor backend gets `OfflineTransport`, which **fails closed**.

And it is *verified* by an automated guard, not just by review:

```powershell
cargo test -p anon-transport --test no_clearnet   # source scan for direct sockets
.\scripts\check-no-clearnet.ps1                   # repository-wide CI scan
```

### 2. 90-day retention — enforced, not asserted

Two bugs in the original design were found and fixed before implementation
(`plan.md` §6.1, §6.2):

**The purge query was silently a no-op.** `strftime('%s','now','-90 days')`
returns a *string of digits*. Compared against a text timestamp column, that is
string comparison, so retention would appear enforced while deleting nothing.
Fixed by:

- all times are `INTEGER` epoch seconds;
- every row carries a precomputed absolute `expires_at`;
- tables are `STRICT`, so SQLite rejects the type confusion outright;
- purge filters the indexed `expires_at`, never a re-derived window.

**`VACUUM` is not a physical erase.** It is logical compaction; flash
wear-levelling and the FTL can retain old blocks. Message ciphertext uses a
**per-month derived data key**, and retired buckets are refused by normal key
lookup. However, the master key can still regenerate those keys. Neither this
policy nor `secure_delete` and `VACUUM` guarantees cryptographic erasure of storage
remnants or old backups. Independent erasable key material and a reviewed
migration are required before claiming that guarantee.

Retention covers **every** content table — messages, conversations, attachments,
mailbox buffers, and the consent audit log — and a test fails if a new content
table is added without an `expires_at` column (`plan.md` §6.4, §6.5).

### 3. Consent is a security control, not a notification

`plan.md` §5.2's six constraints are enforced structurally:

- **Fail closed** — a denied *or expired* rotation leaves an explicit
  `rotation_stale` state; `is_forward_secret()` goes false and
  `assert_forward_secret()` turns that into a hard error. Ignoring the prompt
  never silently continues.
- **Backend owns the truth** — the frontend can only decide a proposal the
  backend already issued. `ConsentSubmission` has no epochs, no names, and no
  keys, so it *cannot* express anything but "yes" or "no".
- **Signed payload** — the proposal is Ed25519-signed over exactly the fields the
  user sees, so the modal displays verifiable text.
- **Replay-safe** — a proposal has a nonce and a one-shot decision; a second
  submission is rejected, and the nonce handle is consumed on use.
- **Bounded wait** — expiry is recorded as a *decision*, never as approval.
- **Audited** — every decision is logged with its proposal id.

**Consent fatigue (decision D4):** prompting on everything trains users to click
through. Only member-removal and manual rotations **block**; routine rotations are
**batchable**.

---

## Identity and addressing

Two things that look similar are kept strictly apart:

- **Contact code** — `anon1...`, Bech32m over
  `version ‖ ed25519_pubkey ‖ x25519_pubkey ‖ BLAKE3 checksum`. This is the
  durable thing a human copies. It is *not* a Tor address.
- **Onion address** — `...onion`. Routing only. A real v3 address is
  `base32(SHA3-256(pubkey ‖ blinded_pubkey ‖ version)[..35]).onion`, produced by
  the onion service and rotatable. **Treating an onion address as an identity
  would be a security bug.**

Display names are local aliases. They are unauthenticated: two peers can claim the
same name. The contact code is the only durable identifier.

### Escrow (optional, user-held)

There is no server, no cloud, and no recovery code the app can regenerate. If you
choose recovery, the app produces an AEAD-encrypted artifact (Argon2id, mobile-
calibrated, parameters stored in the header) that **you** store. The app never
persists it. Storing it in a cloud drive makes that drive your escrow agent.

---

## Building

Requires Rust **1.92+**, as specified by the workspace.

### Windows prerequisite

SQLCipher is built with the `bundled-sqlcipher-vendored-openssl` feature, so
OpenSSL is compiled from source and **Perl is required**:

```powershell
winget install StrawberryPerl.StrawberryPerl
```

Without Perl the build fails with `openssl-sys: Command 'perl' not found`.

If Perl is installed but not on `PATH` (the winget package does not add it), point
the build at it for the session:

```powershell
$env:PATH = "C:\Strawberry\perl\bin;C:\Strawberry\c\bin;$env:PATH"
```

### Linux prerequisite (Debian / Ubuntu)

The same vendored-OpenSSL build applies, so `perl` and `libssl-dev` are required.
The Tauri shell additionally needs WebKitGTK 4.1 and GTK 3:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config libssl-dev perl \
  libgtk-3-dev libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev \
  libfuse2 file
```

`libfuse2` is only needed to *run* the AppImage; it is not a build dependency.

### Build and test

```powershell
cargo build
cargo test --workspace
.\scripts\check-no-clearnet.ps1
```

The Tor transport is **feature-gated**:

```powershell
cargo build -p anon-transport --features arti   # embed Arti
```

The default build has no Arti and therefore **cannot transmit** — that is the
fail-closed default, not an oversight.

### Linux packages

The bundle config produces a `.deb` and an AppImage on Linux:

```bash
cargo build -p anon-app --release
npx --yes @tauri-apps/cli@^2 bundle --bundles deb,appimage
```

Artifacts land in `target/release/bundle/deb/` and
`target/release/bundle/appimage/`. The `linux` CI job builds and uploads both, so
a Linux-only break fails a pull request rather than a release.

#### If the AppImage asks for a password, or opens no window

Two separate problems produce the same report — "it asked for my password and then
never started".

**The password prompt is not the app.** An AppImage is a self-mounting archive: the
runtime mounts its payload through FUSE before any of our code runs. On a system
without FUSE 2 the runtime cannot mount, and some desktop environments respond by
offering to install `libfuse2` through polkit — that is the password dialog. If the
install is declined or fails, the process exits before `anon` starts, so nothing
appears. Either install FUSE 2 once:

```bash
sudo apt-get install libfuse2
```

or run the AppImage without FUSE at all, which needs no privileges:

```bash
./anon_*_amd64.AppImage --appimage-extract-and-run
```

The `.deb` avoids this entirely, because it installs normally and needs no FUSE.

**A window that never paints** is a WebKitGTK rendering failure, not a mount
failure — usually "Failed to get GBM device" on a driver or virtual machine without
working DMA-BUF support. The app sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` by default
to fall back to the shared-memory path. To keep the faster path on hardware that
works, set it to `0` before launching. If the window is still blank, also try
`WEBKIT_DISABLE_COMPOSITING_MODE=1`; that one is not set by default because it
disables accelerated compositing for everyone.

**If it still exits silently**, the reason is written to `startup.log` in the app
data directory (`~/.local/share/com.jaredch.tornel/`). A launch that fails before
the window opens — most often because no Secret Service provider is running — now
opens the window and explains itself instead of exiting, but the log is the
fallback when even that cannot happen.

### Android

The app builds for Android as well as desktop. The Android project is generated
rather than committed, so the first build creates it:

```bash
cd crates/anon-app
npx --yes @tauri-apps/cli@^2 android init
npx --yes @tauri-apps/cli@^2 android build --apk
```

Prerequisites are the Android SDK with NDK 27, JDK 21, and the four Android Rust
targets (`rustup target add aarch64-linux-android armv7-linux-androideabi
i686-linux-android x86_64-linux-android`).

Four Android-specific notes:

* **Build on Linux or macOS, not Windows.** SQLCipher compiles a vendored OpenSSL,
  and its `Configure` script requires a Perl that emits Unix paths. Strawberry Perl
  on Windows does not, and the build fails with "This perl implementation doesn't
  produce Unix like paths". The `android` CI job runs on Linux for this reason.
* **The NDK's `ranlib` must be reachable under a target-prefixed name.** The vendored
  OpenSSL build invokes `aarch64-linux-android-ranlib`, which the NDK does not ship —
  it provides `llvm-ranlib` only. Symlink the LLVM tools under the prefixed names (the
  release workflow does this) or the build fails at `make install_dev`.
* **`crates/anon-app/package.json` is required.** The generated Gradle project's build
  task shells out to `npm run -- tauri android android-studio-script`, so a
  `package.json` with a `tauri` script must exist in the crate directory. Without it
  Gradle fails with `ENOENT: no such file or directory, open '.../package.json'`.
* **The identity seed uses the Android Keystore.** `keyring`'s `v1` facade covers
  macOS, Windows and `*nix` but deliberately not Android, so the Android build
  installs `android-native-keyring-store` (Keystore + SharedPreferences) into
  `keyring-core` itself. The seed is still never written to a plaintext file, and an
  unavailable Keystore still blocks the app rather than degrading.

The release workflow produces an **unsigned** APK named
`app-universal-release-unsigned.apk`, because the generated Gradle project has no release
signing config and a keystore is a long-lived secret that CI must not invent. To distribute
it, add a `signingConfigs.release` block to `gen/android/app/build.gradle.kts` and supply
the keystore through repository secrets; until then, sign the artifact yourself with
`apksigner` before installing.

### Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds the NSIS
installer on Windows, the `.deb`/`.AppImage` on Linux, and the Android APK — all
with `--features tor` — and publishes one GitHub release with a `SHA256SUMS.txt`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

A manual `workflow_dispatch` run builds the same artifacts without creating a
release, so the pipeline can be exercised before a tag exists.

The `publish` job requires Windows and Linux but deliberately **not** Android. Android is
the newest target and the one most likely to break on a toolchain change (NDK, Gradle, the
vendored OpenSSL build), and a break there must not block the desktop packages. The job's
condition uses `!cancelled()` rather than relying on the default gate, because GitHub ANDs
an implicit `success()` into every job that declares `needs` — without it, a failed Android
job skips the release even though the condition never mentions Android. That is what
happened on the `v0.1.2` run: Windows and Linux both succeeded and the release was skipped
because Android's SDK setup failed.

### Dependency advisories

`cargo audit` runs in CI and fails on any advisory not listed in
[`.cargo/audit.toml`](./.cargo/audit.toml). Every entry there is a transitive
dependency with no available fix, and each one records why it is tolerated and
what would make it exploitable. The gate still fails on any *new* advisory — an
ignore list that is never re-examined is worse than no gate at all.

---

## Dependency constraints worth knowing

Three pins are deliberate and will break the build if changed casually:

- **`rusqlite` is pinned to 0.37.** Three crates constrain it and only one version
  satisfies all of them: `arti-client` (via `tor-dirmgr`) requires
  `>=0.36, <0.41`, and `openmls_sqlite_storage` requires `0.37`. Two `rusqlite`
  versions in one graph would link two different `libsqlite3-sys`, and cargo
  rejects that outright because both declare `links = "sqlite3"`. 0.37 is the
  intersection. Bumping it requires re-checking both ranges.
- **`argon2` 0.6 has no `std` feature**; it uses `zeroize`. Passing `std` fails
  resolution.
- **`arti-client` needs `onion-service-client` even to *host*.** Its
  `create_onion_service` path references `KeystoreSelector`, which is only
  re-exported under `all(onion-service-client, experimental-api)`. Enabling
  `onion-service-service` alone fails to compile with "use of undeclared type
  `KeystoreSelector`". That is an upstream feature-gating bug, not a choice here;
  the feature list in `crates/anon-transport/Cargo.toml` documents it.

Also note `rand_core` 0.10 removed `OsRng`. Randomness comes from
`getrandom::fill`, which is also what lets escrow export the raw seed.

Arti is pre-1.0 and onion-service *hosting* (`tor-hsservice`) is its least mature
surface (`plan.md` §3.4). Every Arti call is meant to stay behind
`AnonymityTransport`.

---

## Repository layout

```
Cargo.toml                 workspace, pinned dependencies
plan.md                    the engineering blueprint (source of truth)
crates/anon-core/          identity, contact codes, escrow, retention
crates/anon-storage/       SQLCipher store, schema, purge, crypto-shredding, mailbox
crates/anon-transport/     transport abstraction, Arti client + onion service, no-clearnet guard
crates/anon-mls/           MLS group ratcheting over openmls
crates/anon-messaging/     wire format, delivery, replay protection, group + mailbox policy
crates/anon-consent/       rotation proposals, consent gate, audit
crates/anon-ipc/           Rust↔webview boundary
crates/anon-app/           Tauri v2 shell (command adapter + webview/UI)
crates/anon-cli/           anon-demo: two-process walkthrough
scripts/check-no-clearnet.ps1
```

---

## Status

**Implemented and covered by automated tests:**

| Area | What works |
| --- | --- |
| Identity | Ed25519 + X25519 keygen, deterministic derivation, signing/verification, fingerprints |
| **Keychain** | The identity seed lives in the **OS keychain** (Windows Credential Manager / macOS Keychain / Linux Secret Service) via `keyring` 4.2.0. A legacy `identity.seed` file is migrated on first launch — written, **read back and compared byte-for-byte**, then deleted. An unavailable keychain is **fatal**: the app refuses to start rather than writing a plaintext seed. A seed conflict between keychain and file is fatal too, because picking either would discard a contact code the user may have shared |
| **User-held passphrase** | The database key comes from a passphrase **you** choose and type on every launch. Nothing machine-held remains: `db.passphrase` is gone. An existing install is migrated by a **resumable copy-then-swap rekey** — the copy is opened with the new passphrase and its row counts compared against the original before anything is replaced, so a crash at any stage leaves the original intact. Verified against a **real** 256 KiB install: all 24 tables' row counts identical before and after, old key rejected, `db.passphrase` deleted |
| Contact codes | Bech32m encode/decode, BLAKE3 checksum, version gate, low-order and undecodable key rejection |
| Escrow | AEAD artifact with Argon2id, header bound as associated data, passphrase assessment, export/import round-trip |
| Retention | Absolute expiry math, read-time expiry enforcement, boundary semantics, restart-durable live-bucket set; inbound timestamp renewal remains an open risk |
| Storage | SQLCipher store, `STRICT` schema, per-table purge, logical bucket retirement, schema audit; forensic key erasure is not implemented |
| Transport | `AnonymityTransport` gate, onion route validation, fail-closed `OfflineTransport`, automated no-clearnet guard |
| Messaging | Padded frame format, AEAD header binding, bounded in-memory replay/duplicate rejection, delivery states; durable replay protection remains open |
| **Groups (MLS)** | RFC 9420 ratcheting via `openmls`: create/add/remove, epoch advance, key-package validation, join from Welcome, state persisted in the same SQLCipher file. **Removal is tested to lock the removed member out** (`removed_member_cannot_decrypt`), which is the §7.1 Phase 4 exit criterion |
| **Group Chat & Roles UI** | Full SimpleX-style 2-pane chat workspace with a collapsible **Members & Roles** drawer (`Owner`, `Admin`, `Moderator`, `Member`), `group_roles` SQLCipher table, MLS-encrypted role sync (`set_member_role`), KeyPackage generation (`generate_key_package`), Join-from-Welcome (`join_group`), and MLS-encrypted group chat + file/image fan-out over Tor (`send_group_message`). A member removal **drafts the rotation proposal** and opens the consent modal. |
| **Mailbox** | Peer-hosted offline buffer with per-sender byte/count quotas and a per-mailbox total cap enforced *before* any write, host-side TTL through the shared purge, AAD-bound so a host cannot rewrite recipient/sender/expiry, and receipts that can never be mistaken for delivery |
| Consent | Signed proposals, one-shot nonce binding, expiry-as-decision, fail-closed stale epoch, audit log |
| IPC | Boundary DTOs, input validation, secret-handle indirection, and a **drift guard that parses `dto.rs`** and fails if a field is not in the reviewed inventory or is named like secret material (negative-tested by planting `private_seed`, which failed three independent checks) |
| **Arti** | Feature-gated client bootstrap, outbound length-prefixed onion connection with application-layer receipt, and v3 onion-service hosting via `tor-hsservice` (`--features arti`). Verified end-to-end across two isolated Arti profiles and alongside an active Tor Browser daemon: onion addresses persist across restarts, descriptors publish (`State::Running`), and inbound rendezvous streams deliver authenticated frames to the encrypted SQLCipher store. |
| **Bootstrap deadline** | `bootstrap()` returns at a deadline (default 120s, `ANON_TOR_BOOTSTRAP_TIMEOUT_SECS`). A cooperative async timeout is backed by an outer thread deadline. If the underlying operation does not yield or stop, a worker can outlive that deadline; retries should use a new transport and may encounter a state lock until the worker exits. |
| **Tor diagnostics** | A `tracing` subscriber installed by `anon_transport::init_tracing()` in both the CLI and the app, **silent unless `RUST_LOG` is set**. `RUST_LOG=arti_client=debug,tor_dirmgr=info` prints bootstrap stages. An absent or blank `RUST_LOG` is silent; a malformed one warns on stderr rather than failing the launch |
| **Bridges** | `TorConfig` + `tor.conf` / `ANON_TOR_BRIDGES` for users behind a censoring network. Bridge lines are validated before a client is built, and **bridges requested but unusable is an error, never a silent fallback to a direct connection** — falling back would be a privacy failure. A malformed line, an unknown directive, or a bridge whose pluggable transport has no configured binary all fail closed |
| **Tauri shell** | Real desktop app in `crates/anon-app`: launches, renders identity/messages/consent, and reports failures honestly. Verified by running it (see below). The adapter holds no crypto — it deserializes, calls one backend method, serializes |

**Not yet implemented:**

- **Immediate discovery revocation and per-contact identities.** Restricted discovery
  uses signed provisioning with a persona-scoped key; it does not supply these stronger properties.
- **Automated background polling of peer-hosted offline mailboxes.** The `Mailbox` and `MailboxHost` storage/quota engines are implemented and tested in `anon-storage` and `anon-messaging`, but live chat delivery currently targets online peers directly over Tor rendezvous.

### The Tauri shell

`crates/anon-app` is a real Tauri v2 desktop app that builds and launches:

```
cargo build -p anon-app          # offline transport: refuses to send, says why
cargo build -p anon-app --features tor
cargo run -p anon-app
```

Verified by launching it: the window opens, `identity_view` returns a live Bech32m
contact code and fingerprint, the transport banner explains why sending is
unavailable, the Messages tab renders, and pressing Send surfaces the backend's
validation error (`[invalid_input] a required field was empty: conversation_id`)
with its stable code.

### The app starts locked, and that is the point

The user-held passphrase changed startup structurally. The app no longer opens its
database at launch — it cannot, because there is nothing to open it with until you
type your passphrase. Startup now decides *which screen to show* and hands the webview
a vault to act on:

| State | Screen |
| --- | --- |
| No database | "Choose a passphrase" |
| Database + `db.passphrase` | "Choose a passphrase for this device" — explains that the existing key is being replaced and the messages are kept |
| Database, no `db.passphrase` | "Unlock" |
| A rekey marker on disk | "Finishing a passphrase change", naming the stage it stopped at |

Every command that touches user data goes through `AppState::backend()`, which returns
a `locked` error until one of the three vault commands succeeds. That is the
enforcement: there is no backend to call, so there is no path that reads a message
without the passphrase.

**Verified by launching it against a real existing install.** The data directory held
`anon.db` (262,144 bytes), `anon.db.salt`, and `db.passphrase`. After launching:

```
=== before launch ===        === after launch ===
anon.db       262144         anon.db       262144
anon.db.salt      16         anon.db.salt      16
db.passphrase     64         db.passphrase     64
```

Byte-unchanged. The app **did not migrate unattended** — it showed the migration
screen and waited. That is the behaviour the old build lacked: it opened the database
with a machine-held key and never asked.

**The migration itself is verified against that same real database**, not a synthetic
one. `crates/anon-app/tests/real_migration.rs` copies the install, migrates it, and
asserts every table's row count is identical before and after:

```
row counts before: [("groups", 1), ("openmls_group_data", 10), ("openmls_epoch_keys_pairs", 1),
                    ("openmls_signature_keys", 1), ("schema_meta", 4), ... 24 tables]
row counts after:  [ ... identical ... ]
groups after migration: 1
```

It also asserts the machine-held passphrase is rejected afterwards, the user passphrase
opens the database, `db.passphrase` is deleted, and no `.rekey-*` artifacts remain. Run
it with `ANON_REAL_MIGRATION_DIR` set to a real install.

### The honest cost of the passphrase

**The app no longer starts without a login.** Every launch asks for the passphrase.
That is a real usability regression, and it is the direct price of the security
improvement: the key is no longer sitting next to the database, which means it has to
come from you.

There is also **no recovery**. If you forget the passphrase, the message history is
unreadable — that is what makes it protection rather than a formality. Your *identity*
is separate: it lives in the OS keychain and can be restored from an escrow artifact,
so a forgotten database passphrase costs you history, not your contact code.

#### What the passphrase policy actually requires

The rule is **12 characters**, plus two rejections: the passphrase must not be exactly
a well-known weak string (`password`, `letmein`, `monkey`, …), and it must not be
*degenerate* repetition (`aaaaaaaaaaaa`, `abcabcabcabc`, `abcdefghijkl`,
`passwordpassword`). Everything else is accepted, and the strength bar is advisory — it
warns, it does not gate.

Three earlier behaviours were stricter than that and have been removed, because they
refused good passphrases:

* The deny-list matched on **substring**, so any passphrase *containing* a listed word
  was refused as "well-known weak" — `my-dragon-photograph-42` was rejected outright.
  It now matches the whole string only.
* The setup screen's placeholder said **"16+ characters"** while the policy enforced 12,
  so the screen contradicted the rule it was describing. The placeholder now reads the
  minimum from Rust.
* The pattern check was used as a **hard gate** even though it is deliberately broad. It
  flags any repetition or monotonic run, which is worth warning about, but refusing on it
  rejected long passphrases that merely repeat a substantial unit twice —
  `Tromso2024Tromso2024` was refused outright. The hard gate is now the narrower
  `is_obviously_weak_pattern`, which refuses only repetition that adds no real entropy: a
  single repeated character, a unit of four characters or fewer repeated to fill the
  string, a monotonic run, or a deny-listed word repeated. A long unit repeated twice is
  warned about and accepted.

The pattern check still requires a run to span the whole passphrase, so `correct-horse-abc`
is fine. That is pinned by a test so it cannot be tightened into rejecting real
passphrases.

The migration needs free space for a full second copy of the database, because it
copies rather than rewriting in place. That is deliberate: an in-place `PRAGMA rekey`
has no rollback, and this is a database with no server-side backup.

**The Groups tab is verified against the real database, not just in unit tests.**
A harness opened the actual `anon.db` the shell created — production Argon2id
parameters, the real `db.passphrase` file — and ran the same backend calls the
webview issues. It created a group, read its member list, listed it, then **reopened
the file** and confirmed the row was still on disk:

```
-- create_group --
  group_id    : f9d6e97444341936b6da3c8c073dc676
  name        : Some("verification group")
  epoch       : 0
  member_count: 1
-- group_members --
  leaf 0  anon1qys23ta…  self=true
-- persistence: reopen the file and list again --
  1 group row(s) on disk
  the created group is on disk: true
-- error shapes the UI branches on --
  empty name    -> [invalid_input] a required field was empty: name
  unknown group -> [unknown_group] no group with that id is stored on this device
  bad group id  -> [invalid_group_id] the group id could not be parsed: the group id must be hexadecimal
```

The harness was deleted after use; the evidence is the transcript above. What this
does **not** prove is delivery: adding a member produces a Welcome, but with no
completed Tor bootstrap there is nowhere to send it.

### The keychain migration, verified on a real install

The migration was exercised against the actual data directory this machine had been
using, not a synthetic one. Before launch it held `identity.seed` (value redacted).
After launching the app once:

```
=== after launch ===
anon.db        262144
anon.db.salt       16
db.passphrase      64
identity.seed still present? False
```

Reading the seed back out of Windows Credential Manager confirmed it was
**byte-identical to the file that was deleted**, so the contact code did not
change. A second launch confirmed the identity was stable with the file gone.
The seed previously printed in this transcript must be treated as compromised;
never include key material in verification output or documentation.

The real keychain round-trip is also covered by opt-in tests
(`ANON_KEYCHAIN_TEST=1 cargo test -p anon-app keychain::tests::the_os_keychain`), which
pass on Windows Credential Manager. They are opt-in because they would otherwise
clobber a developer's real identity.

Three bugs this surfaced, all fixed:

1. **`window.__TAURI__` was never injected.** Tauri 2 defaults
   `withGlobalTauri` to `false`, so every command failed silently and the page
   rendered placeholder dashes forever. Now enabled, and `main.js` fails loudly if
   the bridge is missing rather than looking alive but being deaf.
2. **Serde renamed every DTO field.** A blanket
   `#[serde(rename_all = "camelCase")]` made the wire use `contactCode` while the
   JS read `contact_code`, so the contact code rendered blank. Removed: the wire
   now uses the same names as the Rust fields, which is also what the boundary
   inventory checks.
3. **Tauri converts command arguments to camelCase.** `invoke("export_escrow",
   {passphrase})` needed `rename_all = "snake_case"` on the commands to match the
   DTO fields the frontend sends.

### A second bug this work found and fixed

The IPC boundary guard was documented in `anon-ipc`'s lib docs but its test file
never existed, so nothing was enforcing it. Writing it immediately found real
drift: `PeerView.contact_code` and `HandleView.handle` were crossing the boundary
unreviewed, and the inventory still listed a `state` field that no longer exists.
Both are fixed, and the guard is negative-tested.

### A bug this work found and fixed

Bucket keys are *derived*, not stored (§6.2). That made the "which buckets are
live" set the only record that a key may still be derived — and it was in-memory
only. The consequence was that **every message written before an app restart
became unreadable**, because the ring started empty and every older row looked
like it belonged to a shredded bucket. Nothing errored at write time; the loss
only appeared on the next launch. The set is now persisted in `live_buckets` with
a `retired_at` column, so logical retirement survives a restart instead of being
undone by one. This does not prevent derivation from a recovered master key.
Both directions are pinned by regression tests
(`a_message_survives_a_restart_and_is_still_readable`,
`a_shredded_bucket_is_not_resurrected_by_a_restart`).

**Known schedule risk:** mobile distribution (§8). Anonymity tools have been
rejected or removed from major app stores, and decision D6 puts mobile in v1, so
this needs validating early rather than at submission time.

---

## How to verify Tor bootstrap and live P2P onion messaging

These probes require access to the live Tor network.

### 1. Ask Tor where it gets to

The app uses its own embedded Arti client; it neither requires nor reuses an
installed Tor daemon or an active Tor Browser session. It does not open a
local SOCKS or control port. Each app data directory has its own `arti/state`
and `arti/cache`; two instances should use different data directories. A second
instance sharing one profile can encounter Arti state locks. Bridges, configured
separately for this app, may still require an installed pluggable-transport
executable. No configuration automatically copies Tor Browser's bridges.

```powershell
$env:RUST_LOG = "arti=debug"
$env:ANON_TOR_BOOTSTRAP_TIMEOUT_SECS = "60"
cargo run -p anon-cli --features tor -- tor-probe
```

Pass a data directory (`tor-probe <dir>`) to have it read `<dir>/tor.conf`; without
one it uses `ANON_TOR_BRIDGES` only. The probe loads bridges through the same
`TorConfig` path the app uses, so a bridge misconfiguration fails here rather than
being silently ignored.

`RUST_LOG` is the only switch. With it unset the command is silent apart from its
own result line — a diagnostic switch must not add noise to a normal run.

On a network that works you will see the percentage climb and then:

```text
BOOTSTRAPPED — status Ready
launched onion service at <56-character-base32>.onion (publication and delivery unverified)
```

To verify **full two-peer onion service publication, rendezvous, X25519 encryption,
Ed25519 signature verification, and SQLCipher persistence**:

```powershell
cargo run -p anon-cli --features tor -- tor-e2e-chat .\peer-a .\peer-b "Hello over Tor!"
```

On the Windows development machine, an unpatched Arti dependency previously
spun while parsing the directory consensus. The workspace temporarily patches
`saturating-time` 0.5.0 using the MIT-licensed source in `vendor/saturating-time`:
it stops limit searches when a sub-resolution operation makes no progress and
computes saturation bounds lazily. With this patch, isolated Arti profiles
reach 100% bootstrap, publish v3 onion descriptors (`State::Running`), and
exchange authenticated encrypted messages over Tor rendezvous both when no
external Tor is running and when Tor Browser's `tor.exe` is actively running on
ports `9150`/`9151`. Remove the override only after a fixed upstream release has
been verified, including on Windows.

### 2. Run the gated integration test

```powershell
$env:ANON_TOR_E2E = "1"
$env:ANON_TOR_BOOTSTRAP_TIMEOUT_SECS = "120"
cargo test -p anon-transport --features arti --test tor_e2e -- --nocapture
```

Without the environment variable the live test does not run. When explicitly
enabled, it bootstraps two isolated Arti clients, hosts an onion service, waits
for descriptor publication (`is_onion_service_reachable()`), and verifies live
payload delivery over Tor rendezvous.

### 3. If consensus download fails

In order of likelihood:

1. **Tor may be blocked or the network may be unreliable.** Try a bridge. Put this in `tor.conf` in the app's
   data directory (or set `ANON_TOR_BRIDGES`):
   ```text
   Bridge obfs4 <host>:<port> <fingerprint> cert=<cert> iat-mode=0
   UseTransport obfs4=C:\path\to\obfs4proxy.exe
   ```
   A bridge line whose transport has no configured binary is an **error**, not a
   silent fallback to a direct connection — see the Bridges row in the status table.
2. **A captive portal or firewall.** Check network access and system clock;
   Arti needs working connections to Tor relays or configured bridges.
3. **A very slow link.** Raise `ANON_TOR_BOOTSTRAP_TIMEOUT_SECS`. The default is
   120s; a healthy bootstrap takes seconds to tens of seconds.

### What is and is not claimed

| Claim | Status |
| --- | --- |
| The bootstrap path runs, reports stages, and **returns** at a deadline | **Verified** — unit tests plus the CLI probe above |
| A bootstrap that cannot finish fails closed with a reason | **Verified** — `a_bootstrap_returns_at_the_deadline_instead_of_hanging` |
| Bridge configuration is validated and fails closed when unusable | **Verified** — 15 `tor_config` tests plus `bootstrap_fails_closed_when_bridges_are_unusable` |
| An onion service is published, reachable, and delivers authenticated frames | **Verified** — `tor_e2e` and `anon-demo tor-e2e-chat` over the live Tor network |

---

## Build environment notes

This repository was built and verified on Windows with:

- Rust 1.92 (workspace MSRV 1.92)
- Visual Studio 2022 with the MSVC toolchain
- Strawberry Perl 5.42 (required by `openssl-sys`; see above)

If Perl is unavailable and cannot be installed system-wide, the portable ZIP from
the Strawberry Perl releases page works without an installer — extract it and put
`perl\bin` on `PATH` for the build.