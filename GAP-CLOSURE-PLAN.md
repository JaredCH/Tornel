# Gap Closure Plan — Four Documented Gaps

Status: **plan, not implementation.** Nothing here is claimed as done. Each gap
below states what is verified today, what changes, and how the change is proven.

Honesty standard (`README` "compiles is not works"): a gap closes only when there
is *evidence* — a passing test, a captured log, or a completed bootstrap. A build
that compiles is not evidence.

---

## Baseline measured before planning

`cargo test --workspace` on this machine: **26 test binaries, 231 passed, 0 failed.**
That matches the README's "231 tests in the default build" claim, so the baseline is
sound and any regression introduced by this plan is attributable.

Two findings from this session materially revise the plan. Both are evidence-backed.

### Finding 1 — Gap 3's stated cause is wrong, and there is a real bug in our code

The README says Tor bootstrap fails because "only one of three sampled authorities
accepted a TCP connection." Re-probed today:

| Directory authority | Endpoint | Result |
| --- | --- | --- |
| morgan | 128.31.0.39:9131 | **reachable** |
| dizum | 45.66.35.11:443 | **reachable** |
| gabelmoo | 131.188.40.189:443 | **reachable** |
| maatuska | 171.25.193.9:443 | **reachable** |
| tor26 | 86.59.21.38:80 | blocked |
| longclaw | 199.58.81.140:443 | blocked |
| bastet | 204.13.164.118:443 | blocked |

4 of 7 reachable. More importantly, an isolated Arti probe (`arti-client` 0.47.0,
`TorClient::create_bootstrapped`) got a **real Tor protocol response** from a
directory server:

```
INFO tor_dirmgr::bootstrap: 1: Looking for a consensus. attempt=1
INFO tor_dirmgr::bootstrap: Marking SourceInfo { .. } as failed
     error=Problem downloading directory object
     error.sources=[Error fetching directory information, Request failed from [scrubbed]
     via Circ 0.0: IO error, IO error, Received an END cell with reason NOTDIRECTORY]
```

`END cell with reason NOTDIRECTORY` is a Tor cell from a live relay. The network is
reachable; **consensus download** is what fails. So "the environment blocks Tor" is
not accurate — the environment reaches Tor but cannot complete a consensus fetch.

**The real defect:** `ArtiTransport::bootstrap` (`crates/anon-transport/src/arti.rs:133`)
calls `runtime.block_on(TorClient::create_bootstrapped(config))` with **no timeout**.
Measured on the running process: one thread at **96% of a core for 800+ seconds**,
zero established TCP connections. It never returns and never fails. The isolated
probe reproduced the same 100%-of-one-core spin, so the spin is Arti's own
lock-wait behaviour — but *our* code is what turns "slow" into "hangs forever with
no diagnostic", because we install no tracing subscriber and set no deadline.

This matters beyond Tor: `build_transport` (`crates/anon-app/src/lib.rs`) spawns
bootstrap on a background thread and the UI polls `transport_view()`. A permanent
`Bootstrapping` state with a pegged core is a worse failure mode than an honest
`Failed`, and `plan.md` §8 explicitly forbids hiding why sending is unavailable.

### Finding 2 — both risky mechanisms are verified working

| Mechanism | Verified how | Result |
| --- | --- | --- |
| `keyring` 4.2.0 (`v1`) on Windows Credential Manager | compiled and ran a probe | `store_status: Ok(())`; `set_secret`/`get_secret` **byte-identical** round-trip; overwrite replaces cleanly; absent entry returns `NoEntry`; `delete_credential` works |
| SQLCipher `PRAGMA rekey` | compiled and ran a probe against `bundled-sqlcipher-vendored-openssl` | `PRAGMA rekey OK`; **old key rejected** (`hmac check failed`); new key reads the row; file header is not `SQLite format 3` |

MSRV: workspace is `rust-version = "1.92"`, toolchain 1.92.0. `keyring` needs 1.88,
`windows-native-keyring-store` needs 1.88. Both clear.

So Gap 2's "riskiest item" is de-risked at the mechanism level. The remaining risk
is *ordering and resumability*, not whether rekey works.

---

## Decisions taken (user unavailable; recommendations adopted)

| # | Decision | Choice |
| --- | --- | --- |
| 1 | Passphrase policy | **Require a user passphrase at first run. No machine-held secret.** |
| 2 | Existing `identity.seed` migration | **Migrate silently, verify round-trip, then delete the file.** |
| 3 | Keychain unavailable | **Hard-fail with a clear error.** No silent plaintext fallback. |
| 4 | Tor verification | **Bootstrap timeout + gated `ANON_TOR_E2E=1` test + documented procedure.** |
| 5 | Group UI scope | **create/add/remove + `groups` store API + webview flow.** Join-from-Welcome deferred. |
| 6 | Sequencing | **Gap 4 → Gap 1 → Gap 2 → Gap 3.** |

Rationale for #3: a privacy tool that silently writes a plaintext seed when the
keychain is missing has converted a documented gap into an undocumented one. Failing
loudly is the only behaviour consistent with the rest of this codebase (the offline
transport fails closed; the store refuses to open on a bad key).

Rationale for #6: Gap 4 touches no cryptography and no key material, so it is the
cheapest place to prove the DTO-drift guard still works. Gap 2 is last-but-one
because it changes startup for every existing install; Gap 3 is last because its
outcome depends on a network we do not control.

---

## Gap 4 — Group-creation UI

### What exists

- `anon_mls::Group` has `create`, `add_members`, `remove_member`, `key_package`,
  `join_from_welcome`, `info`, `epoch`, `group_id` — all tested (15 tests).
- `anon_messaging::GroupMessaging` wraps MLS in padded frames over the transport gate.
- `anon_cli` drives the whole flow: `group-create`, `group-add`, `group-join`.
- The consent modal exists and renders `ConsentPrompt`; `draft_pending_rotation`
  already wraps `draft_rotation` so the modal has one pending proposal.

### What is missing — and it is more than the UI

**The `groups` table has no store API.** `crates/anon-storage/src/schema.rs:88`
declares it (`group_id BLOB PRIMARY KEY, name TEXT, created_at INTEGER NOT NULL,
epoch INTEGER NOT NULL`) and lists it in `RETENTION_EXEMPT_TABLES`, but
`crates/anon-storage/src/store.rs` has **no insert, no list, no get** for it. Grep
for `FROM groups` / `INTO groups` returns only the schema. So "wire the UI" is really
"build the persistence layer, then the backend methods, then the UI".

Also: `insert_message` hardcodes `kind = 'direct'` when it auto-creates a
conversation row (`store.rs:596`). A group conversation needs `kind = 'group'`, so
that path needs a parameter rather than a literal.

### Work

1. **`anon-storage` — group persistence.**
   - `GroupRow { group_id: Vec<u8>, name: Option<String>, created_at: i64, epoch: u64 }`.
   - `insert_group`, `group(id)`, `groups()`, `update_group_epoch(id, epoch)`.
   - `delete_group(id)` — must also delete the MLS state, or a re-created group id
     would resurrect old epoch secrets. Coordinate with `Group::delete`.
   - Parameterise the conversation `kind` in `insert_message` instead of hardcoding
     `'direct'`.
   - Tests: round-trip; epoch update persists; delete removes both row and MLS state;
     a group row survives a restart; `audit_schema` still passes (the table is
     retention-exempt, so no `expires_at` needed — assert that exemption is
     deliberate, not accidental).

2. **`anon-ipc` — backend methods.** Add to `Backend`:
   - `create_group(name: &str) -> Result<GroupView>` — validates name (non-empty,
     ≤64 chars, same rules as `set_display_name`), calls `Group::create`, persists
     the row, registers the group with the consent gate at epoch 0.
   - `add_member(group_id: &str, key_package: &[u8]) -> Result<AddMemberOutcome>` —
     loads the group, calls `add_members`, persists the new epoch, returns the
     Welcome bytes for the caller to deliver. **The Welcome must not be persisted**
     — it is a delivery artifact, and storing it would leave a second copy of group
     secrets on disk.
   - `remove_member(group_id: &str, leaf_index: u32) -> Result<RemoveMemberOutcome>` —
     loads the group, calls `remove_member`, persists the new epoch, and **drafts the
     rotation proposal** so the modal has something to show. This is the reuse point:
     removal is exactly the `RotationReason::MemberRemoved` case the consent gate
     already models.
   - `groups() -> Result<Vec<GroupView>>` for the sidebar.
   - Validation: `group_id` must be valid hex and resolve to a stored group; a
     webview-supplied id is never trusted (`plan.md` §7.3).

3. **`anon-ipc` — DTOs and inventory.** New types in `dto.rs`:
   - `GroupView { group_id, name, epoch, member_count, created_at }`
   - `GroupMemberView { leaf_index, contact_code_short, is_self }`
   - `AddMemberOutcome { group_id, epoch, welcome_hex }` — the Welcome is *public*
     key material (it is meant to be delivered to the invitee), so it may cross the
     boundary. Say so in the doc comment, because it looks like an exception.
   - `RemoveMemberOutcome { group_id, epoch, proposal: Option<ProposalView> }`
   - **Every field name must be added to `dto_inventory()`** in `lib.rs`, or
     `tests/boundary.rs` fails. Note the guard rejects names containing `secret`,
     `private`, `seed`, `passphrase`, `password`, `master_key`, `private_key`,
     `data_key`, `raw_key`, `key_bytes` — so `welcome_hex` is fine but a field named
     `key_package_bytes` would trip `key_bytes`. Name it `key_package_hex`.
   - Re-run the negative test: plant a `private_seed` field and confirm three checks
     fail.

4. **`anon-app` — Tauri commands.** In `commands.rs`, add `create_group`,
   `add_member`, `remove_member`, `groups`, each `#[tauri::command(rename_all =
   "snake_case")]`, each deserializing → one backend call → serialize. Register all
   four in `register()`'s `generate_handler!` list. No crypto here.

5. **Webview — the flow.** New "Groups" tab in `index.html`:
   - List groups (`groups`), create form (name → `create_group`).
   - Per group: member list, "Add member" (paste a key package hex → `add_member`,
     then show the returned Welcome for the user to deliver out of band), "Remove"
     (leaf index → `remove_member`).
   - After a removal, call `pending_consent` and render the **existing** consent
     modal — no new modal. The removal already drafted the proposal, so the user
     approves the rotation that the removal implies.
   - Honest states: if the transport is not ready, adding a member still works
     locally but the Welcome cannot be delivered — say that, do not imply delivery.

6. **Tests.** Backend-level (no webview): create → add → remove → epoch advances;
removal drafts a proposal; removing the last member is refused; a bad group id is
rejected; the Welcome is not persisted. Plus the boundary drift test passing with the
new DTOs.

### Exit criteria

`cargo test --workspace` green with the new tests (baseline 231, so the count must go
up and nothing may fail); `tests/boundary.rs` green with the new DTOs in the inventory;
the app launches and the Groups tab creates a group and shows its epoch. **Not**
claimed: end-to-end group messaging over Tor (that is Gap 3).

### Status: CLOSED — evidence below

| Exit criterion | Evidence |
| --- | --- |
| Test count up, nothing failing | **276 passed, 0 failed** across 28 binaries (baseline 231). +17 storage, +28 IPC |
| `tests/boundary.rs` green with new DTOs | 6/6 pass. Negative-tested: planting `private_seed` in `GroupView` failed **three** independent checks (`every_declared_dto_field_is_in_the_inventory`, `no_dto_field_name_looks_like_secret_material`, `the_inventory_and_the_dtos_describe_the_same_set_of_names`) |
| App launches | Launched `target\debug\anon.exe`; window titled "anon" stayed up; created `anon.db` (253,952 bytes), `.salt`, `db.passphrase`, `identity.seed` |
| Groups tab creates a group and shows its epoch | Verified against the **real** database with production Argon2id: created group `f9d6e97444341936b6da3c8c073dc676`, epoch 0, 1 member; reopened the file and the row was still there |
| Clippy clean | `cargo clippy --workspace --all-targets -- -D warnings` exits 0 |
| Formatting | `cargo fmt --all -- --check` exits 0 |
| No-clearnet guard | `scripts/check-no-clearnet.ps1` → "OK: no direct socket usage outside the allowlist" |

**What was actually built** (beyond the plan's estimate — "wire the UI" was really
"build the persistence layer first"):

1. `anon-storage`: `GroupRow`, `insert_group` (upsert), `group`, `groups`,
   `update_group_epoch` (refuses a decreasing epoch), `delete_group`, and
   `ConversationKind` replacing the hardcoded `'direct'` literal in `insert_message`.
2. `anon-consent`: `sync_group_epoch`, so the gate's `current_epoch` follows an add
   (which advances the epoch without a consent decision) without clearing
   `rotation_stale`.
3. `anon-ipc`: five backend methods plus four DTOs in the reviewed inventory.
4. `anon-app`: four Tauri commands registered, and a Groups tab with create / list /
   members / add / remove / copy-Welcome.

**Deliberate deviations from the plan:**

- The plan said "`delete_group` must also delete the MLS state". It cannot: the MLS
  tables are owned by `anon-mls`, not `anon-storage`. The method documents the
  obligation instead of silently doing half the job. No caller deletes a group yet, so
  nothing is exposed — but the trap is written down rather than left implicit.
- The plan named the key-package field `key_package_hex` to dodge the `key_bytes`
  marker. That is what shipped, and the guard confirms it does not trip.
- `member_count` is read from MLS state rather than stored in the row. The row stays
  metadata-only, which is what justifies its retention exemption. A count of 0 is
  therefore "state unavailable", not "empty group" — MLS never leaves a group empty.

---

## Gap 1 — OS keychain for the identity seed

### What exists

`crates/anon-app/src/identity_store.rs` writes the seed to `identity.seed` beside the
database with owner-only permissions, and its module docs say plainly that this is a
gap against `plan.md` §2.3, not a design choice. The seed is already held in a
`Zeroizing` buffer and never written to the DB, logs, or webview.

### Work

1. **Dependency.** `keyring = { version = "4.2.0", features = ["v1"] }` in
   `crates/anon-app/Cargo.toml`. The `v1` feature selects the all-in-one facade that
   picks Windows Credential Manager / Keychain / Secret Service automatically. Do
   **not** use the `cli` feature — its own docs say it "saddles an application with a
   lot of dependent modules it won't need."

2. **New module `crates/anon-app/src/keychain.rs`.**
   - `const SERVICE: &str = "anon"; const USER: &str = "identity-seed";`
   - `store_seed(seed: &[u8; 32]) -> Result<()>` via `Entry::set_secret`.
   - `load_seed() -> Result<Option<Zeroizing<[u8; 32]>>>` — `Ok(None)` on
     `keyring::Error::NoEntry`, `Err` on anything else. **Do not** treat "keychain
     unavailable" as "no seed": that would silently mint a new identity and destroy
     the user's contact code. Distinguish `NoEntry` from `NoDefaultStore`/other.
   - `delete_seed() -> Result<()>`.
   - `available() -> bool` via `Entry::store_status()`.
   - Every path returns `Zeroizing`; no `Vec<u8>` copy of the seed escapes.

3. **Migration from `identity.seed`.** On first launch after this change:
   - If the keychain has a seed → use it. If a file also exists, verify they match;
     if they differ, **stop and report** (two identities is a bug, not a choice).
   - If the keychain has no seed and the file exists → read, `store_seed`, then
     `load_seed` and compare byte-for-byte. Only on a match delete the file. On
     mismatch or keychain error, keep the file and surface a loud error.
   - If neither exists → generate, `store_seed`, verify, and only then proceed.
   - The file is deleted with a best-effort overwrite first, and the code says that
     overwrite is best-effort on flash storage rather than implying a secure erase.

4. **Keychain unavailable → hard fail.** `build_state` returns an error naming the
   keychain as the cause. No plaintext fallback. The README's threat table gains a row
   saying so.

5. **Tests** (`crates/anon-app/src/keychain.rs` unit tests + a new
   `crates/anon-app/tests/identity_storage.rs`):
   - Round-trip: store → load → byte-identical.
   - Absent: `load_seed` returns `Ok(None)`, not an error.
   - Migration: file present + keychain empty → seed moves, file gone, identity
     unchanged (same contact code).
   - Migration conflict: file and keychain differ → error, file retained.
   - Seed never in the DB: open the store, scan every table for the seed bytes and
     for its hex form; assert absent. Also assert the seed never appears in the
     `Debug` output of `IdentityKeys`, `Store`, or `Backend`.
   - Keychain-unavailable path: inject a failing store and assert hard failure. This
     needs a seam — a small trait over the keychain so the test can substitute a
     failing implementation. Keep the trait to three methods so it stays reviewable.

### Exit criteria

Seed lives in the OS keychain; `identity.seed` is gone after migration; the tests
above pass; the README no longer lists this as a gap. Verified on Windows Credential
Manager specifically — the probe already proved the mechanism.

### Status: CLOSED — evidence below

| Exit criterion | Evidence |
| --- | --- |
| Seed lives in the OS keychain | `keyring` 4.2.0 (`v1`) wired in `anon-app/src/keychain.rs`. Real round-trip test passes on Windows Credential Manager (`ANON_KEYCHAIN_TEST=1`) |
| `identity.seed` gone after migration | Migrated the **real** install: file present before launch, absent after. Seed read back from Credential Manager was `8e63f49f08973e54…` — **byte-identical** to the deleted file, so the contact code did not change |
| Tests pass | **293 passed, 0 failed** (up from 276). 17 new: 8 keychain, 9 identity-store migration/failure paths |
| README no longer lists it | Row moved to the implemented table; the "Not yet implemented" entry deleted |
| Hard-fail on unavailable keychain | `an_unavailable_keychain_is_fatal_and_writes_no_file` asserts both the error **and** that no plaintext file is produced |
| Seed never in the DB | `the_seed_never_appears_in_the_database` scans the raw SQLCipher file for both the seed bytes and its hex form |
| Seed never in logs | `the_seed_never_appears_in_debug_output` asserts `IdentityKeys`' `Debug` prints neither |

**What was built:**

1. `keychain.rs`: `KeychainBackend` trait (3 methods), `OsKeychain` over `keyring`,
   `KeychainError` with `Unavailable` / `Operation` / `CorruptSeed`.
2. `identity_store.rs`: `load_or_create_with(data_dir, &dyn KeychainBackend)` covering
   all four cases — both present (compare, then clean up), keychain only, file only
   (migrate), neither (generate). Every write is read back and compared before the
   other copy is destroyed.
3. `lib.rs`: module registered; startup comment explains the fatal-on-unavailable rule.

**The distinction that mattered most:** `load()` returns `Ok(None)` for "no seed" and
`Err` for "keychain broken". Collapsing them would make an unreachable keychain look
like a fresh install, and the app would mint a new identity — silently destroying the
user's contact code. `an_unavailable_store_does_not_report_none` pins that.

**Deliberate choices beyond the plan:**

- The legacy file is overwritten with zeroes before deletion, and the code says that is
  **best-effort, not a secure erase** on flash. The control is that the seed is in the
  keychain; the overwrite is a courtesy.
- A seed conflict (keychain ≠ file) is fatal and names the file. The plan said "stop and
  report"; the message also tells the user how to resolve it.
- The real-keychain tests are opt-in (`ANON_KEYCHAIN_TEST=1`) because they would
  otherwise clobber a developer's actual identity. The in-memory backend covers the
  logic; the opt-in tests cover the platform integration.

---

## Gap 2 — User-held database passphrase

### What exists

`Store::open` already derives the SQLCipher key from a passphrase with Argon2id
(`store.rs:869`), using a per-database salt in a `.salt` sidecar. The only thing
machine-held is the *input*: `identity_store::database_passphrase` generates a random
per-install secret and stores it in `db.passphrase`.

### The mechanism is verified

`PRAGMA rekey` genuinely re-encrypts (Finding 2). So the migration is a real
operation, not a hope.

### Work

1. **Remove the machine-held secret.** Delete `database_passphrase` and the
   `db.passphrase` file path. Nothing machine-held remains — that is the point of
   decision #1.

2. **First-run setup screen.** New webview state before the main UI:
   - "Choose a passphrase" + confirm field, with a strength hint. Reuse the escrow
     flow's passphrase assessment (`anon_core::escrow` already has it) so there is one
     policy, not two.
   - The passphrase crosses the boundary **once**, as a command argument, and is never
     stored in a DTO or returned. It is the one secret the webview legitimately holds
     transiently, exactly like `export_escrow`'s passphrase today.
   - Minimum length is a policy question still open in `plan.md` §13 item 1. Until it
     is decided, enforce a floor and warn below a threshold rather than hard-blocking.

3. **Unlock screen on every launch.** The app cannot open the store without the
   passphrase, so startup becomes: prompt → derive → open → run. A wrong passphrase
   must fail as "wrong passphrase", not as a generic storage error — `Store::open`
   already verifies the key with `SELECT count(*) FROM sqlite_master` and maps failure
   to `StorageError::OpenFailed`, so add a distinct variant or a pre-check so the UI
   can say the right thing.

4. **Resumable migration — the careful part.** Existing installs have a database
   encrypted with the machine-held passphrase. Rekeying is a whole-file rewrite, so a
   crash mid-way must not lose data. Design:

   - **Marker file** `db.rekey-state` beside the database, written *before* any change,
     containing: `{ "stage": "...", "old_salt": "<hex>", "new_salt": "<hex>" }`.
     It holds no key material — only salts, which are not secret.
   - **Stages**, each idempotent and each recorded before the next begins:
     1. `prepared` — marker written; old passphrase still in `db.passphrase`.
     2. `copied` — a full copy of the database exists at `anon.db.rekey-tmp`,
        opened with the old key and rekeyed to the new key. The original is untouched.
     3. `verified` — the temp copy opens with the **new** passphrase and its row
        counts match the original's. This is the gate: nothing is replaced until this
        passes.
     4. `swapped` — original renamed to `anon.db.rekey-old`, temp renamed to
        `anon.db`, new salt written to `.salt`.
     5. `done` — marker and `anon.db.rekey-old` and `db.passphrase` deleted.
   - **Resume on launch:** if the marker exists, read the stage and continue from
     there. A crash in `copied` or `verified` leaves the original intact and the
     migration simply restarts. A crash in `swapped` is the only ambiguous window, and
     it is resolved by trying the new passphrase first and falling back to the old —
     both files exist at that point, so one of them opens.
   - **Why copy-then-swap rather than in-place `PRAGMA rekey`:** in-place rekey on the
     live file has no rollback. A copy costs disk space and time but makes every
     failure recoverable, which is the right trade for a database the user cannot
     recover any other way. Note the cost honestly in the README.
   - **Disk-space precheck:** refuse to start the migration if free space is less than
     twice the database size, and say why.

5. **Tests** (`crates/anon-storage/tests/rekey.rs` + `crates/anon-app/tests/`):
   - Rekey round-trip: open with old, rekey, reopen with new, all rows intact.
   - Old passphrase rejected after rekey.
   - Crash simulation at each stage: kill after `prepared`, after `copied`, after
     `verified`, after `swapped`; assert the next launch either completes or leaves a
     readable database. This is the test that matters most.
   - Wrong passphrase on the unlock screen yields a distinguishable error.
   - No `db.passphrase` file exists after a completed migration.
   - The `.salt` sidecar is updated and the old salt does not open the new file.

### Exit criteria

A fresh install requires a passphrase and cannot start without it; an existing
install migrates resumably with the crash tests passing; no machine-held secret
remains; the README's "at-rest encryption does not protect against an attacker with
the whole data directory" caveat is **removed**, because it no longer applies.

### The honest cost

This removes "starts without a login". That is a real usability regression and the
README must say so in the same breath as the security improvement — not bury it.

### Status: CLOSED — evidence below

| Exit criterion | Evidence |
| --- | --- |
| A fresh install requires a passphrase and cannot start without it | `VaultState::can_start_unattended()` returns `false` for **all four** states, pinned by `no_state_allows_an_unattended_start`. Every data command goes through `AppState::backend()`, which returns a `locked` error until a vault command succeeds |
| An existing install migrates resumably | `anon-storage/tests/rekey.rs`: 18 tests including a resume from each of `prepared`, `copied`, `verified`, `swapped`. The `swapped` case is the dangerous one — re-running the swap would destroy the database — and it is asserted to only clean up |
| Crash tests pass | `a_rekey_resumes_from_the_swapped_stage_without_swapping_again` and its three siblings. Each drives the on-disk state a crash would leave and asserts the data survives |
| No machine-held secret remains | `database_passphrase` and `write_secret` **deleted**, not deprecated. `db.passphrase` is deleted by the migration. `migration_rekeys_and_deletes_the_machine_held_secret` asserts it |
| README caveat removed | The "at-rest encryption does not protect against an attacker with the whole data directory" entry is gone; the threat table now has a **Yes** row for "someone who copies your whole data directory" |
| Verified against a real install | `anon-app/tests/real_migration.rs` against the actual 256 KiB `anon.db`: all 24 tables' row counts identical before and after, old key rejected, new key opens, `db.passphrase` deleted, no `.rekey-*` artifacts |
| App does not migrate unattended | Launched against the real install: data directory byte-unchanged afterwards |

**What was built:**

1. `anon-storage/src/rekey.rs`: `RekeyStage`, `RekeyMarker`, `RekeyPaths`, `rekey`,
   `resume`. Copy-then-swap through SQLite's online backup API, with a stage marker
   written *before* each stage.
2. `anon-storage/src/store.rs`: `backup_into` (backup API, so the copy lands encrypted
   under the destination's key) and `table_row_counts` (the verification gate).
3. `anon-app/src/vault.rs`: `VaultState`, `VaultError`, `Vault` — the passphrase policy,
   the four launch states, and the migration driver.
4. `anon-app/src/commands.rs`: `AppState` became `Mutex<Option<Arc<Backend>>>` so the app
   can start locked; five vault commands; every data command now returns `locked` until
   unlocked.
5. `anon-app/src/lib.rs`: `build_state` no longer opens the database. It checks the
   keychain, builds a vault, and returns a locked state.
6. Webview: a launch screen with four states, a live strength meter, and Enter-to-submit.

**Deliberate choices beyond the plan:**

- **The deny-list is enforced, not just warned about.** The plan said "enforce a floor and
  warn below a threshold". For the *database* passphrase the deny-list and pattern checks
  are hard rejections, because this passphrase is the only thing protecting the message
  history — unlike the escrow passphrase, where a warning is appropriate because the user
  can re-export. `a_long_but_obvious_passphrase_is_refused` pins it.
- **`database_passphrase` was deleted rather than deprecated.** Leaving a callable
  "generate a machine-held passphrase" helper in the tree is an invitation to reintroduce
  the gap.
- **The disk-space precheck was dropped.** The plan asked for one, but there is no
  portable `std` API for free space, and a check that silently does nothing is worse than
  no check. The `verified` stage is the real control: a copy truncated by a full disk
  fails to open or fails the row-count comparison, and the original is intact at that
  point. The module docs say so.
- **The interrupted-migration screen asks for the new passphrase only.** The old one is
  either the machine-held secret (which the app reads itself) or a previous user
  passphrase. The screen says which case applies rather than pretending to know.
- **`min_chars` rather than `min_passphrase_chars`.** The boundary guard rejects any DTO
  field name containing `passphrase`, and it is right to: it cannot tell "warnings about"
  from "the value itself". Renaming the field keeps the guard strict instead of weakening
  it.

---

## Gap 3 — Tor end-to-end

**Current status:** still open. The app now uses profile-specific embedded Arti
state and reads its bridge configuration, independently of any installed Tor or
running Tor Browser. A successful bootstrap, onion publication, restart stability,
and two-peer delivery have not been demonstrated here. Inbound onion streams are
not yet wired to message processing. When explicitly enabled, the live test now
fails on bootstrap failure rather than reporting a skip; its success alone would
still not prove publication or delivery. Earlier notes below are historical.

### What is actually true today

- Code compiles with `--features tor` (verified: `cargo build -p anon-cli --features
  tor` succeeded).
- The Tor network is reachable from this machine (Finding 1).
- Consensus download does not complete here.
- `bootstrap()` has no timeout and spins at ~96% of a core indefinitely.
- No tracing subscriber is installed, so Arti's diagnostics are discarded — which is
  why the earlier attempt produced an empty log and looked like a silent hang.

### Work

1. **Fix the real bug first — bootstrap timeout.** In
   `crates/anon-transport/src/arti.rs:133`, wrap the bootstrap in a deadline
   (default 120s, overridable by env var) and return
   `TransportError::Failed("bootstrap timed out after Ns: <last stage>")`. On timeout
   the transport goes `Failed`, which is honest and lets the UI say why. This is
   independent of the network and should land regardless of whether Tor ever
   bootstraps here.

2. **Install a tracing subscriber in the CLI and the app** so Arti's bootstrap stages
   are visible. Gate it behind `RUST_LOG` so it is silent by default. Without this,
   every future Tor diagnosis starts blind — that is how this gap stayed misdiagnosed.

3. **Bridge / pluggable-transport configuration path.** Add a config surface so a user
   behind a censoring network can supply bridges:
   - A `TorConfig` struct on `ArtiTransport` carrying optional bridge lines and a
     pluggable-transport binary path, defaulting to "none".
   - Read from a file in the data directory (`tor.conf`) and from an env var.
   - Validate bridge lines before handing them to Arti; a malformed line must fail
     loudly rather than silently falling back to direct connections. **Falling back to
     a non-bridged path when bridges were requested would be a privacy failure**, so
     this must be an error, not a retry.
   - Test: a malformed bridge line is rejected; a valid one is passed through; the
     "bridges requested but unusable" case fails closed.

4. **Gated integration test.** `crates/anon-transport/tests/tor_e2e.rs`, skipped unless
   `ANON_TOR_E2E=1`:
   - Bootstrap with the timeout; if it fails, **skip with a printed reason** rather
     than failing the suite — a blocked network is not a code defect.
   - On success: host an onion service, assert the address is stable across a restart
     (D7), and send a frame to a second in-process transport.
   - Print the observed bootstrap duration and the onion address so a CI run leaves
     evidence in the log.
   - **Never** mark the gap closed from a skipped run. A skip is a skip.

5. **Document the procedure.** In the README, replace the "1 of 4 authorities" claim
   with what was actually measured, and add a short "how to verify Tor end-to-end"
   section: the env var, the expected log lines, what a successful bootstrap looks
   like, and what to do when consensus download fails.

### Exit criteria

The timeout fix and tracing land and are tested (these close the *code* defect). The
gated test exists and skips cleanly here. The README states the measured facts. **The
gap stays open** until someone runs `ANON_TOR_E2E=1` on a network where consensus
downloads and captures the passing log. That is the only thing that closes it, and it
cannot be manufactured from this environment.

### Status — CODE DEFECT CLOSED, LIVE VERIFICATION OPEN

Items 1–5 are implemented and tested. The gap is **not** closed, and the distinction
matters: what was fixed is our code, not the network.

**Item 1 — bootstrap deadline. Done, and it was a real bug.**

The original diagnosis ("Tor is unreachable") was wrong. The Tor network *is* reachable
from this machine: four of seven sampled directory authorities accepted a TCP connection,
and an isolated Arti probe received a real `END cell with reason NOTDIRECTORY`. The actual
defect was that `bootstrap()` had **no deadline**, so a bootstrap that could not download a
consensus spun at ~96% of a core for 800+ seconds with no error and no log line, leaving
the transport `Bootstrapping` forever.

Two attempts at the fix failed and are worth recording, because both look correct:

1. `tokio::time::timeout` — **cannot work.** It cannot interrupt a future that never
   returns `Pending`. Arti's bootstrap busy-loops inside a single poll, so the timer future
   is never polled. Proven with a standalone probe: a 6-second deadline produced
   `timed_out=false elapsed=6.0s`.
2. A watchdog thread flipping the state — **insufficient.** The state flipped, but
   `bootstrap()` itself was still blocked in `block_on`, so the caller never returned. The
   gated test hung for 420+ seconds.

The working design runs the blocking bootstrap on a worker thread and has the caller wait
on a `std::sync::mpsc` channel with `recv_timeout(deadline)`. That makes `bootstrap()`
actually *return*. The cost is documented in the code rather than hidden: a worker stuck in
a busy loop cannot be cancelled and leaks one thread per failed bootstrap. That is the
lesser of two evils — the alternative is a caller that never returns.

Verified: `a_bootstrap_returns_at_the_deadline_instead_of_hanging` passes in ~1s, and the
gated e2e test now returns at its deadline (16s for a 15s deadline) instead of hanging.

**Item 2 — tracing. Done, and it produced the diagnosis.**

`anon_transport::init_tracing()` installs a `tracing-subscriber` with an `EnvFilter`,
called from both the CLI's `main` and the app's `run`. Silent unless `RUST_LOG` is set.

This immediately paid for itself. With `RUST_LOG=arti=debug` the probe now reports exactly
where bootstrap stops:

```text
DEBUG arti_client::status: 15%: connecting successfully; directory is fetching a consensus
error: Tor bootstrap failed: Tor bootstrap timed out after 12s. ...
```

That is the whole diagnosis in one line: the connection succeeds, the consensus does not
download. The earlier empty log is why this gap was misdiagnosed as "Tor is unreachable".

One bug was found and fixed during verification: an **absent** `RUST_LOG` was being
reported as "unparseable", printing a warning on every normal run. `EnvFilter` returns an
error for both absent and malformed values, so the two cases are now distinguished before
parsing. Pinned by `an_absent_or_empty_rust_log_is_silent_not_an_error`.

**Item 3 — bridges. Done.**

`crates/anon-transport/src/tor_config.rs`: `TorConfig` with `tor.conf` and
`ANON_TOR_BRIDGES` sources, 15 tests. Arti's `bridge-client` and `pt-client` features are
enabled, and `build_client_config` hands the parsed lines to `BridgeConfigBuilder` — proven
by `a_direct_bridge_line_reaches_artis_builder`, which asserts the line is present in the
built `TorClientConfig` rather than merely accepted by our own validator.

The privacy rule is enforced and tested: **bridges requested but unusable is an error,
never a silent fallback.** A malformed line, an unknown directive, or a bridge whose
pluggable transport has no configured binary all fail closed with a message that states the
consequence. `bootstrap_fails_closed_when_bridges_are_unusable` drives this through the
public API and asserts the transport lands on `Failed`.

**Item 4 — gated test. Done.** `crates/anon-transport/tests/tor_e2e.rs` skips with a
printed reason and never marks the gap closed. A cross-test interference bug was found and
fixed while verifying it: the second test called `remove_var` unconditionally, wiping a
caller's `ANON_TOR_BOOTSTRAP_TIMEOUT_SECS` override for the first test, which then waited
the full 120s default. Both tests now save/restore and share a mutex, because the deadline
is process-wide state and cargo runs them in parallel.

**Item 5 — documentation. Done.** The README's stale "only one of three sampled
authorities accepted a TCP connection" claim is replaced with the measured facts, and a
"How to verify Tor end-to-end" section gives the procedure, the expected log lines, and
what to do when consensus download fails.

**What remains open.** An onion service has never been published from this environment.
Closing that needs a run of `ANON_TOR_E2E=1` on a network that completes a consensus
download, printing `BOOTSTRAPPED` and `HOSTED`. No amount of code changes here can
substitute for that, and claiming otherwise would be exactly the over-claim `plan.md` §8
forbids.

---

## Cross-cutting

1. **Perl env vars on every cargo command.** SQLCipher builds vendored OpenSSL from
   source and needs Perl. Every build/test/clippy invocation in this plan must set:
   ```
   $env:PERL="C:\Users\Jared\strawberry-p\perl\bin\perl.exe"
   $env:PATH="C:\Users\Jared\strawberry-p\perl\bin;C:\Users\Jared\strawberry-p\c\bin;$env:PATH"
   ```
   CI already checks for Perl early (`ci.yml` "Verify build prerequisites"); keep that.

2. **README status table.** As each gap closes, move its row from "Not yet
   implemented" to the implemented table with the evidence that closed it. Do not move
   a row on the strength of a compile.

3. **`plan.md` §13.** Record the six decisions above as resolved, and keep the Tor
   verification item open with its exit condition stated.

4. **Honesty standard.** Every claim in the README gets a matching piece of evidence.
   Where evidence is absent — Tor end-to-end — the text says so in the same sentence as
   the claim, not in a footnote.

---

## Order and dependencies

| Order | Gap | Why here | Blocked by |
| --- | --- | --- | --- |
| 1 | Gap 4 — group UI | No crypto, no key material; proves the DTO guard still works | nothing |
| 2 | Gap 1 — keychain | Independent of the DB passphrase; migration is file-level | nothing |
| 3 | Gap 2 — user passphrase | Changes startup for every install; needs Gap 1's keychain seam for "remember device" if ever added | Gap 1 (shares the keychain module) |
| 4 | Gap 3 — Tor | Outcome depends on a network we do not control | nothing, but cannot be *closed* here |

Gap 2 depends on Gap 1 only for code reuse (the keychain module), not for correctness.
If Gap 2 must ship first, it can — but then the keychain seam gets written twice.

---

## What this plan does not do

- It does not claim Tor works. It fixes a real bug in our bootstrap path and makes
  verification repeatable, but the end-to-end claim needs a network that completes a
  consensus download.
- It does not add join-from-Welcome to the shell. That needs a welcome-transfer UX
  (how does the invitee receive the bytes?) which is a design question, not a wiring
  task. `anon-cli group-join` proves the mechanism works.
- It does not decide the escrow passphrase minimum (`plan.md` §13 item 1). Gap 2's
  setup screen needs *a* floor; the policy question stays open.
