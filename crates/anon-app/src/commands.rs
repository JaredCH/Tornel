//! The Tauri command surface (`plan.md` §7.3).
//!
//! # What this module is
//!
//! A thin adapter. Every command here does three things and no more:
//!
//! 1. Deserialize the webview's arguments into an `anon_ipc` DTO.
//! 2. Call one `anon_ipc::Backend` method.
//! 3. Serialize the result back.
//!
//! It contains no cryptography, no key handling, and no SQL. Those live in the
//! crates below, where they are tested without a webview. If a rule needs to be
//! enforced, it is enforced *there*, not here — a Tauri command is the easiest
//! place in the whole system to accidentally bypass a check, so this module is
//! kept too small to hide one.
//!
//! # The boundary rule
//!
//! No private key, seed, passphrase, or database handle crosses into the webview.
//! The return types are `anon_ipc` DTOs, which cannot hold secret material by
//! construction, plus a few plain strings. The one exception is
//! [`export_escrow`], which returns the escrow artifact — and that is deliberate:
//! the artifact is *for the user*, the backend does not persist it, and the whole
//! point of the flow is that the user takes custody of it (`plan.md` §2.5).

use crate::vault::{Vault, VaultError, VaultState};
use anon_ipc::{
    AddMemberOutcome, Backend, CommandError, ConsentPrompt, ConsentSubmission, ConversationView,
    GroupMemberView, GroupView, IdentityView, IpcError, MessageView, PeerView, RemoveMemberOutcome,
    SendRequest, StrengthView, TransportView, VaultView,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::State;

/// The application state shared by every command.
///
/// # Why the backend is behind a `Mutex<Option<..>>`
///
/// The app now starts **locked** (gap-closure plan Gap 2): the database cannot be opened
/// until the user supplies their passphrase. So there is no backend at startup, and one
/// appears only after a successful unlock. `Option` is that absence, and the `Mutex` is
/// what lets the unlock command install it while other commands are reading.
///
/// Every command that needs the backend goes through [`AppState::backend`], which returns
/// a `locked` error rather than panicking when the app has not been unlocked. That is the
/// difference between a UI that says "enter your passphrase" and one that crashes.
pub struct AppState {
    /// The backend, once the vault has been unlocked.
    backend: Mutex<Option<Arc<Backend>>>,
    /// Serialises vault setup/unlock/migrate calls so a double click or rapid
    /// Enter press cannot build two backends and two Arti instances concurrently.
    unlock_lock: Mutex<()>,
    /// The vault: the database path plus the passphrase policy.
    ///
    /// Always present, because the launch screen needs it before any backend exists.
    vault: Arc<Vault>,
    /// The data directory, for the identity store.
    data_dir: std::path::PathBuf,
}

impl AppState {
    /// Build a locked state: a vault and a data directory, no backend yet.
    pub fn locked(vault: Vault, data_dir: std::path::PathBuf) -> Self {
        Self {
            backend: Mutex::new(None),
            unlock_lock: Mutex::new(()),
            vault: Arc::new(vault),
            data_dir,
        }
    }

    /// Install a backend after a successful unlock or setup.
    ///
    /// Replaces any existing backend. That is deliberate: a second unlock (after a
    /// failed first attempt, or a re-lock) must not leave two backends holding two
    /// connections to the same database.
    ///
    /// Also starts the background retention purge. It cannot start at launch any more,
    /// because there is no store to purge until the user unlocks — and starting a timer
    /// against a store that does not exist yet would be a panic waiting to happen.
    pub fn install(&self, backend: Backend) {
        let store = backend.store().clone();
        let transport = backend.messaging().transport().clone();
        let mut slot = self.backend.lock().unwrap();
        if let Some(old) = slot.take() {
            old.messaging().transport().shutdown();
        }
        *slot = Some(Arc::new(backend));
        crate::spawn_purge_timer(store);
        std::thread::spawn(move || {
            if let Err(error) = transport.start() {
                eprintln!("anon: transport startup failed: {error}");
            }
        });
    }

    /// The backend, or a `locked` error.
    ///
    /// Returning an error rather than panicking is what lets the webview render "enter
    /// your passphrase" instead of dying. Every command that touches user data calls
    /// this.
    pub fn backend(&self) -> UiResult<Arc<Backend>> {
        self.backend
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| UiError::from(CommandError::new("locked", "the app is locked")))
    }

    /// The vault, for the launch screen.
    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// The data directory.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// Whether a backend is installed.
    pub fn is_unlocked(&self) -> bool {
        self.backend.lock().unwrap().is_some()
    }
}

/// An error the webview can render.
///
/// Tauri requires command errors to be `Serialize`. We deliberately send only the
/// flat [`CommandError`] shape — a code and a display message — so internal error
/// structure (paths, key state) never reaches JavaScript.
#[derive(Debug, Serialize)]
pub struct UiError {
    /// Stable code the frontend branches on.
    pub code: String,
    /// Human-readable message, safe to display.
    pub message: String,
}

impl From<CommandError> for UiError {
    fn from(e: CommandError) -> Self {
        Self {
            code: e.code.to_string(),
            message: e.message,
        }
    }
}

impl From<IpcError> for UiError {
    /// Map a raw `IpcError` through the same code/message mapping
    /// `CommandError` uses, so the webview sees one consistent error shape
    /// regardless of which backend method produced it.
    fn from(e: IpcError) -> Self {
        Self::from(CommandError::from(e))
    }
}

type UiResult<T> = std::result::Result<T, UiError>;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The identity panel's data.
#[tauri::command(rename_all = "snake_case")]
pub fn identity_view(state: State<'_, AppState>) -> UiResult<IdentityView> {
    state.backend()?.identity_view().map_err(UiError::from)
}

/// Set or clear the local display name.
///
/// Names are allowed but are not identity (`plan.md` §2): this changes a label,
/// never a key.
#[tauri::command(rename_all = "snake_case")]
pub fn set_display_name(state: State<'_, AppState>, name: Option<String>) -> UiResult<()> {
    state
        .backend()?
        .set_display_name(name)
        .map_err(UiError::from)
}

/// Record that the user completed the escrow export flow.
#[tauri::command(rename_all = "snake_case")]
pub fn note_escrow_exported(state: State<'_, AppState>) -> UiResult<()> {
    state.backend()?.note_escrow_exported();
    Ok(())
}

/// Export an escrow artifact, hex-encoded.
///
/// # Why this returns the artifact
///
/// This is the one command whose return value is sensitive, and it is intentional.
/// The artifact is encrypted under a user-chosen passphrase and exists so the user
/// can restore their identity on another device. The backend does not store it and
/// neither does the frontend beyond the download the user triggers (`plan.md`
/// §2.5). Returning it is the entire purpose of the flow.
///
/// It is hex rather than raw bytes because Tauri's IPC is JSON; the frontend
/// decodes it into a `Blob` and hands it to the user's download flow.
#[tauri::command(rename_all = "snake_case")]
pub fn export_escrow(state: State<'_, AppState>, passphrase: String) -> UiResult<String> {
    let artifact = state
        .backend()?
        .export_escrow(&passphrase)
        .map_err(UiError::from)?;
    Ok(hex_encode(&artifact))
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Transport status for the header and the "cannot send" banner.
#[tauri::command(rename_all = "snake_case")]
pub fn transport_view(state: State<'_, AppState>) -> UiResult<TransportView> {
    Ok(state.backend()?.transport_view())
}

#[tauri::command]
pub fn privacy_view(state: State<'_, AppState>) -> UiResult<anon_ipc::PrivacyView> {
    state.backend()?.privacy_view().map_err(UiError::from)
}

/// Retry queued frames that are due. Returns how many went out.
///
/// Called on a timer by the webview, so a message queued while the peer was
/// offline goes out on its own once the transport is usable again.
#[tauri::command(rename_all = "snake_case")]
pub fn drain_send_queue(state: State<'_, AppState>) -> UiResult<usize> {
    state.backend()?.drain_send_queue().map_err(UiError::from)
}

/// Frames still waiting to go out for one conversation.
#[tauri::command(rename_all = "snake_case")]
pub fn queued_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> UiResult<Vec<anon_ipc::QueuedMessageView>> {
    state
        .backend()?
        .queued_messages(&conversation_id)
        .map_err(UiError::from)
}

#[tauri::command]
pub fn list_personas(
    state: State<'_, AppState>,
) -> Result<Vec<crate::personas::PersonaView>, String> {
    crate::personas::list(state.data_dir())
}

#[tauri::command]
pub fn create_persona(
    state: State<'_, AppState>,
    name: String,
) -> Result<crate::personas::PersonaView, String> {
    crate::personas::create(state.data_dir(), &name)
}

#[tauri::command]
pub fn open_persona(state: State<'_, AppState>, id: String) -> Result<(), String> {
    crate::personas::open(state.data_dir(), &id)
}

#[tauri::command]
pub fn enable_restricted_discovery(state: State<'_, AppState>) -> UiResult<anon_ipc::PrivacyView> {
    state
        .backend()?
        .enable_restricted_discovery()
        .map_err(UiError::from)
}

#[tauri::command]
pub fn export_invite(state: State<'_, AppState>) -> UiResult<String> {
    state.backend()?.export_invite().map_err(UiError::from)
}

#[tauri::command]
pub fn set_traffic_shaping(
    state: State<'_, AppState>,
    enabled: bool,
) -> UiResult<anon_ipc::PrivacyView> {
    state
        .backend()?
        .set_traffic_shaping(enabled)
        .map_err(UiError::from)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Conversations for the sidebar.
#[tauri::command(rename_all = "snake_case")]
pub fn conversations(state: State<'_, AppState>) -> UiResult<Vec<ConversationView>> {
    state.backend()?.conversations().map_err(UiError::from)
}

/// Messages in one conversation.
#[tauri::command(rename_all = "snake_case")]
pub fn messages(state: State<'_, AppState>, conversation_id: String) -> UiResult<Vec<MessageView>> {
    state
        .backend()?
        .messages(&conversation_id)
        .map_err(UiError::from)
}

/// Known peers.
#[tauri::command(rename_all = "snake_case")]
pub fn peers(state: State<'_, AppState>) -> UiResult<Vec<PeerView>> {
    state.backend()?.peers().map_err(UiError::from)
}

/// Add a peer contact by contact code and return the shared direct conversation id.
#[derive(Debug, Serialize)]
pub struct AddPeerResult {
    pub peer: PeerView,
    pub conversation_id: String,
}

#[tauri::command(rename_all = "snake_case")]
pub fn add_peer(
    state: State<'_, AppState>,
    contact_code: String,
    label: Option<String>,
) -> UiResult<AddPeerResult> {
    let (peer, conversation_id) = state
        .backend()?
        .add_peer(&contact_code, label)
        .map_err(UiError::from)?;
    Ok(AddPeerResult {
        peer,
        conversation_id,
    })
}

/// A send request as the webview sends it.
#[derive(Debug, Deserialize)]
pub struct SendArgs {
    /// Target conversation hex id or peer contact code.
    pub conversation_id: String,
    /// Recipient onion address.
    pub recipient_onion: String,
    /// Epoch to encrypt under.
    pub epoch: u64,
    /// The message text.
    pub body: String,
}

/// The result of a send, shaped for the UI.
#[derive(Debug, Serialize)]
pub struct SendResult {
    /// Stable code: `queued_local`, `at_mailbox`, `delivered`, `read`.
    pub code: &'static str,
    /// Honest label to display.
    pub label: &'static str,
    /// Whether a peer has confirmed receipt.
    pub peer_confirmed: bool,
}

/// Send an authenticated, X25519-encrypted direct message over Tor.
#[tauri::command(rename_all = "snake_case")]
pub async fn send_message(
    state: State<'_, AppState>,
    mut request: SendArgs,
) -> UiResult<SendResult> {
    use zeroize::Zeroize;
    let backend = state.backend()?;
    let mut ipc_req = SendRequest {
        conversation_id: request.conversation_id,
        recipient_onion: request.recipient_onion,
        epoch: request.epoch,
        body: std::mem::take(&mut request.body),
    };
    let result = tauri::async_runtime::spawn_blocking(move || {
        let res = backend.send_direct(&ipc_req);
        ipc_req.body.zeroize();
        res
    })
    .await
    .map_err(|e| UiError::from(CommandError::new("internal", e.to_string())))?;
    let delivery = result.map_err(UiError::from)?;
    Ok(SendResult {
        code: delivery.code(),
        label: delivery.label(),
        peer_confirmed: delivery.is_peer_confirmed(),
    })
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

/// The outstanding consent prompt, if any.
#[tauri::command(rename_all = "snake_case")]
pub fn pending_consent(state: State<'_, AppState>) -> UiResult<Option<ConsentPrompt>> {
    Ok(state.backend()?.pending_consent())
}

/// Submit a consent decision.
///
/// The webview supplies only the proposal id, the nonce handle it was given, and a
/// boolean. It cannot influence *what* it is approving — only whether to approve
/// (`plan.md` §5.2).
#[tauri::command(rename_all = "snake_case")]
pub fn submit_consent(
    state: State<'_, AppState>,
    submission: ConsentSubmission,
) -> UiResult<String> {
    let backend = state.backend()?;
    let now = backend.store().now();
    let outcome = backend
        .submit_consent(&submission, now)
        .map_err(UiError::from)?;
    Ok(format!("{outcome:?}"))
}

/// Draft a rotation proposal and make it the pending prompt.
///
/// Exposed so the shell can demonstrate the consent flow without a group UI. A
/// production build would call this from the rotation scheduler in Rust, not from
/// the webview — the webview should never *initiate* a rotation, only approve one.
#[tauri::command(rename_all = "snake_case")]
pub fn draft_rotation(
    state: State<'_, AppState>,
    group_id: String,
    group_name: String,
    epoch_after: u64,
    member_count: u32,
    ttl_seconds: i64,
) -> UiResult<ConsentPrompt> {
    let backend = state.backend()?;
    let now = backend.store().now();
    backend
        .draft_pending_rotation(
            &group_id,
            &group_name,
            anon_consent::RotationReason::MemberRemoved,
            epoch_after,
            member_count,
            now,
            ttl_seconds,
        )
        .map_err(UiError::from)
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------
//
// Four commands, each deserialize -> one backend call -> serialize. No crypto and no
// SQL: the group lifecycle lives in `anon-ipc`, where it is tested without a webview.
//
// The one value here that looks sensitive is `welcome_hex` from `add_member`. It is
// public key material addressed to the invitee — the artifact the inviter must deliver
// so the invitee can join — and it grants no ability to read past traffic. See
// `anon_ipc::AddMemberOutcome`'s docs for why it is not an exception to the boundary
// rule.

/// Every group this device belongs to, for the sidebar.
#[tauri::command(rename_all = "snake_case")]
pub fn groups(state: State<'_, AppState>) -> UiResult<Vec<GroupView>> {
    state.backend()?.groups().map_err(UiError::from)
}

/// Create a group with the local user as its only member.
#[tauri::command(rename_all = "snake_case")]
pub fn create_group(state: State<'_, AppState>, name: String) -> UiResult<GroupView> {
    state.backend()?.create_group(&name).map_err(UiError::from)
}

/// Generate a single-use MLS KeyPackage (hex) so a peer can add this user to a group.
#[tauri::command(rename_all = "snake_case")]
pub fn generate_key_package(state: State<'_, AppState>) -> UiResult<String> {
    state
        .backend()?
        .generate_key_package()
        .map_err(UiError::from)
}

/// Join an MLS group from a hex-encoded Welcome message.
#[tauri::command(rename_all = "snake_case")]
pub fn join_group(
    state: State<'_, AppState>,
    name: String,
    welcome_hex: String,
) -> UiResult<GroupView> {
    state
        .backend()?
        .join_group(&name, &welcome_hex)
        .map_err(UiError::from)
}

/// The members of one group.
#[tauri::command(rename_all = "snake_case")]
pub fn group_members(
    state: State<'_, AppState>,
    group_id: String,
) -> UiResult<Vec<GroupMemberView>> {
    state
        .backend()?
        .group_members(&group_id)
        .map_err(UiError::from)
}

/// Add a member from their key package, returning the Welcome to deliver.
///
/// The Welcome is returned rather than stored: the inviter's job is to hand it over
/// once, and persisting it would leave a second copy of group-joining material on disk.
#[tauri::command(rename_all = "snake_case")]
pub fn add_member(
    state: State<'_, AppState>,
    group_id: String,
    key_package_hex: String,
) -> UiResult<AddMemberOutcome> {
    state
        .backend()?
        .add_member(&group_id, &key_package_hex)
        .map_err(UiError::from)
}

/// Remove a member by leaf index.
#[tauri::command(rename_all = "snake_case")]
pub fn remove_member(
    state: State<'_, AppState>,
    group_id: String,
    leaf_index: u32,
) -> UiResult<RemoveMemberOutcome> {
    state
        .backend()?
        .remove_member(&group_id, leaf_index)
        .map_err(UiError::from)
}

/// Set a member's role (`owner`, `admin`, `moderator`, `member`) in a group.
#[tauri::command(rename_all = "snake_case")]
pub fn set_member_role(
    state: State<'_, AppState>,
    group_id: String,
    leaf_index: u32,
    role: String,
) -> UiResult<Vec<GroupMemberView>> {
    state
        .backend()?
        .set_member_role(&group_id, leaf_index, &role)
        .map_err(UiError::from)
}

/// Send an MLS-encrypted message (or attachment) to a group and fan out over Tor.
#[tauri::command(rename_all = "snake_case")]
pub async fn send_group_message(
    state: State<'_, AppState>,
    group_id: String,
    mut body: String,
) -> UiResult<SendResult> {
    use zeroize::Zeroize;
    let backend = state.backend()?;
    let payload = std::mem::take(&mut body);
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut payload = payload;
        let res = backend.send_group_message(&group_id, &payload);
        payload.zeroize();
        res
    })
    .await
    .map_err(|e| UiError::from(CommandError::new("internal", e.to_string())))?;
    let delivery = result.map_err(UiError::from)?;
    Ok(SendResult {
        code: delivery.code(),
        label: delivery.label(),
        peer_confirmed: delivery.is_peer_confirmed(),
    })
}

// ---------------------------------------------------------------------------
// Vault: the launch screen (gap-closure plan Gap 2)
// ---------------------------------------------------------------------------
//
// These four commands are the only ones callable while the app is locked. Every other
// command goes through `AppState::backend()`, which returns a `locked` error until one of
// these succeeds.
//
// # The passphrase crosses the boundary exactly once
//
// `unlock_vault`, `create_vault`, and `migrate_vault` each take the passphrase as a
// command argument. It is not stored in a DTO, not returned, and not logged. This is the
// same pattern `export_escrow` already uses, and for the same reason: the user has to
// type it somewhere, and the webview is where they type.
//
// # Why there is no "remember me"
//
// A remembered passphrase would have to be stored somewhere the app can read without the
// user — which is exactly the machine-held secret this gap closes. There is no middle
// ground: either the passphrase is user-held or it is not.

/// What the launch screen should render.
///
/// Callable while locked. The webview calls this first and routes to setup or unlock.
#[tauri::command(rename_all = "snake_case")]
pub fn vault_view(state: State<'_, AppState>) -> UiResult<VaultView> {
    let vault = state.vault();
    let vault_state = vault.state();

    Ok(VaultView {
        state: match &vault_state {
            VaultState::FreshInstall => "fresh_install",
            VaultState::NeedsMigration => "needs_migration",
            VaultState::Locked => "locked",
            VaultState::InterruptedMigration { .. } => "interrupted_migration",
        }
        .to_string(),
        is_setup: vault_state.is_setup(),
        min_chars: crate::vault::MIN_CHARS,
        migration_stage: match vault_state {
            VaultState::InterruptedMigration { stage } => Some(stage),
            _ => None,
        },
    })
}

/// Assess a candidate passphrase for the setup screen's live hint.
///
/// Callable while locked. Takes the candidate as an argument and returns only facts about
/// it — never the candidate itself. The webview already has the value it typed, so
/// returning it would add nothing but a second copy in the IPC log.
#[tauri::command(rename_all = "snake_case")]
pub fn assess_strength(state: State<'_, AppState>, candidate: String) -> UiResult<StrengthView> {
    let vault = state.vault();
    let assessment = vault.assess(&candidate);
    Ok(StrengthView {
        meets_minimum_length: assessment.meets_minimum_length,
        entropy_bits: assessment.estimated_entropy_bits,
        is_well_known_weak: assessment.is_well_known_weak,
        is_repeated_pattern: assessment.is_repeated_pattern,
        warnings: assessment.warnings,
        // The same call the vault makes when it creates the database, so the hint
        // and the enforcement cannot disagree.
        acceptable: vault.is_acceptable(&candidate),
    })
}

/// Create a new database with a user-chosen passphrase (fresh install).
///
/// On success the backend is installed and the app is unlocked — the user should not have
/// to type the passphrase twice in a row.
#[tauri::command(rename_all = "snake_case")]
pub fn create_vault(
    state: State<'_, AppState>,
    passphrase: String,
    confirm: String,
) -> UiResult<VaultView> {
    let guard = state.unlock_lock.lock().unwrap();
    if state.is_unlocked() {
        drop(guard);
        return vault_view(state);
    }
    let vault = state.vault();
    let store = vault.create(&passphrase, &confirm).map_err(vault_error)?;

    // The identity seed comes from the OS keychain (`plan.md` §2.3). An unavailable
    // keychain is fatal: the app must not start in a mode that would write a plaintext
    // seed.
    let identity = crate::identity_store::load_or_create(state.data_dir())
        .map_err(|e| UiError::from(CommandError::new("keychain", e.to_string())))?;

    let backend = Backend::new(
        identity,
        crate::build_transport(state.data_dir()),
        Arc::new(store),
    );
    backend.initialize_privacy(true).map_err(UiError::from)?;
    state.install(backend);
    drop(guard);

    vault_view(state)
}

/// Unlock an existing database with the user's passphrase.
///
/// A wrong passphrase returns the `wrong_passphrase` code so the screen can say "check it
/// and try again" rather than "storage error" — those mean very different things to a
/// user, and only one of them is worth retrying.
#[tauri::command(rename_all = "snake_case")]
pub fn unlock_vault(state: State<'_, AppState>, passphrase: String) -> UiResult<VaultView> {
    let guard = state.unlock_lock.lock().unwrap();
    if state.is_unlocked() {
        drop(guard);
        return vault_view(state);
    }
    let vault = state.vault();
    let store = vault.unlock(&passphrase).map_err(vault_error)?;

    let identity = crate::identity_store::load_or_create(state.data_dir())
        .map_err(|e| UiError::from(CommandError::new("keychain", e.to_string())))?;

    let backend = Backend::new(
        identity,
        crate::build_transport(state.data_dir()),
        Arc::new(store),
    );
    backend.initialize_privacy(false).map_err(UiError::from)?;
    state.install(backend);
    drop(guard);

    vault_view(state)
}

/// Migrate an existing install from the machine-held passphrase to a user passphrase.
///
/// The user chooses the new passphrase; the app reads the machine-held one itself, uses it
/// as the old key, and deletes it. See [`crate::vault::Vault::migrate`] for why the rekey
/// runs before the deletion.
#[tauri::command(rename_all = "snake_case")]
pub fn migrate_vault(
    state: State<'_, AppState>,
    passphrase: String,
    confirm: String,
) -> UiResult<VaultView> {
    let guard = state.unlock_lock.lock().unwrap();
    if state.is_unlocked() {
        drop(guard);
        return vault_view(state);
    }
    let vault = state.vault();
    let (store, _report) = vault.migrate(&passphrase, &confirm).map_err(vault_error)?;

    let identity = crate::identity_store::load_or_create(state.data_dir())
        .map_err(|e| UiError::from(CommandError::new("keychain", e.to_string())))?;

    let backend = Backend::new(
        identity,
        crate::build_transport(state.data_dir()),
        Arc::new(store),
    );
    backend.initialize_privacy(false).map_err(UiError::from)?;
    state.install(backend);
    drop(guard);

    vault_view(state)
}

/// Map a vault failure to a display-safe error with a stable code.
///
/// The codes are what the launch screen branches on. `wrong_passphrase` is the one that
/// matters most: it is the only failure the user can fix by trying again, so it must not
/// be collapsed into a generic error.
fn vault_error(e: VaultError) -> UiError {
    let code = match &e {
        VaultError::WrongPassphrase => "wrong_passphrase",
        VaultError::WeakPassphrase(_) => "weak_passphrase",
        VaultError::Mismatch => "passphrase_mismatch",
        VaultError::Storage(_) => "storage",
        VaultError::Io(_) => "io",
        VaultError::Migration(_) => "migration",
    };
    UiError {
        code: code.to_string(),
        message: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The commands this app registers.
///
/// Kept as a single list so the surface is countable — `plan.md` §7.3 asks for "a
/// small, explicitly enumerated command set", and a list you can read in one screen
/// is the cheapest way to keep it that way.
pub fn register(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder.invoke_handler(tauri::generate_handler![
        // The launch screen. These are the only commands callable while locked.
        vault_view,
        list_personas,
        create_persona,
        open_persona,
        assess_strength,
        create_vault,
        unlock_vault,
        migrate_vault,
        // Everything below requires an unlocked backend.
        identity_view,
        set_display_name,
        note_escrow_exported,
        export_escrow,
        transport_view,
        drain_send_queue,
        queued_messages,
        privacy_view,
        enable_restricted_discovery,
        export_invite,
        set_traffic_shaping,
        conversations,
        messages,
        peers,
        add_peer,
        send_message,
        pending_consent,
        submit_consent,
        draft_rotation,
        groups,
        create_group,
        generate_key_package,
        join_group,
        group_members,
        add_member,
        remove_member,
        set_member_role,
        send_group_message,
    ])
}

#[cfg(test)]
mod tests {
    use anon_ipc::DeliveryState;

    #[test]
    fn delivery_state_codes_are_stable() {
        // The frontend branches on these strings; changing one is a breaking change.
        assert_eq!(DeliveryState::QueuedLocal.code(), "queued_local");
        assert_eq!(DeliveryState::AtMailbox.code(), "at_mailbox");
        assert_eq!(DeliveryState::Delivered.code(), "delivered");
        assert_eq!(DeliveryState::Read.code(), "read");
    }
}
