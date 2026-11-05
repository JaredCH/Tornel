//! The backend facade (`plan.md` §7.3).
//!
//! Owns the identity, the store, the transport, the messaging service, and the
//! consent gate, and exposes exactly the operations the UI may invoke.
//!
//! # Why this is one struct and not a bag of functions
//!
//! `plan.md` §7.3 requires a "small, explicitly enumerated command set". Making
//! the boundary a single type with a handful of methods means the surface is
//! countable and reviewable, and it is the *only* place where the crates meet.
//!
//! # Where secrets live
//!
//! Secrets live in Rust and are referenced across the boundary by
//! [`SecretHandle`]. `Backend` holds a map from handle to nonce for outstanding
//! consent prompts; the webview only ever sees the handle.

use crate::dto::{
    AddMemberOutcome, ConsentPrompt, ConsentSubmission, ConversationView, DeliveryState,
    GroupMemberView, GroupView, IdentityView, MessageView, PeerView, ProposalView,
    QueuedMessageView, RemoveMemberOutcome, SendRequest, TransportView,
};
use crate::error::{CommandError, IpcError, Result};
use crate::SecretHandle;
use anon_consent::{ConsentGate, ConsentOutcome, DecisionRequest, ProposalId, RotationProposal};
use anon_core::{ContactCode, IdentityKeys};
use anon_messaging::frame::Frame;
use anon_messaging::{MessagingService, PROTOCOL_VERSION};
use anon_mls::{Group, MlsProvider};
use anon_storage::{GroupRow, Store};
use anon_transport::{AnonymityClass, AnonymityTransport, OnionId, PeerRoute, TransportStatus};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Direct 1-on-1 message envelope inside a padded [`Frame`].
///
/// ```text
/// magic       4 bytes ("ANM1")
/// sent_at     i64 LE  (8 bytes)
/// signature   64 bytes (Ed25519 signature over domain || conversation || epoch || sent_at || body)
/// body        variable UTF-8 message bytes
/// ```
const DIRECT_ENVELOPE_MAGIC: &[u8; 4] = b"ANM1";
const DIRECT_SIGN_DOMAIN: &[u8] = b"anon/v1/direct-msg-sig";
const DIRECT_KEY_DOMAIN: &[u8] = b"anon/v1/direct-frame-key";
const DIRECT_CONV_DOMAIN: &[u8] = b"anon/v1/direct-conversation";
const GROUP_ENVELOPE_MAGIC: &[u8; 4] = b"ANG1";
const GROUP_FRAME_DOMAIN: &[u8] = b"anon/v1/group-frame/";
const GROUP_ROLE_CONTROL_PREFIX: &[u8] = b"ANON_GROUP_ROLE_V1:";

/// Compute the 16-byte conversation id for an MLS group id.
pub fn group_conversation_id(group_id: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = group_id.len().min(16);
    out[..n].copy_from_slice(&group_id[..n]);
    out
}

fn derive_group_frame_key(group_id: &[u8], conversation: &[u8; 16], epoch: u64) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut info = Vec::with_capacity(GROUP_FRAME_DOMAIN.len() + group_id.len() + 16 + 8);
    info.extend_from_slice(GROUP_FRAME_DOMAIN);
    info.extend_from_slice(group_id);
    info.extend_from_slice(conversation);
    info.extend_from_slice(&epoch.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, group_id);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn encode_group_envelope(sent_at: i64, sender_code: &str, body: &[u8]) -> Vec<u8> {
    let code_bytes = sender_code.as_bytes();
    let code_len = (code_bytes.len().min(u16::MAX as usize)) as u16;
    let mut out = Vec::with_capacity(4 + 8 + 2 + (code_len as usize) + body.len());
    out.extend_from_slice(GROUP_ENVELOPE_MAGIC);
    out.extend_from_slice(&sent_at.to_le_bytes());
    out.extend_from_slice(&code_len.to_le_bytes());
    out.extend_from_slice(&code_bytes[..code_len as usize]);
    out.extend_from_slice(body);
    out
}

fn decode_group_envelope(envelope: &[u8]) -> std::result::Result<(i64, String, Vec<u8>), ()> {
    if envelope.len() < 4 + 8 + 2 {
        return Err(());
    }
    if &envelope[..4] != GROUP_ENVELOPE_MAGIC {
        return Err(());
    }
    let sent_at = i64::from_le_bytes(envelope[4..12].try_into().map_err(|_| ())?);
    let code_len = u16::from_le_bytes(envelope[12..14].try_into().map_err(|_| ())?) as usize;
    if envelope.len() < 14 + code_len {
        return Err(());
    }
    let sender_code = std::str::from_utf8(&envelope[14..14 + code_len])
        .map_err(|_| ())?
        .to_string();
    let body = envelope[14 + code_len..].to_vec();
    Ok((sent_at, sender_code, body))
}

/// Compute the deterministic 16-byte conversation id for a pair of public identities.
pub fn direct_conversation_id(
    a: &anon_core::PublicIdentity,
    b: &anon_core::PublicIdentity,
) -> [u8; 16] {
    let mut keys = [(a.identity, a.agreement), (b.identity, b.agreement)];
    keys.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECT_CONV_DOMAIN);
    for (id_key, ag_key) in &keys {
        hasher.update(id_key);
        hasher.update(ag_key);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

/// Derive the authenticated X25519 shared frame key for a direct conversation and epoch.
pub fn derive_direct_key(
    identity: &IdentityKeys,
    peer: &anon_core::PublicIdentity,
    conversation: &[u8; 16],
    epoch: u64,
) -> zeroize::Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let shared = zeroize::Zeroizing::new(identity.diffie_hellman(&peer.agreement));
    let mut ids = [identity.public().identity, peer.identity];
    ids.sort_unstable();

    let mut info = Vec::with_capacity(DIRECT_KEY_DOMAIN.len() + 64 + 16 + 8);
    info.extend_from_slice(DIRECT_KEY_DOMAIN);
    info.extend_from_slice(&ids[0]);
    info.extend_from_slice(&ids[1]);
    info.extend_from_slice(conversation);
    info.extend_from_slice(&epoch.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(conversation), shared.as_ref());
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn direct_signing_transcript(
    conversation: &[u8; 16],
    epoch: u64,
    sent_at: i64,
    body: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DIRECT_SIGN_DOMAIN.len() + 16 + 8 + 8 + body.len());
    msg.extend_from_slice(DIRECT_SIGN_DOMAIN);
    msg.extend_from_slice(conversation);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&sent_at.to_le_bytes());
    msg.extend_from_slice(body);
    msg
}

fn encode_direct_envelope(
    identity: &IdentityKeys,
    conversation: &[u8; 16],
    epoch: u64,
    sent_at: i64,
    body: &[u8],
) -> Vec<u8> {
    let transcript = direct_signing_transcript(conversation, epoch, sent_at, body);
    let sig = identity.sign(&transcript).to_bytes();
    let mut out = Vec::with_capacity(4 + 8 + 64 + body.len());
    out.extend_from_slice(DIRECT_ENVELOPE_MAGIC);
    out.extend_from_slice(&sent_at.to_le_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(body);
    out
}

fn decode_and_verify_direct_envelope(
    peer: &anon_core::PublicIdentity,
    conversation: &[u8; 16],
    epoch: u64,
    envelope: &[u8],
) -> std::result::Result<(i64, Vec<u8>), ()> {
    if envelope.len() < 4 + 8 + 64 {
        return Err(());
    }
    if &envelope[..4] != DIRECT_ENVELOPE_MAGIC {
        return Err(());
    }
    let sent_at = i64::from_le_bytes(envelope[4..12].try_into().map_err(|_| ())?);
    let sig: [u8; 64] = envelope[12..76].try_into().map_err(|_| ())?;
    let body = &envelope[76..];
    let transcript = direct_signing_transcript(conversation, epoch, sent_at, body);
    peer.verify(&transcript, &sig).map_err(|_| ())?;
    Ok((sent_at, body.to_vec()))
}

#[path = "privacy.rs"]
mod privacy;

/// The backend.
pub struct Backend {
    privacy_lock: Mutex<()>,
    identity: Arc<IdentityKeys>,
    store: Arc<Store>,
    messaging: Arc<MessagingService>,
    consent: ConsentGate,
    display_name: Mutex<Option<String>>,
    escrow_exported: Mutex<bool>,
    /// Maps a handle to the nonce of an outstanding consent prompt.
    ///
    /// This is the one place a secret (the nonce) is addressed from the boundary,
    /// and it is addressed indirectly by design (`plan.md` §5.2, §7.3).
    pending_nonces: Mutex<HashMap<String, [u8; 32]>>,
    /// The proposal the modal should currently render, with its nonce handle.
    ///
    /// Held so [`Backend::pending_consent`] can re-serve the *same* prompt on a
    /// refresh. Minting a fresh handle per call would give the UI two independent
    /// approval paths for one proposal.
    pending_prompt: Mutex<Option<(ProposalView, String)>>,
}

impl Backend {
    /// Build a backend over a transport and store.
    pub fn new(
        identity: IdentityKeys,
        transport: Arc<dyn AnonymityTransport>,
        store: Arc<Store>,
    ) -> Self {
        let consent = ConsentGate::new(&identity, 1024);
        let identity = Arc::new(identity);
        let messaging = Arc::new(MessagingService::new(transport.clone(), store.clone()));
        // Read before `store` moves into `Self`.
        let saved_name = store.display_name().unwrap_or(None);

        {
            let identity = Arc::clone(&identity);
            let store = Arc::clone(&store);
            let messaging = Arc::clone(&messaging);
            transport.set_inbound_handler(Arc::new(move |bytes| {
                let _ = Self::handle_inbound_bytes(&identity, &store, &messaging, &bytes);
            }));
        }

        Self {
            identity,
            privacy_lock: Mutex::new(()),
            store,
            messaging,
            consent,
            // The name survives restarts: it is loaded from the store here and
            // written through on every change. Before this, the name lived only
            // in this mutex and vanished on every launch — which also meant the
            // signed invite could not carry it.
            display_name: Mutex::new(saved_name),
            escrow_exported: Mutex::new(false),
            pending_nonces: Mutex::new(HashMap::new()),
            pending_prompt: Mutex::new(None),
        }
    }

    // -- Identity ----------------------------------------------------------

    /// The user's contact code. Public by design.
    pub fn contact_code(&self) -> Result<String> {
        ContactCode::encode(&self.identity.public()).map_err(IpcError::Core)
    }

    /// Set the local display name (`plan.md` §2: names are allowed but are not
    /// identity).
    ///
    /// The name is persisted in the store, so it survives a restart and can be
    /// included in the signed invite. Validation happens before any write.
    pub fn set_display_name(&self, name: Option<String>) -> Result<()> {
        let validated = match &name {
            Some(n) => {
                let t = n.trim();
                if t.is_empty() {
                    return Err(IpcError::EmptyField("display_name"));
                }
                if t.chars().count() > 64 {
                    return Err(IpcError::FieldTooLong("display_name"));
                }
                Some(t.to_string())
            }
            None => None,
        };
        self.store
            .set_display_name(validated.as_deref())
            .map_err(IpcError::Storage)?;
        *self.display_name.lock().unwrap() = validated;
        Ok(())
    }

    /// Everything the UI needs to render the identity panel.
    pub fn identity_view(&self) -> Result<IdentityView> {
        Ok(IdentityView {
            contact_code: self.contact_code()?,
            fingerprint: self.identity.public().fingerprint(),
            display_name: self.display_name.lock().unwrap().clone(),
            escrow_exported: *self.escrow_exported.lock().unwrap(),
        })
    }

    /// Record that the user completed the escrow export flow.
    ///
    /// The artifact itself never reaches the backend's persistent state
    /// (`plan.md` §2.5): we only remember that the flow happened, so the UI can
    /// stop nagging.
    pub fn note_escrow_exported(&self) {
        *self.escrow_exported.lock().unwrap() = true;
    }

    /// Export an escrow artifact (`plan.md` §2.5).
    ///
    /// The artifact is returned to the caller so the **user** can store it. The
    /// backend does not persist it; there is no server to send it to.
    pub fn export_escrow(&self, passphrase: &str) -> Result<Vec<u8>> {
        if passphrase.trim().is_empty() {
            return Err(IpcError::EmptyField("passphrase"));
        }
        let artifact = anon_core::escrow::export(
            &self.identity,
            passphrase,
            anon_core::escrow::Argon2Params::mobile_default(),
        )?;
        self.note_escrow_exported();
        Ok(artifact)
    }

    // -- Transport ---------------------------------------------------------

    /// Transport status for the header (`plan.md` §8: never hide why sending is
    /// unavailable).
    pub fn transport_view(&self) -> TransportView {
        let t = self.messaging.transport();
        let reason = self.messaging.send_unavailable_reason();
        let can_send = self.messaging.can_send() && t.is_onion_service_reachable();
        let blocked_reason = if reason.is_some() {
            reason
        } else if !t.is_onion_service_reachable() {
            Some(
                "Connected to Tor; publishing your v3 onion service descriptor (typically 20–60s)…"
                    .to_string(),
            )
        } else {
            None
        };
        TransportView {
            anonymity: match t.anonymity() {
                AnonymityClass::TorOnion => "tor_onion",
                AnonymityClass::Loopback => "loopback",
                AnonymityClass::None => "none",
            }
            .to_string(),
            status: match t.status() {
                TransportStatus::Idle => "idle",
                TransportStatus::Bootstrapping => "bootstrapping",
                TransportStatus::Ready => "ready",
                TransportStatus::Failed => "failed",
            }
            .to_string(),
            can_send,
            blocked_reason,
            local_onion_short: t.local_onion().map(|o| o.short_label()),
            local_onion: t.local_onion().map(|o| o.as_str().to_string()),
            queued_count: self.messaging.queued_count().unwrap_or(0),
        }
    }

    /// Retry every queued frame that is due.
    ///
    /// Called on a timer by the shell. Returns how many frames went out, so the UI
    /// can refresh a conversation only when something actually changed.
    pub fn drain_send_queue(&self) -> std::result::Result<usize, CommandError> {
        let report = self
            .messaging
            .drain_queue(self.store.now())
            .map_err(CommandError::from)?;
        Ok(report.sent)
    }

    /// Queued frames for one conversation, oldest first.
    ///
    /// Exposed so the UI can show a message as "queued" rather than pretending it
    /// was delivered (`plan.md` §8).
    pub fn queued_messages(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<Vec<QueuedMessageView>, CommandError> {
        let (conv, _) = conversation_id_bytes(conversation_id)?;
        let queued = self
            .messaging
            .queued_for(&conv)
            .map_err(CommandError::from)?;
        Ok(queued
            .into_iter()
            .map(|q| QueuedMessageView {
                id: hex_encode(&q.id),
                created_at: q.created_at,
                attempts: q.attempts,
                last_error: q.last_error,
            })
            .collect())
    }

    // -- Sending -----------------------------------------------------------

    /// Send a message.
    ///
    /// Refuses rather than degrading: if anonymity is unavailable, or the group is
    /// not forward-secret, the message is not sent (`plan.md` §1.2, §5.2).
    pub fn send(
        &self,
        request: &SendRequest,
        key: &[u8; 32],
        now: i64,
    ) -> std::result::Result<DeliveryState, CommandError> {
        request.validate()?;

        if !self.messaging.can_send() {
            let reason = self
                .messaging
                .send_unavailable_reason()
                .unwrap_or_else(|| "sending is unavailable".to_string());
            return Err(CommandError::from(IpcError::SendUnavailable(reason)));
        }

        let onion = OnionId::parse(&request.recipient_onion)
            .map_err(|_| CommandError::from(IpcError::BadOnion(request.recipient_onion.clone())))?;

        let conversation = conversation_id_bytes(&request.conversation_id)?;
        let route = PeerRoute::onion(onion);

        let report = self.messaging.send(
            &route,
            conversation.0,
            request.epoch,
            key,
            request.body.as_bytes(),
        )?;

        // `now` is accepted so the caller's clock is the one used for any
        // accompanying bookkeeping, matching the store's injected-clock design.
        let _ = now;

        Ok(map_outcome(report.outcome))
    }

    // -- Consent -----------------------------------------------------------

    /// Register a group so rotations can be drafted for it.
    pub fn register_group(&self, group_id: &str, epoch: u64) {
        self.consent.register_group(group_id, epoch);
    }

    /// Draft a rotation and return the prompt for the modal.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_rotation(
        &self,
        group_id: &str,
        group_name: &str,
        reason: anon_consent::RotationReason,
        epoch_after: u64,
        member_count: u32,
        now: i64,
        ttl_seconds: i64,
    ) -> std::result::Result<ConsentPrompt, CommandError> {
        let proposal = self
            .consent
            .draft_rotation(
                &self.identity,
                group_id,
                group_name,
                reason,
                epoch_after,
                member_count,
                now,
                ttl_seconds,
            )
            .map_err(CommandError::from)?;

        // Hold the nonce in Rust and hand the UI only a handle.
        let handle = SecretHandle::mint();
        self.pending_nonces
            .lock()
            .unwrap()
            .insert(handle.to_string(), *proposal.nonce());

        Ok(ConsentPrompt {
            proposal: proposal_view(&proposal),
            nonce_handle: handle.to_string(),
        })
    }

    /// Submit a decision from the modal.
    ///
    /// # Replay and binding
    ///
    /// The handle is consumed (removed) on the first call, so a second submission
    /// with the same handle cannot resolve — an independent layer of replay
    /// protection on top of the gate's own nonce check (`plan.md` §5.2).
    pub fn submit_consent(
        &self,
        submission: &ConsentSubmission,
        now: i64,
    ) -> std::result::Result<ConsentOutcome, CommandError> {
        submission.validate()?;

        // Take the nonce, consuming the handle. `remove` rather than `get` is
        // what makes this one-shot.
        let nonce = self
            .pending_nonces
            .lock()
            .unwrap()
            .remove(&submission.nonce_handle)
            .ok_or_else(|| CommandError::from(IpcError::UnknownHandle))?;

        let outcome = if submission.approved {
            ConsentOutcome::Approved
        } else {
            ConsentOutcome::Denied
        };

        let request = DecisionRequest {
            proposal_id: ProposalId::parse(&submission.proposal_id),
            outcome,
            nonce,
        };

        let decided = self
            .consent
            .decide(&request, now)
            .map_err(CommandError::from)?;

        // The proposal is resolved, so it must stop being offered to the modal.
        // Leaving it pending would let the UI display a proposal whose decision has
        // already been recorded (`plan.md` §5.2 "idempotent").
        *self.pending_prompt.lock().unwrap() = None;

        Ok(decided)
    }

    /// Whether a group currently has forward secrecy.
    pub fn is_forward_secret(&self, group_id: &str) -> bool {
        self.consent
            .group_state(group_id)
            .map(|s| s.is_forward_secret())
            .unwrap_or(false)
    }

    // -- Groups ------------------------------------------------------------

    /// Create a group with the local user as its only member.
    ///
    /// The MLS group is created first, then the row is persisted. That order matters:
    /// a row without MLS state is a group the app cannot use, whereas MLS state
    /// without a row is merely invisible and can be re-recorded. So the failure that
    /// leaves debris is the recoverable one.
    ///
    /// The group is registered with the consent gate at its creation epoch, so a
    /// later rotation has a `epoch_before` to name.
    pub fn create_group(&self, name: &str) -> std::result::Result<GroupView, CommandError> {
        let name = validate_group_name(name)?;
        let identity = self.identity_bytes()?;

        let provider = self.group_provider()?;
        let group = Group::create(&provider, &identity).map_err(CommandError::from)?;

        let row = GroupRow {
            group_id: group.group_id().to_vec(),
            name: Some(name),
            created_at: self.store.now(),
            epoch: group.epoch(),
        };
        self.store.insert_group(&row).map_err(CommandError::from)?;
        if let Ok(self_code) = self.contact_code() {
            let _ = self
                .store
                .set_group_role(&row.group_id, &self_code, "owner");
        }
        let conv = group_conversation_id(&row.group_id);
        let _ = self.store.ensure_conversation(
            &conv,
            anon_storage::ConversationKind::Group,
            &row.group_id,
        );

        // Register at the creation epoch so a rotation has a starting point.
        self.consent
            .register_group(&hex_encode(&row.group_id), row.epoch);

        Ok(GroupView {
            group_id: hex_encode(&row.group_id),
            name: row.name,
            epoch: row.epoch,
            member_count: group.info().members.len() as u32,
            created_at: row.created_at,
        })
    }

    /// Generate a single-use MLS KeyPackage (hex-encoded) for the local user so another
    /// peer can invite this device into a group (`plan.md` §4.3).
    pub fn generate_key_package(&self) -> std::result::Result<String, CommandError> {
        let identity = self.identity_bytes()?;
        let provider = self.group_provider()?;
        let bytes = Group::key_package(&provider, &identity).map_err(CommandError::from)?;
        Ok(hex_encode(&bytes))
    }

    /// Join an MLS group from a Welcome message (hex-encoded) and persist it locally.
    pub fn join_group(
        &self,
        name: &str,
        welcome_hex: &str,
    ) -> std::result::Result<GroupView, CommandError> {
        let name = validate_group_name(name)?;
        let welcome = decode_hex(welcome_hex.trim()).map_err(|_| {
            CommandError::from(IpcError::BadGroupId(
                "the Welcome message must be hexadecimal".to_string(),
            ))
        })?;
        if welcome.is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("welcome_hex")));
        }

        let provider = self.group_provider()?;
        let group = Group::join_from_welcome(&provider, &welcome).map_err(CommandError::from)?;
        let row = GroupRow {
            group_id: group.group_id().to_vec(),
            name: Some(name),
            created_at: self.store.now(),
            epoch: group.epoch(),
        };
        self.store.insert_group(&row).map_err(CommandError::from)?;
        // Record leaf 0 as owner if not already set, and self as member
        for m in group.info().members {
            let code_str = String::from_utf8_lossy(&m.identity).trim().to_string();
            if m.index == 0 {
                let _ = self.store.set_group_role(&row.group_id, &code_str, "owner");
            } else if m.is_self {
                let _ = self
                    .store
                    .set_group_role(&row.group_id, &code_str, "member");
            }
        }
        let conv = group_conversation_id(&row.group_id);
        let _ = self.store.ensure_conversation(
            &conv,
            anon_storage::ConversationKind::Group,
            &row.group_id,
        );
        self.consent
            .register_group(&hex_encode(&row.group_id), row.epoch);

        Ok(GroupView {
            group_id: hex_encode(&row.group_id),
            name: row.name,
            epoch: row.epoch,
            member_count: group.info().members.len() as u32,
            created_at: row.created_at,
        })
    }

    /// Add a member to a group from their serialized key package.
    ///
    /// Returns the Welcome message for the caller to deliver. **The Welcome is not
    /// persisted** — it is a delivery artifact, and storing it would leave a second
    /// copy of group-joining material on disk for no benefit.
    ///
    /// The key package is attacker-supplied bytes until MLS validates it, so
    /// validation happens inside [`Group::add_members`] rather than here; this method
    /// only checks that the input is non-empty and well-formed hex.
    pub fn add_member(
        &self,
        group_id: &str,
        key_package_hex: &str,
    ) -> std::result::Result<AddMemberOutcome, CommandError> {
        let group_bytes = decode_group_id(group_id)?;
        let key_package = decode_hex(key_package_hex).map_err(|_| {
            CommandError::from(IpcError::BadGroupId(
                "the key package must be hexadecimal".to_string(),
            ))
        })?;
        if key_package.is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("key_package_hex")));
        }

        // The row must exist: a webview-supplied id is never trusted to name a group
        // the backend has not recorded (`plan.md` §7.3).
        let row = self
            .store
            .group(&group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let provider = self.group_provider()?;
        let mut group = Group::load(&provider, &group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::GroupStateMissing))?;

        let outcome = group
            .add_members(&provider, &[key_package])
            .map_err(CommandError::from)?;

        // Persist the new epoch. An add advances the epoch immediately, so the stored
        // epoch must follow or the next rotation would name a stale "before".
        self.store
            .update_group_epoch(&group_bytes, outcome.epoch)
            .map_err(CommandError::from)?;
        self.consent
            .sync_group_epoch(&hex_encode(&group_bytes), outcome.epoch);

        // Best-effort fan-out of the MLS Commit to existing members with known .onion routes
        if self.messaging.can_send() {
            let conv = group_conversation_id(&group_bytes);
            let prev_epoch = outcome.epoch.saturating_sub(1);
            let key = derive_group_frame_key(&group_bytes, &conv, prev_epoch);
            for route in self.member_onion_routes(&group.info().members) {
                let _ = self
                    .messaging
                    .send(&route, conv, prev_epoch, &key, &outcome.commit);
            }
        }

        Ok(AddMemberOutcome {
            group_id: hex_encode(&row.group_id),
            epoch: outcome.epoch,
            welcome_hex: hex_encode(&outcome.welcome),
        })
    }

    /// Remove a member from a group by leaf index.
    ///
    /// Removal advances the epoch and implies a rotation, so this drafts the rotation
    /// proposal and returns it for the existing consent modal to render. That is the
    /// reuse point: removal is exactly the `RotationReason::MemberRemoved` case the
    /// gate already models, so no new consent machinery is needed.
    ///
    /// # Ordering
    ///
    /// The gate's `current_epoch` is deliberately **not** synced before drafting. The
    /// proposal's `epoch_before` must name the epoch the member was removed *from*, so
    /// the modal shows "N → N+1" rather than "N+1 → N+1". The gate catches up when the
    /// decision is finalised.
    pub fn remove_member(
        &self,
        group_id: &str,
        leaf_index: u32,
    ) -> std::result::Result<RemoveMemberOutcome, CommandError> {
        let group_bytes = decode_group_id(group_id)?;
        let group_hex = hex_encode(&group_bytes);

        let row = self
            .store
            .group(&group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let provider = self.group_provider()?;
        let mut group = Group::load(&provider, &group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::GroupStateMissing))?;

        // Ensure the gate knows the group at its pre-removal epoch. A group created
        // through `create_group` is already registered; one reached another way (a
        // future join-from-Welcome path) may not be.
        if self.consent.group_state(&group_hex).is_none() {
            self.consent.register_group(&group_hex, group.epoch());
        }

        let outcome = group
            .remove_member(&provider, leaf_index)
            .map_err(CommandError::from)?;

        self.store
            .update_group_epoch(&group_bytes, outcome.epoch)
            .map_err(CommandError::from)?;

        // Best-effort fan-out of the MLS Commit to remaining members with known .onion routes
        if self.messaging.can_send() {
            let conv = group_conversation_id(&group_bytes);
            let prev_epoch = outcome.epoch.saturating_sub(1);
            let key = derive_group_frame_key(&group_bytes, &conv, prev_epoch);
            for route in self.member_onion_routes(&group.info().members) {
                let _ = self
                    .messaging
                    .send(&route, conv, prev_epoch, &key, &outcome.commit);
            }
        }

        // Draft the rotation the removal implies. The member count is read from the
        // group *after* the removal, which is what the modal should show.
        let member_count = group.info().members.len() as u32;
        let group_name = row.name.clone().unwrap_or_else(|| "group".to_string());
        let now = self.store.now();
        let proposal = self.draft_pending_rotation(
            &group_hex,
            &group_name,
            anon_consent::RotationReason::MemberRemoved,
            outcome.epoch,
            member_count,
            now,
            PROPOSAL_TTL_SECONDS,
        )?;

        Ok(RemoveMemberOutcome {
            group_id: group_hex,
            epoch: outcome.epoch,
            proposal: Some(proposal.proposal),
        })
    }

    /// Every group this device belongs to, for the sidebar.
    ///
    /// `member_count` is read from the MLS state rather than the row, because the row
    /// deliberately stores only metadata. A group whose MLS state is missing reports
    /// `member_count == 0`, which is unambiguous: MLS refuses to leave a group empty,
    /// so a real group always has at least its creator. The UI should treat 0 as
    /// "state unavailable" rather than "empty group".
    pub fn groups(&self) -> std::result::Result<Vec<GroupView>, CommandError> {
        let rows = self.store.groups().map_err(CommandError::from)?;
        let mut out = Vec::with_capacity(rows.len());

        // One provider for the whole listing: opening a secondary connection per group
        // would be a connection storm for no benefit.
        let provider = self.group_provider().ok();

        for row in rows {
            let member_count = provider
                .as_ref()
                .and_then(|p| Group::load(p, &row.group_id).ok().flatten())
                .map(|g| g.info().members.len() as u32)
                .unwrap_or(0);

            out.push(GroupView {
                group_id: hex_encode(&row.group_id),
                name: row.name,
                epoch: row.epoch,
                member_count,
                created_at: row.created_at,
            });
        }
        Ok(out)
    }

    /// The members of one group, for the member list.
    ///
    /// Reads the MLS ratchet tree, so the list is what the group actually contains
    /// rather than what a row claims. A group whose MLS state is missing is an error
    /// here — unlike the listing, a member list that silently came back empty would be
    /// actively misleading.
    pub fn group_members(
        &self,
        group_id: &str,
    ) -> std::result::Result<Vec<GroupMemberView>, CommandError> {
        let group_bytes = decode_group_id(group_id)?;

        // The row must exist first, so an unknown id is "unknown group" rather than
        // "missing MLS state" — the two mean different things to the user.
        self.store
            .group(&group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let provider = self.group_provider()?;
        let group = Group::load(&provider, &group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let roles = self
            .store
            .group_roles(&group_bytes)
            .unwrap_or_default()
            .into_iter()
            .collect::<HashMap<String, String>>();
        let contacts = self.store.contacts().unwrap_or_default();
        let self_display = self.display_name.lock().unwrap().clone();

        Ok(group
            .info()
            .members
            .into_iter()
            .map(|m| {
                let code_str = String::from_utf8_lossy(&m.identity).trim().to_string();
                let default_role = if m.index == 0 { "owner" } else { "member" };
                let role = roles
                    .get(&code_str)
                    .cloned()
                    .unwrap_or_else(|| default_role.to_string());
                let display_name = if m.is_self {
                    self_display.clone()
                } else {
                    contacts
                        .iter()
                        .find(|c| c.contact_code == code_str)
                        .and_then(|c| c.display_name.as_ref())
                        .map(|n| n.split('|').next().unwrap_or("").trim().to_string())
                        .filter(|s| !s.is_empty())
                };
                GroupMemberView {
                    leaf_index: m.index,
                    contact_code_short: short_fingerprint(&m.identity),
                    is_self: m.is_self,
                    role,
                    display_name,
                }
            })
            .collect())
    }

    /// Assign a role (`owner`, `admin`, `moderator`, `member`) to a group member by leaf index,
    /// enforcing role hierarchy and broadcasting the update over MLS to online group members.
    pub fn set_member_role(
        &self,
        group_id: &str,
        leaf_index: u32,
        role: &str,
    ) -> std::result::Result<Vec<GroupMemberView>, CommandError> {
        let normalized_role = role.trim().to_ascii_lowercase();
        if !matches!(
            normalized_role.as_str(),
            "owner" | "admin" | "moderator" | "member"
        ) {
            return Err(CommandError::from(IpcError::EmptyField("role")));
        }

        let group_bytes = decode_group_id(group_id)?;
        self.store
            .group(&group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let provider = self.group_provider()?;
        let mut group = Group::load(&provider, &group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::GroupStateMissing))?;

        let info = group.info();
        let self_code = self.contact_code().map_err(CommandError::from)?;
        let caller_leaf = info.members.iter().find(|m| m.is_self).map(|m| m.index);
        let caller_role = self
            .store
            .group_role(&group_bytes, &self_code)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                if caller_leaf == Some(0) {
                    "owner".to_string()
                } else {
                    "member".to_string()
                }
            });

        if !matches!(caller_role.as_str(), "owner" | "admin") {
            return Err(CommandError::new(
                "forbidden_role",
                "only a group Owner or Admin can change member roles",
            ));
        }

        let target = info
            .members
            .iter()
            .find(|m| m.index == leaf_index)
            .ok_or_else(|| {
                CommandError::from(IpcError::Group(anon_mls::MlsError::UnknownMember(
                    leaf_index,
                )))
            })?;
        let target_code = String::from_utf8_lossy(&target.identity).trim().to_string();

        self.store
            .set_group_role(&group_bytes, &target_code, &normalized_role)
            .map_err(CommandError::from)?;

        // Best-effort MLS control broadcast to online group members with known .onion routes
        if self.messaging.can_send() {
            let control_body = format!(
                "{}{}|{}",
                String::from_utf8_lossy(GROUP_ROLE_CONTROL_PREFIX),
                target_code,
                normalized_role
            );
            let now = self.store.now();
            let env = encode_group_envelope(now, &self_code, control_body.as_bytes());
            if let Ok(mls_ct) = group.encrypt(&provider, &env) {
                let conv = group_conversation_id(&group_bytes);
                let key = derive_group_frame_key(&group_bytes, &conv, group.epoch());
                for route in self.member_onion_routes(&info.members) {
                    let _ = self
                        .messaging
                        .send(&route, conv, group.epoch(), &key, &mls_ct);
                }
            }
        }

        self.group_members(group_id)
    }

    /// Send an MLS-encrypted message (or attachment) to a group and fan out over Tor
    /// to every group member whose `.onion` route is known in contacts (`plan.md` §4.2, §9).
    pub fn send_group_message(
        &self,
        group_id: &str,
        body: &str,
    ) -> std::result::Result<DeliveryState, CommandError> {
        const MAX_BODY: usize = 520_000;
        if body.is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("body")));
        }
        if body.len() > MAX_BODY {
            return Err(CommandError::from(IpcError::FieldTooLong("body")));
        }
        let body = anon_messaging::attachment::sanitize_body(body.as_bytes())?;

        let group_bytes = decode_group_id(group_id)?;
        self.store
            .group(&group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::UnknownGroup))?;

        let provider = self.group_provider()?;
        let mut group = Group::load(&provider, &group_bytes)
            .map_err(CommandError::from)?
            .ok_or_else(|| CommandError::from(IpcError::GroupStateMissing))?;

        let info = group.info();
        let now = self.store.now();
        let self_code = self.contact_code().map_err(CommandError::from)?;
        let env = encode_group_envelope(now, &self_code, &body);

        // Encrypt with OpenMLS (advances the sender's ratcheting generation for this epoch).
        let mls_ct = group.encrypt(&provider, &env).map_err(CommandError::from)?;
        let conv = group_conversation_id(&group_bytes);
        let key = derive_group_frame_key(&group_bytes, &conv, group.epoch());

        self.store
            .ensure_conversation(&conv, anon_storage::ConversationKind::Group, &group_bytes)
            .map_err(CommandError::from)?;
        self.store
            .insert_message_in(
                &conv,
                anon_storage::ConversationKind::Group,
                self_code.as_bytes(),
                now,
                &body,
            )
            .map_err(CommandError::from)?;

        let routes = self.member_onion_routes(&info.members);
        if !routes.is_empty() && self.messaging.can_send() {
            for route in &routes {
                let _ = self
                    .messaging
                    .send(route, conv, group.epoch(), &key, &mls_ct);
            }
        }

        Ok(DeliveryState::QueuedLocal)
    }

    fn member_onion_routes(&self, members: &[anon_mls::GroupMember]) -> Vec<PeerRoute> {
        let contacts = self.store.contacts().unwrap_or_default();
        let mut routes = Vec::new();
        for m in members {
            if m.is_self {
                continue;
            }
            let code_str = String::from_utf8_lossy(&m.identity).trim().to_string();
            if let Some(c) = contacts.iter().find(|c| c.contact_code == code_str) {
                if let Some(dn) = &c.display_name {
                    let onion_part = if let Some((_, o)) = dn.split_once('|') {
                        o.trim()
                    } else if dn.trim().ends_with(".onion") {
                        dn.trim()
                    } else {
                        ""
                    };
                    if let Ok(onion) = OnionId::parse(onion_part) {
                        routes.push(PeerRoute::onion(onion));
                    }
                }
            }
        }
        routes
    }

    /// The local user's contact code as MLS credential bytes.
    ///
    /// The MLS credential identity is the contact code (`plan.md` §2.2), not a display
    /// name, so a member list is a list of cryptographic identities.
    fn identity_bytes(&self) -> std::result::Result<Vec<u8>, CommandError> {
        Ok(self.contact_code()?.into_bytes())
    }

    /// Open an MLS provider over a secondary connection to the same encrypted store.
    ///
    /// A fresh connection per operation rather than a long-lived one: `MlsProvider`
    /// owns its `Connection` and is not `Clone`, and SQLite supports multiple
    /// connections to one file. The key is applied from the store's key ring, so no key
    /// material is handled here.
    fn group_provider(&self) -> std::result::Result<MlsProvider, CommandError> {
        let conn = self
            .store
            .open_secondary_connection()
            .map_err(CommandError::from)?;
        MlsProvider::new(conn).map_err(CommandError::from)
    }

    // -- Internal ----------------------------------------------------------

    /// The messaging service, for tests that need to exchange frames.
    pub fn messaging(&self) -> &MessagingService {
        &self.messaging
    }

    /// The store.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The consent gate, for tests.
    pub fn consent(&self) -> &ConsentGate {
        &self.consent
    }

    // -- Listing -----------------------------------------------------------

    /// Conversations for the sidebar (`plan.md` §7.3: `get_*` for rendered
    /// content).
    ///
    /// Returns metadata only. A label is derived, not stored: a direct
    /// conversation is labelled by its peer's contact label (when known) plus
    /// short fingerprint, which is what the user can verify out of band.
    pub fn conversations(&self) -> std::result::Result<Vec<ConversationView>, CommandError> {
        let rows = self.store.conversations().map_err(CommandError::from)?;
        let contacts = self.store.contacts().map_err(CommandError::from)?;
        let my_pub = self.identity.public();

        // Build the conversation-id -> label map once. The previous version decoded
        // every contact's `ContactCode` inside the loop over conversations, so the
        // work was O(conversations x contacts) with a curve25519 decode per
        // comparison. The webview calls this every 3 s, which made it the single
        // most expensive thing the app did while idle.
        let mut labels: std::collections::HashMap<Vec<u8>, String> =
            std::collections::HashMap::with_capacity(contacts.len());
        for c in &contacts {
            let Ok(code) = ContactCode::decode(&c.contact_code) else {
                continue;
            };
            let peer_pub = code.public_identity();
            let id = direct_conversation_id(&my_pub, &peer_pub);
            let short = short_fingerprint(c.contact_code.as_bytes());
            let label = match &c.display_name {
                Some(name) => {
                    let clean = name.split('|').next().unwrap_or("").trim();
                    if clean.is_empty() {
                        short
                    } else {
                        format!("{clean} ({short})")
                    }
                }
                None => short,
            };
            labels.insert(id.as_slice().to_vec(), label);
        }

        Ok(rows
            .into_iter()
            .filter(|r| r.kind == "direct")
            .map(|r| {
                let label = labels
                    .get(r.id.as_slice())
                    .cloned()
                    .unwrap_or_else(|| conversation_label(&r.kind, &r.peer_or_group));
                ConversationView {
                    id: hex_encode(&r.id),
                    kind: r.kind.clone(),
                    label,
                    expires_at: r.expires_at,
                    message_count: r.message_count,
                }
            })
            .collect())
    }

    /// Messages in one conversation, for the message pane.
    ///
    /// Each row is decrypted here so the webview receives display-ready text and
    /// the crypto-shredding check runs in Rust (`plan.md` §6.2). A message whose
    /// bucket was shredded is reported as unreadable rather than silently dropped,
    /// so the UI can show "purged" instead of a gap.
    pub fn messages(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<Vec<MessageView>, CommandError> {
        let (conversation, _version) = match conversation_id_bytes(conversation_id) {
            Ok(v) => v,
            Err(e) => {
                if let Ok(decoded) = ContactCode::decode(conversation_id.trim()) {
                    (
                        direct_conversation_id(&self.identity.public(), &decoded.public_identity()),
                        PROTOCOL_VERSION,
                    )
                } else if let Ok(gbytes) = decode_group_id(conversation_id) {
                    (group_conversation_id(&gbytes), PROTOCOL_VERSION)
                } else {
                    return Err(e);
                }
            }
        };
        let rows = self
            .store
            .messages_in(&conversation)
            .map_err(CommandError::from)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let body = match self.store.read_message(&row.id) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => "[purged]".to_string(),
            };
            out.push(MessageView {
                message_id: hex_encode(&row.id),
                sender_fingerprint: short_fingerprint(&row.sender),
                // The untruncated sender bytes, so the UI can attribute exactly.
                sender_code: String::from_utf8_lossy(&row.sender).to_string(),
                sent_at: row.sent_at,
                expires_at: row.expires_at,
                // Anything read back from local storage was, by definition, not
                // acknowledged by a peer — so this is the honest state.
                delivery: DeliveryState::QueuedLocal,
                body,
            });
        }
        Ok(out)
    }

    /// Known peers.
    pub fn peers(&self) -> std::result::Result<Vec<PeerView>, CommandError> {
        let rows = self.store.contacts().map_err(CommandError::from)?;
        Ok(rows
            .into_iter()
            .map(|r| PeerView {
                contact_code: r.contact_code,
                onion_short: r.display_name,
                added_at: r.added_at,
                verified: false,
            })
            .collect())
    }

    /// Add or update a peer contact by contact code (`plan.md` §4.3).
    ///
    /// Returns the deterministic 32-hex-character direct conversation id shared
    /// with this peer, plus the peer view.
    fn save_peer(
        &self,
        contact_code: &str,
        label: Option<String>,
    ) -> std::result::Result<(PeerView, String), CommandError> {
        let decoded = ContactCode::decode(contact_code)
            .map_err(|e| CommandError::from(IpcError::BadContactCode(e.to_string())))?;
        let canonical = decoded.to_code().map_err(CommandError::from)?;
        let peer_pub = decoded.public_identity();

        if peer_pub == self.identity.public() {
            return Err(CommandError::from(IpcError::BadContactCode(
                "cannot add your own contact code as a peer".to_string(),
            )));
        }

        let display_name = match label {
            Some(s) => {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else if t.chars().count() > 140 {
                    return Err(CommandError::from(IpcError::FieldTooLong("label")));
                } else {
                    Some(t.to_string())
                }
            }
            None => None,
        };

        let added_at = self.store.now();
        let row = anon_storage::ContactRow {
            contact_code: canonical.clone(),
            display_name: display_name.clone(),
            added_at,
            fingerprint: peer_pub.fingerprint(),
        };
        self.store
            .insert_contact(&row)
            .map_err(CommandError::from)?;

        let conv = direct_conversation_id(&self.identity.public(), &peer_pub);
        self.store
            .ensure_conversation(
                &conv,
                anon_storage::ConversationKind::Direct,
                canonical.as_bytes(),
            )
            .map_err(CommandError::from)?;
        Ok((
            PeerView {
                contact_code: canonical,
                onion_short: display_name,
                added_at,
                verified: false,
            },
            hex_encode(&conv),
        ))
    }

    /// Send an authenticated, X25519-encrypted direct message to a known peer (`plan.md` §3.2, §9).
    ///
    /// If `conversation_id` in `request` matches a known contact's deterministic
    /// direct conversation id, or if `conversation_id` is a contact code, this
    /// derives the X25519 shared key, signs the message envelope with the local
    /// Ed25519 identity key, transmits the padded frame over Tor, and records the
    /// sent message locally under the 90-day retention ceiling.
    pub fn send_direct(
        &self,
        request: &SendRequest,
    ) -> std::result::Result<DeliveryState, CommandError> {
        const MAX_BODY: usize = 520_000;
        if request.recipient_onion.trim().is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("recipient_onion")));
        }
        if request.body.is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("body")));
        }
        if request.body.len() > MAX_BODY {
            return Err(CommandError::from(IpcError::FieldTooLong("body")));
        }
        let body = anon_messaging::attachment::sanitize_body(request.body.as_bytes())?;

        // A transport that is merely *not ready yet* (bootstrapping, or the peer's
        // onion service not published) is a delay, not a failure: the frame is
        // queued and retried. A transport that can never carry the frame — no Tor
        // backend compiled in — is a real refusal, because queueing it would only
        // promise a delivery that cannot happen.
        if !self.messaging.can_send() && !self.messaging.can_queue() {
            let reason = self
                .messaging
                .send_unavailable_reason()
                .unwrap_or_else(|| "sending is unavailable".to_string());
            return Err(CommandError::from(IpcError::SendUnavailable(reason)));
        }

        let onion = OnionId::parse(&request.recipient_onion)
            .map_err(|_| CommandError::from(IpcError::BadOnion(request.recipient_onion.clone())))?;

        let peer_pub = self.resolve_peer_for_conversation(&request.conversation_id)?;
        let conv = direct_conversation_id(&self.identity.public(), &peer_pub);
        let peer_code = ContactCode::encode(&peer_pub).map_err(CommandError::from)?;
        self.store
            .ensure_conversation(
                &conv,
                anon_storage::ConversationKind::Direct,
                peer_code.as_bytes(),
            )
            .map_err(CommandError::from)?;
        let key = derive_direct_key(&self.identity, &peer_pub, &conv, request.epoch);

        let now = self.store.now();
        let envelope = encode_direct_envelope(&self.identity, &conv, request.epoch, now, &body);

        let route = PeerRoute::onion(onion);
        // `send_or_queue` keeps the sealed frame on this device when the peer is
        // unreachable, so an offline recipient is a delay rather than a loss. The
        // message is recorded locally either way, so the sender's own history is
        // complete even while the frame is still queued.
        let report = self
            .messaging
            .send_or_queue(
                &route,
                conv,
                request.epoch,
                &key,
                &envelope,
                self.store.expiry_for(now),
            )
            .map_err(CommandError::from)?;

        let self_code = self.contact_code().map_err(CommandError::from)?;
        self.store
            .insert_message(&conv, self_code.as_bytes(), now, &body)
            .map_err(CommandError::from)?;

        Ok(map_outcome(report.outcome))
    }

    fn resolve_peer_for_conversation(
        &self,
        id_or_code: &str,
    ) -> std::result::Result<anon_core::PublicIdentity, CommandError> {
        let trimmed = id_or_code.trim();
        if trimmed.is_empty() {
            return Err(CommandError::from(IpcError::EmptyField("conversation_id")));
        }

        // First: if the user pasted a contact code directly, decode it and ensure it is in contacts.
        if let Ok(decoded) = ContactCode::decode(trimmed) {
            let peer_pub = decoded.public_identity();
            if peer_pub == self.identity.public() {
                return Err(CommandError::from(IpcError::BadContactCode(
                    "cannot message your own contact code".to_string(),
                )));
            }
            let canonical = decoded.to_code().map_err(CommandError::from)?;
            let row = anon_storage::ContactRow {
                contact_code: canonical,
                display_name: None,
                added_at: self.store.now(),
                fingerprint: peer_pub.fingerprint(),
            };
            self.store
                .insert_contact(&row)
                .map_err(CommandError::from)?;
            return Ok(peer_pub);
        }

        // Otherwise, interpret as 32-hex conversation id and match against known contacts.
        let (target_conv, _) = conversation_id_bytes(trimmed)?;
        let contacts = self.store.contacts().map_err(CommandError::from)?;
        let my_pub = self.identity.public();
        for c in contacts {
            if let Ok(code) = ContactCode::decode(&c.contact_code) {
                let peer_pub = code.public_identity();
                if direct_conversation_id(&my_pub, &peer_pub) == target_conv {
                    return Ok(peer_pub);
                }
            }
        }

        Err(CommandError::from(IpcError::BadContactCode(
            "no known peer contact matches this conversation; add the peer's contact code first"
                .to_string(),
        )))
    }

    /// Process raw bytes received from an inbound transport stream.
    pub fn process_inbound_payload(&self, bytes: &[u8]) -> std::result::Result<bool, CommandError> {
        Self::handle_inbound_bytes(&self.identity, &self.store, &self.messaging, bytes)
    }

    fn handle_inbound_bytes(
        identity: &IdentityKeys,
        store: &Store,
        messaging: &MessagingService,
        bytes: &[u8],
    ) -> std::result::Result<bool, CommandError> {
        let frame =
            Frame::decode(bytes).map_err(|e| CommandError::from(IpcError::Messaging(e.into())))?;
        let conv = frame.conversation();
        let epoch = frame.epoch();

        let contacts = store.contacts().map_err(CommandError::from)?;
        let my_pub = identity.public();

        for c in contacts {
            let Ok(code) = ContactCode::decode(&c.contact_code) else {
                continue;
            };
            let peer_pub = code.public_identity();
            if direct_conversation_id(&my_pub, &peer_pub) != conv {
                continue;
            }

            let key = derive_direct_key(identity, &peer_pub, &conv, epoch);
            let Ok(envelope) = frame.open(&key) else {
                return Err(CommandError::from(IpcError::Messaging(
                    anon_messaging::FrameError::AuthFailed.into(),
                )));
            };

            // If the payload carries the signed direct envelope, verify the Ed25519 signature
            // and store only the inner message body.
            if let Ok((sent_at, body)) =
                decode_and_verify_direct_envelope(&peer_pub, &conv, epoch, &envelope)
            {
                // Durable replay check: the in-memory set is lost on restart, so
                // the store's seen-frames table is the authority across relaunches.
                let now = store.now();
                if !messaging.outbox().observe(frame.id()) {
                    return Ok(false);
                }
                if !store
                    .observe_frame(frame.id().as_bytes(), now)
                    .unwrap_or(false)
                {
                    return Ok(false);
                }
                // Retention is computed from *our* receive time, not the
                // sender's claim. The old code clamped a stale sent_at up to
                // now-300s and used it for expiry, so replaying an old frame
                // renewed its 90-day window on every attempt. The clamped value
                // is now display/ordering only; expiry comes from `now`.
                let effective_sent = sent_at.clamp(now.saturating_sub(300), now);
                let expires_at = store.expiry_for(now);
                store
                    .insert_message_with_expiry(
                        &conv,
                        anon_storage::ConversationKind::Direct,
                        c.contact_code.as_bytes(),
                        effective_sent,
                        expires_at,
                        &body,
                    )
                    .map_err(CommandError::from)?;
                return Ok(true);
            }
        }

        // 2. Otherwise, check if the frame belongs to a local MLS group.
        if let Ok(groups) = store.groups() {
            for g in groups {
                if group_conversation_id(&g.group_id) != conv {
                    continue;
                }
                let key = derive_group_frame_key(&g.group_id, &conv, epoch);
                let Ok(mls_ct) = frame.open(&key) else {
                    continue;
                };
                if !messaging.outbox().observe(frame.id()) {
                    return Ok(false);
                }
                let now = store.now();
                if !store
                    .observe_frame(frame.id().as_bytes(), now)
                    .unwrap_or(false)
                {
                    return Ok(false);
                }
                let Ok(conn) = store.open_secondary_connection() else {
                    return Ok(false);
                };
                let Ok(provider) = MlsProvider::new(conn) else {
                    return Ok(false);
                };
                let Ok(Some(mut mls_group)) = Group::load(&provider, &g.group_id) else {
                    return Ok(false);
                };
                match mls_group.decrypt(&provider, &mls_ct) {
                    Ok(plaintext) => {
                        if let Ok((sent_at, sender_code, body)) = decode_group_envelope(&plaintext)
                        {
                            if body.starts_with(GROUP_ROLE_CONTROL_PREFIX) {
                                // Role changes are authorized, not just
                                // authenticated: the plaintext proves who *sent*
                                // the frame, but only an owner or admin may
                                // change a role. Without this check any group
                                // member could promote themselves to owner by
                                // sending one control frame.
                                let sender_role = store
                                    .group_role(&g.group_id, sender_code.trim())
                                    .ok()
                                    .flatten()
                                    .unwrap_or_else(|| "member".to_string())
                                    .to_lowercase();
                                if sender_role != "owner" && sender_role != "admin" {
                                    return Ok(true);
                                }
                                let rest = String::from_utf8_lossy(
                                    &body[GROUP_ROLE_CONTROL_PREFIX.len()..],
                                );
                                if let Some((target_code, new_role)) = rest.split_once('|') {
                                    let _ = store.set_group_role(
                                        &g.group_id,
                                        target_code.trim(),
                                        new_role.trim(),
                                    );
                                }
                                return Ok(true);
                            }
                            let now = store.now();
                            // Same rule as direct messages: expiry from receive
                            // time, clamped sent_at for display only.
                            let effective_sent = sent_at.clamp(now.saturating_sub(300), now);
                            let expires_at = store.expiry_for(now);
                            let _ = store.ensure_conversation(
                                &conv,
                                anon_storage::ConversationKind::Group,
                                &g.group_id,
                            );
                            store
                                .insert_message_with_expiry(
                                    &conv,
                                    anon_storage::ConversationKind::Group,
                                    sender_code.as_bytes(),
                                    effective_sent,
                                    expires_at,
                                    &body,
                                )
                                .map_err(CommandError::from)?;
                            return Ok(true);
                        }
                    }
                    Err(anon_mls::MlsError::NotApplicationMessage) => {
                        // A staged MLS Commit was merged, advancing the group's epoch.
                        let _ = store.update_group_epoch(&g.group_id, mls_group.epoch());
                        return Ok(true);
                    }
                    Err(_) => {}
                }
            }
        }

        Ok(false)
    }

    // -- Consent surface for the modal -------------------------------------

    /// The outstanding consent prompt, if any.
    ///
    /// Returns `None` when nothing is pending. The nonce is *not* re-issued: the
    /// handle recorded at draft time is returned, so a modal refresh cannot mint a
    /// second approval path (`plan.md` §5.2).
    pub fn pending_consent(&self) -> Option<ConsentPrompt> {
        let pending = self.pending_prompt.lock().unwrap().clone()?;
        Some(ConsentPrompt {
            proposal: pending.0,
            nonce_handle: pending.1,
        })
    }

    /// Draft a rotation and remember it as the pending prompt.
    ///
    /// Wraps [`Backend::draft_rotation`] so the modal has a single "pending"
    /// proposal to render rather than a list the UI would have to reconcile.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_pending_rotation(
        &self,
        group_id: &str,
        group_name: &str,
        reason: anon_consent::RotationReason,
        epoch_after: u64,
        member_count: u32,
        now: i64,
        ttl_seconds: i64,
    ) -> std::result::Result<ConsentPrompt, CommandError> {
        let prompt = self.draft_rotation(
            group_id,
            group_name,
            reason,
            epoch_after,
            member_count,
            now,
            ttl_seconds,
        )?;
        *self.pending_prompt.lock().unwrap() =
            Some((prompt.proposal.clone(), prompt.nonce_handle.clone()));
        Ok(prompt)
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.messaging.transport().shutdown();
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("transport", &self.messaging.transport().status())
            .field("display_name", &"<omitted>")
            .finish_non_exhaustive()
    }
}

fn map_outcome(outcome: anon_messaging::DeliveryOutcome) -> DeliveryState {
    use anon_messaging::DeliveryOutcome as O;
    match outcome {
        O::QueuedLocal => DeliveryState::QueuedLocal,
        O::DeliveredToMailbox => DeliveryState::AtMailbox,
        O::DeliveredToPeer => DeliveryState::Delivered,
        O::ReadByPeer => DeliveryState::Read,
    }
}

fn proposal_view(p: &RotationProposal) -> ProposalView {
    ProposalView {
        proposal_id: p.id().as_str().to_string(),
        group_id: p.group_id().to_string(),
        group_name: p.group_name().to_string(),
        reason: p.reason().label().to_string(),
        epoch_before: p.epoch_before(),
        epoch_after: p.epoch_after(),
        member_count: p.member_count(),
        expires_at: p.expires_at(),
        content_hash: p.content_hash(),
        is_blocking: p.is_blocking(),
        prompt_text: p.prompt_text(),
    }
}

/// How long a drafted rotation stays decidable.
///
/// `plan.md` §5.1's bounded-wait requirement: a proposal that is never answered must
/// expire as a *decision*, not linger forever. 24 hours is long enough that a user who
/// steps away can still answer, and short enough that a stale epoch does not persist
/// for days.
const PROPOSAL_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Validate a group display name.
///
/// Same rules as `set_display_name`: non-empty after trimming, at most 64 characters.
/// Kept as one function so the two limits cannot drift apart — a name that is legal
/// for the identity panel must be legal for a group.
fn validate_group_name(name: &str) -> std::result::Result<String, CommandError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CommandError::from(IpcError::EmptyField("name")));
    }
    if trimmed.chars().count() > 64 {
        return Err(CommandError::from(IpcError::FieldTooLong("name")));
    }
    Ok(trimmed.to_string())
}

/// Decode a hex group id into raw bytes.
///
/// A group id is an MLS `GroupId`, whose length is not fixed by the protocol. The
/// bound here is a sanity limit, not a protocol rule: an id longer than 64 bytes is
/// not something this app creates, and accepting one would mean trusting an arbitrary
/// blob from the webview as a storage key.
fn decode_group_id(hex: &str) -> std::result::Result<Vec<u8>, CommandError> {
    let trimmed = hex.trim();
    if trimmed.is_empty() {
        return Err(CommandError::from(IpcError::EmptyField("group_id")));
    }
    let bytes = decode_hex(trimmed).map_err(|_| {
        CommandError::from(IpcError::BadGroupId(
            "the group id must be hexadecimal".to_string(),
        ))
    })?;
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(CommandError::from(IpcError::BadGroupId(
            "the group id must be between 1 and 64 bytes".to_string(),
        )));
    }
    Ok(bytes)
}

/// Decode a hex string into bytes. Returns `Err(())` for odd length or non-hex.
fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?);
    }
    Ok(out)
}

/// Lowercase hex, for ids crossing the boundary.
///
/// The webview gets hex strings rather than raw bytes so a DTO stays plain JSON
/// and cannot be mistaken for a binary handle.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A short, display-safe fingerprint from raw sender bytes.
///
/// Sender bytes are a contact code or a fingerprint; either way the UI only needs
/// enough to distinguish speakers. Truncating here keeps the boundary payload
/// small and avoids implying the short form is verifiable.
fn short_fingerprint(sender: &[u8]) -> String {
    let text = String::from_utf8_lossy(sender);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let head: String = trimmed.chars().take(12).collect();
    if trimmed.chars().count() > 12 {
        format!("{head}…")
    } else {
        head
    }
}

/// A label for a conversation row.
///
/// Derived rather than stored: a direct conversation is labelled by its peer's
/// short fingerprint, which is the value the user can verify out of band. A group
/// is labelled by its group id, since group names are local metadata the store does
/// not currently carry.
fn conversation_label(kind: &str, peer_or_group: &[u8]) -> String {
    let short = short_fingerprint(peer_or_group);
    match kind {
        "group" => format!("group {short}"),
        _ => short,
    }
}

/// Convert the hex conversation id from the webview into raw bytes.
fn conversation_id_bytes(hex: &str) -> std::result::Result<([u8; 16], u8), CommandError> {
    let trimmed = hex.trim();
    if trimmed.len() != 32 {
        return Err(CommandError::from(IpcError::BadContactCode(
            "conversation id must be 32 hex characters".to_string(),
        )));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &trimmed[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            CommandError::from(IpcError::BadContactCode(
                "conversation id must be hexadecimal".to_string(),
            ))
        })?;
    }
    Ok((out, PROTOCOL_VERSION))
}

/// Build a frame for tests without going through the transport.
pub fn seal_for_test(
    key: &[u8; 32],
    conversation: [u8; 16],
    epoch: u64,
    body: &[u8],
) -> Result<Frame> {
    Frame::seal(key, conversation, epoch, body).map_err(|e| IpcError::Messaging(e.into()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn signed_invites_enable_restricted_contacts_and_reject_tampering() {
        let onion = anon_transport::OnionId::parse(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion",
        )
        .unwrap();
        let alice = Backend::new(
            IdentityKeys::from_seed(&[81; 32]),
            Arc::new(anon_transport::MockTransport::tor_like(onion.clone())),
            test_store("privacy-alice"),
        );
        let bob = Backend::new(
            IdentityKeys::from_seed(&[82; 32]),
            Arc::new(anon_transport::MockTransport::tor_like(onion)),
            test_store("privacy-bob"),
        );
        alice.initialize_privacy(true).unwrap();
        bob.initialize_privacy(true).unwrap();
        let invite = alice.export_invite().unwrap();
        assert!(bob.add_peer(&alice.contact_code().unwrap(), None).is_err());
        assert!(bob.add_peer(&invite.replace("vww6", "aww6"), None).is_err());
        assert!(bob.store.contacts().unwrap().is_empty());
        bob.add_peer(&invite, Some("Alice".into())).unwrap();
        assert_eq!(bob.privacy_view().unwrap().legacy_contacts, 0);
        assert!(bob.privacy_view().unwrap().restricted_discovery);
        assert!(!invite.contains("secret"));
        bob.initialize_privacy(false).unwrap();
        assert!(bob.privacy_view().unwrap().restricted_discovery);
        assert!(!bob.privacy_view().unwrap().traffic_shaping);
        assert!(bob.set_traffic_shaping(true).unwrap().traffic_shaping);
        assert!(!bob.set_traffic_shaping(false).unwrap().traffic_shaping);
    }

    #[test]
    fn the_display_name_survives_a_restart() {
        let store = test_store("name-persist");
        let backend = Backend::new(
            IdentityKeys::from_seed(&[85; 32]),
            Arc::new(anon_transport::OfflineTransport::new("test")),
            Arc::clone(&store),
        );
        assert_eq!(backend.identity_view().unwrap().display_name, None);
        backend.set_display_name(Some("Jared".into())).unwrap();

        // Simulate a restart: a new backend over the same store path.
        let path = store.path().to_owned();
        drop(backend);
        drop(store);
        let reopened = test_store_at(&path);
        let backend2 = Backend::new(
            IdentityKeys::from_seed(&[85; 32]),
            Arc::new(anon_transport::OfflineTransport::new("test")),
            reopened,
        );
        assert_eq!(
            backend2.identity_view().unwrap().display_name,
            Some("Jared".to_string())
        );

        // Clearing persists too.
        backend2.set_display_name(None).unwrap();
        assert_eq!(backend2.identity_view().unwrap().display_name, None);
    }

    #[test]
    fn the_invite_carries_the_signed_name_and_the_recipient_adopts_it() {
        let onion = anon_transport::OnionId::parse(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion",
        )
        .unwrap();
        let alice = Backend::new(
            IdentityKeys::from_seed(&[86; 32]),
            Arc::new(MockTransport::tor_like(onion.clone())),
            test_store("invite-name-alice"),
        );
        let bob = Backend::new(
            IdentityKeys::from_seed(&[87; 32]),
            Arc::new(MockTransport::tor_like(onion.clone())),
            test_store("invite-name-bob"),
        );
        alice.initialize_privacy(true).unwrap();
        bob.initialize_privacy(true).unwrap();
        alice.set_display_name(Some("Alice P".into())).unwrap();

        let invite = alice.export_invite().unwrap();
        assert!(invite.contains("Alice P"), "the name travels in the invite");

        // Tampering with the signed name must fail signature verification.
        let tampered = invite.replace("Alice P", "Eve E");
        assert!(bob.add_peer(&tampered, None).is_err());

        // A local label wins over the signed name.
        bob.add_peer(&invite, Some("My alias".into())).unwrap();
        let contacts = bob.store.contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(
            contacts[0].display_name.as_deref(),
            Some("My alias|vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
        );

        // With no local label, the signed name is adopted.
        let carol = Backend::new(
            IdentityKeys::from_seed(&[88; 32]),
            Arc::new(MockTransport::tor_like(onion)),
            test_store("invite-name-carol"),
        );
        carol.initialize_privacy(true).unwrap();
        carol.add_peer(&invite, None).unwrap();
        let contacts = carol.store.contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(
            contacts[0]
                .display_name
                .as_deref()
                .unwrap_or("")
                .starts_with("Alice P|"),
            "the signed name is adopted when no local label is given, got {:?}",
            contacts[0].display_name
        );
    }

    use super::*;
    use anon_storage::{Argon2Params, Store, StoreConfig};
    use anon_transport::MockTransport;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn privacy_migration_requires_upgraded_contacts_and_survives_reopening() {
        let onion = anon_transport::OnionId::parse(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion",
        )
        .unwrap();
        let legacy = Backend::new(
            IdentityKeys::from_seed(&[83; 32]),
            Arc::new(MockTransport::tor_like(onion.clone())),
            test_store("privacy-legacy"),
        );
        let peer = Backend::new(
            IdentityKeys::from_seed(&[84; 32]),
            Arc::new(MockTransport::tor_like(onion.clone())),
            test_store("privacy-upgraded"),
        );
        legacy.initialize_privacy(false).unwrap();
        assert!(!legacy.privacy_view().unwrap().restricted_discovery);
        assert!(!legacy.privacy_view().unwrap().traffic_shaping);
        legacy
            .add_peer(&peer.contact_code().unwrap(), None)
            .unwrap();
        assert_eq!(legacy.privacy_view().unwrap().legacy_contacts, 1);
        assert!(legacy.enable_restricted_discovery().is_err());
        assert!(legacy.set_traffic_shaping(true).is_err());
        legacy
            .add_peer(&peer.export_invite().unwrap(), None)
            .unwrap();
        legacy.enable_restricted_discovery().unwrap();
        legacy.set_traffic_shaping(true).unwrap();
        let path = legacy.store.path().to_owned();
        drop(legacy);
        let store = Store::open(
            &path,
            "test-passphrase-1234",
            StoreConfig {
                params: Argon2Params::test_fast(),
                purge_on_open: false,
                vacuum_after_purge: false,
            },
        )
        .unwrap();
        let reopened = Backend::new(
            IdentityKeys::from_seed(&[83; 32]),
            Arc::new(MockTransport::tor_like(onion)),
            Arc::new(store),
        );
        reopened.initialize_privacy(false).unwrap();
        let view = reopened.privacy_view().unwrap();
        assert!(view.restricted_discovery && view.traffic_shaping);
        assert_eq!(view.legacy_contacts, 0);
        assert_eq!(reopened.store.contacts().unwrap().len(), 1);
    }

    #[test]
    fn privacy_shaping_caps_contacts_without_silently_changing_policy() {
        let onion = anon_transport::OnionId::parse(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion",
        )
        .unwrap();
        let backend = Backend::new(
            IdentityKeys::from_seed(&[85; 32]),
            Arc::new(MockTransport::tor_like(onion.clone())),
            test_store("privacy-cap"),
        );
        backend.initialize_privacy(true).unwrap();
        backend.set_traffic_shaping(true).unwrap();
        for index in 0..5u8 {
            let peer = Backend::new(
                IdentityKeys::from_seed(&[90 + index; 32]),
                Arc::new(MockTransport::tor_like(onion.clone())),
                test_store(&format!("privacy-cap-{index}")),
            );
            let invite = peer.export_invite().unwrap();
            if index < 4 {
                backend.add_peer(&invite, None).unwrap();
            } else {
                assert!(backend.add_peer(&invite, None).is_err());
                assert_eq!(backend.store.contacts().unwrap().len(), 4);
                assert!(backend.privacy_view().unwrap().traffic_shaping);
                backend.set_traffic_shaping(false).unwrap();
                backend.add_peer(&invite, None).unwrap();
                assert!(backend.set_traffic_shaping(true).is_err());
                assert!(!backend.privacy_view().unwrap().traffic_shaping);
            }
        }
    }

    fn image_attachment() -> String {
        let image = image::RgbImage::from_pixel(64, 48, image::Rgb([40, 100, 180]));
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .encode_image(&image)
            .unwrap();
        jpeg.extend_from_slice(b"private camera serial");
        format!(
            "{}{}",
            anon_messaging::attachment::ATTACHMENT_PREFIX,
            serde_json::json!({
                "name": "Alice-camera-serial.jpg", "mime": "image/jpeg", "size": jpeg.len(),
                "dataUrl": format!("data:image/jpeg;base64,{}", STANDARD.encode(jpeg)),
                "caption": "photo"
            })
        )
    }

    fn assert_clean_attachment(body: &str) {
        let payload = body
            .strip_prefix(anon_messaging::attachment::ATTACHMENT_PREFIX)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(value["name"], "image.jpg");
        assert_eq!(value["caption"], "photo");
        let bytes = STANDARD
            .decode(
                value["dataUrl"]
                    .as_str()
                    .unwrap()
                    .split_once(',')
                    .unwrap()
                    .1,
            )
            .unwrap();
        assert!(!bytes.windows(7).any(|part| part == b"private"));
        let image = image::load_from_memory(&bytes).unwrap();
        assert!(image.width() < 64 && image.height() < 48);
    }

    fn test_store(tag: &str) -> Arc<Store> {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "anon-ipc-direct-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Arc::new(open_store_at(&p.join("test.db")))
    }

    /// Open a store at an existing path, as a restart would.
    fn test_store_at(path: &std::path::Path) -> Arc<Store> {
        Arc::new(open_store_at(path))
    }

    fn open_store_at(path: &std::path::Path) -> Store {
        let config = StoreConfig {
            params: Argon2Params::test_fast(),
            purge_on_open: false,
            vacuum_after_purge: false,
        };
        let mut store = Store::open(path, "test-passphrase-1234", config).unwrap();
        store.freeze_clock_at(1_700_000_000);
        store
    }

    #[test]
    fn direct_x25519_key_and_conversation_id_are_symmetric() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();

        let conv_ab = direct_conversation_id(&alice.public(), &bob.public());
        let conv_ba = direct_conversation_id(&bob.public(), &alice.public());
        assert_eq!(conv_ab, conv_ba);

        let key_ab = derive_direct_key(&alice, &bob.public(), &conv_ab, 0);
        let key_ba = derive_direct_key(&bob, &alice.public(), &conv_ba, 0);
        assert_eq!(*key_ab, *key_ba);

        // And a third party derives a completely different key.
        let mallory = IdentityKeys::generate().unwrap();
        let key_ma = derive_direct_key(&mallory, &alice.public(), &conv_ab, 0);
        assert_ne!(*key_ab, *key_ma);
    }

    #[test]
    fn two_backends_exchange_authenticated_direct_messages_over_transport() {
        let onion_a =
            OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
                .unwrap();
        let onion_b =
            OnionId::parse("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
                .unwrap();

        let trans_a = Arc::new(MockTransport::tor_like(onion_a));
        let trans_b = Arc::new(MockTransport::tor_like(onion_b.clone()));

        let alice = Backend::new(
            IdentityKeys::generate().unwrap(),
            trans_a.clone(),
            test_store("alice"),
        );
        let bob = Backend::new(
            IdentityKeys::generate().unwrap(),
            trans_b.clone(),
            test_store("bob"),
        );

        let alice_code = alice.contact_code().unwrap();
        let bob_code = bob.contact_code().unwrap();

        // Bob registers Alice as a contact so Bob's inbound handler knows Alice's keys.
        let (_, conv_hex_bob) = bob.add_peer(&alice_code, Some("Alice".into())).unwrap();

        // Alice sends to Bob using Bob's contact code directly in `conversation_id`.
        let state = alice
            .send_direct(&SendRequest {
                conversation_id: bob_code.clone(),
                recipient_onion: onion_b.as_str().to_string(),
                epoch: 0,
                body: "hello over authenticated onion".to_string(),
            })
            .unwrap();
        assert_eq!(state, DeliveryState::QueuedLocal);

        // Deliver the wire bytes from Alice's transport into Bob's inbound handler.
        let delivered = trans_a.take_delivered();
        assert_eq!(delivered.len(), 1);
        trans_b.inject_inbound(delivered[0].1.clone());

        // Bob now has the conversation and the verified message plaintext.
        let convs = bob.conversations().unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].id, conv_hex_bob);

        let msgs = bob.messages(&conv_hex_bob).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "hello over authenticated onion");

        // Replaying the exact same frame is ignored.
        trans_b.inject_inbound(delivered[0].1.clone());
        assert_eq!(bob.messages(&conv_hex_bob).unwrap().len(), 1);

        let mut request = SendRequest {
            conversation_id: bob_code,
            recipient_onion: onion_b.as_str().to_string(),
            epoch: 0,
            body: format!(
                "{}{{\"dataUrl\":\"data:image/jpeg;base64,JVBERi0xLjc=\"}}",
                anon_messaging::attachment::ATTACHMENT_PREFIX
            ),
        };
        assert_eq!(
            alice.send_direct(&request).unwrap_err().code,
            "unsafe_attachment"
        );
        assert!(trans_a.take_delivered().is_empty());
        assert_eq!(alice.messages(&conv_hex_bob).unwrap().len(), 1);

        request.body = image_attachment();
        alice.send_direct(&request).unwrap();
        let delivered = trans_a.take_delivered();
        assert_eq!(delivered.len(), 1);
        trans_b.inject_inbound(delivered[0].1.clone());
        let received = bob.messages(&conv_hex_bob).unwrap();
        let sent = alice.messages(&conv_hex_bob).unwrap();
        let received = received
            .iter()
            .find(|message| {
                message
                    .body
                    .starts_with(anon_messaging::attachment::ATTACHMENT_PREFIX)
            })
            .unwrap();
        assert_clean_attachment(&received.body);
        assert!(sent.iter().any(|message| message.body == received.body));
        assert_ne!(received.body, request.body);
    }

    #[test]
    fn a_stale_sent_at_does_not_renew_retention() {
        let onion_a =
            OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
                .unwrap();
        let onion_b =
            OnionId::parse("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
                .unwrap();
        let trans_a = Arc::new(MockTransport::tor_like(onion_a));
        let trans_b = Arc::new(MockTransport::tor_like(onion_b.clone()));
        let alice = Backend::new(
            IdentityKeys::generate().unwrap(),
            trans_a.clone(),
            test_store("stale-alice"),
        );
        let bob = Backend::new(
            IdentityKeys::generate().unwrap(),
            trans_b.clone(),
            test_store("stale-bob"),
        );
        bob.add_peer(&alice.contact_code().unwrap(), None).unwrap();

        // Alice sends a message whose envelope claims it was sent 30 days ago.
        // The clamp keeps it at now-300s for display, but the old code derived
        // expiry from that clamped value — so replaying the frame renewed the
        // 90-day window each time. Expiry must come from receive time instead.
        let stale_sent_at = bob.store.now() - 30 * 86_400;
        let conv = direct_conversation_id(&alice.identity.public(), &bob.identity.public());
        let key = derive_direct_key(&alice.identity, &bob.identity.public(), &conv, 0);
        let body = encode_direct_envelope(
            &alice.identity,
            &conv,
            0,
            stale_sent_at,
            b"old but replayed",
        );
        let frame = Frame::seal(&key, conv, 0, &body).unwrap();
        trans_b.inject_inbound(frame.encode());

        let conv_hex = hex_encode(&conv);
        let msgs = bob.messages(&conv_hex).unwrap();
        assert_eq!(msgs.len(), 1, "the frame is accepted once");

        // The stored expiry is anchored to receive time, not the sender's claim:
        // it must be ~90 days from NOW, not from 30 days ago.
        let expected_floor = bob.store.expiry_for(bob.store.now()) - 86_400;
        assert!(
            msgs[0].expires_at >= expected_floor,
            "expiry is anchored to receive time, got {} want >= {}",
            msgs[0].expires_at,
            expected_floor
        );

        // Replaying the same frame changes nothing — and, critically, does not
        // push the expiry further out.
        trans_b.inject_inbound(frame.encode());
        let msgs_after = bob.messages(&conv_hex).unwrap();
        assert_eq!(msgs_after.len(), 1, "the replay is rejected");
        assert_eq!(
            msgs_after[0].expires_at, msgs[0].expires_at,
            "a replay does not renew retention"
        );
    }

    #[test]
    fn a_role_change_from_a_non_admin_is_ignored() {
        let onion =
            OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
                .unwrap();
        let transport = Arc::new(MockTransport::tor_like(onion.clone()));
        let alice = Backend::new(
            IdentityKeys::generate().unwrap(),
            transport.clone(),
            test_store("role-alice"),
        );
        let mallory = Backend::new(
            IdentityKeys::generate().unwrap(),
            transport.clone(),
            test_store("role-mallory"),
        );
        let view = alice.create_group("team").unwrap();
        let group_id = decode_group_id(&view.group_id).unwrap();

        // Mallory is a member (joined via Welcome), not an admin.
        let alice_provider = alice.group_provider().unwrap();
        let mallory_provider = mallory.group_provider().unwrap();
        let mut group = Group::load(&alice_provider, &group_id).unwrap().unwrap();
        let key_package = Group::key_package(
            &mallory_provider,
            mallory.contact_code().unwrap().as_bytes(),
        )
        .unwrap();
        let added = group.add_members(&alice_provider, &[key_package]).unwrap();
        Group::join_from_welcome(&mallory_provider, &added.welcome).unwrap();

        // Mallory sends a role-control frame promoting himself to owner.
        let conv = group_conversation_id(&group_id);
        let key = derive_group_frame_key(&group_id, &conv, group.epoch());
        let promote = format!(
            "{}{}|owner",
            String::from_utf8_lossy(GROUP_ROLE_CONTROL_PREFIX),
            mallory.contact_code().unwrap()
        );
        let plaintext = encode_group_envelope(
            alice.store.now(),
            &mallory.contact_code().unwrap(),
            promote.as_bytes(),
        );
        let frame = Frame::seal(&key, conv, group.epoch(), &plaintext).unwrap();
        transport.inject_inbound(frame.encode());

        // The promotion is ignored: Mallory's recorded role is unchanged.
        let role = alice
            .store
            .group_role(&group_id, &mallory.contact_code().unwrap())
            .unwrap();
        assert_ne!(
            role.as_deref(),
            Some("owner"),
            "a member cannot promote himself with a control frame"
        );
    }

    #[test]
    fn group_attachments_are_sanitized_before_mls_and_storage() {
        let onion =
            OnionId::parse("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
                .unwrap();
        let transport = Arc::new(MockTransport::tor_like(onion.clone()));
        let alice = Backend::new(
            IdentityKeys::generate().unwrap(),
            transport.clone(),
            test_store("attachment-group-alice"),
        );
        let bob = Backend::new(
            IdentityKeys::generate().unwrap(),
            transport.clone(),
            test_store("attachment-group-bob"),
        );
        alice
            .add_peer(
                &bob.contact_code().unwrap(),
                Some(format!("Bob|{}", onion.as_str())),
            )
            .unwrap();
        let view = alice.create_group("photos").unwrap();
        let group_id = decode_group_id(&view.group_id).unwrap();
        let alice_provider = alice.group_provider().unwrap();
        let bob_provider = bob.group_provider().unwrap();
        let mut group = Group::load(&alice_provider, &group_id).unwrap().unwrap();
        let key_package =
            Group::key_package(&bob_provider, bob.contact_code().unwrap().as_bytes()).unwrap();
        let added = group.add_members(&alice_provider, &[key_package]).unwrap();
        let mut bob_group = Group::join_from_welcome(&bob_provider, &added.welcome).unwrap();
        let conversation = group_conversation_id(&group_id);
        let conversation_hex = hex_encode(&conversation);
        let epoch = group.epoch();
        let invalid = format!(
            "{}{{\"dataUrl\":\"data:application/pdf;base64,JVBERi0xLjc=\"}}",
            anon_messaging::attachment::ATTACHMENT_PREFIX
        );
        assert_eq!(
            alice
                .send_group_message(&view.group_id, &invalid)
                .unwrap_err()
                .code,
            "unsafe_attachment"
        );
        assert!(transport.take_delivered().is_empty());
        assert!(alice.messages(&conversation_hex).unwrap().is_empty());
        assert_eq!(
            Group::load(&alice_provider, &group_id)
                .unwrap()
                .unwrap()
                .epoch(),
            epoch
        );

        alice
            .send_group_message(&view.group_id, &image_attachment())
            .unwrap();
        let delivered = transport.take_delivered();
        assert_eq!(delivered.len(), 1);
        let frame = Frame::decode(&delivered[0].1).unwrap();
        let ciphertext = frame
            .open(&derive_group_frame_key(&group_id, &conversation, epoch))
            .unwrap();
        let envelope = bob_group.decrypt(&bob_provider, &ciphertext).unwrap();
        let sent = alice.messages(&conversation_hex).unwrap();
        assert_eq!(sent.len(), 1);
        assert_clean_attachment(&sent[0].body);
        assert_eq!(
            envelope,
            encode_group_envelope(
                alice.store.now(),
                &alice.contact_code().unwrap(),
                sent[0].body.as_bytes()
            )
        );
    }
}
