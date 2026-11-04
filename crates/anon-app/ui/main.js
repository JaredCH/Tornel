// The webview's entire interaction with the backend.
//
// plan.md §7.3: presentation and consent only. This file contains no
// cryptography, no key material, and no database access. It calls a small,
// fixed set of commands and renders what comes back. Every value it receives is
// a plain DTO from anon-ipc, which cannot carry a secret by construction.
//
// The command surface is deliberately tiny and enumerated here so it is
// reviewable in one screen:
//
//   identity_view()            -> IdentityView
//   set_display_name(name)     -> ()
//   transport_view()           -> TransportView
//   conversations()            -> ConversationView[]
//   messages(conversation_id)  -> MessageView[]
//   send_message(req)          -> DeliveryState
//   draft_rotation(...)        -> ConsentPrompt
//   submit_consent(sub)        -> ConsentOutcome
//   export_escrow(passphrase)  -> hex string (the user saves it; we do not)
//   note_escrow_exported()     -> ()
//   groups()                   -> GroupView[]
//   create_group(name)         -> GroupView
//   group_members(group_id)    -> GroupMemberView[]
//   add_member(group_id, kp)   -> AddMemberOutcome
//   remove_member(gid, leaf)   -> RemoveMemberOutcome
//
// The launch screen (Gap 2) exposes the following vault commands:
//
//   vault_view()                       -> VaultView
//   assess_strength(candidate)         -> StrengthView
//   create_vault(passphrase, confirm)  -> VaultView
//   unlock_vault(passphrase)           -> VaultView
//   migrate_vault(passphrase, confirm) -> VaultView
//
// Persona listing, creation, and opening are also available while locked.
// Messaging and identity commands return a `locked` error until unlock succeeds. That is the
// enforcement: the app cannot read a message or send one without the passphrase, because
// there is no backend to call.

// The Tauri bridge. `withGlobalTauri` must be true in tauri.conf.json for this
// object to be injected — without it every command would fail silently and the
// page would render placeholder dashes forever. Failing loudly here is better
// than a UI that looks alive but cannot talk to Rust.
if (!window.__TAURI__) {
  document.addEventListener("DOMContentLoaded", () => {
    const line = document.getElementById("status-line");
    line.textContent =
      "Tauri bridge not injected. Set \"withGlobalTauri\": true in tauri.conf.json and rebuild.";
    line.classList.add("error");
  });
  throw new Error("window.__TAURI__ is undefined: the IPC bridge was not injected");
}

const { invoke } = window.__TAURI__.core;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

/** Render an error without ever dumping a stack or an internal path. */
function showError(target, err) {
  const message = typeof err === "string" ? err : err?.message ?? "unknown error";
  const code = err?.code ? `[${err.code}] ` : "";
  target.textContent = `${code}${message}`;
  target.classList.add("error");
}

function clearError(target) {
  target.textContent = "";
  target.classList.remove("error");
}

/** Format epoch seconds as a short local date. */
function when(epochSeconds) {
  if (!epochSeconds) return "—";
  const d = new Date(epochSeconds * 1000);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// The launch screen (Gap 2: user-held database passphrase)
// ---------------------------------------------------------------------------
//
// The app cannot open its database without the user's passphrase, so this runs before
// anything else. It asks Rust which of four states the install is in and shows the
// matching screen. Nothing here decides policy — the vault does — this only routes and
// renders.
//
// The passphrase is read from the input, passed straight to Rust, and the input is
// cleared immediately afterwards. It is never assigned to a module-level variable, never
// put in localStorage, and never logged. That matters: a passphrase left in a JS variable
// survives until the page reloads, and a passphrase in localStorage survives until the
// user clears it.

/** The launch screen's element handles. */
const launch = {
  root: () => $("launch"),
  setup: () => $("launch-setup"),
  unlock: () => $("launch-unlock"),
  interrupted: () => $("launch-interrupted"),
  blocked: () => $("launch-blocked"),
};

/** Hide every launch sub-screen. */
function hideLaunchScreens() {
  launch.setup().hidden = true;
  launch.unlock().hidden = true;
  launch.interrupted().hidden = true;
  launch.blocked().hidden = true;
}

/**
 * Show the launch screen for a vault state.
 *
 * Called at startup and again after a failed attempt, so the screen always reflects what
 * Rust says rather than what the page assumed.
 */
function renderLaunch(view) {
  launch.root().hidden = false;
  $("app").hidden = true;
  hideLaunchScreens();

  // A blocked launch has no useful action to offer, so it is checked first: showing a
  // passphrase screen would invite the user to type a passphrase that cannot be used.
  if (view.state === "blocked") {
    launch.blocked().hidden = false;
    $("blocked-reason").textContent = view.blocked_reason ?? "startup failed";
    return;
  }

  if (view.state === "interrupted_migration") {
    launch.interrupted().hidden = false;
    $("interrupted-stage").textContent = view.migration_stage ?? "unknown";
    $("interrupted-passphrase").focus();
    return;
  }

  if (view.is_setup) {
    launch.setup().hidden = false;
    // A migration and a fresh install both ask the user to choose a passphrase, but the
    // explanation differs and the user deserves to know which one they are in. An
    // existing install being told "choose a passphrase" without being told *why* reads as
    // "your data is gone".
    if (view.state === "needs_migration") {
      $("setup-title").textContent = "Choose a passphrase for this device";
      $("setup-explain").textContent =
        "This device already has a database, encrypted with a key the app generated for " +
        "you. Choose a passphrase to replace it. Your messages are kept — the change is " +
        "made on a copy and verified before anything is replaced.";
    } else {
      $("setup-title").textContent = "Choose a passphrase";
      $("setup-explain").textContent =
        "This passphrase protects your message history on this device. It is never " +
        "stored, so you will enter it on every launch.";
    }
    // Take the minimum from Rust rather than hardcoding it. The placeholder used to say
    // "16+ characters" while the policy enforced 12, so the screen contradicted the rule
    // it was describing.
    if (view.min_chars) {
      $("setup-passphrase").placeholder = `Vault passphrase (${view.min_chars}+ characters)`;
    }
    $("setup-passphrase").focus();
    return;
  }

  launch.unlock().hidden = false;
  $("unlock-passphrase").focus();
}

/** Hide the launch screen and show the app. */
function enterApp() {
  launch.root().hidden = true;
  $("app").hidden = false;
  // Start the display refresh loops now rather than at DOMContentLoaded: while locked,
  // every command returns a `locked` error and the status line would fill with noise.
  startRefreshLoops();
}

/**
 * Ask Rust for the vault state and render the matching screen.
 *
 * Returns the state so the caller can decide whether to enter the app.
 */
async function refreshLaunch() {
  const view = await invoke("vault_view");
  renderLaunch(view);
  return view;
}

/**
 * Update the strength hint as the user types.
 *
 * Debounced: the assessment runs Argon2-free heuristics in Rust, but calling across the
 * IPC boundary on every keystroke would still be wasteful. 150 ms is short enough to feel
 * live and long enough to skip most intermediate states.
 */
let strengthTimer = null;
function scheduleStrengthCheck() {
  clearTimeout(strengthTimer);
  strengthTimer = setTimeout(async () => {
    const candidate = $("setup-passphrase").value;
    const box = $("strength");
    if (!candidate) {
      box.hidden = true;
      return;
    }
    try {
      const view = await invoke("assess_strength", { candidate });
      box.hidden = false;

      // The bar is a coarse visual: entropy saturates at 128 bits, which is well past
      // "strong enough". Showing a bar that never fills would be discouraging; showing
      // one that fills at 40 bits would be dishonest.
      const pct = Math.min(100, Math.round((view.entropy_bits / 128) * 100));
      const fill = $("strength-fill");
      fill.style.width = `${pct}%`;

      // Colour from *acceptance*, not from entropy. A long-but-obvious passphrase
      // ("passwordpassword") has high estimated entropy and is still refused by the
      // vault, so colouring by entropy alone produced a green bar over a rejected
      // passphrase. The bar must never look better than the policy allows.
      //
      // `acceptable` is the vault's own answer, so the bar cannot contradict the
      // button. A passphrase that is merely *warned* about (a long unit repeated
      // twice) is acceptable and shows as such; only a refusal turns the bar weak.
      fill.dataset.level = !view.acceptable
        ? "weak"
        : view.entropy_bits >= 80
          ? "strong"
          : "fair";

      $("strength-text").textContent = view.acceptable
        ? `Estimated ${view.entropy_bits} bits — acceptable.`
        : `Estimated ${view.entropy_bits} bits — not yet acceptable.`;

      const list = $("strength-warnings");
      list.innerHTML = "";
      for (const w of view.warnings) {
        const li = document.createElement("li");
        li.textContent = w;
        list.appendChild(li);
      }
    } catch (err) {
      box.hidden = true;
    }
  }, 150);
}

/** Submit the setup form (fresh install or migration). */
let setupInFlight = false;
async function submitSetup() {
  if (setupInFlight) return;
  const result = $("setup-result");
  clearError(result);

  const passphrase = $("setup-passphrase").value;
  const confirm = $("setup-confirm").value;

  // Clear the inputs before awaiting: if the call fails, the values are already gone from
  // the DOM. The user retypes, which is a small cost against leaving a passphrase sitting
  // in an input element.
  $("setup-passphrase").value = "";
  $("setup-confirm").value = "";
  $("strength").hidden = true;

  setupInFlight = true;
  $("setup-submit").disabled = true;
  result.textContent = "Setting up encrypted database (Argon2id)…";
  result.classList.remove("error");

  try {
    const view = await invoke("vault_view");
    const command = view.state === "needs_migration" ? "migrate_vault" : "create_vault";
    const next = await invoke(command, { passphrase, confirm });
    renderLaunch(next);
    if (!next.is_setup) {
      enterApp();
      await refreshAll();
    }
  } catch (err) {
    showError(result, err);
    // Re-render so the screen reflects the current state — a failed migration may have
    // changed it.
    try {
      renderLaunch(await invoke("vault_view"));
    } catch {
      /* the state read failed too; the error above is the useful one */
    }
  } finally {
    setupInFlight = false;
    $("setup-submit").disabled = false;
  }
}

/** Submit the unlock form. */
let unlockInFlight = false;
async function submitUnlock() {
  if (unlockInFlight) return;
  const result = $("unlock-result");
  clearError(result);

  const passphrase = $("unlock-passphrase").value;
  $("unlock-passphrase").value = "";

  unlockInFlight = true;
  $("unlock-submit").disabled = true;
  result.textContent = "Unlocking database (Argon2id)…";
  result.classList.remove("error");

  try {
    const next = await invoke("unlock_vault", { passphrase });
    renderLaunch(next);
    enterApp();
    await refreshAll();
  } catch (err) {
    showError(result, err);
    $("unlock-passphrase").focus();
  } finally {
    unlockInFlight = false;
    $("unlock-submit").disabled = false;
  }
}

/** Submit the interrupted-migration form. */
async function submitInterrupted() {
  const result = $("interrupted-result");
  clearError(result);

  const passphrase = $("interrupted-passphrase").value;
  $("interrupted-passphrase").value = "";

  try {
    // The interrupted screen asks for the *new* passphrase. The old one is either the
    // machine-held secret (which the app reads itself) or the previous user passphrase,
    // which the user must supply — so this screen asks for both when the marker says the
    // swap had not happened yet.
    const next = await invoke("unlock_vault", { passphrase });
    renderLaunch(next);
    enterApp();
    await refreshAll();
  } catch (err) {
    showError(result, err);
  }
}

// ---------------------------------------------------------------------------
// App State (Presentation only; no secrets)
// ---------------------------------------------------------------------------

let selfContactCode = "";
let selfContactShort = "";
let selfOnionAddress = "";
let selfDisplayName = "";
let cachedPeers = [];
let cachedConversations = [];
let cachedGroups = [];
let cachedGroupMembers = [];
let selectedConversationId = null;
let selectedGroupId = null;
let activeSidebarFilter = "all";
let sidebarSearchQuery = "";
let stagedAttachment = null; // { name, mime, size, dataUrl }
let stagedGroupAttachment = null; // { name, mime, size, dataUrl }

async function updateInviteBundleDisplay() {
  const el = $("invite-bundle");
  if (!el) return;
  if (selfContactCode && selfOnionAddress && selfOnionAddress.endsWith(".onion")) {
    try {
      el.textContent = await invoke("export_invite");
    } catch {
      el.textContent = "Invite unavailable";
    }
  } else if (selfContactCode) {
    el.textContent = `${selfContactCode} (waiting for .onion…)`;
  } else {
    el.textContent = "waiting for Tor…";
  }
}

function openModal(modalId) {
  if (modalId === "modal-identity") {
    refreshPrivacy();
    refreshPersonas();
  }
  const backdrop = $("modal-backdrop");
  if (!backdrop) return;
  backdrop.hidden = false;
  for (const card of backdrop.querySelectorAll(".modal-card")) {
    card.hidden = card.id !== modalId;
  }
}

function closeModals() {
  const backdrop = $("modal-backdrop");
  if (!backdrop) return;
  backdrop.hidden = true;
  for (const card of backdrop.querySelectorAll(".modal-card")) {
    card.hidden = true;
  }
}

// ---------------------------------------------------------------------------
// Transport status
// ---------------------------------------------------------------------------

async function refreshTransport() {
  const el = $("transport");
  const text = $("transport-text");
  const banner = $("banner");

  try {
    const view = await invoke("transport_view");
    // Sending stays enabled while the transport is merely *not ready yet*: the
    // frame is queued and retried, so disabling the button would hide a working
    // path. It is disabled only when the transport can never carry a frame.
    const queueable = view.anonymity === "tor_onion";
    $("send").disabled = (!view.can_send && !queueable) || sendInFlight;
    el.dataset.state = view.status;
    text.textContent =
      view.status === "ready"
        ? view.can_send
          ? "Tor Online"
          : "Tor Publishing…"
        : `${view.status}`;

    if (view.queued_count > 0) {
      text.textContent += ` · ${view.queued_count} queued`;
    }

    if (view.can_send) {
      banner.hidden = true;
      $("banner-title").textContent = "";
      $("banner-reason").textContent = "";
    } else {
      banner.hidden = false;
      $("banner-title").textContent = "Tor Onion Status:";
      $("banner-reason").textContent =
        view.blocked_reason ?? "the transport is not ready";
    }

    selfOnionAddress = view.local_onion ?? "";
    $("status-line").textContent = view.local_onion_short
      ? view.can_send
        ? `${view.local_onion_short}….onion (online)`
        : `${view.local_onion_short}….onion (publishing…)`
      : "starting embedded Arti Tor…";
    if ($("local-onion")) {
      $("local-onion").textContent = view.local_onion ?? "waiting for Tor bootstrap…";
    }
    updateInviteBundleDisplay();
  } catch (err) {
    $("send").disabled = true;
    el.dataset.state = "failed";
    text.textContent = "offline";
    banner.hidden = false;
    $("banner-title").textContent = "Cannot read transport status.";
    showError($("banner-reason"), err);
  }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

async function refreshIdentity() {
  try {
    const view = await invoke("identity_view");
    selfContactCode = view.contact_code;
    selfContactShort = `${view.contact_code.slice(0, 12)}…`;
    selfDisplayName = view.display_name ?? "";

    $("contact-code").textContent = view.contact_code;
    $("fingerprint").textContent = view.fingerprint;
    $("display-name").value = selfDisplayName;

    if ($("sidebar-display-name")) {
      $("sidebar-display-name").textContent = selfDisplayName || "Anonymous";
    }
    if ($("sidebar-fingerprint")) {
      $("sidebar-fingerprint").textContent = view.fingerprint;
    }
    if ($("self-avatar")) {
      $("self-avatar").textContent = (selfDisplayName || "A").trim().charAt(0).toUpperCase();
    }

    const escrow = $("escrow-state");
    escrow.textContent = view.escrow_exported
      ? "✓ an escrow artifact has been exported"
      : "no escrow artifact exported yet";
    escrow.classList.toggle("done", view.escrow_exported);
    updateInviteBundleDisplay();
  } catch (err) {
    showError($("status-line"), err);
  }
}

async function saveDisplayName() {
  const name = $("display-name").value.trim();
  try {
    await invoke("set_display_name", { name: name === "" ? null : name });
    await refreshIdentity();
    $("status-line").textContent = "display name saved";
  } catch (err) {
    showError($("status-line"), err);
  }
}

async function copyTextWithFallback(text, elementId, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    $("status-line").textContent = successMessage;
  } catch {
    const el = $(elementId);
    if (el) {
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
    $("status-line").textContent = "select and copy the highlighted text";
  }
}

async function copyContactCode() {
  await copyTextWithFallback($("contact-code").textContent, "contact-code", "contact code copied");
}

async function copyLocalOnion() {
  if (!selfOnionAddress || !selfOnionAddress.endsWith(".onion")) {
    $("status-line").textContent = "onion service not ready yet";
    return;
  }
  await copyTextWithFallback(selfOnionAddress, "local-onion", "onion address copied");
}

async function copyInviteBundle() {
  try {
    const bundle = await invoke("export_invite");
    $("invite-bundle").textContent = bundle;
    await copyTextWithFallback(bundle, "invite-bundle", "signed invite copied");
  } catch (error) {
    showError($("status-line"), error);
  }
}

async function exportEscrow() {
  const passphrase = $("escrow-passphrase").value;
  const note = $("escrow-note");
  clearError(note);

  if (!passphrase.trim()) {
    note.textContent = "Enter a passphrase first.";
    note.classList.add("error");
    return;
  }

  try {
    const artifact = await invoke("export_escrow", { passphrase });
    const blob = new Blob([hexToBytes(artifact)], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "anon-escrow.bin";
    a.click();
    URL.revokeObjectURL(url);

    await invoke("note_escrow_exported");
    await refreshIdentity();
    note.textContent =
      "Artifact downloaded. Store it somewhere safe — it is the only way to restore this identity.";
    $("escrow-passphrase").value = "";
  } catch (err) {
    showError(note, err);
  }
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Friends (Peers) & Direct Conversations
// ---------------------------------------------------------------------------

function splitLabelAndOnion(stored) {
  if (!stored) return { label: null, onion: null };
  const idx = stored.indexOf("|");
  if (idx !== -1) {
    const label = stored.slice(0, idx).trim();
    const onion = stored.slice(idx + 1).trim();
    return { label: label || null, onion: onion || null };
  }
  if (stored.trim().endsWith(".onion")) {
    return { label: null, onion: stored.trim() };
  }
  return { label: stored.trim(), onion: null };
}

/** Parse a pasted invite string like `anon1...@xyz.onion#Alice` into { code, onion, label }. */
function parseInviteInput(raw) {
  let text = (raw || "").trim();
  if (text.startsWith("tornel1:")) return { code: text, onion: null, label: null, signed: true };
  let label = null;
  const hashIdx = text.indexOf("#");
  if (hashIdx !== -1) {
    try {
      label = decodeURIComponent(text.slice(hashIdx + 1).trim());
    } catch {
      label = text.slice(hashIdx + 1).trim();
    }
    text = text.slice(0, hashIdx).trim();
  }
  const atIdx = text.indexOf("@");
  if (atIdx !== -1) {
    const code = text.slice(0, atIdx).trim();
    const onion = text.slice(atIdx + 1).trim();
    return { code, onion, label };
  }
  return { code: text, onion: null, label };
}

function findPeerForConversation(conv) {
  if (!conv) return null;
  for (const p of cachedPeers) {
    const shortCode = `${p.contact_code.slice(0, 12)}…`;
    if (conv.label.includes(shortCode) || conv.id === p.contact_code) {
      return p;
    }
  }
  if (cachedPeers.length === 1 && cachedConversations.length === 1) {
    return cachedPeers[0];
  }
  return null;
}

function applySidebarFilter() {
  const chatsSec = $("sidebar-section-chats");
  const groupsSec = $("sidebar-section-groups");
  if (chatsSec) {
    chatsSec.hidden = activeSidebarFilter === "groups";
  }
  if (groupsSec) {
    groupsSec.hidden = activeSidebarFilter === "friends";
  }
}

async function refreshPeers() {
  const list = $("peers");
  if (!list) return;
  try {
    const items = await invoke("peers");
    cachedPeers = items;
    list.innerHTML = "";

    const q = sidebarSearchQuery.toLowerCase();
    for (const p of items) {
      const shortCode = `${p.contact_code.slice(0, 12)}…`;
      // If a conversation already exists and is shown in #conversations for this peer,
      // only show in #peers when filtering by 'friends' so the 'All' list has no duplicate rows.
      const hasConv = cachedConversations.some((c) => c.label.includes(shortCode));
      if (hasConv && activeSidebarFilter === "all") {
        continue;
      }

      const parsed = splitLabelAndOnion(p.onion_short);
      const displayTitle = parsed.label ? parsed.label : shortCode;
      if (q && !displayTitle.toLowerCase().includes(q) && !p.contact_code.toLowerCase().includes(q)) {
        continue;
      }

      const li = document.createElement("li");
      const av = document.createElement("div");
      av.className = "item-avatar";
      av.textContent = displayTitle.charAt(0).toUpperCase();

      const body = document.createElement("div");
      body.className = "item-body";
      const label = document.createElement("div");
      label.className = "label";
      label.textContent = parsed.label ? `${parsed.label} (${shortCode})` : shortCode;
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = parsed.onion ? `🧅 ${parsed.onion.slice(0, 14)}….onion` : "Direct friend";
      body.append(label, meta);

      const activatePeer = async (e) => {
        if (e) e.stopPropagation();
        if (parsed.onion) {
          $("recipient-onion").value = parsed.onion;
        }
        await selectConversation(p.contact_code, label.textContent, parsed.onion);
      };
      li.addEventListener("click", activatePeer);
      li.append(av, body);
      list.appendChild(li);
    }
  } catch (err) {
    list.innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    showError(li, err);
    list.appendChild(li);
  }
}

async function addPeer() {
  const result = $("add-peer-result");
  clearError(result);

  const parsedInvite = parseInviteInput($("peer-contact-code").value);
  const contactCode = parsedInvite.code;
  const labelRaw = $("peer-label").value.trim() || parsedInvite.label || "";
  const onionRaw = ($("peer-onion") ? $("peer-onion").value.trim() : "") || parsedInvite.onion || "";

  if (!contactCode) {
    result.textContent = "Paste a peer contact code or invite bundle first.";
    result.classList.add("error");
    return;
  }

  let combinedLabel = null;
  if (labelRaw && onionRaw) {
    combinedLabel = `${labelRaw}|${onionRaw}`;
  } else if (onionRaw) {
    combinedLabel = `|${onionRaw}`;
  } else if (labelRaw) {
    combinedLabel = labelRaw;
  }

  try {
    const out = await invoke("add_peer", {
      contact_code: contactCode,
      label: parsedInvite.signed ? (labelRaw || null) : combinedLabel,
    });
    result.textContent = `friend saved · opening chat…`;
    result.classList.add("ok");
    $("peer-contact-code").value = "";
    $("peer-label").value = "";
    if ($("peer-onion")) $("peer-onion").value = "";
    const savedOnion = splitLabelAndOnion(out.peer.onion_short).onion || onionRaw;
    if (savedOnion) {
      $("recipient-onion").value = savedOnion;
    }
    closeModals();
    await refreshPeers();
    await refreshConversations();
    await selectConversation(
      out.conversation_id,
      labelRaw ? `${labelRaw} (${out.peer.contact_code.slice(0, 12)}…)` : `${out.peer.contact_code.slice(0, 12)}…`,
      savedOnion
    );
  } catch (err) {
    showError(result, err);
  }
}

async function selectConversation(conversationId, labelText, explicitOnion) {
  selectedConversationId = conversationId;
  selectedGroupId = null;

  $("chat-empty-state").hidden = true;
  $("group-detail").hidden = true;
  const detail = $("conversation-detail");
  detail.hidden = false;

  const title = labelText || "Direct Chat";
  $("conversation-detail-title").textContent = title;
  $("conversation-detail-id").textContent = conversationId;
  $("conversation-id").value = conversationId;
  if ($("chat-header-avatar")) {
    $("chat-header-avatar").textContent = title.trim().charAt(0).toUpperCase();
  }

  // Auto-populate peer's .onion route if known
  let resolvedOnion = explicitOnion || "";
  if (!resolvedOnion) {
    for (const p of cachedPeers) {
      const parsed = splitLabelAndOnion(p.onion_short);
      const shortCode = `${p.contact_code.slice(0, 12)}…`;
      if (parsed.onion && (title.includes(shortCode) || conversationId === p.contact_code)) {
        resolvedOnion = parsed.onion;
        break;
      }
    }
    if (!resolvedOnion && cachedPeers.length === 1) {
      const parsed = splitLabelAndOnion(cachedPeers[0].onion_short);
      if (parsed.onion) resolvedOnion = parsed.onion;
    }
  }
  if (resolvedOnion) {
    $("recipient-onion").value = resolvedOnion;
  }

  updateHeaderOnionPill();
  await refreshConversationMessages(conversationId);
  renderConversationsList();
  renderGroupsList();
}

function updateHeaderOnionPill() {
  const pill = $("chat-header-onion-status");
  if (!pill) return;
  const onion = $("recipient-onion").value.trim();
  if (onion && onion.endsWith(".onion")) {
    pill.textContent = `🧅 Route: ${onion.slice(0, 14)}….onion`;
    $("route-bar").hidden = true;
  } else {
    pill.textContent = "⚠️ Set peer .onion route to send";
    $("route-bar").hidden = false;
  }
}

// ---------------------------------------------------------------------------
// File / Image Attachment Encoding & Rendering
// ---------------------------------------------------------------------------

const ATTACHMENT_PREFIX = "ANON_ATTACHMENT_V1:";

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function stageSelectedFile(file) {
  if (!file) return;
  // Max raw size ~360 KB so base64 + JSON + envelope fits inside the 512 KiB padded Tor frame
  if (file.size > 360 * 1024) {
    showError($("send-result"), "Attachment exceeds 360 KB Tor single-frame limit.");
    return;
  }
  clearError($("send-result"));
  const reader = new FileReader();
  reader.onload = () => {
    stagedAttachment = {
      name: file.name,
      mime: file.type || "application/octet-stream",
      size: file.size,
      dataUrl: reader.result,
    };
    renderStagedAttachment();
  };
  reader.readAsDataURL(file);
}

function clearStagedAttachment() {
  stagedAttachment = null;
  if ($("file-input")) $("file-input").value = "";
  renderStagedAttachment();
}

function renderStagedAttachment() {
  const bar = $("attachment-staging");
  if (!bar) return;
  if (!stagedAttachment) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  $("attachment-name").textContent = stagedAttachment.name;
  $("attachment-meta").textContent = `${stagedAttachment.mime} · ${formatBytes(stagedAttachment.size)} (encrypted in Tor frame)`;
  const thumb = $("attachment-thumb");
  if (stagedAttachment.mime.startsWith("image/")) {
    thumb.src = stagedAttachment.dataUrl;
    thumb.hidden = false;
  } else {
    thumb.hidden = true;
  }
}

function buildMessageBody(text, attachment) {
  if (!attachment) return text;
  const payload = JSON.stringify({
    name: attachment.name,
    mime: attachment.mime,
    size: attachment.size,
    dataUrl: attachment.dataUrl,
    caption: text || "",
  });
  return `${ATTACHMENT_PREFIX}${payload}`;
}

function parseMessageBody(rawBody) {
  if (typeof rawBody === "string" && rawBody.startsWith(ATTACHMENT_PREFIX)) {
    try {
      const parsed = JSON.parse(rawBody.slice(ATTACHMENT_PREFIX.length));
      return {
        isAttachment: true,
        name: parsed.name || "attachment",
        mime: parsed.mime || "application/octet-stream",
        size: Number(parsed.size) || 0,
        dataUrl: typeof parsed.dataUrl === "string" ? parsed.dataUrl : "",
        caption: parsed.caption || "",
      };
    } catch {
      /* treat as normal text if malformed */
    }
  }
  return { isAttachment: false, text: rawBody };
}

async function refreshConversationMessages(conversationId) {
  const list = $("conversation-messages");
  if (!list) return;
  try {
    const items = await invoke("messages", { conversation_id: conversationId });
    list.innerHTML = "";
    if (!items.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "No messages yet. Say hello or share an image/file over Tor!";
      list.appendChild(li);
      return;
    }

    for (const m of items) {
      const isOutgoing =
        selfContactShort && m.sender_fingerprint === selfContactShort;
      const li = document.createElement("li");
      li.className = `msg-row ${isOutgoing ? "outgoing" : "incoming"}`;

      const bubble = document.createElement("div");
      bubble.className = "msg-bubble";

      const parsed = parseMessageBody(m.body);
      if (parsed.isAttachment && parsed.dataUrl.startsWith("data:")) {
        const attachWrap = document.createElement("div");
        attachWrap.className = "msg-attachment";

        if (parsed.mime.startsWith("image/")) {
          const img = document.createElement("img");
          img.src = parsed.dataUrl;
          img.alt = parsed.name;
          attachWrap.appendChild(img);
        }

        const card = document.createElement("div");
        card.className = "file-card";
        const icon = document.createElement("span");
        icon.className = "file-card-icon";
        icon.textContent = parsed.mime.startsWith("image/") ? "🖼️" : "📄";

        const meta = document.createElement("div");
        meta.className = "file-card-meta";
        const fname = document.createElement("div");
        fname.className = "file-card-name";
        fname.textContent = parsed.name;
        const fsize = document.createElement("div");
        fsize.className = "file-card-size";
        fsize.textContent = `${formatBytes(parsed.size)} · ${parsed.mime}`;
        meta.append(fname, fsize);

        const dl = document.createElement("a");
        dl.href = parsed.dataUrl;
        dl.download = parsed.name;
        dl.className = "ghost small-btn";
        dl.style.textDecoration = "none";
        dl.textContent = "Save";

        card.append(icon, meta, dl);
        attachWrap.appendChild(card);
        bubble.appendChild(attachWrap);

        if (parsed.caption) {
          const cap = document.createElement("div");
          cap.className = "msg-text";
          cap.textContent = parsed.caption;
          bubble.appendChild(cap);
        }
      } else {
        const textDiv = document.createElement("div");
        textDiv.className = "msg-text";
        textDiv.textContent = m.body;
        bubble.appendChild(textDiv);
      }

      const meta = document.createElement("div");
      meta.className = "msg-meta";
      const who = isOutgoing ? "You" : m.sender_fingerprint;
      meta.textContent = `${who} · ${when(m.sent_at)} · TTL ${when(m.expires_at)}`;

      li.append(bubble, meta);
      list.appendChild(li);
    }

    const scrollBox = $("messages-scroll");
    if (scrollBox) {
      scrollBox.scrollTop = scrollBox.scrollHeight;
    }
  } catch (err) {
    list.innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    showError(li, err);
    list.appendChild(li);
  }
}

function renderConversationsList() {
  const list = $("conversations");
  if (!list) return;
  list.innerHTML = "";

  const q = sidebarSearchQuery.toLowerCase();
  const filtered = cachedConversations.filter(
    (c) => !q || c.label.toLowerCase().includes(q) || c.id.toLowerCase().includes(q)
  );

  if (!filtered.length && !cachedPeers.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No chats yet — click '+ Add Friend'.";
    list.appendChild(li);
    return;
  }

  for (const c of filtered) {
    const li = document.createElement("li");
    if (selectedConversationId === c.id) {
      li.classList.add("selected");
    }

    const av = document.createElement("div");
    av.className = "item-avatar";
    av.textContent = (c.label || "C").trim().charAt(0).toUpperCase();

    const body = document.createElement("div");
    body.className = "item-body";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = c.label;
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${c.message_count} msg(s) · TTL ${when(c.expires_at)}`;
    body.append(label, meta);

    const activateConv = async (e) => {
      if (e) e.stopPropagation();
      const matchedPeer = findPeerForConversation(c);
      const parsed = matchedPeer ? splitLabelAndOnion(matchedPeer.onion_short) : { onion: null };
      await selectConversation(c.id, c.label, parsed.onion);
    };
    li.addEventListener("click", activateConv);
    li.append(av, body);
    list.appendChild(li);
  }
}

async function refreshConversations() {
  try {
    cachedConversations = await invoke("conversations");
    renderConversationsList();
    await refreshPeers();

    if (!selectedConversationId && !selectedGroupId && cachedConversations.length >= 1) {
      const first = cachedConversations[0];
      const matchedPeer = findPeerForConversation(first);
      const parsed = matchedPeer ? splitLabelAndOnion(matchedPeer.onion_short) : { onion: null };
      await selectConversation(first.id, first.label, parsed.onion);
      return;
    }
    if (selectedConversationId) {
      await refreshConversationMessages(selectedConversationId);
    }
  } catch (err) {
    const list = $("conversations");
    if (list) {
      list.innerHTML = "";
      const li = document.createElement("li");
      li.className = "empty";
      showError(li, err);
      list.appendChild(li);
    }
  }
}

let sendInFlight = false;
async function sendMessage() {
  if (sendInFlight) return;
  const result = $("send-result");
  clearError(result);

  const rawText = $("body").value;
  const finalBody = buildMessageBody(rawText, stagedAttachment);

  const request = {
    conversation_id: $("conversation-id").value.trim(),
    recipient_onion: $("recipient-onion").value.trim(),
    epoch: Number($("epoch").value) || 0,
    body: finalBody,
  };

  if (!request.recipient_onion) {
    $("route-bar").hidden = false;
    showError(result, "Enter the recipient's .onion address in the Route bar above.");
    $("recipient-onion").focus();
    return;
  }

  sendInFlight = true;
  $("send").disabled = true;
  result.textContent = "Routing encrypted frame over Tor v3 rendezvous…";
  result.classList.remove("error", "ok");

  try {
    const state = await invoke("send_message", { request });
    // "Queued" is not "delivered": say so plainly rather than showing a checkmark
    // for a frame that has not left the device yet (`plan.md` §8).
    const queued = state.code === "queued_local";
    result.textContent = queued
      ? `⏳ ${state.label} — will send when the peer is reachable`
      : `✓ ${state.label ?? state}`;
    result.classList.add(queued ? "hint" : "ok");
    $("body").value = "";
    clearStagedAttachment();
    await refreshConversations();
  } catch (err) {
    showError(result, err);
  } finally {
    sendInFlight = false;
    await refreshTransport();
  }
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

function renderGroupsList() {
  const list = $("groups");
  if (!list) return;
  list.innerHTML = "";

  const q = sidebarSearchQuery.toLowerCase();
  const filtered = cachedGroups.filter(
    (g) => !q || (g.name || "").toLowerCase().includes(q) || g.group_id.toLowerCase().includes(q)
  );

  if (!filtered.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No groups yet — click '+ Create Group'.";
    list.appendChild(li);
    return;
  }

  for (const g of filtered) {
    const li = document.createElement("li");
    if (selectedGroupId === g.group_id) {
      li.classList.add("selected");
    }

    const av = document.createElement("div");
    av.className = "item-avatar group-av";
    av.textContent = "#";

    const body = document.createElement("div");
    body.className = "item-body";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = g.name ?? "(unnamed group)";
    const meta = document.createElement("div");
    meta.className = "meta";
    const members =
      g.member_count === 0 ? "state unavailable" : `${g.member_count} member(s)`;
    meta.textContent = `epoch ${g.epoch} · ${members}`;
    body.append(label, meta);

    const activateGroup = async (e) => {
      if (e) e.stopPropagation();
      await selectGroup(g.group_id);
    };
    li.addEventListener("click", activateGroup);
    li.append(av, body);
    list.appendChild(li);
  }
}

async function refreshGroups() {
  try {
    cachedGroups = await invoke("groups");
    renderGroupsList();
  } catch (err) {
    const list = $("groups");
    if (list) {
      list.innerHTML = "";
      const li = document.createElement("li");
      li.className = "empty";
      showError(li, err);
      list.appendChild(li);
    }
  }
}

/** Show one group's chat + roles panel. */
async function selectGroup(groupId) {
  selectedGroupId = groupId;
  selectedConversationId = null;

  $("chat-empty-state").hidden = true;
  $("conversation-detail").hidden = true;
  const detail = $("group-detail");
  detail.hidden = false;

  clearError($("add-member-result"));
  clearError($("remove-member-result"));
  clearError($("role-change-result"));
  clearError($("group-send-result"));
  $("welcome-out").hidden = true;
  $("key-package").value = "";
  $("remove-leaf").value = "";

  try {
    const items = await invoke("groups");
    cachedGroups = items;
    renderGroupsList();
    renderConversationsList();
    const g = items.find((x) => x.group_id === groupId);
    if (!g) {
      detail.hidden = true;
      selectedGroupId = null;
      $("status-line").textContent = "that group no longer exists";
      return;
    }
    $("group-detail-title").textContent = g.name ?? "(unnamed group)";
    $("group-detail-id").textContent = g.group_id;
    $("group-detail-epoch").textContent = String(g.epoch);
    $("group-detail-count").textContent =
      g.member_count === 0 ? "state unavailable" : String(g.member_count);
    await refreshGroupMembers(groupId);
    await refreshGroupMessages(groupId);
  } catch (err) {
    showError($("status-line"), err);
  }
}

function roleLabel(role) {
  switch ((role || "member").toLowerCase()) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "moderator":
      return "Mod";
    default:
      return "Member";
  }
}

function makeRoleBadge(role) {
  const r = (role || "member").toLowerCase();
  const badge = document.createElement("span");
  badge.className = `role-badge role-${r}`;
  badge.textContent = roleLabel(r);
  return badge;
}

/** Render the member list and role management controls for one group. */
async function refreshGroupMembers(groupId) {
  const list = $("group-members");
  try {
    const members = await invoke("group_members", { group_id: groupId });
    cachedGroupMembers = members;
    list.innerHTML = "";
    if (!members.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "No members reported.";
      list.appendChild(li);
      return;
    }

    const selfMember = members.find((m) => m.is_self);
    const myRole = (selfMember?.role || "member").toLowerCase();
    const canManageRoles = myRole === "owner" || myRole === "admin";
    const canManageMembers = myRole === "owner" || myRole === "admin" || myRole === "moderator";

    const myBadge = $("group-my-role-badge");
    if (myBadge) {
      myBadge.className = `role-badge role-${myRole}`;
      myBadge.textContent = `Your role: ${roleLabel(myRole)}`;
    }
    if ($("group-admin-add-section")) {
      $("group-admin-add-section").hidden = !canManageMembers;
    }
    if ($("group-admin-remove-section")) {
      $("group-admin-remove-section").hidden = !canManageMembers;
    }

    for (const m of members) {
      const li = document.createElement("li");
      li.className = "member-role-item";

      const top = document.createElement("div");
      top.className = "member-role-top";

      const nameSpan = document.createElement("span");
      nameSpan.className = "member-role-name";
      const display = m.display_name
        ? `${m.display_name} (${m.contact_code_short})`
        : m.contact_code_short;
      nameSpan.textContent = m.is_self ? `${display} (you)` : display;

      top.append(nameSpan, makeRoleBadge(m.role));
      li.appendChild(top);

      const bottom = document.createElement("div");
      bottom.className = "member-role-controls";
      const leafMeta = document.createElement("span");
      leafMeta.className = "meta";
      leafMeta.textContent = `leaf ${m.leaf_index}`;
      bottom.appendChild(leafMeta);

      if (canManageRoles) {
        const select = document.createElement("select");
        select.className = "role-select";
        for (const r of ["owner", "admin", "moderator", "member"]) {
          const opt = document.createElement("option");
          opt.value = r;
          opt.textContent = roleLabel(r);
          if ((m.role || "member").toLowerCase() === r) {
            opt.selected = true;
          }
          select.appendChild(opt);
        }
        select.addEventListener("change", async () => {
          await changeMemberRole(groupId, m.leaf_index, select.value);
        });
        bottom.appendChild(select);
      }

      li.appendChild(bottom);
      list.appendChild(li);
    }
  } catch (err) {
    list.innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    showError(li, err);
    list.appendChild(li);
  }
}

async function changeMemberRole(groupId, leafIndex, newRole) {
  const result = $("role-change-result");
  clearError(result);
  try {
    await invoke("set_member_role", {
      group_id: groupId,
      leaf_index: leafIndex,
      role: newRole,
    });
    result.textContent = `updated leaf ${leafIndex} to ${roleLabel(newRole)}`;
    result.classList.add("ok");
    await refreshGroupMembers(groupId);
    await refreshGroupMessages(groupId);
  } catch (err) {
    showError(result, err);
    await refreshGroupMembers(groupId);
  }
}

function stageGroupFile(file) {
  if (!file) return;
  if (file.size > 360 * 1024) {
    showError($("group-send-result"), "Attachment exceeds 360 KB Tor single-frame limit.");
    return;
  }
  clearError($("group-send-result"));
  const reader = new FileReader();
  reader.onload = () => {
    stagedGroupAttachment = {
      name: file.name,
      mime: file.type || "application/octet-stream",
      size: file.size,
      dataUrl: reader.result,
    };
    renderStagedGroupAttachment();
  };
  reader.readAsDataURL(file);
}

function clearStagedGroupAttachment() {
  stagedGroupAttachment = null;
  if ($("group-file-input")) $("group-file-input").value = "";
  renderStagedGroupAttachment();
}

function renderStagedGroupAttachment() {
  const bar = $("group-attachment-staging");
  if (!bar) return;
  if (!stagedGroupAttachment) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  $("group-attachment-name").textContent = stagedGroupAttachment.name;
  $("group-attachment-meta").textContent = `${stagedGroupAttachment.mime} · ${formatBytes(stagedGroupAttachment.size)} (MLS encrypted)`;
  const thumb = $("group-attachment-thumb");
  if (stagedGroupAttachment.mime.startsWith("image/")) {
    thumb.src = stagedGroupAttachment.dataUrl;
    thumb.hidden = false;
  } else {
    thumb.hidden = true;
  }
}

async function refreshGroupMessages(groupId) {
  const list = $("group-messages");
  if (!list || !groupId) return;
  try {
    const items = await invoke("messages", { conversation_id: groupId });
    list.innerHTML = "";
    if (!items.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "No group messages yet — send an MLS-encrypted message or attachment below!";
      list.appendChild(li);
      return;
    }

    for (const m of items) {
      const isOutgoing = selfContactShort && m.sender_fingerprint === selfContactShort;
      const memberInfo = cachedGroupMembers.find(
        (gm) => gm.contact_code_short === m.sender_fingerprint || (isOutgoing && gm.is_self)
      );
      const memberRole = memberInfo?.role || (isOutgoing ? "owner" : "member");
      const senderLabel = isOutgoing
        ? `${selfDisplayName || "You"}`
        : memberInfo?.display_name
          ? `${memberInfo.display_name} (${m.sender_fingerprint})`
          : m.sender_fingerprint;

      const li = document.createElement("li");
      li.className = `msg-row ${isOutgoing ? "outgoing" : "incoming"}`;

      const bubble = document.createElement("div");
      bubble.className = "msg-bubble";

      const senderHeader = document.createElement("div");
      senderHeader.className = "msg-sender-header";
      const sName = document.createElement("span");
      sName.textContent = senderLabel;
      senderHeader.append(sName, makeRoleBadge(memberRole));
      bubble.appendChild(senderHeader);

      const parsed = parseMessageBody(m.body);
      if (parsed.isAttachment && parsed.dataUrl.startsWith("data:")) {
        const attachWrap = document.createElement("div");
        attachWrap.className = "msg-attachment";

        if (parsed.mime.startsWith("image/")) {
          const img = document.createElement("img");
          img.src = parsed.dataUrl;
          img.alt = parsed.name;
          attachWrap.appendChild(img);
        }

        const card = document.createElement("div");
        card.className = "file-card";
        const icon = document.createElement("span");
        icon.className = "file-card-icon";
        icon.textContent = parsed.mime.startsWith("image/") ? "🖼️" : "📄";

        const meta = document.createElement("div");
        meta.className = "file-card-meta";
        const fname = document.createElement("div");
        fname.className = "file-card-name";
        fname.textContent = parsed.name;
        const fsize = document.createElement("div");
        fsize.className = "file-card-size";
        fsize.textContent = `${formatBytes(parsed.size)} · ${parsed.mime}`;
        meta.append(fname, fsize);

        const dl = document.createElement("a");
        dl.href = parsed.dataUrl;
        dl.download = parsed.name;
        dl.className = "ghost small-btn";
        dl.style.textDecoration = "none";
        dl.textContent = "Save";

        card.append(icon, meta, dl);
        attachWrap.appendChild(card);
        bubble.appendChild(attachWrap);

        if (parsed.caption) {
          const cap = document.createElement("div");
          cap.className = "msg-text";
          cap.textContent = parsed.caption;
          bubble.appendChild(cap);
        }
      } else {
        const textDiv = document.createElement("div");
        textDiv.className = "msg-text";
        textDiv.textContent = m.body;
        bubble.appendChild(textDiv);
      }

      const meta = document.createElement("div");
      meta.className = "msg-meta";
      meta.textContent = `${when(m.sent_at)} · TTL ${when(m.expires_at)}`;

      li.append(bubble, meta);
      list.appendChild(li);
    }

    const scrollBox = $("group-messages-scroll");
    if (scrollBox) {
      scrollBox.scrollTop = scrollBox.scrollHeight;
    }
  } catch (err) {
    list.innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    showError(li, err);
    list.appendChild(li);
  }
}

let groupSendInFlight = false;
async function sendGroupMessage() {
  if (groupSendInFlight || !selectedGroupId) return;
  const result = $("group-send-result");
  clearError(result);

  const rawText = $("group-body").value;
  const finalBody = buildMessageBody(rawText, stagedGroupAttachment);
  if (!finalBody.trim()) {
    result.textContent = "Write a message or attach a file first.";
    result.classList.add("error");
    return;
  }

  groupSendInFlight = true;
  $("group-send").disabled = true;
  result.textContent = "Encrypting with MLS & fanning out over Tor…";
  result.classList.remove("error", "ok");

  try {
    const state = await invoke("send_group_message", {
      group_id: selectedGroupId,
      body: finalBody,
    });
    result.textContent = `✓ ${state.label ?? state}`;
    result.classList.add("ok");
    $("group-body").value = "";
    clearStagedGroupAttachment();
    await refreshGroupMessages(selectedGroupId);
  } catch (err) {
    showError(result, err);
  } finally {
    groupSendInFlight = false;
    $("group-send").disabled = false;
  }
}

/** Create a group from the name field. */
async function createGroup() {
  const result = $("create-group-result");
  clearError(result);
  const name = $("group-name").value.trim();

  if (!name) {
    result.textContent = "Enter a group name first.";
    result.classList.add("error");
    return;
  }

  try {
    const view = await invoke("create_group", { name });
    result.textContent = `created "${view.name}" at epoch ${view.epoch}`;
    result.classList.add("ok");
    $("group-name").value = "";
    closeModals();
    await refreshGroups();
    await selectGroup(view.group_id);
  } catch (err) {
    showError(result, err);
  }
}

/** Generate a single-use KeyPackage for joining a group. */
async function generateMyKeyPackage() {
  try {
    const hex = await invoke("generate_key_package");
    const box = $("my-key-package");
    box.value = hex;
    box.hidden = false;
    $("copy-kp-btn").hidden = false;
    await copyTextWithFallback(hex, "my-key-package", "single-use KeyPackage generated & copied!");
  } catch (err) {
    showError($("join-group-result"), err);
  }
}

async function copyMyKeyPackage() {
  const hex = $("my-key-package").value;
  if (!hex) return;
  await copyTextWithFallback(hex, "my-key-package", "KeyPackage copied!");
}

/** Join a group from a hex Welcome message. */
async function joinGroupFromWelcome() {
  const result = $("join-group-result");
  clearError(result);
  const name = $("join-group-name").value.trim();
  const welcomeHex = $("join-welcome-hex").value.trim();

  if (!name) {
    result.textContent = "Enter a local group name first.";
    result.classList.add("error");
    return;
  }
  if (!welcomeHex) {
    result.textContent = "Paste the Welcome hex from the group admin.";
    result.classList.add("error");
    return;
  }

  try {
    const view = await invoke("join_group", { name, welcome_hex: welcomeHex });
    result.textContent = `joined "${view.name}" at epoch ${view.epoch}`;
    result.classList.add("ok");
    $("join-group-name").value = "";
    $("join-welcome-hex").value = "";
    closeModals();
    await refreshGroups();
    await selectGroup(view.group_id);
  } catch (err) {
    showError(result, err);
  }
}

async function addMember() {
  const result = $("add-member-result");
  clearError(result);
  $("welcome-out").hidden = true;

  if (!selectedGroupId) {
    result.textContent = "Open a group first.";
    result.classList.add("error");
    return;
  }

  const keyPackage = $("key-package").value.trim();
  if (!keyPackage) {
    result.textContent = "Paste the invitee's key package first.";
    result.classList.add("error");
    return;
  }

  try {
    const outcome = await invoke("add_member", {
      group_id: selectedGroupId,
      key_package_hex: keyPackage,
    });

    result.textContent = `member added; the group is now at epoch ${outcome.epoch}`;
    result.classList.add("ok");

    $("welcome-hex").value = outcome.welcome_hex;
    $("welcome-out").hidden = false;
    $("key-package").value = "";

    await refreshGroups();
    await refreshGroupMembers(selectedGroupId);
    await refreshTransport();
  } catch (err) {
    showError(result, err);
  }
}

async function removeMember() {
  const result = $("remove-member-result");
  clearError(result);

  if (!selectedGroupId) {
    result.textContent = "Open a group first.";
    result.classList.add("error");
    return;
  }

  const raw = $("remove-leaf").value.trim();
  if (raw === "") {
    result.textContent = "Enter the leaf index of the member to remove.";
    result.classList.add("error");
    return;
  }
  const leafIndex = Number(raw);
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    result.textContent = "The leaf index must be a non-negative whole number.";
    result.classList.add("error");
    return;
  }

  try {
    const outcome = await invoke("remove_member", {
      group_id: selectedGroupId,
      leaf_index: leafIndex,
    });

    result.textContent = outcome.proposal
      ? `member removed; the group is now at epoch ${outcome.epoch}. ` +
        "Approve the rotation in the Consent prompt to restore forward secrecy."
      : `member removed; the group is now at epoch ${outcome.epoch}.`;
    result.classList.add("ok");
    $("remove-leaf").value = "";

    await refreshGroups();
    await refreshGroupMembers(selectedGroupId);
    await refreshConsent();
    if (outcome.proposal) {
      openModal("modal-consent");
    }
  } catch (err) {
    showError(result, err);
  }
}

async function copyWelcome() {
  const text = $("welcome-hex").value;
  try {
    await navigator.clipboard.writeText(text);
    $("status-line").textContent = "Welcome copied";
  } catch {
    $("welcome-hex").select();
    $("status-line").textContent = "select and copy the highlighted Welcome";
  }
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

let pendingPrompt = null;

async function refreshConsent() {
  const empty = $("consent-empty");
  const prompt = $("consent-prompt");
  const badgeBtn = $("open-consent-modal-btn");

  try {
    const p = await invoke("pending_consent");
    if (!p) {
      pendingPrompt = null;
      empty.hidden = false;
      prompt.hidden = true;
      if (badgeBtn) badgeBtn.hidden = true;
      return;
    }

    pendingPrompt = p;
    empty.hidden = true;
    prompt.hidden = false;
    if (badgeBtn) badgeBtn.hidden = false;

    const v = p.proposal;
    $("consent-text").textContent = v.prompt_text;
    $("consent-group").textContent = v.group_name;
    $("consent-reason").textContent = v.reason;
    $("consent-epoch").textContent = `${v.epoch_before} → ${v.epoch_after}`;
    $("consent-members").textContent = String(v.member_count);
    $("consent-expires").textContent = when(v.expires_at);
  } catch (err) {
    showError($("consent-result"), err);
  }
}

async function decideConsent(approved) {
  const result = $("consent-result");
  clearError(result);

  if (!pendingPrompt) {
    result.textContent = "No proposal to decide.";
    return;
  }

  try {
    const outcome = await invoke("submit_consent", {
      submission: {
        proposal_id: pendingPrompt.proposal.proposal_id,
        nonce_handle: pendingPrompt.nonce_handle,
        approved,
      },
    });
    result.textContent = `decision recorded: ${outcome}`;
    result.classList.add("ok");
    pendingPrompt = null;
    await refreshConsent();
    setTimeout(closeModals, 600);
  } catch (err) {
    showError(result, err);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wireSidebarFilters() {
  const tabs = document.querySelectorAll(".filter-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      activeSidebarFilter = tab.dataset.filter || "all";
      applySidebarFilter();
      refreshPeers();
    });
  });

  const searchInput = $("sidebar-search");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      sidebarSearchQuery = searchInput.value.trim();
      renderConversationsList();
      refreshPeers();
      renderGroupsList();
    });
  }
}

function wireModals() {
  document.querySelectorAll("[data-close-modal]").forEach((btn) => {
    btn.addEventListener("click", closeModals);
  });
  const backdrop = $("modal-backdrop");
  if (backdrop) {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) closeModals();
    });
  }

  $("btn-new-friend")?.addEventListener("click", () => openModal("modal-add-friend"));
  $("empty-add-friend")?.addEventListener("click", () => openModal("modal-add-friend"));
  $("btn-new-group")?.addEventListener("click", () => openModal("modal-create-group"));
  $("empty-create-group")?.addEventListener("click", () => openModal("modal-create-group"));
  $("btn-join-group")?.addEventListener("click", () => openModal("modal-join-group"));
  $("open-identity-btn")?.addEventListener("click", () => openModal("modal-identity"));
  $("open-profile-modal-btn")?.addEventListener("click", () => openModal("modal-identity"));
  $("open-consent-modal-btn")?.addEventListener("click", () => openModal("modal-consent"));

  // Auto-parse invite bundle when pasted into #peer-contact-code
  $("peer-contact-code")?.addEventListener("input", (e) => {
    const parsed = parseInviteInput(e.target.value);
    if (parsed.onion) {
      e.target.value = parsed.code;
      if ($("peer-onion")) $("peer-onion").value = parsed.onion;
      if (parsed.label && $("peer-label") && !$("peer-label").value) {
        $("peer-label").value = parsed.label;
      }
    }
  });
}

async function refreshAll() {
  await Promise.all([
    refreshTransport(),
    refreshIdentity(),
    refreshPeers(),
    refreshConversations(),
    refreshGroups(),
    refreshConsent(),
    refreshPrivacy(),
  ]);
}

window.addEventListener("DOMContentLoaded", async () => {
  wireSidebarFilters();
  wireModals();
  wirePrivacyControls();
  await refreshPersonas();

  $("copy-code")?.addEventListener("click", copyContactCode);
  $("copy-onion")?.addEventListener("click", copyLocalOnion);
  $("copy-invite-bundle")?.addEventListener("click", copyInviteBundle);
  $("quick-share-btn")?.addEventListener("click", copyInviteBundle);
  $("empty-share-invite")?.addEventListener("click", copyInviteBundle);

  $("save-name")?.addEventListener("click", saveDisplayName);
  $("export-escrow")?.addEventListener("click", exportEscrow);
  $("add-peer")?.addEventListener("click", addPeer);
  $("send")?.addEventListener("click", sendMessage);
  $("create-group")?.addEventListener("click", createGroup);
  $("generate-kp-btn")?.addEventListener("click", generateMyKeyPackage);
  $("copy-kp-btn")?.addEventListener("click", copyMyKeyPackage);
  $("join-group-submit")?.addEventListener("click", joinGroupFromWelcome);
  $("add-member")?.addEventListener("click", addMember);
  $("remove-member")?.addEventListener("click", removeMember);
  $("copy-welcome")?.addEventListener("click", copyWelcome);
  $("consent-approve")?.addEventListener("click", () => decideConsent(true));
  $("consent-deny")?.addEventListener("click", () => decideConsent(false));

  // Route bar toggle & live update
  $("toggle-route-bar")?.addEventListener("click", () => {
    const bar = $("route-bar");
    if (bar) bar.hidden = !bar.hidden;
  });
  $("recipient-onion")?.addEventListener("input", updateHeaderOnionPill);

  // Attachment picker & drag-and-drop
  $("attach-btn")?.addEventListener("click", () => $("file-input")?.click());
  $("file-input")?.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (file) stageSelectedFile(file);
  });
  $("attachment-clear")?.addEventListener("click", clearStagedAttachment);

  // Enter to send in chat composer (Shift+Enter inserts newline)
  $("body")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!$("send").disabled) {
        sendMessage();
      }
    }
  });

  // Group chat composer, attachment picker & drawer toggle
  $("toggle-group-drawer")?.addEventListener("click", () => {
    const drawer = $("group-drawer");
    if (drawer) drawer.hidden = !drawer.hidden;
  });
  $("group-send")?.addEventListener("click", sendGroupMessage);
  $("group-attach-btn")?.addEventListener("click", () => $("group-file-input")?.click());
  $("group-file-input")?.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (file) stageGroupFile(file);
  });
  $("group-attachment-clear")?.addEventListener("click", clearStagedGroupAttachment);
  $("group-body")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!$("group-send").disabled) {
        sendGroupMessage();
      }
    }
  });

  // Launch screen wiring
  $("setup-passphrase")?.addEventListener("input", scheduleStrengthCheck);
  $("setup-submit")?.addEventListener("click", submitSetup);
  $("unlock-submit")?.addEventListener("click", submitUnlock);
  $("interrupted-submit")?.addEventListener("click", submitInterrupted);

  for (const [input, submit] of [
    ["setup-confirm", submitSetup],
    ["unlock-passphrase", submitUnlock],
    ["interrupted-passphrase", submitInterrupted],
  ]) {
    $(input)?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submit();
      }
    });
  }

  try {
    const view = await refreshLaunch();
    if (!view.is_setup && view.state !== "interrupted_migration") {
      return;
    }
    return;
  } catch (err) {
    const line = $("status-line");
    line.textContent = "Could not read the vault state.";
    line.classList.add("error");
    showError($("setup-result"), err);
    launch.root().hidden = false;
    launch.setup().hidden = false;
    $("setup-title").textContent = "Startup failed";
    $("setup-explain").textContent =
      "The app could not determine the state of its database. This usually means the " +
      "data directory is unreadable. The error below is the specific cause.";
    $("setup-submit").disabled = true;
    return;
  }
});

function startRefreshLoops() {
  setInterval(refreshTransport, 2000);
  setInterval(async () => {
    await refreshConversations();
    if (selectedGroupId) {
      await refreshGroupMembers(selectedGroupId);
      await refreshGroupMessages(selectedGroupId);
    }
  }, 3000);
  setInterval(refreshConsent, 3000);
  // Retry queued frames. The backend applies its own per-frame backoff, so a
  // short interval here is cheap: most passes find nothing due and return.
  setInterval(drainSendQueue, 5000);
}

/**
 * Ask the backend to retry queued frames, refreshing the open conversation when
 * something actually went out.
 */
async function drainSendQueue() {
  try {
    const sent = await invoke("drain_send_queue");
    if (sent > 0) {
      await refreshConversations();
      if (selectedConversationId) {
        await refreshConversationMessages(selectedConversationId);
      }
    }
  } catch {
    // A failed drain is not worth surfacing: the frames stay queued and the next
    // pass retries. The transport banner already explains why sending is blocked.
  }
}

async function refreshPrivacy() {
  try {
    const view = await invoke("privacy_view");
    $("restricted-discovery").checked = view.restricted_discovery;
    $("restricted-discovery").disabled = view.restricted_discovery || view.legacy_contacts > 0;
    $("discovery-state").textContent = view.restricted_discovery
      ? "Restricted discovery enabled"
      : view.legacy_contacts > 0
        ? `${view.legacy_contacts} contacts need upgraded signed invitations`
        : "Legacy public discovery";
    $("traffic-shaping").checked = view.traffic_shaping;
    $("traffic-shaping").disabled = !view.restricted_discovery;
  } catch (error) {
    showError($("privacy-result"), error);
  }
}

async function refreshPersonas() {
  try {
    const personas = await invoke("list_personas");
    for (const prefix of ["launch", "identity"]) {
      const select = $(`${prefix}-personas`);
      const previous = select.value;
      select.replaceChildren();
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = personas.length ? "Select persona" : "No additional personas";
      select.appendChild(placeholder);
      for (const persona of personas) {
        const option = document.createElement("option");
        option.value = persona.id;
        option.textContent = persona.name;
        select.appendChild(option);
      }
      if (personas.some((persona) => persona.id === previous)) select.value = previous;
      $(`${prefix}-open-persona`).disabled = !select.value;
    }
  } catch (error) {
    showError($("launch-persona-result"), error);
  }
}

function wirePrivacyControls() {
  for (const [id, command] of [["restricted-discovery", "enable_restricted_discovery"], ["traffic-shaping", "set_traffic_shaping"]]) {
    $(id).addEventListener("change", async (event) => {
      const enabled = event.target.checked;
      event.target.disabled = true;
      clearError($("privacy-result"));
      try {
        await invoke(command, command === "set_traffic_shaping" ? { enabled } : {});
      } catch (error) {
        showError($("privacy-result"), error);
      } finally {
        await refreshPrivacy();
      }
    });
  }
  for (const prefix of ["launch", "identity"]) {
    const select = $(`${prefix}-personas`);
    select.addEventListener("change", () => { $(`${prefix}-open-persona`).disabled = !select.value; });
    for (const action of ["create", "open"]) {
      const button = $(`${prefix}-${action}-persona`);
      button.addEventListener("click", async () => {
        button.disabled = true;
        const result = $(`${prefix}-persona-result`);
        clearError(result);
        try {
          let id = select.value;
          if (action === "create") {
            const persona = await invoke("create_persona", { name: $(`${prefix}-persona-name`).value });
            id = persona.id;
            $(`${prefix}-persona-name`).value = "";
          }
          await invoke("open_persona", { id });
          result.textContent = "Persona opened in a separate window";
          await refreshPersonas();
        } catch (error) {
          showError(result, error);
        } finally {
          button.disabled = action === "open" && !select.value;
        }
      });
    }
  }
}
