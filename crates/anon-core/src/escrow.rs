//! Optional user-held seed escrow (`plan.md` §2.5, decision D5).
//!
//! Recovery is **optional and entirely user-controlled**. There is no server, no
//! cloud, and no escrow agent: the app produces an encrypted artifact that the
//! user stores themselves. The app never transmits or persists it.
//!
//! # Artifact layout
//!
//! ```text
//! magic      = "ANONESCR"        (8 bytes)
//! version    = 1                 (1 byte)
//! kdf_params = m_cost u32 LE ‖ t_cost u32 LE ‖ p_cost u32 LE   (12 bytes)
//! salt       = 16 bytes
//! nonce      = 12 bytes
//! ciphertext = AEAD(seed, aad = header) ‖ 16-byte tag
//! ```
//!
//! The KDF parameters live **in the artifact header** and are used on import, so
//! a future build that raises the cost parameters can still decrypt artifacts
//! produced by an older one (`plan.md` §2.5). The header is bound into the AEAD
//! associated data, so tampering with the cost parameters or version makes
//! decryption fail rather than silently weakening the derivation.
//!
//! # Threat model (see `plan.md` §2.5`)
//!
//! * The artifact is offline. If a user stores it in a cloud drive, that drive
//!   becomes the escrow agent and the "no server" claim must be qualified in the
//!   UI — that is a UX/communication obligation, not something this module can
//!   enforce.
//! * Passphrase strength is the entire security margin. [`assess_passphrase`]
//!   reports weakness so the UI can warn **without silently rejecting** the
//!   user's choice.
//! * A stolen artifact plus a weak passphrase is a full identity compromise.
//!   The UI must state this at export time.
//! * **Group MLS state is deliberately not included.** Restoring identity does
//!   not restore group keys; the user must rejoin via an invite. This preserves
//!   forward secrecy.

use crate::{CoreError, IdentityKeys, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

/// File-format magic. Distinguishes an escrow artifact from any other blob.
pub const ESCROW_MAGIC: &[u8; 8] = b"ANONESCR";

/// Artifact format version produced by this build.
pub const ESCROW_VERSION: u8 = 1;

/// Salt length. 16 bytes is plenty for Argon2 (it is not a password).
const SALT_LEN: usize = 16;

/// AEAD nonce length for ChaCha20-Poly1305.
const NONCE_LEN: usize = 12;

/// Fixed prefix: magic + version + cost parameters.
const HEADER_LEN: usize = 8 + 1 + 12;

/// Minimum acceptable passphrase length, in characters.
///
/// This is a floor, not a strength guarantee. See [`assess_passphrase`].
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Argon2id cost parameters, stored in the artifact so import always uses the
/// parameters that were used at export time (`plan.md` §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Defaults calibrated for **mobile** (`plan.md` §6.3).
    ///
    /// 64 MiB memory, 3 passes, 1 lane. Mobile-first by design: these are
    /// deliberately not tuned for a desktop, because an artifact exported on
    /// mobile must stay decryptable there.
    pub const fn mobile_default() -> Self {
        Self {
            m_cost: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }

    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.m_cost.to_le_bytes());
        out[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        out[8..12].copy_from_slice(&self.p_cost.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(CoreError::EscrowMalformed("truncated KDF parameters"));
        }
        let m_cost = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let t_cost = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let p_cost = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

        // Bound the parameters on import. An attacker who can edit an artifact
        // cannot lower security (the AEAD binds the header), but could set an
        // absurd memory cost to force an OOM on the victim. Reject that.
        if m_cost == 0 || t_cost == 0 || p_cost == 0 {
            return Err(CoreError::EscrowMalformed("zero KDF cost parameter"));
        }
        if m_cost > 1_048_576 {
            return Err(CoreError::EscrowMalformed("KDF memory cost too large"));
        }
        if t_cost > 64 {
            return Err(CoreError::EscrowMalformed("KDF iteration count too large"));
        }

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    fn derive_key(self, passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| CoreError::EscrowMalformed("invalid KDF parameters"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase, salt, key.as_mut())
            .map_err(|_| CoreError::Crypto)?;
        Ok(key)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::mobile_default()
    }
}

/// A passphrase strength assessment for the UI to act on.
///
/// The UI **warns**; it does not hard-block. `plan.md` §13 leaves the exact
/// policy open, so this type reports facts and lets the caller decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseAssessment {
    /// Whether the passphrase meets the minimum length.
    pub meets_minimum_length: bool,
    /// Estimated entropy in bits (order-of-magnitude, not a guarantee).
    pub estimated_entropy_bits: u32,
    /// Human-readable warnings, empty when nothing is wrong.
    pub warnings: Vec<String>,
    /// Whether the passphrase is on the well-known-weak deny-list.
    ///
    /// Exposed as a fact rather than only as warning text so a caller can apply a
    /// stricter policy without string-matching the warning. That string match was
    /// the bug behind "the bar is green but the vault refuses": the UI coloured
    /// the bar from entropy alone, while the vault rejected on this flag.
    pub is_well_known_weak: bool,
    /// Whether the passphrase looks like a repeated or sequential pattern.
    ///
    /// Same reasoning as [`Self::is_well_known_weak`]: a fact, not prose.
    pub is_repeated_pattern: bool,
}

impl PassphraseAssessment {
    /// Whether the passphrase should be presented as acceptable.
    ///
    /// This is the *escrow* policy: length only. The database passphrase uses a
    /// stricter rule — see [`Self::is_acceptable_for_vault`] — because it is the
    /// only thing protecting the message history.
    pub fn is_acceptable(&self) -> bool {
        self.meets_minimum_length
    }

    /// Whether the passphrase is acceptable for the encrypted database.
    ///
    /// Stricter than [`Self::is_acceptable`]: the minimum length **and** not a
    /// known-weak or patterned string. A long-but-obvious passphrase is refused
    /// here even though the escrow flow would warn and proceed.
    ///
    /// This lives on the assessment so the UI and the vault cannot disagree about
    /// the policy — the disagreement is what produced a green bar over a rejected
    /// passphrase.
    pub fn is_acceptable_for_vault(&self) -> bool {
        self.meets_minimum_length && !self.is_well_known_weak && !self.is_repeated_pattern
    }
}

/// Estimate passphrase strength and report warnings.
///
/// This is intentionally a coarse estimator. It exists to catch "123456" and
/// obvious patterns, not to be a rigorous entropy measure — claiming precision
/// here would be misleading.
pub fn assess_passphrase(passphrase: &str) -> PassphraseAssessment {
    let charset = charset_size(passphrase);
    let chars = passphrase.chars().count() as u32;

    // Bits = length * log2(alphabet). Saturated to avoid overflow on long input.
    let bits_per_char = (charset as f64).log2();
    let estimated = ((chars as f64) * bits_per_char).min(u32::MAX as f64) as u32;

    let mut warnings = Vec::new();

    if chars < MIN_PASSPHRASE_CHARS as u32 {
        warnings.push(format!(
            "Shorter than the {MIN_PASSPHRASE_CHARS}-character minimum."
        ));
    }

    if charset <= 10 {
        warnings.push("Uses only digits; this is very weak.".to_string());
    }

    let well_known_weak = is_common_passphrase(passphrase);
    if well_known_weak {
        warnings.push("This is a well-known weak passphrase.".to_string());
    }

    let repeated = is_repeated_pattern(passphrase);
    if repeated {
        warnings.push("Looks like a repeated or sequential pattern.".to_string());
    }

    if estimated < 60 {
        warnings.push(
            "Estimated strength is low for protecting a long-lived identity key.".to_string(),
        );
    }

    PassphraseAssessment {
        meets_minimum_length: chars >= MIN_PASSPHRASE_CHARS as u32,
        estimated_entropy_bits: estimated,
        warnings,
        is_well_known_weak: well_known_weak,
        is_repeated_pattern: repeated,
    }
}

fn charset_size(s: &str) -> u32 {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_symbol = s.chars().any(|c| !c.is_alphanumeric());
    let has_non_ascii = !s.is_ascii();

    let mut size = 0u32;
    if has_lower {
        size += 26;
    }
    if has_upper {
        size += 26;
    }
    if has_digit {
        size += 10;
    }
    if has_symbol {
        size += 33; // printable ASCII punctuation + space
    }
    if has_non_ascii {
        size += 100; // coarse allowance for a wider script
    }
    size.max(1)
}

fn is_common_passphrase(s: &str) -> bool {
    // A tiny deny-list for obvious cases. Not a substitute for real strength;
    // the point is to catch the worst choices and warn honestly.
    const COMMON: &[&str] = &[
        "password",
        "passphrase",
        "123456789012",
        "qwertyuiop",
        "letmein",
        "correcthorsebatterystaple",
        "admin",
        "iloveyou",
        "trustno1",
        "monkey",
        "dragon",
        "abc123",
    ];
    // Exact match, not substring.
    //
    // This used to be `lower.contains(c)`, which rejected any passphrase that merely
    // *contained* a listed word. That made the policy far stricter than it looked: a
    // long, high-entropy passphrase like "my-dragon-photograph-42" was refused outright
    // because it contains "dragon", and the user was told it was "well-known weak" when
    // it is nothing of the sort. A deny-list entry is a whole passphrase someone might
    // actually type, so comparing the whole string is the correct test.
    //
    // The length floor and the pattern check still catch the cases this list exists for;
    // this only stops the list from rejecting good passphrases by accident.
    let lower = s.to_lowercase();
    COMMON.iter().any(|c| lower == *c)
}

fn is_repeated_pattern(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 4 {
        return false;
    }

    // Single repeated character (e.g. "aaaaaaaaaaaa").
    if chars.iter().all(|c| *c == chars[0]) {
        return true;
    }

    // A short block repeated to fill the string (e.g. "abcabcabcabc").
    for period in 1..=chars.len() / 2 {
        if !chars.len().is_multiple_of(period) {
            continue;
        }
        if chars.chunks(period).all(|c| c == &chars[..period]) {
            return true;
        }
    }

    // Monotonic runs covering the whole string (e.g. "abcdefghij", "9876543210").
    // `windows(2).all(..)` already requires every adjacent pair to be consecutive, so a
    // passphrase that merely contains a run is not caught here — only one that is nothing
    // but a run.
    let ascending = chars.windows(2).all(|w| w[1] as u32 == w[0] as u32 + 1);
    let descending = chars.windows(2).all(|w| w[0] as u32 == w[1] as u32 + 1);
    ascending || descending
}

/// Encrypt the identity seed into a user-storable artifact.
///
/// The returned bytes are the artifact the user keeps. This module does **not**
/// write them anywhere — persisting the artifact is out of scope for the app
/// (`plan.md` §2.5).
pub fn export(keys: &IdentityKeys, passphrase: &str, params: Argon2Params) -> Result<Vec<u8>> {
    let assessment = assess_passphrase(passphrase);
    if !assessment.is_acceptable() {
        return Err(CoreError::EscrowWeakPassphrase(
            "below the minimum length; ask the user to confirm or lengthen it",
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| CoreError::Crypto)?;
    getrandom::fill(&mut nonce).map_err(|_| CoreError::Crypto)?;

    let key = params.derive_key(passphrase.as_bytes(), &salt)?;

    // Build the header; it becomes the AEAD associated data so every header
    // field is integrity-protected.
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(ESCROW_MAGIC);
    header.push(ESCROW_VERSION);
    header.extend_from_slice(&params.to_bytes());

    let plaintext = keys.to_escrow_seed();

    let key_ref: &[u8; 32] = &key;
    let cipher = ChaCha20Poly1305::new(key_ref.into());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| CoreError::Crypto)?;

    let mut artifact = Vec::with_capacity(HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    artifact.extend_from_slice(&header);
    artifact.extend_from_slice(&salt);
    artifact.extend_from_slice(&nonce);
    artifact.extend_from_slice(&ciphertext);
    Ok(artifact)
}

/// Decrypt an artifact and rebuild the identity.
///
/// The same seed always yields the same contact code, so a caller can compare
/// the restored identity against a previously known code (`plan.md` §2.5).
pub fn import(artifact: &[u8], passphrase: &str) -> Result<IdentityKeys> {
    if artifact.len() < HEADER_LEN + SALT_LEN + NONCE_LEN + 16 {
        return Err(CoreError::EscrowMalformed("artifact is truncated"));
    }

    if &artifact[..8] != ESCROW_MAGIC {
        return Err(CoreError::EscrowMalformed("bad magic"));
    }

    let version = artifact[8];
    if version != ESCROW_VERSION {
        return Err(CoreError::EscrowUnsupportedVersion {
            found: version,
            supported: ESCROW_VERSION,
        });
    }

    let params = Argon2Params::from_bytes(&artifact[9..HEADER_LEN])?;
    let header = &artifact[..HEADER_LEN];

    let salt_bytes: [u8; SALT_LEN] = artifact[HEADER_LEN..HEADER_LEN + SALT_LEN]
        .try_into()
        .map_err(|_| CoreError::EscrowMalformed("bad salt"))?;

    let nonce_start = HEADER_LEN + SALT_LEN;
    let nonce_bytes: [u8; NONCE_LEN] = artifact[nonce_start..nonce_start + NONCE_LEN]
        .try_into()
        .map_err(|_| CoreError::EscrowMalformed("bad nonce"))?;

    let ciphertext = &artifact[nonce_start + NONCE_LEN..];

    let key = params.derive_key(passphrase.as_bytes(), &salt_bytes)?;

    let key_ref: &[u8; 32] = &key;
    let cipher = ChaCha20Poly1305::new(key_ref.into());
    let mut plaintext = cipher
        .decrypt(
            (&nonce_bytes).into(),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        // Map to a single opaque error: distinguishing "wrong passphrase" from
        // "corrupted artifact" leaks information and helps no legitimate caller.
        .map_err(|_| CoreError::EscrowDecrypt)?;

    let seed: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::EscrowMalformed("unexpected seed length"))?;

    // Scrub the decrypted buffer now that the seed has been moved into the key.
    plaintext.zeroize();

    let keys = IdentityKeys::from_seed(&Zeroizing::new(seed));

    // Confirm the artifact round-tripped to a usable identity.
    let _ = keys.public();

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small parameters so tests stay fast. The *format* is what is under test;
    /// production cost is covered by `mobile_default_parameters_are_strong`.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            m_cost: 8, // 8 KiB
            t_cost: 1,
            p_cost: 1,
        }
    }

    const STRONG: &str = "correct-horse-battery-staple-9!";

    #[test]
    fn export_import_roundtrip_restores_identity() {
        // The headline D5 property from plan.md §2.5.
        let keys = IdentityKeys::from_seed(&[5u8; 32]);
        let artifact = export(&keys, STRONG, fast_params()).unwrap();
        let restored = import(&artifact, STRONG).unwrap();
        assert_eq!(keys.public(), restored.public());
    }

    #[test]
    fn restored_identity_keeps_the_same_contact_code() {
        use crate::ContactCode;
        let keys = IdentityKeys::generate().unwrap();
        let code_before = ContactCode::encode(&keys.public()).unwrap();

        let artifact = export(&keys, STRONG, fast_params()).unwrap();
        let restored = import(&artifact, STRONG).unwrap();
        let code_after = ContactCode::encode(&restored.public()).unwrap();

        assert_eq!(code_before, code_after);
    }

    #[test]
    fn wrong_passphrase_fails_and_does_not_panic() {
        let keys = IdentityKeys::generate().unwrap();
        let artifact = export(&keys, STRONG, fast_params()).unwrap();
        match import(&artifact, "definitely-the-wrong-one-x") {
            Err(CoreError::EscrowDecrypt) => {}
            other => panic!("expected decrypt failure, got {other:?}"),
        }
    }

    #[test]
    fn tampering_with_any_header_byte_breaks_decryption() {
        let keys = IdentityKeys::generate().unwrap();
        let base = export(&keys, STRONG, fast_params()).unwrap();

        // Every header byte is in the AEAD associated data, so each must be
        // covered. A tag-only integrity check would miss this.
        for idx in 0..HEADER_LEN {
            let mut tampered = base.clone();
            tampered[idx] ^= 0x01;
            let result = import(&tampered, STRONG);
            assert!(
                result.is_err(),
                "header byte {idx} was not integrity-protected"
            );
        }
    }

    #[test]
    fn tampering_with_salt_or_nonce_breaks_decryption() {
        let keys = IdentityKeys::generate().unwrap();
        let base = export(&keys, STRONG, fast_params()).unwrap();

        for idx in HEADER_LEN..HEADER_LEN + SALT_LEN + NONCE_LEN {
            let mut tampered = base.clone();
            tampered[idx] ^= 0x01;
            assert!(import(&tampered, STRONG).is_err(), "byte {idx} not covered");
        }
    }

    #[test]
    fn tampering_with_ciphertext_breaks_decryption() {
        let keys = IdentityKeys::generate().unwrap();
        let mut artifact = export(&keys, STRONG, fast_params()).unwrap();
        let last = artifact.len() - 1;
        artifact[last] ^= 0x01;
        assert!(import(&artifact, STRONG).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let keys = IdentityKeys::generate().unwrap();
        let mut artifact = export(&keys, STRONG, fast_params()).unwrap();
        artifact[0] = b'X';
        match import(&artifact, STRONG) {
            Err(CoreError::EscrowMalformed("bad magic")) => {}
            other => panic!("expected bad-magic failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_version() {
        let keys = IdentityKeys::generate().unwrap();
        let mut artifact = export(&keys, STRONG, fast_params()).unwrap();
        artifact[8] = 42;
        match import(&artifact, STRONG) {
            Err(CoreError::EscrowUnsupportedVersion {
                found: 42,
                supported: 1,
            }) => {}
            other => panic!("expected version failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_artifacts() {
        let keys = IdentityKeys::generate().unwrap();
        let artifact = export(&keys, STRONG, fast_params()).unwrap();
        for cut in [
            0usize,
            1,
            HEADER_LEN,
            HEADER_LEN + SALT_LEN,
            artifact.len() - 1,
        ] {
            match import(&artifact[..cut], STRONG) {
                Err(_) => {}
                Ok(_) => panic!("accepted a truncated artifact of length {cut}"),
            }
        }
    }

    #[test]
    fn rejects_absurd_kdf_parameters_in_header() {
        // Guards the OOM vector described in `Argon2Params::from_bytes`.
        let keys = IdentityKeys::generate().unwrap();
        let mut artifact = export(&keys, STRONG, fast_params()).unwrap();
        // Set memory cost to 1 GiB and iteration count to 250.
        artifact[9..13].copy_from_slice(&1_048_577u32.to_le_bytes());
        artifact[13..17].copy_from_slice(&250u32.to_le_bytes());
        match import(&artifact, STRONG) {
            Err(CoreError::EscrowMalformed(_)) => {}
            other => panic!("expected rejection of absurd parameters, got {other:?}"),
        }
    }

    #[test]
    fn refuses_to_export_a_weak_passphrase() {
        let keys = IdentityKeys::generate().unwrap();
        match export(&keys, "short", fast_params()) {
            Err(CoreError::EscrowWeakPassphrase(_)) => {}
            other => panic!("expected weak-passphrase rejection, got {other:?}"),
        }
    }

    #[test]
    fn export_is_non_deterministic_due_to_fresh_salt_and_nonce() {
        let keys = IdentityKeys::generate().unwrap();
        let a = export(&keys, STRONG, fast_params()).unwrap();
        let b = export(&keys, STRONG, fast_params()).unwrap();
        assert_ne!(a, b, "salt/nonce must be freshly generated per export");
        // Both still decrypt to the same identity.
        assert_eq!(
            import(&a, STRONG).unwrap().public(),
            import(&b, STRONG).unwrap().public()
        );
    }

    #[test]
    fn artifact_does_not_contain_the_seed_in_plaintext() {
        let keys = IdentityKeys::from_seed(&[0xABu8; 32]);
        let seed = keys.to_escrow_seed();
        let artifact = export(&keys, STRONG, fast_params()).unwrap();

        assert!(
            !artifact.windows(32).any(|w| w == &seed[..]),
            "raw seed found in the artifact"
        );
    }

    #[test]
    fn mobile_default_parameters_are_strong() {
        let p = Argon2Params::mobile_default();
        // plan.md §6.3: >= 64 MiB memory on a mobile-calibrated default.
        assert!(p.m_cost >= 65_536, "memory cost below the mobile target");
        assert!(p.t_cost >= 3, "iteration count too low");
    }

    #[test]
    fn passphrase_assessment_flags_obvious_weakness() {
        let weak = assess_passphrase("12345678");
        assert!(!weak.meets_minimum_length);
        assert!(!weak.is_acceptable());
        assert!(!weak.warnings.is_empty());

        // An exact deny-list entry is flagged as well-known. `passwordpassword` is not
        // (the list matches whole strings), but it is still refused — as a repeated
        // pattern, which is what it actually is.
        let common = assess_passphrase("password");
        assert!(common.warnings.iter().any(|w| w.contains("well-known")));

        let doubled = assess_passphrase("passwordpassword");
        assert!(doubled.warnings.iter().any(|w| w.contains("pattern")));
        assert!(!doubled.is_acceptable_for_vault());

        let repeated = assess_passphrase("ababababababab");
        assert!(repeated.warnings.iter().any(|w| w.contains("pattern")));

        let sequential = assess_passphrase("abcdefghijklm");
        assert!(sequential.warnings.iter().any(|w| w.contains("pattern")));
    }

    #[test]
    fn strong_passphrase_passes_assessment() {
        let strong = assess_passphrase("Tr0ub4dor&3-feldspar-quixotic");
        assert!(strong.meets_minimum_length);
        assert!(strong.is_acceptable());
        assert!(strong.estimated_entropy_bits >= 60);
    }

    #[test]
    fn a_good_passphrase_containing_a_listed_word_is_accepted() {
        // Regression test for an over-strict policy: the deny-list used to match on
        // substring, so any passphrase containing "dragon", "admin", "monkey" and friends
        // was refused as "well-known weak" no matter how long or random it was. These are
        // all long, high-entropy passphrases that merely happen to contain a listed word.
        for candidate in [
            "my-dragon-photograph-42",
            "administering-quixotic-feldspar",
            "monkeywrench-trombone-velocity",
            "trustno1-but-actually-a-long-phrase",
        ] {
            let assessment = assess_passphrase(candidate);
            assert!(
                !assessment.is_well_known_weak,
                "`{candidate}` must not be flagged as a well-known weak passphrase"
            );
            assert!(
                assessment.is_acceptable_for_vault(),
                "`{candidate}` must be acceptable for the vault"
            );
        }
    }

    #[test]
    fn the_deny_list_still_rejects_the_exact_weak_strings() {
        // The relaxation above must not weaken the case the list exists for.
        for candidate in ["password", "passphrase", "letmein", "monkey", "dragon"] {
            assert!(
                assess_passphrase(candidate).is_well_known_weak,
                "`{candidate}` is exactly a listed weak passphrase and must be refused"
            );
        }
    }

    #[test]
    fn a_passphrase_that_merely_contains_a_run_is_accepted() {
        // The pattern check requires the run to span the whole string, so a passphrase
        // that ends in a short sequence is fine. This pins that, because tightening the
        // check to "contains a run" would reject most real passphrases.
        let assessment = assess_passphrase("correct-horse-abc");
        assert!(
            !assessment.is_repeated_pattern,
            "a passphrase containing a run must not be treated as a repeated pattern"
        );
        assert!(assessment.is_acceptable_for_vault());
    }

    #[test]
    fn assessment_warns_but_is_not_the_gate_for_a_long_passphrase() {
        // A long single-character passphrase is degenerate but long; the
        // assessment must warn rather than pretend it is fine.
        let a = assess_passphrase("aaaaaaaaaaaaaaaaaaaa");
        assert!(a.meets_minimum_length);
        assert!(a.warnings.iter().any(|w| w.contains("pattern")));
    }
}
