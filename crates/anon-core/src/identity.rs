//! Identity keys (`plan.md` §2.1).
//!
//! Two keypairs per user:
//!
//! * **Ed25519** — identity and signing.
//! * **X25519** — encryption / Diffie-Hellman handshakes.
//!
//! The X25519 secret is derived deterministically from the Ed25519 seed via
//! HKDF with domain separation, so escrow only has to transport **one** seed
//! (`plan.md` §2.5). This keeps the escrow artifact small and the restore path
//! simple, while the domain tag keeps the two keypairs cryptographically
//! independent.
//!
//! # Secret handling
//!
//! `IdentityKeys` is not `Clone` and not `Debug`-printable in terms of secrets.
//! Its fields are `zeroize`-enabled containers, so dropping it scrubs memory.
//! There is deliberately **no** `Display`/`Serialize` impl: the only supported
//! way to persist a secret is [`IdentityKeys::to_escrow_seed`], whose output is
//! itself a `Zeroizing` buffer.

use crate::{CoreError, Result, KDF_DOMAIN_X25519};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Length of an Ed25519 seed / secret key.
pub const SEED_LEN: usize = 32;

/// A full identity keypair set. Holds live secret material.
///
/// Secrets are wiped on drop. See the module docs for the reasoning behind
/// deriving X25519 from the Ed25519 seed.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeys {
    #[zeroize(skip)]
    signing: SigningKey,
    #[zeroize(skip)]
    agreement: StaticSecret,
}

impl IdentityKeys {
    /// Generate a fresh identity from OS entropy.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| CoreError::Crypto)?;
        Ok(Self::from_seed(&seed))
    }

    /// Derive an identity deterministically from a 32-byte seed.
    ///
    /// This is the **restore path** for escrow import (`plan.md` §2.5): the same
    /// seed always yields the same contact code.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let signing = SigningKey::from_bytes(seed);

        // Derive the agreement secret with HKDF domain separation. The Ed25519
        // seed is a uniformly random 32 bytes, so using it as HKDF input key
        // material is sound.
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut agreement_bytes = Zeroizing::new([0u8; 32]);
        // `expand` only fails on absurd output lengths; 32 is valid.
        hk.expand(KDF_DOMAIN_X25519, agreement_bytes.as_mut())
            .expect("32 bytes is a valid HKDF output length");

        let agreement = StaticSecret::from(*agreement_bytes);

        Self { signing, agreement }
    }

    /// The public half, safe to share.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            identity: self.signing.verifying_key().to_bytes(),
            agreement: XPublicKey::from(&self.agreement).to_bytes(),
        }
    }

    /// Sign a message with the identity key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Borrow the agreement secret for a Diffie-Hellman operation.
    ///
    /// Deliberately not exposed as a public field or a `to_bytes` clone: callers
    /// perform the DH here rather than extracting the secret.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> [u8; 32] {
        let shared = self.agreement.diffie_hellman(&XPublicKey::from(*peer));
        *shared.as_bytes()
    }

    /// Export the escrow seed.
    ///
    /// The returned buffer is `Zeroizing`, so it is scrubbed when dropped. It
    /// must only ever be handed to the escrow encryptor (`plan.md` §2.5) — never
    /// logged, persisted, or sent over IPC.
    pub fn to_escrow_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        // `SigningKey::to_bytes` returns an owned copy; wrapping it in
        // `Zeroizing` means it is scrubbed as soon as the caller drops it.
        // Callers must never clone this out of the wrapper.
        Zeroizing::new(self.signing.to_bytes())
    }
}

/// The public half of an identity. Safe to share, log, and store unencrypted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    /// Ed25519 verifying key.
    pub identity: [u8; 32],
    /// X25519 public key.
    pub agreement: [u8; 32],
}

impl PublicIdentity {
    /// Verify a signature made by the identity key of this public identity.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.identity).map_err(|_| CoreError::InvalidKey)?;
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig)
            .map_err(|_| CoreError::CodeInvalidKey)
    }

    /// Compact human-readable fingerprint for out-of-band comparison.
    ///
    /// Derived from both public keys so a user comparing fingerprints verifies
    /// the whole identity, not just the signing half.
    pub fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"anon/v1/fingerprint");
        hasher.update(&self.identity);
        hasher.update(&self.agreement);
        let digest = hasher.finalize();

        // Grouped base32-ish hex in 4-char blocks to make verbal comparison
        // practical. Not a secret; no need for constant-time handling.
        let hex = hex_encode(&digest.as_bytes()[..8]);
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl std::fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump raw key bytes into logs; the fingerprint is sufficient.
        f.debug_struct("PublicIdentity")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl std::fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally opaque: secrets must never reach a formatter.
        f.write_str("IdentityKeys(<redacted>)")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let seed = [42u8; 32];
        let a = IdentityKeys::from_seed(&seed);
        let b = IdentityKeys::from_seed(&seed);
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn distinct_seeds_give_distinct_identities() {
        let a = IdentityKeys::from_seed(&[1u8; 32]);
        let b = IdentityKeys::from_seed(&[2u8; 32]);
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let keys = IdentityKeys::generate().unwrap();
        let pubid = keys.public();
        let msg = b"epoch 7 commit";
        let sig = keys.sign(msg);
        pubid.verify(msg, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verification_rejects_tampered_message() {
        let keys = IdentityKeys::generate().unwrap();
        let pubid = keys.public();
        let sig = keys.sign(b"original");
        assert!(pubid.verify(b"tampered", &sig.to_bytes()).is_err());
    }

    #[test]
    fn escrow_seed_roundtrip_preserves_identity() {
        // Core D5 property: export -> import yields the same contact code.
        let keys = IdentityKeys::generate().unwrap();
        let seed = keys.to_escrow_seed();
        let restored = IdentityKeys::from_seed(&seed);
        assert_eq!(keys.public(), restored.public());
    }

    #[test]
    fn dh_agreement_is_symmetric() {
        let a = IdentityKeys::generate().unwrap();
        let b = IdentityKeys::generate().unwrap();
        let ab = a.diffie_hellman(&b.public().agreement);
        let ba = b.diffie_hellman(&a.public().agreement);
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 32]);
    }

    #[test]
    fn signing_and_agreement_keys_are_independent() {
        // Guards against a regression where the X25519 key is accidentally the
        // Ed25519 key bytes, which would conflate the two security domains.
        let keys = IdentityKeys::from_seed(&[7u8; 32]);
        let p = keys.public();
        assert_ne!(p.identity, p.agreement);
    }

    #[test]
    fn debug_does_not_leak_secrets_or_keys() {
        let keys = IdentityKeys::generate().unwrap();
        let rendered = format!("{:?}", keys);
        assert_eq!(rendered, "IdentityKeys(<redacted>)");

        let pubid = format!("{:?}", keys.public());
        assert!(pubid.contains("fingerprint"));
        // No raw key material should appear in a debug rendering.
        let raw = hex_encode(&keys.public().identity);
        assert!(!pubid.contains(&raw));
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let keys = IdentityKeys::from_seed(&[3u8; 32]);
        let fp = keys.public().fingerprint();
        assert_eq!(fp, keys.public().fingerprint());
        // 8 bytes -> 16 hex chars -> 4 groups of 4 -> 3 separators.
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches('-').count(), 3);
    }
}
