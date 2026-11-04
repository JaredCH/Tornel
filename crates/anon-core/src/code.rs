//! Human-shareable contact codes (`plan.md` §2.2).
//!
//! A contact code carries the public identity only. It is **not** a Tor onion
//! address — the plan explicitly separates the two (`plan.md` §2.1, verification
//! note): an onion address is `base32(SHA3-256(pubkey ‖ blinded_pubkey ‖ ver))`
//! and is routing-only, whereas this code is the durable thing a human copies.
//!
//! # Wire format
//!
//! ```text
//! payload  = version (1 byte) ‖ ed25519_pubkey (32 B) ‖ x25519_pubkey (32 B)
//! checksum = BLAKE3(payload)[..4]
//! body     = payload ‖ checksum            (69 bytes)
//! text     = bech32m("anon", body)
//! ```
//!
//! ## Why Bech32m rather than plain Bech32
//!
//! Bech32m (BIP-350) is the encoding the Bech32 spec recommends for **new**
//! applications with no 90-character length constraint. It keeps the strong
//! typo-detection properties of Bech32 while changing the checksum constant,
//! which prevents cross-decoding between the two variants.
//!
//! ## Why an extra BLAKE3 checksum on top of Bech32m
//!
//! Bech32m's own checksum already detects errors within the encoded string, so
//! this layer is **defence in depth**, not the primary guard. It makes the
//! payload self-verifying if the bytes are ever transported outside the Bech32m
//! envelope (a QR code payload, a binary blob, a stored record), and it lets us
//! reject a code whose inner bytes were mutated by something that re-encoded it.

use crate::{CoreError, PublicIdentity, Result};
use bech32::{Bech32m, Hrp};

/// Human-readable prefix for contact codes.
pub const CONTACT_CODE_HRP: &str = "anon";

/// Format version understood by this build.
pub const CODE_VERSION: u8 = 1;

/// `version (1) + ed25519 (32) + x25519 (32)`.
pub const PAYLOAD_LEN: usize = 1 + 32 + 32;
/// Payload plus the 4-byte BLAKE3 checksum.
pub const BODY_LEN: usize = PAYLOAD_LEN + 4;

/// A decoded, validated contact code.
///
/// Holding this type is proof the code passed HRP, length, version, checksum,
/// and public-key validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContactCode {
    identity: PublicIdentity,
}

impl ContactCode {
    /// Encode a public identity into a shareable code.
    pub fn encode(identity: &PublicIdentity) -> Result<String> {
        let body = Self::body_of(identity);

        let hrp = Hrp::parse(CONTACT_CODE_HRP).map_err(|_| CoreError::CodeEncoding)?;
        bech32::encode::<Bech32m>(hrp, &body).map_err(|_| CoreError::CodeEncoding)
    }

    /// Decode and fully validate a contact code.
    ///
    /// Validation order is deliberate: cheap structural checks run before the
    /// public keys are parsed so malformed input is rejected without touching
    /// curve arithmetic.
    pub fn decode(text: &str) -> Result<Self> {
        // Normalise: codes are frequently pasted with surrounding whitespace.
        let trimmed = text.trim();

        let (hrp, data) = bech32::decode(trimmed).map_err(|_| CoreError::CodeEncoding)?;
        if !hrp.as_str().eq_ignore_ascii_case(CONTACT_CODE_HRP) {
            return Err(CoreError::CodeWrongHrp {
                expected: CONTACT_CODE_HRP,
            });
        }

        if data.len() != BODY_LEN {
            return Err(CoreError::CodeWrongLength {
                expected: BODY_LEN,
                found: data.len(),
            });
        }

        let version = data[0];
        if version != CODE_VERSION {
            return Err(CoreError::CodeUnsupportedVersion {
                found: version,
                supported: CODE_VERSION,
            });
        }

        let payload = &data[..PAYLOAD_LEN];
        let checksum = &data[PAYLOAD_LEN..];

        // Constant-time comparison is unnecessary here (both values are public),
        // but comparing via `subtle` documents that this is a security check.
        let expected = Self::checksum_of(payload);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(checksum, &expected)) {
            return Err(CoreError::CodeChecksum);
        }

        let mut identity_bytes = [0u8; 32];
        let mut agreement_bytes = [0u8; 32];
        identity_bytes.copy_from_slice(&data[1..33]);
        agreement_bytes.copy_from_slice(&data[33..65]);

        // Reject non-canonical / low-order encodings rather than trusting them.
        Self::validate_public_keys(&identity_bytes, &agreement_bytes)?;

        Ok(Self {
            identity: PublicIdentity {
                identity: identity_bytes,
                agreement: agreement_bytes,
            },
        })
    }

    /// The decoded public identity.
    pub fn public_identity(&self) -> PublicIdentity {
        self.identity
    }

    /// Re-encode to canonical text (useful for normalising user input).
    pub fn to_code(&self) -> Result<String> {
        Self::encode(&self.identity)
    }

    fn body_of(identity: &PublicIdentity) -> Vec<u8> {
        let mut body = Vec::with_capacity(BODY_LEN);
        body.push(CODE_VERSION);
        body.extend_from_slice(&identity.identity);
        body.extend_from_slice(&identity.agreement);
        let checksum = Self::checksum_of(&body);
        body.extend_from_slice(&checksum);
        body
    }

    fn checksum_of(payload: &[u8]) -> [u8; 4] {
        // Domain-separated so this digest can never collide with a fingerprint
        // or any other BLAKE3 use in the codebase.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"anon/v1/contact-code");
        hasher.update(payload);
        let digest = hasher.finalize();

        let mut out = [0u8; 4];
        out.copy_from_slice(&digest.as_bytes()[..4]);
        out
    }

    fn validate_public_keys(identity: &[u8; 32], agreement: &[u8; 32]) -> Result<()> {
        // Ed25519: decompress to guarantee the point is on the curve. dalek 3.0
        // re-encodes canonically on `to_bytes`, so the comparison below is a
        // cheap belt-and-braces invariant rather than an active guard: it is
        // unreachable for every input dalek accepts today, but it would catch a
        // future encoding change that started returning non-canonical bytes.
        let vk = ed25519_dalek::VerifyingKey::from_bytes(identity)
            .map_err(|_| CoreError::CodeInvalidKey)?;
        if vk.to_bytes() != *identity {
            return Err(CoreError::CodeInvalidKey);
        }

        // X25519: reject the low-order points that force a shared secret of zero.
        // `x25519_dalek` provides this check for public keys.
        if !is_valid_x25519_public(agreement) {
            return Err(CoreError::CodeInvalidKey);
        }

        Ok(())
    }
}

/// Reject X25519 public keys that are known low-order points.
///
/// A low-order peer key drives the Diffie-Hellman result to a small set of
/// values (including all-zero), destroying confidentiality. `x25519-dalek`
/// already returns an error from `diffie_hellman` for these, but rejecting them
/// at *decode* time means a malformed contact code never enters the system.
fn is_valid_x25519_public(bytes: &[u8; 32]) -> bool {
    // All-zero is the canonical low-order case.
    if bytes == &[0u8; 32] {
        return false;
    }

    // The remaining low-order points, from the X25519 specification's
    // "small-order points" list. Any of these would collapse the DH output.
    const LOW_ORDER: [[u8; 32]; 6] = [
        [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ],
        [
            0xe0u8, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5fu8, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        [
            0xecu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xedu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xeeu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    !LOW_ORDER.iter().any(|p| p == bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKeys;

    fn sample() -> PublicIdentity {
        IdentityKeys::from_seed(&[11u8; 32]).public()
    }

    #[test]
    fn roundtrip_preserves_identity() {
        let id = sample();
        let code = ContactCode::encode(&id).unwrap();
        assert!(code.starts_with("anon1"));
        let decoded = ContactCode::decode(&code).unwrap();
        assert_eq!(decoded.public_identity(), id);
    }

    #[test]
    fn encoding_is_deterministic_and_canonical() {
        let id = sample();
        let a = ContactCode::encode(&id).unwrap();
        let b = ContactCode::encode(&id).unwrap();
        assert_eq!(a, b);
        // Lowercase, no padding, and re-decodable to the same text.
        assert_eq!(a, a.to_lowercase());
        assert_eq!(ContactCode::decode(&a).unwrap().to_code().unwrap(), a);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let code = ContactCode::encode(&sample()).unwrap();
        let padded = format!("  \t{code}\n ");
        assert!(ContactCode::decode(&padded).is_ok());
    }

    #[test]
    fn checksum_detects_payload_corruption() {
        let id = sample();
        let mut body = ContactCode::body_of(&id);
        // Flip a payload bit (leaving the trailing BLAKE3 checksum stale).
        body[5] ^= 0x01;
        let hrp = Hrp::parse(CONTACT_CODE_HRP).unwrap();
        let corrupted = bech32::encode::<Bech32m>(hrp, &body).unwrap();

        match ContactCode::decode(&corrupted) {
            Err(CoreError::CodeChecksum) => {}
            other => panic!("expected checksum failure, got {other:?}"),
        }
    }

    #[test]
    fn bech32m_layer_catches_single_character_typos() {
        // Independent of our BLAKE3 checksum: Bech32m must reject a transposed
        // character during decode, before any payload validation runs.
        let code = ContactCode::encode(&sample()).unwrap();
        let mut chars: Vec<char> = code.chars().collect();
        let idx = chars.len() - 3;
        chars[idx] = if chars[idx] == 'q' { 'p' } else { 'q' };
        let typo: String = chars.into_iter().collect();

        assert!(ContactCode::decode(&typo).is_err());
    }

    #[test]
    fn rejects_wrong_hrp() {
        let hrp = Hrp::parse("other").unwrap();
        let body = ContactCode::body_of(&sample());
        let code = bech32::encode::<Bech32m>(hrp, &body).unwrap();
        match ContactCode::decode(&code) {
            Err(CoreError::CodeWrongHrp { .. }) => {}
            other => panic!("expected HRP failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_length() {
        let hrp = Hrp::parse(CONTACT_CODE_HRP).unwrap();
        let code = bech32::encode::<Bech32m>(hrp, &[1u8, 2, 3]).unwrap();
        match ContactCode::decode(&code) {
            Err(CoreError::CodeWrongLength { .. }) => {}
            other => panic!("expected length failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_version() {
        let id = sample();
        let mut body = ContactCode::body_of(&id);
        body[0] = 99;
        // Recompute the checksum so the version check is the failing gate.
        let checksum = ContactCode::checksum_of(&body[..PAYLOAD_LEN]);
        body[PAYLOAD_LEN..].copy_from_slice(&checksum);

        let hrp = Hrp::parse(CONTACT_CODE_HRP).unwrap();
        let code = bech32::encode::<Bech32m>(hrp, &body).unwrap();
        match ContactCode::decode(&code) {
            Err(CoreError::CodeUnsupportedVersion {
                found: 99,
                supported: 1,
            }) => {}
            other => panic!("expected version failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_all_zero_agreement_key() {
        let id = PublicIdentity {
            identity: sample().identity,
            agreement: [0u8; 32],
        };
        let code = ContactCode::encode(&id).unwrap();
        match ContactCode::decode(&code) {
            Err(CoreError::CodeInvalidKey) => {}
            other => panic!("expected invalid-key failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_low_order_agreement_key() {
        let id = PublicIdentity {
            identity: sample().identity,
            agreement: [
                1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        };
        let code = ContactCode::encode(&id).unwrap();
        match ContactCode::decode(&code) {
            Err(CoreError::CodeInvalidKey) => {}
            other => panic!("expected invalid-key failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_undecodable_ed25519_key() {
        // Deterministic negative vector: a compressed point whose y-coordinate
        // has the sign bit set but no valid x. Verified failing against
        // ed25519-dalek 3.0 (see the probe that produced these values).
        let mut bad = [0u8; 32];
        bad[0] = 0x02;
        bad[31] = 0x40;
        let id = PublicIdentity {
            identity: bad,
            agreement: sample().agreement,
        };
        assert!(ContactCode::decode(&ContactCode::encode(&id).unwrap()).is_err());
    }

    #[test]
    fn rejects_empty_and_garbage_input() {
        assert!(ContactCode::decode("").is_err());
        assert!(ContactCode::decode("anon1").is_err());
        assert!(ContactCode::decode("not a bech32 string at all").is_err());
    }
}
