//! Wire format, padding, and message identity (`plan.md` §9.1, §9.2).
//!
//! # Frame layout
//!
//! ```text
//! version      1 byte
//! pad_bucket   u32 LE   -- the size bucket this frame was padded to
//! payload_len  u32 LE   -- true plaintext length, before padding
//! id           16 bytes -- ULID-like message id
//! conversation 16 bytes
//! epoch        u64 LE
//! nonce        12 bytes
//! body         pad_bucket bytes: ciphertext ‖ zero padding, then a tag
//! ```
//!
//! The header is passed to the AEAD as **associated data**, so version, bucket,
//! length, id, conversation, and epoch are all integrity-protected. That is what
//! stops an attacker from re-bucketing a frame (defeating padding) or moving a
//! ciphertext into another conversation (§9.1).
//!
//! # Why padding sizes are in the *header*
//!
//! An observer who can see the frame on the wire learns its padded size anyway
//! (it is the byte count). Declaring it in the authenticated header means a
//! receiver rejects a frame whose real size disagrees with its declared bucket,
//! so the padding cannot be silently stripped in transit.

use crate::error::FrameError;
use crate::{NONCE_LEN, PAD_BUCKETS, PROTOCOL_VERSION, TAG_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

/// Header size: version(1) + bucket(4) + len(4) + id(16) + conversation(16)
/// + epoch(8) + nonce(12).
pub const HEADER_LEN: usize = 1 + 4 + 4 + 16 + 16 + 8 + NONCE_LEN;

/// A message identifier.
///
/// `plan.md` §9.1 calls for monotonic, unique ids so recipients can reject
/// duplicates and detect clock regression. A random 128-bit value is used here
/// for uniqueness; monotonicity is enforced by the receiver's seen-set plus an
/// epoch check rather than by trusting the sender's clock — a sender's clock is
/// exactly the thing a malicious peer can lie about.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MessageId([u8; 16]);

impl MessageId {
    /// Generate a fresh random id.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy is available");
        Self(bytes)
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Short hex label for logs and UI. An id is not secret.
    pub fn short_label(&self) -> String {
        self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A prepared, padded, encrypted frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    version: u8,
    bucket: usize,
    payload_len: u32,
    id: MessageId,
    conversation: [u8; 16],
    epoch: u64,
    nonce: [u8; NONCE_LEN],
    body: Vec<u8>,
}

/// Choose the smallest bucket that fits `plaintext_len` plus a tag.
///
/// Returns `None` when the payload cannot fit in any bucket, which the caller
/// reports as a hard failure rather than silently truncating.
pub fn bucket_for(plaintext_len: usize) -> Option<usize> {
    PAD_BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= plaintext_len + TAG_LEN)
}

/// The largest payload that can be sent.
pub fn max_payload_len() -> usize {
    PAD_BUCKETS
        .last()
        .copied()
        .unwrap_or(0)
        .saturating_sub(TAG_LEN)
}

impl Frame {
    /// Encrypt and pad a payload into a frame.
    ///
    /// `key` is the conversation's data key. Idempotent per call: a fresh random
    /// nonce and id are generated each time, so two frames for the same plaintext
    /// differ (nonce reuse would be catastrophic for a stream cipher).
    pub fn seal(
        key: &[u8; 32],
        conversation: [u8; 16],
        epoch: u64,
        plaintext: &[u8],
    ) -> Result<Self, FrameError> {
        let bucket = bucket_for(plaintext.len()).ok_or(FrameError::TooLarge)?;
        debug_assert!(bucket >= plaintext.len() + TAG_LEN);

        let id = MessageId::generate();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("OS entropy is available");

        let header = HeaderFields {
            version: PROTOCOL_VERSION,
            bucket,
            payload_len: plaintext.len() as u32,
            id,
            conversation,
            epoch,
            nonce,
        };

        // Pad the plaintext to the bucket size *before* sealing, so the
        // ciphertext length equals the bucket and reveals nothing about the
        // true length. The tag is appended by the AEAD within the same space.
        let mut padded = vec![0u8; bucket - TAG_LEN];
        padded[..plaintext.len()].copy_from_slice(plaintext);

        let cipher = ChaCha20Poly1305::new(key.into());
        let body = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &padded,
                    aad: &header.encode(),
                },
            )
            .map_err(|_| FrameError::AuthFailed)?;

        // Scrub the padded plaintext; the ciphertext is what we keep.
        zeroize::Zeroize::zeroize(&mut padded);

        debug_assert_eq!(body.len(), bucket);

        Ok(Self {
            version: PROTOCOL_VERSION,
            bucket,
            payload_len: plaintext.len() as u32,
            id,
            conversation,
            epoch,
            nonce,
            body,
        })
    }

    /// Decrypt and unpad a frame.
    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>, FrameError> {
        if self.version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion {
                found: self.version,
                supported: PROTOCOL_VERSION,
            });
        }

        let header = HeaderFields {
            version: self.version,
            bucket: self.bucket,
            payload_len: self.payload_len,
            id: self.id,
            conversation: self.conversation,
            epoch: self.epoch,
            nonce: self.nonce,
        };

        let cipher = ChaCha20Poly1305::new(key.into());
        let padded = cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &self.body,
                    aad: &header.encode(),
                },
            )
            .map_err(|_| FrameError::AuthFailed)?;

        let declared = self.payload_len as usize;
        if declared > padded.len() {
            return Err(FrameError::BadPadding);
        }

        Ok(padded[..declared].to_vec())
    }

    /// Serialise to bytes for transmission.
    ///
    /// The on-wire length is fixed by the bucket, so the byte count leaks nothing
    /// beyond the bucket itself.
    pub fn encode(&self) -> Vec<u8> {
        let header = HeaderFields {
            version: self.version,
            bucket: self.bucket,
            payload_len: self.payload_len,
            id: self.id,
            conversation: self.conversation,
            epoch: self.epoch,
            nonce: self.nonce,
        };
        let mut out = header.encode();
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a frame from bytes, validating structure.
    ///
    /// Structural validation happens here; authentication happens in
    /// [`Frame::open`]. Separating them means a malformed frame is rejected
    /// before any crypto runs.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(FrameError::Truncated);
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion {
                found: version,
                supported: PROTOCOL_VERSION,
            });
        }

        let read_u32 = |o: usize| -> u32 {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };

        let bucket = read_u32(1) as usize;
        let payload_len = read_u32(5);

        // The bucket must be one we defined, and must actually fit the tag plus
        // the declared payload. Otherwise a sender could declare a huge bucket
        // to force a large allocation.
        if !PAD_BUCKETS.contains(&bucket) {
            return Err(FrameError::BadPadding);
        }
        if (payload_len as usize) + TAG_LEN > bucket {
            return Err(FrameError::BadPadding);
        }

        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[9..25]);

        let mut conversation = [0u8; 16];
        conversation.copy_from_slice(&bytes[25..41]);

        let epoch = u64::from_le_bytes(bytes[41..49].try_into().unwrap());

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[49..HEADER_LEN]);

        let body = &bytes[HEADER_LEN..];
        if body.len() != bucket {
            return Err(FrameError::LengthMismatch {
                declared: bucket,
                actual: body.len(),
            });
        }

        Ok(Self {
            version,
            bucket,
            payload_len,
            id: MessageId::from_bytes(id),
            conversation,
            epoch,
            nonce,
            body: body.to_vec(),
        })
    }

    /// The message id.
    pub fn id(&self) -> MessageId {
        self.id
    }

    /// The conversation this frame belongs to.
    pub fn conversation(&self) -> [u8; 16] {
        self.conversation
    }

    /// The epoch this frame was encrypted under.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The padded size bucket. Public because it is visible on the wire anyway.
    pub fn bucket(&self) -> usize {
        self.bucket
    }

    /// Total encoded length.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.body.len()
    }
}

/// The authenticated header, factored out so `seal` and `decode` cannot drift.
struct HeaderFields {
    version: u8,
    bucket: usize,
    payload_len: u32,
    id: MessageId,
    conversation: [u8; 16],
    epoch: u64,
    nonce: [u8; NONCE_LEN],
}

impl HeaderFields {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.push(self.version);
        out.extend_from_slice(&(self.bucket as u32).to_le_bytes());
        out.extend_from_slice(&self.payload_len.to_le_bytes());
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.conversation);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3u8; 32];

    fn conv() -> [u8; 16] {
        [7u8; 16]
    }

    #[test]
    fn seal_and_open_round_trip() {
        let f = Frame::seal(&KEY, conv(), 1, b"hello world").unwrap();
        assert_eq!(f.open(&KEY).unwrap(), b"hello world");
    }

    #[test]
    fn round_trip_survives_encoding() {
        let f = Frame::seal(&KEY, conv(), 5, b"payload").unwrap();
        let encoded = f.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.open(&KEY).unwrap(), b"payload");
        assert_eq!(decoded.id(), f.id());
        assert_eq!(decoded.epoch(), 5);
    }

    #[test]
    fn padding_hides_the_true_length() {
        // §9.4 baseline: two very different payloads must produce the same
        // on-wire size when they fall in the same bucket.
        let short = Frame::seal(&KEY, conv(), 1, b"a").unwrap();
        let longer = Frame::seal(&KEY, conv(), 1, &vec![b'x'; 400]).unwrap();

        assert_eq!(short.bucket(), 512);
        assert_eq!(longer.bucket(), 512);
        assert_eq!(short.encode().len(), longer.encode().len());
    }

    #[test]
    fn padding_grows_through_buckets_as_expected() {
        assert_eq!(bucket_for(1).unwrap(), 512);
        assert_eq!(bucket_for(496).unwrap(), 512); // 496 + 16 == 512
        assert_eq!(bucket_for(497).unwrap(), 2048);
        assert_eq!(bucket_for(2032).unwrap(), 2048);
        assert_eq!(bucket_for(2033).unwrap(), 8192);
        assert_eq!(bucket_for(32_752).unwrap(), 32_768);
        assert_eq!(bucket_for(32_753).unwrap(), 131_072);
        assert_eq!(bucket_for(524_272).unwrap(), 524_288);
        assert!(bucket_for(524_273).is_none());
        assert_eq!(max_payload_len(), 524_272);
    }

    #[test]
    fn same_plaintext_produces_different_frames() {
        // Fresh nonce and id per seal: nonce reuse would break the cipher.
        let a = Frame::seal(&KEY, conv(), 1, b"same").unwrap();
        let b = Frame::seal(&KEY, conv(), 1, b"same").unwrap();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn tampering_with_body_fails_authentication() {
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        let mut bytes = f.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let decoded = Frame::decode(&bytes).unwrap();
        assert!(decoded.open(&KEY).is_err());
    }

    #[test]
    fn re_bucketing_a_frame_fails_authentication() {
        // The bucket is authenticated, so an attacker cannot strip padding to
        // make a short message look differently sized.
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        let mut bytes = f.encode();
        // Rewrite the bucket field to a different valid bucket.
        bytes[1..5].copy_from_slice(&(2048u32).to_le_bytes());
        // Structural decode rejects the size mismatch first.
        assert!(Frame::decode(&bytes).is_err());
    }

    #[test]
    fn changing_the_declared_payload_len_fails_authentication() {
        // §9.1: length is bound into the AEAD, so it cannot be edited to leak
        // padding as data.
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        let mut bytes = f.encode();
        bytes[5..9].copy_from_slice(&(2u32).to_le_bytes());
        let decoded = Frame::decode(&bytes).unwrap();
        assert!(decoded.open(&KEY).is_err());
    }

    #[test]
    fn moving_a_frame_to_another_conversation_fails_authentication() {
        // §9.1: conversation is bound, preventing cross-conversation replay.
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        let mut bytes = f.encode();
        bytes[25] ^= 0xFF; // first byte of the conversation id
        let decoded = Frame::decode(&bytes).unwrap();
        assert!(decoded.open(&KEY).is_err());
    }

    #[test]
    fn changing_the_epoch_fails_authentication() {
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        let mut bytes = f.encode();
        bytes[41] ^= 0x01;
        let decoded = Frame::decode(&bytes).unwrap();
        assert!(decoded.open(&KEY).is_err());
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let f = Frame::seal(&KEY, conv(), 1, b"secret").unwrap();
        assert!(f.open(&[9u8; 32]).is_err());
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let f = Frame::seal(&KEY, conv(), 1, b"x").unwrap();
        let mut bytes = f.encode();
        bytes[0] = 42;
        match Frame::decode(&bytes) {
            Err(FrameError::UnsupportedVersion { found: 42, .. }) => {}
            other => panic!("expected version rejection, got {other:?}"),
        }
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let f = Frame::seal(&KEY, conv(), 1, b"x").unwrap();
        let bytes = f.encode();
        for cut in [0usize, 1, HEADER_LEN, bytes.len() - 1] {
            assert!(
                Frame::decode(&bytes[..cut]).is_err(),
                "accepted {cut} bytes"
            );
        }
    }

    #[test]
    fn non_bucket_sizes_are_rejected() {
        let f = Frame::seal(&KEY, conv(), 1, b"x").unwrap();
        let mut bytes = f.encode();
        bytes[1..5].copy_from_slice(&(1234u32).to_le_bytes());
        match Frame::decode(&bytes) {
            Err(FrameError::BadPadding) => {}
            other => panic!("expected BadPadding, got {other:?}"),
        }
    }

    #[test]
    fn oversized_payload_is_rejected_not_truncated() {
        let huge = vec![0u8; max_payload_len() + 1];
        match Frame::seal(&KEY, conv(), 1, &huge) {
            Err(FrameError::TooLarge) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn empty_payload_round_trips() {
        let f = Frame::seal(&KEY, conv(), 1, b"").unwrap();
        assert_eq!(f.open(&KEY).unwrap(), b"");
        assert_eq!(f.bucket(), 512);
    }

    #[test]
    fn message_ids_are_unique_and_labelable() {
        let a = MessageId::generate();
        let b = MessageId::generate();
        assert_ne!(a, b);
        assert_eq!(a.short_label().len(), 8);
        assert_eq!(a.to_string().len(), 32);
    }
}
