use thiserror::Error;

/// Errors from core identity, encoding, and escrow operations.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("contact code has an invalid Bech32m encoding")]
    CodeEncoding,

    #[error("contact code has the wrong human-readable prefix (expected `{expected}`)")]
    CodeWrongHrp { expected: &'static str },

    #[error("contact code has the wrong length: expected {expected} bytes, found {found}")]
    CodeWrongLength { expected: usize, found: usize },

    #[error("contact code carries unsupported format version {found} (this build understands {supported})")]
    CodeUnsupportedVersion { found: u8, supported: u8 },

    #[error("contact code checksum mismatch")]
    CodeChecksum,

    #[error("contact code contains an invalid public key")]
    CodeInvalidKey,

    #[error("escrow artifact is malformed: {0}")]
    EscrowMalformed(&'static str),

    #[error("escrow artifact was produced by a different version (found {found}, supported {supported})")]
    EscrowUnsupportedVersion { found: u8, supported: u8 },

    #[error("escrow decryption failed (wrong passphrase or corrupted artifact)")]
    EscrowDecrypt,

    #[error("escrow passphrase does not meet the minimum requirement: {0}")]
    EscrowWeakPassphrase(&'static str),

    #[error("invalid key material")]
    InvalidKey,

    #[error("cryptographic operation failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, CoreError>;
